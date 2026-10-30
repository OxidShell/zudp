//! Noise XX handshake driver.
//!
//! Message flow (`step` byte on the wire):
//!
//! ```text
//! 1  initiator → responder   e                 payload: initiator session index
//! 2  responder → initiator   e, ee, s, es      payload: responder session index
//! 3  initiator → responder   s, se             (no payload)
//! ```
//!
//! Recovery rules, because any of these datagrams can be lost or the remote can restart:
//!
//! - The initiator retransmits msg1 with back-off until msg2 arrives or the handshake times
//!   out.  A responder that sees the same msg1 twice resends its cached msg2.
//! - A msg1 that does not match the responder's half-open state replaces it: the remote
//!   restarted mid-handshake, and its old state can never complete.
//! - The initiator is done after writing msg3, so [`initiate`] keeps resending msg3 and an
//!   encrypted Ping until something authenticated comes back from the responder.
//! - Half-open states expire after the handshake timeout.

use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::Weak,
    time::{Duration, Instant},
};

use bytes::Bytes;
use tokio::sync::oneshot;

use crate::{
    Error,
    engine::EngineInner,
    frame::{Frame, WIRE_VERSION},
    peer::random_u64,
    security::{SecureChannel, build_initiator, build_responder},
};

const STEP_INIT: u8 = 1;
const STEP_RESPONSE: u8 = 2;
const STEP_FINISH: u8 = 3;

/// First retransmit delay; doubles up to [`RETRY_MAX`].
const RETRY_MIN: Duration = Duration::from_millis(200);
const RETRY_MAX: Duration = Duration::from_secs(1);

/// Largest Noise XX message (msg2: 32 e + 48 s + 16 tag + 8 payload + 16 tag), with headroom.
const MSG_BUF: usize = 256;

/// Session index length carried in msg1 / msg2 payloads.
const INDEX_LEN: usize = 8;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Role {
    Initiator,
    Responder,
}

/// How a handshake that someone is waiting on ended.
#[derive(Debug)]
pub(crate) enum Outcome {
    Ready,
    KeyMismatch,
}

/// A handshake in progress with one remote address.
pub(crate) struct Pending {
    hs: snow::HandshakeState,
    role: Role,
    /// Session index we told the remote to put on Secure frames addressed to us.
    pub(crate) local_index: u64,
    /// Remote's session index, learned from msg1 (responder) or msg2 (initiator).
    remote_index: u64,
    started: Instant,
    /// Wire bytes of the last message we sent, resent on retransmit.
    last_sent: Bytes,
    /// The remote message that produced `last_sent`; a byte-identical copy is a retransmit.
    last_received: Option<Bytes>,
    /// Our msg1 ephemeral key, used to break the tie when both sides initiate at once.
    our_ephemeral: Option<[u8; 32]>,
    waiter: Option<oneshot::Sender<Outcome>>,
}

pub(crate) type PendingMap = HashMap<SocketAddr, Pending>;

/// Material for a freshly established session, handed to the engine to install.
pub(crate) struct Established {
    pub channel: SecureChannel,
    pub remote_static: Option<[u8; 32]>,
    pub local_index: u64,
    pub initiator: bool,
    /// msg3 wire bytes; the initiator resends them until the responder answers.
    pub finish_wire: Option<Bytes>,
}

fn wire(step: u8, payload: Vec<u8>) -> Bytes {
    Frame::Handshake {
        step,
        version: WIRE_VERSION,
        payload: Bytes::from(payload),
    }
    .encode()
}

fn read_index(payload: &[u8]) -> Option<u64> {
    let bytes: [u8; INDEX_LEN] = payload.get(..INDEX_LEN)?.try_into().ok()?;
    Some(u64::from_be_bytes(bytes))
}

fn remote_static(hs: &snow::HandshakeState) -> Option<[u8; 32]> {
    hs.get_remote_static()?.try_into().ok()
}

fn pinned_key_ok(inner: &EngineInner, hs: &snow::HandshakeState) -> bool {
    match &inner.config.remote_key {
        None => true,
        Some(expected) => hs.get_remote_static() == Some(expected.as_slice()),
    }
}

fn into_established(
    pending: Pending,
    finish_wire: Option<Bytes>,
) -> Result<(Established, Option<oneshot::Sender<Outcome>>), snow::Error> {
    let remote_static = remote_static(&pending.hs);
    let transport = pending.hs.into_stateless_transport_mode()?;
    Ok((
        Established {
            channel: SecureChannel::new(transport, pending.remote_index),
            remote_static,
            local_index: pending.local_index,
            initiator: pending.role == Role::Initiator,
            finish_wire,
        },
        pending.waiter,
    ))
}

/// Process one handshake frame from `from`.
///
/// Returns a datagram to send back and, when the handshake completed, the session to
/// install.  The caller installs the session before notifying any waiter.
pub(crate) fn on_message(
    inner: &EngineInner,
    from: SocketAddr,
    step: u8,
    version: u8,
    payload: &Bytes,
) -> (
    Option<Bytes>,
    Option<(Established, Option<oneshot::Sender<Outcome>>)>,
) {
    let Some(kp) = inner.keypair.as_ref() else {
        tracing::debug!(target: "zudp::handshake", peer = %from, "ignored — security not configured");
        return (None, None);
    };
    if version != WIRE_VERSION {
        tracing::warn!(target: "zudp::handshake", peer = %from, version, ours = WIRE_VERSION, "ignored — wire version mismatch");
        return (None, None);
    }
    let mut pending = inner.pending.lock();
    match step {
        STEP_INIT => respond(inner, kp, &mut pending, from, payload),
        STEP_RESPONSE => finish_as_initiator(inner, &mut pending, from, payload),
        STEP_FINISH => finish_as_responder(inner, &mut pending, from, payload),
        _ => (None, None),
    }
}

fn respond(
    inner: &EngineInner,
    kp: &crate::security::Keypair,
    pending: &mut PendingMap,
    from: SocketAddr,
    payload: &Bytes,
) -> (
    Option<Bytes>,
    Option<(Established, Option<oneshot::Sender<Outcome>>)>,
) {
    let mut waiter = None;
    if let Some(existing) = pending.get_mut(&from) {
        match existing.role {
            Role::Responder if existing.last_received.as_ref() == Some(payload) => {
                return (Some(existing.last_sent.clone()), None);
            }
            Role::Initiator => {
                // Both sides initiated: the larger msg1 ephemeral key stays initiator.
                let theirs: Option<[u8; 32]> = payload.get(..32).and_then(|e| e.try_into().ok());
                if existing.our_ephemeral > theirs {
                    return (None, None);
                }
                waiter = existing.waiter.take();
            }
            Role::Responder => {}
        }
    }
    if !pending.contains_key(&from) && pending.len() >= inner.config.max_peers {
        tracing::warn!(target: "zudp::handshake", peer = %from, "too many handshakes in progress — dropping msg1");
        return (None, None);
    }

    let mut hs = match build_responder(kp) {
        Ok(hs) => hs,
        Err(e) => {
            tracing::error!(target: "zudp::handshake", peer = %from, "build_responder: {e}");
            return (None, None);
        }
    };
    let mut buf = [0u8; MSG_BUF];
    let Some(remote_index) = hs
        .read_message(payload, &mut buf)
        .ok()
        .and_then(|n| read_index(&buf[..n]))
    else {
        tracing::debug!(target: "zudp::handshake", peer = %from, "invalid msg1");
        return (None, None);
    };
    let local_index = random_u64();
    let mut out = vec![0u8; MSG_BUF];
    let n = match hs.write_message(&local_index.to_be_bytes(), &mut out) {
        Ok(n) => n,
        Err(e) => {
            tracing::warn!(target: "zudp::handshake", peer = %from, "write msg2: {e}");
            return (None, None);
        }
    };
    out.truncate(n);
    let reply = wire(STEP_RESPONSE, out);
    pending.insert(
        from,
        Pending {
            hs,
            role: Role::Responder,
            local_index,
            remote_index,
            started: Instant::now(),
            last_sent: reply.clone(),
            last_received: Some(payload.clone()),
            our_ephemeral: None,
            waiter,
        },
    );
    (Some(reply), None)
}

fn finish_as_initiator(
    inner: &EngineInner,
    pending: &mut PendingMap,
    from: SocketAddr,
    payload: &Bytes,
) -> (
    Option<Bytes>,
    Option<(Established, Option<oneshot::Sender<Outcome>>)>,
) {
    let Some(state) = pending.get_mut(&from).filter(|p| p.role == Role::Initiator) else {
        return (None, None);
    };
    let mut buf = [0u8; MSG_BUF];
    let Some(remote_index) = state
        .hs
        .read_message(payload, &mut buf)
        .ok()
        .and_then(|n| read_index(&buf[..n]))
    else {
        // A forged or corrupted msg2 leaves our state unusable; start over on retransmit.
        tracing::debug!(target: "zudp::handshake", peer = %from, "invalid msg2");
        if let Some(stale) = pending.remove(&from) {
            restart_initiator(inner, pending, from, stale);
        }
        return (None, None);
    };
    if !pinned_key_ok(inner, &state.hs) {
        tracing::warn!(target: "zudp::security", peer = %from, "handshake aborted — remote key does not match pinned key");
        if let Some(mut aborted) = pending.remove(&from)
            && let Some(waiter) = aborted.waiter.take()
        {
            let _ = waiter.send(Outcome::KeyMismatch);
        }
        return (None, None);
    }
    state.remote_index = remote_index;
    let mut out = vec![0u8; MSG_BUF];
    let n = match state.hs.write_message(&[], &mut out) {
        Ok(n) => n,
        Err(e) => {
            tracing::warn!(target: "zudp::handshake", peer = %from, "write msg3: {e}");
            return (None, None);
        }
    };
    out.truncate(n);
    let finish = wire(STEP_FINISH, out);
    let Some(state) = pending.remove(&from) else {
        return (None, None);
    };
    match into_established(state, Some(finish.clone())) {
        Ok(done) => (Some(finish), Some(done)),
        Err(e) => {
            tracing::error!(target: "zudp::handshake", peer = %from, "into_transport_mode: {e}");
            (None, None)
        }
    }
}

/// Replace a broken initiator state with a fresh one that keeps the same waiter.
fn restart_initiator(
    inner: &EngineInner,
    pending: &mut PendingMap,
    from: SocketAddr,
    stale: Pending,
) {
    let Some(kp) = inner.keypair.as_ref() else {
        return;
    };
    if let Ok(mut fresh) = new_initiator(kp) {
        fresh.waiter = stale.waiter;
        fresh.started = stale.started;
        pending.insert(from, fresh);
    }
}

fn finish_as_responder(
    inner: &EngineInner,
    pending: &mut PendingMap,
    from: SocketAddr,
    payload: &Bytes,
) -> (
    Option<Bytes>,
    Option<(Established, Option<oneshot::Sender<Outcome>>)>,
) {
    let Some(state) = pending.get_mut(&from).filter(|p| p.role == Role::Responder) else {
        return (None, None);
    };
    let mut buf = [0u8; MSG_BUF];
    if let Err(e) = state.hs.read_message(payload, &mut buf) {
        tracing::debug!(target: "zudp::handshake", peer = %from, "invalid msg3: {e}");
        return (None, None);
    }
    if !pinned_key_ok(inner, &state.hs) {
        tracing::warn!(target: "zudp::security", peer = %from, "handshake aborted — remote key does not match pinned key");
        pending.remove(&from);
        return (None, None);
    }
    let Some(state) = pending.remove(&from) else {
        return (None, None);
    };
    match into_established(state, None) {
        Ok(done) => (None, Some(done)),
        Err(e) => {
            tracing::error!(target: "zudp::handshake", peer = %from, "into_transport_mode: {e}");
            (None, None)
        }
    }
}

fn new_initiator(kp: &crate::security::Keypair) -> Result<Pending, Error> {
    let mut hs = build_initiator(kp)?;
    let local_index = random_u64();
    let mut out = vec![0u8; MSG_BUF];
    let n = hs.write_message(&local_index.to_be_bytes(), &mut out)?;
    out.truncate(n);
    let our_ephemeral = out.get(..32).and_then(|e| e.try_into().ok());
    Ok(Pending {
        hs,
        role: Role::Initiator,
        local_index,
        remote_index: 0,
        started: Instant::now(),
        last_sent: wire(STEP_INIT, out),
        last_received: None,
        our_ephemeral,
        waiter: None,
    })
}

/// Drop half-open handshakes older than the handshake timeout.
pub(crate) fn expire(inner: &EngineInner) {
    let timeout = inner.config.handshake_timeout;
    inner.pending.lock().retain(|addr, p| {
        let keep = p.started.elapsed() < timeout;
        if !keep {
            tracing::debug!(target: "zudp::handshake", peer = %addr, role = ?p.role, "half-open handshake expired");
        }
        keep
    });
}

/// `true` when `index` belongs to a handshake that has not finished on our side yet.
pub(crate) fn is_pending_index(inner: &EngineInner, index: u64) -> bool {
    inner
        .pending
        .lock()
        .values()
        .any(|p| p.local_index == index)
}

/// Run a full handshake with `peer` as initiator.
///
/// Returns once the session is established on both ends: something authenticated has come
/// back from the remote.  Fails with [`Error::HandshakeTimeout`] or [`Error::KeyMismatch`].
pub(crate) async fn initiate(engine: &Weak<EngineInner>, peer: SocketAddr) -> Result<(), Error> {
    let (deadline, rx) = {
        let inner = engine.upgrade().ok_or_else(stopped)?;
        let Some(kp) = inner.keypair.as_ref() else {
            return Ok(());
        };
        let mut state = new_initiator(kp)?;
        let (tx, rx) = oneshot::channel();
        state.waiter = Some(tx);
        // Registered before the first send so a fast msg2 always finds the initiator state.
        inner.pending.lock().insert(peer, state);
        (Instant::now() + inner.config.handshake_timeout, rx)
    };

    let outcome = retransmit_until(engine, peer, deadline, rx, |inner| {
        inner
            .pending
            .lock()
            .get(&peer)
            .filter(|p| p.role == Role::Initiator)
            .map(|p| p.last_sent.clone())
    })
    .await;
    match outcome {
        Some(Outcome::Ready) => {}
        Some(Outcome::KeyMismatch) => return Err(Error::KeyMismatch),
        None => {
            if let Some(inner) = engine.upgrade() {
                inner.pending.lock().remove(&peer);
            }
            return Err(Error::HandshakeTimeout { peer });
        }
    }

    confirm(engine, peer, deadline).await
}

/// Resend whatever `next_wire` yields with back-off until `rx` resolves or `deadline`.
async fn retransmit_until<F>(
    engine: &Weak<EngineInner>,
    peer: SocketAddr,
    deadline: Instant,
    mut rx: oneshot::Receiver<Outcome>,
    next_wire: F,
) -> Option<Outcome>
where
    F: Fn(&EngineInner) -> Option<Bytes>,
{
    let mut delay = RETRY_MIN;
    loop {
        let wire = {
            let inner = engine.upgrade()?;
            let sock = inner.get_socket();
            next_wire(&inner).map(|w| (w, sock))
        };
        if let Some((wire, sock)) = wire
            && let Err(e) = sock.send_to(&wire, peer).await
        {
            tracing::debug!(target: "zudp::handshake", %peer, "send: {e}");
        }
        let now = Instant::now();
        if now >= deadline {
            return None;
        }
        match tokio::time::timeout(delay.min(deadline - now), &mut rx).await {
            Ok(Ok(outcome)) => return Some(outcome),
            Ok(Err(_)) => return None,
            Err(_) => delay = (delay * 2).min(RETRY_MAX),
        }
    }
}

/// Wait for the first authenticated frame from `peer`, resending msg3 and a Ping meanwhile.
async fn confirm(
    engine: &Weak<EngineInner>,
    peer: SocketAddr,
    deadline: Instant,
) -> Result<(), Error> {
    let mut delay = RETRY_MIN;
    loop {
        let (session, inner) = {
            let inner = engine.upgrade().ok_or_else(stopped)?;
            let session = inner
                .peers
                .get(&peer)
                .map(|r| r.value().clone())
                .ok_or(Error::HandshakeTimeout { peer })?;
            (session, inner)
        };
        let wait = session.confirmed_notify.notified();
        tokio::pin!(wait);
        wait.as_mut().enable();
        if session.is_confirmed() {
            session.clear_finish_wire();
            return Ok(());
        }
        let sock = inner.get_socket();
        let ping = crate::engine::ping_for(&inner, &session);
        let finish = session.finish_wire();
        drop(inner);
        if let Some(finish) = finish {
            let _ = sock.send_to(&finish, peer).await;
        }
        let _ = sock.send_to(&ping, peer).await;
        let now = Instant::now();
        if now >= deadline {
            return Err(Error::HandshakeTimeout { peer });
        }
        let _ = tokio::time::timeout(delay.min(deadline - now), wait).await;
        delay = (delay * 2).min(RETRY_MAX);
    }
}

fn stopped() -> Error {
    Error::EngineStopped {
        reason: "engine stopped during handshake".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn index_payload_roundtrip() {
        assert_eq!(read_index(&42u64.to_be_bytes()), Some(42));
        assert_eq!(read_index(&[1, 2, 3]), None);
    }
}
