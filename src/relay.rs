//! Relayed sessions and hole punching, client side.
//!
//! A client with a secure session to a relay node R can open a session to the peer with
//! static key `T` *through* R.  The two ends run an ordinary Noise XX handshake and then
//! exchange ordinary `Secure` frames; those wire bytes travel opaque inside the client's
//! own sessions with R:
//!
//! ```text
//! A ──Secure_AR(Via { to: T, inner })──► R ──Secure_RB(ViaFrom { from: A, inner })──► B
//!                    └──────── inner = Handshake / Secure_AB, never decrypted by R ────┘
//! ```
//!
//! R's `from` claim only says which session an inner frame belongs to; the end-to-end
//! session decides whether it is accepted.  A handshake whose authenticated static key
//! differs from the claim is dropped, and so is a `Secure` frame whose session index
//! belongs to another peer than the one claimed.
//!
//! Once a relayed session exists both ends ask R for an introduction.  When both asked,
//! R tells each the public address it observes for the other, both send authenticated
//! keepalives straight there, and the first authenticated frame that arrives directly
//! moves the session onto the direct path.  If the direct path goes silent, traffic falls
//! back to the relay; the session itself is never interrupted.

#[cfg(feature = "relay")]
pub(crate) mod node;

use std::{
    net::SocketAddr,
    sync::{Arc, atomic::Ordering},
    time::Duration,
};

use bytes::{Bytes, BytesMut};

use crate::{
    PeerAddr,
    addr::Path,
    engine::{self, EngineInner},
    event::{DisconnectReason, PeerEvent},
    frame::Frame,
    peer::PeerState,
};

/// Wait before asking the relay for another introduction while traffic still goes through
/// it (punching failed, or the direct path was lost).
const INTRO_RETRY: Duration = Duration::from_secs(30);
/// Authenticated probes sent to the introduced address, and their spacing.
const PUNCH_PROBES: u32 = 10;
const PUNCH_INTERVAL: Duration = Duration::from_millis(100);

/// `true` for frames that only make sense between a relay node and its direct clients.
pub(crate) fn is_relay_frame(frame: &Frame) -> bool {
    matches!(
        frame,
        Frame::Via { .. }
            | Frame::ViaFrom { .. }
            | Frame::Unreachable { .. }
            | Frame::IntroRequest { .. }
            | Frame::Intro { .. }
    )
}

/// Wrap the wire bytes `wire` for the peer with key `to`, reached through `relay`: a
/// `Via` frame sealed in our session with the relay.  `None` without that session.
pub(crate) fn via(
    engine: &EngineInner,
    relay: SocketAddr,
    to: [u8; 32],
    wire: Bytes,
) -> Option<(Bytes, SocketAddr)> {
    let relay_peer = engine.peers.get(&PeerAddr::Direct(relay))?.value().clone();
    if !relay_peer.has_channel() {
        return None;
    }
    let sealed = engine::seal(
        engine,
        &relay_peer,
        &Frame::Via { to, inner: wire }.encode(),
    )?;
    relay_peer.mark_sent();
    Some((sealed, relay))
}

/// Handle a frame that arrived inside the secure session with `peer`.
///
/// Relay frames from a direct peer are consumed here; anything else is returned for
/// normal dispatch, re-attributed to the relayed peer when it came out of a `ViaFrom`.
pub(crate) async fn open(
    engine: &Arc<EngineInner>,
    peer: Arc<PeerState>,
    frame: Frame,
) -> Option<(Arc<PeerState>, Frame)> {
    let relay = match peer.addr() {
        PeerAddr::Direct(addr) => addr,
        // Relaying inside an end-to-end session is not a thing; drop rather than nest.
        PeerAddr::Relayed { .. } => return (!is_relay_frame(&frame)).then_some((peer, frame)),
    };
    match frame {
        Frame::ViaFrom { from, inner } => open_via_from(engine, relay, from, &inner).await,
        Frame::Unreachable { to } => {
            on_unreachable(engine, PeerAddr::Relayed { relay, key: to });
            None
        }
        Frame::Intro { peer: key, addr } => {
            on_intro(engine, PeerAddr::Relayed { relay, key }, addr);
            None
        }
        Frame::Via { to, inner } => {
            forward(engine, &peer, to, inner).await;
            None
        }
        Frame::IntroRequest { peer: key } => {
            #[cfg(feature = "relay")]
            if let Some(node) = &engine.relay {
                node.introduce(engine, &peer, key).await;
            }
            #[cfg(not(feature = "relay"))]
            let _ = key;
            None
        }
        frame => Some((peer, frame)),
    }
}

/// A `Via` from a client: relay it when this socket is a relay node, otherwise tell the
/// client at once that `to` cannot be reached here.
async fn forward(engine: &Arc<EngineInner>, client: &Arc<PeerState>, to: [u8; 32], inner: Bytes) {
    #[cfg(feature = "relay")]
    if let Some(node) = &engine.relay {
        node.forward(engine, client, to, inner).await;
        return;
    }
    let _ = inner;
    if let Some(wire) = engine::seal(engine, client, &Frame::Unreachable { to }.encode()) {
        engine.send_to_peer(client, wire, "unreachable").await;
    }
}

/// Unwrap the opaque frame a relay delivered on behalf of the client it says has `claimed`.
async fn open_via_from(
    engine: &Arc<EngineInner>,
    relay: SocketAddr,
    claimed: [u8; 32],
    inner: &Bytes,
) -> Option<(Arc<PeerState>, Frame)> {
    let handle = PeerAddr::Relayed {
        relay,
        key: claimed,
    };
    match Frame::decode(BytesMut::from(inner.as_ref())) {
        Ok(Frame::Handshake {
            step,
            version,
            payload,
        }) => {
            engine::handle_handshake(step, version, &payload, handle, engine).await;
            None
        }
        Ok(Frame::Secure {
            index,
            nonce,
            ciphertext,
        }) => open_relayed_secure(engine, handle, index, nonce, &ciphertext).await,
        Ok(Frame::SessionUnknown { index }) => {
            engine::on_session_unknown(engine, handle, index);
            None
        }
        Ok(_) => {
            tracing::debug!(target: "zudp::relay", peer = %handle, "relayed frame of a kind that is never relayed — dropped");
            None
        }
        Err(e) => {
            tracing::debug!(target: "zudp::relay", peer = %handle, "bad relayed frame: {e}");
            None
        }
    }
}

/// Authenticate a relayed `Secure` frame.  The session its index names must belong to the
/// peer the relay claimed; otherwise the relay (or someone injecting through it) is trying
/// to pass one peer's traffic off as another's.
async fn open_relayed_secure(
    engine: &Arc<EngineInner>,
    handle: PeerAddr,
    index: u64,
    nonce: u64,
    ciphertext: &Bytes,
) -> Option<(Arc<PeerState>, Frame)> {
    let Some(peer) = engine.by_index.get(&index).map(|r| r.value().clone()) else {
        if !crate::handshake::is_pending_index(engine, index) {
            engine::send_session_unknown(engine, handle, index).await;
        }
        return None;
    };
    if peer.addr() != handle {
        tracing::warn!(target: "zudp::relay", claimed = %handle, session = %peer.addr(), "relayed frame attributed to the wrong sender — dropped");
        engine.dropped_forged.fetch_add(1, Ordering::Relaxed);
        return None;
    }
    let plain = engine::decrypt(&peer, nonce, ciphertext)?;
    peer.advance_nonce(nonce);
    peer.mark_seen();
    peer.mark_confirmed();
    engine::inner_frame(peer, &plain)
}

/// The relay could not deliver to `handle`: fail its pending handshake, or end a session
/// that has no other path.
fn on_unreachable(engine: &Arc<EngineInner>, handle: PeerAddr) {
    if crate::handshake::fail_unreachable(engine, handle) {
        return;
    }
    let on_relay = engine
        .peers
        .get(&handle)
        .is_some_and(|p| p.direct_path().is_none());
    if on_relay && engine.forget_peer(handle).is_some() {
        tracing::info!(target: "zudp::relay", peer = %handle, "relay reports the peer unreachable");
        engine.emit(PeerEvent::Disconnected {
            addr: handle,
            reason: DisconnectReason::Unreachable,
        });
    }
}

/// Ask the relay to introduce us to the relayed `peer`, at most once per [`INTRO_RETRY`].
pub(crate) fn request_intro(engine: &Arc<EngineInner>, peer: &PeerState) {
    let PeerAddr::Relayed { relay, key } = peer.addr() else {
        return;
    };
    if !engine.config.punching || !peer.begin_intro(INTRO_RETRY) {
        return;
    }
    let Some(relay_peer) = engine
        .peers
        .get(&PeerAddr::Direct(relay))
        .map(|r| r.value().clone())
    else {
        return;
    };
    let Some(wire) = engine::seal(
        engine,
        &relay_peer,
        &Frame::IntroRequest { peer: key }.encode(),
    ) else {
        return;
    };
    tracing::debug!(target: "zudp::relay", peer = %peer.addr(), "asking the relay for an introduction");
    let engine = engine.clone();
    tokio::spawn(async move {
        engine
            .send_to_peer(&relay_peer, wire, "intro request")
            .await;
    });
}

/// The relay says the relayed peer `handle` is seen at `addr`: probe it there.
fn on_intro(engine: &Arc<EngineInner>, handle: PeerAddr, addr: SocketAddr) {
    if !engine.config.punching {
        return;
    }
    let Some(peer) = engine
        .peers
        .get(&handle)
        .map(|r| r.value().clone())
        .filter(|p| p.has_channel())
    else {
        return;
    };
    tracing::debug!(target: "zudp::relay", peer = %handle, %addr, "introduced — punching");
    let weak = Arc::downgrade(engine);
    tokio::spawn(async move {
        for _ in 0..PUNCH_PROBES {
            let Some(engine) = weak.upgrade().filter(|e| e.is_current(&peer)) else {
                return;
            };
            if peer.direct_path() == Some(addr) {
                return;
            }
            // An authenticated keepalive: it opens our NAT mapping toward `addr`, and once it
            // gets through it is what moves the remote's side of the session.
            if let Some(ping) = engine::ping_for(&engine, &peer) {
                let sock = engine.get_socket();
                drop(engine);
                if let Err(e) = sock.send_to(&ping, addr).await {
                    tracing::debug!(target: "zudp::relay", %addr, "punch probe failed: {e}");
                }
            }
            tokio::time::sleep(PUNCH_INTERVAL).await;
        }
    });
}

/// An authenticated frame from the relayed `peer` arrived straight from `from`.
///
/// Only the newest frame so far may move the path, like roaming on direct sessions, so a
/// late datagram from an address the peer already left cannot drag the session back.
pub(crate) fn on_direct(
    engine: &EngineInner,
    peer: &Arc<PeerState>,
    from: SocketAddr,
    newest: bool,
) {
    let Some(previous) = peer.touch_direct(from, newest) else {
        return;
    };
    if let Some(old) = previous {
        engine.punched.remove_if(&old, |_, p| Arc::ptr_eq(p, peer));
    }
    engine.punched.insert(from, peer.clone());
    tracing::info!(target: "zudp::relay", peer = %peer.addr(), direct = %from, "session moved to a direct path");
    engine.emit(PeerEvent::PathChanged {
        addr: peer.addr(),
        path: Path::Direct(from),
    });
}

/// Background upkeep for one relayed peer: fall back to the relay when the direct path
/// went silent, and retry the introduction while traffic still goes via the relay.
pub(crate) fn tick(engine: &Arc<EngineInner>, peer: &Arc<PeerState>) {
    let PeerAddr::Relayed { relay, .. } = peer.addr() else {
        return;
    };
    // Well inside the peer timeout, so the relay path takes over before the session dies.
    let direct_timeout = engine.config.effective_peer_timeout() * 3 / 5;
    let Some(lost) = peer.expire_direct(direct_timeout) else {
        if peer.direct_path().is_none() {
            request_intro(engine, peer);
        }
        return;
    };
    engine.punched.remove_if(&lost, |_, p| Arc::ptr_eq(p, peer));
    tracing::info!(target: "zudp::relay", peer = %peer.addr(), direct = %lost, "direct path went silent — back to the relay");
    engine.emit(PeerEvent::PathChanged {
        addr: peer.addr(),
        path: Path::Relayed(relay),
    });
    // Tell the remote over the relay right away that we are still here.
    if let Some((ping, dest)) =
        engine::ping_for(engine, peer).and_then(|ping| engine.outbound(peer, ping))
    {
        peer.mark_sent();
        let sock = engine.get_socket();
        tokio::spawn(async move {
            let _ = sock.send_to(&ping, dest).await;
        });
    }
}
