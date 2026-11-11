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
    net::{IpAddr, SocketAddr},
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
/// An introduction is only accepted this soon after we asked for it.
const INTRO_ACCEPT: Duration = Duration::from_secs(10);
/// A path challenge to the same address is not repeated sooner than this.
const CHALLENGE_RETRY: Duration = Duration::from_millis(250);
/// How long a challenge token is honoured: answers on paths with a round trip up to this
/// long still validate.
const CHALLENGE_LIFETIME: Duration = Duration::from_secs(5);
/// Relayed handshake initiations accepted per second from one relay.
pub(crate) const RELAYED_HANDSHAKES_PER_SEC: f64 = 20.0;

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
        Frame::ViaFrom { from, inner } => {
            let handle = PeerAddr::Relayed { relay, key: from };
            if !accepts(engine, handle) {
                tracing::debug!(target: "zudp::relay", %relay, "relayed frame through a relay we did not accept — dropped");
                engine
                    .dropped_relay_unaccepted
                    .fetch_add(1, Ordering::Relaxed);
                return None;
            }
            open_via_from(engine, handle, &inner).await
        }
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

/// May the relay in `handle` deliver frames for it?  Any relay may answer sessions we
/// started through it (and keep sessions alive that exist); only relays the application
/// accepted may open new ones toward us.
fn accepts(engine: &EngineInner, handle: PeerAddr) -> bool {
    let PeerAddr::Relayed { relay, .. } = handle else {
        return false;
    };
    engine.inbound_relays.read().contains(&relay)
        || engine.peers.contains_key(&handle)
        || engine.pending.lock().contains_key(&handle)
}

/// Unwrap the opaque frame a relay delivered on behalf of the client `handle` names.
async fn open_via_from(
    engine: &Arc<EngineInner>,
    handle: PeerAddr,
    inner: &Bytes,
) -> Option<(Arc<PeerState>, Frame)> {
    match Frame::decode(BytesMut::from(inner.as_ref())) {
        Ok(Frame::Handshake {
            step,
            version,
            payload,
        }) => {
            // Each relayed msg1 costs us key exchanges; bound them per relay.
            let PeerAddr::Relayed { relay, .. } = handle else {
                return None;
            };
            if step == 1 && !engine.relayed_hs_limiter.lock().allow(relay.ip()) {
                engine.dropped_rate_limited.fetch_add(1, Ordering::Relaxed);
                return None;
            }
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

/// `true` when the relayed `peer` may be punched to without the application asking: its
/// key is pinned, or the application called `punch` for it before.
fn punch_approved(engine: &EngineInner, key: &[u8; 32]) -> bool {
    engine.config.pinned_keys.contains(key) || engine.punch_allowed.read().contains(key)
}

/// Start punching to a freshly installed relayed session when it is approved.  Asking for
/// an introduction reveals our address to the peer, so unknown peers never get one.
pub(crate) fn auto_punch(engine: &Arc<EngineInner>, peer: &PeerState) {
    if let Some(key) = peer.addr().key()
        && punch_approved(engine, &key)
    {
        request_intro(engine, peer, INTRO_RETRY);
    }
}

/// The application approves punching to the relayed peer `handle`: remember it for later
/// sessions with that key and ask the relay for an introduction now.
pub(crate) fn punch(engine: &Arc<EngineInner>, handle: PeerAddr) -> Result<(), crate::Error> {
    let no_session = || crate::Error::NoSession { peer: handle };
    let key = handle.key().ok_or_else(no_session)?;
    let peer = engine
        .peers
        .get(&handle)
        .map(|r| r.value().clone())
        .filter(|p| p.has_channel())
        .ok_or_else(no_session)?;
    engine.punch_allowed.write().insert(key);
    request_intro(engine, &peer, Duration::ZERO);
    Ok(())
}

/// Ask the relay to introduce us to the relayed `peer`, unless we did within `cooldown`.
///
/// The request goes only to the relay the session runs through, and the relay only
/// answers when the peer asked for us too.
fn request_intro(engine: &Arc<EngineInner>, peer: &PeerState, cooldown: Duration) {
    let PeerAddr::Relayed { relay, key } = peer.addr() else {
        return;
    };
    if !engine.config.punching || !peer.begin_intro(cooldown) {
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

/// How local an address is: 0 public, 1 private or link-local, 2 loopback; `None` for
/// addresses no peer can be reached at.
fn locality(ip: IpAddr) -> Option<u8> {
    match ip {
        IpAddr::V4(v4) => {
            let shared = v4.octets()[0] == 100 && v4.octets()[1] & 0xc0 == 64; // 100.64/10
            if v4.is_unspecified() || v4.is_broadcast() || v4.is_multicast() {
                None
            } else if v4.is_loopback() {
                Some(2)
            } else if v4.is_private() || v4.is_link_local() || shared {
                Some(1)
            } else {
                Some(0)
            }
        }
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return locality(IpAddr::V4(v4));
            }
            if v6.is_unspecified() || v6.is_multicast() {
                None
            } else if v6.is_loopback() {
                Some(2)
            } else if v6.is_unique_local() || v6.is_unicast_link_local() {
                Some(1)
            } else {
                Some(0)
            }
        }
    }
}

/// May we punch toward `addr`, introduced by the relay at `relay`?  Public addresses yes;
/// a private one only from a private relay and loopback only from a loopback relay — a
/// public relay naming a LAN address is trying to aim our probes at our own network.
fn punchable(addr: SocketAddr, relay: SocketAddr) -> bool {
    addr.port() != 0
        && matches!(
            (locality(addr.ip()), locality(relay.ip())),
            (Some(target), Some(relay)) if target <= relay
        )
}

/// The relay says the relayed peer `handle` is seen at `addr`: probe it there — if we
/// asked, the address is plausible and no campaign is already running.
fn on_intro(engine: &Arc<EngineInner>, handle: PeerAddr, addr: SocketAddr) {
    let PeerAddr::Relayed { relay, .. } = handle else {
        return;
    };
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
    if !peer.take_intro(INTRO_ACCEPT) {
        tracing::debug!(target: "zudp::relay", peer = %handle, "unsolicited introduction ignored");
        return;
    }
    if !punchable(addr, relay) {
        tracing::warn!(target: "zudp::relay", peer = %handle, %addr, "introduction to an address we will not probe");
        return;
    }
    if !peer.begin_punch() {
        return;
    }
    tracing::debug!(target: "zudp::relay", peer = %handle, %addr, "introduced — punching");
    let weak = Arc::downgrade(engine);
    tokio::spawn(async move {
        for _ in 0..PUNCH_PROBES {
            let Some(engine) = weak.upgrade().filter(|e| e.is_current(&peer)) else {
                break;
            };
            if peer.direct_path() == Some(addr) {
                break;
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
        peer.end_punch();
    });
}

/// An authenticated frame of the relayed `peer`'s session arrived straight from `from`.
///
/// The path only moves after a challenge sent to `from` comes back from `from`: a frame
/// alone proves the sender holds the session, not that it lives at the address the frame
/// claims to come from (a relay or on-path attacker can hold a frame back and deliver it
/// from any spoofed address).  Only the newest frame so far triggers a challenge, so a late
/// datagram from an address the peer already left cannot drag the session back.  Returns
/// the frame for normal dispatch, unless it was part of the validation.
pub(crate) async fn on_direct(
    engine: &Arc<EngineInner>,
    peer: Arc<PeerState>,
    from: SocketAddr,
    newest: bool,
    frame: Frame,
) -> Option<(Arc<PeerState>, Frame)> {
    let PeerAddr::Relayed { relay, .. } = peer.addr() else {
        return Some((peer, frame));
    };
    if from == relay {
        // The relay's own address is never a direct path to someone else.
        return None;
    }
    if peer.direct_path() == Some(from) {
        peer.touch_direct(from, false);
    } else if let Frame::PathResponse { token } = frame {
        // An answer settles its challenge; it never starts a new one.
        if peer.answer_challenge(from, token) {
            switch_direct(engine, &peer, from);
        }
        return None;
    } else if newest
        && let Some(token) = peer.begin_challenge(from, CHALLENGE_RETRY, CHALLENGE_LIFETIME)
    {
        send_direct(engine, &peer, Frame::PathChallenge { token }, from).await;
    }
    match frame {
        Frame::PathChallenge { token } => {
            send_direct(engine, &peer, Frame::PathResponse { token }, from).await;
            None
        }
        Frame::PathResponse { .. } => None,
        frame => Some((peer, frame)),
    }
}

/// Seal `frame` in `peer`'s session and send it straight to `to`.
async fn send_direct(engine: &EngineInner, peer: &PeerState, frame: Frame, to: SocketAddr) {
    let Some(wire) = engine::seal(engine, peer, &frame.encode()) else {
        return;
    };
    if let Err(e) = engine.get_socket().send_to(&wire, to).await {
        tracing::debug!(target: "zudp::relay", %to, "path validation send failed: {e}");
    }
}

/// `from` answered our challenge: move `peer`'s traffic there.
fn switch_direct(engine: &EngineInner, peer: &Arc<PeerState>, from: SocketAddr) {
    let Some(previous) = peer.touch_direct(from, true) else {
        return;
    };
    if let Some(old) = previous {
        engine.punched.remove_if(&old, |_, p| Arc::ptr_eq(p, peer));
    }
    engine.punched.insert(from, peer.clone());
    tracing::info!(target: "zudp::relay", peer = %peer.addr(), direct = %from, "session moved to a validated direct path");
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
            auto_punch(engine, peer);
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

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    #[test]
    fn introductions_only_aim_where_the_relay_lives() {
        let public_relay = addr("198.51.100.1:7800");
        let lan_relay = addr("192.168.1.2:7800");
        let lo_relay = addr("127.0.0.1:7800");
        assert!(punchable(addr("203.0.113.9:4000"), public_relay));
        assert!(punchable(addr("[2001:db8::9]:4000"), public_relay));
        for bad in [
            "0.0.0.0:4000",
            "255.255.255.255:4000",
            "224.0.0.1:4000",
            "[ff02::1]:4000",
            "[::]:4000",
            "203.0.113.9:0",
        ] {
            assert!(!punchable(addr(bad), lo_relay), "{bad}");
        }
        for lan in [
            "10.0.0.5:4000",
            "192.168.1.9:4000",
            "169.254.1.1:4000",
            "100.64.0.1:4000",
            "[fe80::1]:4000",
            "[fd00::1]:4000",
        ] {
            assert!(
                !punchable(addr(lan), public_relay),
                "{lan} from a public relay"
            );
            assert!(punchable(addr(lan), lan_relay), "{lan} from a LAN relay");
        }
        assert!(!punchable(addr("127.0.0.1:4000"), public_relay));
        assert!(!punchable(addr("127.0.0.1:4000"), lan_relay));
        assert!(punchable(addr("127.0.0.1:4000"), lo_relay));
    }

    #[test]
    fn introductions_are_accepted_once_and_only_when_asked_for() {
        let peer = PeerState::new(PeerAddr::Relayed {
            relay: addr("198.51.100.1:7800"),
            key: [1; 32],
        });
        assert!(!peer.take_intro(INTRO_ACCEPT), "unsolicited");
        assert!(peer.begin_intro(Duration::ZERO));
        assert!(peer.take_intro(INTRO_ACCEPT));
        assert!(
            !peer.take_intro(INTRO_ACCEPT),
            "a second answer to one request"
        );
        assert!(peer.begin_punch());
        assert!(!peer.begin_punch(), "two campaigns at once");
        peer.end_punch();
        assert!(peer.begin_punch());
    }
}
