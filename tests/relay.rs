//! Relayed sessions: two clients of a relay node talk end to end through it, and punch
//! through to a direct path when they can.
#![cfg(feature = "relay")]

mod common;

use std::{
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use bytes::Bytes;
use common::{drain, lo};
use parking_lot::Mutex;
use tokio::time::timeout;
use zudp::{
    Error, Keypair, Path, PeerAddr, PeerEvent, PeerEvents, RelayLimits, RelayTap, Zudp, ZudpSocket,
};

type Socket = ZudpSocket<Vec<u8>>;

/// An open relay node on loopback: the socket, its address and its static key.
async fn relay(limits: RelayLimits) -> (Socket, SocketAddr, [u8; 32]) {
    let key = Keypair::generate();
    let socket: Socket = lo()
        .port(0)
        .security(key.clone())
        .relay_node(limits, |_: &[u8; 32], _: &[u8; 32]| true)
        .listen()
        .await
        .unwrap();
    let addr = socket.local_addr().unwrap();
    (socket, addr, key.public)
}

/// A client socket already holding a session with the relay at `relay`, accepting the
/// relayed sessions it delivers.
async fn client(builder: Zudp, relay: SocketAddr) -> (Socket, [u8; 32]) {
    client_of(builder.accept_relayed_from(relay), relay).await
}

/// Like [`client`] without accepting inbound relayed sessions.
async fn client_of(builder: Zudp, relay: SocketAddr) -> (Socket, [u8; 32]) {
    let key = Keypair::generate();
    let socket: Socket = builder
        .port(0)
        .security(key.clone())
        .listen()
        .await
        .unwrap();
    socket.connect(relay).await.unwrap();
    (socket, key.public)
}

fn relayed(relay: SocketAddr, key: [u8; 32]) -> PeerAddr {
    PeerAddr::Relayed { relay, key }
}

async fn wait_for(
    events: &mut PeerEvents,
    within: Duration,
    mut pred: impl FnMut(&PeerEvent) -> bool,
) -> PeerEvent {
    timeout(within, async {
        loop {
            let event = events.recv().await.unwrap();
            if pred(&event) {
                return event;
            }
        }
    })
    .await
    .expect("expected event did not arrive")
}

/// A tap that passes everything through and records what it saw.
fn recording_tap() -> (RelayTap, Arc<Mutex<Vec<Bytes>>>) {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let log = seen.clone();
    let tap: RelayTap = Arc::new(move |from, _to, inner: &Bytes| {
        log.lock().push(inner.clone());
        vec![(*from, inner.clone())]
    });
    (tap, seen)
}

#[tokio::test]
async fn relayed_session_carries_data_both_ways() {
    let (relay, relay_addr, _) = relay(RelayLimits::default()).await;
    let (a, a_key) = client(lo().punching(false), relay_addr).await;
    let (mut b, b_key) = client(lo().punching(false), relay_addr).await;
    let mut b_events = b.events();

    let to_b = a.connect_via(relay_addr, b_key).await.unwrap();
    assert_eq!(to_b, relayed(relay_addr, b_key));
    assert_eq!(a.peer_path(to_b), Some(Path::Relayed(relay_addr)));
    let connected = wait_for(&mut b_events, Duration::from_secs(1), |e| {
        matches!(e, PeerEvent::Connected { .. })
    })
    .await;
    assert_eq!(
        connected,
        PeerEvent::Connected {
            addr: relayed(relay_addr, a_key),
            key: Some(a_key)
        }
    );

    a.send(b"hello".to_vec(), to_b).await.unwrap();
    let big: Vec<u8> = (0..20_000u32).map(|i| (i % 251) as u8).collect();
    a.send(big.clone(), to_b).await.unwrap();
    let got = drain(&mut b, Duration::from_millis(500)).await;
    assert_eq!(got.len(), 2, "lost relayed messages");
    assert_eq!(got[0].msg, b"hello");
    assert_eq!(got[1].msg, big, "fragmented message corrupted");
    assert_eq!(got[0].from, relayed(relay_addr, a_key));
    assert_eq!(b.peer_remote_static_key(got[0].from), Some(a_key));

    let mut a = a;
    b.send(b"back".to_vec(), got[0].from).await.unwrap();
    let reply = timeout(Duration::from_secs(1), a.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!((reply.msg, reply.from), (b"back".to_vec(), to_b));
    assert!(relay.engine_stats().relay_forwarded_packets > 10);
}

#[tokio::test]
async fn relay_only_ever_sees_ciphertext() {
    let (relay, relay_addr, _) = relay(RelayLimits::default()).await;
    let (tap, seen) = recording_tap();
    relay.set_relay_tap(Some(tap));
    let (a, _) = client(lo().punching(false), relay_addr).await;
    let (mut b, b_key) = client(lo().punching(false), relay_addr).await;
    let to_b = a.connect_via(relay_addr, b_key).await.unwrap();

    const MARKER: &[u8] = b"plaintext-marker-7f3a";
    a.send(MARKER.to_vec(), to_b).await.unwrap();
    a.send_unreliable(MARKER.to_vec(), to_b).await.unwrap();
    let got = drain(&mut b, Duration::from_millis(400)).await;
    assert_eq!(got.len(), 2);
    assert!(got.iter().all(|p| p.msg == MARKER));

    let seen = seen.lock();
    assert!(seen.len() > 5, "tap saw too little: {}", seen.len());
    assert!(
        !seen
            .iter()
            .any(|inner| inner.windows(MARKER.len()).any(|w| w == MARKER)),
        "relay forwarded plaintext"
    );
}

#[tokio::test]
async fn relay_cannot_attribute_data_to_another_key() {
    let (relay, relay_addr, _) = relay(RelayLimits::default()).await;
    let (a, a_key) = client(lo().punching(false), relay_addr).await;
    let (mut b, b_key) = client(lo().punching(false), relay_addr).await;
    let (_c, c_key) = client(lo().punching(false), relay_addr).await;
    let to_b = a.connect_via(relay_addr, b_key).await.unwrap();
    a.send(b"genuine".to_vec(), to_b).await.unwrap();
    assert_eq!(drain(&mut b, Duration::from_millis(300)).await.len(), 1);

    // From now on the relay claims A's frames come from C.
    let forge: RelayTap = Arc::new(move |from, _to, inner: &Bytes| {
        let claimed = if *from == a_key { c_key } else { *from };
        vec![(claimed, inner.clone())]
    });
    relay.set_relay_tap(Some(forge));
    for i in 0..5u8 {
        a.send(vec![i], to_b).await.unwrap();
        a.send_unreliable(vec![i], to_b).await.unwrap();
    }
    let got = drain(&mut b, Duration::from_millis(400)).await;
    assert!(got.is_empty(), "accepted forged frames: {got:?}");
    assert!(b.engine_stats().dropped_forged >= 10);
    assert!(b.peer_stats(relayed(relay_addr, c_key)).is_none());

    // A handshake the relay attributes to C never yields a session with C.
    let (d, _) = client(lo().handshake_timeout(Duration::from_secs(1)), relay_addr).await;
    let forge_all: RelayTap = Arc::new(move |_from, to, inner: &Bytes| {
        let claimed = if *to == b_key { c_key } else { *to };
        vec![(claimed, inner.clone())]
    });
    relay.set_relay_tap(Some(forge_all));
    assert!(d.connect_via(relay_addr, b_key).await.is_err());
    assert!(b.peer_stats(relayed(relay_addr, c_key)).is_none());
}

#[tokio::test]
async fn replayed_relayed_frames_are_delivered_once() {
    let (relay, relay_addr, _) = relay(RelayLimits::default()).await;
    let (a, _) = client(lo().punching(false), relay_addr).await;
    let (mut b, b_key) = client(lo().punching(false), relay_addr).await;
    let to_b = a.connect_via(relay_addr, b_key).await.unwrap();

    let replays = Arc::new(AtomicUsize::new(0));
    let count = replays.clone();
    let duplicate: RelayTap = Arc::new(move |from, _to, inner: &Bytes| {
        count.fetch_add(1, Ordering::Relaxed);
        vec![(*from, inner.clone()), (*from, inner.clone())]
    });
    relay.set_relay_tap(Some(duplicate));
    for i in 0..5u8 {
        a.send_unreliable(vec![i], to_b).await.unwrap();
        a.send(vec![100 + i], to_b).await.unwrap();
    }
    let got = drain(&mut b, Duration::from_millis(400)).await;
    assert!(replays.load(Ordering::Relaxed) >= 10);
    let mut msgs: Vec<u8> = got.iter().map(|p| p.msg[0]).collect();
    msgs.sort_unstable();
    assert_eq!(msgs, vec![0, 1, 2, 3, 4, 100, 101, 102, 103, 104]);
}

#[tokio::test]
async fn offline_and_denied_targets_fail_fast_and_alike() {
    let (relay, relay_addr, _) = relay(RelayLimits::default()).await;
    let (a, a_key) = client(lo(), relay_addr).await;
    let (_b, b_key) = client(lo(), relay_addr).await;
    relay.set_relay_policy(Some(Arc::new(move |from: &[u8; 32], to: &[u8; 32]| {
        !(*from == a_key && *to == b_key)
    })));

    let offline = Keypair::generate().public;
    for (target, why) in [(b_key, "denied"), (offline, "offline")] {
        let started = Instant::now();
        let result = a.connect_via(relay_addr, target).await;
        assert!(
            matches!(result, Err(Error::Unreachable { key }) if key == target),
            "{why}: {result:?}"
        );
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "{why}: too slow"
        );
    }
    let stats = relay.engine_stats();
    assert!(stats.relay_unreachable >= 2);
    assert!(stats.relay_denied >= 1);

    // A node that is not a relay answers the same way.
    let plain: Socket = lo()
        .port(0)
        .security(Keypair::generate())
        .listen()
        .await
        .unwrap();
    let plain_addr = plain.local_addr().unwrap();
    a.connect(plain_addr).await.unwrap();
    let result = a.connect_via(plain_addr, b_key).await;
    assert!(
        matches!(result, Err(Error::Unreachable { .. })),
        "{result:?}"
    );
}

#[tokio::test]
async fn relay_limits_drop_and_count() {
    let limits = RelayLimits::default()
        .packet_rate(30.0, 30.0)
        .max_inner(600);
    let (relay, relay_addr, _) = relay(limits).await;
    let (a, _) = client(lo().punching(false), relay_addr).await;
    let (mut b, b_key) = client(lo().punching(false), relay_addr).await;
    let to_b = a.connect_via(relay_addr, b_key).await.unwrap();

    a.send_unreliable(vec![7; 1_000], to_b).await.unwrap();
    assert!(drain(&mut b, Duration::from_millis(300)).await.is_empty());
    assert!(relay.engine_stats().relay_dropped_oversize >= 1);

    for i in 0..200u8 {
        a.send_unreliable(vec![i], to_b).await.unwrap();
    }
    let got = drain(&mut b, Duration::from_millis(300)).await;
    assert!(!got.is_empty() && got.len() < 100, "got {}", got.len());
    assert!(relay.engine_stats().relay_dropped_rate_limited >= 100);
}

#[tokio::test]
async fn punching_moves_to_direct_and_falls_back_to_the_relay() {
    let (_relay, relay_addr, _) = relay(RelayLimits::default()).await;
    let fast = || lo().keepalive_interval(Duration::from_millis(200));
    let (mut a, a_key) = client(fast(), relay_addr).await;
    let (mut b, b_key) = client(fast(), relay_addr).await;
    let b_addr = b.local_addr().unwrap();
    let mut a_events = a.events();
    let mut b_events = b.events();

    let to_b = a.connect_via(relay_addr, b_key).await.unwrap();
    let to_a = relayed(relay_addr, a_key);
    // Both applications approve the other side; only then is anything punched.
    a.punch(to_b).unwrap();
    b.punch(to_a).unwrap();
    let punched = |addr: PeerAddr| move |e: &PeerEvent| matches!(e, PeerEvent::PathChanged { addr: a, path: Path::Direct(_) } if *a == addr);
    wait_for(&mut a_events, Duration::from_secs(2), punched(to_b)).await;
    wait_for(&mut b_events, Duration::from_secs(2), punched(to_a)).await;
    assert_eq!(a.peer_path(to_b), Some(Path::Direct(b_addr)));

    a.send(b"direct".to_vec(), to_b).await.unwrap();
    let got = drain(&mut b, Duration::from_millis(300)).await;
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].from, to_a, "the handle changed with the path");

    // Break the direct path; both sides fall back to the relay and keep the session.
    a.debug_block_addr(b_addr, true);
    let fell_back = |addr: PeerAddr| {
        move |e: &PeerEvent| {
            assert!(
                !matches!(e, PeerEvent::Reset { addr: a, .. } | PeerEvent::Disconnected { addr: a, .. } if *a == addr),
                "session lost: {e:?}"
            );
            *e == PeerEvent::PathChanged {
                addr,
                path: Path::Relayed(relay_addr),
            }
        }
    };
    wait_for(&mut a_events, Duration::from_secs(2), fell_back(to_b)).await;
    wait_for(&mut b_events, Duration::from_secs(2), fell_back(to_a)).await;

    a.send(b"via relay again".to_vec(), to_b).await.unwrap();
    let got = drain(&mut b, Duration::from_millis(300)).await;
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].msg, b"via relay again");
    b.send(b"and back".to_vec(), to_a).await.unwrap();
    let reply = timeout(Duration::from_secs(1), a.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!((reply.msg, reply.from), (b"and back".to_vec(), to_b));
    tokio::time::sleep(Duration::from_millis(800)).await;
    assert!(
        a.peer_stats(to_b).is_some(),
        "session timed out on the relay"
    );
    while let Some(event) = a_events.try_recv() {
        fell_back(to_b)(&event);
    }
}

#[tokio::test]
async fn pinned_keys_apply_to_relayed_peers() {
    let (_relay, relay_addr, relay_key) = relay(RelayLimits::default()).await;
    let (_b, b_key) = client(lo(), relay_addr).await;

    let wrong = Keypair::generate().public;
    let (a, _) = client(
        lo().pin_remote_key(relay_key).pin_remote_key(wrong),
        relay_addr,
    )
    .await;
    let result = a.connect_via(relay_addr, b_key).await;
    assert!(matches!(result, Err(Error::KeyMismatch)), "{result:?}");

    let (a, _) = client(
        lo().pin_remote_key(relay_key).pin_remote_key(b_key),
        relay_addr,
    )
    .await;
    a.connect_via(relay_addr, b_key).await.unwrap();

    // The responder's pins count too: B only accepts the relay and someone else.
    let (_c, c_key) = client(
        lo().pin_remote_key(relay_key).pin_remote_key(wrong),
        relay_addr,
    )
    .await;
    let (a, _) = client(lo().handshake_timeout(Duration::from_secs(1)), relay_addr).await;
    let result = a.connect_via(relay_addr, c_key).await;
    assert!(
        matches!(result, Err(Error::HandshakeTimeout { .. })),
        "{result:?}"
    );
}

#[tokio::test]
async fn relays_must_be_accepted_to_open_sessions_toward_us() {
    let (_relay, relay_addr, _) = relay(RelayLimits::default()).await;
    let (a, _) = client(
        lo().handshake_timeout(Duration::from_millis(600)),
        relay_addr,
    )
    .await;
    let (b, b_key) = client_of(lo(), relay_addr).await;
    let result = a.connect_via(relay_addr, b_key).await;
    assert!(
        matches!(result, Err(Error::HandshakeTimeout { .. })),
        "{result:?}"
    );
    assert!(b.engine_stats().dropped_relay_unaccepted >= 1);

    // Accepting the relay later lets the next attempt through.
    b.accept_relayed_from(relay_addr);
    a.connect_via(relay_addr, b_key).await.unwrap();
}

#[tokio::test]
async fn relayed_sessions_respect_the_peer_cap() {
    let (_relay, relay_addr, _) = relay(RelayLimits::default()).await;
    let (b, b_key) = client(lo().max_peers(4), relay_addr).await;
    let mut clients = vec![];
    for _ in 0..4 {
        let (a, a_key) = client(lo(), relay_addr).await;
        a.connect_via(relay_addr, b_key).await.unwrap();
        clients.push((a, a_key));
    }
    tokio::time::sleep(Duration::from_millis(100)).await;
    // One relay may fill at most half of B's peer table; the relay session itself stays.
    assert!(
        b.peer_stats(relay_addr).is_some(),
        "the relay session was evicted"
    );
    let held = clients
        .iter()
        .filter(|(_, key)| b.peer_stats(relayed(relay_addr, *key)).is_some())
        .count();
    assert_eq!(held, 2, "relayed sessions held");
    let newest = clients.last().unwrap().1;
    assert!(
        b.peer_stats(relayed(relay_addr, newest)).is_some(),
        "evicted the newcomer"
    );
}

#[tokio::test]
async fn relayed_handshake_floods_do_not_starve_direct_handshakes() {
    let (relay, relay_addr, _) = relay(RelayLimits::default()).await;
    let (a, _) = client(
        lo().handshake_timeout(Duration::from_millis(500)),
        relay_addr,
    )
    .await;
    let (b, b_key) = client(lo().max_peers(8), relay_addr).await;
    // The relay turns every msg1 into hundreds of msg1s from made-up keys.
    let flood: RelayTap = Arc::new(move |from, _to, inner: &Bytes| {
        let is_msg1 =
            inner.len() >= 3 && inner[inner.len() - 1] == 0x09 && inner[inner.len() - 3] == 1;
        if !is_msg1 {
            return vec![(*from, inner.clone())];
        }
        (0..300u16)
            .map(|i| {
                let mut fake = [0u8; 32];
                fake[..2].copy_from_slice(&i.to_be_bytes());
                (fake, inner.clone())
            })
            .collect()
    });
    relay.set_relay_tap(Some(flood));
    let _ = a.connect_via(relay_addr, b_key).await;
    assert!(b.engine_stats().dropped_rate_limited >= 200);

    // A direct handshake to B still goes through.
    let b_addr = b.local_addr().unwrap();
    let d: Socket = lo()
        .port(0)
        .security(Keypair::generate())
        .listen()
        .await
        .unwrap();
    timeout(Duration::from_secs(2), d.connect(b_addr))
        .await
        .expect("direct handshake starved")
        .unwrap();
}

#[tokio::test]
async fn nothing_is_punched_without_approval_and_without_a_policy_nothing_is_relayed() {
    let (relay, relay_addr, _) = relay(RelayLimits::default()).await;
    let fast = || lo().keepalive_interval(Duration::from_millis(200));
    let (a, _) = client(fast(), relay_addr).await;
    let (_b, b_key) = client(fast(), relay_addr).await;
    let to_b = a.connect_via(relay_addr, b_key).await.unwrap();
    tokio::time::sleep(Duration::from_millis(800)).await;
    assert_eq!(a.peer_path(to_b), Some(Path::Relayed(relay_addr)));
    assert_eq!(relay.engine_stats().relay_introductions, 0);

    // A relay without a policy relays nothing — not even to a connected client.
    relay.set_relay_policy(None);
    let (c, _) = client(lo(), relay_addr).await;
    let result = c.connect_via(relay_addr, b_key).await;
    assert!(
        matches!(result, Err(Error::Unreachable { .. })),
        "{result:?}"
    );
}

#[tokio::test]
async fn a_spoofed_source_cannot_move_a_relayed_session() {
    let (relay, relay_addr, _) = relay(RelayLimits::default()).await;
    let (a, _) = client(lo(), relay_addr).await;
    let (mut b, b_key) = client(lo(), relay_addr).await;
    let to_b = a.connect_via(relay_addr, b_key).await.unwrap();

    // The relay holds back one authenticated A→B frame...
    let held: Arc<Mutex<Option<Bytes>>> = Arc::default();
    let stash = held.clone();
    relay.set_relay_tap(Some(Arc::new(move |from, _to, inner: &Bytes| {
        let mut slot = stash.lock();
        if slot.is_none() && inner.last() == Some(&0x0A) {
            *slot = Some(inner.clone());
            return vec![];
        }
        vec![(*from, inner.clone())]
    })));
    a.send_unreliable(b"held back".to_vec(), to_b)
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    let frame = held.lock().take().expect("nothing held back");
    relay.set_relay_tap(None);

    // ...and delivers it to B straight from an address of its choosing.
    let spoofer = tokio::net::UdpSocket::bind((common::LO, 0)).await.unwrap();
    spoofer
        .send_to(&frame, b.local_addr().unwrap())
        .await
        .unwrap();
    let mut buf = [0u8; 2048];
    let challenge = timeout(Duration::from_millis(500), spoofer.recv_from(&mut buf)).await;
    assert!(challenge.is_ok(), "B did not challenge the new address");
    tokio::time::sleep(Duration::from_millis(200)).await;
    let a_handle = drain(&mut b, Duration::from_millis(200))
        .await
        .first()
        .map(|p| p.from);
    let a_handle = a_handle.expect("the held-back frame itself is still authentic");
    assert_eq!(
        b.peer_path(a_handle),
        Some(Path::Relayed(relay_addr)),
        "path moved without validation"
    );
}
