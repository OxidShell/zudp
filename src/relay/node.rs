//! The relay node role: forward opaque inner frames between secure sessions.
//!
//! A relay node knows which static key sits on which of its sessions, because every client
//! completed a Noise handshake with it.  It never holds the keys of the sessions it relays,
//! so it cannot read, forge or replay what it forwards in a way the endpoints accept.  It
//! only ever sends to keys that hold a session with it — never to an address a client
//! names — so it cannot be used to reflect traffic at third parties.

use std::{
    collections::HashMap,
    fmt,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use bytes::Bytes;
use parking_lot::{Mutex, RwLock};

use crate::{PeerAddr, engine::EngineInner, frame::Frame, peer::PeerState};

/// A relay route (pair of clients) unused for this long no longer counts toward the cap.
const ROUTE_IDLE: Duration = Duration::from_mins(1);
/// How long an introduction request waits for the other side's matching request.
const INTRO_WINDOW: Duration = Duration::from_secs(10);
/// A client's rate buckets are forgotten after this long without traffic.
const CLIENT_IDLE: Duration = Duration::from_mins(1);

/// Decides who may reach whom through a relay node.
///
/// Called for every relayed frame and every introduction, with the static keys of the
/// sending client and of the target.  A denied frame gets the same `Unreachable` answer as
/// one for a target that is not connected, so a client cannot tell the two apart.
///
/// Any `Fn(&[u8; 32], &[u8; 32]) -> bool` is a policy.
pub trait RelayPolicy: Send + Sync {
    /// `true` when the client with key `from` may send to the client with key `to`.
    fn allow(&self, from: &[u8; 32], to: &[u8; 32]) -> bool;
}

impl<F> RelayPolicy for F
where
    F: Fn(&[u8; 32], &[u8; 32]) -> bool + Send + Sync,
{
    fn allow(&self, from: &[u8; 32], to: &[u8; 32]) -> bool {
        self(from, to)
    }
}

/// Built-in abuse limits of a relay node; see [`Zudp::relay_node`](crate::Zudp::relay_node).
///
/// Rates are per client static key and count relayed frames and their inner bytes.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct RelayLimits {
    /// Sustained relayed frames per second per client.
    pub packets_per_sec: f64,
    /// Frames a client may relay in a burst.
    pub burst_packets: f64,
    /// Sustained relayed inner bytes per second per client.
    pub bytes_per_sec: f64,
    /// Inner bytes a client may relay in a burst.
    pub burst_bytes: f64,
    /// Largest inner frame relayed; bigger ones are dropped.
    pub max_inner: usize,
    /// Most client pairs relaying at the same time; a new pair beyond it is `Unreachable`.
    pub max_routes: usize,
}

impl Default for RelayLimits {
    /// 2 000 frames/s (burst 400), 4 MB/s (burst 1 MB), 1 500 B inner frames, 4 096 routes.
    fn default() -> Self {
        Self {
            packets_per_sec: 2_000.0,
            burst_packets: 400.0,
            bytes_per_sec: 4_000_000.0,
            burst_bytes: 1_000_000.0,
            max_inner: 1_500,
            max_routes: 4_096,
        }
    }
}

impl RelayLimits {
    /// Per-client frame rate and burst.
    #[must_use]
    pub fn packet_rate(mut self, per_sec: f64, burst: f64) -> Self {
        self.packets_per_sec = per_sec;
        self.burst_packets = burst;
        self
    }

    /// Per-client inner byte rate and burst.
    #[must_use]
    pub fn byte_rate(mut self, per_sec: f64, burst: f64) -> Self {
        self.bytes_per_sec = per_sec;
        self.burst_bytes = burst;
        self
    }

    /// Largest inner frame relayed.  Relayed frames from zudp peers with the default MTU
    /// stay below 1 400 bytes.
    #[must_use]
    pub fn max_inner(mut self, bytes: usize) -> Self {
        self.max_inner = bytes;
        self
    }

    /// Most client pairs relaying at once.
    #[must_use]
    pub fn max_routes(mut self, routes: usize) -> Self {
        self.max_routes = routes;
        self
    }
}

/// Test hook: sees every frame a relay node is about to forward — the claimed sender, the
/// target and the opaque inner bytes — and returns what to deliver instead, as
/// `(claimed sender, inner bytes)` pairs.  Returning the input unchanged is a no-op.
///
/// It models what a malicious relay can do (drop, duplicate, re-attribute, alter), so
/// tests can show the endpoints reject it.  Not part of the stable API.
#[doc(hidden)]
pub type RelayTap =
    Arc<dyn Fn(&[u8; 32], &[u8; 32], &Bytes) -> Vec<([u8; 32], Bytes)> + Send + Sync>;

/// Relay counters, all monotonic.
#[derive(Default)]
pub(crate) struct RelayCounters {
    pub forwarded_packets: AtomicU64,
    pub forwarded_bytes: AtomicU64,
    pub dropped_rate_limited: AtomicU64,
    pub dropped_oversize: AtomicU64,
    pub unreachable: AtomicU64,
    pub denied: AtomicU64,
    pub routes_full: AtomicU64,
    pub introductions: AtomicU64,
}

#[derive(Clone, Copy)]
struct Bucket {
    tokens: f64,
    last: Instant,
}

impl Bucket {
    fn full(burst: f64, now: Instant) -> Self {
        Self {
            tokens: burst,
            last: now,
        }
    }

    fn take(&mut self, amount: f64, rate: f64, burst: f64, now: Instant) -> bool {
        let elapsed = now.duration_since(self.last).as_secs_f64();
        self.tokens = (self.tokens + rate * elapsed).min(burst);
        self.last = now;
        if self.tokens >= amount {
            self.tokens -= amount;
            true
        } else {
            false
        }
    }
}

/// Two client static keys.
type KeyPair = ([u8; 32], [u8; 32]);

/// Rate state of one client.
struct Client {
    packets: Bucket,
    bytes: Bucket,
}

/// State of a socket built with [`Zudp::relay_node`](crate::Zudp::relay_node).
pub(crate) struct RelayNode {
    limits: RelayLimits,
    policy: RwLock<Option<Arc<dyn RelayPolicy>>>,
    tap: RwLock<Option<RelayTap>>,
    clients: Mutex<HashMap<[u8; 32], Client>>,
    /// Client pairs (smaller key first) that relayed recently → last use.
    routes: Mutex<HashMap<KeyPair, Instant>>,
    /// Introduction requests `(from, to)` waiting for the matching `(to, from)`.
    intros: Mutex<HashMap<KeyPair, Instant>>,
    pub counters: RelayCounters,
}

impl fmt::Debug for RelayNode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RelayNode")
            .field("limits", &self.limits)
            .finish_non_exhaustive()
    }
}

impl RelayNode {
    pub fn new(limits: RelayLimits, policy: Option<Arc<dyn RelayPolicy>>) -> Self {
        Self {
            limits,
            policy: RwLock::new(policy),
            tap: RwLock::new(None),
            clients: Mutex::new(HashMap::new()),
            routes: Mutex::new(HashMap::new()),
            intros: Mutex::new(HashMap::new()),
            counters: RelayCounters::default(),
        }
    }

    pub fn set_policy(&self, policy: Option<Arc<dyn RelayPolicy>>) {
        *self.policy.write() = policy;
    }

    pub fn set_tap(&self, tap: Option<RelayTap>) {
        *self.tap.write() = tap;
    }

    fn allowed(&self, from: &[u8; 32], to: &[u8; 32]) -> bool {
        from != to
            && self
                .policy
                .read()
                .as_ref()
                .is_none_or(|p| p.allow(from, to))
    }

    /// Charge one frame of `bytes` inner bytes to `client`; `false` when over its budget.
    fn charge(&self, client: [u8; 32], bytes: usize) -> bool {
        let now = Instant::now();
        let l = &self.limits;
        let mut clients = self.clients.lock();
        let state = clients.entry(client).or_insert_with(|| Client {
            packets: Bucket::full(l.burst_packets, now),
            bytes: Bucket::full(l.burst_bytes, now),
        });
        // Inner frames are capped at `max_inner`, far below f64's exact-integer range.
        #[allow(clippy::cast_precision_loss)]
        let bytes = bytes as f64;
        // Check both before spending either, so a frame refused for bytes costs no packet.
        let mut packets = state.packets;
        let mut volume = state.bytes;
        if !packets.take(1.0, l.packets_per_sec, l.burst_packets, now)
            || !volume.take(bytes, l.bytes_per_sec, l.burst_bytes, now)
        {
            return false;
        }
        state.packets = packets;
        state.bytes = volume;
        true
    }

    /// The live session of the client with static key `key`.
    fn session(engine: &EngineInner, key: &[u8; 32]) -> Option<Arc<PeerState>> {
        engine
            .by_key
            .get(key)
            .map(|r| r.value().clone())
            .filter(|p| p.has_channel() && engine.peers.contains_key(&p.addr()))
    }

    /// Record a relayed exchange between `a` and `b`; `false` when it would open a route
    /// beyond the cap.
    fn route(&self, a: [u8; 32], b: [u8; 32]) -> bool {
        let pair = if a <= b { (a, b) } else { (b, a) };
        let mut routes = self.routes.lock();
        if !routes.contains_key(&pair) && routes.len() >= self.limits.max_routes {
            return false;
        }
        routes.insert(pair, Instant::now());
        true
    }

    /// Relay `inner` from `client` to the client with key `to`.
    pub async fn forward(
        &self,
        engine: &Arc<EngineInner>,
        client: &Arc<PeerState>,
        to: [u8; 32],
        inner: Bytes,
    ) {
        let Some(from) = client.remote_static_key() else {
            return;
        };
        let c = &self.counters;
        if inner.len() > self.limits.max_inner {
            tracing::debug!(target: "zudp::relay", len = inner.len(), max = self.limits.max_inner, "oversized relay frame dropped");
            c.dropped_oversize.fetch_add(1, Ordering::Relaxed);
            return;
        }
        if !self.charge(from, inner.len()) {
            tracing::trace!(target: "zudp::relay", client = %client.addr(), "relay rate limit");
            c.dropped_rate_limited.fetch_add(1, Ordering::Relaxed);
            return;
        }
        let target = Self::session(engine, &to);
        let online = target.is_some();
        let allowed = self.allowed(&from, &to);
        let routed = online && allowed && self.route(from, to);
        let Some(target) = target.filter(|_| routed) else {
            // Offline, denied and over the route cap all look the same to the client.
            if !allowed {
                c.denied.fetch_add(1, Ordering::Relaxed);
            } else if online {
                c.routes_full.fetch_add(1, Ordering::Relaxed);
            }
            c.unreachable.fetch_add(1, Ordering::Relaxed);
            if let Some(wire) =
                crate::engine::seal(engine, client, &Frame::Unreachable { to }.encode())
            {
                engine.send_to_peer(client, wire, "unreachable").await;
            }
            return;
        };
        let tap = self.tap.read().clone();
        let deliveries = match tap {
            Some(tap) => tap(&from, &to, &inner),
            None => vec![(from, inner)],
        };
        for (claimed, inner) in deliveries {
            let len = inner.len() as u64;
            let frame = Frame::ViaFrom {
                from: claimed,
                inner,
            };
            let Some(wire) = crate::engine::seal(engine, &target, &frame.encode()) else {
                return;
            };
            target.mark_sent();
            engine.send_to_peer(&target, wire, "relay forward").await;
            c.forwarded_packets.fetch_add(1, Ordering::Relaxed);
            c.forwarded_bytes.fetch_add(len, Ordering::Relaxed);
        }
    }

    /// `client` asks to be introduced to the client with key `to`.  Addresses are only
    /// handed out when both sides asked for each other, so no client can look up where
    /// another one is.
    pub async fn introduce(
        &self,
        engine: &Arc<EngineInner>,
        client: &Arc<PeerState>,
        to: [u8; 32],
    ) {
        let Some(from) = client.remote_static_key() else {
            return;
        };
        if !self.charge(from, 0) || !self.allowed(&from, &to) {
            return;
        }
        let Some(target) = Self::session(engine, &to) else {
            return;
        };
        let (PeerAddr::Direct(client_addr), PeerAddr::Direct(target_addr)) =
            (client.addr(), target.addr())
        else {
            return;
        };
        {
            let mut intros = self.intros.lock();
            let matched = intros
                .remove(&(to, from))
                .is_some_and(|asked| asked.elapsed() < INTRO_WINDOW);
            if !matched {
                if intros.len() < self.limits.max_routes {
                    intros.insert((from, to), Instant::now());
                }
                return;
            }
        }
        self.counters.introductions.fetch_add(1, Ordering::Relaxed);
        tracing::debug!(target: "zudp::relay", a = %client_addr, b = %target_addr, "introducing relay clients");
        for (peer, key, addr) in [(client, to, target_addr), (&target, from, client_addr)] {
            if let Some(wire) =
                crate::engine::seal(engine, peer, &Frame::Intro { peer: key, addr }.encode())
            {
                engine.send_to_peer(peer, wire, "intro").await;
            }
        }
    }

    /// Forget idle routes, stale introduction requests and idle clients' rate state.
    pub fn prune(&self) {
        self.routes
            .lock()
            .retain(|_, used| used.elapsed() < ROUTE_IDLE);
        self.intros
            .lock()
            .retain(|_, asked| asked.elapsed() < INTRO_WINDOW);
        self.clients
            .lock()
            .retain(|_, c| c.packets.last.elapsed() < CLIENT_IDLE);
    }
}
