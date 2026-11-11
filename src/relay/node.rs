//! The relay node role: forward opaque inner frames between secure sessions.
//!
//! A relay node knows which static key sits on which of its sessions, because every client
//! completed a Noise handshake with it.  It never holds the keys of the sessions it relays,
//! so it cannot read, forge or replay what it forwards in a way the endpoints accept.  It
//! only ever sends to keys that hold a session with it — never to an address a client
//! names — so it cannot be used to reflect traffic at third parties.
//!
//! Anyone may run a public relay, and anyone may connect to one, so every resource a client
//! can make the node hold is bounded per client key, per source network (an IPv4 address or
//! an IPv6 /64) and in total — and full tables evict the least recently used entry of the
//! offender rather than refusing everybody.

use std::{
    collections::HashMap,
    fmt,
    hash::Hash,
    net::{IpAddr, Ipv6Addr},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use bytes::Bytes;
use parking_lot::{Mutex, RwLock};

use crate::{PeerAddr, engine::EngineInner, frame::Frame, peer::PeerState};

/// A relay route (pair of clients) unused for this long is forgotten.
const ROUTE_IDLE: Duration = Duration::from_mins(1);
/// How long an introduction request waits for the other side's matching request.
const INTRO_WINDOW: Duration = Duration::from_secs(10);
/// Rate buckets are forgotten after this long without traffic.
const CLIENT_IDLE: Duration = Duration::from_mins(1);
/// Pending introduction requests one client may have at a time.
const MAX_INTROS_PER_CLIENT: usize = 16;

/// Decides who may reach whom through a relay node.
///
/// Called for every relayed frame and every introduction, with the static keys of the
/// sending client and of the target.  A denied frame gets the same `Unreachable` answer as
/// one for a target that is not connected, so a client cannot tell the two apart.
///
/// Any `Fn(&[u8; 32], &[u8; 32]) -> bool` is a policy.  Without a policy a relay node
/// relays nothing: an open relay (`|_, _| true`) tells anyone who knows a client's key
/// whether that client is online, so it has to be asked for explicitly.
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
/// Rates count relayed frames and their inner bytes.  A frame must fit the budget of its
/// client key, of the client's source network (IPv4 address or IPv6 /64) and of the node
/// as a whole.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct RelayLimits {
    /// Sustained relayed frames per second per client key.
    pub packets_per_sec: f64,
    /// Frames a client key may relay in a burst.
    pub burst_packets: f64,
    /// Sustained relayed inner bytes per second per client key.
    pub bytes_per_sec: f64,
    /// Inner bytes a client key may relay in a burst.
    pub burst_bytes: f64,
    /// Sustained relayed frames per second per source network.
    pub ip_packets_per_sec: f64,
    /// Frames a source network may relay in a burst.
    pub ip_burst_packets: f64,
    /// Sustained relayed inner bytes per second per source network.
    pub ip_bytes_per_sec: f64,
    /// Inner bytes a source network may relay in a burst.
    pub ip_burst_bytes: f64,
    /// Sustained relayed frames per second for the whole node.
    pub total_packets_per_sec: f64,
    /// Frames the whole node relays in a burst.
    pub total_burst_packets: f64,
    /// Sustained relayed inner bytes per second for the whole node.
    pub total_bytes_per_sec: f64,
    /// Inner bytes the whole node relays in a burst.
    pub total_burst_bytes: f64,
    /// Largest inner frame relayed; bigger ones are dropped.
    pub max_inner: usize,
    /// Client pairs tracked at once.  A new pair beyond it evicts the least recently used.
    pub max_routes: usize,
    /// Client pairs one client key takes part in; a new one evicts that client's oldest.
    pub max_routes_per_client: usize,
    /// Client pairs opened from one source network; a new one evicts that network's oldest.
    pub max_routes_per_ip: usize,
    /// Secure sessions from one source network; a new one evicts that network's least
    /// recently seen session.
    pub max_sessions_per_ip: usize,
}

impl Default for RelayLimits {
    /// Per key 2 000 frames/s (burst 400) and 4 MB/s (burst 1 MB); per network 4 000
    /// frames/s (burst 800) and 8 MB/s (burst 2 MB); in total 50 000 frames/s (burst
    /// 10 000) and 50 MB/s (burst 10 MB); 1 500 B inner frames; 4 096 routes, 64 per key,
    /// 256 per network; 64 sessions per network.
    fn default() -> Self {
        Self {
            packets_per_sec: 2_000.0,
            burst_packets: 400.0,
            bytes_per_sec: 4_000_000.0,
            burst_bytes: 1_000_000.0,
            ip_packets_per_sec: 4_000.0,
            ip_burst_packets: 800.0,
            ip_bytes_per_sec: 8_000_000.0,
            ip_burst_bytes: 2_000_000.0,
            total_packets_per_sec: 50_000.0,
            total_burst_packets: 10_000.0,
            total_bytes_per_sec: 50_000_000.0,
            total_burst_bytes: 10_000_000.0,
            max_inner: crate::frame::RELAYED_INNER_MAX,
            max_routes: 4_096,
            max_routes_per_client: 64,
            max_routes_per_ip: 256,
            max_sessions_per_ip: 64,
        }
    }
}

impl RelayLimits {
    /// Per-client-key frame rate and burst.
    #[must_use]
    pub fn packet_rate(mut self, per_sec: f64, burst: f64) -> Self {
        self.packets_per_sec = per_sec;
        self.burst_packets = burst;
        self
    }

    /// Per-client-key inner byte rate and burst.
    #[must_use]
    pub fn byte_rate(mut self, per_sec: f64, burst: f64) -> Self {
        self.bytes_per_sec = per_sec;
        self.burst_bytes = burst;
        self
    }

    /// Per-source-network frame rate and burst.
    #[must_use]
    pub fn ip_packet_rate(mut self, per_sec: f64, burst: f64) -> Self {
        self.ip_packets_per_sec = per_sec;
        self.ip_burst_packets = burst;
        self
    }

    /// Per-source-network inner byte rate and burst.
    #[must_use]
    pub fn ip_byte_rate(mut self, per_sec: f64, burst: f64) -> Self {
        self.ip_bytes_per_sec = per_sec;
        self.ip_burst_bytes = burst;
        self
    }

    /// Whole-node frame rate and burst.
    #[must_use]
    pub fn total_packet_rate(mut self, per_sec: f64, burst: f64) -> Self {
        self.total_packets_per_sec = per_sec;
        self.total_burst_packets = burst;
        self
    }

    /// Whole-node inner byte rate and burst.
    #[must_use]
    pub fn total_byte_rate(mut self, per_sec: f64, burst: f64) -> Self {
        self.total_bytes_per_sec = per_sec;
        self.total_burst_bytes = burst;
        self
    }

    /// Largest inner frame relayed.  zudp peers never send relayed frames above 1 500 bytes
    /// (the default), whatever their MTU; a smaller value drops their full-size fragments,
    /// counted in `relay_dropped_oversize`.
    #[must_use]
    pub fn max_inner(mut self, bytes: usize) -> Self {
        self.max_inner = bytes;
        self
    }

    /// Client pairs tracked at once, in total, per client key and per source network.
    #[must_use]
    pub fn max_routes(mut self, total: usize, per_client: usize, per_ip: usize) -> Self {
        self.max_routes = total;
        self.max_routes_per_client = per_client;
        self.max_routes_per_ip = per_ip;
        self
    }

    /// Secure sessions accepted from one source network.
    #[must_use]
    pub fn max_sessions_per_ip(mut self, sessions: usize) -> Self {
        self.max_sessions_per_ip = sessions;
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
    pub routes_evicted: AtomicU64,
    pub sessions_evicted: AtomicU64,
    pub introductions: AtomicU64,
}

/// The network a source address is accounted to: the IPv4 address itself, or the /64 of
/// an IPv6 address (one subscriber usually holds a whole /64).
pub(crate) fn network_of(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(_) => ip,
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => {
                let bits = u128::from(v6) & !u128::from(u64::MAX);
                IpAddr::V6(Ipv6Addr::from(bits))
            }
        },
    }
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

/// Rate and burst of a [`Budget`]: `(packets/s, packet burst, bytes/s, byte burst)`.
type Rates = (f64, f64, f64, f64);

/// A packet bucket and a byte bucket.
#[derive(Clone, Copy)]
struct Budget {
    packets: Bucket,
    bytes: Bucket,
}

impl Budget {
    fn full((_, packet_burst, _, byte_burst): Rates, now: Instant) -> Self {
        Self {
            packets: Bucket::full(packet_burst, now),
            bytes: Bucket::full(byte_burst, now),
        }
    }

    /// The budget after spending one frame of `bytes`, or `None` when over it.
    fn spend(mut self, bytes: f64, rates: Rates, now: Instant) -> Option<Self> {
        let (pps, packet_burst, bps, byte_burst) = rates;
        (self.packets.take(1.0, pps, packet_burst, now)
            && self.bytes.take(bytes, bps, byte_burst, now))
        .then_some(self)
    }
}

#[derive(Default)]
struct Budgets {
    clients: HashMap<[u8; 32], Budget>,
    networks: HashMap<IpAddr, Budget>,
    total: Option<Budget>,
}

/// Two client static keys.
type KeyPair = ([u8; 32], [u8; 32]);

struct Route {
    used: Instant,
    /// Source network of the client that opened the route.
    network: IpAddr,
}

struct IntroRequest {
    asked: Instant,
    network: IpAddr,
}

/// State of a socket built with [`Zudp::relay_node`](crate::Zudp::relay_node).
pub(crate) struct RelayNode {
    limits: RelayLimits,
    policy: RwLock<Option<Arc<dyn RelayPolicy>>>,
    tap: RwLock<Option<RelayTap>>,
    budgets: Mutex<Budgets>,
    /// Client pairs (smaller key first) that relayed recently.
    routes: Mutex<HashMap<KeyPair, Route>>,
    /// Introduction requests `(from, to)` waiting for the matching `(to, from)`.
    intros: Mutex<HashMap<KeyPair, IntroRequest>>,
    pub counters: RelayCounters,
}

impl fmt::Debug for RelayNode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RelayNode")
            .field("limits", &self.limits)
            .finish_non_exhaustive()
    }
}

/// Remove the least recently used entry among those matching `pred`, when at least `cap`
/// of them exist.  Returns `true` when something was evicted.
fn evict_lru<K: Copy + Eq + Hash, V>(
    map: &mut HashMap<K, V>,
    cap: usize,
    used: impl Fn(&V) -> Instant,
    pred: impl Fn(&K, &V) -> bool,
) -> bool {
    if map.iter().filter(|(k, v)| pred(k, v)).count() < cap.max(1) {
        return false;
    }
    let oldest = map
        .iter()
        .filter(|(k, v)| pred(k, v))
        .min_by_key(|(_, v)| used(v))
        .map(|(k, _)| *k);
    oldest.is_some_and(|k| map.remove(&k).is_some())
}

impl RelayNode {
    pub fn new(limits: RelayLimits, policy: Option<Arc<dyn RelayPolicy>>) -> Self {
        Self {
            limits,
            policy: RwLock::new(policy),
            tap: RwLock::new(None),
            budgets: Mutex::new(Budgets::default()),
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

    pub fn max_sessions_per_ip(&self) -> usize {
        self.limits.max_sessions_per_ip
    }

    /// Default-deny: without a policy nothing is relayed.
    fn allowed(&self, from: &[u8; 32], to: &[u8; 32]) -> bool {
        from != to
            && self
                .policy
                .read()
                .as_ref()
                .is_some_and(|p| p.allow(from, to))
    }

    /// Charge one frame of `bytes` inner bytes to `client` at `network`; `false` when over
    /// the client's, the network's or the node's budget.  Nothing is spent then.
    fn charge(&self, client: [u8; 32], network: IpAddr, bytes: usize) -> bool {
        let now = Instant::now();
        let l = &self.limits;
        let per_key = (
            l.packets_per_sec,
            l.burst_packets,
            l.bytes_per_sec,
            l.burst_bytes,
        );
        let per_net = (
            l.ip_packets_per_sec,
            l.ip_burst_packets,
            l.ip_bytes_per_sec,
            l.ip_burst_bytes,
        );
        let total = (
            l.total_packets_per_sec,
            l.total_burst_packets,
            l.total_bytes_per_sec,
            l.total_burst_bytes,
        );
        // Inner frames are capped at `max_inner`, far below f64's exact-integer range.
        #[allow(clippy::cast_precision_loss)]
        let bytes = bytes as f64;
        let mut b = self.budgets.lock();
        let key_budget = *b
            .clients
            .entry(client)
            .or_insert_with(|| Budget::full(per_key, now));
        let net_budget = *b
            .networks
            .entry(network)
            .or_insert_with(|| Budget::full(per_net, now));
        let total_budget = *b.total.get_or_insert_with(|| Budget::full(total, now));
        let (Some(k), Some(n), Some(t)) = (
            key_budget.spend(bytes, per_key, now),
            net_budget.spend(bytes, per_net, now),
            total_budget.spend(bytes, total, now),
        ) else {
            return false;
        };
        b.clients.insert(client, k);
        b.networks.insert(network, n);
        b.total = Some(t);
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

    /// Record a relayed exchange `from` → `to` opened from `network`.  A new pair beyond a
    /// cap evicts the least recently used pair of the client, then of its network, then of
    /// the node — never refusing, so a flood of throwaway pairs cannot lock others out.
    fn route(&self, from: [u8; 32], to: [u8; 32], network: IpAddr) {
        let pair = if from <= to { (from, to) } else { (to, from) };
        let now = Instant::now();
        let mut routes = self.routes.lock();
        if let Some(route) = routes.get_mut(&pair) {
            route.used = now;
            return;
        }
        let l = &self.limits;
        let used = |r: &Route| r.used;
        let mut evicted = evict_lru(&mut routes, l.max_routes_per_client, used, |p, _| {
            p.0 == from || p.1 == from
        });
        evicted |= evict_lru(&mut routes, l.max_routes_per_ip, used, |_, r| {
            r.network == network
        });
        evicted |= evict_lru(&mut routes, l.max_routes, used, |_, _| true);
        if evicted {
            self.counters.routes_evicted.fetch_add(1, Ordering::Relaxed);
        }
        routes.insert(pair, Route { used: now, network });
    }

    /// Relay `inner` from `client` to the client with key `to`.
    pub async fn forward(
        &self,
        engine: &Arc<EngineInner>,
        client: &Arc<PeerState>,
        to: [u8; 32],
        inner: Bytes,
    ) {
        let (Some(from), PeerAddr::Direct(client_addr)) =
            (client.remote_static_key(), client.addr())
        else {
            return;
        };
        let network = network_of(client_addr.ip());
        let c = &self.counters;
        if inner.len() > self.limits.max_inner {
            tracing::debug!(target: "zudp::relay", len = inner.len(), max = self.limits.max_inner, "oversized relay frame dropped");
            c.dropped_oversize.fetch_add(1, Ordering::Relaxed);
            return;
        }
        if !self.charge(from, network, inner.len()) {
            tracing::trace!(target: "zudp::relay", client = %client_addr, "relay rate limit");
            c.dropped_rate_limited.fetch_add(1, Ordering::Relaxed);
            return;
        }
        let allowed = self.allowed(&from, &to);
        let Some(target) = Self::session(engine, &to).filter(|_| allowed) else {
            // Offline and denied look the same to the client.
            if !allowed {
                c.denied.fetch_add(1, Ordering::Relaxed);
            }
            c.unreachable.fetch_add(1, Ordering::Relaxed);
            if let Some(wire) =
                crate::engine::seal(engine, client, &Frame::Unreachable { to }.encode())
            {
                engine.send_to_peer(client, wire, "unreachable").await;
            }
            return;
        };
        self.route(from, to, network);
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
        let (Some(from), PeerAddr::Direct(client_addr)) =
            (client.remote_static_key(), client.addr())
        else {
            return;
        };
        let network = network_of(client_addr.ip());
        if !self.charge(from, network, 0) || !self.allowed(&from, &to) {
            return;
        }
        let Some(target) = Self::session(engine, &to) else {
            return;
        };
        let PeerAddr::Direct(target_addr) = target.addr() else {
            return;
        };
        if !self.match_intro(from, to, network) {
            return;
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

    /// Record that `from` asked to be introduced to `to`; `true` when `to` already asked for
    /// `from` (both requests are consumed).  Unmatched requests are bounded per client, per
    /// network and in total, each overflow evicting that scope's oldest request.
    fn match_intro(&self, from: [u8; 32], to: [u8; 32], network: IpAddr) -> bool {
        let mut intros = self.intros.lock();
        if intros
            .remove(&(to, from))
            .is_some_and(|i| i.asked.elapsed() < INTRO_WINDOW)
        {
            return true;
        }
        let asked = |i: &IntroRequest| i.asked;
        evict_lru(&mut intros, MAX_INTROS_PER_CLIENT, asked, |k, _| {
            k.0 == from
        });
        evict_lru(&mut intros, self.limits.max_routes_per_ip, asked, |_, i| {
            i.network == network
        });
        evict_lru(&mut intros, self.limits.max_routes, asked, |_, _| true);
        intros.insert(
            (from, to),
            IntroRequest {
                asked: Instant::now(),
                network,
            },
        );
        false
    }

    /// The session of the client with `key` ended: release its routes and introductions.
    pub fn forget_client(&self, key: &[u8; 32]) {
        self.routes.lock().retain(|(a, b), _| a != key && b != key);
        self.intros.lock().retain(|(a, b), _| a != key && b != key);
    }

    /// Count one session evicted to keep a network under `max_sessions_per_ip`.
    pub fn session_evicted(&self) {
        self.counters
            .sessions_evicted
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Forget idle routes, stale introduction requests and idle rate state.
    pub fn prune(&self) {
        self.routes
            .lock()
            .retain(|_, r| r.used.elapsed() < ROUTE_IDLE);
        self.intros
            .lock()
            .retain(|_, i| i.asked.elapsed() < INTRO_WINDOW);
        let mut b = self.budgets.lock();
        b.clients
            .retain(|_, c| c.packets.last.elapsed() < CLIENT_IDLE);
        b.networks
            .retain(|_, c| c.packets.last.elapsed() < CLIENT_IDLE);
    }

    #[cfg(test)]
    fn routes(&self) -> usize {
        self.routes.lock().len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv6_networks_are_per_64() {
        let a: IpAddr = "2001:db8:1:2:aaaa::1".parse().unwrap();
        let b: IpAddr = "2001:db8:1:2:bbbb::2".parse().unwrap();
        let c: IpAddr = "2001:db8:1:3::1".parse().unwrap();
        assert_eq!(network_of(a), network_of(b));
        assert_ne!(network_of(a), network_of(c));
        let mapped: IpAddr = "::ffff:198.51.100.7".parse().unwrap();
        assert_eq!(
            network_of(mapped),
            "198.51.100.7".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn route_floods_only_evict_their_own() {
        let node = RelayNode::new(RelayLimits::default().max_routes(8, 4, 6), None);
        let legit: IpAddr = "198.51.100.1".parse().unwrap();
        let attacker: IpAddr = "203.0.113.1".parse().unwrap();
        node.route([1; 32], [2; 32], legit);
        for i in 0..100u8 {
            node.route([200; 32], [i; 32], attacker);
            node.route([100 + (i % 50); 32], [255; 32], attacker);
        }
        let routes = node.routes.lock();
        assert!(
            routes.contains_key(&([1; 32], [2; 32])),
            "legit route evicted"
        );
        assert!(routes.len() <= 8);
        assert!(routes.values().filter(|r| r.network == attacker).count() <= 6);
        assert!(
            routes
                .keys()
                .filter(|(a, b)| *a == [200; 32] || *b == [200; 32])
                .count()
                <= 4
        );
        drop(routes);
        node.forget_client(&[1; 32]);
        assert!(node.routes() <= 6, "routes of a gone client were kept");
    }

    #[test]
    fn pending_introductions_are_capped_per_client() {
        let node = RelayNode::new(RelayLimits::default(), None);
        let net: IpAddr = "198.51.100.1".parse().unwrap();
        let other: IpAddr = "203.0.113.1".parse().unwrap();
        assert!(
            !node.match_intro([9; 32], [1; 32], other),
            "legit request waits"
        );
        for i in 0..200u8 {
            assert!(!node.match_intro([7; 32], [i; 32], net));
        }
        let intros = node.intros.lock();
        assert_eq!(
            intros.keys().filter(|k| k.0 == [7; 32]).count(),
            MAX_INTROS_PER_CLIENT
        );
        drop(intros);
        assert!(
            node.match_intro([1; 32], [9; 32], other),
            "a flood by one client displaced another client's request"
        );
    }

    #[test]
    fn budgets_are_per_key_per_network_and_total() {
        let limits = RelayLimits::default()
            .packet_rate(0.0, 5.0)
            .ip_packet_rate(0.0, 8.0)
            .total_packet_rate(0.0, 12.0);
        let node = RelayNode::new(limits, None);
        let net_a: IpAddr = "198.51.100.1".parse().unwrap();
        let net_b: IpAddr = "203.0.113.1".parse().unwrap();
        let ok = |key: u8, net| (0..20).filter(|_| node.charge([key; 32], net, 10)).count();
        assert_eq!(ok(1, net_a), 5, "per-key budget");
        assert_eq!(ok(2, net_a), 3, "fresh key, same network: network budget");
        assert_eq!(
            ok(3, net_b),
            4,
            "other network: only the total budget is left"
        );
    }
}
