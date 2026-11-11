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
    net::IpAddr,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use bytes::Bytes;
use parking_lot::{Mutex, RwLock};

use crate::{PeerAddr, engine::EngineInner, frame::Frame, peer::PeerState};

pub(crate) use crate::rate::network_of;

/// How long an introduction request waits for the other side's matching request.
const INTRO_WINDOW: Duration = Duration::from_secs(10);
/// Rate buckets are forgotten after this long without traffic.
const CLIENT_IDLE: Duration = Duration::from_mins(1);
/// Pending introduction requests one client may have at a time; a new one evicts its own
/// oldest.
const MAX_INTROS_PER_CLIENT: usize = 16;
/// Pending introduction requests one source network may have; a new one evicts that
/// network's oldest.
const MAX_INTROS_PER_NETWORK: usize = 64;
/// Pending introduction requests one IPv6 /48 (or IPv4 address) may have; a new one
/// evicts that prefix's oldest.
const MAX_INTROS_PER_PREFIX: usize = 256;
/// Pending introduction requests in total; when full, a new request makes room in the
/// heaviest prefix (see [`crate::rate::heaviest_prefixes`]).
const MAX_PENDING_INTROS: usize = 4_096;

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
    /// Secure sessions from one source network (IPv4 address or IPv6 /64); a new one
    /// evicts that network's least recently seen session.
    pub max_sessions_per_ip: usize,
    /// Secure sessions from one IPv6 /48; a new one evicts that prefix's least recently
    /// seen session.  (IPv4 is accounted per address only.)
    pub max_sessions_per_prefix: usize,
}

impl Default for RelayLimits {
    /// Per key 2 000 frames/s (burst 400) and 4 MB/s (burst 1 MB); per network 4 000
    /// frames/s (burst 800) and 8 MB/s (burst 2 MB); in total 50 000 frames/s (burst
    /// 10 000) and 50 MB/s (burst 10 MB); 1 500 B inner frames; 64 sessions per network,
    /// 256 per IPv6 /48.
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
            max_sessions_per_ip: 64,
            max_sessions_per_prefix: 256,
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

    /// Secure sessions accepted from one source network and from one IPv6 /48.
    #[must_use]
    pub fn max_sessions_per_ip(mut self, per_network: usize, per_prefix: usize) -> Self {
        self.max_sessions_per_ip = per_network;
        self.max_sessions_per_prefix = per_prefix;
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
    pub sessions_evicted: AtomicU64,
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

struct IntroRequest {
    asked: Instant,
    network: IpAddr,
    /// IPv6 /48 (or IPv4 address) of the asking client.
    prefix: IpAddr,
}

/// State of a socket built with [`Zudp::relay_node`](crate::Zudp::relay_node).
pub(crate) struct RelayNode {
    limits: RelayLimits,
    policy: RwLock<Option<Arc<dyn RelayPolicy>>>,
    tap: RwLock<Option<RelayTap>>,
    budgets: Mutex<Budgets>,
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

    /// Session caps: per source network, per IPv6 /48.
    pub fn session_caps(&self) -> (usize, usize) {
        (
            self.limits.max_sessions_per_ip,
            self.limits.max_sessions_per_prefix,
        )
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
    /// `from` (both requests are consumed).  Unmatched requests are bounded per client and
    /// per network, each overflow evicting that scope's own oldest request, and in total,
    /// where a new request is refused rather than pushing out someone else's.
    fn match_intro(&self, from: [u8; 32], to: [u8; 32], network: IpAddr) -> bool {
        let mut intros = self.intros.lock();
        if intros
            .remove(&(to, from))
            .is_some_and(|i| i.asked.elapsed() < INTRO_WINDOW)
        {
            return true;
        }
        if let Some(pending) = intros.get_mut(&(from, to)) {
            // Asking again only refreshes the request; it never needs a new slot.
            pending.asked = Instant::now();
            return false;
        }
        let prefix = crate::rate::prefix_of(network);
        let asked = |i: &IntroRequest| i.asked;
        evict_lru(&mut intros, MAX_INTROS_PER_CLIENT, asked, |k, _| {
            k.0 == from
        });
        evict_lru(&mut intros, MAX_INTROS_PER_NETWORK, asked, |_, i| {
            i.network == network
        });
        evict_lru(&mut intros, MAX_INTROS_PER_PREFIX, asked, |_, i| {
            i.prefix == prefix
        });
        if intros.len() >= MAX_PENDING_INTROS {
            let heaviest =
                crate::rate::heaviest_prefixes(intros.values().map(|i| i.prefix), prefix);
            evict_lru(&mut intros, 1, asked, |_, i| heaviest.contains(&i.prefix));
        }
        intros.insert(
            (from, to),
            IntroRequest {
                asked: Instant::now(),
                network,
                prefix,
            },
        );
        false
    }

    /// The session of the client with `key` ended: release its introduction requests.
    pub fn forget_client(&self, key: &[u8; 32]) {
        self.intros.lock().retain(|(a, b), _| a != key && b != key);
    }

    /// Count one session evicted to keep a source within its session caps.
    pub fn session_evicted(&self) {
        self.counters
            .sessions_evicted
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Forget stale introduction requests and idle rate state.
    pub fn prune(&self) {
        self.intros
            .lock()
            .retain(|_, i| i.asked.elapsed() < INTRO_WINDOW);
        let mut b = self.budgets.lock();
        b.clients
            .retain(|_, c| c.packets.last.elapsed() < CLIENT_IDLE);
        b.networks
            .retain(|_, c| c.packets.last.elapsed() < CLIENT_IDLE);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn pending_introductions_never_push_out_other_networks() {
        let node = RelayNode::new(RelayLimits::default(), None);
        let legit: IpAddr = "198.51.100.1".parse().unwrap();
        assert!(!node.match_intro([9; 32], [1; 32], legit));
        // Many clients in one network only displace each other.
        let attacker: IpAddr = "203.0.113.1".parse().unwrap();
        for i in 0..=255u8 {
            node.match_intro([i; 32], [200; 32], attacker);
        }
        assert_eq!(
            node.intros
                .lock()
                .values()
                .filter(|i| i.network == attacker)
                .count(),
            MAX_INTROS_PER_NETWORK
        );
        // One /48 cycling through many /64s and keys stays within its prefix cap...
        for i in 0..4_096u16 {
            let net = IpAddr::from([0x2001, 0xdb8, 1, i, 0, 0, 0, 1]);
            let mut key = [0u8; 32];
            key[..2].copy_from_slice(&i.to_be_bytes());
            key[2] = 0xee;
            node.match_intro(key, [201; 32], net);
        }
        let in_prefix = node
            .intros
            .lock()
            .values()
            .filter(|i| i.prefix == crate::rate::prefix_of("2001:db8:1::1".parse().unwrap()))
            .count();
        assert!(in_prefix <= MAX_INTROS_PER_PREFIX, "{in_prefix}");
        // ...so other requests survive, and new ones and repeats still get in.
        assert!(!node.match_intro([2; 32], [3; 32], "192.0.2.2".parse().unwrap()));
        assert!(!node.match_intro([2; 32], [3; 32], "192.0.2.2".parse().unwrap()));
        assert!(node.match_intro([3; 32], [2; 32], "192.0.2.3".parse().unwrap()));
        assert!(
            node.match_intro([1; 32], [9; 32], "192.0.2.1".parse().unwrap()),
            "another prefix's request was pushed out"
        );
    }

    #[test]
    fn a_full_intro_table_makes_room_in_the_heaviest_prefix() {
        let node = RelayNode::new(RelayLimits::default(), None);
        let legit: IpAddr = "198.51.100.1".parse().unwrap();
        assert!(!node.match_intro([9; 32], [1; 32], legit));
        // Fill the table from 16 /48s at their per-prefix cap.
        for p in 0..16u16 {
            for i in 0..MAX_INTROS_PER_PREFIX {
                let i = u16::try_from(i).unwrap();
                let net = IpAddr::from([0x2001, p, 0, i, 0, 0, 0, 1]);
                let mut key = [0u8; 32];
                key[..2].copy_from_slice(&p.to_be_bytes());
                key[2..4].copy_from_slice(&i.to_be_bytes());
                node.match_intro(key, [201; 32], net);
            }
        }
        assert!(node.intros.lock().len() <= MAX_PENDING_INTROS);
        assert!(!node.match_intro([4; 32], [5; 32], "192.0.2.4".parse().unwrap()));
        assert!(
            node.intros.lock().contains_key(&([4; 32], [5; 32])),
            "a newcomer was refused by a full table"
        );
        assert!(
            node.match_intro([1; 32], [9; 32], "192.0.2.1".parse().unwrap()),
            "a light prefix paid for the heavy ones"
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
