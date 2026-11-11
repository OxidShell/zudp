use std::{
    collections::HashMap,
    hash::Hash,
    net::{IpAddr, Ipv6Addr},
    time::Instant,
};

/// The network a source address is accounted to: the IPv4 address itself, or the /64 of
/// an IPv6 address (one subscriber usually holds a whole /64).
pub(crate) fn network_of(ip: IpAddr) -> IpAddr {
    masked(ip, 64)
}

/// The allocation a source address belongs to: the IPv4 address itself, or the /48 of an
/// IPv6 address (a site may hold up to 65 536 /64s).
///
/// IPv4 is accounted per address on purpose: a carrier-grade NAT puts many unrelated users
/// behind one address and a /24 would lump in even more, so heavy IPv4 users behind CGNAT
/// share one budget — the price of not letting one IPv4 /24 owner pose as many sources.
#[cfg(any(feature = "relay", test))]
pub(crate) fn prefix_of(ip: IpAddr) -> IpAddr {
    masked(ip, 48)
}

fn masked(ip: IpAddr, bits: u32) -> IpAddr {
    match ip {
        IpAddr::V4(_) => ip,
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(Ipv6Addr::from(u128::from(v6) & (u128::MAX << (128 - bits)))),
        },
    }
}

/// Token-bucket rate limiter per key (a source IP unless said otherwise).
///
/// Tokens refill at `max_pps` per second up to `burst`.  Each allowed packet
/// consumes one token.  A packet is dropped if fewer than one token is available.
///
/// Not `Sync` by design — owned exclusively by the engine task, zero lock overhead.
pub(crate) struct RateLimiter<K = IpAddr> {
    buckets: HashMap<K, (Instant, f64)>,
    max_pps: f64,
    burst: f64,
    /// Most keys tracked; a new key beyond it is refused until idle ones are pruned.
    max_keys: usize,
    /// Monotonic tick counter; prune runs every `PRUNE_INTERVAL_TICKS` ticks.
    ticks: u32,
}

/// How many background ticks between bucket prune passes.
///
/// Background fires every `keepalive_interval / 4` (default 1.25 s).
/// 48 ticks ≈ 60 s — matches the idle-bucket threshold.
const PRUNE_INTERVAL_TICKS: u32 = 48;

impl<K: Hash + Eq> RateLimiter<K> {
    pub(crate) fn new(max_pps: f64, burst: f64) -> Self {
        Self {
            buckets: HashMap::new(),
            max_pps,
            burst,
            max_keys: usize::MAX,
            ticks: 0,
        }
    }

    /// Track at most `max_keys` keys, for keys a remote chooses (untrusted, unbounded).
    #[cfg(any(feature = "security", test))]
    pub(crate) fn capped(mut self, max_keys: usize) -> Self {
        self.max_keys = max_keys;
        self
    }

    /// Returns `true` if the packet from `key` is allowed, `false` if throttled.
    pub(crate) fn allow(&mut self, key: K) -> bool {
        let now = Instant::now();
        if self.buckets.len() >= self.max_keys && !self.buckets.contains_key(&key) {
            return false;
        }
        let (last, tokens) = self.buckets.entry(key).or_insert((now, self.burst));
        let elapsed = now.duration_since(*last).as_secs_f64();
        *tokens = (*tokens + self.max_pps * elapsed).min(self.burst);
        *last = now;
        if *tokens >= 1.0 {
            *tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// Drop buckets idle for more than 60 s.  Call once per background tick;
    /// the actual `HashMap` scan runs only every [`PRUNE_INTERVAL_TICKS`] ticks.
    pub(crate) fn tick_prune(&mut self) {
        self.ticks += 1;
        if !self.ticks.is_multiple_of(PRUNE_INTERVAL_TICKS) {
            return;
        }
        if let Some(cutoff) = Instant::now().checked_sub(std::time::Duration::from_mins(1)) {
            self.buckets.retain(|_, (last, _)| *last > cutoff);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn networks_and_prefixes() {
        let a: IpAddr = "2001:db8:1:2:aaaa::1".parse().unwrap();
        let b: IpAddr = "2001:db8:1:2:bbbb::2".parse().unwrap();
        let c: IpAddr = "2001:db8:1:3::1".parse().unwrap();
        let d: IpAddr = "2001:db8:2::1".parse().unwrap();
        assert_eq!(network_of(a), network_of(b));
        assert_ne!(network_of(a), network_of(c));
        assert_eq!(prefix_of(a), prefix_of(c), "same /48");
        assert_ne!(prefix_of(a), prefix_of(d));
        let mapped: IpAddr = "::ffff:198.51.100.7".parse().unwrap();
        let v4: IpAddr = "198.51.100.7".parse().unwrap();
        assert_eq!((network_of(mapped), prefix_of(mapped)), (v4, v4));
    }

    #[test]
    fn a_capped_limiter_refuses_new_keys_when_full() {
        let mut limiter = RateLimiter::<u32>::new(1.0, 1.0).capped(2);
        assert!(limiter.allow(1));
        assert!(limiter.allow(2));
        assert!(!limiter.allow(3), "a third key");
        assert!(!limiter.allow(1), "known keys keep their own budget");
    }
}
