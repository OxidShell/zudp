use std::{collections::HashMap, net::IpAddr, time::Instant};

/// Per-IP token-bucket rate limiter.
///
/// Tokens refill at `max_pps` per second up to `burst`.  Each allowed packet
/// consumes one token.  A packet is dropped if fewer than one token is available.
///
/// Not `Sync` by design — owned exclusively by the engine task, zero lock overhead.
pub(crate) struct RateLimiter {
    buckets: HashMap<IpAddr, (Instant, f64)>,
    max_pps: f64,
    burst: f64,
    /// Monotonic tick counter; prune runs every `PRUNE_INTERVAL_TICKS` ticks.
    ticks: u32,
}

/// How many background ticks between bucket prune passes.
///
/// Background fires every `keepalive_interval / 4` (default 1.25 s).
/// 48 ticks ≈ 60 s — matches the idle-bucket threshold.
const PRUNE_INTERVAL_TICKS: u32 = 48;

impl RateLimiter {
    pub(crate) fn new(max_pps: f64, burst: f64) -> Self {
        Self {
            buckets: HashMap::new(),
            max_pps,
            burst,
            ticks: 0,
        }
    }

    /// Returns `true` if the packet from `ip` is allowed, `false` if throttled.
    pub(crate) fn allow(&mut self, ip: IpAddr) -> bool {
        let now = Instant::now();
        let (last, tokens) = self.buckets.entry(ip).or_insert((now, self.burst));
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
    /// the actual HashMap scan runs only every [`PRUNE_INTERVAL_TICKS`] ticks.
    pub(crate) fn tick_prune(&mut self) {
        self.ticks += 1;
        if self.ticks % PRUNE_INTERVAL_TICKS != 0 {
            return;
        }
        if let Some(cutoff) = Instant::now().checked_sub(std::time::Duration::from_mins(1)) {
            self.buckets.retain(|_, (last, _)| *last > cutoff);
        }
    }
}
