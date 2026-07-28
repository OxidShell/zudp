use std::time::{Duration, Instant};

const INITIAL_PACING_RATE: f64 = 1_000_000.0; // 1 MB/s
const MIN_PACING_RATE: f64 = 10_000.0;
const MAX_PACING_RATE: f64 = 100_000_000.0; // 100 MB/s
/// Initial burst allowance: typical game state syncs fit inside this without any pacing delay.
const MAX_BURST_BYTES: f64 = 65_535.0;
const MIN_RTT_WINDOW: Duration = Duration::from_secs(10);
/// If SRTT > min_rtt × this factor, queue bloat is assumed and rate backs off.
const RTT_INFLATION_THRESHOLD: f64 = 1.25;
/// Cap on inter-send sleep so congestion never stalls latency-sensitive retransmits.
const MAX_PACE_SLEEP: Duration = Duration::from_millis(10);

/// Per-peer congestion controller: BBR-lite with RTT-based pacing rate estimation.
///
/// RTT samples come from Ping/Pong echo timestamps.  The smoothed RTT (`srtt`) and
/// minimum RTT (`min_rtt`) track the path; when `srtt` inflates beyond
/// `1.25 × min_rtt` the pacing rate is reduced to drain buffer bloat.
///
/// New sends always go through immediately (gaming latency budget).
/// Bulk retransmit batches respect the pacing rate via optional sleep hints from [`consume`].
pub struct CongestionCtrl {
    /// Smoothed RTT in microseconds (EWMA, α = 1/8).  `None` until first sample.
    srtt_us: Option<u64>,
    /// Minimum RTT in microseconds over the current [`MIN_RTT_WINDOW`].
    min_rtt_us: u64,
    min_rtt_window_start: Instant,
    /// Estimated bottleneck pacing rate in bytes/second.
    pacing_rate: f64,
    /// Token bucket balance in bytes; can go negative during bursts.
    tokens: f64,
    last_refill: Instant,
}

impl CongestionCtrl {
    pub fn new() -> Self {
        let now = Instant::now();
        Self {
            srtt_us: None,
            min_rtt_us: u64::MAX,
            min_rtt_window_start: now,
            pacing_rate: INITIAL_PACING_RATE,
            tokens: MAX_BURST_BYTES,
            last_refill: now,
        }
    }

    /// Record a new RTT sample (microseconds) from a Ping/Pong echo and adjust pacing rate.
    pub fn on_rtt_sample(&mut self, rtt_us: u64) {
        // EWMA with α = 1/8: new_srtt = 7/8 * srtt + 1/8 * sample.
        self.srtt_us = Some(match self.srtt_us {
            None => rtt_us,
            Some(srtt) => (srtt - (srtt >> 3)) + (rtt_us >> 3),
        });

        let window_expired = self.min_rtt_window_start.elapsed() >= MIN_RTT_WINDOW;
        if rtt_us < self.min_rtt_us || window_expired {
            self.min_rtt_us = rtt_us;
            self.min_rtt_window_start = Instant::now();
        }

        self.update_pacing_rate();
    }

    fn update_pacing_rate(&mut self) {
        let Some(srtt) = self.srtt_us else { return };
        if self.min_rtt_us == 0 || self.min_rtt_us == u64::MAX {
            return;
        }
        let inflation = srtt as f64 / self.min_rtt_us as f64;
        if inflation > RTT_INFLATION_THRESHOLD {
            // Multiplicative decrease: drain the queue.
            self.pacing_rate = (self.pacing_rate * 0.75).max(MIN_PACING_RATE);
        } else {
            // Additive increase: probe for more bandwidth.
            self.pacing_rate = (self.pacing_rate * 1.05).min(MAX_PACING_RATE);
        }
    }

    /// Charge `bytes` against the token bucket (refilling based on elapsed time).
    ///
    /// Returns a capped sleep hint when the bucket is overdrawn.  Callers that can
    /// tolerate a small delay (retransmit batches) should honour it; latency-sensitive
    /// new sends may ignore it.
    pub fn consume(&mut self, bytes: usize) -> Option<Duration> {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        self.last_refill = now;

        self.tokens = (self.tokens + self.pacing_rate * elapsed).min(MAX_BURST_BYTES);
        self.tokens -= bytes as f64;

        if self.tokens < 0.0 {
            let raw = (-self.tokens) / self.pacing_rate;
            Some(Duration::from_secs_f64(raw).min(MAX_PACE_SLEEP))
        } else {
            None
        }
    }

    /// Current pacing rate in bytes/second.
    pub fn pacing_rate(&self) -> f64 {
        self.pacing_rate
    }

    /// Smoothed RTT.  `None` until the first Pong is received.
    pub fn srtt(&self) -> Option<Duration> {
        self.srtt_us.map(Duration::from_micros)
    }

    /// `srtt / min_rtt`: close to 1.0 = path clear; above 1.25 = queue building.
    /// `None` until at least one sample has been taken.
    pub fn congestion_factor(&self) -> Option<f64> {
        let srtt = self.srtt_us?;
        if self.min_rtt_us == 0 || self.min_rtt_us == u64::MAX {
            return None;
        }
        Some(srtt as f64 / self.min_rtt_us as f64)
    }
}
