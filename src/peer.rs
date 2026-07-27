use std::{
    collections::BTreeMap,
    net::SocketAddr,
    sync::atomic::{AtomicU64, Ordering},
    time::Instant,
};

use bytes::Bytes;
use parking_lot::Mutex;

// ── Send-side ────────────────────────────────────────────────────────────────

/// A fully encoded frame retained for NACK-triggered retransmission.
pub struct SentPacket {
    pub frame: Bytes,
    pub sent_at: Instant,
}

/// Send-side state for one remote peer, shared between the caller and the engine task.
pub struct PeerState {
    pub addr: SocketAddr,
    next_seq: AtomicU64,
    pub sent: Mutex<BTreeMap<u64, SentPacket>>,
    pub last_sent: Mutex<Instant>,
    pub last_seen: Mutex<Instant>,
}

impl PeerState {
    #[must_use]
    pub fn new(addr: SocketAddr) -> Self {
        let now = Instant::now();
        Self {
            addr,
            next_seq: AtomicU64::new(1),
            sent: Mutex::new(BTreeMap::new()),
            last_sent: Mutex::new(now),
            last_seen: Mutex::new(now),
        }
    }

    pub fn alloc_seq(&self) -> u64 {
        self.next_seq.fetch_add(1, Ordering::Relaxed)
    }

    pub fn record_sent(&self, seq: u64, frame: Bytes) {
        self.sent.lock().insert(
            seq,
            SentPacket {
                frame,
                sent_at: Instant::now(),
            },
        );
        *self.last_sent.lock() = Instant::now();
    }

    pub fn frames_for_retransmit(&self, seqs: &[u64]) -> Vec<(u64, Bytes)> {
        let sent = self.sent.lock();
        seqs.iter()
            .filter_map(|seq| sent.get(seq).map(|p| (*seq, p.frame.clone())))
            .collect()
    }

    pub fn prune_sent(&self, max_age: std::time::Duration) {
        if let Some(cutoff) = Instant::now().checked_sub(max_age) {
            self.sent.lock().retain(|_, p| p.sent_at > cutoff);
        }
    }

    pub fn mark_seen(&self) {
        *self.last_seen.lock() = Instant::now();
    }

    pub fn secs_since_sent(&self) -> u64 {
        self.last_sent.lock().elapsed().as_secs()
    }
}

// ── Receive-side ─────────────────────────────────────────────────────────────

/// An in-order payload element delivered by [`RecvState::ingest`].
#[derive(Debug)]
pub enum Inbound {
    /// A complete reliable message payload.
    Data(Bytes),
    /// One slice of a fragmented reliable message.
    Fragment {
        msg_id: u32,
        frag_idx: u16,
        frag_total: u16,
        data: Bytes,
    },
}

/// Per-peer receive state, owned exclusively by the engine task.
///
/// Both `Stream` and `Fragment` frames share the same sequence space on each peer,
/// so a single reorder buffer handles both.
pub struct RecvState {
    pub expected_seq: u64,
    buf: BTreeMap<u64, Inbound>,
}

impl RecvState {
    #[must_use]
    pub fn new() -> Self {
        Self {
            expected_seq: 1,
            buf: BTreeMap::new(),
        }
    }

    /// Process an incoming reliable payload at `seq`.
    ///
    /// Returns:
    /// - `ready`: in-order payloads available for delivery (possibly multiple, after gap fills).
    /// - `nack_seqs`: sequence numbers to NACK (gaps detected before `seq`).
    pub fn ingest(&mut self, seq: u64, payload: Inbound) -> (Vec<Inbound>, Vec<u64>) {
        if seq < self.expected_seq {
            return (vec![], vec![]);
        }

        if seq > self.expected_seq {
            let nack_seqs: Vec<u64> = (self.expected_seq..seq).collect();
            self.buf.insert(seq, payload);
            return (vec![], nack_seqs);
        }

        // In-order: deliver immediately and drain any consecutive buffered entries.
        let mut ready = vec![payload];
        self.expected_seq += 1;
        while let Some(next) = self.buf.remove(&self.expected_seq) {
            ready.push(next);
            self.expected_seq += 1;
        }
        (ready, vec![])
    }
}
