#[cfg(feature = "security")]
use std::sync::OnceLock;
use std::{
    collections::{BTreeMap, HashMap},
    net::SocketAddr,
    time::{Duration, Instant},
};

use bytes::Bytes;
use parking_lot::Mutex;

#[cfg(feature = "security")]
use crate::security::SecureChannel;

// ── Send-side ────────────────────────────────────────────────────────────────

/// A fully encoded frame retained for NACK-triggered retransmission.
pub struct SentPacket {
    pub frame: Bytes,
    pub sent_at: Instant,
}

/// Send-side state for one remote peer, shared between the caller and the engine task.
pub struct PeerState {
    pub addr: SocketAddr,
    /// Per-stream sequence counters; each stream starts at 1 and advances independently.
    next_seqs: Mutex<HashMap<u16, u64>>,
    /// Per-stream send buffers for NACK-triggered retransmission.
    pub sent: Mutex<HashMap<u16, BTreeMap<u64, SentPacket>>>,
    pub last_sent: Mutex<Instant>,
    pub last_seen: Mutex<Instant>,
    /// In-progress Noise XX handshake state; `None` once the channel is established.
    #[cfg(feature = "security")]
    pub handshake: Mutex<Option<snow::HandshakeState>>,
    /// Established Noise transport channel; set exactly once after handshake completes.
    #[cfg(feature = "security")]
    pub channel: OnceLock<SecureChannel>,
}

impl PeerState {
    #[must_use]
    pub fn new(addr: SocketAddr) -> Self {
        let now = Instant::now();
        Self {
            addr,
            next_seqs: Mutex::new(HashMap::new()),
            sent: Mutex::new(HashMap::new()),
            last_sent: Mutex::new(now),
            last_seen: Mutex::new(now),
            #[cfg(feature = "security")]
            handshake: Mutex::new(None),
            #[cfg(feature = "security")]
            channel: OnceLock::new(),
        }
    }

    /// Allocate the next sequence number for `stream_id`.  Each stream starts at 1.
    pub fn alloc_seq(&self, stream_id: u16) -> u64 {
        let mut map = self.next_seqs.lock();
        let counter = map.entry(stream_id).or_insert(1);
        let seq = *counter;
        *counter += 1;
        seq
    }

    pub fn record_sent(&self, stream_id: u16, seq: u64, frame: Bytes) {
        self.sent
            .lock()
            .entry(stream_id)
            .or_default()
            .insert(seq, SentPacket { frame, sent_at: Instant::now() });
        *self.last_sent.lock() = Instant::now();
    }

    pub fn frames_for_retransmit(&self, stream_id: u16, seqs: &[u64]) -> Vec<(u64, Bytes)> {
        let map = self.sent.lock();
        let Some(stream_buf) = map.get(&stream_id) else {
            return vec![];
        };
        seqs.iter()
            .filter_map(|seq| stream_buf.get(seq).map(|p| (*seq, p.frame.clone())))
            .collect()
    }

    pub fn prune_sent(&self, max_age: Duration) {
        if let Some(cutoff) = Instant::now().checked_sub(max_age) {
            let mut map = self.sent.lock();
            for stream_buf in map.values_mut() {
                stream_buf.retain(|_, p| p.sent_at > cutoff);
            }
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

/// Per-(peer, stream) receive state, owned exclusively by the engine task.
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
