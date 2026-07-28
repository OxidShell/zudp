#[cfg(feature = "security")]
use std::sync::OnceLock;
use std::{
    collections::{BTreeMap, HashMap},
    hash::{Hash, Hasher},
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicU32, AtomicU64, Ordering},
    },
    time::{Duration, Instant, SystemTime},
};

use tokio::sync::oneshot;

use bytes::Bytes;
use parking_lot::{Mutex, RwLock};

#[cfg(feature = "security")]
use crate::security::SecureChannel;
use crate::cc::CongestionCtrl;

// ── Send-side ────────────────────────────────────────────────────────────────

/// A fully encoded frame retained for NACK-triggered retransmission.
pub struct SentPacket {
    pub frame: Bytes,
    pub sent_at: Instant,
}

/// Send-side state for one remote peer, shared between the caller and the engine task.
pub struct PeerState {
    /// Current remote address; updated transparently on network migration.
    addr: Arc<RwLock<SocketAddr>>,
    /// Session ID we include in every Ping to this peer so they can migrate us if our IP changes.
    pub my_session_id: u64,
    /// Session ID the remote includes in their Pings; lets us recognise them from a new address.
    their_session_id: Mutex<Option<u64>>,
    /// Per-stream sequence counters; each stream starts at 1 and advances independently.
    next_seqs: Mutex<HashMap<u16, u64>>,
    /// Per-stream send buffers for NACK-triggered retransmission.
    pub sent: Mutex<HashMap<u16, BTreeMap<u64, SentPacket>>>,
    pub last_sent: Mutex<Instant>,
    pub last_seen: Mutex<Instant>,
    /// RTT-based congestion controller; updated on every Pong.
    pub cc: Mutex<CongestionCtrl>,
    /// Path MTU discovered by PLPMTUD; 0 = discovery not yet complete, use config default.
    effective_mtu: AtomicU32,
    /// Pending MTU probe acks: maps `probe_id → oneshot sender` woken by the engine on MtuAck.
    pub probe_acks: Mutex<HashMap<u16, oneshot::Sender<()>>>,
    /// In-progress Noise XX handshake state; `None` once the channel is established.
    #[cfg(feature = "security")]
    pub handshake: Mutex<Option<snow::HandshakeState>>,
    /// Established Noise transport channel; set exactly once after handshake completes.
    #[cfg(feature = "security")]
    pub channel: OnceLock<SecureChannel>,
    /// Notified (via `notify_one`) when `channel` transitions from `None` to `Some`.
    /// `connect()` awaits this so it never returns before encryption is active.
    #[cfg(feature = "security")]
    pub channel_ready: tokio::sync::Notify,
}

impl PeerState {
    #[must_use]
    pub fn new(addr: SocketAddr) -> Self {
        let now = Instant::now();
        Self {
            addr: Arc::new(RwLock::new(addr)),
            my_session_id: gen_session_id(),
            their_session_id: Mutex::new(None),
            next_seqs: Mutex::new(HashMap::new()),
            sent: Mutex::new(HashMap::new()),
            last_sent: Mutex::new(now),
            last_seen: Mutex::new(now),
            cc: Mutex::new(CongestionCtrl::new()),
            effective_mtu: AtomicU32::new(0),
            probe_acks: Mutex::new(HashMap::new()),
            #[cfg(feature = "security")]
            handshake: Mutex::new(None),
            #[cfg(feature = "security")]
            channel: OnceLock::new(),
            #[cfg(feature = "security")]
            channel_ready: tokio::sync::Notify::new(),
        }
    }

    /// Current remote address.
    pub fn addr(&self) -> SocketAddr {
        *self.addr.read()
    }

    /// Shared handle to the live address so `ZudpConn` tracks migrations automatically.
    pub fn addr_arc(&self) -> Arc<RwLock<SocketAddr>> {
        self.addr.clone()
    }

    /// Update the stored address after the remote migrates to a new network.
    pub fn migrate_to(&self, new_addr: SocketAddr) {
        *self.addr.write() = new_addr;
    }

    /// Record the session ID received from the remote's Pings.
    ///
    /// Returns `true` if this is the first time the ID is learned (caller should register in sessions map).
    pub fn store_their_session_id(&self, id: u64) -> bool {
        let mut guard = self.their_session_id.lock();
        if guard.is_none() {
            *guard = Some(id);
            true
        } else {
            false
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

    /// Effective path MTU discovered by PLPMTUD; falls back to `default` until discovery completes.
    pub fn effective_mtu_or(&self, default: usize) -> usize {
        match self.effective_mtu.load(Ordering::Relaxed) {
            0 => default,
            v => v as usize,
        }
    }

    pub fn set_effective_mtu(&self, mtu: usize) {
        self.effective_mtu.store(mtu as u32, Ordering::Relaxed);
    }
}

/// Generate a non-cryptographic but sufficiently unique session ID without adding dependencies.
fn gen_session_id() -> u64 {
    use std::collections::hash_map::DefaultHasher;

    static SEQ: AtomicU64 = AtomicU64::new(0);

    let mut h = DefaultHasher::new();
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .hash(&mut h);
    SEQ.fetch_add(1, Ordering::Relaxed).hash(&mut h);
    // Stack address adds a bit of process-specific entropy.
    let addr: u64 = (&h as *const _ as usize) as u64;
    addr.hash(&mut h);
    h.finish()
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
