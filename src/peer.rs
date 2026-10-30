#[cfg(feature = "security")]
use std::sync::OnceLock;
use std::{
    collections::{BTreeMap, HashMap, HashSet},
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

use crate::cc::CongestionCtrl;
use crate::frame::MAX_NACK_SEQS;
#[cfg(feature = "security")]
use crate::security::SecureChannel;

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
    /// Established Noise transport channel; replaced on every completed handshake so
    /// reconnecting peers get fresh keys instead of silently reusing stale ones.
    #[cfg(feature = "security")]
    pub channel: RwLock<Option<SecureChannel>>,
    /// The remote peer's X25519 static public key, extracted from the Noise handshake.
    /// Set once when the handshake finishes; `None` until then.
    #[cfg(feature = "security")]
    pub remote_static_key: OnceLock<[u8; 32]>,
    /// Notified (via `notify_one`) when `channel` transitions from `None` to `Some`.
    /// `connect()` awaits this so it never returns before encryption is active.
    #[cfg(feature = "security")]
    pub channel_ready: tokio::sync::Notify,
    /// Total bytes received from this peer (payload bytes, not wire bytes).
    pub rx_bytes: AtomicU64,
    /// Total bytes sent to this peer (payload bytes, not wire bytes).
    pub tx_bytes: AtomicU64,
    /// Number of frames retransmitted due to NACKs from this peer.
    pub retransmit_count: AtomicU64,
    /// Streams with a tail-loss probe task running (see `engine::arm_tail_probe`).
    pub tail_probe_armed: Mutex<HashSet<u16>>,
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
            channel: RwLock::new(None),
            #[cfg(feature = "security")]
            remote_static_key: OnceLock::new(),
            #[cfg(feature = "security")]
            channel_ready: tokio::sync::Notify::new(),
            rx_bytes: AtomicU64::new(0),
            tx_bytes: AtomicU64::new(0),
            retransmit_count: AtomicU64::new(0),
            tail_probe_armed: Mutex::new(HashSet::new()),
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

    pub fn record_sent(&self, stream_id: u16, seq: u64, frame: Bytes, max_frames: usize) {
        self.tx_bytes
            .fetch_add(frame.len() as u64, Ordering::Relaxed);
        let mut map = self.sent.lock();
        let stream_buf = map.entry(stream_id).or_default();
        if stream_buf.len() >= max_frames
            && let Some((evicted_seq, _)) = stream_buf.pop_first()
        {
            tracing::warn!(
                target: "zudp::peer",
                stream_id,
                evicted_seq,
                cap = max_frames,
                "sent buffer full — evicting oldest frame (NACK for it will not retransmit)"
            );
        }
        stream_buf.insert(
            seq,
            SentPacket {
                frame,
                sent_at: Instant::now(),
            },
        );
        drop(map);
        *self.last_sent.lock() = Instant::now();
    }

    pub fn frames_for_retransmit(&self, stream_id: u16, seqs: &[u64]) -> Vec<(u64, Bytes)> {
        let map = self.sent.lock();
        let Some(stream_buf) = map.get(&stream_id) else {
            return vec![];
        };
        let frames: Vec<(u64, Bytes)> = seqs
            .iter()
            .filter_map(|seq| stream_buf.get(seq).map(|p| (*seq, p.frame.clone())))
            .collect();
        self.retransmit_count
            .fetch_add(frames.len() as u64, Ordering::Relaxed);
        frames
    }

    /// The most recently sent frame still buffered on `stream_id`: `(seq, plain_frame, sent_at)`.
    pub fn newest_sent(&self, stream_id: u16) -> Option<(u64, Bytes, Instant)> {
        let map = self.sent.lock();
        let (seq, packet) = map.get(&stream_id)?.last_key_value()?;
        Some((*seq, packet.frame.clone(), packet.sent_at))
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

    /// The remote peer's X25519 static public key, extracted from the Noise handshake.
    ///
    /// Returns `None` until the handshake completes.
    #[cfg(feature = "security")]
    #[must_use]
    pub fn remote_static_key(&self) -> Option<&[u8; 32]> {
        self.remote_static_key.get()
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
///
/// Frames are buffered by sequence number and handed out in order through
/// [`pop_ready`](Self::pop_ready), so a frame is only consumed once the caller has
/// room to deliver it.
pub struct RecvState {
    expected_seq: u64,
    buf: BTreeMap<u64, Inbound>,
    /// Frames at or beyond `expected_seq + window` are dropped: they cannot be NACKed back
    /// into place anyway, and accepting them would let one forged sequence number make the
    /// receiver track an unbounded gap.
    window: u64,
    /// When a sequence gap was first detected.  Used by [`prune_gap`](Self::prune_gap)
    /// to skip a hole the sender can no longer retransmit.
    gap_since: Option<Instant>,
}

impl RecvState {
    #[must_use]
    pub fn new(window: usize) -> Self {
        Self {
            expected_seq: 1,
            buf: BTreeMap::new(),
            window: u64::try_from(window).unwrap_or(u64::MAX).max(1),
            gap_since: None,
        }
    }

    /// Buffer a reliable payload received at `seq`.
    ///
    /// Returns the sequence numbers still missing before `seq` (at most
    /// [`MAX_NACK_SEQS`]); already-buffered ones are not asked for again.  With
    /// `allow_reorder == false` only the next in-order frame is accepted.
    pub fn ingest(&mut self, seq: u64, payload: Inbound, allow_reorder: bool) -> Vec<u64> {
        if seq < self.expected_seq
            || seq - self.expected_seq >= self.window
            || (seq != self.expected_seq && !allow_reorder)
            || self.buf.contains_key(&seq)
        {
            return vec![];
        }
        let nack_seqs = (self.expected_seq..seq)
            .filter(|missing| !self.buf.contains_key(missing))
            .take(MAX_NACK_SEQS)
            .collect();
        self.buf.insert(seq, payload);
        self.refresh_gap();
        nack_seqs
    }

    /// `true` when the next in-order payload is buffered.
    #[must_use]
    pub fn has_ready(&self) -> bool {
        self.buf.contains_key(&self.expected_seq)
    }

    /// Take the next in-order payload, if it has arrived.
    pub fn pop_ready(&mut self) -> Option<Inbound> {
        let next = self.buf.remove(&self.expected_seq)?;
        self.expected_seq += 1;
        self.refresh_gap();
        Some(next)
    }

    fn refresh_gap(&mut self) {
        if self.buf.is_empty() || self.has_ready() {
            self.gap_since = None;
        } else if self.gap_since.is_none() {
            self.gap_since = Some(Instant::now());
        }
    }

    /// Skip a gap that has been unresolved for longer than `max_age`.
    ///
    /// Called periodically by the engine background task.  Returns `true` when a skip
    /// occurred so the caller can emit a warning.  Only the missing sequence numbers are
    /// skipped; everything buffered after the hole is still delivered.
    pub fn prune_gap(&mut self, max_age: Duration) -> bool {
        let Some(since) = self.gap_since else {
            return false;
        };
        if since.elapsed() < max_age {
            return false;
        }
        if let Some((&first, _)) = self.buf.first_key_value() {
            self.expected_seq = first;
        }
        self.gap_since = None;
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn data() -> Inbound {
        Inbound::Data(Bytes::from_static(b"x"))
    }

    fn drain(recv: &mut RecvState) -> usize {
        std::iter::from_fn(|| recv.pop_ready()).count()
    }

    #[test]
    fn nack_skips_seqs_already_buffered() {
        let mut recv = RecvState::new(1024);
        assert_eq!(recv.ingest(3, data(), true), vec![1, 2]);
        assert_eq!(recv.ingest(5, data(), true), vec![1, 2, 4], "3 is buffered");
        assert!(recv.ingest(1, data(), true).is_empty());
        assert_eq!(
            drain(&mut recv),
            1,
            "2 still missing, so only 1 is delivered"
        );
    }

    #[test]
    fn huge_sequence_number_is_dropped_without_allocating() {
        let mut recv = RecvState::new(1024);
        assert!(recv.ingest(u64::MAX - 1, data(), true).is_empty());
        assert!(recv.ingest(1 << 40, data(), true).is_empty());
        assert!(recv.buf.is_empty());
        assert!(recv.ingest(1, data(), true).is_empty());
        assert_eq!(drain(&mut recv), 1);
    }

    #[test]
    fn nack_list_is_capped() {
        let mut recv = RecvState::new(4096);
        assert_eq!(recv.ingest(4000, data(), true).len(), MAX_NACK_SEQS);
    }

    #[test]
    fn undelivered_frames_stay_buffered() {
        let mut recv = RecvState::new(1024);
        recv.ingest(1, data(), true);
        recv.ingest(2, data(), true);
        assert!(recv.has_ready());
        assert!(
            recv.ingest(1, data(), true).is_empty(),
            "duplicate of a buffered frame"
        );
        assert_eq!(drain(&mut recv), 2);
        assert!(!recv.has_ready());
    }

    #[test]
    fn in_order_only_rejects_out_of_order() {
        let mut recv = RecvState::new(1024);
        assert!(recv.ingest(2, data(), false).is_empty());
        assert!(!recv.has_ready());
        recv.ingest(1, data(), false);
        assert_eq!(drain(&mut recv), 1);
    }

    #[test]
    fn gap_timeout_keeps_frames_after_the_hole() {
        let mut recv = RecvState::new(1024);
        recv.ingest(3, data(), true);
        recv.ingest(4, data(), true);
        assert!(recv.prune_gap(Duration::ZERO));
        assert_eq!(drain(&mut recv), 2);
    }
}
