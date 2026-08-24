use std::{
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicU16, Ordering},
    },
    time::Duration,
};

use tokio::sync::oneshot;

use crate::{engine::EngineInner, frame::Frame};

/// Minimum guaranteed IPv4 MTU (RFC 791).
const MTU_MIN: usize = 576;
/// Ceiling the binary search won't cross unless [`Zudp::max_mtu`] raises it.
///
/// Standard non-jumbo Ethernet (1500 B link MTU minus 20 B IPv4 + 8 B UDP
/// headers), not the 9000 B a jumbo frame would allow. Probes here don't set
/// the DF bit, so a probe above the real path MTU can still get acked if it
/// happens to survive IP fragmentation and reassembly in that one 200 ms
/// window — which doesn't mean it'll keep working once these packets compete
/// with real traffic. Searching all the way to 9000 by default settles on an
/// MTU that then drops data intermittently on any path that doesn't actually
/// support jumbo frames end to end (most LANs don't). 1472 never needs
/// fragmentation on a standard link, so this failure mode goes away for
/// everyone who hasn't said otherwise.
///
/// [`Zudp::max_mtu`]: crate::Zudp::max_mtu
pub(crate) const DEFAULT_MTU_CEILING: usize = 1472;
/// Absolute cap regardless of [`Zudp::max_mtu`] — covers jumbo Ethernet.
///
/// [`Zudp::max_mtu`]: crate::Zudp::max_mtu
const MTU_ABSOLUTE_MAX: usize = 9000;
/// Per-probe timeout.  200 ms is enough for any reasonable LAN/WAN path.
const PROBE_TIMEOUT: Duration = Duration::from_millis(200);
/// Maximum outstanding `MtuProbe` frames per peer.  Prevents unbounded `probe_acks` growth.
const MAX_CONCURRENT_PROBES: usize = 8;

static PROBE_ID: AtomicU16 = AtomicU16::new(1);

/// Discover the path MTU toward `peer_addr` via PLPMTUD binary search.
///
/// Runs a quick check at `initial_mtu` first — fast-paths the common case where
/// the configured default is exactly right — then binary-searches the rest of
/// `[MTU_MIN, max_mtu]` (`max_mtu` itself clamped to [`MTU_ABSOLUTE_MAX`]; see
/// [`Zudp::max_mtu`](crate::Zudp::max_mtu) for raising it past the default
/// [`DEFAULT_MTU_CEILING`]). Each step waits up to [`PROBE_TIMEOUT`] for a
/// [`Frame::MtuAck`].
///
/// Returns the largest packet size (bytes) that was successfully acknowledged.
/// Worst case: ~10 probes × 200 ms ≈ 2 s at the default ceiling; typical: 1–7 probes.
pub async fn probe(
    inner: &Arc<EngineInner>,
    peer_addr: SocketAddr,
    initial_mtu: usize,
    max_mtu: usize,
) -> usize {
    let max_mtu = max_mtu.clamp(MTU_MIN, MTU_ABSOLUTE_MAX);
    let initial_mtu = initial_mtu.clamp(MTU_MIN, max_mtu);
    let mut lo = MTU_MIN;
    let mut hi = max_mtu;
    let mut best = MTU_MIN;

    if probe_once(inner, peer_addr, initial_mtu).await {
        best = initial_mtu;
        lo = initial_mtu + 1;
    } else {
        hi = initial_mtu.saturating_sub(1);
    }

    while lo <= hi {
        let mid = lo + (hi - lo) / 2;
        if probe_once(inner, peer_addr, mid).await {
            best = mid;
            lo = mid + 1;
        } else {
            hi = mid.saturating_sub(1);
        }
    }

    best
}

async fn probe_once(inner: &Arc<EngineInner>, peer_addr: SocketAddr, size: usize) -> bool {
    if size < 3 {
        return false;
    }
    let probe_id = PROBE_ID.fetch_add(1, Ordering::Relaxed);
    let (tx, rx) = oneshot::channel::<()>();

    let peer = inner.get_or_create_peer(peer_addr);
    {
        let mut acks = peer.probe_acks.lock();
        if acks.len() >= MAX_CONCURRENT_PROBES {
            return false;
        }
        acks.insert(probe_id, tx);
    }

    let padding = size - 3;
    let wire = Frame::MtuProbe { probe_id, padding }.encode();
    if inner.get_socket().send_to(&wire, peer_addr).await.is_err() {
        peer.probe_acks.lock().remove(&probe_id);
        return false;
    }

    let ok = tokio::time::timeout(PROBE_TIMEOUT, rx).await.is_ok();
    if !ok {
        peer.probe_acks.lock().remove(&probe_id);
    }
    ok
}
