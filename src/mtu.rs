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
/// Maximum probed size; covers jumbo Ethernet (9000 B).
const MTU_MAX: usize = 9000;
/// Per-probe timeout.  200 ms is enough for any reasonable LAN/WAN path.
const PROBE_TIMEOUT: Duration = Duration::from_millis(200);

static PROBE_ID: AtomicU16 = AtomicU16::new(1);

/// Discover the path MTU toward `peer_addr` via PLPMTUD binary search.
///
/// Runs a quick check at `initial_mtu` first — fast-paths the common case where
/// the configured default is exactly right — then binary-searches the remaining
/// range.  Each step waits up to [`PROBE_TIMEOUT`] for an [`Frame::MtuAck`].
///
/// Returns the largest packet size (bytes) that was successfully acknowledged.
/// Worst case: ~13 probes × 200 ms ≈ 2.6 s; typical: 1–7 probes.
pub async fn probe(inner: &Arc<EngineInner>, peer_addr: SocketAddr, initial_mtu: usize) -> usize {
    let initial_mtu = initial_mtu.clamp(MTU_MIN, MTU_MAX);
    let mut lo = MTU_MIN;
    let mut hi = MTU_MAX;
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
    peer.probe_acks.lock().insert(probe_id, tx);

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
