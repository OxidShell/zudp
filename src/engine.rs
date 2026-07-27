use std::{collections::HashMap, net::SocketAddr, sync::Arc, time::Duration};

use bytes::{Bytes, BytesMut};
use parking_lot::RwLock;
use tokio::{sync::mpsc, time};

use crate::{
    Config,
    frag::FragAssembler,
    frame::Frame,
    peer::{Inbound, PeerState, RecvState},
    socket::RawSocket,
};

/// State shared between the engine task and the [`crate::ZudpSocket`] / [`crate::ZudpConn`] handles.
pub(crate) struct EngineInner {
    pub socket: RawSocket,
    pub peers: RwLock<HashMap<SocketAddr, Arc<PeerState>>>,
    pub config: Arc<Config>,
}

impl EngineInner {
    pub fn get_or_create_peer(self: &Arc<Self>, addr: SocketAddr) -> Arc<PeerState> {
        {
            let r = self.peers.read();
            if let Some(p) = r.get(&addr) {
                return p.clone();
            }
        }
        let mut w = self.peers.write();
        w.entry(addr)
            .or_insert_with(|| Arc::new(PeerState::new(addr)))
            .clone()
    }
}

/// Spawn the engine background task and return the inbound receiver.
///
/// The engine reads from the socket, dispatches frames, retransmits on NACK,
/// and sends keepalives.  All send I/O from `ZudpSocket`/`ZudpConn` bypasses
/// the engine and hits the socket directly.
pub(crate) fn spawn(inner: Arc<EngineInner>) -> mpsc::UnboundedReceiver<(Bytes, SocketAddr)> {
    let (inbound_tx, inbound_rx) = mpsc::unbounded_channel();
    tokio::spawn(run(inner, inbound_tx));
    inbound_rx
}

async fn run(inner: Arc<EngineInner>, inbound_tx: mpsc::UnboundedSender<(Bytes, SocketAddr)>) {
    // Per-peer receive state is local to this task — no lock needed.
    let mut recv_states: HashMap<SocketAddr, (RecvState, FragAssembler)> = HashMap::new();
    let keepalive_interval = inner.config.keepalive_interval;
    let sent_prune_age = inner.config.sent_prune_age;

    let mut ticker = time::interval(keepalive_interval / 4);

    loop {
        tokio::select! {
            biased; // check recv first to minimise latency

            result = inner.socket.recv_from() => {
                match result {
                    Ok((data, from)) => {
                        handle_incoming(data, from, &inner, &inbound_tx, &mut recv_states).await;
                    }
                    Err(e) => {
                        tracing::error!(target: "zudp::engine", "recv error: {e}");
                        break;
                    }
                }
            }

            _ = ticker.tick() => {
                run_background(&inner, &mut recv_states, keepalive_interval, sent_prune_age).await;
            }
        }
    }

    tracing::warn!(target: "zudp::engine", "engine task exited");
}

async fn handle_incoming(
    data: BytesMut,
    from: SocketAddr,
    inner: &Arc<EngineInner>,
    inbound_tx: &mpsc::UnboundedSender<(Bytes, SocketAddr)>,
    recv_states: &mut HashMap<SocketAddr, (RecvState, FragAssembler)>,
) {
    let frame = match Frame::decode(data) {
        Ok(f) => f,
        Err(e) => {
            tracing::warn!(target: "zudp::engine", peer = %from, "bad frame: {e}");
            return;
        }
    };

    // Bump last-seen for any peer we already know (clone Arc, release lock immediately).
    let known_peer = inner.peers.read().get(&from).cloned();
    if let Some(peer) = known_peer {
        peer.mark_seen();
    }

    match frame {
        Frame::Datagram(payload) => {
            let _ = inbound_tx.send((payload, from));
        }

        Frame::Stream { seq, payload } => {
            let (recv, _frag) = recv_states
                .entry(from)
                .or_insert_with(|| (RecvState::new(), FragAssembler::new()));

            let (ready, nack_seqs) = recv.ingest(seq, Inbound::Data(payload));
            send_nack_if_needed(nack_seqs, from, inner).await;
            for item in ready {
                if let Inbound::Data(bytes) = item {
                    let _ = inbound_tx.send((bytes, from));
                }
            }
        }

        Frame::Nack(seqs) => {
            // Clone the Arc before releasing the lock so no guard crosses an await.
            let peer_opt = inner.peers.read().get(&from).cloned();
            if let Some(peer) = peer_opt {
                let to_retransmit = peer.frames_for_retransmit(&seqs);
                for (seq, frame) in to_retransmit {
                    tracing::debug!(target: "zudp::engine", peer = %from, seq, "retransmit on NACK");
                    if let Err(e) = inner.socket.send_to(&frame, from).await {
                        tracing::warn!(target: "zudp::engine", peer = %from, "retransmit failed: {e}");
                    }
                }
            }
        }

        Frame::Ping { echo } => {
            let pong = Frame::Pong { echo }.encode();
            if let Err(e) = inner.socket.send_to(&pong, from).await {
                tracing::warn!(target: "zudp::engine", peer = %from, "pong failed: {e}");
            }
        }

        Frame::Fragment {
            msg_id,
            frag_idx,
            frag_total,
            seq,
            payload,
        } => {
            let (recv, frag_assembler) = recv_states
                .entry(from)
                .or_insert_with(|| (RecvState::new(), FragAssembler::new()));

            let inbound = Inbound::Fragment {
                msg_id,
                frag_idx,
                frag_total,
                data: payload,
            };
            let (ready, nack_seqs) = recv.ingest(seq, inbound);
            send_nack_if_needed(nack_seqs, from, inner).await;

            for item in ready {
                if let Inbound::Fragment {
                    msg_id,
                    frag_idx,
                    frag_total,
                    data,
                } = item
                    && let Some(complete) =
                        frag_assembler.insert(msg_id, frag_idx, frag_total, data)
                {
                    let _ = inbound_tx.send((complete, from));
                }
            }
        }

        Frame::Relay {
            dest,
            inner: payload,
        } => {
            // This node is acting as a relay — forward the inner bytes verbatim.
            if let Err(e) = inner.socket.send_to(&payload, dest).await {
                tracing::warn!(target: "zudp::engine", %dest, "relay forward failed: {e}");
            }
        }

        // last_seen already bumped above; nothing more to do for these.
        Frame::Pong { .. } | Frame::Probe { .. } | Frame::Beacon { .. } => {}
    }
}

async fn send_nack_if_needed(nack_seqs: Vec<u64>, to: SocketAddr, inner: &Arc<EngineInner>) {
    if nack_seqs.is_empty() {
        return;
    }
    tracing::debug!(target: "zudp::engine", peer = %to, count = nack_seqs.len(), "sending NACK");
    let frame = Frame::Nack(nack_seqs).encode();
    if let Err(e) = inner.socket.send_to(&frame, to).await {
        tracing::warn!(target: "zudp::engine", peer = %to, "nack send failed: {e}");
    }
}

async fn run_background(
    inner: &Arc<EngineInner>,
    recv_states: &mut HashMap<SocketAddr, (RecvState, FragAssembler)>,
    keepalive_interval: Duration,
    sent_prune_age: Duration,
) {
    let keepalive_threshold = keepalive_interval.as_secs();
    let now_millis = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0u64, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));

    let peers: Vec<Arc<PeerState>> = inner.peers.read().values().cloned().collect();

    for peer in peers {
        // Keepalive: send Ping if idle.
        if peer.secs_since_sent() >= keepalive_threshold {
            let ping = Frame::Ping { echo: now_millis }.encode();
            if let Err(e) = inner.socket.send_to(&ping, peer.addr).await {
                tracing::warn!(target: "zudp::engine", peer = %peer.addr, "keepalive failed: {e}");
            }
            tracing::trace!(target: "zudp::engine", peer = %peer.addr, "sent keepalive ping");
        }
        // Prune sent buffer to avoid unbounded growth.
        peer.prune_sent(sent_prune_age);
    }

    // Prune stale fragment assemblies (sender may have died mid-message).
    for (_, frag_assembler) in recv_states.values_mut() {
        frag_assembler.prune(sent_prune_age);
    }
}
