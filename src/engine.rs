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
    /// Current socket; replaced atomically on rebind.  Use [`get_socket`] to obtain a cheap clone.
    pub socket: RwLock<RawSocket>,
    pub peers: RwLock<HashMap<SocketAddr, Arc<PeerState>>>,
    /// Reverse index: remote's `my_session_id` → peer, for detecting address migrations.
    pub sessions: RwLock<HashMap<u64, Arc<PeerState>>>,
    pub config: Arc<Config>,
    /// Noise keypair for the `security` feature; `None` when security is disabled.
    #[cfg(feature = "security")]
    pub keypair: Option<crate::security::Keypair>,
}

impl EngineInner {
    /// Cheap handle to the current socket (clones the inner `Arc<UdpSocket>`).
    pub fn get_socket(&self) -> RawSocket {
        self.socket.read().clone()
    }

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
/// Each item is `(payload_bytes, sender_addr, stream_id)`.
pub(crate) fn spawn(
    inner: Arc<EngineInner>,
) -> mpsc::UnboundedReceiver<(Bytes, SocketAddr, u16)> {
    let (inbound_tx, inbound_rx) = mpsc::unbounded_channel();
    tokio::spawn(run(inner, inbound_tx));
    inbound_rx
}

async fn run(
    inner: Arc<EngineInner>,
    inbound_tx: mpsc::UnboundedSender<(Bytes, SocketAddr, u16)>,
) {
    // Keyed by (peer_addr, stream_id) so each stream has independent reorder + reassembly.
    let mut recv_states: HashMap<(SocketAddr, u16), (RecvState, FragAssembler)> = HashMap::new();
    // Stateful relay table: maps server_addr → client_addr.
    // Populated when a Relay frame arrives; used to forward server replies back to the client.
    let mut relay_table: HashMap<SocketAddr, SocketAddr> = HashMap::new();
    let keepalive_interval = inner.config.keepalive_interval;
    let sent_prune_age = inner.config.sent_prune_age;

    // Local recv socket; replaced in-place when the socket is rebound.
    let mut recv_sock = inner.get_socket();

    let mut ticker = time::interval(keepalive_interval / 4);

    loop {
        tokio::select! {
            biased;

            result = recv_sock.recv_from() => {
                match result {
                    Ok((data, from)) => {
                        handle_incoming(
                            data, from, &inner, &inbound_tx,
                            &mut recv_states, &mut relay_table,
                        ).await;
                    }
                    Err(e) => {
                        tracing::warn!(target: "zudp::engine", "recv error: {e} — attempting socket rebind");
                        match rebind_socket(&inner).await {
                            Ok(new_sock) => {
                                recv_sock = new_sock;
                                // Ping all known peers so they can migrate our address.
                                ping_all_peers(&inner, &recv_sock).await;
                            }
                            Err(bind_err) => {
                                tracing::error!(target: "zudp::engine", "rebind failed: {bind_err}");
                                break;
                            }
                        }
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

/// Try to bind a new socket on the same local address (same port if available, else port 0).
///
/// On success, replaces `inner.socket` so future `send_to` calls use the new interface.
async fn rebind_socket(inner: &Arc<EngineInner>) -> Result<RawSocket, crate::Error> {
    let old_local = inner.get_socket().local_addr()?;
    let new_sock = match RawSocket::bind(old_local).await {
        Ok(s) => s,
        Err(_) => {
            let any = SocketAddr::new(old_local.ip(), 0);
            RawSocket::bind(any).await?
        }
    };
    let new_addr = new_sock.local_addr()?;
    *inner.socket.write() = new_sock.clone();
    tracing::info!(target: "zudp::engine", old = %old_local, new = %new_addr, "socket rebound");
    Ok(new_sock)
}

/// Send a Ping carrying our session ID to every known peer so they update our address.
async fn ping_all_peers(inner: &Arc<EngineInner>, sock: &RawSocket) {
    let now_ms = now_millis();
    let peers: Vec<Arc<PeerState>> = inner.peers.read().values().cloned().collect();
    for peer in peers {
        let ping = Frame::Ping { echo: now_ms, session_id: peer.my_session_id }.encode();
        if let Err(e) = sock.send_to(&ping, peer.addr()).await {
            tracing::warn!(target: "zudp::engine", peer = %peer.addr(), "post-rebind ping failed: {e}");
        }
    }
}

async fn handle_incoming(
    data: BytesMut,
    from: SocketAddr,
    inner: &Arc<EngineInner>,
    inbound_tx: &mpsc::UnboundedSender<(Bytes, SocketAddr, u16)>,
    recv_states: &mut HashMap<(SocketAddr, u16), (RecvState, FragAssembler)>,
    relay_table: &mut HashMap<SocketAddr, SocketAddr>,
) {
    // Stateful relay pass-through: if `from` is a server we're relaying for, forward its raw
    // reply bytes directly to the mapped client without decoding.  This is checked before
    // Frame::decode so that encrypted and opaque frames are forwarded transparently.
    if let Some(&client_addr) = relay_table.get(&from) {
        tracing::trace!(target: "zudp::engine", server = %from, client = %client_addr, "relay ← server → client");
        if let Err(e) = inner.get_socket().send_to(&data, client_addr).await {
            tracing::warn!(target: "zudp::engine", client = %client_addr, "relay forward to client failed: {e}");
        }
        return;
    }

    let frame = match Frame::decode(data) {
        Ok(f) => f,
        Err(e) => {
            tracing::warn!(target: "zudp::engine", peer = %from, "bad frame: {e}");
            return;
        }
    };

    let known_peer = inner.peers.read().get(&from).cloned();
    if let Some(peer) = &known_peer {
        peer.mark_seen();
    }

    #[cfg(feature = "security")]
    {
        match frame {
            Frame::Handshake { payload } => {
                handle_handshake(payload, from, inner).await;
            }
            Frame::Secure { nonce, ciphertext } => {
                let Some(peer) = known_peer else {
                    tracing::warn!(target: "zudp::engine", peer = %from, "secure frame from unknown peer");
                    return;
                };
                let Some(channel) = peer.channel.get() else {
                    tracing::warn!(target: "zudp::engine", peer = %from, "secure frame but no channel yet");
                    return;
                };
                let plain = match channel.decrypt(nonce, &ciphertext) {
                    Ok(p) => p,
                    Err(e) => {
                        tracing::warn!(target: "zudp::engine", peer = %from, "decrypt failed: {e}");
                        return;
                    }
                };
                let inner_frame = match Frame::decode(BytesMut::from(plain.as_slice())) {
                    Ok(f) => f,
                    Err(e) => {
                        tracing::warn!(target: "zudp::engine", peer = %from, "inner frame decode failed: {e}");
                        return;
                    }
                };
                dispatch_frame(inner_frame, from, inner, inbound_tx, recv_states, relay_table).await;
            }
            frame => dispatch_frame(frame, from, inner, inbound_tx, recv_states, relay_table).await,
        }
    }

    #[cfg(not(feature = "security"))]
    dispatch_frame(frame, from, inner, inbound_tx, recv_states, relay_table).await;
}

async fn dispatch_frame(
    frame: Frame,
    from: SocketAddr,
    inner: &Arc<EngineInner>,
    inbound_tx: &mpsc::UnboundedSender<(Bytes, SocketAddr, u16)>,
    recv_states: &mut HashMap<(SocketAddr, u16), (RecvState, FragAssembler)>,
    relay_table: &mut HashMap<SocketAddr, SocketAddr>,
) {
    match frame {
        Frame::Datagram(payload) => {
            let _ = inbound_tx.send((payload, from, 0));
        }

        Frame::Stream {
            seq,
            stream_id,
            payload,
        } => {
            let (recv, _frag) = recv_states
                .entry((from, stream_id))
                .or_insert_with(|| (RecvState::new(), FragAssembler::new()));

            let (ready, nack_seqs) = recv.ingest(seq, Inbound::Data(payload));
            send_nack_if_needed(nack_seqs, stream_id, from, inner).await;
            for item in ready {
                if let Inbound::Data(bytes) = item {
                    let _ = inbound_tx.send((bytes, from, stream_id));
                }
            }
        }

        Frame::Nack { stream_id, seqs } => {
            let peer_opt = inner.peers.read().get(&from).cloned();
            if let Some(peer) = peer_opt {
                let to_retransmit = peer.frames_for_retransmit(stream_id, &seqs);
                for (seq, plain_frame) in to_retransmit {
                    let wire = encrypt_or_plain(&peer, &plain_frame);
                    tracing::debug!(target: "zudp::engine", peer = %from, seq, stream_id, "retransmit on NACK");
                    if let Err(e) = inner.get_socket().send_to(&wire, from).await {
                        tracing::warn!(target: "zudp::engine", peer = %from, "retransmit failed: {e}");
                    }
                }
            }
        }

        Frame::Ping { echo, session_id } => {
            let peer = find_or_migrate_peer(from, session_id, inner, recv_states);
            let pong = Frame::Pong { echo, session_id: peer.my_session_id }.encode();
            if let Err(e) = inner.get_socket().send_to(&pong, from).await {
                tracing::warn!(target: "zudp::engine", peer = %from, "pong failed: {e}");
            }
        }

        Frame::Pong { session_id, .. } => {
            // Learn the remote's session ID from their Pong if not yet known.
            if let Some(peer) = inner.peers.read().get(&from).cloned() {
                if peer.store_their_session_id(session_id) {
                    inner.sessions.write().insert(session_id, peer);
                }
            }
        }

        Frame::Fragment {
            msg_id,
            frag_idx,
            frag_total,
            seq,
            stream_id,
            payload,
        } => {
            let (recv, frag_assembler) = recv_states
                .entry((from, stream_id))
                .or_insert_with(|| (RecvState::new(), FragAssembler::new()));

            let inbound = Inbound::Fragment {
                msg_id,
                frag_idx,
                frag_total,
                data: payload,
            };
            let (ready, nack_seqs) = recv.ingest(seq, inbound);
            send_nack_if_needed(nack_seqs, stream_id, from, inner).await;

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
                    let _ = inbound_tx.send((complete, from, stream_id));
                }
            }
        }

        Frame::Relay {
            dest,
            inner: payload,
        } => {
            // Record client→server mapping so replies from `dest` can be routed back to `from`.
            // Upsert handles client address migrations transparently.
            relay_table.insert(dest, from);
            tracing::trace!(target: "zudp::engine", client = %from, server = %dest, "relay client → server");
            if let Err(e) = inner.get_socket().send_to(&payload, dest).await {
                tracing::warn!(target: "zudp::engine", %dest, "relay forward failed: {e}");
            }
        }

        Frame::Probe { .. } | Frame::Beacon { .. } => {}

        // Handshake and Secure are handled before dispatch_frame is called.
        #[cfg(feature = "security")]
        Frame::Handshake { .. } | Frame::Secure { .. } => {}
    }
}

/// Locate the peer for an incoming Ping, handling first contact, familiar address, and migration.
///
/// Migration: if `session_id` matches a known peer but `from` differs, the peer's address is
/// updated, the `peers` map is re-keyed, and all `recv_states` entries are moved to the new key.
fn find_or_migrate_peer(
    from: SocketAddr,
    session_id: u64,
    inner: &Arc<EngineInner>,
    recv_states: &mut HashMap<(SocketAddr, u16), (RecvState, FragAssembler)>,
) -> Arc<PeerState> {
    // Fast path: familiar address.
    if let Some(peer) = inner.peers.read().get(&from).cloned() {
        if peer.store_their_session_id(session_id) {
            inner.sessions.write().insert(session_id, peer.clone());
        }
        return peer;
    }

    // Migration: known session but new address.
    if let Some(peer) = inner.sessions.read().get(&session_id).cloned() {
        let old_addr = peer.addr();
        if old_addr != from {
            tracing::info!(
                target: "zudp::engine",
                old = %old_addr,
                new = %from,
                "peer address migrated"
            );
            peer.migrate_to(from);
            {
                let mut peers = inner.peers.write();
                peers.remove(&old_addr);
                peers.insert(from, peer.clone());
            }
            // Move all recv_states from old key to new key.
            let stream_ids: Vec<u16> = recv_states
                .keys()
                .filter(|(a, _)| *a == old_addr)
                .map(|(_, s)| *s)
                .collect();
            for sid in stream_ids {
                if let Some(state) = recv_states.remove(&(old_addr, sid)) {
                    recv_states.insert((from, sid), state);
                }
            }
        }
        return peer;
    }

    // First contact: create peer and register session.
    let peer = inner.get_or_create_peer(from);
    peer.store_their_session_id(session_id);
    inner.sessions.write().insert(session_id, peer.clone());
    peer
}

/// If the peer has an established Noise channel, re-encrypt the plain frame; otherwise send as-is.
///
/// Used for NACK-triggered retransmits: each retransmit gets a fresh nonce to avoid reuse.
#[allow(unused_variables)]
fn encrypt_or_plain(peer: &PeerState, plain: &Bytes) -> Bytes {
    #[cfg(feature = "security")]
    if let Some(channel) = peer.channel.get() {
        match channel.encrypt(plain) {
            Ok((nonce, ct)) => {
                return Frame::Secure {
                    nonce,
                    ciphertext: Bytes::from(ct),
                }
                .encode();
            }
            Err(e) => {
                tracing::warn!(target: "zudp::engine", "retransmit encrypt failed: {e}");
            }
        }
    }
    plain.clone()
}

async fn send_nack_if_needed(
    nack_seqs: Vec<u64>,
    stream_id: u16,
    to: SocketAddr,
    inner: &Arc<EngineInner>,
) {
    if nack_seqs.is_empty() {
        return;
    }
    tracing::debug!(target: "zudp::engine", peer = %to, count = nack_seqs.len(), stream_id, "sending NACK");
    let frame = Frame::Nack { stream_id, seqs: nack_seqs }.encode();
    if let Err(e) = inner.get_socket().send_to(&frame, to).await {
        tracing::warn!(target: "zudp::engine", peer = %to, "nack send failed: {e}");
    }
}

async fn run_background(
    inner: &Arc<EngineInner>,
    recv_states: &mut HashMap<(SocketAddr, u16), (RecvState, FragAssembler)>,
    keepalive_interval: Duration,
    sent_prune_age: Duration,
) {
    let keepalive_threshold = keepalive_interval.as_secs();
    let now_ms = now_millis();

    let peers: Vec<Arc<PeerState>> = inner.peers.read().values().cloned().collect();

    for peer in peers {
        if peer.secs_since_sent() >= keepalive_threshold {
            let ping = Frame::Ping { echo: now_ms, session_id: peer.my_session_id }.encode();
            if let Err(e) = inner.get_socket().send_to(&ping, peer.addr()).await {
                tracing::warn!(target: "zudp::engine", peer = %peer.addr(), "keepalive failed: {e}");
            }
            tracing::trace!(target: "zudp::engine", peer = %peer.addr(), "sent keepalive ping");
        }
        peer.prune_sent(sent_prune_age);
    }

    for (_, frag_assembler) in recv_states.values_mut() {
        frag_assembler.prune(sent_prune_age);
    }
}

fn now_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0u64, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

/// Drive a Noise XX handshake step on behalf of the engine.
///
/// - If no handshake exists for `from` yet, creates a responder state (server role).
/// - If a handshake already exists (initiator stored it before sending msg1), reads the
///   incoming message and, if it's the initiator's turn, writes the next message.
/// - When both sides finish all three messages, transitions to `StatelessTransportState`.
#[cfg(feature = "security")]
async fn handle_handshake(payload: Bytes, from: SocketAddr, inner: &Arc<EngineInner>) {
    use crate::security::{SecureChannel, build_responder};

    let Some(kp) = inner.keypair.as_ref() else {
        tracing::debug!(target: "zudp::engine", peer = %from, "handshake ignored — security not configured");
        return;
    };

    let peer = inner.get_or_create_peer(from);

    // Initialise as responder if this peer's handshake hasn't started yet.
    {
        let mut guard = peer.handshake.lock();
        if guard.is_none() {
            match build_responder(kp) {
                Ok(hs) => *guard = Some(hs),
                Err(e) => {
                    tracing::error!(target: "zudp::engine", peer = %from, "build_responder: {e}");
                    return;
                }
            }
        }
    }

    // Process the incoming message; determine if we need to reply and/or finish.
    let outcome = {
        let mut guard = peer.handshake.lock();
        let hs = guard.as_mut().expect("initialised above");

        let mut rbuf = vec![0u8; 1024];
        if let Err(e) = hs.read_message(&payload, &mut rbuf) {
            tracing::warn!(target: "zudp::engine", peer = %from, "handshake read: {e}");
            return;
        }

        // After reading, check if the handshake is done (responder finishes on msg3).
        let finished_after_read = hs.is_handshake_finished();

        if finished_after_read {
            // Take the state before releasing the guard.
            let hs_owned = guard.take().unwrap();
            (None::<Bytes>, Some(hs_owned))
        } else {
            // Still our turn to write (msg2 for responder, msg3 for initiator).
            let mut wbuf = vec![0u8; 1024];
            let n = match hs.write_message(&[], &mut wbuf) {
                Ok(n) => n,
                Err(e) => {
                    tracing::warn!(target: "zudp::engine", peer = %from, "handshake write: {e}");
                    return;
                }
            };
            wbuf.truncate(n);
            let reply = Bytes::from(wbuf);

            // After writing, check again (initiator finishes on msg3 write).
            let finished_after_write = hs.is_handshake_finished();
            let hs_owned = if finished_after_write {
                guard.take()
            } else {
                None
            };

            (Some(reply), hs_owned)
        }
    }; // handshake lock released

    let (reply, finished_hs) = outcome;

    if let Some(reply_bytes) = reply {
        let wire = Frame::Handshake {
            payload: reply_bytes,
        }
        .encode();
        if let Err(e) = inner.get_socket().send_to(&wire, from).await {
            tracing::warn!(target: "zudp::engine", peer = %from, "handshake send: {e}");
        }
    }

    if let Some(hs) = finished_hs {
        match hs.into_stateless_transport_mode() {
            Ok(transport) => {
                let _ = peer.channel.set(SecureChannel::new(transport));
                tracing::info!(target: "zudp::engine", peer = %from, "Noise XX handshake complete");
            }
            Err(e) => {
                tracing::error!(target: "zudp::engine", peer = %from, "into_transport_mode: {e}");
            }
        }
    }
}
