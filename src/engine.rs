use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use bytes::{Bytes, BytesMut};
use dashmap::DashMap;
use parking_lot::{Mutex, RwLock};
use tokio::{sync::mpsc, task::JoinSet, time};

use crate::{
    Config,
    frag::FragAssembler,
    frame::Frame,
    peer::{Inbound, PeerState, RecvState},
    socket::RawSocket,
};

/// Runtime-mutable relay access control, updateable without socket rebind.
pub struct RelayPolicy {
    /// IP allowlist for relay frame sources.  Empty = allow all.
    pub allowlist: Vec<std::net::IpAddr>,
    /// Maximum entries in the relay routing table.
    pub max_entries: usize,
}

/// Maximum concurrent NACK retransmit tasks across the engine.
///
/// Each task handles one NACK batch (one peer, one burst of missing seqs).  Capping
/// prevents memory/CPU runaway when a peer floods NACKs faster than retransmits drain.
const MAX_RETRANSMIT_TASKS: usize = 32;

/// Capacity of the bounded inbound channel between the engine task and the socket handle.
///
/// At 1 400 B/frame and 8 192 slots this is ~11 MB peak backpressure before the engine
/// starts dropping frames.  The engine uses `try_send` so the recv loop is never stalled.
const INBOUND_CAP: usize = 8_192;

/// State shared between the engine task and the [`crate::ZudpSocket`] / [`crate::ZudpConn`] handles.
pub(crate) struct EngineInner {
    /// Current socket; replaced atomically on rebind.  Use [`get_socket`] to obtain a cheap clone.
    pub socket: RwLock<RawSocket>,
    pub peers: DashMap<SocketAddr, Arc<PeerState>>,
    /// Reverse index: remote's `my_session_id` → peer, for detecting address migrations.
    pub sessions: DashMap<u64, Arc<PeerState>>,
    pub config: Arc<Config>,
    /// Noise keypair for the `security` feature; `None` when security is disabled.
    #[cfg(feature = "security")]
    pub keypair: Option<crate::security::Keypair>,
    /// Set by the engine task before it exits; callers read this to distinguish a
    /// clean shutdown from an unexpected crash (rebind failure, etc.).
    pub shutdown_reason: Mutex<Option<String>>,
    pub dropped_rate_limited: AtomicU64,
    pub dropped_peer_cap: AtomicU64,
    pub dropped_relay_blocked: AtomicU64,
    pub dropped_relay_cap: AtomicU64,
    /// Runtime-mutable relay access policy (allowlist + table cap).
    pub relay_policy: RwLock<RelayPolicy>,
}

impl EngineInner {
    /// Cheap handle to the current socket (clones the inner `Arc<UdpSocket>`).
    pub fn get_socket(&self) -> RawSocket {
        self.socket.read().clone()
    }

    pub fn get_or_create_peer(self: &Arc<Self>, addr: SocketAddr) -> Arc<PeerState> {
        if let Some(p) = self.peers.get(&addr) {
            return p.value().clone();
        }
        if self.peers.len() >= self.config.max_peers {
            let evict_addr = self
                .peers
                .iter()
                .min_by_key(|r| *r.value().last_seen.lock())
                .map(|r| *r.key());
            if let Some(evict) = evict_addr {
                tracing::warn!(
                    target: "zudp::engine",
                    evicted = %evict,
                    new = %addr,
                    "peer table full — evicting least-recently-seen peer"
                );
                self.peers.remove(&evict);
            }
            self.dropped_peer_cap.fetch_add(1, Ordering::Relaxed);
        }
        self.peers
            .entry(addr)
            .or_insert_with(|| Arc::new(PeerState::new(addr)))
            .value()
            .clone()
    }
}

/// Spawn the engine background task and return the inbound receiver.
///
/// `shutdown_rx` resolves when the caller drops the paired `oneshot::Sender`; the engine
/// then drains in-flight retransmits and exits cleanly.
///
/// Each item on the returned channel is `(payload_bytes, sender_addr, stream_id)`.
pub(crate) fn spawn(
    inner: Arc<EngineInner>,
    shutdown_rx: tokio::sync::oneshot::Receiver<()>,
) -> mpsc::Receiver<(Bytes, SocketAddr, u16)> {
    let (inbound_tx, inbound_rx) = mpsc::channel(INBOUND_CAP);
    tokio::spawn(run(inner, inbound_tx, shutdown_rx));
    inbound_rx
}

async fn run(
    inner: Arc<EngineInner>,
    inbound_tx: mpsc::Sender<(Bytes, SocketAddr, u16)>,
    mut shutdown_rx: tokio::sync::oneshot::Receiver<()>,
) {
    // Keyed by (peer_addr, stream_id) so each stream has independent reorder + reassembly.
    let mut recv_states: HashMap<(SocketAddr, u16), (RecvState, FragAssembler)> = HashMap::new();
    // Stateful relay table: maps server_addr → (client_addr, last_seen_gen).
    // `last_seen_gen` is the relay_gen value at the last Frame::Relay from that client.
    // Entries pruned when (relay_gen - last_seen_gen) >= relay_ttl_ticks.
    // No Instant/syscall in the hot path — generation counter is a u32 store.
    let mut relay_table: HashMap<SocketAddr, (SocketAddr, u32)> = HashMap::new();
    // Monotonic counter incremented once per background tick.  Wrapping arithmetic
    // is intentional: correct for the ~170-year lifetime of a u32 at 240 ticks/5 min.
    let mut relay_gen: u32 = 0;
    // TTL expressed as a tick delta: 5 minutes / tick_interval.
    let relay_ttl_ticks = {
        let tick_secs = inner.config.keepalive_interval.as_secs_f64() / 4.0;
        (300.0_f64 / tick_secs).ceil() as u32
    };

    let keepalive_interval = inner.config.keepalive_interval;
    let sent_prune_age = inner.config.sent_prune_age;

    let mut rate_limiter = crate::rate::RateLimiter::new(
        inner.config.max_pps_per_ip,
        (inner.config.max_pps_per_ip / 5.0).max(1.0),
    );

    // Bounded pool for NACK retransmit tasks.  Each task may sleep for CC pacing, so
    // they are spawned off the recv loop to avoid stalling it — but the pool is capped
    // to prevent unbounded task accumulation under heavy loss or adversarial NACKs.
    let mut retransmit_tasks: JoinSet<()> = JoinSet::new();

    // Local recv socket; replaced in-place when the socket is rebound.
    let mut recv_sock = inner.get_socket();

    let mut ticker = time::interval(keepalive_interval / 4);

    loop {
        // Reap completed retransmit tasks without blocking.
        while retransmit_tasks.try_join_next().is_some() {}

        tokio::select! {
            biased;

            _ = &mut shutdown_rx => {
                *inner.shutdown_reason.lock() = Some("shutdown requested".into());
                tracing::info!(target: "zudp::engine", "graceful shutdown — draining retransmits");
                break;
            }

            result = recv_sock.recv_from() => {
                match result {
                    Ok((data, from)) => {
                        if inner.config.max_pps_per_ip > 0.0
                            && !rate_limiter.allow(from.ip())
                        {
                            tracing::trace!(target: "zudp::engine", %from, "rate limited");
                            inner.dropped_rate_limited.fetch_add(1, Ordering::Relaxed);
                            continue;
                        }
                        handle_incoming(
                            data, from, &inner, &inbound_tx,
                            &mut recv_states, &mut relay_table, relay_gen,
                            &mut retransmit_tasks,
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
                                let reason = format!("socket rebind failed: {bind_err}");
                                tracing::error!(target: "zudp::engine", "{reason}");
                                *inner.shutdown_reason.lock() = Some(reason);
                                break;
                            }
                        }
                    }
                }
            }

            _ = ticker.tick() => {
                run_background(
                    &inner, &mut recv_states, &mut relay_table, &mut relay_gen,
                    relay_ttl_ticks, &mut rate_limiter, keepalive_interval, sent_prune_age,
                );
            }
        }
    }

    // Drain in-flight retransmits before the socket closes.
    retransmit_tasks.shutdown().await;
    tracing::info!(target: "zudp::engine", "engine task exited");
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
    let now_ms = now_micros();
    let peers: Vec<Arc<PeerState>> = inner.peers.iter().map(|r| r.value().clone()).collect();
    for peer in peers {
        let ping = secure_frame(
            &peer,
            Frame::Ping {
                echo: now_ms,
                session_id: peer.my_session_id,
            },
        );
        if let Err(e) = sock.send_to(&ping, peer.addr()).await {
            tracing::warn!(target: "zudp::engine", peer = %peer.addr(), "post-rebind ping failed: {e}");
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle_incoming(
    data: BytesMut,
    from: SocketAddr,
    inner: &Arc<EngineInner>,
    inbound_tx: &mpsc::Sender<(Bytes, SocketAddr, u16)>,
    recv_states: &mut HashMap<(SocketAddr, u16), (RecvState, FragAssembler)>,
    relay_table: &mut HashMap<SocketAddr, (SocketAddr, u32)>,
    relay_gen: u32,
    retransmit_tasks: &mut JoinSet<()>,
) {
    // Stateful relay pass-through: if `from` is a server we're relaying for, forward its raw
    // reply bytes directly to the mapped client without decoding.  This is checked before
    // Frame::decode so that encrypted and opaque frames are forwarded transparently.
    if let Some(&(client_addr, _)) = relay_table.get(&from) {
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

    let known_peer = inner.peers.get(&from).map(|r| r.value().clone());
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
                let plain = {
                    let channel_guard = peer.channel.read();
                    let Some(channel) = channel_guard.as_ref() else {
                        tracing::warn!(target: "zudp::engine", peer = %from, "secure frame but no channel yet");
                        return;
                    };
                    match channel.decrypt(nonce, &ciphertext) {
                        Ok(p) => p,
                        Err(e) => {
                            tracing::warn!(target: "zudp::engine", peer = %from, "decrypt failed: {e}");
                            return;
                        }
                    }
                    // channel_guard dropped here, before the dispatch_frame await below
                };
                let inner_frame = match Frame::decode(BytesMut::from(plain.as_slice())) {
                    Ok(f) => f,
                    Err(e) => {
                        tracing::warn!(target: "zudp::engine", peer = %from, "inner frame decode failed: {e}");
                        return;
                    }
                };
                dispatch_frame(
                    inner_frame,
                    from,
                    inner,
                    inbound_tx,
                    recv_states,
                    relay_table,
                    relay_gen,
                    retransmit_tasks,
                )
                .await;
            }
            frame => {
                dispatch_frame(
                    frame,
                    from,
                    inner,
                    inbound_tx,
                    recv_states,
                    relay_table,
                    relay_gen,
                    retransmit_tasks,
                )
                .await
            }
        }
    }

    #[cfg(not(feature = "security"))]
    dispatch_frame(
        frame,
        from,
        inner,
        inbound_tx,
        recv_states,
        relay_table,
        relay_gen,
        retransmit_tasks,
    )
    .await;
}

// All parameters are genuinely distinct state that the frame dispatch needs to mutate or read;
// grouping them into a context struct would add complexity without architectural benefit.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
async fn dispatch_frame(
    frame: Frame,
    from: SocketAddr,
    inner: &Arc<EngineInner>,
    inbound_tx: &mpsc::Sender<(Bytes, SocketAddr, u16)>,
    recv_states: &mut HashMap<(SocketAddr, u16), (RecvState, FragAssembler)>,
    relay_table: &mut HashMap<SocketAddr, (SocketAddr, u32)>,
    relay_gen: u32,
    retransmit_tasks: &mut JoinSet<()>,
) {
    match frame {
        Frame::Datagram(payload) => {
            let peer = inner.get_or_create_peer(from);
            peer.rx_bytes
                .fetch_add(payload.len() as u64, std::sync::atomic::Ordering::Relaxed);
            if inbound_tx.try_send((payload, from, 0)).is_err() {
                tracing::warn!(target: "zudp::engine", %from, "inbound channel full — dropping datagram");
            }
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
            let peer = inner.get_or_create_peer(from);
            for item in ready {
                if let Inbound::Data(bytes) = item {
                    peer.rx_bytes
                        .fetch_add(bytes.len() as u64, std::sync::atomic::Ordering::Relaxed);
                    if inbound_tx.try_send((bytes, from, stream_id)).is_err() {
                        tracing::warn!(target: "zudp::engine", %from, stream_id, "inbound channel full — dropping stream frame");
                    }
                }
            }
        }

        Frame::Nack { stream_id, seqs } => {
            if let Some(peer) = inner.peers.get(&from).map(|r| r.value().clone()) {
                let to_retransmit = peer.frames_for_retransmit(stream_id, &seqs);
                if !to_retransmit.is_empty() {
                    if retransmit_tasks.len() >= MAX_RETRANSMIT_TASKS {
                        tracing::warn!(
                            target: "zudp::engine",
                            peer = %from, stream_id,
                            cap = MAX_RETRANSMIT_TASKS,
                            "retransmit pool full — dropping NACK batch"
                        );
                    } else {
                        // Spawn so the engine recv loop isn't stalled by CC pacing sleeps.
                        let sock = inner.get_socket();
                        retransmit_tasks.spawn(async move {
                            for (seq, plain_frame) in to_retransmit {
                                let wire = encrypt_or_plain(&peer, &plain_frame);
                                // Extract delay before awaiting — MutexGuard is not Send.
                                let delay = peer.cc.lock().consume(wire.len());
                                if let Some(d) = delay {
                                    tokio::time::sleep(d).await;
                                }
                                tracing::debug!(
                                    target: "zudp::engine",
                                    peer = %from, seq, stream_id,
                                    "retransmit on NACK"
                                );
                                if let Err(e) = sock.send_to(&wire, from).await {
                                    tracing::warn!(
                                        target: "zudp::engine",
                                        peer = %from,
                                        "retransmit failed: {e}"
                                    );
                                }
                            }
                        });
                    }
                }
            }
        }

        Frame::Ping { echo, session_id } => {
            let peer = find_or_migrate_peer(from, session_id, inner, recv_states);
            let pong = secure_frame(
                &peer,
                Frame::Pong {
                    echo,
                    session_id: peer.my_session_id,
                },
            );
            if let Err(e) = inner.get_socket().send_to(&pong, from).await {
                tracing::warn!(target: "zudp::engine", peer = %from, "pong failed: {e}");
            }
        }

        Frame::Pong { echo, session_id } => {
            if let Some(peer) = inner.peers.get(&from).map(|r| r.value().clone()) {
                if peer.store_their_session_id(session_id) {
                    inner.sessions.insert(session_id, peer.clone());
                }
                // echo carries a µs timestamp; RTT is the round-trip in microseconds.
                let now_us = now_micros();
                if echo <= now_us {
                    let rtt_us = now_us - echo;
                    let pacing_rate = {
                        let mut cc = peer.cc.lock();
                        cc.on_rtt_sample(rtt_us);
                        cc.pacing_rate() as u64
                    };
                    tracing::debug!(
                        target: "zudp::engine",
                        peer = %from,
                        rtt_us,
                        pacing_rate,
                        "RTT sample"
                    );
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

            let peer = inner.get_or_create_peer(from);
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
                    peer.rx_bytes
                        .fetch_add(complete.len() as u64, std::sync::atomic::Ordering::Relaxed);
                    if inbound_tx.try_send((complete, from, stream_id)).is_err() {
                        tracing::warn!(target: "zudp::engine", %from, stream_id, "inbound channel full — dropping reassembled fragment");
                    }
                }
            }
        }

        Frame::Relay {
            dest,
            inner: payload,
        } => {
            // Read relay policy atomically — policy may be updated at runtime.
            let (policy_allowlist, policy_max) = {
                let p = inner.relay_policy.read();
                (p.allowlist.clone(), p.max_entries)
            };
            // Allowlist check: if non-empty, only listed IPs may use this node as a relay.
            if !policy_allowlist.is_empty() && !policy_allowlist.contains(&from.ip()) {
                tracing::warn!(target: "zudp::engine", %from, "relay denied — not in allowlist");
                inner.dropped_relay_blocked.fetch_add(1, Ordering::Relaxed);
                return;
            }
            // Cap relay table size to prevent unbounded memory growth under abuse.
            if !relay_table.contains_key(&dest) && relay_table.len() >= policy_max {
                tracing::warn!(target: "zudp::engine", "relay table full — dropping entry for {dest}");
                inner.dropped_relay_cap.fetch_add(1, Ordering::Relaxed);
                return;
            }
            // Record client→server mapping so replies from `dest` can be routed back to `from`.
            // Upsert refreshes the generation counter — zero syscall cost.
            relay_table
                .entry(dest)
                .and_modify(|(stored_from, last_gen)| {
                    *stored_from = from;
                    *last_gen = relay_gen;
                })
                .or_insert((from, relay_gen));
            tracing::trace!(target: "zudp::engine", client = %from, server = %dest, "relay client → server");
            if let Err(e) = inner.get_socket().send_to(&payload, dest).await {
                tracing::warn!(target: "zudp::engine", %dest, "relay forward failed: {e}");
            }
        }

        Frame::MtuProbe { probe_id, .. } => {
            // Reflect probe_id in a tiny MtuAck — always gets through regardless of path MTU.
            let ack_frame = Frame::MtuAck { probe_id };
            let ack = if let Some(peer) = inner.peers.get(&from).map(|r| r.value().clone()) {
                secure_frame(&peer, ack_frame)
            } else {
                ack_frame.encode()
            };
            if let Err(e) = inner.get_socket().send_to(&ack, from).await {
                tracing::warn!(target: "zudp::engine", peer = %from, "mtu ack send failed: {e}");
            }
        }

        Frame::MtuAck { probe_id } => {
            if let Some(peer) = inner.peers.get(&from).map(|r| r.value().clone())
                && let Some(tx) = peer.probe_acks.lock().remove(&probe_id)
            {
                let _ = tx.send(());
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
    if let Some(peer) = inner.peers.get(&from).map(|r| r.value().clone()) {
        if peer.store_their_session_id(session_id) {
            inner.sessions.insert(session_id, peer.clone());
        }
        return peer;
    }

    // Migration: known session but new address.
    if let Some(peer) = inner.sessions.get(&session_id).map(|r| r.value().clone()) {
        let old_addr = peer.addr();
        if old_addr != from {
            tracing::info!(
                target: "zudp::engine",
                old = %old_addr,
                new = %from,
                "peer address migrated"
            );
            peer.migrate_to(from);
            inner.peers.remove(&old_addr);
            inner.peers.insert(from, peer.clone());
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
            // Path has changed — reset discovered MTU and re-probe.
            peer.set_effective_mtu(0);
            spawn_mtu_probe(inner, from);
        }
        return peer;
    }

    // First contact: create peer, register session, and discover path MTU.
    let peer = inner.get_or_create_peer(from);
    peer.store_their_session_id(session_id);
    inner.sessions.insert(session_id, peer.clone());
    spawn_mtu_probe(inner, from);
    peer
}

/// Fire-and-forget PLPMTUD probe toward `peer_addr`.
///
/// Spawned on first contact and on every migration so the server always knows the usable path
/// MTU — not just the client side (which probes inside `connect()`).
fn spawn_mtu_probe(inner: &Arc<EngineInner>, peer_addr: SocketAddr) {
    let inner = inner.clone();
    let initial_mtu = inner.config.mtu;
    let max_mtu = inner.config.max_mtu;
    let _mtu_probe = tokio::spawn(async move {
        let discovered = crate::mtu::probe(&inner, peer_addr, initial_mtu, max_mtu).await;
        if let Some(p) = inner.peers.get(&peer_addr) {
            p.set_effective_mtu(discovered);
        }
        tracing::info!(
            target: "zudp::mtu",
            peer = %peer_addr,
            mtu = discovered,
            "path MTU discovered"
        );
    });
}

/// Encode `frame` and encrypt it for `peer` if an established Noise channel exists.
///
/// Falls back to plaintext when called before the handshake completes or when the
/// `security` feature is disabled.  All post-handshake control frames (Ping, Pong,
/// Nack, `MtuAck`) go through this so passive observers cannot read session metadata.
fn secure_frame(peer: &PeerState, frame: Frame) -> Bytes {
    let plain = frame.encode();
    encrypt_or_plain(peer, &plain)
}

/// If the peer has an established Noise channel, re-encrypt the plain frame; otherwise send as-is.
///
/// Used for NACK-triggered retransmits: each retransmit gets a fresh nonce to avoid reuse.
#[allow(unused_variables)]
fn encrypt_or_plain(peer: &PeerState, plain: &Bytes) -> Bytes {
    #[cfg(feature = "security")]
    {
        let guard = peer.channel.read();
        if let Some(channel) = guard.as_ref() {
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
    let nack = Frame::Nack {
        stream_id,
        seqs: nack_seqs,
    };
    let wire = if let Some(peer) = inner.peers.get(&to).map(|r| r.value().clone()) {
        secure_frame(&peer, nack)
    } else {
        nack.encode()
    };
    if let Err(e) = inner.get_socket().send_to(&wire, to).await {
        tracing::warn!(target: "zudp::engine", peer = %to, "nack send failed: {e}");
    }
}

#[allow(clippy::too_many_arguments)]
fn run_background(
    inner: &Arc<EngineInner>,
    recv_states: &mut HashMap<(SocketAddr, u16), (RecvState, FragAssembler)>,
    relay_table: &mut HashMap<SocketAddr, (SocketAddr, u32)>,
    relay_gen: &mut u32,
    relay_ttl_ticks: u32,
    rate_limiter: &mut crate::rate::RateLimiter,
    keepalive_interval: Duration,
    sent_prune_age: Duration,
) {
    let keepalive_threshold = keepalive_interval.as_secs();
    let now_ms = now_micros();

    let peers: Vec<Arc<PeerState>> = inner.peers.iter().map(|r| r.value().clone()).collect();

    for peer in peers {
        if peer.secs_since_sent() >= keepalive_threshold {
            // Spawn each keepalive independently so sequential `send_to` calls
            // don't stall the recv loop when many peers need pinging at once.
            let sock = inner.get_socket();
            let peer_clone = peer.clone();
            tokio::spawn(async move {
                let addr = peer_clone.addr();
                let ping = secure_frame(
                    &peer_clone,
                    Frame::Ping {
                        echo: now_ms,
                        session_id: peer_clone.my_session_id,
                    },
                );
                if let Err(e) = sock.send_to(&ping, addr).await {
                    tracing::warn!(target: "zudp::engine", peer = %addr, "keepalive failed: {e}");
                }
                tracing::trace!(target: "zudp::engine", peer = %addr, "sent keepalive ping");
            });
        }
        peer.prune_sent(sent_prune_age);
    }

    for ((addr, stream_id), (recv, frag_assembler)) in recv_states.iter_mut() {
        frag_assembler.prune(sent_prune_age);
        if recv.prune_gap(sent_prune_age) {
            tracing::warn!(
                target: "zudp::engine",
                peer = %addr,
                stream_id,
                "gap timeout — missing seq discarded, stream resyncing"
            );
        }
    }

    // Advance the relay generation counter and prune stale entries.
    // Wrapping arithmetic is intentional — correct over the ~170-year u32 lifetime.
    *relay_gen = relay_gen.wrapping_add(1);
    let current_gen = *relay_gen;
    relay_table
        .retain(|_, (_, last_seen_gen)| current_gen.wrapping_sub(*last_seen_gen) < relay_ttl_ticks);

    rate_limiter.tick_prune();
}

fn now_micros() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0u64, |d| u64::try_from(d.as_micros()).unwrap_or(u64::MAX))
}

/// Drive a Noise XX handshake step on behalf of the engine.
///
/// - If no handshake exists for `from` yet, creates a responder state (server role).
/// - If a handshake already exists (initiator stored it before sending msg1), reads the
///   incoming message and, if it's the initiator's turn, writes the next message.
/// - When both sides finish all three messages, transitions to `StatelessTransportState`.
/// - If `inner.config.remote_key` is set, the remote's static key is verified after the
///   handshake finishes.  A mismatch silently aborts — no channel is established and
///   `connect()` will time out on the other side.
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
    // Returns (optional reply, optional finished handshake, key_mismatch).
    let outcome = 'step: {
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
            // Key pinning check — must happen before consuming state.
            if !check_pinned_key(hs, inner, from) {
                let _ = guard.take();
                break 'step (None::<Bytes>, None, true);
            }
            let hs_owned = guard.take().unwrap();
            break 'step (None, Some(hs_owned), false);
        }

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
        if finished_after_write {
            // Key pinning check — must happen before consuming state.
            if !check_pinned_key(hs, inner, from) {
                let _ = guard.take();
                // Don't send msg3 either — abort silently.
                break 'step (None, None, true);
            }
        }

        let hs_owned = if finished_after_write {
            guard.take()
        } else {
            None
        };
        (Some(reply), hs_owned, false)
    }; // handshake lock released

    let (reply, finished_hs, key_mismatch) = outcome;

    if key_mismatch {
        tracing::warn!(target: "zudp::security", peer = %from, "handshake aborted — key mismatch");
        return;
    }

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
        // Extract and persist the remote static key before consuming the handshake state.
        if let Some(remote) = hs.get_remote_static() {
            let mut key = [0u8; 32];
            key.copy_from_slice(remote);
            // `set` is a no-op if already initialised; safe to ignore the result.
            let _ = peer.remote_static_key.set(key);
        }
        match hs.into_stateless_transport_mode() {
            Ok(transport) => {
                *peer.channel.write() = Some(SecureChannel::new(transport));
                // Unblock connect() which may be waiting for encryption to be active.
                peer.channel_ready.notify_one();
                tracing::info!(target: "zudp::engine", peer = %from, "Noise XX handshake complete");
            }
            Err(e) => {
                tracing::error!(target: "zudp::engine", peer = %from, "into_transport_mode: {e}");
            }
        }
    }
}

/// Check the remote's static key against the pinned key in config.
///
/// Returns `true` if the key is acceptable (no pinning, or pinned key matches).
/// Returns `false` and logs a warning if the key is pinned and doesn't match.
/// Must be called while the `HandshakeState` is still active (before consuming it).
#[cfg(feature = "security")]
fn check_pinned_key(hs: &snow::HandshakeState, inner: &Arc<EngineInner>, from: SocketAddr) -> bool {
    let Some(expected) = &inner.config.remote_key else {
        return true;
    };
    match hs.get_remote_static() {
        Some(remote) if remote == expected.as_slice() => true,
        Some(_) => {
            tracing::warn!(target: "zudp::security", peer = %from, "key mismatch — remote key does not match pinned key");
            false
        }
        None => {
            tracing::warn!(target: "zudp::security", peer = %from, "key pinning: remote static not available");
            false
        }
    }
}
