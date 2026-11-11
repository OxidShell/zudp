use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::Duration,
};

use bytes::{Bytes, BytesMut};
use dashmap::DashMap;
use parking_lot::{Mutex, RwLock};
use tokio::{sync::mpsc, task::JoinSet, time};

use crate::{
    Config, PeerAddr,
    event::{DisconnectReason, PeerEvent},
    frag::FragAssembler,
    frame::Frame,
    peer::{Inbound, PeerState, RecvState},
    socket::{self, RawSocket},
};

/// Maximum concurrent NACK retransmit tasks across the engine.
///
/// Each task handles one NACK batch (one peer, one burst of missing seqs).  Capping
/// prevents memory/CPU runaway when a peer floods NACKs faster than retransmits drain.
const MAX_RETRANSMIT_TASKS: usize = 32;

/// Tail-loss probes sent per idle period before giving up (backoff doubles each time).
const TAIL_PROBES: u32 = 3;
/// Probe timeout bounds: `2 × srtt`, clamped; [`TAIL_PROBE_DEFAULT`] before the first RTT sample.
const TAIL_PROBE_MIN: Duration = Duration::from_millis(10);
const TAIL_PROBE_MAX: Duration = Duration::from_secs(1);
const TAIL_PROBE_DEFAULT: Duration = Duration::from_millis(100);

/// Capacity of the bounded inbound channel between the engine task and the socket handle.
///
/// At 1 400 B/frame and 8 192 slots this is ~11 MB peak backpressure before the engine
/// starts dropping frames.  The engine uses `try_send` so the recv loop is never stalled.
const INBOUND_CAP: usize = 8_192;

/// Consecutive hard receive errors before an ephemeral-port socket is replaced.
const REBIND_AFTER_ERRORS: u32 = 10;
/// Handshake frames accepted per second per source IP, separate from the data budget.
const HANDSHAKE_PPS_PER_IP: f64 = 20.0;

/// Back-off unit between retries after a hard receive error.
const RECV_ERROR_BACKOFF: Duration = Duration::from_millis(20);

/// Smallest per-stream receive window, whatever `sent_buffer_frames` is set to.
const MIN_RECV_WINDOW: usize = 1_024;

/// Receive side of one (peer, stream).
pub(crate) struct StreamRx {
    /// [`PeerState::generation`] this state belongs to; a mismatch means the peer was reset.
    generation: u64,
    recv: RecvState,
    frag: FragAssembler,
}

pub(crate) type RecvStates = HashMap<(PeerAddr, u16), StreamRx>;

/// State shared between the engine task and the [`crate::ZudpSocket`] / [`crate::ZudpConn`] handles.
pub(crate) struct EngineInner {
    /// Current socket; replaced atomically on rebind.  Use [`get_socket`] to obtain a cheap clone.
    pub socket: RwLock<RawSocket>,
    pub peers: DashMap<PeerAddr, Arc<PeerState>>,
    /// Reverse index: remote engine instance id → peer, for detecting address migrations.
    pub sessions: DashMap<u64, Arc<PeerState>>,
    /// Random id of this engine, sent in every Ping and Pong.
    pub instance_id: u64,
    /// Lifecycle notifications; see [`PeerEvent`].
    pub events: tokio::sync::broadcast::Sender<PeerEvent>,
    pub config: Arc<Config>,
    /// Noise keypair for the `security` feature; `None` when security is disabled.
    #[cfg(feature = "security")]
    pub keypair: Option<crate::security::Keypair>,
    /// Set by the engine task before it exits; callers read this to distinguish a
    /// clean shutdown from an unexpected crash (rebind failure, etc.).
    pub shutdown_reason: Mutex<Option<String>>,
    pub dropped_rate_limited: AtomicU64,
    pub dropped_peer_cap: AtomicU64,
    /// Plaintext data frames dropped because a keypair is configured.
    pub dropped_unauthenticated: AtomicU64,
    /// Set when a reliable stream could not deliver because the inbound channel was full;
    /// the engine then waits for capacity and drains every stream.
    pub delivery_stalled: AtomicBool,
    /// Handshakes in progress, keyed by remote address.
    #[cfg(feature = "security")]
    pub pending: Mutex<crate::handshake::PendingMap>,
    /// Our session index → peer, so Secure frames find their session from any address.
    #[cfg(feature = "security")]
    pub by_index: DashMap<u64, Arc<PeerState>>,
    /// Budget for `SessionUnknown` replies per source IP.
    #[cfg(feature = "security")]
    pub hint_limiter: Mutex<crate::rate::RateLimiter<PeerAddr>>,
    /// Remote static key → direct session, so a relay node finds the client a key names.
    #[cfg(feature = "security")]
    pub by_key: DashMap<[u8; 32], Arc<PeerState>>,
    /// Punched direct address → the relayed peer whose traffic now arrives from it.
    #[cfg(feature = "security")]
    pub punched: DashMap<SocketAddr, Arc<PeerState>>,
    /// Relayed frames dropped because the relay's sender claim did not match the session.
    pub dropped_forged: AtomicU64,
    /// Relayed frames dropped because they came through a relay we never accepted.
    pub dropped_relay_unaccepted: AtomicU64,
    /// Relays allowed to deliver new inbound relayed sessions to us.
    #[cfg(feature = "security")]
    pub inbound_relays: RwLock<std::collections::HashSet<SocketAddr>>,
    /// Static keys of relayed peers the application approved for hole punching.
    #[cfg(feature = "security")]
    pub punch_allowed: RwLock<std::collections::HashSet<[u8; 32]>>,
    /// Budget for relayed handshake initiations per relay IP.
    #[cfg(feature = "security")]
    pub relayed_hs_limiter: Mutex<crate::rate::RateLimiter>,
    /// Relay node state; `Some` when built with [`crate::Zudp::relay_node`].
    #[cfg(feature = "relay")]
    pub relay: Option<crate::relay::node::RelayNode>,
}

impl EngineInner {
    /// Cheap handle to the current socket (clones the inner `Arc<UdpSocket>`).
    pub fn get_socket(&self) -> RawSocket {
        self.socket.read().clone()
    }

    /// `true` when a Noise keypair is configured.
    #[cfg_attr(not(feature = "security"), allow(clippy::unused_self))]
    pub fn secured(&self) -> bool {
        #[cfg(feature = "security")]
        {
            self.keypair.is_some()
        }
        #[cfg(not(feature = "security"))]
        {
            false
        }
    }

    pub fn get_or_create_peer(self: &Arc<Self>, addr: PeerAddr) -> Arc<PeerState> {
        self.peer_for_incoming(addr).0
    }

    /// Like [`get_or_create_peer`](Self::get_or_create_peer); also says whether it was created.
    pub fn peer_for_incoming(self: &Arc<Self>, addr: PeerAddr) -> (Arc<PeerState>, bool) {
        if let Some(p) = self.peers.get(&addr) {
            return (p.value().clone(), false);
        }
        self.make_room(addr);
        let mut created = false;
        let peer = self
            .peers
            .entry(addr)
            .or_insert_with(|| {
                created = true;
                Arc::new(PeerState::new(addr))
            })
            .value()
            .clone();
        (peer, created)
    }

    /// Start a new session state for `addr`, dropping everything the old one carried.
    ///
    /// Sequence counters, send buffers, receive state, fragments, congestion state, keys and
    /// the session-id index all belong to one remote incarnation; reusing them across a
    /// restart makes the new incarnation's frames look stale.
    pub fn replace_peer(&self, addr: PeerAddr) -> Arc<PeerState> {
        if !self.peers.contains_key(&addr) {
            self.make_room(addr);
        }
        let fresh = Arc::new(match self.peers.get(&addr) {
            Some(old) => PeerState::with_addr(old.addr_arc()),
            None => PeerState::new(addr),
        });
        if let Some(old) = self.peers.insert(addr, fresh.clone()) {
            self.unindex(&old);
        }
        fresh
    }

    /// Keep the peer table under `max_peers` before `new` is added: evict the least
    /// recently seen peer when it is full.
    fn make_room(&self, new: PeerAddr) {
        if self.evict_lru(new, self.config.max_peers, |_| true) {
            self.dropped_peer_cap.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// When at least `cap` peers match `pred`, evict the least recently seen of them to make
    /// room for `new`.  Returns `true` when a peer was evicted.
    pub fn evict_lru(&self, new: PeerAddr, cap: usize, pred: impl Fn(&PeerAddr) -> bool) -> bool {
        if self.peers.iter().filter(|r| pred(r.key())).count() < cap.max(1) {
            return false;
        }
        let Some(evict) = self
            .peers
            .iter()
            .filter(|r| pred(r.key()) && *r.key() != new)
            .min_by_key(|r| *r.value().last_seen.lock())
            .map(|r| *r.key())
        else {
            return false;
        };
        tracing::warn!(
            target: "zudp::engine",
            evicted = %evict,
            %new,
            "peer cap reached — evicting least-recently-seen peer"
        );
        self.forget_peer(evict);
        self.emit(PeerEvent::Disconnected {
            addr: evict,
            reason: DisconnectReason::Evicted,
        });
        true
    }

    /// Remove `addr` and every index entry pointing at it.  Returns the removed state.
    pub fn forget_peer(&self, addr: PeerAddr) -> Option<Arc<PeerState>> {
        let (_, old) = self.peers.remove(&addr)?;
        self.unindex(&old);
        Some(old)
    }

    pub fn unindex(&self, old: &Arc<PeerState>) {
        #[cfg(feature = "security")]
        if let Some(index) = old.local_index() {
            self.by_index.remove_if(&index, |_, p| Arc::ptr_eq(p, old));
        }
        if let Some(id) = old.their_session_id() {
            self.sessions.remove_if(&id, |_, p| Arc::ptr_eq(p, old));
        }
        #[cfg(feature = "security")]
        {
            if let Some(key) = old.remote_static_key()
                && self
                    .by_key
                    .remove_if(&key, |_, p| Arc::ptr_eq(p, old))
                    .is_some()
            {
                #[cfg(feature = "relay")]
                if let Some(node) = &self.relay {
                    node.forget_client(&key);
                }
            }
            if let Some(direct) = old.direct_path() {
                self.punched.remove_if(&direct, |_, p| Arc::ptr_eq(p, old));
            }
        }
    }

    /// Publish a lifecycle event; nobody listening is fine.
    pub fn emit(&self, event: PeerEvent) {
        let _ = self.events.send(event);
    }

    /// Drop `addr` on request.  Returns `false` when there was no such peer.
    pub fn remove_peer(&self, addr: PeerAddr) -> bool {
        #[cfg(feature = "security")]
        self.pending.lock().remove(&addr);
        if self.forget_peer(addr).is_none() {
            return false;
        }
        self.emit(PeerEvent::Disconnected {
            addr,
            reason: DisconnectReason::Removed,
        });
        true
    }

    /// `true` while `peer` is still the live state for its address.
    pub fn is_current(&self, peer: &Arc<PeerState>) -> bool {
        self.peers
            .get(&peer.addr())
            .is_some_and(|p| Arc::ptr_eq(p.value(), peer))
    }

    /// The datagram that carries `wire` to `peer` along its current path, and where to
    /// send it.  `None` when the path is gone (a relayed peer whose relay session ended).
    pub fn outbound(&self, peer: &PeerState, wire: Bytes) -> Option<(Bytes, SocketAddr)> {
        #[cfg(feature = "security")]
        if let Some(direct) = peer.direct_path() {
            return Some((wire, direct));
        }
        self.outbound_to(peer.addr(), wire)
    }

    /// Like [`outbound`](Self::outbound) for a peer that may have no state yet (handshakes).
    pub fn outbound_to(&self, to: PeerAddr, wire: Bytes) -> Option<(Bytes, SocketAddr)> {
        match to {
            PeerAddr::Direct(addr) => Some((wire, addr)),
            #[cfg(feature = "security")]
            PeerAddr::Relayed { relay, key } => crate::relay::via(self, relay, key, wire),
            #[cfg(not(feature = "security"))]
            PeerAddr::Relayed { .. } => None,
        }
    }

    /// Send `wire` to `peer` along its current path (a punched direct path included),
    /// logging a failure.
    pub async fn send_to_peer(&self, peer: &PeerState, wire: Bytes, what: &'static str) {
        let routed = self.outbound(peer, wire);
        self.send_routed(peer.addr(), routed, what).await;
    }

    /// Like [`send_to_peer`](Self::send_to_peer) for a peer that may have no state yet.
    pub async fn send_to_addr(&self, to: PeerAddr, wire: Bytes, what: &'static str) {
        let peer = self.peers.get(&to).map(|r| r.value().clone());
        match peer {
            Some(peer) => self.send_to_peer(&peer, wire, what).await,
            None => self.send_handshake(to, wire, what).await,
        }
    }

    /// Send a handshake message to `to`: always along the handle's own route (through the
    /// relay for a relayed peer), never along a punched path, which belongs to the session
    /// being replaced.
    pub async fn send_handshake(&self, to: PeerAddr, wire: Bytes, what: &'static str) {
        let routed = self.outbound_to(to, wire);
        self.send_routed(to, routed, what).await;
    }

    async fn send_routed(
        &self,
        to: PeerAddr,
        routed: Option<(Bytes, SocketAddr)>,
        what: &'static str,
    ) {
        let Some((datagram, dest)) = routed else {
            tracing::debug!(target: "zudp::engine", peer = %to, what, "no path to peer");
            return;
        };
        if let Err(e) = self.get_socket().send_to(&datagram, dest).await {
            tracing::warn!(target: "zudp::engine", peer = %to, what, "send failed: {e}");
        }
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
) -> mpsc::Receiver<(Bytes, PeerAddr, u16)> {
    let (inbound_tx, inbound_rx) = mpsc::channel(INBOUND_CAP);
    tokio::spawn(run(inner, inbound_tx, shutdown_rx));
    inbound_rx
}

async fn run(
    inner: Arc<EngineInner>,
    inbound_tx: mpsc::Sender<(Bytes, PeerAddr, u16)>,
    mut shutdown_rx: tokio::sync::oneshot::Receiver<()>,
) {
    // Keyed by (peer_addr, stream_id) so each stream has independent reorder + reassembly.
    let mut recv_states: RecvStates = HashMap::new();
    let keepalive_interval = inner.config.keepalive_interval;
    let sent_prune_age = inner.config.sent_prune_age;

    let mut rate_limiter = crate::rate::RateLimiter::new(
        inner.config.max_pps_per_ip,
        (inner.config.max_pps_per_ip / 5.0).max(1.0),
    );

    // Bounded pool for NACK retransmit tasks.  Each task may sleep for CC pacing, so
    // they are spawned off the recv loop to avoid stalling it — but the pool is capped
    // to prevent unbounded task accumulation under heavy loss or adversarial NACKs.
    // Handshakes get their own budget so a data flood from an IP cannot starve that IP's
    // reconnect, while a handshake flood still cannot exhaust the engine.
    let mut handshake_limiter =
        crate::rate::RateLimiter::new(HANDSHAKE_PPS_PER_IP, HANDSHAKE_PPS_PER_IP);

    let mut retransmit_tasks: JoinSet<()> = JoinSet::new();

    // Local recv socket; replaced in-place when the socket is rebound.
    let mut recv_sock = inner.get_socket();
    let mut recv_errors: u32 = 0;

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
                        recv_errors = 0;
                        let limiter = if is_handshake(&data) {
                            &mut handshake_limiter
                        } else {
                            &mut rate_limiter
                        };
                        // Addresses that completed a handshake are not throttled; the budget is
                        // for traffic nobody has authenticated yet.
                        let trusted = inner
                            .peers
                            .get(&PeerAddr::Direct(from))
                            .is_some_and(|p| p.has_channel())
                            || is_punched(&inner, from);
                        if inner.config.max_pps_per_ip > 0.0 && !trusted && !limiter.allow(from.ip()) {
                            tracing::trace!(target: "zudp::engine", %from, "rate limited");
                            inner.dropped_rate_limited.fetch_add(1, Ordering::Relaxed);
                            continue;
                        }
                        handle_incoming(
                            data, from, &inner, &inbound_tx,
                            &mut recv_states,
                            &mut retransmit_tasks,
                        ).await;
                    }
                    Err(e) if socket::is_transient_recv_error(&e) => {
                        tracing::debug!(target: "zudp::engine", "transient recv error ignored: {e}");
                    }
                    Err(e) => {
                        recv_errors += 1;
                        tracing::warn!(target: "zudp::engine", errors = recv_errors, "recv error: {e}");
                        if recv_errors < REBIND_AFTER_ERRORS || inner.config.port != 0 {
                            // A requested port is never given up: keep retrying the socket.
                            time::sleep(RECV_ERROR_BACKOFF * recv_errors.min(50)).await;
                            continue;
                        }
                        recv_errors = 0;
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

            permit = inbound_tx.reserve(), if inner.delivery_stalled.load(Ordering::Relaxed) => {
                drop(permit);
                inner.delivery_stalled.store(false, Ordering::Relaxed);
                drain_all_streams(&inner, &mut recv_states, &inbound_tx);
            }

            _ = ticker.tick() => {
                run_background(
                    &inner, &mut recv_states, &mut rate_limiter, keepalive_interval, sent_prune_age,
                );
            }
        }
    }

    // Drain in-flight retransmits before the socket closes.
    retransmit_tasks.shutdown().await;
    tracing::info!(target: "zudp::engine", "engine task exited");
}

/// Replace a failing ephemeral-port socket with a fresh one on a new ephemeral port.
///
/// On success, replaces `inner.socket` so future `send_to` calls use the new interface.
async fn rebind_socket(inner: &Arc<EngineInner>) -> Result<RawSocket, crate::Error> {
    let old_local = inner.get_socket().local_addr()?;
    let mut new_sock = RawSocket::bind(SocketAddr::new(old_local.ip(), 0)).await?;
    new_sock.adopt_blocklist(&inner.get_socket());
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
        let Some(ping) = secure_frame(
            inner,
            &peer,
            Frame::Ping {
                echo: now_ms,
                session_id: inner.instance_id,
            },
        ) else {
            continue;
        };
        let Some((datagram, dest)) = inner.outbound(&peer, ping) else {
            continue;
        };
        if let Err(e) = sock.send_to(&datagram, dest).await {
            tracing::warn!(target: "zudp::engine", peer = %peer.addr(), "post-rebind ping failed: {e}");
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle_incoming(
    data: BytesMut,
    from: SocketAddr,
    inner: &Arc<EngineInner>,
    inbound_tx: &mpsc::Sender<(Bytes, PeerAddr, u16)>,
    recv_states: &mut RecvStates,
    retransmit_tasks: &mut JoinSet<()>,
) {
    let frame = match Frame::decode(data) {
        Ok(f) => f,
        Err(e) => {
            tracing::warn!(target: "zudp::engine", peer = %from, "bad frame: {e}");
            return;
        }
    };

    let known_peer = inner
        .peers
        .get(&PeerAddr::Direct(from))
        .map(|r| r.value().clone());
    // On a secured socket only authenticated frames count as signs of life.
    if let Some(peer) = &known_peer
        && !inner.secured()
    {
        peer.mark_seen();
    }

    #[cfg(feature = "security")]
    {
        match frame {
            Frame::Handshake {
                step,
                version,
                payload,
            } => {
                handle_handshake(step, version, &payload, PeerAddr::Direct(from), inner).await;
            }
            Frame::Secure {
                index,
                nonce,
                ciphertext,
            } => {
                let Some((peer, inner_frame)) =
                    open_secure(inner, from, index, nonce, &ciphertext, recv_states).await
                else {
                    return;
                };
                let Some((peer, inner_frame)) = crate::relay::open(inner, peer, inner_frame).await
                else {
                    return;
                };
                // Dispatch under the session's (possibly just migrated) address so a late
                // datagram from the old address does not split its state.
                dispatch_frame(
                    inner_frame,
                    peer.addr(),
                    inner,
                    inbound_tx,
                    recv_states,
                    retransmit_tasks,
                )
                .await;
            }
            Frame::SessionUnknown { index } => {
                on_session_unknown(inner, PeerAddr::Direct(from), index);
            }
            frame => {
                if inner.secured() && !plaintext_allowed(&frame) {
                    tracing::trace!(target: "zudp::engine", peer = %from, "plaintext frame on a secured socket dropped");
                    inner
                        .dropped_unauthenticated
                        .fetch_add(1, Ordering::Relaxed);
                    return;
                }
                dispatch_frame(
                    frame,
                    PeerAddr::Direct(from),
                    inner,
                    inbound_tx,
                    recv_states,
                    retransmit_tasks,
                )
                .await;
            }
        }
        announce_plain_peer(inner, PeerAddr::Direct(from));
    }

    #[cfg(not(feature = "security"))]
    dispatch_frame(
        frame,
        PeerAddr::Direct(from),
        inner,
        inbound_tx,
        recv_states,
        retransmit_tasks,
    )
    .await;

    #[cfg(not(feature = "security"))]
    announce_plain_peer(inner, PeerAddr::Direct(from));
}

// All parameters are genuinely distinct state that the frame dispatch needs to mutate or read;
// grouping them into a context struct would add complexity without architectural benefit.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
async fn dispatch_frame(
    frame: Frame,
    from: PeerAddr,
    inner: &Arc<EngineInner>,
    inbound_tx: &mpsc::Sender<(Bytes, PeerAddr, u16)>,
    recv_states: &mut RecvStates,
    retransmit_tasks: &mut JoinSet<()>,
) {
    match frame {
        Frame::Datagram(payload) => {
            let peer = data_peer(inner, from).await;
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
            let peer = data_peer(inner, from).await;
            ingest_reliable(
                inner,
                &peer,
                from,
                stream_id,
                seq,
                Inbound::Data(payload),
                recv_states,
                inbound_tx,
            )
            .await;
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
                        let wires: Vec<(u64, Bytes, SocketAddr)> = to_retransmit
                            .into_iter()
                            .filter_map(|(seq, plain)| {
                                let (wire, dest) =
                                    inner.outbound(&peer, seal(inner, &peer, &plain)?)?;
                                Some((seq, wire, dest))
                            })
                            .collect();
                        retransmit_tasks.spawn(async move {
                            for (seq, wire, dest) in wires {
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
                                if let Err(e) = sock.send_to(&wire, dest).await {
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
            let Some(peer) = observe_session(from, session_id, inner, recv_states, true) else {
                return;
            };
            let Some(pong) = secure_frame(
                inner,
                &peer,
                Frame::Pong {
                    echo,
                    session_id: inner.instance_id,
                },
            ) else {
                return;
            };
            peer.mark_sent();
            inner.send_to_peer(&peer, pong, "pong").await;
        }

        Frame::Pong { echo, session_id } => {
            if let Some(peer) = observe_session(from, session_id, inner, recv_states, false) {
                // echo carries a µs timestamp; RTT is the round-trip in microseconds.
                let now_us = now_micros();
                if echo <= now_us {
                    let rtt_us = now_us - echo;
                    let pacing_rate = {
                        let mut cc = peer.cc.lock();
                        cc.on_rtt_sample(rtt_us);
                        // Bounded to [10_000, 100_000_000] by the controller.
                        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
                        let rate = cc.pacing_rate() as u64;
                        rate
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
            let peer = data_peer(inner, from).await;
            let inbound = Inbound::Fragment {
                msg_id,
                frag_idx,
                frag_total,
                data: payload,
            };
            ingest_reliable(
                inner,
                &peer,
                from,
                stream_id,
                seq,
                inbound,
                recv_states,
                inbound_tx,
            )
            .await;
        }

        Frame::MtuProbe { probe_id, .. } => {
            // Reflect probe_id in a tiny MtuAck — always gets through regardless of path MTU.
            // Plaintext when there is no session: the ack reveals nothing and probes precede it.
            let ack = inner
                .peers
                .get(&from)
                .and_then(|peer| secure_frame(inner, &peer, Frame::MtuAck { probe_id }))
                .unwrap_or_else(|| Frame::MtuAck { probe_id }.encode());
            inner.send_to_addr(from, ack, "mtu ack").await;
        }

        Frame::MtuAck { probe_id } => {
            if let Some(peer) = inner.peers.get(&from).map(|r| r.value().clone())
                && let Some(tx) = peer.probe_acks.lock().remove(&probe_id)
            {
                let _ = tx.send(());
            }
        }

        Frame::Probe { .. } | Frame::Beacon { .. } => {}

        // Relay frames only mean something inside a session with a direct peer, where
        // `relay::open` consumed them; plaintext ones are noise.
        // Path validation is handled where a relayed peer's direct frames are opened.
        #[cfg(feature = "security")]
        Frame::Via { .. }
        | Frame::ViaFrom { .. }
        | Frame::Unreachable { .. }
        | Frame::IntroRequest { .. }
        | Frame::Intro { .. }
        | Frame::PathChallenge { .. }
        | Frame::PathResponse { .. } => {}

        // Handshake and Secure are handled before dispatch_frame is called.
        #[cfg(feature = "security")]
        Frame::Handshake { .. } | Frame::Secure { .. } | Frame::SessionUnknown { .. } => {}
    }
}

/// Match the engine instance id in a Ping or Pong from `from` to a peer.
///
/// Handles first contact, a familiar address, a restarted remote on the same address (its
/// state is reset), and a known remote seen from a new address (migration).  Returns
/// `None` only when `create` is false and nothing matched.
fn observe_session(
    from: PeerAddr,
    session_id: u64,
    inner: &Arc<EngineInner>,
    recv_states: &mut RecvStates,
    create: bool,
) -> Option<Arc<PeerState>> {
    if from.is_relayed() {
        // A relayed session is bounded by its handshake and never moves by instance id; the
        // same remote may well hold a direct session too, which owns its id in `sessions`.
        let peer = inner.peers.get(&from).map(|r| r.value().clone())?;
        peer.set_their_session_id(session_id);
        return Some(peer);
    }
    if let Some(peer) = inner.peers.get(&from).map(|r| r.value().clone()) {
        match peer.their_session_id() {
            Some(known) if known == session_id => return Some(peer),
            None => {
                // A state made by a data frame before the remote's id was known: if that id
                // belongs to a peer at another address, it is that peer arriving from here.
                if let Some(moved) = inner
                    .sessions
                    .get(&session_id)
                    .map(|r| r.value().clone())
                    .filter(|p| !Arc::ptr_eq(p, &peer) && p.addr() != from)
                {
                    migrate_peer(inner, &moved, from, recv_states);
                    return Some(moved);
                }
                peer.set_their_session_id(session_id);
                inner.sessions.insert(session_id, peer.clone());
                return Some(peer);
            }
            Some(_) if inner.secured() => {
                // With Noise, sessions are bounded by handshakes, not by this id.
                peer.set_their_session_id(session_id);
                inner.sessions.insert(session_id, peer.clone());
                return Some(peer);
            }
            Some(previous) => {
                tracing::info!(
                    target: "zudp::engine",
                    peer = %from,
                    previous,
                    current = session_id,
                    "remote restarted — resetting its session"
                );
                let fresh = inner.replace_peer(from);
                fresh.set_their_session_id(session_id);
                fresh.announce();
                inner.emit(PeerEvent::Reset {
                    addr: from,
                    key: None,
                });
                inner.sessions.insert(session_id, fresh.clone());
                return Some(fresh);
            }
        }
    }

    if let Some(peer) = inner.sessions.get(&session_id).map(|r| r.value().clone()) {
        migrate_peer(inner, &peer, from, recv_states);
        return Some(peer);
    }

    if !create {
        return None;
    }
    let peer = inner.get_or_create_peer(from);
    peer.set_their_session_id(session_id);
    inner.sessions.insert(session_id, peer.clone());
    if let PeerAddr::Direct(addr) = from {
        spawn_mtu_probe(inner, addr);
    }
    Some(peer)
}

/// Move `peer` to `to`: re-key the peer table and its receive state, and re-probe the MTU.
///
/// Whatever state sat at `to` (a placeholder made by frames that arrived before we knew who
/// was sending) is discarded; anything it buffered is requested again on the moved state.
fn migrate_peer(
    inner: &Arc<EngineInner>,
    peer: &Arc<PeerState>,
    to: PeerAddr,
    recv_states: &mut RecvStates,
) {
    let old_addr = peer.addr();
    if old_addr == to {
        return;
    }
    tracing::info!(target: "zudp::engine", old = %old_addr, new = %to, "peer address migrated");
    peer.migrate_to(to);
    inner
        .peers
        .remove_if(&old_addr, |_, p| Arc::ptr_eq(p, peer));
    if let Some(placeholder) = inner.peers.insert(to, peer.clone())
        && !Arc::ptr_eq(&placeholder, peer)
    {
        inner.unindex(&placeholder);
    }
    recv_states.retain(|(addr, _), _| *addr != to);
    let moved: Vec<u16> = recv_states
        .keys()
        .filter(|(a, _)| *a == old_addr)
        .map(|(_, s)| *s)
        .collect();
    for sid in moved {
        if let Some(state) = recv_states.remove(&(old_addr, sid)) {
            recv_states.insert((to, sid), state);
        }
    }
    peer.set_effective_mtu(0);
    if let PeerAddr::Direct(addr) = to {
        spawn_mtu_probe(inner, addr);
    }
    inner.emit(PeerEvent::Migrated { from: old_addr, to });
}

/// Fire-and-forget PLPMTUD probe toward `peer_addr`.
///
/// Spawned on first contact and on every migration so the server always knows the usable path
/// MTU — not just the client side (which probes inside `connect()`).
pub(crate) fn spawn_mtu_probe(inner: &Arc<EngineInner>, peer_addr: SocketAddr) {
    let weak = Arc::downgrade(inner);
    let initial_mtu = inner.config.mtu;
    let max_mtu = inner.config.max_mtu;
    let _mtu_probe = tokio::spawn(async move {
        let discovered = crate::mtu::probe(&weak, peer_addr, initial_mtu, max_mtu).await;
        let Some(inner) = weak.upgrade() else { return };
        let Some(discovered) = discovered else {
            tracing::debug!(target: "zudp::mtu", peer = %peer_addr, "no MTU probe answered — keeping configured MTU");
            return;
        };
        if let Some(p) = inner.peers.get(&PeerAddr::Direct(peer_addr)) {
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

/// Encode `frame` and seal it for `peer`; see [`seal`].
fn secure_frame(inner: &EngineInner, peer: &PeerState, frame: Frame) -> Option<Bytes> {
    seal(inner, peer, &frame.encode())
}

/// Wrap an encoded frame for the wire.
///
/// With a Noise session it is encrypted under a fresh nonce (so retransmits never reuse
/// one).  Without a keypair it goes out as-is.  With a keypair but no session yet it returns
/// `None`: nothing but handshake traffic may leave a secured socket in plaintext.
pub(crate) fn seal(inner: &EngineInner, peer: &PeerState, plain: &Bytes) -> Option<Bytes> {
    #[cfg(feature = "security")]
    {
        let guard = peer.channel.read();
        if let Some(channel) = guard.as_ref() {
            return match channel.encrypt(plain) {
                Ok((nonce, ct)) => Some(
                    Frame::Secure {
                        index: channel.remote_index(),
                        nonce,
                        ciphertext: Bytes::from(ct),
                    }
                    .encode(),
                ),
                Err(e) => {
                    tracing::warn!(target: "zudp::engine", peer = %peer.addr(), "encrypt failed: {e}");
                    None
                }
            };
        }
    }
    let _ = peer;
    (!inner.secured()).then(|| plain.clone())
}

/// Recover from tail loss on a reliable stream.
///
/// The receiver only NACKs a gap when a later frame reveals it, so if the last frames of a
/// burst are lost nothing ever asks for them.  Once `stream_id` goes quiet for a probe
/// timeout, re-send its newest frame (TCP's tail loss probe): a duplicate is discarded,
/// a missing tail is delivered, and a hole before it gets requested again as usual.
///
/// Call after recording a reliable send.  At most one task runs per (peer, stream).
pub(crate) fn arm_tail_probe(inner: &Arc<EngineInner>, peer: &Arc<PeerState>, stream_id: u16) {
    if !peer.tail_probe_armed.lock().insert(stream_id) {
        return;
    }
    // Weak: a probe task must not keep the socket bound after the engine stops.
    let weak = Arc::downgrade(inner);
    let peer = peer.clone();
    tokio::spawn(async move {
        let mut probed_seq = 0;
        let mut probes = 0;
        loop {
            let pto = probe_timeout(&peer);
            let newest = peer.newest_sent(stream_id);
            match &newest {
                Some((_, _, sent_at)) if sent_at.elapsed() < pto => {
                    tokio::time::sleep(pto.saturating_sub(sent_at.elapsed())).await;
                }
                Some((seq, frame, _)) if *seq != probed_seq || probes < TAIL_PROBES => {
                    if *seq != probed_seq {
                        probed_seq = *seq;
                        probes = 0;
                    }
                    let Some(inner) = weak.upgrade().filter(|i| i.is_current(&peer)) else {
                        // Engine gone or the peer was reset: these frames belong to nobody now.
                        peer.tail_probe_armed.lock().remove(&stream_id);
                        return;
                    };
                    send_tail_probe(&inner, &peer, frame, stream_id, *seq).await;
                    drop(inner);
                    probes += 1;
                    tokio::time::sleep(pto * 2u32.pow(probes)).await;
                }
                _ => {
                    // Disarm under the lock: a send recorded after this check re-arms.
                    let mut armed = peer.tail_probe_armed.lock();
                    if peer.newest_sent(stream_id).map(|n| n.0) == newest.as_ref().map(|n| n.0) {
                        armed.remove(&stream_id);
                        return;
                    }
                }
            }
        }
    });
}

fn probe_timeout(peer: &PeerState) -> Duration {
    peer.cc.lock().srtt().map_or(TAIL_PROBE_DEFAULT, |srtt| {
        (srtt * 2).clamp(TAIL_PROBE_MIN, TAIL_PROBE_MAX)
    })
}

async fn send_tail_probe(
    inner: &Arc<EngineInner>,
    peer: &PeerState,
    plain_frame: &Bytes,
    stream_id: u16,
    seq: u64,
) {
    let Some(wire) = seal(inner, peer, plain_frame) else {
        return;
    };
    peer.cc.lock().consume(wire.len());
    tracing::debug!(target: "zudp::engine", peer = %peer.addr(), seq, stream_id, "tail loss probe");
    inner.send_to_peer(peer, wire, "tail loss probe").await;
}

async fn send_nack_if_needed(
    nack_seqs: Vec<u64>,
    stream_id: u16,
    to: PeerAddr,
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
    let wire = match inner.peers.get(&to).map(|r| r.value().clone()) {
        Some(peer) => secure_frame(inner, &peer, nack),
        None => (!inner.secured()).then(|| nack.encode()),
    };
    let Some(wire) = wire else { return };
    inner.send_to_addr(to, wire, "nack").await;
}

#[allow(clippy::too_many_arguments)]
fn run_background(
    inner: &Arc<EngineInner>,
    recv_states: &mut RecvStates,
    rate_limiter: &mut crate::rate::RateLimiter,
    keepalive_interval: Duration,
    sent_prune_age: Duration,
) {
    let peer_timeout = inner.config.effective_peer_timeout();
    let peers: Vec<Arc<PeerState>> = inner.peers.iter().map(|r| r.value().clone()).collect();

    for peer in peers {
        if peer.since_seen() >= peer_timeout {
            let addr = peer.addr();
            if inner
                .peers
                .remove_if(&addr, |_, p| Arc::ptr_eq(p, &peer))
                .is_some()
            {
                inner.unindex(&peer);
                tracing::info!(target: "zudp::engine", peer = %addr, "peer timed out");
                inner.emit(PeerEvent::Disconnected {
                    addr,
                    reason: DisconnectReason::TimedOut,
                });
            }
            continue;
        }
        #[cfg(feature = "security")]
        crate::relay::tick(inner, &peer);
        // Ping when we have been quiet, and also when they have: a peer that only receives
        // must still hear from us, and we must still hear from it, within the timeout.
        if peer.since_sent() >= keepalive_interval || peer.since_seen() >= keepalive_interval {
            // Spawn each keepalive independently so sequential `send_to` calls
            // don't stall the recv loop when many peers need pinging at once.
            let sock = inner.get_socket();
            let addr = peer.addr();
            let Some((ping, dest)) = ping_for(inner, &peer).and_then(|p| inner.outbound(&peer, p))
            else {
                peer.prune_sent(sent_prune_age);
                continue;
            };
            peer.mark_sent();
            tokio::spawn(async move {
                if let Err(e) = sock.send_to(&ping, dest).await {
                    tracing::warn!(target: "zudp::engine", peer = %addr, "keepalive failed: {e}");
                }
                tracing::trace!(target: "zudp::engine", peer = %addr, "sent keepalive ping");
            });
        }
        peer.prune_sent(sent_prune_age);
    }

    recv_states.retain(|(addr, _), rx| {
        inner
            .peers
            .get(addr)
            .is_some_and(|p| p.generation == rx.generation)
    });
    for ((addr, stream_id), rx) in recv_states.iter_mut() {
        rx.frag.prune(sent_prune_age);
        if rx.recv.prune_gap(sent_prune_age) {
            tracing::warn!(
                target: "zudp::engine",
                peer = %addr,
                stream_id,
                "gap timeout — missing seq discarded, stream resyncing"
            );
        }
    }

    rate_limiter.tick_prune();

    #[cfg(feature = "relay")]
    if let Some(node) = &inner.relay {
        node.prune();
    }
    #[cfg(feature = "security")]
    crate::handshake::expire(inner);
    #[cfg(feature = "security")]
    {
        inner.hint_limiter.lock().tick_prune();
        inner.relayed_hs_limiter.lock().tick_prune();
    }
}

fn now_micros() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0u64, |d| u64::try_from(d.as_micros()).unwrap_or(u64::MAX))
}

/// Feed one handshake message to the driver, answer it, and install a finished session.
#[cfg(feature = "security")]
pub(crate) async fn handle_handshake(
    step: u8,
    version: u8,
    payload: &Bytes,
    from: PeerAddr,
    inner: &Arc<EngineInner>,
) {
    let (reply, done) = crate::handshake::on_message(inner, from, step, version, payload);
    if let Some((established, waiter)) = done {
        let peer = install_session(inner, from, established);
        if let Some(waiter) = waiter {
            let _ = waiter.send(crate::handshake::Outcome::Ready {
                generation: peer.generation,
            });
        }
    }
    if let Some(reply) = reply {
        inner.send_handshake(from, reply, "handshake").await;
    }
}

/// Make `established` the live session for `addr`.
#[cfg(feature = "security")]
fn install_session(
    inner: &Arc<EngineInner>,
    addr: PeerAddr,
    established: crate::handshake::Established,
) -> Arc<PeerState> {
    let had_session = inner.peers.get(&addr).is_some_and(|p| p.has_channel());
    let key = established.remote_static;
    if !inner.peers.contains_key(&addr) {
        limit_sessions(inner, addr);
    }
    // A new session starts on the relay; a punched path belonged to the old one.
    let was_punched = match addr {
        PeerAddr::Relayed { relay, .. } => inner
            .peers
            .get(&addr)
            .and_then(|p| p.direct_path())
            .map(|_| relay),
        PeerAddr::Direct(_) => None,
    };
    let peer = inner.replace_peer(addr);
    if let Some(relay) = was_punched {
        inner.emit(PeerEvent::PathChanged {
            addr,
            path: crate::Path::Relayed(relay),
        });
    }
    let local_index = established.channel.local_index();
    peer.set_channel(
        established.channel,
        key,
        established.finish_wire,
        established.initiator,
    );
    inner.by_index.insert(local_index, peer.clone());
    match (addr, key) {
        (PeerAddr::Direct(_), Some(key)) => {
            inner.by_key.insert(key, peer.clone());
        }
        (PeerAddr::Relayed { .. }, _) => crate::relay::auto_punch(inner, &peer),
        (PeerAddr::Direct(_), None) => {}
    }
    peer.announce();
    inner.emit(if had_session {
        PeerEvent::Reset { addr, key }
    } else {
        PeerEvent::Connected { addr, key }
    });
    tracing::info!(target: "zudp::engine", peer = %addr, initiator = established.initiator, "Noise XX handshake complete");
    peer
}

/// Bound what one source can make us hold before a new session at `addr` is installed:
/// sessions through one relay may take at most half of `max_peers`, and a relay node keeps
/// at most `max_sessions_per_ip` sessions per source network.  Over the bound, that
/// source's least recently seen session makes room.
#[cfg(feature = "security")]
fn limit_sessions(inner: &EngineInner, addr: PeerAddr) {
    match addr {
        PeerAddr::Relayed { relay, .. } => {
            let cap = inner.config.max_peers / 2;
            inner.evict_lru(
                addr,
                cap,
                |p| matches!(p, PeerAddr::Relayed { relay: r, .. } if *r == relay),
            );
        }
        PeerAddr::Direct(direct) => {
            #[cfg(not(feature = "relay"))]
            let _ = direct;
            #[cfg(feature = "relay")]
            if let Some(node) = &inner.relay {
                use crate::relay::node::network_of;
                let network = network_of(direct.ip());
                let same_network =
                    |p: &PeerAddr| p.direct().is_some_and(|a| network_of(a.ip()) == network);
                if inner.evict_lru(addr, node.max_sessions_per_ip(), same_network) {
                    node.session_evicted();
                }
            }
        }
    }
}

/// A keepalive Ping for `peer`, encrypted when a session exists.
pub(crate) fn ping_for(inner: &EngineInner, peer: &PeerState) -> Option<Bytes> {
    secure_frame(
        inner,
        peer,
        Frame::Ping {
            echo: now_micros(),
            session_id: inner.instance_id,
        },
    )
}

/// `true` when the datagram is a Noise handshake frame (type byte is last on the wire).
fn is_handshake(data: &[u8]) -> bool {
    #[cfg(feature = "security")]
    {
        data.last() == Some(&crate::frame::TYPE_HANDSHAKE)
    }
    #[cfg(not(feature = "security"))]
    {
        let _ = data;
        false
    }
}

/// Retry delivery on every stream after the application freed inbound capacity.
fn drain_all_streams(
    inner: &Arc<EngineInner>,
    recv_states: &mut RecvStates,
    inbound_tx: &mpsc::Sender<(Bytes, PeerAddr, u16)>,
) {
    for (&(addr, stream_id), rx) in recv_states.iter_mut() {
        let Some(peer) = inner
            .peers
            .get(&addr)
            .map(|r| r.value().clone())
            .filter(|p| p.generation == rx.generation)
        else {
            continue;
        };
        deliver_ready(
            &mut rx.recv,
            &mut rx.frag,
            &peer,
            addr,
            stream_id,
            inbound_tx,
            &inner.delivery_stalled,
        );
    }
}
/// Buffer one reliable frame, NACK what is missing before it, and deliver whatever is now
/// in order.
#[allow(clippy::too_many_arguments)]
async fn ingest_reliable(
    inner: &Arc<EngineInner>,
    peer: &PeerState,
    from: PeerAddr,
    stream_id: u16,
    seq: u64,
    inbound: Inbound,
    recv_states: &mut RecvStates,
    inbound_tx: &mpsc::Sender<(Bytes, PeerAddr, u16)>,
) {
    let window = inner.config.sent_buffer_frames.max(MIN_RECV_WINDOW);
    let fresh = || StreamRx {
        generation: peer.generation,
        recv: RecvState::new(window),
        frag: FragAssembler::new(),
    };
    let rx = recv_states.entry((from, stream_id)).or_insert_with(fresh);
    if rx.generation != peer.generation {
        *rx = fresh();
    }
    // Until a plain-mode peer's session is known, its frames may belong to a previous
    // incarnation of the remote, so only accept the very next one: nothing stale gets
    // buffered and nothing gets NACKed from a sender that is about to reset.
    let allow_reorder = inner.secured() || peer.their_session_id().is_some();
    let nack_seqs = rx.recv.ingest(seq, inbound, allow_reorder);
    deliver_ready(
        &mut rx.recv,
        &mut rx.frag,
        peer,
        from,
        stream_id,
        inbound_tx,
        &inner.delivery_stalled,
    );
    send_nack_if_needed(nack_seqs, stream_id, from, inner).await;
}

/// Hand in-order payloads to the application while the inbound channel has room.
///
/// A payload is only taken out of the receive buffer once a channel slot is reserved for
/// it, so a slow application stalls the stream instead of silently losing reliable data.
fn deliver_ready(
    recv: &mut RecvState,
    frag: &mut FragAssembler,
    peer: &PeerState,
    from: PeerAddr,
    stream_id: u16,
    inbound_tx: &mpsc::Sender<(Bytes, PeerAddr, u16)>,
    stalled: &AtomicBool,
) {
    while recv.has_ready() {
        let Ok(permit) = inbound_tx.try_reserve() else {
            tracing::trace!(target: "zudp::engine", %from, stream_id, "inbound channel full — holding stream");
            stalled.store(true, Ordering::Relaxed);
            return;
        };
        let complete = match recv.pop_ready() {
            Some(Inbound::Data(bytes)) => Some(bytes),
            Some(Inbound::Fragment {
                msg_id,
                frag_idx,
                frag_total,
                data,
            }) => frag.insert(msg_id, frag_idx, frag_total, data),
            None => None,
        };
        if let Some(bytes) = complete {
            peer.rx_bytes
                .fetch_add(bytes.len() as u64, Ordering::Relaxed);
            permit.send((bytes, from, stream_id));
        }
    }
}

/// The peer a data frame from `from` belongs to.
///
/// A peer first seen through a data frame is pinged at once so its engine instance id, and
/// with it restart and migration detection, is known within one round trip.
async fn data_peer(inner: &Arc<EngineInner>, from: PeerAddr) -> Arc<PeerState> {
    let (peer, created) = inner.peer_for_incoming(from);
    if created && let Some(ping) = ping_for(inner, &peer) {
        inner.send_to_peer(&peer, ping, "first-contact ping").await;
    }
    peer
}

/// Frames a secured socket accepts outside a Noise session: handshakes, discovery and path
/// MTU probing.  Everything else must arrive inside a `Secure` frame.
#[cfg(feature = "security")]
fn plaintext_allowed(frame: &Frame) -> bool {
    matches!(
        frame,
        Frame::Handshake { .. }
            | Frame::Secure { .. }
            | Frame::SessionUnknown { .. }
            | Frame::Probe { .. }
            | Frame::Beacon { .. }
            | Frame::MtuProbe { .. }
            | Frame::MtuAck { .. }
    )
}

/// Without security a session starts with the first frame heard from an address.
fn announce_plain_peer(inner: &EngineInner, from: PeerAddr) {
    if inner.secured() {
        return;
    }
    if let Some(peer) = inner.peers.get(&from).map(|r| r.value().clone())
        && peer.announce()
    {
        inner.emit(PeerEvent::Connected {
            addr: from,
            key: None,
        });
    }
}

/// Authenticate a Secure frame and find its session by index.
///
/// A frame that decrypts and carries a newer nonce than any before moves the session to
/// `from` (roaming).  A frame for an index we do not know earns the sender a rate-limited
/// `SessionUnknown` so it can re-handshake instead of talking into the void.
#[cfg(feature = "security")]
async fn open_secure(
    inner: &Arc<EngineInner>,
    from: SocketAddr,
    index: u64,
    nonce: u64,
    ciphertext: &Bytes,
    recv_states: &mut RecvStates,
) -> Option<(Arc<PeerState>, Frame)> {
    let Some(peer) = inner.by_index.get(&index).map(|r| r.value().clone()) else {
        if !crate::handshake::is_pending_index(inner, index) {
            send_session_unknown(inner, PeerAddr::Direct(from), index).await;
        }
        return None;
    };
    // A relayed session only moves onto a direct path when punching is on.
    let relayed = peer.addr().is_relayed();
    if relayed && !inner.config.punching {
        return None;
    }
    let plain = decrypt(&peer, nonce, ciphertext)?;
    let newest = peer.advance_nonce(nonce);
    peer.mark_seen();
    peer.mark_confirmed();
    if relayed {
        let (peer, frame) = inner_frame(peer, &plain)?;
        return crate::relay::on_direct(inner, peer, from, newest, frame).await;
    }
    if peer.addr() != from && newest {
        migrate_peer(inner, &peer, PeerAddr::Direct(from), recv_states);
    }
    inner_frame(peer, &plain)
}

/// Decrypt a Secure frame in `peer`'s session; `None` when it does not authenticate or
/// is a replay.
#[cfg(feature = "security")]
pub(crate) fn decrypt(peer: &PeerState, nonce: u64, ciphertext: &[u8]) -> Option<Vec<u8>> {
    let guard = peer.channel.read();
    match guard.as_ref()?.decrypt(nonce, ciphertext) {
        Ok(plain) => Some(plain),
        Err(e) => {
            tracing::debug!(target: "zudp::engine", peer = %peer.addr(), "decrypt failed: {e}");
            None
        }
    }
}

/// Decode the plaintext of a Secure frame.  Session-layer frames never travel encrypted,
/// so one found inside is dropped.
#[cfg(feature = "security")]
pub(crate) fn inner_frame(peer: Arc<PeerState>, plain: &[u8]) -> Option<(Arc<PeerState>, Frame)> {
    match Frame::decode(BytesMut::from(plain)) {
        Ok(Frame::Handshake { .. } | Frame::Secure { .. } | Frame::SessionUnknown { .. }) => None,
        Ok(frame) => Some((peer, frame)),
        Err(e) => {
            tracing::warn!(target: "zudp::engine", peer = %peer.addr(), "inner frame decode failed: {e}");
            None
        }
    }
}

/// `true` when `addr` is the punched direct path of a relayed session.
fn is_punched(inner: &EngineInner, addr: SocketAddr) -> bool {
    #[cfg(feature = "security")]
    {
        inner.punched.contains_key(&addr)
    }
    #[cfg(not(feature = "security"))]
    {
        let _ = (inner, addr);
        false
    }
}

#[cfg(feature = "security")]
pub(crate) async fn send_session_unknown(inner: &Arc<EngineInner>, to: PeerAddr, index: u64) {
    // Per source IP for direct peers; per peer for relayed ones, so every peer behind one
    // relay gets its own budget.
    let budget = match to {
        PeerAddr::Direct(addr) => PeerAddr::Direct(SocketAddr::new(addr.ip(), 0)),
        relayed @ PeerAddr::Relayed { .. } => relayed,
    };
    if !inner.hint_limiter.lock().allow(budget) {
        return;
    }
    tracing::debug!(target: "zudp::engine", peer = %to, index, "secure frame for an unknown session");
    let wire = Frame::SessionUnknown { index }.encode();
    inner.send_to_addr(to, wire, "session-unknown").await;
}

/// The remote lost the session we initiated (it restarted): handshake again in the
/// background.  The hint is unauthenticated, so it only ever starts a handshake — the old
/// session stays until a new one replaces it.
#[cfg(feature = "security")]
pub(crate) fn on_session_unknown(inner: &Arc<EngineInner>, from: PeerAddr, index: u64) {
    let peer = inner
        .peers
        .get(&from)
        .map(|r| r.value().clone())
        .or_else(|| {
            // A relayed peer we punched through answers from its direct address.
            let addr = from.direct()?;
            inner.punched.get(&addr).map(|r| r.value().clone())
        });
    let Some(peer) = peer else {
        return;
    };
    let from = peer.addr();
    if !peer.is_initiator()
        || peer.remote_index() != Some(index)
        || !peer.begin_rehandshake(inner.config.handshake_timeout)
    {
        return;
    }
    tracing::info!(target: "zudp::engine", peer = %from, "remote lost our session — re-handshaking");
    let weak = Arc::downgrade(inner);
    tokio::spawn(async move {
        if let Err(e) = crate::handshake::initiate(&weak, from).await {
            tracing::warn!(target: "zudp::engine", peer = %from, "re-handshake failed: {e}");
        }
    });
}
