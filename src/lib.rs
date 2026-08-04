//! # ZUDP — Zero UDP
//!
//! A minimal, low-overhead UDP protocol with optional reliability, fragmentation,
//! keepalives, and relay/tunnel support.
//!
//! ## Quick start
//!
//! ```rust,no_run
//! use zudp::rkyv::{Archive, Deserialize, Serialize};
//! use zudp::Zudp;
//!
//! #[derive(Archive, Serialize, Deserialize)]
//! enum Msg { Ping, Pong, Data(Vec<u8>) }
//!
//! #[tokio::main]
//! async fn main() -> anyhow::Result<()> {
//!     // Multi-peer socket — type on the terminal call
//!     let mut socket = Zudp::default().port(5000).listen::<Msg>().await?;
//!     let pkt = socket.recv().await?;   // pkt.msg, pkt.from, pkt.stream
//!
//!     // Single-peer connection
//!     let mut conn = Zudp::default().port(0).connect::<Msg>("1.2.3.4:5000".parse()?).await?;
//!     conn.send(Msg::Ping).await?;
//!     let pkt = conn.recv().await?;     // pkt.msg, pkt.from (== peer), pkt.stream
//!     Ok(())
//! }
//! ```

mod cc;
mod codec;
#[cfg(feature = "discovery")]
mod discovery;
mod engine;
mod error;
mod frag;
mod frame;
mod mtu;
mod peer;
mod rate;
#[cfg(feature = "security")]
mod security;
mod socket;

/// Stream ID for the default reliable channel.  Pass to `send_stream` / `recv_stream`
/// or use `send` / `recv` which implicitly target this stream.
pub const DEFAULT_STREAM: u16 = 0;

pub use codec::{Decode, Encode};
#[cfg(feature = "discovery")]
pub use discovery::{
    AdvertiseHandle, AppId, DISCOVERY_PORT, DiscoveredPeer, Discovery, DiscoveryConfig, ScanStream,
};
pub use error::Error;
#[cfg(feature = "security")]
pub use security::Keypair;

/// Raw byte passthrough codec. Encodes by copying the `Bytes` to a `Vec`;
/// decodes by copying the slice into a new `Bytes`. Use this when you want
/// to own the framing yourself and have zudp treat the payload as opaque.
#[derive(Debug, Clone)]
pub struct RawBytes(pub Bytes);

impl Encode for RawBytes {
    fn encode_to_bytes(&self) -> Result<Vec<u8>, Error> {
        Ok(self.0.to_vec())
    }
}

impl Decode for RawBytes {
    fn decode_from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        Ok(RawBytes(Bytes::copy_from_slice(bytes)))
    }
}

/// A clonable send handle for a [`ZudpSocket`].
///
/// Obtained via [`ZudpSocket::sender`]. Multiple `ZudpSender` instances share
/// the same underlying socket through an [`Arc`], so they can be passed freely
/// across tasks or threads.
#[derive(Clone)]
pub struct ZudpSender {
    inner: Arc<Inner>,
}

impl ZudpSender {
    /// Send `msg` to `peer` on `stream_id`.
    ///
    /// # Errors
    /// Returns `Err` on I/O failure or if the message is too large to fragment.
    pub async fn send_stream<M: Encode>(
        &self,
        msg: M,
        peer: SocketAddr,
        stream_id: u16,
    ) -> Result<(), Error> {
        self.inner.send_msg(&msg, peer, true, stream_id).await
    }
}

/// Per-peer statistics snapshot.  Returned by [`ZudpSocket::peer_stats`].
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct PeerStats {
    /// Smoothed round-trip time.  `None` until the first Pong is received.
    pub srtt: Option<Duration>,
    /// `srtt / min_rtt`: near 1.0 = clear path; >1.25 = queue building.  `None` until first RTT sample.
    pub congestion_factor: Option<f64>,
    /// Current BBR-lite pacing rate estimate in bytes/second.
    pub pacing_rate_bps: u64,
    /// Total application payload bytes received from this peer.
    pub rx_bytes: u64,
    /// Total application payload bytes sent to this peer.
    pub tx_bytes: u64,
    /// Number of frames retransmitted due to NACKs from this peer.
    pub retransmit_count: u64,
}

/// Engine-wide drop counters.  Returned by [`ZudpSocket::engine_stats`].
///
/// All counters are monotonically increasing since the socket was created.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct EngineStats {
    /// Packets dropped because the source IP exceeded the configured per-IP rate limit.
    pub dropped_rate_limited: u64,
    /// New peers rejected because the peer table was full (triggers LRU eviction).
    pub dropped_peer_cap: u64,
    /// Relay frames dropped because the source IP was not in the allowlist.
    pub dropped_relay_blocked: u64,
    /// Relay frames dropped because the relay routing table was full.
    pub dropped_relay_cap: u64,
}

/// A message received from a ZUDP socket, together with its origin and stream.
///
/// Returned by [`ZudpSocket::recv`] and [`ZudpConn::recv`].
///
/// ```rust,no_run
/// # use zudp::{Zudp, Packet};
/// # use zudp::rkyv::{Archive, Deserialize, Serialize};
/// # #[derive(Archive, Serialize, Deserialize)] enum Msg { Hi }
/// # async fn f() -> Result<(), zudp::Error> {
/// # let mut socket = Zudp::default().port(0).listen::<Msg>().await?;
/// // field access
/// let pkt = socket.recv().await?;
/// println!("from {} on stream {}", pkt.from, pkt.stream);
///
/// // or destructure
/// let Packet { msg, from, stream } = socket.recv().await?;
/// # Ok(()) }
/// ```
#[derive(Debug)]
pub struct Packet<M> {
    /// The decoded application message.
    pub msg: M,
    /// Address the message was received from.
    pub from: std::net::SocketAddr,
    /// Stream the message was sent on (`0` = [`DEFAULT_STREAM`]).
    pub stream: u16,
}

/// Re-exported so users can use `rkyv::Archive`, `rkyv::Serialize`, `rkyv::Deserialize` without a direct `rkyv` dependency.
#[cfg(feature = "rkyv")]
pub use ::rkyv;
/// Re-exported so users can derive `Encode`/`Decode` without a direct `bitcode` dependency.
#[cfg(feature = "bitcode")]
pub use ::bitcode;
/// Re-exported so users can derive `Serialize`/`Deserialize` without a direct `serde` dependency.
#[cfg(feature = "serde")]
pub use ::serde;
/// Re-exported alongside `serde` for codec access without a direct `postcard` dependency.
#[cfg(feature = "serde")]
pub use ::postcard;

use std::{
    marker::PhantomData,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicU64, AtomicU32, Ordering},
    },
    time::Duration,
};

use bytes::Bytes;
use dashmap::DashMap;
use parking_lot::RwLock;
use tokio::sync::mpsc;
use engine::EngineInner;

use frag::fragment;
use frame::Frame;
use peer::PeerState;
use socket::RawSocket;

/// Protocol configuration, built via [`Zudp`].
#[derive(Clone)]
pub struct Config {
    pub(crate) port: u16,
    pub(crate) bind_ip: IpAddr,
    /// Enable NACK-based reliability for `send()` calls.
    pub(crate) reliable: bool,
    /// Interval between keepalive probes when the channel is idle.
    pub(crate) keepalive_interval: Duration,
    /// Sent-packet buffer entries older than this are assumed delivered and pruned.
    pub(crate) sent_prune_age: Duration,
    /// Application-level MTU: messages larger than this are fragmented.
    pub(crate) mtu: usize,
    /// Optional relay node to route packets through for NAT traversal.
    pub(crate) relay_addr: Option<SocketAddr>,
    /// Noise X25519 keypair; when set, all data frames are encrypted end-to-end.
    #[cfg(feature = "security")]
    pub(crate) security: Option<security::Keypair>,
    /// Pinned remote static public key; handshakes presenting a different key are aborted.
    #[cfg(feature = "security")]
    pub(crate) remote_key: Option<[u8; 32]>,
    /// Maximum number of tracked peers.  New peers beyond this limit are handled
    /// ephemerally (not inserted into the peer table) to cap memory usage.
    pub(crate) max_peers: usize,
    /// Per-IP packet rate limit in packets per second (token bucket).  0 = disabled.
    pub(crate) max_pps_per_ip: f64,
    /// IP allowlist for relay requests.  Empty = allow all (open relay, current behaviour).
    pub(crate) relay_allowlist: Vec<IpAddr>,
    /// Maximum number of entries in the relay routing table.
    pub(crate) max_relay_entries: usize,
    /// Per-stream sent-frame buffer cap for NACK retransmission.
    ///
    /// Each frame slot holds one UDP fragment (~MTU bytes).  At 1 400 B/frame the default
    /// of 1 024 covers ~1.4 MB per stream; raise this for high-bitrate streams (e.g. set
    /// to 8 192 for 30 fps H.264 video at 5 Mbps, which generates ~450 frags/s).
    pub(crate) sent_buffer_frames: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            port: 0,
            bind_ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            reliable: true,
            keepalive_interval: Duration::from_secs(5),
            sent_prune_age: Duration::from_secs(10),
            mtu: 1400,
            relay_addr: None,
            #[cfg(feature = "security")]
            security: None,
            #[cfg(feature = "security")]
            remote_key: None,
            max_peers: 1_024,
            max_pps_per_ip: 1_000.0,
            relay_allowlist: vec![],
            max_relay_entries: 256,
            sent_buffer_frames: 1_024,
        }
    }
}

/// Entry point for constructing a ZUDP socket.
///
/// Chain configuration methods, then call `.listen::<M>()` or `.connect::<M>(peer)`.
/// The message type `M` can also be inferred from a variable annotation:
///
/// ```rust,no_run
/// # use zudp::{Zudp, ZudpSocket};
/// # #[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)] enum Msg { Hi }
/// # async fn f() -> Result<(), zudp::Error> {
/// // turbofish on the terminal call
/// let socket = Zudp::default().port(1234).listen::<Msg>().await?;
///
/// // or inferred from the type annotation
/// let socket: ZudpSocket<Msg> = Zudp::default().port(1234).listen().await?;
/// # Ok(()) }
/// ```
#[derive(Clone, Default)]
pub struct Zudp {
    config: Config,
}

impl Zudp {
    /// Bind on this port (0 = OS-assigned).
    #[must_use]
    pub fn port(mut self, port: u16) -> Self {
        self.config.port = port;
        self
    }

    /// Bind on this specific IP (default: `0.0.0.0`).
    #[must_use]
    pub fn bind_ip(mut self, ip: IpAddr) -> Self {
        self.config.bind_ip = ip;
        self
    }

    /// Enable or disable NACK-based reliability (default: `true`).
    ///
    /// When disabled, every `send()` call behaves like `send_unreliable()`.
    #[must_use]
    pub fn reliable(mut self, enabled: bool) -> Self {
        self.config.reliable = enabled;
        self
    }

    /// Interval between keepalive probes on an idle channel (default: 5 s).
    #[must_use]
    pub fn keepalive_interval(mut self, interval: Duration) -> Self {
        self.config.keepalive_interval = interval;
        self
    }

    /// Application-level MTU: messages above this size are fragmented
    /// at the ZUDP layer (default: 1400 bytes).
    #[must_use]
    pub fn mtu(mut self, bytes: usize) -> Self {
        self.config.mtu = bytes;
        self
    }

    /// Route all packets through a relay node (useful for NAT traversal).
    #[must_use]
    pub fn relay(mut self, relay_addr: SocketAddr) -> Self {
        self.config.relay_addr = Some(relay_addr);
        self
    }

    /// Enable Noise XX end-to-end encryption using the given X25519 keypair.
    ///
    /// When set, every data frame is encrypted with `ChaCha20-Poly1305` and
    /// authenticated with `BLAKE2s`.  The handshake is performed automatically
    /// on first contact.
    ///
    /// Generate a keypair with [`Keypair::generate()`].
    #[cfg(feature = "security")]
    #[must_use]
    pub fn security(mut self, keypair: Keypair) -> Self {
        self.config.security = Some(keypair);
        self
    }

    /// Require the remote peer's X25519 static key to equal `key`.
    ///
    /// Pass `keypair.public_key()` from the server's [`Keypair`].  Without this,
    /// any peer that completes a valid Noise XX handshake is accepted (opportunistic
    /// encryption only).  Mismatched keys cause the handshake to be silently
    /// aborted; [`connect`](Self::connect) will time out.
    #[cfg(feature = "security")]
    #[must_use]
    pub fn pin_remote_key(mut self, key: [u8; 32]) -> Self {
        self.config.remote_key = Some(key);
        self
    }

    /// Maximum number of tracked peers (default: 1 024).
    ///
    /// Peers beyond this limit are still reachable but their state is not stored,
    /// capping per-socket memory use under large fan-in.
    #[must_use]
    pub fn max_peers(mut self, n: usize) -> Self {
        self.config.max_peers = n;
        self
    }

    /// Per-IP inbound packet rate limit in packets per second (default: 1 000).
    ///
    /// Uses a token-bucket algorithm with a burst of `max_pps / 5`.
    /// Set to `0.0` to disable rate limiting.
    #[must_use]
    pub fn rate_limit(mut self, max_pps: f64) -> Self {
        self.config.max_pps_per_ip = max_pps;
        self
    }

    /// IP allowlist for relay requests (default: empty = open relay).
    ///
    /// When non-empty, only packets whose source IP is in the list are allowed
    /// to use this socket as a relay node.  All others are silently dropped.
    #[must_use]
    pub fn relay_allowlist(mut self, ips: Vec<IpAddr>) -> Self {
        self.config.relay_allowlist = ips;
        self
    }

    /// Maximum number of entries in the relay routing table (default: 256).
    ///
    /// New relay destinations beyond this cap are dropped; existing routes
    /// continue to function.
    #[must_use]
    pub fn max_relay_entries(mut self, n: usize) -> Self {
        self.config.max_relay_entries = n;
        self
    }

    /// Per-stream sent-frame buffer cap for NACK retransmission (default: 1 024).
    ///
    /// Each slot holds one UDP fragment (~MTU bytes).  Raise this for high-bitrate
    /// streams so frames are never evicted before `sent_prune_age` expires — an evicted
    /// frame that the receiver NACKs cannot be retransmitted, causing the receive-side
    /// reorder buffer to stall permanently until the gap timeout fires.
    ///
    /// Rule of thumb: `max_frags_per_second × sent_prune_age_secs × 1.2`.
    /// For 30 fps H.264 at 5 Mbps (≈ 450 frags/s, 10 s prune age): 5 400 → use 8 192.
    #[must_use]
    pub fn sent_buffer(mut self, frames: usize) -> Self {
        self.config.sent_buffer_frames = frames;
        self
    }

    /// Bind and start listening for packets from any peer.
    ///
    /// # Errors
    /// Returns `Err` if the OS refuses to bind the requested address/port.
    pub async fn listen<M>(self) -> Result<ZudpSocket<M>, Error> {
        ZudpSocket::new(self.config).await
    }

    /// Bind, then connect to a specific peer.
    ///
    /// All `send()` calls on the returned [`ZudpConn`] go to `peer`.
    /// `recv()` only delivers messages originating from `peer`.
    ///
    /// When the `security` feature is enabled and a keypair was configured via
    /// [`.security()`](Self::security), the full three-message Noise XX handshake
    /// completes before this function returns — the channel is encrypted and ready.
    ///
    /// # Errors
    /// Returns `Err` if the OS refuses to bind the requested address/port.
    pub async fn connect<M>(self, peer: SocketAddr) -> Result<ZudpConn<M>, Error> {
        let socket = ZudpSocket::new(self.config).await?;
        // Pre-create the peer entry so ZudpConn can share the live-address Arc.
        let peer_state = socket.inner.get_or_create_peer(peer);
        let peer_addr = peer_state.addr_arc();
        #[cfg(feature = "security")]
        if socket.inner.config.security.is_some() {
            socket.inner.initiate_handshake(peer).await?;
        }
        // Probe path MTU in background; sends use config.mtu until discovery completes.
        // Total cap: 5 s.  Individual probes are already capped at 200 ms each;
        // the outer timeout guards against extreme binary-search depths or stalled peers.
        {
            let inner = socket.inner.engine.clone();
            let initial_mtu = socket.inner.config.mtu;
            tokio::spawn(async move {
                let discovered = tokio::time::timeout(
                    Duration::from_secs(5),
                    mtu::probe(&inner, peer, initial_mtu),
                )
                .await
                .unwrap_or(initial_mtu);
                if let Some(p) = inner.peers.get(&peer) {
                    p.set_effective_mtu(discovered);
                }
                tracing::info!(target: "zudp::mtu", peer = %peer, mtu = discovered, "path MTU discovered");
            });
        }
        Ok(ZudpConn { socket, peer: peer_addr })
    }
}

struct Inner {
    engine: Arc<EngineInner>,
    config: Arc<Config>,
    next_msg_id: AtomicU32,
    /// Dropped on `Inner::drop` to signal the engine to shut down gracefully.
    _shutdown: tokio::sync::oneshot::Sender<()>,
}

impl Inner {
    async fn new(
        config: Config,
    ) -> Result<(Arc<Self>, mpsc::Receiver<(Bytes, SocketAddr, u16)>), Error> {
        let addr = SocketAddr::new(config.bind_ip, config.port);
        let socket = RawSocket::bind(addr).await?;
        let config = Arc::new(config);
        let engine = Arc::new(EngineInner {
            socket: RwLock::new(socket),
            peers: DashMap::new(),
            sessions: DashMap::new(),
            config: config.clone(),
            #[cfg(feature = "security")]
            keypair: config.security.clone(),
            shutdown_reason: parking_lot::Mutex::new(None),
            dropped_rate_limited: AtomicU64::new(0),
            dropped_peer_cap: AtomicU64::new(0),
            dropped_relay_blocked: AtomicU64::new(0),
            dropped_relay_cap: AtomicU64::new(0),
            relay_policy: RwLock::new(engine::RelayPolicy {
                allowlist: config.relay_allowlist.clone(),
                max_entries: config.max_relay_entries,
            }),
        });
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let rx = engine::spawn(engine.clone(), shutdown_rx);
        let inner = Arc::new(Self {
            engine,
            config,
            next_msg_id: AtomicU32::new(0),
            _shutdown: shutdown_tx,
        });
        Ok((inner, rx))
    }

    /// Initiate a Noise XX handshake toward `peer` and block until the channel is established.
    ///
    /// Sends msg1, then yields to the executor while the engine drives msg2 and msg3.
    /// Returns only after the `SecureChannel` is live, so callers cannot accidentally
    /// send plaintext frames.  Typical wait: one network round-trip.
    #[cfg(feature = "security")]
    async fn initiate_handshake(&self, peer_addr: SocketAddr) -> Result<(), Error> {
        use security::build_initiator;

        let kp = self
            .config
            .security
            .as_ref()
            .expect("called only when security is Some");
        let mut hs = build_initiator(kp)?;

        let mut buf = vec![0u8; 1024];
        let n = hs.write_message(&[], &mut buf)?;
        buf.truncate(n);

        let wire = Frame::Handshake {
            payload: Bytes::from(buf),
        }
        .encode();

        let peer = self.get_or_create_peer(peer_addr);

        // Register the notification future BEFORE sending msg1.  `notify_one` stores a permit
        // even if it fires before we first poll the future, so this ordering prevents any race
        // between the server responding very quickly and our subsequent `.await`.
        let notified = peer.channel_ready.notified();

        self.engine.get_socket().send_to(&wire, peer_addr).await?;
        *peer.handshake.lock() = Some(hs);

        // Fast path: channel already established (extremely unlikely in practice but correct).
        // Slow path: yield until the engine calls `notify_one` after msg3.
        if peer.channel.get().is_none() {
            notified.await;
        }

        Ok(())
    }

    fn alloc_msg_id(&self) -> u32 {
        self.next_msg_id.fetch_add(1, Ordering::Relaxed)
    }

    fn get_or_create_peer(&self, addr: SocketAddr) -> Arc<PeerState> {
        self.engine.get_or_create_peer(addr)
    }

    /// Encode and send a message to `dest` on `stream_id`.
    ///
    /// If `reliable` is `true` and the protocol config has reliability enabled,
    /// the frame is tracked for NACK-triggered retransmission.
    async fn send_msg<M: Encode>(
        &self,
        msg: &M,
        dest: SocketAddr,
        reliable: bool,
        stream_id: u16,
    ) -> Result<(), Error> {
        let payload = Bytes::from(msg.encode_to_bytes()?);

        let actual_dest = self.config.relay_addr.unwrap_or(dest);
        let wrap_relay = self.config.relay_addr.is_some();
        let reliable = reliable && self.config.reliable;

        // Single peer lookup covers both MTU discovery and send-side state;
        // avoids a second lock acquisition in send_single/send_fragmented.
        let peer = self.get_or_create_peer(dest);
        let mtu = peer.effective_mtu_or(self.config.mtu);

        if payload.len() <= mtu {
            self.send_single(payload, peer, actual_dest, wrap_relay, reliable, stream_id)
                .await
        } else {
            self.send_fragmented(payload, peer, actual_dest, wrap_relay, stream_id, mtu)
                .await
        }
    }

    async fn send_single(
        &self,
        payload: Bytes,
        peer: Arc<PeerState>,
        actual_dest: SocketAddr,
        wrap_relay: bool,
        reliable: bool,
        stream_id: u16,
    ) -> Result<(), Error> {
        if reliable {
            let seq = peer.alloc_seq(stream_id);
            // Always store plain bytes; retransmits re-encrypt with a fresh nonce.
            let plain_frame = Frame::Stream {
                seq,
                stream_id,
                payload,
            }
            .encode();
            let inner_wire = maybe_encrypt(&peer, &plain_frame)?;
            let wire = if wrap_relay {
                Frame::Relay {
                    dest: peer.addr(),
                    inner: inner_wire,
                }
                .encode()
            } else {
                inner_wire
            };
            // Track token usage; new sends are never delayed (latency budget).
            peer.cc.lock().consume(wire.len());
            self.engine.get_socket().send_to(&wire, actual_dest).await?;
            peer.record_sent(stream_id, seq, plain_frame, self.config.sent_buffer_frames);
        } else if wrap_relay {
            let frame = Frame::Datagram(payload).encode();
            let wire = Frame::Relay {
                dest: peer.addr(),
                inner: frame,
            }
            .encode();
            self.engine.get_socket().send_to(&wire, actual_dest).await?;
        } else {
            // Scatter-gather: send payload + 1-byte type tag without copying payload.
            // (Unreliable datagrams are not encrypted — no peer channel tracking for these.)
            let type_tag = [frame::TYPE_DATAGRAM];
            self.engine
                .get_socket()
                .send_to_vectored(
                    &[
                        std::io::IoSlice::new(&payload),
                        std::io::IoSlice::new(&type_tag),
                    ],
                    actual_dest,
                )
                .await?;
        }
        Ok(())
    }

    async fn send_fragmented(
        &self,
        payload: Bytes,
        peer: Arc<PeerState>,
        actual_dest: SocketAddr,
        wrap_relay: bool,
        stream_id: u16,
        mtu: usize,
    ) -> Result<(), Error> {
        let chunks = fragment(&payload, mtu)?;
        let msg_id = self.alloc_msg_id();
        // fragment() guarantees chunks.len() ≤ MAX_FRAGMENTS = u16::MAX; error if not.
        let frag_total = u16::try_from(chunks.len()).map_err(|_| Error::MessageTooLarge {
            got: chunks.len(),
            max: frag::MAX_FRAGMENTS,
        })?;

        for (frag_idx, chunk) in (0u16..).zip(chunks) {
            let seq = peer.alloc_seq(stream_id);
            let plain_frame = Frame::Fragment {
                msg_id,
                frag_idx,
                frag_total,
                seq,
                stream_id,
                payload: chunk,
            }
            .encode();
            let inner_wire = maybe_encrypt(&peer, &plain_frame)?;
            let wire = if wrap_relay {
                Frame::Relay {
                    dest: peer.addr(),
                    inner: inner_wire,
                }
                .encode()
            } else {
                inner_wire
            };
            // Track tokens; new fragment sends are not delayed (65 KB burst budget
            // covers typical game state syncs without any pacing delay).
            peer.cc.lock().consume(wire.len());
            self.engine.get_socket().send_to(&wire, actual_dest).await?;
            peer.record_sent(stream_id, seq, plain_frame, self.config.sent_buffer_frames);
        }
        Ok(())
    }
}

/// Encrypt `plain` using the peer's Noise channel if one exists; otherwise return `plain` as-is.
// Result is needed when the `security` feature is enabled (channel.encrypt can fail).
#[allow(clippy::unnecessary_wraps)]
fn maybe_encrypt(peer: &PeerState, plain: &Bytes) -> Result<Bytes, Error> {
    #[cfg(feature = "security")]
    if let Some(channel) = peer.channel.get() {
        let (nonce, ct) = channel.encrypt(plain)?;
        return Ok(Frame::Secure {
            nonce,
            ciphertext: Bytes::from(ct),
        }
        .encode());
    }
    let _ = peer;
    Ok(plain.clone())
}

/// A ZUDP socket that sends and receives messages from any remote peer.
///
/// Created by [`Zudp::listen`].
pub struct ZudpSocket<M> {
    inner: Arc<Inner>,
    rx: mpsc::Receiver<(Bytes, SocketAddr, u16)>,
    _phantom: PhantomData<fn() -> M>,
}

impl<M> ZudpSocket<M> {
    async fn new(config: Config) -> Result<Self, Error> {
        let (inner, rx) = Inner::new(config).await?;
        Ok(Self {
            inner,
            rx,
            _phantom: PhantomData,
        })
    }

    /// Local address this socket is bound to.
    ///
    /// # Errors
    /// Returns `Err` if the OS cannot retrieve the socket's local address.
    #[must_use = "the address is returned, not printed"]
    pub fn local_addr(&self) -> Result<SocketAddr, Error> {
        self.inner.engine.get_socket().local_addr()
    }

    /// Smoothed RTT to `peer`.  `None` until the first Pong from that peer.
    #[must_use]
    pub fn peer_srtt(&self, peer: SocketAddr) -> Option<Duration> {
        self.inner.engine.peers.get(&peer)?.cc.lock().srtt()
    }

    /// Congestion factor for `peer` (SRTT / min_RTT).
    ///
    /// Values near 1.0 mean the path is clear; above 1.25 indicates buffer bloat.
    /// `None` until at least one RTT sample has been taken.
    #[must_use]
    pub fn peer_congestion_factor(&self, peer: SocketAddr) -> Option<f64> {
        self.inner.engine.peers.get(&peer)?.cc.lock().congestion_factor()
    }

    /// Full statistics snapshot for `peer`.  `None` if the peer is not in the table.
    #[must_use]
    pub fn peer_stats(&self, peer: SocketAddr) -> Option<PeerStats> {
        let p = self.inner.engine.peers.get(&peer)?.value().clone();
        let (srtt, congestion_factor, pacing_rate_bps) = {
            let cc = p.cc.lock();
            // pacing_rate is bounded to [10_000, 100_000_000] — cast is safe.
            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            let rate = cc.pacing_rate() as u64;
            (cc.srtt(), cc.congestion_factor(), rate)
        };
        Some(PeerStats {
            srtt,
            congestion_factor,
            pacing_rate_bps,
            rx_bytes: p.rx_bytes.load(Ordering::Relaxed),
            tx_bytes: p.tx_bytes.load(Ordering::Relaxed),
            retransmit_count: p.retransmit_count.load(Ordering::Relaxed),
        })
    }

    /// Engine-wide drop counters since the socket was created.
    #[must_use]
    pub fn engine_stats(&self) -> EngineStats {
        let e = &self.inner.engine;
        EngineStats {
            dropped_rate_limited: e.dropped_rate_limited.load(Ordering::Relaxed),
            dropped_peer_cap: e.dropped_peer_cap.load(Ordering::Relaxed),
            dropped_relay_blocked: e.dropped_relay_blocked.load(Ordering::Relaxed),
            dropped_relay_cap: e.dropped_relay_cap.load(Ordering::Relaxed),
        }
    }

    /// Return a clonable send handle that shares this socket's underlying state.
    ///
    /// The returned [`ZudpSender`] can be cheaply cloned and sent across tasks.
    #[must_use]
    pub fn sender(&self) -> ZudpSender {
        ZudpSender { inner: self.inner.clone() }
    }

    /// The remote peer's X25519 static public key as negotiated by the Noise
    /// handshake.  Returns `None` if the peer is unknown or the handshake has
    /// not yet completed.
    #[cfg(feature = "security")]
    #[must_use]
    pub fn peer_remote_static_key(&self, peer: SocketAddr) -> Option<[u8; 32]> {
        self.inner
            .engine
            .peers
            .get(&peer)
            .and_then(|p| p.remote_static_key().copied())
    }

    /// Update the relay access policy at runtime without rebinding the socket.
    ///
    /// - `allowlist`: IPs allowed to submit relay frames.  Pass `vec![]` to allow all.
    /// - `max_entries`: maximum entries in the relay routing table.
    pub fn set_relay_policy(&self, allowlist: Vec<IpAddr>, max_entries: usize) {
        let mut p = self.inner.engine.relay_policy.write();
        p.allowlist = allowlist;
        p.max_entries = max_entries;
    }

    /// Send a reliable, ordered message to `peer` on stream 0.
    ///
    /// Reliability uses NACK-based retransmission. For fire-and-forget,
    /// use [`send_unreliable`](Self::send_unreliable). To target a specific
    /// stream, use [`send_stream`](Self::send_stream).
    ///
    /// # Errors
    /// Returns `Err` on I/O failure or if the message is too large to fragment.
    pub async fn send(&self, msg: M, peer: SocketAddr) -> Result<(), Error>
    where
        M: Encode,
    {
        self.inner.send_msg(&msg, peer, true, DEFAULT_STREAM).await
    }

    /// Send a reliable, ordered message to `peer` on the given `stream_id`.
    ///
    /// Each stream maintains an independent sequence space, so loss on one
    /// stream never blocks delivery on another (no head-of-line blocking).
    ///
    /// # Errors
    /// Returns `Err` on I/O failure or if the message is too large to fragment.
    pub async fn send_stream(&self, msg: M, peer: SocketAddr, stream_id: u16) -> Result<(), Error>
    where
        M: Encode,
    {
        self.inner.send_msg(&msg, peer, true, stream_id).await
    }

    /// Send an unreliable, unordered datagram to `peer`.
    ///
    /// No retransmission. Zero overhead beyond the 1-byte frame type tag.
    ///
    /// # Errors
    /// Returns `Err` on I/O failure.
    pub async fn send_unreliable(&self, msg: M, peer: SocketAddr) -> Result<(), Error>
    where
        M: Encode,
    {
        self.inner.send_msg(&msg, peer, false, DEFAULT_STREAM).await
    }

    /// Receive the next message from any peer on any stream.
    ///
    /// # Errors
    /// Returns `Err(Error::EngineStopped)` if the engine task has stopped, with the reason
    /// (e.g. socket rebind failure).  Returns `Err(Error::ChannelClosed)` if the internal
    /// channel closed for an unknown reason.
    pub async fn recv(&mut self) -> Result<Packet<M>, Error>
    where
        M: Decode,
    {
        loop {
            let Some((bytes, from, stream)) = self.rx.recv().await else {
                let reason = self
                    .inner
                    .engine
                    .shutdown_reason
                    .lock()
                    .clone()
                    .unwrap_or_else(|| "channel closed".into());
                return Err(Error::EngineStopped { reason });
            };
            match M::decode_from_bytes(&bytes) {
                Ok(msg) => return Ok(Packet { msg, from, stream }),
                Err(e) => {
                    tracing::warn!(target: "zudp", peer = %from, "decode failed: {e}");
                }
            }
        }
    }
}

/// A ZUDP socket bound to a single remote peer.
///
/// Created by [`Zudp::connect`].
/// `send()` and `recv()` target `peer` exclusively.
///
/// The peer's address is tracked dynamically: if the remote migrates to a new network interface
/// the session continues transparently — `peer()` returns the current address after migration.
pub struct ZudpConn<M> {
    socket: ZudpSocket<M>,
    /// Shared with `PeerState.addr`; updated in-place when the remote migrates.
    peer: Arc<RwLock<SocketAddr>>,
}

impl<M> ZudpConn<M> {
    /// Current remote peer address.
    ///
    /// Updated automatically when the peer migrates to a new network interface.
    #[must_use]
    pub fn peer(&self) -> SocketAddr {
        *self.peer.read()
    }

    /// Clonable send handle that shares this connection's underlying socket.
    ///
    /// Useful for splitting the send path across tasks while the receive
    /// loop drives `recv()` exclusively.
    #[must_use]
    pub fn sender(&self) -> ZudpSender {
        self.socket.sender()
    }

    /// Local address this socket is bound to.
    ///
    /// # Errors
    /// Returns `Err` if the OS cannot retrieve the socket's local address.
    #[must_use = "the address is returned, not printed"]
    pub fn local_addr(&self) -> Result<SocketAddr, Error> {
        self.socket.local_addr()
    }

    /// Path MTU discovered by PLPMTUD.  `None` until the background probe completes
    /// (typically 1–2 s after `connect()`); use `Zudp::mtu(N)` to set a fixed override.
    #[must_use]
    pub fn effective_mtu(&self) -> Option<usize> {
        self.socket
            .inner
            .engine
            .peers
            .get(&self.peer())
            .map(|p| p.effective_mtu_or(0))
            .filter(|&v| v != 0)
    }

    /// Smoothed RTT to the bound peer.  `None` until the first Pong is received.
    #[must_use]
    pub fn srtt(&self) -> Option<Duration> {
        self.socket.peer_srtt(self.peer())
    }

    /// Congestion factor (SRTT / min_RTT).
    ///
    /// Values near 1.0 mean the path is clear; above 1.25 indicates buffer bloat.
    /// `None` until at least one RTT sample has been taken.
    #[must_use]
    pub fn congestion_factor(&self) -> Option<f64> {
        self.socket.peer_congestion_factor(self.peer())
    }

    /// Full statistics snapshot for the bound peer.
    #[must_use]
    pub fn peer_stats(&self) -> Option<PeerStats> {
        self.socket.peer_stats(self.peer())
    }

    /// Engine-wide drop counters since the socket was created.
    #[must_use]
    pub fn engine_stats(&self) -> EngineStats {
        self.socket.engine_stats()
    }

    /// Send a reliable, ordered message to the bound peer on stream 0.
    ///
    /// # Errors
    /// Returns `Err` on I/O failure or if the message is too large to fragment.
    pub async fn send(&self, msg: M) -> Result<(), Error>
    where
        M: Encode,
    {
        self.socket.send(msg, self.peer()).await
    }

    /// Send a reliable, ordered message to the bound peer on `stream_id`.
    ///
    /// Each stream has an independent sequence space — loss on one stream
    /// never delays delivery on another.
    ///
    /// # Errors
    /// Returns `Err` on I/O failure or if the message is too large to fragment.
    pub async fn send_stream(&self, msg: M, stream_id: u16) -> Result<(), Error>
    where
        M: Encode,
    {
        self.socket.send_stream(msg, self.peer(), stream_id).await
    }

    /// Send an unreliable datagram to the bound peer.
    ///
    /// # Errors
    /// Returns `Err` on I/O failure.
    pub async fn send_unreliable(&self, msg: M) -> Result<(), Error>
    where
        M: Encode,
    {
        self.socket.send_unreliable(msg, self.peer()).await
    }

    /// Receive the next message from the bound peer on any stream.
    ///
    /// `pkt.from` reflects the peer's current address (updated after a network migration).
    /// Messages from unrelated peers are silently discarded.
    ///
    /// # Errors
    /// Returns `Err(Error::ChannelClosed)` if the engine task has stopped.
    pub async fn recv(&mut self) -> Result<Packet<M>, Error>
    where
        M: Decode,
    {
        loop {
            let pkt = self.socket.recv().await?;
            let current = *self.peer.read();
            if pkt.from == current {
                return Ok(pkt);
            }
            tracing::debug!(
                target: "zudp",
                unexpected = %pkt.from,
                expected = %current,
                "dropping message from unexpected peer"
            );
        }
    }
}
