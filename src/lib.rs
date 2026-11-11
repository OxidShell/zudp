//! # ZUDP — Zero UDP
//!
//! A minimal, low-overhead UDP protocol with optional reliability, fragmentation,
//! keepalives, end-to-end encryption, and relayed sessions with hole punching.
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
//!
//! ## Peers, direct and relayed
//!
//! Peers are named by [`PeerAddr`].  A direct peer is its UDP address — every method that
//! takes a peer accepts a `SocketAddr` through `impl Into<PeerAddr>`.  With the `security`
//! feature, a client connected to a relay node (a socket built with `Zudp::relay_node`,
//! `relay` feature) reaches other clients of that relay by static public key with
//! `ZudpSocket::connect_via`; the session is end-to-end encrypted, the relay only forwards
//! ciphertext, and hole punching moves it onto a direct path when NAT allows.  Such a peer
//! is a `PeerAddr::Relayed` handle that stays the same whichever path its traffic takes.

mod addr;
mod cc;
mod codec;
#[cfg(feature = "discovery")]
mod discovery;
mod engine;
mod error;
mod event;
mod frag;
mod frame;
#[cfg(feature = "security")]
mod handshake;
mod mtu;
mod peer;
mod rate;
#[cfg(feature = "security")]
mod relay;
#[cfg(feature = "security")]
mod security;
mod socket;

/// Stream ID for the default reliable channel.  Pass to `send_stream` / `recv_stream`
/// or use `send` / `recv` which implicitly target this stream.
pub const DEFAULT_STREAM: u16 = 0;

pub use addr::{Path, PeerAddr};
pub use codec::{Decode, Encode};
#[cfg(feature = "discovery")]
pub use discovery::{
    AdvertiseHandle, AppId, DISCOVERY_PORT, DiscoveredPeer, Discovery, DiscoveryConfig,
    DiscoveryEvent, ScanStream,
};
pub use error::Error;
pub use event::{DisconnectReason, PeerEvent, PeerEvents};
pub use frame::WIRE_VERSION;
#[cfg(feature = "relay")]
#[doc(hidden)]
pub use relay::node::RelayTap;
#[cfg(feature = "relay")]
pub use relay::node::{RelayLimits, RelayPolicy};
#[cfg(feature = "security")]
pub use security::{Keypair, ReplayWindow};

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
    /// Subscribe to peer lifecycle events; see [`PeerEvent`].
    #[must_use]
    pub fn events(&self) -> PeerEvents {
        self.inner.events()
    }

    /// Forget `peer` now: drop its session, buffers and receive state and emit
    /// [`PeerEvent::Disconnected`] with [`DisconnectReason::Removed`].  Returns `false` when
    /// the peer was unknown.
    #[must_use = "false means the peer was not known"]
    pub fn remove_peer(&self, peer: impl Into<PeerAddr>) -> bool {
        self.inner.engine.remove_peer(peer.into())
    }

    /// Send `msg` to `peer` on `stream_id`.
    ///
    /// # Errors
    /// Returns `Err` on I/O failure or if the message is too large to fragment.
    pub async fn send_stream<M: Encode>(
        &self,
        msg: M,
        peer: impl Into<PeerAddr>,
        stream_id: u16,
    ) -> Result<(), Error> {
        self.inner
            .send_msg(&msg, peer.into(), true, stream_id)
            .await
    }

    /// Open a session with a direct peer; see [`ZudpSocket::connect`].
    ///
    /// # Errors
    /// As [`ZudpSocket::connect`].
    pub async fn connect(&self, peer: SocketAddr) -> Result<PeerAddr, Error> {
        Ok(*self.inner.connect(peer).await?.read())
    }

    /// Open a relayed session; see [`ZudpSocket::connect_via`].
    ///
    /// # Errors
    /// As [`ZudpSocket::connect_via`].
    #[cfg(feature = "security")]
    pub async fn connect_via(
        &self,
        relay: SocketAddr,
        target: [u8; 32],
    ) -> Result<PeerAddr, Error> {
        Ok(*self.inner.connect_via(relay, target).await?.read())
    }

    /// Smoothed RTT to `peer` as measured by transport-level Ping/Pong.
    /// Returns `None` until the first Pong has been received.
    #[must_use]
    pub fn peer_srtt(&self, peer: impl Into<PeerAddr>) -> Option<std::time::Duration> {
        self.inner.engine.peers.get(&peer.into())?.cc.lock().srtt()
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
    /// Plaintext data frames dropped because this socket requires encryption.
    pub dropped_unauthenticated: u64,
    /// Relayed frames dropped because the relay attributed them to a peer other than the
    /// one their end-to-end session authenticates.
    pub dropped_forged: u64,
    /// Relay node: frames forwarded between clients.
    pub relay_forwarded_packets: u64,
    /// Relay node: inner bytes forwarded between clients.
    pub relay_forwarded_bytes: u64,
    /// Relay node: frames dropped by a client's packet or byte rate limit.
    pub relay_dropped_rate_limited: u64,
    /// Relay node: frames dropped for exceeding the maximum inner size.
    pub relay_dropped_oversize: u64,
    /// Relay node: `Unreachable` answers sent (target offline, denied, or over the route cap).
    pub relay_unreachable: u64,
    /// Relay node: of those, the ones the policy denied.
    pub relay_denied: u64,
    /// Relay node: of those, the ones refused because the route cap was reached.
    pub relay_routes_full: u64,
    /// Relay node: client pairs introduced to each other for hole punching.
    pub relay_introductions: u64,
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
    /// The peer the message came from.  For a direct peer this compares equal to its
    /// `SocketAddr`; see [`PeerAddr`].
    pub from: PeerAddr,
    /// Stream the message was sent on (`0` = [`DEFAULT_STREAM`]).
    pub stream: u16,
}

/// Re-exported so users can derive `Encode`/`Decode` without a direct `bitcode` dependency.
#[cfg(feature = "bitcode")]
pub use ::bitcode;
/// Re-exported alongside `serde` for codec access without a direct `postcard` dependency.
#[cfg(feature = "serde")]
pub use ::postcard;
/// Re-exported so users can use `rkyv::Archive`, `rkyv::Serialize`, `rkyv::Deserialize` without a direct `rkyv` dependency.
#[cfg(feature = "rkyv")]
pub use ::rkyv;
/// Re-exported so users can derive `Serialize`/`Deserialize` without a direct `serde` dependency.
#[cfg(feature = "serde")]
pub use ::serde;

use std::{
    marker::PhantomData,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicU32, AtomicU64, Ordering},
    },
    time::Duration,
};

use bytes::Bytes;
use dashmap::DashMap;
use engine::EngineInner;
use parking_lot::RwLock;
use tokio::sync::mpsc;

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
    /// Ceiling for path MTU discovery (see [`Zudp::max_mtu`]).
    pub(crate) max_mtu: usize,
    /// Noise X25519 keypair; when set, all data frames are encrypted end-to-end.
    #[cfg(feature = "security")]
    pub(crate) security: Option<security::Keypair>,
    /// Pinned remote static public keys; when non-empty, handshakes presenting any other
    /// key are aborted.
    #[cfg(feature = "security")]
    pub(crate) pinned_keys: Vec<[u8; 32]>,
    /// Punch relayed sessions through to a direct path when NAT allows it.
    #[cfg(feature = "security")]
    pub(crate) punching: bool,
    /// Relay node limits; `Some` makes this socket a relay node.
    #[cfg(feature = "relay")]
    pub(crate) relay: Option<RelayLimits>,
    /// Initial relay policy; `None` lets every client reach every other.
    #[cfg(feature = "relay")]
    pub(crate) relay_policy: Option<Arc<dyn RelayPolicy>>,
    /// Maximum number of tracked peers.  New peers beyond this limit are handled
    /// ephemerally (not inserted into the peer table) to cap memory usage.
    pub(crate) max_peers: usize,
    /// Per-IP packet rate limit in packets per second (token bucket).  0 = disabled.
    pub(crate) max_pps_per_ip: f64,
    /// Per-stream sent-frame buffer cap for NACK retransmission.
    ///
    /// Each frame slot holds one UDP fragment (~MTU bytes).  At 1 400 B/frame the default
    /// of 1 024 covers ~1.4 MB per stream; raise this for high-bitrate streams (e.g. set
    /// to 8 192 for 30 fps H.264 video at 5 Mbps, which generates ~450 frags/s).
    pub(crate) sent_buffer_frames: usize,
    /// How long a Noise handshake may take before it is abandoned.
    pub(crate) handshake_timeout: Duration,
    /// Silence after which a peer is dropped; `None` = 3 × keepalive interval.
    pub(crate) peer_timeout: Option<Duration>,
}

impl Config {
    pub(crate) fn effective_peer_timeout(&self) -> Duration {
        self.peer_timeout.unwrap_or(self.keepalive_interval * 3)
    }
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
            max_mtu: mtu::DEFAULT_MTU_CEILING,
            #[cfg(feature = "security")]
            security: None,
            #[cfg(feature = "security")]
            pinned_keys: Vec::new(),
            #[cfg(feature = "security")]
            punching: true,
            #[cfg(feature = "relay")]
            relay: None,
            #[cfg(feature = "relay")]
            relay_policy: None,
            max_peers: 1_024,
            max_pps_per_ip: 1_000.0,
            sent_buffer_frames: 1_024,
            handshake_timeout: Duration::from_secs(5),
            peer_timeout: None,
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

    /// Ceiling for path MTU discovery (default: 1472 bytes, standard
    /// non-jumbo Ethernet — see the comment on `mtu::DEFAULT_MTU_CEILING`
    /// for why that's the default and not something bigger).
    ///
    /// Raise this only on a network you know carries jumbo frames end to
    /// end — every hop, not just the two machines talking. Discovery still
    /// can't set the DF bit on its probes, so a path that only carries
    /// jumbo frames some of the way can still make discovery settle on an
    /// MTU that then drops packets under real traffic; this knob doesn't
    /// change that risk, it just lets you accept it deliberately instead of
    /// discovery opting you into it silently.
    #[must_use]
    pub fn max_mtu(mut self, bytes: usize) -> Self {
        self.config.max_mtu = bytes;
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

    /// Only accept sessions with peers whose X25519 static key was pinned.
    ///
    /// Pass `keypair.public_key()` from the remote's [`Keypair`].  Call it once per trusted
    /// key: a relay client typically pins the relay node and every peer it reaches through
    /// it.  Without any pinned key, any peer that completes a valid Noise XX handshake is
    /// accepted (opportunistic encryption only).
    ///
    /// The pin covers every handshake on the socket, direct and relayed alike.  As the
    /// initiator, [`connect`](Self::connect) fails with [`Error::KeyMismatch`]; as the
    /// responder, the handshake is silently aborted.
    #[cfg(feature = "security")]
    #[must_use]
    pub fn pin_remote_key(mut self, key: [u8; 32]) -> Self {
        if !self.config.pinned_keys.contains(&key) {
            self.config.pinned_keys.push(key);
        }
        self
    }

    /// Punch relayed sessions through to a direct path (default: `true`).
    ///
    /// When on, both ends of a session opened with
    /// [`ZudpSocket::connect_via`] ask the relay for an introduction, probe each other's
    /// public address with authenticated keepalives, and move the session onto the direct
    /// path once one gets through ([`PeerEvent::PathChanged`]).  A direct path that goes
    /// silent falls back to the relay.  Where NAT does not allow it (symmetric NAT on both
    /// sides) the session simply stays on the relay.  When off, traffic always goes through
    /// the relay and the relay never learns we would like to know the peer's address.
    #[cfg(feature = "security")]
    #[must_use]
    pub fn punching(mut self, enabled: bool) -> Self {
        self.config.punching = enabled;
        self
    }

    /// Make this socket a relay node with the given abuse limits.
    ///
    /// A relay node forwards end-to-end encrypted frames between the clients connected to
    /// it, addressed by their static public keys (see [`ZudpSocket::connect_via`]), and
    /// introduces clients to each other for hole punching.  It never sees plaintext and
    /// never sends to an address a client names, so it is safe to expose publicly.
    /// Requires [`security`](Self::security).  Gate who may reach whom with
    /// [`relay_policy`](Self::relay_policy).
    #[cfg(feature = "relay")]
    #[must_use]
    pub fn relay_node(mut self, limits: RelayLimits) -> Self {
        self.config.relay = Some(limits);
        self
    }

    /// Who may reach whom through this relay node (default: everyone connected).
    /// Replace it at runtime with [`ZudpSocket::set_relay_policy`].
    #[cfg(feature = "relay")]
    #[must_use]
    pub fn relay_policy(mut self, policy: impl RelayPolicy + 'static) -> Self {
        self.config.relay_policy = Some(Arc::new(policy));
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

    /// Drop a peer after this long without receiving anything from it, emitting
    /// [`PeerEvent::Disconnected`] and making [`ZudpConn::recv`] fail with
    /// [`Error::PeerTimeout`].  Keepalive Pings keep live peers well inside it.
    /// Default: 3 × [`keepalive_interval`](Self::keepalive_interval) (15 s).
    #[must_use]
    pub fn peer_timeout(mut self, timeout: Duration) -> Self {
        self.config.peer_timeout = Some(timeout);
        self
    }

    /// How long [`connect`](Self::connect) (and a re-handshake after the remote lost our
    /// session) keeps retransmitting before giving up with [`Error::HandshakeTimeout`].
    /// Default: 5 s.  Half-open responder states are dropped after the same time.
    #[must_use]
    pub fn handshake_timeout(mut self, timeout: Duration) -> Self {
        self.config.handshake_timeout = timeout;
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
    /// [`.security()`](Self::security), the Noise XX handshake completes before this function
    /// returns, and so does one authenticated round trip: both ends hold the session.
    /// Lost handshake datagrams are retransmitted with back-off.
    ///
    /// # Errors
    /// - [`Error::Io`] if the OS refuses to bind the requested address/port.
    /// - [`Error::HandshakeTimeout`] if the handshake does not finish within
    ///   [`handshake_timeout`](Self::handshake_timeout).
    /// - [`Error::KeyMismatch`] if a key was pinned and the remote presented another one.
    pub async fn connect<M>(self, peer: SocketAddr) -> Result<ZudpConn<M>, Error> {
        let socket = ZudpSocket::new(self.config).await?;
        let peer = socket.inner.connect(peer).await?;
        Ok(ZudpConn::new(socket, peer))
    }

    /// Bind, connect to the relay node at `relay`, then open an end-to-end session through
    /// it with the peer whose static public key is `target`.
    ///
    /// The returned [`ZudpConn`] talks to `target`; see [`ZudpSocket::connect_via`] for the
    /// semantics and for reaching several peers through one relay from a single socket.
    ///
    /// # Errors
    /// Everything [`connect`](Self::connect) can return for the relay, then
    /// [`Error::Unreachable`] when the relay cannot reach `target`, and
    /// [`Error::HandshakeTimeout`] / [`Error::KeyMismatch`] for the end-to-end handshake.
    #[cfg(feature = "security")]
    pub async fn connect_via<M>(
        self,
        relay: SocketAddr,
        target: [u8; 32],
    ) -> Result<ZudpConn<M>, Error> {
        let socket = ZudpSocket::new(self.config).await?;
        socket.inner.connect(relay).await?;
        let peer = socket.inner.connect_via(relay, target).await?;
        Ok(ZudpConn::new(socket, peer))
    }
}

/// Replies to 0.0.0.0 / :: come back from a concrete loopback address, which would never
/// match the peer entry; talk to loopback explicitly instead.
fn reachable(peer: SocketAddr) -> SocketAddr {
    match peer.ip() {
        IpAddr::V4(ip) if ip.is_unspecified() => {
            SocketAddr::new(Ipv4Addr::LOCALHOST.into(), peer.port())
        }
        IpAddr::V6(ip) if ip.is_unspecified() => {
            SocketAddr::new(std::net::Ipv6Addr::LOCALHOST.into(), peer.port())
        }
        _ => peer,
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
    ) -> Result<(Arc<Self>, mpsc::Receiver<(Bytes, PeerAddr, u16)>), Error> {
        let addr = SocketAddr::new(config.bind_ip, config.port);
        let socket = RawSocket::bind(addr).await?;
        let config = Arc::new(config);
        let engine = Arc::new(EngineInner {
            socket: RwLock::new(socket),
            peers: DashMap::new(),
            sessions: DashMap::new(),
            instance_id: peer::random_u64(),
            events: tokio::sync::broadcast::channel(event::EVENT_CAPACITY).0,
            config: config.clone(),
            #[cfg(feature = "security")]
            keypair: config.security.clone(),
            shutdown_reason: parking_lot::Mutex::new(None),
            dropped_rate_limited: AtomicU64::new(0),
            dropped_peer_cap: AtomicU64::new(0),
            dropped_unauthenticated: AtomicU64::new(0),
            delivery_stalled: std::sync::atomic::AtomicBool::new(false),
            #[cfg(feature = "security")]
            pending: parking_lot::Mutex::new(std::collections::HashMap::new()),
            #[cfg(feature = "security")]
            by_index: DashMap::new(),
            #[cfg(feature = "security")]
            hint_limiter: parking_lot::Mutex::new(rate::RateLimiter::new(5.0, 5.0)),
            #[cfg(feature = "security")]
            by_key: DashMap::new(),
            #[cfg(feature = "security")]
            punched: DashMap::new(),
            dropped_forged: AtomicU64::new(0),
            #[cfg(feature = "relay")]
            relay: config
                .relay
                .clone()
                .map(|limits| relay::node::RelayNode::new(limits, config.relay_policy.clone())),
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

    fn events(&self) -> PeerEvents {
        PeerEvents {
            rx: self.engine.events.subscribe(),
        }
    }

    /// Open a session with the direct peer at `peer`; returns its live handle.  A secure
    /// session that is already up is reused.
    async fn connect(&self, peer: SocketAddr) -> Result<Arc<RwLock<PeerAddr>>, Error> {
        let peer = reachable(peer);
        let handle = PeerAddr::Direct(peer);
        #[cfg(feature = "security")]
        if let Some(existing) = self.established(handle) {
            return Ok(existing.addr_arc());
        }
        // Pre-create the peer entry so ZudpConn can share the live-address Arc.
        let peer_state = self.get_or_create_peer(handle);
        let live = peer_state.addr_arc();
        #[cfg(feature = "security")]
        if self.engine.secured() {
            handshake::initiate(&Arc::downgrade(&self.engine), handle).await?;
        }
        if !self.engine.secured()
            && let Some(ping) = engine::ping_for(&self.engine, &peer_state)
        {
            // Announce our instance id first, so a server that still has state from a previous
            // process on this address resets it before our first data frame.
            self.engine.get_socket().send_to(&ping, peer).await?;
        }
        // Probe path MTU in background; sends use config.mtu until discovery completes.
        engine::spawn_mtu_probe(&self.engine, peer);
        Ok(live)
    }

    /// The confirmed secure session with `peer`, if there is one.
    #[cfg(feature = "security")]
    fn established(&self, peer: PeerAddr) -> Option<Arc<PeerState>> {
        self.engine
            .peers
            .get(&peer)
            .map(|p| p.value().clone())
            .filter(|p| p.has_channel() && p.is_confirmed())
    }

    /// Open an end-to-end session with `target` through the relay at `relay`.
    #[cfg(feature = "security")]
    async fn connect_via(
        &self,
        relay: SocketAddr,
        target: [u8; 32],
    ) -> Result<Arc<RwLock<PeerAddr>>, Error> {
        let relay = reachable(relay);
        if !self.engine.secured() || self.established(PeerAddr::Direct(relay)).is_none() {
            return Err(Error::NoSession {
                peer: PeerAddr::Direct(relay),
            });
        }
        let handle = PeerAddr::Relayed { relay, key: target };
        if self.established(handle).is_none() {
            handshake::initiate(&Arc::downgrade(&self.engine), handle).await?;
        }
        self.engine
            .peers
            .get(&handle)
            .map(|p| p.addr_arc())
            .ok_or(Error::HandshakeTimeout { peer: handle })
    }

    fn peer_path(&self, peer: PeerAddr) -> Option<Path> {
        let state = self.engine.peers.get(&peer)?.value().clone();
        match peer {
            PeerAddr::Direct(addr) => Some(Path::Direct(addr)),
            PeerAddr::Relayed { relay, .. } => {
                #[cfg(feature = "security")]
                if let Some(direct) = state.direct_path() {
                    return Some(Path::Direct(direct));
                }
                let _ = state;
                Some(Path::Relayed(relay))
            }
        }
    }

    fn alloc_msg_id(&self) -> u32 {
        self.next_msg_id.fetch_add(1, Ordering::Relaxed)
    }

    fn get_or_create_peer(&self, addr: PeerAddr) -> Arc<PeerState> {
        self.engine.get_or_create_peer(addr)
    }

    /// Encode and send a message to `dest` on `stream_id`.
    ///
    /// If `reliable` is `true` and the protocol config has reliability enabled,
    /// the frame is tracked for NACK-triggered retransmission.
    async fn send_msg<M: Encode>(
        &self,
        msg: &M,
        dest: PeerAddr,
        reliable: bool,
        stream_id: u16,
    ) -> Result<(), Error> {
        let payload = Bytes::from(msg.encode_to_bytes()?);

        let reliable = reliable && self.config.reliable;

        // Single peer lookup covers both MTU discovery and send-side state;
        // avoids a second lock acquisition in send_single/send_fragmented.
        let peer = if self.engine.secured() {
            // Never create a session-less peer on a secured socket: it could only send plaintext.
            self.engine
                .peers
                .get(&dest)
                .map(|p| p.value().clone())
                .filter(|p| p.has_channel())
                .ok_or(Error::NoSession { peer: dest })?
        } else {
            self.get_or_create_peer(dest)
        };
        let mtu = if dest.is_relayed() {
            relayed_mtu(self.config.mtu)
        } else {
            peer.effective_mtu_or(self.config.mtu)
        };

        if payload.len() <= mtu {
            self.send_single(payload, peer, reliable, stream_id).await
        } else {
            self.send_fragmented(payload, peer, stream_id, mtu).await
        }
    }

    async fn send_single(
        &self,
        payload: Bytes,
        peer: Arc<PeerState>,
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
            let (wire, dest) = routed(&self.engine, &peer, &plain_frame)?;
            // Track token usage; new sends are never delayed (latency budget).
            peer.cc.lock().consume(wire.len());
            self.engine.get_socket().send_to(&wire, dest).await?;
            peer.record_sent(stream_id, seq, plain_frame, self.config.sent_buffer_frames);
            engine::arm_tail_probe(&self.engine, &peer, stream_id);
        } else if let (false, PeerAddr::Direct(dest)) = (self.engine.secured(), peer.addr()) {
            // Scatter-gather: send payload + 1-byte type tag without copying payload.
            let type_tag = [frame::TYPE_DATAGRAM];
            self.engine
                .get_socket()
                .send_to_vectored(
                    &[
                        std::io::IoSlice::new(&payload),
                        std::io::IoSlice::new(&type_tag),
                    ],
                    dest,
                )
                .await?;
        } else {
            let (wire, dest) = routed(&self.engine, &peer, &Frame::Datagram(payload).encode())?;
            self.engine.get_socket().send_to(&wire, dest).await?;
        }
        peer.mark_sent();
        Ok(())
    }

    async fn send_fragmented(
        &self,
        payload: Bytes,
        peer: Arc<PeerState>,
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
            let (wire, dest) = routed(&self.engine, &peer, &plain_frame)?;
            // Track tokens; new fragment sends are not delayed (65 KB burst budget
            // covers typical game state syncs without any pacing delay).
            peer.cc.lock().consume(wire.len());
            self.engine.get_socket().send_to(&wire, dest).await?;
            peer.record_sent(stream_id, seq, plain_frame, self.config.sent_buffer_frames);
        }
        engine::arm_tail_probe(&self.engine, &peer, stream_id);
        Ok(())
    }
}

/// Fragment size for a relayed peer: the relay hop adds [`frame::VIA_OVERHEAD`] bytes to
/// every datagram, and its path may flip between direct and relayed at any time.
fn relayed_mtu(mtu: usize) -> usize {
    #[cfg(feature = "security")]
    {
        mtu.saturating_sub(frame::VIA_OVERHEAD).max(64)
    }
    #[cfg(not(feature = "security"))]
    {
        mtu
    }
}

/// Seal `plain` for `peer` (see [`engine::seal`]) and wrap it for the peer's current path.
fn routed(
    engine: &EngineInner,
    peer: &PeerState,
    plain: &Bytes,
) -> Result<(Bytes, SocketAddr), Error> {
    engine::seal(engine, peer, plain)
        .and_then(|wire| engine.outbound(peer, wire))
        .ok_or(Error::NoSession { peer: peer.addr() })
}

/// The relay node counters of `engine`, all zero when it is not a relay node.
#[cfg_attr(not(feature = "relay"), allow(clippy::needless_pass_by_value))]
fn relay_stats(engine: &EngineInner) -> EngineStats {
    #[cfg(feature = "relay")]
    if let Some(node) = &engine.relay {
        let c = &node.counters;
        return EngineStats {
            relay_forwarded_packets: c.forwarded_packets.load(Ordering::Relaxed),
            relay_forwarded_bytes: c.forwarded_bytes.load(Ordering::Relaxed),
            relay_dropped_rate_limited: c.dropped_rate_limited.load(Ordering::Relaxed),
            relay_dropped_oversize: c.dropped_oversize.load(Ordering::Relaxed),
            relay_unreachable: c.unreachable.load(Ordering::Relaxed),
            relay_denied: c.denied.load(Ordering::Relaxed),
            relay_routes_full: c.routes_full.load(Ordering::Relaxed),
            relay_introductions: c.introductions.load(Ordering::Relaxed),
            ..EngineStats::default()
        };
    }
    let _ = engine;
    EngineStats::default()
}

/// A ZUDP socket that sends and receives messages from any remote peer.
///
/// Created by [`Zudp::listen`].
pub struct ZudpSocket<M> {
    inner: Arc<Inner>,
    rx: mpsc::Receiver<(Bytes, PeerAddr, u16)>,
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
    pub fn peer_srtt(&self, peer: impl Into<PeerAddr>) -> Option<Duration> {
        self.inner.engine.peers.get(&peer.into())?.cc.lock().srtt()
    }

    /// Congestion factor for `peer` (SRTT / `min_RTT`).
    ///
    /// Values near 1.0 mean the path is clear; above 1.25 indicates buffer bloat.
    /// `None` until at least one RTT sample has been taken.
    #[must_use]
    pub fn peer_congestion_factor(&self, peer: impl Into<PeerAddr>) -> Option<f64> {
        self.inner
            .engine
            .peers
            .get(&peer.into())?
            .cc
            .lock()
            .congestion_factor()
    }

    /// Full statistics snapshot for `peer`.  `None` if the peer is not in the table.
    #[must_use]
    pub fn peer_stats(&self, peer: impl Into<PeerAddr>) -> Option<PeerStats> {
        let p = self.inner.engine.peers.get(&peer.into())?.value().clone();
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
            dropped_unauthenticated: e.dropped_unauthenticated.load(Ordering::Relaxed),
            dropped_forged: e.dropped_forged.load(Ordering::Relaxed),
            ..relay_stats(e)
        }
    }

    /// Return a clonable send handle that shares this socket's underlying state.
    ///
    /// The returned [`ZudpSender`] can be cheaply cloned and sent across tasks.
    #[must_use]
    pub fn sender(&self) -> ZudpSender {
        ZudpSender {
            inner: self.inner.clone(),
        }
    }

    /// Subscribe to peer lifecycle events; see [`PeerEvent`].
    #[must_use]
    pub fn events(&self) -> PeerEvents {
        self.inner.events()
    }

    /// Forget `peer` now: drop its session, buffers and receive state and emit
    /// [`PeerEvent::Disconnected`] with [`DisconnectReason::Removed`].  Returns `false` when
    /// the peer was unknown.
    #[must_use = "false means the peer was not known"]
    pub fn remove_peer(&self, peer: impl Into<PeerAddr>) -> bool {
        self.inner.engine.remove_peer(peer.into())
    }

    /// Open a session with the direct peer at `peer` from this socket and return its handle.
    ///
    /// Same as [`Zudp::connect`] without binding a new socket: with security on, the
    /// handshake and one authenticated round trip complete before it returns, and a session
    /// that is already up is reused.  Typically used to reach a relay node before
    /// [`connect_via`](Self::connect_via).
    ///
    /// # Errors
    /// `Error::HandshakeTimeout` or `Error::KeyMismatch` when the handshake fails;
    /// [`Error::Io`] when the first datagram cannot be sent.
    pub async fn connect(&self, peer: SocketAddr) -> Result<PeerAddr, Error> {
        Ok(*self.inner.connect(peer).await?.read())
    }

    /// Open an end-to-end session with the peer whose static public key is `target`,
    /// through the relay node at `relay`, and return its handle
    /// ([`PeerAddr::Relayed`]).
    ///
    /// This socket must already hold a session with the relay (see
    /// [`connect`](Self::connect)).  The Noise XX handshake with `target` runs through the
    /// relay; the relay forwards it, and everything after it, as opaque bytes it cannot
    /// decrypt or forge.  The session authenticates `target` itself — a relay that delivers
    /// another key's handshake makes this fail with [`Error::KeyMismatch`] — and pinned keys
    /// ([`Zudp::pin_remote_key`]) apply as for direct peers.  Relayed peers get the full
    /// feature set: reliable streams, fragmentation (at an MTU reduced by the relay
    /// overhead), congestion control, keepalives, timeouts and [`PeerEvent`]s.
    ///
    /// Unless [`Zudp::punching`] is off, both ends then try to punch a direct path and move
    /// the session onto it ([`PeerEvent::PathChanged`]); the handle stays the same.
    ///
    /// The other end needs no call: an incoming relayed session shows up as
    /// [`PeerEvent::Connected`] with a relayed handle, and its messages arrive in `recv`.
    ///
    /// # Errors
    /// - [`Error::NoSession`] (naming the relay) without a secure session with the relay.
    /// - [`Error::Unreachable`] when the relay cannot reach `target` — it is not connected
    ///   to the relay or the relay's policy refuses; the relay does not say which.
    /// - [`Error::HandshakeTimeout`] / [`Error::KeyMismatch`] as for [`Zudp::connect`].
    #[cfg(feature = "security")]
    pub async fn connect_via(
        &self,
        relay: SocketAddr,
        target: [u8; 32],
    ) -> Result<PeerAddr, Error> {
        Ok(*self.inner.connect_via(relay, target).await?.read())
    }

    /// The path `peer`'s traffic takes right now: [`Path::Direct`] for direct peers and
    /// punched relayed peers, [`Path::Relayed`] for relayed peers still on their relay.
    /// `None` when the peer is unknown.
    #[must_use]
    pub fn peer_path(&self, peer: impl Into<PeerAddr>) -> Option<Path> {
        self.inner.peer_path(peer.into())
    }

    /// Replace this relay node's policy at runtime; `None` lets every client reach every
    /// other.  Does nothing on a socket that is not a relay node.
    #[cfg(feature = "relay")]
    pub fn set_relay_policy(&self, policy: Option<Arc<dyn RelayPolicy>>) {
        if let Some(node) = &self.inner.engine.relay {
            node.set_policy(policy);
        }
    }

    /// Test hook: intercept what this relay node forwards; see [`RelayTap`].
    #[cfg(feature = "relay")]
    #[doc(hidden)]
    pub fn set_relay_tap(&self, tap: Option<RelayTap>) {
        if let Some(node) = &self.inner.engine.relay {
            node.set_tap(tap);
        }
    }

    /// Test hook: silently lose every datagram to and from `addr` (or stop doing so), as
    /// if the network path to it broke.  Not part of the stable API.
    #[doc(hidden)]
    pub fn debug_block_addr(&self, addr: SocketAddr, blocked: bool) {
        self.inner.engine.get_socket().set_blocked(addr, blocked);
    }

    /// The remote peer's X25519 static public key as negotiated by the Noise
    /// handshake.  Returns `None` if the peer is unknown or the handshake has
    /// not yet completed.
    #[cfg(feature = "security")]
    #[must_use]
    pub fn peer_remote_static_key(&self, peer: impl Into<PeerAddr>) -> Option<[u8; 32]> {
        self.inner
            .engine
            .peers
            .get(&peer.into())
            .and_then(|p| p.remote_static_key())
    }

    /// Send a reliable, ordered message to `peer` on stream 0.
    ///
    /// Reliability uses NACK-based retransmission. For fire-and-forget,
    /// use [`send_unreliable`](Self::send_unreliable). To target a specific
    /// stream, use [`send_stream`](Self::send_stream).
    ///
    /// # Errors
    /// Returns `Err` on I/O failure or if the message is too large to fragment.
    pub async fn send(&self, msg: M, peer: impl Into<PeerAddr>) -> Result<(), Error>
    where
        M: Encode,
    {
        self.inner
            .send_msg(&msg, peer.into(), true, DEFAULT_STREAM)
            .await
    }

    /// Send a reliable, ordered message to `peer` on the given `stream_id`.
    ///
    /// Each stream maintains an independent sequence space, so loss on one
    /// stream never blocks delivery on another (no head-of-line blocking).
    ///
    /// # Errors
    /// Returns `Err` on I/O failure or if the message is too large to fragment.
    pub async fn send_stream(
        &self,
        msg: M,
        peer: impl Into<PeerAddr>,
        stream_id: u16,
    ) -> Result<(), Error>
    where
        M: Encode,
    {
        self.inner
            .send_msg(&msg, peer.into(), true, stream_id)
            .await
    }

    /// Send an unreliable, unordered datagram to `peer`.
    ///
    /// No retransmission. Zero overhead beyond the 1-byte frame type tag.
    ///
    /// # Errors
    /// Returns `Err` on I/O failure.
    pub async fn send_unreliable(&self, msg: M, peer: impl Into<PeerAddr>) -> Result<(), Error>
    where
        M: Encode,
    {
        self.inner
            .send_msg(&msg, peer.into(), false, DEFAULT_STREAM)
            .await
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
    peer: Arc<RwLock<PeerAddr>>,
    events: PeerEvents,
}

impl<M> ZudpConn<M> {
    fn new(socket: ZudpSocket<M>, peer: Arc<RwLock<PeerAddr>>) -> Self {
        let events = socket.events();
        Self {
            socket,
            peer,
            events,
        }
    }

    /// The path the bound peer's traffic currently takes; see [`ZudpSocket::peer_path`].
    #[must_use]
    pub fn path(&self) -> Option<Path> {
        self.socket.peer_path(self.peer())
    }

    /// Subscribe to peer lifecycle events; see [`PeerEvent`].
    #[must_use]
    pub fn events(&self) -> PeerEvents {
        self.socket.events()
    }

    /// Current handle of the remote peer.
    ///
    /// For a direct peer it is updated automatically when the peer migrates to a new
    /// network interface; a relayed peer keeps its handle for the whole session.
    #[must_use]
    pub fn peer(&self) -> PeerAddr {
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

    /// Congestion factor (SRTT / `min_RTT`).
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
    /// - [`Error::PeerTimeout`] once nothing was heard from the peer for the peer timeout
    ///   (messages that arrived before are still returned first).
    /// - [`Error::EngineStopped`] if the engine task has stopped.
    pub async fn recv(&mut self) -> Result<Packet<M>, Error>
    where
        M: Decode,
    {
        loop {
            let pkt = tokio::select! {
                biased;
                pkt = self.socket.recv() => pkt?,
                event = self.events.recv() => {
                    if let Ok(PeerEvent::Disconnected { addr, reason: DisconnectReason::TimedOut }) = event
                        && addr == *self.peer.read()
                    {
                        return Err(Error::PeerTimeout { peer: addr });
                    }
                    continue;
                }
            };
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
