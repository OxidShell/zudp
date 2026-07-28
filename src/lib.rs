//! # ZUDP — Zero UDP
//!
//! A minimal, low-overhead UDP protocol with optional reliability, fragmentation,
//! keepalives, and relay/tunnel support.
//!
//! ## Quick start
//!
//! ```rust,no_run
//! use zudp::bitcode::{Encode, Decode};
//! use zudp::Zudp;
//!
//! #[derive(Encode, Decode)]
//! enum Msg { Ping, Pong, Data(Vec<u8>) }
//!
//! #[tokio::main]
//! async fn main() -> anyhow::Result<()> {
//!     // Multi-peer socket — type on the terminal call
//!     let mut socket = Zudp::default().port(5000).listen::<Msg>().await?;
//!     let (msg, from, _stream) = socket.recv().await?;
//!
//!     // Single-peer connection
//!     let mut conn = Zudp::default().port(0).connect::<Msg>("1.2.3.4:5000".parse()?).await?;
//!     conn.send(Msg::Ping).await?;
//!     let reply = conn.recv().await?;
//!     Ok(())
//! }
//! ```

mod codec;
#[cfg(feature = "discovery")]
mod discovery;
mod engine;
mod error;
mod frag;
mod frame;
mod peer;
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
        atomic::{AtomicU32, Ordering},
    },
    time::Duration,
};

use bytes::Bytes;
use parking_lot::RwLock;
use tokio::sync::mpsc;

use engine::EngineInner;
use frag::fragment;
use frame::Frame;
use peer::PeerState;
use socket::RawSocket;

// ── Config ────────────────────────────────────────────────────────────────────

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
        }
    }
}

// ── Builder ───────────────────────────────────────────────────────────────────

/// Entry point for constructing a ZUDP socket.
///
/// Chain configuration methods, then call `.listen::<M>()` or `.connect::<M>(peer)`.
/// The message type `M` can also be inferred from a variable annotation:
///
/// ```rust,no_run
/// # use zudp::{Zudp, ZudpSocket};
/// # #[derive(bitcode::Encode, bitcode::Decode)] enum Msg { Hi }
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
    /// [`.security()`](Self::security), the Noise XX handshake is initiated
    /// automatically before returning.
    ///
    /// # Errors
    /// Returns `Err` if the OS refuses to bind the requested address/port.
    pub async fn connect<M>(self, peer: SocketAddr) -> Result<ZudpConn<M>, Error> {
        let socket = ZudpSocket::new(self.config).await?;
        #[cfg(feature = "security")]
        if socket.inner.config.security.is_some() {
            socket.inner.initiate_handshake(peer).await?;
        }
        Ok(ZudpConn { socket, peer })
    }
}

// ── Shared socket internals ───────────────────────────────────────────────────

struct Inner {
    engine: Arc<EngineInner>,
    config: Arc<Config>,
    next_msg_id: AtomicU32,
}

impl Inner {
    async fn new(
        config: Config,
    ) -> Result<(Arc<Self>, mpsc::UnboundedReceiver<(Bytes, SocketAddr, u16)>), Error> {
        let addr = SocketAddr::new(config.bind_ip, config.port);
        let socket = RawSocket::bind(addr).await?;
        let config = Arc::new(config);
        let engine = Arc::new(EngineInner {
            socket,
            peers: RwLock::new(std::collections::HashMap::new()),
            config: config.clone(),
            #[cfg(feature = "security")]
            keypair: config.security.clone(),
        });
        let rx = engine::spawn(engine.clone());
        let inner = Arc::new(Self {
            engine,
            config,
            next_msg_id: AtomicU32::new(0),
        });
        Ok((inner, rx))
    }

    /// Initiate a Noise XX handshake toward `peer`.
    ///
    /// Writes msg1, stores the in-progress `HandshakeState` in the peer slot,
    /// and returns.  The engine drives the remaining two messages.
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
        self.engine.socket.send_to(&wire, peer_addr).await?;

        let peer = self.get_or_create_peer(peer_addr);
        *peer.handshake.lock() = Some(hs);

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

        if payload.len() <= self.config.mtu {
            self.send_single(payload, dest, actual_dest, wrap_relay, reliable, stream_id)
                .await
        } else {
            self.send_fragmented(payload, dest, actual_dest, wrap_relay, stream_id)
                .await
        }
    }

    async fn send_single(
        &self,
        payload: Bytes,
        peer_addr: SocketAddr,
        actual_dest: SocketAddr,
        wrap_relay: bool,
        reliable: bool,
        stream_id: u16,
    ) -> Result<(), Error> {
        if reliable {
            let peer = self.get_or_create_peer(peer_addr);
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
                    dest: peer_addr,
                    inner: inner_wire,
                }
                .encode()
            } else {
                inner_wire
            };
            self.engine.socket.send_to(&wire, actual_dest).await?;
            peer.record_sent(stream_id, seq, plain_frame);
        } else if wrap_relay {
            let frame = Frame::Datagram(payload).encode();
            let wire = Frame::Relay {
                dest: peer_addr,
                inner: frame,
            }
            .encode();
            self.engine.socket.send_to(&wire, actual_dest).await?;
        } else {
            // Scatter-gather: send payload + 1-byte type tag without copying payload.
            // (Unreliable datagrams are not encrypted — no peer channel tracking for these.)
            let type_tag = [frame::TYPE_DATAGRAM];
            self.engine
                .socket
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
        peer_addr: SocketAddr,
        actual_dest: SocketAddr,
        wrap_relay: bool,
        stream_id: u16,
    ) -> Result<(), Error> {
        let chunks = fragment(&payload, self.config.mtu)?;
        let msg_id = self.alloc_msg_id();
        // fragment() guarantees chunks.len() ≤ MAX_FRAGMENTS = u16::MAX; error if not.
        let frag_total = u16::try_from(chunks.len()).map_err(|_| Error::MessageTooLarge {
            got: chunks.len(),
            max: frag::MAX_FRAGMENTS,
        })?;
        let peer = self.get_or_create_peer(peer_addr);

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
                    dest: peer_addr,
                    inner: inner_wire,
                }
                .encode()
            } else {
                inner_wire
            };
            self.engine.socket.send_to(&wire, actual_dest).await?;
            peer.record_sent(stream_id, seq, plain_frame);
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

// ── ZudpSocket (multi-peer) ────────────────────────────────────────────────────

/// A ZUDP socket that sends and receives messages from any remote peer.
///
/// Created by [`Zudp::listen`].
pub struct ZudpSocket<M> {
    inner: Arc<Inner>,
    rx: mpsc::UnboundedReceiver<(Bytes, SocketAddr, u16)>,
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
        self.inner.engine.socket.local_addr()
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
    /// Returns `(message, sender_addr, stream_id)`.
    ///
    /// # Errors
    /// Returns `Err(Error::ChannelClosed)` if the engine task has stopped.
    pub async fn recv(&mut self) -> Result<(M, SocketAddr, u16), Error>
    where
        M: Decode,
    {
        loop {
            let (bytes, from, stream_id) = self.rx.recv().await.ok_or(Error::ChannelClosed)?;
            match M::decode_from_bytes(&bytes) {
                Ok(msg) => return Ok((msg, from, stream_id)),
                Err(e) => {
                    tracing::warn!(target: "zudp", peer = %from, "decode failed: {e}");
                }
            }
        }
    }
}

// ── ZudpConn (single-peer) ────────────────────────────────────────────────────

/// A ZUDP socket bound to a single remote peer.
///
/// Created by [`Zudp::connect`].
/// `send()` and `recv()` target `peer` exclusively.
pub struct ZudpConn<M> {
    socket: ZudpSocket<M>,
    peer: SocketAddr,
}

impl<M> ZudpConn<M> {
    /// Remote peer address.
    #[must_use]
    pub fn peer(&self) -> SocketAddr {
        self.peer
    }

    /// Local address this socket is bound to.
    ///
    /// # Errors
    /// Returns `Err` if the OS cannot retrieve the socket's local address.
    #[must_use = "the address is returned, not printed"]
    pub fn local_addr(&self) -> Result<SocketAddr, Error> {
        self.socket.local_addr()
    }

    /// Send a reliable, ordered message to the bound peer on stream 0.
    ///
    /// # Errors
    /// Returns `Err` on I/O failure or if the message is too large to fragment.
    pub async fn send(&self, msg: M) -> Result<(), Error>
    where
        M: Encode,
    {
        self.socket.send(msg, self.peer).await
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
        self.socket.send_stream(msg, self.peer, stream_id).await
    }

    /// Send an unreliable datagram to the bound peer.
    ///
    /// # Errors
    /// Returns `Err` on I/O failure.
    pub async fn send_unreliable(&self, msg: M) -> Result<(), Error>
    where
        M: Encode,
    {
        self.socket.send_unreliable(msg, self.peer).await
    }

    /// Receive the next message from the bound peer on any stream.
    ///
    /// Returns `(message, stream_id)`. Messages from other peers are silently discarded.
    ///
    /// # Errors
    /// Returns `Err(Error::ChannelClosed)` if the engine task has stopped.
    pub async fn recv(&mut self) -> Result<(M, u16), Error>
    where
        M: Decode,
    {
        loop {
            let (msg, from, stream_id) = self.socket.recv().await?;
            if from == self.peer {
                return Ok((msg, stream_id));
            }
            tracing::debug!(
                target: "zudp",
                unexpected = %from,
                expected = %self.peer,
                "dropping message from unexpected peer"
            );
        }
    }
}
