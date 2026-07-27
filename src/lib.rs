//! # ZUDP — Zero UDP
//!
//! A minimal, low-overhead UDP protocol with optional reliability, fragmentation,
//! keepalives, and relay/tunnel support.
//!
//! ## Quick start
//!
//! ```rust,no_run
//! use zudp::{Zudp, Encode, Decode};
//!
//! #[derive(bitcode::Encode, bitcode::Decode)]
//! enum Msg { Ping, Pong, Data(Vec<u8>) }
//!
//! #[tokio::main]
//! async fn main() -> anyhow::Result<()> {
//!     // Multi-peer socket — type on the terminal call
//!     let mut socket = Zudp::default().port(5000).listen::<Msg>().await?;
//!     let (msg, from) = socket.recv().await?;
//!
//!     // Single-peer connection
//!     let mut conn = Zudp::default().port(0).connect::<Msg>("1.2.3.4:5000".parse()?).await?;
//!     conn.send(Msg::Ping).await?;
//!     let reply = conn.recv().await?;
//!     Ok(())
//! }
//! ```

mod codec;
mod engine;
mod error;
mod frag;
mod frame;
mod peer;
mod socket;

pub use codec::{Decode, Encode};
pub use error::Error;

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
    /// # Errors
    /// Returns `Err` if the OS refuses to bind the requested address/port.
    pub async fn connect<M>(self, peer: SocketAddr) -> Result<ZudpConn<M>, Error> {
        let socket = ZudpSocket::new(self.config).await?;
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
    ) -> Result<(Arc<Self>, mpsc::UnboundedReceiver<(Bytes, SocketAddr)>), Error> {
        let addr = SocketAddr::new(config.bind_ip, config.port);
        let socket = RawSocket::bind(addr).await?;
        let config = Arc::new(config);
        let engine = Arc::new(EngineInner {
            socket,
            peers: RwLock::new(std::collections::HashMap::new()),
            config: config.clone(),
        });
        let rx = engine::spawn(engine.clone());
        let inner = Arc::new(Self {
            engine,
            config,
            next_msg_id: AtomicU32::new(0),
        });
        Ok((inner, rx))
    }

    fn alloc_msg_id(&self) -> u32 {
        self.next_msg_id.fetch_add(1, Ordering::Relaxed)
    }

    fn get_or_create_peer(&self, addr: SocketAddr) -> Arc<PeerState> {
        self.engine.get_or_create_peer(addr)
    }

    /// Encode and send a message to `dest`.
    ///
    /// If `reliable` is `true` and the protocol config has reliability enabled,
    /// the frame is tracked for NACK-triggered retransmission.
    async fn send_msg<M: Encode>(
        &self,
        msg: &M,
        dest: SocketAddr,
        reliable: bool,
    ) -> Result<(), Error> {
        let payload = Bytes::from(msg.encode_to_bytes()?);

        let actual_dest = self.config.relay_addr.unwrap_or(dest);
        let wrap_relay = self.config.relay_addr.is_some();

        let reliable = reliable && self.config.reliable;

        if payload.len() <= self.config.mtu {
            self.send_single(payload, dest, actual_dest, wrap_relay, reliable)
                .await
        } else {
            self.send_fragmented(payload, dest, actual_dest, wrap_relay)
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
    ) -> Result<(), Error> {
        if reliable {
            let peer = self.get_or_create_peer(peer_addr);
            let seq = peer.alloc_seq();
            let frame = Frame::Stream { seq, payload }.encode();
            let wire = if wrap_relay {
                Frame::Relay {
                    dest: peer_addr,
                    inner: frame.clone(),
                }
                .encode()
            } else {
                frame.clone()
            };
            self.engine.socket.send_to(&wire, actual_dest).await?;
            peer.record_sent(seq, frame);
        } else if wrap_relay {
            let frame = Frame::Datagram(payload).encode();
            let wire = Frame::Relay { dest: peer_addr, inner: frame }.encode();
            self.engine.socket.send_to(&wire, actual_dest).await?;
        } else {
            // Scatter-gather: send payload + 1-byte type tag without copying payload.
            let type_tag = [frame::TYPE_DATAGRAM];
            self.engine
                .socket
                .send_to_vectored(
                    &[std::io::IoSlice::new(&payload), std::io::IoSlice::new(&type_tag)],
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
            let seq = peer.alloc_seq();
            let frame = Frame::Fragment {
                msg_id,
                frag_idx,
                frag_total,
                seq,
                payload: chunk,
            }
            .encode();
            let wire = if wrap_relay {
                Frame::Relay {
                    dest: peer_addr,
                    inner: frame.clone(),
                }
                .encode()
            } else {
                frame.clone()
            };
            self.engine.socket.send_to(&wire, actual_dest).await?;
            peer.record_sent(seq, frame);
        }
        Ok(())
    }
}

// ── ZudpSocket (multi-peer) ────────────────────────────────────────────────────

/// A ZUDP socket that sends and receives messages from any remote peer.
///
/// Created by [`Zudp::listen`].
pub struct ZudpSocket<M> {
    inner: Arc<Inner>,
    rx: mpsc::UnboundedReceiver<(Bytes, SocketAddr)>,
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

    /// Send a reliable, ordered message to `peer`.
    ///
    /// Reliability uses NACK-based retransmission. For fire-and-forget,
    /// use [`send_unreliable`](Self::send_unreliable).
    ///
    /// # Errors
    /// Returns `Err` on I/O failure or if the message is too large to fragment.
    pub async fn send(&self, msg: M, peer: SocketAddr) -> Result<(), Error>
    where
        M: Encode,
    {
        self.inner.send_msg(&msg, peer, true).await
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
        self.inner.send_msg(&msg, peer, false).await
    }

    /// Receive the next message from any peer.
    ///
    /// # Errors
    /// Returns `Err(Error::ChannelClosed)` if the engine task has stopped.
    pub async fn recv(&mut self) -> Result<(M, SocketAddr), Error>
    where
        M: Decode,
    {
        loop {
            let (bytes, from) = self.rx.recv().await.ok_or(Error::ChannelClosed)?;
            match M::decode_from_bytes(&bytes) {
                Ok(msg) => return Ok((msg, from)),
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

    /// Send a reliable, ordered message to the bound peer.
    ///
    /// # Errors
    /// Returns `Err` on I/O failure or if the message is too large to fragment.
    pub async fn send(&self, msg: M) -> Result<(), Error>
    where
        M: Encode,
    {
        self.socket.send(msg, self.peer).await
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

    /// Receive the next message from the bound peer.
    ///
    /// Messages from other peers are silently discarded.
    ///
    /// # Errors
    /// Returns `Err(Error::ChannelClosed)` if the engine task has stopped.
    pub async fn recv(&mut self) -> Result<M, Error>
    where
        M: Decode,
    {
        loop {
            let (msg, from) = self.socket.recv().await?;
            if from == self.peer {
                return Ok(msg);
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
