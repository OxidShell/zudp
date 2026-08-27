#![allow(clippy::module_name_repetitions)]

use std::{
    collections::HashSet,
    marker::PhantomData,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use bytes::{Bytes, BytesMut};
use parking_lot::RwLock;
use tokio::{net::UdpSocket, task::AbortHandle, time};

use crate::{Decode, Encode, Error, frame::Frame};

const PROTO_VER: u16 = 1;

/// Default UDP port for discovery probes and beacons.
pub const DISCOVERY_PORT: u16 = 7701;

fn fnv1a(bytes: &[u8]) -> u64 {
    let mut h: u64 = 14_695_981_039_346_656_037;
    for &b in bytes {
        h ^= u64::from(b);
        h = h.wrapping_mul(1_099_511_628_211);
    }
    h
}

/// Stable application identifier derived from a string name via FNV-1a.
///
/// Two nodes using the same string name will have the same `AppId`,
/// ensuring discovery only surfaces peers running the same application.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AppId(u64);

impl AppId {
    /// Derive an `AppId` from any string-like value.
    #[must_use]
    pub fn of(name: impl AsRef<str>) -> Self {
        Self(fnv1a(name.as_ref().as_bytes()))
    }

    /// The raw 64-bit hash.
    #[must_use]
    pub fn raw(self) -> u64 {
        self.0
    }
}

impl From<&str> for AppId {
    fn from(s: &str) -> Self {
        Self::of(s)
    }
}

impl From<String> for AppId {
    fn from(s: String) -> Self {
        Self::of(&s)
    }
}

impl From<u64> for AppId {
    fn from(v: u64) -> Self {
        Self(v)
    }
}

/// Configuration for a discovery session.
///
/// Build with [`DiscoveryConfig::new`] then chain optional builder methods:
///
/// ```rust,no_run
/// # use zudp::DiscoveryConfig;
/// # use std::time::Duration;
/// let cfg = DiscoveryConfig::new("my-game", 7700)
///     .probe_interval(Duration::from_secs(2));
/// ```
pub struct DiscoveryConfig<M = ()> {
    pub(crate) app_id: AppId,
    pub(crate) data_port: u16,
    pub(crate) discovery_port: u16,
    pub(crate) probe_interval: Duration,
    pub(crate) meta: M,
}

impl DiscoveryConfig<()> {
    /// Construct a config with the two required parameters.
    ///
    /// - `app_id`: any type convertible to [`AppId`] — a `&str`, `String`, or raw `u64`.
    /// - `data_port`: the ZUDP data port this node listens on (advertised to peers).
    #[must_use]
    pub fn new(app_id: impl Into<AppId>, data_port: u16) -> Self {
        Self {
            app_id: app_id.into(),
            data_port,
            discovery_port: DISCOVERY_PORT,
            probe_interval: Duration::from_secs(5),
            meta: (),
        }
    }
}

impl<M> DiscoveryConfig<M> {
    /// Attach metadata that is broadcast to peers alongside this node's beacon.
    ///
    /// Calling this changes the config's generic type from `M` to `N`, enabling
    /// the typestate pattern:
    ///
    /// ```rust,no_run
    /// # use zudp::DiscoveryConfig;
    /// # #[derive(bitcode::Encode, bitcode::Decode, Clone)] struct GameInfo { name: String }
    /// let cfg = DiscoveryConfig::new("my-game", 7700)
    ///     .meta(GameInfo { name: "Alice".into() });
    /// ```
    pub fn meta<N>(self, meta: N) -> DiscoveryConfig<N> {
        DiscoveryConfig {
            app_id: self.app_id,
            data_port: self.data_port,
            discovery_port: self.discovery_port,
            probe_interval: self.probe_interval,
            meta,
        }
    }

    /// Override the discovery UDP port (default: [`DISCOVERY_PORT`]).
    #[must_use]
    pub fn discovery_port(mut self, port: u16) -> Self {
        self.discovery_port = port;
        self
    }

    /// Interval between broadcast re-probes when scanning (default: 5 s).
    #[must_use]
    pub fn probe_interval(mut self, interval: Duration) -> Self {
        self.probe_interval = interval;
        self
    }
}

impl<A: Into<AppId>> From<(A, u16)> for DiscoveryConfig<()> {
    fn from((app_id, data_port): (A, u16)) -> Self {
        Self::new(app_id, data_port)
    }
}

impl<A: Into<AppId>, M> From<(A, u16, M)> for DiscoveryConfig<M> {
    fn from((app_id, data_port, meta): (A, u16, M)) -> Self {
        DiscoveryConfig::new(app_id, data_port).meta(meta)
    }
}

/// A peer found on the local network.
#[derive(Debug, Clone)]
pub struct DiscoveredPeer<M> {
    /// Source address of the beacon (the peer's discovery socket).
    pub from: SocketAddr,
    /// Address to pass to [`crate::Zudp::connect`] to open a data connection.
    pub data_addr: SocketAddr,
    /// Application-defined metadata the peer is advertising.
    pub meta: M,
}

/// Handle to a running advertise task.
///
/// Dropping this handle stops the advertisement immediately.
pub struct AdvertiseHandle<M> {
    meta: Arc<RwLock<M>>,
    abort: AbortHandle,
}

impl<M: Send + 'static> AdvertiseHandle<M> {
    /// Replace the metadata sent in future beacons without restarting the task.
    pub fn set_meta(&self, meta: M) {
        *self.meta.write() = meta;
    }
}

impl<M> Drop for AdvertiseHandle<M> {
    fn drop(&mut self) {
        self.abort.abort();
    }
}

/// Continuous stream of newly discovered peers.
///
/// Created by [`Discovery::scan_stream`]. Each call to [`next`](Self::next)
/// blocks until a previously-unseen peer responds, yielding it exactly once
/// (deduped by data address). Re-probes the network at `probe_interval` to
/// catch peers that join after the scan begins.
pub struct ScanStream<M> {
    socket: Arc<UdpSocket>,
    app_id: u64,
    broadcast_addr: SocketAddr,
    ticker: time::Interval,
    seen: HashSet<SocketAddr>,
    _phantom: PhantomData<fn() -> M>,
}

impl<M: Decode> ScanStream<M> {
    /// Wait for the next newly-discovered peer.
    ///
    /// Never returns `Ok` for a peer already reported in this session.
    ///
    /// # Errors
    /// Returns `Err` on I/O or message-decode failure.
    pub async fn next(&mut self) -> Result<DiscoveredPeer<M>, Error> {
        loop {
            tokio::select! {
                biased;

                result = recv_frame(&self.socket) => {
                    let (frame, from) = result?;
                    let Frame::Beacon { app_id, proto_ver, data_port, meta } = frame else {
                        continue;
                    };
                    if app_id != self.app_id || proto_ver != PROTO_VER {
                        continue;
                    }
                    let data_addr = SocketAddr::new(from.ip(), data_port);
                    if !self.seen.insert(data_addr) {
                        continue;
                    }
                    let meta = M::decode_from_bytes(&meta)?;
                    return Ok(DiscoveredPeer { from, data_addr, meta });
                }

                _ = self.ticker.tick() => {
                    let probe = Frame::Probe {
                        app_id: self.app_id,
                        proto_ver: PROTO_VER,
                    }.encode();
                    let _ = self.socket.send_to(&probe, self.broadcast_addr).await;
                }
            }
        }
    }
}

/// LAN peer discovery service.
///
/// All methods are associated functions — no shared state is held between calls.
/// Each operation binds its own ephemeral discovery socket.
pub struct Discovery;

impl Discovery {
    /// Start advertising this node on the LAN.
    ///
    /// Binds a discovery socket on `config.discovery_port` and responds to
    /// incoming [`Frame::Probe`] frames with a [`Frame::Beacon`] carrying `meta`.
    /// The task runs until the returned [`AdvertiseHandle`] is dropped.
    ///
    /// # Errors
    /// Returns `Err` if the OS refuses to bind the discovery port.
    #[must_use = "dropping the handle stops advertising"]
    pub fn advertise<C, M>(config: C) -> Result<AdvertiseHandle<M>, Error>
    where
        C: Into<DiscoveryConfig<M>>,
        M: Encode + Send + Sync + 'static,
    {
        let cfg = config.into();
        let socket = Arc::new(bind_discovery_socket(cfg.discovery_port)?);
        let meta = Arc::new(RwLock::new(cfg.meta));
        let meta_arc = meta.clone();

        let jh = tokio::spawn(run_advertise(
            socket,
            cfg.app_id.raw(),
            cfg.data_port,
            meta_arc,
        ));
        Ok(AdvertiseHandle {
            meta,
            abort: jh.abort_handle(),
        })
    }

    /// Open a continuous scan for peers with a matching app ID.
    ///
    /// Sends an initial broadcast probe then returns a [`ScanStream`] that
    /// yields each newly-seen peer exactly once, re-probing at `probe_interval`.
    ///
    /// # Errors
    /// Returns `Err` if binding or the initial probe broadcast fails.
    pub async fn scan_stream<M>(
        config: impl Into<DiscoveryConfig<()>>,
    ) -> Result<ScanStream<M>, Error>
    where
        M: Decode,
    {
        let cfg = config.into();
        // Bind our own port, not cfg.discovery_port: a node that also has
        // advertise() running already owns that port, and a second bind
        // only fans out on SO_REUSEPORT (no Windows). Advertisers still
        // listen on discovery_port so probes still reach them.
        let socket = Arc::new(bind_discovery_socket(0)?);
        let broadcast_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::BROADCAST), cfg.discovery_port);

        let probe = Frame::Probe {
            app_id: cfg.app_id.raw(),
            proto_ver: PROTO_VER,
        }
        .encode();
        socket.send_to(&probe, broadcast_addr).await?;

        let mut ticker = time::interval(cfg.probe_interval);
        ticker.set_missed_tick_behavior(time::MissedTickBehavior::Skip);
        ticker.tick().await; // discard immediate first tick

        Ok(ScanStream {
            socket,
            app_id: cfg.app_id.raw(),
            broadcast_addr,
            ticker,
            seen: HashSet::new(),
            _phantom: PhantomData,
        })
    }

    /// Scan once and collect all peers that respond within `timeout`.
    ///
    /// # Errors
    /// Returns `Err` if binding, the probe broadcast, or any response decode fails.
    pub async fn scan_once<M>(
        config: impl Into<DiscoveryConfig<()>>,
        timeout: Duration,
    ) -> Result<Vec<DiscoveredPeer<M>>, Error>
    where
        M: Decode,
    {
        let cfg = config.into();
        // Same as scan_stream: bind our own port instead of discovery_port.
        let socket = bind_discovery_socket(0)?;
        let broadcast_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::BROADCAST), cfg.discovery_port);
        let app_id = cfg.app_id.raw();

        let probe = Frame::Probe {
            app_id,
            proto_ver: PROTO_VER,
        }
        .encode();
        socket.send_to(&probe, broadcast_addr).await?;

        let mut peers = Vec::new();
        let mut seen: HashSet<SocketAddr> = HashSet::new();
        let deadline = time::Instant::now() + timeout;

        loop {
            let remaining = deadline.saturating_duration_since(time::Instant::now());
            if remaining.is_zero() {
                break;
            }
            match time::timeout(remaining, recv_frame(&socket)).await {
                Err(_elapsed) => break,
                Ok(Err(e)) => return Err(e),
                Ok(Ok((
                    Frame::Beacon {
                        app_id: bid,
                        proto_ver,
                        data_port,
                        meta,
                    },
                    from,
                ))) if bid == app_id && proto_ver == PROTO_VER => {
                    let data_addr = SocketAddr::new(from.ip(), data_port);
                    if seen.insert(data_addr) {
                        let meta = M::decode_from_bytes(&meta)?;
                        peers.push(DiscoveredPeer {
                            from,
                            data_addr,
                            meta,
                        });
                    }
                }
                Ok(Ok(_)) => {}
            }
        }

        Ok(peers)
    }
}

fn bind_discovery_socket(port: u16) -> Result<UdpSocket, Error> {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port);
    let sock = socket2::Socket::new(
        socket2::Domain::IPV4,
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )?;
    #[cfg(unix)]
    sock.set_reuse_port(true)?;
    sock.set_reuse_address(true)?;
    sock.set_broadcast(true)?;
    sock.set_nonblocking(true)?;
    sock.bind(&socket2::SockAddr::from(addr))?;
    let std_sock: std::net::UdpSocket = sock.into();
    Ok(UdpSocket::from_std(std_sock)?)
}

async fn recv_frame(socket: &UdpSocket) -> Result<(Frame, SocketAddr), Error> {
    let mut buf = BytesMut::with_capacity(65_536);
    let (_, addr) = socket.recv_buf_from(&mut buf).await?;
    Frame::decode(buf).map(|f| (f, addr))
}

async fn run_advertise<M: Encode + Send + Sync + 'static>(
    socket: Arc<UdpSocket>,
    app_id: u64,
    data_port: u16,
    meta: Arc<RwLock<M>>,
) {
    loop {
        let (frame, from) = match recv_frame(&socket).await {
            Ok(pair) => pair,
            Err(e) => {
                tracing::warn!(target: "zudp::discovery", "recv error: {e}");
                break;
            }
        };

        let Frame::Probe {
            app_id: pid,
            proto_ver,
        } = frame
        else {
            continue;
        };
        if pid != app_id || proto_ver != PROTO_VER {
            continue;
        }

        let meta_bytes = match meta.read().encode_to_bytes() {
            Ok(b) => Bytes::from(b),
            Err(e) => {
                tracing::warn!(target: "zudp::discovery", "meta encode error: {e}");
                continue;
            }
        };

        let beacon = Frame::Beacon {
            app_id,
            proto_ver: PROTO_VER,
            data_port,
            meta: meta_bytes,
        }
        .encode();

        if let Err(e) = socket.send_to(&beacon, from).await {
            tracing::warn!(target: "zudp::discovery", %from, "beacon send failed: {e}");
        }
    }
}
