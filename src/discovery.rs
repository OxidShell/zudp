#![allow(clippy::module_name_repetitions)]

use std::{
    collections::{HashMap, HashSet, VecDeque},
    marker::PhantomData,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
    time::{Duration, Instant},
};

use bytes::{Bytes, BytesMut};
use parking_lot::RwLock;
use tokio::{net::UdpSocket, task::AbortHandle, time};

use crate::{Decode, Encode, Error, frame::Frame, socket::is_transient_recv_error};

/// Discovery wire version.  2: beacons carry the advertiser instance id.
const PROTO_VER: u16 = 2;

const RECV_BUF: usize = 65_536;

/// Pause after a hard receive error on the advertise socket before trying again.
const ADVERTISE_ERROR_BACKOFF: Duration = Duration::from_millis(100);

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
    pub(crate) broadcast_addr: Ipv4Addr,
    pub(crate) peer_ttl: Option<Duration>,
    pub(crate) probes: ProbePlan,
    pub(crate) meta: M,
}

/// Where a scan sends its probes besides `broadcast_addr`.
#[derive(Debug, Clone)]
pub(crate) struct ProbePlan {
    pub(crate) loopback: bool,
    pub(crate) interfaces: bool,
    pub(crate) extra: Vec<SocketAddr>,
}

impl Default for ProbePlan {
    fn default() -> Self {
        Self {
            loopback: true,
            interfaces: true,
            extra: Vec::new(),
        }
    }
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
            broadcast_addr: Ipv4Addr::BROADCAST,
            peer_ttl: None,
            probes: ProbePlan::default(),
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
    /// # use zudp::wincode::{SchemaRead, SchemaWrite};
    /// # use zudp::DiscoveryConfig;
    /// # #[derive(zudp::wincode::SchemaWrite, zudp::wincode::SchemaRead, Clone)] #[wincode(crate = "zudp::wincode")] struct GameInfo { name: String }
    /// let cfg = DiscoveryConfig::new("my-game", 7700)
    ///     .meta(GameInfo { name: "Alice".into() });
    /// ```
    pub fn meta<N>(self, meta: N) -> DiscoveryConfig<N> {
        DiscoveryConfig {
            app_id: self.app_id,
            data_port: self.data_port,
            discovery_port: self.discovery_port,
            probe_interval: self.probe_interval,
            broadcast_addr: self.broadcast_addr,
            peer_ttl: self.peer_ttl,
            probes: self.probes,
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

    /// How long a scanned peer may stay silent before it is reported
    /// [`DiscoveryEvent::Lost`] (default: 3 × `probe_interval`).
    #[must_use]
    pub fn peer_ttl(mut self, ttl: Duration) -> Self {
        self.peer_ttl = Some(ttl);
        self
    }

    /// Override the IPv4 broadcast address probes are sent to (default: `255.255.255.255`).
    ///
    /// On Linux, limited broadcast (`255.255.255.255`) is not delivered to local sockets
    /// on the same host. Use `127.255.255.255` (loopback broadcast) when both advertiser
    /// and scanner run in the same process or on the same machine in a test environment.
    #[must_use]
    pub fn broadcast_addr(mut self, addr: Ipv4Addr) -> Self {
        self.broadcast_addr = addr;
        self
    }

    /// Whether scans also probe `127.0.0.1` (default: on).
    ///
    /// Advertisers on the same machine then answer even where the OS blocks
    /// LAN broadcast, such as macOS without the Local Network permission.
    #[must_use]
    pub fn probe_loopback(mut self, enabled: bool) -> Self {
        self.probes.loopback = enabled;
        self
    }

    /// Whether scans also probe the directed broadcast address of every IPv4
    /// interface, e.g. `192.168.1.255` (default: on).
    ///
    /// Reaches the LAN when the route for `255.255.255.255` points elsewhere,
    /// such as a VPN tunnel on macOS.
    #[must_use]
    pub fn probe_interfaces(mut self, enabled: bool) -> Self {
        self.probes.interfaces = enabled;
        self
    }

    /// Extra addresses every scan round probes too: hosts to ask directly by
    /// unicast, or other broadcast addresses, for networks that drop broadcast.
    #[must_use]
    pub fn probe_targets(mut self, targets: impl IntoIterator<Item = SocketAddr>) -> Self {
        self.probes.extra.extend(targets);
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
    /// Random id of the advertiser run; it changes when the peer restarts.
    pub instance: u64,
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

/// A change in the set of peers a [`ScanStream`] sees.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum DiscoveryEvent<M> {
    /// A peer answered for the first time (or again after it was reported [`Lost`](Self::Lost)).
    Found(DiscoveredPeer<M>),
    /// A known peer changed its metadata, or restarted (new [`DiscoveredPeer::instance`]).
    Updated(DiscoveredPeer<M>),
    /// No beacon from `data_addr` for the configured peer TTL.
    Lost { data_addr: SocketAddr },
    /// Sending a probe to `target` failed, e.g. macOS refusing LAN broadcast
    /// without the Local Network permission (`EHOSTUNREACH`). Reported once
    /// per target until a probe to it succeeds again; the scan keeps running
    /// and peers reachable through other targets are still found.
    ProbeFailed {
        target: SocketAddr,
        error: Arc<std::io::Error>,
    },
}

struct Seen {
    last: Instant,
    instance: u64,
    meta: Bytes,
}

/// Continuous view of the peers on the network.
///
/// Created by [`Discovery::scan_stream`].  Re-probes every `probe_interval`, reports each
/// peer when it appears, again when it restarts or changes its metadata, and once more when
/// it stops answering for `peer_ttl` (see [`next_event`](Self::next_event)).
pub struct ScanStream<M> {
    socket: Arc<UdpSocket>,
    app_id: u64,
    broadcast_addr: SocketAddr,
    probes: ProbePlan,
    ticker: time::Interval,
    peer_ttl: Duration,
    seen: HashMap<SocketAddr, Seen>,
    /// Data address each advertiser instance was first seen at. One machine
    /// answers loopback and broadcast probes from different source addresses;
    /// it is still one peer.
    instances: HashMap<u64, SocketAddr>,
    lost: VecDeque<SocketAddr>,
    /// Targets whose last probe failed, so a failure is reported once.
    failing: HashSet<SocketAddr>,
    failed: VecDeque<(SocketAddr, Arc<std::io::Error>)>,
    _phantom: PhantomData<fn() -> M>,
}

impl<M: Decode> ScanStream<M> {
    /// Wait for the next peer that is new, restarted, or changed its metadata.
    ///
    /// Peers that go silent are dropped from the view without being reported here; use
    /// [`next_event`](Self::next_event) to see them leave.
    ///
    /// # Errors
    /// Returns `Err` only if the scan socket itself fails.
    pub async fn next(&mut self) -> Result<DiscoveredPeer<M>, Error> {
        loop {
            match self.next_event().await? {
                DiscoveryEvent::Found(peer) | DiscoveryEvent::Updated(peer) => return Ok(peer),
                DiscoveryEvent::Lost { .. } | DiscoveryEvent::ProbeFailed { .. } => {}
            }
        }
    }

    /// Wait for the next change: a peer found, updated or lost, or a probe
    /// target that started failing.
    ///
    /// Malformed or foreign datagrams are skipped, never returned as errors.
    ///
    /// # Errors
    /// Returns `Err` only if the scan socket itself fails.
    pub async fn next_event(&mut self) -> Result<DiscoveryEvent<M>, Error> {
        loop {
            if let Some((target, error)) = self.failed.pop_front() {
                return Ok(DiscoveryEvent::ProbeFailed { target, error });
            }
            if let Some(data_addr) = self.lost.pop_front() {
                return Ok(DiscoveryEvent::Lost { data_addr });
            }
            let received = tokio::select! {
                biased;
                result = recv_datagram(&self.socket) => Some(result),
                _ = self.ticker.tick() => None,
            };
            match received {
                Some(Ok((buf, from))) => {
                    if let Ok(frame) = Frame::decode(buf)
                        && let Some(event) = self.observe(frame, from)
                    {
                        return Ok(event);
                    }
                }
                Some(Err(e)) if is_transient_recv_error(&e) => {}
                Some(Err(e)) => return Err(e.into()),
                None => {
                    self.expire();
                    self.probe().await;
                }
            }
        }
    }

    /// Every address this round probes: the broadcast address, then
    /// loopback, each interface's directed broadcast and the extra targets.
    /// Interfaces are listed again each round, so a network switch is seen.
    fn targets(&self) -> Vec<SocketAddr> {
        let port = self.broadcast_addr.port();
        let mut targets = vec![self.broadcast_addr];
        if self.probes.loopback {
            targets.push(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port));
        }
        if self.probes.interfaces {
            targets
                .extend(interface_broadcasts().map(|addr| SocketAddr::new(IpAddr::V4(addr), port)));
        }
        targets.extend(self.probes.extra.iter().copied());
        let mut seen = HashSet::new();
        targets.retain(|target| seen.insert(*target));
        targets
    }

    /// Sends one probe to every target. A target that fails is queued as
    /// [`DiscoveryEvent::ProbeFailed`] once; it is reported again only after a
    /// probe to it succeeded in between.
    async fn probe(&mut self) {
        let probe = Frame::Probe {
            app_id: self.app_id,
            proto_ver: PROTO_VER,
        }
        .encode();
        for target in self.targets() {
            match self.socket.send_to(&probe, target).await {
                Ok(_) => {
                    self.failing.remove(&target);
                }
                Err(error) => {
                    tracing::debug!(target: "zudp::discovery", %target, "probe failed: {error}");
                    if self.failing.insert(target) {
                        self.failed.push_back((target, Arc::new(error)));
                    }
                }
            }
        }
    }

    fn expire(&mut self) {
        let ttl = self.peer_ttl;
        let lost = &mut self.lost;
        self.seen.retain(|addr, seen| {
            let keep = seen.last.elapsed() < ttl;
            if !keep {
                lost.push_back(*addr);
            }
            keep
        });
        let seen = &self.seen;
        self.instances.retain(|_, addr| seen.contains_key(addr));
    }

    /// Turn one beacon into an event, if it changes anything.
    fn observe(&mut self, frame: Frame, from: SocketAddr) -> Option<DiscoveryEvent<M>> {
        let Frame::Beacon {
            app_id,
            proto_ver,
            data_port,
            instance,
            meta,
        } = frame
        else {
            return None;
        };
        if app_id != self.app_id || proto_ver != PROTO_VER {
            return None;
        }
        let data_addr = SocketAddr::new(from.ip(), data_port);
        let now = Instant::now();
        // The same advertiser answering through another probe target (loopback
        // and a LAN broadcast reach one local app from two addresses).
        if let Some(&known) = self.instances.get(&instance)
            && known != data_addr
        {
            if let Some(seen) = self.seen.get_mut(&known) {
                seen.last = now;
            }
            return None;
        }
        self.instances.insert(instance, data_addr);
        let found = if let Some(seen) = self.seen.get_mut(&data_addr) {
            seen.last = now;
            if seen.instance == instance && seen.meta == meta {
                return None;
            }
            if seen.instance != instance {
                self.instances.remove(&seen.instance);
            }
            seen.instance = instance;
            seen.meta = meta.clone();
            false
        } else {
            self.seen.insert(
                data_addr,
                Seen {
                    last: now,
                    instance,
                    meta: meta.clone(),
                },
            );
            true
        };
        let meta = match M::decode_from_bytes(&meta) {
            Ok(meta) => meta,
            Err(e) => {
                tracing::debug!(target: "zudp::discovery", %from, "beacon meta decode failed: {e}");
                return None;
            }
        };
        let peer = DiscoveredPeer {
            from,
            data_addr,
            instance,
            meta,
        };
        Some(if found {
            DiscoveryEvent::Found(peer)
        } else {
            DiscoveryEvent::Updated(peer)
        })
    }
}

/// LAN peer discovery service.
///
/// All methods are associated functions — no shared state is held between calls.
/// Advertisers bind the well-known discovery port; scanners bind an ephemeral port.
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
            crate::peer::random_u64(),
            meta_arc,
        ));
        Ok(AdvertiseHandle {
            meta,
            abort: jh.abort_handle(),
        })
    }

    /// Open a continuous scan for peers with a matching app ID.
    ///
    /// Sends an initial round of probes then returns a [`ScanStream`] that
    /// yields each newly-seen peer exactly once, re-probing at `probe_interval`.
    ///
    /// A probe that cannot be sent does not end the scan: it is reported as
    /// [`DiscoveryEvent::ProbeFailed`] by [`ScanStream::next_event`], and the
    /// other targets (loopback, interface broadcasts, extra targets) still run.
    ///
    /// # Errors
    /// Returns `Err` only if the scan socket cannot be bound.
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
        let broadcast_addr = SocketAddr::new(IpAddr::V4(cfg.broadcast_addr), cfg.discovery_port);

        let mut ticker = time::interval(cfg.probe_interval);
        ticker.set_missed_tick_behavior(time::MissedTickBehavior::Skip);
        ticker.tick().await; // discard immediate first tick

        let mut scan = ScanStream {
            socket,
            app_id: cfg.app_id.raw(),
            broadcast_addr,
            probes: cfg.probes,
            ticker,
            peer_ttl: cfg.peer_ttl.unwrap_or(cfg.probe_interval * 3),
            seen: HashMap::new(),
            instances: HashMap::new(),
            lost: VecDeque::new(),
            failing: HashSet::new(),
            failed: VecDeque::new(),
            _phantom: PhantomData,
        };
        scan.probe().await;
        Ok(scan)
    }

    /// Scan once and collect all peers that respond within `timeout`.
    ///
    /// Malformed replies are skipped.
    ///
    /// # Errors
    /// Returns `Err` if binding or the probe broadcast fails.
    pub async fn scan_once<M>(
        config: impl Into<DiscoveryConfig<()>>,
        timeout: Duration,
    ) -> Result<Vec<DiscoveredPeer<M>>, Error>
    where
        M: Decode,
    {
        let mut scan = Self::scan_stream::<M>(config).await?;
        let mut peers = Vec::new();
        let mut reported: HashSet<SocketAddr> = HashSet::new();
        let deadline = time::Instant::now() + timeout;
        loop {
            let remaining = deadline.saturating_duration_since(time::Instant::now());
            if remaining.is_zero() {
                break;
            }
            match time::timeout(remaining, scan.next()).await {
                Err(_elapsed) => break,
                Ok(Err(e)) => return Err(e),
                Ok(Ok(peer)) => {
                    if reported.insert(peer.data_addr) {
                        peers.push(peer);
                    }
                }
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
    #[cfg(windows)]
    crate::socket::win::disable_udp_connreset(&sock)?;
    let std_sock: std::net::UdpSocket = sock.into();
    Ok(UdpSocket::from_std(std_sock)?)
}

async fn recv_datagram(socket: &UdpSocket) -> std::io::Result<(BytesMut, SocketAddr)> {
    let mut buf = BytesMut::with_capacity(RECV_BUF);
    let (_, addr) = socket.recv_buf_from(&mut buf).await?;
    Ok((buf, addr))
}

async fn run_advertise<M: Encode + Send + Sync + 'static>(
    socket: Arc<UdpSocket>,
    app_id: u64,
    data_port: u16,
    instance: u64,
    meta: Arc<RwLock<M>>,
) {
    // Never exits on its own: one bad datagram or a transient socket error must not
    // silently end advertising while the handle still looks alive.
    loop {
        let (buf, from) = match recv_datagram(&socket).await {
            Ok(pair) => pair,
            Err(e) if is_transient_recv_error(&e) => continue,
            Err(e) => {
                tracing::warn!(target: "zudp::discovery", "recv error: {e}");
                time::sleep(ADVERTISE_ERROR_BACKOFF).await;
                continue;
            }
        };
        let Ok(frame) = Frame::decode(buf) else {
            continue;
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
            instance,
            meta: meta_bytes,
        }
        .encode();

        if let Err(e) = socket.send_to(&beacon, from).await {
            tracing::warn!(target: "zudp::discovery", %from, "beacon send failed: {e}");
        }
    }
}

/// Directed broadcast address of every IPv4 interface that has one, loopback
/// excluded. Empty when the interfaces cannot be listed.
fn interface_broadcasts() -> impl Iterator<Item = Ipv4Addr> {
    if_addrs::get_if_addrs()
        .unwrap_or_default()
        .into_iter()
        .filter(|interface| !interface.is_loopback())
        .filter_map(|interface| match interface.addr {
            if_addrs::IfAddr::V4(v4) => v4.broadcast,
            if_addrs::IfAddr::V6(_) => None,
        })
}
