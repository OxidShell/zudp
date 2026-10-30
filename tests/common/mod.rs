//! Helpers shared by the robustness tests.
#![allow(dead_code)]

use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket as StdUdp},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};

use tokio::{net::UdpSocket, sync::RwLock, time::timeout};
use zudp::Zudp;

pub const LO: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

pub fn lo() -> Zudp {
    Zudp::default().bind_ip(LO)
}

pub fn free_port() -> u16 {
    StdUdp::bind((LO, 0)).unwrap().local_addr().unwrap().port()
}

/// Receive until nothing arrives for `quiet`.
pub async fn drain<M: zudp::Decode>(
    socket: &mut zudp::ZudpSocket<M>,
    quiet: Duration,
) -> Vec<zudp::Packet<M>> {
    let mut out = vec![];
    while let Ok(Ok(packet)) = timeout(quiet, socket.recv()).await {
        out.push(packet);
    }
    out
}

/// Encode a plaintext reliable stream frame by hand.
pub fn raw_stream_frame(seq: u64, stream_id: u16, payload: &[u8]) -> Vec<u8> {
    let mut wire = payload.to_vec();
    wire.extend_from_slice(&seq.to_be_bytes());
    wire.extend_from_slice(&stream_id.to_be_bytes());
    wire.push(0x01);
    wire
}

/// Which way a datagram is travelling through a [`Proxy`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dir {
    ToServer,
    ToClient,
}

type Filter = Arc<dyn Fn(Dir, &[u8]) -> bool + Send + Sync>;

/// A UDP middlebox between one client and one server.
///
/// `filter` returns `false` to drop a datagram.  [`Proxy::rebind`] changes the source
/// port the server sees, like a NAT rebinding or a Wi-Fi switch.
pub struct Proxy {
    pub addr: SocketAddr,
    back: Arc<RwLock<Arc<UdpSocket>>>,
    client: Arc<RwLock<Option<SocketAddr>>>,
    front: Arc<UdpSocket>,
    server: SocketAddr,
    filter: Filter,
    pub paused: Arc<AtomicBool>,
    pub forwarded: Arc<AtomicUsize>,
    back_task: tokio::task::JoinHandle<()>,
}

impl Proxy {
    pub async fn new(
        server: SocketAddr,
        filter: impl Fn(Dir, &[u8]) -> bool + Send + Sync + 'static,
    ) -> Self {
        let filter: Filter = Arc::new(filter);
        let front = Arc::new(UdpSocket::bind((LO, 0)).await.unwrap());
        let back = Arc::new(UdpSocket::bind((LO, 0)).await.unwrap());
        let client = Arc::new(RwLock::new(None));
        let paused = Arc::new(AtomicBool::new(false));
        let forwarded = Arc::new(AtomicUsize::new(0));
        let back_lock = Arc::new(RwLock::new(back.clone()));
        {
            let (front, back_lock, client, filter, paused, forwarded) = (
                front.clone(),
                back_lock.clone(),
                client.clone(),
                filter.clone(),
                paused.clone(),
                forwarded.clone(),
            );
            tokio::spawn(async move {
                let mut buf = vec![0u8; 65_536];
                loop {
                    let Ok((n, from)) = front.recv_from(&mut buf).await else {
                        return;
                    };
                    *client.write().await = Some(from);
                    if paused.load(Ordering::Relaxed) || !filter(Dir::ToServer, &buf[..n]) {
                        continue;
                    }
                    forwarded.fetch_add(1, Ordering::Relaxed);
                    let back = back_lock.read().await.clone();
                    let _ = back.send_to(&buf[..n], server).await;
                }
            });
        }
        let back_task = spawn_back(
            back,
            front.clone(),
            client.clone(),
            filter.clone(),
            paused.clone(),
        );
        Self {
            addr: front.local_addr().unwrap(),
            back: back_lock,
            client,
            front,
            server,
            filter,
            paused,
            forwarded,
            back_task,
        }
    }

    pub async fn rebind(&mut self) {
        self.back_task.abort();
        let fresh = Arc::new(UdpSocket::bind((LO, 0)).await.unwrap());
        *self.back.write().await = fresh.clone();
        self.back_task = spawn_back(
            fresh,
            self.front.clone(),
            self.client.clone(),
            self.filter.clone(),
            self.paused.clone(),
        );
    }

    pub async fn upstream_addr(&self) -> SocketAddr {
        self.back.read().await.local_addr().unwrap()
    }

    pub fn server(&self) -> SocketAddr {
        self.server
    }
}

fn spawn_back(
    back: Arc<UdpSocket>,
    front: Arc<UdpSocket>,
    client: Arc<RwLock<Option<SocketAddr>>>,
    filter: Filter,
    paused: Arc<AtomicBool>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65_536];
        loop {
            let Ok((n, _)) = back.recv_from(&mut buf).await else {
                return;
            };
            if paused.load(Ordering::Relaxed) || !filter(Dir::ToClient, &buf[..n]) {
                continue;
            }
            if let Some(c) = *client.read().await {
                let _ = front.send_to(&buf[..n], c).await;
            }
        }
    })
}
