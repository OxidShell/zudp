//! Handshake recovery: lost datagrams, aborted peers, silent peers.
#![cfg(feature = "security")]

mod common;

use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use common::{Dir, LO, Proxy, drain, free_port, lo};
use tokio::{net::UdpSocket, time::timeout};
use zudp::Keypair;

const NOISE: &str = "Noise_XX_25519_ChaChaPoly_BLAKE2s";

/// Handshake step of a datagram, if it is a handshake frame.
fn handshake_step(wire: &[u8]) -> Option<u8> {
    (wire.len() >= 3 && wire[wire.len() - 1] == 0x09).then(|| wire[wire.len() - 3])
}

/// A proxy that drops the first `n` handshake datagrams of `step` going `dir`.
async fn lossy(server: std::net::SocketAddr, dir: Dir, step: u8, n: usize) -> Proxy {
    let dropped = Arc::new(AtomicUsize::new(0));
    Proxy::new(server, move |d, wire| {
        if d == dir
            && handshake_step(wire) == Some(step)
            && dropped.fetch_add(1, Ordering::Relaxed) < n
        {
            return false;
        }
        true
    })
    .await
}

async fn secure_server() -> (zudp::ZudpSocket<Vec<u8>>, std::net::SocketAddr) {
    let server: zudp::ZudpSocket<Vec<u8>> = lo()
        .port(0)
        .security(Keypair::generate())
        .listen()
        .await
        .unwrap();
    let addr = server.local_addr().unwrap();
    (server, addr)
}

async fn connect_and_send(target: std::net::SocketAddr, server: &mut zudp::ZudpSocket<Vec<u8>>) {
    let conn = timeout(
        Duration::from_secs(4),
        lo().port(0)
            .security(Keypair::generate())
            .connect::<Vec<u8>>(target),
    )
    .await
    .expect("connect hung")
    .expect("connect failed");
    conn.send(b"through".to_vec()).await.unwrap();
    let got = drain(server, Duration::from_millis(500)).await;
    assert_eq!(got.len(), 1, "data must flow once connect returned");
}

#[tokio::test]
async fn lost_msg1_is_retransmitted() {
    let (mut server, addr) = secure_server().await;
    let proxy = lossy(addr, Dir::ToServer, 1, 2).await;
    connect_and_send(proxy.addr, &mut server).await;
}

#[tokio::test]
async fn lost_msg2_is_recovered() {
    let (mut server, addr) = secure_server().await;
    let proxy = lossy(addr, Dir::ToClient, 2, 2).await;
    connect_and_send(proxy.addr, &mut server).await;
}

#[tokio::test]
async fn lost_msg3_does_not_leave_a_half_open_session() {
    let (mut server, addr) = secure_server().await;
    let proxy = lossy(addr, Dir::ToServer, 3, 2).await;
    connect_and_send(proxy.addr, &mut server).await;
}

#[tokio::test]
async fn silent_peer_times_out() {
    let silent = UdpSocket::bind((LO, 0)).await.unwrap();
    let started = std::time::Instant::now();
    let result = lo()
        .port(0)
        .security(Keypair::generate())
        .handshake_timeout(Duration::from_millis(800))
        .connect::<Vec<u8>>(silent.local_addr().unwrap())
        .await;
    assert!(matches!(result, Err(zudp::Error::HandshakeTimeout { .. })));
    assert!(started.elapsed() < Duration::from_secs(2));
}

/// A client that died after msg2 must not wedge its address on the server.
#[tokio::test]
async fn aborted_handshake_does_not_wedge_the_address() {
    let (mut server, addr) = secure_server().await;
    let port = free_port();
    {
        let raw = UdpSocket::bind((LO, port)).await.unwrap();
        let kp = Keypair::generate();
        let mut hs = snow::Builder::new(NOISE.parse().unwrap())
            .local_private_key(&kp.private)
            .build_initiator()
            .unwrap();
        let mut buf = vec![0u8; 1024];
        let n = hs.write_message(&7u64.to_be_bytes(), &mut buf).unwrap();
        let mut wire = buf[..n].to_vec();
        wire.extend_from_slice(&[1, zudp::WIRE_VERSION, 0x09]);
        raw.send_to(&wire, addr).await.unwrap();
        let mut reply = vec![0u8; 2048];
        let (n, _) = timeout(Duration::from_secs(2), raw.recv_from(&mut reply))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(handshake_step(&reply[..n]), Some(2));
    }
    let conn = timeout(
        Duration::from_secs(3),
        lo().port(port)
            .security(Keypair::generate())
            .connect::<Vec<u8>>(addr),
    )
    .await
    .expect("connect from the same address hung")
    .unwrap();
    conn.send(b"fresh".to_vec()).await.unwrap();
    assert_eq!(
        drain(&mut server, Duration::from_millis(500)).await.len(),
        1
    );
}

#[tokio::test]
async fn connecting_to_the_unspecified_address_reaches_loopback() {
    let server: zudp::ZudpSocket<Vec<u8>> = zudp::Zudp::default()
        .port(0)
        .security(Keypair::generate())
        .listen()
        .await
        .unwrap();
    let target = server.local_addr().unwrap();
    assert!(target.ip().is_unspecified());
    let conn = timeout(
        Duration::from_secs(3),
        zudp::Zudp::default()
            .port(0)
            .security(Keypair::generate())
            .connect::<Vec<u8>>(target),
    )
    .await
    .expect("connect hung");
    assert!(conn.is_ok());
}
