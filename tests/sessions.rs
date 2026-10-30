//! A remote that restarts gets a fresh session instead of inheriting stale state.

mod common;

use std::{net::SocketAddr, time::Duration};

use common::{LO, drain, free_port, lo};

/// Wait until `port` can be bound again, i.e. the previous owner released it.
async fn wait_released(port: u16) {
    for _ in 0..100 {
        if std::net::UdpSocket::bind((LO, port)).is_ok() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("port {port} never released");
}

#[tokio::test]
async fn client_restart_on_the_same_address_is_delivered() {
    let mut server: zudp::ZudpSocket<Vec<u8>> = lo().port(0).listen().await.unwrap();
    let server_addr = server.local_addr().unwrap();
    let port = free_port();
    {
        let first = lo()
            .port(port)
            .connect::<Vec<u8>>(server_addr)
            .await
            .unwrap();
        for i in 0..50u8 {
            first.send(vec![i]).await.unwrap();
        }
        assert_eq!(
            drain(&mut server, Duration::from_millis(300)).await.len(),
            50
        );
    }
    wait_released(port).await;
    let second = lo()
        .port(port)
        .connect::<Vec<u8>>(server_addr)
        .await
        .unwrap();
    for i in 0..10u8 {
        second.send(vec![100 + i]).await.unwrap();
    }
    let got = drain(&mut server, Duration::from_millis(500)).await;
    assert_eq!(
        got.len(),
        10,
        "restarted client's frames were dropped as stale"
    );
}

#[tokio::test]
async fn server_restart_resumes_quickly() {
    let port = free_port();
    let addr = SocketAddr::new(LO, port);
    let first: zudp::ZudpSocket<Vec<u8>> = lo().port(port).listen().await.unwrap();
    let client = lo().port(0).connect::<Vec<u8>>(addr).await.unwrap();
    for i in 0..2_000u32 {
        client.send(i.to_be_bytes().to_vec()).await.unwrap();
    }
    drop(first);
    wait_released(port).await;
    let mut second: zudp::ZudpSocket<Vec<u8>> = lo().port(port).listen().await.unwrap();
    let sender = client.sender();
    let pump = tokio::spawn(async move {
        for i in 0..100u32 {
            let _ = sender.send_stream(i.to_be_bytes().to_vec(), addr, 0).await;
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    });
    let started = std::time::Instant::now();
    let first_packet = tokio::time::timeout(Duration::from_secs(3), second.recv()).await;
    pump.abort();
    assert!(
        first_packet.is_ok(),
        "stream stalled after the server restarted"
    );
    assert!(started.elapsed() < Duration::from_secs(1));
}

#[cfg(feature = "security")]
#[tokio::test]
async fn secure_rehandshake_on_the_same_address_resets_state_and_key() {
    use zudp::Keypair;

    let mut server: zudp::ZudpSocket<Vec<u8>> = lo()
        .port(0)
        .security(Keypair::generate())
        .listen()
        .await
        .unwrap();
    let server_addr = server.local_addr().unwrap();
    let port = free_port();
    let first_key = Keypair::generate();
    {
        let first = lo()
            .port(port)
            .security(first_key.clone())
            .connect::<Vec<u8>>(server_addr)
            .await
            .unwrap();
        for i in 0..20u8 {
            first.send(vec![i]).await.unwrap();
        }
        assert_eq!(
            drain(&mut server, Duration::from_millis(300)).await.len(),
            20
        );
    }
    wait_released(port).await;
    let second_key = Keypair::generate();
    let second = tokio::time::timeout(
        Duration::from_secs(3),
        lo().port(port)
            .security(second_key.clone())
            .connect::<Vec<u8>>(server_addr),
    )
    .await
    .expect("re-handshake from the same address hung")
    .unwrap();
    for i in 0..5u8 {
        second.send(vec![i]).await.unwrap();
    }
    assert_eq!(
        drain(&mut server, Duration::from_millis(500)).await.len(),
        5
    );
    let peer = SocketAddr::new(LO, port);
    assert_eq!(server.peer_remote_static_key(peer), Some(second_key.public));
}
