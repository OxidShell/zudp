//! Data sockets own their port exclusively and release it as soon as the handle is gone.

mod common;

use std::{net::UdpSocket as StdUdp, time::Duration};

use common::{LO, drain, free_port, lo};

#[tokio::test]
async fn second_socket_on_the_same_port_is_refused() {
    let port = free_port();
    let _first: zudp::ZudpSocket<Vec<u8>> = lo().port(port).listen().await.unwrap();
    let second = lo().port(port).listen::<Vec<u8>>().await;
    assert!(second.is_err(), "a stale socket must not share the port");
}

#[tokio::test]
async fn port_is_released_promptly_after_drop() {
    let mut server: zudp::ZudpSocket<Vec<u8>> = lo().port(0).listen().await.unwrap();
    let server_addr = server.local_addr().unwrap();
    let port = free_port();
    {
        let client = lo()
            .port(port)
            .connect::<Vec<u8>>(server_addr)
            .await
            .unwrap();
        for i in 0..20u8 {
            client.send(vec![i]).await.unwrap();
        }
        assert_eq!(
            drain(&mut server, Duration::from_millis(200)).await.len(),
            20
        );
    }
    let started = std::time::Instant::now();
    while StdUdp::bind((LO, port)).is_err() {
        assert!(
            started.elapsed() < Duration::from_millis(300),
            "port still bound after the connection was dropped"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}
