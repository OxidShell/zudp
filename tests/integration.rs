use std::{collections::HashMap, net::IpAddr, net::Ipv4Addr, time::Duration};

use tokio::time::timeout;
use zudp::Zudp;

const RECV_TIMEOUT: Duration = Duration::from_secs(5);
const LOOPBACK: IpAddr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));

macro_rules! recv {
    ($socket:expr) => {
        timeout(RECV_TIMEOUT, $socket.recv())
            .await
            .expect("recv timed out")
            .expect("recv error")
    };
}

fn lo() -> Zudp {
    Zudp::default().bind_ip(LOOPBACK)
}

#[tokio::test]
async fn small_reliable_message() {
    let mut server: zudp::ZudpSocket<Vec<u8>> = lo().port(0).listen().await.unwrap();
    let server_addr = server.local_addr().unwrap();

    let client = lo().port(0).connect::<Vec<u8>>(server_addr).await.unwrap();

    let msg = b"hello world".to_vec();
    client.send(msg.clone()).await.unwrap();

    let pkt = recv!(server);
    assert_eq!(pkt.msg, msg);
    assert_eq!(pkt.stream, 0);
}

#[tokio::test]
async fn echo_roundtrip() {
    let mut server: zudp::ZudpSocket<Vec<u8>> = lo().port(0).listen().await.unwrap();
    let server_addr = server.local_addr().unwrap();

    let mut client = lo().port(0).connect::<Vec<u8>>(server_addr).await.unwrap();

    tokio::spawn(async move {
        let pkt = timeout(RECV_TIMEOUT, server.recv())
            .await
            .unwrap()
            .unwrap();
        let mut echoed = pkt.msg.clone();
        echoed.extend_from_slice(b"_ack");
        server.send(echoed, pkt.from).await.unwrap();
    });

    client.send(b"ping".to_vec()).await.unwrap();
    let reply = recv!(client);
    assert_eq!(reply.msg, b"ping_ack".to_vec());
}

#[tokio::test]
async fn fragmented_message() {
    // Tiny MTU forces fragmentation of the 2 KiB payload.
    let mut server: zudp::ZudpSocket<Vec<u8>> = lo().port(0).mtu(200).listen().await.unwrap();
    let server_addr = server.local_addr().unwrap();

    let client = lo()
        .port(0)
        .mtu(200)
        .connect::<Vec<u8>>(server_addr)
        .await
        .unwrap();

    let big = vec![0xABu8; 2000];
    client.send(big.clone()).await.unwrap();

    let pkt = recv!(server);
    assert_eq!(pkt.msg, big);
}

#[tokio::test]
async fn multi_stream() {
    let mut server: zudp::ZudpSocket<Vec<u8>> = lo().port(0).listen().await.unwrap();
    let server_addr = server.local_addr().unwrap();

    let client = lo()
        .port(0)
        .connect::<Vec<u8>>(server_addr)
        .await
        .unwrap();

    client.send_stream(b"s0".to_vec(), 0).await.unwrap();
    client.send_stream(b"s1".to_vec(), 1).await.unwrap();

    let pkt1 = recv!(server);
    let pkt2 = recv!(server);

    let mut by_stream: HashMap<u16, Vec<u8>> = HashMap::new();
    for pkt in [pkt1, pkt2] {
        by_stream.insert(pkt.stream, pkt.msg);
    }
    assert_eq!(by_stream[&0], b"s0".to_vec());
    assert_eq!(by_stream[&1], b"s1".to_vec());
}

#[tokio::test]
async fn unreliable_datagram() {
    let mut server: zudp::ZudpSocket<Vec<u8>> = lo().port(0).listen().await.unwrap();
    let server_addr = server.local_addr().unwrap();

    let client = lo()
        .port(0)
        .connect::<Vec<u8>>(server_addr)
        .await
        .unwrap();

    client.send_unreliable(b"fire and forget".to_vec()).await.unwrap();

    let pkt = recv!(server);
    assert_eq!(pkt.msg, b"fire and forget".to_vec());
}

#[tokio::test]
async fn multiple_messages_in_order() {
    let mut server: zudp::ZudpSocket<u64> = lo().port(0).listen().await.unwrap();
    let server_addr = server.local_addr().unwrap();

    let client = lo().port(0).connect::<u64>(server_addr).await.unwrap();

    for i in 0u64..5 {
        client.send(i).await.unwrap();
    }

    for expected in 0u64..5 {
        let pkt = recv!(server);
        assert_eq!(pkt.msg, expected, "out-of-order delivery on stream 0");
    }
}
