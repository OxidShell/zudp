//! Regression tests for hostile input and slow consumers.

mod common;

use std::time::Duration;

use common::{drain, lo, raw_stream_frame};
use tokio::{net::UdpSocket, time::timeout};

#[tokio::test(flavor = "multi_thread")]
async fn forged_huge_sequence_number_is_ignored() {
    let mut server: zudp::ZudpSocket<zudp::RawBytes> = lo().port(0).listen().await.unwrap();
    let server_addr = server.local_addr().unwrap();
    let raw = UdpSocket::bind((common::LO, 0)).await.unwrap();
    for seq in [u64::MAX - 1, 1 << 40, 5_000_000] {
        raw.send_to(&raw_stream_frame(seq, 0, b"evil"), server_addr)
            .await
            .unwrap();
    }
    raw.send_to(&raw_stream_frame(1, 0, b"ok"), server_addr)
        .await
        .unwrap();
    let packet = timeout(Duration::from_secs(2), server.recv())
        .await
        .expect("engine stays responsive")
        .unwrap();
    assert_eq!(&packet.msg.0[..], b"ok");
}

#[tokio::test(flavor = "multi_thread")]
async fn reliable_data_survives_a_full_inbound_channel() {
    const COUNT: u32 = 10_000;
    let mut server: zudp::ZudpSocket<Vec<u8>> = lo()
        .port(0)
        .rate_limit(0.0)
        .sent_buffer(16_384)
        .listen()
        .await
        .unwrap();
    let server_addr = server.local_addr().unwrap();
    let client = lo()
        .port(0)
        .rate_limit(0.0)
        .sent_buffer(16_384)
        .connect::<Vec<u8>>(server_addr)
        .await
        .unwrap();
    for i in 0..COUNT {
        client.send(i.to_be_bytes().to_vec()).await.unwrap();
        if i % 500 == 0 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }
    // Nothing was read while sending, so the 8 192-slot inbound channel overflowed.
    let got = drain(&mut server, Duration::from_secs(2)).await;
    let seqs: Vec<u32> = got
        .iter()
        .map(|p| u32::from_be_bytes(p.msg[..4].try_into().unwrap()))
        .collect();
    assert_eq!(seqs, (0..COUNT).collect::<Vec<_>>());
}

#[tokio::test]
async fn unanswered_mtu_probes_keep_the_configured_mtu() {
    let silent = UdpSocket::bind((common::LO, 0)).await.unwrap();
    let conn = lo()
        .port(0)
        .connect::<Vec<u8>>(silent.local_addr().unwrap())
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert_eq!(
        conn.effective_mtu(),
        None,
        "a silent peer must not pin the MTU to the minimum"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn data_flood_from_an_ip_does_not_starve_its_handshake() {
    let server: zudp::ZudpSocket<Vec<u8>> = lo()
        .port(0)
        .security(zudp::Keypair::generate())
        .listen()
        .await
        .unwrap();
    let server_addr = server.local_addr().unwrap();
    let flood = tokio::spawn(async move {
        let raw = UdpSocket::bind((common::LO, 0)).await.unwrap();
        loop {
            for _ in 0..200 {
                let _ = raw.send_to(&[0x00], server_addr).await;
            }
            tokio::task::yield_now().await;
        }
    });
    tokio::time::sleep(Duration::from_millis(100)).await;
    let connect = lo()
        .port(0)
        .security(zudp::Keypair::generate())
        .connect::<Vec<u8>>(server_addr);
    let result = timeout(Duration::from_secs(3), connect).await;
    flood.abort();
    assert!(
        matches!(result, Ok(Ok(_))),
        "handshake starved by the data flood"
    );
}
