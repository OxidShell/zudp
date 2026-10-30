//! A socket with a keypair neither accepts nor emits plaintext data.
#![cfg(feature = "security")]

mod common;

use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use common::{LO, Proxy, drain, lo, raw_stream_frame};
use tokio::{net::UdpSocket, time::timeout};
use zudp::{Keypair, RawBytes};

#[tokio::test]
async fn plaintext_data_is_dropped() {
    let mut server: zudp::ZudpSocket<RawBytes> = lo()
        .port(0)
        .security(Keypair::generate())
        .listen()
        .await
        .unwrap();
    let addr = server.local_addr().unwrap();
    let raw = UdpSocket::bind((LO, 0)).await.unwrap();
    raw.send_to(&raw_stream_frame(1, 0, b"forged"), addr)
        .await
        .unwrap();
    raw.send_to(b"forged datagram\x00", addr).await.unwrap();
    assert!(
        timeout(Duration::from_millis(300), server.recv())
            .await
            .is_err()
    );
    assert!(server.engine_stats().dropped_unauthenticated >= 2);
}

#[tokio::test]
async fn sending_without_a_session_is_an_error() {
    let server: zudp::ZudpSocket<Vec<u8>> = lo()
        .port(0)
        .security(Keypair::generate())
        .listen()
        .await
        .unwrap();
    let nobody = "127.0.0.1:9".parse().unwrap();
    let result = server.send(b"leak".to_vec(), nobody).await;
    assert!(matches!(result, Err(zudp::Error::NoSession { .. })));
    let result = server.send_unreliable(b"leak".to_vec(), nobody).await;
    assert!(matches!(result, Err(zudp::Error::NoSession { .. })));
}

#[tokio::test]
async fn unreliable_datagrams_are_encrypted() {
    let mut server: zudp::ZudpSocket<RawBytes> = lo()
        .port(0)
        .security(Keypair::generate())
        .listen()
        .await
        .unwrap();
    let leaked = Arc::new(AtomicBool::new(false));
    let seen = leaked.clone();
    let proxy = Proxy::new(server.local_addr().unwrap(), move |_, wire| {
        if wire.windows(12).any(|w| w == b"secret-dgram") {
            seen.store(true, Ordering::Relaxed);
        }
        true
    })
    .await;
    let conn = lo()
        .port(0)
        .security(Keypair::generate())
        .connect::<RawBytes>(proxy.addr)
        .await
        .unwrap();
    conn.send_unreliable(RawBytes(b"secret-dgram".to_vec().into()))
        .await
        .unwrap();
    let got = drain(&mut server, Duration::from_millis(300)).await;
    assert_eq!(got.len(), 1);
    assert_eq!(&got[0].msg.0[..], b"secret-dgram");
    assert!(
        !leaked.load(Ordering::Relaxed),
        "datagram crossed the wire in plaintext"
    );
}
