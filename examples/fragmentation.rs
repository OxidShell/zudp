// Sends 50 KB in a single `send()` call. ZUDP auto-fragments it into ~36 chunks
// (50 000 / 1 400-byte MTU), each assigned its own sequence number. The receiver
// reassembles them transparently before delivering to `recv()`.

use std::net::SocketAddr;

use bitcode::{Decode, Encode};
use zudp::{Zudp, ZudpSocket};

#[derive(Debug, Encode, Decode, PartialEq)]
enum Msg {
    LargeData(Vec<u8>),
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::WARN)
        .init();

    let server_task = tokio::spawn(async {
        let mut server: ZudpSocket<Msg> = Zudp::default()
            .port(7701)
            .listen()
            .await
            .expect("server bind");

        let (msg, from, _stream) = server.recv().await.expect("recv");
        let Msg::LargeData(data) = msg;
        println!(
            "server: received {} bytes from {} — reassembly OK",
            data.len(),
            from
        );
        assert_eq!(data.len(), 50_000);
        assert!(data.iter().all(|&b| b == 0xAB));
    });

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let server: SocketAddr = "127.0.0.1:7701".parse().unwrap();
    let client = Zudp::default()
        .port(0)
        .connect::<Msg>(server)
        .await
        .unwrap();

    let payload = vec![0xABu8; 50_000];
    let mtu = 1400usize;
    let frags = payload.len().div_ceil(mtu);
    println!(
        "client: sending {} bytes → {} fragments of {} bytes",
        payload.len(),
        frags,
        mtu
    );
    client.send(Msg::LargeData(payload)).await.unwrap();

    server_task.await.unwrap();
    println!("done.");
}
