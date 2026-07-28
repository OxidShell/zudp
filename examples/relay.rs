// Three participants:
//
//   client  ──(Relay frame)──►  relay node  ──(inner frame)──►  server
//
// The relay node is an ordinary ZUDP socket — the engine transparently
// forwards Frame::Relay packets without decoding the inner message type.
//
// Trade-off: the server sees `from` == relay address, not the real client.
// NACKs also stop at the relay, so use `send_unreliable` for relay paths.

use std::net::SocketAddr;

use zudp::rkyv::{Archive, Deserialize, Serialize};
use zudp::{Zudp, ZudpSocket};

#[derive(Debug, Archive, Serialize, Deserialize)]
enum Msg {
    Greeting(String),
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::WARN)
        .init();

    let relay_handle = tokio::spawn(async {
        let _relay: ZudpSocket<Msg> = Zudp::default()
            .port(7800)
            .listen()
            .await
            .expect("relay bind");
        println!("relay: listening on 127.0.0.1:7800");
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
    });

    let server_task = tokio::spawn(async {
        let mut server: ZudpSocket<Msg> = Zudp::default()
            .port(7801)
            .listen()
            .await
            .expect("server bind");

        let pkt = server.recv().await.expect("recv");
        println!(
            "server: received {:?}\n        apparent sender: {} (relay addr, not client)",
            pkt.msg, pkt.from
        );
    });

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let relay_addr: SocketAddr = "127.0.0.1:7800".parse().unwrap();
    let server_addr: SocketAddr = "127.0.0.1:7801".parse().unwrap();

    let client = Zudp::default()
        .port(0)
        .relay(relay_addr)
        .connect::<Msg>(server_addr)
        .await
        .unwrap();

    let msg = Msg::Greeting("hello through the relay!".into());
    client.send_unreliable(msg).await.unwrap();
    println!("client: sent message via relay at {relay_addr}");

    server_task.await.unwrap();
    relay_handle.abort();
    println!("done.");
}
