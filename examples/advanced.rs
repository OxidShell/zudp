use std::net::SocketAddr;

use bitcode::{Decode, Encode};
use zudp::{Zudp, ZudpSocket};

#[derive(Debug, Encode, Decode, PartialEq)]
enum Msg {
    LargeData(Vec<u8>),
    Greeting(String),
}

// ── Fragmentation demo ────────────────────────────────────────────────────────
//
// Sends 50 KB in a single `send()` call. ZUDP auto-fragments it into ~36 chunks
// (50 000 / 1 400-byte MTU), each assigned its own sequence number. The receiver
// reassembles them transparently before delivering to `recv()`.

async fn fragmentation_demo() {
    println!("\n=== Fragmentation ===");

    let server_task = tokio::spawn(async {
        let mut server: ZudpSocket<Msg> =
            Zudp::default().port(7701).listen().await.expect("server bind");

        let (msg, from) = server.recv().await.expect("recv");
        let Msg::LargeData(data) = msg else {
            panic!("unexpected variant");
        };
        println!(
            "server: received {} bytes from {} — reassembly OK ✓",
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
}

// ── Relay demo ────────────────────────────────────────────────────────────────
//
// Three participants:
//
//   client  ──(Relay frame)──►  relay node  ──(inner frame)──►  server
//
// The relay node is an ordinary ZUDP socket — the engine transparently
// forwards Frame::Relay packets without decoding the inner message type.
//
// Trade-off: the server sees `from` == relay address, not the real client.
// NACKs also stop at the relay (they don't propagate back to the sender),
// so reliable delivery only holds client → relay; use `send_unreliable` if
// you need to relay high-frequency fire-and-forget data like game state.

async fn relay_demo() {
    println!("\n=== Relay ===");

    // 1. Relay node — just needs to be alive on its port.
    //    The engine handles Frame::Relay forwarding automatically.
    let relay_handle = tokio::spawn(async {
        let _relay: ZudpSocket<Msg> =
            Zudp::default().port(7800).listen().await.expect("relay bind");
        println!("relay: listening on 127.0.0.1:7800");
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
    });

    // 2. Server — receives the forwarded inner frame from the relay.
    let server_task = tokio::spawn(async {
        let mut server = Zudp::default()
            .port(7801)
            .listen::<Msg>()
            .await
            .expect("server bind");

        let (msg, apparent_from) = server.recv().await.expect("recv");
        println!(
            "server: received {msg:?}\n        apparent sender: {apparent_from} (relay addr, not client)"
        );
    });

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let relay_addr: SocketAddr = "127.0.0.1:7800".parse().unwrap();
    let server_addr: SocketAddr = "127.0.0.1:7801".parse().unwrap();

    // 3. Client — `.relay(relay_addr)` wraps every outgoing packet in a
    //    Frame::Relay header; the relay node strips it and forwards the inner
    //    frame to `server_addr`.
    let client = Zudp::default()
        .port(0)
        .relay(relay_addr)
        .connect::<Msg>(server_addr)
        .await
        .unwrap();

    let msg = Msg::Greeting("hello through the relay!".into());
    // Use send_unreliable so NACKs (which can't traverse the relay back to us)
    // don't cause stalls. For loss-sensitive data, run a relay that understands
    // the protocol at both ends.
    client.send_unreliable(msg).await.unwrap();
    println!("client: sent message via relay at {relay_addr}");

    server_task.await.unwrap();
    relay_handle.abort();
}

// ─────────────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::WARN)
        .init();

    fragmentation_demo().await;
    relay_demo().await;

    println!("\nAll demos complete.");
}
