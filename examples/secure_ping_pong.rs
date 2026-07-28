//! Demonstrates end-to-end Noise XX encryption.
//!
//! Run with:
//!   `cargo run --example secure_ping_pong --features security`
//!
//! Both sockets exchange three Noise handshake messages before any data flows.
//! The send/recv API is identical to the unencrypted path.

use std::{net::SocketAddr, time::Duration};

use zudp::rkyv::{Archive, Deserialize, Serialize};
use zudp::{Keypair, Zudp};

#[derive(Debug, Archive, Serialize, Deserialize)]
enum Msg {
    Ping(u32),
    Pong(u32),
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let server_kp = Keypair::generate();
    let client_kp = Keypair::generate();

    println!("server public key: {}", hex(&server_kp.public_key()[..8]));
    println!("client public key: {}", hex(&client_kp.public_key()[..8]));

    let server_task = tokio::spawn(async move {
        let mut server = Zudp::default()
            .port(7750)
            .security(server_kp)
            .listen::<Msg>()
            .await
            .expect("server bind");

        println!("\nserver listening on {}", server.local_addr().unwrap());

        for i in 1u32..=3 {
            let pkt = server.recv().await.expect("server recv");
            let Msg::Ping(seq) = pkt.msg else { continue };
            println!("server  ←  Ping({seq}) from {}  [encrypted ✓]", pkt.from);

            server.send(Msg::Pong(seq), pkt.from).await.expect("server send");
            println!("server  →  Pong({seq}) to {}  [encrypted ✓]", pkt.from);

            let _ = i;
        }
    });

    // Give the server a moment to bind.
    tokio::time::sleep(Duration::from_millis(50)).await;

    let peer: SocketAddr = "127.0.0.1:7750".parse()?;

    // connect() triggers the 3-message Noise XX handshake automatically.
    let mut conn = Zudp::default()
        .port(0)
        .security(client_kp)
        .connect::<Msg>(peer)
        .await?;

    println!("\nclient connected {} → {peer}", conn.local_addr()?);
    println!("Noise XX handshake complete — channel encrypted\n");

    for seq in 1u32..=3 {
        conn.send(Msg::Ping(seq)).await?;
        println!("client  →  Ping({seq})");

        let pkt = conn.recv().await?;
        println!("client  ←  {:?}\n", pkt.msg);

        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    server_task.await?;
    Ok(())
}

fn hex(b: &[u8]) -> String {
    use std::fmt::Write as _;
    b.iter().fold(String::new(), |mut s, x| {
        let _ = write!(s, "{x:02x}");
        s
    })
}
