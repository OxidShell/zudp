//! Demonstrates remote key pinning with Noise XX.
//!
//! Run with:
//!   `cargo run --example key_pinning --features security`
//!
//! Shows two scenarios:
//!   1. Correct pin  — connect() succeeds, data flows.
//!   2. Wrong pin    — connect() times out (the handshake is silently aborted
//!                     server-side; no error frame is sent to prevent peer enumeration).

use std::{net::SocketAddr, time::Duration};

use bitcode::{Decode, Encode};
use zudp::{Keypair, Zudp};

#[derive(Debug, Encode, Decode)]
enum Msg {
    Hello,
    Hi,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let server_kp = Keypair::generate();

    // Expose the server's public key — in production you'd bake this into the client binary
    // or distribute it via a trusted channel (config file, DNS TXT record, etc.).
    let server_public_key = *server_kp.public_key();
    println!(
        "server public key (first 8 B): {}",
        hex(&server_public_key[..8])
    );

    // ── Server (accepts any correctly-pinned client) ─────────────────────────
    let server_kp_clone = server_kp.clone();
    let server = tokio::spawn(async move {
        let mut socket = Zudp::default()
            .port(7770)
            .security(server_kp_clone)
            .listen::<Msg>()
            .await
            .expect("server bind");

        println!("server  listening on {}", socket.local_addr().unwrap());

        // Handle one round for scenario 1 (correct pin).
        let pkt = socket.recv().await.expect("server recv");
        println!("server  ← {:?} from {} [handshake completed ✓]", pkt.msg, pkt.from);
        socket.send(Msg::Hi, pkt.from).await.expect("server send");

        // Scenario 2 never reaches here — the engine silently aborts the handshake
        // when the client's static key is checked against the server's pin.
        // (This server has no pin; it's the *client* that pins the server key.)
    });

    tokio::time::sleep(Duration::from_millis(50)).await;
    let peer: SocketAddr = "127.0.0.1:7770".parse()?;

    // ── Scenario 1: correct pin ──────────────────────────────────────────────
    println!("\n--- Scenario 1: correct pin ---");
    {
        let client_kp = Keypair::generate();
        let mut conn = Zudp::default()
            .port(0)
            .security(client_kp)
            // Pin the exact key we know the server holds.
            .pin_remote_key(server_public_key)
            .connect::<Msg>(peer)
            .await?;

        println!("client  connected — Noise XX complete, key matched ✓");
        conn.send(Msg::Hello).await?;
        let reply = conn.recv().await?;
        println!("client  ← {:?}", reply.msg);
    }

    // Give the server task time to finish its single recv/send round.
    server.await?;

    // The server is now done. Spin up a fresh one for scenario 2.
    let server_kp2 = server_kp.clone();
    let server2 = tokio::spawn(async move {
        let mut socket = Zudp::default()
            .port(7771)
            .security(server_kp2)
            .listen::<Msg>()
            .await
            .expect("server2 bind");
        // Just sit here — the client with the wrong pin will never reach us at the app layer.
        let _ = tokio::time::timeout(Duration::from_secs(3), socket.recv()).await;
    });

    let peer2: SocketAddr = "127.0.0.1:7771".parse()?;

    // ── Scenario 2: wrong pin ────────────────────────────────────────────────
    println!("\n--- Scenario 2: wrong pin (should time out) ---");
    {
        let wrong_key = Keypair::generate();
        let wrong_public = *wrong_key.public_key();
        println!("pinning wrong key: {}", hex(&wrong_public[..8]));

        let result = tokio::time::timeout(
            Duration::from_secs(2),
            Zudp::default()
                .port(0)
                .security(Keypair::generate())
                // Wrong key — the server silently aborts the handshake; connect() hangs.
                .pin_remote_key(wrong_public)
                .connect::<Msg>(peer2),
        )
        .await;

        match result {
            Err(_elapsed) => println!("client  connect() timed out as expected ✓"),
            Ok(Ok(_)) => println!("BUG: should not have connected with wrong key"),
            Ok(Err(e)) => println!("client  error: {e}"),
        }
    }

    server2.abort();
    println!("\nDone.");
    Ok(())
}

fn hex(b: &[u8]) -> String {
    use std::fmt::Write as _;
    b.iter().fold(String::new(), |mut s, x| {
        let _ = write!(s, "{x:02x}");
        s
    })
}
