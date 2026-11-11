// Three participants, all on loopback here, but the shape is the real one:
//
//   alice (behind NAT) ──Secure──► relay node (public) ◄──Secure── bob (behind NAT)
//          └─────────── end-to-end Noise session, opaque to the relay ───────────┘
//
// Alice and Bob each hold a secure session with the relay.  Alice then opens a session
// with Bob's *static key* through it: the relay forwards ciphertext it cannot read or
// forge.  Both then ask the relay for an introduction and punch a direct path; the
// session moves onto it (PathChanged) without changing its handle.
//
//   cargo run --example relay --features relay

use std::time::Duration;

use zudp::rkyv::{Archive, Deserialize, Serialize};
use zudp::{Keypair, PeerEvent, RelayLimits, Zudp, ZudpSocket};

#[derive(Debug, Archive, Serialize, Deserialize)]
#[cfg_attr(
    feature = "serde",
    derive(zudp::serde::Serialize, zudp::serde::Deserialize)
)]
enum Msg {
    Greeting(String),
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::WARN)
        .init();

    // The relay node: an ordinary secure socket with the relay role switched on.
    let relay: ZudpSocket<Msg> = Zudp::default()
        .bind_ip("127.0.0.1".parse()?)
        .security(Keypair::generate())
        .relay_node(RelayLimits::default())
        // Who may reach whom; here everyone connected to the relay.
        .relay_policy(|_from: &[u8; 32], _to: &[u8; 32]| true)
        .listen()
        .await?;
    let relay_addr = relay.local_addr()?;
    println!("relay: listening on {relay_addr}");

    // Bob connects to the relay and waits; he needs no call to accept relayed sessions.
    let bob_key = Keypair::generate();
    let bob_public = bob_key.public;
    let mut bob: ZudpSocket<Msg> = Zudp::default().security(bob_key).listen().await?;
    bob.connect(relay_addr).await?;
    let bob_task = tokio::spawn(async move {
        let pkt = bob.recv().await?;
        println!("bob:   received {:?} from {}", pkt.msg, pkt.from);
        bob.send(Msg::Greeting("hi alice".into()), pkt.from).await?;
        // Keep the socket alive long enough to finish punching.
        tokio::time::sleep(Duration::from_secs(1)).await;
        anyhow::Ok(())
    });

    // Alice reaches Bob by his static key, through the relay.
    let alice_key = Keypair::generate();
    let mut alice: ZudpSocket<Msg> = Zudp::default().security(alice_key).listen().await?;
    let mut events = alice.events();
    alice.connect(relay_addr).await?;
    let bob_handle = alice.connect_via(relay_addr, bob_public).await?;
    println!(
        "alice: session with {bob_handle} over {:?}",
        alice.peer_path(bob_handle)
    );

    alice
        .send(Msg::Greeting("hello through the relay".into()), bob_handle)
        .await?;
    let reply = alice.recv().await?;
    println!("alice: received {:?} from {}", reply.msg, reply.from);

    // Hole punching runs in the background; on loopback it always succeeds.
    let punched = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if let PeerEvent::PathChanged { path, .. } = events.recv().await? {
                return anyhow::Ok(path);
            }
        }
    })
    .await;
    match punched {
        Ok(path) => println!("alice: session now goes over {:?}", path?),
        Err(_) => println!("alice: no direct path — staying on the relay"),
    }

    bob_task.await??;
    let stats = relay.engine_stats();
    println!(
        "relay: forwarded {} frames ({} bytes) without reading any of them",
        stats.relay_forwarded_packets, stats.relay_forwarded_bytes
    );
    Ok(())
}
