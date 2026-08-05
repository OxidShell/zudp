//! Demonstrates independent reliable streams over a single ZUDP connection.
//!
//! Run with:
//!   `cargo run --example multi_stream`
//!
//! Two streams carry different message types simultaneously:
//!   - Stream 0: game commands (small, high-priority)
//!   - Stream 1: world-state snapshots (large, low-priority)
//!
//! Loss on one stream never delays delivery on the other — there is no
//! head-of-line blocking between streams.

use std::{net::SocketAddr, time::Duration};

use zudp::rkyv::{Archive, Deserialize, Serialize};
use zudp::Zudp;

const STREAM_COMMANDS: u16 = 0;
const STREAM_STATE: u16 = 1;

#[derive(Debug, Archive, Serialize, Deserialize)]
#[cfg_attr(feature = "serde", derive(zudp::serde::Serialize, zudp::serde::Deserialize))]
enum Command {
    Jump,
    Fire { target_id: u32 },
    Respawn,
}

#[derive(Debug, Archive, Serialize, Deserialize)]
#[cfg_attr(feature = "serde", derive(zudp::serde::Serialize, zudp::serde::Deserialize))]
enum StateSnapshot {
    World { tick: u32, data: Vec<u8> },
}

// The server uses a single enum to receive from both streams.
#[derive(Debug, Archive, Serialize, Deserialize)]
#[cfg_attr(feature = "serde", derive(zudp::serde::Serialize, zudp::serde::Deserialize))]
enum ServerMsg {
    Command(Command),
    State(StateSnapshot),
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let server_task = tokio::spawn(async {
        let mut server = Zudp::default()
            .port(7760)
            .listen::<ServerMsg>()
            .await
            .expect("server bind");

        println!("server listening on {}", server.local_addr().unwrap());

        for _ in 0..5 {
            let pkt = server.recv().await.expect("server recv");
            println!("server  ←  stream {}  {:?}  from {}", pkt.stream, pkt.msg, pkt.from);
        }
        println!("server done");
    });

    tokio::time::sleep(Duration::from_millis(50)).await;

    let peer: SocketAddr = "127.0.0.1:7760".parse()?;

    // Client A — sends commands on stream 0 and snapshots on stream 1.
    let conn = Zudp::default()
        .port(0)
        .connect::<ServerMsg>(peer)
        .await?;

    println!("client connected {}", conn.local_addr()?);

    // Stream 0: urgent game commands.
    conn.send_stream(ServerMsg::Command(Command::Jump), STREAM_COMMANDS)
        .await?;
    conn.send_stream(ServerMsg::Command(Command::Fire { target_id: 42 }), STREAM_COMMANDS)
        .await?;
    conn.send_stream(ServerMsg::Command(Command::Respawn), STREAM_COMMANDS)
        .await?;

    // Stream 1: a large world-state snapshot (will be fragmented if > MTU).
    let snapshot = vec![0u8; 5_000];
    conn.send_stream(
        ServerMsg::State(StateSnapshot::World {
            tick: 100,
            data: snapshot,
        }),
        STREAM_STATE,
    )
    .await?;

    // Stream 0 again: loss on stream 1's large snapshot cannot block this.
    conn.send_stream(ServerMsg::Command(Command::Fire { target_id: 99 }), STREAM_COMMANDS)
        .await?;

    println!("client sent 3 commands on stream 0, 1 snapshot on stream 1, 1 more command");

    server_task.await?;
    Ok(())
}
