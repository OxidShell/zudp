//! Demonstrates the PeerStats and EngineStats observability APIs.
//!
//! Run with:
//!   `cargo run --example observability`
//!
//! Shows how to inspect RTT, pacing rate, byte counters, and engine-wide drop
//! counters while a connection is active.

use std::{net::SocketAddr, time::Duration};

use zudp::rkyv::{Archive, Deserialize, Serialize};
use zudp::Zudp;

#[derive(Debug, Archive, Serialize, Deserialize)]
#[cfg_attr(feature = "serde", derive(zudp::serde::Serialize, zudp::serde::Deserialize))]
enum Msg {
    Data(Vec<u8>),
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    // ── Server ──────────────────────────────────────────────────────────────
    let server = tokio::spawn(async {
        let mut socket = Zudp::default()
            .port(7760)
            .listen::<Msg>()
            .await
            .expect("server bind");

        println!("server  listening on {}", socket.local_addr().unwrap());

        // Echo every message back and print per-peer stats after each round.
        loop {
            let pkt = socket.recv().await.expect("server recv");
            let Msg::Data(ref payload) = pkt.msg;
            let from = pkt.from;

            // Echo back.
            socket
                .send(Msg::Data(payload.clone()), from)
                .await
                .expect("server send");

            // Per-peer snapshot — all reads are atomic, zero lock contention.
            if let Some(s) = socket.peer_stats(from) {
                println!(
                    "server  peer_stats  srtt={:?}  cf={:.3}  pacing={} B/s  \
                     rx={} B  tx={} B  retransmits={}",
                    s.srtt,
                    s.congestion_factor.unwrap_or(1.0),
                    s.pacing_rate_bps,
                    s.rx_bytes,
                    s.tx_bytes,
                    s.retransmit_count,
                );
            }

            // Engine-wide counters — useful for dashboards / alerting.
            let e = socket.engine_stats();
            println!(
                "server  engine_stats  rate_limited={}  peer_cap_evictions={}  \
                 relay_blocked={}  relay_cap={}",
                e.dropped_rate_limited,
                e.dropped_peer_cap,
                e.dropped_relay_blocked,
                e.dropped_relay_cap,
            );
        }
    });

    tokio::time::sleep(Duration::from_millis(50)).await;

    // ── Client ──────────────────────────────────────────────────────────────
    let peer: SocketAddr = "127.0.0.1:7760".parse()?;

    let mut conn = Zudp::default().port(0).connect::<Msg>(peer).await?;
    println!("\nclient  connected {} → {peer}\n", conn.local_addr()?);

    // Send messages of increasing size so the path MTU and pacing rate settle.
    let sizes = [64usize, 512, 1_024, 1_400, 4_096];
    for &sz in &sizes {
        let payload = vec![0xABu8; sz];
        conn.send(Msg::Data(payload)).await?;

        let pkt = conn.recv().await?;
        let Msg::Data(ref echo) = pkt.msg;

        // ZudpConn also exposes the same stats methods.
        let s = conn.peer_stats().expect("peer in table");
        println!(
            "client  sent {sz} B, got {} B back \
             | srtt={:?}  pacing={} B/s  tx={} B  rx={} B",
            echo.len(),
            s.srtt,
            s.pacing_rate_bps,
            s.tx_bytes,
            s.rx_bytes,
        );

        let e = conn.engine_stats();
        println!(
            "client  engine_stats  rate_limited={}  peer_cap_evictions={}",
            e.dropped_rate_limited, e.dropped_peer_cap,
        );

        println!();
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    server.abort();
    Ok(())
}
