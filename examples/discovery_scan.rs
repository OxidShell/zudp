use std::time::Duration;

use zudp::rkyv::{Archive, Deserialize, Serialize};
use zudp::{Discovery, DiscoveryConfig};

#[derive(Debug, Clone, Archive, Serialize, Deserialize)]
#[cfg_attr(feature = "serde", derive(zudp::serde::Serialize, zudp::serde::Deserialize))]
struct GameInfo {
    name: String,
    players: u8,
    map: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    // ── One-shot scan: collect all peers that reply within 500 ms ────────────
    println!("=== scan_once (500 ms window) ===");
    let peers = Discovery::scan_once::<GameInfo>(
        DiscoveryConfig::new("zudp-example", 0),
        Duration::from_millis(500),
    )
    .await?;

    if peers.is_empty() {
        println!("no peers found — start discovery_advertise on the same LAN");
    } else {
        for peer in &peers {
            println!(
                "found: {} | players={} map={} | connect to {}",
                peer.meta.name, peer.meta.players, peer.meta.map, peer.data_addr
            );
        }
    }

    // ── Continuous scan: stream peers as they appear ─────────────────────────
    println!("\n=== scan_stream (continuous, Ctrl-C to stop) ===");
    let cfg = DiscoveryConfig::new("zudp-example", 0).probe_interval(Duration::from_secs(3));
    let mut stream = Discovery::scan_stream::<GameInfo>(cfg).await?;

    loop {
        tokio::select! {
            result = stream.next() => {
                let peer = result?;
                println!(
                    "new peer: {} | players={} map={} | data_addr={}",
                    peer.meta.name, peer.meta.players, peer.meta.map, peer.data_addr
                );
            }
            _ = tokio::signal::ctrl_c() => {
                println!("stopping");
                break;
            }
        }
    }

    Ok(())
}
