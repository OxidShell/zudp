use std::time::Duration;

use zudp::rkyv::{Archive, Deserialize, Serialize};
use zudp::{Discovery, DiscoveryConfig};

#[derive(Debug, Clone, Archive, Serialize, Deserialize)]
struct GameInfo {
    name: String,
    players: u8,
    map: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let info = GameInfo {
        name: "Alice's game".into(),
        players: 3,
        map: "desert".into(),
    };

    let cfg = DiscoveryConfig::new("zudp-example", 7700)
        .meta(info.clone())
        .probe_interval(Duration::from_secs(2));

    let handle = Discovery::advertise(cfg)?;

    println!(
        "advertising '{}' on data port 7700 — run discovery_scan to find this node",
        info.name
    );
    println!("press Ctrl-C to stop");

    // Hot-swap the metadata after 5 seconds to show set_meta works.
    tokio::time::sleep(Duration::from_secs(5)).await;
    handle.set_meta(GameInfo {
        name: "Alice's game".into(),
        players: 4,
        map: "desert".into(),
    });
    println!("bumped player count to 4");

    tokio::signal::ctrl_c().await?;
    println!("stopping");
    Ok(())
}
