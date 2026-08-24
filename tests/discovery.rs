use std::time::Duration;

use zudp::rkyv::{Archive, Deserialize, Serialize};
use zudp::{Discovery, DiscoveryConfig};

#[derive(Debug, Clone, Archive, Serialize, Deserialize)]
#[cfg_attr(
    feature = "serde",
    derive(zudp::serde::Serialize, zudp::serde::Deserialize)
)]
struct Info {
    name: String,
}

/// Grabs a free UDP port so each test run uses its own discovery port.
fn free_udp_port() -> u16 {
    std::net::UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

#[tokio::test]
async fn scan_once_finds_a_peer_advertised_from_the_same_process() {
    let discovery_port = free_udp_port();

    let advertise_cfg = DiscoveryConfig::new("zudp-test", 4242)
        .discovery_port(discovery_port)
        .meta(Info {
            name: "peer".into(),
        });
    let _advertise = Discovery::advertise(advertise_cfg).unwrap();

    let scan_cfg = DiscoveryConfig::new("zudp-test", 0).discovery_port(discovery_port);
    let peers = Discovery::scan_once::<Info>(scan_cfg, Duration::from_millis(500))
        .await
        .unwrap();

    assert_eq!(peers.len(), 1);
    assert_eq!(peers[0].meta.name, "peer");
    assert_eq!(peers[0].data_addr.port(), 4242);
}
