use std::net::Ipv4Addr;
use std::time::Duration;

use zudp::wincode::{SchemaRead, SchemaWrite};
use zudp::{Discovery, DiscoveryConfig};

#[derive(Debug, Clone, SchemaWrite, SchemaRead)]
#[wincode(crate = "zudp::wincode")]
#[cfg_attr(
    feature = "serde",
    derive(zudp::serde::Serialize, zudp::serde::Deserialize)
)]
struct Info {
    name: String,
}

/// Grabs a free UDP port for a test-isolated discovery channel.
/// The socket is dropped immediately; the TOCTOU window is negligible on loopback.
fn free_udp_port() -> u16 {
    std::net::UdpSocket::bind("0.0.0.0:0")
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

    // 255.255.255.255 doesn't loop back to local sockets on Linux; use loopback broadcast.
    let scan_cfg = DiscoveryConfig::new("zudp-test", 0)
        .discovery_port(discovery_port)
        .broadcast_addr(Ipv4Addr::new(127, 255, 255, 255));
    let peers = Discovery::scan_once::<Info>(scan_cfg, Duration::from_millis(500))
        .await
        .unwrap();

    assert_eq!(peers.len(), 1);
    assert_eq!(peers[0].meta.name, "peer");
    assert_eq!(peers[0].data_addr.port(), 4242);
}

fn quick_scan(discovery_port: u16) -> DiscoveryConfig {
    DiscoveryConfig::new("zudp-test", 0)
        .discovery_port(discovery_port)
        .broadcast_addr(Ipv4Addr::new(127, 255, 255, 255))
        .probe_interval(Duration::from_millis(150))
        .peer_ttl(Duration::from_millis(500))
}

fn advertise(discovery_port: u16, name: &str) -> zudp::AdvertiseHandle<Info> {
    let cfg = DiscoveryConfig::new("zudp-test", 4242)
        .discovery_port(discovery_port)
        .meta(Info { name: name.into() });
    Discovery::advertise(cfg).unwrap()
}

async fn event(scan: &mut zudp::ScanStream<Info>) -> zudp::DiscoveryEvent<Info> {
    tokio::time::timeout(Duration::from_secs(3), scan.next_event())
        .await
        .expect("no discovery event")
        .unwrap()
}

#[tokio::test]
async fn scan_reports_found_lost_and_found_again_after_a_restart() {
    let port = free_udp_port();
    let first = advertise(port, "peer");
    let mut scan = Discovery::scan_stream::<Info>(quick_scan(port))
        .await
        .unwrap();
    let zudp::DiscoveryEvent::Found(found) = event(&mut scan).await else {
        panic!("expected Found");
    };
    drop(first);
    assert!(matches!(
        event(&mut scan).await,
        zudp::DiscoveryEvent::Lost { data_addr } if data_addr == found.data_addr
    ));
    let _second = advertise(port, "peer");
    let zudp::DiscoveryEvent::Found(again) = event(&mut scan).await else {
        panic!("expected Found again");
    };
    assert_ne!(again.instance, found.instance);
}

#[tokio::test]
async fn scan_reports_metadata_changes() {
    let port = free_udp_port();
    let handle = advertise(port, "before");
    let mut scan = Discovery::scan_stream::<Info>(quick_scan(port))
        .await
        .unwrap();
    assert!(matches!(
        event(&mut scan).await,
        zudp::DiscoveryEvent::Found(_)
    ));
    handle.set_meta(Info {
        name: "after".into(),
    });
    let zudp::DiscoveryEvent::Updated(peer) = event(&mut scan).await else {
        panic!("expected Updated");
    };
    assert_eq!(peer.meta.name, "after");
}

#[tokio::test]
async fn advertiser_survives_garbage() {
    let port = free_udp_port();
    let _handle = advertise(port, "sturdy");
    let junk = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    for packet in [&b""[..], &[0xFF; 3][..], &[0x07][..]] {
        junk.send_to(packet, ("127.0.0.1", port)).unwrap();
    }
    tokio::time::sleep(Duration::from_millis(50)).await;
    let peers = Discovery::scan_once::<Info>(quick_scan(port), Duration::from_millis(500))
        .await
        .unwrap();
    assert_eq!(peers.len(), 1, "advertiser died on a malformed datagram");
}

/// A scan whose broadcast reaches nobody (TEST-NET-1 is never routed to a
/// host), so only the other probe targets can find peers.
fn scan_without_broadcast(discovery_port: u16) -> DiscoveryConfig {
    DiscoveryConfig::new("zudp-test", 0)
        .discovery_port(discovery_port)
        .broadcast_addr(Ipv4Addr::new(192, 0, 2, 1))
        .probe_interfaces(false)
        .probe_interval(Duration::from_millis(150))
}

#[tokio::test]
async fn loopback_probe_finds_a_local_peer_without_broadcast() {
    let port = free_udp_port();
    let _handle = advertise(port, "local");
    let peers =
        Discovery::scan_once::<Info>(scan_without_broadcast(port), Duration::from_millis(500))
            .await
            .unwrap();
    assert_eq!(peers.len(), 1);
    assert_eq!(peers[0].meta.name, "local");
}

/// The address this host uses to reach the LAN, if it has one. Connecting a
/// UDP socket sends nothing; it only picks the route.
fn lan_ip() -> Option<std::net::IpAddr> {
    let socket = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect(("192.0.2.1", 9)).ok()?;
    let ip = socket.local_addr().ok()?.ip();
    (!ip.is_loopback() && !ip.is_unspecified()).then_some(ip)
}

#[tokio::test]
async fn a_peer_reached_through_two_targets_is_reported_once() {
    let Some(lan) = lan_ip() else {
        eprintln!("no LAN address; skipping");
        return;
    };
    let port = free_udp_port();
    let _handle = advertise(port, "twice");
    let scan = scan_without_broadcast(port).probe_targets([std::net::SocketAddr::new(lan, port)]);
    let peers = Discovery::scan_once::<Info>(scan, Duration::from_millis(500))
        .await
        .unwrap();
    assert_eq!(
        peers.len(),
        1,
        "loopback and LAN answers were two peers: {peers:?}"
    );
}

// Linux refuses to send UDP to port 0 (`EINVAL`), a target that always fails.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn a_failing_target_is_reported_once_and_the_scan_goes_on() {
    let port = free_udp_port();
    let _handle = advertise(port, "still-found");
    let broken = std::net::SocketAddr::from(([127, 0, 0, 1], 0));
    let mut scan =
        Discovery::scan_stream::<Info>(scan_without_broadcast(port).probe_targets([broken]))
            .await
            .unwrap();
    let mut failures = 0;
    let mut found = false;
    let deadline = tokio::time::Instant::now() + Duration::from_millis(700);
    while let Ok(event) = tokio::time::timeout_at(deadline, scan.next_event()).await {
        match event.unwrap() {
            zudp::DiscoveryEvent::ProbeFailed { target, .. } => {
                assert_eq!(target, broken);
                failures += 1;
            }
            zudp::DiscoveryEvent::Found(peer) => found = peer.meta.name == "still-found",
            _ => {}
        }
    }
    assert_eq!(
        failures, 1,
        "a failing target must be reported once, not every round"
    );
    assert!(found, "the scan stopped after a probe failed");
}
