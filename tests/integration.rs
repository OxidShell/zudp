use std::{net::IpAddr, net::Ipv4Addr, time::Duration};
use std::collections::HashMap;

use tokio::time::timeout;
use zudp::Zudp;

const RECV_TIMEOUT: Duration = Duration::from_secs(5);
const LOOPBACK: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

macro_rules! recv {
    ($socket:expr) => {
        timeout(RECV_TIMEOUT, $socket.recv())
            .await
            .expect("recv timed out")
            .expect("recv error")
    };
}

fn lo() -> Zudp {
    Zudp::default().bind_ip(LOOPBACK)
}

#[tokio::test]
async fn small_reliable_message() {
    let mut server: zudp::ZudpSocket<Vec<u8>> = lo().port(0).listen().await.unwrap();
    let server_addr = server.local_addr().unwrap();

    let client = lo().port(0).connect::<Vec<u8>>(server_addr).await.unwrap();

    let msg = b"hello world".to_vec();
    client.send(msg.clone()).await.unwrap();

    let pkt = recv!(server);
    assert_eq!(pkt.msg, msg);
    assert_eq!(pkt.stream, 0);
}

#[tokio::test]
async fn echo_roundtrip() {
    let mut server: zudp::ZudpSocket<Vec<u8>> = lo().port(0).listen().await.unwrap();
    let server_addr = server.local_addr().unwrap();

    let mut client = lo().port(0).connect::<Vec<u8>>(server_addr).await.unwrap();

    tokio::spawn(async move {
        let pkt = timeout(RECV_TIMEOUT, server.recv())
            .await
            .unwrap()
            .unwrap();
        let mut echoed = pkt.msg.clone();
        echoed.extend_from_slice(b"_ack");
        server.send(echoed, pkt.from).await.unwrap();
    });

    client.send(b"ping".to_vec()).await.unwrap();
    let reply = recv!(client);
    assert_eq!(reply.msg, b"ping_ack".to_vec());
}

#[tokio::test]
async fn fragmented_message() {
    // Tiny MTU forces fragmentation of the 2 KiB payload.
    let mut server: zudp::ZudpSocket<Vec<u8>> = lo().port(0).mtu(200).listen().await.unwrap();
    let server_addr = server.local_addr().unwrap();

    let client = lo()
        .port(0)
        .mtu(200)
        .connect::<Vec<u8>>(server_addr)
        .await
        .unwrap();

    let big = vec![0xABu8; 2000];
    client.send(big.clone()).await.unwrap();

    let pkt = recv!(server);
    assert_eq!(pkt.msg, big);
}

async fn discovered_mtu(conn: &zudp::ZudpConn<Vec<u8>>) -> usize {
    timeout(Duration::from_secs(6), async {
        loop {
            if let Some(mtu) = conn.effective_mtu() {
                return mtu;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("mtu discovery timed out")
}

#[tokio::test]
async fn mtu_discovery_defaults_to_a_safe_non_jumbo_ceiling() {
    // Loopback has no real link MTU limit, so every probe up to 9000 bytes
    // succeeds — exactly the condition that used to let discovery settle on
    // a jumbo frame size that a real network path can't actually sustain.
    // The default ceiling has to hold even here.
    let mut server: zudp::ZudpSocket<Vec<u8>> = lo().port(0).listen().await.unwrap();
    let server_addr = server.local_addr().unwrap();
    let client = lo().port(0).connect::<Vec<u8>>(server_addr).await.unwrap();
    client.send(b"hi".to_vec()).await.unwrap();
    recv!(server);

    let mtu = discovered_mtu(&client).await;
    assert!(
        mtu <= 1472,
        "discovery has to stay at or under the safe default ceiling, got {mtu}"
    );
}

#[tokio::test]
async fn max_mtu_lets_discovery_go_past_the_default_ceiling() {
    let mut server: zudp::ZudpSocket<Vec<u8>> = lo().port(0).max_mtu(9000).listen().await.unwrap();
    let server_addr = server.local_addr().unwrap();
    let client = lo()
        .port(0)
        .max_mtu(9000)
        .connect::<Vec<u8>>(server_addr)
        .await
        .unwrap();
    client.send(b"hi".to_vec()).await.unwrap();
    recv!(server);

    let mtu = discovered_mtu(&client).await;
    assert!(
        mtu > 1472,
        "max_mtu(9000) should let discovery go past the default ceiling, got {mtu}"
    );
}

#[tokio::test]
async fn multi_stream() {
    let mut server: zudp::ZudpSocket<Vec<u8>> = lo().port(0).listen().await.unwrap();
    let server_addr = server.local_addr().unwrap();

    let client = lo()
        .port(0)
        .connect::<Vec<u8>>(server_addr)
        .await
        .unwrap();

    client.send_stream(b"s0".to_vec(), 0).await.unwrap();
    client.send_stream(b"s1".to_vec(), 1).await.unwrap();

    let pkt1 = recv!(server);
    let pkt2 = recv!(server);

    let mut by_stream: HashMap<u16, Vec<u8>> = HashMap::new();
    for pkt in [pkt1, pkt2] {
        by_stream.insert(pkt.stream, pkt.msg);
    }
    assert_eq!(by_stream[&0], b"s0".to_vec());
    assert_eq!(by_stream[&1], b"s1".to_vec());
}

#[tokio::test]
async fn unreliable_datagram() {
    let mut server: zudp::ZudpSocket<Vec<u8>> = lo().port(0).listen().await.unwrap();
    let server_addr = server.local_addr().unwrap();

    let client = lo()
        .port(0)
        .connect::<Vec<u8>>(server_addr)
        .await
        .unwrap();

    client.send_unreliable(b"fire and forget".to_vec()).await.unwrap();

    let pkt = recv!(server);
    assert_eq!(pkt.msg, b"fire and forget".to_vec());
}

#[tokio::test]
async fn multiple_messages_in_order() {
    let mut server: zudp::ZudpSocket<u64> = lo().port(0).listen().await.unwrap();
    let server_addr = server.local_addr().unwrap();

    let client = lo().port(0).connect::<u64>(server_addr).await.unwrap();

    for i in 0u64..5 {
        client.send(i).await.unwrap();
    }

    for expected in 0u64..5 {
        let pkt = recv!(server);
        assert_eq!(pkt.msg, expected, "out-of-order delivery on stream 0");
    }
}

#[cfg(feature = "security")]
#[tokio::test]
async fn key_pinning_correct_key_allowed() {
    use zudp::Keypair;

    let server_kp = Keypair::generate();
    let client_kp = Keypair::generate();

    let mut server: zudp::ZudpSocket<Vec<u8>> = Zudp::default()
        .bind_ip(LOOPBACK)
        .port(0)
        .security(server_kp.clone())
        .listen()
        .await
        .unwrap();
    let server_addr = server.local_addr().unwrap();

    let client = Zudp::default()
        .bind_ip(LOOPBACK)
        .port(0)
        .security(client_kp)
        .pin_remote_key(*server_kp.public_key())
        .connect::<Vec<u8>>(server_addr)
        .await
        .unwrap();

    client.send(b"pinned ok".to_vec()).await.unwrap();
    let pkt = recv!(server);
    assert_eq!(pkt.msg, b"pinned ok".to_vec());
}

#[cfg(feature = "security")]
#[tokio::test]
async fn key_pinning_wrong_key_rejected() {
    use zudp::Keypair;

    let server_kp = Keypair::generate();
    let client_kp = Keypair::generate();
    let wrong_kp = Keypair::generate();

    let server: zudp::ZudpSocket<Vec<u8>> = Zudp::default()
        .bind_ip(LOOPBACK)
        .port(0)
        .security(server_kp)
        .listen()
        .await
        .unwrap();
    let server_addr = server.local_addr().unwrap();

    // connect() blocks until channel_ready fires; with a wrong pinned key it never fires.
    let result = timeout(
        Duration::from_secs(2),
        Zudp::default()
            .bind_ip(LOOPBACK)
            .port(0)
            .security(client_kp)
            .pin_remote_key(*wrong_kp.public_key())
            .connect::<Vec<u8>>(server_addr),
    )
    .await;

    assert!(result.is_err(), "connect() should time out with a wrong pinned key");
}

#[cfg(feature = "security")]
#[tokio::test]
async fn key_pinning_none_allows_any() {
    use zudp::Keypair;

    let server_kp = Keypair::generate();
    let client_kp = Keypair::generate();

    let mut server: zudp::ZudpSocket<Vec<u8>> = Zudp::default()
        .bind_ip(LOOPBACK)
        .port(0)
        .security(server_kp)
        .listen()
        .await
        .unwrap();
    let server_addr = server.local_addr().unwrap();

    // No pin_remote_key — any valid peer should be accepted.
    let client = Zudp::default()
        .bind_ip(LOOPBACK)
        .port(0)
        .security(client_kp)
        .connect::<Vec<u8>>(server_addr)
        .await
        .unwrap();

    client.send(b"no pin ok".to_vec()).await.unwrap();
    let pkt = recv!(server);
    assert_eq!(pkt.msg, b"no pin ok".to_vec());
}

#[tokio::test]
async fn rate_limit_throttled() {
    // max_pps=10 → burst=max(10/5,1)=2 tokens initially.
    // Sending 10 packets instantly should let through at most burst (2) + ~0 refill.
    let mut server: zudp::ZudpSocket<Vec<u8>> = Zudp::default()
        .bind_ip(LOOPBACK)
        .port(0)
        .rate_limit(10.0)
        .listen()
        .await
        .unwrap();
    let server_addr = server.local_addr().unwrap();

    let client = lo().port(0).connect::<Vec<u8>>(server_addr).await.unwrap();

    for _ in 0..10u8 {
        client.send(vec![0u8]).await.unwrap();
    }

    // Collect what arrives within a short window.
    let mut received = 0usize;
    let deadline = tokio::time::Instant::now() + Duration::from_millis(300);
    while let Ok(Ok(_)) = tokio::time::timeout_at(deadline, server.recv()).await {
        received += 1;
    }

    // Rate limiter drops most packets; at most burst+small-refill worth should arrive.
    assert!(received >= 1, "at least the burst should get through, got {received}");
    assert!(received <= 5, "rate limiter should have throttled most, got {received}");
}

#[tokio::test]
async fn peer_table_cap() {
    let mut server: zudp::ZudpSocket<Vec<u8>> = Zudp::default()
        .bind_ip(LOOPBACK)
        .port(0)
        .max_peers(2)
        .listen()
        .await
        .unwrap();
    let server_addr = server.local_addr().unwrap();

    let c1 = lo().port(0).connect::<Vec<u8>>(server_addr).await.unwrap();
    let c2 = lo().port(0).connect::<Vec<u8>>(server_addr).await.unwrap();
    let c3 = lo().port(0).connect::<Vec<u8>>(server_addr).await.unwrap();

    c1.send(vec![1]).await.unwrap();
    c2.send(vec![2]).await.unwrap();
    c3.send(vec![3]).await.unwrap();

    // At least 2 messages should arrive (from the 2 tracked peers).
    let pkt1 = recv!(server);
    let pkt2 = recv!(server);
    assert!(!pkt1.msg.is_empty());
    assert!(!pkt2.msg.is_empty());
}

#[tokio::test]
async fn peer_stats_tracks_rx_and_tx_bytes() {
    let mut server: zudp::ZudpSocket<Vec<u8>> = lo().port(0).listen().await.unwrap();
    let server_addr = server.local_addr().unwrap();

    let client = lo().port(0).connect::<Vec<u8>>(server_addr).await.unwrap();
    let client_addr = client.local_addr().unwrap();

    let payload = vec![0xAAu8; 256];
    client.send(payload.clone()).await.unwrap();
    let _ = recv!(server);

    // Server must have recorded non-zero rx_bytes from the client.
    // (rx_bytes tracks encoded payload bytes, not raw message size.)
    let srv = server
        .peer_stats(client_addr)
        .expect("client should be in server peer table");
    assert!(
        srv.rx_bytes > 0,
        "server rx_bytes should be non-zero, got {}",
        srv.rx_bytes
    );

    // Client must have recorded non-zero tx_bytes to the server.
    // (tx_bytes tracks plain-frame bytes including stream header overhead.)
    let cli = client.peer_stats().expect("server should be in client peer table");
    assert!(
        cli.tx_bytes > 0,
        "client tx_bytes should be non-zero, got {}",
        cli.tx_bytes
    );
}

#[tokio::test]
async fn engine_stats_rate_limited_counter_increments() {
    // max_pps=1 → burst=max(0.2,1)=1 token; firing 20 packets instantly saturates it quickly.
    let server: zudp::ZudpSocket<Vec<u8>> = Zudp::default()
        .bind_ip(LOOPBACK)
        .port(0)
        .rate_limit(1.0)
        .listen()
        .await
        .unwrap();
    let server_addr = server.local_addr().unwrap();

    let client = lo().port(0).connect::<Vec<u8>>(server_addr).await.unwrap();
    for _ in 0..20u8 {
        client.send(vec![0u8]).await.unwrap();
    }
    tokio::time::sleep(Duration::from_millis(100)).await;

    let stats = server.engine_stats();
    assert!(
        stats.dropped_rate_limited >= 1,
        "dropped_rate_limited should be non-zero under burst, got {}",
        stats.dropped_rate_limited
    );
}

#[tokio::test]
async fn engine_stats_peer_cap_counter_increments() {
    // max_peers=1: a second distinct peer causes an LRU eviction and increments the counter.
    let server: zudp::ZudpSocket<Vec<u8>> = Zudp::default()
        .bind_ip(LOOPBACK)
        .port(0)
        .max_peers(1)
        .listen()
        .await
        .unwrap();
    let server_addr = server.local_addr().unwrap();

    let c1 = lo().port(0).connect::<Vec<u8>>(server_addr).await.unwrap();
    c1.send(vec![1]).await.unwrap();
    tokio::time::sleep(Duration::from_millis(30)).await;

    let c2 = lo().port(0).connect::<Vec<u8>>(server_addr).await.unwrap();
    c2.send(vec![2]).await.unwrap();
    tokio::time::sleep(Duration::from_millis(30)).await;

    let stats = server.engine_stats();
    assert!(
        stats.dropped_peer_cap >= 1,
        "dropped_peer_cap should increment on LRU eviction, got {}",
        stats.dropped_peer_cap
    );
}

#[tokio::test]
async fn engine_stats_relay_blocked_counter_increments() {
    // Relay only allows 127.0.0.2; our loopback client is 127.0.0.1 — blocked.
    let relay: zudp::ZudpSocket<Vec<u8>> = Zudp::default()
        .bind_ip(LOOPBACK)
        .port(0)
        .relay_allowlist(vec![IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2))])
        .listen()
        .await
        .unwrap();
    let relay_addr = relay.local_addr().unwrap();
    let server: zudp::ZudpSocket<Vec<u8>> = lo().port(0).listen().await.unwrap();
    let server_addr = server.local_addr().unwrap();

    let client = lo()
        .port(0)
        .relay(relay_addr)
        .connect::<Vec<u8>>(server_addr)
        .await
        .unwrap();
    client.send(b"blocked".to_vec()).await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;

    let stats = relay.engine_stats();
    assert!(
        stats.dropped_relay_blocked >= 1,
        "dropped_relay_blocked should increment, got {}",
        stats.dropped_relay_blocked
    );
}

#[tokio::test]
async fn lru_eviction_keeps_most_recently_active_peer() {
    // max_peers=1: when c2 arrives it evicts c1 (c1 is LRU at that moment).
    let server: zudp::ZudpSocket<Vec<u8>> = Zudp::default()
        .bind_ip(LOOPBACK)
        .port(0)
        .max_peers(1)
        .listen()
        .await
        .unwrap();
    let server_addr = server.local_addr().unwrap();

    let c1 = lo().port(0).connect::<Vec<u8>>(server_addr).await.unwrap();
    let c2 = lo().port(0).connect::<Vec<u8>>(server_addr).await.unwrap();
    let c1_addr = c1.local_addr().unwrap();
    let c2_addr = c2.local_addr().unwrap();

    // c1 sends first — gets inserted into the table.
    c1.send(vec![1]).await.unwrap();
    tokio::time::sleep(Duration::from_millis(20)).await;

    // c2 sends — c1 is the only (and thus least-recently-seen) peer, so c1 is evicted.
    c2.send(vec![2]).await.unwrap();
    tokio::time::sleep(Duration::from_millis(20)).await;

    assert!(
        server.peer_stats(c1_addr).is_none(),
        "c1 should have been evicted as the LRU peer"
    );
    assert!(
        server.peer_stats(c2_addr).is_some(),
        "c2 should be in the peer table after evicting c1"
    );
}

#[tokio::test]
async fn relay_allowlist_blocks_unauthorized() {
    let mut real_server: zudp::ZudpSocket<Vec<u8>> = lo().port(0).listen().await.unwrap();
    let real_server_addr = real_server.local_addr().unwrap();

    // Relay node allows only 127.0.0.2 — our loopback (127.0.0.1) is not in the list.
    let relay: zudp::ZudpSocket<Vec<u8>> = Zudp::default()
        .bind_ip(LOOPBACK)
        .port(0)
        .relay_allowlist(vec![IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2))])
        .listen()
        .await
        .unwrap();
    let relay_addr = relay.local_addr().unwrap();

    let client = lo()
        .port(0)
        .relay(relay_addr)
        .connect::<Vec<u8>>(real_server_addr)
        .await
        .unwrap();

    client.send(b"blocked".to_vec()).await.unwrap();

    let result = timeout(Duration::from_millis(500), real_server.recv()).await;
    assert!(result.is_err(), "relay should have blocked the unauthorized sender");
}

#[tokio::test]
async fn relay_table_cap() {
    let mut server1: zudp::ZudpSocket<Vec<u8>> = lo().port(0).listen().await.unwrap();
    let server1_addr = server1.local_addr().unwrap();
    let mut server2: zudp::ZudpSocket<Vec<u8>> = lo().port(0).listen().await.unwrap();
    let server2_addr = server2.local_addr().unwrap();

    // Relay with table cap = 1: only one destination may be tracked at a time.
    let relay: zudp::ZudpSocket<Vec<u8>> = Zudp::default()
        .bind_ip(LOOPBACK)
        .port(0)
        .max_relay_entries(1)
        .listen()
        .await
        .unwrap();
    let relay_addr = relay.local_addr().unwrap();

    let client1 = lo()
        .port(0)
        .relay(relay_addr)
        .connect::<Vec<u8>>(server1_addr)
        .await
        .unwrap();
    let client2 = lo()
        .port(0)
        .relay(relay_addr)
        .connect::<Vec<u8>>(server2_addr)
        .await
        .unwrap();

    // First client's route should be established.
    client1.send(b"via relay".to_vec()).await.unwrap();
    let pkt = recv!(server1);
    assert_eq!(pkt.msg, b"via relay".to_vec());

    // Second client's destination is a new relay entry, but cap=1 is full.
    client2.send(b"should be dropped".to_vec()).await.unwrap();
    let result = timeout(Duration::from_millis(500), server2.recv()).await;
    assert!(result.is_err(), "relay table should be full — second route dropped");
}

/// Bulk request/response with default config: each ~60 KB message must be
/// delivered promptly, without waiting on an application-level retry.
#[tokio::test]
async fn bulk_request_response_does_not_stall() {
    let mut server: zudp::ZudpSocket<Vec<u8>> = lo().port(0).listen().await.unwrap();
    let server_addr = server.local_addr().unwrap();
    let mut client = lo().port(0).connect::<Vec<u8>>(server_addr).await.unwrap();

    tokio::spawn(async move {
        while let Ok(pkt) = server.recv().await {
            server.send(vec![0xAC], pkt.from).await.unwrap();
        }
    });

    for round in 0..60u8 {
        client.send(vec![round; 60_000]).await.unwrap();
        let ack = timeout(Duration::from_secs(2), client.recv())
            .await
            .unwrap_or_else(|_| panic!("round {round}: no ack within 2 s"))
            .unwrap();
        assert_eq!(ack.msg, vec![0xAC]);
    }
}
