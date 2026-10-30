//! Dead peers are detected, reported and cleaned up; live idle peers are kept.

mod common;

use std::time::Duration;

use common::{LO, lo};
use tokio::time::timeout;
use zudp::{DisconnectReason, PeerEvent};

fn quick() -> zudp::Zudp {
    lo().keepalive_interval(Duration::from_millis(200))
        .peer_timeout(Duration::from_millis(700))
}

async fn next_event(events: &mut zudp::PeerEvents, wait: Duration) -> PeerEvent {
    timeout(wait, events.recv())
        .await
        .expect("no event in time")
        .unwrap()
}

#[tokio::test]
async fn dead_peer_times_out_and_is_reported() {
    let server: zudp::ZudpSocket<Vec<u8>> = quick().port(0).listen().await.unwrap();
    let mut events = server.events();
    let client_addr = {
        let client = quick()
            .port(0)
            .connect::<Vec<u8>>(server.local_addr().unwrap())
            .await
            .unwrap();
        client.send(b"hi".to_vec()).await.unwrap();
        let addr = client.local_addr().unwrap();
        let addr = std::net::SocketAddr::new(LO, addr.port());
        assert_eq!(
            next_event(&mut events, Duration::from_secs(1)).await,
            PeerEvent::Connected { addr, key: None }
        );
        addr
    };
    assert_eq!(
        next_event(&mut events, Duration::from_secs(3)).await,
        PeerEvent::Disconnected {
            addr: client_addr,
            reason: DisconnectReason::TimedOut
        }
    );
    assert!(
        server.peer_stats(client_addr).is_none(),
        "state not cleaned up"
    );
}

#[tokio::test]
async fn conn_recv_fails_when_the_server_dies() {
    let server: zudp::ZudpSocket<Vec<u8>> = quick().port(0).listen().await.unwrap();
    let mut client = quick()
        .port(0)
        .connect::<Vec<u8>>(server.local_addr().unwrap())
        .await
        .unwrap();
    drop(server);
    let result = timeout(Duration::from_secs(3), client.recv())
        .await
        .expect("recv never noticed the dead server");
    assert!(matches!(result, Err(zudp::Error::PeerTimeout { .. })));
}

#[tokio::test]
async fn idle_live_peers_are_kept() {
    let mut server: zudp::ZudpSocket<Vec<u8>> = quick().port(0).listen().await.unwrap();
    let mut events = server.events();
    let client = quick()
        .port(0)
        .connect::<Vec<u8>>(server.local_addr().unwrap())
        .await
        .unwrap();
    client.send(b"one".to_vec()).await.unwrap();
    timeout(Duration::from_secs(1), server.recv())
        .await
        .unwrap()
        .unwrap();
    tokio::time::sleep(Duration::from_secs(2)).await;
    while let Some(event) = events.try_recv() {
        assert!(
            !matches!(event, PeerEvent::Disconnected { .. }),
            "live idle peer dropped: {event:?}"
        );
    }
    client.send(b"two".to_vec()).await.unwrap();
    let packet = timeout(Duration::from_secs(1), server.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(packet.msg, b"two");
}

#[tokio::test]
async fn remove_peer_drops_state_and_reports_it() {
    let mut server: zudp::ZudpSocket<Vec<u8>> = lo().port(0).listen().await.unwrap();
    let mut events = server.events();
    let client = lo()
        .port(0)
        .connect::<Vec<u8>>(server.local_addr().unwrap())
        .await
        .unwrap();
    client.send(b"x".to_vec()).await.unwrap();
    let from = timeout(Duration::from_secs(1), server.recv())
        .await
        .unwrap()
        .unwrap()
        .from;
    assert!(server.remove_peer(from));
    assert!(!server.remove_peer(from));
    let mut saw_removed = false;
    while let Some(event) = events.try_recv() {
        saw_removed |= event
            == PeerEvent::Disconnected {
                addr: from,
                reason: DisconnectReason::Removed,
            };
    }
    assert!(saw_removed);
    assert!(server.peer_stats(from).is_none());
}

#[cfg(feature = "security")]
#[tokio::test]
async fn secure_sessions_report_connected_and_reset_with_the_key() {
    use zudp::Keypair;

    let server: zudp::ZudpSocket<Vec<u8>> = lo()
        .port(0)
        .security(Keypair::generate())
        .listen()
        .await
        .unwrap();
    let server_addr = server.local_addr().unwrap();
    let mut events = server.events();
    let port = common::free_port();
    let addr = std::net::SocketAddr::new(LO, port);
    let first = Keypair::generate();
    drop(
        lo().port(port)
            .security(first.clone())
            .connect::<Vec<u8>>(server_addr)
            .await
            .unwrap(),
    );
    assert_eq!(
        next_event(&mut events, Duration::from_secs(1)).await,
        PeerEvent::Connected {
            addr,
            key: Some(first.public)
        }
    );
    while std::net::UdpSocket::bind((LO, port)).is_err() {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let second = Keypair::generate();
    let _conn = lo()
        .port(port)
        .security(second.clone())
        .connect::<Vec<u8>>(server_addr)
        .await
        .unwrap();
    assert_eq!(
        next_event(&mut events, Duration::from_secs(1)).await,
        PeerEvent::Reset {
            addr,
            key: Some(second.public)
        }
    );
}
