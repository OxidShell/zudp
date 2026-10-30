//! A session survives its client changing address, and a lost session is re-established.

mod common;

use std::time::Duration;

use common::{Proxy, drain, lo};
use tokio::time::timeout;
use zudp::PeerEvent;

async fn migrate(secure: bool) {
    #[cfg(not(feature = "security"))]
    let _ = secure;
    #[allow(unused_mut)]
    let mut builder = lo().port(0);
    #[cfg(feature = "security")]
    if secure {
        builder = builder.security(zudp::Keypair::generate());
    }
    let mut server: zudp::ZudpSocket<Vec<u8>> = builder.listen().await.unwrap();
    let mut events = server.events();
    let mut proxy = Proxy::new(server.local_addr().unwrap(), |_, _| true).await;
    #[allow(unused_mut)]
    let mut builder = lo().port(0);
    #[cfg(feature = "security")]
    if secure {
        builder = builder.security(zudp::Keypair::generate());
    }
    let mut client = builder.connect::<Vec<u8>>(proxy.addr).await.unwrap();
    client.send(vec![255]).await.unwrap();
    assert_eq!(
        drain(&mut server, Duration::from_millis(300)).await.len(),
        1
    );

    let old = proxy.upstream_addr().await;
    proxy.rebind().await;
    let new = proxy.upstream_addr().await;
    for i in 0..20u8 {
        client.send(vec![i]).await.unwrap();
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let got: Vec<u8> = drain(&mut server, Duration::from_secs(1))
        .await
        .into_iter()
        .map(|p| {
            assert_eq!(p.from, new, "delivered under the old address");
            p.msg[0]
        })
        .collect();
    assert_eq!(
        got,
        (0..20).collect::<Vec<_>>(),
        "lost or duplicated across the move"
    );

    let mut migrated = false;
    while let Some(event) = events.try_recv() {
        migrated |= event == PeerEvent::Migrated { from: old, to: new };
    }
    assert!(migrated, "no Migrated event");

    server.send(b"back".to_vec(), new).await.unwrap();
    let reply = timeout(Duration::from_secs(1), client.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(reply.msg, b"back");
}

#[tokio::test]
async fn plain_session_follows_an_address_change() {
    migrate(false).await;
}

#[cfg(feature = "security")]
#[tokio::test]
async fn secure_session_follows_an_address_change() {
    migrate(true).await;
}

#[cfg(feature = "security")]
#[tokio::test]
async fn client_rehandshakes_after_the_server_restarts() {
    use common::{LO, free_port};
    use std::net::SocketAddr;
    use zudp::Keypair;

    let port = free_port();
    let addr = SocketAddr::new(LO, port);
    let server_key = Keypair::generate();
    let first: zudp::ZudpSocket<Vec<u8>> = lo()
        .port(port)
        .security(server_key.clone())
        .listen()
        .await
        .unwrap();
    let client = lo()
        .port(0)
        .security(Keypair::generate())
        .connect::<Vec<u8>>(addr)
        .await
        .unwrap();
    let mut events = client.events();
    drop(first);
    while std::net::UdpSocket::bind((LO, port)).is_err() {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let mut second: zudp::ZudpSocket<Vec<u8>> =
        lo().port(port).security(server_key).listen().await.unwrap();
    // The first send hits the restarted server, which answers SessionUnknown.
    client.send(b"lost".to_vec()).await.unwrap();
    let reset = timeout(Duration::from_secs(3), async {
        loop {
            if let PeerEvent::Reset { addr: a, .. } = events.recv().await.unwrap() {
                return a;
            }
        }
    })
    .await
    .expect("client never re-handshook");
    assert_eq!(reset, addr);
    client.send(b"again".to_vec()).await.unwrap();
    let got = drain(&mut second, Duration::from_millis(500)).await;
    assert!(got.iter().any(|p| p.msg == b"again"));
}
