use std::net::SocketAddr;

use zudp::rkyv::{Archive, Deserialize, Serialize};
use zudp::Zudp;

#[derive(Debug, Archive, Serialize, Deserialize)]
enum Msg {
    Ping,
    Pong,
    Data(Vec<u8>),
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    // Spawn server
    let server_task = tokio::spawn(async {
        let mut server = Zudp::default()
            .port(7700)
            .listen::<Msg>()
            .await
            .expect("server bind failed");

        println!("server listening on {}", server.local_addr().unwrap());

        let pkt = server.recv().await.expect("server recv failed");
        println!("server got {:?} from {}", pkt.msg, pkt.from);

        server
            .send(Msg::Pong, pkt.from)
            .await
            .expect("server reply failed");
        println!("server sent Pong");
    });

    // Give the server a moment to bind.
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let peer: SocketAddr = "127.0.0.1:7700".parse()?;
    let mut client = Zudp::default().port(0).connect::<Msg>(peer).await?;

    println!("client bound on {}", client.local_addr()?);
    client.send(Msg::Ping).await?;
    println!("client sent Ping");

    let pkt = client.recv().await?;
    println!("client got {:?}", pkt.msg);

    server_task.await?;
    Ok(())
}
