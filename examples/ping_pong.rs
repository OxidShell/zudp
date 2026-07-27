use std::net::SocketAddr;

use bitcode::{Decode, Encode};
use zudp::Zudp;

#[derive(Debug, Encode, Decode)]
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
            .messages::<Msg>()
            .port(7700)
            .listen()
            .await
            .expect("server bind failed");

        println!("server listening on {}", server.local_addr().unwrap());

        let (msg, from) = server.recv().await.expect("server recv failed");
        println!("server got {msg:?} from {from}");

        server
            .send(Msg::Pong, from)
            .await
            .expect("server reply failed");
        println!("server sent Pong");
    });

    // Give the server a moment to bind.
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let peer: SocketAddr = "127.0.0.1:7700".parse()?;
    let mut client = Zudp::default()
        .messages::<Msg>()
        .port(0)
        .connect(peer)
        .await?;

    println!("client bound on {}", client.local_addr()?);
    client.send(Msg::Ping).await?;
    println!("client sent Ping");

    let reply = client.recv().await?;
    println!("client got {reply:?}");

    server_task.await?;
    Ok(())
}
