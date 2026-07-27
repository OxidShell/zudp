use bitcode::{Decode, Encode};
use zudp::Zudp;

#[derive(Debug, Encode, Decode)]
enum Msg {
    Ping { sent_at_us: u64 },
    Pong { sent_at_us: u64 },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let port: u16 = std::env::args()
        .nth(1)
        .and_then(|a| a.parse().ok())
        .unwrap_or(7700);

    let mut socket = Zudp::default().port(port).listen::<Msg>().await?;
    println!("listening on {}", socket.local_addr()?);

    loop {
        let (msg, from) = socket.recv().await?;
        match msg {
            Msg::Ping { sent_at_us } => {
                println!("ping from {from}");
                socket.send(Msg::Pong { sent_at_us }, from).await?;
            }
            Msg::Pong { .. } => {}
        }
    }
}
