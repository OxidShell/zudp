use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bitcode::{Decode, Encode};
use zudp::Zudp;

#[derive(Debug, Encode, Decode)]
enum Msg {
    Ping { sent_at_us: u64 },
    Pong { sent_at_us: u64 },
}

fn now_us() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_micros()).unwrap_or(u64::MAX))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let peer: std::net::SocketAddr = std::env::args()
        .nth(1)
        .expect("usage: client <ip:port>  [count]  [interval_ms]")
        .parse()?;

    let count: u32 = std::env::args()
        .nth(2)
        .and_then(|a| a.parse().ok())
        .unwrap_or(10);

    let interval_ms: u64 = std::env::args()
        .nth(3)
        .and_then(|a| a.parse().ok())
        .unwrap_or(500);

    let mut conn = Zudp::default().port(0).connect::<Msg>(peer).await?;
    println!("connected {} → {peer}", conn.local_addr()?);
    println!("sending {count} pings every {interval_ms} ms\n");

    let mut rtts: Vec<f64> = Vec::with_capacity(count as usize);

    for seq in 1..=count {
        let sent_at = now_us();
        conn.send(Msg::Ping {
            sent_at_us: sent_at,
        })
        .await?;

        match tokio::time::timeout(Duration::from_secs(2), conn.recv()).await {
            Err(_) => println!("#{seq:>3}  timeout"),
            Ok(Err(e)) => println!("#{seq:>3}  error: {e}"),
            Ok(Ok((Msg::Pong { sent_at_us }, _stream))) => {
                let elapsed_us = now_us().saturating_sub(sent_at_us);
                #[allow(clippy::cast_precision_loss)]
                let rtt_ms = elapsed_us as f64 / 1000.0;
                rtts.push(rtt_ms);
                println!("#{seq:>3}  rtt = {rtt_ms:.2} ms");
            }
            Ok(Ok(_)) => {} // Ping echo or unexpected variant
        }

        if seq < count {
            tokio::time::sleep(Duration::from_millis(interval_ms)).await;
        }
    }

    if !rtts.is_empty() {
        let min = rtts.iter().copied().fold(f64::INFINITY, f64::min);
        let max = rtts.iter().copied().fold(f64::NEG_INFINITY, f64::max);
        #[allow(clippy::cast_precision_loss)]
        let avg = rtts.iter().sum::<f64>() / rtts.len() as f64;
        let lost = count as usize - rtts.len();
        #[allow(clippy::cast_precision_loss)]
        let loss_pct = lost as f64 / f64::from(count) * 100.0;
        println!("\n--- {peer} ping statistics ---");
        println!(
            "{count} sent, {} received, {lost} lost ({loss_pct:.0}% loss)",
            rtts.len(),
        );
        println!("rtt min/avg/max = {min:.2}/{avg:.2}/{max:.2} ms");
    }

    Ok(())
}
