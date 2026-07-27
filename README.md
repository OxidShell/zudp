# zudp

Minimal UDP protocol for real-time applications. NACK-based reliability, automatic fragmentation, relay/NAT traversal, and a zero-boilerplate API.

```toml
[dependencies]
zudp = "0.1"
```

## Quick start

```rust
use bitcode::{Encode, Decode};
use zudp::Zudp;

#[derive(Encode, Decode)]
enum Msg { Ping, Pong }

// listener (accepts any peer)
let mut socket = Zudp::default().port(5000).listen::<Msg>().await?;
let (msg, from) = socket.recv().await?;
socket.send(Msg::Pong, from).await?;

// single-peer connection
let mut conn = Zudp::default().port(0).connect::<Msg>(peer).await?;
conn.send(Msg::Ping).await?;
let reply = conn.recv().await?; // returns M, not (M, addr)
```

## Features

| | |
|---|---|
| **Reliability** | NACK-based retransmission — only missing packets are resent |
| **Fragmentation** | Messages above the MTU (default 1 400 B) are split and reassembled transparently |
| **Relay** | Route packets through a relay node for NAT traversal |
| **Keepalives** | Idle channels send periodic pings to detect dead peers |
| **Codec** | `bitcode` by default; swap to `serde`+postcard via feature flag |

## Builder options

```rust
Zudp::default()
    .port(7700)            // 0 = OS-assigned
    .bind_ip(ip)           // default: 0.0.0.0
    .reliable(true)        // NACK retransmission on/off
    .mtu(1400)             // fragmentation threshold in bytes
    .keepalive_interval(Duration::from_secs(5))
    .relay(relay_addr)     // wrap every packet in a relay header
    .listen::<Msg>()       // ZudpSocket<Msg>  — multi-peer
    .connect::<Msg>(peer)  // ZudpConn<Msg>    — single-peer
```

## Codec features

```toml
zudp = { version = "0.1", default-features = false, features = ["serde"] }
```

| Feature | Codec | Error type |
|---|---|---|
| `bitcode` (default) | bitcode | `bitcode::Error` |
| `serde` | postcard | `postcard::Error` |
| both | postcard wins | `Box<dyn Error>` |

## Relay

```rust
// client wraps every packet in a Frame::Relay header
let conn = Zudp::default()
    .relay("relay.example.com:7800".parse()?)
    .connect::<Msg>(server_addr)
    .await?;

// NACKs do not propagate through the relay — use send_unreliable for relay paths
conn.send_unreliable(msg).await?;
```

The relay node is a plain `ZudpSocket`; no special configuration needed.
The server sees `from == relay_addr`, not the original client address.

## License

MIT
