# zudp

Minimal UDP protocol for real-time applications. NACK-based reliability, automatic fragmentation, relay/NAT traversal, and optional LAN discovery.

```toml
[dependencies]
zudp = "0.1"                                    # bitcode codec, no discovery
zudp = { version = "0.1", features = ["discovery"] }  # + LAN peer discovery
```

## Quick start

```rust
use bitcode::{Encode, Decode};
use zudp::Zudp;

#[derive(Encode, Decode)]
enum Msg { Ping, Pong }

// listener — accepts any peer
let mut socket = Zudp::default().port(5000).listen::<Msg>().await?;
let (msg, from) = socket.recv().await?;
socket.send(Msg::Pong, from).await?;

// single-peer connection
let mut conn = Zudp::default().port(0).connect::<Msg>(peer).await?;
conn.send(Msg::Ping).await?;
let reply = conn.recv().await?;
```

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

## LAN discovery

Requires `features = ["discovery"]`.

```rust
use zudp::{Discovery, DiscoveryConfig};

#[derive(Encode, Decode, Clone)]
struct GameInfo { name: String, players: u8 }

// advertise — responds to probes from scanners on the same LAN
let handle = Discovery::advertise(
    DiscoveryConfig::new("my-game", 7700)
        .meta(GameInfo { name: "Alice".into(), players: 3 })
)?;
handle.set_meta(GameInfo { name: "Alice".into(), players: 4 }); // hot-swap

// scan once — collect all peers that reply within a timeout
let peers = Discovery::scan_once::<GameInfo>(
    DiscoveryConfig::new("my-game", 0),
    Duration::from_millis(500),
).await?;

// scan continuously — yields each new peer exactly once
let mut stream = Discovery::scan_stream::<GameInfo>(
    DiscoveryConfig::new("my-game", 0),
).await?;
let peer = stream.next().await?;
// connect to peer.data_addr via Zudp::connect
```

`DiscoveryConfig` builder: `.discovery_port(u16)`, `.probe_interval(Duration)`.
`AppId` is derived from the app name string via a stable FNV-1a hash.

## Codec features

```toml
zudp = { version = "0.1", default-features = false, features = ["serde"] }
```

| Feature | Codec | Error type |
|---|---|---|
| `bitcode` (default) | bitcode | `bitcode::Error` |
| `serde` | postcard | `postcard::Error` |
| both | postcard | `Box<dyn Error>` |
| neither | manual impls | `Box<dyn Error>` |

## Relay

The relay node is a plain `ZudpSocket` — no special configuration needed.
The client wraps every packet in a `Frame::Relay` header; the relay forwards the
inner bytes to the real destination. The server sees `from == relay_addr`.

```rust
let conn = Zudp::default()
    .relay("relay.example.com:7800".parse()?)
    .connect::<Msg>(server_addr)
    .await?;
```

## License

MIT
