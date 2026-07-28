# zudp

Minimal UDP protocol for real-time applications. NACK-based reliability, automatic fragmentation, relay/NAT traversal, optional end-to-end encryption, and optional LAN discovery.

```toml
[dependencies]
zudp = "0.1"                                               # bitcode codec
zudp = { version = "0.1", features = ["security"] }        # + Noise XX encryption
zudp = { version = "0.1", features = ["discovery"] }       # + LAN peer discovery
zudp = { version = "0.1", features = ["security", "discovery"] }  # both
```

## Quick start

```rust
use bitcode::{Encode, Decode};
use zudp::Zudp;

#[derive(Encode, Decode)]
enum Msg { Ping, Pong }

// listener — accepts any peer
let mut socket = Zudp::default().port(5000).listen::<Msg>().await?;
let (msg, from, stream_id) = socket.recv().await?;  // stream_id = 0 for default stream
socket.send(Msg::Pong, from).await?;

// single-peer connection
let mut conn = Zudp::default().port(0).connect::<Msg>(peer).await?;
conn.send(Msg::Ping).await?;
let (reply, stream_id) = conn.recv().await?;
```

## Builder options

```rust
Zudp::default()
    .port(7700)                              // 0 = OS-assigned
    .bind_ip(ip)                             // default: 0.0.0.0
    .reliable(true)                          // NACK retransmission on/off
    .mtu(1400)                               // fragmentation threshold in bytes
    .keepalive_interval(Duration::from_secs(5))
    .relay(relay_addr)                       // wrap every packet in a relay header
    .security(Keypair::generate())           // enable Noise XX encryption
    .listen::<Msg>()                         // ZudpSocket<Msg>  — multi-peer
    .connect::<Msg>(peer)                    // ZudpConn<Msg>    — single-peer
```

## Multiple streams

Each reliable connection supports up to 65 535 independent ordered streams. Streams have separate sequence spaces, so packet loss on one stream never delays delivery on another (no head-of-line blocking).

```rust
// server: recv returns (message, peer_addr, stream_id)
let (msg, from, stream_id) = socket.recv().await?;
socket.send_stream(reply, from, stream_id).await?;   // reply on same stream

// client: send to specific stream
conn.send_stream(Msg::Command(cmd), 0).await?;         // stream 0 — commands
conn.send_stream(Msg::Snapshot(data), 1).await?;       // stream 1 — snapshots
let (msg, stream_id) = conn.recv().await?;             // from any stream
```

`DEFAULT_STREAM = 0`. `send()` / `recv()` target stream 0 — existing code continues to work unchanged.

## End-to-end encryption

Requires `features = ["security"]`. Uses Noise XX with X25519 DH, ChaCha20-Poly1305 AEAD, and BLAKE2s — the same cryptography as WireGuard. Mutual authentication: both sides verify each other's public key.

```rust
use zudp::{Keypair, Zudp};

// Generate a keypair once and persist it (e.g. to disk).
let keypair = Keypair::generate();

// Server — listen with security enabled.
let mut socket = Zudp::default()
    .port(7700)
    .security(keypair.clone())
    .listen::<Msg>()
    .await?;

// Client — connect; Noise XX handshake happens automatically.
let mut conn = Zudp::default()
    .port(0)
    .security(Keypair::generate())
    .connect::<Msg>(server_addr)
    .await?;

// Send/recv API is identical — encryption is transparent.
conn.send(Msg::Ping).await?;
let reply = conn.recv().await?;
```

The three Noise handshake messages are exchanged before any data flows. Reliable frames (Stream, Fragment) are encrypted; keepalive Ping/Pong and Nack frames are not. NACK retransmits re-encrypt with a fresh nonce to prevent nonce reuse.

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
