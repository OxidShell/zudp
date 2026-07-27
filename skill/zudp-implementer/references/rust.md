# Using the `zudp` Rust crate

This file covers how to use `zudp` as a dependency — sending and receiving messages,
configuring the socket, working with the codec, relay, and discovery.  It is not about
implementing the wire protocol; that is in `SKILL.md` and `PROTOCOL.md`.

---

## Dependency

```toml
[dependencies]
zudp = "0.1"                                         # bitcode codec (default)
zudp = { version = "0.1", features = ["discovery"] } # + LAN peer discovery
zudp = { version = "0.1", default-features = false, features = ["serde"] } # postcard codec
```

---

## Message types

Every message type must implement `zudp::Encode` + `zudp::Decode`.
With the default `bitcode` feature, derive them via `bitcode`:

```rust
use bitcode::{Encode, Decode};

#[derive(Encode, Decode)]
enum Msg {
    Ping,
    Pong,
    Data(Vec<u8>),
    Move { x: f32, y: f32 },
}
```

With the `serde` feature, implement `serde::Serialize` + `serde::Deserialize` instead:

```rust
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize)]
struct Msg { /* … */ }
```

Custom codecs: implement `zudp::Encode` and `zudp::Decode` manually.

---

## Two socket types

### `ZudpSocket<M>` — multi-peer (server / P2P node)

Created via `Zudp::listen`.  Sends to and receives from any remote address.

```rust
use zudp::Zudp;

// bind on port 7700, accept any peer
let mut socket = Zudp::default()
    .port(7700)
    .listen::<Msg>()
    .await?;

// recv returns (message, sender_addr)
let (msg, from) = socket.recv().await?;

// send reliable (NACK-tracked) message to a specific peer
socket.send(Msg::Pong, from).await?;

// send unreliable datagram (fire-and-forget, zero overhead)
socket.send_unreliable(Msg::Data(bytes), from).await?;
```

### `ZudpConn<M>` — single-peer (client)

Created via `Zudp::connect`.  All sends go to the bound peer; `recv` discards messages
from any other source.

```rust
let peer: SocketAddr = "1.2.3.4:7700".parse()?;
let mut conn = Zudp::default()
    .port(0)           // OS-assigned local port
    .connect::<Msg>(peer)
    .await?;

conn.send(Msg::Ping).await?;
let reply = conn.recv().await?;  // returns M, not (M, addr)
```

---

## Builder options

```rust
Zudp::default()
    .port(7700)                              // local bind port; 0 = OS-assigned
    .bind_ip(IpAddr::V4(Ipv4Addr::UNSPECIFIED)) // default: 0.0.0.0
    .reliable(true)                          // enable NACK retransmission (default: true)
    .mtu(1400)                               // fragmentation threshold in bytes (default: 1400)
    .keepalive_interval(Duration::from_secs(5))  // idle ping interval (default: 5 s)
    .relay(relay_addr)                       // route all packets through a relay node
    .listen::<Msg>()                         // → ZudpSocket<M>
    // or
    .connect::<Msg>(peer_addr)              // → ZudpConn<M>
```

All builder methods take `self` and return `Self`, so they chain freely.
`listen` and `connect` are async and return `Result<_, zudp::Error>`.

---

## Reliability

`send()` is reliable by default: the frame is buffered and retransmitted on NACK.
`send_unreliable()` sends a Datagram frame — no buffer, no retransmit, ~1 byte overhead.

```rust
// reliable — use for game state, commands, chat
socket.send(Msg::Move { x: 1.0, y: 2.0 }, peer).await?;

// unreliable — use for position updates, audio, anything where stale data is useless
socket.send_unreliable(Msg::Move { x: 1.0, y: 2.0 }, peer).await?;
```

Disable reliability entirely for an unreliable-only socket:

```rust
Zudp::default().reliable(false).port(0).listen::<Msg>().await?
// now send() behaves like send_unreliable()
```

---

## Fragmentation

Transparent.  Messages larger than `mtu` (default 1 400 B) are split automatically on
`send` and reassembled on `recv`.  The caller sees no difference.

```rust
// 50 KB message — automatically fragmented into ~36 Fragment frames
socket.send(Msg::Data(vec![0u8; 50_000]), peer).await?;

// on the receiver side, recv() returns the fully reassembled message
let (Msg::Data(bytes), from) = socket.recv().await? else { … };
assert_eq!(bytes.len(), 50_000);
```

Tune the threshold:

```rust
Zudp::default().mtu(512)   // more, smaller fragments — lower latency on lossy links
Zudp::default().mtu(8000)  // fewer fragments — better throughput on reliable networks
```

Maximum message size: `mtu * 65535` bytes.

---

## Relay / NAT traversal

Configure a relay node on the client; the relay is a plain `ZudpSocket` with no special setup.

```rust
// client — wraps every packet in a Relay frame addressed to the relay node
let conn = Zudp::default()
    .port(0)
    .relay("relay.example.com:7800".parse()?)
    .connect::<Msg>(server_addr)
    .await?;

// relay node — just a normal listening socket; forwards Relay frames automatically
let mut relay = Zudp::default().port(7800).listen::<Msg>().await?;
// (relay doesn't need to recv() — the engine handles forwarding internally)
```

The server sees `from == relay_addr`, not the original client address.
NACK retransmission still works end-to-end (client retransmits to relay; relay re-forwards).

---

## Discovery (`features = ["discovery"]`)

### Advertise

```rust
use zudp::{Discovery, DiscoveryConfig};

#[derive(Encode, Decode, Clone)]
struct GameInfo { name: String, players: u8 }

// start advertising; handle keeps the task alive
let handle = Discovery::advertise(
    DiscoveryConfig::new("my-game", 7700)  // app name, data port
        .meta(GameInfo { name: "Alice".into(), players: 3 })
        .probe_interval(Duration::from_secs(2))
)?;

// update metadata at runtime without restarting
handle.set_meta(GameInfo { name: "Alice".into(), players: 4 });

// advertising stops when handle is dropped
drop(handle);
```

`Discovery::advertise` is synchronous (no `.await` needed).

### Scan once

```rust
let peers = Discovery::scan_once::<GameInfo>(
    DiscoveryConfig::new("my-game", 0),  // data port 0 = "I'm scanning, not hosting"
    Duration::from_millis(500),          // wait window
).await?;

for peer in peers {
    println!("{} at {} (players: {})", peer.meta.name, peer.data_addr, peer.meta.players);
    // connect to peer.data_addr via Zudp::connect
}
```

### Scan continuously

```rust
let mut stream = Discovery::scan_stream::<GameInfo>(
    DiscoveryConfig::new("my-game", 0)
        .probe_interval(Duration::from_secs(3)),
).await?;

loop {
    let peer = stream.next().await?;  // blocks until a new peer appears
    println!("new peer: {} at {}", peer.meta.name, peer.data_addr);
}
```

`ScanStream` deduplicates by `data_addr` — each peer is yielded at most once per stream instance.

### `DiscoveredPeer` fields

```rust
pub struct DiscoveredPeer<M> {
    pub from: SocketAddr,      // source address of the beacon (the peer's discovery socket)
    pub data_addr: SocketAddr, // pass this to Zudp::connect
    pub meta: M,               // decoded application metadata
}
```

### DiscoveryConfig builder

```rust
DiscoveryConfig::new(app_id, data_port)  // required: app name (or AppId) + data port
    .meta(value)                          // metadata to broadcast; changes generic type M
    .discovery_port(7701)                 // override discovery UDP port (default: 7701)
    .probe_interval(Duration::from_secs(5))
```

Tuple `From` impls for quick construction:

```rust
Discovery::scan_once::<GameInfo>(("my-game", 0), timeout).await?
Discovery::advertise(("my-game", 7700, GameInfo { … }))?
```

---

## Error handling

`zudp::Error` is a non-exhaustive enum.  Match the variants you care about; use `_` for the rest.

```rust
use zudp::Error;

match socket.recv().await {
    Ok((msg, from)) => { /* … */ }
    Err(Error::ChannelClosed) => { /* engine stopped — socket is dead */ }
    Err(Error::Io(e)) => { /* OS I/O error */ }
    Err(e) => { eprintln!("recv error: {e}"); }
}
```

Key variants:

| Variant | When |
|---|---|
| `Error::Io(io::Error)` | OS refused bind, send, or recv |
| `Error::ChannelClosed` | The background engine task exited |
| `Error::Decode(_)` | Received bytes could not be decoded as `M` |
| `Error::MessageTooLarge { got, max }` | Message would need more than 65 535 fragments |
| `Error::FrameTruncated { frame, field }` | Incoming UDP packet was malformed |

---

## Local address

Both socket types expose `local_addr()`:

```rust
let socket = Zudp::default().port(0).listen::<Msg>().await?;
println!("bound on {}", socket.local_addr()?);
// useful when port was 0 — OS assigned a port; you need it to tell peers where to connect
```

---

## Common patterns

### Game server (authoritative)

```rust
let mut server = Zudp::default().port(7700).listen::<ClientMsg>().await?;
loop {
    let (msg, from) = server.recv().await?;
    let response = process(msg);
    server.send(response, from).await?;
}
```

### P2P with discovery

```rust
// both peers advertise and scan simultaneously
let _advert = Discovery::advertise(("mygame", local_data_port, my_info))?;
let mut stream = Discovery::scan_stream::<MyInfo>(("mygame", 0)).await?;
let peer = stream.next().await?;
let mut conn = Zudp::default().port(0).connect::<Msg>(peer.data_addr).await?;
```

### High-frequency position updates + reliable events

```rust
// unreliable for position (tolerate loss)
socket.send_unreliable(Msg::Position { x, y }, peer).await?;

// reliable for important events (guaranteed delivery)
socket.send(Msg::PlayerJoined { id }, peer).await?;
```
