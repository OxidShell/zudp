# Using the `zudp` Rust crate

This file covers how to use `zudp` as a dependency — sending and receiving messages,
configuring the socket, working with the codec, relay, and discovery.  It is not about
implementing the wire protocol; that is in `SKILL.md` and `PROTOCOL.md`.

---

## Dependency

```toml
[dependencies]
zudp = "0.3"                                                        # rkyv codec (default)
zudp = { version = "0.3", features = ["security"] }                 # + Noise XX encryption
zudp = { version = "0.3", features = ["discovery"] }                # + LAN peer discovery
zudp = { version = "0.3", features = ["security", "discovery"] }    # both
zudp = { version = "0.3", default-features = false, features = ["serde"] }   # postcard codec
zudp = { version = "0.3", default-features = false, features = ["bitcode"] } # bitcode codec
```

---

## Message types

Every message type must implement `zudp::Encode` + `zudp::Decode`.
With the default `rkyv` feature, derive the three rkyv traits:

```rust
use zudp::rkyv::{Archive, Deserialize, Serialize};

#[derive(Archive, Serialize, Deserialize)]
enum Msg {
    Ping,
    Pong,
    Data(Vec<u8>),
    Move { x: f32, y: f32 },
}
```

With `default-features = false, features = ["bitcode"]`:

```rust
use zudp::bitcode::{Encode, Decode};

#[derive(Encode, Decode)]
enum Msg { /* … */ }
```

With `default-features = false, features = ["serde"]`:

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

// recv returns a Packet<M> with named fields
let pkt = socket.recv().await?;
// pkt.msg   — the decoded message
// pkt.from  — sender address
// pkt.stream — stream ID (0 = DEFAULT_STREAM)

// destructure if preferred
let zudp::Packet { msg, from, stream } = socket.recv().await?;

// send reliable (NACK-tracked) message to a specific peer on stream 0
socket.send(Msg::Pong, from).await?;

// send on a specific stream (independent sequence space, no HoL blocking)
socket.send_stream(Msg::Data(bytes), from, 1).await?;

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
let pkt = conn.recv().await?;   // pkt.msg, pkt.from, pkt.stream

// send on a named stream
conn.send_stream(Msg::Ping, 1).await?;
```

When the `security` feature is enabled, `connect()` blocks until the full Noise XX
handshake (3 messages) completes.  The channel is encrypted and ready before the first
`send()` can be called.

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
    .security(Keypair::generate())           // enable Noise XX encryption (feature = "security")
    .listen::<Msg>()                         // → ZudpSocket<M>
    // or
    .connect::<Msg>(peer_addr)              // → ZudpConn<M>
```

All builder methods take `self` and return `Self`, so they chain freely.
`listen` and `connect` are async and return `Result<_, zudp::Error>`.

---

## Multiple streams

Each connection supports up to 65 535 independent reliable streams (IDs 0–65 534). Streams have separate sequence spaces, so loss on one stream never delays delivery on another.

```rust
// send on named streams
socket.send_stream(Msg::Command(cmd), peer, 0).await?;    // stream 0 — commands
socket.send_stream(Msg::Snapshot(data), peer, 1).await?;  // stream 1 — snapshots

// recv returns Packet<M>; pkt.stream is the stream_id
let pkt = socket.recv().await?;
socket.send_stream(reply, pkt.from, pkt.stream).await?;

// ZudpConn
conn.send_stream(msg, 1).await?;
let pkt = conn.recv().await?;   // pkt.stream tells which stream delivered
```

`DEFAULT_STREAM = 0`. `send()` / `recv()` use stream 0 — all existing code continues to work.

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

The relay is **stateful and bidirectional** — no special configuration needed.  When the client sends through it, the relay records a routing table entry and automatically forwards server replies back to the client.

```rust
// client — wraps every packet via relay
let conn = Zudp::default()
    .port(0)
    .relay("relay.example.com:7800".parse()?)
    .connect::<Msg>(server_addr)
    .await?;

// relay node — plain ZudpSocket; bidirectional routing table maintained by the engine
let _relay = Zudp::default().port(7800).listen::<()>().await?;
// relay does NOT need to call recv() — engine handles all forwarding internally
```

- Server sees `from == relay_addr`, not the real client address.
- NACK retransmission is end-to-end (client retransmits to relay; relay re-forwards).
- When client migrates to a new IP, the relay table updates automatically on the next outbound packet.
- Encrypted traffic (`security` feature) flows through relay transparently — raw bytes are forwarded before decoding.

## Network migration

Sessions persist across network changes automatically.  No application-level code required.

```rust
// client — after network change (WiFi → mobile, DHCP renew, etc.) the connection continues
let mut conn = Zudp::default()
    .port(0)
    .connect::<Msg>(server_addr)
    .await?;

// send and recv work uninterrupted even after the local IP changes
conn.send(Msg::Ping).await?;
let pkt = conn.recv().await?;

// conn.peer() returns the server's current address (auto-updated if server migrates too)
println!("peer is now {}", conn.peer());
```

**How it works**: each peer has a random session ID sent in every Ping/Pong.  On network change, the engine rebinds the socket and sends Pings to all known peers.  Each peer recognises the session ID from the new address and updates its routing table.

**Works for:**
- Client (behind any NAT) → Server (public IP)
- Client configured with `.relay(...)` — relay table updates automatically

**Does not work for:** P2P where both peers are behind NAT without a relay (NAT mappings expire on network change).

---

## Congestion control

Built-in per peer; no configuration required.  RTT samples are collected automatically from
Ping/Pong exchanges.

```rust
// ZudpConn — query congestion state
if let Some(rtt) = conn.srtt() {
    println!("RTT: {rtt:?}");
}
if let Some(factor) = conn.congestion_factor() {
    if factor > 1.25 {
        // srtt has grown > 25% above min_rtt → queue building
        // consider reducing voluntary send rate or switching to unreliable
    }
}

// ZudpSocket — per-peer query
if let Some(rtt) = socket.peer_srtt(peer_addr) { /* … */ }
if let Some(f)   = socket.peer_congestion_factor(peer_addr) { /* … */ }
```

- `srtt()` / `peer_srtt()` — smoothed RTT as `Option<Duration>` (`None` until first Pong).
- `congestion_factor()` — `srtt / min_rtt`; below 1.25 = path clear; above 1.25 = bloat.
- NACK retransmits are automatically paced (up to 10 ms inter-send) when the token bucket is overdrawn; new sends are never delayed.
- The 65 KB burst allowance covers typical game state syncs without any pacing delay.

---

## Security (`features = ["security"]`)

End-to-end encryption using the Noise XX protocol pattern (`Noise_XX_25519_ChaChaPoly_BLAKE2s`).
The same cryptography as WireGuard: X25519 key exchange, ChaCha20-Poly1305 AEAD, BLAKE2s hash.
Mutual authentication — both endpoints verify each other.

```rust
use zudp::{Keypair, Zudp};

// Generate and persist a keypair.
let server_kp = Keypair::generate();
let client_kp = Keypair::generate();

// Server — .security() enables encryption for all incoming connections.
let mut socket = Zudp::default()
    .port(7700)
    .security(server_kp)
    .listen::<Msg>()
    .await?;

// Client — handshake (3 Noise messages) happens automatically inside connect().
let mut conn = Zudp::default()
    .port(0)
    .security(client_kp)
    .connect::<Msg>(server_addr)
    .await?;

// send/recv API is identical — encryption is transparent.
conn.send(Msg::Ping).await?;
let reply = conn.recv().await?;
```

Key points:
- Call `Keypair::generate()` once per node, persist the keypair (e.g. to disk), and reuse it.
- The handshake is driven automatically by the engine; no user code is required.
- Reliable frames (Stream, Fragment) are encrypted. Keepalives and NACKs are not.
- NACK retransmits re-encrypt with a fresh nonce — nonce reuse is never possible.
- The `Error::Security(snow::Error)` variant is added when this feature is enabled.

---

## Discovery (`features = ["discovery"]`)

### Advertise

```rust
use zudp::{Discovery, DiscoveryConfig};

#[derive(Archive, Serialize, Deserialize, Clone)]
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
    Ok(pkt) => { /* pkt.msg, pkt.from, pkt.stream */ }
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
    let pkt = server.recv().await?;
    let response = process(pkt.msg);
    server.send(response, pkt.from).await?;
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
