# zudp

Minimal UDP protocol for real-time applications. NACK-based reliability, automatic fragmentation, relay/NAT traversal, RTT-based congestion control, optional end-to-end encryption, and optional LAN discovery.

## Quick start

```rust
use bitcode::{Encode, Decode};
use zudp::Zudp;

#[derive(Encode, Decode)]
enum Msg { Ping, Pong }

// listener — accepts any peer
let mut socket = Zudp::default().port(5000).listen::<Msg>().await?;
let pkt = socket.recv().await?;   // pkt.msg, pkt.from, pkt.stream
socket.send(Msg::Pong, pkt.from).await?;

// single-peer connection
let mut conn = Zudp::default().port(0).connect::<Msg>(peer).await?;
conn.send(Msg::Ping).await?;
let pkt = conn.recv().await?;     // pkt.msg, pkt.from (== peer), pkt.stream
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
    .pin_remote_key(server_keypair.public_key().clone()) // reject peers with wrong key
    .max_peers(1024)                         // LRU-evict oldest peer at cap
    .rate_limit(1000.0)                      // per-IP token-bucket PPS (0.0 = off)
    .relay_allowlist(vec![trusted_ip])       // restrict who may use this node as relay
    .max_relay_entries(256)                  // relay routing table cap
    .listen::<Msg>()                         // ZudpSocket<Msg>  — multi-peer
    .connect::<Msg>(peer)                    // ZudpConn<Msg>    — single-peer
```

## Multiple streams

Each reliable connection supports up to 65 535 independent ordered streams. Streams have separate sequence spaces, so packet loss on one stream never delays delivery on another (no head-of-line blocking).

```rust
// server
let pkt = socket.recv().await?;
socket.send_stream(reply, pkt.from, pkt.stream).await?;  // reply on same stream

// client: send to specific stream
conn.send_stream(Msg::Command(cmd), 0).await?;           // stream 0 — commands
conn.send_stream(Msg::Snapshot(data), 1).await?;         // stream 1 — snapshots
let pkt = conn.recv().await?;                            // pkt.stream tells which
```

`DEFAULT_STREAM = 0`. `send()` / `recv()` target stream 0 — existing code continues to work unchanged.

## Congestion control

Built-in BBR-lite per peer — RTT-based, not loss-based, so it detects queue build-up before drops occur.

- RTT measured from Ping/Pong echo timestamps; EWMA smoothed.
- Pacing rate adjusts: backs off when `srtt > 1.25 × min_rtt`, probes up otherwise.
- 65 KB burst allowance covers typical game state syncs without any delay.
- NACK retransmits are paced (up to 10 ms inter-send); new sends are never delayed.

```rust
// query congestion state on a conn
if let Some(rtt) = conn.srtt() {
    println!("RTT {rtt:?}");
}
if let Some(factor) = conn.congestion_factor() {
    if factor > 1.25 { /* consider reducing send rate */ }
}

// same on a multi-peer socket
if let Some(rtt) = socket.peer_srtt(peer_addr) { /* … */ }
```

## Observability

`ZudpSocket` and `ZudpConn` expose live stats with no lock contention (all atomics):

```rust
// Per-peer snapshot — None if the peer is not in the table.
if let Some(stats) = socket.peer_stats(peer_addr) {
    println!("RTT {:?}  pacing {} B/s", stats.srtt, stats.pacing_rate_bps);
    println!("rx {} B  tx {} B  retransmits {}", stats.rx_bytes, stats.tx_bytes, stats.retransmit_count);
}

// Engine-wide drop counters (monotonically increasing since socket creation).
let e = socket.engine_stats();
println!("rate-limited {} / peer-cap {} / relay-blocked {} / relay-cap {}",
    e.dropped_rate_limited, e.dropped_peer_cap, e.dropped_relay_blocked, e.dropped_relay_cap);
```

`dropped_peer_cap` increments each time the peer table is full and an LRU eviction occurs.
`dropped_rate_limited`, `dropped_relay_blocked`, `dropped_relay_cap` are self-explanatory.

## Hardening

All limits are enforced on the receive path, require no peer cooperation, and are configurable at build time:

```rust
// Per-IP rate limit — token bucket, default 1000 pps / 200 burst.
// Set to 0.0 to disable.
Zudp::default().rate_limit(500.0) …

// Peer table cap — evicts least-recently-seen peer when full.
Zudp::default().max_peers(512) …

// Relay allowlist — empty means open relay (default); non-empty restricts relay use.
Zudp::default()
    .relay_allowlist(vec!["10.0.0.0".parse()?, "10.0.0.1".parse()?])
    .max_relay_entries(64) …

// Update relay policy at runtime without rebinding the socket.
socket.set_relay_policy(new_allowlist, new_max_entries);
```

Fragment bombs are also capped: `frag_total > 1 024` and more than 64 concurrent assemblies per (peer, stream) are rejected at the engine level before any allocation occurs.

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

// Client — connect; Noise XX handshake completes before connect() returns.
let mut conn = Zudp::default()
    .port(0)
    .security(Keypair::generate())
    .connect::<Msg>(server_addr)
    .await?;

// Send/recv API is identical — encryption is transparent.
conn.send(Msg::Ping).await?;
let pkt = conn.recv().await?;
```

All three Noise handshake messages complete inside `connect()` — the channel is encrypted and ready before the first `send()`. Once the channel is established, **all** frame types are wrapped in `Secure` except Datagram (unreliable fire-and-forget) and routing/discovery frames (Relay, Probe, Beacon, Handshake). This includes Ping/Pong keepalives (which carry session IDs) and Nack frames (which expose sequence timing) — encrypting them prevents replay-based migration attacks and traffic analysis. NACK retransmits re-encrypt the original plaintext with a fresh nonce; the old ciphertext is never re-sent.

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

## Relay

The relay node is a plain `ZudpSocket` — no special configuration needed.
The relay is **stateful and bidirectional**: when a client sends through it, the relay records a routing table entry so server replies are automatically forwarded back to the client.

```rust
// client — wrap every packet via relay
let conn = Zudp::default()
    .relay("relay.example.com:7800".parse()?)
    .connect::<Msg>(server_addr)
    .await?;

// relay node — just a listening socket; routing table maintained automatically by the engine
let _relay = Zudp::default().port(7800).listen::<()>().await?;
// (relay doesn't need to call recv() — the engine handles all forwarding internally)
```

Server replies flow back through the relay to the client without any extra configuration.
When the client migrates to a new network, the relay table is updated automatically on the next outbound packet.

## Network migration

When the local interface changes (WiFi → mobile, DHCP renew, VPN toggle), ZUDP restores the session automatically:

1. Engine detects the socket error and rebinds to a new interface.
2. Engine sends keepalive Pings carrying a per-peer session ID to all known peers.
3. Each peer recognises the session ID and migrates the client's address in its peer table.
4. Traffic resumes — no reconnect, no application-level handling required.

Works for client→server topologies where the server has a public IP.  P2P connections where both peers are behind NAT require a relay.

## License

MIT
