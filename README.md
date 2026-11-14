# zudp

Minimal UDP protocol for real-time applications. NACK-based reliability, automatic fragmentation, RTT-based congestion control, optional end-to-end encryption, relayed sessions with hole punching for peers behind NAT, and optional LAN discovery.

## Quick start

No message codec is on by default. Pick one with a feature (`wincode`, `serde`, `bitcode` or `rkyv`), send `zudp::RawBytes`, or implement `Encode`/`Decode` yourself:

```toml
zudp = { version = "0.4", features = ["wincode"] }
```

```rust
use zudp::wincode::{SchemaRead, SchemaWrite};
use zudp::Zudp;

#[derive(SchemaWrite, SchemaRead)]
#[wincode(crate = "zudp::wincode")]
enum Msg { Ping, Pong }

// listener — accepts any peer
let mut socket = Zudp::default().port(5000).listen::<Msg>().await?;
let pkt = socket.recv().await?;   // pkt.msg, pkt.from (a PeerAddr), pkt.stream
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
    .security(Keypair::generate())           // enable Noise XX encryption
    .pin_remote_key(*server_keypair.public_key()) // only accept pinned keys (repeatable)
    .punching(true)                          // allow punching relayed sessions (default on)
    .accept_relayed_from(relay_addr)         // accept inbound relayed sessions from this relay
    .relay_node(RelayLimits::default(), policy) // act as a relay node (`relay` feature)
    .max_peers(1024)                         // LRU-evict oldest peer at cap
    .rate_limit(1000.0)                      // per-IP token-bucket PPS (0.0 = off)
    .listen::<Msg>()                         // ZudpSocket<Msg>  — multi-peer
    .connect::<Msg>(peer)                    // ZudpConn<Msg>    — single-peer
    .connect_via::<Msg>(relay, peer_key)     // ZudpConn<Msg>    — single peer through a relay
```

## Addressing peers

Every API that names a peer — `send*`, `Packet::from`, `peer_stats`, `remove_peer`, `PeerEvent` — uses `PeerAddr`:

```rust
pub enum PeerAddr {
    Direct(SocketAddr),                          // reached at a UDP address
    Relayed { relay: SocketAddr, key: [u8; 32] }, // reached by static key through a relay
}
```

Direct peers keep the `SocketAddr` API: methods take `impl Into<PeerAddr>`, so `socket.send(msg, addr)` with a `SocketAddr` still works, and a `PeerAddr` compares equal to the `SocketAddr` of a direct peer (`pkt.from == addr`). A direct handle follows the peer when it migrates (`PeerEvent::Migrated`). A relayed handle is stable for the whole session, whichever path the traffic currently takes (`socket.peer_path(peer)`).

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
println!("rate-limited {} / peer-cap {} / forged {}",
    e.dropped_rate_limited, e.dropped_peer_cap, e.dropped_forged);
```

`dropped_peer_cap` increments each time the peer table is full and an LRU eviction occurs.
`dropped_forged` counts relayed frames whose relay-claimed sender did not match the session they authenticate into.
`dropped_relay_unaccepted` counts relayed frames from a relay that was not accepted (see below).
A relay node also reports `relay_forwarded_packets` / `relay_forwarded_bytes`, `relay_dropped_rate_limited`, `relay_dropped_oversize`, `relay_unreachable` (of which `relay_denied`), `relay_sessions_evicted` and `relay_introductions`.

## Hardening

All limits are enforced on the receive path, require no peer cooperation, and are configurable at build time:

```rust
// Per-IP rate limit — token bucket, default 1000 pps / 200 burst.
// Set to 0.0 to disable.
Zudp::default().rate_limit(500.0) …

// Peer table cap — evicts least-recently-seen peer when full.
Zudp::default().max_peers(512) …

```

Relay nodes add their own limits; see [Relay node](#relay-node).

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

The Noise handshake and one authenticated round trip complete inside `connect()` — both ends hold the session before the first `send()`. A multi-peer socket opens sessions with `socket.connect(addr)` the same way. Lost handshake datagrams are retransmitted; `connect()` fails with `Error::HandshakeTimeout` after `handshake_timeout` (default 5 s) and with `Error::KeyMismatch` when a pinned key does not match. Once the channel is established, **all** data — including unreliable datagrams — is wrapped in `Secure`; only handshake, discovery and MTU-probe frames travel in plaintext. A socket with a keypair drops plaintext data and returns `Error::NoSession` instead of sending in the clear. This includes Ping/Pong keepalives (which carry session IDs) and Nack frames (which expose sequence timing) — encrypting them prevents replay-based migration attacks and traffic analysis. NACK retransmits re-encrypt the original plaintext with a fresh nonce; the old ciphertext is never re-sent. Every secure session keeps a 4 096-nonce anti-replay window: a replayed datagram is dropped, whatever it carries.

`pin_remote_key` may be called several times; any pinned key is accepted. Pins apply to every handshake on the socket, direct and relayed alike — a relay client pins the relay node and the peers it reaches through it.

## LAN discovery

Requires `features = ["discovery"]`.

```rust
use zudp::{Discovery, DiscoveryConfig};

#[derive(Archive, Serialize, Deserialize, Clone)]
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

`DiscoveryConfig` builder: `.discovery_port(u16)`, `.probe_interval(Duration)`, `.peer_ttl(Duration)`, `.probe_loopback(bool)`, `.probe_interfaces(bool)`, `.probe_targets(addrs)`.
Scans probe `255.255.255.255`, `127.0.0.1` and each interface's directed broadcast, plus any extra targets: same-host apps are found even where the OS blocks LAN broadcast (macOS Local Network privacy), and hosts on networks that drop broadcast can be asked by unicast.
`ScanStream::next_event()` yields `DiscoveryEvent::{Found, Updated, Lost, ProbeFailed}`: a peer that restarts (new `instance`) or changes its metadata is reported again, one that stops answering for `peer_ttl` is reported lost, and a probe target that cannot be sent to is reported once without ending the scan.
`AppId` is derived from the app name string via a stable FNV-1a hash.

## Relay and NAT traversal

Requires `features = ["security"]` for clients and `features = ["relay"]` for the relay node. Two peers behind NAT, both connected to a public relay node, talk through it with **end-to-end** Noise and move to a direct path when NAT allows.

```rust
// relay node — public, anyone may run one; the policy is mandatory
let relay = Zudp::default()
    .port(7800)
    .security(relay_keypair)
    .relay_node(RelayLimits::default(), |from: &[u8; 32], to: &[u8; 32]| allowed(from, to))
    .listen::<Msg>()
    .await?;

// bob — connects to the relay and accepts the sessions it delivers
let mut bob = Zudp::default()
    .security(bob_keypair)
    .accept_relayed_from(relay_addr)
    .listen::<Msg>()
    .await?;
bob.connect(relay_addr).await?;
let pkt = bob.recv().await?;              // pkt.from == PeerAddr::Relayed { relay, key: alice }
bob.send(reply, pkt.from).await?;
bob.punch(pkt.from)?;                     // bob trusts alice: allow a direct path

// alice — reaches bob by his static key
let alice = Zudp::default().security(alice_keypair).listen::<Msg>().await?;
alice.connect(relay_addr).await?;
let bob_handle = alice.connect_via(relay_addr, bob_public_key).await?;
alice.send(msg, bob_handle).await?;
alice.punch(bob_handle)?;
```

`Zudp::connect_via::<M>(relay, key)` does the same for a single-peer `ZudpConn`. See `examples/relay.rs`.

**How it works.** Alice's handshake with Bob and every frame of their session travel as opaque bytes inside Alice's and Bob's own secure sessions with the relay (`Via { to }` from Alice, `ViaFrom { from }` to Bob). The relay picks the session by static key; it cannot decrypt what it forwards. Identity comes from the Alice↔Bob handshake, not from the relay: a handshake whose authenticated key differs from the key the relay claims is aborted, and a frame whose session belongs to another peer than the one claimed is dropped (`dropped_forged`). Pinned keys apply as for direct peers. Relayed sessions get reliability, NACKs, fragmentation (at an MTU 66 bytes smaller, the relay overhead, capped so relayed frames fit the relays' default 1 500-byte `max_inner`), congestion control, keepalives, timeouts and peer events.

**Which relays may reach us.** Any direct peer could pretend to be a relay, so relayed frames are only accepted from relays we chose: a relay may always carry sessions we opened through it with `connect_via`, and may open new sessions toward us only when accepted with `accept_relayed_from(relay)` (builder or socket method). Everything else is dropped (`dropped_relay_unaccepted`). Sessions through one relay may fill at most half of `max_peers` (the least recently seen is evicted first), relayed handshake initiations are limited to 20 per second per relay, and each relay has its own budget of half-open handshakes (a quarter of `max_peers`), so a hostile relay cannot crowd out direct handshakes.

**Failing fast.** When the target is not connected to the relay, or the relay's policy refuses, the relay answers `Unreachable` at once: `connect_via` fails with `Error::Unreachable` and an established relayed session ends with `PeerEvent::Disconnected { reason: DisconnectReason::Unreachable }`. Denied and offline look exactly the same; but whoever the policy *lets* reach a client learns whether it is online, so choose the policy accordingly — there is no default, and a relay without a policy relays nothing.

**Hole punching** (allowed by default; `.punching(false)` disables it completely). Punching exchanges public addresses, so it only starts for peers the application trusts: automatically for pinned keys, otherwise once the application calls `socket.punch(peer)` (the approval then covers later sessions with that key). Both ends must approve — the relay only introduces two clients that both asked for each other, and tells each the public address it observes for the other. An introduction is only accepted within 10 s of our own request, one punch campaign runs per peer at a time, and addresses that are unspecified, multicast or broadcast are refused, as are private, link-local and loopback addresses unless the relay itself is on such a network. Both ends then send authenticated keepalives straight there. A direct path is only used after it is validated: an authenticated frame from a new address triggers an encrypted challenge sent *to* that address, and traffic moves (`PeerEvent::PathChanged { addr, path: Path::Direct(..) }`, same session and handle) only when the authenticated answer comes back *from* it — a frame replayed from a spoofed source cannot move the session, and a path that works in one direction only is never used. Once punched, everything of the session (NACKs and retransmits included) goes direct, so it survives the relay going away; a direct and a relayed session with the same peer can coexist. If the direct path goes silent for 3/5 of the peer timeout, traffic falls back to the relay (`PathChanged { path: Path::Relayed(relay) }`) without losing the session; while on the relay, approved peers retry the introduction every 30 s. Where NAT does not allow punching (symmetric NAT on both sides), the session stays on the relay, without errors.

### Relay node

A relay node is a secure socket with `.relay_node(limits, policy)`. It only ever sends to static keys that hold a session with it — never to an address a client names — so it cannot be used to reflect traffic. Budgets apply per client key, per source network (an IPv4 address or an IPv6 /64) and for the whole node; a frame has to fit all three. Sessions are capped per source network and per IPv6 /48, and a full session table makes room in its heaviest prefix: a newcomer whose prefix is at least as heavy as any other displaces its own prefix's least recently seen session, otherwise the least recently seen session among the prefixes tied for the most sessions goes. A flood from one allocation therefore displaces its own sessions first; a client elsewhere is only displaced once its prefix holds as many sessions as the heaviest one. IPv4 is accounted per address: users behind one carrier-grade NAT share one budget (the alternative, per /24, would lump even more strangers together). Handshakes are budgeted per network (/64), so rotating addresses inside an allocation buys nothing. A client's pending introductions are released when its session ends.

| Limit (`RelayLimits`) | Default | When exceeded |
|---|---|---|
| `packet_rate` / `byte_rate` per client key | 2 000 frames/s (burst 400), 4 MB/s (burst 1 MB) | dropped, `relay_dropped_rate_limited` |
| `ip_packet_rate` / `ip_byte_rate` per source network | 4 000 frames/s (burst 800), 8 MB/s (burst 2 MB) | dropped, `relay_dropped_rate_limited` |
| `total_packet_rate` / `total_byte_rate` whole node | 50 000 frames/s (burst 10 000), 50 MB/s (burst 10 MB) | dropped, `relay_dropped_rate_limited` |
| `max_inner(bytes)` | 1 500 | dropped, `relay_dropped_oversize` |
| `max_sessions_per_ip(per_network, per_prefix)` | 64 per /64 (or IPv4 address), 256 per IPv6 /48 | that scope's least recently seen session evicted, `relay_sessions_evicted` |
| full session table (`max_peers`) | 1 024 | the heaviest prefix's least recently seen session evicted, `relay_sessions_evicted` |
| pending introductions | 16 per client, 64 per network, 256 per IPv6 /48 (own oldest evicted), 4 096 total (heaviest prefix makes room) | — |
| `max_peers` (socket-wide) | 1 024 | LRU eviction of clients |
| handshakes per source network (socket-wide) | 20/s | dropped, `dropped_rate_limited` |

The policy (`RelayPolicy`, or any `Fn(&[u8; 32], &[u8; 32]) -> bool`) is consulted for every relayed frame and introduction and can be replaced at runtime with `socket.set_relay_policy(Some(Arc::new(policy)))`; `None` relays nothing.

### Threat model

The relay **sees**: the static keys of its own clients and their public addresses; who talks to whom, when, how often and how much (frame sizes and timing); who asked to be introduced to whom.

The relay **cannot**: read anything (end-to-end ChaCha20-Poly1305 under keys it never holds); forge a frame or a sender (the end-to-end handshake authenticates the peer, the claimed sender is checked against it); replay frames (anti-replay window); impersonate a peer (Noise XX, plus pins); redirect a session to another address (a new direct path has to answer an encrypted challenge at that address); open sessions toward clients that did not accept it; learn a client's address for a client that did not approve punching to that peer.

The relay **can**: drop, delay or reorder traffic (a denial of service any on-path router has), and end a relayed session early — an `Unreachable` ends a session that has no direct path, and a forged `SessionUnknown` triggers a re-handshake — which is no more than dropping its traffic would do; lie in an introduction, which makes the clients send a few authenticated probes and one challenge to a plausible wrong address and then stay on the relay. A relayed session is bound to the relay it was opened through (and to that relay's address as the client sees it).

## Network migration

When a peer's address changes (Wi-Fi → mobile, DHCP renew, VPN toggle, NAT rebinding), the session follows it: secure sessions by the session index in every encrypted frame, plain sessions by the engine instance id in keepalive Pings. The other side emits `PeerEvent::Migrated` — no reconnect, no application-level handling required.

## Reconnects and peer lifecycle

```rust
let mut events = socket.events();
while let Ok(event) = events.recv().await {
    match event {
        zudp::PeerEvent::Connected { addr, key } => { /* new session */ }
        zudp::PeerEvent::Reset { addr, key } => { /* remote restarted: resend state */ }
        zudp::PeerEvent::Migrated { from, to } => { /* same session, new address */ }
        zudp::PeerEvent::PathChanged { addr, path } => { /* relayed session punched / fell back */ }
        zudp::PeerEvent::Disconnected { addr, reason } => { /* timed out / removed */ }
        _ => {}
    }
}
```

- A peer silent for `peer_timeout` (default 3 × keepalive) is dropped; `ZudpConn::recv()` then fails with `Error::PeerTimeout`.
- A remote that restarts on the same address gets a fresh session (`Reset`) instead of having its frames discarded as stale.
- If a secure server restarts, a connected client re-handshakes automatically and emits `Reset`.
- `remove_peer(addr)` drops a peer immediately.

Direct connections work for client→server topologies where the server has a public IP. Peers that are both behind NAT connect through a relay node (see [Relay and NAT traversal](#relay-and-nat-traversal)).

## Wire version 3

`WIRE_VERSION` is 3; peers on another version ignore each other's handshakes. Changes from 2:

- The plaintext, socket-wide `Relay` frame (and `relay()`, `relay_allowlist`, `max_relay_entries`, `set_relay_policy(allowlist, cap)`) is gone.
- Relayed sessions use `Via` (`0x06`), `ViaFrom` (`0x0E`) and `Unreachable` (`0x0F`); hole punching uses `IntroRequest` (`0x10`) and `Intro` (`0x11`), and direct paths are validated with `PathChallenge` (`0x12`) / `PathResponse` (`0x13`). All of them only ever travel inside a `Secure` frame; a plaintext one is dropped.
- Secure frames are checked against an anti-replay window.

API changes that come with it: peers are addressed by `PeerAddr` (see [Addressing peers](#addressing-peers)); `Packet::from`, `PeerEvent` fields and the peer in `Error::{NoSession, PeerTimeout, HandshakeTimeout}` are `PeerAddr`; `ZudpConn::peer()` returns `PeerAddr`. Code that kept peers in a `HashMap<SocketAddr, _>` switches the key type to `PeerAddr`.

## License

MIT
