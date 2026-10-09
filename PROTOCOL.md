# ZUDP Protocol Specification

Version 0.2 — wire format is not yet stable.

---

## Overview

ZUDP is a UDP-based protocol that adds optional reliability, ordered delivery, transparent fragmentation, keepalives, relay/NAT traversal, and LAN peer discovery on top of raw UDP datagrams.

Every packet is a single UDP datagram. The protocol has no handshake, no connection state at the network level, and no acknowledgement of received packets — only negative acknowledgement (NACK) of missing ones.

---

## Wire format

### Framing

ZUDP frames are encoded **tail-first**: the payload (if any) is written first, fixed-size fields follow, and the **frame type byte is always the very last byte**. This makes frame dispatch O(1) — the receiver reads the last byte of the UDP datagram to determine which frame type it has received before touching any other byte.

```
[variable-length prefix] [fixed-size suffix] [type: u8]
```

All multi-byte integers are **big-endian**.

### Frame types

| Tag | Name | Total overhead |
|-----|------|---------------|
| `0x00` | Datagram | 1 B |
| `0x01` | Stream | 11 B |
| `0x02` | Nack | 3 B + N×8 B |
| `0x03` | Ping | 17 B |
| `0x04` | Pong | 17 B |
| `0x05` | Fragment | 19 B |
| `0x06` | Relay | 8 B (IPv4) / 20 B (IPv6) |
| `0x07` | Probe | 11 B |
| `0x08` | Beacon | 13 B + meta |
| `0x09` | Handshake | variable (32–96 B) |
| `0x0A` | Secure | 9 B + AEAD tag (16 B) |
| `0x0B` | MtuProbe | 3 B + padding |
| `0x0C` | MtuAck | 3 B |

---

## Frame definitions

### Datagram — `0x00`

Unreliable, unordered delivery. No sequence number; no retransmission.

```
[payload bytes] [0x00]
```

The unreliable fast path avoids copying the payload: when no relay is configured the sender uses scatter-gather I/O to write the payload and the 1-byte type tag in a single syscall.

### Stream — `0x01`

Reliable, in-order delivery on a specific stream. Each stream has an independent sequence space, so loss on one stream never delays delivery on another.

```
[payload bytes] [seq: u64] [stream_id: u16] [0x01]
```

- `stream_id`: identifies which logical stream this frame belongs to (`0` = default stream). Values 0–65 534 are available.
- `seq` starts at 1 per (peer, stream) pair (0 is reserved/unused).
- Sequence numbers are per-**sender** and per-**stream**; each side of each stream maintains its own counter independently.
- The receiver buffers out-of-order arrivals per stream and delivers them in order within each stream.
- Missing sequence numbers trigger a Nack for that stream (see below).

### Nack — `0x02`

Negative acknowledgement. Requests retransmission of one or more sequence numbers **on a specific stream**.

```
[seq_0: u64] [seq_1: u64] ... [seq_N: u64] [stream_id: u16] [0x02]
```

- `stream_id`: identifies which stream's sequence space the listed numbers belong to.
- The `seq` body must be a multiple of 8 bytes; each 8-byte group is one `u64` sequence number.
- Maximum sequences per Nack: 128 (`MAX_NACK_SEQS`).
- Nacks are sent immediately when a gap is detected in the received sequence space for a stream.
- The sender retransmits the buffered encoded frame for each requested sequence number. Frames older than `sent_prune_age` (default 10 s) have been pruned and cannot be retransmitted.

### Ping — `0x03`

Keepalive probe.  `echo` is the sender's current Unix timestamp in **microseconds**.  `session_id` is the **sender's own** randomly-generated session identifier, sent so the receiver can recognise this node if its network address changes between Pings.

```
[echo: u64] [session_id: u64] [0x03]
```

Sent when no outbound frame has been sent to a peer for `keepalive_interval` (default 5 s).  The keepalive tick runs at `keepalive_interval / 4`.

On receipt the engine stores `session_id` in its per-peer session registry.  If a Ping arrives from an **unknown address** but carries a **known `session_id`**, the peer's address is migrated transparently (see *Network Migration* below).

### Pong — `0x04`

Reply to a Ping.  Mirrors `echo` unchanged; carries the **replier's** own `session_id`.

```
[echo: u64] [session_id: u64] [0x04]
```

Receiving any frame from a peer updates `last_seen`.  Neither Ping nor Pong carry sequence numbers; they are not tracked for retransmission.

The `echo` round-trip is also used by the congestion controller: the receiver computes `rtt_us = now_us − echo` and feeds it into the per-peer RTT estimator (see *Congestion Control* below).  Using microseconds allows sub-millisecond RTT tracking on LAN paths.

### Fragment — `0x05`

One slice of a fragmented reliable message on a specific stream. Messages exceeding the configured MTU (default 1 400 B) are split into at most `u16::MAX` fragments before transmission.

```
[payload bytes] [msg_id: u32] [frag_total: u16] [frag_idx: u16] [seq: u64] [stream_id: u16] [0x05]
```

- `stream_id`: the stream on which this fragment is delivered; matches the Stream frame semantics.
- `msg_id`: monotonically increasing per-socket counter identifying the original message; wraps at `u32::MAX`.
- `frag_total`: total number of fragments for this message.
- `frag_idx`: zero-based index of this fragment within the message (0 ≤ `frag_idx` < `frag_total`).
- `seq`: each fragment occupies its own slot in the per-stream reliable sequence space, just like a Stream frame. The reassembler is triggered only after all `frag_total` sequence numbers have been delivered in order on the stream.

Reassembly uses a pre-allocated `Vec<Option<Bytes>>` of length `frag_total`. When all slots are filled the fragments are concatenated in index order. Incomplete assemblies are pruned after `sent_prune_age`.

### Relay — `0x06`

Relay forwarding request.  The sending node wraps an inner frame and addresses it to a relay node; the relay node strips the outer header and forwards `inner` verbatim to `dest`.

**IPv4 format** (addr tag `0x00`):

```
[inner bytes] [port: u16] [ip: 4 bytes] [0x00] [0x06]
```

**IPv6 format** (addr tag `0x01`):

```
[inner bytes] [port: u16] [ip: 16 bytes] [0x01] [0x06]
```

- The relay node is a plain ZUDP socket with no special configuration; it handles both client→server and server→client routing automatically.
- The destination sees `from == relay_addr`, not the originator's address.
- Reliable frames can be relayed; NACK-triggered retransmission is end-to-end (originator retransmits to relay, relay re-forwards).

#### Stateful relay (bidirectional routing)

Every ZUDP engine that receives Relay frames automatically maintains a **relay routing table**:

```
relay_table: HashMap<server_addr, client_addr>
```

**Client → Server**: when a Relay frame arrives from `client_addr` destined for `server_addr`, the engine records `relay_table[server_addr] = client_addr` and forwards `inner` to `server_addr`.

**Server → Client**: when any frame arrives from `server_addr` (which appears in `relay_table`), the relay engine forwards the **raw bytes** to `relay_table[server_addr]` without decoding.  This happens before Frame::decode, so encrypted, opaque, and partially-formed frames are forwarded transparently.

**Migration**: if the client migrates to a new address and sends a Relay frame from the new address, `relay_table[server_addr]` is updated automatically.  Future server replies are delivered to the new address with no relay reconfiguration.

The routing table is maintained per relay-engine instance and is not persisted across restarts.  One server address maps to exactly one client address (the most recent sender); for multi-client scenarios a dedicated relay with per-session allocation is required.

See **Access control and hardening → Relay abuse protection** for allowlist, table-cap, and TTL semantics.

### Handshake — `0x09` *(feature: `security`)*

One message in a Noise XX key exchange. Three messages are exchanged before the connection is encrypted.

```
[noise_message bytes] [0x09]
```

Message sizes for `Noise_XX_25519_ChaChaPoly_BLAKE2s`:

| Message | Direction | Size |
|---|---|---|
| msg1 | initiator → responder | 32 B |
| msg2 | responder → initiator | 80 B |
| msg3 | initiator → responder | 48 B |

After all three messages the handshake is complete. Both sides call `into_stateless_transport_mode()` and all subsequent data frames are wrapped in `Secure` frames.

### Secure — `0x0A` *(feature: `security`)*

A Noise-encrypted data frame. The `ciphertext` is the output of `ChaCha20-Poly1305` AEAD applied to any plain inner frame — once the channel is established, all frame types except Handshake and Relay/Probe/Beacon are wrapped in Secure.

```
[ciphertext bytes] [nonce: u64] [0x0A]
```

- `nonce`: per-peer send-side counter, strictly increasing per sender. Provided explicitly because UDP packets may arrive out of order — `StatelessTransportState` takes the nonce as a parameter rather than tracking it internally.
- The AEAD tag (16 B) is appended to the ciphertext by the cipher; it is not a separate field.
- The decrypting side validates the tag before delivering the plaintext.
- NACK retransmits re-encrypt the original plaintext with a **fresh nonce** to avoid nonce reuse. The old nonce must not be reused even if the ciphertext is identical.
- Anti-replay: a 64-bit sliding window (`highest` + bitmask) rejects nonces already seen within the last 64 slots of the highest received nonce. Nonces more than 64 behind the window are rejected unconditionally.

### MtuProbe — `0x0B`

Path-MTU discovery probe.  The frame is padded with zero bytes so the total datagram is exactly the size being probed.  The receiver responds with MtuAck (`0x0C`) — a tiny 3-byte frame that always gets through regardless of path MTU.

```
[zeros: padding bytes] [probe_id: u16] [0x0B]
```

Total wire size: `padding + 3` bytes.

- `probe_id`: 16-bit monotonically increasing counter per (socket, peer) pair; the matching MtuAck carries the same value back.
- `padding`: chosen by the binary-search probe algorithm so the datagram tests a specific MTU size.
- All non-probe fields are zero to avoid probe frames being confused with real data if misdelivered.

### MtuAck — `0x0C`

Path-MTU discovery acknowledgement.  Always exactly 3 bytes.

```
[probe_id: u16] [0x0C]
```

- `probe_id`: mirrors the value from the corresponding MtuProbe.
- Receivers always respond to MtuProbe with MtuAck, regardless of whether a Noise channel is established. (MtuAck is sent plaintext from the responder side; if a channel exists on the probing side, MtuAck is wrapped in Secure so the probe_id is not exposed.)

### Probe — `0x07` *(feature: `discovery`)*

LAN discovery broadcast. Sent to the broadcast address `255.255.255.255` on the discovery port. Any node that is advertising the same `app_id` and `proto_ver` must reply with a Beacon.

```
[app_id: u64] [proto_ver: u16] [0x07]
```

- `app_id`: FNV-1a 64-bit hash of the application name string.
- `proto_ver`: discovery protocol version (currently `1`).

### Beacon — `0x08` *(feature: `discovery`)*

LAN discovery reply. Sent as a unicast response to a Probe, back to the probe's source address.

```
[meta bytes] [data_port: u16] [proto_ver: u16] [app_id: u64] [0x08]
```

- `data_port`: the ZUDP data port the advertising node is listening on.
- `meta`: application-defined metadata encoded with the active codec (may be 0 bytes).
- `app_id` and `proto_ver`: must match the incoming Probe for the beacon to be accepted by the scanner.

---

## Reliability

### Sequence space

Each (peer, stream_id) pair has an independent send-side sequence counter, starting at 1. Stream and Fragment frames on the same stream share that stream's counter. A frame with `stream_id = 0` is the default stream; higher values are additional independent streams.

The sequence number 0 is never allocated on any stream.

### Multiple streams

Up to 65 535 independent reliable streams are supported per peer pair (stream IDs 0–65 534). Each stream has its own:

- Send-side sequence counter
- Send buffer (`BTreeMap<seq, (plain_frame, sent_at)>`)
- Receive reorder buffer + `expected_seq`
- FragAssembler for large message reassembly

**No head-of-line blocking**: packet loss on stream 1 does not affect delivery on stream 0. NACKs carry the `stream_id` so retransmission is targeted to the correct stream's send buffer.

### Send buffer

The sender keeps a `BTreeMap<seq, (plain_frame, sent_at)>` per (peer, stream). Entries are inserted on send and pruned when older than `sent_prune_age` (default 10 s). The **plain** (pre-encryption) wire frame is stored, so NACK retransmits can re-encrypt with a fresh nonce (nonce reuse is forbidden).

### Receive reorder buffer

The receiver keeps a `BTreeMap<seq, Inbound>` per (peer, stream) and an `expected_seq` counter (starts at 1) per stream:

- Frame at `seq == expected_seq`: deliver immediately, then drain consecutive buffered entries.
- Frame at `seq > expected_seq`: NACK every seq in `[expected_seq, seq)` not already buffered, buffer this frame.
- Frame at `seq < expected_seq`: duplicate — silently discard.

Nacks are sent immediately on gap detection; there is no delayed-NACK timer.

### Tail loss probe

A gap is only detected when a later frame arrives, so losing the last frames of a burst (or
the retransmits of an earlier gap) would otherwise stall the stream until the application
sends again. After each reliable send the sender arms one probe task per (peer, stream):
once the stream has been idle for a probe timeout (`2 × srtt`, clamped to 10 ms–1 s; 100 ms
before the first RTT sample), it re-sends the newest buffered frame of that stream, up to 3
times with doubling backoff. The receiver needs nothing new: a duplicate is discarded, a
missing tail frame is delivered, and a hole before it is NACKed.

### Limits

| Constant | Value |
|---|---|
| `MAX_NACK_SEQS` | 128 sequence numbers per Nack frame |
| `MAX_FRAGMENTS` | 65 535 fragments per message (`u16::MAX`) |
| `MAX_FRAG_RECV` | 1 024 — `frag_total` values above this are rejected (fragment bomb mitigation) |
| `MAX_CONCURRENT_ASSEMBLIES` | 64 — max concurrent incomplete fragment assemblies per (peer, stream) |
| `MAX_SENT_FRAMES_PER_STREAM` | 1 024 — per-stream send buffer cap; oldest frame evicted when full |
| `MAX_RETRANSMIT_TASKS` | 32 — max concurrent NACK retransmit tasks; overflow batches are dropped |
| `INBOUND_CAP` | 8 192 — bounded inbound channel slots; frames dropped when full (`try_send`) |
| Default MTU | 1 400 B |
| Default `sent_prune_age` | 10 s |
| Default `keepalive_interval` | 5 s |
| Default `max_peers` | 1 024 |
| Default `max_pps_per_ip` | 1 000 (burst: 200) |
| Default `max_relay_entries` | 256 |
| Socket send/recv buffer | 4 MiB each |
| Recv read buffer | 64 KiB (max UDP datagram) |

---

## Fragmentation

A message larger than the configured MTU is split into `ceil(len / mtu)` chunks before sending. Each chunk becomes a Fragment frame that occupies one sequence number in the reliable stream.

Chunks are zero-copy slices (`Bytes::slice`) of the original buffer — no data is copied at the split boundary.

Reassembly completes when all `frag_total` fragments for a given `msg_id` have been delivered in sequence order. The output buffer is pre-sized to `sum(chunk.len())` to avoid reallocation during concatenation.

---

## Discovery *(feature: `discovery`)*

### AppId

The application identity is a 64-bit FNV-1a hash of a human-readable name string. Two nodes using the same name string will produce the same `AppId` and discover each other. The hash is computed inline (no external dependency) and is **not** cryptographically secure.

```
FNV-1a 64-bit:
  offset_basis = 14695981039346656037
  prime        = 1099511628211
  for each byte b: hash = (hash XOR b) * prime
```

### Protocol version

The discovery protocol version (`proto_ver`) is a separate `u16` field in both Probe and Beacon frames, currently fixed at `1`. Nodes with mismatched `proto_ver` ignore each other's frames.

### Probe flow

1. Scanner binds a UDP socket on the discovery port (default `7701`) with `SO_BROADCAST` and `SO_REUSEPORT`.
2. Scanner sends a Probe to `255.255.255.255:discovery_port`.
3. Every advertising node listening on the same port receives the broadcast.
4. Each advertiser validates `app_id` and `proto_ver`; if both match, it sends a unicast Beacon back to the probe's source address.
5. The scanner receives the Beacon, decodes the meta, and records the peer (deduped by `data_addr`).
6. The scanner re-probes at `probe_interval` (default 5 s) to catch peers that join later.

### Advertise task

The advertiser runs a background task that loops on `recv_from`. For each received Probe matching its `app_id` and `proto_ver`, it encodes the current metadata snapshot (under a read lock) and sends a Beacon. The metadata can be hot-swapped at any time via `AdvertiseHandle::set_meta` — the next Beacon will carry the new value.

Dropping the `AdvertiseHandle` aborts the task immediately.

### Socket isolation

Each `Discovery::advertise`, `scan_stream`, and `scan_once` call binds its own socket. Because `SO_REUSEPORT` is set, multiple sockets on the same machine can coexist on the same discovery port without interfering.

---

## Security *(feature: `security`)*

### Noise pattern

`Noise_XX_25519_ChaChaPoly_BLAKE2s` — mutual authentication, X25519 DH, ChaCha20-Poly1305 AEAD, BLAKE2s hash. The same pattern used by WireGuard.

- XX means both endpoints exchange their static public keys and authenticate each other.
- No pre-shared knowledge required — no certificate authorities, no PSK.
- After the 3-message handshake both sides derive independent send/recv symmetric keys.

### Handshake flow

```
Initiator                              Responder
  │                                       │
  │──── Handshake(msg1) ─────────────────▶│  write_message(&[], buf)
  │                                       │  read_message(msg1)
  │                                       │  write_message(&[], buf)
  │◀─── Handshake(msg2) ─────────────────│
  │                                       │
  │  read_message(msg2)                   │
  │  write_message(&[], buf)              │
  │──── Handshake(msg3) ─────────────────▶│
  │                                       │  read_message(msg3)
  │  into_stateless_transport_mode()      │  into_stateless_transport_mode()
  │──── Secure(nonce, cipher) ───────────▶│  (all data henceforth encrypted)
```

The initiator is always the node that called `Zudp::connect()`. The responder is the node that called `Zudp::listen()`. The engine drives the handshake automatically.

`Zudp::connect()` **blocks until all three messages complete** before returning to the caller. This guarantees that no application data can be sent before the `SecureChannel` is established. Implementations must enforce the same invariant: do not expose a send API on the connection handle until `into_stateless_transport_mode()` has been called successfully.

### Encrypted send path

1. Encode the inner frame (Stream / Fragment) as usual.
2. Store the **plain** encoded frame in the send buffer (for NACK retransmits).
3. Encrypt with `channel.encrypt(plain)` → `(nonce, ciphertext)`.
4. Send `Frame::Secure { nonce, ciphertext }`.

### Encrypted receive path

1. Receive `Frame::Secure { nonce, ciphertext }`.
2. Check anti-replay window; reject if nonce already seen or too old.
3. Decrypt with `channel.decrypt(nonce, ciphertext)`.
4. Decode the inner frame and dispatch normally (through the reliability layer).

### What is and is not encrypted

| Frame | Encrypted when channel is open |
|---|---|
| Stream | yes |
| Fragment | yes |
| Ping / Pong | yes — keepalives carry a session ID; encrypting them prevents replay-based migration attacks |
| Nack | yes — sequence numbers reveal delivery timing; encrypting prevents traffic analysis |
| MtuAck | yes |
| Datagram (unreliable) | no — bypass for latency-critical fire-and-forget data |
| Handshake | no (by definition, sent before the channel exists) |
| Relay / Probe / Beacon | no (routing/discovery frames are always plaintext) |

### Nonce exhaustion

The send nonce is a monotonically increasing `u64` starting from 0. At a rate of one million messages per second it takes ~585 000 years to exhaust. No special handling is needed.

### Remote key pinning *(feature: `security`)*

An endpoint may pin the expected X25519 static public key of its peer. If provided, the key is checked during the Noise XX handshake immediately after the remote's static key becomes available — after `read_message(msg2)` on the initiator side, and after `read_message(msg3)` on the responder side. A mismatch causes the handshake to be aborted silently (no error frame is sent to avoid oracle attacks). The `connect()` call on the initiator will time out rather than return an error, preventing peer enumeration.

---

## Access control and hardening

These limits are enforced by the engine on the receiving path and require no coordination with the remote peer.

### Per-IP rate limiting

A token-bucket rate limiter is maintained per source IP address. Tokens refill at `max_pps` per second up to `burst` (default: `max_pps / 5`, minimum 1). Each accepted packet consumes one token; packets that arrive when the bucket is empty are silently dropped. The rate limiter is applied before frame parsing — malformed or oversized packets are still subject to the limit.

- Default: `max_pps = 1 000`, `burst = 200`.
- Idle buckets (no traffic for 60 s) are pruned to bound memory.

### Peer table cap

The engine tracks at most `max_peers` distinct remote addresses in its peer table. When a packet arrives from an unknown address and the table is at capacity, the **least-recently-seen** peer is evicted (LRU by `last_seen` timestamp) to make room, and the new peer is inserted normally. The `dropped_peer_cap` counter is incremented each time an eviction occurs; it is accessible via `EngineStats`.

This bounds memory usage at any load while preserving service to genuinely active peers — idle peers are displaced before active ones.

- Default: `max_peers = 1 024`.

### Relay abuse protection

A relay engine enforces two additional limits on its routing table:

**Allowlist** — if configured, only source IPs present in the allowlist may submit Relay frames. Frames from any other IP are dropped before the routing table is updated. An empty allowlist (the default) allows any source.

**Table cap** — the routing table is bounded by `max_relay_entries`. A Relay frame that would add a new destination beyond the cap is dropped; existing entries are unaffected.

**Entry TTL** — routing entries expire after 300 seconds of inactivity (no Relay frames received for that destination). Expiry is implemented as a generation counter rather than wall-clock timestamps to avoid per-packet syscalls.

- Defaults: no allowlist, `max_relay_entries = 256`.

---

## Congestion Control

ZUDP uses a BBR-lite congestion controller per peer.  It is RTT-based (not loss-based), so it responds to queue build-up before packet loss occurs — important for gaming where a single NACK stall is already harmful.

### RTT estimation

RTT samples come from Ping/Pong echo timestamps (`echo` is a Unix timestamp in **microseconds**).  Each Pong yields:

```
rtt_us = now_us − echo
```

The smoothed RTT (`srtt`) is an EWMA with α = 1/8:

```
srtt = 7/8 × srtt + 1/8 × rtt_sample
```

The minimum RTT (`min_rtt`) is the smallest sample observed within a rolling 10-second window.  When the window expires it resets to the current sample.

### Pacing rate

An estimated pacing rate (bytes/second) is maintained per peer:

- Initial value: 1 MB/s.
- On each RTT sample, compute `inflation = srtt / min_rtt`.
  - `inflation > 1.25` → queue bloat detected → `pacing_rate × 0.75` (multiplicative decrease, floor 10 KB/s).
  - `inflation ≤ 1.25` → path clear → `pacing_rate × 1.05` (additive increase, ceiling 100 MB/s).

### Token bucket

A per-peer token bucket controls the effective send rate.  Tokens refill at `pacing_rate` bytes/second; sending `N` bytes deducts `N` tokens.  The bucket caps at `65 535` bytes (burst allowance), which is enough to send a typical game state sync without any delay.

When the bucket is overdrawn, `consume(bytes)` returns a suggested sleep duration:

```
sleep = min(−tokens / pacing_rate, 10 ms)
```

The 10 ms cap ensures congestion never completely stalls a retransmit.

### Send-path policy

| Send type | Token tracking | Pacing delay |
|---|---|---|
| New reliable send (`send`, `send_stream`) | yes | **never** — gaming latency budget |
| Fragmented send (`send` > MTU) | yes | **never** — burst allowance covers typical sizes |
| NACK retransmit | yes | **yes** (up to 10 ms) — retransmits tolerate small delay |
| Unreliable datagram | no | never |

Retransmit pacing is performed in a dedicated spawned task so the engine receive loop is never stalled.

### Exposed metrics

Implementations should expose per-peer congestion state for application use:

- `srtt(): Option<Duration>` — smoothed RTT; `None` until first Pong.
- `congestion_factor(): Option<f64>` — `srtt / min_rtt`; values near 1.0 mean path is clear.

---

## Network Migration

When a node changes its local network interface (WiFi → mobile, DHCP renew, VPN toggle), its UDP socket becomes invalid and the far end's peer table still points to the old address.  ZUDP recovers transparently via session IDs embedded in Ping/Pong frames.

### Session IDs

Each `PeerState` is assigned a random 64-bit `my_session_id` on creation.  This value is:

- Included in every outbound Ping and Pong as the sender's session identifier.
- Stored as `their_session_id` by the receiver the first time it arrives.
- Registered in a `sessions: HashMap<u64, PeerState>` index for O(1) lookup by session ID.

### Client-side rebind

When `recv_from()` returns an unrecoverable I/O error (e.g. `ENETUNREACH` after an interface disappears):

1. Engine creates a new UDP socket bound to the same local address (fallback: port 0).
2. Engine replaces `EngineInner.socket` so all future sends use the new interface.
3. Engine immediately sends Ping to every known peer, carrying `peer.my_session_id`, from the new socket.

### Server-side migration detection

When a Ping arrives from an **unknown source address** `new_addr`:

1. Engine looks up `sessions[session_id]`.
2. If found and `old_addr != new_addr`:
   - `peer.migrate_to(new_addr)` — updates the live address Arc.
   - `peers.remove(old_addr); peers.insert(new_addr, peer)` — re-keys the peer map.
   - All `recv_states[(old_addr, stream_id)]` entries are moved to `(new_addr, stream_id)`.
   - Logging: `"peer address migrated" old=… new=…`.
3. Subsequent data frames from `new_addr` are routed correctly.

### `ZudpConn` tracking

`ZudpConn.peer` is an `Arc<RwLock<SocketAddr>>` that shares storage with `PeerState.addr`.  When the remote peer migrates, `ZudpConn.peer()` automatically returns the new address and `recv()` accepts frames from it — no reconnect needed.

### Limitations

| Topology | After network change |
|---|---|
| Client (any NAT) → Server (public IP) | ✓ migration works |
| Client configured with relay | ✓ relay table updates on first Ping from new addr |
| P2P both behind NAT (no relay) | ✗ new NAT mappings needed — use relay or re-initiate hole punching |

---

## Path MTU Discovery (PLPMTUD)

ZUDP probes the actual path MTU between two peers using a binary-search algorithm driven by `MtuProbe` / `MtuAck` frames.  The goal is to send frames as large as the path allows without IP fragmentation, which would cause the entire datagram to be lost if any fragment is dropped.

### When probing runs

- On **first contact**: `spawn_mtu_probe()` is called when a new peer is registered (both on the server side when it first receives a Ping, and on the client side inside `connect()`).
- On **address migration**: when a peer migrates to a new address, the effective MTU is reset to zero and probing restarts for the new path.

### Algorithm

The probe starts at the configured application MTU and binary-searches downward until it finds the largest size that receives an MtuAck within the timeout.

Each probe is a `MtuProbe` frame padded so the total datagram equals the size under test (including ZUDP and UDP/IP headers).

| Parameter | Value |
|---|---|
| Per-probe timeout | 200 ms |
| Total probe cap (`connect()`) | 5 s |
| Fallback on timeout | configured `mtu` (no change) |

### Effective MTU

The discovered value is stored atomically per peer (`effective_mtu: AtomicU32`).  Senders read it on every `send_msg()` call to determine whether to send a single Stream frame or fragment.  Until discovery completes (or if it times out), the configured `mtu` is used.

On MtuAck receipt, the engine wakes the probe task via a `oneshot::Sender<()>` registered per `probe_id` in `PeerState.probe_acks`.

---

## Observability

The engine exposes monotonically-increasing atomic counters and per-peer snapshots that carry zero lock contention in steady state.

### Per-peer stats (`PeerStats`)

Available via `ZudpSocket::peer_stats(addr)` and `ZudpConn::peer_stats()`.

| Field | Type | Description |
|---|---|---|
| `srtt` | `Option<Duration>` | Smoothed RTT; `None` until first Pong |
| `congestion_factor` | `Option<f64>` | `srtt / min_rtt`; near 1.0 = clear path |
| `pacing_rate_bps` | `u64` | Current BBR-lite pacing rate in bytes/second |
| `rx_bytes` | `u64` | Application payload bytes received from this peer |
| `tx_bytes` | `u64` | Application payload bytes sent to this peer |
| `retransmit_count` | `u64` | Frames retransmitted due to NACKs |

### Engine-wide stats (`EngineStats`)

Available via `ZudpSocket::engine_stats()` and `ZudpConn::engine_stats()`.

| Field | Type | Description |
|---|---|---|
| `dropped_rate_limited` | `u64` | Packets dropped by the per-IP rate limiter |
| `dropped_peer_cap` | `u64` | Times the peer table was full and an LRU eviction occurred |
| `dropped_relay_blocked` | `u64` | Relay frames from IPs not in the allowlist |
| `dropped_relay_cap` | `u64` | Relay frames dropped because the routing table was full |

All counters are read with `Ordering::Relaxed`; they may lag by one instruction reorder but are never negative or wrapping in practice over a socket's lifetime.

---

## Codec layer

The application message is encoded/decoded by an interchangeable codec layer. The wire carries raw bytes; the frame protocol has no knowledge of the message schema.

| Cargo feature | Encoder | Decoder | Encode error | Decode error |
|---|---|---|---|---|
| `rkyv` (default) | `rkyv::to_bytes` | `rkyv::from_bytes` (validated) | `rancor::Error` | `rancor::Error` |
| `bitcode` | `bitcode::encode` (infallible) | `bitcode::decode` | — | `bitcode::Error` |
| `serde` | `postcard::to_allocvec` | `postcard::from_bytes` | `postcard::Error` | `postcard::Error` |
| `serde` + any | postcard | postcard | `Box<dyn Error>` | `Box<dyn Error>` |
| none | user-supplied `Encode`/`Decode` impls | same | `Box<dyn Error>` | `Box<dyn Error>` |

Priority when multiple features are active: `serde` > `rkyv` > `bitcode`.

Custom codecs are supported by manually implementing the `Encode` and `Decode` traits.
