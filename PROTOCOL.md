# ZUDP Protocol Specification

Wire version 3 — the wire format is not yet stable.

---

## Overview

ZUDP is a UDP-based protocol that adds optional reliability, ordered delivery, transparent fragmentation, keepalives, end-to-end relayed sessions with hole punching for NAT traversal, and LAN peer discovery on top of raw UDP datagrams.

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
| `0x06` | Via *(inside Secure only)* | 33 B |
| `0x07` | Probe | 11 B |
| `0x08` | Beacon | 21 B + meta |
| `0x09` | Handshake | 3 B + Noise message (40–104 B) |
| `0x0A` | Secure | 17 B + AEAD tag (16 B) |
| `0x0B` | MtuProbe | 3 B + padding |
| `0x0C` | MtuAck | 3 B |
| `0x0D` | SessionUnknown | 9 B |
| `0x0E` | ViaFrom *(inside Secure only)* | 33 B |
| `0x0F` | Unreachable *(inside Secure only)* | 33 B |
| `0x10` | IntroRequest *(inside Secure only)* | 33 B |
| `0x11` | Intro *(inside Secure only)* | 40 B (IPv4) / 52 B (IPv6) |
| `0x12` | PathChallenge *(inside Secure only)* | 9 B |
| `0x13` | PathResponse *(inside Secure only)* | 9 B |

### Wire version

The session protocol is versioned by `WIRE_VERSION` (currently **3**), carried in every Handshake frame. A responder ignores handshakes from another version, so mismatched peers fail with `HandshakeTimeout` instead of exchanging garbage. Version 2 added the handshake `step`/`version` bytes, the session index in Secure frames and the SessionUnknown frame. Version 3 removed the plaintext `Relay` frame, added the relay frames `Via`, `ViaFrom`, `Unreachable`, `IntroRequest`, `Intro`, `PathChallenge` and `PathResponse` (all only valid inside a Secure frame), and an anti-replay window on Secure frames. Discovery has its own `proto_ver` (see *Discovery*).

---

## Frame definitions

### Datagram — `0x00`

Unreliable, unordered delivery. No sequence number; no retransmission.

```
[payload bytes] [0x00]
```

The unreliable fast path avoids copying the payload: on a socket without a keypair, to a direct peer, the sender uses scatter-gather I/O to write the payload and the 1-byte type tag in a single syscall.

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

Keepalive probe.  `echo` is the sender's current Unix timestamp in **microseconds**.  `session_id` is the **sender's engine instance id**: random per socket (per process run), the same towards every peer. It lets the receiver recognise this node from a new address (migration) and notice when the node at a known address restarted.

```
[echo: u64] [session_id: u64] [0x03]
```

Sent when nothing was sent to a peer, or nothing was received from it, for `keepalive_interval` (default 5 s).  The keepalive tick runs at `keepalive_interval / 4`.  A node also pings immediately when a data frame arrives from an address it has never seen, and a plain-mode `connect()` pings before returning, so instance ids are known within one round trip.

On receipt (Ping or Pong) the engine stores `session_id` in its per-peer session registry.  If it arrives from an **unknown address** but carries a **known `session_id`**, the peer's address is migrated transparently (see *Network Migration* below).  Without security, a **different** `session_id` from a **known address** means the remote restarted: every piece of per-peer state is discarded and a fresh session starts (`PeerEvent::Reset`).

### Pong — `0x04`

Reply to a Ping.  Mirrors `echo` unchanged; carries the **replier's** engine instance id.

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

### Relay frames — `0x06`, `0x0E`–`0x11` *(feature: `security`)*

Relay frames are only ever sent inside a Secure frame between a relay node and one of its direct clients; a plaintext one is dropped, and one found inside a relayed (end-to-end) session is dropped too — relaying does not nest. Keys are X25519 static public keys.

```
Via          : [inner bytes] [to: 32 bytes]   [0x06]   client → relay
ViaFrom      : [inner bytes] [from: 32 bytes] [0x0E]   relay → client
Unreachable  : [to: 32 bytes]                 [0x0F]   relay → client
IntroRequest : [peer: 32 bytes]               [0x10]   client → relay
Intro        : [port: u16] [ip: 4|16 bytes] [addr tag: 0x00 v4 | 0x01 v6] [peer: 32 bytes] [0x11]   relay → client
```

- `inner` is a complete wire frame of the end-to-end session between two relay clients: a `Handshake`, a `Secure` or a `SessionUnknown` frame. The relay never decrypts it (it has no key for it).
- `Via { to }`: deliver `inner` to the client whose session with the relay authenticated static key `to`. The relay answers `Unreachable { to }` when no such client is connected, when its policy refuses the pair, or when its route cap is reached — the same answer in every case.
- `ViaFrom { from }`: `inner` came from the client with key `from`. The receiver treats this as a claim: a handshake must authenticate exactly `from`, and a Secure frame's session index must name the session with `from` through this relay; otherwise the frame is dropped (`EngineStats::dropped_forged`).
- `IntroRequest { peer }` / `Intro { peer, addr }`: hole punching (see *Relayed sessions*).

A relayed frame carries 66 bytes more than a direct one (`Via`/`ViaFrom` header 33 B, relay session Secure header 17 B and AEAD tag 16 B); relayed peers fragment at `min(relay path MTU, mtu) - 66`, and never above 1 448 B, so the inner frame (chunk + 19 B Fragment header + 33 B Secure overhead) stays within 1 500 B, the default `max_inner` of a relay node. A relay configured with a smaller `max_inner` drops larger fragments (`relay_dropped_oversize`). The relayed size applies even after punching, because the path can fall back to the relay at any time.

### Relayed sessions *(feature: `security`)*

A client with a secure session to relay node R opens a session with key `T` through R (`connect_via(R, T)`): the Noise XX handshake and all subsequent Secure frames of that session travel as `inner` bytes. Each end addresses the other as `PeerAddr::Relayed { relay: R, key }`; the handle stays the same for the whole session. Reliability, fragmentation, congestion control, keepalives, timeouts and peer events work as for direct peers. Pinned keys apply to relayed handshakes exactly as to direct ones. An `Unreachable` answer fails a pending handshake with `Error::Unreachable`, and ends an established session that has no direct path with `PeerEvent::Disconnected { reason: Unreachable }`.

**Accepted relays.** A client processes `ViaFrom` only from relays it accepted for inbound sessions (`accept_relayed_from`), or for sessions it opened through that relay itself (a pending or established handshake with that handle); everything else is dropped (`dropped_relay_unaccepted`). Relayed handshake initiations (msg1) are limited to 20/s per relay, each relay has its own budget of half-open handshakes (`max_peers / 4`, at least 8) separate from direct ones, and established sessions through one relay may take at most `max_peers / 2` slots (the least recently seen of them is evicted). Installing any session respects `max_peers` (LRU eviction).

**Hole punching.** Punching is only started for approved peers: keys pinned with `pin_remote_key`, or keys the application approved with `punch(peer)`. For those, both ends send `IntroRequest { peer }` to R after installing the session (again every 30 s while their traffic still goes through R; `punch` asks at once). R only answers when both requests are present within 10 s and its policy allows the pair: it sends each side `Intro { peer, addr }` with the public address it observes for the other. A client accepts an `Intro` only within 10 s of its own request for that peer (once per request), runs one punch campaign per peer at a time, and refuses unspecified, multicast and broadcast addresses, port 0, and private / link-local (loopback) addresses unless the relay's own address is private (loopback). Each side then sends up to 10 encrypted Pings, 100 ms apart, of the end-to-end session straight to `addr`.

Once punched, *everything* of the session — data, NACKs, retransmits, tail-loss probes, keepalives, Pongs, SessionUnknown hints — goes over the direct path, so the session keeps working, loss recovery included, even if the relay disappears. Handshake messages (including re-handshakes) always go through the relay. A new session with the same handle (the peer restarted) starts on the relay again and reports `PathChanged { path: Relayed(R) }` before its `Reset`.

A peer can hold a direct session and a relayed session at the same time (say, on the same LAN and through a relay); they are separate sessions with separate handles. Relayed sessions never take part in instance-id migration, so one never absorbs the other.

**Path validation.** An authenticated, fresh frame of a relayed session that carries the newest nonce so far and arrives directly from an address `X` other than R and other than the current direct path makes the receiver send `PathChallenge { token }` (random u64) inside the session straight to `X`, at most once per 250 ms per address. The peer answers every challenge with `PathResponse { token }` sent back to the address the challenge came from. Only an authenticated `PathResponse` with the outstanding token that arrives from `X` moves the path there (`PeerEvent::PathChanged { path: Direct(X) }`); from then on everything is sent directly, and `X` is exempt from the per-IP rate limit. A frame captured and re-sent from a spoofed address therefore costs one challenge to that address and moves nothing, and a path that only works in one direction is never used: the challenge or its answer would not get through. When nothing authenticated arrives on the direct path for 3/5 of `peer_timeout`, traffic goes back through R (`PathChanged { path: Relayed(R) }`) and a Ping is sent through R at once; the session is unaffected. With `punching(false)` no introduction is requested and directly-arriving frames of relayed sessions are dropped.

```
PathChallenge : [token: u64] [0x12]
PathResponse  : [token: u64] [0x13]
```

**Relay node.** A socket built with `relay_node(limits, policy)` keeps an index from static key to session and forwards `Via` frames as `ViaFrom` frames to the session of the named key. It never sends to an address a client supplies, so it cannot reflect traffic. Without a policy (`set_relay_policy(None)`) it relays nothing. Every frame is charged to three packet+byte token buckets — per client key, per source network (IPv4 address or IPv6 /64) and for the whole node (defaults: 2 000/s burst 400 and 4 MB/s burst 1 MB; 4 000/s burst 800 and 8 MB/s burst 2 MB; 50 000/s burst 10 000 and 50 MB/s burst 10 MB). Inner frames above `max_inner` (1 500 B) are dropped. Client pairs are tracked up to 64 per key, 256 per network and 4 096 in total; a new pair beyond a cap evicts the least recently used pair of that scope (never refusing), and pairs idle for 60 s or whose client left are forgotten. Pending introduction requests are capped the same way (16 per client, 256 per network, 4 096 total). At most `max_sessions_per_ip` (64) secure sessions are kept per source network; a new one evicts that network's least recently seen session. The relay can always end a relayed session early (`Unreachable`, forged `SessionUnknown`), which is no more than it could do by dropping traffic.

### Handshake — `0x09` *(feature: `security`)*

One message in a Noise XX key exchange. Three messages are exchanged before the connection is encrypted.

```
[noise_message bytes] [step: u8] [version: u8] [0x09]
```

- `step`: 1 = msg1, 2 = msg2, 3 = msg3.
- `version`: the sender's `WIRE_VERSION`.

Message sizes for `Noise_XX_25519_ChaChaPoly_BLAKE2s`:

| Message | Direction | Noise size | Noise payload |
|---|---|---|---|
| msg1 | initiator → responder | 40 B | initiator session index (u64, plaintext) |
| msg2 | responder → initiator | 104 B | responder session index (u64, encrypted) |
| msg3 | initiator → responder | 64 B | — |

After all three messages the handshake is complete. Both sides call `into_stateless_transport_mode()` and all subsequent data frames are wrapped in `Secure` frames addressed with the other side's session index.

### Secure — `0x0A` *(feature: `security`)*

A Noise-encrypted data frame. The `ciphertext` is the output of `ChaCha20-Poly1305` AEAD applied to any plain inner frame — once the channel is established, all frame types except Handshake, SessionUnknown and Probe/Beacon/MtuProbe are wrapped in Secure.

```
[ciphertext bytes] [nonce: u64] [index: u64] [0x0A]
```

- `index`: the session index the **receiver** chose in the handshake. The receiver finds the session by index, not by source address, so a session keeps working after the sender's address changes (see *Network Migration*).

- `nonce`: per-peer send-side counter, strictly increasing per sender. Provided explicitly because UDP packets may arrive out of order — `StatelessTransportState` takes the nonce as a parameter rather than tracking it internally.
- The AEAD tag (16 B) is appended to the ciphertext by the cipher; it is not a separate field.
- The decrypting side validates the tag before delivering the plaintext.
- NACK retransmits re-encrypt the original plaintext with a **fresh nonce** to avoid nonce reuse. The old nonce must not be reused even if the ciphertext is identical.
- Each session keeps an anti-replay window over the last 4 096 nonces (wire version 3): an authenticated frame whose nonce was already accepted, or is 4 096 or more behind the newest, is dropped. Only authenticated frames advance the window. The window is wide so legitimate reordering at high frame rates is never rejected. The highest authenticated nonce per session is tracked as well, so that only a **newer** frame can move a session to a new address or path; replaying an old datagram from elsewhere cannot redirect it.

### SessionUnknown — `0x0D` *(feature: `security`)*

```
[index: u64] [0x0D]
```

Sent in plaintext in reply to a Secure frame whose `index` the receiver does not know (it restarted and lost the session), rate-limited to 5 per second per source IP (per relayed peer for sessions through a relay, so peers behind one relay do not share a budget). The initiator of the session named by `index` starts a new handshake in the background (at most once per handshake timeout); the old session stays in place until the new one replaces it, so a forged SessionUnknown can cost a handshake but cannot tear a session down. Responders ignore it.

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
[meta bytes] [instance: u64] [data_port: u16] [proto_ver: u16] [app_id: u64] [0x08]
```

- `data_port`: the ZUDP data port the advertising node is listening on.
- `instance`: random per `Discovery::advertise` call; a new value from the same address means the advertiser restarted.
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
- Frame at `seq > expected_seq`: NACK the first 128 seqs in `[expected_seq, seq)` not already buffered, buffer this frame.
- Frame at `seq ≥ expected_seq + window` (window = `max(sent_buffer, 1024)`): dropped, so a forged sequence number cannot make the receiver track an unbounded gap.
- In-order payloads are handed to the application only when the inbound channel has room; otherwise they stay buffered and delivery resumes as soon as the application reads again (no reliable data is dropped for backpressure).
- Until a plain-mode peer's instance id is known, only the next in-order frame is accepted, so frames from a previous incarnation of the remote are neither buffered nor NACKed.
- After a gap stays unresolved for `sent_prune_age`, only the missing seqs are skipped; frames buffered after the hole are still delivered.
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
| `INBOUND_CAP` | 8 192 — bounded inbound channel slots; reliable frames wait in the reorder buffer when full, unreliable datagrams are dropped |
| Default MTU | 1 400 B |
| Default `sent_prune_age` | 10 s |
| Default `keepalive_interval` | 5 s |
| Default `max_peers` | 1 024 |
| Default `max_pps_per_ip` | 1 000 (burst: 200); handshakes have a separate 20/s budget; peers with an established Noise session are exempt |
| Default `handshake_timeout` | 5 s |
| Default `peer_timeout` | 3 × `keepalive_interval` |
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

The discovery protocol version (`proto_ver`) is a separate `u16` field in both Probe and Beacon frames, currently `2` (version 2 added `instance` to Beacon). Nodes with mismatched `proto_ver` ignore each other's frames.

### Scan events

`ScanStream::next_event()` reports `DiscoveryEvent::Found` the first time a data address answers, `Updated` when its metadata or `instance` changes, and `Lost` once it has not answered for `peer_ttl` (default 3 × `probe_interval`); a lost peer that answers again is `Found` again. `ScanStream::next()` returns the peers of `Found` and `Updated`. Malformed or foreign datagrams are skipped by scanners and advertisers alike; the advertise task never exits on its own.

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

`Zudp::connect()` **returns only after the handshake completed and one authenticated round trip succeeded** (an encrypted Ping answered by an encrypted Pong), so both ends hold the session. Loss is recovered by retransmission with back-off from 200 ms to 1 s, until `handshake_timeout` (default 5 s) expires with `Error::HandshakeTimeout`:

- msg1 lost: the initiator resends msg1.
- msg2 lost: the initiator resends msg1; a responder that sees a byte-identical msg1 resends its cached msg2.
- msg3 lost: the initiator resends msg3 together with the confirming Ping until the responder answers.
- A msg1 that does not match the responder's half-open state replaces it (the remote restarted mid-handshake). Half-open states expire after `handshake_timeout`.
- If both sides initiate at once, the one whose msg1 ephemeral key is larger stays initiator.

On a socket with a keypair, plaintext Datagram, Stream, Fragment, Nack, Ping, Pong and relay frames are dropped (counted in `EngineStats::dropped_unauthenticated`), and sending to a peer without a session fails with `Error::NoSession` instead of falling back to plaintext.

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
| Datagram (unreliable) | yes (since wire version 2) |
| Handshake | no (by definition, sent before the channel exists) |
| Probe / Beacon / MtuProbe / SessionUnknown | no (discovery and path probing are always plaintext) |
| Via / ViaFrom / Unreachable / IntroRequest / Intro | always — never valid in plaintext |

### Nonce exhaustion

The send nonce is a monotonically increasing `u64` starting from 0. At a rate of one million messages per second it takes ~585 000 years to exhaust. No special handling is needed.

### Remote key pinning *(feature: `security`)*

An endpoint may pin one or more expected X25519 static public keys (`pin_remote_key` is repeatable; any pinned key is accepted, and the pins cover direct and relayed handshakes alike). If provided, the key is checked during the Noise XX handshake immediately after the remote's static key becomes available — after `read_message(msg2)` on the initiator side, and after `read_message(msg3)` on the responder side. A mismatch aborts the handshake; no error frame is sent. The initiator learns the responder's key from msg2, so `connect()` fails immediately with `Error::KeyMismatch`. A responder that pins a key drops the handshake silently, and the initiator times out.

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

See *Relayed sessions → Relay node*: packet and byte token buckets per client key, per source network and in total, a maximum inner frame size, per-client / per-network / total caps on client pairs and pending introductions that evict rather than refuse, a per-network session cap, and a mandatory policy (default-deny). A denied and an offline target get the same `Unreachable` answer; only clients the policy lets through can learn whether a target is connected. Introductions are only given out when both sides asked for each other, so no client can look up another's address.

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

When a node changes network (Wi-Fi → mobile, DHCP renew, VPN toggle, NAT rebinding), the far end sees its datagrams arrive from a new address.  ZUDP keeps the session: with security by the session index in every Secure frame, without security by the engine instance id in Ping/Pong frames.  Either way the far end emits `PeerEvent::Migrated { from, to }`.

### Secure sessions (roaming)

A Secure frame is matched to its session by `index`.  When it authenticates, carries a nonce newer than any before, and comes from a different address, the session is re-keyed to that address (peer table, receive state, MTU re-probe).  No Ping is needed, so the first data frame after the move already arrives on the right session.

### Instance ids (plain mode)

Each engine picks a random 64-bit instance id at start.  It is:

- Included in every outbound Ping and Pong.
- Stored per peer by the receiver and indexed in `sessions: HashMap<u64, PeerState>`.
- Used to detect a restarted remote: a new id from a known address resets that peer.

### Receive errors

Errors about a single remote (ICMP port unreachable surfacing as `ConnectionReset` / `ConnectionRefused`, unreachable networks, interruptions) are ignored; on Windows `SIO_UDP_CONNRESET` is switched off so they do not occur.  Other errors are retried with back-off.  Only a socket bound to an ephemeral port is replaced after 10 consecutive hard errors; a socket bound to a requested port is never moved to another port.

### Exclusive ports

Data sockets are bound without `SO_REUSEPORT` / `SO_REUSEADDR` (and with `SO_EXCLUSIVEADDRUSE` on Windows).  A second socket on the same port fails to bind instead of silently receiving part of the traffic, and background tasks hold only weak references so the port is released as soon as the last handle is dropped.

### Server-side migration detection

When a Ping arrives from an **unknown source address** `new_addr`:

1. Engine looks up `sessions[session_id]` (plain mode; secure sessions roam by index as above).
2. If found and `old_addr != new_addr`:
   - `peer.migrate_to(new_addr)` — updates the live address Arc.
   - `peers.remove(old_addr); peers.insert(new_addr, peer)` — re-keys the peer map.
   - All `recv_states[(old_addr, stream_id)]` entries are moved to `(new_addr, stream_id)`.
   - Logging: `"peer address migrated" old=… new=…`.
3. Subsequent data frames from `new_addr` are routed correctly.

### `ZudpConn` tracking

`ZudpConn.peer` is an `Arc<RwLock<PeerAddr>>` that shares storage with `PeerState.addr`.  When the remote peer migrates, `ZudpConn.peer()` automatically returns the new address and `recv()` accepts frames from it — no reconnect needed.

### Limitations

| Topology | After network change |
|---|---|
| Client (any NAT) → Server (public IP) | ✓ migration works (plain and secure) |
| Relay client (any NAT) → relay node (public IP) | ✓ migration works; its relayed sessions are unaffected |
| Relayed session on a punched direct path | ✓ the newest authenticated frame from a new address moves the path; a silent path falls back to the relay |
| P2P both behind NAT without a relay | ✗ new NAT mappings needed — use a relay node |

---

## Peer liveness and events

- A peer that sends nothing for `peer_timeout` (default 3 × `keepalive_interval` = 15 s) is dropped with all its state; with security only authenticated frames count.  Keepalive Pings keep live, idle peers well inside the timeout.
- `ZudpSocket::events()` / `ZudpConn::events()` / `ZudpSender::events()` return a `PeerEvents` subscription yielding `PeerEvent::{Connected, Reset, Migrated, PathChanged, Disconnected}`.  `PathChanged` reports a relayed session moving between its relay and a punched direct path.  `Disconnected` carries a `DisconnectReason`: `TimedOut`, `Removed` (`remove_peer`), `Evicted` (peer table full) or `Unreachable` (the relay reported a relayed peer gone).
- `ZudpConn::recv()` returns `Error::PeerTimeout` once its peer timed out (after any messages that were already received).
- When a remote restarts or re-handshakes, the old per-peer state (sequence counters, send buffers, receive and fragment state, congestion state, keys) is replaced as a whole and `PeerEvent::Reset` is emitted.

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
| Fallback when no probe is answered | configured `mtu` (no change) |

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
| `dropped_unauthenticated` | `u64` | Plaintext data frames dropped by a socket with a keypair |
| `dropped_forged` | `u64` | Relayed frames whose relay-claimed sender did not match their session |
| `relay_forwarded_packets` / `relay_forwarded_bytes` | `u64` | Relay node: frames / inner bytes forwarded |
| `relay_dropped_rate_limited` | `u64` | Relay node: frames over a client's packet or byte budget |
| `relay_dropped_oversize` | `u64` | Relay node: inner frames above `max_inner` |
| `dropped_relay_unaccepted` | `u64` | Relayed frames from a relay that was not accepted |
| `relay_unreachable` | `u64` | Relay node: `Unreachable` answers (of which `relay_denied` by policy) |
| `relay_routes_evicted` / `relay_sessions_evicted` | `u64` | Relay node: client pairs / sessions evicted to stay within their caps |
| `relay_introductions` | `u64` | Relay node: client pairs introduced for hole punching |

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
