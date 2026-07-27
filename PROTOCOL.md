# ZUDP Protocol Specification

Version 0.1 — wire format is not yet stable.

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
| `0x01` | Stream | 9 B |
| `0x02` | Nack | 0 B (no payload) |
| `0x03` | Ping | 9 B |
| `0x04` | Pong | 9 B |
| `0x05` | Fragment | 17 B |
| `0x06` | Relay | 8 B (IPv4) / 20 B (IPv6) |
| `0x07` | Probe | 11 B |
| `0x08` | Beacon | 13 B + meta |
| `0x09` | Handshake | variable (32–96 B) |
| `0x0A` | Secure | 9 B + AEAD tag (16 B) |

---

## Frame definitions

### Datagram — `0x00`

Unreliable, unordered delivery. No sequence number; no retransmission.

```
[payload bytes] [0x00]
```

The unreliable fast path avoids copying the payload: when no relay is configured the sender uses scatter-gather I/O to write the payload and the 1-byte type tag in a single syscall.

### Stream — `0x01`

Reliable, ordered delivery. Carries a monotonically increasing sequence number.

```
[payload bytes] [seq: u64] [0x01]
```

- `seq` starts at 1 per peer (0 is reserved/unused).
- Sequence numbers are per-**sender**; each side of a connection maintains its own counter.
- The receiver buffers out-of-order arrivals and delivers them in order.
- Missing sequence numbers trigger a Nack (see below).

### Nack — `0x02`

Negative acknowledgement. Requests retransmission of one or more sequence numbers.

```
[seq_0: u64] [seq_1: u64] ... [seq_N: u64] [0x02]
```

- Body must be a multiple of 8 bytes; each 8-byte group is one `u64` sequence number.
- Maximum sequences per Nack: 128 (`MAX_NACK_SEQS`).
- Nacks are sent immediately when a gap is detected in the received sequence space.
- The sender retransmits the buffered encoded frame for each requested sequence number. Frames older than `sent_prune_age` (default 10 s) have been pruned and cannot be retransmitted.

### Ping — `0x03`

Keepalive probe. The `echo` value is an arbitrary token (typically the current Unix timestamp in milliseconds).

```
[echo: u64] [0x03]
```

Sent when no outbound frame has been sent to a peer for `keepalive_interval` (default 5 s). The keepalive tick runs at `keepalive_interval / 4`.

### Pong — `0x04`

Reply to a Ping. Mirrors the `echo` value unchanged.

```
[echo: u64] [0x04]
```

Receiving any frame from a peer updates `last_seen`. Neither Ping nor Pong carry sequence numbers; they are not tracked for retransmission.

### Fragment — `0x05`

One slice of a fragmented reliable message. Messages exceeding the configured MTU (default 1 400 B) are split into at most `u16::MAX` fragments before transmission.

```
[payload bytes] [msg_id: u32] [frag_total: u16] [frag_idx: u16] [seq: u64] [0x05]
```

- `msg_id`: monotonically increasing per-socket counter identifying the original message; wraps at `u32::MAX`.
- `frag_total`: total number of fragments for this message.
- `frag_idx`: zero-based index of this fragment within the message (0 ≤ `frag_idx` < `frag_total`).
- `seq`: each fragment occupies its own slot in the reliable sequence space, just like a Stream frame. The reassembler is triggered only after all `frag_total` sequence numbers have been delivered in order.

Reassembly uses a pre-allocated `Vec<Option<Bytes>>` of length `frag_total`. When all slots are filled the fragments are concatenated in index order. Incomplete assemblies are pruned after `sent_prune_age`.

### Relay — `0x06`

Relay forwarding request. The sending node wraps an inner frame and addresses it to a relay node; the relay node strips the outer header and forwards `inner` verbatim to `dest`.

**IPv4 format** (addr tag `0x00`):

```
[inner bytes] [port: u16] [ip: 4 bytes] [0x00] [0x06]
```

**IPv6 format** (addr tag `0x01`):

```
[inner bytes] [port: u16] [ip: 16 bytes] [0x01] [0x06]
```

- The relay node is a plain ZUDP socket with no special configuration; it forwards any Relay frame it receives.
- The destination sees `from == relay_addr`, not the originator's address. Return traffic must also be routed through the relay if the originator is behind NAT.
- Reliable frames can be relayed, but NACK-triggered retransmission is end-to-end: the originator retransmits to the relay, which forwards again.

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

A Noise-encrypted data frame. The `ciphertext` is the output of `ChaCha20-Poly1305` AEAD applied to any plain inner frame (Stream, Fragment, Datagram).

```
[ciphertext bytes] [nonce: u64] [0x0A]
```

- `nonce`: per-peer send-side counter, strictly increasing per sender. Provided explicitly because UDP packets may arrive out of order — `StatelessTransportState` takes the nonce as a parameter rather than tracking it internally.
- The AEAD tag (16 B) is appended to the ciphertext by the cipher; it is not a separate field.
- The decrypting side validates the tag before delivering the plaintext.
- NACK retransmits re-encrypt the original plaintext with a **fresh nonce** to avoid nonce reuse. The old nonce must not be reused even if the ciphertext is identical.
- Anti-replay: a 64-bit sliding window (`highest` + bitmask) rejects nonces already seen within the last 64 slots of the highest received nonce. Nonces more than 64 behind the window are rejected unconditionally.

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

Stream and Fragment frames share a single per-peer send-side sequence counter, starting at 1. Each frame consumes one sequence number regardless of type. The sequence number 0 is never allocated.

### Send buffer

The sender keeps a `BTreeMap<seq, (plain_frame, sent_at)>` per peer. Entries are inserted on send and pruned when older than `sent_prune_age` (default 10 s). The **plain** (pre-encryption) wire frame is stored, so NACK retransmits can re-encrypt with a fresh nonce (nonce reuse is forbidden).

### Receive reorder buffer

The receiver keeps a `BTreeMap<seq, Inbound>` per peer and an `expected_seq` counter (starts at 1):

- Frame at `seq == expected_seq`: deliver immediately, then drain consecutive buffered entries.
- Frame at `seq > expected_seq`: NACK all gaps `[expected_seq, seq)`, buffer this frame.
- Frame at `seq < expected_seq`: duplicate — silently discard.

Nacks are sent immediately on gap detection; there is no delayed-NACK timer.

### Limits

| Constant | Value |
|---|---|
| `MAX_NACK_SEQS` | 128 sequence numbers per Nack frame |
| `MAX_FRAGMENTS` | 65 535 fragments per message (`u16::MAX`) |
| Default MTU | 1 400 B |
| Default `sent_prune_age` | 10 s |
| Default `keepalive_interval` | 5 s |
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

| Frame | Encrypted |
|---|---|
| Stream | yes (wrapped in Secure when channel is open) |
| Fragment | yes |
| Ping / Pong | no (keepalives are unencrypted) |
| Nack | no (only contains sequence numbers, no payload) |
| Datagram (unreliable) | no |
| Handshake | no (by definition, sent before the channel exists) |
| Relay / Probe / Beacon | no |

### Nonce exhaustion

The send nonce is a monotonically increasing `u64` starting from 0. At a rate of one million messages per second it takes ~585 000 years to exhaust. No special handling is needed.

---

## Codec layer

The application message is encoded/decoded by an interchangeable codec layer. The wire carries raw bytes; the frame protocol has no knowledge of the message schema.

| Cargo feature | Encoder | Decoder | Encode error | Decode error |
|---|---|---|---|---|
| `bitcode` (default) | `bitcode::encode` (infallible) | `bitcode::decode` | — | `bitcode::Error` |
| `serde` | `postcard::to_allocvec` | `postcard::from_bytes` | `postcard::Error` | `postcard::Error` |
| both | postcard | postcard | `Box<dyn Error>` | `Box<dyn Error>` |
| neither | user-supplied `Encode`/`Decode` impls | same | `Box<dyn Error>` | `Box<dyn Error>` |

Custom codecs are supported by manually implementing the `Encode` and `Decode` traits.
