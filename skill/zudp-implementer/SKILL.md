---
name: zudp-implementer
description: >
  Implement or use the ZUDP protocol. Invoke this skill whenever the user wants to implement
  ZUDP in any language (Python, Go, C, TypeScript, C#, …), use the zudp Rust crate in their
  project, add ZUDP client or server support, build a ZUDP subsystem (frame codec, reliability,
  fragmentation, relay, LAN discovery), write tests for a ZUDP implementation, or reverse-engineer
  a ZUDP packet capture. Also invoke when the user mentions "zudp", shares PROTOCOL.md, or asks
  how to do networking with this protocol — even if they don't say "implement" explicitly.
---

# ZUDP Implementer

Two distinct use cases — determine which applies before writing any code:

- **Using the Rust crate** (`zudp` as a dependency): read `references/rust.md` first.
- **Implementing the protocol** in another language or from scratch: continue below.

The authoritative wire spec is `PROTOCOL.md` in the repository root — read it if available.
Everything below is the implementation-focused distillation: invariants, order of work,
critical gotchas, and a mandatory test checklist.

---

## Before you write any code

1. **Ask which language and runtime** if not stated. Async I/O primitives differ enormously
   (tokio, asyncio, goroutines, libuv, threads…); pick the right one early.
2. **Ask which features are needed.** ZUDP has a layered feature set.  A minimal interoperable
   client needs only Datagram + Stream + Nack.  Relay and Discovery are optional.
3. **Read `PROTOCOL.md`** if it exists on disk.  The wire format there is authoritative.
   This skill embeds only the byte layouts you need to stay fast; semantic detail lives in the spec.

---

## Implementation order

Build bottom-up and test each layer before starting the next.  Skipping ahead produces
untestable integration bugs.

```
1. Frame codec          — encode / decode every frame type; roundtrip test each
2. Raw UDP socket       — send_to, recv_from, SO_REUSEPORT, buffer sizes
3. Reliability layer    — RecvState (reorder buffer) + send buffer (retransmit map)
4. Fragmentation        — split on send, reassemble on recv
5. Engine / event loop  — background read loop, NACK dispatch, keepalive tick
6. Public API           — listen / connect / send / recv
7. Relay (optional)     — wrap/unwrap Relay frames
8. Discovery (optional) — Probe/Beacon, SO_BROADCAST socket
```

---

## Wire format

**The type byte is always the last byte of every UDP datagram.**  Read byte `[-1]` first.
This is the ONLY entry point into the parser — never inspect the payload before you know the type.

All multi-byte integers are **big-endian**.  No exceptions.

### Frame layouts (tail-first order — fields are written left-to-right, type byte last)

```
Datagram  (0x00): [payload]                                                       + [0x00]
Stream    (0x01): [payload] [seq:u64]                                             + [0x01]
Nack      (0x02): [seq_0:u64] … [seq_N:u64]                                       + [0x02]
Ping      (0x03): [echo:u64]                                                      + [0x03]
Pong      (0x04): [echo:u64]                                                      + [0x04]
Fragment  (0x05): [payload] [msg_id:u32] [frag_total:u16] [frag_idx:u16] [seq:u64]+ [0x05]
Relay/v4  (0x06): [inner]   [port:u16]  [ip:4B]  [0x00]                          + [0x06]
Relay/v6  (0x06): [inner]   [port:u16]  [ip:16B] [0x01]                          + [0x06]
Probe     (0x07): [app_id:u64] [proto_ver:u16]                                    + [0x07]
Beacon    (0x08): [meta]   [data_port:u16] [proto_ver:u16] [app_id:u64]           + [0x08]
```

**Parsing is always from the tail.**  To decode a datagram:
- Pop the last byte → frame type.
- Pop fields from the new tail in the order listed above, right-to-left.
- Whatever bytes remain after all fixed fields are stripped = the payload / inner / meta.

---

## Behavioral contracts

These are the properties a correct ZUDP implementation MUST satisfy.  Violating any of them
breaks interoperability.

### Sequence numbers
- Per-sender, per-peer counter.  Each side has its own counter; they are completely independent.
- Start at **1**.  Zero is never allocated.
- Stream and Fragment frames share the same counter on the sending side.
- The receiver tracks one `expected_seq` per remote peer.

### NACK semantics
- Send a Nack **immediately** when a gap is detected — there is no delayed-ACK timer.
- Gap detection: you received `seq = N` but `expected = M` where `M < N`.
  NACK every value in `[M, N)`.
- A Nack body must be a multiple of 8 bytes.  Each 8-byte group is one `u64` sequence number.
- Maximum 128 sequence numbers per Nack frame.
- On receiving a Nack, retransmit the stored encoded frames for the listed sequence numbers.
  If a sequence has already been pruned from the send buffer, silently skip it.

### Send buffer
- Keep the fully-encoded wire bytes for every reliable frame sent, keyed by sequence number.
- Use a sorted map (BTreeMap / SortedDict / TreeMap) so pruning old entries is O(log n).
- Prune entries older than `sent_prune_age` (default 10 s) on a background tick.

### Reorder buffer
```
on recv(seq, payload):
    if seq < expected:         drop (duplicate)
    if seq > expected:         buffer[seq] = payload; NACK [expected, seq)
    if seq == expected:
        deliver payload
        expected += 1
        while buffer[expected] exists:
            deliver buffer.pop(expected)
            expected += 1
```

### Fragmentation
- Split: `chunks = ceil(len / mtu)` slices.  Each slice is a Fragment frame with its own `seq`.
- `msg_id` is a per-socket monotonically increasing counter (u32, wraps).
- `frag_idx` is zero-based.  `frag_total` is the total count.
- Reassembly: pre-allocate a slot array of size `frag_total`.  Fill slots as fragments arrive
  (they arrive in order because they go through the reliability layer first).  Concatenate
  when all slots are full, in index order.
- Maximum fragments per message: 65 535 (`u16::MAX`).

### Keepalives
- Send Ping when no outbound frame has been sent for `keepalive_interval` (default 5 s).
- Reply to every Ping with Pong mirroring the `echo` value unchanged.
- The keepalive tick fires at `keepalive_interval / 4` to avoid missing the threshold.

### Relay
- The relay node is a plain ZUDP socket.  On receiving a `Frame::Relay`, forward `inner`
  verbatim to `dest`; do not wrap or modify.
- The server sees `from == relay_addr`, not the original sender's IP.
- Reliable framing works end-to-end: the originator retransmits to the relay on Nack;
  the relay re-forwards.

---

## Discovery (optional feature)

### AppId
```
FNV-1a 64-bit:
  h = 14695981039346656037  (offset basis)
  for each byte b: h = (h XOR b) * 1099511628211
```
Two nodes using the same app-name string produce the same AppId.  This is not
cryptographically secure — it is a stable hash for peer matching only.

### Socket requirements
- Bind to `0.0.0.0:<discovery_port>` (default `7701`).
- Set `SO_BROADCAST` and `SO_REUSEPORT` (or `SO_REUSEADDR` on platforms without REUSEPORT).
- Non-blocking / async.

### Probe flow
```
Scanner:
  1. send Probe(app_id, proto_ver=1) → broadcast 255.255.255.255:<discovery_port>
  2. receive Beacon frames; validate app_id and proto_ver match
  3. re-probe every probe_interval (default 5 s)

Advertiser:
  1. bind discovery socket
  2. loop recv_from
  3. on Probe(app_id, proto_ver) where both match:
       encode meta with the active codec
       send Beacon(app_id, proto_ver=1, data_port, meta) → unicast back to probe.from
```

`proto_ver` for the discovery protocol is always `1`.  Ignore frames with a mismatched version.

---

## Language-specific notes

| Concern | Python | Go | C / C++ | TypeScript/Node |
|---|---|---|---|---|
| Big-endian u64 | `struct.pack('>Q', v)` | `binary.BigEndian.PutUint64` | `htobe64` | `buf.writeBigUInt64BE` |
| Async socket | `asyncio.DatagramProtocol` | `net.UDPConn` + goroutine | `epoll` / `io_uring` | `dgram.createSocket` |
| SO_BROADCAST | `s.setsockopt(SOL_SOCKET, SO_BROADCAST, 1)` | `syscall.SetsockoptInt` | `setsockopt` | `socket.setBroadcast(true)` |
| Background loop | `asyncio.create_task` | `go func(){}()` | pthread / thread | `setImmediate` / worker |

---

## Mandatory test checklist

Do not mark the implementation done until every item passes.

### Frame codec (unit)
- [ ] Roundtrip encode→decode for every frame type: Datagram, Stream, Nack, Ping, Pong,
      Fragment, Relay/v4, Relay/v6, Probe, Beacon.
- [ ] Decode of a truncated packet returns an error, not a panic / exception.
- [ ] Nack body with length not a multiple of 8 returns an error.
- [ ] Unknown type byte (e.g. `0xFF`) returns an error.
- [ ] Beacon with empty meta (0 bytes) roundtrips correctly.

### Reliability (unit)
- [ ] In-order delivery: send seq 1, 2, 3 → receive in order, no NACK.
- [ ] Out-of-order gap: receive seq 1 then seq 3 → NACK for seq 2 emitted; seq 3 buffered;
      after seq 2 arrives, both 2 and 3 delivered in order.
- [ ] Duplicate: receive seq 1 twice → second is silently dropped.
- [ ] Retransmit: after NACK for seq 2, sender retransmits; receiver delivers.

### Fragmentation (unit)
- [ ] A message of exactly `mtu` bytes is sent as one Stream frame (no Fragment).
- [ ] A message of `mtu + 1` bytes is split into two Fragments with correct `frag_idx` and
      `frag_total`.
- [ ] All fragments reassemble to the exact original bytes.
- [ ] Out-of-order fragments (via the reliability layer) still reassemble correctly.

### Integration (two live sockets)
- [ ] Send a small reliable message from A to B; B receives it.
- [ ] Send a message larger than MTU from A to B; B reassembles it correctly.
- [ ] Kill A's send loop mid-transfer; B sends NACK; A retransmits; B reassembles.
- [ ] Keepalive: leave connection idle for `keepalive_interval`; verify Ping/Pong exchange.

### Discovery (if implemented)
- [ ] Advertiser and scanner on the same machine, same discovery port: scanner receives
      exactly one DiscoveredPeer with correct `data_addr` and decoded `meta`.
- [ ] Two advertisers: scanner receives two distinct peers.
- [ ] Mismatched `app_id`: scanner does not surface the peer.

---

## Pitfalls to avoid

- **Parsing from the head.** Several fields (payload, inner, meta) are variable-length and sit
  at the *front* of the datagram.  Their length is only known after you've stripped all the
  fixed fields from the tail.  Always parse from the tail.
- **Forgetting Fragment uses `seq`.** Fragment frames enter the reliability/reorder buffer just
  like Stream frames.  Reassembly only starts after the reliability layer has delivered all
  fragments in order.  Do not bypass the reorder buffer for Fragment.
- **Global sequence counter.** The sequence number is per-peer, per-direction.  If A sends to
  B and C, B and C each have their own independent sequence counter.
- **NACK on every gap re-receipt.** The receiver should NACK only when it first detects a gap
  (when the out-of-order packet arrives).  Don't re-NACK on every subsequent receive.
- **Relay forwarding the outer frame.** The relay forwards `inner` — the already-encoded inner
  frame — not the outer Relay frame itself.
- **Discovery: not setting SO_BROADCAST.** Sending to 255.255.255.255 silently fails or raises
  a permission error on most OSes if SO_BROADCAST is not set.
- **Discovery: proto_ver mismatch.** Always validate `proto_ver == 1`.  Ignore frames with any
  other value; do not log an error for them (future versions will use higher values).
