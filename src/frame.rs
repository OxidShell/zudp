#[cfg(feature = "security")]
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use bytes::{BufMut, Bytes, BytesMut};

use crate::Error;

/// Version of the session wire protocol, carried in every handshake message.
///
/// 2: handshake frames carry step + version; Secure frames carry the receiver's session index.
/// 3: the plaintext `Relay` frame is gone; relayed sessions travel as `Via` / `ViaFrom`
///    inside Secure frames, with `Unreachable`, `IntroRequest` and `Intro` for hole punching.
pub const WIRE_VERSION: u8 = 3;

/// Maximum number of sequence numbers encoded in a single Nack frame.
pub const MAX_NACK_SEQS: usize = 128;

/// Wire format overhead appended after the payload, per frame type:
///
/// ```text
/// Datagram  : [payload][0x00]                                                     (1 byte)
/// Stream    : [payload][seq: u64 BE][stream_id: u16 BE][0x01]                     (11 bytes)
/// Nack      : [seq0: u64 BE]...[stream_id: u16 BE][0x02]                          (3 + N*8 bytes)
/// Ping      : [echo: u64 BE][session_id: u64 BE][0x03]                            (17 bytes)
/// Pong      : [echo: u64 BE][session_id: u64 BE][0x04]                            (17 bytes)
/// Fragment  : [payload][msg_id: u32 BE][frag_total: u16 BE][frag_idx: u16 BE]
///                      [seq: u64 BE][stream_id: u16 BE][0x05]                     (19 bytes)
/// Probe     : [app_id: u64 BE][proto_ver: u16 BE][0x07]                           (11 bytes)
/// Beacon    : [meta bytes][instance: u64 BE][data_port: u16 BE][proto_ver: u16 BE]
///                         [app_id: u64 BE][0x08]                                  (21 + meta bytes)
/// MtuProbe  : [zeros: padding bytes][probe_id: u16 BE][0x0B]                     (3 + padding bytes)
/// MtuAck    : [probe_id: u16 BE][0x0C]                                            (3 bytes)
/// Handshake : [noise msg][step: u8][version: u8][0x09]                            (3 bytes)
/// Secure    : [ciphertext][nonce: u64 BE][index: u64 BE][0x0A]                   (17 bytes)
/// SessionUnknown : [index: u64 BE][0x0D]                                          (9 bytes)
/// ```
///
/// Relay frames, only ever sent inside a `Secure` frame (a plaintext one is dropped):
///
/// ```text
/// Via          : [inner][to: 32 bytes][0x06]                                      (33 bytes)
/// ViaFrom      : [inner][from: 32 bytes][0x0E]                                    (33 bytes)
/// Unreachable  : [to: 32 bytes][0x0F]                                             (33 bytes)
/// IntroRequest : [peer: 32 bytes][0x10]                                           (33 bytes)
/// Intro(v4)    : [port: u16 BE][ip: 4 bytes][0x00][peer: 32 bytes][0x11]          (40 bytes)
/// Intro(v6)    : [port: u16 BE][ip: 16 bytes][0x01][peer: 32 bytes][0x11]         (52 bytes)
/// ```
///
/// Path validation, only ever sent inside the end-to-end session of a relayed peer:
///
/// ```text
/// PathChallenge : [token: u64 BE][0x12]                                           (9 bytes)
/// PathResponse  : [token: u64 BE][0x13]                                           (9 bytes)
/// ```
///
/// The frame type byte is always last, making parsing O(1) from the tail.
pub(crate) const TYPE_DATAGRAM: u8 = 0x00;
const TYPE_STREAM: u8 = 0x01;
const TYPE_NACK: u8 = 0x02;
const TYPE_PING: u8 = 0x03;
const TYPE_PONG: u8 = 0x04;
const TYPE_FRAGMENT: u8 = 0x05;
#[cfg(feature = "security")]
const TYPE_VIA: u8 = 0x06;
const TYPE_PROBE: u8 = 0x07;
const TYPE_BEACON: u8 = 0x08;
#[cfg(feature = "security")]
pub(crate) const TYPE_HANDSHAKE: u8 = 0x09;
#[cfg(feature = "security")]
const TYPE_SECURE: u8 = 0x0A;
pub(crate) const TYPE_MTU_PROBE: u8 = 0x0B;
const TYPE_MTU_ACK: u8 = 0x0C;
#[cfg(feature = "security")]
const TYPE_SESSION_UNKNOWN: u8 = 0x0D;
#[cfg(feature = "security")]
const TYPE_VIA_FROM: u8 = 0x0E;
#[cfg(feature = "security")]
const TYPE_UNREACHABLE: u8 = 0x0F;
#[cfg(feature = "security")]
const TYPE_INTRO_REQUEST: u8 = 0x10;
#[cfg(feature = "security")]
const TYPE_INTRO: u8 = 0x11;
#[cfg(feature = "security")]
const TYPE_PATH_CHALLENGE: u8 = 0x12;
#[cfg(feature = "security")]
const TYPE_PATH_RESPONSE: u8 = 0x13;

#[cfg(feature = "security")]
const ADDR_V4: u8 = 0x00;
#[cfg(feature = "security")]
const ADDR_V6: u8 = 0x01;

/// Bytes a relayed frame carries on top of a direct one: the `Via` / `ViaFrom` header
/// (key + type) plus the relay session's `Secure` header and AEAD tag.
#[cfg(feature = "security")]
pub(crate) const VIA_OVERHEAD: usize = 33 + 17 + 16;

#[derive(Debug, Clone)]
pub enum Frame {
    /// Unreliable fire-and-forget delivery.
    Datagram(Bytes),
    /// Reliably delivered, in-order payload on a specific stream.
    Stream {
        seq: u64,
        stream_id: u16,
        payload: Bytes,
    },
    /// Negative acknowledgement — request retransmission of the listed sequences on a stream.
    Nack { stream_id: u16, seqs: Vec<u64> },
    /// Keepalive probe.  `session_id` is the sender's own session ID so the receiver can
    /// recognise this peer if it migrates to a new address before the next Ping arrives.
    Ping { echo: u64, session_id: u64 },
    /// Keepalive reply.  `session_id` is the *replier's* session ID.
    Pong { echo: u64, session_id: u64 },
    /// One slice of a fragmented reliable message, on a specific stream.
    Fragment {
        msg_id: u32,
        frag_idx: u16,
        frag_total: u16,
        seq: u64,
        stream_id: u16,
        payload: Bytes,
    },
    /// LAN discovery broadcast — asks nodes with matching `app_id` and `proto_ver` to reply.
    Probe { app_id: u64, proto_ver: u16 },
    /// LAN discovery reply — unicast answer to a `Probe`, carrying the node's data port and metadata.
    Beacon {
        app_id: u64,
        proto_ver: u16,
        data_port: u16,
        /// Random per advertiser start; a new value from the same address means a restart.
        instance: u64,
        meta: Bytes,
    },
    /// One Noise XX handshake message (msg1, msg2, or msg3).
    #[cfg(feature = "security")]
    Handshake {
        /// Noise XX message number: 1 (initiator), 2 (responder), 3 (initiator).
        step: u8,
        /// [`WIRE_VERSION`] of the sender; peers on another version are ignored.
        version: u8,
        payload: Bytes,
    },
    /// Noise-encrypted data frame; `nonce` is the per-send AEAD counter.
    #[cfg(feature = "security")]
    Secure {
        /// Session index the receiver chose during the handshake; finds the session even
        /// when the sender's address changed.
        index: u64,
        nonce: u64,
        ciphertext: Bytes,
    },
    /// "I have no session with this index": the sender lost our session (it restarted).
    /// Unauthenticated, so it only ever prompts a re-handshake.
    #[cfg(feature = "security")]
    SessionUnknown { index: u64 },
    /// Relay request: deliver `inner` to the relay client whose static key is `to`.
    #[cfg(feature = "security")]
    Via { to: [u8; 32], inner: Bytes },
    /// Relay delivery: `inner` came from the relay client the relay says has key `from`.
    /// The claim is only trusted once `inner`'s own end-to-end session proves it.
    #[cfg(feature = "security")]
    ViaFrom { from: [u8; 32], inner: Bytes },
    /// The relay cannot deliver to `to` (offline, or not allowed — deliberately the same).
    #[cfg(feature = "security")]
    Unreachable { to: [u8; 32] },
    /// Ask the relay to introduce us to `peer` for hole punching.
    #[cfg(feature = "security")]
    IntroRequest { peer: [u8; 32] },
    /// The relay's answer to a mutual `IntroRequest`: `peer` is seen at `addr`.
    #[cfg(feature = "security")]
    Intro { peer: [u8; 32], addr: SocketAddr },
    /// "Answer me at the address this came from": sent straight to a candidate direct
    /// address of a relayed peer before any traffic moves there.
    #[cfg(feature = "security")]
    PathChallenge { token: u64 },
    /// Echo of a `PathChallenge`, sent back to the address the challenge came from.
    #[cfg(feature = "security")]
    PathResponse { token: u64 },
    /// PLPMTUD path-MTU probe.  `padding` zero bytes are prepended so the total
    /// datagram is `padding + 3` bytes — the size being probed.
    MtuProbe { probe_id: u16, padding: usize },
    /// PLPMTUD path-MTU acknowledgement.  Always 3 bytes; gets through any path.
    MtuAck { probe_id: u16 },
}

impl Frame {
    #[must_use]
    #[allow(clippy::too_many_lines)]
    pub fn encode(self) -> Bytes {
        match self {
            Frame::Datagram(payload) => {
                let mut buf = BytesMut::with_capacity(payload.len() + 1);
                buf.extend_from_slice(&payload);
                buf.put_u8(TYPE_DATAGRAM);
                buf.freeze()
            }
            Frame::Stream {
                seq,
                stream_id,
                payload,
            } => {
                let mut buf = BytesMut::with_capacity(payload.len() + 11);
                buf.extend_from_slice(&payload);
                buf.put_u64(seq);
                buf.put_u16(stream_id);
                buf.put_u8(TYPE_STREAM);
                buf.freeze()
            }
            Frame::Nack { stream_id, seqs } => {
                let count = seqs.len().min(MAX_NACK_SEQS);
                let mut buf = BytesMut::with_capacity(count * 8 + 3);
                for seq in seqs.iter().take(count) {
                    buf.put_u64(*seq);
                }
                buf.put_u16(stream_id);
                buf.put_u8(TYPE_NACK);
                buf.freeze()
            }
            Frame::Ping { echo, session_id } => {
                let mut buf = BytesMut::with_capacity(17);
                buf.put_u64(echo);
                buf.put_u64(session_id);
                buf.put_u8(TYPE_PING);
                buf.freeze()
            }
            Frame::Pong { echo, session_id } => {
                let mut buf = BytesMut::with_capacity(17);
                buf.put_u64(echo);
                buf.put_u64(session_id);
                buf.put_u8(TYPE_PONG);
                buf.freeze()
            }
            Frame::Fragment {
                msg_id,
                frag_idx,
                frag_total,
                seq,
                stream_id,
                payload,
            } => {
                let mut buf = BytesMut::with_capacity(payload.len() + 19);
                buf.extend_from_slice(&payload);
                buf.put_u32(msg_id);
                buf.put_u16(frag_total);
                buf.put_u16(frag_idx);
                buf.put_u64(seq);
                buf.put_u16(stream_id);
                buf.put_u8(TYPE_FRAGMENT);
                buf.freeze()
            }
            Frame::Probe { app_id, proto_ver } => {
                let mut buf = BytesMut::with_capacity(11);
                buf.put_u64(app_id);
                buf.put_u16(proto_ver);
                buf.put_u8(TYPE_PROBE);
                buf.freeze()
            }
            Frame::Beacon {
                app_id,
                proto_ver,
                data_port,
                instance,
                meta,
            } => {
                let mut buf = BytesMut::with_capacity(meta.len() + 21);
                buf.extend_from_slice(&meta);
                buf.put_u64(instance);
                buf.put_u16(data_port);
                buf.put_u16(proto_ver);
                buf.put_u64(app_id);
                buf.put_u8(TYPE_BEACON);
                buf.freeze()
            }
            #[cfg(feature = "security")]
            Frame::Handshake {
                step,
                version,
                payload,
            } => {
                let mut buf = BytesMut::with_capacity(payload.len() + 3);
                buf.extend_from_slice(&payload);
                buf.put_u8(step);
                buf.put_u8(version);
                buf.put_u8(TYPE_HANDSHAKE);
                buf.freeze()
            }
            #[cfg(feature = "security")]
            Frame::Secure {
                index,
                nonce,
                ciphertext,
            } => {
                let mut buf = BytesMut::with_capacity(ciphertext.len() + 17);
                buf.extend_from_slice(&ciphertext);
                buf.put_u64(nonce);
                buf.put_u64(index);
                buf.put_u8(TYPE_SECURE);
                buf.freeze()
            }
            #[cfg(feature = "security")]
            Frame::SessionUnknown { index } => {
                let mut buf = BytesMut::with_capacity(9);
                buf.put_u64(index);
                buf.put_u8(TYPE_SESSION_UNKNOWN);
                buf.freeze()
            }
            #[cfg(feature = "security")]
            Frame::Via { to, inner } => keyed(&inner, &to, TYPE_VIA),
            #[cfg(feature = "security")]
            Frame::ViaFrom { from, inner } => keyed(&inner, &from, TYPE_VIA_FROM),
            #[cfg(feature = "security")]
            Frame::Unreachable { to } => keyed(&[], &to, TYPE_UNREACHABLE),
            #[cfg(feature = "security")]
            Frame::IntroRequest { peer } => keyed(&[], &peer, TYPE_INTRO_REQUEST),
            #[cfg(feature = "security")]
            Frame::Intro { peer, addr } => {
                let mut buf = BytesMut::with_capacity(52);
                buf.put_u16(addr.port());
                match addr.ip() {
                    IpAddr::V4(ip) => {
                        buf.extend_from_slice(&ip.octets());
                        buf.put_u8(ADDR_V4);
                    }
                    IpAddr::V6(ip) => {
                        buf.extend_from_slice(&ip.octets());
                        buf.put_u8(ADDR_V6);
                    }
                }
                buf.extend_from_slice(&peer);
                buf.put_u8(TYPE_INTRO);
                buf.freeze()
            }
            #[cfg(feature = "security")]
            Frame::PathChallenge { token } => token_frame(token, TYPE_PATH_CHALLENGE),
            #[cfg(feature = "security")]
            Frame::PathResponse { token } => token_frame(token, TYPE_PATH_RESPONSE),
            Frame::MtuProbe { probe_id, padding } => {
                let total = padding + 3;
                let mut buf = BytesMut::zeroed(total);
                let id = probe_id.to_be_bytes();
                buf[total - 3] = id[0];
                buf[total - 2] = id[1];
                buf[total - 1] = TYPE_MTU_PROBE;
                buf.freeze()
            }
            Frame::MtuAck { probe_id } => {
                let mut buf = BytesMut::with_capacity(3);
                buf.put_u16(probe_id);
                buf.put_u8(TYPE_MTU_ACK);
                buf.freeze()
            }
        }
    }

    #[allow(clippy::too_many_lines)]
    pub fn decode(mut data: BytesMut) -> Result<Self, Error> {
        let frame_type = pop_u8(&mut data).ok_or(Error::FrameEmpty)?;

        match frame_type {
            TYPE_DATAGRAM => Ok(Frame::Datagram(data.freeze())),

            TYPE_STREAM => {
                let stream_id = pop_u16(&mut data).ok_or(Error::FrameTruncated {
                    frame: "stream",
                    field: "stream_id",
                })?;
                let seq = pop_u64(&mut data).ok_or(Error::FrameTruncated {
                    frame: "stream",
                    field: "seq",
                })?;
                Ok(Frame::Stream {
                    seq,
                    stream_id,
                    payload: data.freeze(),
                })
            }

            TYPE_NACK => {
                let stream_id = pop_u16(&mut data).ok_or(Error::FrameTruncated {
                    frame: "nack",
                    field: "stream_id",
                })?;
                if !data.len().is_multiple_of(8) {
                    return Err(Error::NackInvalidLength { len: data.len() });
                }
                let seqs = data
                    .chunks(8)
                    .map(|c| u64::from_be_bytes([c[0], c[1], c[2], c[3], c[4], c[5], c[6], c[7]]))
                    .collect();
                Ok(Frame::Nack { stream_id, seqs })
            }

            TYPE_PING => {
                let session_id = pop_u64(&mut data).ok_or(Error::FrameTruncated {
                    frame: "ping",
                    field: "session_id",
                })?;
                let echo = pop_u64(&mut data).ok_or(Error::FrameTruncated {
                    frame: "ping",
                    field: "echo",
                })?;
                Ok(Frame::Ping { echo, session_id })
            }

            TYPE_PONG => {
                let session_id = pop_u64(&mut data).ok_or(Error::FrameTruncated {
                    frame: "pong",
                    field: "session_id",
                })?;
                let echo = pop_u64(&mut data).ok_or(Error::FrameTruncated {
                    frame: "pong",
                    field: "echo",
                })?;
                Ok(Frame::Pong { echo, session_id })
            }

            TYPE_FRAGMENT => {
                // tail-first: stream_id(2) seq(8) frag_idx(2) frag_total(2) msg_id(4)
                let stream_id = pop_u16(&mut data).ok_or(Error::FrameTruncated {
                    frame: "fragment",
                    field: "stream_id",
                })?;
                let seq = pop_u64(&mut data).ok_or(Error::FrameTruncated {
                    frame: "fragment",
                    field: "seq",
                })?;
                let frag_idx = pop_u16(&mut data).ok_or(Error::FrameTruncated {
                    frame: "fragment",
                    field: "frag_idx",
                })?;
                let frag_total = pop_u16(&mut data).ok_or(Error::FrameTruncated {
                    frame: "fragment",
                    field: "frag_total",
                })?;
                let msg_id = pop_u32(&mut data).ok_or(Error::FrameTruncated {
                    frame: "fragment",
                    field: "msg_id",
                })?;
                Ok(Frame::Fragment {
                    msg_id,
                    frag_idx,
                    frag_total,
                    seq,
                    stream_id,
                    payload: data.freeze(),
                })
            }

            TYPE_PROBE => {
                let proto_ver = pop_u16(&mut data).ok_or(Error::FrameTruncated {
                    frame: "probe",
                    field: "proto_ver",
                })?;
                let app_id = pop_u64(&mut data).ok_or(Error::FrameTruncated {
                    frame: "probe",
                    field: "app_id",
                })?;
                Ok(Frame::Probe { app_id, proto_ver })
            }

            TYPE_BEACON => {
                let app_id = pop_u64(&mut data).ok_or(Error::FrameTruncated {
                    frame: "beacon",
                    field: "app_id",
                })?;
                let proto_ver = pop_u16(&mut data).ok_or(Error::FrameTruncated {
                    frame: "beacon",
                    field: "proto_ver",
                })?;
                let data_port = pop_u16(&mut data).ok_or(Error::FrameTruncated {
                    frame: "beacon",
                    field: "data_port",
                })?;
                let instance = pop_u64(&mut data).ok_or(Error::FrameTruncated {
                    frame: "beacon",
                    field: "instance",
                })?;
                Ok(Frame::Beacon {
                    app_id,
                    proto_ver,
                    data_port,
                    instance,
                    meta: data.freeze(),
                })
            }

            #[cfg(feature = "security")]
            TYPE_HANDSHAKE => {
                let version = pop_u8(&mut data).ok_or(Error::FrameTruncated {
                    frame: "handshake",
                    field: "version",
                })?;
                let step = pop_u8(&mut data).ok_or(Error::FrameTruncated {
                    frame: "handshake",
                    field: "step",
                })?;
                Ok(Frame::Handshake {
                    step,
                    version,
                    payload: data.freeze(),
                })
            }

            #[cfg(feature = "security")]
            TYPE_SECURE => {
                let index = pop_u64(&mut data).ok_or(Error::FrameTruncated {
                    frame: "secure",
                    field: "index",
                })?;
                let nonce = pop_u64(&mut data).ok_or(Error::FrameTruncated {
                    frame: "secure",
                    field: "nonce",
                })?;
                Ok(Frame::Secure {
                    index,
                    nonce,
                    ciphertext: data.freeze(),
                })
            }

            #[cfg(feature = "security")]
            TYPE_SESSION_UNKNOWN => {
                let index = pop_u64(&mut data).ok_or(Error::FrameTruncated {
                    frame: "session_unknown",
                    field: "index",
                })?;
                Ok(Frame::SessionUnknown { index })
            }

            #[cfg(feature = "security")]
            TYPE_VIA => {
                let to = pop_key(&mut data, "via")?;
                Ok(Frame::Via {
                    to,
                    inner: data.freeze(),
                })
            }

            #[cfg(feature = "security")]
            TYPE_VIA_FROM => {
                let from = pop_key(&mut data, "via_from")?;
                Ok(Frame::ViaFrom {
                    from,
                    inner: data.freeze(),
                })
            }

            #[cfg(feature = "security")]
            TYPE_UNREACHABLE => Ok(Frame::Unreachable {
                to: pop_key(&mut data, "unreachable")?,
            }),

            #[cfg(feature = "security")]
            TYPE_INTRO_REQUEST => Ok(Frame::IntroRequest {
                peer: pop_key(&mut data, "intro_request")?,
            }),

            #[cfg(feature = "security")]
            TYPE_INTRO => {
                let peer = pop_key(&mut data, "intro")?;
                let ip = match pop_u8(&mut data) {
                    Some(ADDR_V4) => {
                        pop_bytes::<4>(&mut data).map(|ip| IpAddr::from(Ipv4Addr::from(ip)))
                    }
                    Some(ADDR_V6) => {
                        pop_bytes::<16>(&mut data).map(|ip| IpAddr::from(Ipv6Addr::from(ip)))
                    }
                    Some(tag) => return Err(Error::UnknownAddrTag { tag }),
                    None => None,
                };
                let ip = ip.ok_or(Error::FrameTruncated {
                    frame: "intro",
                    field: "ip",
                })?;
                let port = pop_u16(&mut data).ok_or(Error::FrameTruncated {
                    frame: "intro",
                    field: "port",
                })?;
                Ok(Frame::Intro {
                    peer,
                    addr: SocketAddr::new(ip, port),
                })
            }

            #[cfg(feature = "security")]
            TYPE_PATH_CHALLENGE => Ok(Frame::PathChallenge {
                token: pop_u64(&mut data).ok_or(Error::FrameTruncated {
                    frame: "path_challenge",
                    field: "token",
                })?,
            }),

            #[cfg(feature = "security")]
            TYPE_PATH_RESPONSE => Ok(Frame::PathResponse {
                token: pop_u64(&mut data).ok_or(Error::FrameTruncated {
                    frame: "path_response",
                    field: "token",
                })?,
            }),

            TYPE_MTU_PROBE => {
                let probe_id = pop_u16(&mut data).ok_or(Error::FrameTruncated {
                    frame: "mtu_probe",
                    field: "probe_id",
                })?;
                Ok(Frame::MtuProbe {
                    probe_id,
                    padding: data.len(),
                })
            }

            TYPE_MTU_ACK => {
                let probe_id = pop_u16(&mut data).ok_or(Error::FrameTruncated {
                    frame: "mtu_ack",
                    field: "probe_id",
                })?;
                Ok(Frame::MtuAck { probe_id })
            }

            tag => Err(Error::UnknownFrameType { tag }),
        }
    }
}

/// `[token: u64][type]`, the shape of both path validation frames.
#[cfg(feature = "security")]
fn token_frame(token: u64, frame_type: u8) -> Bytes {
    let mut buf = BytesMut::with_capacity(9);
    buf.put_u64(token);
    buf.put_u8(frame_type);
    buf.freeze()
}

/// `[body][key: 32 bytes][type]`, the shape of every relay frame but `Intro`.
#[cfg(feature = "security")]
fn keyed(body: &[u8], key: &[u8; 32], frame_type: u8) -> Bytes {
    let mut buf = BytesMut::with_capacity(body.len() + 33);
    buf.extend_from_slice(body);
    buf.extend_from_slice(key);
    buf.put_u8(frame_type);
    buf.freeze()
}

// --- tail-pop helpers (all frames are encoded tail-first for O(1) type dispatch) ---

fn pop_u8(buf: &mut BytesMut) -> Option<u8> {
    if buf.is_empty() {
        return None;
    }
    let len = buf.len();
    let v = buf[len - 1];
    buf.truncate(len - 1);
    Some(v)
}

fn pop_u16(buf: &mut BytesMut) -> Option<u16> {
    if buf.len() < 2 {
        return None;
    }
    let len = buf.len();
    let v = u16::from_be_bytes([buf[len - 2], buf[len - 1]]);
    buf.truncate(len - 2);
    Some(v)
}

fn pop_u32(buf: &mut BytesMut) -> Option<u32> {
    if buf.len() < 4 {
        return None;
    }
    let len = buf.len();
    let v = u32::from_be_bytes([buf[len - 4], buf[len - 3], buf[len - 2], buf[len - 1]]);
    buf.truncate(len - 4);
    Some(v)
}

fn pop_u64(buf: &mut BytesMut) -> Option<u64> {
    if buf.len() < 8 {
        return None;
    }
    let len = buf.len();
    let v = u64::from_be_bytes([
        buf[len - 8],
        buf[len - 7],
        buf[len - 6],
        buf[len - 5],
        buf[len - 4],
        buf[len - 3],
        buf[len - 2],
        buf[len - 1],
    ]);
    buf.truncate(len - 8);
    Some(v)
}

#[cfg(feature = "security")]
fn pop_bytes<const N: usize>(buf: &mut BytesMut) -> Option<[u8; N]> {
    let start = buf.len().checked_sub(N)?;
    let out = buf[start..].try_into().ok()?;
    buf.truncate(start);
    Some(out)
}

#[cfg(feature = "security")]
fn pop_key(buf: &mut BytesMut, frame: &'static str) -> Result<[u8; 32], Error> {
    pop_bytes::<32>(buf).ok_or(Error::FrameTruncated {
        frame,
        field: "key",
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(frame: Frame) -> Frame {
        let encoded = frame.encode();
        Frame::decode(BytesMut::from(encoded.as_ref())).expect("decode failed")
    }

    #[test]
    fn datagram_roundtrip() {
        let payload = Bytes::from_static(b"hello");
        let Frame::Datagram(out) = roundtrip(Frame::Datagram(payload.clone())) else {
            panic!("wrong variant");
        };
        assert_eq!(out, payload);
    }

    #[test]
    fn stream_roundtrip() {
        let payload = Bytes::from_static(b"reliable data");
        let Frame::Stream {
            seq,
            stream_id,
            payload: out,
        } = roundtrip(Frame::Stream {
            seq: 42,
            stream_id: 3,
            payload: payload.clone(),
        })
        else {
            panic!("wrong variant");
        };
        assert_eq!(seq, 42);
        assert_eq!(stream_id, 3);
        assert_eq!(out, payload);
    }

    #[test]
    fn stream_default_stream_roundtrip() {
        let payload = Bytes::from_static(b"default stream");
        let Frame::Stream { stream_id, .. } = roundtrip(Frame::Stream {
            seq: 1,
            stream_id: 0,
            payload: payload.clone(),
        }) else {
            panic!("wrong variant");
        };
        assert_eq!(stream_id, 0);
    }

    #[test]
    fn nack_roundtrip() {
        let seqs = vec![1u64, 5, 9];
        let Frame::Nack {
            stream_id,
            seqs: out,
        } = roundtrip(Frame::Nack {
            stream_id: 2,
            seqs: seqs.clone(),
        })
        else {
            panic!("wrong variant");
        };
        assert_eq!(stream_id, 2);
        assert_eq!(out, seqs);
    }

    #[test]
    fn fragment_roundtrip() {
        let payload = Bytes::from_static(b"frag chunk");
        let Frame::Fragment {
            msg_id,
            frag_idx,
            frag_total,
            seq,
            stream_id,
            payload: out,
        } = roundtrip(Frame::Fragment {
            msg_id: 7,
            frag_idx: 2,
            frag_total: 5,
            seq: 99,
            stream_id: 1,
            payload: payload.clone(),
        })
        else {
            panic!("wrong variant");
        };
        assert_eq!(msg_id, 7);
        assert_eq!(frag_idx, 2);
        assert_eq!(frag_total, 5);
        assert_eq!(seq, 99);
        assert_eq!(stream_id, 1);
        assert_eq!(out, payload);
    }

    #[test]
    fn probe_roundtrip() {
        let Frame::Probe { app_id, proto_ver } = roundtrip(Frame::Probe {
            app_id: 0xdead_beef_cafe_babe,
            proto_ver: 1,
        }) else {
            panic!("wrong variant");
        };
        assert_eq!(app_id, 0xdead_beef_cafe_babe);
        assert_eq!(proto_ver, 1);
    }

    #[test]
    fn beacon_roundtrip() {
        let meta = Bytes::from_static(b"hello discovery");
        let Frame::Beacon {
            app_id,
            proto_ver,
            data_port,
            instance,
            meta: out_meta,
        } = roundtrip(Frame::Beacon {
            app_id: 0xdead_beef_cafe_babe,
            proto_ver: 1,
            data_port: 7700,
            instance: 42,
            meta: meta.clone(),
        })
        else {
            panic!("wrong variant");
        };
        assert_eq!(app_id, 0xdead_beef_cafe_babe);
        assert_eq!(proto_ver, 1);
        assert_eq!(data_port, 7700);
        assert_eq!(instance, 42);
        assert_eq!(out_meta, meta);
    }

    #[cfg(feature = "security")]
    #[test]
    fn handshake_roundtrip() {
        let payload = Bytes::from_static(b"noise handshake msg");
        let Frame::Handshake {
            step,
            version,
            payload: out,
        } = roundtrip(Frame::Handshake {
            step: 2,
            version: WIRE_VERSION,
            payload: payload.clone(),
        })
        else {
            panic!("wrong variant");
        };
        assert_eq!((step, version, out), (2, WIRE_VERSION, payload));
    }

    #[cfg(feature = "security")]
    #[test]
    fn secure_roundtrip() {
        let ciphertext = Bytes::from_static(b"encrypted data with aead tag xxxx");
        let Frame::Secure {
            index,
            nonce,
            ciphertext: out,
        } = roundtrip(Frame::Secure {
            index: 0x0102_0304_0506_0708,
            nonce: 0xdead_beef_0000_0001,
            ciphertext: ciphertext.clone(),
        })
        else {
            panic!("wrong variant");
        };
        assert_eq!(index, 0x0102_0304_0506_0708);
        assert_eq!(nonce, 0xdead_beef_0000_0001);
        assert_eq!(out, ciphertext);
    }

    #[cfg(feature = "security")]
    #[test]
    fn session_unknown_roundtrip() {
        let Frame::SessionUnknown { index } = roundtrip(Frame::SessionUnknown { index: 99 }) else {
            panic!("wrong variant");
        };
        assert_eq!(index, 99);
    }

    #[cfg(feature = "security")]
    #[test]
    fn relay_frames_roundtrip() {
        let inner = Bytes::from_static(b"opaque inner");
        let Frame::Via { to, inner: out } = roundtrip(Frame::Via {
            to: [7; 32],
            inner: inner.clone(),
        }) else {
            panic!("wrong variant");
        };
        assert_eq!((to, out), ([7; 32], inner.clone()));
        let Frame::ViaFrom { from, inner: out } = roundtrip(Frame::ViaFrom {
            from: [8; 32],
            inner: inner.clone(),
        }) else {
            panic!("wrong variant");
        };
        assert_eq!((from, out), ([8; 32], inner));
        let Frame::Unreachable { to } = roundtrip(Frame::Unreachable { to: [9; 32] }) else {
            panic!("wrong variant");
        };
        assert_eq!(to, [9; 32]);
        let Frame::IntroRequest { peer } = roundtrip(Frame::IntroRequest { peer: [1; 32] }) else {
            panic!("wrong variant");
        };
        assert_eq!(peer, [1; 32]);
        for addr in ["198.51.100.7:4000", "[2001:db8::1]:4001"] {
            let addr: SocketAddr = addr.parse().unwrap();
            let Frame::Intro { peer, addr: out } = roundtrip(Frame::Intro {
                peer: [2; 32],
                addr,
            }) else {
                panic!("wrong variant");
            };
            assert_eq!((peer, out), ([2; 32], addr));
        }
        let Frame::PathChallenge { token } = roundtrip(Frame::PathChallenge { token: 77 }) else {
            panic!("wrong variant");
        };
        assert_eq!(token, 77);
        let Frame::PathResponse { token } = roundtrip(Frame::PathResponse { token: 78 }) else {
            panic!("wrong variant");
        };
        assert_eq!(token, 78);
        let mut short = BytesMut::from(&[0u8; 10][..]);
        short.put_u8(TYPE_VIA);
        assert!(matches!(
            Frame::decode(short),
            Err(Error::FrameTruncated { .. })
        ));
    }

    #[test]
    fn mtu_probe_roundtrip() {
        let Frame::MtuProbe { probe_id, padding } = roundtrip(Frame::MtuProbe {
            probe_id: 0xABCD,
            padding: 1397,
        }) else {
            panic!("wrong variant");
        };
        assert_eq!(probe_id, 0xABCD);
        assert_eq!(padding, 1397);
    }

    #[test]
    fn mtu_probe_size_is_correct() {
        let padding = 1397;
        let encoded = Frame::MtuProbe {
            probe_id: 1,
            padding,
        }
        .encode();
        assert_eq!(encoded.len(), padding + 3);
    }

    #[test]
    fn mtu_ack_roundtrip() {
        let Frame::MtuAck { probe_id } = roundtrip(Frame::MtuAck { probe_id: 42 }) else {
            panic!("wrong variant");
        };
        assert_eq!(probe_id, 42);
    }
}
