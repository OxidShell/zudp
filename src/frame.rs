use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use bytes::{BufMut, Bytes, BytesMut};

use crate::Error;

/// Maximum number of sequence numbers encoded in a single Nack frame.
pub const MAX_NACK_SEQS: usize = 128;

/// Wire format overhead appended after the payload, per frame type:
///
/// ```text
/// Datagram  : [payload][0x00]                                                     (1 byte)
/// Stream    : [payload][seq: u64 BE][stream_id: u16 BE][0x01]                     (11 bytes)
/// Nack      : [seq0: u64 BE]...[stream_id: u16 BE][0x02]                          (3 + N*8 bytes)
/// Ping      : [echo: u64 BE][0x03]                                                (9 bytes)
/// Pong      : [echo: u64 BE][0x04]                                                (9 bytes)
/// Fragment  : [payload][msg_id: u32 BE][frag_total: u16 BE][frag_idx: u16 BE]
///                      [seq: u64 BE][stream_id: u16 BE][0x05]                     (19 bytes)
/// Relay(v4) : [inner][port: u16 BE][ip: 4 bytes][0x00][0x06]                     (8 bytes)
/// Relay(v6) : [inner][port: u16 BE][ip: 16 bytes][0x01][0x06]                    (20 bytes)
/// Probe     : [app_id: u64 BE][proto_ver: u16 BE][0x07]                           (11 bytes)
/// Beacon    : [meta bytes][data_port: u16 BE][proto_ver: u16 BE]
///                         [app_id: u64 BE][0x08]                                  (13 + meta bytes)
/// ```
///
/// The frame type byte is always last, making parsing O(1) from the tail.
pub(crate) const TYPE_DATAGRAM: u8 = 0x00;
const TYPE_STREAM: u8 = 0x01;
const TYPE_NACK: u8 = 0x02;
const TYPE_PING: u8 = 0x03;
const TYPE_PONG: u8 = 0x04;
const TYPE_FRAGMENT: u8 = 0x05;
const TYPE_RELAY: u8 = 0x06;
const TYPE_PROBE: u8 = 0x07;
const TYPE_BEACON: u8 = 0x08;
#[cfg(feature = "security")]
const TYPE_HANDSHAKE: u8 = 0x09;
#[cfg(feature = "security")]
const TYPE_SECURE: u8 = 0x0A;

const ADDR_V4: u8 = 0x00;
const ADDR_V6: u8 = 0x01;

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
    /// Keepalive probe carrying an echo token.
    Ping { echo: u64 },
    /// Keepalive reply mirroring the probe token.
    Pong { echo: u64 },
    /// One slice of a fragmented reliable message, on a specific stream.
    Fragment {
        msg_id: u32,
        frag_idx: u16,
        frag_total: u16,
        seq: u64,
        stream_id: u16,
        payload: Bytes,
    },
    /// Relay request: forward `inner` to `dest` unchanged.
    Relay { dest: SocketAddr, inner: Bytes },
    /// LAN discovery broadcast — asks nodes with matching `app_id` and `proto_ver` to reply.
    Probe { app_id: u64, proto_ver: u16 },
    /// LAN discovery reply — unicast answer to a `Probe`, carrying the node's data port and metadata.
    Beacon {
        app_id: u64,
        proto_ver: u16,
        data_port: u16,
        meta: Bytes,
    },
    /// One Noise XX handshake message (msg1, msg2, or msg3).
    #[cfg(feature = "security")]
    Handshake { payload: Bytes },
    /// Noise-encrypted data frame; `nonce` is the per-send AEAD counter.
    #[cfg(feature = "security")]
    Secure { nonce: u64, ciphertext: Bytes },
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
            Frame::Ping { echo } => {
                let mut buf = BytesMut::with_capacity(9);
                buf.put_u64(echo);
                buf.put_u8(TYPE_PING);
                buf.freeze()
            }
            Frame::Pong { echo } => {
                let mut buf = BytesMut::with_capacity(9);
                buf.put_u64(echo);
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
            Frame::Relay { dest, inner } => {
                let (ip_bytes, addr_tag): (Vec<u8>, u8) = match dest.ip() {
                    IpAddr::V4(ip) => (ip.octets().to_vec(), ADDR_V4),
                    IpAddr::V6(ip) => (ip.octets().to_vec(), ADDR_V6),
                };
                let overhead = 2 + ip_bytes.len() + 2; // port + ip + addr_tag + type
                let mut buf = BytesMut::with_capacity(inner.len() + overhead);
                buf.extend_from_slice(&inner);
                buf.put_u16(dest.port());
                buf.extend_from_slice(&ip_bytes);
                buf.put_u8(addr_tag);
                buf.put_u8(TYPE_RELAY);
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
                meta,
            } => {
                let mut buf = BytesMut::with_capacity(meta.len() + 13);
                buf.extend_from_slice(&meta);
                buf.put_u16(data_port);
                buf.put_u16(proto_ver);
                buf.put_u64(app_id);
                buf.put_u8(TYPE_BEACON);
                buf.freeze()
            }
            #[cfg(feature = "security")]
            Frame::Handshake { payload } => {
                let mut buf = BytesMut::with_capacity(payload.len() + 1);
                buf.extend_from_slice(&payload);
                buf.put_u8(TYPE_HANDSHAKE);
                buf.freeze()
            }
            #[cfg(feature = "security")]
            Frame::Secure { nonce, ciphertext } => {
                let mut buf = BytesMut::with_capacity(ciphertext.len() + 9);
                buf.extend_from_slice(&ciphertext);
                buf.put_u64(nonce);
                buf.put_u8(TYPE_SECURE);
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
                let echo = pop_u64(&mut data).ok_or(Error::FrameTruncated {
                    frame: "ping",
                    field: "echo",
                })?;
                Ok(Frame::Ping { echo })
            }

            TYPE_PONG => {
                let echo = pop_u64(&mut data).ok_or(Error::FrameTruncated {
                    frame: "pong",
                    field: "echo",
                })?;
                Ok(Frame::Pong { echo })
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

            TYPE_RELAY => {
                let addr_tag = pop_u8(&mut data).ok_or(Error::FrameTruncated {
                    frame: "relay",
                    field: "addr_tag",
                })?;
                let dest = match addr_tag {
                    ADDR_V4 => {
                        let ip = pop_bytes::<4>(&mut data).ok_or(Error::FrameTruncated {
                            frame: "relay",
                            field: "ipv4_addr",
                        })?;
                        let port = pop_u16(&mut data).ok_or(Error::FrameTruncated {
                            frame: "relay",
                            field: "port",
                        })?;
                        SocketAddr::new(IpAddr::V4(Ipv4Addr::from(ip)), port)
                    }
                    ADDR_V6 => {
                        let ip = pop_bytes::<16>(&mut data).ok_or(Error::FrameTruncated {
                            frame: "relay",
                            field: "ipv6_addr",
                        })?;
                        let port = pop_u16(&mut data).ok_or(Error::FrameTruncated {
                            frame: "relay",
                            field: "port",
                        })?;
                        SocketAddr::new(IpAddr::V6(Ipv6Addr::from(ip)), port)
                    }
                    tag => return Err(Error::UnknownAddrTag { tag }),
                };
                Ok(Frame::Relay {
                    dest,
                    inner: data.freeze(),
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
                Ok(Frame::Beacon {
                    app_id,
                    proto_ver,
                    data_port,
                    meta: data.freeze(),
                })
            }

            #[cfg(feature = "security")]
            TYPE_HANDSHAKE => Ok(Frame::Handshake {
                payload: data.freeze(),
            }),

            #[cfg(feature = "security")]
            TYPE_SECURE => {
                let nonce = pop_u64(&mut data).ok_or(Error::FrameTruncated {
                    frame: "secure",
                    field: "nonce",
                })?;
                Ok(Frame::Secure {
                    nonce,
                    ciphertext: data.freeze(),
                })
            }

            tag => Err(Error::UnknownFrameType { tag }),
        }
    }
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

fn pop_bytes<const N: usize>(buf: &mut BytesMut) -> Option<[u8; N]> {
    if buf.len() < N {
        return None;
    }
    let len = buf.len();
    let mut out = [0u8; N];
    out.copy_from_slice(&buf[len - N..]);
    buf.truncate(len - N);
    Some(out)
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
    fn relay_ipv4_roundtrip() {
        let dest: SocketAddr = "127.0.0.1:9000".parse().unwrap();
        let inner = Bytes::from_static(b"inner packet");
        let Frame::Relay {
            dest: out_dest,
            inner: out_inner,
        } = roundtrip(Frame::Relay {
            dest,
            inner: inner.clone(),
        })
        else {
            panic!("wrong variant");
        };
        assert_eq!(out_dest, dest);
        assert_eq!(out_inner, inner);
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
            meta: out_meta,
        } = roundtrip(Frame::Beacon {
            app_id: 0xdead_beef_cafe_babe,
            proto_ver: 1,
            data_port: 7700,
            meta: meta.clone(),
        })
        else {
            panic!("wrong variant");
        };
        assert_eq!(app_id, 0xdead_beef_cafe_babe);
        assert_eq!(proto_ver, 1);
        assert_eq!(data_port, 7700);
        assert_eq!(out_meta, meta);
    }

    #[test]
    fn relay_ipv6_roundtrip() {
        let dest: SocketAddr = "[::1]:9001".parse().unwrap();
        let inner = Bytes::from_static(b"v6 inner");
        let Frame::Relay {
            dest: out_dest,
            inner: out_inner,
        } = roundtrip(Frame::Relay {
            dest,
            inner: inner.clone(),
        })
        else {
            panic!("wrong variant");
        };
        assert_eq!(out_dest, dest);
        assert_eq!(out_inner, inner);
    }

    #[cfg(feature = "security")]
    #[test]
    fn handshake_roundtrip() {
        let payload = Bytes::from_static(b"noise handshake msg");
        let Frame::Handshake { payload: out } = roundtrip(Frame::Handshake {
            payload: payload.clone(),
        }) else {
            panic!("wrong variant");
        };
        assert_eq!(out, payload);
    }

    #[cfg(feature = "security")]
    #[test]
    fn secure_roundtrip() {
        let ciphertext = Bytes::from_static(b"encrypted data with aead tag xxxx");
        let Frame::Secure {
            nonce,
            ciphertext: out,
        } = roundtrip(Frame::Secure {
            nonce: 0xdead_beef_0000_0001,
            ciphertext: ciphertext.clone(),
        })
        else {
            panic!("wrong variant");
        };
        assert_eq!(nonce, 0xdead_beef_0000_0001);
        assert_eq!(out, ciphertext);
    }
}
