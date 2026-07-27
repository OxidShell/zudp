use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use bytes::{BufMut, Bytes, BytesMut};

use crate::Error;

/// Maximum number of sequence numbers encoded in a single Nack frame.
pub const MAX_NACK_SEQS: usize = 128;

/// Wire format overhead appended after the payload, per frame type:
///
/// ```text
/// Datagram  : [payload][0x00]                                          (1 byte)
/// Stream    : [payload][seq: u64 BE][0x01]                             (9 bytes)
/// Nack      : [seq0: u64 BE]...[0x02]                                  (no payload)
/// Ping      : [echo: u64 BE][0x03]                                     (9 bytes)
/// Pong      : [echo: u64 BE][0x04]                                     (9 bytes)
/// Fragment  : [payload][msg_id: u32 BE][frag_total: u16 BE]
///                      [frag_idx: u16 BE][seq: u64 BE][0x05]           (17 bytes)
/// Relay(v4) : [inner][port: u16 BE][ip: 4 bytes][0x00][0x06]          (8 bytes)
/// Relay(v6) : [inner][port: u16 BE][ip: 16 bytes][0x01][0x06]         (20 bytes)
/// ```
///
/// The frame type byte is always last, making parsing O(1) from the tail.
const TYPE_DATAGRAM: u8 = 0x00;
const TYPE_STREAM: u8 = 0x01;
const TYPE_NACK: u8 = 0x02;
const TYPE_PING: u8 = 0x03;
const TYPE_PONG: u8 = 0x04;
const TYPE_FRAGMENT: u8 = 0x05;
const TYPE_RELAY: u8 = 0x06;

const ADDR_V4: u8 = 0x00;
const ADDR_V6: u8 = 0x01;

#[derive(Debug, Clone)]
pub enum Frame {
    /// Unreliable fire-and-forget delivery.
    Datagram(Bytes),
    /// Reliably delivered, ordered payload with a sequence number.
    Stream { seq: u64, payload: Bytes },
    /// Negative acknowledgement — request retransmission of the listed sequences.
    Nack(Vec<u64>),
    /// Keepalive probe carrying an echo token.
    Ping { echo: u64 },
    /// Keepalive reply mirroring the probe token.
    Pong { echo: u64 },
    /// One slice of a fragmented reliable message.
    Fragment {
        msg_id: u32,
        frag_idx: u16,
        frag_total: u16,
        seq: u64,
        payload: Bytes,
    },
    /// Relay request: forward `inner` to `dest` unchanged.
    Relay { dest: SocketAddr, inner: Bytes },
}

impl Frame {
    #[must_use]
    pub fn encode(self) -> Bytes {
        match self {
            Frame::Datagram(payload) => {
                let mut buf = BytesMut::with_capacity(payload.len() + 1);
                buf.extend_from_slice(&payload);
                buf.put_u8(TYPE_DATAGRAM);
                buf.freeze()
            }
            Frame::Stream { seq, payload } => {
                let mut buf = BytesMut::with_capacity(payload.len() + 9);
                buf.extend_from_slice(&payload);
                buf.put_u64(seq);
                buf.put_u8(TYPE_STREAM);
                buf.freeze()
            }
            Frame::Nack(seqs) => {
                let count = seqs.len().min(MAX_NACK_SEQS);
                let mut buf = BytesMut::with_capacity(count * 8 + 1);
                for seq in seqs.iter().take(count) {
                    buf.put_u64(*seq);
                }
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
                payload,
            } => {
                let mut buf = BytesMut::with_capacity(payload.len() + 17);
                buf.extend_from_slice(&payload);
                buf.put_u32(msg_id);
                buf.put_u16(frag_total);
                buf.put_u16(frag_idx);
                buf.put_u64(seq);
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
        }
    }

    pub fn decode(mut data: BytesMut) -> Result<Self, Error> {
        let frame_type =
            pop_u8(&mut data).ok_or_else(|| Error::InvalidFrame("empty packet".into()))?;

        match frame_type {
            TYPE_DATAGRAM => Ok(Frame::Datagram(data.freeze())),

            TYPE_STREAM => {
                let seq = pop_u64(&mut data)
                    .ok_or_else(|| Error::InvalidFrame("stream: missing seq".into()))?;
                Ok(Frame::Stream {
                    seq,
                    payload: data.freeze(),
                })
            }

            TYPE_NACK => {
                if !data.len().is_multiple_of(8) {
                    return Err(Error::InvalidFrame(
                        "nack: length not a multiple of 8".into(),
                    ));
                }
                let seqs = data
                    .chunks(8)
                    .map(|c| u64::from_be_bytes([c[0], c[1], c[2], c[3], c[4], c[5], c[6], c[7]]))
                    .collect();
                Ok(Frame::Nack(seqs))
            }

            TYPE_PING => {
                let echo = pop_u64(&mut data)
                    .ok_or_else(|| Error::InvalidFrame("ping: missing echo".into()))?;
                Ok(Frame::Ping { echo })
            }

            TYPE_PONG => {
                let echo = pop_u64(&mut data)
                    .ok_or_else(|| Error::InvalidFrame("pong: missing echo".into()))?;
                Ok(Frame::Pong { echo })
            }

            TYPE_FRAGMENT => {
                // layout (reading tail-first): seq(8) frag_idx(2) frag_total(2) msg_id(4)
                let seq = pop_u64(&mut data)
                    .ok_or_else(|| Error::InvalidFrame("fragment: missing seq".into()))?;
                let frag_idx = pop_u16(&mut data)
                    .ok_or_else(|| Error::InvalidFrame("fragment: missing frag_idx".into()))?;
                let frag_total = pop_u16(&mut data)
                    .ok_or_else(|| Error::InvalidFrame("fragment: missing frag_total".into()))?;
                let msg_id = pop_u32(&mut data)
                    .ok_or_else(|| Error::InvalidFrame("fragment: missing msg_id".into()))?;
                Ok(Frame::Fragment {
                    msg_id,
                    frag_idx,
                    frag_total,
                    seq,
                    payload: data.freeze(),
                })
            }

            TYPE_RELAY => {
                let addr_tag = pop_u8(&mut data)
                    .ok_or_else(|| Error::InvalidFrame("relay: missing addr tag".into()))?;
                let dest = match addr_tag {
                    ADDR_V4 => {
                        let ip = pop_bytes::<4>(&mut data)
                            .ok_or_else(|| Error::InvalidFrame("relay: missing IPv4".into()))?;
                        let port = pop_u16(&mut data)
                            .ok_or_else(|| Error::InvalidFrame("relay: missing port".into()))?;
                        SocketAddr::new(IpAddr::V4(Ipv4Addr::from(ip)), port)
                    }
                    ADDR_V6 => {
                        let ip = pop_bytes::<16>(&mut data)
                            .ok_or_else(|| Error::InvalidFrame("relay: missing IPv6".into()))?;
                        let port = pop_u16(&mut data)
                            .ok_or_else(|| Error::InvalidFrame("relay: missing port".into()))?;
                        SocketAddr::new(IpAddr::V6(Ipv6Addr::from(ip)), port)
                    }
                    t => {
                        return Err(Error::InvalidFrame(format!(
                            "relay: unknown addr tag 0x{t:02x}"
                        )));
                    }
                };
                Ok(Frame::Relay {
                    dest,
                    inner: data.freeze(),
                })
            }

            t => Err(Error::InvalidFrame(format!("unknown frame type 0x{t:02x}"))),
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
        let Frame::Stream { seq, payload: out } = roundtrip(Frame::Stream {
            seq: 42,
            payload: payload.clone(),
        }) else {
            panic!("wrong variant");
        };
        assert_eq!(seq, 42);
        assert_eq!(out, payload);
    }

    #[test]
    fn nack_roundtrip() {
        let seqs = vec![1u64, 5, 9];
        let Frame::Nack(out) = roundtrip(Frame::Nack(seqs.clone())) else {
            panic!("wrong variant");
        };
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
            payload: out,
        } = roundtrip(Frame::Fragment {
            msg_id: 7,
            frag_idx: 2,
            frag_total: 5,
            seq: 99,
            payload: payload.clone(),
        })
        else {
            panic!("wrong variant");
        };
        assert_eq!(msg_id, 7);
        assert_eq!(frag_idx, 2);
        assert_eq!(frag_total, 5);
        assert_eq!(seq, 99);
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
}
