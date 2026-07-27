use std::{fmt, net::SocketAddr};

#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    Encode(Box<dyn std::error::Error + Send + Sync + 'static>),
    Decode(Box<dyn std::error::Error + Send + Sync + 'static>),
    ChannelClosed,
    MessageTooLarge { got: usize, max: usize },
    UnknownRelay(SocketAddr),
    /// Packet had no bytes at all — frame type byte is missing.
    FrameEmpty,
    /// Packet was cut short: a required field was not present.
    FrameTruncated { frame: &'static str, field: &'static str },
    /// Nack body length is not a multiple of 8.
    NackInvalidLength { len: usize },
    /// Relay address-family tag was not 0x00 (v4) or 0x01 (v6).
    UnknownAddrTag { tag: u8 },
    /// Frame type byte did not match any known variant.
    UnknownFrameType { tag: u8 },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "I/O: {e}"),
            Self::Encode(e) => write!(f, "encode: {e}"),
            Self::Decode(e) => write!(f, "decode: {e}"),
            Self::ChannelClosed => f.write_str("channel closed — engine stopped"),
            Self::MessageTooLarge { got, max } => {
                write!(f, "message needs {got} fragments, max is {max}")
            }
            Self::UnknownRelay(addr) => write!(f, "no route to relay {addr}"),
            Self::FrameEmpty => f.write_str("frame parse: empty packet"),
            Self::FrameTruncated { frame, field } => {
                write!(f, "frame parse: {frame} missing `{field}`")
            }
            Self::NackInvalidLength { len } => {
                write!(f, "frame parse: nack body {len} B is not a multiple of 8")
            }
            Self::UnknownAddrTag { tag } => {
                write!(f, "frame parse: unknown relay addr tag 0x{tag:02x}")
            }
            Self::UnknownFrameType { tag } => {
                write!(f, "frame parse: unknown frame type 0x{tag:02x}")
            }
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            Self::Encode(e) | Self::Decode(e) => Some(e.as_ref()),
            _ => None,
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}
