use std::{fmt, net::SocketAddr};

// cfg shorthand: "exactly one codec active"
// bitcode-only: all(feature = "bitcode", not(feature = "serde"))
// serde-only:   all(feature = "serde",   not(feature = "bitcode"))
// both/neither: the complement — handled by the fallback Box variants

#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),

    // encode is infallible (bitcode::encode returns Vec<u8>), so no Encode here.
    #[cfg(all(feature = "bitcode", not(feature = "serde")))]
    Decode(bitcode::Error),

    #[cfg(all(feature = "serde", not(feature = "bitcode")))]
    Encode(postcard::Error),

    #[cfg(all(feature = "serde", not(feature = "bitcode")))]
    Decode(postcard::Error),

    // Preserves the source error without stringly-typing it.
    #[cfg(not(any(
        all(feature = "bitcode", not(feature = "serde")),
        all(feature = "serde", not(feature = "bitcode")),
    )))]
    Encode(Box<dyn std::error::Error + Send + Sync + 'static>),

    #[cfg(not(any(
        all(feature = "bitcode", not(feature = "serde")),
        all(feature = "serde", not(feature = "bitcode")),
    )))]
    Decode(Box<dyn std::error::Error + Send + Sync + 'static>),

    ChannelClosed,
    /// The engine task stopped unexpectedly.  `reason` explains why.
    EngineStopped {
        reason: String,
    },
    MessageTooLarge {
        got: usize,
        max: usize,
    },
    UnknownRelay(SocketAddr),
    /// Packet had no bytes — frame type byte is missing.
    FrameEmpty,
    /// Packet was cut short: a required field was absent.
    FrameTruncated {
        frame: &'static str,
        field: &'static str,
    },
    /// Nack body length is not a multiple of 8.
    NackInvalidLength {
        len: usize,
    },
    /// Relay address-family tag was neither 0x00 (v4) nor 0x01 (v6).
    UnknownAddrTag {
        tag: u8,
    },
    /// Frame type byte did not match any known variant.
    UnknownFrameType {
        tag: u8,
    },
    /// Noise protocol error (handshake or AEAD failure).
    #[cfg(feature = "security")]
    Security(snow::Error),

    /// Remote's X25519 key didn't match the pinned key.
    #[cfg(feature = "security")]
    KeyMismatch,

    /// Packet dropped — source IP exceeded configured rate limit.
    Throttled,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "I/O: {e}"),

            #[cfg(all(feature = "bitcode", not(feature = "serde")))]
            Self::Decode(e) => write!(f, "decode: {e}"),

            #[cfg(all(feature = "serde", not(feature = "bitcode")))]
            Self::Encode(e) => write!(f, "encode: {e}"),
            #[cfg(all(feature = "serde", not(feature = "bitcode")))]
            Self::Decode(e) => write!(f, "decode: {e}"),

            #[cfg(not(any(
                all(feature = "bitcode", not(feature = "serde")),
                all(feature = "serde", not(feature = "bitcode")),
            )))]
            Self::Encode(e) => write!(f, "encode: {e}"),
            #[cfg(not(any(
                all(feature = "bitcode", not(feature = "serde")),
                all(feature = "serde", not(feature = "bitcode")),
            )))]
            Self::Decode(e) => write!(f, "decode: {e}"),

            Self::ChannelClosed => f.write_str("channel closed"),
            Self::EngineStopped { reason } => write!(f, "engine stopped: {reason}"),
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
            #[cfg(feature = "security")]
            Self::Security(e) => write!(f, "security: {e}"),
            #[cfg(feature = "security")]
            Self::KeyMismatch => f.write_str("security: remote key does not match pinned key"),
            Self::Throttled => f.write_str("packet dropped: rate limit exceeded"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),

            #[cfg(all(feature = "bitcode", not(feature = "serde")))]
            Self::Decode(e) => Some(e),

            #[cfg(all(feature = "serde", not(feature = "bitcode")))]
            Self::Encode(e) => Some(e),
            #[cfg(all(feature = "serde", not(feature = "bitcode")))]
            Self::Decode(e) => Some(e),

            #[cfg(not(any(
                all(feature = "bitcode", not(feature = "serde")),
                all(feature = "serde", not(feature = "bitcode")),
            )))]
            Self::Encode(e) => Some(e.as_ref()),
            #[cfg(not(any(
                all(feature = "bitcode", not(feature = "serde")),
                all(feature = "serde", not(feature = "bitcode")),
            )))]
            Self::Decode(e) => Some(e.as_ref()),

            #[cfg(feature = "security")]
            Self::Security(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

#[cfg(feature = "security")]
impl From<snow::Error> for Error {
    fn from(e: snow::Error) -> Self {
        Self::Security(e)
    }
}
