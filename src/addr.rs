//! How a remote peer is addressed.

use std::{fmt, net::SocketAddr};

/// Handle for one remote peer.
///
/// Every send, receive, statistic and [`PeerEvent`](crate::PeerEvent) names its peer with
/// this type.
///
/// - [`Direct`](Self::Direct) peers are reached at a UDP address.  The handle follows the
///   peer: after a network migration ([`PeerEvent::Migrated`](crate::PeerEvent::Migrated))
///   the session is addressed by its new address.
/// - [`Relayed`](Self::Relayed) peers are reached by their static public key through a relay
///   node (see [`ZudpSocket::connect_via`](crate::ZudpSocket::connect_via)).  The handle is
///   stable for the whole session, even when hole punching moves the traffic onto a direct
///   path ([`PeerEvent::PathChanged`](crate::PeerEvent::PathChanged)).
///
/// Direct peers keep working through the `SocketAddr` API: every method that takes a peer
/// accepts `impl Into<PeerAddr>`, and a `PeerAddr` compares equal to the `SocketAddr` of a
/// direct peer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum PeerAddr {
    /// A peer reached at this UDP address.
    Direct(SocketAddr),
    /// A peer reached by static public key through the relay node at `relay`.
    Relayed {
        /// The relay node this session was opened through.
        relay: SocketAddr,
        /// The peer's X25519 static public key, proven by the end-to-end handshake.
        key: [u8; 32],
    },
}

impl PeerAddr {
    /// The UDP address of a direct peer; `None` for a relayed one.
    #[must_use]
    pub const fn direct(&self) -> Option<SocketAddr> {
        match self {
            Self::Direct(addr) => Some(*addr),
            Self::Relayed { .. } => None,
        }
    }

    /// The static key a relayed peer is addressed by; `None` for a direct one.
    #[must_use]
    pub const fn key(&self) -> Option<[u8; 32]> {
        match self {
            Self::Direct(_) => None,
            Self::Relayed { key, .. } => Some(*key),
        }
    }

    /// `true` for a peer addressed through a relay node.
    #[must_use]
    pub const fn is_relayed(&self) -> bool {
        matches!(self, Self::Relayed { .. })
    }
}

impl From<SocketAddr> for PeerAddr {
    fn from(addr: SocketAddr) -> Self {
        Self::Direct(addr)
    }
}

impl PartialEq<SocketAddr> for PeerAddr {
    fn eq(&self, other: &SocketAddr) -> bool {
        self.direct() == Some(*other)
    }
}

impl PartialEq<PeerAddr> for SocketAddr {
    fn eq(&self, other: &PeerAddr) -> bool {
        other == self
    }
}

impl fmt::Display for PeerAddr {
    /// A direct peer prints as its address; a relayed one as the first bytes of its key in
    /// hex followed by `@relay`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Direct(addr) => addr.fmt(f),
            Self::Relayed { relay, key } => {
                for byte in &key[..4] {
                    write!(f, "{byte:02x}")?;
                }
                write!(f, "…@{relay}")
            }
        }
    }
}

/// The network path a session's traffic currently takes.  See
/// [`PeerEvent::PathChanged`](crate::PeerEvent::PathChanged).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Path {
    /// Straight to the peer at this address.
    Direct(SocketAddr),
    /// Wrapped in the secure session with the relay node at this address.
    Relayed(SocketAddr),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn direct_compares_with_its_socket_addr() {
        let addr: SocketAddr = "127.0.0.1:9".parse().unwrap();
        assert_eq!(PeerAddr::from(addr), addr);
        assert_eq!(addr, PeerAddr::Direct(addr));
        let relayed = PeerAddr::Relayed {
            relay: addr,
            key: [0xab; 32],
        };
        assert_ne!(relayed, addr);
        assert_eq!(relayed.to_string(), "abababab…@127.0.0.1:9");
    }
}
