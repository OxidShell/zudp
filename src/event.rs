//! Peer lifecycle notifications.

use std::net::SocketAddr;

use tokio::sync::broadcast;

use crate::Error;

/// Events buffered per subscriber before the oldest are dropped.
pub(crate) const EVENT_CAPACITY: usize = 256;

/// Something happened to a remote peer.
///
/// Subscribe with [`ZudpSocket::events`](crate::ZudpSocket::events),
/// [`ZudpConn::events`](crate::ZudpConn::events) or
/// [`ZudpSender::events`](crate::ZudpSender::events).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum PeerEvent {
    /// A new session with `addr` exists: the Noise handshake finished, or (without
    /// security) the first frame arrived from that address.  `key` is the remote's static
    /// public key when security is on.
    Connected {
        addr: SocketAddr,
        key: Option<[u8; 32]>,
    },
    /// The remote at `addr` restarted or re-handshook; all per-peer state was discarded and a
    /// fresh session replaced it.  Anything in flight on the old session is gone.
    Reset {
        addr: SocketAddr,
        key: Option<[u8; 32]>,
    },
    /// The same session is now reachable at `to` (NAT rebinding, Wi-Fi switch, new IP).
    Migrated { from: SocketAddr, to: SocketAddr },
    /// The peer at `addr` is gone and its state was dropped.
    Disconnected {
        addr: SocketAddr,
        reason: DisconnectReason,
    },
}

/// Why a [`PeerEvent::Disconnected`] was emitted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DisconnectReason {
    /// Nothing was received for the configured peer timeout.
    TimedOut,
    /// [`remove_peer`](crate::ZudpSocket::remove_peer) was called.
    Removed,
    /// The peer table was full and this was the least recently seen peer.
    Evicted,
}

/// A subscription to [`PeerEvent`]s.
///
/// Each subscriber sees every event emitted after it subscribed.  A subscriber that falls
/// more than 256 events behind skips the oldest ones (logged as a warning).
pub struct PeerEvents {
    pub(crate) rx: broadcast::Receiver<PeerEvent>,
}

impl PeerEvents {
    /// Wait for the next event.
    ///
    /// # Errors
    /// [`Error::EngineStopped`] once the socket is gone.
    pub async fn recv(&mut self) -> Result<PeerEvent, Error> {
        loop {
            match self.rx.recv().await {
                Ok(event) => return Ok(event),
                Err(broadcast::error::RecvError::Lagged(skipped)) => {
                    tracing::warn!(target: "zudp", skipped, "peer event subscriber lagged");
                }
                Err(broadcast::error::RecvError::Closed) => {
                    return Err(Error::EngineStopped {
                        reason: "socket closed".into(),
                    });
                }
            }
        }
    }

    /// The next event if one is already queued.
    #[must_use]
    pub fn try_recv(&mut self) -> Option<PeerEvent> {
        loop {
            match self.rx.try_recv() {
                Ok(event) => return Some(event),
                Err(broadcast::error::TryRecvError::Lagged(_)) => {}
                Err(_) => return None,
            }
        }
    }
}
