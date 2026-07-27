use std::{net::SocketAddr, sync::Arc};

use bytes::BytesMut;
use tokio::net::UdpSocket;

const RECV_BUF_LEN: usize = 65_536;

/// Socket-level send and receive buffer sizes (4 MB each).
const SOCK_BUF_SIZE: usize = 4 * 1024 * 1024;

/// Thin wrapper around a tokio [`UdpSocket`] with OS-level buffer tuning applied at bind time.
///
/// Cloning is cheap: both copies share the same underlying file descriptor via [`Arc`].
#[derive(Clone)]
pub struct RawSocket {
    inner: Arc<UdpSocket>,
}

impl RawSocket {
    // Async signature kept for API consistency; no await needed at bind time.
    #[allow(clippy::unused_async)]
    pub async fn bind(addr: SocketAddr) -> Result<Self, crate::Error> {
        let sock = socket2::Socket::new(
            socket2::Domain::for_address(addr),
            socket2::Type::DGRAM,
            Some(socket2::Protocol::UDP),
        )?;
        #[cfg(unix)]
        sock.set_reuse_port(true)?;
        sock.set_reuse_address(true)?;
        sock.set_send_buffer_size(SOCK_BUF_SIZE)?;
        sock.set_recv_buffer_size(SOCK_BUF_SIZE)?;
        sock.set_nonblocking(true)?;
        sock.bind(&socket2::SockAddr::from(addr))?;
        let std_sock: std::net::UdpSocket = sock.into();
        Ok(Self {
            inner: Arc::new(UdpSocket::from_std(std_sock)?),
        })
    }

    #[inline]
    pub async fn send_to(&self, data: &[u8], addr: SocketAddr) -> Result<(), crate::Error> {
        self.inner.send_to(data, addr).await?;
        Ok(())
    }

    pub async fn recv_from(&self) -> Result<(BytesMut, SocketAddr), crate::Error> {
        let mut buf = BytesMut::zeroed(RECV_BUF_LEN);
        let (len, addr) = self.inner.recv_from(&mut buf).await?;
        buf.truncate(len);
        Ok((buf, addr))
    }

    pub fn local_addr(&self) -> Result<SocketAddr, crate::Error> {
        Ok(self.inner.local_addr()?)
    }
}
