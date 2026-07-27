use std::{net::SocketAddr, sync::Arc};

use bytes::BytesMut;
use tokio::{io::Interest, net::UdpSocket};

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

    /// Send scatter-gather buffers to `addr` in a single syscall (no payload copy).
    pub async fn send_to_vectored(
        &self,
        bufs: &[std::io::IoSlice<'_>],
        addr: SocketAddr,
    ) -> Result<(), crate::Error> {
        let sock_addr = socket2::SockAddr::from(addr);
        loop {
            self.inner.writable().await?;
            match self.inner.try_io(Interest::WRITABLE, || {
                socket2::SockRef::from(&*self.inner).send_to_vectored(bufs, &sock_addr)
            }) {
                Ok(_) => return Ok(()),
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(e) => return Err(e.into()),
            }
        }
    }

    /// Receive into a fresh buffer without zero-initialising it first.
    ///
    /// `recv_buf_from` uses `ReadBuf` internally, which writes only into uninit
    /// spare capacity and marks exactly the received bytes as initialised.
    pub async fn recv_from(&self) -> Result<(BytesMut, SocketAddr), crate::Error> {
        let mut buf = BytesMut::with_capacity(RECV_BUF_LEN);
        let (_, addr) = self.inner.recv_buf_from(&mut buf).await?;
        Ok((buf, addr))
    }

    pub fn local_addr(&self) -> Result<SocketAddr, crate::Error> {
        Ok(self.inner.local_addr()?)
    }
}
