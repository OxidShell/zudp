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
    /// Bind a data socket.
    ///
    /// The port is held exclusively: with `SO_REUSEPORT` / `SO_REUSEADDR` a second socket
    /// on the same port (a restarted process while the old one lingers) silently receives
    /// part of the traffic, so neither is set, and Windows gets `SO_EXCLUSIVEADDRUSE`.
    // Async signature kept for API consistency; no await needed at bind time.
    #[allow(clippy::unused_async)]
    pub async fn bind(addr: SocketAddr) -> Result<Self, crate::Error> {
        let sock = socket2::Socket::new(
            socket2::Domain::for_address(addr),
            socket2::Type::DGRAM,
            Some(socket2::Protocol::UDP),
        )?;
        #[cfg(windows)]
        win::exclusive_addr_use(&sock)?;
        sock.set_send_buffer_size(SOCK_BUF_SIZE)?;
        sock.set_recv_buffer_size(SOCK_BUF_SIZE)?;
        sock.set_nonblocking(true)?;
        sock.bind(&socket2::SockAddr::from(addr))?;
        #[cfg(windows)]
        win::disable_udp_connreset(&sock)?;
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
    pub async fn recv_from(&self) -> Result<(BytesMut, SocketAddr), std::io::Error> {
        let mut buf = BytesMut::with_capacity(RECV_BUF_LEN);
        let (_, addr) = self.inner.recv_buf_from(&mut buf).await?;
        Ok((buf, addr))
    }

    pub fn local_addr(&self) -> Result<SocketAddr, crate::Error> {
        Ok(self.inner.local_addr()?)
    }
}

/// `true` for receive errors that say something about one remote, not about our socket.
///
/// An ICMP port-unreachable from a peer that went away surfaces as `ConnectionReset` on
/// Windows and `ConnectionRefused` on some platforms; the socket itself is still fine.
pub fn is_transient_recv_error(e: &std::io::Error) -> bool {
    use std::io::ErrorKind;
    matches!(
        e.kind(),
        ErrorKind::ConnectionReset
            | ErrorKind::ConnectionRefused
            | ErrorKind::ConnectionAborted
            | ErrorKind::Interrupted
            | ErrorKind::WouldBlock
            | ErrorKind::TimedOut
            | ErrorKind::HostUnreachable
            | ErrorKind::NetworkUnreachable
            | ErrorKind::NetworkDown
    )
}

#[cfg(windows)]
pub(crate) mod win {
    use std::os::windows::io::AsRawSocket;

    use windows_sys::Win32::Networking::WinSock::{
        SIO_UDP_CONNRESET, SO_EXCLUSIVEADDRUSE, SOCKET, SOCKET_ERROR, SOL_SOCKET, WSAIoctl,
        setsockopt,
    };

    #[allow(clippy::cast_possible_truncation)]
    fn raw(sock: &socket2::Socket) -> SOCKET {
        // A Windows SOCKET is pointer-sized; `as_raw_socket` widens it to u64.
        sock.as_raw_socket() as SOCKET
    }

    #[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
    /// Refuse to share the port with any other socket.
    pub fn exclusive_addr_use(sock: &socket2::Socket) -> std::io::Result<()> {
        let on: i32 = 1;
        // SAFETY: `on` outlives the call and the length matches its size.
        let rc = unsafe {
            setsockopt(
                raw(sock),
                SOL_SOCKET,
                SO_EXCLUSIVEADDRUSE,
                (&raw const on).cast(),
                size_of::<i32>() as i32,
            )
        };
        if rc == SOCKET_ERROR {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }

    #[allow(clippy::cast_possible_truncation)]
    /// Stop Windows from reporting ICMP port-unreachable as `WSAECONNRESET` on `recv_from`.
    ///
    /// Without this, one peer going away makes every later receive on the shared socket
    /// fail until something else is received.
    pub fn disable_udp_connreset(sock: &socket2::Socket) -> std::io::Result<()> {
        let off: u32 = 0;
        let mut returned: u32 = 0;
        // SAFETY: the in-buffer is a live u32, no out-buffer, synchronous (no OVERLAPPED).
        let rc = unsafe {
            WSAIoctl(
                raw(sock),
                SIO_UDP_CONNRESET,
                (&raw const off).cast(),
                size_of::<u32>() as u32,
                std::ptr::null_mut(),
                0,
                &raw mut returned,
                std::ptr::null_mut(),
                None,
            )
        };
        if rc == SOCKET_ERROR {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }
}
