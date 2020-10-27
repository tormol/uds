use std::os::unix::io::{RawFd, AsRawFd, FromRawFd, IntoRawFd};
use std::os::unix::net::{UnixStream, UnixListener, UnixDatagram};
use std::io::{self, IoSlice, IoSliceMut};

use libc::SOCK_STREAM;

use crate::addr::UnixSocketAddr;
use crate::helpers::*;
use crate::ancillary::*;
use crate::credentials::*;

pub trait UnixStreamExt: AsRawFd + FromRawFd + Sized {
    fn local_unix_addr(&self) -> Result<UnixSocketAddr, io::Error> {
        get_unix_addr(self.as_raw_fd(), GetAddr::LOCAL)
    }
    fn peer_unix_addr(&self) -> Result<UnixSocketAddr, io::Error> {
        get_unix_addr(self.as_raw_fd(), GetAddr::PEER)
    }

    fn connect_to_unix_addr(addr: &UnixSocketAddr) -> Result<Self, io::Error>;
    fn connect_from_to_unix_addr(from: &UnixSocketAddr,  to: &UnixSocketAddr)
    -> Result<Self, io::Error>;

    fn send_fds(&self,  bytes: &[u8],  fds: &[RawFd]) -> Result<usize, io::Error> {
        send_ancillary(self.as_raw_fd(), None, 0, &[IoSlice::new(bytes)], fds, None)
    }
    fn recv_fds(&self,  buf: &mut[u8],  fd_buf: &mut[RawFd]) -> Result<(usize, usize), io::Error> {
        recv_fds(self.as_raw_fd(), None, &mut[IoSliceMut::new(buf)], fd_buf)
            .map(|(bytes, _, fds)| (bytes, fds) )
    }

    fn initial_peer_credentials(&self) -> Result<ConnCredentials, io::Error> {
        peer_credentials(self.as_raw_fd())
    }
}

impl UnixStreamExt for UnixStream {
    fn connect_to_unix_addr(addr: &UnixSocketAddr) -> Result<Self, io::Error> {
        let socket = Socket::new(SOCK_STREAM, false)?;
        set_unix_addr(socket.as_raw_fd(), SetAddr::PEER, addr)?;
        Ok(unsafe { Self::from_raw_fd(socket.into_raw_fd()) })
    }
    fn connect_from_to_unix_addr(from: &UnixSocketAddr,  to: &UnixSocketAddr)
    -> Result<Self, io::Error> {
        let socket = Socket::new(SOCK_STREAM, false)?;
        set_unix_addr(socket.as_raw_fd(), SetAddr::LOCAL, from)?;
        set_unix_addr(socket.as_raw_fd(), SetAddr::PEER, to)?;
        Ok(unsafe { Self::from_raw_fd(socket.into_raw_fd()) })
    }
}

#[cfg(feature="mio-uds")]
impl UnixStreamExt for mio_uds::UnixStream {
    fn connect_to_unix_addr(addr: &UnixSocketAddr) -> Result<Self, io::Error> {
        let socket = Socket::new(SOCK_STREAM, true)?;
        set_unix_addr(socket.as_raw_fd(), SetAddr::PEER, addr)?;
        Ok(unsafe { Self::from_raw_fd(socket.into_raw_fd()) })
    }
    fn connect_from_to_unix_addr(from: &UnixSocketAddr,  to: &UnixSocketAddr)
    -> Result<Self, io::Error> {
        let socket = Socket::new(SOCK_STREAM, true)?;
        set_unix_addr(socket.as_raw_fd(), SetAddr::LOCAL, from)?;
        set_unix_addr(socket.as_raw_fd(), SetAddr::PEER, to)?;
        Ok(unsafe { Self::from_raw_fd(socket.into_raw_fd()) })
    }
}

#[cfg(feature="mio_07")]
impl UnixStreamExt for mio_07::net::UnixStream {
    fn connect_to_unix_addr(addr: &UnixSocketAddr) -> Result<Self, io::Error> {
        let socket = Socket::new(SOCK_STREAM, true)?;
        set_unix_addr(socket.as_raw_fd(), SetAddr::PEER, addr)?;
        Ok(unsafe { Self::from_raw_fd(socket.into_raw_fd()) })
    }
    fn connect_from_to_unix_addr(from: &UnixSocketAddr,  to: &UnixSocketAddr)
    -> Result<Self, io::Error> {
        let socket = Socket::new(SOCK_STREAM, true)?;
        set_unix_addr(socket.as_raw_fd(), SetAddr::LOCAL, from)?;
        set_unix_addr(socket.as_raw_fd(), SetAddr::PEER, to)?;
        Ok(unsafe { Self::from_raw_fd(socket.into_raw_fd()) })
    }
}



/// Extension trait for using [`UnixSocketAddr`](struct.UnixSocketAddr.html) with `UnixListener` types.
pub trait UnixListenerExt: AsRawFd + FromRawFd + Sized {
    type Conn: FromRawFd;

    /// Create a socket bound to a `UnixSocketAddr` and start listening on it.
    fn bind_unix_addr(on: &UnixSocketAddr) -> Result<Self, io::Error>;

    /// Get the address this socket is listening on.
    fn local_unix_addr(&self) -> Result<UnixSocketAddr, io::Error> {
        get_unix_addr(self.as_raw_fd(), GetAddr::LOCAL)
    }

    /// Accept a connection and return the client's address as
    /// an `uds::UnixSocketAddr`.
    fn accept_unix_addr(&self) -> Result<(Self::Conn, UnixSocketAddr), io::Error>;
}

impl UnixListenerExt for UnixListener {
    type Conn = UnixStream;

    fn bind_unix_addr(on: &UnixSocketAddr) -> Result<Self, io::Error> {
        let socket = Socket::new(SOCK_STREAM, false)?;
        set_unix_addr(socket.as_raw_fd(), SetAddr::LOCAL, on)?;
        socket.start_listening()?;
        Ok(unsafe { Self::from_raw_fd(socket.into_raw_fd()) })
    }

    fn accept_unix_addr(&self) -> Result<(Self::Conn, UnixSocketAddr), io::Error> {
        let (socket, addr) = Socket::accept_from(self.as_raw_fd(), false)?;
        let conn = unsafe { Self::Conn::from_raw_fd(socket.into_raw_fd()) };
        Ok((conn, addr))
    }
}

#[cfg(feature="mio-uds")]
impl UnixListenerExt for mio_uds::UnixListener {
    type Conn = mio_uds::UnixStream;

    fn bind_unix_addr(on: &UnixSocketAddr) -> Result<Self, io::Error> {
        let socket = Socket::new(SOCK_STREAM, true)?;
        set_unix_addr(socket.as_raw_fd(), SetAddr::LOCAL, on)?;
        socket.start_listening()?;
        Ok(unsafe { Self::from_raw_fd(socket.into_raw_fd()) })
    }

    fn accept_unix_addr(&self) -> Result<(Self::Conn, UnixSocketAddr), io::Error> {
        let (socket, addr) = Socket::accept_from(self.as_raw_fd(), true)?;
        let conn = unsafe { Self::Conn::from_raw_fd(socket.into_raw_fd()) };
        Ok((conn, addr))
    }
}

#[cfg(feature="mio_07")]
impl UnixListenerExt for mio_07::net::UnixListener {
    type Conn = mio_07::net::UnixStream;

    fn bind_unix_addr(on: &UnixSocketAddr) -> Result<Self, io::Error> {
        let socket = Socket::new(SOCK_STREAM, true)?;
        set_unix_addr(socket.as_raw_fd(), SetAddr::LOCAL, on)?;
        socket.start_listening()?;
        Ok(unsafe { Self::from_raw_fd(socket.into_raw_fd()) })
    }

    fn accept_unix_addr(&self) -> Result<(Self::Conn, UnixSocketAddr), io::Error> {
        let (socket, addr) = Socket::accept_from(self.as_raw_fd(), true)?;
        let conn = unsafe { Self::Conn::from_raw_fd(socket.into_raw_fd()) };
        Ok((conn, addr))
    }
}



pub trait UnixDatagramExt: AsRawFd + FromRawFd + Sized {
    fn local_unix_addr(&self) -> Result<UnixSocketAddr, io::Error> {
        get_unix_addr(self.as_raw_fd(), GetAddr::LOCAL)
    }
    fn peer_unix_addr(&self) -> Result<UnixSocketAddr, io::Error> {
        get_unix_addr(self.as_raw_fd(), GetAddr::PEER)
    }

    fn bind_to_unix_addr(&self,  addr: &UnixSocketAddr) -> Result<(), io::Error> {
        set_unix_addr(self.as_raw_fd(), SetAddr::LOCAL, addr)
    }
    fn connect_to_unix_addr(&self,  addr: &UnixSocketAddr) -> Result<(), io::Error> {
        set_unix_addr(self.as_raw_fd(), SetAddr::PEER, addr)
    }

    fn send_fds_to(&self,  datagram: &[u8],  fds: &[RawFd],  addr: &UnixSocketAddr)
    -> Result<usize, io::Error> {
        send_ancillary(self.as_raw_fd(), Some(addr), 0, &[IoSlice::new(datagram)], fds, None)
    }
    fn send_fds(&self,  datagram: &[u8],  fds: &[RawFd]) -> Result<usize, io::Error> {
        send_ancillary(self.as_raw_fd(), None, 0, &[IoSlice::new(datagram)], fds, None)
    }
    fn recv_fds_from(&self,  buf: &mut[u8],  fd_buf: &mut[RawFd])
    -> Result<(usize, usize, UnixSocketAddr), io::Error> {
        let mut addr = UnixSocketAddr::default();
        recv_fds(self.as_raw_fd(), Some(&mut addr), &mut[IoSliceMut::new(buf)], fd_buf)
            .map(|(bytes, _, fds)| (bytes, fds, addr) )
    }
    fn recv_fds(&self,  buf: &mut[u8],  fd_buf: &mut[RawFd]) -> Result<(usize, usize), io::Error> {
        recv_fds(self.as_raw_fd(), None, &mut[IoSliceMut::new(buf)], fd_buf)
            .map(|(bytes, _, fds)| (bytes, fds) )
    }

    /// Get the credentials of the process that created a socket pair.
    ///
    /// This information is only available on Linux, and only for sockets that
    /// was created with `pair()` or the underlying `socketpair()`.
    /// For sockets that have merely been "connected" to an address
    /// or not connected at all, an error of kind `NotConnected`
    /// or `InvalidInput` is returned.
    ///
    /// The use cases of this function gotta be very narrow:
    ///
    /// * It will return the credentials of the current process unless
    ///   the side of the socket this method is called on was received via
    ///   FD-passing or inherited from a parent.
    /// * If it was created by the direct parent process,
    ///   one might as well use `getppid()` and go from there?
    /// * A returned pid can be repurposed by the OS before the call returns.
    /// * uids or groups will be those in effect when the pair was created,
    ///   and will not reflect changes in privileges.
    ///
    /// Despite these limitations, the feature is supported by Linux at least
    /// (but not macOS or FreeBSD), so might as well expose it.
    fn initial_pair_credentials(&self) -> Result<ConnCredentials, io::Error> {
        peer_credentials(self.as_raw_fd())
    }
}

impl UnixDatagramExt for UnixDatagram {}

#[cfg(feature="mio-uds")]
impl UnixDatagramExt for mio_uds::UnixDatagram {}

#[cfg(feature="mio_07")]
impl UnixDatagramExt for mio_07::net::UnixDatagram {}
