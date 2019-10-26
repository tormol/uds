use std::os::unix::io::{RawFd, AsRawFd, FromRawFd, IntoRawFd};
use std::os::unix::net::{UnixStream, UnixListener, UnixDatagram};
use std::io::{self, IoSlice, IoSliceMut};

use libc::SOCK_STREAM;

use crate::addr::UnixSocketAddr;
use crate::helpers::*;
use crate::ancillary::*;

pub trait UnixStreamExt: AsRawFd + FromRawFd + Sized {
    fn local_unix_addr(&self) -> Result<UnixSocketAddr, io::Error> {
        local_addr(self.as_raw_fd())
    }
    fn peer_unix_addr(&self) -> Result<UnixSocketAddr, io::Error> {
        peer_addr(self.as_raw_fd())
    }

    fn connect_to_unix_addr(addr: &UnixSocketAddr) -> Result<Self, io::Error>;
    fn connect_from_to_unix_addr(from: &UnixSocketAddr,  to: &UnixSocketAddr)
    -> Result<Self, io::Error>;

    fn send_fds(&self,  bytes: &[u8],  fds: &[RawFd]) -> Result<usize, io::Error> {
        send_ancillary(self.as_raw_fd(), None, 0, &[IoSlice::new(bytes)], fds, None)
    }
    fn recv_fds(&self,  buf: &mut[u8],  fd_buf: &mut[RawFd]) -> Result<(usize, usize), io::Error> {
        recv_fds(self.as_raw_fd(), None, &mut[IoSliceMut::new(buf)], fd_buf)
    }

    //fn peer_credentials(&self) -> QueriedCredentials;
}

impl UnixStreamExt for UnixStream {
    fn connect_to_unix_addr(addr: &UnixSocketAddr) -> Result<Self, io::Error> {
        let socket = Socket::new(SOCK_STREAM, false)?;
        connect_to(socket.as_raw_fd(), addr)?;
        Ok(unsafe { Self::from_raw_fd(socket.into_raw_fd()) })
    }
    fn connect_from_to_unix_addr(from: &UnixSocketAddr,  to: &UnixSocketAddr)
    -> Result<Self, io::Error> {
        let socket = Socket::new(SOCK_STREAM, false)?;
        bind_to(socket.as_raw_fd(), from)?;
        connect_to(socket.as_raw_fd(), to)?;
        Ok(unsafe { Self::from_raw_fd(socket.into_raw_fd()) })
    }
}

#[cfg(feature="mio-uds")]
impl UnixStreamExt for mio_uds::UnixStream {
    fn connect_to_unix_addr(addr: &UnixSocketAddr) -> Result<Self, io::Error> {
        let socket = Socket::new(SOCK_STREAM, true)?;
        connect_to(socket.as_raw_fd(), addr)?;
        Ok(unsafe { Self::from_raw_fd(socket.into_raw_fd()) })
    }
    fn connect_from_to_unix_addr(from: &UnixSocketAddr,  to: &UnixSocketAddr)
    -> Result<Self, io::Error> {
        let socket = Socket::new(SOCK_STREAM, true)?;
        bind_to(socket.as_raw_fd(), from)?;
        connect_to(socket.as_raw_fd(), to)?;
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
        local_addr(self.as_raw_fd())
    }

    /// Accept a connection and return the client's address as
    /// an `uds::UnixSocketAddr`.
    fn accept_unix_addr(&self) -> Result<(Self::Conn, UnixSocketAddr), io::Error>;
}

impl UnixListenerExt for UnixListener {
    type Conn = UnixStream;

    fn bind_unix_addr(on: &UnixSocketAddr) -> Result<Self, io::Error> {
        let socket = Socket::new(SOCK_STREAM, false)?;
        bind_to(socket.as_raw_fd(), on)?;
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
        bind_to(socket.as_raw_fd(), on)?;
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
        local_addr(self.as_raw_fd())
    }
    fn peer_unix_addr(&self) -> Result<UnixSocketAddr, io::Error> {
        peer_addr(self.as_raw_fd())
    }

    fn bind_to_unix_addr(&self,  addr: &UnixSocketAddr) -> Result<(), io::Error> {
        bind_to(self.as_raw_fd(), addr)
    }
    fn connect_to_unix_addr(&self,  addr: &UnixSocketAddr) -> Result<(), io::Error> {
        connect_to(self.as_raw_fd(), addr)
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
            .map(|(bytes, fds)| (bytes, fds, addr) )
    }
    fn recv_fds(&self,  buf: &mut[u8],  fd_buf: &mut[RawFd]) -> Result<(usize, usize), io::Error> {
        recv_fds(self.as_raw_fd(), None, &mut[IoSliceMut::new(buf)], fd_buf)
    }
}

impl UnixDatagramExt for UnixDatagram {}

#[cfg(feature="mio-uds")]
impl UnixDatagramExt for mio_uds::UnixDatagram {}
