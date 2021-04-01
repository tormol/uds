use crate::{nonblocking, UnixSocketAddr, ConnCredentials};
use futures::{future::poll_fn, ready};
use std::io::{self, ErrorKind, IoSlice, IoSliceMut};
use std::net::Shutdown;
use std::os::unix::io::RawFd;
use std::path::Path;
use std::task::{Context, Poll};
use tokio_02::io::PollEvented;

/// An I/O object representing a Unix Sequenced-packet socket.
pub struct UnixSeqpacketConn {
    io: PollEvented<nonblocking::UnixSeqpacketConn>,
}

impl UnixSeqpacketConn {
    /// Connects to the socket named by path.
    ///
    /// This function will create a new Unix socket and connect to the path
    /// specified, associating the returned stream with the default event loop's
    /// handle.
    pub async fn connect<P: AsRef<Path>>(path: P) -> io::Result<UnixSeqpacketConn> {
        let conn = nonblocking::UnixSeqpacketConn::connect(path)?;
        let conn = UnixSeqpacketConn::from_nonblocking(conn)?;

        poll_fn(|cx| conn.io.poll_write_ready(cx)).await?;
        Ok(conn)
    }

    /// Connect to an unix seqpacket server listening at `addr`.
    pub async fn connect_addr(addr: &UnixSocketAddr) -> io::Result<Self> {
        let conn = nonblocking::UnixSeqpacketConn::connect_unix_addr(addr)?;
        let conn = UnixSeqpacketConn::from_nonblocking(conn)?;

        poll_fn(|cx| conn.io.poll_write_ready(cx)).await?;
        Ok(conn)
    }
    /// Bind to an address before connecting to a listening seqpacet socket.
    pub async fn connect_from_addr(from: &UnixSocketAddr, to: &UnixSocketAddr)
    -> io::Result<Self> {
        let conn = nonblocking::UnixSeqpacketConn::connect_from_to_unix_addr(from, to)?;
        let conn = UnixSeqpacketConn::from_nonblocking(conn)?;

        poll_fn(|cx| conn.io.poll_write_ready(cx)).await?;
        Ok(conn)
    }

    /// Creates a tokio-compatible socket from a nonblocking variant.
    pub fn from_nonblocking(conn: nonblocking::UnixSeqpacketConn) -> io::Result<UnixSeqpacketConn> {
        let io = PollEvented::new(conn)?;
        Ok(UnixSeqpacketConn { io })
    }

    /// Creates an unnamed pair of connected sockets.
    ///
    /// This function will create a pair of interconnected Unix sockets for
    /// communicating back and forth between one another. Each socket will
    /// be associated with the default event loop's handle.
    pub fn pair() -> io::Result<(UnixSeqpacketConn, UnixSeqpacketConn)> {
        let (a, b) = nonblocking::UnixSeqpacketConn::pair()?;
        let a = UnixSeqpacketConn::from_nonblocking(a)?;
        let b = UnixSeqpacketConn::from_nonblocking(b)?;

        Ok((a, b))
    }

    /// Shuts down the read, write, or both halves of this connection.
    pub fn shutdown(&self, how: Shutdown) -> io::Result<()> {
        self.io.get_ref().shutdown(how)
    }

    /// Get the address of this side of the connection.
    pub fn local_addr(&self) -> Result<UnixSocketAddr, io::Error> {
        self.io.get_ref().local_unix_addr()
    }
    /// Get the address of the other side of the connection.
    pub fn peer_addr(&self) -> Result<UnixSocketAddr, io::Error> {
        self.io.get_ref().peer_unix_addr()
    }

    /// Get information about the process of the peer when the connection was established.
    ///
    /// See documentation of the returned type for details.
    pub fn initial_peer_credentials(&self) -> Result<ConnCredentials, io::Error> {
        self.io.get_ref().initial_peer_credentials()
    }
    /// Get the SELinux security context of the process that created the other
    /// end of this connection.
    ///
    /// Will return an error on other operating systems than Linux or Android,
    /// and also if running inside kubernetes.
    /// On success the number of bytes used is returned. (like `Read`)
    ///
    /// The default security context is `unconfined`, without any trailing NUL.  
    /// A buffor of 50 bytes is probably always big enough.
    pub fn initial_peer_selinux_context(&self, buf: &mut[u8]) -> Result<usize, io::Error> {
        self.io.get_ref().initial_peer_selinux_context(buf)
    }
}

impl UnixSeqpacketConn {
    /// Send a packet to the socket's peer.
    pub async fn send(&mut self,  packet: &[u8]) -> io::Result<usize> {
        poll_fn(|cx| self.poll_send_priv(cx, |conn| conn.send(packet) ) ).await
    }
    /// Receive a packet from the socket's peer.
    pub async fn recv(&mut self,  buffer: &mut[u8]) -> io::Result<usize> {
        poll_fn(|cx| {
            self.poll_recv_priv(cx, |conn| conn.recv(buffer).map(|(received, _)| received ) )
        }).await
    }

    /// Send a packet assembled from multiple byte slices.
    pub async fn send_vectored<'a, 'b>
    (&'a mut self,  slices: &'b [IoSlice<'b>]) -> io::Result<usize> {
        poll_fn(|cx| self.poll_send_priv(cx, |conn| conn.send_vectored(slices) ) ).await
    }
    /// Receive a packet and place the bytes across multiple buffers.
    pub async fn recv_vectored<'a, 'b>
    (&'a mut self,  buffers: &'b mut [IoSliceMut<'b>]) -> io::Result<usize> {
        poll_fn(|cx| {
            self.poll_recv_priv(
                cx,
                |conn| conn.recv_vectored(buffers).map(|(received, _)| received )
            )
        }).await
    }

    /// Receive a packet without removing it from the incoming queue.
    pub async fn peek(&mut self,  buffer: &mut[u8]) -> io::Result<usize> {
        poll_fn(|cx| {
            self.poll_recv_priv(cx, |conn| conn.peek(buffer).map(|(received, _)| received ) )
        }).await
    }
    /// Read a packet into multiple buffers without removing it from the incoming queue.
    pub async fn peek_vectored<'a, 'b>
    (&'a mut self,  buffers: &'b mut [IoSliceMut<'b>]) -> io::Result<usize> {
        poll_fn(|cx| {
            self.poll_recv_priv(
                cx,
                |conn| conn.peek_vectored(buffers).map(|(received, _)| received )
            )
        }).await
    }

    /// Send a packet with associated file descriptors.
    pub async fn send_fds(&mut self,  bytes: &[u8],  fds: &[RawFd]) -> io::Result<usize> {
        poll_fn(|cx| self.poll_send_priv(cx, |conn| conn.send_fds(bytes, fds) ) ).await
    }
    /// Receive a packet and associated file descriptors.
    pub async fn recv_fds(&mut self,  byte_buffer: &mut[u8],  fd_buffer: &mut[RawFd])
    -> io::Result<(usize, bool, usize)> {
        poll_fn(|cx| self.poll_recv_priv(cx, |conn| conn.recv_fds(byte_buffer, fd_buffer) ) ).await
    }

    pub(crate) fn poll_send_priv
    <O, S: Fn(&nonblocking::UnixSeqpacketConn)->Result<O,io::Error>>
    (&self,  cx: &mut Context<'_>,  send_op: S) -> Poll<Result<O, io::Error>> {
        ready!(self.io.poll_write_ready(cx))?;
        match send_op(self.io.get_ref()) {
            Err(ref e) if e.kind() == ErrorKind::WouldBlock => {
                self.io.clear_write_ready(cx)?;
                Poll::Pending
            }
            x => Poll::Ready(x),
        }
    }

    pub(crate) fn poll_recv_priv
    <O, R: FnMut(&nonblocking::UnixSeqpacketConn)->Result<O,io::Error>>
    (&self,  cx: &mut Context<'_>,  mut recv_op: R) -> Poll<Result<O, io::Error>> {
        ready!(self.io.poll_read_ready(cx, mio::Ready::readable()))?;
        match recv_op(self.io.get_ref()) {
            Err(ref e) if e.kind() == ErrorKind::WouldBlock => {
                self.io.clear_read_ready(cx, mio::Ready::readable())?;
                Poll::Pending
            }
            x => Poll::Ready(x),
        }
    }
}

/// An I/O object representing a Unix Sequenced-packet socket.
pub struct UnixSeqpacketListener {
    io: PollEvented<nonblocking::UnixSeqpacketListener>,
}

impl UnixSeqpacketListener {
    pub fn bind<P: AsRef<Path>>(path: P) -> io::Result<UnixSeqpacketListener> {
        let listener = nonblocking::UnixSeqpacketListener::bind(path)?;
        let listener = UnixSeqpacketListener::new(listener)?;

        Ok(listener)
    }

    pub fn bind_addr(addr: &UnixSocketAddr) -> io::Result<Self> {
        let listener = nonblocking::UnixSeqpacketListener::bind_unix_addr(addr)?;
        let listener = UnixSeqpacketListener::new(listener)?;

        Ok(listener)
    }

    pub(crate) fn new(
        conn: nonblocking::UnixSeqpacketListener,
    ) -> io::Result<UnixSeqpacketListener> {
        let io = PollEvented::new(conn)?;
        Ok(UnixSeqpacketListener { io })
    }

    /// Accepts a new incoming connection to this listener.
    pub async fn accept(&mut self) -> io::Result<(UnixSeqpacketConn, UnixSocketAddr)> {
        poll_fn(|cx| self.poll_accept(cx)).await
    }

    pub(crate) fn poll_accept(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<(UnixSeqpacketConn, UnixSocketAddr)>> {
        let (io, addr) = ready!(self.poll_accept_nonblocking(cx))?;
        let io = UnixSeqpacketConn::from_nonblocking(io)?;

        Ok((io, addr)).into()
    }

    fn poll_accept_nonblocking(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<(nonblocking::UnixSeqpacketConn, UnixSocketAddr)>> {
        ready!(self.io.poll_read_ready(cx, mio::Ready::readable()))?;

        match self.io.get_ref().accept_unix_addr() {
            Ok((socket, addr)) => Ok((socket, addr)).into(),
            Err(ref err) if err.kind() == ErrorKind::WouldBlock => {
                self.io.clear_read_ready(cx, mio::Ready::readable())?;
                Poll::Pending
            }
            Err(err) => Err(err).into(),
        }
    }

    /// Get the address of this side of the connection.
    pub fn local_addr(&self) -> Result<UnixSocketAddr, io::Error> {
        self.io.get_ref().local_unix_addr()
    }
}
