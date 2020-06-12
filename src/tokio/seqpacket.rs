use crate::nonblocking;
use futures::{future::poll_fn, ready};
use std::io;
use std::net::Shutdown;
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
}

impl UnixSeqpacketConn {
    /// Sends data on the socket to the socket's peer.
    pub async fn send(&mut self, buf: &[u8]) -> io::Result<usize> {
        poll_fn(|cx| self.poll_send_priv(cx, buf)).await
    }

    /// Receives data from the socket.
    pub async fn recv(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        poll_fn(|cx| self.poll_recv_priv(cx, buf)).await
    }

    pub(crate) fn poll_recv_priv(
        &self,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        ready!(self.io.poll_read_ready(cx, mio::Ready::readable()))?;

        match self.io.get_ref().recv(buf) {
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                self.io.clear_read_ready(cx, mio::Ready::readable())?;
                Poll::Pending
            }
            Err(e) => Poll::Ready(Err(e)),
            Ok((x, _truncated)) => Poll::Ready(Ok(x)),
        }
    }

    pub(crate) fn poll_send_priv(
        &self,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        ready!(self.io.poll_write_ready(cx))?;

        match self.io.get_ref().send(buf) {
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                self.io.clear_write_ready(cx)?;
                Poll::Pending
            }
            x => Poll::Ready(x),
        }
    }
}
