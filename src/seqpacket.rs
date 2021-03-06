use std::io::{self, ErrorKind, IoSlice, IoSliceMut};
use std::mem;
use std::net::Shutdown;
use std::os::unix::io::{RawFd, FromRawFd, AsRawFd, IntoRawFd};
use std::path::Path;
use std::time::Duration;

use libc::{SOCK_SEQPACKET, MSG_EOR, MSG_PEEK, c_void, close, send};

#[cfg(feature="mio")]
use mio::{event::Evented, unix::EventedFd, Poll, Token as Token_06, Ready, PollOpt};

#[cfg(feature="mio_07")]
use mio_07::{event::Source, unix::SourceFd, Registry, Token as Token_07, Interest};

use crate::addr::*;
use crate::helpers::*;
use crate::ancillary::*;
use crate::credentials::*;

/// Implement traits apropriate for any file-descriptor-wrapping type.
macro_rules! impl_rawfd_traits {($type:tt) => {
    impl FromRawFd for $type {
        unsafe fn from_raw_fd(fd: RawFd) -> Self {
            $type { fd }
        }
    }
    impl AsRawFd for $type {
        fn as_raw_fd(&self) -> RawFd {
            self.fd
        }
    }
    impl IntoRawFd for $type {
        fn into_raw_fd(self) -> RawFd {
            let fd = self.fd;
            mem::forget(self);
            fd
        }
    }
    impl Drop for $type {
        fn drop(&mut self) {
            let _ = unsafe { close(self.fd) };
        }
    }
}}

/// Implement `mio::Evented` and `mio::Source` for a fd-wrapping type.
macro_rules! impl_mio_if_enabled {($type:tt) => {
    #[cfg(feature="mio")]
    impl Evented for $type {
        fn register(&self,  poll: &Poll,  token: Token_06,  interest: Ready,  opts: PollOpt)
        -> Result<(), io::Error> {
            EventedFd(&self.fd).register(poll, token, interest, opts)
        }
        fn reregister(&self,  poll: &Poll,  token: Token_06,  interest: Ready,  opts: PollOpt)
        -> Result<(), io::Error> {
            EventedFd(&self.fd).reregister(poll, token, interest, opts)
        }
        fn deregister(&self,  poll: &Poll) -> Result<(), io::Error> {
            EventedFd(&self.fd).deregister(poll)
        }
    }

    #[cfg(feature="mio_07")]
    impl Source for $type {
        fn register(&mut self,  registry: &Registry,  token: Token_07,  interest: Interest)
        -> Result<(), io::Error> {
            SourceFd(&self.fd).register(registry, token, interest)
        }
        fn reregister(&mut self,  registry: &Registry,  token: Token_07,  interest: Interest)
        -> Result<(), io::Error> {
            SourceFd(&self.fd).reregister(registry, token, interest)
        }
        fn deregister(&mut self,  registry: &Registry) -> Result<(), io::Error> {
            SourceFd(&self.fd).deregister(registry)
        }
    }

    #[cfg(feature="mio_07")]
    impl<'a> Source for &'a $type {
        fn register(&mut self,  registry: &Registry,  token: Token_07,  interest: Interest)
        -> Result<(), io::Error> {
            SourceFd(&self.fd).register(registry, token, interest)
        }
        fn reregister(&mut self,  registry: &Registry,  token: Token_07,  interest: Interest)
        -> Result<(), io::Error> {
            SourceFd(&self.fd).reregister(registry, token, interest)
        }
        fn deregister(&mut self,  registry: &Registry) -> Result<(), io::Error> {
            SourceFd(&self.fd).deregister(registry)
        }
    }
}}



/// An unix domain sequential packet connection.
///
/// Sequential-packet connections have an interface similar to streams,
/// but behave more like connected datagram sockets.
///
/// They have guaranteed in-order and reliable delivery,
/// which unix datagrams technically doesn't.
///
/// # Operating system support
///
/// Sequential-packet sockets are supported by Linux, FreeBSD, NetBSD
/// and Illumos, but not by for example macOS or OpenBSD.
///
/// # Zero-length packets
///
/// ... are best avoided:  
/// On Linux and FreeBSD zero-length packets can be sent and received,
/// but there is no way to distinguish receiving one from reaching
/// end of connection unless the packet has an ancillary payload.
/// Also beware of trying to receive with a zero-length buffer,
/// as that will on FreeBSD (and probably other BSDs with seqpacket sockets)
/// always succeed even if there is no packet waiting.
///
/// Illumos and Solaris doesn't support receiving zero-length packets at all:
/// writes succeed but recv() will block.
///
/// # Examples
///
/// What is sent separately is received separately:
///
#[cfg_attr(not(target_vendor="apple"), doc="```")]
#[cfg_attr(target_vendor="apple", doc="```no_run")]
/// let (a, b) = uds::UnixSeqpacketConn::pair().expect("Cannot create seqpacket pair");
///
/// a.send(b"first").unwrap();
/// a.send(b"second").unwrap();
///
/// let mut buffer_big_enough_for_both = [0; 20];
/// let (len, _truncated) = b.recv(&mut buffer_big_enough_for_both).unwrap();
/// assert_eq!(&buffer_big_enough_for_both[..len], b"first");
/// let (len, _truncated) = b.recv(&mut buffer_big_enough_for_both).unwrap();
/// assert_eq!(&buffer_big_enough_for_both[..len], b"second");
/// ```
///
/// Connect to a listener on a socket file and write to it:
///
#[cfg_attr(not(target_vendor="apple"), doc="```")]
#[cfg_attr(target_vendor="apple", doc="```no_run")]
/// use uds::{UnixSeqpacketListener, UnixSeqpacketConn};
///
/// # let _ = std::fs::remove_file("seqpacket.socket"); // pre-emptively delete just in case
/// let listener = UnixSeqpacketListener::bind("seqpacket.socket")
///     .expect("create seqpacket listener");
/// let conn = UnixSeqpacketConn::connect("seqpacket.socket")
///     .expect("connect to seqpacket listener");
///
/// let message = "Hello, listener";
/// let sent = conn.send(message.as_bytes()).unwrap();
/// assert_eq!(sent, message.len());
///
/// std::fs::remove_file("seqpacket.socket").unwrap(); // clean up after ourselves
/// ```
///
/// Connect to a listener on an abstract address:
///
#[cfg_attr(any(target_os="linux", target_os="android"), doc="```")]
#[cfg_attr(not(any(target_os="linux", target_os="android")), doc="```no_run")]
/// use uds::{UnixSeqpacketListener, UnixSeqpacketConn, UnixSocketAddr};
///
/// let addr = UnixSocketAddr::new("@seqpacket example").unwrap();
/// let listener = UnixSeqpacketListener::bind_unix_addr(&addr)
///     .expect("create abstract seqpacket listener");
/// let _client = UnixSeqpacketConn::connect_unix_addr(&addr)
///     .expect("connect to abstract seqpacket listener");
/// let (_server, _addr) = listener.accept_unix_addr().unwrap();
/// ```
#[derive(Debug)]
#[repr(transparent)]
pub struct UnixSeqpacketConn {
    fd: RawFd,
}

impl_rawfd_traits!{UnixSeqpacketConn}

impl UnixSeqpacketConn {
    /// Connect to an unix seqpacket server listening at `path`.
    ///
    /// This is a wrapper around [`connect_unix_addr()`](#method.connect_unix_addr)
    /// for convenience and compatibility with std.
    pub fn connect<P: AsRef<Path>>(path: P) -> Result<Self, io::Error> {
        let addr = UnixSocketAddr::from_path(&path)?;
        Self::connect_unix_addr(&addr)
    }
    /// Connect to an unix seqpacket server listening at `addr`.
    pub fn connect_unix_addr(addr: &UnixSocketAddr) -> Result<Self, io::Error> {
        let socket = Socket::new(SOCK_SEQPACKET, false)?;
        set_unix_addr(socket.as_raw_fd(), SetAddr::PEER,  addr)?;
        Ok(UnixSeqpacketConn { fd: socket.into_raw_fd() })
    }
    /// Bind to an address before connecting to a listening sequplacet socket.
    pub fn connect_from_to_unix_addr(from: &UnixSocketAddr,  to: &UnixSocketAddr)
    -> Result<Self, io::Error> {
        let socket = Socket::new(SOCK_SEQPACKET, false)?;
        set_unix_addr(socket.as_raw_fd(), SetAddr::LOCAL, from)?;
        set_unix_addr(socket.as_raw_fd(), SetAddr::PEER, to)?;
        Ok(UnixSeqpacketConn { fd: socket.into_raw_fd() })
    }

    /// Create a pair of unix-domain seqpacket conneections connected to each other.
    ///
    /// # Examples
    ///
    #[cfg_attr(not(target_vendor="apple"), doc="```")]
    #[cfg_attr(target_vendor="apple", doc="```no_run")]
    /// let (a, b) = uds::UnixSeqpacketConn::pair().unwrap();
    /// assert!(a.local_unix_addr().unwrap().is_unnamed());
    /// assert!(b.local_unix_addr().unwrap().is_unnamed());
    ///
    /// a.send(b"hello").unwrap();
    /// b.recv(&mut[0; 20]).unwrap();
    /// ```
    pub fn pair() -> Result<(Self, Self), io::Error> {
        let (a, b) = Socket::pair(SOCK_SEQPACKET, false)?;
        let a = UnixSeqpacketConn { fd: a.into_raw_fd() };
        let b = UnixSeqpacketConn { fd: b.into_raw_fd() };
        Ok((a, b))
    }

    /// Get the address of this side of the connection.
    pub fn local_unix_addr(&self) -> Result<UnixSocketAddr, io::Error> {
        get_unix_addr(self.fd, GetAddr::LOCAL)
    }
    /// Get the address of the other side of the connection.
    pub fn peer_unix_addr(&self) -> Result<UnixSocketAddr, io::Error> {
        get_unix_addr(self.fd, GetAddr::PEER)
    }
    /// Get information about the process of the peer when the connection was established.
    ///
    /// See documentation of the returned type for details.
    pub fn initial_peer_credentials(&self) -> Result<ConnCredentials, io::Error> {
        peer_credentials(self.fd)
    }


    /// Send a packet to the peer.
    pub fn send(&self,  packet: &[u8]) -> Result<usize, io::Error> {
        let ptr = packet.as_ptr() as *const c_void;
        let flags = MSG_NOSIGNAL | MSG_EOR;
        let sent = cvt_r!(unsafe { send(self.fd, ptr, packet.len(), flags) })?;
        Ok(sent as usize)
    }
    /// Receive a packet from the peer.
    ///
    /// The returned `bool` indicates whether the packet was truncated due to
    /// the buffer beeing too small.
    pub fn recv(&self,  buffer: &mut[u8]) -> Result<(usize, bool), io::Error> {
        let mut buffers = [IoSliceMut::new(buffer)];
        let (bytes, ancillary) = recv_ancillary(self.fd, None, 0, &mut buffers, &mut[])?;
        Ok((bytes, ancillary.message_truncated()))
    }
    /// Send a packet assembled from multiple byte slices.
    pub fn send_vectored(&self,  slices: &[IoSlice])
    -> Result<usize, io::Error> {
        // Can't use writev() because we need to pass flags,
        // and the flags accepted by pwritev2() aren't the one we need to pass.
        send_ancillary(self.as_raw_fd(), None, MSG_EOR, slices, &[], None)
    }
    /// Read a packet into multiple buffers.
    ///
    /// The returned `bool` indicates whether the packet was truncated due to
    /// too short buffers.
    pub fn recv_vectored(&self,  buffers: &mut[IoSliceMut])
    -> Result<(usize, bool), io::Error> {
        recv_ancillary(self.fd, None, 0, buffers, &mut[])
            .map(|(bytes, ancillary)| (bytes, ancillary.message_truncated()) )
    }
    /// Send a packet with associated file descriptors.
    pub fn send_fds(&self,  bytes: &[u8],  fds: &[RawFd])
    -> Result<usize, io::Error> {
        send_ancillary(self.fd, None, MSG_EOR, &[IoSlice::new(bytes)], fds, None)
    }
    /// Receive a packet and associated file descriptors.
    pub fn recv_fds(&self,  byte_buffer: &mut[u8],  fd_buffer: &mut[RawFd])
    -> Result<(usize, bool, usize), io::Error> {
        recv_fds(self.fd, None, &mut[IoSliceMut::new(byte_buffer)], fd_buffer)
    }
    /// Receive a packet without removing it from the incoming queue.
    ///
    /// The returned `bool` indicates whether the packet was truncated due to
    /// the buffer being too small.
    ///
    /// # Examples
    ///
    #[cfg_attr(not(target_vendor="apple"), doc="```")]
    #[cfg_attr(target_vendor="apple", doc="```no_run")]
    /// let (a, b) = uds::UnixSeqpacketConn::pair().unwrap();
    /// a.send(b"hello").unwrap();
    /// let mut buf = [0u8; 10];
    /// assert_eq!(b.peek(&mut buf[..1]).unwrap(), (1, true));
    /// assert_eq!(&buf[..2], &[b'h', 0]);
    /// assert_eq!(b.peek(&mut buf).unwrap(), (5, false));
    /// assert_eq!(&buf[..5], b"hello");
    /// assert_eq!(b.recv(&mut buf).unwrap(), (5, false));
    /// assert_eq!(&buf[..5], b"hello");
    /// ```
    pub fn peek(&self,  buffer: &mut[u8]) -> Result<(usize, bool), io::Error> {
        let mut buffers = [IoSliceMut::new(buffer)];
        recv_ancillary(self.fd, None, MSG_PEEK, &mut buffers, &mut[])
            .map(|(bytes, ancillary)| (bytes, ancillary.message_truncated()) )
    }
    /// Receive a packet without removing it from the incoming queue.
    ///
    /// The returned `bool` indicates whether the packet was truncated due to
    /// the combined buffers being too small.
    pub fn peek_vectored(&self,  buffers: &mut[IoSliceMut])
    -> Result<(usize, bool), io::Error> {
        recv_ancillary(self.fd, None, MSG_PEEK, buffers, &mut[])
            .map(|(bytes, ancillary)| (bytes, ancillary.message_truncated()) )
    }

    /// Returns the value of the `SO_ERROR` option.
    ///
    /// This might only provide errors generated from nonblocking `connect()`s,
    /// which this library doesn't support. It is therefore unlikely to be 
    /// useful, but is provided for parity with stream counterpart in std.
    ///
    /// # Examples
    ///
    #[cfg_attr(not(target_vendor="apple"), doc="```")]
    #[cfg_attr(target_vendor="apple", doc="```no_run")]
    /// let (a, b) = uds::UnixSeqpacketConn::pair().unwrap();
    /// drop(b);
    ///
    /// assert!(a.send(b"anyone there?").is_err());
    /// assert!(a.take_error().unwrap().is_none());
    /// ```
    pub fn take_error(&self) -> Result<Option<io::Error>, io::Error> {
        take_error(self.fd)
    }


    /// Create a new file descriptor also pointing to this side of this connection.
    ///
    /// # Examples
    ///
    /// Both new and old can send and receive, and share queues:
    ///
    #[cfg_attr(not(target_vendor="apple"), doc="```")]
    #[cfg_attr(target_vendor="apple", doc="```no_run")]
    /// let (a1, b) = uds::nonblocking::UnixSeqpacketConn::pair().unwrap();
    /// let a2 = a1.try_clone().unwrap();
    ///
    /// a1.send(b"first").unwrap();
    /// a2.send(b"second").unwrap();
    ///
    /// let mut buf = [0u8; 20];
    /// let (len, _truncated) = b.recv(&mut buf).unwrap();
    /// assert_eq!(&buf[..len], b"first");
    /// b.send(b"hello first").unwrap();
    /// let (len, _truncated) = b.recv(&mut buf).unwrap();
    /// assert_eq!(&buf[..len], b"second");
    /// b.send(b"hello second").unwrap();
    ///
    /// let (len, _truncated) = a2.recv(&mut buf).unwrap();
    /// assert_eq!(&buf[..len], b"hello first");
    /// let (len, _truncated) = a1.recv(&mut buf).unwrap();
    /// assert_eq!(&buf[..len], b"hello second");
    /// ```
    ///
    /// Clone can still be used after the first one has been closed:
    ///
    #[cfg_attr(not(target_vendor="apple"), doc="```")]
    #[cfg_attr(target_vendor="apple", doc="```no_run")]
    /// let (a, b1) = uds::nonblocking::UnixSeqpacketConn::pair().unwrap();
    /// a.send(b"hello").unwrap();
    ///
    /// let b2 = b1.try_clone().unwrap();
    /// drop(b1);
    /// assert_eq!(b2.recv(&mut[0; 10]).unwrap().0, "hello".len());
    /// ```
    pub fn try_clone(&self) -> Result<Self, io::Error> {
        let cloned = Socket::try_clone_from(self.fd)?;
        Ok(UnixSeqpacketConn { fd: cloned.into_raw_fd() })
    }

    /// Sets the read timeout to the duration specified.
    ///
    /// If the value specified is `None`, then `recv()` and its variants will
    /// block indefinitely.  
    /// An error is returned if the duration is zero.
    ///
    /// The duration is rounded to microsecond precission.
    /// Currently it's rounded down except if that would make it all zero.
    ///
    /// # Operating System Support
    ///
    /// On Illumos (and pressumably also Solaris) timeouts appears not to work
    /// for unix domain sockets.
    ///
    /// # Examples
    ///
    #[cfg_attr(not(any(target_vendor="apple", target_os="illumos", target_os="solaris")), doc="```")]
    #[cfg_attr(any(target_vendor="apple", target_os="illumos", target_os="solaris"), doc="```no_run")]
    /// use std::io::ErrorKind;
    /// use std::time::Duration;
    /// use uds::UnixSeqpacketConn;
    ///
    /// let (a, b) = UnixSeqpacketConn::pair().unwrap();
    /// a.set_read_timeout(Some(Duration::new(0, 2_000_000))).unwrap();
    /// let error = a.recv(&mut[0; 1024]).unwrap_err();
    /// assert_eq!(error.kind(), ErrorKind::WouldBlock);
    /// ```
    pub fn set_read_timeout(&self,  timeout: Option<Duration>)
    -> Result<(), io::Error> {
        set_timeout(self.fd, TimeoutDirection::READ, timeout)
    }
    /// Get the read timeout of this socket.
    ///
    /// `None` is returned if there is no timeout.
    ///
    /// Note that subsecond parts might have been be rounded by the OS
    /// (in addition to the rounding to microsecond in `set_read_timeout()`).
    ///
    /// # Examples
    ///
    #[cfg_attr(not(any(target_vendor="apple", target_os="illumos", target_os="solaris")), doc="```")]
    #[cfg_attr(any(target_vendor="apple", target_os="illumos", target_os="solaris"), doc="```no_run")]
    /// use uds::UnixSeqpacketConn;
    /// use std::time::Duration;
    ///
    /// let timeout = Some(Duration::new(2, 0));
    /// let conn = UnixSeqpacketConn::pair().unwrap().0;
    /// conn.set_read_timeout(timeout).unwrap();
    /// assert_eq!(conn.read_timeout().unwrap(), timeout);
    /// ```
    pub fn read_timeout(&self) -> Result<Option<Duration>, io::Error> {
        get_timeout(self.fd, TimeoutDirection::READ)
    }
    /// Sets the write timeout to the duration specified.
    ///
    /// If the value specified is `None`, then `send()` and its variants will
    /// block indefinitely.  
    /// An error is returned if the duration is zero.
    ///
    /// # Operating System Support
    ///
    /// On Illumos (and pressumably also Solaris) timeouts appears not to work
    /// for unix domain sockets.
    ///
    /// # Examples
    ///
    #[cfg_attr(not(any(target_vendor="apple", target_os="illumos", target_os="solaris")), doc="```")]
    #[cfg_attr(any(target_vendor="apple", target_os="illumos", target_os="solaris"), doc="```no_run")]
    /// # use std::io::ErrorKind;
    /// # use std::time::Duration;
    /// # use uds::UnixSeqpacketConn;
    /// #
    /// let (conn, _other) = UnixSeqpacketConn::pair().unwrap();
    /// conn.set_write_timeout(Some(Duration::new(0, 500 * 1000))).unwrap();
    /// loop {
    ///     if let Err(e) = conn.send(&[0; 1000]) {
    ///         assert_eq!(e.kind(), ErrorKind::WouldBlock, "{}", e);
    ///         break
    ///     }
    /// }
    /// ```
    pub fn set_write_timeout(&self,  timeout: Option<Duration>)
    -> Result<(), io::Error> {
        set_timeout(self.fd, TimeoutDirection::WRITE, timeout)
    }
    /// Get the write timeout of this socket.
    ///
    /// `None` is returned if there is no timeout.
    ///
    /// # Examples
    ///
    #[cfg_attr(not(target_vendor="apple"), doc="```")]
    #[cfg_attr(target_vendor="apple", doc="```no_run")]
    /// let conn = uds::UnixSeqpacketConn::pair().unwrap().0;
    /// assert!(conn.write_timeout().unwrap().is_none());
    /// ```
    pub fn write_timeout(&self) -> Result<Option<Duration>, io::Error> {
        get_timeout(self.fd, TimeoutDirection::WRITE)
    }

    /// Enable or disable nonblocking mode.
    ///
    /// Consider using the nonblocking variant of this type instead.
    /// This method mainly exists for feature parity with std's `UnixStream`.
    ///
    /// # Examples
    ///
    /// Trying to receive when there are no packets waiting:
    ///
    #[cfg_attr(not(target_vendor="apple"), doc="```")]
    #[cfg_attr(target_vendor="apple", doc="```no_run")]
    /// # use std::io::ErrorKind;
    /// # use uds::UnixSeqpacketConn;
    /// let (a, b) = UnixSeqpacketConn::pair().expect("create seqpacket pair");
    /// a.set_nonblocking(true).unwrap();
    /// assert_eq!(a.recv(&mut[0; 20]).unwrap_err().kind(), ErrorKind::WouldBlock);
    /// ```
    ///
    /// Trying to send when the OS buffer for the connection is full:
    ///
    #[cfg_attr(not(target_vendor="apple"), doc="```")]
    #[cfg_attr(target_vendor="apple", doc="```no_run")]
    /// # use std::io::ErrorKind;
    /// # use uds::UnixSeqpacketConn;
    /// let (a, b) = UnixSeqpacketConn::pair().expect("create seqpacket pair");
    /// a.set_nonblocking(true).unwrap();
    /// loop {
    ///     if let Err(error) = a.send(&[b'#'; 1000]) {
    ///         assert_eq!(error.kind(), ErrorKind::WouldBlock);
    ///         break;
    ///     }
    /// }
    /// ```
    pub fn set_nonblocking(&self,  nonblocking: bool) -> Result<(), io::Error> {
        set_nonblocking(self.fd, nonblocking)
    }

    /// Shuts down the read, write, or both halves of this connection.
    pub fn shutdown(&self, how: Shutdown) -> io::Result<()> {
        let how = match how {
            Shutdown::Read => libc::SHUT_RD,
            Shutdown::Write => libc::SHUT_WR,
            Shutdown::Both => libc::SHUT_RDWR,
        };
        unsafe { cvt!(libc::shutdown(self.as_raw_fd(), how)) }?;
        Ok(())
    }
}



/// An unix domain listener for sequential packet connections.
///
/// See [`UnixSeqpacketConn`](struct.UnixSeqpacketConn.html) for a description
/// of this type of connection.
///
/// # Examples
///
#[cfg_attr(not(target_vendor="apple"), doc="```")]
#[cfg_attr(target_vendor="apple", doc="```no_run")]
/// # let _ = std::fs::remove_file("seqpacket_listener.socket");
/// let listener = uds::UnixSeqpacketListener::bind("seqpacket_listener.socket")
///     .expect("Create seqpacket listener");
/// let _client = uds::UnixSeqpacketConn::connect("seqpacket_listener.socket").unwrap();
/// let (conn, _addr) = listener.accept_unix_addr().unwrap();
/// conn.send(b"Welcome").unwrap();
/// # std::fs::remove_file("seqpacket_listener.socket").unwrap();
/// ```
#[derive(Debug)]
#[repr(transparent)]
pub struct UnixSeqpacketListener {
    fd: RawFd
}
impl_rawfd_traits!{UnixSeqpacketListener}
impl UnixSeqpacketListener {
    pub fn bind<P: AsRef<Path>>(path: P) -> Result<Self, io::Error> {
        let addr = UnixSocketAddr::from_path(path.as_ref())?;
        Self::bind_unix_addr(&addr)
    }
    pub fn bind_unix_addr(addr: &UnixSocketAddr) -> Result<Self, io::Error> {
        let socket = Socket::new(SOCK_SEQPACKET, false)?;
        set_unix_addr(socket.as_raw_fd(), SetAddr::LOCAL, addr)?;
        socket.start_listening()?;
        Ok(UnixSeqpacketListener { fd: socket.into_raw_fd() })
    }

    pub fn local_unix_addr(&self) -> Result<UnixSocketAddr, io::Error> {
        get_unix_addr(self.fd, GetAddr::LOCAL)
    }

    pub fn accept_unix_addr(&self)
    -> Result<(UnixSeqpacketConn, UnixSocketAddr), io::Error> {
        let (socket, addr) = Socket::accept_from(self.fd, false)?;
        let conn = UnixSeqpacketConn { fd: socket.into_raw_fd() };
        Ok((conn, addr))
    }

    /// Returns the value of the `SO_ERROR` option.
    ///
    /// This might never produce any errors for listeners. It is therefore
    /// unlikely to be useful, but is provided for parity with
    /// `std::unix::net::UnixListener`.
    pub fn take_error(&self) -> Result<Option<io::Error>, io::Error> {
        take_error(self.fd)
    }

    /// Create a new file descriptor listening for the same connections.
    pub fn try_clone(&self) -> Result<Self, io::Error> {
        let cloned = Socket::try_clone_from(self.fd)?;
        Ok(UnixSeqpacketListener { fd: cloned.into_raw_fd() })
    }

    /// Set a maximum duration to wait in a single `accept()` on this socket.
    ///
    /// `None` disables a previously set timeout.
    /// An error is returned if the duration is zero.
    ///
    /// # Operating System Support
    ///
    /// Only Linux appers to apply timeouts to `accept()`.  
    /// On macOS, FreeBSD and NetBSD, timeouts are silently ignored.  
    /// On Illumos setting timeouts for all unix domain sockets silently fails.
    ///
    /// On OSes where timeouts are known to not work, this function will
    /// return an error even if setting the timeout didn't fail.
    ///
    /// # Examples
    ///
    #[cfg_attr(any(target_os="linux", target_os="android"), doc="```")]
    #[cfg_attr(not(any(target_os="linux", target_os="android")), doc="```no_run")]
    /// # use uds::{UnixSeqpacketListener, UnixSocketAddr};
    /// # use std::io::ErrorKind;
    /// # use std::time::Duration;
    /// #
    /// # let addr = UnixSocketAddr::new("@set_timeout").unwrap();
    /// let listener = UnixSeqpacketListener::bind_unix_addr(&addr).unwrap();
    /// listener.set_timeout(Some(Duration::new(0, 200_000_000))).unwrap();
    /// let err = listener.accept_unix_addr().unwrap_err();
    /// assert_eq!(err.kind(), ErrorKind::WouldBlock);
    /// ```
    pub fn set_timeout(&self,  timeout: Option<Duration>)
    -> Result<(), io::Error> {
        match set_timeout(self.fd, TimeoutDirection::READ, timeout) {
            #[cfg(any(
                target_vendor="apple", target_os="freebsd",
                target_os="netbsd",
                target_os="illumos", target_os="solaris",
            ))]
            Ok(()) if timeout.is_some() => Err(io::Error::new(
                ErrorKind::InvalidInput,
                "listener timeouts are not supported on this OS"
            )),
            result => result
        }
    }
    /// Get the timeout for `accept()` on this socket.
    ///
    /// `None` is returned if there is no timeout.
    ///
    /// Even if a timeout has is set, it is ignored by `accept()` on
    /// most operating systems except Linux.
    ///
    /// # Examples
    ///
    #[cfg_attr(any(target_os="linux", target_os="android"), doc="```")]
    #[cfg_attr(not(any(target_os="linux", target_os="android")), doc="```no_run")]
    /// # use uds::{UnixSeqpacketListener, UnixSocketAddr};
    /// # use std::time::Duration;
    /// #
    /// # let addr = UnixSocketAddr::new("@timeout").unwrap();
    /// let listener = UnixSeqpacketListener::bind_unix_addr(&addr).unwrap();
    /// assert_eq!(listener.timeout().unwrap(), None);
    /// let timeout = Some(Duration::new(2, 0));
    /// listener.set_timeout(timeout).unwrap();
    /// assert_eq!(listener.timeout().unwrap(), timeout);
    /// ```
    pub fn timeout(&self) -> Result<Option<Duration>, io::Error> {
        get_timeout(self.fd, TimeoutDirection::READ)
    }

    /// Enable or disable nonblocking-ness of [`accept_unix_addr()`](#method.accept_unix addr).
    ///
    /// The returned connnections will still be in blocking mode regardsless.
    ///
    /// Consider using the nonblocking variant of this type instead;
    /// this method mostly exists for feature parity with std's `UnixListener`.
    ///
    /// # Examples
    ///
    #[cfg_attr(not(target_vendor="apple"), doc="```")]
    #[cfg_attr(target_vendor="apple", doc="```no_run")]
    /// # use std::io::ErrorKind;
    /// # use uds::{UnixSocketAddr, UnixSeqpacketListener};
    /// #
    /// # let addr = UnixSocketAddr::from_path("nonblocking_seqpacket_listener.socket").unwrap();
    /// # let _ = std::fs::remove_file("nonblocking_seqpacket_listener.socket");
    /// let listener = UnixSeqpacketListener::bind_unix_addr(&addr).expect("create listener");
    /// listener.set_nonblocking(true).expect("enable noblocking mode");
    /// assert_eq!(listener.accept_unix_addr().unwrap_err().kind(), ErrorKind::WouldBlock);
    /// # std::fs::remove_file("nonblocking_seqpacket_listener.socket").expect("delete socket file");
    /// ```
    pub fn set_nonblocking(&self,  nonblocking: bool) -> Result<(), io::Error> {
        set_nonblocking(self.fd, nonblocking)
    }
}



/// A non-blocking unix domain sequential-packet connection.
///
/// Differs from [`uds::UnixSeqpacketConn`](../struct.UnixSeqpacketConn.html)
/// in that all operations that send or receive data will return an `Error` of
/// kind `ErrorKind::WouldBlock` instead of blocking.
/// This is done by creating the socket as non-blocking, and not by passing
/// `MSG_DONTWAIT`. If creating this type from a raw file descriptor, ensure
/// the fd is set to nonblocking before using it through this type.
///
/// This type can be used with mio if one of the mio features are enabled:
///
/// For mio version 0.6:
///
/// ```toml
/// uds = { version = "x.y", features=["mio"] }
/// ```
///
/// For mio version 0.7:
///
/// ```toml
/// uds = { version = "x.y", features=["mio_07"] }
/// ```
///
/// # Examples
///
/// Sending or receiving when it would block a normal socket:
///
#[cfg_attr(not(target_vendor="apple"), doc="```")]
#[cfg_attr(target_vendor="apple", doc="```no_run")]
/// use uds::nonblocking::UnixSeqpacketConn;
/// use std::io::ErrorKind;
///
/// let (a, b) = UnixSeqpacketConn::pair().expect("create nonblocking seqpacket pair");
///
/// // trying to receive when there are no packets waiting
/// assert_eq!(a.recv(&mut[0]).unwrap_err().kind(), ErrorKind::WouldBlock);
///
/// // trying to send when the OS buffer for the connection is full
/// loop {
///     if let Err(error) = a.send(&[0u8; 1000]) {
///         assert_eq!(error.kind(), ErrorKind::WouldBlock);
///         break;
///     }
/// }
/// ```
///
/// Registering with mio (v0.6):
///
#[cfg_attr(all(feature="mio", not(target_vendor="apple")), doc="```")]
#[cfg_attr(all(feature="mio", target_vendor="apple"), doc="```no_run")]
#[cfg_attr(not(feature="mio"), doc="```no_compile")]
/// use uds::nonblocking::UnixSeqpacketConn;
/// use mio::{Poll, Token, Ready, PollOpt, Events};
/// use std::io::ErrorKind;
///
/// let (a, b) = UnixSeqpacketConn::pair()
///     .expect("create nonblocking seqpacket pair");
///
/// let poll = Poll::new().expect("create mio poll");
/// let mut events = Events::with_capacity(10);
/// poll.register(&a, Token(1), Ready::all(),  PollOpt::edge())
///     .expect("register unix seqpacket connection with mio");
///
/// b.send(b"this is it").expect("send seqpacket");
///
/// poll.poll(&mut events, None).expect("receive mio notifications");
/// let current_events = events.iter().collect::<Vec<_>>();
/// assert!(current_events.len() > 0);
/// assert_eq!(current_events[0].token(), Token(1));
/// assert_eq!(a.recv(&mut [0; 8]).expect("receive packet"), (8, true/*truncated*/));
/// ```
#[derive(Debug)]
#[repr(transparent)]
pub struct NonblockingUnixSeqpacketConn {
    fd: RawFd,
}

impl_rawfd_traits!{NonblockingUnixSeqpacketConn}
impl_mio_if_enabled!{NonblockingUnixSeqpacketConn}

// can't Deref<Target=UnixSeqpacketConn> because that would include try_clone()
// and later set_(read|write)_timeout()
impl NonblockingUnixSeqpacketConn {
    /// Connect to an unix seqpacket server listening at `path`.
    ///
    /// This is a wrapper around [`connect_unix_addr()`](#method.connect_unix_addr)
    /// for convenience and compatibility with std.
    pub fn connect<P: AsRef<Path>>(path: P) -> Result<Self, io::Error> {
        let addr = UnixSocketAddr::from_path(&path)?;
        Self::connect_unix_addr(&addr)
    }
    /// Connect to an unix seqpacket server listening at `addr`.
    pub fn connect_unix_addr(addr: &UnixSocketAddr) -> Result<Self, io::Error> {
        let socket = Socket::new(SOCK_SEQPACKET, true)?;
        set_unix_addr(socket.as_raw_fd(), SetAddr::PEER, addr)?;
        Ok(NonblockingUnixSeqpacketConn { fd: socket.into_raw_fd() })
    }
    /// Bind to an address before connecting to a listening seqpacket socket.
    pub fn connect_from_to_unix_addr(from: &UnixSocketAddr,  to: &UnixSocketAddr)
    -> Result<Self, io::Error> {
        let socket = Socket::new(SOCK_SEQPACKET, true)?;
        set_unix_addr(socket.as_raw_fd(), SetAddr::LOCAL, from)?;
        set_unix_addr(socket.as_raw_fd(), SetAddr::PEER, to)?;
        Ok(NonblockingUnixSeqpacketConn { fd: socket.into_raw_fd() })
    }

    /// Create a pair of nonblocking unix-domain seqpacket conneections connected to each other.
    ///
    /// # Examples
    ///
    #[cfg_attr(not(target_vendor="apple"), doc="```")]
    #[cfg_attr(target_vendor="apple", doc="```no_run")]
    /// let (a, b) = uds::nonblocking::UnixSeqpacketConn::pair().unwrap();
    /// assert!(a.local_unix_addr().unwrap().is_unnamed());
    /// assert!(b.local_unix_addr().unwrap().is_unnamed());
    /// assert_eq!(b.recv(&mut[0; 20]).unwrap_err().kind(), std::io::ErrorKind::WouldBlock);
    /// a.send(b"hello").unwrap();
    /// assert_eq!(b.recv(&mut[0; 20]).unwrap(), (5, false));
    /// ```
    pub fn pair() -> Result<(Self, Self), io::Error> {
        let (a, b) = Socket::pair(SOCK_SEQPACKET, true)?;
        let a = NonblockingUnixSeqpacketConn { fd: a.into_raw_fd() };
        let b = NonblockingUnixSeqpacketConn { fd: b.into_raw_fd() };
        Ok((a, b))
    }

    /// Get the address of this side of the connection.
    pub fn local_unix_addr(&self) -> Result<UnixSocketAddr, io::Error> {
        get_unix_addr(self.fd, GetAddr::LOCAL)
    }
    /// Get the address of the other side of the connection.
    pub fn peer_unix_addr(&self) -> Result<UnixSocketAddr, io::Error> {
        get_unix_addr(self.fd, GetAddr::PEER)
    }
    /// Get information about the process of the peer when the connection was established.
    ///
    /// See documentation of the returned type for details.
    pub fn initial_peer_credentials(&self) -> Result<ConnCredentials, io::Error> {
        peer_credentials(self.fd)
    }

    /// Send a packet to the peer.
    pub fn send(&self,  packet: &[u8]) -> Result<usize, io::Error> {
        let ptr = packet.as_ptr() as *const c_void;
        let flags = MSG_NOSIGNAL | MSG_EOR;
        let sent = cvt_r!(unsafe { send(self.fd, ptr, packet.len(), flags) })?;
        Ok(sent as usize)
    }
    /// Receive a packet from the peer.
    ///
    /// The returned `bool` indicates whether the packet was truncated due to
    /// too short buffer.
    pub fn recv(&self,  buffer: &mut[u8]) -> Result<(usize, bool), io::Error> {
        let mut buffers = [IoSliceMut::new(buffer)];
        let (bytes, ancillary) = recv_ancillary(self.fd, None, 0, &mut buffers, &mut[])?;
        Ok((bytes, ancillary.message_truncated()))
    }
    /// Send a packet assembled from multiple byte slices.
    pub fn send_vectored(&self,  slices: &[IoSlice])
    -> Result<usize, io::Error> {
        // Can't use writev() because we need to pass flags,
        // and the flags accepted by pwritev2() aren't the one we need to pass.
        send_ancillary(self.as_raw_fd(), None, MSG_EOR, slices, &[], None)
    }
    /// Read a packet into multiple buffers.
    ///
    /// The returned `bool` indicates whether the packet was truncated due to
    /// too short buffers.
    pub fn recv_vectored(&self,  buffers: &mut[IoSliceMut])
    -> Result<(usize, bool), io::Error> {
        recv_ancillary(self.fd, None, 0, buffers, &mut[])
            .map(|(bytes, ancillary)| (bytes, ancillary.message_truncated()) )
    }
    /// Send a packet with associated file descriptors.
    pub fn send_fds(&self,  bytes: &[u8],  fds: &[RawFd])
    -> Result<usize, io::Error> {
        send_ancillary(self.fd, None, MSG_EOR, &[IoSlice::new(bytes)], fds, None)
    }
    /// Receive a packet and associated file descriptors.
    pub fn recv_fds(&self,  byte_buffer: &mut[u8],  fd_buffer: &mut[RawFd])
    -> Result<(usize, bool, usize), io::Error> {
        recv_fds(self.fd, None, &mut[IoSliceMut::new(byte_buffer)], fd_buffer)
    }
    /// Receive a packet without removing it from the incoming queue.
    ///
    /// The returned `bool` indicates whether the packet was truncated due to
    /// the buffer being too small.
    ///
    /// # Examples
    ///
    #[cfg_attr(not(target_vendor="apple"), doc="```")]
    #[cfg_attr(target_vendor="apple", doc="```no_run")]
    /// # use std::io::ErrorKind::*;
    /// let (a, b) = uds::nonblocking::UnixSeqpacketConn::pair().unwrap();
    /// let mut buf = [0u8; 10];
    /// assert_eq!(b.peek(&mut buf).unwrap_err().kind(), WouldBlock);
    /// a.send(b"hello").unwrap();
    /// assert_eq!(b.peek(&mut buf).unwrap(), (5, false));
    /// assert_eq!(&buf[..5], b"hello");
    /// assert_eq!(b.recv(&mut buf).unwrap(), (5, false));
    /// assert_eq!(&buf[..5], b"hello");
    /// assert_eq!(b.peek(&mut buf).unwrap_err().kind(), WouldBlock);
    /// ```
    pub fn peek(&self,  buffer: &mut[u8]) -> Result<(usize, bool), io::Error> {
        let mut buffers = [IoSliceMut::new(buffer)];
        recv_ancillary(self.fd, None, MSG_PEEK, &mut buffers, &mut[])
            .map(|(bytes, ancillary)| (bytes, ancillary.message_truncated()) )
    }
    /// Receive a packet without removing it from the incoming queue.
    ///
    /// The returned `bool` indicates whether the packet was truncated due to
    /// the combined buffers being too small.
    pub fn peek_vectored(&self,  buffers: &mut[IoSliceMut])
    -> Result<(usize, bool), io::Error> {
        recv_ancillary(self.fd, None, MSG_PEEK, buffers, &mut[])
            .map(|(bytes, ancillary)| (bytes, ancillary.message_truncated()) )
    }

    /// Returns the value of the `SO_ERROR` option.
    ///
    /// This might only provide errors generated from nonblocking `connect()`s,
    /// which this library doesn't support. It is therefore unlikely to be 
    /// useful, but is provided for parity with `mio`s `UnixStream`.
    ///
    /// # Examples
    ///
    #[cfg_attr(not(target_vendor="apple"), doc="```")]
    #[cfg_attr(target_vendor="apple", doc="```no_run")]
    /// let (a, _b) = uds::nonblocking::UnixSeqpacketConn::pair().unwrap();
    ///
    /// assert!(a.recv(&mut[0u8; 1024]).is_err());
    /// assert!(a.take_error().unwrap().is_none());
    /// ```
    pub fn take_error(&self) -> Result<Option<io::Error>, io::Error> {
        take_error(self.fd)
    }


    /// Create a new file descriptor also pointing to this side of this connection.
    ///
    /// # Examples
    ///
    #[cfg_attr(not(target_vendor="apple"), doc="```")]
    #[cfg_attr(target_vendor="apple", doc="```no_run")]
    /// # use uds::nonblocking::UnixSeqpacketConn;
    /// # use std::io::ErrorKind;
    /// #
    /// let (a1, b) = UnixSeqpacketConn::pair().unwrap();
    /// b.send(b"first come first serve").unwrap();
    /// let a2 = a1.try_clone().unwrap();
    /// a2.recv(&mut[0u8; 10]).unwrap();
    /// assert_eq!(a1.recv(&mut[0u8; 10]).unwrap_err().kind(), ErrorKind::WouldBlock);
    ///
    /// b.send(b"more").unwrap();
    /// a1.recv(&mut[0u8; 10]).unwrap();
    /// assert_eq!(a2.recv(&mut[0u8; 10]).unwrap_err().kind(), ErrorKind::WouldBlock);
    /// ```
    pub fn try_clone(&self) -> Result<Self, io::Error> {
        let cloned = Socket::try_clone_from(self.fd)?;
        // nonblockingness is shared and therefore inherited
        Ok(NonblockingUnixSeqpacketConn { fd: cloned.into_raw_fd() })
    }

    /// Shuts down the read, write, or both halves of this connection.
    pub fn shutdown(&self, how: Shutdown) -> io::Result<()> {
        let how = match how {
            Shutdown::Read => libc::SHUT_RD,
            Shutdown::Write => libc::SHUT_WR,
            Shutdown::Both => libc::SHUT_RDWR,
        };
        unsafe { cvt!(libc::shutdown(self.as_raw_fd(), how)) }?;
        Ok(())
    }
}



/// A non-blocking unix domain listener for sequential-packet connections.
///
/// Differs from [`UnixSeqpacketListener`](../struct.UnixSeqpacketListener.html)
/// in that [`accept()`](struct.NonblockingUnixSeqpacketListener.html#method.accept)
/// returns non-blocking [connection sockets](struct.NonblockingUnixSeqpacketConn.html)
/// and doesn't block if no client `connect()`ions are pending.
///
/// This type can be used with mio if the `mio` feature is enabled:
///
/// ```toml
/// uds = { version = "x.y", features=["mio"] }
/// ```
///
/// # Examples
///
#[cfg_attr(not(target_vendor="apple"), doc="```")]
#[cfg_attr(target_vendor="apple", doc="```no_run")]
/// use uds::nonblocking::{UnixSeqpacketListener, UnixSeqpacketConn};
/// use std::io::ErrorKind;
///
/// # let _ = std::fs::remove_file("nonblocking_seqpacket_listener.socket");
/// let listener = UnixSeqpacketListener::bind("nonblocking_seqpacket_listener.socket")
///     .expect("Cannot create nonblocking seqpacket listener");
///
/// // doesn't block if no connections are waiting:
/// assert_eq!(listener.accept_unix_addr().unwrap_err().kind(), ErrorKind::WouldBlock);
///
/// // returned connections are nonblocking:
/// let _client = UnixSeqpacketConn::connect("nonblocking_seqpacket_listener.socket").unwrap();
/// let (conn, _addr) = listener.accept_unix_addr().unwrap();
/// assert_eq!(conn.recv(&mut[0u8; 20]).unwrap_err().kind(), ErrorKind::WouldBlock);
/// #
/// # std::fs::remove_file("nonblocking_seqpacket_listener.socket").unwrap();
/// ```
///
/// Registering with mio (v0.7):
///
#[cfg_attr(all(feature="mio_07", not(target_vendor="apple")), doc="```")]
#[cfg_attr(all(feature="mio_07", target_vendor="apple"), doc="```no_run")]
#[cfg_attr(not(feature="mio_07"), doc="```no_compile")]
/// use uds::nonblocking::{UnixSeqpacketListener, UnixSeqpacketConn};
/// use mio_07::{Poll, Events, Token, Interest};
/// use std::io::ErrorKind;
///
/// # let _ = std::fs::remove_file("seqpacket.sock");
/// let listener = UnixSeqpacketListener::bind("seqpacket.sock")
///     .expect("create nonblocking seqpacket listener");
///
/// let mut poll = Poll::new().expect("create mio poll");
/// let mut events = Events::with_capacity(10);
/// poll.registry()
///     .register(&mut &listener, Token(0), Interest::READABLE)
///     .expect("register unix seqpacket listener with mio");
///
/// let _conn = UnixSeqpacketConn::connect("seqpacket.sock")
///     .expect("create nonblocking seqpacket socket and connect to listener");
///
/// poll.poll(&mut events, None).expect("receive mio notifications");
/// let current_events = events.iter().collect::<Vec<_>>();
/// assert!(current_events.len() > 0);
/// assert_eq!(current_events[0].token(), Token(0));
/// let (_, _addr) = listener.accept_unix_addr().expect("accept connection");
/// ```
#[derive(Debug)]
#[repr(transparent)]
pub struct NonblockingUnixSeqpacketListener {
    fd: RawFd
}

impl_rawfd_traits!{NonblockingUnixSeqpacketListener}
impl_mio_if_enabled!{NonblockingUnixSeqpacketListener}

impl NonblockingUnixSeqpacketListener {
    /// Connect to an unix seqpacket server listening at `path`.
    ///
    /// This is a wrapper around [`connect_unix_addr()`](#method.connect_unix_addr)
    /// for convenience and compatibility with std.
    pub fn bind<P: AsRef<Path>>(path: P) -> Result<Self, io::Error> {
        let addr = UnixSocketAddr::from_path(&path)?;
        Self::bind_unix_addr(&addr)
    }
    /// `accept_unix_addr()` doesn't block if no connections are waiting:
    ///
    #[cfg_attr(not(target_vendor="apple"), doc="```")]
    #[cfg_attr(target_vendor="apple", doc="```no_run")]
    /// # use uds::nonblocking::UnixSeqpacketListener;
    /// # use std::io::ErrorKind;
    /// #
    /// let _ = std::fs::remove_file("nonblocking_seqpacket_listener.socket");
    /// let listener = UnixSeqpacketListener::bind("nonblocking_seqpacket_listener.socket")
    ///     .expect("Cannot create nonblocking seqpacket listener");
    /// assert_eq!(listener.accept_unix_addr().unwrap_err().kind(), ErrorKind::WouldBlock);
    /// std::fs::remove_file("nonblocking_seqpacket_listener.socket").unwrap();
    /// ```
    pub fn bind_unix_addr(addr: &UnixSocketAddr) -> Result<Self, io::Error> {
        let socket = Socket::new(SOCK_SEQPACKET, true)?;
        set_unix_addr(socket.as_raw_fd(), SetAddr::LOCAL, addr)?;
        socket.start_listening()?;
        Ok(NonblockingUnixSeqpacketListener { fd: socket.into_raw_fd() })
    }

    /// Get the address this listener was bound to.
    pub fn local_unix_addr(&self) -> Result<UnixSocketAddr, io::Error> {
        get_unix_addr(self.fd, GetAddr::LOCAL)
    }

    /// Accept a non-blocking connection, non-blockingly.
    pub fn accept_unix_addr(&self)
    -> Result<(NonblockingUnixSeqpacketConn, UnixSocketAddr), io::Error> {
        let (socket, addr) = Socket::accept_from(self.fd, true)?;
        let conn = NonblockingUnixSeqpacketConn { fd: socket.into_raw_fd() };
        Ok((conn, addr))
    }

    /// Returns the value of the `SO_ERROR` option.
    ///
    /// This might never produce any errors for listeners. It is therefore
    /// unlikely to be useful, but is provided for parity with `mio`s
    /// `UnixListener`.
    ///
    /// # Examples
    ///
    #[cfg_attr(any(target_os="linux", target_os="android"), doc="```")]
    #[cfg_attr(not(any(target_os="linux", target_os="android")), doc="```no_run")]
    /// let listener = uds::nonblocking::UnixSeqpacketListener::bind_unix_addr(
    ///     &uds::UnixSocketAddr::new("@nonblocking_take_error").unwrap()
    /// ).unwrap();
    ///
    /// assert!(listener.accept_unix_addr().is_err());
    /// assert!(listener.take_error().unwrap().is_none());
    /// ```
    pub fn take_error(&self) -> Result<Option<io::Error>, io::Error> {
        take_error(self.fd)
    }

    /// Create a new file descriptor listening for the same connections.
    pub fn try_clone(&self) -> Result<Self, io::Error> {
        let cloned = Socket::try_clone_from(self.fd)?;
        // nonblockingness is shared and therefore inherited
        Ok(NonblockingUnixSeqpacketListener { fd: cloned.into_raw_fd() })
    }
}
