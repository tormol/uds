
use std::
{
    ffi::c_void, io::{self, IoSlice, IoSliceMut}, os::
    {
        fd::{AsFd, OwnedFd, RawFd}, 
        unix::{io::{AsRawFd, FromRawFd}, net::{UnixDatagram, UnixListener, UnixStream}} 
    }
};

use libc::{MSG_PEEK, recvfrom, sendto};

use crate::addr::UnixSocketAddr;
use crate::helpers::*;
use crate::ancillary::*;
use crate::credentials::*;

/// Extension trait for `std::os::unix::net::UnixStream` and nonblocking equivalents.
pub trait UnixStreamExt: AsFd + AsRawFd + FromRawFd 
{
    /// Get the address of this socket, as a type that fully supports abstract addresses.
    fn local_unix_addr(&self) -> Result<UnixSocketAddr, io::Error> 
    {
        get_unix_local_addr(self)
    }

    /// Returns the address of the other end of this stream,
    /// as a type that fully supports abstract addresses.
    fn peer_unix_addr(&self) -> Result<UnixSocketAddr, io::Error> 
    {
        get_unix_peer_addr(self)
    }

    /// Creates a connection to a listening path-based or abstract named socket.
    fn connect_to_unix_addr(addr: &UnixSocketAddr) -> Result<Self, io::Error> where Self: Sized;

    /// Creates a path-based or abstract-named socket and connects to a listening socket.
    fn connect_from_to_unix_addr(from: &UnixSocketAddr, to: &UnixSocketAddr) -> Result<Self, io::Error> 
        where Self: Sized;

    /// Sends file descriptors in addition to bytes.
    fn send_fds(&self, bytes: &[u8], fds: Vec<OwnedFd>) -> Result<usize, io::Error> 
    {
        let fds_raw = fds.iter().map(|fd| fd.as_raw_fd()).collect::<Vec<RawFd>>();

        send_ancillary(self, None, 0, &[IoSlice::new(bytes)], &fds_raw, None)
    }

    /// Receives file descriptors in addition to bytes.
    /// 
    /// A FDs are placed into pre-allocated mutable slice. Received valies are stored
    /// in reception sequence. The first [Option::None] does mean the rest are None too.
    fn recv_slice_fds(&self, buf: &mut[u8], fd_buf: &mut [Option<OwnedFd>]) -> Result<(usize, usize), io::Error> 
    {
        recv_slice_fds(self, None, &mut[IoSliceMut::new(buf)], fd_buf)
            .map(|(bytes, _, fds)| (bytes, fds) )
    }

    /// A FDs are placed into Vec with the specific capacity. 
    /// 
    /// A FDs will be truncated if the capacity is not large enough.
    fn recv_fds(&self,  buf: &mut[u8], fd_buf: &mut Vec<OwnedFd>) -> Result<(usize, usize), io::Error> 
    {
        recv_fds(self, None, &mut[IoSliceMut::new(buf)], fd_buf)
            .map(|(bytes, _, fds)| (bytes, fds) )
    }

    /// Returns the credentials of the process that created the other end of this stream.
    fn initial_peer_credentials(&self) -> Result<ConnCredentials, io::Error> 
    {
        peer_credentials(self)
    }
    /// Returns the SELinux security context of the process that created the other end of this stream.
    ///
    /// Will return an error on other operating systems than Linux or Android,
    /// and also if running under kubernetes.
    /// On success the number of bytes used is returned. (like `Read`)
    ///
    /// The default security context is `unconfined`, without any trailing NUL.  
    /// A buffor of 50 bytes is probably always big enough.
    fn initial_peer_selinux_context(&self, buffer: &mut[u8]) -> Result<usize, io::Error> 
    {
        selinux_context(self, buffer)
    }
}

impl UnixStreamExt for UnixStream 
{
    fn connect_to_unix_addr(addr: &UnixSocketAddr) -> Result<Self, io::Error> 
    {
        let socket = Socket::<SocketStream>::new(false)?;
        socket.set_unix_peer_addr(addr)?;
        
        return Ok(Self::from( <Socket<SocketStream> as Into<OwnedFd>>::into(socket)));
    }

    fn connect_from_to_unix_addr(from: &UnixSocketAddr,  to: &UnixSocketAddr) -> Result<Self, io::Error> 
    {
        let socket = Socket::<SocketStream>::new(false)?;
        socket.set_unix_local_addr(from)?;
        socket.set_unix_peer_addr(to)?;
        
        return Ok(Self::from( <Socket<SocketStream> as Into<OwnedFd>>::into(socket)));
    }
}

#[cfg(feature = "mio")]
impl UnixStreamExt for mio::net::UnixStream 
{
    fn connect_to_unix_addr(addr: &UnixSocketAddr) -> Result<Self, io::Error> 
    {
        let socket = Socket::<SocketStream>::new(true)?;
        socket.set_unix_peer_addr(addr)?;

        return Ok(Self::from( <Socket<SocketStream> as Into<OwnedFd>>::into(socket)));
    }

    fn connect_from_to_unix_addr(from: &UnixSocketAddr,  to: &UnixSocketAddr) -> Result<Self, io::Error> 
    {
        let socket = Socket::<SocketStream>::new(true)?;
        socket.set_unix_local_addr(from)?;
        socket.set_unix_peer_addr(to)?;

        return Ok(Self::from( <Socket<SocketStream> as Into<OwnedFd>>::into(socket)));
    }
}

/// Extension trait for using [`UnixSocketAddr`](struct.UnixSocketAddr.html) with `UnixListener` types.
pub trait UnixListenerExt: AsFd + AsRawFd + FromRawFd 
{
    /// The type represeting the stream connection returned by `accept_unix_addr()`.
    type Conn: FromRawFd;

    /// Creates a socket bound to a `UnixSocketAddr` and starts listening on it.
    fn bind_unix_addr(on: &UnixSocketAddr) -> Result<Self, io::Error> 
        where Self: Sized;

    /// Returns the address this socket is listening on.
    fn local_unix_addr(&self) -> Result<UnixSocketAddr, io::Error> 
    {
        get_unix_local_addr(self)
    }

    /// Accepts a connection and returns the client's address as
    /// an `uds_fork::UnixSocketAddr`.
    fn accept_unix_addr(&self) -> Result<(Self::Conn, UnixSocketAddr), io::Error>;
}

impl UnixListenerExt for UnixListener 
{
    type Conn = UnixStream;

    fn bind_unix_addr(on: &UnixSocketAddr) -> Result<Self, io::Error> 
    {
        let socket = Socket::<SocketStream>::new(false)?;
        socket.set_unix_local_addr(on)?;

        socket.start_listening()?;
        
        return 
            Ok(Self::from( <Socket<SocketStream> as Into<OwnedFd>>::into(socket)));
    }

    fn accept_unix_addr(&self) -> Result<(Self::Conn, UnixSocketAddr), io::Error> 
    {
        let (socket, addr) = Socket::<SocketStream>::accept_from(self, false)?;
        let conn = 
                Self::Conn::from(<Socket<SocketStream> as Into<OwnedFd>>::into(socket));
        
        return Ok((conn, addr));
    }
}


#[cfg(feature = "mio")]
impl UnixListenerExt for mio::net::UnixListener 
{
    type Conn = mio::net::UnixStream;

    fn bind_unix_addr(on: &UnixSocketAddr) -> Result<Self, io::Error> 
    {
        let socket = Socket::<SocketStream>::new(true)?;
        socket.set_unix_local_addr(on)?;

        socket.start_listening()?;

        return 
            Ok(Self::from( <Socket<SocketStream> as Into<OwnedFd>>::into(socket)));
    }

    fn accept_unix_addr(&self) -> Result<(Self::Conn, UnixSocketAddr), io::Error> 
    {
        let (socket, addr) = Socket::<SocketStream>::accept_from(self, true)?;
    
        let conn = 
                Self::Conn::from(<Socket<SocketStream> as Into<OwnedFd>>::into(socket));

        Ok((conn, addr))
    }
}

/// Extension trait for `std::os::unix::net::UnixDatagram` and nonblocking equivalents.
pub trait UnixDatagramExt: AsFd + AsRawFd + FromRawFd 
{
    /// Create a socket bound to a path or abstract name.
    ///
    /// # Examples
    ///
    #[cfg_attr(any(target_os="linux", target_os="android"), doc="```")]
    #[cfg_attr(not(any(target_os="linux", target_os="android")), doc="```no_run")]
    /// # use std::os::unix::net::UnixDatagram;
    /// # use uds_fork::{UnixDatagramExt, UnixSocketAddr};
    /// #
    /// # fn main() -> Result<(), std::io::Error> {
    /// let addr = UnixSocketAddr::new("@abstract")?;
    /// let socket = UnixDatagram::bind_unix_addr(&addr)?;
    /// # let _ = socket.send_to_unix_addr(b"where are you", &addr);
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// This is equivalent of:
    ///
    /// ```
    /// # use std::os::unix::net::UnixDatagram;
    /// # use uds_fork::{UnixDatagramExt, UnixSocketAddr};
    /// #
    /// # fn main() -> Result<(), std::io::Error> {
    /// # let addr = UnixSocketAddr::new("/tmp/me")?;
    /// let socket = UnixDatagram::unbound()?;
    /// socket.bind_to_unix_addr(&addr)?;
    /// # let _ = std::fs::remove_file("/tmp/me");
    /// # Ok(())
    /// # }
    /// ```
    fn bind_unix_addr(addr: &UnixSocketAddr) -> Result<Self, io::Error> 
        where Self: Sized;

    /// Returns the address of this socket, as a type that fully supports abstract addresses.
    fn local_unix_addr(&self) -> Result<UnixSocketAddr, io::Error> 
    {
        get_unix_local_addr(self)
    }

    /// Returns the address of the connected socket, as a type that fully supports abstract addresses.
    fn peer_unix_addr(&self) -> Result<UnixSocketAddr, io::Error> 
    {
        get_unix_peer_addr(self)
    }

    /// Creates a path or abstract name for the socket.
    fn bind_to_unix_addr(&self,  addr: &UnixSocketAddr) -> Result<(), io::Error> 
    {
        set_unix_local_addr(self, addr)
    }

    /// Connects the socket to a path-based or abstract named socket.
    fn connect_to_unix_addr(&self,  addr: &UnixSocketAddr) -> Result<(), io::Error> 
    {
        set_unix_peer_addr(self, addr)
    }

    /// Sends to the specified address, using an address type that
    /// supports abstract addresses.
    ///
    /// # Examples
    ///
    /// Send to an abstract address:
    ///
    #[cfg_attr(any(target_os="linux", target_os="android"), doc="```")]
    #[cfg_attr(not(any(target_os="linux", target_os="android")), doc="```no_run")]
    /// # use std::os::unix::net::UnixDatagram;
    /// # use uds_fork::{UnixDatagramExt, UnixSocketAddr};
    /// #
    /// let socket = UnixDatagram::unbound().expect("create datagram socket");
    /// let _ = socket.send_to_unix_addr(
    ///     b"Is there anyone there?",
    ///     &UnixSocketAddr::from_abstract("somewhere").expect("OS supports abstract addresses"),
    /// );
    /// ```
    fn send_to_unix_addr(&self,  datagram: &[u8],  addr: &UnixSocketAddr) -> Result<usize, io::Error> 
    {
        let (sockaddr, socklen) = addr.as_raw_general();
        
        return 
            unsafe {
                cvt_r!(
                    sendto(
                        self.as_raw_fd(),
                        datagram.as_ptr() as *const c_void,
                        datagram.len(),
                        MSG_NOSIGNAL,
                        sockaddr,
                        socklen,
                    )
                )
                .map(|signed| signed as usize )
            };
    }
    /// Sends a datagram created from multiple segments to the specified address,
    /// using an address type that supports abstract addresses.
    ///
    /// # Examples
    ///
    /// Send a datagram with a fixed header:
    ///
    /// ```
    /// # use std::os::unix::net::UnixDatagram;
    /// # use std::io::IoSlice;
    /// # use uds_fork::{UnixDatagramExt, UnixSocketAddr};
    /// #
    /// let socket = UnixDatagram::unbound().expect("create datagram socket");
    /// let to = UnixSocketAddr::new("/var/run/someone.sock").unwrap();
    /// let msg = [
    ///     IoSlice::new(b"hello "),
    ///     IoSlice::new(to.as_pathname().unwrap().to_str().unwrap().as_bytes()),
    /// ];
    /// let _ = socket.send_vectored_to_unix_addr(&msg, &to);
    /// ```
    fn send_vectored_to_unix_addr(&self,  datagram: &[IoSlice],  addr: &UnixSocketAddr) -> Result<usize, io::Error> 
    {
        send_ancillary(self, Some(addr), 0, datagram, &[], None)
    }

    /// Receives from any peer, storing its address in a type that exposes
    /// abstract addresses.
    ///
    /// # Examples
    ///
    /// Respond to the received datagram, regardsless of where it was sent from:
    ///
    /// ```
    /// use std::os::unix::net::UnixDatagram;
    /// use uds_fork::{UnixSocketAddr, UnixDatagramExt};
    ///
    /// let dir = tempfile::tempdir().unwrap();
    /// let mut file_path = dir.path().join("echo.sock");
    /// 
    /// let server = UnixDatagram::bind(&file_path).expect("create server socket");
    ///
    /// let mut cli_file_path = dir.path().join("echo_client.sock");
    /// 
    /// let client_addr = UnixSocketAddr::new("@echo_client")
    ///     .or(UnixSocketAddr::new(cli_file_path.as_os_str().to_str().unwrap()))
    ///     .unwrap();
    /// let client = UnixDatagram::unbound().expect("create client ocket");
    /// client.bind_to_unix_addr(&client_addr).expect("create client socket");
    /// client.connect_to_unix_addr(&UnixSocketAddr::new(file_path.as_os_str().to_str().unwrap()).unwrap())
    ///     .expect("connect to server");
    /// client.send(b"hello").expect("send");
    ///
    /// let mut buf = [0; 1024];
    /// let (len, from) = server.recv_from_unix_addr(&mut buf).expect("receive");
    /// server.send_to_unix_addr(&buf[..len], &from).expect("respond");
    ///
    /// let len = client.recv(&mut buf).expect("receive response");
    /// assert_eq!(&buf[..len], "hello".as_bytes());
    ///
    /// let _ = std::fs::remove_file(&file_path);
    /// if let Some(client_path) = client_addr.as_pathname() {
    ///     let _ = std::fs::remove_file(client_path);
    /// }
    /// ```
    fn recv_from_unix_addr(&self,  buf: &mut[u8]) -> Result<(usize, UnixSocketAddr), io::Error> 
    {
        UnixSocketAddr::new_from_ffi(
            |addr, len| 
            {
                unsafe {
                    cvt_r!(
                        recvfrom(
                            self.as_raw_fd(),
                            buf.as_mut_ptr() as *mut c_void,
                            buf.len(),
                            MSG_NOSIGNAL,
                            addr,
                            len,
                        )
                    )
                    .map(|signed| signed as usize )
                }
            }
        )
    }
    /// Uses multiple buffers to receive from any peer, storing its address in
    /// a type that exposes abstract addresses.
    fn recv_vectored_from_unix_addr(&self,  bufs: &mut[IoSliceMut]) -> Result<(usize, UnixSocketAddr), io::Error> 
    {
        let mut addr = UnixSocketAddr::default();

        recv_slice_fds(self, Some(&mut addr), bufs, &mut [])
            .map(|(bytes, _, _)| (bytes, addr) )
    }
    
    /// Reads the next datagram without removing it from the queue.
    ///
    /// # Examples
    ///
    /// Discard datagram if it's the wrong protocol:
    ///
    /// ```
    /// # use std::os::unix::net::UnixDatagram;
    /// # use uds_fork::{UnixSocketAddr, UnixDatagramExt};
    /// #
    /// let checker = UnixDatagram::bind("/tmp/checker.sock").expect("create receiver socket");
    ///
    /// let client = UnixDatagram::unbound().expect("create client ocket");
    /// client.send_to(b"hello", "/tmp/checker.sock").expect("send");
    ///
    /// let mut header = [0; 4];
    /// let (len, _from) = checker.peek_from_unix_addr(&mut header).expect("receive");
    /// if len != 4  ||  header != *b"WTFP" {
    ///     let _ = checker.recv(&mut header); // discard
    /// } else {
    ///     // call function that receives and processes it
    /// }
    /// #
    /// # let _ = std::fs::remove_file("/tmp/checker.sock");
    /// ```
    fn peek_from_unix_addr(&self,  buf: &mut[u8]) -> Result<(usize, UnixSocketAddr), io::Error> 
    {
        UnixSocketAddr::new_from_ffi(
            |addr, len| 
            {
            unsafe 
            {
                cvt_r!(
                    recvfrom(
                        self.as_raw_fd(),
                        buf.as_mut_ptr() as *mut c_void,
                        buf.len(),
                        MSG_PEEK | MSG_NOSIGNAL,
                        addr,
                        len,
                    )
                )
                .map(|signed| signed as usize )
            }
        })
    }

    /// Uses multiple buffers to read the next datagram without removing it
    /// from the queue.
    ///
    /// # Examples
    ///
    #[cfg_attr(any(target_os="linux", target_os="android"), doc="```")]
    #[cfg_attr(not(any(target_os="linux", target_os="android")), doc="```no_run")]
    /// use std::os::unix::net::UnixDatagram;
    /// use std::io::IoSliceMut;
    /// use tempfile::TempDir;
    /// use uds_fork::{UnixDatagramExt, UnixSocketAddr};
    /// 
    /// let dir = tempfile::tempdir().unwrap();
    /// let mut path = dir.path().join("datagram_server.sock");
    /// 
    /// let server = UnixDatagram::bind(&path).unwrap();
    ///
    /// // get a random abstract address on Linux
    /// let client = UnixDatagram::unbound().unwrap();
    /// client.bind_to_unix_addr(&UnixSocketAddr::new_unspecified()).unwrap();
    /// client.connect(&path).unwrap();
    /// client.send(b"headerbodybody").unwrap();
    ///
    /// let (mut buf_a, mut buf_b) = ([0; 6], [0; 12]);
    /// let mut vector = [IoSliceMut::new(&mut buf_a), IoSliceMut::new(&mut buf_b)];
    /// let (bytes, addr) = server.peek_vectored_from_unix_addr(&mut vector).unwrap();
    /// assert_eq!(addr, client.local_unix_addr().unwrap());
    /// assert_eq!(bytes, 14);
    /// assert_eq!(&buf_a, b"header");
    /// assert_eq!(&buf_b[..8], b"bodybody");
    /// #
    /// ```
    fn peek_vectored_from_unix_addr(&self,  bufs: &mut[IoSliceMut]) -> Result<(usize, UnixSocketAddr), io::Error> 
    {
        let mut addr = UnixSocketAddr::default();

        Ancillary::recv_ancillary(self,Some(&mut addr),MSG_PEEK | MSG_NOSIGNAL, bufs,&mut[])
            .map(|(bytes, _)| (bytes, addr) )
    }

    /// Sends file descriptors along with the datagram, on an unconnected socket.
    fn send_fds_to(&self, datagram: &[u8], fds: Vec<OwnedFd>, addr: &UnixSocketAddr) -> Result<usize, io::Error> 
    {
        let fds_raw = fds.iter().map(|fd| fd.as_raw_fd()).collect::<Vec<RawFd>>();

        send_ancillary(self, Some(addr), 0, &[IoSlice::new(datagram)], &fds_raw, None)
    }

    unsafe 
    fn send_fds_to_raw(&self, datagram: &[u8], fds: &[RawFd], addr: &UnixSocketAddr) -> Result<usize, io::Error> 
    {
        send_ancillary(self, Some(addr), 0, &[IoSlice::new(datagram)], fds, None)
    }

    /// Sends file descriptors along with the datagram, on a connected socket.
    fn send_fds(&self, datagram: &[u8], fds: Vec<OwnedFd>) -> Result<usize, io::Error> 
    {
        let fds_raw = fds.iter().map(|fd| fd.as_raw_fd()).collect::<Vec<RawFd>>();

        send_ancillary(self, None, 0, &[IoSlice::new(datagram)], &fds_raw, None)
    }

    unsafe 
    fn send_fds_raw(&self, datagram: &[u8], fds: &[RawFd]) -> Result<usize, io::Error> 
    {
        send_ancillary(self, None, 0, &[IoSlice::new(datagram)], 
            fds, None)
    }

    /// Receives file descriptors along with the datagram, on an unconnected socket
    fn recv_slice_fds_from(&self,  buf: &mut[u8],  fd_buf: &mut [Option<OwnedFd>]) -> Result<(usize, usize, UnixSocketAddr), io::Error> 
    {
        let mut addr = UnixSocketAddr::default();
        recv_slice_fds(self, Some(&mut addr), &mut[IoSliceMut::new(buf)], fd_buf)
            .map(|(bytes, _, fds)| (bytes, fds, addr) )
    }

    fn recv_fds_from(&self,  buf: &mut[u8],  fd_buf: &mut Vec<OwnedFd>) -> Result<(usize, usize, UnixSocketAddr), io::Error> 
    {
        let mut addr = UnixSocketAddr::default();

        recv_fds(self, Some(&mut addr), &mut[IoSliceMut::new(buf)], fd_buf)
            .map(|(bytes, _, fds)| (bytes, fds, addr) )
    }

    /// Receives file descriptors along with the datagram, on a connected socket
    fn recv_slice_fds(&self,  buf: &mut[u8],  fd_buf: &mut [Option<OwnedFd>]) -> Result<(usize, usize), io::Error> 
    {
        recv_slice_fds(self, None, &mut[IoSliceMut::new(buf)], fd_buf)
            .map(|(bytes, _, fds)| (bytes, fds) )
    }

    
    fn recv_fds(&self,  buf: &mut[u8],  fd_buf: &mut Vec<OwnedFd>) -> Result<(usize, usize), io::Error> 
    {
        recv_fds(self, None, &mut[IoSliceMut::new(buf)], fd_buf)
            .map(|(bytes, _, fds)| (bytes, fds) )
    }


    /// Returns the credentials of the process that created a socket pair.
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
    fn initial_pair_credentials(&self) -> Result<ConnCredentials, io::Error> 
    {
        peer_credentials(self)
    }
    /// Returns the SELinux security context of the process that created a socket pair.
    ///
    /// Has the same limitations and gotchas as `initial_pair_credentials()`,
    /// and will return an error on other OSes than Linux or Android
    /// or if running under kubernetes.
    ///
    /// The default security context is the string `unconfined`.
    fn initial_pair_selinux_context(&self,  buffer: &mut[u8]) -> Result<usize, io::Error> 
    {
        selinux_context(self, buffer)
    }
}

impl UnixDatagramExt for UnixDatagram 
{
    fn bind_unix_addr(addr: &UnixSocketAddr) -> Result<Self, io::Error> 
    {
        return 
            UnixDatagram::unbound()
                .map_or_else(
                    |e| Err(e), 
                    |socket|
                        socket
                            .bind_to_unix_addr(addr)
                            .map_or_else(
                                |e| Err(e), 
                                |_| Ok(socket)
                            )
                );
    }
}

#[cfg(feature = "mio")]
impl UnixDatagramExt for mio::net::UnixDatagram 
{
    fn bind_unix_addr(addr: &UnixSocketAddr) -> Result<Self, io::Error> 
    {
        return 
            mio::net::UnixDatagram
                ::unbound()
                    .map_or_else(
                        |e| Err(e), 
                        |socket|
                            socket
                                .bind_to_unix_addr(addr)
                                .map_or_else(
                                    |e| Err(e), 
                                    |_| Ok(socket)
                                )
                    );
    }
}
