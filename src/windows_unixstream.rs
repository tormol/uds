
use std::
{
    cmp::min, ffi::{c_int, c_void}, fs, io::{self, ErrorKind}, mem::{self, MaybeUninit}, net::Shutdown, os::windows::io::
    {
        AsRawSocket, AsSocket, BorrowedSocket, FromRawSocket, IntoRawSocket, OwnedSocket, RawSocket
    }, path::Path, ptr, sync::{LazyLock, OnceLock, atomic::{AtomicU64, Ordering}, mpsc}, thread::{self, JoinHandle}, time::Duration
};

use windows_sys::
{
    Win32::{Foundation::{HANDLE, HANDLE_FLAG_INHERIT, SetHandleInformation}, Networking::WinSock::
    {
        AF_UNIX, FIONBIO, INVALID_SOCKET, MSG_TRUNC, SD_BOTH, SD_RECEIVE, SD_SEND, SO_ERROR, SO_RCVTIMEO, SO_SNDTIMEO, SO_TYPE, SOCK_STREAM, SOCKADDR as sockaddr, SOCKADDR_UN, SOCKET_ERROR, SOL_SOCKET, TIMEVAL, WSA_FLAG_NO_HANDLE_INHERIT, WSA_FLAG_OVERLAPPED, WSACleanup, WSADATA, WSAEMSGSIZE, WSAESHUTDOWN, WSAPROTOCOL_INFOW, WSARecv, WSASend, WSASocketW, WSAStartup, accept, bind, connect, getpeername, getsockname, getsockopt, ioctlsocket, listen, recv, send, shutdown, socket, socklen_t
    }}, 
    core::PCSTR
};

use crate::{LISTEN_BACKLOG, UnixSocketAddr};


fn create_socket() -> io::Result<OwnedSocket>
{
     let socket_res = 
        unsafe 
        { 
            WSASocketW(
                AF_UNIX as i32, 
                SOCK_STREAM, 
                0, 
                ptr::null(), 
                0, 
                WSA_FLAG_NO_HANDLE_INHERIT | WSA_FLAG_OVERLAPPED
            ) 
        };

    if socket_res != INVALID_SOCKET
    {
        return Ok(
            unsafe{ OwnedSocket::from_raw_socket(socket_res as u64) }
        );
    }
    else
    {
        return Err(io::Error::last_os_error());
    }
}

fn connect_socket<S: AsRawSocket>(so: &S, addr: &UnixSocketAddr) -> io::Result<()>
{
    let sa =  unsafe{ addr.as_raw_ptr_general() };

    let res = unsafe { connect(so.as_raw_socket() as usize, sa.0, sa.1) };

    if res != SOCKET_ERROR
    {
        return Ok(());
    }
    else
    {
        return Err(io::Error::last_os_error());
    }
}

fn bind_socket<S: AsRawSocket>(so: &S, addr: &UnixSocketAddr) -> io::Result<()>
{
    let sa =  unsafe{ addr.as_raw_ptr_general() };

    let res = unsafe{ bind(so.as_raw_socket() as usize, sa.0, sa.1) };

    if res != SOCKET_ERROR
    {
        return Ok(());
    }
    else
    {
        return Err(io::Error::last_os_error());
    }
}

fn listen_socket<S: AsRawSocket>(so: &S, backlog: i32) -> io::Result<()>
{
    let res = unsafe{ listen(so.as_raw_socket() as usize, backlog) };

    if res != SOCKET_ERROR
    {
        return Ok(());
    }
    else
    {
        return Err(io::Error::last_os_error());
    }
}

/// Safe wrapper around `getsockname()` or `getpeername()`. 
fn get_unix_local_addr<FD>(socket: &FD) -> Result<UnixSocketAddr, io::Error> 
where FD: AsRawSocket
{
    unsafe 
    {
        UnixSocketAddr::new_from_ffi(
            |addr_ptr, addr_len| 
            {
                if getsockname(socket.as_raw_socket() as usize, addr_ptr, addr_len) != SOCKET_ERROR
                {
                    Ok(())
                }
                else
                {
                    Err(io::Error::last_os_error())
                }
            }
        )
        .map(|((), addr)| addr )
    }
}


fn get_unix_peer_addr<FD>(socket: &FD) -> Result<UnixSocketAddr, io::Error> 
where FD: AsRawSocket
{
    unsafe 
    {
        UnixSocketAddr::new_from_ffi(
            |addr_ptr, addr_len| 
            {
                if getpeername(socket.as_raw_socket() as usize, addr_ptr, addr_len)  != SOCKET_ERROR
                {
                    Ok(())
                }
                else
                {
                    Err(io::Error::last_os_error())
                }
            }
        )
        .map(|((), addr)| addr )
    }
}

pub 
fn get_socket_family<S: AsRawSocket>(fd: &S) -> io::Result<u16>
{
    let mut optval: MaybeUninit<SOCKADDR_UN> = MaybeUninit::zeroed();
    let mut len = size_of::<SOCKADDR_UN>() as socklen_t;
    

    let res = 
        unsafe
        {
            getsockname(fd.as_raw_socket() as usize,optval.as_mut_ptr().cast(), &mut len)
        };

    // more likely it will not fail
    if res != SOCKET_ERROR 
    {
        return Ok(unsafe { optval.assume_init() }.sun_family);
    }
    else
    {
        return Err(io::Error::last_os_error());
    }
}

pub 
fn get_socket_type<S: AsRawSocket>(fd: &S) -> io::Result<c_int>
{
    let mut optval: MaybeUninit<c_int> = MaybeUninit::zeroed();
    let mut len = size_of::<c_int>() as socklen_t;

    let res = 
        unsafe
        {
            getsockopt(fd.as_raw_socket() as usize, SOL_SOCKET, SO_TYPE,
                optval.as_mut_ptr().cast(),&mut len,
            )
        };

    // more likely it will not fail
    if res == 0
    {
        if len as usize != size_of::<c_int>()
        {
            return Err(
                std::io::Error::new(
                    ErrorKind::Other, 
                    format!("assertion trap: returned data len mispatch {} != {}",
                            len, size_of::<c_int>())
                )
            );
        }

        return Ok(unsafe { optval.assume_init() });
    }
    else
    {
        return Err(io::Error::last_os_error());
    }
}

/// Safe wrapper around `getsockopt(SO_ERROR)`.
fn take_error<FD>(socket: &FD) -> Result<Option<io::Error>, io::Error> 
where FD: AsRawSocket
{
    let mut stored_errno: c_int = 0;
    let mut optlen = mem::size_of::<c_int>() as socklen_t;
    let dst_ptr = &mut stored_errno as *mut c_int as *mut u8;
    
    unsafe 
    {
        if getsockopt(socket.as_raw_socket() as usize, SOL_SOCKET, SO_ERROR, dst_ptr, &mut optlen) == -1 
        {
            Err(io::Error::last_os_error())
        } 
        else if optlen != mem::size_of::<c_int>() as socklen_t 
        {
            // std panics here
            Err(
                io::Error::new(
                    ErrorKind::InvalidData,
                    "got unexpected length from getsockopt(SO_ERROR)"
                )
            )
        } 
        else if stored_errno == 0 
        {
            Ok(None)
        } 
        else 
        {
            Ok(Some(io::Error::last_os_error()))
        }
    }
}

fn set_nonblocking<FD: AsRawSocket>(so: &FD,  nonblocking: bool) -> Result<(), io::Error> 
{
    let mut nonblocking = if nonblocking { 1 } else { 0 };

    let res = unsafe{ ioctlsocket(so.as_raw_socket() as usize, FIONBIO, &mut nonblocking) };

    if res == SOCKET_ERROR
    {
        return Err(io::Error::last_os_error());
    }

    return Ok(());
}
 
fn accept_from<FD>(fd: &FD, nonblocking: bool) -> Result<(WindowsUnixStream, UnixSocketAddr), io::Error> 
where FD: AsRawSocket
{
    unsafe 
    { 
        UnixSocketAddr::new_from_ffi(
            |addr_ptr, len_ptr| 
            {
                let socket = 
                    accept(fd.as_raw_socket() as usize, addr_ptr, len_ptr);

                if socket == INVALID_SOCKET
                {
                    return Err(io::Error::last_os_error());
                }

                let o_sock = WindowsUnixStream::from_raw_socket_checked(socket as u64);

                if nonblocking  == true
                {
                    set_nonblocking(&o_sock, true)?;
                }

                return Ok(o_sock);
            }
        ) 
    }
}


fn shutdown_sock<SOCK: AsRawSocket>(sock: &SOCK, how: Shutdown) -> io::Result<()> 
{
    let res = 
        match how 
        {
            Shutdown::Write => 
                unsafe{ shutdown(sock.as_raw_socket() as usize, SD_SEND) },
            Shutdown::Read =>
                unsafe{ shutdown(sock.as_raw_socket() as usize, SD_RECEIVE) },
            Shutdown::Both => 
                unsafe{ shutdown(sock.as_raw_socket() as usize, SD_BOTH) },
        };

    if res == -1
    {
        return Err(io::Error::last_os_error());
    }

    return Ok(());
}

/// `noinherit` - when set to `true` means noinherit
fn set_handle_inherit<S: AsRawSocket>(sock: &S, noinherit: bool) -> io::Result<()>
{
    let res = 
        unsafe 
        {
            SetHandleInformation(
                sock.as_raw_socket() as HANDLE,
                HANDLE_FLAG_INHERIT,
                (noinherit == false) as u32,
            )
        };

    if res != 0
    {
        return Ok(());
    }

    return Err(io::Error::last_os_error());
}

pub struct SockOpts
{
    optname: i32,
    opt: SockOpt,
}

impl SockOpts
{
    const LEVEL: i32 = SOL_SOCKET;

    fn from_opt_duration(value: Option<Duration>) -> TIMEVAL
    {
        value
            .map_or(
                TIMEVAL{ tv_sec: 0, tv_usec: 0 },
                |v| 
                TIMEVAL
                { 
                    tv_sec: min(v.as_secs(), i32::MAX as u64) as i32,
                    tv_usec: v.subsec_micros() as i32,
                }
            )
    }

    fn from_timeval(value: TIMEVAL) -> Option<Duration>
    {
        if value.tv_sec == 0 && value.tv_usec == 0 
        {
            return None;
        } 
        else 
        {
            let sec = value.tv_sec as u64;
            let nsec = (value.tv_usec as u32) * 1000;

            return Some(Duration::new(sec, nsec));
        }
    }

    fn set_rcv_timeout<SOCK: AsRawSocket>(sock: &SOCK, tm: Option<Duration>) -> io::Result<()>
    {
        let op = 
            Self
            {
                optname: SO_RCVTIMEO,
                opt: 
                    SockOpt::RcvTimeout(Self::from_opt_duration(tm))
            };

        return op.setsockopt(sock);
    }

    fn get_rcv_timeout<SOCK: AsRawSocket>(sock: &SOCK) -> io::Result<Option<Duration>>
    {
        let op = 
            Self
            {
                optname: SO_RCVTIMEO,
                opt: 
                    SockOpt::RcvTimeout(TIMEVAL::default())
            };

        let SockOpt::RcvTimeout(v) = op.getsockopt(sock)?
            else
            {   
                return Err(
                    io::Error::new(ErrorKind::Other, "assertion trap: expected SockOpt::RcvTimeout")
                );
            };

        return Ok(Self::from_timeval(v));
    }

    fn set_snd_timeout<SOCK: AsRawSocket>(sock: &SOCK, tm: Option<Duration>) -> io::Result<()>
    {
        let op = 
            Self
            {
                optname: SO_SNDTIMEO,
                opt: 
                    SockOpt::SndTimeout(Self::from_opt_duration(tm))
            };

        return op.setsockopt(sock);
    }

    fn get_snd_timeout<SOCK: AsRawSocket>(sock: &SOCK) -> io::Result<Option<Duration>>
    {
        let op = 
            Self
            {
                optname: SO_SNDTIMEO,
                opt: 
                    SockOpt::SndTimeout(TIMEVAL::default())
            };

        let SockOpt::SndTimeout(v) = op.getsockopt(sock)?
            else
            {   
                return Err(
                    io::Error::new(ErrorKind::Other, "assertion trap: expected SockOpt::SndTimeout")
                );
            };

        return Ok(Self::from_timeval(v));
    }

    fn getsockopt<SOCK>(self, sock: &SOCK) -> io::Result<SockOpt>
    where 
        SOCK: AsRawSocket
    {
        let (mut optval, mut len) = 
            match self.opt
            {
                SockOpt::RcvTimeout(timeval) =>
                    (MaybeUninit::<TIMEVAL>::zeroed(), size_of_val(&timeval) as i32),
                SockOpt::SndTimeout(timeval) => 
                    (MaybeUninit::<TIMEVAL>::zeroed(), size_of_val(&timeval) as i32),
            };

        let res = 
            unsafe
            {
                windows_sys::Win32::Networking::WinSock
                    ::getsockopt(sock.as_raw_socket() as usize,Self::LEVEL, self.optname,
                        optval.as_mut_ptr().cast(),&mut len,
                )
            };

        // more likely it will not fail
        if res != SOCKET_ERROR
        {
            match self.opt
            {
                SockOpt::RcvTimeout(_) =>
                    return Ok(unsafe { SockOpt::RcvTimeout(optval.assume_init()) }),
                SockOpt::SndTimeout(_) => 
                    return Ok(unsafe { SockOpt::SndTimeout(optval.assume_init()) }),
            }
        }
        else
        {
            return Err(std::io::Error::last_os_error());
        }
    }

    fn setsockopt<SOCK>(self, fd: &SOCK) -> io::Result<()>
    where 
        SOCK: AsRawSocket
    {
        let (optval, option_len) = 
            match self.opt
            {
                SockOpt::RcvTimeout(timeval) =>
                    (ptr::addr_of!(timeval).cast(), size_of_val(&timeval) as i32),
                SockOpt::SndTimeout(timeval) => 
                    (ptr::addr_of!(timeval).cast(), size_of_val(&timeval) as i32),
            };

        let res = 
            unsafe
            {
                windows_sys::Win32::Networking::WinSock
                    ::setsockopt(fd.as_raw_socket() as usize, Self::LEVEL, self.optname, 
                        optval, option_len) 
            };

        // more likely it will not fail
        if res != SOCKET_ERROR
        {
            return Ok(());
        }
        else
        {
            return Err(std::io::Error::last_os_error());
        }
    }
}

pub enum SockOpt
{
    RcvTimeout(TIMEVAL),
    SndTimeout(TIMEVAL),
}
 


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecvFlags(pub u32);

impl RecvFlags
{
    pub const MSG_TRUNC: u32 = MSG_TRUNC;
}

fn recv_vectored<S: AsRawSocket>(socket: &S, bufs: &mut [io::IoSliceMut<'_>], flags: c_int) -> io::Result<(usize, RecvFlags)> 
{
    let mut nread = 0;
    let mut flags = flags as u32;
    let res = 
         unsafe
         {
            WSARecv(
                socket.as_raw_socket() as usize,
                bufs.as_mut_ptr().cast(),
                min(bufs.len(), u32::MAX as usize) as u32,
                &mut nread,
                &mut flags,
                ptr::null_mut(),
                None,
            )
        };

    if res == SOCKET_ERROR
    {
        let e = io::Error::last_os_error();

        if e.raw_os_error() == Some(WSAESHUTDOWN as i32)
        {
            return Ok( (0, RecvFlags(0)) );
        }
        else if e.raw_os_error() ==  Some(WSAEMSGSIZE as i32)
        {
            return Ok( (nread as usize, RecvFlags(RecvFlags::MSG_TRUNC)) );
        }
        else
        {
            return Err(e);
        }
    }

    return Ok( (nread as usize, RecvFlags(0)) );
}

fn send_vectored<S: AsRawSocket>(socket: &S, bufs: &[io::IoSlice<'_>], flags: c_int) -> io::Result<usize> 
{
    let mut nsent = 0;

    let res = 
        unsafe
        {
            WSASend(
                socket.as_raw_socket() as usize,
                bufs.as_ptr() as *mut _,
                min(bufs.len(), u32::MAX as usize) as u32,
                &mut nsent,
                flags as u32,
                std::ptr::null_mut(),
                None,
            )
        };

    if res == SOCKET_ERROR
    {
        return Err(io::Error::last_os_error());
    }

    return Ok( nsent as usize);
}

#[derive(Debug)]
struct WsaLazyThing;

impl Drop for WsaLazyThing
{
    fn drop(&mut self) 
    {
        unsafe
        {
            WSACleanup();
        }
    }
}

static WSA_STARTUP: LazyLock<WsaLazyThing> = 
    LazyLock::new(
        ||
        {
            let mut wsadata = MaybeUninit::<WSADATA>::zeroed();
            
            let res = unsafe{ WSAStartup(0x0202, wsadata.as_mut_ptr()) };

            if res != 0
            {
                panic!("WSAStartup error: {}", io::Error::last_os_error());
            }

            WsaLazyThing
        }
    );


/// An unix domain `stream` packet connection for Windows.
/// 
/// It requires WSA version 2.0 or 2.2 i.e Windows 10 and above.
/// 
/// The crate requests version 2.2 by default!
///
/// Is simular to the `UnixStream` but with some limitations:
/// 
/// * no `SOCK_DGRAM` or `SOCK_SEQPACKET` support
/// 
/// * Ancillary data like `SCM_RIGHTS` `SCM_CREDENTIALS`
/// 
/// * Autobind feature
/// 
/// * socketpair
///
/// # Examples
///
/// ```ignore
/// let path = "server3.sock";
/// 
/// let client = WindowsUnixStream::connect(path).unwrap();
/// client.send(b"first").unwrap();
/// client.send(b"second").unwrap();
/// ```
#[derive(Debug)]
#[repr(transparent)]
pub struct WindowsUnixStream
{
    sock: OwnedSocket,
}

impl FromRawSocket for WindowsUnixStream
{
    unsafe 
    fn from_raw_socket(sock: RawSocket) -> Self 
    {
        let os = unsafe{ OwnedSocket::from_raw_socket(sock) };

        return WindowsUnixStream::from(os);
    }
}

impl From<OwnedSocket> for WindowsUnixStream
{
    fn from(os: OwnedSocket) -> Self 
    {
        let sa_fam = get_socket_family(&os).unwrap();
        let sa_type = get_socket_type(&os).unwrap();

        if sa_fam != AF_UNIX || sa_type != SOCK_STREAM
        {
            panic!("assertion trap: provided FD is not AF_UNIX & SOCK_STREAM, {} {}", 
                sa_fam, sa_type);
        }

        let _ = &*WSA_STARTUP;

        return Self{ sock: os };
    }
}

impl From<WindowsUnixStream> for OwnedSocket
{
    fn from(value: WindowsUnixStream) -> Self 
    {
        return value.sock;
    }
}

impl AsSocket for WindowsUnixStream
{
    fn as_socket(&self) -> BorrowedSocket<'_> 
    {
        return self.sock.as_socket();
    }
}

impl AsRawSocket for WindowsUnixStream
{
    fn as_raw_socket(&self) -> RawSocket 
    {
        return self.sock.as_raw_socket();
    }
}

impl IntoRawSocket for WindowsUnixStream
{
    fn into_raw_socket(self) -> RawSocket 
    {
        return self.sock.into_raw_socket();
    }
}

impl io::Write for WindowsUnixStream
{
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> 
    {
        self.send(buf)
    }

    /// Do not access `bufs` after sending!
    fn write_vectored(&mut self, bufs: &[io::IoSlice<'_>]) -> io::Result<usize> 
    {
        send_vectored(self, &bufs, 0)
    }
    
    fn flush(&mut self) -> io::Result<()>
    {
        todo!()
    }
}

impl io::Read for WindowsUnixStream
{
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> 
    {
        self.recv(buf)
    }

    fn read_vectored(&mut self, bufs: &mut [io::IoSliceMut<'_>]) -> io::Result<usize> 
    {
        self.recv_vectored(bufs).map(|(n, _)| n)
    }
}


/*#[cfg(feature = "xio-rs")]
pub mod xio_unix_stream_enabled
{
    use xio_rs::{EsInterfaceRegistry, XioChannel, XioEventPipe, XioEventUid, XioResult, event_registry::XioRegistry};

    use super::WindowsUnixStream;

    impl<ESSR: EsInterfaceRegistry> XioEventPipe<ESSR, Self> for WindowsUnixStream
    {
        fn connect_event_pipe(&mut self, ess: &XioRegistry<ESSR>, ev_uid: XioEventUid, channel: XioChannel) -> XioResult<()> 
        {
            self.set_nonblocking(true)?;

            ess.get_ev_sys().en_register(&self.sock, ev_uid, channel)
        }
    
        fn modify_event_pipe(&mut self, ess: &XioRegistry<ESSR>, ev_uid: XioEventUid, channel: XioChannel) -> XioResult<()> 
        {
            ess.get_ev_sys().modify(&self.sock, ev_uid, channel)
        }
    
        fn disconnect_event_pipe(&mut self, ess: &XioRegistry<ESSR>) -> XioResult<()> 
        {
            ess.get_ev_sys().de_register(&self.sock)
        }
    }
}*/

impl WindowsUnixStream
{
    unsafe 
    fn from_raw_socket_checked(raw_sock: RawSocket) -> Self 
    {
        let os = unsafe{ OwnedSocket::from_raw_socket(raw_sock) };

        let _ = &*WSA_STARTUP;

        return Self{ sock: os };
    }

    /// Connects to an unix stream server listening at `path`.
    ///
    /// This is a wrapper around [`connect_unix_addr()`](#method.connect_unix_addr)
    /// for convenience and compatibility with std.
    pub 
    fn connect<P: AsRef<Path>>(path: P) -> Result<Self, io::Error> 
    {
        let addr = UnixSocketAddr::from_path(&path)?;

        return Self::connect_unix_addr(&addr);
    }

    /// Connects to an unix seqpacket server listening at `addr`.
    pub 
    fn connect_unix_addr(addr: &UnixSocketAddr) -> Result<Self, io::Error> 
    {
        let _ = &*WSA_STARTUP;

        let socket = create_socket()?;

        connect_socket(&socket, addr)?;

        return Ok( Self{ sock: socket } );
    }

    /// Binds to an address before connecting to a listening seqpacet socket.
    pub 
    fn connect_from_to_unix_addr(from: &UnixSocketAddr,  to: &UnixSocketAddr) -> Result<Self, io::Error> 
    {
        let _ = &*WSA_STARTUP;

        let socket = create_socket()?;

        bind_socket(&socket, from)?;

        connect_socket(&socket, to)?;

        return Ok( Self{ sock: socket } );
    }

    /// Creates a socket pair.
    pub 
    fn pair() -> Result<(Self, Self), io::Error> 
    {
        let dir = tempfile::tempdir()?;
        let file_path = dir.path().join("so_pair");

        let bind = WindowsUnixListener::bind(&file_path)?;
       
        let handle0: JoinHandle<Result<WindowsUnixStream, io::Error>> = 
            thread::spawn(move ||
                {
                    let (s, a) = bind.accept_unix_addr()?;

                    return Ok(s);
                }
            );
        
        let s1 = Self::connect(&file_path)?;

        let s2 = 
            handle0
                .join()
                .map_err(|e| 
                    io::Error::new(ErrorKind::Other, format!("join error: {:?}", e))
                )??;

        return Ok( (s1, s2) );
    }

    pub 
    fn try_clone(&self) -> io::Result<Self>
    {
        self.sock.try_clone().map(|osck| Self { sock: osck })
    }

    pub 
    fn set_nonblocking(&self, nonblk: bool) -> io::Result<()>
    {
        set_nonblocking(self, nonblk)
    }

    ///  Cloexec
    pub 
    fn set_no_inherit(&self, no_inh: bool) -> io::Result<()>
    {
        set_handle_inherit(&self.sock, no_inh)
    }

    pub 
    fn set_write_timeout(&self, timeout: Option<Duration>) -> io::Result<()>
    {
        SockOpts::set_snd_timeout(&self.sock, timeout)
    }

    pub 
    fn write_timeout(&self) -> io::Result<Option<Duration>>
    {
        SockOpts::get_snd_timeout(&self.sock)
    }

    pub 
    fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()>
    {
        SockOpts::set_rcv_timeout(&self.sock, timeout)
    }

    pub 
    fn read_timeout(&self) -> io::Result<Option<Duration>>
    {
        SockOpts::get_rcv_timeout(&self.sock)
    }

    /// Returns the address of this side of the connection.
    pub 
    fn local_unix_addr(&self) -> Result<UnixSocketAddr, io::Error> 
    {
        get_unix_local_addr(self)
    }

    /// Returns the address of the other side of the connection.
    pub 
    fn peer_unix_addr(&self) -> Result<UnixSocketAddr, io::Error> 
    {
        get_unix_peer_addr(self)
    }

    /// Sends a packet to the peer.
    pub 
    fn send(&self, packet: &[u8]) -> Result<usize, io::Error> 
    {
        let ptr = packet.as_ptr();
        let pkt_len = min(packet.len(), i32::MAX as usize) as i32;
        let flags = 0;

        let sent = unsafe { send(self.sock.as_raw_socket() as usize, ptr, pkt_len, flags) };
        
        if sent != SOCKET_ERROR
        {
            return Ok(sent as usize);
        }
        
        return Err(std::io::Error::last_os_error());
    }

    /// Receives a packet from the peer.
    pub 
    fn recv(&self, buffer: &mut[u8]) -> Result<usize, io::Error> 
    {
        let ptr = buffer.as_mut_ptr();
        let pkt_len = min(buffer.len(), i32::MAX as usize) as i32;
        let received = unsafe { recv(self.sock.as_raw_socket() as usize, ptr, pkt_len, 0) };
        
        if received >= 0
        {
            return Ok(received as usize);
        }

        return Err(std::io::Error::last_os_error());
    }

    pub 
    fn recv_vectored(&self, bufs: &mut [io::IoSliceMut<'_>]) -> io::Result<(usize, RecvFlags)> 
    {
        recv_vectored(self, bufs, 0)
    }

    /// Windows consumes the [io::IoSlice] instances, so can no logner be accessed.
    /// The [io::Write] borrows, but it is not correct. DO not access the slices after
    /// it were sent.
    pub 
    fn send_vectored(&self, bufs: Vec<io::IoSlice<'_>>) -> io::Result<usize>
    {
        send_vectored(self, &bufs, 0)
    }

    /// Returns the value of the `SO_ERROR` option.
    ///
    /// This might only provide errors generated from nonblocking `connect()`s,
    /// which this library doesn't support. It is therefore unlikely to be 
    /// useful, but is provided for parity with stream counterpart in std.
    pub 
    fn take_error(&self) -> Result<Option<io::Error>, io::Error> 
    {
        take_error(self)
    }

    /// Allows to shudown receiving/sending or both sides.
    pub 
    fn shutdown(&self, how: Shutdown) -> io::Result<()>
    {
        shutdown_sock(&self.sock, how)
    }
}

/// An unix domain listener for [SOCK_STREAM] packet connections which requires
/// WSA version 2.2 i.e Windows 10 minimum.
///
/// See [`WindowsUnixStream`](struct.WindowsUnixStream.html) for a description
/// of this type of connection.
///
/// # Examples
///
/// ```no_run
/// let file_path = "server_test.sock";
/// let listener = uds_fork::WindowsUnixListener::bind(file_path)
///     .expect("Create seqpacket listener");
/// let client = uds_fork::WindowsUnixStream::connect(file_path).unwrap();
/// let (conn, _addr) = listener.accept_unix_addr().unwrap();
/// conn.send(b"Welcome").unwrap();
/// std::thread::sleep(std::time::Duration::from_secs(1));
/// drop(client);
/// ```
#[repr(transparent)]
#[derive(Debug)]
pub struct WindowsUnixListener
{
    sock: OwnedSocket,
}


impl FromRawSocket for WindowsUnixListener
{
    unsafe 
    fn from_raw_socket(sock: RawSocket) -> Self 
    {
        let os = unsafe{ OwnedSocket::from_raw_socket(sock) };

        return WindowsUnixListener::from(os);
    }
}

impl From<OwnedSocket> for WindowsUnixListener
{
    fn from(os: OwnedSocket) -> Self 
    {
        let sa_fam = get_socket_family(&os).unwrap();
        let sa_type = get_socket_type(&os).unwrap();

        if sa_fam != AF_UNIX || sa_type != SOCK_STREAM
        {
            panic!("assertion trap: provided FD is not AF_UNIX & SOCK_SEQPACKET, {} {}", 
                sa_fam, sa_type);
        }

        let _ = &*WSA_STARTUP;

        return Self{ sock: os };
    }
}

impl From<WindowsUnixListener> for OwnedSocket
{
    fn from(mut value: WindowsUnixListener) -> Self 
    {
        return value.sock;
    }
}

impl AsSocket for WindowsUnixListener
{
    fn as_socket(&self) -> BorrowedSocket<'_> 
    {
        return self.sock.as_socket();
    }
}

impl AsRawSocket for WindowsUnixListener
{
    fn as_raw_socket(&self) -> RawSocket 
    {
        return self.sock.as_raw_socket();
    }
}

impl IntoRawSocket for WindowsUnixListener
{
    fn into_raw_socket(mut self) -> RawSocket 
    {
        return self.sock.into_raw_socket();
    }
}

/*
/// A XIO [XioEventPipe] implementation.
#[cfg(feature = "xio-rs")]
pub mod xio_listener_enabled
{
    use xio_rs::{EsInterfaceRegistry, XioChannel, XioEventPipe, XioEventUid, XioResult, event_registry::XioRegistry};

    use super::WindowsUnixListener;

    impl<ESSR: EsInterfaceRegistry> XioEventPipe<ESSR, Self> for WindowsUnixListener
    {
        fn connect_event_pipe(&mut self, ess: &XioRegistry<ESSR>, ev_uid: XioEventUid, channel: XioChannel) -> XioResult<()> 
        {
            self.set_nonblocking(true)?;

            ess.get_ev_sys().en_register(&self.sock, ev_uid, channel)
        }
    
        fn modify_event_pipe(&mut self, ess: &XioRegistry<ESSR>, ev_uid: XioEventUid, channel: XioChannel) -> XioResult<()> 
        {
            ess.get_ev_sys().modify(&self.sock, ev_uid, channel)
        }
    
        fn disconnect_event_pipe(&mut self, ess: &XioRegistry<ESSR>) -> XioResult<()> 
        {
            ess.get_ev_sys().de_register(&self.sock)
        }
    }
}
    */

impl WindowsUnixListener
{
     /// Creates a socket that listens for seqpacket connections on the specified socket file.
    pub 
    fn bind<P: AsRef<Path>>(path: P) -> Result<Self, io::Error> 
    {
        let addr = UnixSocketAddr::from_path(path.as_ref())?;
        
        return Self::bind_unix_addr(&addr);
    }

    /// Creates a socket that listens for seqpacket connections on the specified address.
    /// 
    /// [`addr`]: uds_fork::addr::UnixSocketAddr
    pub 
    fn bind_unix_addr(addr: &UnixSocketAddr) -> Result<Self, io::Error> 
    {
        let _ = &*WSA_STARTUP;

        let socket = create_socket()?;

        bind_socket(&socket, addr)?;

        listen_socket(&socket, LISTEN_BACKLOG)?;
        
        return Ok(Self{ sock: socket });
    }
 
    pub 
    fn set_nonblocking(&self, nonblk: bool) -> io::Result<()>
    {
        set_nonblocking(self, nonblk)
    }

    /// Returns the address the socket is listening on.
    pub 
    fn local_unix_addr(&self) -> Result<UnixSocketAddr, io::Error> 
    {
        get_unix_local_addr(self)
    }

    pub 
    fn listen(&self, backlog: i32) -> io::Result<()>
    {
        listen_socket(self, backlog)
    }

    /// Accepts a new incoming connection to this listener.
    /// 
    /// Rustdocs: 
    /// > This function will block the calling thread until a new Unix connection
    /// > is established. When established, the corresponding [`WindowsUnixStream`] and
    /// > the remote peer's address will be returned.
    /// 
    /// [`WindowsUnixStream`]: uds_fork::WindowsUnixStream
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use uds_fork::WindowsUnixListener;
    ///
    /// fn main() -> std::io::Result<()> 
    /// {
    ///     let listener = WindowsUnixListener::bind("/path/to/the/socket")?;
    ///
    ///     match listener.accept()
    ///     {
    ///         Ok((socket, addr)) => 
    ///             println!("Got a client: {addr:?}"),
    ///         Err(e) => 
    ///             println!("accept function failed: {e:?}"),
    ///     }
    /// 
    ///     return Ok(());
    /// }
    /// ```
    #[inline]
    pub 
    fn accept(&self)-> Result<(WindowsUnixStream, UnixSocketAddr), io::Error> 
    {
        self.accept_unix_addr()
    }

    /// Creates a new independently owned handle to the underlying socket.
    /// 
    /// Rustdocs:
    /// > The returned `WindowsUnixListener` is a reference to the same socket that this
    /// > object references. Both handles can be used to accept incoming
    /// > connections and options set on one listener will affect the other.
    pub 
    fn try_clone(&self) -> io::Result<Self> 
    {
        return Ok(
            Self
            {
                sock: self.sock.try_clone()?
            }
        );
    }

    /// Accepts a new incoming connection to this listener.
    /// 
    /// Rustdocs: 
    /// > This function will block the calling thread until a new Unix connection
    /// > is established. When established, the corresponding [`WindowsUnixStream`] and
    /// > the remote peer's address will be returned.
    /// 
    /// [`WindowsUnixStream`]: uds_fork::WindowsUnixStream
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use uds_fork::WindowsUnixListener;
    ///
    /// fn main() -> std::io::Result<()> 
    /// {
    ///     let listener = WindowsUnixListener::bind("/path/to/the/socket")?;
    ///
    ///     match listener.accept_unix_addr()
    ///     {
    ///         Ok((socket, addr)) => 
    ///             println!("Got a client: {addr:?}"),
    ///         Err(e) => 
    ///             println!("accept function failed: {e:?}"),
    ///     }
    /// 
    ///     return Ok(());
    /// }
    /// ```
    pub 
    fn accept_unix_addr(&self)-> Result<(WindowsUnixStream, UnixSocketAddr), io::Error> 
    {
        let (socket, addr) = accept_from(self, false)?;
        
        return Ok((socket, addr));
    }

    /// Returns the value of the `SO_ERROR` option.
    ///
    /// This might never produce any errors for listeners. It is therefore
    /// unlikely to be useful, but is provided for parity with
    /// `std::unix::net::UnixListener`.
    pub 
    fn take_error(&self) -> Result<Option<io::Error>, io::Error> 
    {
        take_error(self)
    }

    /// Returns an iterator over incoming connections.
    /// 
    /// Rustdoc:
    /// > The iterator will never return [`None`] and will also not yield the
    /// > peer's [`UnixSocketAddr`] structure.
    /// 
    /// ```no_run
    /// use std::thread;
    /// use uds_fork::{WindowsUnixStream, WindowsUnixListener};
    ///
    /// fn handle_client(stream: WindowsUnixStream) 
    /// {
    ///     // ...
    /// }
    ///
    /// fn main() -> std::io::Result<()> 
    /// {
    ///     let listener = WindowsUnixListener::bind("/path/to/the/socket")?;
    ///
    ///     for stream in listener.incoming() 
    ///     {
    ///         match stream 
    ///         {
    ///             Ok(stream) => 
    ///             {
    ///                 thread::spawn(|| handle_client(stream));
    ///             },
    ///             Err(err) => 
    ///             {
    ///                 break;
    ///             }
    ///         }
    ///     }
    /// 
    ///     return Ok(());
    /// }
    /// ```
    pub 
    fn incoming(&self) -> Incoming<'_> 
    {
        Incoming { listener: self }
    }
}

/// A rust std API.
/// 
/// From Rustdocs:
/// > An iterator over incoming connections to a [`UnixListener`].
/// >
/// > It will never return [`None`].
/// 
/// # Examples
///
/// ```no_run
/// use std::thread;
/// use uds_fork::{WindowsUnixStream, WindowsUnixListener};
///
/// fn handle_client(stream: WindowsUnixStream) {
///     // ...
/// }
///
/// fn main() -> std::io::Result<()> 
/// {
///     let listener = WindowsUnixListener::bind("/path/to/the/socket")?;
///
///     for stream in listener.incoming() 
///     {
///         match stream 
///         {
///             Ok(stream) => 
///             {
///                 thread::spawn(|| handle_client(stream));
///             }
///             Err(err) => 
///             {
///                 break;
///             }
///         }
///     }
///     return Ok(());
/// }
/// ```
#[derive(Debug)]
pub struct Incoming<'a> 
{
    listener: &'a WindowsUnixListener,
}

impl<'a> Iterator for Incoming<'a> 
{
    type Item = io::Result<WindowsUnixStream>;

    fn next(&mut self) -> Option<io::Result<WindowsUnixStream>> 
    {
        Some(self.listener.accept().map(|s| s.0))
    }

    fn size_hint(&self) -> (usize, Option<usize>) 
    {
        (usize::MAX, None)
    }
}

impl<'a> IntoIterator for &'a WindowsUnixListener 
{
    type Item = io::Result<WindowsUnixStream>;
    type IntoIter = Incoming<'a>;

    fn into_iter(self) -> Incoming<'a> 
    {
        self.incoming()
    }
}