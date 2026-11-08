/* See each function for copyright holders */

/// Functions to handle OS differences.
/// Several adapted from std.

use std::marker::PhantomData;
use std::mem::MaybeUninit;
use std::os::unix::io::{RawFd, AsFd, AsRawFd, IntoRawFd, BorrowedFd, FromRawFd, OwnedFd};
use std::io::{self, ErrorKind};
use std::{fmt, mem, ptr};
use std::time::Duration;

use libc::{AF_UNIX, SO_TYPE, SOCK_SEQPACKET, SOCK_STREAM, c_int, socklen_t};
use libc::{bind, connect, getsockname, getpeername};
use libc::{socket, accept, listen, socketpair};
use libc::{ioctl, FIONBIO};
#[cfg(not(target_os = "haiku"))]
use libc::{FIOCLEX,FIONCLEX};
use libc::{EINVAL, dup};
use libc::{getsockopt, SOL_SOCKET, SO_ERROR, c_void};
#[cfg_attr(target_env="musl", allow(deprecated))]
use libc::{setsockopt, SO_RCVTIMEO, SO_SNDTIMEO, timeval};
#[cfg(any(target_os="illumos", target_os="solaris"))]
use libc::{F_GETFD, F_SETFD, FD_CLOEXEC};
#[cfg(not(any(target_vendor="apple", target_os = "haiku")))]
use libc::{SOCK_CLOEXEC, SOCK_NONBLOCK};
#[cfg(not(any(target_vendor="apple", target_os = "haiku", all(target_os="android", target_arch="x86"))))]
use libc::{accept4, ENOSYS};
#[cfg(target_vendor="apple")]
use libc::SO_NOSIGPIPE;

use crate::{LISTEN_BACKLOG, addr::*};







#[cfg(not(target_vendor="apple"))]
pub use libc::MSG_NOSIGNAL;
#[cfg(target_vendor="apple")]
pub const MSG_NOSIGNAL: c_int = 0; // SO_NOSIGPIPE is set instead


/// Enables / disables CLOEXEC, for when SOCK_CLOEXEC can't be used.
#[cfg(not(target_os = "haiku"))]
pub(crate) 
fn set_cloexec<FD: AsFd>(fd: FD, close_on_exec: bool) -> Result<(), io::Error> 
{
    let op = if close_on_exec {FIOCLEX} else {FIONCLEX};

    let res = cvt!(unsafe { ioctl(fd.as_fd().as_raw_fd(), op) });

    #[cfg(any(target_os="illumos", target_os="solaris"))]
    if let Err(e) = res && e.kind() == ErrorKind::InvalidInput
    {
        unsafe 
        {
            let prev = cvt!(fcntl(fd.as_fd().as_raw_fd(), F_GETFD))?;
            let change_to = if close_on_exec {prev | FD_CLOEXEC} else {prev & !FD_CLOEXEC};
            if change_to != prev 
            {
                cvt!(fcntl(fd.as_fd().as_raw_fd(), F_SETFD, change_to))?;
            }
            
            return Ok(());
        }
    }

    return res.map(|_| ());
}

#[cfg(target_os = "haiku")]
pub(crate) 
fn set_cloexec<FD: AsFd>(_fd: FD,  _: bool) -> Result<(), io::Error> 
{
    Ok(())
}


/// Enables / disables FIONBIO. Used if SOCK_NONBLOCK can't be used.
pub 
fn set_nonblocking<FD: AsFd>(fd: FD,  nonblocking: bool) -> Result<(), io::Error> 
{
    return 
        cvt!(unsafe { ioctl(fd.as_fd().as_raw_fd(), FIONBIO, &mut (nonblocking as c_int)) })
            .map(|_| ());
}


pub 
fn get_socket_family<S: AsFd>(fd: &S) -> io::Result<u16>
{
    let mut optval: MaybeUninit<libc::sockaddr> = MaybeUninit::zeroed();
    let mut len = size_of::<libc::sockaddr>() as libc::socklen_t;
    

    let res = 
        unsafe
        {
            libc::getsockname(fd.as_fd().as_raw_fd(),optval.as_mut_ptr().cast(), &mut len)
        };

    // more likely it will not fail
    if res == 0
    {
        // .into() fixes compilation error on FreeBSD as it has u8 for sa_family
        return Ok(unsafe { optval.assume_init() }.sa_family.into());
    }
    else
    {
        return Err(std::io::Error::last_os_error());
    }
}

pub 
fn get_socket_type<S: AsFd>(fd: &S) -> io::Result<c_int>
{
    let mut optval: MaybeUninit<c_int> = MaybeUninit::zeroed();
    let mut len = size_of::<c_int>() as libc::socklen_t;

    let res = 
        unsafe
        {
            libc::getsockopt(fd.as_fd().as_raw_fd(),SOL_SOCKET,SO_TYPE,
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
        return Err(std::io::Error::last_os_error());
    }
}

/// Safe wrapper around `bind()` or `connect()`, that retries on EINTR.
pub 
fn set_unix_local_addr<FD>(socket: FD, addr: &UnixSocketAddr) -> Result<(), io::Error> 
where FD: AsFd
{
    let (addr, len) = addr.as_raw_general();

    unsafe 
    {
        // check for EINTR just in case. If the file system is slow or somethhing.
        loop 
        {
            if bind(socket.as_fd().as_raw_fd(), addr, len) != -1 
            {
                break Ok(());
            }

            let err = io::Error::last_os_error();

            if err.kind() != ErrorKind::Interrupted 
            {
                break Err(err);
            }
        }
    }
}

pub 
fn set_unix_peer_addr<FD>(socket: FD, addr: &UnixSocketAddr) -> Result<(), io::Error> 
where FD: AsFd
{
    let (addr, len) = addr.as_raw_general();

    unsafe 
    {
        // check for EINTR just in case. If the file system is slow or somethhing.
        loop 
        {
            if connect(socket.as_fd().as_raw_fd(), addr, len) != -1 
            {
                break Ok(());
            }

            let err = io::Error::last_os_error();

            if err.kind() != ErrorKind::Interrupted 
            {
                break Err(err);
            }
        }
    }
}

/// Safe wrapper around `getsockname()` or `getpeername()`.
pub 
fn get_unix_local_addr<FD>(socket: FD) -> Result<UnixSocketAddr, io::Error> 
where FD: AsFd
{
    unsafe 
    {
        UnixSocketAddr::new_from_ffi(
            |addr_ptr, addr_len| 
            {
                match getsockname(socket.as_fd().as_raw_fd(), addr_ptr, addr_len) 
                {
                    -1 => Err(io::Error::last_os_error()),
                    _ => Ok(()),
                }
            }
        )
        .map(|((), addr)| addr )
    }
}

pub 
fn get_unix_peer_addr<FD>(socket: FD) -> Result<UnixSocketAddr, io::Error> 
where FD: AsFd
{
    unsafe 
    {
        UnixSocketAddr::new_from_ffi(
            |addr_ptr, addr_len| 
            {
                match getpeername(socket.as_fd().as_raw_fd(), addr_ptr, addr_len) 
                {
                    -1 => Err(io::Error::last_os_error()),
                    _ => Ok(()),
                }
            }
        )
        .map(|((), addr)| addr )
    }
}

/// Safe wrapper around `getsockopt(SO_ERROR)`.
pub 
fn take_error<FD>(socket: FD) -> Result<Option<io::Error>, io::Error> 
where FD: AsFd
{
    let mut stored_errno: c_int = 0;
    let mut optlen = mem::size_of::<c_int>() as socklen_t;
    let dst_ptr = &mut stored_errno as *mut c_int as *mut c_void;
    
    unsafe 
    {
        if getsockopt(socket.as_fd().as_raw_fd(), SOL_SOCKET, SO_ERROR, dst_ptr, &mut optlen) == -1 
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
            Ok(Some(io::Error::from_raw_os_error(stored_errno)))
        }
    }
}

#[repr(i32)]
#[derive(Debug)]
pub enum TimeoutDirection
{
    Read = SO_RCVTIMEO,
    Write = SO_SNDTIMEO
}

impl From<TimeoutDirection> for c_int
{
    #[inline]
    fn from(value: TimeoutDirection) -> Self 
    {
        return value as c_int;
    }
}

/// Safe wrapper around `setsockopt(SO_RCVTIMEO)` or `setsockopt(SO_SNDTIMEO)`.
pub 
fn set_timeout<F>(socket: F, direction: TimeoutDirection, timeout: Option<Duration>) -> Result<(), io::Error>
where F: AsFd
{
    let mut time = unsafe { mem::zeroed::<timeval>() };
    
    if let Some(dur) = timeout 
    {
        if dur.as_secs() == 0 && dur.subsec_nanos() == 0 
        {
            return Err(
                io::Error::new(ErrorKind::InvalidInput, "cannot set a 0 duration timeout")
            );
        }

        let secs = 
            if dur.as_secs() > libc::time_t::MAX as u64 
            {
                libc::time_t::MAX
            } 
            else 
            {
                dur.as_secs() as libc::time_t
            };

        time.tv_sec = secs;
        time.tv_usec = dur.subsec_micros() as libc::suseconds_t;

        if time.tv_sec == 0 && time.tv_usec == 0 
        {
            time.tv_usec = 1;
        }
    }

    let time_ptr = ptr::addr_of!(time).cast();
    let time_size = mem::size_of::<timeval>() as socklen_t;
    
    return 
        unsafe 
        { 
            cvt!(setsockopt(socket.as_fd().as_raw_fd(), SOL_SOCKET, direction.into(), time_ptr, time_size)) 
        }
        .map(|_| ());
}

/// Safe wrapper around `getsockopt(SO_RCVTIMEO)` or `getsockopt(SO_SNDTIMEO)`.
pub 
fn get_timeout<FD>(socket: FD, direction: TimeoutDirection) -> Result<Option<Duration>, io::Error> 
where FD: AsFd
{
    let mut time: MaybeUninit<timeval> = MaybeUninit::zeroed();
    let mut time_size = mem::size_of::<timeval>() as socklen_t;

    unsafe 
    {
        cvt!(getsockopt(socket.as_fd().as_raw_fd(), SOL_SOCKET, direction.into(), time.as_mut_ptr().cast(), &mut time_size))?;
    };

    if time_size as usize != mem::size_of::<timeval>() 
    {
        return Err(
            io::Error::new(ErrorKind::InvalidData,"timeout has unexpected size")
        );
    }

    let timeout = unsafe { time.assume_init() };

    if timeout.tv_sec < 0 
    {
        Err(io::Error::new(ErrorKind::InvalidData, "timeout is negative"))
    } 
    else if timeout.tv_usec < 0  ||  timeout.tv_usec >= 1_000_000 
    {
        Err(io::Error::new(ErrorKind::InvalidData, "timeout has invalid microsecond part"))
    } 
    else if timeout.tv_sec == 0  &&  timeout.tv_usec == 0 
    {
        Ok(None)
    } 
    else 
    {
        Ok(Some(Duration::new(timeout.tv_sec as u64, timeout.tv_usec as u32 * 1000)))
    }
}

/// A trait for Socket Type
pub(crate) trait SocketType: fmt::Debug
{
    const SOCK_TYPE: libc::c_int;
}

#[derive(Debug)]
pub(crate) struct SocketSeqPkt;

impl SocketType for SocketSeqPkt
{
    const SOCK_TYPE: libc::c_int = SOCK_SEQPACKET;
}

#[derive(Debug)]
pub(crate) struct SocketStream;

impl SocketType for SocketStream
{
    const SOCK_TYPE: libc::c_int = SOCK_STREAM;
}

/// Used in setup of sockets to ensure the file descriptor is always closed
/// if later parts of the setup fails.
#[derive(Debug)]
pub(crate) struct Socket<ST: SocketType>(OwnedFd, PhantomData<ST>);

impl<ST: SocketType> IntoRawFd for Socket<ST> 
{
    fn into_raw_fd(self) -> RawFd 
    {
        self.0.into_raw_fd()
    }
}

impl<ST: SocketType> AsRawFd for Socket<ST>  
{
    fn as_raw_fd(&self) -> RawFd 
    {
        self.0.as_raw_fd()
    }
}

impl<ST: SocketType> AsFd for Socket<ST>  
{
    fn as_fd(&self) -> BorrowedFd<'_> 
    {
        self.0.as_fd()
    }
}

impl<ST: SocketType> From<Socket<ST>> for OwnedFd 
{
    fn from(value: Socket<ST>) -> Self 
    {
        value.0
    }
}

impl<ST: SocketType> Socket<ST> 
{
    pub(crate)  
    fn set_unix_local_addr(&self, addr: &UnixSocketAddr) -> Result<(), io::Error> 
    {
        set_unix_local_addr(&self, addr)
    }

    pub(crate)  
    fn set_unix_peer_addr(&self, addr: &UnixSocketAddr) -> Result<(), io::Error> 
    {
        set_unix_peer_addr(&self, addr)
    }
}

impl<ST: SocketType> Socket<ST> 
{
    /// Enable / disable Apple-only SO_NOSIGPIPE
    fn set_nosigpipe(&self, nosigpipe: bool) -> Result<(), io::Error> 
    {
        #![allow(unused_variables)]
        #[cfg(target_vendor="apple")] {
            unsafe {
                let nosigpipe = &(nosigpipe as c_int) as *const c_int as *const c_void;
                let int_size = mem::size_of::<c_int>() as socklen_t;
                cvt!(setsockopt(self.0.as_raw_fd(), SOL_SOCKET, SO_NOSIGPIPE, nosigpipe, int_size))?;
            }
        }
        
        return Ok(());
    }

    /// Enables / disables CLOEXEC, for when SOCK_CLOEXEC can't be used.
    #[inline]
    pub 
    fn set_cloexec(&self, close_on_exec: bool) -> Result<(), io::Error> 
    {
        return set_cloexec(&self.0, close_on_exec);
    }

    #[inline]
    fn new_int(fd: RawFd) -> Self
    {
        Self(unsafe { OwnedFd::from_raw_fd(fd) }, PhantomData)
    }

    pub 
    fn new(/*socket_type: c_int, */ nonblocking: bool) -> Result<Self, io::Error> 
    {
        // Set close-on-exec atomically with SOCK_CLOEXEC if possible.
        // Falls through to the portable but race-prone way for compatibility
        // with Linux < 2.6.27 becaue Rust std still supports 2.6.18.
        // (EINVAL is what std checks for, and EPROTONOTSUPPORT is for
        // known-but-not-supported protcol or protocol families).
        #[cfg(not(any(target_vendor="apple", target_os = "haiku")))] 
        {
            let type_flags = ST::SOCK_TYPE | SOCK_CLOEXEC | if nonblocking {SOCK_NONBLOCK} else {0};

            match 
                cvt!(unsafe { socket(AF_UNIX, type_flags, 0) }) 
                    .map(|fd| Socket::new_int(fd))
            {
                Ok(fd) => 
                    return Ok(fd),
                Err(ref e) if e.raw_os_error() == Some(EINVAL) => 
                    {/*try without*/}
                Err(e) => 
                    return Err(e),
            }
        }

        // portable but race-prone
        let socket = 
            cvt!(unsafe { socket(AF_UNIX, ST::SOCK_TYPE, 0) })
                .map(|fd| Socket::new_int(fd))?;

        socket.set_cloexec(true)?;
        socket.set_nosigpipe(true)?;

        if nonblocking == true
        {
            set_nonblocking(&socket, true)?;
        }
        
        return Ok(socket);
    }

    pub 
    fn accept_from<FD>(fd: FD, nonblocking: bool) -> Result<(Self, UnixSocketAddr), io::Error> 
    where FD: AsFd
    {
        unsafe 
        { 
            UnixSocketAddr::new_from_ffi(
                |addr_ptr, len_ptr| 
                {
                    // Use accept4() to set close-on-exec atomically if possible.
                    // (macOS and iOS doesn't have accept4(),
                    //  and the Android emulator prohibits it: https://github.com/tokio-rs/mio/issues/1445)
                    // ENOSYS is handled for compatibility with Linux < 2.6.28,
                    // because Rust std still supports Linux 2.6.18.
                    // (used by RHEL 5 which didn't reach EOL until November 2020).
                    #[cfg(not(any(
                        target_vendor="apple",
                        target_os = "haiku",
                        all(target_os="android", target_arch="x86")
                    )))] 
                    {
                        let flags = SOCK_CLOEXEC | if nonblocking {SOCK_NONBLOCK} else {0};
                        
                        match cvt_r!(accept4(fd.as_fd().as_raw_fd(), addr_ptr, len_ptr, flags)) 
                        {
                            Ok(fd) => 
                                return Ok(Self::new_int(fd)),
                            Err(ref e) if e.raw_os_error() == Some(ENOSYS) => 
                                {/*try normal accept()*/},
                            Err(e) => 
                                return Err(e),
                        }
                    }

                    // Portable but not as efficient:
                    let socket = 
                        cvt_r!(accept(fd.as_fd().as_raw_fd(), addr_ptr, len_ptr))
                            .map(|fd| Socket::new_int(fd))?;

                    socket.set_cloexec(true)?;
                    socket.set_nosigpipe(true)?;

                    if nonblocking  == true
                    {
                        set_nonblocking(&socket, true)?;
                    }

                    return Ok(socket);
                }
            ) 
        }
    }

    pub 
    fn start_listening(&self) -> Result<(), io::Error> 
    {
        cvt!(unsafe { listen(self.0.as_raw_fd(), LISTEN_BACKLOG) }).map(|_| () )
    }

    pub 
    fn try_clone_from<FD: AsFd>(fd: FD) -> Result<Self, io::Error> 
    {
        // nonblocking-ness is shared, so doesn't need to potentially be set.
        // FIXME is SO_NOSIGPIPE shared?
        // If so setting it again doesn't hurt in most cases,
        // but might be unwanted if somebody has for some reason cleared it.

        // use fcntl(F_DUPFD_CLOEXEC) to set close-on-exec atomically
        // if possible, but fall through to dup()-and-ioctl(FIOCLEX)
        // for compatibility with Linux < 2.6.24
        //cvt!(unsafe { fcntl(fd.as_raw_fd(), F_DUPFD_CLOEXEC, 0) }).map(|fd| Self::new_int(fd))
        match fd.as_fd().try_clone_to_owned().map(|owned| Self(owned, PhantomData))
        {
            Ok(socket) => 
            {
                socket.set_nosigpipe(true)?;

                return Ok(socket);
            },
            Err(ref e) if e.raw_os_error() == Some(EINVAL) => 
            {
                // try dup() instead
                let socket = 
                    cvt!(unsafe { dup(fd.as_fd().as_raw_fd()) })
                        .map(|fd| Socket::new_int(fd))?;

                socket.set_cloexec(true)?;
                socket.set_nosigpipe(true)?;

                return Ok(socket);
            }
            Err(e) => 
                return Err(e),
        }
    }

    pub 
    fn pair(/*socket_type: c_int, */ nonblocking: bool) -> Result<(Self, Self), io::Error> 
    {
        let mut fd_buf = [-1; 2];

        // Set close-on-exec atomically with SOCK_CLOEXEC if possible.
        // Falls through for compatibility with Linux < 2.6.27
        #[cfg(not(any(target_vendor="apple", target_os = "haiku")))] 
        {
            let type_flags = ST::SOCK_TYPE | SOCK_CLOEXEC | if nonblocking {SOCK_NONBLOCK} else {0};

            match cvt!(unsafe { socketpair(AF_UNIX, type_flags, 0, fd_buf[..].as_mut_ptr()) }) 
            {
                Ok(_) => 
                    return Ok((Socket::new_int(fd_buf[0]), Socket::new_int(fd_buf[1]))),
                Err(ref e) if e.raw_os_error() == Some(EINVAL) => 
                    {/*try without*/}
                Err(e) => 
                    return Err(e),
            }
        }

        cvt!(unsafe { socketpair(AF_UNIX, ST::SOCK_TYPE, 0, fd_buf[..].as_mut_ptr()) })?;

        let a = Socket::new_int(fd_buf[0]);
        let b = Socket::new_int(fd_buf[1]);
        
        a.set_cloexec(true)?;
        b.set_cloexec(true)?;
        
        a.set_nosigpipe(true)?;
        b.set_nosigpipe(true)?;
        
        if nonblocking == true
        {
            set_nonblocking(&a, true)?;
            set_nonblocking(&b, true)?;
        }
        
        return Ok((a, b));
    }
}
