/* See each function for copyright holders */

/// Functions to handle OS differences.
/// Several adapted from std.

use std::os::unix::io::{RawFd, AsRawFd, IntoRawFd};
use std::io::{self, ErrorKind};
use std::mem;

use libc::{c_int, sockaddr, socklen_t, AF_UNIX};
use libc::{bind, connect, getsockname, getpeername};
use libc::{socket, accept, close, listen, socketpair, ioctl, FIONBIO};
use libc::{fcntl, F_DUPFD_CLOEXEC, EINVAL, dup};

#[cfg(not(target_vendor="apple"))]
use libc::{SOCK_CLOEXEC, SOCK_NONBLOCK};
#[cfg(not(any(target_vendor="apple", target_os="netbsd")))]
// FIXME netbsd has it, but libc doesn't expose it
use libc::{accept4, ENOSYS};
#[cfg(target_vendor="apple")]
use libc::{setsockopt, SOL_SOCKET, SO_NOSIGPIPE, c_void};

use crate::addr::*;



const LISTEN_BACKLOG: c_int = 10; // what std uses, I think

#[cfg(not(target_vendor="apple"))]
pub use libc::MSG_NOSIGNAL;
#[cfg(target_vendor="apple")]
pub const MSG_NOSIGNAL: c_int = 0; // SO_NOSIGPIPE is set instead

/// Enable / disable CLOEXEC, for when SOCK_CLOEXEC can't be used.
pub fn set_cloexec(fd: RawFd,  close_on_exec: bool) -> Result<(), io::Error> {
    let op = if close_on_exec {libc::FIOCLEX} else {libc::FIONCLEX};
    cvt!(unsafe { ioctl(fd, op) })?;
    Ok(())
}



type SetSide = unsafe extern "C" fn(RawFd, *const sockaddr, socklen_t) -> c_int;
unsafe fn set_unix_addr(socket: RawFd,  set_side: SetSide,  addr: &UnixSocketAddr)
-> Result<(), io::Error> {
    let (addr, len) = addr.as_raw_general();
    // check for EINTR just in case. If the file system is slow or somethhing.
    loop {
        if set_side(socket, addr, len) != -1 {
            break Ok(());
        }
        let err = io::Error::last_os_error();
        if err.kind() != ErrorKind::Interrupted {
            break Err(err);
        }
    }
}
/// Safe wrapper around `bind()`, that retries on EINTR.
pub fn bind_to(socket: RawFd,  addr: &UnixSocketAddr) -> Result<(), io::Error> {
    unsafe { set_unix_addr(socket, bind, addr) }
}
/// Safe wrapper around `connect()`, that retries on EINTR.
pub fn connect_to(socket: RawFd,  addr: &UnixSocketAddr) -> Result<(), io::Error> {
    unsafe { set_unix_addr(socket, connect, addr) }
}

type GetSide = unsafe extern "C" fn(RawFd, *mut sockaddr, *mut socklen_t) -> c_int;
unsafe fn get_unix_addr(socket: RawFd,  get_side: GetSide)
-> Result<UnixSocketAddr, io::Error> {
    UnixSocketAddr::new_from_ffi(|addr_ptr, addr_len| {
        match get_side(socket, addr_ptr, addr_len) {
            -1 => Err(io::Error::last_os_error()),
            _ => Ok(()),
        }
    }).map(|((), addr)| addr )
}
/// Safe wrapper around `getsockname()`.
pub fn local_addr(socket: RawFd) -> Result<UnixSocketAddr, io::Error> {
    unsafe { get_unix_addr(socket, getsockname) }
}
/// Safe wrapper around `getpeername()`.
pub fn peer_addr(socket: RawFd) -> Result<UnixSocketAddr, io::Error> {
    unsafe { get_unix_addr(socket, getpeername) }
}



/// Used in setup of sockets to ensure the file descriptor is always closed
/// if later parts of the setup fails.
pub struct Socket(RawFd);

impl Drop for Socket {
    fn drop(&mut self) {
        // ignore errors - unlikely and there is nowhere to return them
        unsafe { close(self.0) };
    }
}

impl IntoRawFd for Socket {
    fn into_raw_fd(self) -> RawFd {
        let fd = self.0;
        mem::forget(self);
        fd
    }
}

impl AsRawFd for Socket {
    fn as_raw_fd(&self) -> RawFd {
        self.0
    }
}

impl Socket {
    /// Enable / disable Apple-only SO_NOSIGPIPE
    fn set_nosigpipe(&self,  nosigpipe: bool) -> Result<(), io::Error> {
        #![allow(unused_variables)]
        #[cfg(target_vendor="apple")] {
            unsafe {
                let nosigpipe = &(nosigpipe as c_int) as *const c_int as *const c_void;
                let int_size = mem::size_of::<c_int>() as socklen_t;
                cvt!(setsockopt(self.0, SOL_SOCKET, SO_NOSIGPIPE, nosigpipe, int_size))?;
            }
        }
        Ok(())
    }

    /// Enable / disable FIONBIO. Used if SOCK_NONBLOCK can't be used.
    fn set_nonblocking(&self,  nonblocking: bool) -> Result<(), io::Error> {
        cvt!(unsafe { ioctl(self.0, FIONBIO, &mut (nonblocking as c_int)) }).map(|_| () )
    }

    pub fn new(socket_type: c_int,  nonblocking: bool) -> Result<Self, io::Error> {
        // Set close-on-exec atomically wit SOCK_CLOEXEC if possible.
        // Falls through to the portable but race-prone way for compatibility
        // with Linux < 2.6.27 becaue Rust std still supports 2.6.18.
        // (EINVAL is what std checks for, and EPROTONOTSUPPORT is for
        // known-but-not-supported protcol or protocol families), 
        #[cfg(not(target_vendor="apple"))] {
            let type_flags = socket_type | SOCK_CLOEXEC | if nonblocking {SOCK_NONBLOCK} else {0};
            match cvt!(unsafe { socket(AF_UNIX, type_flags, 0) }) {
                Ok(fd) => return Ok(Socket(fd)),
                Err(ref e) if e.raw_os_error() == Some(EINVAL) => {/*try without*/}
                Err(e) => return Err(e),
            }
        }

        // portable but race-prone
        let fd = cvt!(unsafe { socket(AF_UNIX, socket_type, 0) })?;
        let socket = Socket(fd);
        set_cloexec(socket.0, true)?;
        socket.set_nosigpipe(true)?;
        if nonblocking {
            socket.set_nonblocking(true)?;
        }
        Ok(socket)
    }

    pub fn accept_from(fd: RawFd,  nonblocking: bool)
    -> Result<(Self, UnixSocketAddr), io::Error> {
        unsafe { UnixSocketAddr::new_from_ffi(|addr_ptr, len_ptr| {
            // Use accept4() to set close-on-exec atomically if possible.
            // ENOSYS is handled for compatibility with Linux < 2.6.28,
            // because Rust std still supports Linux 2.6.18.
            // (used by RHEL 5 which doesn't reach EOL until November 2020).
            #[cfg(any(
                target_os="linux", target_os="android",
                target_os="freebsd", target_os="dragonfly",
                target_os="openbsd" // FIXME netbsd also has this, but libc doesn't expose it
            ))] {
                let flags = SOCK_CLOEXEC | if nonblocking {SOCK_NONBLOCK} else {0};
                match cvt_r!(accept4(fd, addr_ptr, len_ptr, flags)) {
                    Ok(fd) => return Ok(Socket(fd)),
                    Err(ref e) if e.raw_os_error() == Some(ENOSYS) => {/*try normal accept()*/},
                    Err(e) => return Err(e),
                }
            }

            // Portable but not as efficient:
            let fd = cvt_r!(accept(fd, addr_ptr, len_ptr))?;
            let socket = Socket(fd);
            set_cloexec(socket.0, true)?;
            socket.set_nosigpipe(true)?;
            if nonblocking {
                socket.set_nonblocking(true)?;
            }
            Ok(socket)
        }) }
    }

    pub fn start_listening(&self) -> Result<(), io::Error> {
        cvt!(unsafe { listen(self.0, LISTEN_BACKLOG) }).map(|_| () )
    }

    pub fn try_clone_from(fd: RawFd) -> Result<Self, io::Error> {
        // nonblocking-ness is shared, so doesn't need to potentially be set.
        // FIXME is SO_NOSIGPIPE shared?
        // If so setting it again doesn't hurt in most cases,
        // but might be unwanted if somebody has for some reason cleared it.

        // use fcntl(F_DUPFD_CLOEXEC) to set close-on-exec atomically
        // if possible, but fall through to dup()-and-ioctl(FIOCLEX)
        // for compatibility with Linux < 2.6.24
        match cvt!(unsafe { fcntl(fd, F_DUPFD_CLOEXEC, 0) }) {
            Ok(cloned) => {
                let socket = Socket(cloned);
                socket.set_nosigpipe(true)?;
                return Ok(socket);
            },
            Err(ref e) if e.raw_os_error() == Some(EINVAL) => {/*try dup() instead*/}
            Err(e) => return Err(e),
        }

        let cloned = cvt!(unsafe { dup(fd) })?;
        let socket = Socket(cloned);
        set_cloexec(socket.0, true)?;
        socket.set_nosigpipe(true)?;
        Ok(socket)
    }

    pub fn pair(socket_type: c_int,  nonblocking: bool) -> Result<(Self, Self), io::Error> {
        let mut fd_buf = [-1; 2];
        // Set close-on-exec atomically wit SOCK_CLOEXEC if possible.
        // Falls through for compatibility with Linux < 2.6.27
        #[cfg(not(target_vendor="apple"))] {
            let type_flags = socket_type | SOCK_CLOEXEC | if nonblocking {SOCK_NONBLOCK} else {0};
            match cvt!(unsafe { socketpair(AF_UNIX, type_flags, 0, fd_buf[..].as_mut_ptr()) }) {
                Ok(_) => return Ok((Socket(fd_buf[0]), Socket(fd_buf[1]))),
                Err(ref e) if e.raw_os_error() == Some(EINVAL) => {/*try without*/}
                Err(e) => return Err(e),
            }
        }

        cvt!(unsafe { socketpair(AF_UNIX, socket_type, 0, fd_buf[..].as_mut_ptr()) })?;
        let a = Socket(fd_buf[0]);
        let b = Socket(fd_buf[1]);
        set_cloexec(a.0, true)?;
        set_cloexec(b.0, true)?;
        a.set_nosigpipe(true)?;
        b.set_nosigpipe(true)?;
        if nonblocking {
            a.set_nonblocking(true)?;
            b.set_nonblocking(true)?;
        }
        Ok((a, b))
    }
}
