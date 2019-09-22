/* See each function for copyright holders */

/// Functions to handle OS differences.
/// Several adapted from std.

use std::os::unix::io::{RawFd, AsRawFd, IntoRawFd};
use std::io::{self, ErrorKind};
use std::mem;

use libc::{c_int, sockaddr, socklen_t, AF_UNIX};
use libc::{bind, connect, getsockname, getpeername};
use libc::{socket, accept, close, listen, ioctl, FIONBIO};

//#[cfg(target_vendor="apple")]
use libc::{accept4, SOCK_CLOEXEC, SOCK_NONBLOCK, EINVAL, ENOSYS};

use crate::addr::*;

const LISTEN_BACKLOG: c_int = 10; // what std uses, I think

/// Get errno as io::Error on -1.
macro_rules! cvt {($syscall:expr) => {
    match $syscall {
        -1 => Err(io::Error::last_os_error()),
        ok => Ok(ok),
    }
}}

/// Get errno as io::Error on -1 and retry on EINTR.
macro_rules! cvt_r {($syscall:expr) => {
    loop {
        let result = $syscall;
        if result != -1 {
            break Ok(result);
        }
        let err = io::Error::last_os_error();
        if err.kind() != ErrorKind::Interrupted {
            break Err(err);
        }
    }
}}


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
    /// Enable / disable CLOEXEC, for when SOCK_CLOEXEC can't be used.
    fn set_cloexec(&self,  close_on_exec: bool) -> Result<(), io::Error> {
        // FIXME I don't think these ioctls are available everywhere
        let op = if close_on_exec {libc::FIOCLEX} else {libc::FIONCLEX};
        cvt!(unsafe { ioctl(self.0, op) }).map(|_| () )
    }

    /// Enable / disable Apple-only SO_NOSIGPIPE
    fn set_nosigpipe(&self,  nosigpipe: bool) -> Result<(), io::Error> {
        #![allow(unused_variables)]
        #[cfg(target_vendor="apple")] {
            let nosigpipe = &mut (nosigpipe as c_int);
            cvt!(unsafe { setsockopt(self.0, SOL_SOCKET, SO_NOSIGPIPE, nosigpipe) }).map(|_| () )
        }
        #[cfg(not(target_vendor="apple"))]
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
        socket.set_cloexec(true)?;
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
            {
                let flags = SOCK_CLOEXEC | if nonblocking {SOCK_NONBLOCK} else {0};
                match cvt_r!(accept4(fd, addr_ptr, len_ptr, flags)) {
                    Ok(fd) => return Ok(Socket(fd)),
                    Err(ref e) if e.raw_os_error() == Some(ENOSYS) => {},
                    Err(e) => return Err(e),
                }
            }

            // Portable but not as efficient:
            let fd = cvt_r!(accept(fd, addr_ptr, len_ptr))?;
            let socket = Socket(fd);
            socket.set_cloexec(true)?;
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
}
