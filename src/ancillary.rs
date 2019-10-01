use std::os::unix::io::RawFd;
use std::io::{self, ErrorKind, IoSlice, IoSliceMut};
use std::alloc::{self, Layout};
use std::convert::TryInto;
use std::{mem, ptr, slice};

use libc::{c_int, c_void, msghdr, iovec, sockaddr_un, socklen_t};
use libc::{sendmsg, recvmsg, close};
use libc::{MSG_CTRUNC, MSG_CMSG_CLOEXEC};

#[cfg(not(target_vendor="apple"))]
use libc::MSG_NOSIGNAL;
#[cfg(target_vendor="apple")]
const MSG_NOSIGNAL: c_int = 0; // SO_NOSIGPIPE is set instead

use libc::{cmsghdr, CMSG_LEN, CMSG_DATA, CMSG_FIRSTHDR, CMSG_NXTHDR};
use libc::{SOL_SOCKET, SCM_RIGHTS};
#[cfg(any(target_os="linux", target_os="android"))]
use libc::SCM_CREDENTIALS;

use crate::UnixSocketAddr;
use crate::credentials::{SendCredentials, ReceivedCredentials};

#[cfg(all(target_os="linux", target_env="gnu"))]
type ControlLen = usize;
#[cfg(not(all(target_os="linux", target_env="gnu")))]
type ControlLen = libc::socklen_t;

/// Safe wrapper around `sendmsg()`.
pub fn send_ancillary(
    socket: RawFd,  to: Option<&UnixSocketAddr>,  flags: c_int,
    bytes: &[IoSlice],  fds: &[RawFd],  creds: Option<SendCredentials>
) -> Result<usize, io::Error> {
    unsafe {
        let mut msg: msghdr = mem::zeroed();
        msg.msg_name = ptr::null_mut();
        msg.msg_namelen = 0;
        msg.msg_iov = bytes.as_ptr() as *mut iovec;
        msg.msg_iovlen = match bytes.len().try_into() {
            Ok(len) => len,
            Err(_) => {
                return Err(io::Error::new(ErrorKind::InvalidInput, "too many byte slices"));
            }
        };
        msg.msg_flags = 0;
        msg.msg_control = ptr::null_mut();
        msg.msg_controllen = 0;

        if let Some(addr) = to {
            let (addr, len) = addr.as_raw();
            msg.msg_name = addr as *const sockaddr_un as *const c_void as *mut c_void;
            msg.msg_namelen = len;
        }

        let mut needed_capacity = 0;
        #[cfg(any(target_os="linux", target_os="android"))]
        let creds = creds.map(|creds| {
            let creds = creds.into_raw();
            needed_capacity += CMSG_LEN(mem::size_of_val(&creds) as u32);
            creds
        });
        if fds.len() > 0 {
            if fds.len() > 0xff_ff_ff {
                // need to prevent truncation.
                // I use a lower limit in case the macros don't handle overflow.
                return Err(io::Error::new(ErrorKind::InvalidInput, "too many file descriptors"));
            }
            needed_capacity += CMSG_LEN(mem::size_of_val(&fds) as u32);
        }
        // stack buffer which should be big enough for most scenarios
        struct AncillaryFixedBuf(/*for alignment*/[cmsghdr; 0], [u8; 256]);
        let mut ancillary_buf = AncillaryFixedBuf([], [0; 256]);

        msg.msg_controllen = needed_capacity as ControlLen;
        if needed_capacity != 0 {
            if needed_capacity as usize <= mem::size_of::<AncillaryFixedBuf>() {
                msg.msg_control = &mut ancillary_buf.1 as *mut [u8; 256] as *mut c_void;
            } else {
                let layout = Layout::from_size_align(
                    needed_capacity as usize,
                    mem::align_of::<cmsghdr>()
                ).unwrap();
                msg.msg_control = alloc::alloc(layout) as *mut c_void;
            }

            let mut header = &mut*CMSG_FIRSTHDR(&mut msg);
            #[cfg(any(target_os="linux", target_os="android"))] {
                if let Some(creds) = creds {
                    header.cmsg_level = SOL_SOCKET;
                    header.cmsg_type = SCM_CREDENTIALS;
                    header.cmsg_len = CMSG_LEN(mem::size_of_val(&creds) as u32) as ControlLen;
                    *(CMSG_DATA(header) as *mut _) = creds;
                    header = &mut*CMSG_NXTHDR(&mut msg, header);
                }
            }

            if fds.len() > 0 {
                header.cmsg_level = SOL_SOCKET;
                header.cmsg_type = SCM_RIGHTS;
                header.cmsg_len = CMSG_LEN(mem::size_of_val(fds) as u32) as ControlLen;
                let dst = &mut*(CMSG_DATA(header) as *mut RawFd);
                ptr::copy_nonoverlapping(fds.as_ptr(), dst, fds.len());
            }
        }

        let result = cvt_r!(sendmsg(socket, &msg, flags | MSG_NOSIGNAL));

        if needed_capacity as usize > mem::size_of::<AncillaryFixedBuf>() {
            let layout = Layout::from_size_align(needed_capacity as usize, mem::align_of::<cmsghdr>()).unwrap();
            alloc::dealloc(msg.msg_control as *mut u8, layout);
        }

        result.map(|sent| sent as usize )
    }
}



/// A safe (but incomplete) wrapper around `recvmsg()`.
pub fn recv_ancillary(
    socket: RawFd,  from: Option<&mut UnixSocketAddr>,  flags: &mut c_int,
    bufs: &mut[IoSliceMut],  fd_buf: &mut[RawFd],
    credentials: Option<&mut Option<ReceivedCredentials>>,
) -> Result<(usize, usize), io::Error> {
    unsafe {
        let mut msg: msghdr = mem::zeroed();
        msg.msg_name = ptr::null_mut();
        msg.msg_namelen = 0;
        msg.msg_iov = bufs.as_mut_ptr() as *mut iovec;
        msg.msg_iovlen = match bufs.len().try_into() {
            Ok(len) => len,
            Err(_) => {
                return Err(io::Error::new(ErrorKind::InvalidInput, "too many buffers"));
            }
        };
        msg.msg_flags = 0;
        msg.msg_control = ptr::null_mut();
        msg.msg_controllen = 0;

        if let Some(addr) = from {
            let (addr, _) = addr.as_raw_mut();
            msg.msg_name = addr as *mut sockaddr_un as *mut c_void;
            msg.msg_namelen = mem::size_of::<sockaddr_un>() as socklen_t;
        }

        let mut needed_capacity = 0;
        if fd_buf.len() > 0 {
            if fd_buf.len() > 0xff_ff_ff {
                // need to prevent truncation.
                // I use a lower limit in case the macros don't handle overflow.
                return Err(io::Error::new(ErrorKind::InvalidInput, "too many file descriptors"));
            }
            needed_capacity += CMSG_LEN(mem::size_of_val(&fd_buf) as u32);
        }

        // stack buffer which should be big enough for most scenarios
        struct AncillaryFixedBuf(/*for alignment*/[cmsghdr; 0], [u8; 256]);
        let mut ancillary_buf = AncillaryFixedBuf([], [0; 256]);
        msg.msg_controllen = needed_capacity as ControlLen;
        if needed_capacity != 0 {
            if needed_capacity as usize <= mem::size_of::<AncillaryFixedBuf>() {
                msg.msg_control = &mut ancillary_buf.1 as *mut [u8; 256] as *mut c_void;
            } else {
                let layout = Layout::from_size_align(
                    needed_capacity as usize,
                    mem::align_of::<cmsghdr>()
                ).unwrap();
                msg.msg_control = alloc::alloc(layout) as *mut c_void;
            }
        }

        let pass_flags = *flags | MSG_NOSIGNAL | MSG_CMSG_CLOEXEC;
        let result = cvt_r!(recvmsg(socket, &mut msg, pass_flags)).map(|received| {
            let received = received as usize;
            *flags = msg.msg_flags;
            let mut ancillary = CMSG_FIRSTHDR(&msg);
            let mut total_fds = 0;
            while !ancillary.is_null() {
                match ((*ancillary).cmsg_level, (*ancillary).cmsg_type) {
                    (SOL_SOCKET, SCM_RIGHTS) => {
                        let data_bytes = (*ancillary).cmsg_len as usize - CMSG_LEN(0) as usize;
                        // pointer is aligned by the cmsg header
                        let mut fds = slice::from_raw_parts(
                            CMSG_DATA(ancillary) as *const RawFd,
                            data_bytes / mem::size_of::<RawFd>()
                        );
                        if total_fds+fds.len() > fd_buf.len() {
                            // too many file descriptors for buffer
                            // this can happen if capacity was allocated for
                            // both fds and credentials, but no credentials
                            // were received.
                            // FIXME this is a good reason to not expose this
                            // function.
                            *flags |= MSG_CTRUNC; // might be wrong for streams
                            for &fd in &fds[fd_buf.len()-total_fds..] {
                                close(fd);
                            }
                            fds = &fds[..fd_buf.len()-total_fds];
                        }
                        fd_buf[total_fds..total_fds+fds.len()].copy_from_slice(fds);
                        total_fds += fds.len();
                    }
                    _ => {/*ignore unknown or unsupported types; hopefully nothing that requires dropping*/}
                }
                ancillary = CMSG_NXTHDR(&msg, ancillary);
            }
            (received, total_fds)
        });

        if needed_capacity as usize > mem::size_of::<AncillaryFixedBuf>() {
            let layout = Layout::from_size_align(
                needed_capacity as usize,
                mem::align_of::<cmsghdr>()
            ).unwrap();
            alloc::dealloc(msg.msg_control as *mut u8, layout);
        }

        result
    }
}
