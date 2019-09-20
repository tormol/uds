use std::os::unix::io::RawFd;
use std::io::{self, ErrorKind, IoSlice};
use std::alloc::{self, Layout};
use std::convert::TryInto;
use std::{mem, ptr};

use libc::{c_int, c_void, msghdr, iovec, sockaddr_un, sendmsg, MSG_NOSIGNAL};
use libc::{cmsghdr, CMSG_LEN, CMSG_DATA, CMSG_FIRSTHDR};
use libc::{SOL_SOCKET, SCM_RIGHTS};
#[cfg(any(target_os="linux", target_os="android"))]
use libc::{SCM_CREDENTIALS, CMSG_NXTHDR};

use crate::UnixSocketAddr;
use crate::credentials::SendCredentials;

#[cfg(all(target_os="linux", target_env="gnu"))]
type ControlLen = usize;
#[cfg(not(all(target_os="linux", target_env="gnu")))]
type LontrolLen = libc::socklen_t;

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

        let result = loop {
            let sent = sendmsg(socket, &msg, flags | MSG_NOSIGNAL);
            if sent >= 0 {
                break Ok(sent as usize);
            } else {
                let err = io::Error::last_os_error();
                if err.kind() != ErrorKind::Interrupted {
                    break Err(err);
                }
            }
        };

        if needed_capacity as usize > mem::size_of::<AncillaryFixedBuf>() {
            let layout = Layout::from_size_align(needed_capacity as usize, mem::align_of::<cmsghdr>()).unwrap();
            alloc::dealloc(msg.msg_control as *mut u8, layout);
        }

        result
    }
}
