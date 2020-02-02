#[cfg(any(target_os="linux", target_os="android"))]
use std::os::unix::io::RawFd;
use std::io;
use std::mem;

use libc::{getsockopt, SOL_SOCKET, c_void, socklen_t};
#[cfg(any(target_os="linux", target_os="android"))]
use libc::{pid_t, uid_t, gid_t, getpid, getuid, geteuid, getgid, getegid};
#[cfg(any(target_os="linux", target_os="android"))]
use libc::{ucred, SO_PEERCRED};

/// Credentials to be sent with `send_ancillary()`.
///
/// Only on Linux (& Android) does one need to send credentials, and on other
/// operating systems this struct is ignored.
#[derive(Clone,Copy, PartialEq,Eq, Debug)]
#[allow(unused)] // not used yet
pub enum SendCredentials {
    Effective,
    Real,
    Custom{ pid: u32, uid: u32, gid: u32 }
}
#[cfg(any(target_os="linux", target_os="android"))]
impl SendCredentials {
    pub fn into_raw(self) -> ucred {
        let mut ucred: ucred = unsafe { mem::zeroed() };
        let (pid, uid, gid) = match self {
            SendCredentials::Effective => unsafe { (getpid(), geteuid(), getegid()) },
            SendCredentials::Real => unsafe { (getpid(), getuid(), getgid()) },
            SendCredentials::Custom{pid, uid, gid} => (pid as pid_t, uid as uid_t, gid as gid_t),
        };
        ucred.pid = pid;
        ucred.uid = uid;
        ucred.gid = gid;
        return ucred;
    }
}



/// Credentials of the peer process when it called `connect()` or `accept()`.
///
/// Returned by `peer_credentials()`.
///
/// What information is received varies from OS to OS:
/// 
/// * Linux, OpenBSD and NetBSD provides `(pid, euid, egid)`
/// * macOS, FreeBSD and Dragonfly BSD provides euid and group memberships.
/// * Illumos doesn't have this feature, so no information is available.
// TODO make struct with substructs
#[derive(Clone,Copy, PartialEq,Eq,Hash, Debug)]
#[allow(unused)] // only one variant is used per OS
pub enum QueriedCredentials {
    LinuxLike{ pid: u32, euid: u32, egid: u32 },
    MacOsLike{ euid: u32, groups: [u32; 5/*FIXME biggest*/] },
    Unavailable
}

#[cfg(any(target_os="linux", target_os="android"))]
#[allow(unused)] // TODO
pub fn peer_credentials(conn: RawFd) -> Result<QueriedCredentials, io::Error> {
    let mut ucred: ucred = unsafe { mem::zeroed() };
    unsafe {
        let ptr = &mut ucred as *mut ucred as *mut c_void;
        let mut size = mem::size_of::<ucred>() as socklen_t;
        match getsockopt(conn, SOL_SOCKET, SO_PEERCRED, ptr, &mut size) {
            -1 => Err(io::Error::last_os_error()),
            _ => Ok(QueriedCredentials::LinuxLike {
                    pid: ucred.pid as u32,
                    euid: ucred.uid as u32,
                    egid: ucred.gid as u32,
                }),
        }
    }
}



#[cfg(any(target_os="linux", target_os="android"))]
pub type RawReceivedCredentials = libc::ucred;


/// Process credentials received through `recv_ancillary()`.
///
/// What information is returned varies from OS to OS:
///
/// * On Linux (& Android) the information has to be explicitly sent by the
///   peer through `send_ancillary()` or `sendmsg()`, but is validated by the
///   kernel.  
///   Peer chooses whether to send effective or real uid or gid, unless root
///   in which case it can send whatever it wants.
/// * On FreeBSD, NetBSD, Dragonfly, Illumos and likely macOS it is provided
///   by the OS automatically when the socket option is set.
/// * OpenBSD doesn't appear to support receiving credentials.
#[derive(Clone,Copy, PartialEq,Eq,Hash, Debug)]
pub struct ReceivedCredentials {
    #[cfg(any(target_os="linux", target_os="android", target_os="dragonfly"))]
    pid: u32,
    #[cfg(any(target_os="linux", target_os="android"))]
    uid: u32,
    #[cfg(any(target_os="linux", target_os="android"))]
    gid: u32,

    #[cfg(any(
        target_os="freebsd", target_os="netbsd", target_os="dragonfly",
        target_os="illumos", target_os="solaris", target_os="macos",
    ))]
    real_uid: u32,
    #[cfg(any(
        target_os="freebsd", target_os="netbsd", target_os="dragonfly",
        target_os="illumos", target_os="solaris", target_os="macos",
    ))]
    effective_uid: u32,
    #[cfg(any(
        target_os="freebsd", target_os="netbsd", target_os="dragonfly",
        target_os="illumos", target_os="solaris", target_os="macos",
    ))]
    real_gid: u32,
    #[cfg(any(
        target_os="freebsd", target_os="netbsd",
        target_os="illumos", target_os="solaris", target_os="macos",
    ))]
    effective_gid: u32,
    #[cfg(any(
        target_os="freebsd", target_os="netbsd", target_os="dragonfly",
        target_os="illumos", target_os="solaris", target_os="macos",
    ))]
    groups: [u32; 5],
}

#[allow(unused)] // TODO
impl ReceivedCredentials {
    #[cfg(any(target_os="linux", target_os="android"))]
    pub(crate) fn from_raw(creds: libc::ucred) -> Self {
        ReceivedCredentials {
            pid: creds.pid as u32,
            uid: creds.uid as u32,
            gid: creds.gid as u32,
        }
    }

    /// The pid of the peer.
    ///
    /// This information is only available on Linux, Android and Dragonfly BSD.
    pub fn pid(&self) -> Option<u32> {
        #[cfg(any(target_os="linux", target_os="android", target_os="dragonfly"))] {
            Some(self.pid)
        }
        #[cfg(not(any(target_os="linux", target_os="android", target_os="dragonfly")))] {
            None
        }
    }
    pub fn effective_or_sent_uid(&self) -> u32 {
        #[cfg(any(target_os="linux", target_os="android"))] {
            self.uid
        }
        #[cfg(any(
            target_os="freebsd", target_os="netbsd", target_os="dragonfly",
            target_os="illumos", target_os="solaris", target_os="macos",
        ))] {
            self.effective_uid
        }
        #[cfg(not(any(
            target_os="linux", target_os="android",
            target_os="freebsd", target_os="netbsd", target_os="dragonfly",
            target_os="illumos", target_os="solaris", target_os="macos",
        )))] {
            unreachable!("struct cannot be created on unsupported OSes")
        }
    }
    pub fn real_or_sent_uid(&self) -> u32 {
        #[cfg(any(target_os="linux", target_os="android"))] {
            self.uid
        }
        #[cfg(any(
            target_os="freebsd", target_os="netbsd", target_os="dragonfly",
            target_os="illumos", target_os="solaris", target_os="macos",
        ))] {
            self.real_uid
        }
        #[cfg(not(any(
            target_os="linux", target_os="android",
            target_os="freebsd", target_os="netbsd", target_os="dragonfly",
            target_os="illumos", target_os="solaris", target_os="macos",
        )))] {
            unreachable!("struct cannot be created on unsupported OSes")
        }
    }
    pub fn effective_or_sent_gid(&self) -> Option<u32> {
        #[cfg(any(target_os="linux", target_os="android"))] {
            Some(self.gid)
        }
        #[cfg(any(
            target_os="freebsd", target_os="netbsd",
            target_os="illumos", target_os="solaris", target_os="macos",
        ))] {
            Some(self.effective_gid)
        }
        #[cfg(not(any(
            target_os="linux", target_os="android",
            target_os="freebsd", target_os="netbsd",
            target_os="illumos", target_os="solaris", target_os="macos",
        )))] {
            None
        }
    }
    pub fn real_or_sent_gid(&self) -> u32 {
        #[cfg(any(target_os="linux", target_os="android"))] {
            self.gid
        }
        #[cfg(any(
            target_os="freebsd", target_os="netbsd", target_os="dragonfly",
            target_os="illumos", target_os="solaris", target_os="macos",
        ))] {
            self.real_gid
        }
        #[cfg(not(any(
            target_os="linux", target_os="android",
            target_os="freebsd", target_os="netbsd", target_os="dragonfly",
            target_os="illumos", target_os="solaris", target_os="macos",
        )))] {
            unreachable!("struct cannot be created on unsupported OSes")
        }
    }
    /// Get the peer's group memberships.
    ///
    /// This information is only available on macOS, the BSDs and and Illumos.
    /// On other operating systems an empty slice is returned.
    pub fn groups(&self) -> &[u32] {
        #[cfg(any(
            target_os="freebsd", target_os="netbsd", target_os="dragonfly",
            target_os="illumos", target_os="solaris", target_os="macos",
        ))] {
            &self.groups[..]
        }
        #[cfg(not(any(
            target_os="freebsd", target_os="netbsd", target_os="dragonfly",
            target_os="illumos", target_os="solaris", target_os="macos",
        )))] {
            &[]
        }
    }
}
