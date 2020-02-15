use std::os::unix::io::RawFd;
use std::{io, fmt};
use std::num::NonZeroU32;
use std::io::ErrorKind::*;
#[cfg(any(target_os="linux", target_os="android", target_os="freebsd", target_vendor="apple"))]
use std::mem;

#[cfg(any(target_os="linux", target_os="android", target_os="freebsd", target_vendor="apple"))]
use libc::{getsockopt, c_void, socklen_t};
#[cfg(any(target_os="linux", target_os="android"))]
use libc::{pid_t, uid_t, gid_t, getpid, getuid, geteuid, getgid, getegid};
#[cfg(any(target_os="linux", target_os="android"))]
use libc::{ucred, SOL_SOCKET, SO_PEERCRED};
#[cfg(any(target_os="freebsd", target_vendor="apple"))]
use libc::{xucred, XUCRED_VERSION, LOCAL_PEERCRED};
#[cfg(target_vendor="apple")]
use libc::SOL_LOCAL; // Apple is for once the one that does the right thing!

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



/// Credentials of the peer process when it called `connect()`, `accept()` or `pair()`.
///
/// What information is received varies from OS to OS:
/// 
/// * Linux, OpenBSD and NetBSD provides process id, effective user id
///   and effective group id.
/// * macOS, FreeBSD and Dragonfly BSD provides effective user id
///   and group memberships.
/// * Illumos doesn't have this feature, so functions .
#[derive(Clone,Copy, PartialEq)]
pub enum ConnCredentials {
    LinuxLike{ pid: NonZeroU32, euid: u32, egid: u32 },
    MacOsLike{ euid: u32, number_of_groups: u8, groups: [u32; 16/*what libc uses for all*/] },
}
impl ConnCredentials {
    pub fn pid(&self) -> Option<NonZeroU32> {
        match self {
            &ConnCredentials::LinuxLike{ pid, .. } => Some(pid),
            &ConnCredentials::MacOsLike{ .. } => None,
        }
    }
    pub fn euid(&self) -> u32 {
        match self {
            &ConnCredentials::LinuxLike{ euid, .. } => euid,
            &ConnCredentials::MacOsLike{ euid, .. } => euid,
        }
    }
    pub fn egid(&self) -> Option<u32> {
        match self {
            &ConnCredentials::LinuxLike{ egid, .. } => Some(egid),
            &ConnCredentials::MacOsLike{ .. } => None,
        }
    }
    pub fn groups(&self) -> &[u32] {
        match self {
            &ConnCredentials::LinuxLike{ .. } => &[],
            &ConnCredentials::MacOsLike{ number_of_groups: n @ 0..=15, ref groups, .. } => {
                &groups[..(n as usize)]
            },
            &ConnCredentials::MacOsLike{ number_of_groups: 16..=255, ref groups, .. } => groups,
        }
    }
}
impl fmt::Debug for ConnCredentials {
    fn fmt(&self,  fmtr: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        let mut repr = fmtr.debug_struct("ConnCredentials");
        match self {
            &ConnCredentials::LinuxLike{ ref pid, ref euid, ref egid } => {
                repr.field("pid", pid);
                repr.field("euid", euid);
                repr.field("egid", egid);
            }
            &ConnCredentials::MacOsLike{ ref euid, number_of_groups, ref groups } => {
                repr.field("euid", euid);
                let number_of_groups = (number_of_groups as usize).min(groups.len());
                repr.field("groups", &&groups[..number_of_groups]);
            }
        }
        repr.finish()
    }
}


#[cfg(any(target_os="linux", target_os="android"))]
pub fn peer_credentials(conn: RawFd) -> Result<ConnCredentials, io::Error> {
    let mut ucred: ucred = unsafe { mem::zeroed() };
    unsafe {
        let ptr = &mut ucred as *mut ucred as *mut c_void;
        let mut size = mem::size_of::<ucred>() as socklen_t;
        if getsockopt(conn, SOL_SOCKET, SO_PEERCRED, ptr, &mut size) == -1 {
            Err(io::Error::last_os_error())
        } else if let Some(pid) = NonZeroU32::new(ucred.pid as u32) {
            Ok(ConnCredentials::LinuxLike{ pid, euid: ucred.uid as u32, egid: ucred.gid as u32 })
        } else {
            Err(io::Error::new(NotConnected, "socket is not a connection"))
        }
    }
}

#[cfg(any(target_os="freebsd", target_vendor="apple"))]
pub fn peer_credentials(conn: RawFd) -> Result<ConnCredentials, io::Error> {
    let mut xucred: xucred = unsafe { mem::zeroed() };
    xucred.cr_version = XUCRED_VERSION;
    xucred.cr_ngroups = xucred.cr_groups.len() as _;
    // initialize to values that don't signify root, to reduce severity of bugs
    xucred.cr_uid = !0;
    for group_slot in &mut xucred.cr_groups {
        *group_slot = !0;
    }
    #[cfg(target_os="freebsd")]
    const PEERCRED_SOCKET_LEVEL: i32 = 0; // yes literal zero: not SOL_SOCKET and SOL_LOCAL is not a thing
    #[cfg(target_vendor="apple")]
    use SOL_LOCAL as PEERCRED_SOCKET_LEVEL;
    unsafe {
        let ptr = &mut xucred as *mut xucred as *mut c_void;
        let mut size = mem::size_of::<xucred>() as socklen_t;
        match getsockopt(conn, PEERCRED_SOCKET_LEVEL, LOCAL_PEERCRED, ptr, &mut size) {
            -1 => Err(io::Error::last_os_error()),
            _ if xucred.cr_version != XUCRED_VERSION => {
                Err(io::Error::new(InvalidData, "unknown version of peer credentials"))
            },
            _ => {
                let mut groups = [u32::max_value(); 16]; // set all unused group slots to ~0
                let filled_groups = xucred.cr_groups.iter().take(xucred.cr_ngroups as usize);
                for (&src, dst) in filled_groups.zip(&mut groups) {
                    *dst = src.into();
                }
                Ok(ConnCredentials::MacOsLike {
                    euid: xucred.cr_uid.into(),
                    number_of_groups: xucred.cr_ngroups as u8,
                    groups: groups,
                })
            }
        }
    }
}

#[cfg(any(target_os="openbsd", target_os="dragonfly", target_os="netbsd"))]
pub fn peer_credentials(_: RawFd) -> Result<ConnCredentials, io::Error> {
    Err(io::Error::new(Other, "Not yet supported"))
}

#[cfg(not(any(
    target_os="linux", target_os="android", target_os="openbsd", target_os="netbsd",
    target_os="freebsd", target_os="dragonfly", target_os="netbsd", target_vendor="apple",
)))]
pub fn peer_credentials(_: RawFd) -> Result<ConnCredentials, io::Error> {
    Err(io::Error::new(Other, "not available"))
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
