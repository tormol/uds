use std::fmt::{self, Debug, Display};
use std::hash::{Hash, Hasher};
use std::path::Path;
use std::ffi::{OsStr, CStr};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::net;
use std::os::unix::io::RawFd;
use std::{mem, slice};
use std::io::{self, ErrorKind};

use libc::{socklen_t, sockaddr_un, sa_family_t, c_char, AF_UNIX};
use libc::{sockaddr, c_int, bind, connect, getsockname, getpeername};

/// Offset of `.sun_path` in `sockaddr_un`.
///
/// This is not always identical to `mem::size_of::<sa_family_t>()`, as there
/// be other fields before or after `.sun_family`.
fn path_offset() -> socklen_t {
    unsafe {
        let total_size = mem::size_of::<sockaddr_un>();
        let name_size = mem::size_of_val(&mem::zeroed::<sockaddr_un>().sun_path);
        (total_size - name_size) as socklen_t
    }
}

fn as_u8(slice: &[c_char]) -> &[u8] {
    unsafe { &*(slice as *const[c_char] as *const[u8]) }
}

/// A unix domain socket address.
///
/// # Differences from `std`'s `unix::net::SocketAddr`
///
/// This struct can be created from non-library code, and  
/// fully supports abstract socket addresses.
///
/// # Examples
///
/// Creating an abstract address:
///
/// ```
/// use ud3::UnixSocketAddr;
///
/// let addr = UnixSocketAddr::from_escaped("@abstract").unwrap();
/// assert!(addr.is_abstract());
/// assert_eq!(addr.to_string(), "@abstract");
/// ```
#[derive(Clone,Copy)]
pub struct UnixSocketAddr {
    addr: sockaddr_un,
    /// How many bytes of addr are in use.
    ///
    /// Must never be greater than `size_of::<sockaddr_un>()`.
    ///
    /// On BSDs and macOS, `sockaddr_un` has a (non-standard) `.sun_len` field
    /// that *could* be used to store the length instead, but doing that is
    /// not a very good idea:  
    /// At least [NetBSD ignores it](http://mail-index.netbsd.org/tech-net/2006/10/11/0008.html)
    /// so we would still need to pass a correctly set `socklen_t`,
    /// in some cases by referece.
    /// Because it's rarely used and some BSDs aren't afraid to break stuff,
    /// it could even dissappear in the future.  
    /// The size this extra field is also rather minor compared to the size of
    /// `sockaddr_un`, so the possible benefit is tiny.
    len: socklen_t,
}

/// An enum representation of an unix socket address.
///
/// Usefult for pattern matching an [`UnixSocketAddr`](struct.UnixSocketAddr.html)
/// via [`UnixSocketAddr.as_ref()`](struct.UnixSocketAddr.html#method.as_ref).
///
/// It cannot be used in to bind or connect a socket directly because it
/// doesn't contain a `sockaddr_un`, but a `UnixSocketAddr` can be created
/// from it.
///
/// # Examples
///
/// Cleaning pathname sockets after ourselves:
///
/// ```
/// # use ud3::UnixSocketAddr;
/// let addr = UnixSocketAddr::from_path("/var/run/socket.sock")?;
/// if let UnixSocketAddrRef::Path(path) = addr {
///     let _ = std::fs::remove(path);
/// }
/// ```
#[derive(Clone,Copy, PartialEq,Eq,Hash, Debug)]
pub enum UnixSocketAddrRef<'a> {
    Unnamed,
    Path(&'a Path),
    Abstract(&'a [u8]),
}
impl<'a> From<&'a UnixSocketAddr> for UnixSocketAddrRef<'a> {
    fn from(addr: &'a UnixSocketAddr) -> UnixSocketAddrRef<'a> {
        let name_len = (addr.len - path_offset()) as isize;
        if name_len <= 0 {
            UnixSocketAddrRef::Unnamed
        } else if addr.addr.sun_path[0] == b'\0' as c_char {
            let slice = &addr.addr.sun_path[1..name_len as usize];
            UnixSocketAddrRef::Abstract(as_u8(slice))
        } else {
            let slice = &addr.addr.sun_path[..name_len as usize];
            UnixSocketAddrRef::Path(Path::new(OsStr::from_bytes(as_u8(slice))))
        }
    }
}

impl Debug for UnixSocketAddr {
    fn fmt(&self,  fmtr: &mut fmt::Formatter) -> fmt::Result {
        #[derive(Debug)]
        struct Path<'a>(&'a std::path::Path);
        #[derive(Debug)]
        struct Abstract<'a>(&'a OsStr);

        // doesn't live long enough if created inside match
        let mut path_type = Path("".as_ref());
        let mut abstract_type = Abstract(OsStr::new(""));

        let variant: &dyn Debug = match self.into() {
            UnixSocketAddrRef::Unnamed => &"Unnamed",
            UnixSocketAddrRef::Path(path) => {
                path_type.0 = path;
                &path_type
            },
            UnixSocketAddrRef::Abstract(name) => {
                abstract_type.0 = OsStr::from_bytes(name);
                &abstract_type
            },
        };
        fmtr.debug_tuple("UnixSocketAddr").field(variant).finish()
    }
}

impl Display for UnixSocketAddr {
    fn fmt(&self,  fmtr: &mut fmt::Formatter) -> fmt::Result {
        match self.into() {
            UnixSocketAddrRef::Unnamed => fmtr.write_str("unnamed"),
            UnixSocketAddrRef::Path(path) => write!(fmtr, "{}", path.display()), // TODO check that display() doesn't print \n as-is
            UnixSocketAddrRef::Abstract(name) => write!(fmtr, "@{}", OsStr::from_bytes(name).to_string_lossy()), // FIXME escape to sane characters
        }
    }
}

impl UnixSocketAddr {
    /// Creates a unnamed socket address.
    pub fn new_unnamed() -> Self {
        let mut addr: sockaddr_un = unsafe { mem::zeroed() };
        addr.sun_family = AF_UNIX as sa_family_t;
        UnixSocketAddr {
            len: 0,
            addr,
        }
    }

    /// Creates an address that when passed to `bind()` on Linux binds the
    /// socket to a random abstract address, but is otherwise unnamed.
    ///
    /// # Examples
    ///
    #[cfg_attr(target_os="linux", doc="```")]
    #[cfg_attr(not(target_os="linux"), doc="```no_run")]
    /// # use ud3::{UnixSocketAddr, UnixDatagramExt};
    /// # use std::os::unix::net::UnixDatagram;
    /// let addr = UnixSocketAddr::new_unspecified();
    /// assert!(addr.is_unnamed());
    /// let socket = UnixDatagram::bind_unix_addr(addr)?;
    /// assert!(socket.local_unix_addr().is_abstract());
    /// ```
    pub fn new_unspecified() -> Self {
        let mut addr = Self::new_unnamed();
        addr.len = path_offset();
        return addr;
    }

    /// The maximum size of pathname addesses supported by `UnixSocketAddr`.
    ///
    /// Returns the size of the underlying `sun_path` field,
    /// minus 1 if the OS is known to require a trailing NUL (`'\0'`) byte.
    pub fn max_path_len() -> usize {
        mem::size_of_val(&Self::new_unnamed().addr.sun_path)
    }
    fn from_path_inner(path: &[u8]) -> Result<Self, io::Error> {
        let mut addr = Self::new_unnamed();
        let capacity = mem::size_of_val(&addr.addr.sun_path);
        if path.is_empty() {
            Err(io::Error::new(ErrorKind::NotFound, "path is empty"))
        } else if path.len() > capacity {
            Err(io::Error::new(ErrorKind::InvalidInput, "path is too long for an unix socket address"))
        } else if path.iter().any(|&b| b == b'\0' ) {
            Err(io::Error::new(ErrorKind::InvalidInput, "path cannot contain nul bytes"))
        } else {
            for (dst, src) in addr.addr.sun_path.iter_mut().zip(path) {
                *dst = *src as c_char;
            }
            addr.len = path_offset() + path.len() as socklen_t;
            if path.len() < capacity {
                addr.len += 1; // for increased portability
            }
            Ok(addr)
        }
    }
    /// Create a pathname unix socket address.
    ///
    /// # Errors
    /// 
    /// This function will return an error if the path is too long for the
    /// underlying `sockaddr_un` type, or contains NUL (`'\0'`) bytes.
    pub fn from_path<P: AsRef<Path>+?Sized>(path: &P) -> Result<Self, io::Error> {
        Self::from_path_inner(path.as_ref().as_os_str().as_bytes())
    }

    /// The maximum size of abstract addesses supported by `UnixSocketAddr`.
    ///
    /// Returns the size of the underlying `sun_path` field minus 1 for the
    /// leading `'\0'` byte.
    pub fn max_abstract_len() -> usize {
        mem::size_of_val(&Self::new_unnamed().addr.sun_path) - 1
    }
    /// Whether the operating system is known to support abstract socket
    /// addresses.
    pub const fn has_abstract_addresses() -> bool {
        cfg!(any(target_os="linux", target_os="android", target_os="freebsd"))
    }
    fn from_abstract_inner(name: &[u8]) -> Result<Self, io::Error> {
        let mut addr = Self::new_unnamed();
        if name.len() > mem::size_of_val(&addr.addr.sun_path) - 1 {
            Err(io::Error::new(ErrorKind::InvalidInput, "abstract name is too long"))
        } else {
            for (dst, src) in addr.addr.sun_path[1..].iter_mut().zip(name) {
                *dst = *src as c_char;
            }
            addr.len = path_offset() + 1 + name.len() as socklen_t;
            Ok(addr)
        }
    }
    /// Create an abstract unix socket address.
    ///
    /// Abstract addresses is a non-standard feature which is only available on
    /// Linux and FreeBSD.  
    /// This function is always present, and abstract `UnixSocketAddr`s can be
    /// created even if the operating system doesn't support them.
    /// Actually using the address will hopefully fail when `bind()`ing or
    /// `connect()`ing it.
    ///
    /// Abstract names can contain NUL bytes.
    ///
    /// # Errors
    ///
    /// This function will return an error if the name is too long.
    pub fn from_abstract<N: AsRef<[u8]>+?Sized>(name: &N) -> Result<Self, io::Error> {
        Self::from_abstract_inner(name.as_ref())
    }

    fn from_escaped_inner(_name: &[u8]) -> Result<Self, io::Error> {
        unimplemented!("TODO implement un-escaping, with @ for abstract socket")
        // or is that actually necessary? in the rare case one needs a path socket starting with
        // @, one can use ./@
    }
    /// Allows creating abstract, path or unspecified address based on an
    /// user-supplied string.
    ///
    /// # Examples
    ///
    /// Leading '@' creates an abstract address:
    /// 
    /// ```
    /// # use ud3::UnixSocketAddr;
    /// assert!(UnixSocketAddr::from_escaped("@abstract").unwrap().is_abstract());
    /// ```
    pub fn from_escaped<A: AsRef<[u8]>+?Sized>(addr: &A) -> Result<Self, io::Error> {
        Self::from_escaped_inner(addr.as_ref())
    }

    pub fn as_raw(&self) -> (&sockaddr_un, socklen_t) {
        (&self.addr, self.len)
    }
    pub fn as_raw_ref(&self) -> (&sockaddr, socklen_t) {
        (unsafe { &*(&self.addr as *const sockaddr_un as *const sockaddr) }, self.len)
    }
    /// Get mutable references to a general `struct sockaddr` and a `socklen_t`.
    /// 
    /// Useful for passing to `getpeername()` or `getsockname()`, but before
    /// doing that one should set the returned `socklen_t` reference to the
    /// size of `struct sockaddr_un`. (this method doesn't mutate directly).
    /// 
    /// # Unsafety
    ///
    /// Assigning a value > `sizeof(struct sockaddr_un)` to the `socklen_t`
    /// reference might lead to out-of-bounds reads later.
    pub unsafe fn as_raw_mut_ref(&mut self) -> (&mut sockaddr, &mut socklen_t) {
        (&mut*(&mut self.addr as *mut sockaddr_un as *mut sockaddr), &mut self.len)
    }
    pub fn into_raw(self) -> (sockaddr_un, socklen_t) {
        (self.addr, self.len)
    }
    pub unsafe fn as_mut_raw(&mut self) -> (&mut sockaddr_un, &mut socklen_t) {
        (&mut self.addr, &mut self.len)
    }
    pub unsafe fn from_raw_unchecked(addr: sockaddr_un,  len: socklen_t) -> Self {
        Self{addr, len}
    }
    /// Create an `UnixSocketAddr` from a pointer to a generic `sockaddr` and
    /// a length.
    ///
    /// # Unsafety
    ///
    /// * `len` must not be greater than the size of the memory `addr` points to.
    /// * `addr` must point to valid memory if `len` is greater than zero, or be NULL.
    pub unsafe fn from_raw(addr: *const sockaddr,  len: socklen_t) -> Result<Self, io::Error> {
        let mut copy = Self::new_unnamed();
        if addr.is_null() && len == 0 {
            Ok(Self::new_unnamed())
        } else if addr.is_null() {
            Err(io::Error::new(ErrorKind::InvalidInput, "addr is NULL"))
        } else if len < path_offset() {
            Err(io::Error::new(ErrorKind::InvalidInput, "address length is too low"))
        } else if len > path_offset() + mem::size_of_val(&copy.addr.sun_path) as socklen_t {
            Err(io::Error::new(ErrorKind::InvalidInput, "address is too long"))
        } else if (&*addr).sa_family != AF_UNIX as sa_family_t {
            Err(io::Error::new(ErrorKind::InvalidData, "not an unix socket address"))
        } else {
            let addr = addr as *const sockaddr_un;
            let sun_path_ptr = (&*addr).sun_path.as_ptr();
            let sun_path = slice::from_raw_parts(sun_path_ptr, len as usize);
            copy.addr.sun_path.copy_from_slice(sun_path);
            copy.len = len;
            Ok(copy)
        }
    }

    /// Try to convert from a `std::os::unix::net::SocketAddr`.
    ///
    /// This can fail if the std SocketAddr represents an abstract address, as
    /// it doesn't provide any method for viewing it.
    pub fn from_std(addr: net::SocketAddr) -> Option<Self> {
        if let Some(path) = addr.as_pathname() {
            Some(Self::from_path(path).expect("pathname addr cannot be converted"))
        } else if addr.is_unnamed() {
            Some(Self::new_unnamed())
        } else {
            None
        }
    }

    /// This method can create unnamed and named addresses, but not abstract ones.
    /// 
    /// Creates path socket addr for non-empty strings,
    /// and unnamed socket address if empty.
    ///
    /// # Errors
    ///
    /// Returns ENAMETOOLONG if path (without the trailing `'\0'`) is too long
    /// for `sockaddr_un.sun_path`.
    pub fn from_c_str(path: &CStr) -> Result<Self, io::Error> {
        let path = path.to_bytes();
        let mut addr = Self::new_unnamed();
        if path.is_empty() {
            Ok(addr)
        } else if path.len() > mem::size_of_val(&addr.addr.sun_path) {
            Err(io::Error::new(ErrorKind::InvalidInput, "path is too long for unix socket address"))
        } else {
            for (dst, src) in addr.addr.sun_path.iter_mut().zip(path) {
                *dst = *src as c_char;
            }
            addr.len = path_offset() + path.len() as socklen_t;
            if path.len() < mem::size_of_val(&addr.addr.sun_path) {
                addr.len += 1;
            }
            Ok(addr)
        }
    }

    pub fn is_unnamed(&self) -> bool {
        self.len <= path_offset()
    }
    pub fn is_abstract(&self) -> bool {
        self.len > path_offset()  &&  self.addr.sun_path[0] as u8 == b'\0'
    }
    pub fn is_absolute_path(&self) -> bool {
        self.len > path_offset()  &&  self.addr.sun_path[0] as u8 == b'/'
    }
    pub fn is_relative_path(&self) -> bool {
        self.len > path_offset()
            &&  self.addr.sun_path[0] as u8 != b'\0'
            &&  self.addr.sun_path[0] as u8 != b'/'
    }
    pub fn is_path(&self) -> bool {
        self.len > path_offset()  &&  self.addr.sun_path[0] as u8 != b'\0'
    }

    /// Get a view that can be pattern matched to the differnt types of
    /// addresses.
    pub fn as_ref(&self) -> UnixSocketAddrRef {
        UnixSocketAddrRef::from(self)
    }
}

impl Default for UnixSocketAddr {
    fn default() -> Self {
        Self::new_unnamed()
    }
}

impl PartialEq for UnixSocketAddr {
    fn eq(&self,  other: &Self) -> bool {
        self.as_ref() == other.as_ref()
    }
}
impl Eq for UnixSocketAddr {}
impl Hash for UnixSocketAddr {
    fn hash<H: Hasher>(&self,  hasher: &mut H) {
        self.as_ref().hash(hasher)
    }
}

impl PartialEq<[u8]> for UnixSocketAddr {
    fn eq(&self,  unescaped: &[u8]) -> bool {
        match (self.as_ref(), unescaped.first()) {
            (UnixSocketAddrRef::Path(path), Some(_)) => path.as_os_str().as_bytes() == unescaped,
            (UnixSocketAddrRef::Abstract(name), Some(b'\0')) => name == &unescaped[1..],
            (UnixSocketAddrRef::Unnamed, None) => true,
            (_, _) => false,
        }
    }
}
impl PartialEq<UnixSocketAddr> for [u8]  {
    fn eq(&self,  addr: &UnixSocketAddr) -> bool {
        addr == self
    }
}



type SetSide = unsafe extern "C" fn(RawFd, *const sockaddr, socklen_t) -> c_int;
unsafe fn set_unix_addr(socket: RawFd,  set_side: SetSide,  addr: &UnixSocketAddr)
-> Result<(), io::Error> {
    let (addr, len) = addr.as_raw_ref();
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
    let mut addr = mem::zeroed::<sockaddr_un>();
    let mut addr_len = mem::size_of_val(&addr) as socklen_t;
    let addr_ptr = &mut addr as *mut sockaddr_un as *mut sockaddr;
    if get_side(socket, addr_ptr, &mut addr_len) == -1 {
        Err(io::Error::last_os_error())
    } else if addr.sun_family != AF_UNIX as sa_family_t {
        Err(io::Error::new(ErrorKind::InvalidData, "Unexpected type of address (not an unix socket)"))
    } else {
        Ok(UnixSocketAddr::from_raw_unchecked(addr, addr_len))
    }
}
/// Safe wrapper around `getsockname()`.
pub fn local_addr(socket: RawFd) -> Result<UnixSocketAddr, io::Error> {
    unsafe { get_unix_addr(socket, getsockname) }
}
/// Safe wrapper around `getpeername()`.
pub fn peer_addr(socket: RawFd) -> Result<UnixSocketAddr, io::Error> {
    unsafe { get_unix_addr(socket, getpeername) }
}
