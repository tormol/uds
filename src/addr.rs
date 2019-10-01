use std::fmt::{self, Debug, Display};
use std::hash::{Hash, Hasher};
use std::path::Path;
use std::ffi::{OsStr, CStr};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::net;
use std::{mem, slice};
use std::io::{self, ErrorKind};

use libc::{sockaddr, sa_family_t, AF_UNIX, socklen_t, sockaddr_un, c_char};

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
/// This type fully supports abstract socket addresses,
/// and can be created by user code and not returned by `accept()` and similar.
///
/// # Examples
///
/// Creating an abstract address:
///
/// ```
/// use ud3::UnixSocketAddr;
///
/// let addr = UnixSocketAddr::new("@abstract").expect("too long");
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
/// # use ud3::{UnixSocketAddr, UnixSocketAddrRef};
/// let addr = UnixSocketAddr::from_path("/var/run/socket.sock").unwrap();
/// if let UnixSocketAddrRef::Path(path) = addr.as_ref() {
///     let _ = std::fs::remove_file(path);
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
        let name_len = addr.len as isize - path_offset() as isize;
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
    /// Allows creating abstract, path or unspecified address based on an
    /// user-supplied string.
    ///
    /// A leading `'@'` or `'\0'` signifies an abstract address,
    /// an empty slice is takes as the unnamed address, and anything else is a
    /// path address.  
    /// If a relative path address starts with `'@'`, escape it by prepending
    /// `"./"`.
    ///
    /// # Errors
    ///
    /// * A path or abstract address is too long.
    /// * A path address contains `'\0'`.
    ///
    /// # Examples
    ///
    /// Abstract address:
    /// 
    /// ```
    /// # use ud3::UnixSocketAddr;
    /// assert!(UnixSocketAddr::new("@abstract").unwrap().is_abstract());
    /// assert!(UnixSocketAddr::new("\0abstract").unwrap().is_abstract());
    /// ```
    ///
    /// Escaped path address:
    /// 
    /// ```
    /// # use ud3::UnixSocketAddr;
    /// assert!(UnixSocketAddr::new("./@path").unwrap().is_relative_path());
    /// ```
    ///
    /// Unnamed address:
    /// 
    /// ```
    /// # use ud3::UnixSocketAddr;
    /// assert_eq!(UnixSocketAddr::new("").unwrap(), UnixSocketAddr::new_unnamed());
    /// ```
    pub fn new<A: AsRef<[u8]>+?Sized>(addr: &A) -> Result<Self, io::Error> {
        fn parse(addr: &[u8]) -> Result<UnixSocketAddr, io::Error> {
            match addr.first() {
                Some(&b'@') | Some(&b'\0') => UnixSocketAddr::from_abstract(&addr[1..]),
                Some(_) => UnixSocketAddr::from_path(Path::new(OsStr::from_bytes(addr))),
                None => Ok(UnixSocketAddr::new_unnamed()),
            }
        }
        parse(addr.as_ref())
    }

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
    #[cfg_attr(any(target_os="linux", target_os="android"), doc="```")]
    #[cfg_attr(not(any(target_os="linux", target_os="android")), doc="```no_run")]
    /// # use ud3::{UnixSocketAddr, UnixDatagramExt};
    /// # use std::os::unix::net::UnixDatagram;
    /// let addr = UnixSocketAddr::new_unspecified();
    /// assert!(addr.is_unnamed());
    /// let socket = UnixDatagram::unbound().unwrap();
    /// socket.bind_to_unix_addr(&addr).unwrap();
    /// assert!(socket.local_unix_addr().unwrap().is_abstract());
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

    /// Create a pathname unix socket address.
    ///
    /// # Errors
    /// 
    /// This function will return an error if the path is too long for the
    /// underlying `sockaddr_un` type, or contains NUL (`'\0'`) bytes.
    pub fn from_path<P: AsRef<Path>+?Sized>(path: &P) -> Result<Self, io::Error> {
        fn from_path_inner(path: &[u8]) -> Result<UnixSocketAddr, io::Error> {
            let mut addr = UnixSocketAddr::new_unnamed();
            let capacity = mem::size_of_val(&addr.addr.sun_path);
            if path.is_empty() {
                Err(io::Error::new(ErrorKind::NotFound, "path is empty"))
            } else if path.len() > capacity {
                let message = "path is too long for an unix socket address";
                Err(io::Error::new(ErrorKind::InvalidInput, message))
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
        from_path_inner(path.as_ref().as_os_str().as_bytes())
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
    pub const fn can_use_abstract_addresses() -> bool {
        cfg!(any(target_os="linux", target_os="android", target_os="freebsd"))
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
    /// Call [`max_abstract_len()`](#method.max_abstract_len)
    /// get the limit.
    pub fn from_abstract<N: AsRef<[u8]>+?Sized>(name: &N) -> Result<Self, io::Error> {
        fn from_abstract_inner(name: &[u8]) -> Result<UnixSocketAddr, io::Error> {
            let mut addr = UnixSocketAddr::new_unnamed();
            if name.len() > UnixSocketAddr::max_abstract_len() {
                Err(io::Error::new(ErrorKind::InvalidInput, "abstract name is too long"))
            } else {
                for (dst, src) in addr.addr.sun_path[1..].iter_mut().zip(name) {
                    *dst = *src as c_char;
                }
                addr.len = path_offset() + 1 + name.len() as socklen_t;
                Ok(addr)
            }
        }
        from_abstract_inner(name.as_ref())
    }

    /// Try to convert a `std::os::unix::net::SocketAddr` into an `UnixSocketAddr`.
    ///
    /// This can fail (produce `None`) if the `std ``SocketAddr` represents an
    /// abstract address, because it doesn't provide any method for viewing it.
    /// (other than parsing its `Debug` output, anyway.)
    pub fn from_std(addr: net::SocketAddr) -> Option<Self> {
        if let Some(path) = addr.as_pathname() {
            Some(Self::from_path(path).expect("pathname addr cannot be converted"))
        } else if addr.is_unnamed() {
            Some(Self::new_unnamed())
        } else {
            None
        }
    }

    /// This method can create unnamed and path addresses, but not abstract ones.
    /// 
    /// Creates unnamed addres for empty strings, and path addresses otherwise.
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
            let message = "path is too long for unix socket address";
            Err(io::Error::new(ErrorKind::InvalidInput, message))
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

    /// Prepare a `struct sockaddr*` and `socklen_t*` for passing to ffi
    /// (such as `getsockname()`, `getpeername()`, `accept()`),
    /// and sanitize the produced address afterwards.
    /// 
    /// For now the only sanitization performed is checking that the
    /// address is `AF_UNIX`.
    ///
    /// # Safety
    ///
    /// Assigning a value > `sizeof(struct sockaddr_un)` to the `socklen_t`
    /// reference might lead to out-of-bounds reads later.
    pub unsafe fn new_from_ffi<R, F>(call: F) -> Result<(R, Self), io::Error>
    where F: FnOnce(&mut sockaddr, &mut socklen_t) -> Result<R, io::Error> {
        let mut addr = Self::new_unspecified();
        addr.len = mem::size_of_val(&addr.addr) as socklen_t;
        let (addr_ptr, addr_len_ptr) = addr.as_raw_mut_general();
        match call(addr_ptr, addr_len_ptr) {
            Ok(_) if addr.addr.sun_family != AF_UNIX as sa_family_t => Err(io::Error::new(
                ErrorKind::InvalidData,
                "file descriptor did not correspond to a Unix socket" // identical to std's
            )),
            Ok(ret)  => Ok((ret, addr)),
            Err(err) => Err(err),
        }
    }

    /// Create an `UnixSocketAddr` from a pointer to a generic `sockaddr` and
    /// a length.
    ///
    /// # Safety
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

    /// Create an `UnixSocketAddr` without any validation.
    ///
    /// # Safety
    ///
    /// * `len` must be `<= size_of::<sockaddr_un>()`.
    /// * `addr.sun_family` should be `AF_UNIX` or strange things could happen.
    /// * `addr.sun_len` if it exists should be zero.
    pub unsafe fn from_raw_unchecked(addr: sockaddr_un,  len: socklen_t) -> Self {
        Self{addr, len}
    }

    /// Split the address into its inner, raw parts.
    pub fn into_raw(self) -> (sockaddr_un, socklen_t) {
        (self.addr, self.len)
    }

    /// Get a general `sockaddr` reference to the address and its length.
    ///
    /// Useful for passing to `bind()`, `connect()`, `sendto()` or other FFI.
    pub fn as_raw_general(&self) -> (&sockaddr, socklen_t) {
        (unsafe { &*(&self.addr as *const sockaddr_un as *const sockaddr) }, self.len)
    }

    /// Get a reference to the inner `struct sockaddr_un`, and length.
    pub fn as_raw(&self) -> (&sockaddr_un, socklen_t) {
        (&self.addr, self.len)
    }

    /// Get mutable references to a general `struct sockaddr` and `socklen_t`.
    ///
    /// If passing to `getpeername()`, `accept()` or similar, remember to set
    /// the length to the capacity,
    /// and consider using [`new_from_ffi()`](#method.new_from_ffi) instead.
    /// 
    /// # Safety
    ///
    /// Assigning a value > `sizeof(struct sockaddr_un)` to the `socklen_t`
    /// reference might lead to out-of-bounds reads later.
    pub unsafe fn as_raw_mut_general(&mut self) -> (&mut sockaddr, &mut socklen_t) {
        (&mut*(&mut self.addr as *mut sockaddr_un as *mut sockaddr), &mut self.len)
    }

    /// Get mutable references to the inner `struct sockaddr_un` and length.
    ///
    /// # Safety
    ///
    /// Assigning a value > `sizeof(struct sockaddr_un)` to the `socklen_t`
    /// reference might lead to out-of-bounds reads later.
    pub unsafe fn as_raw_mut(&mut self) -> (&mut sockaddr_un, &mut socklen_t) {
        (&mut self.addr, &mut self.len)
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
