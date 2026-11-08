#![allow(
    clippy::useless_conversion, // not useless on all platforms
    clippy::match_overlapping_arm, // cumbersome to avoid when using inclusive ranges
)]

use std::ops::{Deref, DerefMut};
use std::borrow::{Borrow, BorrowMut, Cow};
use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::io::RawFd;
use std::io::{self, ErrorKind, IoSlice, IoSliceMut};
use std::convert::TryInto;
use std::{mem, ptr, slice};
use std::marker::PhantomData;

#[cfg(feature = "unsatable_preview")]
use std::os::unix::net::SocketAncillary;

use libc::{c_int, c_uint, c_void};
use libc::{msghdr, iovec, cmsghdr, sockaddr, sockaddr_un};
use libc::{sendmsg, recvmsg};
//#[cfg(not(any(target_os="illumos", target_os="solaris")))]
use libc::{MSG_TRUNC, MSG_CTRUNC};
#[cfg(not(any(target_os="illumos", target_os="solaris")))]
use libc::{CMSG_SPACE, CMSG_LEN, CMSG_DATA, CMSG_FIRSTHDR, CMSG_NXTHDR};
//#[cfg(not(any(target_os="illumos", target_os="solaris")))]
use libc::{SOL_SOCKET, SCM_RIGHTS};
#[cfg(any(target_os="linux", target_os="android"))]
use libc::SCM_CREDENTIALS;
#[cfg(not(any(target_vendor="apple", target_os="illumos", target_os="solaris", target_os = "haiku")))]
use libc::MSG_CMSG_CLOEXEC;

#[cfg(feature = "unsatable_preview")]
use crate::ancillary_rust::SocketAncillaryCover;

use crate::helpers::*;
use crate::UnixSocketAddr;
use crate::credentials::{SendCredentials, ReceivedCredentials};
#[cfg(any(target_os="linux", target_os="android"))]
use crate::credentials::RawReceivedCredentials;

// Type of cmsghdr.cmsg_len, which varies between OSes and C libraries
// (can't get away with using ` as _` because we use the max value in some places.)
// cfg based on libc 0.2.82 source code.
#[cfg(any(
    all(target_os="linux", not(target_env="musl")),
    target_os="android",
    target_env="uclibc",
))]
type ControlLen = usize;
#[cfg(not(any(
    all(target_os="linux", not(target_env="musl")),
    target_os="android",
    target_env="uclibc",
)))]
type ControlLen = libc::socklen_t;

/// An aux buffer static aligned to 8
#[repr(C, align(8))]
#[derive(Debug)]
struct AncillaryFixedBuf<const N: usize>(/*for alignment*/[u8; N]);

impl<const N: usize> Deref for AncillaryFixedBuf<N> 
{
    type Target = [u8];

    fn deref(&self) -> &[u8] 
    {
        self.0.as_slice()
    }
}
impl<const N: usize> DerefMut for AncillaryFixedBuf<N>
{
    fn deref_mut(&mut self) -> &mut[u8] 
    {
        self.0.as_mut_slice()
    }
}

/// Safe wrapper around `sendmsg()`.
/// 
/// A legacy.
pub 
fn send_ancillary<FD: AsFd>(
    socket: FD,  
    to: Option<&UnixSocketAddr>,  
    flags: c_int,
    bytes: &[IoSlice],  
    fds: &[RawFd],  
    creds: Option<SendCredentials>
) -> Result<usize, io::Error> 
{
    #[cfg(not(any(target_os="linux", target_os="android")))]
    let _ = creds; // silence `unused` warning
    unsafe 
    {
        let mut msg: msghdr = mem::zeroed();
        msg.msg_name = ptr::null_mut();
        msg.msg_namelen = 0;
        msg.msg_iov = bytes.as_ptr() as *mut iovec;
        msg.msg_iovlen = 
            bytes.len().try_into() 
                .map_err(|e|
                    io::Error::new(ErrorKind::InvalidInput, 
                        format!("too many byte slices {}", e))
                )?;

        msg.msg_flags = 0;
        msg.msg_control = ptr::null_mut();
        msg.msg_controllen = 0;

        if let Some(addr) = to 
        {
            let (addr, len) = addr.as_raw();
            msg.msg_name = addr as *const sockaddr_un as *const c_void as *mut c_void;
            msg.msg_namelen = len;
        }

        let mut needed_capacity = 0;

        #[cfg(any(target_os="linux", target_os="android"))]
        let creds = 
            creds.map(
                |creds| 
                {
                    let creds = creds.into_raw();
                    needed_capacity += CMSG_SPACE(mem::size_of_val(&creds) as u32);
                    creds
                }
            );

        if fds.len() > 0 
        {
            if fds.len() > 0xff_ff_ff 
            {
                // need to prevent truncation.
                // I use a lower limit in case the macros don't handle overflow.
                return Err(
                    io::Error::new(ErrorKind::InvalidInput, "too many file descriptors")
                );
            }
            #[cfg(not(any(target_os="illumos", target_os="solaris")))] 
            {
                needed_capacity += CMSG_SPACE(mem::size_of_val::<[RawFd]>(&fds) as u32);
            }
            #[cfg(any(target_os="illumos", target_os="solaris"))] 
            {
                return Err(
                    io::Error::new(
                        ErrorKind::Other,
                        "ancillary data support is not implemented yet for Illumos or Solaris"
                    )
                );
            }
        }

        // stack buffer which should be big enough for most scenarios

        let ancillary_buf = 
            AncillaryFixedBuf( [0_u8; unsafe { CMSG_SPACE(60*size_of::<RawFd>() as u32) as usize}] );
    

        if needed_capacity != 0 
        {

            msg.msg_controllen = needed_capacity as ControlLen;

            let cap: Cow<'_, [u8]> = 
                if needed_capacity as usize >= mem::size_of_val(&ancillary_buf)
                {
                    Cow::Owned(AncillaryBufType::<0>::create_heap(needed_capacity as ControlLen))
                }
                else 
                {
                    assert_eq!(ancillary_buf.0.as_ptr() as usize % mem::align_of::<cmsghdr>(), 0, "assertion trap: ancillary_buf is not aligned!");

                    Cow::Borrowed(ancillary_buf.0.as_slice())    
                };

            msg.msg_control = cap.as_ptr() as *mut c_void;

            #[cfg(not(any(target_os="illumos", target_os="solaris")))] 
            {
                let header_ptr = CMSG_FIRSTHDR(&mut msg);
                assert!(!header_ptr.is_null(), "CMSG_FIRSTHDR returned unexpected NULL pointer");

                #[allow(unused_mut)]
                let mut header = &mut*header_ptr;
                
                #[cfg(any(target_os="linux", target_os="android"))] 
                {
                    if let Some(creds) = creds 
                    {
                        use libc::ucred;

                        header.cmsg_level = SOL_SOCKET;
                        header.cmsg_type = SCM_CREDENTIALS;
                        header.cmsg_len = CMSG_LEN(mem::size_of_val(&creds) as u32) as ControlLen;
                        
                        let data = CMSG_DATA(header) as *mut c_void as *mut ucred;

                        if data.is_aligned() == false
                        {
                            ptr::write_unaligned(data, creds);
                        }
                        else
                        {
                            ptr::write(data, creds);
                        }
                       // *(CMSG_DATA(header) as *mut c_void as *mut _) = creds;
                        
                        let header_ptr = CMSG_NXTHDR(&mut msg, header);
                        if fds.len() > 0 
                        {
                            assert_eq!(header_ptr.is_null(), false, "CMSG_NXTHDR returned unexpected NULL pointer");
                        
                            header = &mut*header_ptr;
                        }
                    }
                }

                if fds.len() > 0 
                {
                    header.cmsg_level = SOL_SOCKET;
                    header.cmsg_type = SCM_RIGHTS;
                    header.cmsg_len = CMSG_LEN(mem::size_of_val::<[RawFd]>(&fds) as u32) as ControlLen;
                    
                    let mut dst = CMSG_DATA(header) as *mut c_void as *mut RawFd;
                    
                    for fd in fds
                    {
                        if dst.is_aligned() == false
                        {
                            ptr::write_unaligned(dst, *fd);
                        }
                        else
                        {
                            ptr::write(dst, *fd);
                        }

                        dst = dst.add(1);
                    }
                }
            }
        }

        let result = 
            cvt_r!(sendmsg(socket.as_fd().as_raw_fd(), &msg, flags | MSG_NOSIGNAL));

        result.map(|sent| sent as usize )
    }
}

/// A different type of buffers.
#[derive(Debug)]
enum AncillaryBufType<const N: usize>
{
    /// Allocated on the stack, first element aligned to 8
    Stack(AncillaryFixedBuf<N>),

    /// Allocated in the heap, first element aligned to safely read u64
    Heap(Vec<u8>)
}

impl<const N: usize> Deref for AncillaryBufType<N> 
{
    type Target = [u8];

    fn deref(&self) -> &[u8] 
    {
        match self
        {
            Self::Stack(afb) => 
                &*afb,
            Self::Heap(heap) => 
                heap.as_slice()
        }
    }
}
impl<const N: usize> DerefMut for AncillaryBufType<N> 
{
    fn deref_mut(&mut self) -> &mut[u8] 
    {
        match self
        {
            Self::Stack(afb) => 
                &mut *afb,
            Self::Heap(heap) => 
                heap.as_mut_slice()
        }
    }
}

impl<const N: usize> AncillaryBufType<N>
{
    fn new_stack() -> Self
    {
        let ancillary_buf = AncillaryFixedBuf([0_u8; N] );

        assert_eq!(ancillary_buf.as_ptr() as usize % mem::align_of::<cmsghdr>(), 0, 
            "assertion trap: AncillaryBuf::with_capacity() ancillary_buf is not aligned!");

        return Self::Stack(ancillary_buf);
    }


    unsafe 
    fn create_heap(needed_capacity: ControlLen) -> Vec<u8>
    {
        assert!(needed_capacity != 0);

        let needed_capacity_div = (needed_capacity-1) / 8 + 1;

        let heap_buf = vec![0_u64; needed_capacity_div as usize];

        assert_eq!(heap_buf.as_ptr() as usize % mem::align_of::<cmsghdr>(), 0, 
            "assertion trap: ancillary_buf in heap is not aligned! {:p}", heap_buf.as_ptr());
            
        let (p, sz, cap) = heap_buf.into_raw_parts();
        let heap_buf = unsafe{ Vec::<u8>::from_raw_parts(p.cast(), sz * size_of::<u64>(), cap * size_of::<u64>()) };

        assert_eq!(heap_buf.as_ptr() as usize % mem::align_of::<cmsghdr>(), 0, 
            "assertion trap: ancillary_buf in heap is not aligned! {:p}", heap_buf.as_ptr());

        return heap_buf;
    }

    /// A `bytes` cannot be zero.
    fn new_heap(bytes: usize) -> Self
    {
        return Self::Heap(unsafe{ Self::create_heap(bytes as ControlLen) });
    }
}


/// An ancillary data buffer that supports any capacity.
///
/// For reasonable ancillary capacities it uses a stack-based array.
#[derive(Debug)]
pub struct AncillaryBuf 
{
    //capacity: ControlLen,
    buf: AncillaryBufType<{Self::MAX_STACK_CAPACITY }>,
}

impl AncillaryBuf 
{
    pub const MAX_STACK_CAPACITY: usize = 256;

    pub const MAX_CAPACITY: usize = ControlLen::MAX as usize;

    pub 
    fn with_capacity(bytes: usize) -> io::Result<Self> 
    {
        let buf = 
            if bytes <= Self::MAX_STACK_CAPACITY
            {
                AncillaryBufType::new_stack()
            }
            else if bytes <= Self::MAX_CAPACITY
            {
                AncillaryBufType::new_heap(bytes)
            }
            else
            {
                return Err(
                    io::Error::new(
                        ErrorKind::OutOfMemory, format!("capacity is too high {}", bytes)
                    )
                )
            };

        return Ok(
            Self 
            {
                /*capacity: 
                    bytes as ControlLen,*/
                buf: 
                    buf,
            }
        );
    }

    pub 
    fn with_fd_capacity(num_fds: usize) -> io::Result<Self>
    {
        #[cfg(not(any(target_os="illumos", target_os="solaris")))]
        {
            // To prevent truncation or overflow (in CMSG macros or elsewhere)
            // cmsghdr having bigger alignment than RawFd isn't a problem,
            //  as that doesn't affect the maximum capacity.
            // If the size of cmsghdr is not divisible by the size of RawFd
            //  (which could theoretically happen if all three cmsghdr fields
            //  are u16 or u8 somewher), then some bytes will not be usable.
            //  But dividing by the size of RawFd silently takes care of that
            //  as it rounds down.
            // FIXME This should ideally be a constant, but it's not really a
            //  problem. (libc doesn't have a const_fn feature, probably
            //  because old compilers wouldn't be able to even parse it.
            let max_fds =
                (c_uint::MAX - unsafe { CMSG_SPACE(0) }) as usize / mem::size_of::<RawFd>();

            if num_fds == 0 
            {
                return Self::with_capacity(0)
            } 
            else if num_fds <= max_fds 
            {
                let payload_bytes = num_fds * mem::size_of::<RawFd>();
                
                return 
                    Self::with_capacity(unsafe{ CMSG_SPACE(payload_bytes as c_uint) } as usize)
            } 
            else 
            {
                return Err(
                    io::Error::new(
                        ErrorKind::FileTooLarge, 
                        format!("too many file descriptors for ancillary buffer length, max: {} req: {}",
                            max_fds, num_fds)
                    )
                );
            }
        }
        #[cfg(any(target_os="illumos", target_os="solaris"))] {
            Self::with_capacity(num_fds) // any non-zero value is not supported
        }
    }
}
impl Default for AncillaryBuf 
{
    fn default() -> Self 
    {
        Self 
        {
            /*capacity: 
                Self::MAX_STACK_CAPACITY as ControlLen,*/
            buf: 
                AncillaryBufType::new_stack()
        }
    }
}

impl Deref for AncillaryBuf 
{
    type Target = [u8];

    fn deref(&self) -> &[u8] 
    {
        &self.buf
    }
}
impl DerefMut for AncillaryBuf 
{
    fn deref_mut(&mut self) -> &mut[u8] 
    {
        &mut self.buf
    }
}
impl Borrow<[u8]> for AncillaryBuf 
{
    fn borrow(&self) -> &[u8] 
    {
        &*self
    }
}
impl BorrowMut<[u8]> for AncillaryBuf 
{
    fn borrow_mut(&mut self) -> &mut[u8] 
    {
        &mut*self
    }
}
impl AsRef<[u8]> for AncillaryBuf 
{
    fn as_ref(&self) -> &[u8] 
    {
        &*self
    }
}
impl AsMut<[u8]> for AncillaryBuf 
{
    fn as_mut(&mut self) -> &mut[u8] 
    {
        &mut*self
    }
}

/// One ancillary message produced by [`Ancillary`](#struct.Ancillary)
#[derive(Debug)]
pub enum AncillaryItem
{
    /// One or more file descriptors sent by the peer.
    ///
    /// Consumer of the iterator is responsible for closing them.
    Fds(Vec<OwnedFd>),

    /// Credentials of the sending process.
    #[allow(unused)]
    Credentials(ReceivedCredentials),

    //Timestamp(),
    //SecurityContext(&'a[u8]),
    /// An unknown or unsupported ancillary message type was received.
    ///
    /// It's up to you whether to ignore or treat as an error.
    Unsupported
}

impl AncillaryItem
{
    /// Creates a new [`FdSlice`] with the lifetime from a `unaligned_ptr` and a `len`.
    ///
    /// # Safety
    /// The unaligned_ptr does not need to be properly aligned, but it needs to point to at least `len` [`RawFd`]s.
    /// The unaligned_ptr may not be null.
    unsafe 
    fn new_fds(unaligned_ptr: *const RawFd, len: usize) -> Self 
    {
        assert!(!unaligned_ptr.is_null(), "No NULL pointer for FdSlice");
        
        let owned_fd_list = 
            unsafe { slice::from_raw_parts(unaligned_ptr, len) }
                .into_iter()
                .map(|fd| unsafe{ OwnedFd::from_raw_fd(*fd)} )
                .collect::<Vec<OwnedFd>>();
        
        return Self::Fds(owned_fd_list);
    }
}

/// An iterator over ancillary messages received with `recv_ancillary()`.
#[derive(Debug)]
pub struct Ancillary<'a>
{
    // addr and bytes are not used here:
    // * addr is usually placed on the stack by the calling wrapper method,
    //   which means that its lifetime ends when this struct is returned.
    // * the iovec is incremented by Linux, but possibly not others.
    msg: msghdr,

    _ancillary_buf: PhantomData<&'a[u8]>,
    /// The next message, initialized with CMSG_FIRSTHDR()
    #[cfg(not(any(target_os="illumos", target_os="solaris")))]
    next_message: *mut cmsghdr,

    /// A counter of bytes read `msg_controllen`.
    msg_ctrl_len_read: usize,
}



impl<'a> Iterator for Ancillary<'a>
{
    type Item = io::Result<AncillaryItem>;

    #[cfg(not(any(target_os="illumos", target_os="solaris")))]
    fn next(&mut self) -> Option<Self::Item>
    {
        unsafe 
        {
            if self.next_message.is_null() 
            {
                return None;
            }

            // do not use this value, unitl validated, see below
            let msg_bytes = (*self.next_message).cmsg_len as usize;

            // validate the msg_bytes
            if (self.msg.msg_controllen as usize - self.msg_ctrl_len_read as usize)  < msg_bytes || msg_bytes < CMSG_LEN(0) as usize
            {
                return Some(
                    Err(io::Error::new(ErrorKind::InvalidData, 
                        format!("malformed cmsghdr struct, cmsg_len < libc::cmsghdr OR larger than out of bounds, \
                            msg_controllen: {}, msg_ctrllen_read: {}, cmsg_len: {}", 
                            self.msg.msg_controllen, self.msg_ctrl_len_read, msg_bytes)))
                );
            }
            
            // increase the read bytes counter (controllen)
            self.msg_ctrl_len_read += msg_bytes;

            // a length of the payload
            let payload_bytes = msg_bytes - CMSG_LEN(0) as usize; 

            // in theory the ancillary buffer is always aligned, but in case if it is not
            let msg = 
                if self.next_message.is_aligned() == false
                {
                    self.next_message.read_unaligned()
                }
                else
                {
                    self.next_message.read()
                };

            let item = 
                match (msg.cmsg_level, msg.cmsg_type) 
                {
                    (SOL_SOCKET, SCM_RIGHTS) => 
                    {
                        let num_fds = payload_bytes / mem::size_of::<RawFd>();
                        
                        // pointer is aligned due to the cmsg header
                        let first_fd = CMSG_DATA(self.next_message) as *const c_void;
                        let first_fd = first_fd.cast::<RawFd>();

                        // consume onece the FD's
                        AncillaryItem::new_fds(first_fd, num_fds)
                    }
                    #[cfg(any(target_os="linux", target_os="android"))]
                    (SOL_SOCKET, SCM_CREDENTIALS) => 
                    {
                        if payload_bytes != CMSG_LEN(size_of::<RawReceivedCredentials>() as u32) as usize
                        {
                            return Some(
                                Err(io::Error::new(ErrorKind::InvalidData, 
                                    format!("malformed cmsghdr struct, cmsg_len(payload_bytes) != libc::ucred")))
                            );
                        }

                        let creds_ptr = CMSG_DATA(self.next_message) as *const c_void;

                        // pointer is aligned due to the cmsg header
                        debug_assert!(
                            creds_ptr as usize & (mem::align_of::<RawReceivedCredentials>()-1) == 0,
                            "CMSG_DATA() is aligned"
                        );

                        let creds_ptr = creds_ptr as *const RawReceivedCredentials;

                        AncillaryItem::Credentials(ReceivedCredentials::from_raw(creds_ptr))
                    }
                    _ => 
                        AncillaryItem::Unsupported,
                };

            self.next_message = CMSG_NXTHDR(&mut self.msg, self.next_message);
            
            return Some(Ok(item));
        }
    }

    #[cfg(any(target_os="illumos", target_os="solaris"))]
    fn next(&mut self) -> Option<Self::Item> 
    {
        None
    }
}

impl<'a> Drop for Ancillary<'a>
{
    fn drop(&mut self) 
    {
        // close all remaining file descriptors
        for ancillary in self 
        {
            let Ok(ancillary) = ancillary
                else { return };

            drop(ancillary);
        }
    }
}
impl<'a> Ancillary<'a>
{
    /// Returns `true` if the non-ancillary part of the datagram or packet was truncated.
    ///
    /// If the provided byte buffer(s) are shorter than the datagram or packet
    /// that was sent, the bytes that couldn't be stored are discarded.
    ///
    /// This function is not meaningful for streams.
    pub 
    fn message_truncated(&self) -> bool 
    {
        self.msg.msg_flags & MSG_TRUNC != 0
    }

    /// Returns `true` if ancillary messages were dropped due to a too short ancillary buffer.
    #[allow(unused)] // type is not yet exposed
    pub 
    fn ancillary_truncated(&self) -> bool 
    {
        self.msg.msg_flags & MSG_CTRUNC != 0
    }

    pub 
    fn get_msg_controllen(&self) -> usize
    {
        self.msg.msg_controllen as usize
    }

    pub
    fn get_msg_ctrl_len_read(&self) -> usize
    {
        self.msg_ctrl_len_read
    }
}

impl<'a> Ancillary<'a>
{
    #[cfg(test)]
    fn recv_ancillary_fake<'ancillary_buf>(
        msg: msghdr,
    ) -> Result<(usize, Ancillary<'ancillary_buf>), io::Error> 
    {
        let received = msg.msg_controllen as u32 + size_of::<msghdr>() as u32;

        let ancillary_iterator =
            unsafe 
            {
                Ancillary 
                {
                    msg,
                    _ancillary_buf: 
                        PhantomData,
                    #[cfg(not(any(target_os="illumos", target_os="solaris")))]
                    next_message: 
                        CMSG_FIRSTHDR(&msg),
                    msg_ctrl_len_read: 
                        0
                }
            };

        return Ok((received as usize, ancillary_iterator));
    }
    /// A safe (but incomplete) wrapper around `recvmsg()`.
    /// 
    /// Legacy.
    pub 
    fn recv_ancillary<'ancillary_buf, FD: AsFd>(
        socket: FD,  
        from: Option<&mut UnixSocketAddr>,  
        mut flags: c_int,
        bufs: &mut[IoSliceMut],  
        ancillary_buf: &'ancillary_buf mut[u8],
    ) -> Result<(usize, Ancillary<'ancillary_buf>), io::Error> 
    {
        unsafe 
        {
            let mut msg: msghdr = mem::zeroed();
            msg.msg_name = ptr::null_mut();
            msg.msg_namelen = 0;
            msg.msg_iov = bufs.as_mut_ptr() as *mut iovec;
            msg.msg_iovlen = 
                bufs.len().try_into()
                    .map_err(|_|
                        io::Error::new(ErrorKind::InvalidInput, "too many content buffers")
                    )?;

            msg.msg_flags = 0;
            msg.msg_control = ptr::null_mut();
            msg.msg_controllen = 0;

            if ancillary_buf.len() > 0 
            {
                #[cfg(any(target_os="illumos", target_os="solaris"))] 
                {
                    return Err(io::Error::new(
                        ErrorKind::Other,
                        "ancillary message support is not implemented yet on Illumos or Solaris, sorry"
                    ))
                }

                if ancillary_buf.as_ptr() as usize % mem::align_of::<cmsghdr>() != 0 
                {
                    return Err(
                        io::Error::new(ErrorKind::InvalidInput, "ancillary buffer is not properly aligned")
                    );
                }

                if ancillary_buf.len() > ControlLen::MAX as usize 
                {
                    return Err(
                        io::Error::new(ErrorKind::InvalidInput, "ancillary buffer is too big")
                    );
                }

                msg.msg_control = ancillary_buf.as_mut_ptr() as *mut c_void;
                msg.msg_controllen = ancillary_buf.len() as ControlLen;
            }

            flags |= MSG_NOSIGNAL;
            #[cfg(not(any(target_vendor="apple", target_os="illumos", target_os="solaris", target_os = "haiku")))] 
            {
                flags |= MSG_CMSG_CLOEXEC;
            }

            let received = 
                match from 
                {
                    Some(addrbuf) => 
                    {
                        let (received, addr) = 
                            UnixSocketAddr::new_from_ffi(
                                |addr, len| 
                                {
                                    msg.msg_name = addr as *mut sockaddr as *mut c_void;
                                    msg.msg_namelen = *len;
                                    let received = cvt_r!(recvmsg(socket.as_fd().as_raw_fd(), &mut msg, flags))? as usize;
                                    *len = msg.msg_namelen;

                                    Ok(received)
                                }
                            )?;

                        *addrbuf = addr;

                        received
                    }
                    None => 
                        cvt_r!( recvmsg(socket.as_fd().as_raw_fd(), &mut msg, flags) )? as usize
                };

            let ancillary_iterator = 
                Ancillary 
                {
                    msg,
                    _ancillary_buf: 
                        PhantomData,
                    #[cfg(not(any(target_os="illumos", target_os="solaris")))]
                    next_message: 
                        CMSG_FIRSTHDR(&msg),
                    msg_ctrl_len_read: 
                        0
                };

            return Ok((received, ancillary_iterator));
        }
    }
}

/// A new (Rust STD) vectored + ancillary sender.
/// 
/// Rust devs are in its dumb manner don't provide an access to buffer and length.
/// So a dirty hack is used. Very unsafe!
#[cfg(feature = "unsatable_preview")]
pub unsafe 
fn send_ancillary_std<FD: AsFd>(
    fd: FD, 
    to: Option<&UnixSocketAddr>,  
    flags: c_int,
    bytes: &[IoSlice],  
    ancillary: &mut SocketAncillary<'_>,
) -> Result<usize, io::Error> 
{
    let mut msg: msghdr = unsafe { mem::zeroed() };
    msg.msg_name = ptr::null_mut();
    msg.msg_namelen = 0;
    msg.msg_iov = bytes.as_ptr() as *mut iovec;
    msg.msg_iovlen = 
        bytes.len().try_into() 
            .map_err(|e|
                io::Error::new(ErrorKind::InvalidInput, 
                    format!("too many byte slices {}", e))
            )?;

    msg.msg_flags = 0;
    msg.msg_control = ptr::null_mut();
    msg.msg_controllen = 0;

    if let Some(addr) = to 
    {
        let (addr, len) = addr.as_raw();
        msg.msg_name = addr as *const sockaddr_un as *const c_void as *mut c_void;
        msg.msg_namelen = len;
    }

    let anci_struct: *mut SocketAncillaryCover = ancillary as *mut _ as *mut SocketAncillaryCover;

    if ancillary.len() > 0
    {
        msg.msg_controllen = ancillary.len();
        msg.msg_control = unsafe { (&mut *anci_struct).buffer.as_mut_ptr().cast() };
    }

    // in std lib they do this... without any reasoning
    unsafe { (&mut *anci_struct).truncated = false };

    let result = 
            cvt_r!(unsafe { sendmsg(fd.as_fd().as_raw_fd(), &msg, flags | MSG_NOSIGNAL) });

    return result.map(|sent| sent as usize );
}

/// A new (Rust STD) ancillary receiver.
/// 
/// Rust devs are in its dumb manner don't provide an access to buffer and length.
/// So a dirty hack is used. Very unsafe!
#[cfg(feature = "unsatable_preview")]
impl<'a> Ancillary<'a>
{
    pub unsafe 
    fn recv_ancillary_std<FD: AsFd>(
        fd: FD, 
        mut flags: i32,
        bufs: &mut[IoSliceMut], 
        anci: &mut SocketAncillary<'_>
    ) -> Result<(usize, bool, UnixSocketAddr), io::Error> 
    {
        let mut msg: msghdr = unsafe { mem::zeroed() };

        let mut addr = UnixSocketAddr::new_unspecified();

        msg.msg_name = unsafe { addr.as_raw_mut_general().0 as *mut sockaddr as *mut c_void };
        msg.msg_namelen = unsafe { *addr.as_raw_mut_general().1 };

        msg.msg_iov = bufs.as_mut_ptr() as *mut iovec;
        msg.msg_iovlen = 
            bufs.len().try_into()
                .map_err(|_|
                    io::Error::new(ErrorKind::InvalidInput, "too many content buffers")
                )?;

        msg.msg_flags = 0;

        let anci_struct: *mut SocketAncillaryCover = anci as *mut _ as *mut SocketAncillaryCover;

        if anci.capacity() > 0
        {
            msg.msg_control = unsafe { (&mut *anci_struct).buffer.as_mut_ptr().cast() };
            msg.msg_controllen = anci.capacity(); 
        }

        flags |= MSG_NOSIGNAL;
        #[cfg(not(any(target_vendor="apple", target_os="illumos", target_os="solaris", target_os = "haiku")))] 
        {
            flags |= MSG_CMSG_CLOEXEC;
        }

        let received = cvt_r!( unsafe { recvmsg(fd.as_fd().as_raw_fd(), &mut msg, flags) })? as usize;

        let trucated = msg.msg_flags & libc::MSG_CTRUNC == libc::MSG_CTRUNC;

        
        unsafe { (&mut *anci_struct).length = msg.msg_controllen as usize; }
        unsafe { (&mut *anci_struct).truncated = trucated; }

        return Ok((received, trucated, addr));
    }
}
   
/// A legacy method.
/// 
/// Receives the FDs into pre-allocated slice! A received FD will become 
/// [Option::Some].
pub 
fn recv_slice_fds<FD: AsFd>(
    fd: FD,  
    from: Option<&mut UnixSocketAddr>,
    bufs: &mut[IoSliceMut],  
    fd_buf: &mut [Option<OwnedFd>]
) -> Result<(usize, bool, usize), io::Error> 
{
    let mut ancillary_buf = 
        AncillaryBuf::with_fd_capacity(
            fd_buf.len()
        )?;    

    let (num_bytes, ancillary) = 
        Ancillary::recv_ancillary(fd, from, 0, bufs, &mut ancillary_buf)?;

    let mut num_fds = 0;

    let msg_truc = ancillary.message_truncated();

    for message in ancillary 
    {
        if let AncillaryItem::Fds(fds) = message?
        {
            // Due to alignment of cmsg_len in glibc the minimum payload
            // capacity is on Linux (and probably Android) 8 bytes,
            // which means we might receive two file descriptors even though
            // we only want one.
            let can_keep = fds.len().min(fd_buf.len()-num_fds);
            num_fds += can_keep;

            for (ofd, i) in fds.into_iter().zip(0..can_keep) 
            {
                #[cfg(any(target_vendor="apple", target_os="freebsd"))] 
                {
                    // set cloexec
                    // This is necessary on FreeBSD as MSG_CMSG_CLOEXEC
                    // appears to have no effect.
                    // FIXME this should be done in a separate iteration
                    // when the fds are received, and not after user code
                    // has had a chance to run.
                    // SAFETY: It's safe to create FdSlice twice from valid values. The values are valid.   
                    let _ = set_cloexec(&ofd, true);

                    
                }

                let _ = fd_buf[i].replace(ofd);
            }

            // the rest of the OwnedFd will be dropped automatically
        }
    }
    
    return 
        Ok((num_bytes, msg_truc, num_fds));
}

/// A legacy method.
/// 
/// Receives the FDs into a [Vec].
pub 
fn recv_fds<FD: AsFd>(
    fd: FD,  
    from: Option<&mut UnixSocketAddr>,
    bufs: &mut[IoSliceMut],  
    fd_buf: &mut Vec<OwnedFd>
) -> Result<(usize, bool, usize), io::Error> 
{
    let mut ancillary_buf = 
        AncillaryBuf::with_fd_capacity(fd_buf.capacity())?;    

    let (num_bytes, ancillary) = 
        Ancillary::recv_ancillary(fd, from, 0, bufs, &mut ancillary_buf)?;

    let msg_truc = ancillary.message_truncated();

    for message in ancillary 
    {
        if let AncillaryItem::Fds(fds) = message? 
        {
            // Due to alignment of cmsg_len in glibc the minimum payload
            // capacity is on Linux (and probably Android) 8 bytes,
            // which means we might receive two file descriptors even though
            // we only want one.
            let (cap, len) = (fd_buf.capacity(), fd_buf.len());

            let can_keep = fds.len().min(cap - len);

            for (ofd, _) in fds.into_iter().zip(0..can_keep) 
            {
                #[cfg(any(target_vendor="apple", target_os="freebsd"))] 
                {
                    // set cloexec
                    // This is necessary on FreeBSD as MSG_CMSG_CLOEXEC
                    // appears to have no effect.
                    // FIXME this should be done in a separate iteration
                    // when the fds are received, and not after user code
                    // has had a chance to run.
                    // SAFETY: It's safe to create FdSlice twice from valid values. The values are valid.   
                    let _ = set_cloexec(&ofd, true);

                    
                }

                fd_buf.push( ofd );
            }

            // the rest of the OwnedFd will be dropped automatically
        }
    }
    
    return 
        Ok((num_bytes, msg_truc, fd_buf.len()));
}

#[cfg(test)]
mod test_incorrect_msg
{
    use std::{io, os::fd::RawFd};

    use super::*;

    fn send_ancillary_fake(
        to: Option<&UnixSocketAddr>,  
        bytes: &[IoSlice], 
        fds: &[RawFd],  
        offset: usize
    ) -> Result<(msghdr, Vec<u8>), io::Error> 
    {
        unsafe 
        {
            let mut msg: msghdr = mem::zeroed();
            msg.msg_name = ptr::null_mut();
            msg.msg_namelen = 0;
            msg.msg_iov = bytes.as_ptr() as *mut iovec;
            msg.msg_iovlen = 
                bytes.len().try_into() 
                    .map_err(|e|
                        io::Error::new(ErrorKind::InvalidInput, 
                            format!("too many byte slices {}", e))
                    )?;

            msg.msg_flags = 0;
            msg.msg_control = ptr::null_mut();
            msg.msg_controllen = 0;

            if let Some(addr) = to 
            {
                let (addr, len) = addr.as_raw();
                msg.msg_name = addr as *const sockaddr_un as *const c_void as *mut c_void;
                msg.msg_namelen = len;
            }

            let mut needed_capacity = 0;

            if fds.len() > 0 
            {
                if fds.len() > 0xff_ff_ff 
                {
                    // need to prevent truncation.
                    // I use a lower limit in case the macros don't handle overflow.
                    return Err(
                        io::Error::new(ErrorKind::InvalidInput, "too many file descriptors")
                    );
                }
                
                needed_capacity += CMSG_SPACE(mem::size_of_val::<[RawFd]>(&fds) as u32);
            }


            let ancillary_buf = AncillaryBufType::<0>::create_heap(needed_capacity as ControlLen);

            #[cfg(target_os = "linux")]
            {
                msg.msg_controllen = needed_capacity as usize;
            }

            #[cfg(not(target_os = "linux"))]
            {
                msg.msg_controllen = needed_capacity;
            }

            if needed_capacity != 0 
            {
                msg.msg_control = ancillary_buf.as_ptr() as *mut c_void;

                #[cfg(not(any(target_os="illumos", target_os="solaris")))] 
                {
                    use libc::CMSG_FIRSTHDR;

                    let header_ptr = CMSG_FIRSTHDR(&mut msg);
                    assert!(!header_ptr.is_null(), "CMSG_FIRSTHDR returned unexpected NULL pointer");

                    #[allow(unused_mut)]
                    let mut header = &mut*header_ptr;

                    if fds.len() > 0 
                    {
                        use libc::{CMSG_DATA, CMSG_LEN, SCM_RIGHTS, SOL_SOCKET};

                        header.cmsg_level = SOL_SOCKET;
                        header.cmsg_type = SCM_RIGHTS;
                        #[cfg(target_os = "linux")]
                        {
                            header.cmsg_len = CMSG_LEN((mem::size_of_val::<[RawFd]>(&fds)) as u32) as usize + offset;
                        }

                        #[cfg(not(target_os = "linux"))]
                        {
                            header.cmsg_len = CMSG_LEN((mem::size_of_val::<[RawFd]>(&fds)) as u32) + offset as u32;
                        }

                        
                        let mut dst = CMSG_DATA(header) as *mut c_void as *mut RawFd;
                        
                        for fd in fds
                        {
                            if dst.is_aligned() == false
                            {
                                ptr::write_unaligned(dst, *fd);
                            }
                            else
                            {
                                ptr::write(dst, *fd);
                            }

                            dst = dst.add(1);
                        }
                    }
                }
            }

            return Ok((msg, ancillary_buf));
        }
    }

    #[test]
    fn test_ansillary_incorrect_cmslen()
    {
        let (msg, _aux) = send_ancillary_fake(None, &[IoSlice::new(b"abc".as_slice())], &[1, 2], 4).unwrap();

        let (_, ancillary) = Ancillary::recv_ancillary_fake(msg).unwrap();

        let mut i = ancillary.into_iter();
        let res = i.next().unwrap();
        
        assert_eq!(res.is_err(), true);
    }

    #[test]
    fn test_ansillary_incorrect_cmslen_1()
    {
        let (msg, _aux) = send_ancillary_fake(None, &[IoSlice::new(b"abc".as_slice())], &[1, 2], 1).unwrap();

        let (_, ancillary) = Ancillary::recv_ancillary_fake(msg).unwrap();

        let mut i = ancillary.into_iter();
        let res = i.next().unwrap();
        
        assert_eq!(res.is_err(), true);
    }

    #[test]
    fn test_ansillary_incorrect_cmslen_ok()
    {
        let (msg, _aux) = send_ancillary_fake(None, &[IoSlice::new(b"abc".as_slice())], &[1, 2], 0).unwrap();

        let (_, ancillary) = Ancillary::recv_ancillary_fake(msg).unwrap();

        let mut i = ancillary.into_iter();
        let res = i.next().unwrap();
        
        assert_eq!(res.is_err(), false);
        println!("ok");
    }

    #[test]
    fn test_heap_allocator()
    {
        let needed_cap_add = 
            move |needed_capacity: ControlLen|
            {
                (((needed_capacity-1) / 8 + 1) * 8) as usize
            };

        let test_writable = 
            move |mut abt_heap: Vec<u8>, needed: usize|
            {
                for i in 0..needed
                {
                    abt_heap[i] = 1;
                }
            };

        let abt_heap = unsafe{ AncillaryBufType::<0>::create_heap(100) };

        assert_eq!(abt_heap.capacity(), needed_cap_add(100));
        assert!(abt_heap.capacity() >= 100);
        test_writable(abt_heap, 100);

        let abt_heap = unsafe{ AncillaryBufType::<0>::create_heap(1) };

        assert_eq!(abt_heap.capacity(), needed_cap_add(1));
        assert!(abt_heap.capacity() >= 1);
        test_writable(abt_heap, 1);

        let abt_heap = unsafe{ AncillaryBufType::<0>::create_heap(2) };

        assert_eq!(abt_heap.capacity(), needed_cap_add(2));
        assert!(abt_heap.capacity() >= 2);
        test_writable(abt_heap, 2);

        let abt_heap = unsafe{ AncillaryBufType::<0>::create_heap(7) };

        assert_eq!(abt_heap.capacity(), needed_cap_add(7));
        assert!(abt_heap.capacity() >= 7);
        test_writable(abt_heap, 7);

        let abt_heap = unsafe{ AncillaryBufType::<0>::create_heap(8) };

        assert_eq!(abt_heap.capacity(), needed_cap_add(8));
        assert!(abt_heap.capacity() == 8);
        test_writable(abt_heap, 8);

        let abt_heap = unsafe{ AncillaryBufType::<0>::create_heap(99) };

        assert_eq!(abt_heap.capacity(), needed_cap_add(99));
        assert!(abt_heap.capacity() >= 99);
        test_writable(abt_heap, 99);
    }
}