/* Copyright (c) 2019-2023 Torbjørn Birch Moltu, 2020 Jon Magnuson, 2022 Jake Shadle, 2022 David Carlier, 2023 Dominik Maier
 *
 * Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
 * http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
 * http://opensource.org/licenses/MIT>, at your option. This file may not be
 * copied, modified, or distributed except according to those terms.
 */

//! A unix domain sockets library that supports abstract addresses, fd-passing,
//! SOCK_SEQPACKET sockets and more.
//!
//! File-descriptor passing and abstract socket support
//! for stream and datagram sockets is provided via extension traits for
//! existing types.
//! 
//! Also it support UnixStream for Windows i.e AF_INET SOCK_STREAM with some limitations.
//!
//! See README for status of operating system support and other general info.
//! 
//! In seqpacket.rs a [UnixSeqpacketConn]:
//! 
//! If the feature `unsatable_preview` is enabled, a `send_vectored_with_ancillary_to`, 
//! `send_vectored_with_ancillary`, `recv_vectored_with_ancillary_from`,
//! `recv_vectored_with_ancillary` are enabled.
//! 
//! A legacy (method provided not by std but this crate) is `recv_vectored_ancillary`.

#![cfg_attr(feature = "unsatable_preview", feature(unix_socket_ancillary_data))]


// Too many features unavailable on solarish to bother cfg()ing individually.
#![cfg_attr(any(target_os="illumos", target_os="solaris", target_os="windows"), allow(unused))]

#![allow(
    clippy::cast_lossless, // improves portability when values are limited by the OS anyway
    clippy::unnecessary_cast, // not necessarily unnecessary on other OSes
    clippy::len_zero, // the `!` in `if !foo.is_empty()` can be easy to miss
    clippy::needless_return, // consistency with early returns, and to not look incomplete
    clippy::redundant_closure, // avoiding auto-functions of tuple structs and enum variants
    clippy::needless_lifetimes, // explicity when useful
    clippy::needless_borrow, // dereferencing one field from a raw pointer
    clippy::bool_to_int_with_if, // clearer than usize::from()
    // more lints are disabled inside ancillary.rs and credentials.rs
)]

#[cfg(feature="mio")]
pub extern crate mio;

//temporary disabled until xio fix comilation errors on netbsd
/*#[cfg(feature="xio-rs")]
pub extern crate xio_rs;*/

#[cfg(target_family = "unix")]
extern crate libc;

#[cfg(target_family = "windows")]
extern crate windows_sys;

#[cfg(target_family = "windows")]
extern crate tempfile;

/// Get errno as io::Error on -1.
macro_rules! cvt {($syscall:expr) => {
    match $syscall 
    {
        -1 => Err(io::Error::last_os_error()),
        ok => Ok(ok),
    }
}}

/// Get errno as io::Error on -1 and retry on EINTR.
macro_rules! cvt_r {($syscall:expr) => {
    loop 
    {
        let result = $syscall;
        if result != -1 
        {
            break Ok(result);
        }

        let err = io::Error::last_os_error();

        if err.kind() != std::io::ErrorKind::Interrupted 
        {
            break Err(err);
        }
    }
}}

#[cfg(target_family = "windows")]
mod windows_unixstream;

mod addr;

#[cfg(feature = "unsatable_preview")]
mod ancillary_rust;

#[cfg(target_family = "unix")]
mod credentials;

#[cfg(target_family = "unix")]
mod helpers;

#[cfg(target_family = "unix")]
mod ancillary;

#[cfg(target_family = "unix")]
mod traits;

#[cfg(target_family = "unix")]
mod seqpacket;


pub(crate) const LISTEN_BACKLOG: std::ffi::c_int = 128;//10; // what std uses, I think


pub use addr::{UnixSocketAddr, UnixSocketAddrRef, AddrName};

#[cfg(windows)]
pub use windows_unixstream::{WindowsUnixListener, WindowsUnixStream, RecvFlags};

#[cfg(windows)]
pub use windows_unixstream::{get_socket_family, get_socket_type};

#[cfg(target_family = "unix")]
pub use ancillary::{AncillaryBuf, Ancillary, AncillaryItem};

#[cfg(target_family = "unix")]
pub use traits::{UnixListenerExt, UnixStreamExt, UnixDatagramExt};

#[cfg(target_family = "unix")]
pub use seqpacket::{UnixSeqpacketListener, UnixSeqpacketConn};

#[cfg(target_family = "unix")]
pub use credentials::ConnCredentials;

#[cfg(target_family = "unix")]
pub mod nonblocking {
    pub use crate::seqpacket::NonblockingUnixSeqpacketListener as UnixSeqpacketListener;
    pub use crate::seqpacket::NonblockingUnixSeqpacketConn as UnixSeqpacketConn;
}

#[cfg(debug_assertions)]
mod doctest_md_files {
    macro_rules! mdfile {($content:expr, $(#[$meta:meta])* $attach_to:ident) => {
        #[doc=$content]
        #[allow(unused)]
        $(#[$meta])* // can't #[cfg_attr(, doc=)] in .md file
        enum $attach_to {}
    }}
    mdfile!{
        include_str!("../README.md"),
        #[cfg(any(target_os="linux", target_os="android"))] // uses abstract addrs
        Readme
    }
}
