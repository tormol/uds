/* Copyright 2019-2020 Torbjørn Birch Moltu
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
//! existing types in `std::os::unix::net` and from [mio_uds](https://github.com/alexcrichton/mio_uds)
//! (the latter is opt-in and must be enabled with `features=["mio_uds"]` in Cargo.toml).
//!
//! See README for status of operating system support and other general info.

#![cfg(unix)] // compile as empty crate on windows

// Too many features unavailable on solarish to bother cfg()ing individually.
#![cfg_attr(any(target_os="illumos", target_os="solaris"), allow(unused))]

extern crate libc;
#[cfg(feature="mio-uds")]
extern crate mio_uds;
#[cfg(feature="mio")]
extern crate mio;
#[cfg(feature="mio_07")]
extern crate mio_07;

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

mod addr;
mod credentials;
mod helpers;
mod ancillary;
mod traits;
mod seqpacket;
#[cfg(feature="tokio")]
pub mod tokio;

pub use addr::{UnixSocketAddr, UnixSocketAddrRef};
pub use traits::{UnixListenerExt, UnixStreamExt, UnixDatagramExt};
pub use seqpacket::{UnixSeqpacketListener, UnixSeqpacketConn};
pub use credentials::ConnCredentials;

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
