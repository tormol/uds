/* Copyright 2019 Torbjørn Birch Moltu
 *
 * Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
 * http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
 * http://opensource.org/licenses/MIT>, at your option. This file may not be
 * copied, modified, or distributed except according to those terms.
 */

extern crate libc;
#[cfg(feature="mio-uds")]
extern crate mio_uds;

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

pub use addr::{UnixSocketAddr, UnixSocketAddrRef};
pub use traits::{UnixListenerExt, UnixStreamExt, UnixDatagramExt};
