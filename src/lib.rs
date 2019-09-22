/* Copyright 2019 Torbjørn Birch Moltu
 *
 * Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
 * http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
 * http://opensource.org/licenses/MIT>, at your option. This file may not be
 * copied, modified, or distributed except according to those terms.
 */

extern crate libc;

mod addr;
mod credentials;
mod helpers;
mod ancillary;
mod traits;

pub use addr::{UnixSocketAddr, UnixSocketAddrRef};
pub use traits::{UnixStreamExt, UnixDatagramExt};
