
/*
Copyrights in the Rust project are retained by their contributors. No
copyright assignment is required to contribute to the Rust project.

Some files include explicit copyright notices and/or license notices.
For full authorship information, see the version control history or
<https://thanks.rust-lang.org>

Except as otherwise noted, Rust is licensed under the Apache License, Version
2.0 <LICENSE-APACHE> or <http://www.apache.org/licenses/LICENSE-2.0> or the MIT
license <LICENSE-MIT> or <http://opensource.org/licenses/MIT>, at your option.
*/



#[derive(Debug)]
pub struct SocketAncillaryCover<'a> 
{
    pub buffer: &'a mut [u8],
    pub length: usize,
    pub truncated: bool,
}
