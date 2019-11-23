# uds

A unix domain sockets Rust library that supports abstract addresses, fd-passing and SOCK_SEQPACKET sockets.

[![crates.io page](https://img.shields.io/crates/v/uds.svg)](https://crates.io/crates/uds) ![License: Apache v2 / MIT](https://img.shields.io/crates/l/uds.svg) [![Documentation](https://docs.rs/uds/badge.svg)](https://docs.rs/uds/) [![cirrus-ci build status](https://api.cirrus-ci.com/github/tormol/uds.svg)](https://cirrus-ci.com/github/tormol/uds) [![travis build status](https://travis-ci.org/tormol/uds.svg)](https://travis-ci.org/tormol/uds)

When possible, features are implemented via extension traits for [`std::os::unix::net`](https://doc.rust-lang.org/std/os/unix/net/index.html) types (and optionally [mio-uds](https://crates.io/crates/mio-uds) types) instead of exposing new structs.
The only new socket structs this crate exposes are those for seqpacket sockets.

## WiP

Currently this crate has only really been tested on Linux, and might not be usable on other operating systems. It *compiles* for FreeBSD, macOS, NetBSD and Solaris, but that doesn't guarantee that the code is correct for that OS's pecularities.  
If you care about being cross-platform, come back later :)
I hope to eventually support all of Linux & Android, FreeBSD, macOS, OpenBSD, NetBSD, Dragonfly BSD and Illumos.
Windows 10 added some unix socket features, but Windows support is not a priority. (PRs are welcome though).

Feature-wise, the goal is to expose everything unix domain sockets have to offer, including credentials, timestamps and more.

## Portability

macOS doesn't support SOCK_SEQPACKET or abstract socket addresses, so if you don't want to bother with supporting non-portable features you are probably better off only using what std or mio-uds provides.
If you're writing a datagram server though, using std or mio-uds means you can't respond to abstract adresses, forcing clients to use path addresses and deal with cleaning up the socket file after themselves.

Even when all operating systems you care about supports something, they might behave differently:  
On Linux file descriptors are cloned when they are sent, but macOS and the BSDs first clones them when they are received. This means that if a fd is closed before the peer receives it you have a problem.

## mio integration

The non-blocking seqpacket types can optionally be used with [mio](https://github.com/carllerche/mio):

To enable it, add this to Cargo.toml:

```toml
[dependencies]
uds = {version="0.0.1", features=["mio"]}
```

## Minimum Rust version

The minimum Rust version is 1.36, because of `std::io::IoSlice`.
If this is a problem for you I can make the parts that need it opt-out.

## License

Licensed under either of

* Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
* MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.
