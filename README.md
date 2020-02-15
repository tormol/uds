# uds

A unix domain sockets Rust library that supports abstract addresses, fd-passing, SOCK_SEQPACKET sockets and more.

[![crates.io page](https://img.shields.io/crates/v/uds.svg)](https://crates.io/crates/uds) ![License: Apache v2 / MIT](https://img.shields.io/crates/l/uds.svg) [![Documentation](https://docs.rs/uds/badge.svg)](https://docs.rs/uds/) [![cirrus-ci build status](https://api.cirrus-ci.com/github/tormol/uds.svg)](https://cirrus-ci.com/github/tormol/uds) [![travis build status](https://travis-ci.com/tormol/uds.svg?branch=master)](https://travis-ci.com/tormol/uds)

When possible, features are implemented via extension traits for [`std::os::unix::net`](https://doc.rust-lang.org/std/os/unix/net/index.html) types (and optionally [mio-uds](https://crates.io/crates/mio-uds) types) instead of exposing new structs.
The only new socket structs this crate exposes are those for seqpacket sockets.

## WiP

At this point only Linux, FreeBSD and macOS are supported and tested on CI.
The crate also *compiles* for NetBSD and Solaris, but might not be usable there.
(Android should work fine, but I haven't actually tested or cross-checked for it.)

I hope to eventually also support OpenBSD, Dragonfly BSD and Illumos, so if you care about being truly cross-platform, come back later :)  
While Windows 10 added some unix socket features, Windows support is not a priority. (PRs are welcome though).

Feature-wise, the goal is to expose everything unix domain sockets have to offer, including all types of credentials, timestamps and more.

## Example

(only runs sucessfully on Linux)

```rust
extern crate uds;

let addr = uds::UnixSocketAddr::from_abstract(b"not a file!")
    .expect("create abstract socket address");
let listener = uds::UnixSeqpacketListener::bind_unix_addr(&addr)
    .expect("create seqpacket listener");

let client = uds::UnixSeqpacketConn::connect_unix_addr(&addr)
    .expect("connect to listener");
client.send_fds(b"Here I come", &[0, 1, 2])
    .expect("send stdin, stdout and stderr");

let (server_side, _) = listener.accept_unix_addr()
    .expect("accept connection");
let creds: uds::ConnCredentials = server_side.initial_peer_credentials()
    .expect("get peer credentials");
if creds.euid() == 0 {
    let mut fd_buf = [-1; 3];
    let (_, _, fds) = server_side.recv_fds(&mut[0u8; 1], &mut fd_buf
        ).expect("receive with fd capacity");
    if fds == 3 {
        /* do something with the file descriptors */
    }
    /* remember to close the file descripts */
} else {
    server_side.send(b"go away!\n").expect("send response");
}
```

## Portability

macOS doesn't support SOCK_SEQPACKET sockets, and abstract socket addresses is Linux-only, so if you don't want to bother with supporting non-portable features you are probably better off only using what std or mio-uds provides.
If you're writing a datagram server though, using std or mio-uds means you can't respond to abstract adresses, forcing clients to use path addresses and deal with cleaning up the socket file after themselves.

Even when all operating systems you care about supports something, they might behave differently:  
On Linux file descriptors are cloned when they are sent, but macOS and the BSDs first clones them when they are received. This means that if a FD is closed before the peer receives it you have a problem.

## mio integration

The non-blocking seqpacket types can optionally be used with [mio](https://github.com/tokio-rs/mio)
(version 0.6):

To enable it, add this to Cargo.toml:

```toml
[dependencies]
uds = {version="0.1.0", features=["mio"]}
```

The extension traits can also be implement for [mio-uds](https://github.com/alexcrichton/mio-uds) types:

To enable them, add this to Cargo.toml:

```toml
[dependencies]
uds = {version="0.1.0", features=["mio-uds"]}
```

## Minimum Rust version

The minimum Rust version is 1.36, because of `std::io::IoSlice`.
If this is a problem I can make the parts that need it opt-out.

## `unsafe` usage

This crate calls many C functions, which are all `unsafe` (even ones as simple as `socket()`).
The public interface is safe (except for `FromRawFd`), so if you find something unsound (even internal functions that aren't marked `unsafe`) please open an issue.

## License

Licensed under either of

* Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
* MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.
