# uds

A unix domain sockets Rust library that supports abstract addresses, fd-passing, SOCK_SEQPACKET sockets and more.

[![crates.io page](https://img.shields.io/crates/v/uds.svg)](https://crates.io/crates/uds) ![License: Apache v2 / MIT](https://img.shields.io/crates/l/uds.svg) [![Documentation](https://docs.rs/uds/badge.svg)](https://docs.rs/uds/) [![cirrus-ci build status](https://api.cirrus-ci.com/github/tormol/uds.svg)](https://cirrus-ci.com/github/tormol/uds) [![travis build status](https://travis-ci.com/tormol/uds.svg?branch=master)](https://travis-ci.com/tormol/uds) [![sourcehut build status](https://builds.sr.ht/~torbmol/uds.svg)](https://builds.sr.ht/~sircmpwn/builds.sr.ht?)

When possible, features are implemented via extension traits for [`std::os::unix::net`](https://doc.rust-lang.org/std/os/unix/net/index.html) types (and optionally [mio-uds](https://crates.io/crates/mio-uds) types) instead of exposing new structs.
The only new socket structs this crate exposes are those for seqpacket sockets.

Timestamps, SELinux context, and ancillary credentials are not yet supported.

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
Also, some OSes might return the original file descriptor without cloning it if it's received within the same process as it was sent from. (DragonFly BSD, possibly macOS and maybe FreeBSD).

| | Linux | macOS | FreeBSD | OpenBSD | NetBSD | Illumos |
|-|-|-|-|-|-|
| **Seqpacket** | Yes | N/A | Yes | Yes | Yes | N/A |
| **peer credentials** | Yes | Yes | Yes | Yes | No | Yes |
| **fd-passing** | Yes | Yes | Yes | Yes | Yes | No |
| **abstract addresses** | Yes | N/A | N/A | N/A | N/A | N/A |
| **mio (0.6 & 0.7 & uds)** | Yes | Yes | Yes | ? | Yes | Yes |
| **tokio** | Yes | Yes | Yes | Yes | Yes | Didn't run |
| **Tested?** | Locally + CI | CI | CI + Manually | CI | Manually | Manually |

### Other OSes

* Android: I haven't tested on it, but I assume there are no differences from regular Linux.
* Windows 10: While it added some unix socket features, Windows support is not a priority. (PRs are welcome though).
* DragonFly BSD: Basic features should work, but tests fail. I plan to support it.
* Solaris: Treated identically as Illumos.

## mio integration

The non-blocking seqpacket types can optionally be used with [mio](https://github.com/tokio-rs/mio)
(version 0.6):

To enable it, add this to Cargo.toml:

```toml
[dependencies]
uds = {version="0.2.1", features=["mio"]}
```

The extension traits can also be implement for [mio-uds](https://github.com/alexcrichton/mio-uds) types:

To enable them, add this to Cargo.toml:

```toml
[dependencies]
uds = {version="0.2.1", features=["mio-uds"]}
```

Mio 0.7 is also supported:

```toml
[dependencies]
uds = {version="0.2.1", features=["mio_07"]}
```

## tokio integration

Futures-aware seqpacket types can optionally be used with [tokio](https://github.com/tokio-rs/tokio)
(version 0.2):

To enable it, add this to Cargo.toml:

```toml
[dependencies]
uds = {version="0.2.1", features=["tokio"]}
```

## Minimum Rust version

The minimum Rust version is 1.39.

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

## Release History

### Version 0.2.1 (2020-11-15)

* Add timeout methods to blocking seqpacket types.
* Add `take_error()` to all seqpacket types.
* Add `peek()` and `peek_vectored()` to seqpacket connection types.
* Remove outdated WiP section of README saying NetBSD and Illumos aren't supported.

### Version 0.2.0 (2020-10-21)

* Require Rust 1.39.
* Add mio 0.7 support, behind optional feature `mio_07`.  
  (mio 0.6 is still supported and enabled with `mio` feature.)
* Add tokio seqpacket types, behind optional feature `tokio`. (by @jmagnuson).
* Add `shutdown()` to seqpacket connection types (by @jmagnuson).
* Fix creating sockets failing on Illumos & Solaris.
  (This crate was setting close-on-exec in an unsupported way.)
* Support peer credentials on Illumos / Solaris.
* Enable close-on-exec and non-blocking mode atomically on all OSes where prossible.  
  (with `SOCK_CLOEXEC`, `SOCK_NONBLOCK` and `accept4()`)  
  The only place missing these are macOS (and anything else by Apple).
* Mark NetBSD and Illumos as supported.

### Version 0.1.0 (2029-02-15)

(initial release)
