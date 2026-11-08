# uds

<img src="https://cdn.4neko.org/uds.webp" width="200"/>


<br/>
<a href = "https://codeberg.org/4neko/uds/actions"><img src="https://codeberg.org/4neko/uds/badges/workflows/multi-os.yml/badge.svg" /></a>

<img src="https://cdn.4neko.org/win_ev_log.webp" width="100"/>

> [!IMPORTANT]  
> Very bad news [ISSUE](https://github.com/tormol/uds/issues/29). I am not able to verify this!

> [!IMPORTANT]  
> I am not original author. A [GitHub](https://github.com/tormol/uds) and [Crates](https://crates.io/crates/uds) are links to original crate. This crate is forked!


A unix domain sockets Rust library that supports abstract addresses, fd-passing, SOCK_SEQPACKET sockets SOCK_STREAM for the `Windows` and more i.e Unix Domain Sockets for Windows.

A `AF_UNIX` `SOCK_STREAM` is implemented for Windows in windows_unixstream.rs as an experiment. WSA veriosn 2.2 is required.

When possible, features are implemented via extension traits for [`std::os::unix::net`](https://doc.rust-lang.org/std/os/unix/net/index.html) types (and optionally [mio](https://crates.io/crates/mio)'s uds types) instead of exposing new structs. And [xio](https://crates.io/crates/xio-rs)'s uds types including Unix Socket for Windows.
The only new socket structs this crate exposes are those for seqpacket sockets.

Ancillary credentials and timestamps are not yet supported.

## Features:

* "xio-rs" enables the Xio-rs event notification system compat code (DISABLED TEMPORARY)
* "mio" enables the Mio event notification system compat code
* "unsatable_preview" enables the all unstable, nightly code i.e send_vectored_with_ancillary().

## Changelog

<details>
  <summary>Changelog </summary>

ISSUE: https://github.com/tormol/uds/issues/32
* Fixed potential read out of bounds when the `cmsg_len` of the `cmsghdr` was not validated.
* Now the `Ancillary` iterator returns `io::Result\<AncillaryItem\>`.  If io::Error is received the
parsing of the messages should be stopped.

ISSUE: https://github.com/tormol/uds/issues/33
Replaces a as_ptr() to as_mut_ptr() however the UB never happened. This is a problem of the Rust language 
designers as they decided to use a model when a variable should be declared as mutable or not which (in my opinion) created more problems than solved. 

* It was partly fixed, however the " the narrowing of sockaddr_un to &mut sockaddr for the addr " was not fixed
as it is ok.

</details>

<details>
  <summary>Changelog Version 0.9.1 (2026-06-07)</summary>

* A xio-rs was disabled due to compilation errors. Will be returned as soon as it will receive updates.
* OpenBSD/NetBSD requires rustc >= 1.95 in order to compile successfully.
</details>

<details>
  <summary>Changelog Version 0.9.0 (2026-04-15)</summary>

While auditing the code, I discovered that the person who was helping me with this crate had mixed up the functions "to_raw_fd()" and  "into_raw_fd()" which may cause a FD leak while sending the FD.
For this reason, a version 0.8.x is considered as faulty.
* A `send_fds` was left as is. It sill consumes the OwnedFd closing it after sending. A `send_fds_raw` was added to send a `RawFd` directly.
* A `recv_fds` was left as is receiving the FDs into the Vec. A `recv_slice_fds` was added to receive the FDs into a mutable slice.
* A `recv_ancillary` was left to receive the FDs using iterator.
* Added `recv_vectored_ancillary` a legacy ancillary iterator.

</details>

<details>
  <summary>Changelog Version 0.8.0 (2026-04-13)</summary>

* Added io::Read and io::Write including `read_to_string` which is based on ioctl FIONREAD. The `read_to_string` may behave not as expected.
* Updated mio to 1.2. I don't want to support legacy and there isn't any reason to do so. If you think - there is one, leave a note please. (I don't want to support it here at all).
* Prepared a recv_vectored_with_ancillary() and  send_vectored_with_ancillary() which requires a unstable Rust compiler. Can be enabled with feature `unsatable_preview`.

</details>




## Examples

### (only runs sucessfully on Linux)

```rust
extern crate uds_fork;

use std::os::{unix::net::UnixDatagram, fd::OwnedFd};

let addr = uds_fork::UnixSocketAddr::from_abstract(b"not a file!")
    .expect("create abstract socket address");
let listener = uds_fork::UnixSeqpacketListener::bind_unix_addr(&addr)
    .expect("create seqpacket listener");

let client = uds_fork::UnixSeqpacketConn::connect_unix_addr(&addr)
    .expect("connect to listener");
let (a, b) = UnixDatagram::pair().expect("create datagram socket pair");
let (aa, _bb) = UnixDatagram::pair().expect("create datagram socket pair");

client.send_fds(b"Here I come", vec![OwnedFd::from(a), OwnedFd::from(b), OwnedFd::from(aa)])
    .expect("send stdin, stdout and stderr");

let (server_side, _) = listener.accept_unix_addr()
    .expect("accept connection");
let creds: uds_fork::ConnCredentials = server_side.initial_peer_credentials()
    .expect("get peer credentials");
if creds.euid() == 0 {
    let mut fd_buf = Vec::with_capacity(3);
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

### (only runs sucessfully on Linux and on nightly, feature = "unsatable_preview")

```rust ignore
extern crate uds_fork;

#![feature(unix_socket_ancillary_data)]

use std::{io::{IoSlice, IoSliceMut}, os::{fd::{IntoRawFd, OwnedFd}, unix::net::{AncillaryData, SocketAncillary, UnixDatagram}}};

use libc::MSG_EOR;

let dir = tempfile::tempdir().unwrap();
let path_full = dir.path().join("seqpacket2.exists.socket");
let path = path_full.as_path();

let addr = 
    uds_fork::UnixSocketAddr::from_path(&path)
        .expect("create abstract socket address");
    
let listener = 
    uds_fork::UnixSeqpacketListener::bind_unix_addr(&addr)
        .expect("create seqpacket listener");

let freya_side_a = 
    uds_fork::UnixSeqpacketConn::connect_unix_addr(&addr)
        .expect("connect to listener");

let (freya_side_b, _) = listener.accept_unix_addr()
    .expect("accept connection");

let (a, b) = UnixDatagram::pair().expect("create datagram socket pair");
let (aa, _bb) = UnixDatagram::pair().expect("create datagram socket pair");

let buf0 = b"Here I come";
let mut ancillary_buffer = [0; 128];
let mut ancillary = SocketAncillary::new(&mut ancillary_buffer[..]);

let fds = [OwnedFd::from(a).into_raw_fd(), OwnedFd::from(b).into_raw_fd(), OwnedFd::from(aa).into_raw_fd()];

ancillary.add_fds(&fds[..]);

freya_side_a.send_vectored_with_ancillary(MSG_EOR, &[IoSlice::new(buf0.as_slice())], &mut ancillary)
    .expect("send stdin, stdout and stderr");

// receive
let mut buf = [0_u8; 256];
let bufs = &mut [IoSliceMut::new(&mut buf[..])];

let mut ancillary_buffer = [0; 128];
let mut ancillary = SocketAncillary::new(&mut ancillary_buffer[..]);

let (count, trunc) = freya_side_b.recv_vectored_with_ancillary(0, bufs, &mut ancillary).unwrap();

println!("count: {}, trunc: {}, anscil len: {}", count, trunc, ancillary.len());

assert_eq!(trunc, false);
assert_eq!(count, buf0.len());
assert_eq!(buf0.as_slice(), &buf[..count]);

for ancillary_result in ancillary.messages() 
{
    if let AncillaryData::ScmRights(scm_rights) = ancillary_result.unwrap() 
    {
        assert_eq!(scm_rights.count(), 3);
    }
    else
    {
        panic!("expected ScmRights")
    }
}
```

### (only runs sucessfully on Windows)

```rust ignore
extern crate uds_fork;
use uds_fork::{RecvFlags, WindowsUnixListener, WindowsUnixStream};

  let path = "server3.sock";
  rem_sock(path);

  let wul = WindowsUnixListener::bind(path).unwrap();

  let client = WindowsUnixStream::connect(path).unwrap();

  let (accp_client, rem_addr) = wul.accept_unix_addr().unwrap();

  println!("accepted connection: {}", rem_addr);
  assert_eq!(rem_addr.to_string().as_str(), "unnamed");

  let sa_fam = uds_fork::get_socket_family(&accp_client).unwrap();
  let sa_type = uds_fork::get_socket_type(&accp_client).unwrap();
  assert_eq!(sa_fam, AF_UNIX);
  assert_eq!(sa_type, SOCK_STREAM);

  println!("{} {}", sa_fam, sa_type);

  let data: [u8; 4] = [1,2,3,4];

  let srv_n = client.send(&data).unwrap();
  assert_eq!(srv_n, data.len());

  let mut rcv_data = [0_u8; 10];
  let rcv_n = accp_client.recv(&mut rcv_data).unwrap();
  assert_eq!(srv_n, rcv_n);
  assert_eq!(&data, &rcv_data[..srv_n]);


  // accp_client -> client
    let data: [u8; 4] = [5,6,7,8];

  let srv_n = accp_client.send(&data).unwrap();
  assert_eq!(srv_n, data.len());

  let mut rcv_data = [0_u8; 10];
  let rcv_n = client.recv(&mut rcv_data).unwrap();
  assert_eq!(srv_n, rcv_n);
  assert_eq!(&data, &rcv_data[..srv_n]);

  rem_sock(path);

```

## Using with Xio (xio-rs)

The Xio can be enabled by enabling the feature "xio-rs".

```rust ignore
let (mut a, b) = UnixSeqpacketConn::pair().unwrap();

let mut reg = XioPollRegistry::<ESS>::new().unwrap();
let mut event_buf = XioPollRegistry::<ESS>::allocate_events(128.try_into().unwrap());

// either
let a_wrapped =
    reg.get_registry()
        .en_register_wrap(a, XioEventUid::manual(1), XioChannel::INPUT)
        .unwrap();
 
// or 
    reg.get_registry()
        .en_register&mut a, XioEventUid::manual(1), XioChannel::INPUT)
        .unwrap();

// so depending on the method, use either:
a_wrapped.inner();

// or continue using a directly
```

## Using with MIO

The MIO crate can be enabled using feature "mio".

```rust ignore
let (mut a, b) = UnixSeqpacketConn::pair().unwrap();

let mut poll = Poll::new().expect("create mio poll");
let mut events = Events::with_capacity(10);

poll.registry()
    .register(&mut a, Token(1), Interest::READABLE)
    .unwrap();
```

## Portability

macOS doesn't support SOCK_SEQPACKET sockets, and abstract socket addresses is Linux-only, so if you don't want to bother with supporting non-portable features you are probably better off only using what std or mio provides.
If you're writing a datagram server though, using std or mio means you can't respond to abstract adresses, forcing clients to use path addresses and deal with cleaning up the socket file after themselves.

Even when all operating systems you care about supports something, they might behave differently:  
On Linux file descriptors are cloned when they are sent, but macOS and the BSDs first clones them when they are received. This means that if a FD is closed before the peer receives it you have a problem.  
Also, some OSes might return the original file descriptor without cloning it if it's received within the same process as it was sent from. (DragonFly BSD, possibly macOS and maybe FreeBSD).

| | Linux | macOS | FreeBSD | OpenBSD | DragonFly BSD | NetBSD | Illumos | Windows |
|-|-|-|-|-|-|-|-|-|
| **Seqpacket** | Yes | N/A | Yes | Yes | Yes | Yes | N/A | N/A |
| **fd-passing** | Yes | Yes | Yes | Yes | Yes | Yes | No | No |
| **abstract addresses** | Yes | N/A | N/A | N/A | N/A | N/A | N/A | N/A |
| **unix_stream_win** | N/A | N/A | N/A | N/A | N/A | N/A | N/A | Yes |
| **Tested?** | Manually<sup>\*</sup> | Manually<sup>\*</sup> | Manually<sup>\*</sup> | Manually<sup>\*</sup> | Manually<sup>\*</sup> | Manually<sup>\*</sup> | Manually<sup>\*</sup> | Manually<sup>\*</sup>

<sup>\*</sup>: Not tested since v0.2.6. (but (cross)checked on CI.)

### Other OSes

* FreeBSD 15 (from version to version) behaves differently on msg truncation and sending empty messages.
See [bugs FreeBSD](https://bugs.freebsd.org/bugzilla/show_bug.cgi?id=279354)
* Android: I haven't tested on it, but I assume there are no differences from regular Linux.
* Windows 10: While it added some unix socket features, Windows support is not a priority. (PRs are welcome though).
* Solaris: Treated identically as Illumos. mio 0.8 doesn't support it.
* Windows: UnixSocketAddr and WindowsUnixStream and WindowsUnixListener only!


## Minimum Rust version

The minimum Rust version is 1.63.  
Older versions might work, but might break in a minor release.

## `unsafe` usage

This crate calls many C functions, which are all `unsafe` (even ones as simple as `socket()`).
The public interface complies with Rust's FD managment recomendations.

## License

<img src="https://cdn.4neko.org/mit_apache.webp" width="250"/>

Licensed under either of

* Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
* MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.
