Version 0.10.0 (2026-11-08)
==========================
ISSUE: https://github.com/tormol/uds/issues/32
* Fixed potential read out of bounds when the `cmsg_len` of the `cmsghdr` was not validated.
* Now the `Ancillary` iterator returns `io::Result\<AncillaryItem\>`.  If io::Error is received the
parsing of the messages should be stopped.

ISSUE: https://github.com/tormol/uds/issues/33
Replaces a as_ptr() to as_mut_ptr() however the UB never happened. This is a problem of the Rust language 
designers as they decided to use a model when a variable should be declared as mutable or not which (in my opinion) created more problems than solved. 

* It was partly fixed, however the " the narrowing of sockaddr_un to &mut sockaddr for the addr " was not fixed
as it is ok.

Version 0.9.1 (2026-06-07)
==========================
* A xio-rs was disabled due to compilation errors. Will be returned as soon as it will receive updates.
* OpenBSD/NetBSD requires rustc >= 1.95 in order to compile successfully.

Version 0.9.0 (2026-04-15)
==========================
While auditing the code, I discovered that the person who was helping me with this crate had mixed up the functions "to_raw_fd()" and  "into_raw_fd()" which may cause a FD leak while sending the FD.
For this reason, a version 0.8.x is considered as faulty.
* A `send_fds` was left as is. It sill consumes the OwnedFd closing it after sending. A `send_fds_raw` was added to send a `RawFd` directly.
* A `recv_fds` was left as is receiving the FDs into the Vec. A `recv_slice_fds` was added to receive the FDs into a mutable slice.
* A `recv_ancillary` was left to receive the FDs using iterator.
* Added `recv_vectored_ancillary` a legacy ancillary iterator.

Version 0.8.0 (2026-04-13)
==========================
* Added io::Read and io::Write including `read_to_string` which is based on ioctl FIONREAD. The `read_to_string` may behave not as expected.
* Updated mio to 1.2. I don't want to support legacy and there isn't any reason to do so. If you think - there is one, leave a note please. (I don't want to support it here at all).
* Prepared a recv_vectored_with_ancillary() and  send_vectored_with_ancillary() which requires a unstable Rust compiler. Can be enabled with feature `unsatable_preview`.

Version 0.7.7 (2026-03-31)
==========================
At the moment I don't have access to the local docsrs server, and there is no other way
it can be tested, so this is a last attempt to fix the problem.
* (fixed) Cargo.toml docs.rs(<--- crap crap crap) wrong docs targets.


Version 0.7.6 (2026-03-31)
==========================
* (fixed) Cargo.toml docs.rs(<--- crap crap crap) wrong docs targets.

Version 0.7.5 (2026-03-31)
==========================
* (fixed) Cargo.toml docs.rs(<--- crap) wrong docs targets.


Version 0.7.4 (2026-03-31)
==========================
* (fixed) in the `addr.rs` a  `from_sockaddr_storage` a new_unspecified() is returned when `len < path_offset()`.
* ? add a windows as a target, so it will appear in the docs

Version 0.7.3 (2026-03-26)
==========================
* Fixed a potential memory unligned access at send_ancillary() and recv_ancillary part in ancilliary.rs
* Added temp dir in tests to avoid leaving the socket files.


Version 0.7.2 (2026-03-24)
==========================
* Fixed docs.rs wrong crate name feature

Version 0.7.1 (2026-03-24)
==========================
* Hotfix: Cargo.toml default features. Removed default items.
* Updated Cargo.toml versions of the deps.
* Added 'Incoming' iterator for `UnixSeqpacketListener`
* Added 'Incoming' iterator for `WindowsUnixListener`.
* Added additional functionality including socket pair for `WindowsUnixSocket`.

Version 0.7.0 (2026-03-21)
==========================
* A Xio (Xio-rs) was added to the crate. It can be enaled by adding it to the features.
* A Mio crate was returned to the crate. It can be enaled by adding it to the features.

Version 0.6.1 (2026-02-04)
==========================
* Fixed release date of previous version
* Added more info and comments.

Version 0.6.0 (2026-01-17)
==========================
* The crate's `addr.rs` is used as dependancy, so this crate can be used on Windows to utilize the `UnixSocketAddr`.
* Added experimental support for unixstream in Windows i.e AF_UNIX SOCK_STREAM.

Version 0.5.4 (2026-01-26)
==========================
* Added missing implementation of `Deref` for `NonblockingUnixSeqpacketListener`.
* Fixed `address already in use` problems in docs.

Version 0.5.3 (2026-01-25)
==========================
* Added from OwnedFd and from RawFd and from Self to OwnedFd. Functions which performs conversion from OwnedFd to Self perform check of the socket type.
* `NonblockingUnixSeqpacketListener` and `NonblockingUnixSeqpacketConn` is now have inside an instance of `UnixSeqpacketConn` and `UnixSeqpacketListener` respectivly which is set to non-blocking.
* Reorganised some functions

Version 0.5.2 (2026-01-21)
==========================
* Fixed compilation errors on OpenBSD
* Fixed one test problem (related to what kernel returns)

Version 0.5.1 (2026-01-18)
==========================
* Fixed compilation errors on FreeBSD.
* ! FreeBSD 15 demonstrates strange behaviour with message trancation and empty messages which 
is not compatiable Linux and FreeBSD 14.
* send_ancillary() memory managment modified

Version 0.5.0 (2026-01-16)
==========================
* A crate was forked due to stale status.
* Moved to Rust 2024
* Added OwnedFd and BorrowedFd to comply with Rust specifications.
* Removed MIO and Tokio. Use AsyncFD and implement MIO for the type youself. (Maybe MIO will be readded later).

Version 0.4.2 (2023-12-31)
==========================
* Reduce max path length by one on Apple OSes, Illumos and Solaris. ([#19](https://github.com/tormol/uds/pull/19))  
  While non-NUL-terminated paths work, the man pages says paths must be NUL-terminated.  
  These OSes support arbitrarily long paths, and this library can't represent those,
  so it already only supported a subset of all possible path addresses.
* Fix `UnixSocketAddr::from_raw()` never having worked. ([#18](https://github.com/tormol/uds/pull/18))
* Fix potentiall soundness issues. ([#13](https://github.com/tormol/uds/pull/13) and [#14](https://github.com/tormol/uds/pull/14))

Version 0.4.1 (2023-08-20)
==========================
* Tokio support is back, now for tokio 1.\*.
* There's now also tokio versions of the extensions traits:
  They don't have any methods that would be async, such as `send_fds()` or `receive_fds()`,
  but allow binding and connecting to `uds_fork::UnixSocketAddr`s, and getting information about the peer.

Version 0.4.0 (2023-08-14)
==========================
* Remove tokio support.
  Because 0.2 is not much used at this point.
  1.\* support might be implemented later.
* Remove mio 0.6, mio-uds & mio 0.7 support.
  To simplify code and reduce combinations of features to test.  
  The feature for mio 0.8 support remains `"mio_08"`: `"mio"` is reserved for mio 1.0.

Version 0.3.0 (2023-08-14)
==========================
* Don't return truncatedness from `UnixSeqpacketConn` and `tokio::UnixSeqpacketConn`s `recv()` and `peek()` methods.
  For consistency with the return types of similar methods on stream and datagram types.  
  Use `recv_vectored()` with empty fd buffer if you want to know whether the packet was truncated.
* Remove default impl of `UnixDatagramExt::bind_unix_addr()`, and remove `Sized` bound on the trait.
* Stop quoting Unnamed in `UnixSocketaddr`'s `Debug` impl.
* Add mio_08 feature, for using this library with mio 0.8.
* Require Rust 1.63.
  (Mainly to make CI pass, so older versions will likely work.)

Version 0.2.7 (2023-08-14)
==========================
* Fix potentialy unaligned accesses and slices in release mode. (Thanks @domenukk!)  
  Would previously panic in debug mode, but now non-aligned payloads are supported.
* Fix large ancillary buffers not being zero-initialized when filling out a buffer to send.  (Thanks @domenukk!)
* Fix using wrong macro when calculating required ancillary buffer size when sending.  
  The only effect of this is was some padding on 64-bit Linux or FreeBSD would not be allocated or sent.  
  This could therefore *not* cause out-of-bounds writes.

Version 0.2.6 (2021-04-03)
==========================
* Add `take_error()` and `into_nonblocking()` to tokio seqpacket types.
* Implement `AsRef` to nonblocking variants for tokio seqpacket types.

Version 0.2.5 (2021-04-01)
==========================
* Add `send_vectored()` and `recv_vectored()` to `::tokio::UnixSeqpacketConn`.
* Add `peek()` and `peek_vectored()` to `::tokio::UnixSeqpacketConn`.
* Add `send_fds()` and `recv_fds()` to `::tokio::UnixSeqpacketConn`.
* Implement `AsRawfd` and `IntoRawFd` for tokio seqpacket types.
* Add fallible `from_raw_fd()` to tokio seqpacket types.
* Add `from_nonblocking()` to `::tokio::UnixSeqpacketListener`.
* Fix `initial_peer_credentials()` impl for Illumos & Solaris writing to stdout.

Version 0.2.4 (2021-03-25)
==========================
* Implement peer credentials on NetBSD and DragonFly BSD.
* Add `initial_peer_selinux_context()`.
* Add `initial_peer_credentials()` to `::tokio::UnixSeqpacketConn`.
* Add `bind_addr()` and `local_addr()` to `::tokio::UnixSeqpacketListener`.
* Add `connect_addr()`, `connect_from_addr()`, `local_addr()` and `peer_addr()`
  to `::tokio::UnixSeqpacketConn`.

Version 0.2.3 (2021-03-06)
==========================
* Add `send_to_unix_addr()`, `recv_from_unix_addr()`, `peek_from_unix_addr()` and vectored variants to `UnixDatagramExt`.
* Add `UnixDatagramExt::bind_unix_addr()`.
  (with a fallback default impl that creates a nonblocking socket)
* Add `as_pathname()` and `as_abstract()` to `UnixSocketAddr`.
* Add `name()` to `UnixSocketAddr` and rename `UnixSocketAddrRef` to `AddrName`,
  with a type alias for backwards compatibility.
* Add `from_raw_bytes()` and `as_raw_bytes()` to `UnixSocketAddr`.
* List DragonFly BSD as supported after testing on it.

Version 0.2.2 (2021-01-31)
==========================
* Compile on 64-bit Android (#4).
* Support OpenBSD (including peer credentials).
* Fix `UnixDatagramExt::recv_fds_from()` always returning unnamed adress.
* Fix `UnixSocketAddr::as_ref()` and its `Debug` impl misrepresenting some unnamed addresses
  as abstract on operating systems that don't have abstract addresses.
* Fix `UnixSocketAddr::as_ref()` and its `Debug` impl having trailing NULs in paths in rare cases.
  (this has only happened on OpenBSD so far).
* Avoid invoking `accept4()` on x86 Android (based on [mio #1445](https://github.com/tokio-rs/mio/issues/1445)).

Version 0.2.1 (2020-11-15)
==========================
* Add timeout methods to blocking seqpacket types.
* Add `take_error()` to all seqpacket types.
* Add `peek()` and `peek_vectored()` to seqpacket connection types.
* Remove outdated WiP section of README saying NetBSD and Illumos aren't supported.

Version 0.2.0 (2020-10-21)
==========================
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

Version 0.1.0 (2029-02-15)
==========================
* Rename `UnixSocketAddr::unspecified()` to `new_unspecified()`.
* Add `peer_credentials()`.
* Support macOS and FreeBSD.

Version 0.0.0 (2019-11-23)
==========================
* Add `UnixSocketAddr` to support abstract addresses.
* Add seqpacket types.
* Add extension traits to support FD passing (and to create and accept `UnixSocketAddr`)
