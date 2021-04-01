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
