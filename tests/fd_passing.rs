#![cfg_attr(any(target_os="illumos", target_os="solaris"), allow(unused))]

extern crate uds;

use std::io::{ErrorKind::*, Read, Write};
use std::os::unix::io::{AsRawFd, FromRawFd};
use std::os::unix::net::{UnixDatagram, UnixStream};
use std::env::consts::*;
use std::mem::ManuallyDrop;

use uds::{UnixDatagramExt, UnixStreamExt};

#[cfg_attr(not(any(target_os="illumos", target_os="solaris")), test)]
fn datagram_send_no_fds() {
    let (a, b) = UnixDatagram::pair().expect("create datagram socket pair");

    // send with empty fd slice, receive without ancillary buffer
    a.send_fds(b"a", &[]).expect("send zero file descriptors");
    let bytes = b.recv(&mut[0u8; 10]).expect("receive normally - without ancillary buffer");
    assert_eq!(bytes, 1);

    // send with empty fd slice, receive for empty fd slice
    a.send_fds(b"aa", &[]).expect("send zero file descriptors");
    let (bytes, fds) = b.recv_fds(&mut[0u8; 10], &mut[]).expect("receive with empty fd buffer");
    assert_eq!(bytes, 2);
    assert_eq!(fds, 0);

    // send without ancillary, receive for empty fd slice
    a.send(b"aaa").expect("send normally - without ancillary");
    let (bytes, fds) = b.recv_fds(&mut[0u8; 10], &mut[]).expect("receive with empty fd buffer");
    assert_eq!(bytes, 3);
    assert_eq!(fds, 0);

    // send with empty fd slice, receive with capacity
    a.send_fds(b"aaaa", &[]).expect("send zero file descriptors");
    let mut fd_buf = [-1; 3];
    let (bytes, fds) = b.recv_fds(&mut[0u8; 10], &mut fd_buf).expect("receive with fd buffer");
    assert_eq!(bytes, 4);
    assert_eq!(fds, 0);
    assert_eq!(fd_buf, [-1; 3]);

    // send without ancillary, receive with capacity
    a.send(b"aaaaa").expect("send normally - without ancillary");
    let mut fd_buf = [-1; 3];
    let (bytes, fds) = b.recv_fds(&mut[0u8; 10], &mut fd_buf).expect("receive with fd buffer");
    assert_eq!(bytes, 5);
    assert_eq!(fds, 0);
    assert_eq!(fd_buf, [-1; 3]);
}

#[cfg_attr(not(any(target_os="illumos", target_os="solaris")), test)]
fn datagram_truncate_fds() {
    let (a, b) = UnixDatagram::pair().expect("create datagram socket pair");

    // send some, receive without ancillary buffer
    a.send_fds(b"a", &[a.as_raw_fd()]).expect("send one fd");
    let bytes = b.recv(&mut[0u8; 10]).expect("receive normally - without ancillary buffer");
    assert_eq!(bytes, 1);

    // send some, receive with zero-length fd slice
    a.send_fds(b"aa", &[a.as_raw_fd()]).expect("send one fd");
    let (bytes, fds) = b.recv_fds(&mut[0u8; 10], &mut[]).expect("receive with empty fd buffer");
    assert_eq!((bytes, fds), (2, 0));

    // send four, receive two
    a.send_fds(b"aaa", &[a.as_raw_fd(), a.as_raw_fd(), b.as_raw_fd(), b.as_raw_fd()])
        .expect("send four fds");
    let mut fd_buf = [-1; 2];
    match b.recv_fds(&mut[0u8; 10], &mut fd_buf) {// receives to capacity or none
        Ok((3, 2)) => {
            assert_ne!(fd_buf[0], -1);
            if fd_buf[0] != a.as_raw_fd()  &&  fd_buf[0] != b.as_raw_fd() {
                let _ = unsafe { UnixDatagram::from_raw_fd(fd_buf[0]) };
            }
            assert_ne!(fd_buf[1], -1);
            if fd_buf[1] != a.as_raw_fd()  &&  fd_buf[1] != b.as_raw_fd() {
                let _ = unsafe { UnixDatagram::from_raw_fd(fd_buf[1]) };
            }
        }
        Ok((3, 0)) => assert_eq!(fd_buf, [-1; 2]),
        Ok((bytes, fds)) => {
            panic!("received {} bytes and {} fds but expected 3 bytes and 2 or 0 fds", bytes, fds);
        }
        Err(e) => panic!("receive with smaller fd buffer failed: {}", e),
    }
}

#[cfg_attr(not(any(target_os="illumos", target_os="solaris")), test)]
fn stream_send_no_fds() {
    let (mut a, mut b) = UnixStream::pair().expect("create stream socket pair");

    // send with empty fd slice, receive without ancillary buffer
    a.send_fds(b"a", &[]).expect("send zero file descriptors");
    let bytes = b.read(&mut[0u8; 10]).expect("read normally - without ancillary buffer");
    assert_eq!(bytes, 1);

    // send with empty fd slice, receive for empty fd slice
    a.send_fds(b"aa", &[]).expect("send zero file descriptors");
    let (bytes, fds) = b.recv_fds(&mut[0u8; 10], &mut[]).expect("receive with empty fd buffer");
    assert_eq!(bytes, 2);
    assert_eq!(fds, 0);

    // send without ancillary, receive for empty fd slice
    a.write(b"aaa").expect("write normally - without ancillary");
    let (bytes, fds) = b.recv_fds(&mut[0u8; 10], &mut[]).expect("receive with empty fd buffer");
    assert_eq!(bytes, 3);
    assert_eq!(fds, 0);

    // send with empty fd slice, receive with capacity
    a.send_fds(b"aaaa", &[]).expect("send zero file descriptors");
    let mut fd_buf = [-1; 3];
    let (bytes, fds) = b.recv_fds(&mut[0u8; 10], &mut fd_buf).expect("receive with fd buffer");
    assert_eq!(bytes, 4);
    assert_eq!(fds, 0);
    assert_eq!(fd_buf, [-1; 3]);

    // send without ancillary, receive with capacity
    a.write(b"aaaaa").expect("write normally - without ancillary");
    let mut fd_buf = [-1; 3];
    let (bytes, fds) = b.recv_fds(&mut[0u8; 10], &mut fd_buf).expect("receive with fd buffer");
    assert_eq!(bytes, 5);
    assert_eq!(fds, 0);
    assert_eq!(fd_buf, [-1; 3]);
}

#[cfg_attr(not(any(target_os="illumos", target_os="solaris")), test)]
fn stream_truncate_fds() {
    let (mut a, mut b) = UnixStream::pair().expect("create stream socket pair");

    // send some, receive without ancillary buffer
    a.send_fds(b"a", &[a.as_raw_fd()]).expect("send one fd");
    let bytes = b.read(&mut[0u8; 10]).expect("read without ancillary buffer");
    assert_eq!(bytes, 1);

    // try to receive fds afterwards (this tests the OS more than this crate)
    b.set_nonblocking(true).expect("enable nonblocking");
    let error = b.recv_fds(&mut[1], &mut[0; 2])
        .expect_err("won't receive fd later without any bytes waiting");
    assert_eq!(error.kind(), WouldBlock);
    // try to receive fds later when there is more data
    a.write(b"aa").expect("write normally - without ancillary");
    let (bytes, fds) = b.recv_fds(&mut[0u8; 10], &mut[0; 2]).expect("receive with capacity");
    assert_eq!((bytes, fds), (2, 0));

    // send some, receive with zero-length fd slice
    a.send_fds(b"aaa", &[a.as_raw_fd()]).expect("send one fd");
    let (bytes, fds) = b.recv_fds(&mut[0u8; 10], &mut[]).expect("receive with empty fd buffer");
    assert_eq!((bytes, fds), (3, 0));

    // try to receive what was truncated, now that we received with ancillary buffer the first time
    let error = b.recv_fds(&mut[1], &mut[0; 2])
        .expect_err("receive fd later without any bytes waiting");
    assert_eq!(error.kind(), WouldBlock);
    a.send_fds(b"aaaa", &[]).expect("send empty fd slice");
    let mut fd_buf = [-1; 4];
    let (bytes, fds) = b.recv_fds(&mut[0u8; 10], &mut fd_buf).expect("receive with capacity");
    assert_eq!((bytes, fds, fd_buf), (4, 0, [-1; 4]));

    // send four, receive two
    a.send_fds(b"aaaaa", &[a.as_raw_fd(), a.as_raw_fd(), b.as_raw_fd(), b.as_raw_fd()])
        .expect("send four fds");
    let mut fd_buf = [-1; 2];
    match b.recv_fds(&mut[0u8; 10], &mut fd_buf) {// receives to capacity or nothing
        Ok((5, 2)) => {
            println!("a={}, b={}, received={:?}", a.as_raw_fd(), b.as_raw_fd(), fd_buf);
            assert_ne!(fd_buf[0], -1);
            if fd_buf[0] != a.as_raw_fd()  &&  fd_buf[0] != b.as_raw_fd() {
                let _ = unsafe { UnixStream::from_raw_fd(fd_buf[0]) };
            }
            assert_ne!(fd_buf[1], -1);
            if fd_buf[1] != a.as_raw_fd()  &&  fd_buf[1] != b.as_raw_fd() {
                let _ = unsafe { UnixStream::from_raw_fd(fd_buf[1]) };
            }
        },
        Ok((5, 0)) => {
            assert_eq!(fd_buf, [-1; 2]);
            if cfg!(any(target_os="linux", target_os="android", target_vendor="apple")) {
                panic!("all FDs were dropped, which is unexpected for {}", OS);
            }
        }
        Ok((bytes, fds)) => {
            panic!("received {} bytes and {} fds but expected 5 bytes and 2 or 0 fds", bytes, fds);
        }
        Err(e) => panic!("receiving with too small ancillary buffer failed: {}", e),
    }
    if cfg!(any(target_os="linux", target_os="android")) {
        // try to receive what was truncated
        a.send_fds(b"aaaaaa", &[a.as_raw_fd()]).expect("send one more fd"); // fails on freebsd
        let mut fd_buf = [-1; 6];
        let (bytes, fds) = b.recv_fds(&mut[0u8; 10], &mut fd_buf).expect("receive with capacity");
        assert_eq!((bytes, fds), (6, 1));
        assert_ne!(fd_buf[0], -1);
        let _ = unsafe { UnixStream::from_raw_fd(fd_buf[0]) };
        assert_eq!(&fd_buf[1..], [-1; 5]);
    }

    // TODO test receiving what was sent in one go with two recvmsg()s without sending more between
    // TODO test not receiving all bytes either.
}

#[cfg_attr(not(any(target_os="illumos", target_os="solaris")), test)]
fn datagram_pass_one_fd() {
    let (a, b) = UnixDatagram::pair().expect("create datagram socket pair");
    a.send_fds(b"", &[a.as_raw_fd()]).expect("send one file descriptor");
    let mut fd_buf = [-1; 3];
    let (bytes, fds) = b.recv_fds(&mut[0u8; 10], &mut fd_buf)
        .expect("receive with ancillary buffer");
    assert_eq!(bytes, 0);
    assert_eq!(fds, 1);
    let mut received = unsafe { ManuallyDrop::new(UnixDatagram::from_raw_fd(fd_buf[0])) };
    received.send(b"got it").expect("send from received fd");
    let bytes = b.recv(&mut[0u8; 10]).expect("receive datagram sent from received fd");
    assert_eq!(bytes, 6);
    if received.as_raw_fd() != a.as_raw_fd() {
        unsafe { ManuallyDrop::drop(&mut received) };
    }
}

#[test]
fn datagram_pass_two_receive_one() {
    //! Tests somewhat that glibc's 64bit minimum payload length is handled
    let (a, b) = UnixDatagram::pair().expect("create datagram socket pair");
    a.send_fds(b"", &[a.as_raw_fd(), b.as_raw_fd()]).expect("send one file descriptor");
    let mut fd_buf = [-1];
    let (bytes, fds) = b.recv_fds(&mut[0u8; 10], &mut fd_buf)
        .expect("receive with ancillary buffer");
    assert_eq!(bytes, 0);
    assert_eq!(fds, 1);
    if fd_buf[0] != a.as_raw_fd() {
        let _ = unsafe { UnixDatagram::from_raw_fd(fd_buf[0]) };
    }
    b.send_fds(b"nothing", &[]).expect("send another datagram with no fds");
    let (bytes, fds) = a.recv_fds(&mut[0u8; 10], &mut fd_buf)
        .expect("receive with ancillary buffer");
    assert_eq!(bytes, "nothing".len());
    assert_eq!(fds, 0);
}

#[cfg_attr(not(any(target_os="illumos", target_os="solaris")), test)]
fn datagram_separate_payloads() {
    let (a, b) = UnixDatagram::pair().expect("create datagram socket pair");

    // send one with then one without
    a.send_fds(b"_", &[a.as_raw_fd()]).expect("send datagram with one fd");
    a.send(b"").expect("send a second datagram, wiithout fd");
    let mut fd_buf = [-1; 2];
    let (bytes, fds) = b.recv_fds(&mut[0u8; 1], &mut fd_buf).expect("receive fds");
    assert_eq!(bytes, 1);
    assert_eq!(fds, 1);
    assert_ne!(fd_buf[0], -1);
    if fd_buf[0] != a.as_raw_fd() {
        let _ = unsafe { UnixDatagram::from_raw_fd(fd_buf[0]) };
    }
    assert_eq!(fd_buf[1], -1);
    let (bytes, fds) = b.recv_fds(&mut[0u8; 1], &mut fd_buf).expect("receive fds");
    assert_eq!(bytes, 0);
    assert_eq!(fds, 0);

    // send twice
    a.send_fds(b"", &[a.as_raw_fd(), a.as_raw_fd()]).expect("send two fds");
    a.send_fds(b"", &[b.as_raw_fd(), b.as_raw_fd()]).expect("sent two fds again");
    for _ in 0..2 {
        let mut fd_buf = [-1; 3];
        let (bytes, fds) = b.recv_fds(&mut[0u8; 3], &mut fd_buf).expect("receive fds");
        assert_eq!(bytes, 0);
        assert_eq!(fds, 2);
        assert!(fd_buf[..2].iter().all(|&fd| fd != -1 ));
        assert_eq!(fd_buf[2], -1);
        if fd_buf[0] != a.as_raw_fd()  &&  fd_buf[0] != b.as_raw_fd() {
            let _ = unsafe { UnixStream::from_raw_fd(fd_buf[0]) };
            let _ = unsafe { UnixStream::from_raw_fd(fd_buf[1]) };
        }
    }
}

#[cfg_attr(not(any(target_os="illumos", target_os="solaris")), test)]
/// a just-to-be-absolutely-sure test
fn stream_fd_order() {
    let (mut a, mut b) = UnixStream::pair().expect("create stream socket pair");
    a.send_fds(b"2", &[a.as_raw_fd(), b.as_raw_fd()]).expect("send two fds");
    let mut fd_buf = [0; 2];
    let (bytes, fds) = b.recv_fds(&mut[0u8; 3], &mut fd_buf).expect("receive fds");
    assert_eq!(bytes, 1);
    assert_eq!(fds, 2);
    let mut received_a = unsafe { ManuallyDrop::new(UnixStream::from_raw_fd(fd_buf[0])) };
    let mut received_b = unsafe { ManuallyDrop::new(UnixStream::from_raw_fd(fd_buf[1])) };

    let _ = a.set_nonblocking(true);
    let _ = b.set_nonblocking(true);
    received_a.write(b"I'm a").expect("write via transferred fd");
    b.read(&mut[0u8; 10]).expect("read bytes sent from received fd[0] (`a`)");
    received_b.write(b"I'm b").expect("write via transferred fd");
    a.read(&mut[0u8; 10]).expect("read bytes sent from received fd[1] (`b`)");
    if received_a.as_raw_fd() != a.as_raw_fd() {// DragonFly BSD is VERY lazy
        unsafe { ManuallyDrop::drop(&mut received_a) };
    }
    if received_b.as_raw_fd() != b.as_raw_fd() {
        unsafe { ManuallyDrop::drop(&mut received_b) };
    }
}

#[cfg_attr(not(any(target_os="illumos", target_os="solaris")), test)]
fn closed_before_received() {
    let (a, b) = UnixDatagram::pair().expect("create datagram socket pair");
    a.send_fds(&[], &[a.as_raw_fd()]).expect("send fd");
    let _ = a; // drop a
    let mut fd_buf = [-1];
    let (_, fds) = b.recv_fds(&mut[], &mut fd_buf).expect("receive fd that is already closed");
    assert_eq!(fds, 1);
    assert_ne!(fd_buf[0], -1);
    let a = unsafe { UnixDatagram::from_raw_fd(fd_buf[0]) };
    a.send(b"still alive").expect("send from fd closed before received");
    b.recv(&mut[0u8; 16]).expect("receive what was sent from sent fd");
}

#[cfg_attr(any(target_os="illumos", target_os="solaris"), test)]
fn errors_on_solarish() {
    let (a, b) = UnixDatagram::pair().expect("create datagram socket pair");
    assert_eq!(a.send_fds(b"0", &[]).expect("send empty fd slice"), (1, 0));
    assert!(format!("{}", err).contains("available"));
    let err = a.send_fds(b"1", &[a.as_raw_fd()]).expect_err("send fd");
    assert!(format!("{}", err).contains("available"));

    b.set_nonblocking(true).expect("make nonblocking");
    let err = b.recv_fds(&mut[0; 16], &mut[])
        .expect_err("receive with empty fd buffer");
    assert!(format!("{}", err).contains("available"));
    let err = b.recv_fds(&mut[0; 16], &mut[-1; 4])
        .expect_err("receive with fd capacity");
    assert!(format!("{}", err).contains("available"));
}
