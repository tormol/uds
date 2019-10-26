extern crate uds;

use std::io::{ErrorKind, Read, Write};
use std::os::unix::io::{AsRawFd, FromRawFd};
use std::os::unix::net::{UnixDatagram, UnixStream};

use uds::{UnixDatagramExt, UnixStreamExt};

#[test]
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

#[test]
fn datagram_truncate_fds() {
    let (a, b) = UnixDatagram::pair().expect("create datagram socket pair");

    // send some, receive without ancillary buffer
    a.send_fds(b"a", &[a.as_raw_fd()]).expect("send one fd");
    let bytes = b.recv(&mut[0u8; 10]).expect("receive normally - without ancillary buffer");
    assert_eq!(bytes, 1);

    // send some, receive with zero-length fd slice
    a.send_fds(b"aa", &[a.as_raw_fd()]).expect("send one fd");
    let (bytes, fds) = b.recv_fds(&mut[0u8; 10], &mut[]).expect("receive with empty fd buffer");
    assert_eq!(bytes, 2);
    assert_eq!(fds, 0);

    // send four, receive two
    a.send_fds(b"aaa", &[a.as_raw_fd(), a.as_raw_fd(), b.as_raw_fd(), b.as_raw_fd()])
        .expect("send four fds");
    let mut fd_buf = [-1; 2];
    let (bytes, fds) = b.recv_fds(&mut[0u8; 10], &mut fd_buf)
        .expect("receive with smaller fd buffer");
    assert_eq!(bytes, 3);
    assert_eq!(fds, 2);
    assert_ne!(fd_buf[0], -1);
    let _ = unsafe { UnixDatagram::from_raw_fd(fd_buf[0]) };
    assert_ne!(fd_buf[1], -1);
    let _ = unsafe { UnixDatagram::from_raw_fd(fd_buf[1]) };
}

#[test]
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

#[test]
fn stream_truncate_fds() {
    let (mut a, mut b) = UnixStream::pair().expect("create stream socket pair");

    // send some, receive without ancillary buffer
    a.send_fds(b"a", &[a.as_raw_fd()]).expect("send one fd");
    let bytes = b.read(&mut[0u8; 10]).expect("read without ancillary buffer");
    assert_eq!(bytes, 1);

    // try to receive fds afterwards (this tests the OS more than this crate)
    b.set_nonblocking(true).expect("enable nonblocking");
    let error = b.recv_fds(&mut[], &mut[0; 2])
        .expect_err("receive fd later without any bytes waiting");
    assert_eq!(error.kind(), ErrorKind::WouldBlock);
    // try to receive fds later when there is more data
    a.write(b"aa").expect("write normally - without ancillary");
    let (bytes, fds) = b.recv_fds(&mut[0u8; 10], &mut[0; 2]).expect("receive with capacity");
    assert_eq!(bytes, 2);
    assert_eq!(fds, 0);

    // send some, receive with zero-length fd slice
    a.send_fds(b"aaa", &[a.as_raw_fd()]).expect("send one fd");
    let (bytes, fds) = b.recv_fds(&mut[0u8; 10], &mut[]).expect("receive with empty fd buffer");
    assert_eq!(bytes, 3);
    assert_eq!(fds, 0);

    // try to receive what was truncated, now that we received with ancillary buffer the first time
    let error = b.recv_fds(&mut[], &mut[0; 2])
        .expect_err("receive fd later without any bytes waiting");
    assert_eq!(error.kind(), ErrorKind::WouldBlock);
    a.send_fds(b"aaaa", &[]).expect("send empty fd slice");
    let mut fd_buf = [-1; 4];
    let (bytes, fds) = b.recv_fds(&mut[0u8; 10], &mut fd_buf).expect("receive with capacity");
    assert_eq!(bytes, 4);
    assert_eq!(fds, 0);
    assert_eq!(fd_buf, [-1; 4]);

    // send four, receive two
    a.send_fds(b"aaaaa", &[a.as_raw_fd(), a.as_raw_fd(), b.as_raw_fd(), b.as_raw_fd()])
        .expect("send four fds");
    let mut fd_buf = [-1; 2];
    let (bytes, fds) = b.recv_fds(&mut[0u8; 10], &mut fd_buf)
        .expect("receive with smaller fd buffer");
    assert_eq!(bytes, 5);
    assert_eq!(fds, 2);
    assert_ne!(fd_buf[0], -1);
    let _ = unsafe { UnixStream::from_raw_fd(fd_buf[0]) };
    assert_ne!(fd_buf[1], -1);
    let _ = unsafe { UnixStream::from_raw_fd(fd_buf[1]) };

    // try to receive what was truncated
    a.send_fds(b"aaaaaa", &[a.as_raw_fd()]).expect("send one more fd");
    let mut fd_buf = [-1; 4];
    let (bytes, fds) = b.recv_fds(&mut[0u8; 10], &mut fd_buf).expect("receive with capacity");
    assert_eq!(bytes, 6);
    assert_eq!(fds, 1);
    assert_ne!(fd_buf[0], -1);
    let _ = unsafe { UnixStream::from_raw_fd(fd_buf[0]) };
    assert_eq!(&fd_buf[1..], [-1; 3]);
}

#[test]
fn datagram_pass_one_fd() {
    let (a, b) = UnixDatagram::pair().expect("create datagram socket pair");
    a.send_fds(b"", &[a.as_raw_fd()]).expect("send one file descriptor");
    let mut fd_buf = [-1; 3];
    let (bytes, fds) = b.recv_fds(&mut[0u8; 10], &mut fd_buf)
        .expect("receive with ancillary buffer");
    assert_eq!(bytes, 0);
    assert_eq!(fds, 1);
    let received = unsafe { UnixDatagram::from_raw_fd(fd_buf[0]) };
    received.send(b"got it").expect("send from received fd");
    let bytes = b.recv(&mut[0u8; 10]).expect("receive datagram sent from received fd");
    assert_eq!(bytes, 6);
}

#[test]
fn datagram_pass_two_receive_one() {
    //! Tests that glibc's 64bit payload length 
    let (a, b) = UnixDatagram::pair().expect("create datagram socket pair");
    a.send_fds(b"", &[a.as_raw_fd(), b.as_raw_fd()]).expect("send one file descriptor");
    let mut fd_buf = [-1];
    let (bytes, fds) = b.recv_fds(&mut[0u8; 10], &mut fd_buf)
        .expect("receive with ancillary buffer");
    assert_eq!(bytes, 0);
    assert_eq!(fds, 1);
    let _ = unsafe { UnixDatagram::from_raw_fd(fd_buf[0]) };
    b.send_fds(b"nothing", &[]).expect("send another datagram with no fds");
    let (bytes, fds) = a.recv_fds(&mut[0u8; 10], &mut fd_buf)
        .expect("receive with ancillary buffer");
    assert_eq!(bytes, "nothing".len());
    assert_eq!(fds, 0);
}

#[test]
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
    let _ = unsafe { UnixDatagram::from_raw_fd(fd_buf[0]) };
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
        unsafe { UnixStream::from_raw_fd(fd_buf[0]) };
        unsafe { UnixStream::from_raw_fd(fd_buf[1]) };
    }
}

#[test]
fn stream_ancillary_payloads_not_merged() {
    let (mut a, b) = UnixStream::pair().expect("create stream socket pair");

    // send some then nothing
    a.send_fds(b"1", &[a.as_raw_fd()]).expect("send one fd");
    a.write(b"0").expect("write more bytes but no fds");
    let mut fd_buf = [-1; 6];
    let (bytes, fds) = b.recv_fds(&mut[0u8; 20], &mut fd_buf).expect("receive fds");
    assert_eq!(bytes, 1);
    assert_eq!(fds, 1);
    assert_ne!(fd_buf[0], -1);
    let _ = unsafe { UnixDatagram::from_raw_fd(fd_buf[0]) };
    let mut fd_buf = [-1; 6];
    let (bytes, fds) = b.recv_fds(&mut[0u8; 20], &mut fd_buf)
        .expect("receive with ancillary capacity");
    assert_eq!(bytes, 1);
    assert_eq!(fds, 0);
    assert_eq!(fd_buf[0], -1);

    // send twice
    a.send_fds(b"2", &[a.as_raw_fd(), a.as_raw_fd()]).expect("send two fds");
    a.send_fds(b"3", &[b.as_raw_fd(), b.as_raw_fd(), b.as_raw_fd()])
        .expect("write three more fds");
    let mut fd_buf = [-1; 6];
    let (bytes, fds) = b.recv_fds(&mut[0u8; 3], &mut fd_buf).expect("receive fds");
    assert_eq!(bytes, 1);
    assert_eq!(fds, 2);
    assert_eq!(fd_buf[2], -1);
    let _ = unsafe { UnixStream::from_raw_fd(fd_buf[0]) };
    let _ = unsafe { UnixStream::from_raw_fd(fd_buf[1]) };
    let mut fd_buf = [-1; 6];
    let (bytes, fds) = b.recv_fds(&mut[0u8; 3], &mut fd_buf).expect("receive fds");
    assert_eq!(bytes, 1);
    assert_eq!(fds, 3);
    assert_eq!(fd_buf[3], -1);
    let _ = unsafe { UnixStream::from_raw_fd(fd_buf[0]) };
    let _ = unsafe { UnixStream::from_raw_fd(fd_buf[1]) };
    let _ = unsafe { UnixStream::from_raw_fd(fd_buf[2]) };
}

#[test] /// a just-to-be-absolutely-sure test
fn stream_fd_order() {
    let (mut a, mut b) = UnixStream::pair().expect("create stream socket pair");
    a.send_fds(b"2", &[a.as_raw_fd(), b.as_raw_fd()]).expect("send two fds");
    let mut fd_buf = [0; 2];
    let (bytes, fds) = b.recv_fds(&mut[0u8; 3], &mut fd_buf).expect("receive fds");
    assert_eq!(bytes, 1);
    assert_eq!(fds, 2);
    let mut received_a = unsafe { UnixStream::from_raw_fd(fd_buf[0]) };
    let mut received_b = unsafe { UnixStream::from_raw_fd(fd_buf[1]) };

    let _ = a.set_nonblocking(true);
    let _ = b.set_nonblocking(true);
    received_a.write(b"I'm a").expect("write via transferred fd");
    b.read(&mut[0u8; 10]).expect("read bytes sent from received fd[0] (`a`)");
    received_b.write(b"I'm b").expect("write via transferred fd");
    a.read(&mut[0u8; 10]).expect("read bytes sent from received fd[1] (`b`)");
}

#[test]
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
