#![cfg(not(target_vendor="apple"))]

use std::io::ErrorKind::*;
use std::io::{IoSlice, IoSliceMut};
use std::net::Shutdown;
use std::os::unix::io::AsRawFd;
use std::time::{Duration, Instant};

use uds::nonblocking::UnixSeqpacketConn as NonblockingUnixSeqpacketConn;
use uds::{UnixSeqpacketConn, UnixSeqpacketListener};

#[test]
fn seqpacket_is_supported() {
    let path = "seqpacket exists.socket";
    let _ = std::fs::remove_file(path);
    let _listener = UnixSeqpacketListener::bind(path).unwrap();
    let _conn = UnixSeqpacketConn::connect(path).unwrap();
    let _ = std::fs::remove_file(path);
}

#[test]
fn truncated_packets_are_not_resumed() {
    let (a, b) = NonblockingUnixSeqpacketConn::pair().unwrap();
    a.send(b"hello").unwrap();
    assert_eq!(b.recv(&mut[0; 20]).unwrap(), 5);
    a.send(b"hello").unwrap();
    let mut buf = [0; 3];
    assert_eq!(b.recv(&mut buf).unwrap(), 3);
    assert_eq!(b.recv(&mut buf).unwrap_err().kind(), WouldBlock);
    assert_eq!(&buf[..3], b"hel");
}

#[cfg_attr(not(any(target_os="illumos", target_os="solaris")), test)]
#[cfg_attr(any(target_os="illumos", target_os="solaris"), allow(unused))]
fn zero_length_packet_sort_of_works() {
    let (a, b) = NonblockingUnixSeqpacketConn::pair().unwrap();
    assert_eq!(a.send(&[]).expect("send zero-length packet"), 0);
    assert_eq!(b.recv(&mut[0u8; 8]).expect("receive zero-length packet"), 0);
    a.send(&[]).unwrap();
    // Only checks length because FreeBSD thinks it gets truncated
    assert_eq!(b.recv(&mut[]).expect("receive zero-length packet with empty buffer"), 0);
    a.send(&[]).unwrap();
    a.send(&[]).unwrap();
    assert_eq!(b.recv(&mut[0u8; 8]).unwrap(), 0);
    assert_eq!(b.recv(&mut[0u8; 8]).expect("empty packets are not merged"), 0);
    a.send(&[]).unwrap();
    drop(a);
    assert_eq!(b.recv(&mut[0u8; 8]).expect("receive zero-length packet"), 0);
    assert_eq!(b.recv(&mut[0u8; 8]).expect("receive end-of-connection packet"), 0);
}

#[cfg_attr(not(any(target_os="illumos", target_os="solaris")), test)]
#[cfg_attr(any(target_os="illumos", target_os="solaris"), allow(unused))]
fn zero_length_vectored_sort_of_works() {
    let (a, b) = NonblockingUnixSeqpacketConn::pair().unwrap();
    let mut buf = [0; 25];

    assert_eq!(a.send_vectored(&[]).unwrap(), 0);
    assert_eq!(a.send_vectored(&[IoSlice::new(&[])]).unwrap(), 0);
    assert_eq!(b.recv(&mut buf).unwrap(), 0);
    assert_eq!(b.recv(&mut buf).unwrap(), 0);

    a.send(b"ignore me").unwrap();
    a.send(b"ignore me").unwrap();
    assert_eq!(b.recv_vectored(&mut[]).unwrap(), (0, true));
    assert_eq!(b.recv_vectored(&mut[IoSliceMut::new(&mut[])]).unwrap(), (0, true));
}

#[test]
fn no_sigpipe() {
    let (a, _) = UnixSeqpacketConn::pair().expect("create seqpacket socket pair");
    assert_eq!(a.send(b"Hello?").unwrap_err().kind(), BrokenPipe);
    assert_eq!(a.send_vectored(&[IoSlice::new(b"Anyone there?")]).unwrap_err().kind(), BrokenPipe);
    if cfg!(not(any(target_os="illumos", target_os="solaris"))) {
        assert_eq!(a.send_fds(b"HELOOO??", &[a.as_raw_fd()]).unwrap_err().kind(), BrokenPipe);
    }

    let (a, _) = NonblockingUnixSeqpacketConn::pair().expect("create nonblocking seqpacket pair");
    assert_eq!(a.send(b"Hello?").unwrap_err().kind(), BrokenPipe);
    assert_eq!(a.send_vectored(&[IoSlice::new(b"Anyone there?")]).unwrap_err().kind(), BrokenPipe);
    if cfg!(not(any(target_os="illumos", target_os="solaris"))) {
        assert_eq!(a.send_fds(b"HELOOO??", &[a.as_raw_fd()]).unwrap_err().kind(), BrokenPipe);
    }
}

#[test]
fn recv_vectored() {
    let (a, b) = UnixSeqpacketConn::pair().expect("create seqpacket socket pair");

    a.send(b"undivided").unwrap();
    let mut array = [b'-'; 10];
    assert_eq!(b.recv_vectored(&mut[IoSliceMut::new(&mut array)]).unwrap(), (9, false));
    assert_eq!(&array, b"undivided-");

    a.send(b"split me").unwrap();
    let (mut array_1, mut array_2) = ([4; 4], [4; 4]);
    let mut buffers = [IoSliceMut::new(&mut array_1), IoSliceMut::new(&mut array_2)];
    assert_eq!(b.recv_vectored(&mut buffers).unwrap(), (8, false));
    assert_eq!(&array_1, b"spli");
    assert_eq!(&array_2, b"t me");

    a.send(b"truncate me").unwrap();
    let mut buffers = [
        IoSliceMut::new(&mut[]),
        IoSliceMut::new(&mut array_1[..1]),
        IoSliceMut::new(&mut[]),
        IoSliceMut::new(&mut array_2),
    ];
    assert_eq!(b.recv_vectored(&mut buffers).unwrap(), (5, true));
    assert_eq!(&array_1[..1], b"t");
    assert_eq!(&array_2, b"runc");

    a.send(b"dont").unwrap();
    a.send(b"mix!").unwrap();
    let mut buffers = [IoSliceMut::new(&mut array_1), IoSliceMut::new(&mut array_2)];
    assert_eq!(b.recv_vectored(&mut buffers).unwrap(), (4, false));
    assert_eq!(&array_1, b"dont");
    assert_ne!(&array_1, b"mix!");
}

#[test]
fn send_vectored() {
    let (a, b) = UnixSeqpacketConn::pair().expect("create seqpacket socket pair");

    assert_eq!(a.send_vectored(&[IoSlice::new(b"undivided")]).unwrap(), 9);
    let mut buf = [b'-'; 10];
    assert_eq!(b.recv(&mut buf).unwrap(), 9);
    assert_eq!(&buf, b"undivided-");

    a.send_vectored(&[IoSlice::new(b"merge"), IoSlice::new(b" me")]).unwrap();
    assert_eq!(b.recv(&mut buf).unwrap(), 8);
    assert_eq!(&buf[..8], b"merge me");

    let slices = [
        IoSlice::new(b"tru"),
        IoSlice::new(b""),
        IoSlice::new(b"ncate"),
        IoSlice::new(b""),
        IoSlice::new(b""),
        IoSlice::new(b" me"),
        IoSlice::new(b""),
    ];
    assert_eq!(a.send_vectored(&slices).unwrap(), 11);
    assert_eq!(b.recv(&mut buf).unwrap(), buf.len());
    assert_eq!(&buf, b"truncate m");

    let slices = [
        IoSlice::new(b""),
        IoSlice::new(b"to"),
        IoSlice::new(b"discard"),
    ];
    b.set_nonblocking(true).unwrap();
    assert_eq!(a.send_vectored(&slices).unwrap(), 9);
    assert_eq!(b.recv(&mut[0u8; 2]).unwrap(), 2);
    assert_eq!(b.recv(&mut buf).unwrap_err().kind(), WouldBlock);
}

#[test]
fn vectored() {
    let (a, b) = NonblockingUnixSeqpacketConn::pair().expect("create nonblocking seqpacket pair");

    assert_eq!(a.send_vectored(&[IoSlice::new(b"undivided")]).unwrap(), 9);
    let mut buf = [b'-'; 10];
    assert_eq!(b.recv_vectored(&mut[IoSliceMut::new(&mut buf)]).unwrap(), (9, false));
    assert_eq!(&buf, b"undivided-");

    let slices = [
        IoSlice::new(b"re"),
        IoSlice::new(b""),
        IoSlice::new(b"shuffle "),
        IoSlice::new(b"me"),
        IoSlice::new(b"!"),
        IoSlice::new(b""),
    ];
    assert_eq!(a.send_vectored(&slices).unwrap(), 13);
    let (mut array_1, mut array_2) = ([9; 9], [3; 3]);
    let mut buffers = [IoSliceMut::new(&mut array_1), IoSliceMut::new(&mut array_2)];
    assert_eq!(b.recv_vectored(&mut buffers).unwrap(), (12, true));
    assert_eq!(&array_1, b"reshuffle");
    assert_eq!(&array_2, b" me");
    let mut buffers = [IoSliceMut::new(&mut array_1)];
    assert_eq!(b.recv_vectored(&mut buffers).unwrap_err().kind(), WouldBlock);
}

#[test]
fn shutdown() {
    // Blocking
    {
        let (sock_tx, sock_rx) = UnixSeqpacketConn::pair().unwrap();
        sock_tx.shutdown(Shutdown::Both).unwrap();
        assert!(sock_tx.send(&[b'h', b'i', b'0']).is_err());
        assert_eq!(sock_rx.recv(&mut [0u8; 3]).unwrap(), 0);
    }
    // Nonblocking
    {
        let (sock_tx, sock_rx) = NonblockingUnixSeqpacketConn::pair().unwrap();
        sock_tx.shutdown(Shutdown::Both).unwrap();
        assert!(sock_tx.send(&[b'h', b'i', b'0']).is_err());
        if cfg!(not(any(target_os="illumos", target_os="solaris"))) {
            // sometimes returns WouldBlock on illumos
            assert_eq!(sock_rx.recv(&mut [0u8; 3]).unwrap(), 0);
        }
    }
}

#[cfg_attr(not(any(target_os="illumos", target_os="solaris")), test)]
#[cfg_attr(any(target_os="illumos", target_os="solaris"), allow(unused))]
fn read_timeout() {
    let (conn, _other) = UnixSeqpacketConn::pair().expect("create seqpacket pair");
    let timeout = Duration::new(0, 200_000_000);
    assert_eq!(conn.read_timeout().expect("get default read timeout"), None);

    conn.set_read_timeout(Some(timeout)).expect("set read timeout to 200ms");
    let returned = conn.read_timeout()
        .expect("get read timeout")
        .expect("timeout was set");
    // OSes converts the set timeout to a number of internal ticks,
    // which means that one might not get back the exact duration.
    // Tnd the tick resolution varies from OS to OS and host to host:
    // * Linux on Travis returns a ttimeout several miliseconds too high.
    // * FreeBSD returns a duration one microsecond smaller than set.
    assert!(
        returned <= timeout + timeout / 25,
        "returned timeout {:?} exceeds the tolerance of {:?} + {:?}",
        returned, timeout, timeout / 25
    );
    assert!(
        returned >= timeout - timeout/100,
        "returned timeout {:?} is lower than the tolerance of {:?} - {:?}",
        returned, timeout, timeout / 100
    );

    let before = Instant::now();
    let result = conn.recv(&mut[0]);
    let after = Instant::now();
    assert_eq!(result.expect_err("recv() timed out").kind(), WouldBlock);
    let elapsed = after - before;
    assert!(elapsed > (timeout*4)/5, "elapsed: {:?}, timeout: {:?}", elapsed, timeout);
    assert!(elapsed < 2*timeout, "elapsed: {:?}, timeout: {:?}", elapsed, timeout);
}

#[cfg_attr(not(any(target_os="illumos", target_os="solaris")), test)]
#[cfg_attr(any(target_os="illumos", target_os="solaris"), allow(unused))]
fn write_timeout() {
    let (conn, _other) = UnixSeqpacketConn::pair().expect("create seqpacket pair");
    let timeout = Duration::new(0, 150_000_000);
    assert_eq!(conn.write_timeout().expect("get default write timeout"), None);

    conn.set_write_timeout(Some(timeout)).expect("set write timeout to 200ms");
    let returned = conn.write_timeout()
        .expect("get write timeout")
        .expect("timeout was set");
    assert!(
        returned <= timeout + timeout / 25,
        "returned timeout {:?} exceeds the tolerance of {:?} + {:?}",
        returned, timeout, timeout / 25
    );
    assert!(
        returned >= timeout - timeout/100,
        "returned timeout {:?} is lower than the tolerance of {:?} - {:?}",
        returned, timeout, timeout / 100
    );

    let elapsed = loop {
        let before = Instant::now();
        let result = conn.send(&[123; 456]);
        let after = Instant::now();
        if let Err(e) = result {
            assert_eq!(e.kind(), WouldBlock);
            break after - before;
        }
    };
    assert!(elapsed > (timeout*4)/5, "elapsed: {:?}, timeout: {:?}", elapsed, timeout);
    assert!(elapsed < 2*timeout, "elapsed: {:?}, timeout: {:?}", elapsed, timeout);
}

#[test]
fn accept_timeout() {
    let addr = "accept_timeout.sock";
    let timeout = Duration::new(0, 250_000_000);
    let _ = std::fs::remove_file(addr);
    let listener = UnixSeqpacketListener::bind(addr)
        .expect("create seqpacket listener");
    std::fs::remove_file(addr).expect("delete created socket file");

    assert_eq!(listener.timeout().expect("get default timeout"), None);
    listener.set_timeout(None).expect("disable timeout");

    if cfg!(any(target_os="linux", target_os="android")) {
        listener.set_timeout(Some(timeout)).expect("set timeout to 200ms");
        let returned = listener.timeout().expect("get timeout").expect("timeout was set");
        // Linux on Travis returns a ttimeout several miliseconds too high.
        assert!(returned - timeout < timeout / 25);

        let before = Instant::now();
        let result = listener.accept_unix_addr();
        let after = Instant::now();
        assert_eq!(result.expect_err("recv() timed out").kind(), WouldBlock);
        let elapsed = after - before;
        assert!(elapsed >= timeout, "elapsed: {:?}, timeout: {:?}", elapsed, timeout);
        assert!(elapsed < 2*timeout, "elapsed: {:?}, timeout: {:?}", elapsed, timeout);
    }
}
