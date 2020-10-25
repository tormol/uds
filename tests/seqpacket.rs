#![cfg(not(target_vendor="apple"))]

extern crate uds;

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
    assert_eq!(b.recv(&mut[0; 20]).unwrap(), (5, false));
    a.send(b"hello").unwrap();
    let mut buf = [0; 3];
    assert_eq!(b.recv(&mut buf).unwrap(), (3, true));
    assert_eq!(b.recv(&mut buf).unwrap_err().kind(), WouldBlock);
    assert_eq!(&buf[..3], b"hel");
}

#[cfg(not(any(target_os="illumos", target_os="solaris")))]
#[test]
fn zero_length_packet_sort_of_works() {
    let (a, b) = NonblockingUnixSeqpacketConn::pair().unwrap();
    assert_eq!(a.send(&[]).expect("send zero-length packet"), 0);
    assert_eq!(b.recv(&mut[0u8; 8]).expect("receive zero-length packet"), (0, false));
    a.send(&[]).unwrap();
    // Only checks length because FreeBSD thinks it gets truncated
    assert_eq!(b.recv(&mut[]).expect("receive zero-length packet with empty buffer").0, 0);
    a.send(&[]).unwrap();
    a.send(&[]).unwrap();
    assert_eq!(b.recv(&mut[0u8; 8]).unwrap(), (0, false));
    assert_eq!(b.recv(&mut[0u8; 8]).expect("empty packets are not merged"), (0, false));
    a.send(&[]).unwrap();
    drop(a);
    assert_eq!(b.recv(&mut[0u8; 8]).expect("receive zero-length packet"), (0, false));
    assert_eq!(b.recv(&mut[0u8; 8]).expect("receive end-of-connection packet"), (0, false));
}

#[test]
fn no_sigpipe() {
    let (a, _) = UnixSeqpacketConn::pair().expect("create seqpacket socket pair");
    assert_eq!(a.send(b"Hello?").unwrap_err().kind(), BrokenPipe);
    assert_eq!(a.send_vectored(&[IoSlice::new(b"Anyone there?")]).unwrap_err().kind(), BrokenPipe);
    assert_eq!(a.send_fds(b"HELOOO??", &[a.as_raw_fd()]).unwrap_err().kind(), BrokenPipe);

    let (a, _) = NonblockingUnixSeqpacketConn::pair().expect("create nonblocking seqpacket pair");
    assert_eq!(a.send(b"Hello?").unwrap_err().kind(), BrokenPipe);
    assert_eq!(a.send_vectored(&[IoSlice::new(b"Anyone there?")]).unwrap_err().kind(), BrokenPipe);
    assert_eq!(a.send_fds(b"HELOOO??", &[a.as_raw_fd()]).unwrap_err().kind(), BrokenPipe);
}

#[test]
fn send_vectored() {
    let (a, b) = UnixSeqpacketConn::pair().expect("create seqpacket socket pair");

    a.send(b"undivided").unwrap();
    let mut array = [b'-'; 10];
    assert_eq!(b.recv_vectored(&mut[IoSliceMut::new(&mut array)]).unwrap(), (9, false));
    assert_eq!(&array, b"undivided-");

    a.send(b"ignore me").unwrap();
    a.send(b"ignore me").unwrap();
    assert_eq!(b.recv_vectored(&mut[]).unwrap(), (0, true));
    assert_eq!(b.recv_vectored(&mut[IoSliceMut::new(&mut[])]).unwrap(), (0, true));

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
fn recv_vectored() {
    let (a, b) = UnixSeqpacketConn::pair().expect("create seqpacket socket pair");

    assert_eq!(a.send_vectored(&[IoSlice::new(b"undivided")]).unwrap(), 9);
    let mut buf = [b'-'; 10];
    assert_eq!(b.recv(&mut buf).unwrap(), (9, false));
    assert_eq!(&buf, b"undivided-");

    assert_eq!(a.send_vectored(&[]).unwrap(), 0);
    assert_eq!(a.send_vectored(&[IoSlice::new(&[])]).unwrap(), 0);
    if cfg!(not(any(target_os="illumos", target_os="solaris"))) {
        assert_eq!(b.recv(&mut buf).unwrap(), (0, false));
        assert_eq!(b.recv(&mut buf).unwrap(), (0, false));
    }

    a.send_vectored(&[IoSlice::new(b"merge"), IoSlice::new(b" me")]).unwrap();
    assert_eq!(b.recv(&mut buf).unwrap(), (8, false));
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
    assert_eq!(b.recv(&mut buf).unwrap(), (buf.len(), true));
    assert_eq!(&buf, b"truncate m");

    let slices = [
        IoSlice::new(b""),
        IoSlice::new(b"to"),
        IoSlice::new(b"discard"),
    ];
    b.set_nonblocking(true).unwrap();
    assert_eq!(a.send_vectored(&slices).unwrap(), 9);
    assert_eq!(b.recv(&mut[0u8; 2]).unwrap(), (2, true));
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
        assert_eq!(sock_rx.recv(&mut [0u8; 3]).unwrap(), (0, false));
    }
    // Nonblocking
    {
        let (sock_tx, sock_rx) = NonblockingUnixSeqpacketConn::pair().unwrap();
        sock_tx.shutdown(Shutdown::Both).unwrap();
        assert!(sock_tx.send(&[b'h', b'i', b'0']).is_err());
        assert_eq!(sock_rx.recv(&mut [0u8; 3]).unwrap(), (0, false));
    }
}

#[test]
fn read_timeout() {
    let (conn, _other) = UnixSeqpacketConn::pair().expect("create seqpacket pair");
    let timeout = Duration::new(0, 200_000_000);
    assert_eq!(conn.read_timeout().expect("get default read timeout"), None);
    conn.set_read_timeout(Some(timeout)).expect("set read timeout to 200ms");
    assert_eq!(conn.read_timeout().expect("get read timeout"), Some(timeout));
    let before = Instant::now();
    let result = conn.recv(&mut[0]);
    let after = Instant::now();
    assert_eq!(result.expect_err("recv() timed out").kind(), WouldBlock);
    let elapsed = after - before;
    assert!(elapsed >= timeout, "elapsed: {:?}, timeout: {:?}", elapsed, timeout);
    assert!(elapsed < 2*timeout, "elapsed: {:?}, timeout: {:?}", elapsed, timeout);
}

#[test]
fn write_timeout() {
    let (conn, _other) = UnixSeqpacketConn::pair().expect("create seqpacket pair");
    let timeout = Duration::new(0, 150_000_000);
    assert_eq!(conn.write_timeout().expect("get default write timeout"), None);
    conn.set_write_timeout(Some(timeout)).expect("set write timeout to 200ms");
    assert_eq!(conn.write_timeout().expect("get write timeout"), Some(timeout));
    let elapsed = loop {
        let before = Instant::now();
        let result = conn.send(&[123; 456]);
        let after = Instant::now();
        if let Err(e) = result {
            assert_eq!(e.kind(), WouldBlock);
            break after - before;
        }
    };
    assert!(elapsed >= timeout, "elapsed: {:?}, timeout: {:?}", elapsed, timeout);
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
    listener.set_timeout(Some(timeout)).expect("set timeout to 200ms");
    assert_eq!(listener.timeout().expect("get timeout"), Some(timeout));
    let before = Instant::now();
    let result = listener.accept_unix_addr();
    let after = Instant::now();
    assert_eq!(result.expect_err("recv() timed out").kind(), WouldBlock);
    let elapsed = after - before;
    assert!(elapsed >= timeout, "elapsed: {:?}, timeout: {:?}", elapsed, timeout);
    assert!(elapsed < 2*timeout, "elapsed: {:?}, timeout: {:?}", elapsed, timeout);
}

#[cfg(feature="tokio")]
mod tokio {
    use std::io;
    use std::net::Shutdown;
    use tempfile::tempdir;
    use uds::tokio::{UnixSeqpacketConn, UnixSeqpacketListener};
    use tokio_02 as tokio;

    #[tokio::test]
    async fn test_listener_accept() {
        let tmp_dir = tempdir().unwrap();
        let sock_path = tmp_dir.path().join("listener.socket");
        let mut listener = UnixSeqpacketListener::bind(&sock_path).unwrap();

        let listener_handle = tokio::task::spawn(async move {
            for i in 1usize..=3 {
                let (mut socket, _) = listener.accept().await?;
                tokio::task::spawn(async move {
                    socket.send(&[b'h', b'i', b'0' + (i as u8)]).await.unwrap();
                });
            }
            Ok::<(), io::Error>(())
        });

        for i in 1usize..=3 {
            let mut socket = UnixSeqpacketConn::connect(&sock_path).await.unwrap();
            let mut buf = [0u8; 3];
            let read = socket.recv(&mut buf).await.unwrap();
            assert_eq!(read, 3);
            assert_eq!(&buf, &[b'h', b'i', b'0' + (i as u8)]);
        }

        assert!(listener_handle.await.is_ok());
    }

    #[tokio::test]
    async fn test_conn_pair() {
        let (mut sock_tx, mut sock_rx) = UnixSeqpacketConn::pair().unwrap();

        tokio::task::spawn(async move {
            sock_tx.send(&[b'h', b'i', b'0']).await.unwrap();
        });

        let mut buf = [0u8; 3];
        let read = sock_rx.recv(&mut buf).await.unwrap();
        assert_eq!(read, 3);
        assert_eq!(&buf, &[b'h', b'i', b'0']);
    }

    #[tokio::test]
    async fn test_shutdown() {
        let (mut sock_tx, mut sock_rx) = UnixSeqpacketConn::pair().unwrap();

        sock_tx.shutdown(Shutdown::Both).unwrap();
        assert!(sock_tx.send(&[b'h', b'i', b'0']).await.is_err());
        assert_eq!(sock_rx.recv(&mut [0u8; 3]).await.unwrap(), 0);
    }
}
