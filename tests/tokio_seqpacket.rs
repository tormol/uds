#![cfg(all(feature="tokio", not(target_vendor="apple")))]

use std::io::{self, ErrorKind::*, IoSlice, IoSliceMut, Read, Write};
use std::net::Shutdown;
use std::os::unix::io::{AsRawFd, FromRawFd, IntoRawFd};
use std::os::unix::net::UnixStream;

use libc::{getpid, geteuid, getegid};

use tokio_02 as tokio;

use uds::tokio::{UnixSeqpacketConn, UnixSeqpacketListener};
use uds::{nonblocking, UnixSocketAddr};

#[tokio::test]
async fn test_listener_accept() {
    let sock_path = "listener.socket";
    let _ = std::fs::remove_file(sock_path);
    let mut listener = UnixSeqpacketListener::bind(sock_path).unwrap();

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
        let mut socket = UnixSeqpacketConn::connect(sock_path).await.unwrap();
        let mut buf = [0u8; 3];
        let read = socket.recv(&mut buf).await.unwrap();
        assert_eq!(read, 3);
        assert_eq!(&buf, &[b'h', b'i', b'0' + (i as u8)]);
    }

    assert!(listener_handle.await.is_ok());
    let _ = std::fs::remove_file(sock_path);
}

#[tokio::test]
async fn test_addr() {
    let listener_path = "tokio listener with addr.socket";
    let _ = std::fs::remove_file(listener_path);
    let listener_addr = UnixSocketAddr::new(&listener_path).unwrap();

    let client_path = "tokio named client.socket";
    let _ = std::fs::remove_file(client_path);
    let client_addr = UnixSocketAddr::new(&client_path).unwrap();

    let mut listener = UnixSeqpacketListener::bind_addr(&listener_addr).unwrap();
    assert_eq!(listener.local_addr().unwrap(), listener_addr);

    let listener_handle = tokio::task::spawn(async move {
        {
            let (mut socket, addr) = listener.accept().await?;
            assert!(addr.is_unnamed());
            socket.send(b"hello").await.unwrap();
        }
        {
            let (mut socket, addr) = listener.accept().await?;
            assert_eq!(addr, client_addr);
            let packet: String = format!("hello {}", addr);
            socket.send(packet.as_bytes()).await.unwrap();
        }
        Ok::<(), io::Error>(())
    });

    {
        let mut buf = [0; 100];
        let mut anon = UnixSeqpacketConn::connect_addr(&listener_addr).await.unwrap();
        assert!(anon.local_addr().unwrap().is_unnamed());
        assert_eq!(anon.peer_addr().unwrap(), listener_addr);
        assert_eq!(anon.recv(&mut buf).await.unwrap(), 5);
        assert_eq!(&buf[..5], b"hello");
    }

    {
        let mut buf = [0; 100];
        let mut named = UnixSeqpacketConn::connect_from_addr(&client_addr, &listener_addr)
            .await
            .unwrap();
        assert_eq!(named.local_addr().unwrap(), client_addr);
        assert!(named.recv(&mut buf).await.unwrap() > 11);
        assert_eq!(&buf[..11], b"hello tokio");
    }

    assert!(listener_handle.await.is_ok());
    let _ = std::fs::remove_file(listener_path);
    let _ = std::fs::remove_file(client_path);
}

#[tokio::test]
async fn test_conn_pair() {
    let (mut sock_tx, mut sock_rx) = UnixSeqpacketConn::pair()
        .expect("create tokio seqpacket pair");

    tokio::task::spawn(async move {
        sock_tx.send(&[b'h', b'i', b'0']).await.expect("send");
    });

    let mut buf = [0u8; 3];
    let read = sock_rx.recv(&mut buf).await.expect("receive");
    assert_eq!(read, 3);
    assert_eq!(&buf, &[b'h', b'i', b'0']);
}

#[tokio::test]
async fn test_vectored() {
    let (mut a, mut b) = UnixSeqpacketConn::pair()
        .expect("create tokio seqpacket pair");

    tokio::task::spawn(async move {
        a.send_vectored(&[
            IoSlice::new(b"hi"),
            IoSlice::new(b"there"),
        ]).await.expect("send vectors");
    });

    let mut bufs = [[0; 3]; 3];
    let mut slices = bufs.iter_mut()
        .map(|array| IoSliceMut::new(array) )
        .collect::<Vec<IoSliceMut>>();
    let received = b.recv_vectored(&mut slices[..])
        .await
        .expect("receive into vectors");
    assert_eq!(received, 7);
    assert_eq!(bufs[0], *b"hit");
    assert_eq!(bufs[1], *b"her");
    assert_eq!(bufs[2], *b"e\0\0");
}

#[tokio::test]
async fn test_peek() {
    let (mut a, mut b) = UnixSeqpacketConn::pair()
        .expect("create tokio seqpacket pair");

    tokio::task::spawn(async move {a.send(b"send one").await.expect("send"); });

    let mut buf = [0; 10];
    let received = b.peek(&mut buf).await.expect("peek");
    assert_eq!(received, 8);
    assert_eq!(&buf, b"send one\0\0");
    let (front, back) = buf[2..].split_at_mut(4);
    let received = b.peek_vectored(&mut[
        IoSliceMut::new(front),
        IoSliceMut::new(back),
    ]).await.expect("peek with vectors");
    assert_eq!(received, 8);
    assert_eq!(&buf, b"sesend one");
}

#[cfg_attr(not(any(target_os="illumos", target_os="solaris")), tokio::test)]
#[cfg_attr(any(target_os="illumos", target_os="solaris"), allow(unused))]
async fn test_fd_passing() {
    let (mut a, mut b) = UnixSeqpacketConn::pair()
        .expect("create tokio seqpacket pair");
    let (mut to_pass, mut to_test) = UnixStream::pair()
        .expect("create blocking stream pair");

    tokio::task::spawn(async move {
        a.send_fds(b"a stream", &[to_pass.as_raw_fd()]).await.expect("send fd");
        to_pass.write(b"once").expect("write");
    });

    let mut byte_buf = [0; 8];
    let mut fd_buf = [-1; 2];
    let (bytes, truncated, fds) = b.recv_fds(&mut byte_buf, &mut fd_buf)
        .await
        .expect("receive fd");
    assert_eq!(bytes, 8);
    assert_eq!(byte_buf, *b"a stream");
    assert_eq!(truncated, false);
    assert_eq!(fds, 1);
    assert_ne!(fd_buf[0], -1);
    assert_eq!(fd_buf[1], -1);

    let mut received = unsafe { UnixStream::from_raw_fd(fd_buf[0]) };
    received.write(b" and again").expect("write on received fd");
    let bytes = to_test.read(&mut byte_buf).expect("read stream");
    assert_eq!(bytes, 8);
    assert_eq!(byte_buf, *b"once and");
}

#[tokio::test]
async fn test_shutdown() {
    let (mut sock_tx, mut sock_rx) = UnixSeqpacketConn::pair().unwrap();

    sock_tx.shutdown(Shutdown::Both).unwrap();
    assert!(sock_tx.send(&[b'h', b'i', b'0']).await.is_err());
    assert_eq!(sock_rx.recv(&mut [0u8; 3]).await.unwrap(), 0);
}

#[tokio::test]
async fn test_peer_credentials() {
    let (a, _b) = UnixSeqpacketConn::pair().expect("create tokio seqpacket pair");
    match a.initial_peer_credentials() {
        Ok(creds) => {
            if let Some(pid) = creds.pid() {
                assert_eq!(pid.get(), unsafe { getpid() } as u32);
            }
            assert_eq!(creds.euid(), unsafe { geteuid() } as u32);
            if let Some(egid) = creds.egid() {
                assert_eq!(egid, unsafe { getegid() } as u32);
            }
        }
        Err(e) => assert_ne!(e.kind(), WouldBlock)
    }
}

#[tokio::test]
async fn test_peer_selinux_context() {
    let (a, _b) = UnixSeqpacketConn::pair().expect("create tokio seqpacket pair");
    let mut buf = [0u8; 1024];
    match a.initial_peer_selinux_context(&mut buf) {
        Ok(len) => {
            assert_ne!(len, 0, "context is not an empty string");
            assert!(len <= buf.len(), "length is within bounds");
        }
        Err(e) => {
            assert_ne!(e.kind(), WouldBlock);
            // fails on Linux on Cirrus, probably as a result of running inside a docker container
        }
    }
}

#[tokio::test]
async fn test_conn_from_raw_fd() {
    let (a_nonblocking, b_nonblocking) = nonblocking::UnixSeqpacketConn::pair()
        .expect("create nonblocking seqpacket pair");

    let a_fd = a_nonblocking.as_raw_fd();
    let mut a = unsafe {
        UnixSeqpacketConn::from_raw_fd(a_nonblocking.into_raw_fd())
            .expect("create from raw fd")
    };
    assert_eq!(a.as_raw_fd(), a_fd);

    a.send(b"I'm registered").await.expect("send from constructed");
    let mut buf = [0; 24];
    let (len, _) = b_nonblocking.recv(&mut buf).expect("receive on un-registered");
    assert_eq!(len, 14);
}

#[tokio::test]
async fn test_conn_into_raw_fd() {
    let (a, mut b) = UnixSeqpacketConn::pair()
        .expect("create tokio seqpacket pair");

    let a_nonblocking = unsafe {
        let a_fd = a.as_raw_fd();
        assert_eq!(a.into_raw_fd(), a_fd);
        nonblocking::UnixSeqpacketConn::from_raw_fd(a_fd)
    };

    a_nonblocking.send(b"hi").expect("send from deregistered socket");
    let mut buf = [0; 10];
    assert_eq!(b.recv(&mut buf).await.expect("receive"), 2);
    assert_eq!(&buf[..2], b"hi");
}
