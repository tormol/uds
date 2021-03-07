#![cfg(all(feature="tokio", not(target_vendor="apple")))]

use std::io::{self, ErrorKind::*};
use std::net::Shutdown;

use tokio_02 as tokio;

use uds::tokio::{UnixSeqpacketConn, UnixSeqpacketListener};
use uds::UnixSocketAddr;

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
