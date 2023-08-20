#![cfg(feature="tokio")]
use std::fs;

use uds::tokio::{UnixStreamExt, UnixListenerExt, UnixDatagramExt};
use uds::UnixSocketAddr;

use std::io::ErrorKind::*;
use std::path::Path;

extern crate tokio;
use tokio::net::{UnixStream, UnixListener, UnixDatagram};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test]
async fn stream_is_nonblocking() {
    let stream_name = "tokio_stream_is_nonblocking_stream.sock";
    let listener_name = "tokio_stream_is_nonblocking_listener.sock";
    let _ = fs::remove_file(stream_name);
    let _ = fs::remove_file(listener_name);
    let stream_addr = UnixSocketAddr::new(stream_name).unwrap();
    let listener_addr = UnixSocketAddr::new(listener_name).unwrap();
    let listener = UnixListener::bind(listener_name).expect("listen");
    let mut stream = UnixStream::connect_from_to_unix_addr(&stream_addr, &listener_addr)
            .expect("connect");
    let (mut listener_side, addr) = listener.accept().await.expect("accept");
    if cfg!(not(target_os="openbsd")) {// .as_pathname() is buggy there
        assert_eq!(addr.as_pathname(), Some(Path::new(stream_name)));
    }

    let _ = fs::remove_file(stream_name);
    let _ = fs::remove_file(listener_name);

    assert_eq!(stream.try_read(&mut [0; 100]).expect_err("read before write").kind(), WouldBlock);
    let sender = tokio::task::spawn(async move {
        let mut buf = [0; 100];
        assert_eq!(stream.read(&mut buf).await.expect("async to work"), 11);
    });
    listener_side.write_all(b"hello tokio").await.expect("write");
    sender.await.unwrap()
}

#[cfg_attr(any(target_os="linux", target_os="android"), tokio::test)]
async fn abstract_stream() {
    let stream_name = "@tokio_abstract_stream";
    let listener_name = "@tokio_abstract_listener";
    let stream_addr = UnixSocketAddr::new(stream_name).unwrap();
    let listener_addr = UnixSocketAddr::new(listener_name).unwrap();
    let listener = UnixListener::bind_unix_addr(&listener_addr).expect("listen");
    assert_eq!(listener.local_unix_addr().unwrap(), listener_addr);
    let mut stream = UnixStream::connect_from_to_unix_addr(&stream_addr, &listener_addr)
            .expect("connect");
    assert_eq!(stream.local_unix_addr().unwrap(), stream_addr);
    assert_eq!(stream.peer_unix_addr().unwrap(), listener_addr);
    let (mut listener_side, addr) = listener.accept().await.expect("accept");
    assert!(addr.as_pathname().is_none());
    assert_eq!(listener_side.peer_unix_addr().unwrap(), stream_addr);
    stream.write_all(b"test").await.expect("write");
    assert_eq!(listener_side.read(&mut [0; 10]).await.expect("read"), 4);
}

#[tokio::test]
async fn datagram_unix_addr() {
    let a_name = "tokio_datagram_a.sock";
    let b_name = "tokio_datagram_b.sock";
    let _ = fs::remove_file(a_name);
    let _ = fs::remove_file(b_name);
    let a_addr = UnixSocketAddr::new(a_name).unwrap();
    let b_addr = UnixSocketAddr::new(b_name).unwrap();
    let a = UnixDatagram::unbound().unwrap();
    a.bind_to_unix_addr(&a_addr).expect("bind a");
    let b = UnixDatagram::bind(b_name).expect("bind b");
    a.connect_to_unix_addr(&b_addr).expect("connect a to b");
    b.connect(a_name).expect("connect b to a");
    if cfg!(not(target_os="openbsd")) {
        assert_eq!(a.local_addr().unwrap().as_pathname(), Some(Path::new(a_name)));
    }
    assert_eq!(b.local_unix_addr().unwrap(), b_addr);

    let _ = fs::remove_file(a_name);
    let _ = fs::remove_file(b_name);

    assert_eq!(a.send(b"hello").await.expect("send"), 5);
    assert_eq!(b.recv(&mut[0; 10]).await.expect("recv"), 5);
}

#[cfg_attr(any(target_os="linux", target_os="android"), tokio::test)]
async fn abstract_datagram() {
    let a_addr = UnixSocketAddr::new("@tokio a").unwrap();
    let b_addr = UnixSocketAddr::new("@tokio b").unwrap();
    let a = UnixDatagram::unbound().unwrap();
    let b = UnixDatagram::unbound().unwrap();
    a.bind_to_unix_addr(&a_addr).expect("bind a");
    b.bind_to_unix_addr(&b_addr).expect("bind b");
    a.connect_to_unix_addr(&b_addr).expect("connect a to b");
    b.connect_to_unix_addr(&a_addr).expect("connect b to a");
    a.send(b"test").await.expect("send");
    b.recv(&mut[0; 10]).await.expect("recv");
}

#[cfg_attr(any(target_os="linux", target_os="android"), tokio::test)]
async fn initial_pair_credentials() {
    let (a, b) = UnixDatagram::pair().unwrap();
    let me = a.initial_pair_credentials().expect("get peer credentials");
    assert_eq!(me, b.initial_pair_credentials().unwrap());
}
