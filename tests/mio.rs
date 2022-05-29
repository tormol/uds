#![cfg(any(all(feature="mio-uds", feature="mio"), feature="mio_07"))]

extern crate uds;
#[cfg(all(feature="mio-uds", feature="mio"))]
extern crate mio_uds;
#[cfg(all(feature="mio-uds", feature="mio"))]
extern crate mio;
#[cfg(feature="mio_07")]
extern crate mio_07;
#[cfg(feature = "mio_08")]
extern crate mio_08;

use std::fs::remove_file;
use std::{io::{Read, Write}, path::Path, time::Duration};
use uds::{UnixSocketAddr, UnixSocketAddrRef, UnixStreamExt, UnixListenerExt};

#[cfg(all(feature="mio-uds", feature="mio"))]
#[test]
fn mio_uds_stream() {
    use mio_uds::{UnixListener, UnixStream};
    use mio::{Poll, Events, Ready, PollOpt, Token};

    let listener_path = "mio-uds listener.ssock";
    let _ = remove_file(listener_path);
    let listener_addr = UnixSocketAddr::new(listener_path).unwrap();
    let listener = UnixListener::bind_unix_addr(&listener_addr)
        .expect("create listener");

    let mut stream = UnixStream::connect_to_unix_addr(&listener_addr)
        .expect("connect");
    let (mut stream_served, addr) = listener.accept_unix_addr()
        .expect("accept connection");
    assert_eq!(addr.as_ref(), UnixSocketAddrRef::Unnamed);

    let poll = Poll::new().expect("create selector");
    poll.register(&listener, Token(0), Ready::readable(), PollOpt::edge())
        .expect("register listener");
    poll.register(&stream, Token(1), Ready::writable(), PollOpt::edge())
        .expect("register stream");
    poll.register(&stream_served, Token(2), Ready::all(), PollOpt::edge())
        .expect("register accepted stream");

    let mut events = Events::with_capacity(10);
    // drain writable events if any
    let _ = poll.poll(&mut events, Some(Duration::from_millis(1)));
    stream.write(b"read me whenever").expect("write to server");
    poll.poll(&mut events, Some(Duration::from_millis(1))).expect("poll after writing");
    assert_eq!(events.iter().next().expect("get write notification").token(), Token(2));
    assert_eq!(stream_served.read(&mut [0; 20]).expect("read from client"), 16);
    let _ = poll.poll(&mut events, Some(Duration::from_millis(1)));

    let stream_path = "mio-uds stream.sock";
    let _ = remove_file(stream_path);
    let _named_stream = UnixStream::connect_from_to_unix_addr(
        &UnixSocketAddr::new(stream_path).unwrap(),
        &listener_addr
    ).expect("connect from path");
    poll.poll(&mut events, Some(Duration::from_millis(1))).expect("poll after trying to connect");
    assert_eq!(events.iter().next().expect("get connect notification").token(), Token(0));

    let (_named_stream_served, addr) = listener.accept()
        .expect("call accept")
        .expect("has waiting connection");
    if cfg!(not(target_os="openbsd")) {// .as_pathname() is buggy there
        assert_eq!(addr.as_pathname(), Some(Path::new(stream_path)));
    }

    remove_file(listener_path).unwrap();
    remove_file(stream_path).unwrap();
}

macro_rules! mio_streams {
    ($version:tt) => {
        use $version::net::{UnixListener, UnixStream};
        use $version::{Poll, Events, Interest, Token};

        let listener_path = concat!(stringify!($version), "_listener.ssock");
        let _ = remove_file(listener_path);
        let listener_addr = UnixSocketAddr::new(listener_path).unwrap();
        let mut listener = UnixListener::bind_unix_addr(&listener_addr)
            .expect("create listener");

        let mut stream = UnixStream::connect_to_unix_addr(&listener_addr)
            .expect("connect");
        let (mut stream_served, addr) = listener.accept_unix_addr()
            .expect("accept connection");
        assert_eq!(addr.as_ref(), UnixSocketAddrRef::Unnamed);

        let mut poll = Poll::new().expect("create selector");
        poll.registry()
            .register(&mut listener, Token(0), Interest::READABLE)
            .expect("register listener");
        poll.registry()
            .register(&mut stream, Token(1), Interest::WRITABLE)
            .expect("register stream");
        poll.registry()
            .register(&mut stream_served, Token(2), Interest::READABLE | Interest::WRITABLE)
            .expect("register accepted stream");

        let mut events = Events::with_capacity(10);
        // drain writable events if any
        let _ = poll.poll(&mut events, Some(Duration::from_millis(1)));
        stream.write(b"read me whenever").expect("write to server");
        poll.poll(&mut events, Some(Duration::from_millis(1))).expect("poll after writing");
        assert_eq!(events.iter().next().expect("get write notification").token(), Token(2));
        assert_eq!(stream_served.read(&mut [0; 20]).expect("read from client"), 16);
        let _ = poll.poll(&mut events, Some(Duration::from_millis(1)));

        let stream_path = concat!(stringify!($version), "_stream.sock");
        let _ = remove_file(stream_path);
        let _named_stream = UnixStream::connect_from_to_unix_addr(
            &UnixSocketAddr::new(stream_path).unwrap(),
            &listener_addr
        ).expect("connect from path");
        poll.poll(&mut events, Some(Duration::from_millis(1))).expect("poll after trying to connect");
        assert_eq!(events.iter().next().expect("get connect notification").token(), Token(0));

        let (_named_stream_served, addr) = listener.accept().expect("accept bound connection");
        if cfg!(not(target_os="openbsd")) {// .as_pathname() is buggy there
            assert_eq!(addr.as_pathname(), Some(Path::new(stream_path)));
        }

        remove_file(listener_path).unwrap();
        remove_file(stream_path).unwrap();
    }
}

#[cfg(feature = "mio_07")]
#[test]
fn mio_07_stream() {
    mio_streams!(mio_07);
}

#[cfg(feature = "mio_08")]
#[test]
fn mio_08_stream() {
    mio_streams!(mio_08);
}
