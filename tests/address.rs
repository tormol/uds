extern crate uds;

use std::os::unix::net::{UnixListener, UnixStream};
use std::io::ErrorKind;

use uds::{UnixSocketAddr, UnixListenerExt, UnixStreamExt};

#[test]
fn std_checks_family() {
    use std::net::{TcpListener, TcpStream};
    use std::os::unix::io::{AsRawFd, FromRawFd};
    use std::mem::ManuallyDrop;

    let ip_listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let port = ip_listener.local_addr().unwrap().port();
    let wrong = unsafe { ManuallyDrop::new(UnixListener::from_raw_fd(ip_listener.as_raw_fd())) };
    assert_eq!(wrong.local_addr().unwrap_err().kind(), ErrorKind::InvalidInput);
    let _conn = TcpStream::connect(("127.0.0.1", port)).unwrap();
    assert_eq!(wrong.accept().unwrap_err().kind(), ErrorKind::InvalidInput);
}

#[test]
fn unnamed_not_unspecified() {
    UnixListener::bind_unix_addr(&UnixSocketAddr::new_unnamed())
        .expect_err("bind to and listen on unnamed address");

    UnixStream::connect_from_to_unix_addr(
        &UnixSocketAddr::new_unnamed(),
        &UnixSocketAddr::new("file").unwrap()
    ).expect_err("connect from unnamed addr");
}
