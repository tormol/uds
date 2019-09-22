extern crate ud3;

use std::os::unix::net::{SocketAddr, UnixStream, UnixListener, UnixDatagram};
use std::io::{self, ErrorKind};

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
    // TODO test peer_addr()
}
