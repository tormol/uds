extern crate uds;

use std::os::unix::net::{UnixListener, UnixStream};
use std::io::ErrorKind::*;
use std::fs::remove_file;

use uds::{UnixSocketAddr, UnixSocketAddrRef, UnixListenerExt, UnixStreamExt};

#[test]
fn std_checks_family() {
    use std::net::{TcpListener, TcpStream};
    use std::os::unix::io::{AsRawFd, FromRawFd};
    use std::mem::ManuallyDrop;

    let ip_listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let port = ip_listener.local_addr().unwrap().port();
    let wrong = unsafe { ManuallyDrop::new(UnixListener::from_raw_fd(ip_listener.as_raw_fd())) };
    assert_eq!(wrong.local_addr().unwrap_err().kind(), InvalidInput);
    let _conn = TcpStream::connect(("127.0.0.1", port)).unwrap();
    assert_eq!(wrong.accept().unwrap_err().kind(), InvalidInput);
}

#[test]
fn unspecified() {
    let listener = UnixListener::bind_unix_addr(&UnixSocketAddr::unspecified())
        .expect("listen to uspecified (abstract) address");
    let listener_addr = listener.local_unix_addr().expect("get auto-bound address");
    assert!(listener_addr.is_abstract());
    match listener_addr.as_ref() {
        UnixSocketAddrRef::Abstract(name) => {
            if name.last() == Some(&b'\0') {
                panic!()
            }
        }
        _ => unreachable!()
    }
    let conn = UnixStream::connect_from_to_unix_addr(
        &UnixSocketAddr::unspecified(),
        &listener_addr
    ).expect(&format!("connect from unspecified (abstract) addr to autobound addr {:?}", listener_addr));
    assert!(conn.local_unix_addr().unwrap().is_abstract());
}

#[test]
fn empty_abstract() {
    let addr = UnixSocketAddr::from_abstract("").unwrap();
    assert!(addr.is_abstract());
    assert_eq!(addr.as_ref(), UnixSocketAddrRef::Abstract(b""));
}

#[test]
fn max_abstract_name() {
    let max = UnixSocketAddr::max_abstract_len();
    let max_addr = UnixSocketAddr::from_abstract(&vec![0; max])
        .expect("create abstract address with max length");
    assert_eq!(max_addr.as_ref(), UnixSocketAddrRef::Abstract(&vec![0; max]));
    let listener = UnixListener::bind_unix_addr(&max_addr)
        .expect("create socket with max abstract name length");
    assert_eq!(listener.local_unix_addr().expect("get local max length abstract addr"), max_addr);
    let conn = UnixStream::connect_to_unix_addr(&max_addr)
        .expect("connect to max length abstract addr");
    assert_eq!(conn.peer_unix_addr().expect("get local max length abstract addr"), max_addr);
}

#[test]
fn max_regular_path_addr() {
    let max_regular_len = UnixSocketAddr::max_path_len()-1;
    let max_regular_path = std::iter::repeat('R').take(max_regular_len).collect::<String>();
    let max_regular_addr = UnixSocketAddr::from_path(&max_regular_path)
        .expect("create path address with max regular length");
    assert_eq!(max_regular_addr.as_ref(), UnixSocketAddrRef::Path(max_regular_path.as_ref()));
    assert_eq!(&max_regular_addr, max_regular_path.as_bytes());

    let _ = remove_file(&max_regular_path);

    let listener = UnixListener::bind_unix_addr(&max_regular_addr)
        .expect("create socket with max regular path length");
    let addr_from_os = listener.local_unix_addr().expect("get local max regular length path addr");
    assert_eq!(addr_from_os.as_ref(), UnixSocketAddrRef::Path(max_regular_path.as_ref()));
    assert_eq!(addr_from_os, max_regular_addr);
    assert_eq!(&addr_from_os, max_regular_path.as_bytes());

    let std_addr = listener.local_addr().expect("std get local max regular length path");
    assert_eq!(std_addr.as_pathname(), Some(max_regular_path.as_ref()));
    let conn = UnixStream::connect(&max_regular_path)
        .expect("std connect to max regular length path");
    assert_eq!(
        conn.peer_unix_addr().expect("get local max regular length path addr"),
        max_regular_addr
    );

    remove_file(&max_regular_path).expect("delete socket file");
}

#[test]
fn max_path_addr() {
    let max_len = UnixSocketAddr::max_path_len();
    let max_path = std::iter::repeat('L').take(max_len).collect::<String>();
    let max_addr = UnixSocketAddr::from_path(&max_path)
        .expect("create path address with max length");
    assert_eq!(max_addr.as_ref(), UnixSocketAddrRef::Path(max_path.as_ref()));
    assert_eq!(&max_addr, max_path.as_bytes());

    let _ = remove_file(&max_path);

    let listener = UnixListener::bind_unix_addr(&max_addr)
        .expect("create socket with max length path addr");
    let addr_from_os = listener.local_unix_addr().expect("get local max length path addr");
    assert_eq!(max_addr.as_ref(), UnixSocketAddrRef::Path(max_path.as_ref()));
    assert_eq!(addr_from_os, max_addr);
    assert_eq!(&addr_from_os, max_path.as_bytes());

    let std_addr = listener.local_addr().expect("std get local max length path");
    assert_eq!(std_addr.as_pathname(), Some(max_path.as_ref()));
    // connecting to max length addr isn't supported though!

    remove_file(&max_path).expect("delete socket file");
}

#[test]
fn too_long_abstract_name() {
    let too_long = UnixSocketAddr::max_abstract_len()+1;
    assert_eq!(
        UnixSocketAddr::from_abstract(&vec![b'L'; too_long])
            .expect_err("create too long abstract address")
            .kind(),
        InvalidInput
    );
    // TODO test passing oversized address to libc::bind()
}

#[test]
fn too_long_path() {
    let too_long = UnixSocketAddr::max_path_len()+1;
    let path = std::iter::repeat('L').take(too_long).collect::<String>();
    assert_eq!(
        UnixSocketAddr::from_path(&path).expect_err("create too long path address").kind(),
        InvalidInput
    );
    assert_eq!(
        UnixListener::bind(&path).expect_err("bind std socket too too long path").kind(),
        InvalidInput
    );
    // TODO test passing oversized address to libc::bind()
}
