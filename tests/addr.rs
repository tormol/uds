extern crate uds;
extern crate libc;

use std::os::unix::net::{UnixListener, UnixStream, UnixDatagram};
use std::os::unix::io::AsRawFd;
use std::io::{self, ErrorKind::*};
use std::fs::remove_file;

use uds::{UnixSocketAddr, UnixSocketAddrRef};
use uds::{UnixListenerExt, UnixStreamExt};

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

#[cfg(any(target_os="linux", target_os="android"))]
#[test]
fn unspecified_creates_abstract() {
    let listener = UnixListener::bind_unix_addr(&UnixSocketAddr::new_unspecified())
        .expect("bind to unspecified (abstract) address");
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
        &UnixSocketAddr::new_unspecified(),
        &listener_addr
    ).expect(&format!("connect from unspecified (abstract) addr to autobound addr {:?}", listener_addr));
    assert!(conn.local_unix_addr().unwrap().is_abstract());
}

#[cfg(not(any(target_os="linux", target_os="android")))]
#[test]
fn cannot_bind_to_unspecified() {
    let bind_err = UnixListener::bind_unix_addr(&UnixSocketAddr::new_unspecified())
        .expect_err("bind to unspecified address when abstract addresses are not supported");
    assert_eq!(bind_err.kind(), InvalidInput);
}

#[test]
fn empty_abstract() {
    if cfg!(any(target_os="linux", target_os="android")) {
        let empty_addr = UnixSocketAddr::from_abstract("")
            .expect("create empty abstract address");
        assert!(empty_addr.is_abstract());
        assert_eq!(empty_addr.as_ref(), UnixSocketAddrRef::Abstract(b""));
        let listener = UnixListener::bind_unix_addr(&empty_addr)
            .expect("bind to empty abstract address");
        let retrieved_local_addr = listener.local_unix_addr()
            .expect("get local empty abstract addr");
        assert_eq!(retrieved_local_addr, empty_addr);
    } else {
        let empty_err = UnixSocketAddr::from_abstract("")
           .expect_err("create empty abstract address");
        assert_eq!(empty_err.kind(), AddrNotAvailable);
    }
}

#[cfg(any(target_os="linux", target_os="android"))]
#[test]
fn max_abstract_name() {
    let max = UnixSocketAddr::max_abstract_len();
    let max_addr = UnixSocketAddr::from_abstract(&vec![0; max])
        .expect("create abstract address with max length");
    assert_eq!(max_addr.as_ref(), UnixSocketAddrRef::Abstract(&vec![0; max]));

    let listener = UnixListener::bind_unix_addr(&max_addr)
        .expect("create socket with max abstract name length");
    let retrieved_local_addr = listener.local_unix_addr()
        .expect("get local max length abstract addr");
    assert_eq!(retrieved_local_addr, max_addr);

    let conn = UnixStream::connect_to_unix_addr(&max_addr)
        .expect("connect to max length abstract addr");
    let retrieved_peer_addr = conn.peer_unix_addr()
        .expect("get local max length abstract addr");
    assert_eq!(retrieved_peer_addr, max_addr);
}

#[cfg(not(any(target_os="linux", target_os="android")))]
#[test]
fn abstract_not_supported() {
    let err = UnixSocketAddr::from_abstract("whaaa")
        .expect_err("create \"normal\" abstract address");
    assert_eq!(err.kind(), AddrNotAvailable);
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
fn max_path_addr() {// std fails this!
    let max_len = UnixSocketAddr::max_path_len();
    let max_path = std::iter::repeat('L').take(max_len).collect::<String>();
    let max_addr = UnixSocketAddr::from_path(&max_path)
        .expect("create path address with max length");
    assert_eq!(max_addr.as_ref(), UnixSocketAddrRef::Path(max_path.as_ref()));
    assert_eq!(&max_addr, max_path.as_bytes());

    let _ = remove_file(&max_path);

    let listener = UnixListener::bind_unix_addr(&max_addr)
        .expect("create socket with max length path addr");
    let addr_from_os = listener.local_unix_addr()
        .expect("get local max length path addr");
    assert_eq!(addr_from_os, max_addr);
    assert_eq!(addr_from_os.as_ref(), UnixSocketAddrRef::Path(max_path.as_ref()));
    assert_eq!(&addr_from_os, max_path.as_bytes());

    remove_file(&max_path).expect("delete socket file");
}

#[test]
fn too_long_abstract_name() {
    let too_long = &vec![b'L'; UnixSocketAddr::max_abstract_len()+1];
    let err = UnixSocketAddr::from_abstract(&too_long)
        .expect_err("create too long abstract address");
    if cfg!(any(target_os="linux", target_os="android")) {
        assert_eq!(err.kind(), InvalidInput); // too long
    } else {
        assert_eq!(err.kind(), AddrNotAvailable); // not supported
    }
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
}


#[test]
fn os_doeest_support_longer_addrs() {
    #[repr(C)]
    struct LongAddr {
        sockaddr: libc::sockaddr_un,
        extra: [u8; 100],
    }
    impl std::ops::Deref for LongAddr {
        type Target = [u8];
        fn deref(&self) -> &[u8] {
            unsafe {
                let included = std::mem::size_of_val(&self.sockaddr.sun_path);
                let extra = std::mem::size_of_val(&self.extra);
                let path_ptr = &self.sockaddr.sun_path[0] as *const _ as *const u8;
                assert_eq!(std::mem::size_of_val(&self.sockaddr)+extra, std::mem::size_of::<Self>());
                assert_eq!(
                    path_ptr as usize - self as *const Self as usize,
                    std::mem::size_of::<Self>() - included - extra
                );
                std::slice::from_raw_parts(path_ptr, included+extra)
            }
        }
    }
    fn new_longaddr(fill: u8,  extra_len: usize) -> (LongAddr, libc::socklen_t) {
        let mut addr = unsafe { std::mem::zeroed::<LongAddr>() };
        addr.sockaddr.sun_family = libc::AF_UNIX as libc::sa_family_t;
        unsafe {
            let included = std::mem::size_of_val(&addr.sockaddr.sun_path);
            let len = included - 1 + extra_len;
            let extra = std::mem::size_of_val(&addr.extra);
            let combined = included + extra;
            if extra >= combined {
                panic!("{} bytes is too long for LongAddr", len);
            }
            let path_ptr = &mut addr.sockaddr.sun_path[0] as *mut _ as *mut u8;
            let path_offset = path_ptr as usize - &addr as *const LongAddr as usize;
            assert_eq!(
                path_offset,
                std::mem::size_of::<LongAddr>() - combined,
                "extended address is contigious"
            );
            let extended_path = std::slice::from_raw_parts_mut(path_ptr, combined);
            for i in 0..len {
                extended_path[i] = fill;
            }
            let addrlen = (path_offset + len + 1) as libc::socklen_t;
            (addr, addrlen)
        }
    }

    let socket_a = UnixDatagram::unbound().unwrap();
    let (path_addr, addrlen) = new_longaddr(b'P', 1);
    unsafe {
        let ret = libc::bind(
            socket_a.as_raw_fd(),
            &path_addr.sockaddr as *const _ as *const libc::sockaddr,
            addrlen
        );
        if ret != -1 {
            libc::close(ret);
            panic!("{} does support addresses longer than sockaddr_un", std::env::consts::OS);
        }
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::EINVAL) {
            panic!(
                "{} rejects too long addresses with {} instead of EINVAL",
                std::env::consts::OS,
                error
            );
        }
    }
}
