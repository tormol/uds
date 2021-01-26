extern crate uds;
extern crate libc;

use std::os::unix::net::{UnixListener, UnixStream};
use std::io::ErrorKind::*;
use std::fs::remove_file;
use std::path::Path;
use std::mem::size_of;

use libc::{sockaddr, sockaddr_un, socklen_t};

use uds::{UnixSocketAddr, UnixSocketAddrRef};
use uds::{UnixListenerExt, UnixStreamExt};

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
    assert!(bind_err.kind() == InvalidInput  ||  bind_err.kind() == Other/*solarish*/);
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
        UnixListener::bind(&path).expect_err("bind std socket to too long path").kind(),
        InvalidInput
    );
}

#[test]
fn path_from_ffi() {
    let ((), addr) = UnixSocketAddr::new_from_ffi(|addr, len| {
        let addr = unsafe { &mut*(addr as *mut sockaddr as *mut sockaddr_un)};
        *len = (&addr.sun_path as *const _ as usize - addr as *const _ as usize) as socklen_t;
        for (src, dst) in b"FFIIIII!!".iter().zip(&mut addr.sun_path[..]) {
            *dst = *src as _;
            *len += 1;
        }
        Ok(())
    }).expect("return address with path");
    assert!(addr.is_path());
    assert_eq!(addr.as_ref(), UnixSocketAddrRef::Path(Path::new("FFIIIII!!")));
    assert_eq!(format!("{:?}", addr), "UnixSocketAddr(Path(\"FFIIIII!!\"))");

    let ((), addr) = UnixSocketAddr::new_from_ffi(|addr, len| {
        let addr = unsafe { &mut*(addr as *mut sockaddr as *mut sockaddr_un)};
        *len = (&addr.sun_path as *const _ as usize - addr as *const _ as usize) as socklen_t;
        addr.sun_path[0] = b'1' as _;
        *len += 2;
        Ok(())
    }).expect("return address with path");
    assert!(addr.is_path());
    assert_eq!(addr.as_ref(), UnixSocketAddrRef::Path(Path::new("1")));
    assert_eq!(format!("{:?}", addr), "UnixSocketAddr(Path(\"1\"))");

    let (len, addr) = UnixSocketAddr::new_from_ffi(|addr, len| {
        let addr = unsafe { &mut*(addr as *mut sockaddr as *mut sockaddr_un)};
        *len = size_of::<sockaddr_un>() as socklen_t;
        for dst in &mut addr.sun_path[..] {
            *dst = b'b' as _;
        }
        Ok(addr.sun_path[..].len())
    }).expect("return address with path");
    assert!(addr.is_path());
    let path = String::from_utf8(vec![b'b'; len]).unwrap();
    assert_eq!(addr.as_ref(), UnixSocketAddrRef::Path(Path::new(&path)));
    assert_eq!(format!("{:?}", addr), format!("UnixSocketAddr(Path(\"{}\"))", path));
}

#[test]
fn unnamed_from_ffi() {
    let ((), addr) = UnixSocketAddr::new_from_ffi(|addr, len| {
        let addr = unsafe { &mut*(addr as *mut sockaddr as *mut sockaddr_un)};
        *len = (&addr.sun_path as *const _ as usize - addr as *const _ as usize) as socklen_t;
        Ok(())
    }).expect("return address with zero path length");
    assert!(addr.is_unnamed());
    assert_eq!(addr.as_ref(), UnixSocketAddrRef::Unnamed);
    assert_eq!(format!("{:?}", addr), "UnixSocketAddr(\"Unnamed\")");

    if !UnixSocketAddr::has_abstract_addresses() {
        let ((), addr) = UnixSocketAddr::new_from_ffi(|addr, len| {
            let addr = unsafe { &mut*(addr as *mut sockaddr as *mut sockaddr_un)};
            *len = (&addr.sun_path as *const _ as usize - &addr as *const _ as usize) as socklen_t;
            addr.sun_path[0] = 0;
            addr.sun_path[1] = 0;
            addr.sun_path[2] = 0;
            *len += 3;
            Ok(())
        }).expect("return address with zero path");
        assert!(addr.is_unnamed());
        assert_eq!(addr.as_ref(), UnixSocketAddrRef::Unnamed);
        assert_eq!(format!("{:?}", addr), "UnixSocketAddr(\"Unnamed\")");
    }
}

#[test]
fn abstract_from_ffi() {
    if UnixSocketAddr::has_abstract_addresses() {
        let ((), addr) = UnixSocketAddr::new_from_ffi(|addr, len| {
            let addr = unsafe { &mut*(addr as *mut sockaddr as *mut sockaddr_un)};
            *len = (&addr.sun_path as *const _ as usize - addr as *const _ as usize) as socklen_t;
            addr.sun_path[0] = 0;
            addr.sun_path[1] = 0;
            addr.sun_path[2] = 7;
            *len += 3;
            Ok(())
        }).expect("return abstract address");
        assert!(addr.is_abstract());
        assert_eq!(addr.as_ref(), UnixSocketAddrRef::Abstract(b"\x00\x07"));
        assert_eq!(format!("{:?}", addr), "UnixSocketAddr(Abstract(\"\\u{0}\\u{7}\"))");
    }
}
