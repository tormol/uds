#![cfg(target_family = "unix")]
extern crate uds_fork;

mod common;

extern crate libc;

use std::os::unix::net::{UnixDatagram, UnixListener, UnixStream};
use std::io::ErrorKind::*;
use std::io::{IoSlice, IoSliceMut};
use std::path::Path;
use std::mem::{self, size_of};


use libc::{sockaddr, sockaddr_un, socklen_t};

//#[cfg(target_family = "windows")]


use uds_fork::{UnixSocketAddr, UnixSocketAddrRef};


use uds_fork::{UnixListenerExt, UnixStreamExt, UnixDatagramExt};

use crate::common::{make_temp_dir_no_file};

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
    println!("{:?}", bind_err);
    
    #[cfg(not(any(target_os="openbsd")))]
    assert!(bind_err.kind() == InvalidInput  ||  bind_err.kind() == Other/*solarish*/);
    
    #[cfg(any(target_os="openbsd"))]
    assert!(bind_err.kind() == NotFound);
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
fn max_regular_path_addr() 
{
    let dir = make_temp_dir_no_file();


    let max_regular_len = UnixSocketAddr::max_path_len()-1;
    let max_regular_path_base = dir.path().display().to_string();
    let max_regular_path_other = std::iter::repeat('R').take(max_regular_len - max_regular_path_base.len()).collect::<String>();
    let max_regular_path = [max_regular_path_base.as_str(), max_regular_path_other.as_str()].concat();
    let max_regular_addr = UnixSocketAddr::from_path(&max_regular_path)
        .expect("create path address with max regular length");
    assert_eq!(max_regular_addr.as_ref(), UnixSocketAddrRef::Path(max_regular_path.as_ref()));
    assert_eq!(&max_regular_addr, max_regular_path.as_bytes());

    
    let listener = UnixListener::bind_unix_addr(&max_regular_addr)
        .expect("create socket with max regular path length");
    let addr_from_os = listener.local_unix_addr().expect("get local max regular length path addr");
    assert_eq!(addr_from_os.as_ref(), UnixSocketAddrRef::Path(max_regular_path.as_ref()));
    assert_eq!(addr_from_os, max_regular_addr);
    assert_eq!(&addr_from_os, max_regular_path.as_bytes());

    let std_addr = listener.local_addr().expect("std get local max regular length path");
    if cfg!(not(target_os="openbsd")) {
        assert_eq!(std_addr.as_pathname(), Some(max_regular_path.as_ref()));
    }
    let conn = UnixStream::connect(&max_regular_path)
        .expect("std connect to max regular length path");
    assert_eq!(
        conn.peer_unix_addr().expect("get local max regular length path addr"),
        max_regular_addr
    );
}

#[test]
fn max_path_addr() 
{// std fails this!
    let dir = make_temp_dir_no_file();

    let max_len = UnixSocketAddr::max_path_len();
    let max_regular_path_base = dir.path().display().to_string();
    let max_regular_path_other = std::iter::repeat('L').take(max_len - max_regular_path_base.len()).collect::<String>();
    let max_path = [max_regular_path_base.as_str(), max_regular_path_other.as_str()].concat();
    let max_addr = UnixSocketAddr::from_path(&max_path)
        .expect("create path address with max length");
    assert_eq!(max_addr.as_ref(), UnixSocketAddrRef::Path(max_path.as_ref()));
    assert_eq!(&max_addr, max_path.as_bytes());


    let listener = UnixListener::bind_unix_addr(&max_addr)
        .expect("create socket with max length path addr");
    let addr_from_os = listener.local_unix_addr()
        .expect("get local max length path addr");
    assert_eq!(addr_from_os, max_addr);
    assert_eq!(addr_from_os.as_ref(), UnixSocketAddrRef::Path(max_path.as_ref()));
    assert_eq!(&addr_from_os, max_path.as_bytes());

}

#[test]
fn too_long_abstract_name() {
    let too_long = &vec![b'L'; UnixSocketAddr::max_abstract_len()+1];
    let err = UnixSocketAddr::from_abstract(&too_long)
        .expect_err("create too long abstract address");
    if cfg!(any(target_os="linux", target_os="android")) 
    {
        assert_eq!(err.kind(), InvalidInput); // too long
    } 
    else 
    {
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
fn path_from_ffi() 
{
    let ((), addr) = UnixSocketAddr::new_from_ffi(|addr, len| {
        let addr = unsafe { &mut*(addr as *mut sockaddr as *mut sockaddr_un)};
        *len = (&addr.sun_path as *const _ as usize - addr as *const _ as usize) as socklen_t;
        for (src, dst) in b"FFIIIII!!".iter().zip(&mut addr.sun_path[..]) {
            *dst = *src as _;
            *len += 1;
        }
        Ok(())
    }).expect("return address with normal path");
    assert!(addr.is_path());
    assert_eq!(addr.as_ref(), UnixSocketAddrRef::Path(Path::new("FFIIIII!!")));
    assert_eq!(format!("{:?}", addr), "UnixSocketAddr(Path(\"FFIIIII!!\"))");

    let ((), addr) = UnixSocketAddr::new_from_ffi(|addr, len| {
        let addr = unsafe { &mut*(addr as *mut sockaddr as *mut sockaddr_un)};
        *len = (&addr.sun_path as *const _ as usize - addr as *const _ as usize) as socklen_t;
        addr.sun_path[0] = b'1' as _;
        *len += 2;
        Ok(())
    }).expect("return address with path with a trailing NUL");
    assert!(addr.is_path());
    assert_eq!(addr.as_ref(), UnixSocketAddrRef::Path(Path::new("1")));
    assert_eq!(format!("{:?}", addr), "UnixSocketAddr(Path(\"1\"))");

    let ((), addr) = UnixSocketAddr::new_from_ffi(|addr, len| {
        let addr = unsafe { &mut*(addr as *mut sockaddr as *mut sockaddr_un)};
        *len = (&addr.sun_path as *const _ as usize - addr as *const _ as usize) as socklen_t;
        addr.sun_path[0] = b'2' as _;
        *len += 3;
        Ok(())
    }).expect("return address with path with two trailing NULs");
    assert!(addr.is_path());
    assert_eq!(addr.as_ref(), UnixSocketAddrRef::Path(Path::new("2")));
    assert_eq!(format!("{:?}", addr), "UnixSocketAddr(Path(\"2\"))");

    let (len, addr) = UnixSocketAddr::new_from_ffi(|addr, len| {
        let addr = unsafe { &mut*(addr as *mut sockaddr as *mut sockaddr_un)};
        *len = size_of::<sockaddr_un>() as socklen_t;
        addr.sun_path.fill(b'b' as _);
        Ok(addr.sun_path.len())
    }).expect("return address with max length path");
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
    assert_eq!(format!("{:?}", addr), "UnixSocketAddr(Unnamed)");

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
        assert_eq!(format!("{:?}", addr), "UnixSocketAddr(Unnamed)");
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
        assert_eq!(format!("{:?}", addr), format!("UnixSocketAddr(Abstract({:?}))", "\x00\x07"));
    }
}

#[test]
fn unconnected_datagrams() 
{
    let dir = make_temp_dir_no_file();

    let p1 = dir.path().join("corner_a.sock");
    let p2 = dir.path().join("corner_b.sock");   
    let p3 = dir.path().join("corner_c.sock");

    let a = UnixDatagram::bind(&p1).expect("create 1st datagram socket");
    let b = UnixDatagram::bind(&p2).expect("create 2nd datagram socket");
    let c = UnixDatagram::bind(&p3).expect("create 3rd datagram socket");

    let addr_a = UnixSocketAddr::new(p1.as_os_str().to_str().unwrap()).unwrap();
    let addr_b = UnixSocketAddr::new(p2.as_os_str().to_str().unwrap()).unwrap();
    let addr_c = UnixSocketAddr::new(p3.as_os_str().to_str().unwrap()).unwrap();
    let mut buf = [0; 10];

    a.send_to_unix_addr(b"red", &addr_b).expect("send datagram to b");
    assert_eq!(b.recv_from_unix_addr(&mut buf).expect("receive with addr"), (3, addr_a));
    assert_eq!(&buf, b"red\0\0\0\0\0\0\0");

    b.send_to_unix_addr(b"green", &addr_c).expect("send datagram to c");

    b.send_vectored_to_unix_addr(
        &[IoSlice::new(b"cy"), IoSlice::new(b"an")],
        &addr_a
    ).expect("send vectored datagram to a");
    assert_eq!(a.peek_from_unix_addr(&mut buf).expect("peek from b"), (4, addr_b));
    assert_eq!(&buf, b"cyan\0\0\0\0\0\0");
    let (len, std_addr) = a.recv_from(&mut buf).expect("receive what was peeked");
    #[cfg(not(target_os="openbsd"))]
    assert_eq!(std_addr.as_pathname(), Some(Path::new(&p2)));
    assert_eq!(&buf[..len], b"cyan");

    c.send_to(b"blue", p1).expect("send datagram to a");
    c.send_to_unix_addr(b"alpha", &addr_a).expect("send datagram to a");
    let (buf_a, buf_b) = buf.split_at_mut(2);
    let (len, addr) = c.recv_vectored_from_unix_addr(&mut[
        IoSliceMut::new(&mut buf_b[..3]), IoSliceMut::new(buf_a)
    ]).expect("receive from b");
    assert_eq!(addr.as_pathname(), Some(Path::new(&p2)));
    assert_eq!(len, 5);
    assert_eq!(&buf, b"engre\0\0\0\0\0");

}

#[test]
fn datagram_peek_vectored() 
{
    let dir = make_temp_dir_no_file();

    let p1 = dir.path().join("datagram_server.sock");
    let p2 = dir.path().join("datagram_client.sock");

    let server = UnixDatagram::bind(&p1).unwrap();

    let client = UnixDatagram::unbound().unwrap();
    if cfg!(any(target_os="linux", target_os="android")) {
        // get a random abstract address
        client.bind_to_unix_addr(&UnixSocketAddr::new_unspecified()).unwrap();
    } else {
        client.bind_to_unix_addr(&UnixSocketAddr::new(p2.as_os_str().to_str().unwrap()).unwrap()).unwrap();
    }
    client.connect(&p1).unwrap();
    client.send(b"headerbodybody").unwrap();

    let (mut buf_a, mut buf_b) = ([0; 6], [0; 12]);
    let mut vector = [IoSliceMut::new(&mut buf_a), IoSliceMut::new(&mut buf_b)];
    let (bytes, addr) = server.peek_vectored_from_unix_addr(&mut vector)
        .expect("peek with vector");
    assert_eq!(addr, client.local_unix_addr().unwrap());
    assert_eq!(bytes, 14);
    assert_eq!(&buf_a, b"header");
    assert_eq!(&buf_b[..8], b"bodybody");

}

#[test]
fn from_raw_path() 
{
    
    let path_addr = UnixSocketAddr::from_path("/tmp/path.sock").unwrap();
    let a = 
    unsafe 
    {
        let (raw_addr, raw_len) = path_addr.as_raw();
        UnixSocketAddr::from_raw(raw_addr as *const sockaddr_un as *const sockaddr, raw_len)
    }
    .expect("from_raw() accepts from_path()");

    assert_eq!(a, path_addr);
    assert!(a.is_path());
}

#[test]
fn from_ref_path() 
{
    
    let path_addr = UnixSocketAddr::from_path("/tmp/path.sock").unwrap();
    let a = 
    unsafe 
    {
        let (raw_addr, raw_len) = path_addr.as_raw();
        let ref_addr: &libc::sockaddr = mem::transmute(raw_addr);

        UnixSocketAddr::from_ref(ref_addr, raw_len)
    }
    .expect("from_raw() accepts from_path()");
    
    assert_eq!(a, path_addr);
    assert!(a.is_path());
}

#[test]
fn from_sockaddr_storage_path() 
{
    
    let path_addr = UnixSocketAddr::from_path("/tmp/path.sock").unwrap();
    let a = 
        unsafe 
        {
            let (raw_addr, raw_len) = path_addr.as_raw();
            let ref_addr: &libc::sockaddr_storage = mem::transmute(raw_addr);

            UnixSocketAddr::from_sockaddr_storage(ref_addr, raw_len)
        }
        .expect("from_raw() accepts from_path()");
    
    assert_eq!(a, path_addr);
    assert!(a.is_path());
}

#[test]
fn from_sockaddr_storage_path_unspec() 
{
    
    let path_addr = UnixSocketAddr::new_unspecified();
    let a = 
        unsafe 
        {
            let (raw_addr, raw_len) = path_addr.as_raw();
            assert_eq!(raw_len, 2);
            let ref_addr: &libc::sockaddr_storage = mem::transmute(raw_addr);

            UnixSocketAddr::from_sockaddr_storage(ref_addr, raw_len)
        }
        .expect("from_raw() accepts from_path()");
    
    assert_eq!(a, path_addr);
    assert!(a.is_unnamed());
}

#[test]
fn from_raw_max_len_path() 
{
    let path = "R".repeat(UnixSocketAddr::max_path_len());
    let path_addr = UnixSocketAddr::from_path(path.as_str()).unwrap();
    let a = 
    unsafe 
    {
        let (raw_addr, raw_len) = path_addr.as_raw();
        UnixSocketAddr::from_raw(raw_addr as *const sockaddr_un as *const sockaddr, raw_len)
    }
    .expect("from_path() is valid");

    assert_eq!(a, path_addr);
    assert!(a.is_path());
}

#[test]
fn from_ref_max_len_path() 
{
    let path = "R".repeat(UnixSocketAddr::max_path_len());
    let path_addr = UnixSocketAddr::from_path(path.as_str()).unwrap();
    let a = 
    unsafe 
    {
        let (raw_addr, raw_len) = path_addr.as_raw();
        let ref_addr: &libc::sockaddr = mem::transmute(raw_addr);

        UnixSocketAddr::from_ref(ref_addr, raw_len)
    }
    .expect("from_path() is valid");

    assert_eq!(a, path_addr);
    assert!(a.is_path());
}

#[test]
fn from_sockaddr_storage_max_len_path() 
{
    let path = "R".repeat(UnixSocketAddr::max_path_len());
    let path_addr = UnixSocketAddr::from_path(path.as_str()).unwrap();
    let a = 
    unsafe 
    {
        let (raw_addr, raw_len) = path_addr.as_raw();
        let ref_addr: &libc::sockaddr_storage = mem::transmute(raw_addr);

        UnixSocketAddr::from_sockaddr_storage(ref_addr, raw_len)
    }
    .expect("from_path() is valid");

    assert_eq!(a, path_addr);
    assert!(a.is_path());
}

#[test]
fn from_raw_too_long_path() 
{
    #[repr(C)]
    struct TooLong 
    {
        fam: libc::sa_family_t,
        path: [u8; 300],
    }
    let path_addr = 
        TooLong 
        {
            fam: libc::AF_UNIX as libc::sa_family_t,
            path: [b'o'; 300],
        };

    unsafe 
    {
        let raw_addr = &path_addr as *const TooLong as *const sockaddr;
        UnixSocketAddr::from_raw(raw_addr, size_of::<TooLong>() as _)
    }
    .expect_err("too long");
}

#[test]
fn from_ref_too_long_path() 
{
    #[repr(C)]
    struct TooLong 
    {
        fam: libc::sa_family_t,
        path: [u8; 300],
    }
    let path_addr = 
        TooLong 
        {
            fam: libc::AF_UNIX as libc::sa_family_t,
            path: [b'o'; 300],
        };

    unsafe 
    {
        let ref_path: &libc::sockaddr = mem::transmute(&path_addr);

        UnixSocketAddr::from_ref(ref_path, size_of::<TooLong>() as _)
    }
    .expect_err("too long");
}

#[test]
fn from_sockaddr_storage_too_long_path() 
{
    #[repr(C)]
    struct TooLong 
    {
        fam: libc::sa_family_t,
        path: [u8; 300],
    }
    let path_addr = 
        TooLong 
        {
            fam: libc::AF_UNIX as libc::sa_family_t,
            path: [b'o'; 300],
        };

    unsafe 
    {
        let ref_path: &libc::sockaddr_storage = mem::transmute(&path_addr);

        UnixSocketAddr::from_sockaddr_storage(ref_path, size_of::<TooLong>() as _)
    }
    .expect_err("too long");
}

#[test]
fn from_raw_empty() {
    let unspecified_addr = UnixSocketAddr::new_unspecified();
    let (raw_addr, raw_len) = unspecified_addr.as_raw();
    let a = unsafe {
        UnixSocketAddr::from_raw(raw_addr as *const sockaddr_un as *const sockaddr, raw_len)
    }.expect("from_raw() accepts new_unspecified()");
    assert_eq!(a, unspecified_addr);
    assert!(a.is_unnamed());

    if !UnixSocketAddr::has_abstract_addresses() {
        let a = unsafe {
            UnixSocketAddr::from_raw(raw_addr as *const sockaddr_un as *const sockaddr, raw_len+10)
        }.expect("from_raw() accepts extra NULs");
        assert_eq!(a, unspecified_addr);
        assert!(a.is_unnamed());
    }
}

#[cfg(any(target_os="linux", target_os="android"))]
#[test]
fn from_raw_abstract() {
    let abstract_addr = UnixSocketAddr::from_abstract(b"aa!").unwrap();
    let a = unsafe {
        let (raw_addr, raw_len) = abstract_addr.as_raw();
        UnixSocketAddr::from_raw(raw_addr as *const sockaddr_un as *const sockaddr, raw_len)
    }.expect("from_raw() accepts from_abstract()");
    assert_eq!(a, abstract_addr);
    assert!(a.is_abstract());

    let max_abstract = "l".repeat(UnixSocketAddr::max_abstract_len());
    let abstract_addr = UnixSocketAddr::from_abstract(max_abstract.as_bytes()).unwrap();
    let (raw_addr, raw_len) = abstract_addr.as_raw();
    let a = unsafe {
        UnixSocketAddr::from_raw(raw_addr as *const sockaddr_un as *const sockaddr, raw_len)
    }.expect("from_raw() accepts longest abstract");
    assert_eq!(a, abstract_addr);
    assert!(a.is_abstract());

    unsafe {
        UnixSocketAddr::from_raw(raw_addr as *const sockaddr_un as *const sockaddr, raw_len+1)
    }.expect_err("from_raw() rejects too long abstract");
}
