#![cfg(target_family = "unix")]

extern crate uds_fork;

mod common;

use std::ffi::OsStr;
use std::os::unix::io::{RawFd, AsRawFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::process::{Command, Stdio};

use uds_fork::{UnixSocketAddr, UnixListenerExt, UnixStreamExt};

use crate::common::{make_temp_dir, make_temp_dir_no_file};

fn is_cloexec(fd: RawFd) -> bool 
{
    let mut exe = std::env::current_exe().expect("get directory of tests binary");
    exe.pop(); // pop tests binary
    if exe.file_name() == Some(OsStr::new("deps")) {// pop conditionally to future-proof
        exe.pop();
    }
    exe.push("cloexec_tester");
    eprintln!("target exe: {:?}", exe);
    let output = Command::new(exe)
        .env_clear() // no PATH
        .arg(fd.to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .output().expect("run cloexec_tester program");
    if !output.stderr.is_empty() {
        panic!("{}", String::from_utf8_lossy(&output.stderr));
    }
    match output.status.code() {
        Some(0) => true,
        Some(1) => false,
        Some(x) => panic!("cloexec_tester exited with unexpected status code {}, but no error", x),
        None => panic!("cloexec_tester was killed by signal"),
    }
}

#[test]
fn stream_listener() 
{
    let (path, _dir) = make_temp_dir("stream_listener_cloexec");

    let addr = UnixSocketAddr::from_path(&path).unwrap();

    let listener = UnixListener::bind_unix_addr(&addr).expect("bind()");
    
    assert!(is_cloexec(listener.as_raw_fd()));
}

#[test]
fn stream_accepted() 
{
    let (path, _dir) = make_temp_dir("stream_accepted_cloexec");

    let listener = UnixListener::bind(&path).expect("bind()");
    let result = UnixStream::connect(&path);
    let _client = result.expect("connect()");
    let (conn, _) = listener.accept_unix_addr().expect("accept()");
    assert!(is_cloexec(conn.as_raw_fd()));
}

#[test]
fn stream_connected() 
{
    let (path, _dir) = make_temp_dir("stream_connected_cloexec");

    let addr = UnixSocketAddr::from_path(&path).unwrap();

    let _listener = UnixListener::bind(&path).unwrap();
    let result = UnixStream::connect_to_unix_addr(&addr);

    let conn = result.expect("connect()");
    assert!(is_cloexec(conn.as_raw_fd()));
}

#[test]
fn stream_connected_from() 
{
    let dir = make_temp_dir_no_file();

    let listen_path = dir.path().join("stream_connected_from_cloexec");

    let connect_from_path = dir.path().join("stream_connected_from_cloexec_src");
    
    let listen_addr = UnixSocketAddr::from_path(&listen_path).unwrap();
    let connect_from_addr = UnixSocketAddr::from_path(&connect_from_path).unwrap();

    let _listener = UnixListener::bind(listen_path).unwrap();
    let result = UnixStream::connect_from_to_unix_addr(&connect_from_addr, &listen_addr);

    let conn = result.expect("connect()");

    assert!(is_cloexec(conn.as_raw_fd()));
}

#[cfg(not(any(target_os="illumos", target_os="solaris")))]
#[test]
fn received() {
    use std::os::fd::OwnedFd;

    
    let (foo, bar) = UnixStream::pair().expect("create unix stream pair");

    let (foo2, _bar2) = UnixStream::pair().expect("create unix stream pair");

    let foo2fd = foo2.as_raw_fd();
    foo.send_fds(b"Hello Bar, it's Foo, your peer", vec![OwnedFd::from(foo2)]).expect("send fd");
    
    let mut fd_buf = [const { None }; 10];
    
    let (_, num_fds) = bar.recv_slice_fds(&mut[b'\0'; 8], &mut fd_buf).expect("receive ancillary");
    
    assert_eq!(num_fds, 1);

    assert!(is_cloexec(fd_buf[0].as_ref().unwrap().as_raw_fd()));
    assert_eq!(foo2fd, fd_buf[0].as_ref().unwrap().as_raw_fd());
}

#[test] /// tests that cloexec_tester detects a fd without cloexec
fn raw_not_cloexec() 
{
    unsafe 
    {
        let mut fds = [-1; 2];
        if libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, fds.as_mut_ptr()) == -1 
        {
            panic!("cannot create unix stream socket pair");
        }
        let _ = libc::close(fds[0]);
        assert!(!is_cloexec(fds[1]));
        let _ = libc::close(fds[1]);
    }
}
