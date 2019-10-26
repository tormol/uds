extern crate uds;

use std::ffi::OsStr;
use std::fs::remove_file;
use std::os::unix::io::{RawFd, AsRawFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::process::{Command, Stdio};

use uds::{UnixSocketAddr, UnixListenerExt, UnixStreamExt};

fn is_cloexec(fd: RawFd) -> bool {
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
        panic!(String::from_utf8_lossy(&output.stderr).into_owned());
    }
    match output.status.code() {
        Some(0) => true,
        Some(1) => false,
        Some(x) => panic!("cloexec_tester exited with unexpected status code {}, but no error", x),
        None => panic!("cloexec_tester was killed by signal"),
    }
}

#[test]
fn stream_listener() {
    let path = "stream_listener_cloexec";
    let addr = UnixSocketAddr::from_path(path).unwrap();
    let _ = remove_file(path);
    let listener = UnixListener::bind_unix_addr(&addr).expect("bind()");
    remove_file(path).expect("remove socket file");
    assert!(is_cloexec(listener.as_raw_fd()));
}

#[test]
fn stream_accepted() {
    let path = "stream_accepted_cloexec";
    let _ = remove_file(path);
    let listener = UnixListener::bind(path).expect("bind()");
    let result = UnixStream::connect(path);
    remove_file(path).expect("remove socket file");
    let _client = result.expect("connect()");
    let (conn, _) = listener.accept_unix_addr().expect("accept()");
    assert!(is_cloexec(conn.as_raw_fd()));
}

#[test]
fn stream_connected() {
    let path = "stream_connected_cloexec";
    let addr = UnixSocketAddr::from_path(path).unwrap();
    let _ = remove_file(path);
    let _listener = UnixListener::bind(path).unwrap();
    let result = UnixStream::connect_to_unix_addr(&addr);
    remove_file(path).expect("remove socket file");
    let conn = result.expect("connect()");
    assert!(is_cloexec(conn.as_raw_fd()));
}

#[test]
fn stream_connected_from() {
    let listen_path = "stream_connected_from_cloexec";
    let connect_from_path = "stream_connected_from_cloexec_src";
    let listen_addr = UnixSocketAddr::from_path(listen_path).unwrap();
    let connect_from_addr = UnixSocketAddr::from_path(connect_from_path).unwrap();

    let _ = remove_file(listen_path);
    let _ = remove_file(connect_from_path);
    let _listener = UnixListener::bind(listen_path).unwrap();
    let result = UnixStream::connect_from_to_unix_addr(&connect_from_addr, &listen_addr);
    remove_file(listen_path).expect("remove listening socket file");
    remove_file(connect_from_path).expect("remove connect from socket file");
    let conn = result.expect("connect()");

    assert!(is_cloexec(conn.as_raw_fd()));
}

#[test]
fn received() {
    let (foo, bar) = UnixStream::pair().expect("create unix stream pair");
    foo.send_fds(b"Hello Bar, it's Foo, your peer", &[foo.as_raw_fd()]).expect("send fd");
    let mut fd_buf = [-1; 10];
    let (_, num_fds) = bar.recv_fds(&mut[b'\0'; 8], &mut fd_buf).expect("receive ancillary");
    assert_eq!(num_fds, 1);
    assert!(is_cloexec(fd_buf[0]));
}

#[test] /// tests that cloexec_tester detects a fd without cloexec
fn raw_not_cloexec() {
    unsafe {
        let mut fds = [-1; 2];
        if libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, fds.as_mut_ptr()) == -1 {
            panic!("cannot create unix stream socket pair");
        }
        let _ = libc::close(fds[0]);
        assert!(!is_cloexec(fds[1]));
        let _ = libc::close(fds[1]);
    }
}
