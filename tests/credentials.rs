#![allow(unused)] // when not applicable, tests should still compile

use std::os::unix::net::{UnixListener, UnixStream, UnixDatagram};
use std::io::{self, ErrorKind::*};
use std::fs::remove_file;

extern crate uds;
use uds::{ConnCredentials, UnixStreamExt, UnixDatagramExt};
use uds::{UnixSeqpacketListener, UnixSeqpacketConn};

extern crate libc;
use libc::{getpid, geteuid, getegid, getgid, getgroups};

#[cfg_attr(
    not(any(
        target_os="linux", target_os="android",
        target_os="freebsd", target_os="dragonfly", target_vendor="apple",
        target_os="openbsd", target_os="netbsd",
        target_os="illumos", target_os="solaris"
    )),
    test
)]
fn peer_credentials_not_supported() {
    let (a, _b) = UnixStream::pair().unwrap();
    let error = a.initial_peer_credentials().unwrap_err();
    assert_eq!(error.kind(), Unsupported);
}

fn assert_credentials_matches_current_process(creds: &ConnCredentials,  socket_type: &str) {
    match creds {
        &ConnCredentials::LinuxLike{ pid, euid, egid } => {
            assert_eq!(u32::from(pid), unsafe { getpid() } as u32, "{} pid matches", socket_type);
            assert_eq!(euid, unsafe { geteuid() } as u32, "{} euid matches", socket_type);
            assert_eq!(egid, unsafe { getegid() } as u32, "{} egid matches", socket_type);
        }
        &ConnCredentials::MacOsLike{ euid, number_of_groups, ref groups } => {
            assert_eq!(euid, unsafe { geteuid() }, "{} euid matches", socket_type);
            assert!(
                (number_of_groups as usize) <= groups.len(),
                "{} groups within bounds ({} not <= {})",
                socket_type,
                number_of_groups,
                groups.len(),
            );
            // check that all the returned groups belongs to the current process
            let mut current_process_groups = [0; 100];
            let number_of_process_groups = unsafe { getgroups(
                    current_process_groups.len() as _,
                    current_process_groups.as_mut_ptr(),
            ) };
            let current_process_groups = match number_of_process_groups {
                -1 => panic!("getgroups(100, <ptr>) failed with {}", io::Error::last_os_error()),
                n => &current_process_groups[..(n as usize)],
            };
            for &peer_group in &groups[..(number_of_groups as usize)] {
                assert!(
                    current_process_groups.contains(&{peer_group as _}),
                    "{} group {} is one of the current process ({:?})",
                    socket_type,
                    peer_group,
                    current_process_groups,
                );
            }
            // other sanity checks
            assert!(number_of_groups >= 1, "{} has at least some groups", socket_type);
            for (i, &group) in groups.iter().enumerate().take(number_of_groups as usize) {
                assert_ne!(group, !0, "{} group[{}] is not a marker value", socket_type, i);
            }
            assert_eq!(
                &groups[number_of_groups as usize..],
                &vec![!0u32; groups.len() - (number_of_groups as usize)][..],
                "{} unused groups are set to a marker value", socket_type
            );
            let (egid, rgid) = (unsafe { getegid() }, unsafe { getgid() });
            assert!(
                groups.contains(&{egid as u32}),
                "{} groups contains egid ({})", socket_type, egid
            );
            assert!(
                groups.contains(&{rgid as u32}),
                "{} groups contains real gid ({})", socket_type, rgid
            );
        }
    }
}

#[test]
fn peer_credentials_of_stream_conn() {
    let path = "stream_credentials.socket";
    let _ = remove_file(path);
    let listener = UnixListener::bind(path).expect("create socket file");
    let client = UnixStream::connect(path).expect("connect");
    remove_file(path).expect("delete socket file");
    let creds = client.initial_peer_credentials().expect("get credentials of server");
    assert_credentials_matches_current_process(&creds, "stream conn");
    let (server, _) = listener.accept().expect("accept");
    assert_eq!(server.initial_peer_credentials().unwrap(), creds); // same process
    assert_eq!(client.initial_peer_credentials().unwrap(), creds); // consistent
}

#[test]
fn peer_credentials_of_stream_pair() {
    let (a, b) = UnixStream::pair().expect("create unix stream pair");
    match a.initial_peer_credentials() {
        Ok(creds) => {
            assert_credentials_matches_current_process(&creds, "stream pair");
            assert_eq!(b.initial_peer_credentials().unwrap(), creds); // same process
            assert_eq!(a.initial_peer_credentials().unwrap(), creds); // consistent
        }
        Err(ref e) if e.kind() == NotConnected => {/*fails with this error on DragonFly BSD*/}
        Err(ref e) if e.kind() == InvalidInput => {/*fails with this error on NetBSD*/}
        Err(e) => panic!("failed with unexpected error {}", e)
    }
}

#[cfg_attr(
    any(
        target_os="linux", target_os="android",
        target_os="freebsd", target_os="dragonfly",
        target_os="openbsd", target_os="netbsd",
        target_os="illumos", target_os="solaris"
    ),
    test
)]
fn peer_credentials_of_seqpacket_conn() {
    let path = "seqpacket_credentials.socket";
    let _ = remove_file(path);
    let listener = UnixSeqpacketListener::bind(path).expect("create socket file");
    let client = UnixSeqpacketConn::connect(path).expect("connect");
    remove_file(path).expect("delete socket file");
    let creds = client.initial_peer_credentials().expect("get credentials of server");
    assert_credentials_matches_current_process(&creds, "stream conn");
    let (server, _) = listener.accept_unix_addr().expect("accept");
    assert_eq!(server.initial_peer_credentials().unwrap(), creds); // same process
    assert_eq!(client.initial_peer_credentials().unwrap(), creds); // consistent
}

#[cfg_attr(
    any(
        target_os="linux", target_os="android",
        target_os="freebsd", target_os="dragonfly",
        target_os="openbsd", target_os="netbsd",
        target_os="illumos", target_os="solaris"
    ),
    test
)]
fn peer_credentials_of_seqpacket_pair() {
    let (a, b) = UnixSeqpacketConn::pair().expect("create unix seqpacket pair");
    match a.initial_peer_credentials() {
        Ok(creds) => {
            assert_credentials_matches_current_process(&creds, "seqpacket pair");
            assert_eq!(b.initial_peer_credentials().unwrap(), creds); // same process
            assert_eq!(a.initial_peer_credentials().unwrap(), creds); // consistent
        }
        Err(ref e) if e.kind() == NotConnected => {/*fails with this error on DragonFly BSD*/}
        Err(ref e) if e.kind() == InvalidInput => {/*fails with this error on NetBSD*/}
        Err(e) => panic!("failed with unexpected error {}", e)
    }
}

#[test]
fn pair_credentials_of_datagram_socketpair() {
    let (a, b) = UnixDatagram::pair().expect("create unix datagram socket pair");
    match a.initial_pair_credentials() {
        Ok(creds) => {
            assert_credentials_matches_current_process(&creds, "datagram socketpair");
            assert_eq!(b.initial_pair_credentials().unwrap(), creds);
        }
        Err(ref e) if e.kind() == InvalidInput => {}
        Err(ref e) if e.kind() == Unsupported /*solarish and DragonFly*/ => {}
        Err(e) => panic!("failed with unexpected error variant {:?}", e.kind())
    }
}

#[test]
fn no_peer_credentials_of_unconnected_datagram_socket() {
    let _ = remove_file("datagram_credentials.socket");
    let socket = UnixDatagram::bind("datagram_credentials.socket")
        .expect("create unix datagram socket");
    remove_file("datagram_credentials.socket").unwrap();
    let err = socket.initial_pair_credentials()
        .expect_err("get credentials of unconnected datagram socket");
    assert!(
        err.kind() == NotConnected // junk returned
        ||  err.kind() == InvalidInput // failed properly
        ||  err.to_string().contains("not supported") // failed with ENOTSUP
    );
}

#[test]
fn no_peer_credentials_of_regularly_connected_datagram_socket() {
    let a_pathname = "datagram_credentials_a.socket";
    let b_pathname = "datagram_credentials_b.socket";
    let _ = remove_file(a_pathname);
    let _ = remove_file(b_pathname);
    let a = UnixDatagram::bind(a_pathname).expect("create unix datagram socket");
    let b = UnixDatagram::bind(b_pathname).expect("create unix datagram socket");
    a.connect(b_pathname).expect("connect a to b");
    b.connect(a_pathname).expect("connect b to a");

    let err = a.initial_pair_credentials()
        .expect_err("get credentials of regularly connected datagram socket");
    assert!(
        err.kind() == NotConnected // junk returned
        ||  err.kind() == InvalidInput // failed properly
        ||  err.to_string().contains("not supported") // failed with ENOTSUP
    );
    let err = b.initial_pair_credentials()
        .expect_err("get credentials of regularly connected datagram socket");
    assert!(
        err.kind() == NotConnected // junk returned
        ||  err.kind() == InvalidInput // failed properly
        ||  err.to_string().contains("not supported") // failed with ENOTSUP
    );
    
    remove_file(a_pathname).expect("delete socket file");
    remove_file(b_pathname).expect("delete socket file");
}



#[test]
fn peer_selinux_context() {
    let (a, _b) = UnixStream::pair().expect("create unix stream socket pair");
    let mut buf = [0u8; 1024];
    match a.initial_peer_selinux_context(&mut buf) {
        Ok(len) => {
            assert!(len <= buf.len(), "length is within bounds");
            assert_ne!(len, 0, "context is not an empty string");
            assert!(buf[..len].iter().all(|&b| b.is_ascii() && !b.is_ascii_control() ));
            assert_eq!(
                &buf[len..],
                &vec![b'\0'; buf.len()-len][..],
                "unused part of buffer is untouched"
            );
            if cfg!(not(any(target_os="linux", target_os="android"))) {
                panic!("unexpectedly succeeded on non-Linux OS");
            }
        }
        Err(_) => {
            assert_eq!(&buf[..], &[0u8; 1024][..], "buffer is untouched on error");
            // fails on Linux on Cirrus, probably as a result of running inside a docker container
        }
    }
}
