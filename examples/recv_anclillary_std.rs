
#![feature(unix_socket_ancillary_data)]

extern crate uds_fork;
use std::{io::{IoSlice, IoSliceMut}, os::{fd::{IntoRawFd, OwnedFd}, unix::net::{AncillaryData, SocketAncillary, UnixDatagram}}};

use libc::MSG_EOR;

fn main()
{
    let dir = tempfile::tempdir().unwrap();
    let path_full = dir.path().join("seqpacket2.exists.socket");
    let path = path_full.as_path();

    let addr = 
        uds_fork::UnixSocketAddr::from_path(&path)
            .expect("create abstract socket address");
        
    let listener = 
        uds_fork::UnixSeqpacketListener::bind_unix_addr(&addr)
            .expect("create seqpacket listener");

    let freya_side_a = 
        uds_fork::UnixSeqpacketConn::connect_unix_addr(&addr)
            .expect("connect to listener");

    let (freya_side_b, _) = listener.accept_unix_addr()
        .expect("accept connection");

    let (a, b) = UnixDatagram::pair().expect("create datagram socket pair");
    let (aa, _bb) = UnixDatagram::pair().expect("create datagram socket pair");

    let buf0 = b"Here I come";
    let mut ancillary_buffer = [0; 128];
    let mut ancillary = SocketAncillary::new(&mut ancillary_buffer[..]);

    let fds = [OwnedFd::from(a).into_raw_fd(), OwnedFd::from(b).into_raw_fd(), OwnedFd::from(aa).into_raw_fd()];

    ancillary.add_fds(&fds[..]);

    freya_side_a.send_vectored_with_ancillary(MSG_EOR, &[IoSlice::new(buf0.as_slice())], &mut ancillary)
        .expect("send stdin, stdout and stderr");

    // receive
    let mut buf = [0_u8; 256];
    let bufs = &mut [IoSliceMut::new(&mut buf[..])];

    let mut ancillary_buffer = [0; 128];
    let mut ancillary = SocketAncillary::new(&mut ancillary_buffer[..]);

    let (count, trunc) = freya_side_b.recv_vectored_with_ancillary(0, bufs, &mut ancillary).unwrap();

    println!("count: {}, trunc: {}, anscil len: {}", count, trunc, ancillary.len());

    assert_eq!(trunc, false);
    assert_eq!(count, buf0.len());
    assert_eq!(buf0.as_slice(), &buf[..count]);

    for ancillary_result in ancillary.messages() 
    {
        if let AncillaryData::ScmRights(scm_rights) = ancillary_result.unwrap() 
        {
            assert_eq!(scm_rights.count(), 3);
        }
        else
        {
            panic!("expected ScmRights")
        }
    }
}
 