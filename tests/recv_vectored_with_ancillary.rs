#![cfg(all(not(target_vendor="apple"), target_family = "unix", feature = "unsatable_preview"))]
#![feature(unix_socket_ancillary_data)]

use std::{io::{IoSlice, IoSliceMut}, os::{fd::{AsRawFd, IntoRawFd, OwnedFd, RawFd}, unix::net::{AncillaryData, SocketAncillary, UnixDatagram}}};

use libc::MSG_EOR;

use crate::common::make_temp_dir;

mod common;

#[test]
fn test_1_simple_legacy_to_new() 
{
    let (pathbuf, _dir) = make_temp_dir("seqpacket1.exists.socket");
    let path = pathbuf.as_path();

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

    // sending
    freya_side_a
        .send_fds(buf0, vec![OwnedFd::from(a), OwnedFd::from(b), OwnedFd::from(aa)])
        .expect("send stdin, stdout and stderr");

    let mut buf = [0_u8; 256];
    let bufs = &mut [IoSliceMut::new(&mut buf[..])];
    
    let mut ancillary_buffer = [0; 128];
    let mut ancillary = SocketAncillary::new(&mut ancillary_buffer[..]);
    
    // receiving
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

#[test]
fn test_2_simple_new_to_legacy() 
{
    let (pathbuf, _dir) = make_temp_dir("seqpacket2.exists.socket");
    let path = pathbuf.as_path();

    let addr = 
        uds_fork::UnixSocketAddr::from_path(&path)
            .expect("create abstract socket address");
        
    let listener = 
        uds_fork::UnixSeqpacketListener::bind_unix_addr(&addr)
            .expect("create seqpacket listener");

    let freya_side_a = 
        uds_fork::UnixSeqpacketConn::connect_unix_addr(&addr)
            .expect("connect to listener");

    let (freya_side_b, _) = listener.accept_unix_addr().expect("accept connection");

    let (a, b) = UnixDatagram::pair().expect("create datagram socket pair");
    let (aa, _bb) = UnixDatagram::pair().expect("create datagram socket pair");

    let buf0 = b"Here I come";
    let mut ancillary_buffer = [0; 128];
    let mut ancillary = SocketAncillary::new(&mut ancillary_buffer[..]);

    let fds = [OwnedFd::from(a), OwnedFd::from(b), OwnedFd::from(aa)];

    let fds_raw = fds.iter().map(|fd| fd.as_raw_fd()).collect::<Vec<RawFd>>();

    ancillary.add_fds(&fds_raw[..]);

    freya_side_a
        .send_vectored_with_ancillary(MSG_EOR, &[IoSlice::new(buf0.as_slice())], &mut ancillary)
        .expect("send stdin, stdout and stderr");

    let mut fd_buf = Vec::with_capacity(4);
    let mut buf1 = [0_u8; 32];

    let (count, trunc, fds_cnt) = freya_side_b.recv_fds(&mut buf1, &mut fd_buf).unwrap();

    println!("count: {}, trunc: {}, fds_cnt: {}", count, trunc, fds_cnt);

    assert_eq!(&buf1[..count], buf0.as_slice());
    assert_eq!(trunc, false);
    assert_eq!(fds_cnt, 3);

}

#[test]
fn test_3_simple_new_to_new() 
{
     let (pathbuf, _dir) = make_temp_dir("seqpacket2.exists.socket");
    let path = pathbuf.as_path();

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

    let fds = [OwnedFd::from(a), OwnedFd::from(b), OwnedFd::from(aa)];

    let fds_raw = fds.iter().map(|fd| fd.as_raw_fd()).collect::<Vec<RawFd>>();

    ancillary.add_fds(&fds_raw[..]);

    freya_side_a
        .send_vectored_with_ancillary(MSG_EOR, &[IoSlice::new(buf0.as_slice())], &mut ancillary)
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