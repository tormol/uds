#![cfg_attr(any(target_os="illumos", target_os="solaris"), allow(unused))]
#![cfg(target_family = "unix")]

// this tests should be run in sequence, otherwise it fails.

extern crate libc;
extern crate uds_fork;

mod common;

use std::{
    env::consts::*, io::{ErrorKind::*, IoSliceMut, Read, Write}, os::
    {
        fd::OwnedFd, 
        unix::
        {
            io::AsRawFd, 
            net::{UnixDatagram, UnixStream}
        }
    }
};


use uds_fork::{AncillaryItem, UnixDatagramExt, UnixSocketAddr, UnixStreamExt};

use crate::common::make_temp_dir_no_file;


#[cfg_attr(not(any(target_os="illumos", target_os="solaris")), test)]
fn datagram_send_no_fds() {
    let (a, b) = UnixDatagram::pair().expect("create datagram socket pair");

    // send with empty fd slice, receive without ancillary buffer
    a.send_fds(b"a", vec![]).expect("send zero file descriptors");
    let bytes = b.recv(&mut[0u8; 10]).expect("receive normally - without ancillary buffer");
    assert_eq!(bytes, 1);

    // send with empty fd slice, receive for empty fd slice
    a.send_fds(b"aa", vec![]).expect("send zero file descriptors");
    let mut rcvfd = Vec::with_capacity(0);

    let (bytes, fds) = b.recv_slice_fds(&mut[0u8; 10], &mut rcvfd).expect("receive with empty fd buffer");
    assert_eq!(bytes, 2);
    assert_eq!(fds, 0);

    // send without ancillary, receive for empty fd slice
    a.send(b"aaa").expect("send normally - without ancillary");
    let (bytes, fds) = b.recv_slice_fds(&mut[0u8; 10], &mut rcvfd).expect("receive with empty fd buffer");
    assert_eq!(bytes, 3);
    assert_eq!(fds, 0);

    // send with empty fd slice, receive with capacity
    a.send_fds(b"aaaa", Vec::new()).expect("send zero file descriptors");
    let mut fd_buf = Vec::with_capacity(3);
    let (bytes, fds) = b.recv_slice_fds(&mut[0u8; 10], &mut fd_buf).expect("receive with fd buffer");
    assert_eq!(bytes, 4);
    assert_eq!(fds, 0);
    assert_eq!(fd_buf.len(), 0);

    // send without ancillary, receive with capacity
    a.send(b"aaaaa").expect("send normally - without ancillary");
    let mut fd_buf = Vec::with_capacity(3);
    let (bytes, fds) = b.recv_slice_fds(&mut[0u8; 10], &mut fd_buf).expect("receive with fd buffer");
    assert_eq!(bytes, 5);
    assert_eq!(fds, 0);
    assert_eq!(fd_buf.len(), 0);
}

#[cfg_attr(not(any(target_os="illumos", target_os="solaris")), test)]
fn datagram_truncate_fds() 
{
    let (a, b) = UnixDatagram::pair().expect("create datagram socket pair");

    let c_a = a.try_clone().unwrap();

    // send some, receive without ancillary buffer
    c_a.send_fds(b"a", vec![OwnedFd::from(a)]).expect("send one fd");
    let bytes = b.recv(&mut[0u8; 10]).expect("receive normally - without ancillary buffer");
    assert_eq!(bytes, 1);

    // send some, receive with zero-length fd slice
    let (a, b) = UnixDatagram::pair().expect("create datagram socket pair");

    let c_a = a.try_clone().unwrap();
    let mut v = Vec::with_capacity(0);

    c_a.send_fds(b"aa", vec![OwnedFd::from(a)]).expect("send one fd");
    let (bytes, fds) = b.recv_slice_fds(&mut[0u8; 10], &mut v).expect("receive with empty fd buffer");
    assert_eq!((bytes, fds), (2, 0));

    // send four, receive two
    let (a, b) = UnixDatagram::pair().expect("create datagram socket pair");

    let (aa, bb) = UnixDatagram::pair().expect("create datagram socket pair");
    let (aaa, bbb) = UnixDatagram::pair().expect("create datagram socket pair");

    let a_fd = aa.as_raw_fd();
    let aa_fd = bb.as_raw_fd();
    let v = vec![OwnedFd::from(aa), OwnedFd::from(bb), OwnedFd::from(aaa), OwnedFd::from(bbb)];

    println!("{:?}", v);

    a
        .send_fds(
            b"aaa", 
            v
        )
        .expect("send four fds");
    let mut fd_buf = Vec::with_capacity(2);

    match b.recv_fds(&mut[0u8; 10], &mut fd_buf) {// receives to capacity or none
        Ok((3, 2)) => 
        {
            println!("{:?}", fd_buf);

            assert_eq!(fd_buf[0].as_raw_fd(), a_fd);
            assert_eq!(fd_buf[1].as_raw_fd(), aa_fd);
        }
        Ok((3, 0)) => 
            assert_eq!(fd_buf.len(), 0),
        // OpenBSD is sensical.
        Err(ref e) if e.raw_os_error() == Some(libc::EMSGSIZE) => 
            assert_eq!(fd_buf.len(), 0),
        Ok((bytes, fds)) => {
            panic!("received {} bytes and {} fds but expected 3 bytes and 2 or 0 fds", bytes, fds);
        }
        Err(e) => panic!("receive with smaller fd buffer failed: {}", e),
    }
}

#[cfg_attr(not(any(target_os="illumos", target_os="solaris")), test)]
fn stream_send_no_fds() {
    let (mut a, mut b) = UnixStream::pair().expect("create stream socket pair");

    // send with empty fd slice, receive without ancillary buffer
    a.send_fds(b"a", vec![]).expect("send zero file descriptors");
    let bytes = b.read(&mut[0u8; 10]).expect("read normally - without ancillary buffer");
    assert_eq!(bytes, 1);

    // send with empty fd slice, receive for empty fd slice
    a.send_fds(b"aa", vec![]).expect("send zero file descriptors");
    let (bytes, fds) = b.recv_slice_fds(&mut[0u8; 10], &mut vec![]).expect("receive with empty fd buffer");
    assert_eq!(bytes, 2);
    assert_eq!(fds, 0);

    // send without ancillary, receive for empty fd slice
    a.write(b"aaa").expect("write normally - without ancillary");
    let (bytes, fds) = b.recv_slice_fds(&mut[0u8; 10], &mut vec![]).expect("receive with empty fd buffer");
    assert_eq!(bytes, 3);
    assert_eq!(fds, 0);

    // send with empty fd slice, receive with capacity
    a.send_fds(b"aaaa", vec![]).expect("send zero file descriptors");
    let mut fd_buf = Vec::with_capacity(3);

    let (bytes, fds) = b.recv_slice_fds(&mut[0u8; 10], &mut fd_buf).expect("receive with fd buffer");
    assert_eq!(bytes, 4);
    assert_eq!(fds, 0);
    assert_eq!(fd_buf.len(), 0);

    // send without ancillary, receive with capacity
    a.write(b"aaaaa").expect("write normally - without ancillary");
    let mut fd_buf = Vec::with_capacity(3);
    let (bytes, fds) = b.recv_slice_fds(&mut[0u8; 10], &mut fd_buf).expect("receive with fd buffer");
    assert_eq!(bytes, 5);
    assert_eq!(fds, 0);
    assert_eq!(fd_buf.len(), 0);
}

#[cfg_attr(not(any(target_os="illumos", target_os="solaris")), test)]
fn stream_truncate_fds() {
    let (mut a, mut b) = UnixStream::pair().expect("create stream socket pair");

    let (aa, _bb) = UnixStream::pair().expect("create stream socket pair");

    // send some, receive without ancillary buffer
    a.send_fds(b"a", vec![OwnedFd::from(aa)]).expect("send one fd");
    let bytes = b.read(&mut[0u8; 10]).expect("read without ancillary buffer");
    assert_eq!(bytes, 1);

    // try to receive fds afterwards (this tests the OS more than this crate)
    b.set_nonblocking(true).expect("enable nonblocking");
    let error = b.recv_slice_fds(&mut[1], &mut Vec::with_capacity(2))
        .expect_err("won't receive fd later without any bytes waiting");
    assert_eq!(error.kind(), WouldBlock);

    // try to receive fds later when there is more data
    a.write(b"aa").expect("write normally - without ancillary");
    let (bytes, fds) = b.recv_slice_fds(&mut[0u8; 10], &mut Vec::with_capacity(2)).expect("receive with capacity");
    assert_eq!((bytes, fds), (2, 0));

    // send some, receive with zero-length fd slice
    let (aa, _bb) = UnixStream::pair().expect("create stream socket pair");

    a.send_fds(b"aaa", vec![OwnedFd::from(aa)]).expect("send one fd");
    let (bytes, fds) = b.recv_slice_fds(&mut[0u8; 10], &mut vec![]).expect("receive with empty fd buffer");
    assert_eq!((bytes, fds), (3, 0));

    // try to receive what was truncated, now that we received with ancillary buffer the first time
    let error = b.recv_slice_fds(&mut[1], &mut Vec::with_capacity(2))
        .expect_err("receive fd later without any bytes waiting");
    assert_eq!(error.kind(), WouldBlock);

    a.send_fds(b"aaaa", vec![]).expect("send empty fd slice");
    let mut fd_buf = Vec::with_capacity(4);
    let (bytes, fds) = b.recv_slice_fds(&mut[0u8; 10], &mut fd_buf).expect("receive with capacity");
    assert_eq!((bytes, fds, fd_buf.len()), (4, 0, 0));

    // send four, receive two
    let (aa, bb) = 
        UnixStream::pair().map(|(a, b)| (OwnedFd::from(a), OwnedFd::from(b))).expect("create stream socket pair");
    let (aaa, bbb) = 
        UnixStream::pair().map(|(a, b)| (OwnedFd::from(a), OwnedFd::from(b))).expect("create stream socket pair");

    let aa_fd = aa.as_raw_fd();
    let bb_fd = bb.as_raw_fd();

    a.send_fds(b"aaaaa", vec![aa, aaa, bb, bbb])
        .expect("send four fds");

    let mut fd_buf = Vec::with_capacity(2);
    match b.recv_fds(&mut[0u8; 10], &mut fd_buf) 
    {   // receives to capacity or nothing
        Ok((5, 2)) => 
        {
            println!("a={}, b={}, received={:?}", aa_fd, bb_fd, fd_buf);

            assert_eq!(fd_buf[0].as_raw_fd(), aa_fd);
            assert_eq!(fd_buf[1].as_raw_fd(), bb_fd);
        },
        Ok((5, 0)) => 
        {
            assert_eq!(fd_buf.len(), 0);
            if cfg!(any(target_os="linux", target_os="android", target_vendor="apple")) {
                panic!("all FDs were dropped, which is unexpected for {}", OS);
            }
        }
        // OpenBSD is sensical.
        Err(ref e) if e.raw_os_error() == Some(libc::EMSGSIZE) => 
            assert_eq!(fd_buf.len(), 0),
        Ok((bytes, fds)) => {
            panic!("received {} bytes and {} fds but expected 5 bytes and 2 or 0 fds", bytes, fds);
        }
        Err(e) => panic!("receiving with too small ancillary buffer failed: {}", e),
    }
    
    if cfg!(any(target_os="linux", target_os="android")) 
    {
        let (aa, _bb) = UnixStream::pair().map(|(a, b)| (OwnedFd::from(a), OwnedFd::from(b))).expect("create stream socket pair");

        let aa_fd = aa.as_raw_fd();

        // try to receive what was truncated
        a.send_fds(b"aaaaaa", vec![aa]).expect("send one more fd"); // fails on freebsd

        let mut fd_buf = Vec::with_capacity(6);
        let (bytes, fds) = b.recv_fds(&mut[0u8; 10], &mut fd_buf).expect("receive with capacity");
        assert_eq!((bytes, fds), (6, 1));
        assert_eq!(fd_buf[0].as_raw_fd(), aa_fd);
        assert_eq!(fd_buf.len(), 1);
    }

    // TODO test receiving what was sent in one go with two recvmsg()s without sending more between
    // TODO test not receiving all bytes either.
}

#[cfg_attr(not(any(target_os="illumos", target_os="solaris")), test)]
fn datagram_pass_one_fd() 
{
    let (a, b) = UnixDatagram::pair().expect("create datagram socket pair");
    
    let (aa, bb) = UnixDatagram::pair().map(|(a, b)| (OwnedFd::from(a), b)).expect("create stream socket pair");

    let aa_fd = aa.as_raw_fd();

    a.send_fds(b"", vec![aa]).expect("send one file descriptor");
    let mut fd_buf = Vec::with_capacity(3);

    let (bytes, fds) = b.recv_fds(&mut[0u8; 10], &mut fd_buf)
        .expect("receive with ancillary buffer");
    assert_eq!(bytes, 0);
    assert_eq!(fds, 1);

    let received = UnixDatagram::from(fd_buf.remove(0));

    received.send(b"got it").expect("send from received fd");
    let bytes = bb.recv(&mut[0u8; 10]).expect("receive datagram sent from received fd");
    assert_eq!(bytes, 6);
    assert_eq!(received.as_raw_fd(), aa_fd);
}

#[cfg_attr(not(any(target_os="illumos", target_os="solaris")), test)]
fn datagram_pass_two_receive_one() 
{
    //! Tests somewhat that glibc's 64bit minimum payload length is handled
    let (a, b) = UnixDatagram::pair().expect("create datagram socket pair");
    let (aa, bb) = UnixDatagram::pair().map(|(a, b)| (OwnedFd::from(a), OwnedFd::from(b))).expect("create stream socket pair");
    let aa_fd = aa.as_raw_fd();

    a.send_fds(b"", vec![aa, bb]).expect("send one file descriptor");

    let mut fd_buf = Vec::with_capacity(1);
    let (bytes, fds) = b.recv_fds(&mut[0u8; 10], &mut fd_buf)
        .expect("receive with ancillary buffer");
    assert_eq!(bytes, 0);
    assert_eq!(fds, 1);
    assert_eq!(fd_buf.remove(0).as_raw_fd(), aa_fd);

    b.send_fds(b"nothing", vec![]).expect("send another datagram with no fds");
    let mut fd_buf = Vec::with_capacity(1);
    let (bytes, fds) = a.recv_slice_fds(&mut[0u8; 10], &mut fd_buf)
        .expect("receive with ancillary buffer");
    assert_eq!(bytes, "nothing".len());
    assert_eq!(fds, 0);
}

#[cfg_attr(not(any(target_os="illumos", target_os="solaris")), test)]
fn datagram_pass_two_receive_two() 
{
    //! Tests somewhat that glibc's 64bit minimum payload length is handled
    let (a, b) = UnixDatagram::pair().expect("create datagram socket pair");
    let (aa, bb) = UnixDatagram::pair().map(|(a, b)| (OwnedFd::from(a), OwnedFd::from(b))).expect("create stream socket pair");
    let aa_fd = aa.as_raw_fd();

    a.send_fds(b"", vec![aa, bb]).expect("send one file descriptor");

    let mut fd_buf = Vec::with_capacity(2);
    let (bytes, fds) = b.recv_fds(&mut[0u8; 64], &mut fd_buf)
        .expect("receive with ancillary buffer");
    assert_eq!(bytes, 0);
    assert_eq!(fds, 2);
    assert_eq!(fd_buf.remove(0).as_raw_fd(), aa_fd);
}

#[cfg_attr(not(any(target_os="illumos", target_os="solaris")), test)]
fn datagram_pass_two_receive_two_ansc_bouns_check() 
{
    use uds_fork::{Ancillary, AncillaryBuf};

    let (a, b) = UnixDatagram::pair().expect("create datagram socket pair");
    let (aa, bb) = UnixDatagram::pair().map(|(a, b)| (OwnedFd::from(a), OwnedFd::from(b))).expect("create stream socket pair");
    let aa_fd = aa.as_raw_fd();

    a.send_fds(b"", vec![aa, bb]).expect("send one file descriptor");

    let mut fd_buf = Vec::with_capacity(2);

    let mut ancillary_buf = 
        AncillaryBuf::with_fd_capacity(fd_buf.capacity()).unwrap();    

    let (num_bytes, ancillary) = 
        Ancillary::recv_ancillary(&b, None, 0, &mut[IoSliceMut::new(&mut[0u8; 64])], &mut ancillary_buf).unwrap();

    let msg_truc = ancillary.message_truncated();

    let mut i = ancillary.into_iter();
    let AncillaryItem::Fds(fds) = i.next().unwrap().unwrap()
        else { panic!("expected Fds") };

    let (cap, len) = (fd_buf.capacity(), fd_buf.len());

    let can_keep = fds.len().min(cap - len);

    for (ofd, _) in fds.into_iter().zip(0..can_keep) 
    {
        #[cfg(any(target_vendor="apple", target_os="freebsd"))] 
        {
            // set cloexec
            // This is necessary on FreeBSD as MSG_CMSG_CLOEXEC
            // appears to have no effect.
            // FIXME this should be done in a separate iteration
            // when the fds are received, and not after user code
            // has had a chance to run.
            // SAFETY: It's safe to create FdSlice twice from valid values. The values are valid.   
            let _ = set_cloexec(&ofd, true);

            
        }

        fd_buf.push( ofd );
    }

    assert_eq!(msg_truc, false);
    assert_eq!(num_bytes, 0);
    assert_eq!(fd_buf.len(), 2);
    assert_eq!(fd_buf.remove(0).as_raw_fd(), aa_fd);
    assert_eq!(i.get_msg_controllen(), i.get_msg_ctrl_len_read());
}

#[cfg_attr(not(any(target_os="illumos", target_os="solaris")), test)]
fn datagram_separate_payloads() 
{
    let (a, b) = UnixDatagram::pair().expect("create datagram socket pair");

    // send one with then one without
    unsafe{ a.send_fds_raw(b"_", &[a.as_raw_fd()]).expect("send datagram with one fd") };
    a.send(b"").expect("send a second datagram, wiithout fd");

    let mut fd_buf = Vec::<OwnedFd>::with_capacity(2);
    
    let (bytes, fds) = b.recv_fds(&mut[0u8; 1], &mut fd_buf).expect("receive fds");
    
    assert_eq!(bytes, 1);
    assert_eq!(fds, 1);
    assert_eq!(fd_buf.len(), 1);
    
    fd_buf.clear();

    let (bytes, fds) = b.recv_fds(&mut[0u8; 1], &mut fd_buf).expect("receive fds");
    assert_eq!(bytes, 0);
    assert_eq!(fds, 0);

    // send twice
    unsafe { a.send_fds_raw(b"", &[a.as_raw_fd(), a.as_raw_fd()]).expect("send two fds") }; 
    unsafe { a.send_fds_raw(b"", &[b.as_raw_fd(), b.as_raw_fd()]).expect("sent two fds again") };

    for _ in 0..2 
    {
        let mut fd_buf = [None, None, None];
        let (bytes, fds) = b.recv_slice_fds(&mut[0u8; 3], &mut fd_buf).expect("receive fds");
        assert_eq!(bytes, 0);
        assert_eq!(fds, 2);
        assert!(fd_buf[..2].iter().all(|fd| fd.is_some() == true ));
        assert_eq!(fd_buf[2].is_none(), true);
        
        if fd_buf[0].as_ref().unwrap().as_raw_fd() != a.as_raw_fd()  &&  fd_buf[0].as_ref().unwrap().as_raw_fd() != b.as_raw_fd()
        {
            println!("not eq");
        }
    }
}

#[cfg_attr(not(any(target_os="illumos", target_os="solaris")), test)]
fn unconnected_datagrams() 
{
    let dir = make_temp_dir_no_file();

    let p1 = dir.path().join("unconnected_send.socket");

    let p2 = dir.path().join("unconnected_recv.socket");

    let send = UnixDatagram::bind(&p1).expect("create first datagram socket");
    let recv = UnixDatagram::bind(&p2).expect("create second datagram socket");
    let unbound = UnixDatagram::unbound().expect("create unbound datagram socket");
    let unbound_fd = unbound.as_raw_fd();

    let addr_send = UnixSocketAddr::new(p1.as_os_str().to_str().unwrap()).unwrap();
    let addr_recv = UnixSocketAddr::new(p2.as_os_str().to_str().unwrap()).unwrap();
   

    let mut byte_buf = [0; 20];
    let mut fd_buf = Vec::with_capacity(20);

    send.send_fds_to(b"next from this", vec![OwnedFd::from(unbound)], &addr_recv)
        .expect("send datagram to address");
    assert_eq!(
        recv.recv_fds_from(&mut byte_buf, &mut fd_buf).expect("receive with addr"),
        (14, 1, addr_send)
    );
    assert_eq!(&byte_buf, b"next from this\0\0\0\0\0\0");
    assert_eq!(fd_buf.len(), 1);
    assert_eq!(fd_buf[0].as_raw_fd(), unbound_fd);
    
    let received = UnixDatagram::from(fd_buf.remove(0));
    assert_eq!(
        received.local_addr().expect("get unix domain address of received socket").as_pathname(),
        None
    );

    received.send_fds_to(
        b"where I came from",
        vec![OwnedFd::from(send), OwnedFd::from(recv)],
        &addr_recv
    ).expect("send datagram from unbound to bound");

}

#[cfg_attr(not(any(target_os="illumos", target_os="solaris")), test)]
/// a just-to-be-absolutely-sure test
fn stream_fd_order() {
    let (a, b) = UnixStream::pair().expect("create stream socket pair");
    let (aa, bb) = UnixStream::pair().expect("create stream socket pair");

    let aa_fd = aa.as_raw_fd();
    let bb_fd = bb.as_raw_fd();

    a.send_fds(b"2", vec![OwnedFd::from(aa), OwnedFd::from(bb)]).expect("send two fds");

    let mut fd_buf = Vec::with_capacity(2);
    let (bytes, fds) = b.recv_fds(&mut[0u8; 3], &mut fd_buf).expect("receive fds");
    assert_eq!(bytes, 1);
    assert_eq!(fds, 2);
    
    let mut received_a = UnixStream::from(fd_buf.remove(0));
    let mut received_b = UnixStream::from(fd_buf.remove(0));

    let _ = received_a.set_nonblocking(true);
    let _ =received_b.set_nonblocking(true);

    received_a.write(b"I'm a").expect("write via transferred fd");
    received_b.read(&mut[0u8; 10]).expect("read bytes sent from received fd[0] (`a`)");
    
    received_b.write(b"I'm b").expect("write via transferred fd");
    received_a.read(&mut[0u8; 10]).expect("read bytes sent from received fd[1] (`b`)");
    
    assert_eq!(received_a.as_raw_fd(), aa_fd);
    assert_eq!(received_b.as_raw_fd(), bb_fd);
}

#[cfg_attr(not(any(target_os="illumos", target_os="solaris")), test)]
fn many_fds() {
    let (a, b) = UnixStream::pair().expect("create stream socket pair");
    // only odd numbers cause difference between CMSG_SPACE() and CMSG_LEN(), and only on 64bit.
    let mut fds = Vec::<OwnedFd>::with_capacity(99);
    let mut fds_fd = Vec::<i32>::with_capacity(99);
        /*(0..99)
            .map(|_|
                {
                    let p = UnixStream::pair().unwrap();
                    [OwnedFd::from(p.0), OwnedFd::from(p.1)]
                }
            )
            .flatten()
            .collect::<Vec<OwnedFd>>();*/

            
    for (i, (fd, fdr)) in fds.iter_mut().zip(fds_fd.iter_mut()).enumerate() 
    {
        match b.try_clone() 
        {
            Ok(clone) => 
            {
                *fdr = clone.as_raw_fd();
                *fd = OwnedFd::from(clone);
            }
            Err(e) => panic!("failed to clone the {}nt fd: {}", i+1, e),
        }
    }
    a.send_fds(&b"99"[..], fds).expect("send 99 fds");

    let mut recv_buf = [0; 10];
    let mut recv_fds = Vec::with_capacity(200);

    b.recv_fds(&mut recv_buf, &mut recv_fds).expect("receive 99 of 200 fds");
    assert_eq!(recv_fds.len(), fds_fd.len());

    for (_, (received, fdst)) in recv_fds.iter().zip(fds_fd.iter()).enumerate()
    {
        assert_eq!(received.as_raw_fd(), *fdst);
    }
}

#[cfg_attr(
    not(any(
        target_vendor="apple", // flaky; timed out on https://travis-ci.com/github/tormol/uds/jobs/384395118
        target_os="illumos", target_os="solaris"
    )),
    test
)]
#[cfg_attr(
    any(target_vendor="apple", target_os="illumos", target_os="solaris"),
    allow(unused)
)]
fn closed_before_received() {
    let (a, b) = UnixDatagram::pair().expect("create datagram socket pair");
    let (aa, bb) = UnixDatagram::pair().expect("create datagram socket pair");
    let aa_fd = aa.as_raw_fd();

    a.send_fds(&[], vec![OwnedFd::from(aa)]).expect("send fd");
    let _ = a; // drop a
    let mut fd_buf = Vec::with_capacity(1);

    let (_, fds) = b.recv_fds(&mut[], &mut fd_buf).expect("receive fd that is already closed");
    assert_eq!(fds, 1);
    assert_eq!(fd_buf.len(), 1);
    let rcv = fd_buf.remove(0);
    assert_eq!(rcv.as_raw_fd(), aa_fd);

    let a = UnixDatagram::from(rcv);
    a.send(b"still alive").expect("send from fd closed before received");
    bb.recv(&mut[0u8; 16]).expect("receive what was sent from sent fd");
}

#[cfg_attr(any(target_os="illumos", target_os="solaris"), test)]
#[cfg_attr(not(any(target_os="illumos", target_os="solaris")), allow(unused))]
fn errors_on_solaris() 
{
    let (a, b) = UnixDatagram::pair().expect("create datagram socket pair");
    a.send_fds(b"0", vec![]).expect("send empty fd slice");

    let (aa, bb) = UnixDatagram::pair().expect("create datagram socket pair");

    let err = a.send_fds(b"1", vec![OwnedFd::from(aa)]).expect_err("send fd");
    assert!(format!("{}", err).contains("not implemented"));

    b.set_nonblocking(true).expect("make nonblocking");
    b.recv_slice_fds(&mut[0; 16], &mut vec![]).expect("receive with empty fd buffer");

    let err = b.recv_slice_fds(&mut[0; 16], &mut Vec::with_capacity(4))
        .expect_err("receive with fd capacity");
    assert!(format!("{}", err).contains("not implemented"));
}
