#![cfg(unix)]


use std::{io::IoSliceMut, os::{fd::OwnedFd, unix::net::UnixDatagram}};

use uds_fork::{AncillaryBuf, AncillaryItem, UnixSeqpacketConn, UnixSeqpacketListener};



fn main()
{
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("seqpkt.sock");

    let listener = UnixSeqpacketListener::bind(&path).unwrap();

    let conn = UnixSeqpacketConn::connect(&path).unwrap();

    let (client, _client_addr) = listener.accept().unwrap();

    let (a, _b) = UnixDatagram::pair().unwrap();

    let n = conn.send_fds(b"test", vec![OwnedFd::from(a)]).unwrap();

    println!("send_fds: {}", n);

    let mut ancillary_buf = AncillaryBuf::with_fd_capacity(2).unwrap(); 

    let mut msg_buf = [0_u8; 64]; 

    let (_n, ancillary) = 
        client
            .recv_vectored_ancillary(0, &mut [IoSliceMut::new(&mut msg_buf)], &mut ancillary_buf)
            .unwrap();   

    let msg_truc = ancillary.message_truncated();

    println!("is truncated: {}", msg_truc);

    for message in ancillary 
    {
        if let AncillaryItem::Fds(fds) = message.unwrap() 
        {
            println!("ancillary FD: {:?}", fds);
        }
    }
}

#[cfg(not(unix))]
fn main()
{}