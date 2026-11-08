#![cfg(windows)]
mod common;

use std::{io::IoSliceMut};

use uds_fork::{RecvFlags, WindowsUnixListener, WindowsUnixStream};
use windows_sys::Win32::Networking::WinSock::{AF_UNIX, SOCK_STREAM};

use crate::common::make_temp_dir;

#[test]
fn test_listener()
{
    let (path, _dir) = make_temp_dir("server1.sock");

    let _wul = WindowsUnixListener::bind(path).unwrap();
}

#[test]
fn test_listener_blocking()
{
    let (path, _dir) = make_temp_dir("server2.sock");

    let wul = WindowsUnixListener::bind(path).unwrap();

    wul.set_nonblocking(true).unwrap();
    wul.set_nonblocking(false).unwrap();

}

#[test]
fn test_pair1()
{
    let (s1, s2) = WindowsUnixStream::pair().unwrap();

    let data: [u8; 4] = [1,2,3,4];

    let s1n = s1.send(&data).unwrap();
    assert_eq!(s1n, data.len());

    let mut rcv_data = [0_u8; 10];
    let s2n = s2.recv(&mut rcv_data).unwrap();
    assert_eq!(s1n, s2n);
    assert_eq!(&data, &rcv_data[..s2n]);

    let s2n = s2.send(&data).unwrap();
    assert_eq!(s2n, data.len());

    let mut rcv_data = [0_u8; 10];
    let s1n = s1.recv(&mut rcv_data).unwrap();
    assert_eq!(s1n, s2n);
    assert_eq!(&data, &rcv_data[..s1n]);
}

#[test]
fn test_listener_send_recv()
{
    let (path, _dir) = make_temp_dir("server3.sock");

    let wul = WindowsUnixListener::bind(&path).unwrap();

    let client = WindowsUnixStream::connect(&path).unwrap();

    let (accp_client, rem_addr) = wul.accept_unix_addr().unwrap();

    println!("accepted connection: {}", rem_addr);
    assert_eq!(rem_addr.to_string().as_str(), "unnamed");

    let sa_fam = uds_fork::get_socket_family(&accp_client).unwrap();
    let sa_type = uds_fork::get_socket_type(&accp_client).unwrap();
    assert_eq!(sa_fam, AF_UNIX);
    assert_eq!(sa_type, SOCK_STREAM);

    println!("{} {}", sa_fam, sa_type);

    let data: [u8; 4] = [1,2,3,4];

    let srv_n = client.send(&data).unwrap();
    assert_eq!(srv_n, data.len());

    let mut rcv_data = [0_u8; 10];
    let rcv_n = accp_client.recv(&mut rcv_data).unwrap();
    assert_eq!(srv_n, rcv_n);
    assert_eq!(&data, &rcv_data[..srv_n]);


    // accp_client -> client
     let data: [u8; 4] = [5,6,7,8];

    let srv_n = accp_client.send(&data).unwrap();
    assert_eq!(srv_n, data.len());

    let mut rcv_data = [0_u8; 10];
    let rcv_n = client.recv(&mut rcv_data).unwrap();
    assert_eq!(srv_n, rcv_n);
    assert_eq!(&data, &rcv_data[..srv_n]);
}


#[test]
fn test_listener_send_recv_vectored()
{
    let (path, _dir) = make_temp_dir("server4.sock");;

    let wul = WindowsUnixListener::bind(&path).unwrap();

    let a = WindowsUnixStream::connect(&path).unwrap();

    let (b, rem_addr) = wul.accept_unix_addr().unwrap();

    println!("accepted connection: {}", rem_addr);
    assert_eq!(rem_addr.to_string().as_str(), "unnamed");


    a.send(b"undivided").unwrap();
    let mut array = [b'-'; 10];
    assert_eq!(b.recv_vectored(&mut[IoSliceMut::new(&mut array)]).unwrap().0, 9);
    assert_eq!(&array, b"undivided-");

    a.send(b"split me").unwrap();
    let (mut array_1, mut array_2) = ([4; 4], [4; 4]);
    let mut buffers = [IoSliceMut::new(&mut array_1), IoSliceMut::new(&mut array_2)];
    assert_eq!(b.recv_vectored(&mut buffers).unwrap(), (8, RecvFlags(0)));
    assert_eq!(&array_1, b"spli");
    assert_eq!(&array_2, b"t me");

    a.send(b"truncate me").unwrap();
    let (mut array_1, mut array_2) = ([4; 4], [4; 4]);
    let mut buffers = [
        IoSliceMut::new(&mut[]),
        IoSliceMut::new(&mut array_1[..1]),
        IoSliceMut::new(&mut[]),
        IoSliceMut::new(&mut array_2),
    ];
    assert_eq!(b.recv_vectored(&mut buffers).unwrap(), (5, RecvFlags(0))); 
    assert_eq!(&array_1[..1], b"t");
    assert_eq!(&array_2, b"runc");

    a.send(b"dont").unwrap();
    a.send(b"mix!").unwrap();
    let mut buffers = [IoSliceMut::new(&mut array_1), IoSliceMut::new(&mut array_2)];
    assert_eq!(b.recv_vectored(&mut buffers).unwrap(), (8, RecvFlags(0)));
    assert_eq!(&array_1, b"ate ");
    assert_ne!(&array_1, b"medo");


}