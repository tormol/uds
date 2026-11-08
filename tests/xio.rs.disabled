#![cfg(all(feature="xio-rs", not(target_os = "windows")))]

use std::{fs, time::Duration};

use uds_fork::{UnixSeqpacketConn, UnixSeqpacketListener};
use xio_rs::{EsInterface, XioChannel, XioEventDecoder, XioEventUid, XioEventsInterface, XioPollRegistry, XioTimeout};

mod common;

use crate::common::make_temp_dir;

fn test_socket<ESS: EsInterface>()
{
    let mut reg = XioPollRegistry::<ESS>::new().unwrap();

    let mut event_buf = XioPollRegistry::<ESS>::allocate_events(1.try_into().unwrap());

    let (sock_path, _dir) = make_temp_dir("test123.sock");

    let mut listener = UnixSeqpacketListener::bind(&sock_path).unwrap();

    let ev = XioEventUid::manual(1);
    reg.get_registry().en_register(&mut listener, ev, XioChannel::INPUT).unwrap();

    let send_buf = &[1,2,3,4,5,6,7,8,9];

    let handle0 = 
        std::thread::spawn(move ||
            {
                std::thread::sleep(Duration::from_millis(700));

                let s = UnixSeqpacketConn::connect(&sock_path).unwrap();

                s.send(&[1,2,3,4,5,6,7,8,9]).unwrap();

                std::thread::sleep(Duration::from_millis(100));
            }
        );

    reg.poll(&mut event_buf, XioTimeout::Timeout(Duration::from_secs(1))).unwrap();

    assert_eq!(event_buf.ev_len(), 1);
    println!("{:?}", event_buf.ev_as_slice()[0]);

    assert_eq!(event_buf.ev_as_slice()[0].readable(), true);
    assert_eq!(event_buf.ev_as_slice()[0].get_uid(), ev);

    let (conn, addr) = listener.accept_unix_addr().unwrap();

    println!("{}", addr);

    let mut buf = vec![0_u8; 20];
    let n = conn.recv(&mut buf).unwrap();

    assert_eq!(n, send_buf.len());

    handle0.join().unwrap();
}

#[cfg(target_os = "linux")]
#[test]
fn test_socket_epoll()
{
    use xio_rs::XioEsEpoll;

    test_socket::<XioEsEpoll>();
}

#[cfg(unix)]
#[test]
fn test_socket_poll()
{
    use xio_rs::XioEsPoll;

    test_socket::<XioEsPoll>();
}

#[cfg(any(
    target_os = "freebsd",
    target_os = "dragonfly",
    target_os = "macos",
    target_os = "ios",
    target_os = "tvos",
    target_os = "visionos",
    target_os = "watchos",
))]
#[test]
fn test_socket_kqueue()
{
    use xio_rs::XioEsKqueue;

    test_socket::<XioEsKqueue>();
}

fn test_socket_wrap<ESS: EsInterface>()
{
    let mut reg = XioPollRegistry::<ESS>::new().unwrap();

    let mut event_buf = XioPollRegistry::<ESS>::allocate_events(1.try_into().unwrap());

    let (sock_path, _dir) = make_temp_dir("test123.sock");

    let listener = UnixSeqpacketListener::bind(&sock_path).unwrap();

    let ev = XioEventUid::manual(1);
    let mut listener = 
        reg.get_registry()
            .en_register_wrap(listener, ev, XioChannel::INPUT).unwrap();

    let send_buf = &[1,2,3,4,5,6,7,8,9];

    let handle0 = 
        std::thread::spawn(move ||
            {
                std::thread::sleep(Duration::from_millis(700));

                let s = UnixSeqpacketConn::connect(&sock_path).unwrap();

                s.send(&[1,2,3,4,5,6,7,8,9]).unwrap();

                std::thread::sleep(Duration::from_millis(100));
            }
        );

    reg.poll(&mut event_buf, XioTimeout::Timeout(Duration::from_secs(1))).unwrap();

    assert_eq!(event_buf.ev_len(), 1);
    println!("{:?}", event_buf.ev_as_slice()[0]);

    assert_eq!(event_buf.ev_as_slice()[0].readable(), true);
    assert_eq!(event_buf.ev_as_slice()[0].get_uid(), ev);

    let (conn, addr) = listener.inner().accept_unix_addr().unwrap();

    println!("{}", addr);

    let mut buf = vec![0_u8; 20];
    let n = conn.recv(&mut buf).unwrap();

    assert_eq!(n, send_buf.len());

    handle0.join().unwrap();

}

#[cfg(target_os = "linux")]
#[test]
fn test_socket_wrap_epoll()
{
    use xio_rs::XioEsEpoll;

    test_socket_wrap::<XioEsEpoll>();
}

#[cfg(unix)]
#[test]
fn test_socket_wrap_poll()
{
    use xio_rs::XioEsPoll;

    test_socket_wrap::<XioEsPoll>();
}

#[cfg(any(
    target_os = "freebsd",
    target_os = "dragonfly",
    target_os = "macos",
    target_os = "ios",
    target_os = "tvos",
    target_os = "visionos",
    target_os = "watchos",
))]
#[test]
fn test_socket_wrap_kqueue()
{
    use xio_rs::XioEsKqueue;

    test_socket_wrap::<XioEsKqueue>();
}