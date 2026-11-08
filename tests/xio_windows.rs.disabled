#![cfg(all(feature="xio-rs", target_os = "windows"))]

use std::time::Duration;

use uds_fork::{WindowsUnixListener, WindowsUnixStream};
use xio_rs::{EsInterface, XioChannel, XioEventDecoder, XioEventUid, XioEventsInterface, XioPollRegistry, XioTimeout};

mod common;

fn test_socket<ESS: EsInterface>()
{   
    let (sock_path, _dir) = make_temp_dir("server3.sock");

    let mut reg = XioPollRegistry::<ESS>::new().unwrap();

    let mut event_buf = XioPollRegistry::<ESS>::allocate_events(1.try_into().unwrap());

    let mut listener = WindowsUnixListener::bind(sock_path).unwrap();

    let ev = XioEventUid::manual(1);
    reg.get_registry().en_register(&mut listener, ev, XioChannel::INPUT).unwrap();

    let send_buf = &[1,2,3,4,5,6,7,8,9];

    let handle0 = 
        std::thread::spawn(move ||
            {
                std::thread::sleep(Duration::from_millis(700));

                let s = WindowsUnixStream::connect(&sock_path).unwrap();

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


#[cfg(windows)]
#[test]
fn test_socket_iocp()
{
    use xio_rs::windows::XioEsIocp;

    test_socket::<XioEsIocp>();
}

#[cfg(windows)]
#[test]
fn test_socket_wfmo()
{
    use xio_rs::XioEsWfmo;

    test_socket::<XioEsWfmo>()
}
