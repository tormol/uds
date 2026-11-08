#![cfg(all(not(target_vendor="apple"), target_family = "unix"))]

use std::{path::PathBuf, thread};

use tempfile::TempDir;
use uds_fork::{UnixSeqpacketConn, UnixSeqpacketListener};


fn make_temp_dir(path: &str) -> (PathBuf, TempDir)
{
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(path);

    return (path, dir);
}

#[test]
fn test_incoming1() 
{
    let snd_buf: [u8; 4] = [1, 2, 3, 4];

    let (path, _dir) = make_temp_dir("server.sock");

    let listener = UnixSeqpacketListener::bind(&path).unwrap();

    let handle0 = 
        thread::spawn(move ||
            {
                let res_conn =  UnixSeqpacketConn::connect(&path);

                println!("{:?}", res_conn);

                let conn = res_conn.unwrap();

                let n = conn.send(&snd_buf).unwrap();
                assert_eq!(n, snd_buf.len());
            }
        );


    for stream in listener.incoming() 
    {
        match stream 
        {
            Ok(stream) => 
            {
                println!("accepted!");

                let mut buf: [u8; 10] = [8_u8; 10];

                let n = stream.recv(&mut buf).unwrap();
                assert_eq!(n, snd_buf.len());

                assert_eq!(&buf[..n], &snd_buf);

                break;
            },
            Err(_err) => 
            {
                break;
            }
        }
    }

    handle0.join().unwrap();

    return;
}
