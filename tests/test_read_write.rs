#![cfg(all(not(target_vendor="apple"), target_family = "unix"))]

use std::io::{Write, Read};

use uds_fork::{UnixSeqpacketConn, UnixSeqpacketListener};

use crate::common::make_temp_dir;

mod common;

fn read_string<S: Read>(stream: &mut S) -> String
{
    //let mut buf = [0_u8; 48];

    let mut s = String::new();

    stream.read_to_string(&mut s).unwrap();

    //stream.read(&mut buf).unwrap();


    //return str::from_utf8(&buf).unwrap().to_string();
    return s;
}

#[test]
fn test_io_read_write()
{
    let (path, _dir) = make_temp_dir("seqpacketr1.exists.socket");

    let listener = UnixSeqpacketListener::bind(&path).unwrap();
    let mut conn = UnixSeqpacketConn::connect(&path).unwrap();

    let (mut client, _addr) = listener.accept().unwrap();

    let test_str = "test string 123";

    write!(&mut client, "{}", test_str).unwrap();

    let rcv_test_str = read_string(&mut conn);


    println!("recv: {}", rcv_test_str);

    assert_eq!(rcv_test_str.as_str(), test_str);
}

#[test]
fn test_io_read_write_not_trunc()
{
    let (path, _dir) = make_temp_dir("seqpacketr1.exists.socket");

    let listener = UnixSeqpacketListener::bind(&path).unwrap();
    let mut conn = UnixSeqpacketConn::connect(&path).unwrap();

    let (mut client, _addr) = listener.accept().unwrap();

    let test_str = 
"値ケソム我極ね画訂キ見欧きお選灰エヲ無七ノヒ坂焉ょドけり創想ぞ己変浜げンフ岳送かイ表料後ひろの絶況意亡夜ぶばイし。明せひスね文皇ウロトツ授気ヌモケ母間ぐるばげ市推守ッ真上つ半業ひ広13止クヨ組4載エチメ督審ごょぱ賄装神ケフハ像59場エ倫秀めげぼ並更速んなゆり公名午もてを。争朝テ祭契のぽトり情歩ケホクソ全暮ルレヲラ法野白き変能ぞわぽえ爆米ネヤ小2鉄計ノ払67総団垣猛スい。";

    write!(&mut client, "{}", test_str).unwrap();

    let rcv_test_str = read_string(&mut conn);


    println!("recv: {}", rcv_test_str);

    assert_eq!(rcv_test_str.as_str(), test_str);
}