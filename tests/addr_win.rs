#![cfg(target_family = "windows")]
extern crate uds_fork;

use std::mem;

use uds_fork::{UnixSocketAddr, UnixSocketAddrRef};

pub use windows_sys::Win32::Networking::WinSock::{SOCKADDR_STORAGE as sockaddr_storage, ADDRESS_FAMILY as sa_family_t, SOCKADDR_UN as sockaddr_un,  SOCKADDR as sockaddr, AF_UNIX};

#[test]
fn from_raw_path() 
{
    let path_addr = UnixSocketAddr::from_path("/tmp/path.sock").unwrap();
    let a = 
    unsafe 
    {
        let (raw_addr, raw_len) = path_addr.as_raw();
        UnixSocketAddr::from_raw(raw_addr as *const sockaddr_un as *const sockaddr, raw_len)
    }
    .expect("from_raw() accepts from_path()");

    assert_eq!(a, path_addr);
    assert!(a.is_path());
}

#[test]
fn from_ref_path() 
{
    
    let path_addr = UnixSocketAddr::from_path("/tmp/path.sock").unwrap();
    let a = 
    unsafe 
    {
        let (raw_addr, raw_len) = path_addr.as_raw();
        let ref_addr: &sockaddr = mem::transmute(raw_addr);

        UnixSocketAddr::from_ref(ref_addr, raw_len)
    }
    .expect("from_raw() accepts from_path()");
    
    assert_eq!(a, path_addr);
    assert!(a.is_path());
}

#[test]
fn from_sockaddr_storage_path() 
{
    
    let path_addr = UnixSocketAddr::from_path("/tmp/path.sock").unwrap();
    let a = 
    unsafe 
    {
        let (raw_addr, raw_len) = path_addr.as_raw();
        let ref_addr: &sockaddr_storage = mem::transmute(raw_addr);

        UnixSocketAddr::from_sockaddr_storage(ref_addr, raw_len)
    }
    .expect("from_raw() accepts from_path()");
    
    assert_eq!(a, path_addr);
    assert!(a.is_path());
}

#[test]
fn from_raw_max_len_path() 
{
    let path = "R".repeat(UnixSocketAddr::max_path_len());
    let path_addr = UnixSocketAddr::from_path(path.as_str()).unwrap();
    let a = 
    unsafe 
    {
        let (raw_addr, raw_len) = path_addr.as_raw();
        UnixSocketAddr::from_raw(raw_addr as *const sockaddr_un as *const sockaddr, raw_len)
    }
    .expect("from_path() is valid");

    assert_eq!(a, path_addr);
    assert!(a.is_path());
}

#[test]
fn from_ref_max_len_path() 
{
    let path = "R".repeat(UnixSocketAddr::max_path_len());
    let path_addr = UnixSocketAddr::from_path(path.as_str()).unwrap();
    let a = 
    unsafe 
    {
        let (raw_addr, raw_len) = path_addr.as_raw();
        let ref_addr: &sockaddr = mem::transmute(raw_addr);

        UnixSocketAddr::from_ref(ref_addr, raw_len)
    }
    .expect("from_path() is valid");

    assert_eq!(a, path_addr);
    assert!(a.is_path());
}

#[test]
fn from_sockaddr_storage_max_len_path() 
{
    let path = "R".repeat(UnixSocketAddr::max_path_len());
    let path_addr = UnixSocketAddr::from_path(path.as_str()).unwrap();
    let a = 
    unsafe 
    {
        let (raw_addr, raw_len) = path_addr.as_raw();
        let ref_addr: &sockaddr_storage = mem::transmute(raw_addr);

        UnixSocketAddr::from_sockaddr_storage(ref_addr, raw_len)
    }
    .expect("from_path() is valid");

    assert_eq!(a, path_addr);
    assert!(a.is_path());
}

#[test]
fn from_raw_too_long_path() 
{
    #[repr(C)]
    struct TooLong 
    {
        fam: sa_family_t,
        path: [u8; 300],
    }
    let path_addr = 
        TooLong 
        {
            fam: AF_UNIX as sa_family_t,
            path: [b'o'; 300],
        };

    unsafe 
    {
        let raw_addr = &path_addr as *const TooLong as *const sockaddr;
        UnixSocketAddr::from_raw(raw_addr, size_of::<TooLong>() as _)
    }
    .expect_err("too long");
}

#[test]
fn from_ref_too_long_path() 
{
    #[repr(C)]
    struct TooLong 
    {
        fam: sa_family_t,
        path: [u8; 300],
    }
    let path_addr = 
        TooLong 
        {
            fam: AF_UNIX as sa_family_t,
            path: [b'o'; 300],
        };

    unsafe 
    {
        let ref_path: &sockaddr = mem::transmute(&path_addr);

        UnixSocketAddr::from_ref(ref_path, size_of::<TooLong>() as _)
    }
    .expect_err("too long");
}

#[test]
fn from_sockaddr_storage_too_long_path() 
{
    #[repr(C)]
    struct TooLong 
    {
        fam: sa_family_t,
        path: [u8; 300],
    }
    let path_addr = 
        TooLong 
        {
            fam: AF_UNIX as sa_family_t,
            path: [b'o'; 300],
        };

    unsafe 
    {
        let ref_path: &sockaddr_storage = mem::transmute(&path_addr);

        UnixSocketAddr::from_sockaddr_storage(ref_path, size_of::<TooLong>() as _)
    }
    .expect_err("too long");
}

#[test]
fn from_raw_empty() {
    let unspecified_addr = UnixSocketAddr::new_unspecified();
    let (raw_addr, raw_len) = unspecified_addr.as_raw();
    let a = unsafe {
        UnixSocketAddr::from_raw(raw_addr as *const sockaddr_un as *const sockaddr, raw_len)
    }.expect("from_raw() accepts new_unspecified()");
    assert_eq!(a, unspecified_addr);
    assert!(a.is_unnamed());

    if UnixSocketAddr::has_abstract_addresses() == false 
    {
        let a = 
            unsafe 
            {
                UnixSocketAddr::from_raw(raw_addr as *const sockaddr_un as *const sockaddr, raw_len+10)
            }
            .expect("from_raw() accepts extra NULs");
        
        assert_eq!(a, unspecified_addr);
        assert!(a.is_unnamed());
    }
}


#[test]
fn test1()
{
    let path16: Vec<u16> = "C:\\test\\test.sock".to_string().encode_utf16().collect();
    let uss = UnixSocketAddr::new_utf16(&path16).unwrap();

    println!("{} {:?}", uss, uss);
    assert_eq!(uss.is_absolute_path(), true);

    let path8 = uss.as_pathname().unwrap();

    println!("{}", path8.display());

    assert_eq!(path8.display().to_string().as_str(), "C:\\test\\test.sock");
    
}