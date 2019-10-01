//! An executable to test close-on-exec by exec()ing to this and 

extern crate libc;

fn main() {
    let mut args = std::env::args();
    let _ = args.next();
    let arg = args.next().unwrap_or_else(|| {
        eprintln!("Usage: test_cloexec <fd to check if open>");
        eprintln!("exit codes: 0=closed, 1=open, 2=unexpected, 3=bad argument(s)");
        eprintln!("panics if writing to stderr fails or argument is not unicode. (sorry)");
        std::process::exit(3);
    });
    if args.next().is_some() {
        eprintln!("Too many arguments");
        std::process::exit(3);
    }
    let fd = arg.parse::<libc::c_int>().unwrap_or_else(|_| {
        eprintln!("fd is not an integer");
        std::process::exit(3);
    });
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags == -1 {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::EBADF) {
            std::process::exit(0); // was closed on exec()
        }
        eprintln!("Got unexpected error from fcntl(): {}", error);
        std::process::exit(2);
    }
    if flags & libc::FD_CLOEXEC == 0 {
        std::process::exit(1); // close-on-exec was not set
    }
    eprintln!("CLOEXEC was set, but ignored!");
    std::process::exit(2);
}
