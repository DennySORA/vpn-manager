//! Messages between the manager and a sandbox holder: one JSON document per `SOCK_SEQPACKET`
//! message, descriptors as `SCM_RIGHTS`, and the sender's process id as `SCM_CREDENTIALS` (the
//! kernel attaches it when the receiving socket has `SO_PASSCRED`, translated into the
//! receiver's pid namespace — that is how the manager learns host pids of processes inside the
//! sandbox's pid namespace).
#![expect(
    unsafe_code,
    reason = "this module owns SCM_RIGHTS fd passing over SOCK_SEQPACKET via socketpair/sendmsg/recvmsg"
)]

use std::io;
use std::os::fd::{FromRawFd, OwnedFd, RawFd};

use serde::Serialize;
use serde::de::DeserializeOwned;

/// Largest message.
pub const MAX_MESSAGE: usize = 64 * 1024;
/// Most descriptors one message carries.
pub const MAX_FDS: usize = 8;

/// A received message.
pub struct Received {
    pub data: Vec<u8>,
    pub fds: Vec<OwnedFd>,
    /// Sender's pid, uid and gid as seen from this process (only with `SO_PASSCRED`).
    pub creds: Option<libc::ucred>,
}

/// A `SOCK_SEQPACKET` socket pair, both ends close-on-exec.
pub fn seqpacket_pair() -> io::Result<(OwnedFd, OwnedFd)> {
    let mut fds = [0; 2];
    // SAFETY: socketpair writes two descriptors into the array we pass.
    let r = unsafe {
        libc::socketpair(
            libc::AF_UNIX,
            libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
            0,
            fds.as_mut_ptr(),
        )
    };
    if r < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: socketpair succeeded: the first descriptor is fresh and owned by nobody else.
    let first = unsafe { OwnedFd::from_raw_fd(fds[0]) };
    // SAFETY: the same for the second.
    let second = unsafe { OwnedFd::from_raw_fd(fds[1]) };
    Ok((first, second))
}

pub fn set_int_option(fd: RawFd, level: i32, name: i32, value: i32) -> io::Result<()> {
    #[expect(
        clippy::cast_possible_truncation,
        reason = "size_of::<i32>() is 4, which socklen_t holds"
    )]
    let len = size_of::<i32>() as libc::socklen_t;
    // SAFETY: pointer to a live c_int of the size we pass.
    let r = unsafe { libc::setsockopt(fd, level, name, (&raw const value).cast(), len) };
    if r < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Have the kernel attach the sender's credentials to every message this socket receives.
pub fn pass_credentials(fd: RawFd) -> io::Result<()> {
    set_int_option(fd, libc::SOL_SOCKET, libc::SO_PASSCRED, 1)
}

/// Bound blocking receives on this socket.
pub fn set_receive_timeout(fd: RawFd, timeout: std::time::Duration) -> io::Result<()> {
    let tv = libc::timeval {
        tv_sec: timeout.as_secs() as libc::time_t,
        tv_usec: libc::suseconds_t::from(timeout.subsec_micros().cast_signed()),
    };
    #[expect(
        clippy::cast_possible_truncation,
        reason = "size_of::<timeval>() is 16, which socklen_t holds"
    )]
    let len = size_of::<libc::timeval>() as libc::socklen_t;
    // SAFETY: pointer to a live timeval of the size we pass.
    let r = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            (&raw const tv).cast(),
            len,
        )
    };
    if r < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Send one message with descriptors. Never raises SIGPIPE.
pub fn send(fd: RawFd, data: &[u8], fds: &[RawFd]) -> io::Result<()> {
    if data.len() > MAX_MESSAGE || fds.len() > MAX_FDS {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "message too large",
        ));
    }
    let mut iov = libc::iovec {
        iov_base: data.as_ptr().cast_mut().cast(),
        iov_len: data.len(),
    };
    // At most MAX_FDS descriptors (checked above): their bytes fit u32.
    let fd_bytes = u32::try_from(size_of_val(fds))
        .map_err(|_too_large| io::Error::new(io::ErrorKind::InvalidInput, "message too large"))?;
    // SAFETY: CMSG_SPACE is a pure size computation.
    let space = unsafe { libc::CMSG_SPACE(fd_bytes) } as usize;
    let mut control = vec![0u8; if fds.is_empty() { 0 } else { space }];
    // SAFETY: zeroed msghdr is a valid empty header; we fill the fields below.
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &raw mut iov;
    msg.msg_iovlen = 1;
    if !fds.is_empty() {
        msg.msg_control = control.as_mut_ptr().cast();
        msg.msg_controllen = control.len() as _;
        // SAFETY: CMSG_LEN is a pure size computation.
        let cmsg_len = unsafe { libc::CMSG_LEN(fd_bytes) };
        // SAFETY: CMSG_FIRSTHDR reads the control fields of `msg`, a live header whose control
        // buffer has room for one header with `fds.len()` descriptors.
        let cmsg = unsafe { libc::CMSG_FIRSTHDR(&raw const msg) };
        // SAFETY: that room makes `cmsg` the start of the control buffer, a header we fill.
        let header = unsafe { &mut *cmsg };
        header.cmsg_level = libc::SOL_SOCKET;
        header.cmsg_type = libc::SCM_RIGHTS;
        header.cmsg_len = cmsg_len as _;
        // SAFETY: CMSG_DATA only computes where the header's payload starts.
        let data = unsafe { libc::CMSG_DATA(cmsg) };
        // SAFETY: the payload has room for `fds.len()` descriptors (CMSG_SPACE above).
        unsafe { std::ptr::copy_nonoverlapping(fds.as_ptr(), data.cast::<RawFd>(), fds.len()) };
    }
    loop {
        // SAFETY: msg points at live buffers for the duration of the call.
        let n = unsafe { libc::sendmsg(fd, &raw const msg, libc::MSG_NOSIGNAL) };
        if n >= 0 {
            return Ok(());
        }
        let e = io::Error::last_os_error();
        if e.kind() != io::ErrorKind::Interrupted {
            return Err(e);
        }
    }
}

/// Receive one message. `Ok(None)` when the peer closed the connection.
pub fn recv(fd: RawFd) -> io::Result<Option<Received>> {
    let mut data = vec![0u8; MAX_MESSAGE];
    let mut iov = libc::iovec {
        iov_base: data.as_mut_ptr().cast(),
        iov_len: data.len(),
    };
    #[expect(
        clippy::cast_possible_truncation,
        reason = "MAX_FDS descriptors and one ucred are a few hundred bytes"
    )]
    let (fd_bytes, cred_bytes) = (
        (MAX_FDS * size_of::<RawFd>()) as u32,
        size_of::<libc::ucred>() as u32,
    );
    // SAFETY: CMSG_SPACE is a pure size computation.
    let fd_space = unsafe { libc::CMSG_SPACE(fd_bytes) };
    // SAFETY: the same.
    let cred_space = unsafe { libc::CMSG_SPACE(cred_bytes) };
    let space = (fd_space + cred_space) as usize;
    let mut control = vec![0u8; space];
    // SAFETY: zeroed msghdr is a valid empty header; we fill the fields below.
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &raw mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.as_mut_ptr().cast();
    msg.msg_controllen = control.len() as _;
    let n = loop {
        // SAFETY: msg points at live buffers for the duration of the call.
        let n = unsafe { libc::recvmsg(fd, &raw mut msg, libc::MSG_CMSG_CLOEXEC) };
        if n >= 0 {
            break n.cast_unsigned();
        }
        let e = io::Error::last_os_error();
        if e.kind() != io::ErrorKind::Interrupted {
            return Err(e);
        }
    };
    let mut fds = Vec::new();
    let mut creds = None;
    // The kernel filled `control` with well-formed headers up to msg_controllen; they are walked
    // with the CMSG macros and their payloads copied out unaligned.
    // SAFETY: CMSG_LEN is a pure size computation.
    let header_len = unsafe { libc::CMSG_LEN(0) } as usize;
    // SAFETY: CMSG_FIRSTHDR reads the control fields of `msg`, which recvmsg filled in.
    let mut cmsg = unsafe { libc::CMSG_FIRSTHDR(&raw const msg) };
    while !cmsg.is_null() {
        // SAFETY: a non-null header the CMSG macros found inside `control`.
        let header = unsafe { &*cmsg };
        let payload = header.cmsg_len as usize - header_len;
        if header.cmsg_level == libc::SOL_SOCKET && header.cmsg_type == libc::SCM_RIGHTS {
            let count = payload / size_of::<RawFd>();
            // SAFETY: CMSG_DATA only computes where this header's payload starts.
            let data = unsafe { libc::CMSG_DATA(cmsg) };
            #[expect(
                clippy::cast_ptr_alignment,
                reason = "the descriptors are read with read_unaligned"
            )]
            let base = data as *const RawFd;
            for i in 0..count {
                // SAFETY: descriptor `i` of `count` lies inside this header's payload.
                let at = unsafe { base.add(i) };
                // SAFETY: `at` points at a descriptor number the kernel wrote, maybe unaligned.
                let raw = unsafe { std::ptr::read_unaligned(at) };
                // SAFETY: the kernel installed this descriptor for us (`SCM_RIGHTS`); nothing
                // else owns it.
                fds.push(unsafe { OwnedFd::from_raw_fd(raw) });
            }
        } else if header.cmsg_level == libc::SOL_SOCKET
            && header.cmsg_type == libc::SCM_CREDENTIALS
            && payload >= size_of::<libc::ucred>()
        {
            // SAFETY: CMSG_DATA only computes where this header's payload starts.
            let data = unsafe { libc::CMSG_DATA(cmsg) };
            // SAFETY: the payload holds a whole ucred (checked above), maybe unaligned.
            creds = Some(unsafe { std::ptr::read_unaligned(data as *const libc::ucred) });
        }
        // SAFETY: CMSG_NXTHDR reads `msg` and the current header: the next header, or null.
        cmsg = unsafe { libc::CMSG_NXTHDR(&raw const msg, cmsg) };
    }
    if msg.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) != 0 {
        // Received descriptors are closed when `fds` drops.
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "truncated message",
        ));
    }
    if n == 0 && fds.is_empty() {
        return Ok(None);
    }
    data.truncate(n);
    Ok(Some(Received { data, fds, creds }))
}

pub fn send_json<T: Serialize>(fd: RawFd, msg: &T, fds: &[RawFd]) -> io::Result<()> {
    let data = serde_json::to_vec(msg).map_err(io::Error::other)?;
    send(fd, &data, fds)
}

/// A decoded message, its descriptors and its sender's credentials.
pub type Message<T> = (T, Vec<OwnedFd>, Option<libc::ucred>);

/// Receive and decode one message. `Ok(None)` on end of stream.
pub fn recv_json<T: DeserializeOwned>(fd: RawFd) -> io::Result<Option<Message<T>>> {
    let Some(r) = recv(fd)? else {
        return Ok(None);
    };
    let msg = serde_json::from_slice(&r.data)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    Ok(Some((msg, r.fds, r.creds)))
}
