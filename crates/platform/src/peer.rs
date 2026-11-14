//! Who is at the other end of a loopback TCP connection.
//!
//! The management API on 127.0.0.1 serves only programs of the user VPN Manager runs as — the
//! rule `api.sock` enforces with peer credentials. TCP carries no credentials, so the owner is
//! found in the operating system's socket tables: the client end of a connection accepted on
//! `local` from `peer` is the TCP socket whose local address is `peer` and whose remote address
//! is `local`.
//!
//! - Linux: `/proc/net/tcp` and `/proc/net/tcp6` list every TCP socket of this network namespace
//!   with the uid that owns it.
//! - macOS: libproc lists the descriptors of every process this user may inspect — only its own;
//!   other users' and root's processes refuse `PROC_PIDLISTFDS` — and the addresses of each
//!   socket. A client socket found in one of those processes belongs to this user; one found
//!   nowhere belongs to another user, or is already closed.
//!
//! Either way the answer is a fact about the connection when it was accepted; callers decide
//! once per connection and fail closed on anything but a match.
#![allow(
    unsafe_code,
    reason = "macOS peer process lookup calls libproc (proc_listallpids/proc_pidinfo/proc_pidfdinfo) via libc"
)]

use std::io;
use std::net::{IpAddr, SocketAddr};

/// The owner of the client socket of a loopback TCP connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerOwner {
    pub uid: u32,
    /// The process that holds the socket, when the platform says (macOS).
    pub pid: Option<u32>,
}

/// An IPv4-mapped IPv6 address as the IPv4 address it is.
const fn unmapped(a: SocketAddr) -> SocketAddr {
    match a.ip() {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => SocketAddr::new(IpAddr::V4(v4), a.port()),
            None => a,
        },
        IpAddr::V4(_) => a,
    }
}

// ---------------------------------------------------------------------------------------------
// Linux: /proc/net/tcp{,6}
// ---------------------------------------------------------------------------------------------

/// Largest `/proc/net/tcp*` table read (about 150 bytes per socket).
#[cfg(target_os = "linux")]
const PROC_NET_MAX: u64 = 64 * 1024 * 1024;

/// One address of a `/proc/net/tcp*` line (`0100007F:1F90`): the kernel prints each 32-bit word
/// of the address as the native-endian number it reads from memory, and the port as a number.
#[cfg(any(target_os = "linux", test))]
fn proc_net_addr(s: &str) -> Option<SocketAddr> {
    use std::net::{Ipv4Addr, Ipv6Addr};
    let (addr, port) = s.split_once(':')?;
    let port = u16::from_str_radix(port, 16).ok()?;
    let word = |i: usize| -> Option<[u8; 4]> {
        let w = u32::from_str_radix(addr.get(i * 8..i * 8 + 8)?, 16).ok()?;
        Some(w.to_ne_bytes())
    };
    let ip = match addr.len() {
        8 => IpAddr::V4(Ipv4Addr::from(word(0)?)),
        32 => {
            let mut b = [0u8; 16];
            for i in 0..4 {
                b[i * 4..i * 4 + 4].copy_from_slice(&word(i)?);
            }
            IpAddr::V6(Ipv6Addr::from(b))
        }
        _ => return None,
    };
    Some(SocketAddr::new(ip, port))
}

/// The uid owning the socket of a `/proc/net/tcp*` table whose local address is `peer` and whose
/// remote address is `local` (both already unmapped).
#[cfg(any(target_os = "linux", test))]
fn proc_net_owner(table: &str, local: SocketAddr, peer: SocketAddr) -> Option<u32> {
    table.lines().skip(1).find_map(|line| {
        // sl local_address rem_address st tx_queue:rx_queue tr:tm->when retrnsmt uid ...
        let f: Vec<&str> = line.split_whitespace().take(8).collect();
        let (l, r) = (proc_net_addr(f.get(1)?)?, proc_net_addr(f.get(2)?)?);
        (unmapped(l) == peer && unmapped(r) == local)
            .then(|| f.get(7)?.parse().ok())
            .flatten()
    })
}

#[cfg(target_os = "linux")]
fn read_table(path: &str) -> io::Result<String> {
    use std::io::Read;
    let mut text = String::new();
    std::fs::File::open(path)?
        .take(PROC_NET_MAX + 1)
        .read_to_string(&mut text)?;
    if text.len() as u64 > PROC_NET_MAX {
        return Err(io::Error::other(format!("{path} is larger than expected")));
    }
    Ok(text)
}

/// The owner of the client end of the loopback connection accepted on `local` from `peer`;
/// `Ok(None)` when no such socket exists (any more).
///
/// # Errors
///
/// Fails when the socket tables or a process's descriptors cannot be read.
#[cfg(target_os = "linux")]
pub fn tcp_peer_owner(local: SocketAddr, peer: SocketAddr) -> io::Result<Option<PeerOwner>> {
    let (local, peer) = (unmapped(local), unmapped(peer));
    // An IPv4 client may connect from an IPv6 socket (IPv4-mapped): look in both tables then.
    let tables: &[&str] = if peer.is_ipv4() {
        &["/proc/net/tcp", "/proc/net/tcp6"]
    } else {
        &["/proc/net/tcp6"]
    };
    let mut failure = None;
    for path in tables {
        match read_table(path) {
            Ok(text) => {
                if let Some(uid) = proc_net_owner(&text, local, peer) {
                    return Ok(Some(PeerOwner { uid, pid: None }));
                }
            }
            // A kernel without IPv6 has no tcp6 table.
            Err(e) if e.kind() == io::ErrorKind::NotFound && *path != tables[0] => {}
            Err(e) => failure = Some(e),
        }
    }
    failure.map_or(Ok(None), Err)
}

// ---------------------------------------------------------------------------------------------
// macOS: libproc
// ---------------------------------------------------------------------------------------------

/// `struct socket_fdinfo` of `<sys/proc_info.h>`, read by offset. The layout is the same on arm64
/// and `x86_64` (checked against the SDK headers; see the tests): `psi` at 24; in `socket_info`,
/// `soi_kind` at 232 and `soi_proto` at 240; in `in_sockinfo`, `insi_fport` at 0, `insi_lport`
/// at 4, `insi_vflag` at 24, `insi_faddr` at 32, `insi_laddr` at 48; an IPv4 address is the
/// last 4 bytes of its 16-byte `in4in6_addr`.
#[cfg(target_os = "macos")]
mod sockinfo {
    pub const PROC_PIDFDSOCKETINFO: i32 = 3;
    pub const SOCKINFO_TCP: i32 = 2;
    pub const INI_IPV4: u8 = 0x1;
    pub const INI_IPV6: u8 = 0x2;
    /// The size of the struct, as `proc_pidfdinfo` takes and returns it.
    pub const SIZE: libc::c_int = 792;
    /// The same, as a buffer length.
    pub const LEN: usize = SIZE as usize;
    const PSI: usize = 24;
    pub const KIND: usize = PSI + 232;
    const IN: usize = PSI + 240;
    pub const FPORT: usize = IN;
    pub const LPORT: usize = IN + 4;
    pub const VFLAG: usize = IN + 24;
    pub const FADDR: usize = IN + 32;
    pub const LADDR: usize = IN + 48;

    #[repr(C, align(8))]
    pub struct SocketFdInfo(pub [u8; LEN]);
}

/// A count or size libproc returned, when it is one (`None`: nothing, or the call failed).
#[cfg(target_os = "macos")]
fn positive(n: libc::c_int) -> Option<usize> {
    usize::try_from(n).ok().filter(|n| *n > 0)
}

#[cfg(target_os = "macos")]
fn all_pids() -> io::Result<Vec<libc::pid_t>> {
    // SAFETY: a null buffer asks for the number of processes.
    let n = unsafe { libc::proc_listallpids(std::ptr::null_mut(), 0) };
    let Some(n) = positive(n) else {
        return Err(io::Error::last_os_error());
    };
    // Room for processes started meanwhile.
    let mut pids: Vec<libc::pid_t> = vec![0; n + 256];
    let bytes = libc::c_int::try_from(pids.len() * std::mem::size_of::<libc::pid_t>())
        .map_err(|_| io::Error::other("the process list is too large"))?;
    // SAFETY: the buffer holds `pids.len()` pids, `bytes` long.
    let got = unsafe { libc::proc_listallpids(pids.as_mut_ptr().cast::<libc::c_void>(), bytes) };
    let Some(got) = positive(got) else {
        return Err(io::Error::last_os_error());
    };
    pids.truncate(got);
    Ok(pids)
}

/// The descriptors of `pid`; None when it is gone or not ours to inspect.
#[cfg(target_os = "macos")]
fn descriptors(pid: libc::pid_t) -> Option<Vec<libc::proc_fdinfo>> {
    let entry = std::mem::size_of::<libc::proc_fdinfo>();
    // SAFETY: a null buffer asks for the size needed.
    let need =
        unsafe { libc::proc_pidinfo(pid, libc::PROC_PIDLISTFDS, 0, std::ptr::null_mut(), 0) };
    let need = positive(need)?;
    // Room for descriptors opened meanwhile.
    let mut fds = vec![
        libc::proc_fdinfo {
            proc_fd: 0,
            proc_fdtype: 0,
        };
        need / entry + 32
    ];
    let bytes = libc::c_int::try_from(fds.len() * entry).ok()?;
    // SAFETY: the buffer holds `fds.len()` entries of the size the call writes.
    let got = unsafe {
        libc::proc_pidinfo(
            pid,
            libc::PROC_PIDLISTFDS,
            0,
            fds.as_mut_ptr().cast::<libc::c_void>(),
            bytes,
        )
    };
    let got = positive(got)?;
    fds.truncate(got / entry);
    Some(fds)
}

/// Local and remote address of TCP socket `fd` of `pid`; None for anything else (or when it is
/// gone meanwhile).
#[cfg(target_os = "macos")]
fn tcp_endpoints(pid: libc::pid_t, fd: i32) -> io::Result<Option<(SocketAddr, SocketAddr)>> {
    use sockinfo::{
        FADDR, FPORT, INI_IPV4, INI_IPV6, KIND, LADDR, LEN, LPORT, PROC_PIDFDSOCKETINFO, SIZE,
        SOCKINFO_TCP, SocketFdInfo, VFLAG,
    };
    use std::net::{Ipv4Addr, Ipv6Addr};
    let mut info = SocketFdInfo([0; LEN]);
    // SAFETY: the buffer is a `struct socket_fdinfo` (SIZE bytes, 8-aligned), as the flavor needs.
    let n = unsafe {
        libc::proc_pidfdinfo(
            pid,
            fd,
            PROC_PIDFDSOCKETINFO,
            info.0.as_mut_ptr().cast::<libc::c_void>(),
            SIZE,
        )
    };
    if n <= 0 {
        return Ok(None);
    }
    if n != SIZE {
        // Never guess at a layout this code does not know.
        return Err(io::Error::other(format!(
            "socket_fdinfo is {n} bytes here, not {SIZE}"
        )));
    }
    let b = &info.0;
    let i32_at = |off: usize| -> Option<i32> {
        b.get(off..off + 4)
            .and_then(|s| <[u8; 4]>::try_from(s).ok())
            .map(i32::from_ne_bytes)
    };
    if i32_at(KIND) != Some(SOCKINFO_TCP) {
        return Ok(None);
    }
    let vflag = b[VFLAG];
    let ip = |off: usize| -> Option<IpAddr> {
        if vflag & INI_IPV4 != 0 {
            let a: [u8; 4] = b.get(off + 12..off + 16)?.try_into().ok()?;
            Some(IpAddr::V4(Ipv4Addr::from(a)))
        } else if vflag & INI_IPV6 != 0 {
            let a: [u8; 16] = b.get(off..off + 16)?.try_into().ok()?;
            Some(IpAddr::V6(Ipv6Addr::from(a)))
        } else {
            None
        }
    };
    // Ports are kept as the network-order 16-bit value read natively: the low half of the `int`.
    let port = |off: usize| i32_at(off).map(|p| u16::from_be((p.cast_unsigned() & 0xffff) as u16));
    let (Some(lip), Some(lport), Some(fip), Some(fport)) =
        (ip(LADDR), port(LPORT), ip(FADDR), port(FPORT))
    else {
        return Ok(None);
    };
    Ok(Some((
        SocketAddr::new(lip, lport),
        SocketAddr::new(fip, fport),
    )))
}

/// The owner of the client end of the loopback connection accepted on `local` from `peer`;
/// `Ok(None)` when no process this user may inspect holds it (another user's, or closed).
///
/// # Errors
///
/// Fails when the process list cannot be read.
#[cfg(target_os = "macos")]
pub fn tcp_peer_owner(local: SocketAddr, peer: SocketAddr) -> io::Result<Option<PeerOwner>> {
    let (local, peer) = (unmapped(local), unmapped(peer));
    let mut pids = all_pids()?;
    // Newest first: a client that just connected is most often a process that just started
    // (curl, vpnctl); a browser is found wherever it is.
    pids.sort_unstable_by(|a, b| b.cmp(a));
    for pid in pids.into_iter().filter(|p| *p > 0) {
        let Some(fds) = descriptors(pid) else {
            continue;
        };
        for fd in fds
            .iter()
            .filter(|f| f.proc_fdtype == libc::PROX_FDTYPE_SOCKET as u32)
        {
            let Some((l, r)) = tcp_endpoints(pid, fd.proc_fd)? else {
                continue;
            };
            if unmapped(l) == peer && unmapped(r) == local {
                let pid = pid.cast_unsigned();
                // The process that holds it decides the owner (only this user's are visible,
                // unless VPN Manager runs as root).
                let uid = crate::process::identity(pid)
                    .map(|i| i.uid)
                    .ok_or_else(|| io::Error::other("the client process ended meanwhile"))?;
                return Ok(Some(PeerOwner {
                    uid,
                    pid: Some(pid),
                }));
            }
        }
    }
    Ok(None)
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub fn tcp_peer_owner(_local: SocketAddr, _peer: SocketAddr) -> io::Result<Option<PeerOwner>> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "finding the owner of a TCP connection is not implemented on this platform",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Real lines of a little-endian Linux host (header, the client end, the server end).
    const TCP: &str = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:4A38 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 41250 1 0000000000000000 100 0 0 10 0
   1: 0100007F:D3B4 0100007F:4A38 01 00000000:00000000 00:00000000 00000000  1001        0 41901 1 0000000000000000 20 4 30 10 -1
   2: 0100007F:4A38 0100007F:D3B4 01 00000000:00000000 00:00000000 00000000  1000        0 41902 1 0000000000000000 20 4 30 10 -1
";
    const TCP6: &str = "  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000001000000:B9A2 00000000000000000000000001000000:4A39 01 00000000:00000000 00:00000000 00000000  1002        0 52001 1 0000000000000000 20 4 30 10 -1
   1: 0000000000000000FFFF00000100007F:C001 0000000000000000FFFF00000100007F:4A38 01 00000000:00000000 00:00000000 00000000  1003        0 52002 1 0000000000000000 20 4 30 10 -1
";

    fn a(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    #[test]
    #[cfg(target_endian = "little")]
    fn proc_net_addresses_are_read_as_the_kernel_prints_them() {
        assert_eq!(proc_net_addr("0100007F:4A38"), Some(a("127.0.0.1:19000")));
        assert_eq!(
            proc_net_addr("00000000000000000000000001000000:4A39"),
            Some(a("[::1]:19001"))
        );
        assert_eq!(
            proc_net_addr("0000000000000000FFFF00000100007F:C001"),
            Some(a("[::ffff:127.0.0.1]:49153"))
        );
        assert_eq!(proc_net_addr("0100007F"), None);
        assert_eq!(proc_net_addr("0100007F:XYZ1"), None);
        assert_eq!(proc_net_addr("01007F:4A38"), None);
    }

    #[test]
    #[cfg(target_endian = "little")]
    fn the_client_end_is_found_by_its_direction() {
        let server = a("127.0.0.1:19000");
        let client = a("127.0.0.1:54196");
        // The client end (local = client, remote = server), not the server's own end.
        assert_eq!(proc_net_owner(TCP, server, client), Some(1001));
        // Asked the other way round, it is the server's end.
        assert_eq!(proc_net_owner(TCP, client, server), Some(1000));
        // A port nobody connected from.
        assert_eq!(proc_net_owner(TCP, server, a("127.0.0.1:54197")), None);
        // IPv6, and an IPv4 client on an IPv6 socket (IPv4-mapped).
        assert_eq!(
            proc_net_owner(TCP6, a("[::1]:19001"), a("[::1]:47522")),
            Some(1002)
        );
        assert_eq!(
            proc_net_owner(TCP6, server, a("127.0.0.1:49153")),
            Some(1003)
        );
        assert_eq!(proc_net_owner("garbage\n1 2 3\n", server, client), None);
    }
}
