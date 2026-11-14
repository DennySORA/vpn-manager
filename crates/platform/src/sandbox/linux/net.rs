//! Network setup inside a fresh sandbox network namespace, with syscalls and rtnetlink only:
//! `lo` up, the TUN device with its address(es) and MTU, and default routes through it for the
//! address families the profile has. A family without an address gets no route at all, so the
//! kernel refuses it (`ENETUNREACH`) instead of finding another way.
#![expect(
    unsafe_code,
    reason = "this module owns the sandbox's network setup: sockets, ioctl and interface lookups via libc"
)]

use std::ffi::CString;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

// <linux/rtnetlink.h>, <linux/netlink.h>, <linux/if_addr.h>, <linux/if_link.h>
const RTM_NEWLINK: u16 = 16;
const RTM_NEWADDR: u16 = 20;
const RTM_NEWROUTE: u16 = 24;
const NLMSG_ERROR: u16 = 2;
const NLM_F_REQUEST: u16 = 0x01;
const NLM_F_ACK: u16 = 0x04;
const NLM_F_EXCL: u16 = 0x200;
const NLM_F_CREATE: u16 = 0x400;
const IFLA_MTU: u16 = 4;
const IFA_ADDRESS: u16 = 1;
const IFA_LOCAL: u16 = 2;
const IFA_FLAGS: u16 = 8;
const IFA_F_NODAD: u32 = 0x02;
const RTA_OIF: u16 = 4;
const RT_TABLE_MAIN: u8 = 254;
const RTPROT_BOOT: u8 = 3;
const RT_SCOPE_UNIVERSE: u8 = 0;
const RT_SCOPE_LINK: u8 = 253;
const RTN_UNICAST: u8 = 1;
const IFF_UP: u32 = 0x1;

// <linux/if_tun.h>
const TUNSETIFF: libc::c_ulong = 0x4004_54ca;
const TUNGETIFF: libc::c_ulong = 0x8004_54d2;
const IFF_TUN: libc::c_short = 0x0001;
const IFF_NO_PI: libc::c_short = 0x1000;

/// `struct ifreq` as far as `TUNSETIFF` uses it.
#[repr(C)]
struct IfReq {
    name: [u8; libc::IFNAMSIZ],
    flags: libc::c_short,
    _pad: [u8; 22],
}

/// Create the TUN device `name` (no packet-information header) in this network namespace.
pub fn create_tun(name: &str) -> io::Result<OwnedFd> {
    if name.is_empty() || name.len() >= libc::IFNAMSIZ {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "bad interface name",
        ));
    }
    let path = c"/dev/net/tun";
    // SAFETY: open with a valid C string; the result is checked.
    let fd = unsafe { libc::open(path.as_ptr(), libc::O_RDWR | libc::O_CLOEXEC) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fd is a fresh descriptor we own.
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    let mut req = IfReq {
        name: [0; libc::IFNAMSIZ],
        flags: IFF_TUN | IFF_NO_PI,
        _pad: [0; 22],
    };
    req.name[..name.len()].copy_from_slice(name.as_bytes());
    // SAFETY: TUNSETIFF reads a `struct ifreq`, which `IfReq` matches in size and layout.
    let r = unsafe { libc::ioctl(fd.as_raw_fd(), TUNSETIFF as _, &raw mut req) };
    if r < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(fd)
}

/// Name of the interface a TUN descriptor is attached to.
pub fn tun_name(fd: std::os::fd::RawFd) -> io::Result<String> {
    let mut req = IfReq {
        name: [0; libc::IFNAMSIZ],
        flags: 0,
        _pad: [0; 22],
    };
    // SAFETY: TUNGETIFF fills a `struct ifreq`, which `IfReq` matches in size and layout.
    let r = unsafe { libc::ioctl(fd, TUNGETIFF as _, &raw mut req) };
    if r < 0 {
        return Err(io::Error::last_os_error());
    }
    let end = req
        .name
        .iter()
        .position(|b| *b == 0)
        .unwrap_or(req.name.len());
    Ok(String::from_utf8_lossy(&req.name[..end]).into_owned())
}

/// Names of the network interfaces of this process's network namespace.
pub fn interfaces() -> io::Result<Vec<String>> {
    // if_nameindex returns a heap array terminated by a zero entry (or null on failure); it is
    // only read, and handed back to if_freenameindex.
    // SAFETY: if_nameindex has no preconditions.
    let list = unsafe { libc::if_nameindex() };
    if list.is_null() {
        return Err(io::Error::last_os_error());
    }
    let mut names = Vec::new();
    let mut entry = list;
    loop {
        // SAFETY: `entry` is in the array: the walk ends at its terminating zero entry.
        let current = unsafe { &*entry };
        if current.if_index == 0 || current.if_name.is_null() {
            break;
        }
        // SAFETY: the name of an entry before the terminator is a NUL-terminated string.
        let name = unsafe { std::ffi::CStr::from_ptr(current.if_name) };
        names.push(name.to_string_lossy().into_owned());
        // SAFETY: this entry was not the terminator, so the next one is still in the array.
        entry = unsafe { entry.add(1) };
    }
    // SAFETY: the array if_nameindex returned, handed back once.
    unsafe { libc::if_freenameindex(list) };
    Ok(names)
}

pub fn if_index(name: &str) -> io::Result<u32> {
    let c = CString::new(name).map_err(io::Error::other)?;
    // SAFETY: valid C string.
    let index = unsafe { libc::if_nametoindex(c.as_ptr()) };
    if index == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(index)
}

fn push_attr(buf: &mut Vec<u8>, kind: u16, data: &[u8]) {
    let len = 4 + data.len();
    #[expect(
        clippy::cast_possible_truncation,
        reason = "attributes here carry an address, an MTU or flags: a few bytes"
    )]
    buf.extend_from_slice(&(len as u16).to_ne_bytes());
    buf.extend_from_slice(&kind.to_ne_bytes());
    buf.extend_from_slice(data);
    while !buf.len().is_multiple_of(4) {
        buf.push(0);
    }
}

/// A route netlink socket; every request waits for its acknowledgement.
pub struct Netlink {
    fd: OwnedFd,
    seq: u32,
}

impl Netlink {
    pub(crate) fn open() -> io::Result<Self> {
        // SAFETY: plain socket call; the result is checked.
        let fd = unsafe {
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                libc::NETLINK_ROUTE,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: fresh descriptor we own.
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        // SAFETY: zeroed sockaddr_nl is valid; we set the family.
        let mut addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        #[expect(
            clippy::cast_possible_truncation,
            reason = "AF_NETLINK (16) fits sa_family_t"
        )]
        {
            addr.nl_family = libc::AF_NETLINK as libc::sa_family_t;
        }
        #[expect(
            clippy::cast_possible_truncation,
            reason = "size_of::<sockaddr_nl>() is 12, which socklen_t holds"
        )]
        let len = size_of::<libc::sockaddr_nl>() as libc::socklen_t;
        // SAFETY: bind with a pointer to a live sockaddr_nl of the size we pass.
        let r = unsafe { libc::bind(fd.as_raw_fd(), (&raw const addr).cast(), len) };
        if r < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self { fd, seq: 1 })
    }

    fn request(&mut self, kind: u16, flags: u16, body: &[u8]) -> io::Result<()> {
        self.seq += 1;
        let seq = self.seq;
        let mut msg = Vec::with_capacity(16 + body.len());
        #[expect(
            clippy::cast_possible_truncation,
            reason = "request bodies are under 64 bytes"
        )]
        msg.extend_from_slice(&((16 + body.len()) as u32).to_ne_bytes());
        msg.extend_from_slice(&kind.to_ne_bytes());
        msg.extend_from_slice(&(flags | NLM_F_REQUEST | NLM_F_ACK).to_ne_bytes());
        msg.extend_from_slice(&seq.to_ne_bytes());
        msg.extend_from_slice(&0u32.to_ne_bytes());
        msg.extend_from_slice(body);
        // SAFETY: sending an initialized buffer on a socket we own.
        let n = unsafe { libc::send(self.fd.as_raw_fd(), msg.as_ptr().cast(), msg.len(), 0) };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        let mut buf = vec![0u8; 8192];
        loop {
            // SAFETY: receiving into a buffer we own, at most its length.
            let n =
                unsafe { libc::recv(self.fd.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len(), 0) };
            if n < 0 {
                let e = io::Error::last_os_error();
                if e.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(e);
            }
            let mut at = 0usize;
            let n = n.cast_unsigned();
            while at + 16 <= n {
                let len =
                    u32::from_ne_bytes([buf[at], buf[at + 1], buf[at + 2], buf[at + 3]]) as usize;
                let ty = u16::from_ne_bytes([buf[at + 4], buf[at + 5]]);
                let rseq =
                    u32::from_ne_bytes([buf[at + 8], buf[at + 9], buf[at + 10], buf[at + 11]]);
                if len < 16 || at + len > n {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "malformed netlink reply",
                    ));
                }
                if ty == NLMSG_ERROR && rseq == seq && len >= 20 {
                    let code = i32::from_ne_bytes([
                        buf[at + 16],
                        buf[at + 17],
                        buf[at + 18],
                        buf[at + 19],
                    ]);
                    return if code == 0 {
                        Ok(())
                    } else {
                        Err(io::Error::from_raw_os_error(-code))
                    };
                }
                at += (len + 3) & !3;
            }
        }
    }

    /// Bring an interface up, optionally setting its MTU.
    pub(crate) fn link_up(&mut self, index: u32, mtu: Option<u32>) -> io::Result<()> {
        let mut body = Vec::with_capacity(32);
        #[expect(
            clippy::cast_possible_truncation,
            reason = "AF_UNSPEC (0) fits the u8 family field"
        )]
        body.push(libc::AF_UNSPEC as u8);
        body.push(0);
        body.extend_from_slice(&0u16.to_ne_bytes());
        body.extend_from_slice(&index.cast_signed().to_ne_bytes());
        body.extend_from_slice(&IFF_UP.to_ne_bytes());
        body.extend_from_slice(&IFF_UP.to_ne_bytes());
        if let Some(mtu) = mtu {
            push_attr(&mut body, IFLA_MTU, &mtu.to_ne_bytes());
        }
        self.request(RTM_NEWLINK, 0, &body)
    }

    /// Add `addr/prefix` to an interface. IPv6 skips duplicate address detection (nothing else
    /// is on the link), so the address is usable at once.
    pub(crate) fn add_address(&mut self, index: u32, addr: IpAddr, prefix: u8) -> io::Result<()> {
        #[expect(
            clippy::cast_possible_truncation,
            reason = "AF_INET (2) and AF_INET6 (10) fit the u8 family field"
        )]
        let (family, bytes, flags): (u8, Vec<u8>, u32) = match addr {
            IpAddr::V4(a) => (libc::AF_INET as u8, a.octets().to_vec(), 0),
            IpAddr::V6(a) => (libc::AF_INET6 as u8, a.octets().to_vec(), IFA_F_NODAD),
        };
        let mut body = Vec::with_capacity(48);
        body.push(family);
        body.push(prefix);
        #[expect(
            clippy::cast_possible_truncation,
            reason = "ifa_flags holds the low 8 bits; IFA_FLAGS below carries all of them"
        )]
        body.push(flags as u8);
        body.push(RT_SCOPE_UNIVERSE);
        body.extend_from_slice(&index.to_ne_bytes());
        push_attr(&mut body, IFA_LOCAL, &bytes);
        push_attr(&mut body, IFA_ADDRESS, &bytes);
        push_attr(&mut body, IFA_FLAGS, &flags.to_ne_bytes());
        self.request(RTM_NEWADDR, NLM_F_CREATE | NLM_F_EXCL, &body)
    }

    /// Default route of one family through an interface (a point-to-point device: no gateway).
    pub(crate) fn add_default_route(&mut self, index: u32, v6: bool) -> io::Result<()> {
        let mut body = Vec::with_capacity(20);
        #[expect(
            clippy::cast_possible_truncation,
            reason = "AF_INET (2) and AF_INET6 (10) fit the u8 family field"
        )]
        body.push(if v6 {
            libc::AF_INET6 as u8
        } else {
            libc::AF_INET as u8
        });
        body.push(0); // dst_len: default route
        body.push(0); // src_len
        body.push(0); // tos
        body.push(RT_TABLE_MAIN);
        body.push(RTPROT_BOOT);
        body.push(if v6 { RT_SCOPE_UNIVERSE } else { RT_SCOPE_LINK });
        body.push(RTN_UNICAST);
        body.extend_from_slice(&0u32.to_ne_bytes());
        push_attr(&mut body, RTA_OIF, &index.to_ne_bytes());
        self.request(RTM_NEWROUTE, NLM_F_CREATE | NLM_F_EXCL, &body)
    }
}

/// Turn IPv6 off on one interface (the profile has no IPv6 address): no link-local address, no
/// router solicitations, nothing IPv6 leaves through it.
pub fn disable_ipv6(interface: &str) -> io::Result<()> {
    std::fs::write(
        format!("/proc/sys/net/ipv6/conf/{interface}/disable_ipv6"),
        b"1",
    )
}

/// The most the kernel may be told to give one TCP socket's buffer: no request, however wrong,
/// asks for more.
const TCP_LIMIT_MAX: u64 = 256 * 1024 * 1024;

/// Raise the largest size of one TCP socket's buffer in this network namespace (the third value
/// of `tcp_rmem` or `tcp_wmem`) to at least `want` bytes; returns the limit in force. A limit
/// that is already as large stays as it is, and the minimum and the default are never touched.
fn raise_tcp_limit(path: &str, want: u64) -> io::Result<u64> {
    let invalid = || io::Error::new(io::ErrorKind::InvalidData, format!("unexpected {path}"));
    let current = std::fs::read_to_string(path)?;
    let mut values = current.split_whitespace().map(str::parse::<u64>);
    let (Some(Ok(min)), Some(Ok(default)), Some(Ok(max)), None) =
        (values.next(), values.next(), values.next(), values.next())
    else {
        return Err(invalid());
    };
    let want = want.min(TCP_LIMIT_MAX);
    if want <= max {
        return Ok(max);
    }
    std::fs::write(path, format!("{min} {default} {want}"))?;
    Ok(want)
}

/// Raise the kernel's limits on the receive and the send buffer of one TCP socket in this
/// network namespace to at least these, in bytes; returns the limits in force. The kernel sizes
/// each socket's buffers itself, up to them.
pub fn raise_tcp_limits(receive_max: u64, send_max: u64) -> io::Result<(u64, u64)> {
    Ok((
        raise_tcp_limit("/proc/sys/net/ipv4/tcp_rmem", receive_max)?,
        raise_tcp_limit("/proc/sys/net/ipv4/tcp_wmem", send_max)?,
    ))
}

type Families = (Option<(Ipv4Addr, u8)>, Option<(Ipv6Addr, u8)>);

/// The first address of each family, with its prefix length.
pub fn first_per_family(addresses: &[(IpAddr, u8)]) -> Families {
    let v4 = addresses.iter().find_map(|(a, p)| match a {
        IpAddr::V4(a) => Some((*a, *p)),
        IpAddr::V6(_) => None,
    });
    let v6 = addresses.iter().find_map(|(a, p)| match a {
        IpAddr::V6(a) => Some((*a, *p)),
        IpAddr::V4(_) => None,
    });
    (v4, v6)
}
