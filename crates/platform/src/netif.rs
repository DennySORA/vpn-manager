//! This host's own IP addresses, as its interfaces carry them right now (`getifaddrs`).
//!
//! Used to tell a client on this host from another host (a connection from one of these
//! addresses never left the machine, whatever the address looks like) and to show the
//! addresses other hosts reach this one at.
#![allow(
    unsafe_code,
    reason = "interface enumeration calls getifaddrs/freeifaddrs via libc"
)]

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Every address of every interface (loopback included), in the order the OS lists them.
///
/// # Errors
///
/// Fails when `getifaddrs` fails.
pub fn addresses() -> io::Result<Vec<IpAddr>> {
    let mut head: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: getifaddrs writes a list head into the pointer we pass, or fails.
    if unsafe { libc::getifaddrs(&raw mut head) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let mut out = Vec::new();
    let mut cur = head;
    while !cur.is_null() {
        // SAFETY: a non-null node of the list getifaddrs returned, alive until freeifaddrs.
        let ifa = unsafe { &*cur };
        if !ifa.ifa_addr.is_null() {
            // SAFETY: ifa_addr points at a sockaddr whose family says which type it is.
            let family = i32::from(unsafe { (*ifa.ifa_addr).sa_family });
            if family == libc::AF_INET {
                // SAFETY: an AF_INET address is a sockaddr_in.
                #[expect(
                    clippy::cast_ptr_alignment,
                    reason = "getifaddrs allocates each address aligned for its family's sockaddr type"
                )]
                let sin = unsafe { &*(ifa.ifa_addr as *const libc::sockaddr_in) };
                out.push(IpAddr::V4(Ipv4Addr::from(u32::from_be(
                    sin.sin_addr.s_addr,
                ))));
            } else if family == libc::AF_INET6 {
                // SAFETY: an AF_INET6 address is a sockaddr_in6.
                #[expect(
                    clippy::cast_ptr_alignment,
                    reason = "getifaddrs allocates each address aligned for its family's sockaddr type"
                )]
                let sin6 = unsafe { &*(ifa.ifa_addr as *const libc::sockaddr_in6) };
                out.push(IpAddr::V6(Ipv6Addr::from(sin6.sin6_addr.s6_addr)));
            }
        }
        cur = ifa.ifa_next;
    }
    // SAFETY: the list getifaddrs returned, freed once.
    unsafe { libc::freeifaddrs(head) };
    Ok(out)
}

/// Whether other hosts can reach this host at `ip`: not loopback, unspecified, multicast or
/// link-local (a link-local address needs an interface name to be dialed).
#[must_use]
pub const fn reachable(ip: IpAddr) -> bool {
    match ip.to_canonical() {
        IpAddr::V4(v4) => {
            !(v4.is_loopback() || v4.is_unspecified() || v4.is_multicast() || v4.is_link_local())
        }
        IpAddr::V6(v6) => {
            !(v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || v6.is_unicast_link_local())
        }
    }
}

/// The addresses other hosts can reach this host at ([`reachable`]): IPv4 first, each once.
///
/// # Errors
///
/// Fails when the interface addresses cannot be listed.
pub fn reachable_addresses() -> io::Result<Vec<IpAddr>> {
    let mut out: Vec<IpAddr> = addresses()?
        .into_iter()
        .map(|ip| ip.to_canonical())
        .filter(|ip| reachable(*ip))
        .collect();
    out.sort_by_key(|ip| (ip.is_ipv6(), *ip));
    out.dedup();
    Ok(out)
}
