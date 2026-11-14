//! SOCKS5 (RFC 1928) server side: the no-authentication method only, CONNECT and (when the
//! Gateway allows it) UDP ASSOCIATE. BIND is not supported.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::Instant;
use vpn_platform::nobufs::Patient;
use vpn_tunnel::TunnelConnector;

use vpn_ipc::identity::{
    GATEWAY_AUTH_METHOD, GATEWAY_MARK_SSH_PULL, GATEWAY_MARK_SSH_SESSION, gateway_proof,
};

use super::connect::{self, ConnectError, Host};
use super::{Shared, splice, udp};
use crate::counters::TcpClass;
use crate::dns::{Resolve, ResolveError};

pub(super) const VERSION: u8 = 0x05;
const METHOD_NO_AUTH: u8 = 0x00;
const METHOD_NONE_ACCEPTABLE: u8 = 0xFF;

const CMD_CONNECT: u8 = 0x01;
const CMD_UDP_ASSOCIATE: u8 = 0x03;

const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;

pub(super) const REP_SUCCEEDED: u8 = 0x00;
pub(super) const REP_GENERAL_FAILURE: u8 = 0x01;
const REP_NOT_ALLOWED: u8 = 0x02;
const REP_NETWORK_UNREACHABLE: u8 = 0x03;
const REP_HOST_UNREACHABLE: u8 = 0x04;
const REP_CONNECTION_REFUSED: u8 = 0x05;
const REP_COMMAND_NOT_SUPPORTED: u8 = 0x07;
const REP_ADDRESS_TYPE_NOT_SUPPORTED: u8 = 0x08;

/// `BND.ADDR` for CONNECT and failures: the tunnel-side address means nothing to a loopback client.
const UNSPECIFIED: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);
/// After a failure reply, how long to wait for the client to close before we do, so a reset
/// caused by unread pipelined data cannot destroy the reply.
const LINGER: Duration = Duration::from_millis(500);

/// `DST.ADDR` as the client sent it.
pub(super) enum Address {
    Ip(IpAddr),
    Domain(Vec<u8>),
}

impl Address {
    /// The destination host; `None` for an empty or non-UTF-8 domain.
    pub(super) fn into_host(self) -> Option<Host> {
        match self {
            Self::Ip(ip) => Some(Host::Ip(ip)),
            Self::Domain(raw) => String::from_utf8(raw)
                .ok()
                .filter(|name| !name.is_empty())
                .map(|name| Host::parse(&name)),
        }
    }
}

enum Request {
    /// With what the client says the connection carries (a mark in its method list), if anything.
    Connect(Address, u16, Option<TcpClass>),
    /// Carries `DST.PORT`: the port the client will send from, or 0 if unknown.
    UdpAssociate(u16),
    /// Answer with this reply code and close.
    Refuse(u8),
}

pub(super) async fn serve<C: TunnelConnector, R: Resolve>(
    shared: &Arc<Shared<C, R>>,
    mut stream: TcpStream,
    peer: SocketAddr,
    deadline: Instant,
) {
    let auth = shared.config.auth_key.as_deref().map(|k| &**k);
    let request = match tokio::time::timeout_at(deadline, negotiate(&mut stream, auth)).await {
        Ok(Ok(request)) => request,
        Ok(Err(e)) => {
            tracing::debug!(gateway = %shared.config.id, error = %e, "SOCKS5 negotiation failed");
            return;
        }
        Err(_) => {
            tracing::debug!(gateway = %shared.config.id, "SOCKS5 negotiation timed out");
            return;
        }
    };
    match request {
        Request::Connect(address, port, marked) => {
            let class = marked.unwrap_or_else(|| TcpClass::of_port(port));
            connect(shared, stream, address, port, class).await;
        }
        Request::UdpAssociate(port) if shared.config.udp => {
            udp::associate(shared, stream, peer, port).await;
        }
        Request::UdpAssociate(_) => refuse(stream, REP_COMMAND_NOT_SUPPORTED).await,
        Request::Refuse(code) => refuse(stream, code).await,
    }
}

/// Method selection and the request. Reads exactly what the protocol defines, so data a client
/// pipelines after its request stays in the socket for the relay.
async fn negotiate(stream: &mut TcpStream, auth: Option<&[u8; 32]>) -> io::Result<Request> {
    // A host short of buffer space (`ENOBUFS`) is waited out, here as in the relay.
    let stream = &mut Patient::new(stream);
    // VER NMETHODS METHODS...
    let mut greeting = [0u8; 2];
    stream.read_exact(&mut greeting).await?;
    if greeting[0] != VERSION {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "not a SOCKS5 greeting",
        ));
    }
    let mut methods = [0u8; 255];
    let methods = &mut methods[..usize::from(greeting[1])];
    stream.read_exact(methods).await?;
    // A VPN Manager client lists what its connection carries as a private method it never
    // expects to be selected: only how its bytes are counted depends on it.
    let marked = if methods.contains(&GATEWAY_MARK_SSH_PULL) {
        Some(TcpClass::SshPull)
    } else if methods.contains(&GATEWAY_MARK_SSH_SESSION) {
        Some(TcpClass::Ssh)
    } else {
        None
    };
    match auth {
        // `vpnctl` asks this Gateway to prove it belongs to the installation.
        Some(key) if methods.contains(&GATEWAY_AUTH_METHOD) => {
            stream.write_all(&[VERSION, GATEWAY_AUTH_METHOD]).await?;
            let mut nonce = [0u8; 32];
            stream.read_exact(&mut nonce).await?;
            stream.write_all(&gateway_proof(key, &nonce)).await?;
        }
        _ if methods.contains(&METHOD_NO_AUTH) => {
            stream.write_all(&[VERSION, METHOD_NO_AUTH]).await?;
        }
        _ => {
            stream.write_all(&[VERSION, METHOD_NONE_ACCEPTABLE]).await?;
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "client offers no acceptable SOCKS5 method",
            ));
        }
    }

    // VER CMD RSV ATYP DST.ADDR DST.PORT
    let mut head = [0u8; 4];
    stream.read_exact(&mut head).await?;
    if head[0] != VERSION {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "bad SOCKS5 request version",
        ));
    }
    let address = match head[3] {
        ATYP_IPV4 => {
            let mut octets = [0u8; 4];
            stream.read_exact(&mut octets).await?;
            Address::Ip(Ipv4Addr::from(octets).into())
        }
        ATYP_IPV6 => {
            let mut octets = [0u8; 16];
            stream.read_exact(&mut octets).await?;
            Address::Ip(Ipv6Addr::from(octets).into())
        }
        ATYP_DOMAIN => {
            let len = stream.read_u8().await?;
            let mut name = vec![0u8; usize::from(len)];
            stream.read_exact(&mut name).await?;
            Address::Domain(name)
        }
        // The rest of the request cannot be framed.
        _ => return Ok(Request::Refuse(REP_ADDRESS_TYPE_NOT_SUPPORTED)),
    };
    let port = stream.read_u16().await?;
    Ok(match head[1] {
        CMD_CONNECT => Request::Connect(address, port, marked),
        CMD_UDP_ASSOCIATE => Request::UdpAssociate(port),
        // BIND and unknown commands.
        _ => Request::Refuse(REP_COMMAND_NOT_SUPPORTED),
    })
}

async fn connect<C: TunnelConnector, R: Resolve>(
    shared: &Arc<Shared<C, R>>,
    mut stream: TcpStream,
    address: Address,
    port: u16,
    class: TcpClass,
) {
    let Some(host) = address.into_host() else {
        return refuse(stream, REP_HOST_UNREACHABLE).await;
    };
    let upstream = match connect::connect(shared, &host, port).await {
        Ok(upstream) => upstream,
        Err(error) => return refuse(stream, reply_code(&error)).await,
    };
    if Patient::new(&mut stream)
        .write_all(&reply(REP_SUCCEEDED, UNSPECIFIED))
        .await
        .is_err()
    {
        return;
    }
    let idle = shared.config.tcp_idle_timeout;
    let client = stream.into_split();
    let relayed = splice::splice(
        client,
        &[],
        upstream,
        &shared.counters,
        class,
        &shared.shaper,
        idle,
    );
    if let Err(e) = relayed.await {
        tracing::debug!(gateway = %shared.config.id, error = %e, "SOCKS5 relay ended with an error");
    }
}

/// The reply code for a failed CONNECT or UDP ASSOCIATE.
pub(super) const fn reply_code(error: &ConnectError) -> u8 {
    match error {
        ConnectError::Denied(_) | ConnectError::GateClosed => REP_NOT_ALLOWED,
        ConnectError::Resolve(ResolveError::NotFound | ResolveError::InvalidName) => {
            REP_HOST_UNREACHABLE
        }
        ConnectError::NetworkUnreachable => REP_NETWORK_UNREACHABLE,
        ConnectError::HostUnreachable | ConnectError::TimedOut => REP_HOST_UNREACHABLE,
        ConnectError::Refused => REP_CONNECTION_REFUSED,
        ConnectError::Resolve(
            ResolveError::Failed | ResolveError::Overloaded | ResolveError::Interrupted,
        )
        | ConnectError::Admission
        | ConnectError::Failed => REP_GENERAL_FAILURE,
    }
}

/// `VER REP RSV ATYP BND.ADDR BND.PORT`.
pub(super) fn reply(code: u8, bind: SocketAddr) -> Vec<u8> {
    let mut out = Vec::with_capacity(22);
    out.extend_from_slice(&[VERSION, code, 0x00]);
    put_socket_addr(&mut out, bind);
    out
}

/// Send a failure reply and close without losing it: shut down our side, then briefly drain what
/// the client may still send until it closes.
pub(super) async fn refuse(stream: TcpStream, code: u8) {
    let mut stream = Patient::new(stream);
    if stream.write_all(&reply(code, UNSPECIFIED)).await.is_err() {
        return;
    }
    let _ = stream.shutdown().await;
    let mut sink = [0u8; 1024];
    let drain = async { while matches!(stream.read(&mut sink).await, Ok(n) if n > 0) {} };
    let _ = tokio::time::timeout(LINGER, drain).await;
}

/// `ATYP ADDR PORT` with IPv4-mapped IPv6 addresses written as IPv4.
fn put_socket_addr(out: &mut Vec<u8>, addr: SocketAddr) {
    match addr.ip().to_canonical() {
        IpAddr::V4(v4) => {
            out.push(ATYP_IPV4);
            out.extend_from_slice(&v4.octets());
        }
        IpAddr::V6(v6) => {
            out.push(ATYP_IPV6);
            out.extend_from_slice(&v6.octets());
        }
    }
    out.extend_from_slice(&addr.port().to_be_bytes());
}

/// Largest UDP request header we write (`RSV FRAG` + IPv6 address form).
pub(super) const MAX_UDP_HEADER: usize = 3 + 1 + 16 + 2;

/// The UDP request header `RSV(2) FRAG(1) ATYP DST.ADDR DST.PORT` for a datagram from `src`.
pub(super) fn udp_header(src: SocketAddr) -> Vec<u8> {
    let mut out = Vec::with_capacity(MAX_UDP_HEADER);
    out.extend_from_slice(&[0x00, 0x00, 0x00]);
    put_socket_addr(&mut out, src);
    out
}

/// Split a client datagram into destination and payload. `None` if it is malformed or a fragment
/// (FRAG ≠ 0; fragmentation is not supported and such datagrams are dropped).
pub(super) fn parse_udp_datagram(datagram: &[u8]) -> Option<(Address, u16, &[u8])> {
    let [_, _, frag, atyp, rest @ ..] = datagram else {
        return None;
    };
    if *frag != 0 {
        return None;
    }
    let (address, rest) = match *atyp {
        ATYP_IPV4 => {
            let (octets, rest) = rest.split_first_chunk::<4>()?;
            (Address::Ip(Ipv4Addr::from(*octets).into()), rest)
        }
        ATYP_IPV6 => {
            let (octets, rest) = rest.split_first_chunk::<16>()?;
            (Address::Ip(Ipv6Addr::from(*octets).into()), rest)
        }
        ATYP_DOMAIN => {
            let (len, rest) = rest.split_first()?;
            let name = rest.get(..usize::from(*len))?;
            (Address::Domain(name.to_vec()), &rest[name.len()..])
        }
        _ => return None,
    };
    let (port, payload) = rest.split_first_chunk::<2>()?;
    Some((address, u16::from_be_bytes(*port), payload))
}
