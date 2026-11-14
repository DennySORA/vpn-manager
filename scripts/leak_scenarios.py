#!/usr/bin/env python3
"""Scenarios of scripts/leak-capture-linux.sh (Python 3.9+, stdlib only); see DESCRIPTION."""

from __future__ import annotations

import argparse
import contextlib
import errno
import http.client
import ipaddress
import json
import os
import re
import secrets
import shutil
import signal
import socket
import struct
import subprocess
import sys
import threading
import time
import traceback
import urllib.parse
import uuid
from http import HTTPStatus
from pathlib import Path
from typing import TYPE_CHECKING, Any, NoReturn, TypedDict, cast

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable, Iterator
    from typing import TextIO

# The command-line help (argparse description, shown verbatim).
DESCRIPTION = """Scenarios of scripts/leak-capture-linux.sh (Python 3.9+, stdlib only).

  drive      Runs inside the harness namespaces as the unprivileged user (no capabilities in the
             harness's network namespace, like a real installation): starts scripts/dev-stack.sh
             (seeded), runs every scenario and records what it did and when in
             OUT/results/events.jsonl (the analysis attributes packets by these timestamps),
             takes the network-namespace snapshots (OUT/snapshots/netns-*.txt) and writes
             OUT/results/meta.json.
  app-probe  The managed App's side: runs inside the connection's strict sandbox (started by the
             manager through /v1/apps), does what its plan file says and prints one JSON line
             per probe (the App log).

Payload markers: every request, datagram and DNS name the scenarios send carries the run's token
(meta.json "token"). The analysis requires it nowhere but on client<->proxy loopback and inside the
tunnel device: in a WireGuard packet it would be plaintext, on the NIC it would be a leak.
"""

# A JSON object as the API, a plan file or a probe result carries it.
JsonDict = dict[str, Any]

HERE = Path(__file__).absolute().parent

LAB_V4, LAB_V6 = "10.99.0.1", "fd99::1"
CLIENT_V4, CLIENT_V6 = "10.99.0.2", "fd99::2"
# Owned by the lab peer and global in form (RFC 7526's retired 6to4 relay prefix): a stand-in for
# an Internet destination, reachable only through the tunnel.
INTERNET_V4 = "192.88.99.7"
# Global addresses that nothing in the lab serves: through the tunnel they go unanswered.
PUBLIC_V6 = "2606:4700:4700::1111"
# The harness's "outside world": TEST-NET destinations behind the fake NIC.
DIRECT_V4, DIRECT_V6 = "192.0.2.80", "2001:db8:2::80"
SYSTEM_RESOLVER = "192.0.2.53"
NIC_ADDR_V4 = "192.0.2.2"

# Wire constants.
DNS_PORT = 53
QTYPE_A, QTYPE_AAAA = 1, 28
DNS_POINTER = 0xC0
IPV4_VERSION = 4
IPV4_LEN, IPV6_LEN = 4, 16
SOCKS5_ATYP_DOMAIN = 3
# Probe parameters.
UDP_TRIES = 3
QUIC_BURST = 10
ASSOCIATION_MAX_MISSES = 5
API_ATTEMPTS = 3


def log(msg: str) -> None:
    """Print one timestamped progress line."""
    sys.stdout.write(f"[{time.strftime('%H:%M:%S')}] {msg}\n")
    sys.stdout.flush()


def said(text: object) -> str:
    """Text the service wrote (`{"en", "zh-TW", "ja"}`), in English; anything else as it is."""
    if isinstance(text, dict):
        return str(text.get("en", text))
    return str(text)


def elapsed_ms(t0: float) -> int:
    """Return the milliseconds since the monotonic time `t0`."""
    return int((time.monotonic() - t0) * 1000)


# --------------------------------------------------------------------------------------------
# Wire helpers (DNS, SOCKS5, HTTP) shared by the driver and the App
# --------------------------------------------------------------------------------------------


def recv_exact(s: socket.socket, n: int) -> bytes:
    """Read exactly `n` bytes; EOFError when the peer closes first."""
    buf = b""
    while len(buf) < n:
        chunk = s.recv(n - len(buf))
        if not chunk:
            msg = "connection closed"
            raise EOFError(msg)
        buf += chunk
    return buf


def recv_all(s: socket.socket, limit: int = 64 << 20) -> bytes:
    """Read until the peer closes (or `limit` bytes)."""
    buf = bytearray()
    while len(buf) < limit:
        chunk = s.recv(65536)
        if not chunk:
            break
        buf += chunk
    return bytes(buf)


def dns_query(name: str, qtype: int, qid: int | None = None) -> bytes:
    """Build a recursive DNS query for `name` (random id unless given)."""
    qid = secrets.randbelow(65536) if qid is None else qid
    q = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0)
    for label in name.rstrip(".").split("."):
        q += bytes([len(label)]) + label.encode()
    return q + b"\0" + struct.pack(">HH", qtype, 1)


def _skip_name(m: bytes, off: int) -> int:
    while True:
        n = m[off]
        if n == 0:
            return off + 1
        if n & DNS_POINTER == DNS_POINTER:
            return off + 2
        off += 1 + n


def dns_parse(m: bytes) -> tuple[int, int, list[str]]:
    """Parse a DNS response: (id, rcode, [A/AAAA addresses])."""
    qid, flags, qd, an, _ns, _ar = struct.unpack(">HHHHHH", m[:12])
    off = 12
    for _ in range(qd):
        off = _skip_name(m, off) + 4
    addrs = []
    for _ in range(an):
        off = _skip_name(m, off)
        rtype, _cls, _ttl, rdlen = struct.unpack(">HHIH", m[off : off + 10])
        off += 10
        rd = m[off : off + rdlen]
        off += rdlen
        if rtype == QTYPE_A and rdlen == IPV4_LEN:
            addrs.append(socket.inet_ntop(socket.AF_INET, rd))
        elif rtype == QTYPE_AAAA and rdlen == IPV6_LEN:
            addrs.append(socket.inet_ntop(socket.AF_INET6, rd))
    return qid, flags & 0xF, addrs


RCODES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}


def family_of(host: str) -> socket.AddressFamily:
    """Return the address family of a literal address."""
    return socket.AF_INET6 if ":" in host else socket.AF_INET


def socks5_addr(host: str, port: int) -> bytes:
    """Encode a SOCKS5 address (IPv4, IPv6 or domain name) and port."""
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        h = host.encode()
        return b"\x03" + bytes([len(h)]) + h + struct.pack(">H", port)
    else:
        return (
            (b"\x01" if ip.version == IPV4_VERSION else b"\x04")
            + ip.packed
            + struct.pack(">H", port)
        )


def socks5_greet(gw_port: int, timeout: float) -> socket.socket:
    """Connect to a Gateway and agree on SOCKS5 without authentication."""
    s = socket.create_connection(("127.0.0.1", gw_port), timeout=timeout)
    s.sendall(b"\x05\x01\x00")
    if recv_exact(s, 2) != b"\x05\x00":
        s.close()
        msg = "SOCKS5 method not accepted"
        raise OSError(msg)
    return s


def socks5_reply(s: socket.socket) -> tuple[int, int, bytes, int]:
    """Read a SOCKS5 reply: (reply code, address type, address, port)."""
    head = recv_exact(s, 4)
    rep, atyp = head[1], head[3]
    n = {1: 4, 4: 16}.get(atyp)
    if n is None:
        n = recv_exact(s, 1)[0]
    addr = recv_exact(s, n)
    port = struct.unpack(">H", recv_exact(s, 2))[0]
    return rep, atyp, addr, port


def socks5_connect(
    gw_port: int, host: str, port: int, timeout: float = 10.0
) -> tuple[socket.socket | None, int | str, float]:
    """Send a SOCKS5 CONNECT: (socket or None, outcome, seconds until the outcome).

    The socket only when the CONNECT succeeded (reply 0); otherwise the reply code, or
    'no reply: <error>' when the connection was reset or closed without a reply (both mean the
    request was blocked).
    """
    t0 = time.monotonic()
    s = None
    try:
        s = socks5_greet(gw_port, timeout)
        s.sendall(b"\x05\x01\x00" + socks5_addr(host, port))
        rep = socks5_reply(s)[0]
    except (OSError, EOFError) as e:
        if s is not None:
            s.close()
        return None, f"no reply: {errno_name(e)}", time.monotonic() - t0
    elapsed = time.monotonic() - t0
    if rep != 0:
        s.close()
        return None, rep, elapsed
    return s, 0, elapsed


class Socks5Udp:
    """One UDP ASSOCIATE: the control connection, our datagram socket and the relay address."""

    def __init__(
        self,
        gw_port: int,
        timeout: float = 5.0,
        on_relay: Callable[[str], None] | None = None,
    ) -> None:
        """Associate through the Gateway on `gw_port`; `on_relay` learns the relay address."""
        self.ctl = socks5_greet(gw_port, timeout)
        self.u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.u.bind(("127.0.0.1", 0))
        port = self.u.getsockname()[1]
        self.ctl.sendall(b"\x05\x03\x00\x01" + bytes(4) + struct.pack(">H", port))
        rep, atyp, addr, rport = socks5_reply(self.ctl)
        if rep != 0:
            self.close()
            msg = f"UDP ASSOCIATE refused (reply {rep})"
            raise OSError(msg)
        host = socket.inet_ntop(socket.AF_INET if atyp == 1 else socket.AF_INET6, addr)
        if ipaddress.ip_address(host).is_unspecified:
            host = "127.0.0.1"
        self.relay = (host, rport)
        if on_relay:
            on_relay(f"{host}:{rport}")

    def send(self, host: str, port: int, payload: bytes) -> None:
        """Send one datagram to host:port through the relay."""
        self.u.sendto(b"\x00\x00\x00" + socks5_addr(host, port) + payload, self.relay)

    def recv_from(self, timeout: float) -> tuple[str, int, bytes]:
        """Return (source host, source port, payload) of the next relayed datagram."""
        self.u.settimeout(timeout)
        data, _ = self.u.recvfrom(65535)
        atyp = data[3]
        n = {1: 4, 4: 16}.get(atyp, 0)
        if atyp == SOCKS5_ATYP_DOMAIN:
            n = 1 + data[4]
            host = data[5 : 5 + data[4]].decode(errors="replace")
        else:
            host = socket.inet_ntop(
                socket.AF_INET if atyp == 1 else socket.AF_INET6, data[4 : 4 + n]
            )
        port = struct.unpack(">H", data[4 + n : 4 + n + 2])[0]
        return host, port, data[4 + n + 2 :]

    def recv(self, timeout: float) -> bytes:
        """Return the payload of the next relayed datagram."""
        return self.recv_from(timeout)[2]

    def closed(self) -> bool:
        """Tell whether the Gateway ended the association (its control connection closed)."""
        self.ctl.settimeout(0.0)  # non-blocking, as setblocking(False)
        try:
            return self.ctl.recv(1) == b""
        except BlockingIOError:
            return False
        except OSError:
            return True
        finally:
            with contextlib.suppress(OSError):
                self.ctl.settimeout(None)  # blocking, as setblocking(True)

    def close(self) -> None:
        """Close both sockets."""
        for s in (self.u, self.ctl):
            with contextlib.suppress(OSError):
                s.close()


def http_exchange(s: socket.socket, request: bytes, timeout: float = 15.0) -> tuple[int, bytes]:
    """Send a request on a connected socket; (status, body)."""
    s.settimeout(timeout)
    s.sendall(request)
    data = recv_all(s)
    head, _, body = data.partition(b"\r\n\r\n")
    try:
        status = int(head.split(b" ", 2)[1])
    except (IndexError, ValueError):
        status = 0
    if b"transfer-encoding: chunked" in head.lower():
        body = dechunk(body)
    return status, body


def dechunk(b: bytes) -> bytes:
    """Decode a chunked transfer-encoded body."""
    out, i = bytearray(), 0
    while i < len(b):
        j = b.find(b"\r\n", i)
        if j < 0:
            break
        n = int(b[i:j].split(b";")[0] or b"0", 16)
        if n == 0:
            break
        out += b[j + 2 : j + 2 + n]
        i = j + 2 + n + 2
    return bytes(out)


def http_request(method_target: str, host: str, marker: str) -> bytes:
    """Build a GET request carrying the leak marker header."""
    return (
        f"GET {method_target} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n"
        f"User-Agent: vpnm-leak-capture\r\nX-Leak-Marker: {marker}\r\n\r\n"
    ).encode()


def errno_name(e: BaseException) -> str:
    """Return the errno symbol of an error (else its type name)."""
    code = getattr(e, "errno", None)
    return errno.errorcode.get(code, str(code)) if code else type(e).__name__


# --------------------------------------------------------------------------------------------
# The App probe (runs inside the strict sandbox)
# --------------------------------------------------------------------------------------------


class Emit:
    """The App log: one JSON line per probe result on stdout."""

    def __init__(self) -> None:
        """Start with an unlocked output."""
        self.lock = threading.Lock()

    def __call__(
        self, probe: str, ok: object, *, observation: bool = False, **detail: object
    ) -> None:
        """Write one probe result.

        `observation`: product behaviour worth reporting that is not part of the leak verdict
        (the analysis lists it separately).
        """
        line = json.dumps(
            {
                "probe": probe,
                "ok": bool(ok),
                "t": time.time(),
                "detail": detail,
                "observation": observation,
            },
            default=str,
        )
        with self.lock:
            sys.stdout.write(line + "\n")
            sys.stdout.flush()


def app_tcp_echo(host: str, port: int, msg: bytes, timeout: float = 3.0) -> tuple[bool, JsonDict]:
    """Echo `msg` over TCP: (echoed intact, detail)."""
    t0 = time.monotonic()
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.sendall(msg)
            got = recv_exact(s, len(msg))
            return got == msg, {"elapsed_ms": elapsed_ms(t0)}
    except (OSError, EOFError) as e:
        return False, {"error": errno_name(e), "elapsed_ms": elapsed_ms(t0)}


def _udp_try(
    u: socket.socket, dest: tuple[str, int], payload: bytes
) -> tuple[bytes | None, str | None]:
    """Send one datagram and wait for one: (data or None, error name or None)."""
    try:
        u.sendto(payload, dest)
        data, _ = u.recvfrom(65535)
    except OSError as e:
        return None, errno_name(e)
    else:
        return data, None


def app_udp_echo(
    host: str, port: int, msg: bytes, timeout: float = 1.0, tries: int = UDP_TRIES
) -> tuple[bool, JsonDict]:
    """Echo numbered datagrams over UDP: (any echoed, detail)."""
    fam = family_of(host)
    got = 0
    err = None
    with socket.socket(fam, socket.SOCK_DGRAM) as u:
        u.settimeout(timeout)
        for i in range(tries):
            data, e = _udp_try(u, (host, port), msg + b"#%d" % i)
            if data is None:
                err = e
            else:
                got += data == msg + b"#%d" % i
    return got > 0, {"echoed": got, "sent": tries, "error": err}


def _udp_send_recv(
    u: socket.socket, dest: tuple[str, int], payload: bytes
) -> tuple[bool, tuple[bytes, Any] | None, str | None]:
    """Send one datagram, then wait for one: (sent, (data, source) or None, error or None)."""
    sent = False
    try:
        u.sendto(payload, dest)
        sent = True
        reply = u.recvfrom(65535)
    except OSError as e:
        return sent, None, errno_name(e)
    else:
        return sent, reply, None


def app_udp_exchange(
    host: str, port: int, msg: bytes, timeout: float = 1.0, tries: int = UDP_TRIES
) -> JsonDict:
    """Datagrams to host:port on an unconnected socket, recording where any reply came from."""
    replies: list[JsonDict] = []
    err, sent = None, 0
    with socket.socket(family_of(host), socket.SOCK_DGRAM) as u:
        u.settimeout(timeout)
        for i in range(tries):
            ok, reply, e = _udp_send_recv(u, (host, port), msg + b"#%d" % i)
            sent += ok
            if reply is None:
                err = e
            else:
                data, src = reply
                replies.append({"from": src[0], "port": src[1], "echo": data == msg + b"#%d" % i})
    return {"sent": sent, "replies": replies, "error": err}


def app_expect_tcp_refused(host: str, port: int, timeout: float = 4.0) -> tuple[bool, JsonDict]:
    """Expect the connection not to be made: how it failed and how fast."""
    t0 = time.monotonic()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return False, {"connected": True}
    except OSError as e:
        return True, {"error": errno_name(e), "elapsed_ms": elapsed_ms(t0)}


def app_send_udp(host: str, port: int, payload: bytes) -> JsonDict:
    """Send one datagram; whether the kernel took it."""
    fam = family_of(host)
    try:
        with socket.socket(fam, socket.SOCK_DGRAM) as u:
            u.sendto(payload, (host, port))
    except OSError as e:
        return {"sent": False, "error": errno_name(e)}
    else:
        return {"sent": True}


def app_dns_udp(server: str, name: str, qtype: int, timeout: float) -> JsonDict:
    """Resolve `name` over UDP at `server`: rcode, addresses, time taken."""
    t0 = time.monotonic()
    try:
        with socket.socket(family_of(server), socket.SOCK_DGRAM) as u:
            u.settimeout(timeout)
            q = dns_query(name, qtype)
            u.sendto(q, (server, DNS_PORT))
            while True:
                data, _ = u.recvfrom(65535)
                if data[:2] == q[:2]:
                    break
        _id, rcode, addrs = dns_parse(data)
    except OSError as e:
        return {"rcode": None, "error": errno_name(e), "elapsed_ms": elapsed_ms(t0)}
    else:
        return {"rcode": RCODES.get(rcode, rcode), "addrs": addrs, "elapsed_ms": elapsed_ms(t0)}


def app_dns_tcp(server: str, name: str, qtype: int, timeout: float) -> JsonDict:
    """Resolve `name` over TCP at `server`: rcode, addresses, time taken."""
    t0 = time.monotonic()
    try:
        with socket.create_connection((server, DNS_PORT), timeout=timeout) as s:
            q = dns_query(name, qtype)
            s.sendall(struct.pack(">H", len(q)) + q)
            n = struct.unpack(">H", recv_exact(s, 2))[0]
            _id, rcode, addrs = dns_parse(recv_exact(s, n))
    except (OSError, EOFError) as e:
        return {"rcode": None, "error": errno_name(e), "elapsed_ms": elapsed_ms(t0)}
    else:
        return {"rcode": RCODES.get(rcode, rcode), "addrs": addrs, "elapsed_ms": elapsed_ms(t0)}


def app_gai(name: str, family: int = 0) -> JsonDict:
    """Resolve `name` with getaddrinfo: addresses, time taken."""
    t0 = time.monotonic()
    try:
        res = socket.getaddrinfo(name, 80, family, socket.SOCK_STREAM)
        addrs = sorted({str(r[4][0]) for r in res})
    except socket.gaierror as e:
        return {"error": f"gaierror {e.errno}: {e.strerror}", "elapsed_ms": elapsed_ms(t0)}
    else:
        return {"addrs": addrs, "elapsed_ms": elapsed_ms(t0)}


def read_text(path: str) -> str:
    """Read a text file, or '<ERRNO>' when it cannot be read."""
    try:
        return Path(path).read_text()
    except OSError as e:
        return f"<{errno_name(e)}>"


def app_environment(emit: Emit, *, expect_v6: bool) -> None:
    """Check the sandbox: interfaces, capabilities, routes, resolver, IPv6."""
    names = sorted(n for _, n in socket.if_nameindex())
    dev = sorted(ln.split(":")[0].strip() for ln in read_text("/proc/net/dev").splitlines()[2:])
    v6 = [ln.split() for ln in read_text("/proc/net/if_inet6").splitlines() if ln.strip()]
    v6_addrs = sorted({(f[5], ":".join(f[0][i : i + 4] for i in range(0, 32, 4))) for f in v6})
    routes4 = read_text("/proc/net/route").splitlines()[1:]
    routes6 = [ln.split() for ln in read_text("/proc/net/ipv6_route").splitlines() if ln.strip()]
    default6 = [r[9] for r in routes6 if r[0] == "0" * 32 and r[1] == "00" and r[9] != "lo"]
    try:
        ip4 = subprocess.run(
            ["ip", "-o", "-4", "addr", "show"],  # noqa: S607 - the sandbox's own PATH, fixed argv
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        ).stdout.split("\n")
    except OSError:
        ip4 = []
    status = read_text("/proc/self/status")
    caps = re.search(r"CapEff:\s*(\S+)", status)
    nnp = re.search(r"NoNewPrivs:\s*(\S+)", status)
    disable_v6 = read_text("/proc/sys/net/ipv6/conf/vpn0/disable_ipv6").strip()
    detail: JsonDict = {
        "if_nameindex": names,
        "proc_net_dev": dev,
        "ipv4": [ln.strip() for ln in ip4 if ln.strip()],
        "ipv6": [f"{iface} {addr}" for iface, addr in v6_addrs],
        "default_route_v4_devs": sorted(
            {ln.split()[0] for ln in routes4 if ln.split() and ln.split()[1] == "00000000"}
        ),
        "default_route_v6_devs": sorted(set(default6)),
        "vpn0_disable_ipv6": disable_v6,
        "resolv_conf": read_text("/etc/resolv.conf"),
        "CapEff": caps.group(1) if caps else None,
        "NoNewPrivs": nnp.group(1) if nnp else None,
        "uid": os.getuid(),
    }
    emit(
        "environment: only lo and vpn0",
        names == ["lo", "vpn0"] and dev == ["lo", "vpn0"],
        **detail,
    )
    emit(
        "environment: no capabilities, no_new_privs",
        detail["CapEff"] == "0000000000000000" and detail["NoNewPrivs"] == "1",
        CapEff=detail["CapEff"],
        NoNewPrivs=detail["NoNewPrivs"],
    )
    emit(
        "environment: default routes only via vpn0",
        detail["default_route_v4_devs"] == ["vpn0"]
        and detail["default_route_v6_devs"] == (["vpn0"] if expect_v6 else []),
        v4=detail["default_route_v4_devs"],
        v6=detail["default_route_v6_devs"],
    )
    emit(
        "environment: resolv.conf names only the sandbox resolver 127.0.0.53",
        re.findall(r"(?m)^nameserver\s+(\S+)", detail["resolv_conf"]) == ["127.0.0.53"],
        resolv_conf=detail["resolv_conf"],
    )
    if not expect_v6:
        has_v6 = [a for a in detail["ipv6"] if a.startswith("vpn0 ")]
        emit(
            "environment: no IPv6 on vpn0 (IPv6 disabled on the device)",
            not has_v6 and disable_v6 == "1",
            ipv6=detail["ipv6"],
            disable_ipv6=disable_v6,
        )


def _marker(tok: str, kind: str) -> Callable[[str], bytes]:
    """Return a function that makes the payload marker `<token>-<kind>-<s>`."""

    def m(s: str) -> bytes:
        return f"{tok}-{kind}-{s}".encode()

    return m


def _baseline_echo(emit: Emit, tok: str, m: Callable[[str], bytes]) -> None:
    """TCP and UDP echo through the tunnel, and UDP whose reply comes from elsewhere."""
    for host in (LAB_V4, LAB_V6, INTERNET_V4):
        ok, d = app_tcp_echo(host, 7, m(f"tcp-echo-{host}") + b"\n")
        emit(f"TCP echo {host}:7 through the tunnel", ok, **d)
    for host in (LAB_V4, LAB_V6):
        ok, d = app_udp_echo(host, 7, m(f"udp-echo-{host}"))
        emit(f"UDP echo {host}:7 through the tunnel", ok, **d)
    # The lab peer answers UDP from its first address (10.99.0.1), not from the address it was
    # sent to. A reply from another address than the App's flow is unsolicited inbound: the
    # strict filter must not deliver it. (The datagrams themselves are seen in the tunnel.)
    for port in (7, DNS_PORT):
        payload = (
            dns_query(f"{tok}-app-udp53-internet.lab.test", 1)
            if port == DNS_PORT
            else m(f"udp-{port}-internet")
        )
        d = app_udp_exchange(INTERNET_V4, port, payload)
        foreign = [r for r in d["replies"] if r["from"] != INTERNET_V4]
        emit(
            f"UDP to {INTERNET_V4}:{port} sent into the tunnel; no reply from another address "
            "let in",
            d["sent"] == UDP_TRIES and not foreign,
            **d,
        )


def _baseline_http(emit: Emit, tok: str) -> None:
    """Resolve a lab name, then HTTP by name per address and to the Internet-like address."""
    name = f"{tok}-app-http.lab.test"
    g = app_gai(name)
    emit(
        "getaddrinfo through the sandbox resolver (A and AAAA)",
        set(g.get("addrs", [])) == {LAB_V4, LAB_V6},
        name=name,
        **g,
    )
    for addr in g.get("addrs", []):
        want = CLIENT_V6 if ":" in addr else CLIENT_V4
        try:
            with socket.create_connection((addr, 80), timeout=5) as s:
                st, body = http_exchange(s, http_request("/ip", name, tok))
            emit(
                f"HTTP GET http://{name}/ip via {addr}",
                st == HTTPStatus.OK and want in body.decode(),
                status=st,
                body=body[:200].decode(errors="replace"),
            )
        except OSError as e:
            emit(f"HTTP GET http://{name}/ip via {addr}", ok=False, error=errno_name(e))
    try:
        with socket.create_connection((INTERNET_V4, 80), timeout=5) as s:
            st, body = http_exchange(s, http_request("/", INTERNET_V4, tok))
        emit(
            f"HTTP GET http://{INTERNET_V4}/ (Internet-like address, via the tunnel only)",
            st == HTTPStatus.OK and b"labpeer ok" in body,
            status=st,
        )
    except OSError as e:
        emit(f"HTTP GET http://{INTERNET_V4}/", ok=False, error=errno_name(e))


def _baseline_dns(emit: Emit, tok: str) -> None:
    """DNS over UDP and TCP to the sandbox resolver and to the lab's resolvers."""
    for server, qtype, transport in (
        ("127.0.0.53", 1, "udp"),
        ("127.0.0.53", 28, "tcp"),
        (LAB_V4, 1, "udp"),
        (LAB_V6, 28, "udp"),
        (INTERNET_V4, 1, "tcp"),
    ):
        where = server.replace(":", "").replace(".", "")
        name = f"{tok}-app-dns-{transport}{qtype}-{where}.lab.test"
        r = (app_dns_udp if transport == "udp" else app_dns_tcp)(server, name, qtype, 5.0)
        want = LAB_V4 if qtype == 1 else LAB_V6
        emit(
            f"DNS {transport.upper()} {'A' if qtype == 1 else 'AAAA'} to {server}:53",
            r.get("rcode") == "NOERROR" and want in r.get("addrs", []),
            **r,
        )


def _baseline_udp_own(emit: Emit, m: Callable[[str], bytes]) -> None:
    """QUIC-like Initial bursts and a STUN binding request (WebRTC): UDP the App sends itself."""
    for host in (LAB_V4, LAB_V6, INTERNET_V4):
        fam = family_of(host)
        sent, err = 0, None
        with socket.socket(fam, socket.SOCK_DGRAM) as u:
            for i in range(QUIC_BURST):
                pkt = (b"\xc3\x00\x00\x00\x01\x08" + m(f"quic-{i}")).ljust(1200, b"\0")
                try:
                    u.sendto(pkt, (host, 443))
                    sent += 1
                except OSError as e:
                    err = errno_name(e)
        emit(
            f"QUIC-like burst to {host}:443 (10 x 1200 B) sent into the tunnel",
            sent == QUIC_BURST,
            sent=sent,
            error=err,
        )
    for host in (LAB_V4, LAB_V6):
        stun = struct.pack(">HHI", 0x0001, 0, 0x2112A442) + m("stun")[:12].ljust(12, b"0")
        d = app_send_udp(host, 3478, stun + m("stun-attr"))
        emit(f"STUN-like binding request to {host}:3478 sent into the tunnel", d["sent"], **d)


def _baseline_refused(emit: Emit, plan: JsonDict, tok: str) -> None:
    """Destinations the connection must refuse (security profile) and the host's own services."""
    for host, port, why in (
        (DIRECT_V4, 80, "TEST-NET (not allowed by the security profile)"),
        (DIRECT_V6, 80, "documentation prefix (not allowed)"),
        (NIC_ADDR_V4, plan["base"], "the harness host's NIC address"),
        ("127.0.0.1", plan["base"], "the host's management port (lo is the sandbox's own)"),
    ):
        ok, d = app_expect_tcp_refused(host, port)
        emit(f"TCP {host}:{port} refused: {why}", ok, **d)
    r = app_dns_udp(SYSTEM_RESOLVER, f"{tok}-app-sysres.example", 1, 2.0)
    emit(
        f"DNS to the host's system resolver {SYSTEM_RESOLVER} gets no answer",
        r.get("rcode") is None,
        **r,
    )
    for host in ("224.0.0.251", "ff02::fb"):
        d = app_send_udp(host, 5353, dns_query(f"{tok}-app-mdns.local", 1))
        emit(f"multicast {host}:5353 (mDNS) attempted (must not leave the tunnel)", ok=True, **d)


def app_baseline(plan: JsonDict, emit: Emit) -> None:
    """Probe a dual-stack strict connection: what must work and what must be refused."""
    tok = plan["token"]
    m = _marker(tok, "app")
    app_environment(emit, expect_v6=True)
    _baseline_echo(emit, tok, m)
    _baseline_http(emit, tok)
    _baseline_dns(emit, tok)
    _baseline_udp_own(emit, m)
    _baseline_refused(emit, plan, tok)


def app_v6_block(plan: JsonDict, emit: Emit) -> None:
    """Probe an IPv4-only strict connection: IPv6 refused, IPv4 working."""
    tok = plan["token"]
    m = _marker(tok, "app6")
    app_environment(emit, expect_v6=False)
    for host, port in ((LAB_V6, 7), (PUBLIC_V6, 443)):
        ok, d = app_expect_tcp_refused(host, port)
        emit(f"IPv6 TCP to [{host}]:{port} refused (profile without IPv6)", ok, **d)
    for host in (LAB_V6, PUBLIC_V6, "ff02::1"):
        d = app_send_udp(host, 7, m(f"udp6-{host}"))
        emit(f"IPv6 UDP to [{host}]:7 not sent", not d["sent"], **d)
    # Whether the sandbox resolver withholds AAAA when the tunnel has no IPv6 (the Gateways'
    # resolver does). Not a leak either way: IPv6 has no route here (checked above and below).
    name = f"{tok}-app6-name.lab.test"
    g = app_gai(name)
    emit(
        "observation: getaddrinfo in an IPv4-only sandbox returns IPv4 only",
        g.get("addrs") == [LAB_V4],
        observation=True,
        name=name,
        **g,
    )
    r = app_dns_udp("127.0.0.53", f"{tok}-app6-aaaa.lab.test", 28, 5.0)
    emit(
        "observation: AAAA through the sandbox resolver of an IPv4-only connection returns "
        "no IPv6 address",
        r.get("rcode") is not None and not [a for a in r.get("addrs", []) if ":" in a],
        observation=True,
        **r,
    )
    try:
        t0 = time.monotonic()
        with socket.create_connection((name, 7), timeout=5) as s:
            s.sendall(m("by-name") + b"\n")
            ok = recv_exact(s, len(m("by-name")) + 1) == m("by-name") + b"\n"
            peer = s.getpeername()[0]
        emit(
            "connect by name falls back to IPv4 only",
            ok and peer == LAB_V4,
            peer=peer,
            elapsed_ms=elapsed_ms(t0),
        )
    except (OSError, EOFError) as e:
        emit("connect by name falls back to IPv4 only", ok=False, error=errno_name(e))
    ok, d = app_tcp_echo(LAB_V4, 7, m("tcp4") + b"\n")
    emit(f"IPv4 TCP echo {LAB_V4}:7 still works", ok, **d)
    ok, d = app_udp_echo(LAB_V4, 7, m("udp4"))
    emit(f"IPv4 UDP echo {LAB_V4}:7 still works", ok, **d)


class _AppLoop:
    """Traffic for the fault scenarios: one result line per attempt, until the stop file."""

    def __init__(self, plan: JsonDict, emit: Emit) -> None:
        self.emit = emit
        self.tok = plan["token"]
        self.stop_file = Path(plan["stop_file"])
        self.end = time.time() + plan.get("max_seconds", 600)
        self.stopping = threading.Event()

    def running(self) -> bool:
        if self.stop_file.exists() or time.time() > self.end:
            self.stopping.set()
        return not self.stopping.is_set()

    def echo_loop(self) -> None:
        tok, emit = self.tok, self.emit
        n = 0
        while self.running():
            n += 1
            ok, d = app_tcp_echo(LAB_V4, 7, f"{tok}-loop-tcp-{n}\n".encode(), timeout=1.0)
            emit("loop tcp4", ok, **d)
            ok, d = app_udp_echo(LAB_V4, 7, f"{tok}-loop-udp4-{n}".encode(), timeout=0.4, tries=1)
            emit("loop udp4", ok, **d)
            ok, d = app_udp_echo(LAB_V6, 7, f"{tok}-loop-udp6-{n}".encode(), timeout=0.4, tries=1)
            emit("loop udp6", ok, **d)
            time.sleep(0.25)

    def dns_loop(self) -> None:
        n = 0
        while self.running():
            n += 1
            r = app_dns_udp("127.0.0.53", f"{self.tok}-loop-dns-{n}.lab.test", 1, 4.0)
            self.emit("loop dns", r.get("rcode") == "NOERROR", **r)
            time.sleep(0.5)

    def upload_loop(self) -> None:
        chunk = (f"{self.tok}-loop-upload ".encode() * 128)[:2048]
        while self.running():
            sent = 0
            try:
                with socket.create_connection((LAB_V4, 9), timeout=2) as s:
                    self.emit("loop upload connected", ok=True)
                    while self.running():
                        s.sendall(chunk)
                        sent += len(chunk)
                        time.sleep(0.02)
            except OSError as e:
                self.emit("loop upload broken", ok=False, error=errno_name(e), sent=sent)
                time.sleep(0.5)


def app_loop(plan: JsonDict, emit: Emit) -> None:
    """Traffic for the fault scenarios: one result line per attempt, until the stop file."""
    loop = _AppLoop(plan, emit)
    threads = [
        threading.Thread(target=f, daemon=True)
        for f in (loop.echo_loop, loop.dns_loop, loop.upload_loop)
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()


def app_dns_down(plan: JsonDict, emit: Emit) -> None:
    """Resolve names while every resolver is unreachable.

    Round 1 at once, the next rounds when their go files appear. Each lookup is timed; nothing
    may resolve, nothing may wait past the deadline.
    """
    tok = plan["token"]

    def round_(label: str) -> None:
        results: list[tuple[str, str, JsonDict]] = []
        jobs: list[tuple[str, Callable[[str], JsonDict]]] = [
            ("UDP A 127.0.0.53", lambda n: app_dns_udp("127.0.0.53", n, 1, 15.0)),
            ("UDP AAAA 127.0.0.53", lambda n: app_dns_udp("127.0.0.53", n, 28, 15.0)),
            ("UDP A 127.0.0.53 (2)", lambda n: app_dns_udp("127.0.0.53", n, 1, 15.0)),
            ("TCP A 127.0.0.53", lambda n: app_dns_tcp("127.0.0.53", n, 1, 15.0)),
            ("getaddrinfo", app_gai),
        ]

        def run(what: str, fn: Callable[[str], JsonDict], name: str) -> None:
            results.append((what, name, fn(name)))

        threads = []
        for i, (what, fn) in enumerate(jobs):
            name = f"{tok}-down-{label}-{i}.lab.test"
            threads.append(threading.Thread(target=run, args=(what, fn, name)))
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        for what, name, r in results:
            emit(f"dns-down {label}: {what}", ok=True, kind=what, name=name, **r)

    round_("round1")
    # The driver creates each go file once the connection is in the next state.
    for n, go in enumerate(plan["go_files"], start=2):
        deadline = time.time() + plan.get("wait_seconds", 200)
        while not Path(go).exists() and time.time() < deadline:
            time.sleep(0.1)
        round_(f"round{n}")


def cmd_app_probe(a: argparse.Namespace) -> int:
    """Run the plan's probes (the managed App's side)."""
    with Path(a.plan).open() as f:
        plan = json.load(f)
    emit = Emit()
    emit("start", ok=True, mode=plan["mode"], pid=os.getpid())
    modes: dict[str, Callable[[JsonDict, Emit], None]] = {
        "baseline": app_baseline,
        "v6-block": app_v6_block,
        "loop": app_loop,
        "dns-down": app_dns_down,
    }
    try:
        modes[plan["mode"]](plan, emit)
    except Exception as e:  # noqa: BLE001 - report any crash as a probe result, never hang
        emit(
            "probe crashed",
            ok=False,
            error=f"{type(e).__name__}: {e}",
            trace=traceback.format_exc()[-1500:],
        )
    emit("done", ok=True)
    return 0


# --------------------------------------------------------------------------------------------
# Driver
# --------------------------------------------------------------------------------------------


class Api:
    """The controller's loopback REST API, with the headers a browser would send."""

    def __init__(self, port: int) -> None:
        """Talk to the controller on 127.0.0.1:`port` (one kept-alive connection)."""
        self.port = port
        self.conn: http.client.HTTPConnection | None = None
        self.lock = threading.Lock()

    def headers(self, method: str, body: object, rev: object) -> dict[str, str]:
        """Return the request headers a browser would send for this request."""
        headers = {"Accept": "application/json"}
        if method not in ("GET", "HEAD"):
            headers["Origin"] = f"http://127.0.0.1:{self.port}"
            headers["Idempotency-Key"] = str(uuid.uuid4())
        if rev is not None:
            headers["If-Match"] = f'"{rev}"'
        if body is not None:
            headers["Content-Type"] = "application/json"
        return headers

    def exchange(
        self, method: str, path: str, data: bytes | None, headers: dict[str, str], timeout: float
    ) -> tuple[http.client.HTTPResponse, bytes]:
        """Send one request, reconnecting up to API_ATTEMPTS times: (response, raw body)."""
        result: tuple[http.client.HTTPResponse, bytes] | None = None
        with self.lock:
            for attempt in range(API_ATTEMPTS):
                try:
                    if self.conn is None:
                        self.conn = http.client.HTTPConnection(
                            "127.0.0.1", self.port, timeout=timeout
                        )
                    self.conn.request(method, path, body=data, headers=headers)
                    r = self.conn.getresponse()
                    result = (r, r.read())
                    if (r.getheader("Connection") or "").lower() == "close":
                        self.conn.close()
                        self.conn = None
                    break
                except (OSError, http.client.HTTPException):
                    if self.conn is not None:
                        self.conn.close()
                    self.conn = None
                    if attempt == API_ATTEMPTS - 1:
                        raise
                    time.sleep(0.2)
        if result is None:
            msg = "API_ATTEMPTS must be at least 1"
            raise RuntimeError(msg)
        return result

    def request(
        self,
        method: str,
        path: str,
        body: object = None,
        rev: object = None,
        timeout: float = 30.0,
    ) -> tuple[int, Any]:
        """Call the API: (HTTP status, JSON value or text)."""
        headers = self.headers(method, body, rev)
        data = None if body is None else json.dumps(body).encode()
        r, raw = self.exchange(method, path, data, headers, timeout)
        ctype = r.getheader("Content-Type") or ""
        try:
            value = json.loads(raw) if raw and "json" in ctype else raw.decode("utf-8", "replace")
        except ValueError:
            value = raw.decode("utf-8", "replace")
        return r.status, value


def proc_cmdlines() -> dict[int, list[str]]:
    """Return the command line of every live (not zombie) process: {pid: argv}."""
    out = {}
    for entry in Path("/proc").iterdir():
        d = entry.name
        if not d.isdigit():
            continue
        try:
            args = (entry / "cmdline").read_bytes().split(b"\0")
            state = (entry / "stat").read_text().rsplit(")", 1)[1].split()[0]
        except OSError:
            continue
        if state != "Z" and args and args[0]:
            out[int(d)] = [x.decode(errors="replace") for x in args if x]
    return out


def proc_state(pid: int) -> str:
    """Return the state letter of a process (OSError when it is gone)."""
    return Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[0]


def alive(pid: int) -> bool:
    """Tell whether `pid` exists and is not a zombie."""
    try:
        return proc_state(pid) != "Z"
    except OSError:
        return False


class KindStats(TypedDict):
    """Counts of one kind of background traffic."""

    ok: int
    fail: int
    errors: dict[str, int]


class Traffic:
    """Clients through the Gateways while faults are injected: every attempt is counted.

    While the tunnel is down nothing is expected to succeed; nothing may leave outside it either.
    """

    def __init__(self, run: Run, socks_port: int, mixed_port: int, label: str) -> None:
        """Prepare the clients (they start with `start`)."""
        self.run, self.socks, self.mixed, self.label = run, socks_port, mixed_port, label
        self.stop_evt = threading.Event()
        self.stats: dict[str, KindStats] = {}
        self.lock = threading.Lock()
        self.timeline: list[tuple[float, str, bool]] = []  # (t, kind, ok)
        self.threads: list[threading.Thread] = []

    def note(self, kind: str, *, ok: bool, detail: str | None = None) -> None:
        """Count one attempt (and its error)."""
        with self.lock:
            s = self.stats.setdefault(kind, {"ok": 0, "fail": 0, "errors": {}})
            if ok:
                s["ok"] += 1
            else:
                s["fail"] += 1
            if not ok and detail:
                s["errors"][detail] = s["errors"].get(detail, 0) + 1
            self.timeline.append((round(time.time(), 3), kind, ok))

    def start(self) -> None:
        """Start every client in its own thread."""
        for f in (
            self.upload,
            self.download,
            self.udp_echo,
            self.dns_names,
            self.http_proxy,
            self.udp_dns,
        ):
            t = threading.Thread(target=self.guard(f), daemon=True)
            t.start()
            self.threads.append(t)

    def guard(self, f: Callable[[], None]) -> Callable[[], None]:
        """Wrap a client: rerun it until stopped, counting each failure."""

        def run() -> None:
            while not self.stop_evt.is_set():
                self.guarded(f)

        return run

    def guarded(self, f: Callable[[], None]) -> None:
        """Run a client once; a failure is counted under its name."""
        try:
            f()
        except Exception as e:  # noqa: BLE001 - keep generating traffic; count every failure
            self.note(f.__name__, ok=False, detail=f"{type(e).__name__}: {e}"[:80])
            self.stop_evt.wait(0.3)

    def mark(self, s: str) -> str:
        """Return the run's marker for this traffic label."""
        return self.run.mark(f"{self.label}-{s}")

    def upload(self) -> None:
        """Send a stream to the lab's discard port."""
        s, rep, _ = socks5_connect(self.socks, LAB_V4, 9, timeout=5)
        if s is None:
            self.note("upload", ok=False, detail=f"connect reply {rep}")
            self.stop_evt.wait(0.3)
            return
        chunk = (self.mark("upload").encode() + b" ") * 64
        with s:
            s.settimeout(5)
            while not self.stop_evt.is_set():
                s.sendall(chunk)
                self.note("upload", ok=True)
                self.stop_evt.wait(0.02)

    def download(self) -> None:
        """Read the lab's chargen stream slowly."""
        s, rep, _ = socks5_connect(self.socks, LAB_V4, 19, timeout=5)
        if s is None:
            self.note("download", ok=False, detail=f"connect reply {rep}")
            self.stop_evt.wait(0.3)
            return
        with s:
            s.settimeout(5)
            # A slow reader (~200 KB/s): TCP flow control keeps the stream at this rate.
            while not self.stop_evt.is_set():
                if not s.recv(4096):
                    msg = "closed"
                    raise EOFError(msg)
                self.note("download", ok=True)
                self.stop_evt.wait(0.02)

    def keep_associated(self, a: Socks5Udp, misses: int) -> None:
        """Raise when a new association is needed.

        That is when the Gateway closed this one (the worker that held it died) or it has stayed
        silent for a while (the guard reconnects).
        """
        if a.closed():
            msg = "association closed by the Gateway"
            raise EOFError(msg)
        if misses >= ASSOCIATION_MAX_MISSES:
            msg = "association silent"
            raise TimeoutError(msg)

    def udp_echo(self) -> None:
        """Echo datagrams to the lab over IPv4 and IPv6 alternately."""
        a = Socks5Udp(self.mixed, timeout=5, on_relay=self.run.relay)
        try:
            n = misses = 0
            while not self.stop_evt.is_set():
                self.keep_associated(a, misses)
                n += 1
                host = LAB_V4 if n % 2 else LAB_V6
                msg = self.mark(f"udp-{n}").encode()
                a.send(host, 7, msg)
                try:
                    ok = a.recv(0.3) == msg
                    misses = 0
                    self.note("udp_echo", ok=ok)
                except OSError:
                    misses += 1
                    self.note("udp_echo", ok=False, detail="no echo")
                self.stop_evt.wait(0.1)
        finally:
            a.close()

    def dns_names(self) -> None:
        """SOCKS5 CONNECT by name (resolved by the Gateway)."""
        n = 0
        while not self.stop_evt.is_set():
            n += 1
            s, rep, _ = socks5_connect(
                self.socks, f"{self.mark(f'name-{n}')}.lab.test", 80, timeout=8
            )
            if s:
                s.close()
            self.note("socks5h_name", ok=rep == 0, detail=f"reply {rep}")
            self.stop_evt.wait(0.4)

    def http_proxy(self) -> None:
        """HTTP proxy requests by name through the Mixed Gateway."""
        n = 0
        while not self.stop_evt.is_set():
            n += 1
            host = f"{self.mark(f'http-{n}')}.lab.test"
            try:
                req = http_request(f"http://{host}/ip", host, self.mark("h"))
                with socket.create_connection(("127.0.0.1", self.mixed), timeout=8) as s:
                    st, _ = http_exchange(s, req, timeout=8)
                self.note("http_proxy", ok=st == HTTPStatus.OK, detail=f"status {st}")
            except OSError as e:
                self.note("http_proxy", ok=False, detail=errno_name(e))
            self.stop_evt.wait(0.6)

    def udp_dns(self) -> None:
        """DNS over UDP through a SOCKS5 UDP association."""
        a = Socks5Udp(self.socks, timeout=5, on_relay=self.run.relay)
        try:
            n = misses = 0
            while not self.stop_evt.is_set():
                self.keep_associated(a, misses)
                n += 1
                q = dns_query(f"{self.mark(f'udpdns-{n}')}.lab.test", 1)
                a.send(LAB_V4, DNS_PORT, q)
                try:
                    r = a.recv(1.0)
                    misses = 0
                    self.note("udp_dns", ok=r[:2] == q[:2])
                except OSError:
                    misses += 1
                    self.note("udp_dns", ok=False, detail="no answer")
                self.stop_evt.wait(0.5)
        finally:
            a.close()

    def stop(self) -> JsonDict:
        """Stop the clients: the counts and the number of attempts."""
        self.stop_evt.set()
        for t in self.threads:
            t.join(timeout=15)
        return {"stats": self.stats, "attempts": len(self.timeline)}


class Run:
    """One harness run: the dev stack, the scenarios and their records."""

    def __init__(self, a: argparse.Namespace) -> None:
        """Prepare the output tree, the tokens, the event log and the App executable."""
        self.a = a
        self.out: str = a.out
        self.base: int = a.base
        self.work: str = a.work
        self.devroot: str = a.devroot
        self.bin = Path(a.devroot, "target", "release")
        self.state = Path(a.work, "s")
        self.mstate = self.state / "state"
        self.res = Path(a.out, "results")
        self.caps = Path(a.out, "captures")
        self.logs = Path(a.out, "logs")
        self.snaps = Path(a.out, "snapshots")
        self.appdir = Path(a.work, "app")
        for d in (self.res, self.caps, self.logs, self.snaps, self.appdir):
            d.mkdir(parents=True, exist_ok=True)
        self.appdir.chmod(0o755)
        self.token = "vpnmleak" + secrets.token_hex(6)
        self.ctl_token = "vpnmctl" + secrets.token_hex(6)
        self.api = Api(self.base)
        # Held open for the whole run, line-buffered: every event is on disk as it happens.
        self.events: TextIO = (self.res / "events.jsonl").open("a", buffering=1)
        self.scen: str | None = None
        self.children: list[subprocess.Popen[bytes]] = []
        self.sandbox_caps: dict[str, subprocess.Popen[bytes]] = {}
        self.current_capture: str | None = None
        self.apps: list[str] = []
        self.instances: list[str] = []
        self.labpeer_runs = 0
        self.deadline_ms = 3000
        self.gw_mixed, self.gw_socks = self.base + 10, self.base + 11
        self.gw4_socks, self.gw4_mixed = self.base + 12, self.base + 13
        self.meta: JsonDict = {
            "token": self.token,
            "control_token": self.ctl_token,
            "base": self.base,
            "api_ports": [self.base],
            "labpeer_api_ports": [self.base + 2],
            "wg_ports": [self.base + 1],
            "gateway_ports": [self.gw_mixed, self.gw_socks, self.gw4_socks, self.gw4_mixed],
            "tunnel_addresses": [CLIENT_V4, CLIENT_V6],
            "source": a.source,
            "commit": a.commit,
            "nic": a.nic,
            "nic_dev": a.nic_dev,
            "out": a.out,
            "started": time.time(),
        }
        self.write_meta()
        # The App executable: a copy of this file in a directory only we can write.
        self.app_exe = self.appdir / "leak_scenarios.py"
        shutil.copyfile(Path(__file__).absolute(), self.app_exe)
        self.app_exe.chmod(0o755)

    # --- records ---------------------------------------------------------------------------

    def write_meta(self) -> None:
        """Write OUT/results/meta.json."""
        with (self.res / "meta.json").open("w") as f:
            json.dump(self.meta, f, indent=1)

    def event(self, kind: str, **kw: object) -> None:
        """Append one event to events.jsonl (tagged with the current scenario)."""
        kw.update({"t": time.time(), "kind": kind})
        if self.scen and "scenario" not in kw:
            kw["scenario"] = self.scen
        self.events.write(json.dumps(kw, default=str, ensure_ascii=False) + "\n")

    def check(
        self,
        name: str,
        ok: object,
        *,
        details: JsonDict | None = None,
        observation: bool = False,
        **detail: object,
    ) -> object:
        """Record a check.

        `details`: a dict merged into the detail (keys such as 'name' that would clash with the
        parameters). `observation`: reported, not part of the verdict.
        """
        detail = dict(details or {}, **detail)
        self.event("check", name=name, ok=bool(ok), detail=detail, observation=observation)
        tag = (
            ("NOTE" if ok else "NOTE: does not hold") if observation else ("PASS" if ok else "FAIL")
        )
        log(
            f"  [{tag}] {name}"
            + ("" if ok else f"  {json.dumps(detail, default=str, ensure_ascii=False)[:400]}")
        )
        return ok

    def relay(self, addr: str) -> None:
        """Record a UDP relay address a Gateway handed out."""
        self.event("relay", addr=addr)

    def mark(self, label: str) -> str:
        """Return the run's payload marker for `label`."""
        return f"{self.token}-{label}"

    @contextlib.contextmanager
    def scenario(self, name: str, title: str, expect: Iterable[str] = ()) -> Iterator[None]:
        """Bracket a scenario in the event log; a failure is recorded, the run goes on."""
        self.scen = name
        self.event("scenario", name=name, phase="begin", title=title, expect=list(expect))
        log(f"== {name}: {title}")
        try:
            yield
        except Exception as e:  # noqa: BLE001 - a failing scenario is recorded, the next one runs
            self.check(
                "scenario ran to completion",
                ok=False,
                error=f"{type(e).__name__}: {e}",
                trace=traceback.format_exc()[-3000:],
            )
        finally:
            time.sleep(0.5)
            self.event("scenario", name=name, phase="end")
            self.scen = None

    # --- processes ---------------------------------------------------------------------------

    def sh(
        self, args: list[str], timeout: float = 20, *, check: bool = False
    ) -> subprocess.CompletedProcess[str]:
        """Run a command, capturing its output (RuntimeError on failure when `check`)."""
        r = subprocess.run(  # noqa: S603 - argv lists built in this file, never a shell
            args, capture_output=True, text=True, timeout=timeout, check=False
        )
        if check and r.returncode != 0:
            msg = f"{args}: {r.returncode} {r.stderr.strip()[:300]}"
            raise RuntimeError(msg)
        return r

    def ns(
        self, pid: int, args: list[str], timeout: float = 20
    ) -> subprocess.CompletedProcess[str]:
        """Run a command in the network namespace of `pid` (a strict worker).

        We join its user namespace, which our uid owns, so we are uid 0 there, never in the
        harness's.
        """
        return self.sh(
            [
                "nsenter",
                "--target",
                str(pid),
                "--user",
                "--net",
                "--preserve-credentials",
                "--",
                *args,
            ],
            timeout=timeout,
        )

    def start_stack(self) -> None:
        """Start scripts/dev-stack.sh (release, seeded) and wait for the seeded connection."""
        env = dict(os.environ)
        out_log = self.logs / "dev-stack.out"
        cmd = [
            str(Path(self.devroot, "scripts", "dev-stack.sh")),
            "--release",
            "--seed",
            "--base",
            str(self.base),
            "--state",
            str(self.state),
        ]
        self.event("command", argv=cmd)
        with out_log.open("w") as logf:
            self.stack = subprocess.Popen(  # noqa: S603 - the checkout's own dev-stack.sh, fixed argv
                cmd,
                stdout=logf,
                stderr=subprocess.STDOUT,
                env=env,
                cwd=self.devroot,
                start_new_session=True,
            )
        text = self.wait_stack_up(out_log)
        m = re.search(r"seeded: profile=(\S+) instance=(\S+)", text)
        if not m:
            msg = f"dev-stack did not seed (state reused?): {text[-1000:]}"
            raise RuntimeError(msg)
        self.profile, self.main = m.group(1), m.group(2)
        self.instances.append(self.main)
        v = self.view_of(self.main)
        self.dns_profile = v["spec"]["dns_profile_id"]
        self.security_profile = v["spec"]["security_profile_id"]
        gws = {g["kind"]: g for g in v["gateways"]}
        self.check(
            "seeded Gateways: Mixed and SOCKS5 with UDP",
            gws.get("mixed", {}).get("port") == self.gw_mixed
            and gws.get("socks5", {}).get("port") == self.gw_socks,
            gateways=[(g["kind"], g["port"], g["udp"]) for g in v["gateways"]],
        )
        st = self.wait_ready(self.main, timeout=60)
        self.check(
            "seeded connection Ready",
            ok=True,
            generation=st["running"]["generation"],
            worker=st["running"]["pid"],
            instance=self.main,
        )
        self.event(
            "ids",
            instance=self.main,
            profile=self.profile,
            dns=self.dns_profile,
            security=self.security_profile,
        )

    def wait_stack_up(self, out_log: Path) -> str:
        """Wait (120 s) for 'dev stack up' in the dev stack's output; return the output."""
        deadline = time.time() + 120
        text = ""
        while time.time() < deadline:
            text = out_log.read_text()
            if "dev stack up" in text:
                break
            if self.stack.poll() is not None:
                msg = f"dev-stack exited: {text[-2000:]}"
                raise RuntimeError(msg)
            time.sleep(0.2)
        else:
            msg = f"dev-stack did not come up: {text[-2000:]}"
            raise TimeoutError(msg)
        return text

    def labpeer_pids(self) -> list[int]:
        """Return the pids of the running lab peer."""
        return [
            p for p, a in proc_cmdlines().items() if a[0].endswith("vpn-labpeer") and "serve" in a
        ]

    def labpeer_paused(self) -> bool:
        """Tell whether a lab peer process is stopped (SIGSTOP)."""
        for p in self.labpeer_pids():
            with contextlib.suppress(OSError):
                if proc_state(p) == "T":
                    return True
        return False

    def stop_labpeer(self, sig: signal.Signals = signal.SIGKILL) -> list[int]:
        """Stop the lab peer.

        SIGKILL: the peer's port is closed, the kernel answers with ICMP port unreachable.
        SIGSTOP: the peer is silent (its socket stays open, nothing answers), as when a peer is
        lost on a real network.
        """
        pids = self.labpeer_pids()
        for p in pids:
            os.kill(p, sig)
        if sig != signal.SIGSTOP:
            for _ in range(100):
                if not any(alive(p) for p in pids):
                    break
                time.sleep(0.05)
            for c in self.children:
                c.poll()
        action = "paused (silent)" if sig == signal.SIGSTOP else "killed"
        self.event("labpeer", action=action, pids=pids, signal=int(sig))
        log(f"  lab peer {action} ({signal.Signals(sig).name}, pids {pids})")
        return pids

    def resume_labpeer(self) -> None:
        """Continue a stopped lab peer (SIGCONT)."""
        pids = self.labpeer_pids()
        for p in pids:
            os.kill(p, signal.SIGCONT)
        self.event("labpeer", action="resumed", pids=pids)
        log(f"  lab peer resumed (pids {pids})")

    def start_labpeer(self) -> None:
        """Start the lab peer again and wait until its WireGuard port is bound."""
        self.labpeer_runs += 1
        # The same arguments as scripts/dev-stack.sh: the same keys, so the imported profile
        # still matches the restarted peer.
        cmd = [
            str(self.bin / "vpn-labpeer"),
            "serve",
            "--listen",
            f"127.0.0.1:{self.base + 1}",
            "--client-config",
            str(self.state / "lab.conf"),
            "--keys",
            str(self.state / "lab.keys"),
            "--api",
            f"127.0.0.1:{self.base + 2}",
        ]
        with (self.logs / f"labpeer-{self.labpeer_runs}.log").open("w") as errf:
            p = subprocess.Popen(  # noqa: S603 - the built vpn-labpeer, fixed argv
                cmd, stdout=subprocess.DEVNULL, stderr=errf
            )
        self.children.append(p)
        want = f":{self.base + 1:04X}"
        for _ in range(100):
            udp = Path("/proc/net/udp").read_text().splitlines()[1:]
            if any(want in ln.split()[1] for ln in udp):
                break
            time.sleep(0.05)
        self.event("labpeer", action="started", pid=p.pid)
        log(f"  lab peer started (pid {p.pid})")

    def ensure_labpeer(self) -> None:
        """Make sure the lab peer runs (resumed or restarted)."""
        if self.labpeer_paused():
            self.resume_labpeer()
        if not self.labpeer_pids():
            self.start_labpeer()

    # --- instances ---------------------------------------------------------------------------

    def view(self, iid: str) -> JsonDict | None:
        """Return the connection's view (spec, status, Gateways), or None."""
        st, v = self.api.request("GET", f"/v1/instances/{iid}")
        return v if st == HTTPStatus.OK and isinstance(v, dict) else None

    def view_of(self, iid: str) -> JsonDict:
        """Return the connection's view; it must exist."""
        v = self.view(iid)
        if v is None:
            msg = f"connection {iid}: no view"
            raise RuntimeError(msg)
        return v

    def status(self, iid: str) -> JsonDict:
        """Return the connection's status ({} when unknown)."""
        v = self.view(iid)
        return cast("JsonDict", (v or {}).get("status") or {})

    def wait_for(
        self,
        iid: str,
        what: str,
        pred: Callable[[JsonDict], object],
        timeout: float = 60.0,
        poll: float = 0.15,
    ) -> JsonDict:
        """Poll the status until `pred` holds (TimeoutError naming the phase and fault)."""
        deadline = time.monotonic() + timeout
        st: JsonDict = {}
        while time.monotonic() < deadline:
            st = self.status(iid)
            if st and pred(st):
                return st
            time.sleep(poll)
        fault = (st.get("recovery") or {}).get("last_fault") or {}
        msg = f"{what}: still {st.get('phase')} ({fault.get('code')}: {said(fault.get('message'))})"
        raise TimeoutError(msg)

    def wait_ready(
        self,
        iid: str,
        after_gen: int | None = None,
        timeout: float = 60.0,
        *,
        sandbox: bool = False,
    ) -> JsonDict:
        """Wait until Ready (a later generation than `after_gen`; with a sandbox if asked)."""

        def ok(s: JsonDict) -> object:
            run = s.get("running") or {}
            return (
                s.get("phase") == "ready"
                and (after_gen is None or run.get("generation", 0) > after_gen)
                and (not sandbox or s.get("sandbox"))
            )

        return self.wait_for(iid, "Ready", ok, timeout)

    def action(self, iid: str, action: str) -> None:
        """Send a lifecycle action (start, stop, restart)."""
        st, body = self.api.request("POST", f"/v1/instances/{iid}/actions", {"action": action})
        if st not in (HTTPStatus.OK, HTTPStatus.ACCEPTED):
            msg = f"{action}: HTTP {st} {body}"
            raise RuntimeError(msg)
        self.event("instance_action", instance=iid, action=action)

    def stop_instance(self, iid: str) -> JsonDict:
        """Stop the connection and wait until it is stopped."""
        self.action(iid, "stop")
        return self.wait_for(iid, "stopped", lambda s: s.get("phase") == "stopped", 40)

    def update_instance(self, iid: str, **changes: object) -> None:
        """Change the connection's spec (PUT with its revision)."""
        spec = self.view_of(iid)["spec"]
        body = {
            k: spec.get(k)
            for k in (
                "name",
                "profile_id",
                "dns_profile_id",
                "security_profile_id",
                "limits",
                "strict",
            )
        }
        body.update(changes)
        st, r = self.api.request("PUT", f"/v1/instances/{iid}", body, rev=spec["revision"])
        if st != HTTPStatus.OK:
            msg = f"update {changes}: HTTP {st} {r}"
            raise RuntimeError(msg)
        self.event("instance_update", instance=iid, changes=changes)

    def set_strict(self, iid: str, *, strict: bool) -> JsonDict:
        """Switch strict mode (stop, update, start) and wait until Ready."""
        self.stop_instance(iid)
        self.update_instance(iid, strict=strict)
        self.action(iid, "start")
        st = self.wait_ready(iid, timeout=60, sandbox=strict)
        self.check(
            f"connection Ready with strict={strict}",
            ok=True,
            generation=st["running"]["generation"],
            worker=st["running"]["pid"],
            sandbox=st.get("sandbox"),
        )
        return st

    def worker(self, iid: str) -> int | None:
        """Return the pid of the connection's worker, if any."""
        return cast("int | None", (self.status(iid).get("running") or {}).get("pid"))

    def kill_worker_at(
        self,
        iid: str,
        phases: set[str],
        trigger: str | None = None,
        timeout: float = 40.0,
        label: str = "",
    ) -> JsonDict:
        """SIGKILL the worker the first time it is seen in one of `phases`.

        After `trigger`, a lifecycle action, when given. Polls the status every ~10 ms.
        """
        before = (self.status(iid).get("running") or {}).get("generation", 0)
        if trigger:
            self.action(iid, trigger)
        seen: list[tuple[Any, Any, Any]] = []
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            st = self.status(iid)
            ph = st.get("phase")
            run = st.get("running") or {}
            pid, gen = run.get("pid"), run.get("generation", 0)
            if not seen or seen[-1] != (ph, gen, pid):
                seen.append((ph, gen, pid))
            if ph in phases and pid and (trigger is None or gen > before) and alive(pid):
                os.kill(pid, signal.SIGKILL)
                self.event("kill", target="worker", phase=ph, pid=pid, generation=gen, label=label)
                log(f"  SIGKILL worker {pid} (generation {gen}) in phase {ph} [{label}]")
                return {
                    "phase": ph,
                    "pid": pid,
                    "generation": gen,
                    "t": time.time(),
                    "seen": seen[-12:],
                }
            time.sleep(0.01)
        msg = f"no worker in {sorted(phases)} within {timeout}s; seen {seen[-12:]}"
        raise TimeoutError(msg)

    def recovered(
        self,
        iid: str,
        killed: JsonDict,
        timeout: float = 60.0,
        sandbox_epoch: object = None,
    ) -> JsonDict:
        """Wait for the generation after the killed one to be Ready, and record the check."""
        t0 = time.time()
        trace: list[tuple[Any, ...]] = []

        def ready(s: JsonDict) -> bool:
            run = s.get("running") or {}
            fault = ((s.get("recovery") or {}).get("last_fault") or {}).get("code")
            cur = (s.get("phase"), run.get("generation"), fault)
            if not trace or trace[-1][1:] != cur:
                trace.append((round(time.time() - t0, 2), *cur))
            return bool(
                s.get("phase") == "ready" and run.get("generation", 0) > killed["generation"]
            )

        st = self.wait_for(iid, "Ready after the kill", ready, timeout, poll=0.1)
        self.last_recovered_at = time.time()
        killed = dict(killed, recovery_trace=trace[-12:])
        run = st["running"]
        same_sandbox = None
        if sandbox_epoch is not None:
            same_sandbox = (st.get("sandbox") or {}).get("epoch") == sandbox_epoch
        self.check(
            f"worker killed in {killed['phase']}: the manager started a new generation "
            "and it became Ready",
            same_sandbox is not False,
            killed_generation=killed["generation"],
            new_generation=run["generation"],
            new_worker=run["pid"],
            seconds=round(time.time() - t0, 2),
            same_sandbox=same_sandbox,
            phases_before_kill=killed["seen"],
            recovery_trace=killed["recovery_trace"],
        )
        return st

    # --- sandbox -----------------------------------------------------------------------------

    def inspect_sandbox(self, iid: str, label: str, *, expect_v6: bool) -> JsonDict:
        """Record the strict sandbox's devices, routes and sockets and check its shape."""
        st = self.status(iid)
        sb = st.get("sandbox") or {}
        pid = st["running"]["pid"]
        lines = []

        def show(title: str, r: subprocess.CompletedProcess[str]) -> str:
            lines.append(f"## {title}\n{r.stdout}{r.stderr}")
            return r.stdout

        links = show("sandbox: ip -d -o link", self.ns(pid, ["ip", "-d", "-o", "link", "show"]))
        addrs = show("sandbox: ip -o addr", self.ns(pid, ["ip", "-o", "addr", "show"]))
        r4 = show(
            "sandbox: ip route (all tables)", self.ns(pid, ["ip", "route", "show", "table", "all"])
        )
        r6 = show(
            "sandbox: ip -6 route (all tables)",
            self.ns(pid, ["ip", "-6", "route", "show", "table", "all"]),
        )
        show("sandbox: ip rule", self.ns(pid, ["ip", "rule", "show"]))
        sysctl = show(
            "sandbox: IPv6 settings of vpn0 and forwarding",
            self.ns(
                pid,
                [
                    "sh",
                    "-c",
                    (
                        "for f in /proc/sys/net/ipv6/conf/vpn0/disable_ipv6 "
                        "/proc/sys/net/ipv6/conf/vpn0/accept_ra /proc/sys/net/ipv4/ip_forward "
                        "/proc/sys/net/ipv6/conf/all/forwarding; "
                        'do echo "$f=$(cat $f 2>/dev/null)"; done'
                    ),
                ],
            ),
        )
        show("sandbox: sockets (ss -uantp)", self.ns(pid, ["ss", "-uantp"]))
        host_udp = show("harness netns: UDP sockets (ss -uanp)", self.sh(["ss", "-uanp"]))
        names = sorted(re.findall(r"^\d+:\s+([^:@\s]+)", links, re.MULTILINE))
        worker_net = str(Path(f"/proc/{pid}/ns/net").readlink())
        harness_net = str(Path("/proc/self/ns/net").readlink())
        holder = sb.get("holder_pid")
        lines.append(
            f"## namespaces\nworker {pid}: {worker_net}\nharness (driver): {harness_net}"
            f"\nholder: {holder}"
        )
        (self.res / f"sandbox-{label}.txt").write_text("\n".join(lines))
        self.check(
            f"sandbox ({label}): interfaces are only lo and vpn0",
            names == ["lo", "vpn0"],
            interfaces=names,
        )
        self.check(
            f"sandbox ({label}): vpn0 is a TUN device, no veth/bridge anywhere",
            " tun " in links and "veth" not in links and "bridge" not in links,
            links=links.strip().splitlines(),
        )
        self.check(
            f"sandbox ({label}): the worker runs in the sandbox's network namespace",
            worker_net != harness_net,
            worker=worker_net,
            harness=harness_net,
        )
        peer = f"127.0.0.1:{self.base + 1}"
        mine = [ln for ln in host_udp.splitlines() if peer in ln and f"pid={pid}," in ln]
        self.check(
            f"sandbox ({label}): WireGuard UDP socket made in the host namespace, held by "
            "the worker, connected to the peer",
            bool(mine),
            sockets=mine,
        )
        d4 = [ln for ln in r4.splitlines() if ln.startswith("default")]
        d6 = [ln for ln in r6.splitlines() if ln.startswith("default")]
        self.check(
            f"sandbox ({label}): default routes only through vpn0",
            d4
            and all("dev vpn0" in ln for ln in d4)
            and ((all("dev vpn0" in ln for ln in d6) and bool(d6)) if expect_v6 else not d6),
            v4=d4,
            v6=d6,
        )
        if not expect_v6:
            self.check(
                f"sandbox ({label}): IPv6 disabled on vpn0, no IPv6 address",
                "disable_ipv6=1" in sysctl and not re.search(r"vpn0\s+inet6", addrs),
                sysctl=sysctl.strip().splitlines(),
                inet6=[ln for ln in addrs.splitlines() if "inet6" in ln],
            )
        self.event(
            "sandbox",
            label=label,
            instance=iid,
            holder_pid=holder,
            worker=pid,
            interfaces=names,
            epoch=sb.get("epoch"),
            addresses=sb.get("addresses"),
        )
        return cast("JsonDict", sb)

    def start_sandbox_capture(self, iid: str, name: str) -> None:
        """Start leak_capture.py on the sandbox's vpn0 (inside its namespaces)."""
        pid = self.worker(iid)
        err_log = self.logs / f"capture-{name}.log"
        cmd = [
            "nsenter",
            "--target",
            str(pid),
            "--user",
            "--net",
            "--preserve-credentials",
            "--",
            sys.executable,
            str(HERE / "leak_capture.py"),
            "capture",
            "--iface",
            "vpn0",
            "--name",
            name,
            "--ring-mb",
            "64",
            "--dir",
            str(self.caps),
        ]
        with err_log.open("w") as errf:
            p = subprocess.Popen(  # noqa: S603 - nsenter + this checkout's leak_capture.py, fixed argv
                cmd, stdout=subprocess.DEVNULL, stderr=errf
            )
        ready = self.caps / (name + ".ready")
        for _ in range(100):
            if ready.exists() or p.poll() is not None:
                break
            time.sleep(0.05)
        ok = ready.exists()
        self.check(
            f"capture of the sandbox's vpn0 running ({name})",
            ok,
            log=err_log.read_text()[-500:] if not ok else "",
        )
        self.sandbox_caps[name] = p
        self.current_capture = name

    def stop_sandbox_capture(self, name: str) -> None:
        """Stop a sandbox capture (SIGTERM; it writes its stats)."""
        p = self.sandbox_caps.pop(name, None)
        if p and p.poll() is None:
            p.send_signal(signal.SIGTERM)
            with contextlib.suppress(subprocess.TimeoutExpired):
                p.wait(timeout=10)

    # --- managed Apps ------------------------------------------------------------------------

    def create_app(self, iid: str, name: str, plan: JsonDict) -> str:
        """Create a managed App (this file, `app-probe` with a plan) in the strict sandbox."""
        plan = dict(plan, token=self.token, base=self.base)
        plan_path = self.appdir / f"plan-{len(self.apps) + 1}.json"
        with plan_path.open("w") as f:
            json.dump(plan, f)
        st, chk = self.api.request(
            "GET",
            "/v1/apps/executable-check?path=" + urllib.parse.quote(str(self.app_exe), safe=""),
        )
        if st != HTTPStatus.OK or not chk.get("ok"):
            msg = f"executable check: HTTP {st} {chk}"
            raise RuntimeError(msg)
        st, v = self.api.request(
            "POST",
            "/v1/apps",
            {
                "instance_id": iid,
                "name": name,
                "executable": str(self.app_exe),
                "args": ["app-probe", "--plan", str(plan_path)],
                "isolation": "strict_netns",
                "executable_sha256": chk["sha256"],
                "env": [{"name": "PYTHONDONTWRITEBYTECODE", "value": "1"}],
            },
        )
        if st != HTTPStatus.CREATED:
            msg = f"create App: HTTP {st} {v}"
            raise RuntimeError(msg)
        app = cast("str", v["spec"]["id"])
        self.apps.append(app)
        self.event("app", action="created", app=app, name=name, mode=plan["mode"], instance=iid)
        return app

    def app_action(self, app: str, action: str) -> None:
        """Send an App action (start, stop)."""
        st, v = self.api.request("POST", f"/v1/apps/{app}/actions", {"action": action})
        if st != HTTPStatus.OK:
            msg = f"App {action}: HTTP {st} {v}"
            raise RuntimeError(msg)
        self.event("app", action=action, app=app)

    def app_status(self, app: str) -> JsonDict:
        """Return the App's status ({} when unknown)."""
        st, v = self.api.request("GET", f"/v1/apps/{app}/status")
        return cast("JsonDict", v if st == HTTPStatus.OK else {})

    def wait_app_running(self, app: str, timeout: float = 30) -> JsonDict:
        """Return the App's status once it runs (or has already run to its end)."""
        deadline = time.time() + timeout
        while time.time() < deadline:
            s = self.app_status(app)
            if s.get("state") == "running" or s.get("last_exit"):
                return s
            if s.get("state") == "failed":
                last = s.get("last_error") or {}
                msg = f"App failed to start: {last.get('code')}: {said(last.get('message'))}"
                raise RuntimeError(msg)
            time.sleep(0.05)
        msg = "App not running"
        raise TimeoutError(msg)

    def wait_app_done(self, app: str, timeout: float = 180) -> JsonDict:
        """Wait until the App has exited."""
        deadline = time.time() + timeout
        s: JsonDict = {}
        while time.time() < deadline:
            s = self.app_status(app)
            if s.get("state") in ("stopped", "failed") and s.get("last_exit"):
                return s
            time.sleep(0.2)
        msg = f"App did not finish: {s}"
        raise TimeoutError(msg)

    def app_lines(self, app: str) -> list[JsonDict]:
        """Return the probe results in the App's log."""
        path = self.mstate / "logs" / "apps" / f"{app}.log"
        out = []
        with contextlib.suppress(OSError), path.open(errors="replace") as f:
            for raw in f:
                line = raw.strip()
                if line.startswith("{") and '"probe"' in line:
                    with contextlib.suppress(ValueError):
                        out.append(json.loads(line))
        return out

    def run_app_probe(
        self, iid: str, name: str, plan: JsonDict, timeout: float = 180
    ) -> tuple[str, list[JsonDict]]:
        """Run an App probe to its end and record each of its results as a check."""
        app = self.create_app(iid, name, plan)
        self.app_action(app, "start")
        st = self.wait_app_running(app)
        if st.get("state") == "running":
            self.check(
                f"App {name} running in the sandbox (isolation strict_netns)",
                st.get("isolation") == "strict_netns",
                pid=st.get("pid"),
                isolation=st.get("isolation"),
            )
        done = self.wait_app_done(app, timeout)
        lines = self.app_lines(app)
        for ln in lines:
            if ln["probe"] in ("start", "done"):
                continue
            self.check(
                f"App: {ln['probe']}",
                ln["ok"],
                details=ln.get("detail", {}),
                observation=bool(ln.get("observation")),
            )
        self.check(
            f"App {name} finished its probes",
            any(ln["probe"] == "done" for ln in lines),
            exit=done.get("last_exit"),
            state=done.get("state"),
        )
        return app, lines

    # --- clients through the Gateways --------------------------------------------------------

    def curl(self, args: list[str], expect: list[str], what: str) -> None:
        """Run curl through a Gateway; it must succeed with one of `expect` in its output."""
        cmd = [
            "curl",
            "-q",
            "-sS",
            "--max-time",
            "15",
            "-g",
            "-H",
            f"X-Leak-Marker: {self.mark('curl')}",
            *args,
        ]
        r = self.sh(cmd, timeout=30)
        ok = r.returncode == 0 and any(e in r.stdout for e in expect)
        self.check(
            f"curl {what}",
            ok,
            argv=" ".join(args),
            rc=r.returncode,
            out=r.stdout[-200:],
            err=r.stderr[-200:],
        )

    def gateway_tests(self, label: str, socks: int, mixed: int, *, v6: bool = True) -> None:
        """Clients through a SOCKS5 and a Mixed Gateway: TCP, UDP, DNS, HTTP, bulk."""
        tok = self.mark(label)
        self.gateway_curl(label, tok, socks, mixed, v6=v6)
        self.gateway_tcp(label, tok, socks, v6=v6)
        for gw in (socks, mixed):
            self.gateway_udp(label, tok, gw, v6=v6)
        s, _, _ = socks5_connect(socks, LAB_V4, 80)
        n = 8_000_000
        got = 0
        if s:
            with s:
                st, body = http_exchange(s, http_request(f"/bytes/{n}", LAB_V4, tok), timeout=60)
                got = len(body) if st == HTTPStatus.OK else 0
        self.check(f"bulk HTTP download of {n} bytes through SOCKS5 [{label}]", got == n, bytes=got)

    def gateway_curl(self, label: str, tok: str, socks: int, mixed: int, *, v6: bool) -> None:
        """Curl through both Gateways, by name and by address."""
        ip_v4, ip_v6 = f'"ip":"{CLIENT_V4}"', f'"ip":"{CLIENT_V6}"'
        any_ip = [ip_v4, ip_v6]
        self.curl(
            ["--socks5-hostname", f"127.0.0.1:{socks}", f"http://{tok}-c1.lab.test/ip"],
            any_ip,
            f"SOCKS5 (name resolved in the tunnel) [{label}]",
        )
        self.curl(
            ["-x", f"http://127.0.0.1:{mixed}", f"http://{tok}-c2.lab.test/ip"],
            any_ip,
            f"HTTP proxy, Mixed Gateway (name resolved in the tunnel) [{label}]",
        )
        self.curl(
            ["--socks5", f"127.0.0.1:{socks}", f"http://{LAB_V4}/ip"],
            [ip_v4],
            f"SOCKS5 to {LAB_V4} [{label}]",
        )
        self.curl(
            ["--socks5-hostname", f"127.0.0.1:{mixed}", f"http://{INTERNET_V4}/"],
            ["labpeer ok"],
            f"SOCKS5 on the Mixed Gateway to {INTERNET_V4} [{label}]",
        )
        if v6:
            self.curl(
                ["--socks5", f"127.0.0.1:{socks}", f"http://[{LAB_V6}]/ip"],
                [ip_v6],
                f"SOCKS5 to [{LAB_V6}] [{label}]",
            )
            self.curl(
                ["-x", f"http://127.0.0.1:{mixed}", f"http://[{LAB_V6}]/ip"],
                [ip_v6],
                f"HTTP proxy to [{LAB_V6}] [{label}]",
            )

    def gateway_tcp(self, label: str, tok: str, socks: int, *, v6: bool) -> None:
        """SOCKS5 CONNECT: TCP echo per address and DNS over TCP."""
        for host in [LAB_V4, INTERNET_V4, *([LAB_V6] if v6 else [])]:
            s, rep, el = socks5_connect(socks, host, 7)
            ok = False
            if s:
                with s:
                    msg = f"{tok}-tcp-echo-{host}\n".encode()
                    s.sendall(msg)
                    ok = recv_exact(s, len(msg)) == msg
            self.check(f"SOCKS5 CONNECT {host}:7 echo [{label}]", ok, reply=rep, ms=int(el * 1000))
        s, rep, _ = socks5_connect(socks, LAB_V4, DNS_PORT)
        ok = False
        if s:
            with s:
                q = dns_query(f"{tok}-tcpdns.lab.test", 1)
                s.sendall(struct.pack(">H", len(q)) + q)
                n = struct.unpack(">H", recv_exact(s, 2))[0]
                _id, rcode, addrs = dns_parse(recv_exact(s, n))
                ok = rcode == 0 and LAB_V4 in addrs
        self.check(f"DNS over TCP to {LAB_V4}:53 through SOCKS5 CONNECT [{label}]", ok, reply=rep)

    def gateway_udp(self, label: str, tok: str, gw: int, *, v6: bool) -> None:
        """SOCKS5 UDP ASSOCIATE on one Gateway: UDP echo and DNS over UDP."""
        a = Socks5Udp(gw, on_relay=self.relay)
        try:
            for host in [LAB_V4, INTERNET_V4, *([LAB_V6] if v6 else [])]:
                msg = f"{tok}-udp-echo-{gw}-{host}".encode()
                got: bytes | None = None
                src: str | None = None
                for _ in range(3):
                    a.send(host, 7, msg)
                    try:
                        shost, sport, got = a.recv_from(1.5)
                        src = f"{shost}:{sport}"
                        break
                    except OSError:
                        pass
                self.check(
                    f"SOCKS5 UDP ASSOCIATE (port {gw}) echo {host}:7 [{label}]",
                    got == msg,
                    relay=f"{a.relay[0]}:{a.relay[1]}",
                    reply_from=src,
                )
            for server, qtype in [(LAB_V4, 1), *([(LAB_V6, 28)] if v6 else [])]:
                q = dns_query(f"{tok}-udpdns-{gw}-{qtype}.lab.test", qtype)
                a.send(server, DNS_PORT, q)
                rcode: int | None
                try:
                    _id, rcode, addrs = dns_parse(a.recv(3.0))
                except OSError as e:
                    rcode, addrs = None, [str(e)]
                self.check(
                    f"DNS over UDP to {server}:53 through UDP ASSOCIATE (port {gw}) [{label}]",
                    rcode == 0 and bool(addrs),
                    rcode=rcode,
                    addrs=addrs,
                )
        finally:
            a.close()

    # --- snapshots (AC-70) -------------------------------------------------------------------

    def snapshot(self, label: str) -> None:
        """Write OUT/snapshots/netns-<label>.txt: the harness namespace's network state."""
        parts = []
        cmds = [
            ("ip -d -o link", ["ip", "-d", "-o", "link", "show"]),
            ("ip -o addr", ["ip", "-o", "addr", "show"]),
            ("ip route (all tables)", ["ip", "route", "show", "table", "all"]),
            ("ip -6 route (all tables)", ["ip", "-6", "route", "show", "table", "all"]),
            ("ip rule", ["ip", "rule", "show"]),
            ("ip -6 rule", ["ip", "-6", "rule", "show"]),
        ]
        for title, cmd in cmds:
            r = self.sh(cmd)
            text = re.sub(r" expires \d+sec", "", r.stdout + r.stderr)
            parts.append(f"## {title}\n{text}")
        parts.append("## /etc/resolv.conf\n" + Path("/etc/resolv.conf").read_text())
        for tool, cmd in (
            ("nft", ["nft", "list", "ruleset"]),
            ("iptables-save", ["iptables-save"]),
            ("ip6tables-save", ["ip6tables-save"]),
        ):
            if shutil.which(tool):
                r = self.sh(cmd)
                parts.append(f"## {tool}\n{r.stdout}{r.stderr}")
            else:
                parts.append(f"## {tool}: not installed on this host")
        sysctls = ["ipv4/ip_forward", "ipv6/conf/all/forwarding", "ipv4/conf/all/rp_filter"]
        parts.append(
            "## sysctl\n"
            + "".join(
                f"net.{s.replace('/', '.')} = {Path('/proc/sys/net/' + s).read_text()}"
                for s in sysctls
            )
        )
        parts.append(
            "## proxy environment of the user (driver)\n"
            + "".join(
                f"{k}={v}\n" for k, v in sorted(os.environ.items()) if k.lower().endswith("_proxy")
            )
        )
        home = os.environ.get("HOME", "")
        listing = []
        for root, _dirs, files in os.walk(home):
            for fn in sorted(files):
                p = Path(root, fn)
                listing.append(f"{os.path.relpath(p, home)} {p.stat().st_size}")
        parts.append(
            f"## files in $HOME ({home}): where desktop proxy settings would be written\n"
            + "\n".join(sorted(listing))
        )
        (self.snaps / f"netns-{label}.txt").write_text("\n".join(parts) + "\n")
        self.event("snapshot", label=label)

    # --- scenarios ---------------------------------------------------------------------------

    def controls(self) -> None:
        """Send the traffic the analysis must see.

        It proves a system-resolver query and direct packets would show on the NIC, and
        plaintext DNS or an unknown port on lo would be flagged.
        """
        tok = self.ctl_token
        r = self.sh(["timeout", "2", "getent", "ahostsv4", f"{tok}-sysres.example"], timeout=10)
        self.event("control_sent", what="getent ahostsv4", rc=r.returncode)
        with contextlib.suppress(OSError):
            socket.create_connection((DIRECT_V4, 80), timeout=1).close()
        for fam, host in ((socket.AF_INET, DIRECT_V4), (socket.AF_INET6, DIRECT_V6)):
            with socket.socket(fam, socket.SOCK_DGRAM) as u:
                u.sendto(f"{tok} direct udp".encode(), (host, 9))
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as u:
            u.sendto(f"{tok} plaintext dns on lo".encode(), ("127.0.0.1", DNS_PORT))
            u.sendto(f"{tok} unknown loopback port".encode(), ("127.0.0.1", 9))
        time.sleep(1.5)
        self.event("control_sent", what="direct tcp/udp v4/v6, loopback udp :53 and :9")

    def faults(self, *, strict: bool) -> None:
        """AC-26: SIGKILL the worker per lifecycle phase, peer gone, while traffic runs."""
        iid = self.main
        label = "strict" if strict else "gw"
        self.ensure_labpeer()
        st = self.wait_ready(iid, timeout=60, sandbox=strict)
        epoch = (st.get("sandbox") or {}).get("epoch") if strict else None
        traffic = Traffic(self, self.gw_socks, self.gw_mixed, f"fault-{label}")
        traffic.start()
        app = None
        stop_file = self.appdir / f"stop-loop-{label}"
        if strict:
            app = self.create_app(
                iid,
                f"leak-loop-{label}",
                {"mode": "loop", "stop_file": str(stop_file), "max_seconds": 900},
            )
            self.app_action(app, "start")
            self.wait_app_running(app)
        time.sleep(3)
        steps = FaultSteps(self, iid, strict=strict, epoch=epoch)
        try:
            steps.run_all()
        finally:
            time.sleep(4)
            self.faults_traffic_summary(traffic, label)
            if app:
                self.faults_app_summary(app, stop_file)
        phases = sorted({k["phase"] for k in steps.kills})
        self.check(
            f"worker killed in phases {phases} [{label}]",
            {"ready", "connecting", "degraded", "verifying"} <= set(phases),
            kills=[(k["phase"], k["pid"], k["generation"]) for k in steps.kills],
        )

    def faults_traffic_summary(self, traffic: Traffic, label: str) -> None:
        """Stop the background traffic and check it ran, and got through after the last fault."""
        summary = traffic.stop()
        self.event("traffic", label=label, **summary)
        self.check(
            f"background traffic ran through the faults [{label}]",
            summary["attempts"] > 0,
            **summary["stats"],
        )
        # The clients kept exercising the product to the end: every kind succeeded again
        # after the last recovery (a client stuck on a dead association would not).
        last = getattr(self, "last_recovered_at", 0)
        after: dict[str, int] = {}
        for t, kind, ok in traffic.timeline:
            after.setdefault(kind, 0)
            after[kind] += ok and t > last
        self.check(
            f"every kind of Gateway traffic got through again after the last recovery [{label}]",
            bool(after) and all(after.values()),
            details=dict(after),
        )

    def faults_app_summary(self, app: str, stop_file: Path) -> None:
        """Stop the App's loop and check its traffic ran through the faults."""
        stop_file.write_text("")
        with contextlib.suppress(Exception):
            self.wait_app_done(app, timeout=30)
        lines = self.app_lines(app)
        per: dict[str, dict[str, int]] = {}
        for ln in lines:
            if ln["probe"].startswith("loop"):
                d = per.setdefault(ln["probe"], {"ok": 0, "fail": 0})
                d["ok" if ln["ok"] else "fail"] += 1
        self.event("app_loop", app=app, results=per)
        self.check(
            "App traffic in the sandbox ran through the faults (attempts per kind)",
            sum(v["ok"] for v in per.values()) > 0,
            details=dict(per),
        )

    def sandbox_ns_pid(self, iid: str) -> int | None:
        """Return a process in the connection's sandbox namespaces to nsenter through.

        Our own vpn0 capture (always there in the strict scenarios, unlike a worker that may just
        have been killed), else the worker.
        """
        for name, p in self.sandbox_caps.items():
            if p.poll() is None and name == self.current_capture:
                return p.pid
        return self.worker(iid)

    def sandbox_default_routes(self, pid: int | None) -> tuple[list[str], list[str]]:
        """Return the sandbox's IPv4 and IPv6 default routes."""
        pid_ = cast("int", pid)
        r4 = [
            ln.strip()
            for ln in self.ns(pid_, ["ip", "route", "show"]).stdout.splitlines()
            if ln.startswith("default")
        ]
        r6 = [
            ln.strip()
            for ln in self.ns(pid_, ["ip", "-6", "route", "show"]).stdout.splitlines()
            if ln.startswith("default")
        ]
        return r4, r6

    def record_sandbox_routes(self, state: str) -> tuple[list[str], list[str]]:
        """Record the sandbox's default routes in the event log."""
        pid = self.sandbox_ns_pid(self.main)
        r4, r6 = self.sandbox_default_routes(pid)
        self.event("route_state", state=state, v4=r4, v6=r6)
        return r4, r6

    def watch_phases(self, iid: str, seconds: float) -> list[tuple[Any, ...]]:
        """Return the connection's phase transitions for `seconds` (polled every 50 ms).

        Each is (seconds, phase, generation, worker pid, last fault code).
        """
        seen: list[tuple[Any, ...]] = []
        t0 = time.time()
        while time.time() - t0 < seconds:
            st = self.status(iid)
            run = st.get("running") or {}
            fault = ((st.get("recovery") or {}).get("last_fault") or {}).get("code")
            cur = (st.get("phase"), run.get("generation"), run.get("pid"), fault)
            if not seen or seen[-1][1:] != cur:
                seen.append((round(time.time() - t0, 2), *cur))
            time.sleep(0.05)
        return seen

    def route_gone_and_kill(self, iid: str, kills: list[JsonDict], epoch: object) -> None:
        """AC-26 'route gone' in the strict sandbox.

        Remove its default routes (fault injection), then SIGKILL the worker while App and
        Gateway traffic keeps trying; restore the routes and let the next generation serve.
        Nothing may leave outside the tunnel meanwhile.
        """
        pid = cast("int", self.sandbox_ns_pid(iid))
        r4, r6 = self.sandbox_default_routes(pid)
        self.event("route_state", state="present (before removal)", v4=r4, v6=r6)
        for ln in r4:
            self.ns(pid, ["ip", "route", "del", *ln.split()])
        for ln in r6:
            self.ns(pid, ["ip", "-6", "route", "del", *ln.split()])
        gone4, gone6 = self.sandbox_default_routes(pid)
        self.event("route_state", state="gone", v4=gone4, v6=gone6)
        self.check(
            "route gone: the sandbox's default routes removed (fault injection)",
            bool(r4) and not gone4 and not gone6,
            before_v4=r4,
            before_v6=r6,
        )
        time.sleep(2)
        k = self.kill_worker_at(iid, {"ready", "degraded"}, label="route gone")
        kills.append(k)
        time.sleep(4)
        for ln in r4:
            self.ns(pid, ["ip", "route", "add", *ln.split()])
        for ln in r6:
            self.ns(pid, ["ip", "-6", "route", "add", *ln.split()])
        back4, back6 = self.sandbox_default_routes(pid)
        self.event("route_state", state="restored", v4=back4, v6=back6)
        self.check("route restored as it was", back4 == r4 and back6 == r6, v4=back4, v6=back6)
        self.recovered(iid, k, timeout=120, sandbox_epoch=epoch)

    def dns_down(self, *, strict: bool) -> None:
        """AC-31, every resolver unreachable.

        round1: the peer silent (SIGSTOP), the gate still open: lookups must fail with SERVFAIL
        by the DNS profile's deadline. round2: the watchdog has closed the gate: lookups refused
        at once. round3: the peer killed (its port refuses): whatever the connection does then
        (strict: the generation ends and reconnects), lookups must still fail within the
        deadline. Never a system-resolver query, never a packet on the NIC (the analysis checks
        that).
        """
        iid = self.main
        label = "strict" if strict else "gw"
        self.ensure_labpeer()
        self.wait_ready(iid, timeout=90, sandbox=strict)
        limit = self.deadline_ms / 1000 + 0.75
        app = None
        go = [self.appdir / f"go-dns-down-{label}-{n}" for n in (2, 3)]
        self.stop_labpeer(signal.SIGSTOP)
        t_down = time.time()
        if strict:
            app = self.create_app(
                iid,
                f"leak-dns-down-{label}",
                {"mode": "dns-down", "go_files": [str(g) for g in go], "wait_seconds": 240},
            )
            self.app_action(app, "start")
        self.dns_down_round(label, "round1", limit, "peer silent, gate open")
        st = self.wait_for(
            iid,
            "degraded (watchdog closed the gate)",
            lambda s: s.get("phase") in ("degraded", "reconnecting", "connecting"),
            timeout=150,
            poll=0.3,
        )
        self.event("dns_down_state", phase=st.get("phase"), after=round(time.time() - t_down, 1))
        self.dns_down_round(label, "round2", limit, "peer silent, gate closed")
        if app:
            go[0].write_text("")
            time.sleep(limit + 1)
        self.stop_labpeer(signal.SIGKILL)
        time.sleep(1.5)
        st = self.status(iid)
        self.event("dns_down_state", phase=st.get("phase"), after=round(time.time() - t_down, 1))
        if app:
            go[1].write_text("")
        self.dns_down_round(label, "round3", limit, f"peer killed, connection {st.get('phase')}")
        if app:
            self.dns_down_app_checks(app, limit)
        self.start_labpeer()
        self.wait_ready(iid, timeout=120, sandbox=strict)

    def dns_down_app_checks(self, app: str, limit: float) -> None:
        """Check every lookup of the App's dns-down probe failed within its limit."""
        self.wait_app_done(app, timeout=120)
        gai_limit = 2 * (self.deadline_ms / 1000 + 0.75)
        for ln in self.app_lines(app):
            if not ln["probe"].startswith("dns-down"):
                continue
            d = ln["detail"]
            el = d.get("elapsed_ms", 0) / 1000
            if d["kind"] == "getaddrinfo":
                ok = "error" in d and el <= gai_limit
                lim = gai_limit
            else:
                ok = d.get("rcode") in ("SERVFAIL", "REFUSED") and el <= limit
                lim = limit
            self.check(f"App {ln['probe']}: failed, within {lim:.2f} s", ok, details=d, limit_s=lim)
            self.event(
                "dns_timing",
                round=ln["probe"].split(":")[0].split()[-1],
                what=f"App {d['kind']}",
                outcome=d.get("rcode") or d.get("error"),
                seconds=round(el, 3),
            )

    def dns_down_round(self, label: str, rnd: str, limit: float, state: str) -> None:
        """Lookups by name through both Gateways at once; each must fail within `limit`."""
        results: list[tuple[str, object, float, bool]] = []

        def socks_name(gw: int, i: int) -> None:
            name = f"{self.mark(f'down-{label}-{rnd}-s{gw}-{i}')}.lab.test"
            s, rep, el = socks5_connect(gw, name, 80, timeout=20)
            if s:
                s.close()
            # Failed = the CONNECT did not succeed: a refusal, or reset/closed without a reply.
            results.append((f"SOCKS5 CONNECT by name via port {gw}", rep, el, s is None))

        def http_name(i: int) -> None:
            host = f"{self.mark(f'down-{label}-{rnd}-h{i}')}.lab.test"
            t0 = time.monotonic()
            st: int | str
            try:
                with socket.create_connection(("127.0.0.1", self.gw_mixed), timeout=20) as s:
                    st, _ = http_exchange(
                        s, http_request(f"http://{host}/", host, self.token), timeout=20
                    )
            except OSError as e:
                st = errno_name(e)
            el = time.monotonic() - t0
            failed = isinstance(st, int) and st >= HTTPStatus.INTERNAL_SERVER_ERROR
            results.append(("HTTP proxy GET by name", st, el, failed))

        jobs = [
            threading.Thread(target=socks_name, args=(gw, i))
            for gw in (self.gw_socks, self.gw_mixed)
            for i in range(2)
        ]
        jobs += [threading.Thread(target=http_name, args=(i,)) for i in range(2)]
        for j in jobs:
            j.start()
        for j in jobs:
            j.join()
        for what, outcome, el, failed in results:
            self.check(
                f"{rnd} ({state}): {what} fails within {limit:.2f} s",
                failed and el <= limit,
                outcome=outcome,
                seconds=round(el, 3),
                limit_s=limit,
            )
            self.event("dns_timing", round=rnd, what=what, outcome=outcome, seconds=round(el, 3))

    def v6_block(self) -> None:
        """AC-20: an IPv4-only profile; IPv6 refused by the Gateways and in the sandbox."""
        self.ensure_labpeer()
        with contextlib.suppress(Exception):
            self.stop_instance(self.main)
        conf = (self.state / "lab.conf").read_text()
        conf4 = re.sub(r"(?m)^Address\s*=.*$", f"Address = {CLIENT_V4}/32", conf)
        st, r = self.api.request(
            "POST",
            "/v1/profiles/import",
            {"mode": "commit", "name": "Lab peer (IPv4 only)", "config": conf4},
        )
        if st not in (HTTPStatus.OK, HTTPStatus.CREATED):
            msg = f"import IPv4-only profile: HTTP {st} {r}"
            raise RuntimeError(msg)
        profile4 = r["profile"]["id"]
        st, v = self.api.request(
            "POST",
            "/v1/instances",
            {
                "name": "IPv4-only",
                "profile_id": profile4,
                "dns_profile_id": self.dns_profile,
                "security_profile_id": self.security_profile,
            },
        )
        if st != HTTPStatus.CREATED:
            msg = f"create IPv4-only connection: HTTP {st} {v}"
            raise RuntimeError(msg)
        iid = v["spec"]["id"]
        self.instances.append(iid)
        self.v4 = iid
        for port, kind in ((self.gw4_socks, "socks5"), (self.gw4_mixed, "mixed")):
            st, g = self.api.request(
                "POST",
                "/v1/gateways",
                {
                    "instance_id": iid,
                    "name": f"v4 {kind}",
                    "kind": kind,
                    "port": port,
                    "udp": True,
                    "enabled": True,
                    "max_connections": 64,
                },
            )
            if st != HTTPStatus.CREATED:
                msg = f"create Gateway: HTTP {st} {g}"
                raise RuntimeError(msg)
            self.event("gateway_port", port=port)
        self.action(iid, "start")
        self.wait_ready(iid, timeout=60)
        self.v6_gateway_checks("v4only-gw")
        self.gateway_tests("v4only-gw", self.gw4_socks, self.gw4_mixed, v6=False)
        self.set_strict(iid, strict=True)
        self.inspect_sandbox(iid, "v4only", expect_v6=False)
        self.start_sandbox_capture(iid, "sandbox-v4only")
        self.v6_gateway_checks("v4only-strict")
        self.run_app_probe(iid, "leak-v6-block", {"mode": "v6-block"})
        time.sleep(1)
        self.stop_sandbox_capture("sandbox-v4only")
        self.stop_instance(iid)

    def v6_gateway_checks(self, label: str) -> None:
        """IPv6 through the IPv4-only connection's Gateways must be refused or dropped."""
        for host, port in ((LAB_V6, 80), (PUBLIC_V6, 443)):
            s, rep, el = socks5_connect(self.gw4_socks, host, port)
            if s:
                s.close()
            self.check(
                f"SOCKS5 CONNECT [{host}]:{port} refused (no IPv6 in the profile) [{label}]",
                s is None and isinstance(rep, int) and rep != 0,
                reply=rep,
                ms=int(el * 1000),
            )
        try:
            with socket.create_connection(("127.0.0.1", self.gw4_mixed), timeout=10) as s:
                st, body = http_exchange(
                    s, http_request(f"http://[{LAB_V6}]/ip", f"[{LAB_V6}]", self.mark(label))
                )
        except OSError as e:
            st, body = 0, errno_name(e).encode()
        self.check(
            f"HTTP proxy GET http://[{LAB_V6}]/ refused [{label}]",
            st >= HTTPStatus.BAD_REQUEST,
            status=st,
            body=body[:200].decode(errors="replace"),
        )
        name = f"{self.mark(label + '-name')}.lab.test"
        s2, rep, _ = socks5_connect(self.gw4_socks, name, 80)
        ok = False
        body = b""
        if s2:
            with s2:
                st, body = http_exchange(s2, http_request("/ip", name, self.mark(label)))
                ok = st == HTTPStatus.OK and f'"ip":"{CLIENT_V4}"'.encode() in body
        self.check(
            f"SOCKS5 CONNECT by name uses IPv4 [{label}]",
            ok,
            reply=rep,
            body=body[:120].decode(errors="replace"),
        )
        a = Socks5Udp(self.gw4_socks, on_relay=self.relay)
        try:
            msg = self.mark(label + "-udp6").encode()
            a.send(LAB_V6, 7, msg)
            got: bytes | None
            try:
                got = a.recv(2.0)
            except OSError:
                got = None
            self.check(f"UDP ASSOCIATE to [{LAB_V6}]:7 dropped [{label}]", got is None)
        finally:
            a.close()

    def teardown(self) -> None:
        """Delete the Apps and connections, stop the dev stack, check nothing is left."""
        for name in list(self.sandbox_caps):
            self.stop_sandbox_capture(name)
        for app in self.apps:
            with contextlib.suppress(Exception):
                self.delete_app(app)
        for iid in self.instances:
            v = self.view(iid)
            if not v:
                continue
            with contextlib.suppress(Exception):
                self.stop_instance(iid)
            v = self.view_of(iid)
            ids = ",".join(g["id"] for g in v["gateways"])
            st, _ = self.api.request(
                "DELETE", f"/v1/instances/{iid}?gateways={ids}", rev=v["spec"]["revision"]
            )
            self.check(
                f"connection {v['spec']['name']} deleted",
                st == HTTPStatus.NO_CONTENT,
                status=st,
            )
        holders: list[int] = []
        for _ in range(100):
            holders = [p for p, a in proc_cmdlines().items() if "sandbox-holder" in a]
            if not holders:
                break
            time.sleep(0.1)
        self.check(
            "no sandbox holder left after deleting the connections", not holders, holders=holders
        )
        self.stop_stack()
        left = {p: a for p, a in proc_cmdlines().items() if a[0].endswith(("vpnd", "vpn-labpeer"))}
        self.check("every product process ended", not left, left=left)

    def delete_app(self, app: str) -> None:
        """Stop an App if it runs, then delete it."""
        s = self.app_status(app)
        if s.get("state") in ("running", "starting"):
            self.app_action(app, "stop")
            for _ in range(100):
                if self.app_status(app).get("state") in ("stopped", "failed"):
                    break
                time.sleep(0.2)
        _, v = self.api.request("GET", f"/v1/apps/{app}")
        self.api.request("DELETE", f"/v1/apps/{app}", rev=v["spec"]["revision"])

    def stop_stack(self) -> None:
        """Stop the dev stack and every lab peer we started; wait for the product to end."""
        stack = getattr(self, "stack", None)
        if stack and stack.poll() is None:
            os.killpg(stack.pid, signal.SIGTERM)
            with contextlib.suppress(subprocess.TimeoutExpired):
                stack.wait(timeout=30)
        for c in self.children:
            if c.poll() is None:
                c.send_signal(signal.SIGTERM)
                with contextlib.suppress(subprocess.TimeoutExpired):
                    c.wait(timeout=10)
        for _ in range(100):
            if not [
                p for p, a in proc_cmdlines().items() if a[0].endswith(("vpnd", "vpn-labpeer"))
            ]:
                break
            time.sleep(0.1)

    def create_dead_dns(self) -> None:
        """Create a DNS profile whose only resolver is unreachable."""
        st, r = self.api.request(
            "POST",
            "/v1/dns-profiles",
            {
                "name": "Lab DNS (unreachable resolver)",
                "servers": [{"transport": "udp", "address": "10.99.0.99:53"}],
                "query_timeout_ms": self.deadline_ms,
                "attempts": 2,
            },
        )
        if st != HTTPStatus.CREATED:
            msg = f"create DNS profile: HTTP {st} {r}"
            raise RuntimeError(msg)
        self.dead_dns = r["id"]

    def main_flow(self) -> None:
        """Run every scenario in order, with the snapshots between them."""
        self.snapshot("0-before")
        with self.scenario("control_pre", "harness controls: what a leak would look like"):
            self.controls()
        with self.scenario("setup", "dev stack (release, seeded) comes up"):
            self.start_stack()
            self.create_dead_dns()
            _, dns = self.api.request("GET", f"/v1/dns-profiles/{self.dns_profile}")
            self.deadline_ms = int(dns.get("query_timeout_ms", 3000))
            self.meta["deadline_ms"] = self.deadline_ms
            self.write_meta()
        self.snapshot("1-running")
        with self.scenario(
            "a_baseline",
            "Gateways: TCP/UDP/DNS, IPv4 and IPv6, through the tunnel only",
            expect=["wireguard"],
        ):
            self.gateway_tests("baseline", self.gw_socks, self.gw_mixed)
        with self.scenario(
            "c_fault_gateway",
            "AC-26 faults with Gateway traffic: SIGKILL the worker per phase, peer gone",
            expect=["wireguard"],
        ):
            self.faults(strict=False)
        with self.scenario("d_dns_down_gateway", "AC-31 every resolver down: Gateway lookups"):
            self.dns_down(strict=False)
        self.snapshot("2-after-faults")
        with self.scenario(
            "b_strict",
            "strict sandbox: lo + vpn0 only, Gateways and a managed App",
            expect=["wireguard", "vpn0_markers"],
        ):
            self.set_strict(self.main, strict=True)
            self.inspect_sandbox(self.main, "dualstack", expect_v6=True)
            self.start_sandbox_capture(self.main, "sandbox-dualstack")
            self.gateway_tests("strict", self.gw_socks, self.gw_mixed)
            self.run_app_probe(self.main, "leak-probe", {"mode": "baseline"})
        with self.scenario(
            "c_fault_strict",
            "AC-26 faults in strict mode: App and Gateway traffic, kills per phase, "
            "route gone/present",
            expect=["wireguard", "vpn0_markers"],
        ):
            self.faults(strict=True)
        with self.scenario(
            "d_dns_down_strict", "AC-31 every resolver down: App and Gateway lookups in strict mode"
        ):
            self.dns_down(strict=True)
        self.snapshot("3-strict")
        self.stop_sandbox_capture("sandbox-dualstack")
        with self.scenario(
            "e_v6_block",
            "AC-20 IPv6 block mode: profile without IPv6, Gateway and strict App",
            expect=["wireguard", "vpn0_ipv4_only"],
        ):
            self.v6_block()
        with self.scenario("teardown", "Apps and connections deleted, dev stack stopped"):
            self.teardown()
        self.snapshot("4-stopped")
        with self.scenario("control_post", "harness controls again: the captures still see"):
            self.controls()


class FaultSteps:
    """The AC-26 fault steps of one `Run.faults` pass; each kill is collected in `kills`."""

    def __init__(self, run: Run, iid: str, *, strict: bool, epoch: object) -> None:
        """Fault the connection `iid` (strict: its sandbox `epoch` must survive)."""
        self.run, self.iid, self.strict, self.epoch = run, iid, strict, epoch
        self.label = "strict" if strict else "gw"
        self.kills: list[JsonDict] = []

    def run_all(self) -> None:
        """Run every step in order (route gone only in strict mode)."""
        steps: list[tuple[str, Callable[[], None]]] = [
            ("ready", self.ready),
            ("right after start", self.right_after_start),
            ("connecting", self.connecting),
            ("peer killed", self.peer_killed),
            ("degraded (silent peer)", self.degraded),
            ("verifying", self.verifying),
        ]
        if self.strict:
            steps.append(("route gone", self.route_gone))
        for title, fn in steps:
            self.step(title, fn)

    def step(self, title: str, fn: Callable[[], None]) -> None:
        """Run one fault; a failure is recorded and the connection brought back for the next."""
        run, iid = self.run, self.iid
        try:
            fn()
        except Exception as e:  # noqa: BLE001 - a failed step is recorded, the next one runs
            run.check(
                f"fault step ran: {title}",
                ok=False,
                error=f"{type(e).__name__}: {e}",
                trace=traceback.format_exc()[-2000:],
            )
            with contextlib.suppress(Exception):
                run.update_instance(iid, dns_profile_id=run.dns_profile)
            run.ensure_labpeer()
            with contextlib.suppress(Exception):
                run.action(iid, "restart")
                run.wait_ready(iid, timeout=120, sandbox=self.strict)

    def ready(self) -> None:
        """Ready, with every kind of traffic flowing."""
        k = self.run.kill_worker_at(self.iid, {"ready"}, label="ready, transfer running")
        self.kills.append(k)
        if self.strict:
            # No worker now: the sandbox keeps its routes through vpn0 ("route still
            # present"); nothing reads the TUN device.
            self.run.record_sandbox_routes("present, worker killed")
        self.run.recovered(self.iid, k, sandbox_epoch=self.epoch)
        time.sleep(2)

    def right_after_start(self) -> None:
        """Kill the new worker right after a (re)start, before it is Ready.

        On loopback the early phases last milliseconds: try a few restarts.
        """
        for _attempt in range(6):
            k = self.run.kill_worker_at(
                self.iid,
                {"starting", "connecting", "verifying", "ready"},
                trigger="restart",
                label="right after start",
            )
            self.kills.append(k)
            self.run.recovered(self.iid, k, sandbox_epoch=self.epoch)
            if k["phase"] != "ready":
                return
            time.sleep(0.5)
        self.run.check("caught a worker before Ready right after a restart", ok=False, attempts=6)

    def connecting(self) -> None:
        """No peer to answer the handshake: the new worker stays in Connecting."""
        self.run.stop_labpeer()
        k = self.run.kill_worker_at(
            self.iid, {"connecting"}, trigger="restart", label="connecting, peer down"
        )
        self.kills.append(k)
        time.sleep(2)
        self.run.start_labpeer()
        self.run.recovered(self.iid, k, timeout=90, sandbox_epoch=self.epoch)
        time.sleep(2)

    def peer_killed(self) -> None:
        """Kill the peer process while traffic runs.

        Its port is closed, so the kernel answers every WireGuard datagram with ICMP port
        unreachable. Watch what the connection does for 20 s (phases are recorded), then bring
        the peer back.
        """
        run, iid = self.run, self.iid
        gen = (run.status(iid).get("running") or {}).get("generation", 0)
        run.stop_labpeer()
        phases = run.watch_phases(iid, 20)
        run.event("peer_killed_phases", phases=phases)
        run.start_labpeer()
        st = run.wait_ready(iid, timeout=120, sandbox=self.strict)
        run.check(
            "peer killed while traffic ran: the connection came back when the peer "
            "returned (that nothing left outside the tunnel meanwhile is the capture "
            "check)",
            ok=True,
            generation_before=gen,
            generation_after=st["running"]["generation"],
        )
        # How the connection reacts to ICMP port unreachable from the peer (phase, generation,
        # worker, last fault code): reported as product behaviour.
        run.check(
            f"observation: connection phases while the peer's port was closed [{self.label}]",
            ok=True,
            observation=True,
            phases=phases,
        )
        time.sleep(2)

    def degraded(self) -> None:
        """Silence the peer (SIGSTOP: nothing answers, nothing is refused).

        As when it is lost on a real network: the worker's watchdog degrades the connection
        after two failed DNS probes (30 s apart); kill the worker in that state.
        """
        self.run.stop_labpeer(signal.SIGSTOP)
        k = self.run.kill_worker_at(
            self.iid, {"degraded"}, timeout=150, label="degraded, peer silent"
        )
        self.kills.append(k)
        time.sleep(3)
        self.run.resume_labpeer()
        self.run.recovered(self.iid, k, timeout=120, sandbox_epoch=self.epoch)
        time.sleep(2)

    def route_gone(self) -> None:
        """Strict only: the sandbox's default routes removed (fault injection), then a kill.

        With no route the sandbox's stack has nowhere to send ("route gone"); after the routes
        are restored the next generation serves again.
        """
        self.run.route_gone_and_kill(self.iid, self.kills, self.epoch)

    def verifying(self) -> None:
        """Kill the worker while the DNS probe cannot be answered (resolver unreachable)."""
        run, iid = self.run, self.iid
        run.update_instance(iid, dns_profile_id=run.dead_dns)
        k = run.kill_worker_at(
            iid,
            {"verifying"},
            trigger="restart",
            timeout=40,
            label="verifying, resolver unreachable",
        )
        self.kills.append(k)
        run.update_instance(iid, dns_profile_id=run.dns_profile)
        time.sleep(1)
        run.action(iid, "restart")
        run.recovered(iid, k, timeout=120, sandbox_epoch=self.epoch)
        time.sleep(2)


def cmd_drive(a: argparse.Namespace) -> int:
    """Run the harness's scenarios (the driver's side)."""
    run = Run(a)
    log(f"token {run.token}; out {a.out}")

    def interrupted(*_: object) -> NoReturn:
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, interrupted)
    try:
        run.main_flow()
    except KeyboardInterrupt:
        run.event("interrupted")
        log("interrupted")
    finally:
        with contextlib.suppress(Exception):
            for name in list(run.sandbox_caps):
                run.stop_sandbox_capture(name)
        run.stop_stack()
        run.meta["finished"] = time.time()
        run.write_meta()
    return 0


def main() -> int:
    """Parse the command line and run `drive` or `app-probe`."""
    ap = argparse.ArgumentParser(
        description=DESCRIPTION, formatter_class=argparse.RawTextHelpFormatter
    )
    sub = ap.add_subparsers(dest="cmd", required=True)
    d = sub.add_parser("drive")
    d.add_argument("--out", required=True)
    d.add_argument("--work", required=True)
    d.add_argument("--devroot", required=True)
    d.add_argument("--base", type=int, required=True)
    d.add_argument("--source", default="")
    d.add_argument("--commit", default="")
    d.add_argument("--nic", default="")
    d.add_argument("--nic-dev", default="")
    p = sub.add_parser("app-probe")
    p.add_argument("--plan", required=True)
    a = ap.parse_args()
    return cmd_drive(a) if a.cmd == "drive" else cmd_app_probe(a)


if __name__ == "__main__":
    sys.exit(main())
