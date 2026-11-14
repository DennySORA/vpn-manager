#!/usr/bin/env python3
"""Packet capture and leak analysis for scripts/leak-capture-linux.sh (Python 3.9+, stdlib only).

The subcommands are described in HELP, which is also the command-line help.
"""

from __future__ import annotations

import argparse
import collections
import ctypes
import difflib
import errno
import ipaddress
import json
import mmap
import os
import re
import select
import signal
import socket
import struct
import sys
import time
from pathlib import Path
from typing import TYPE_CHECKING, Any, BinaryIO, NamedTuple, TypedDict

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator

    JsonObj = dict[str, Any]
    # Allowed (True), listed but not counted ("listed"), or a violation (False).
    Verdict = bool | str
    # Timestamp in ns, packet type, hardware type, protocol, hardware address, data, truncated.
    RawPacket = tuple[int, int, int, int, bytes, bytes, bool]
    # Scenario name, begin and end time, the begin event.
    Window = tuple[str, float, float, JsonObj]
    FlowKey = tuple[str, str, str, int | None, int | None]

HELP = """\
Packet capture and leak analysis for scripts/leak-capture-linux.sh (Python 3.9+, stdlib only).

  capture --iface IF --name NAME --dir DIR [--skip-outgoing] [--tun-nic] [--ring-mb N]
      Record every packet of one interface into DIR/NAME.pcap: pcap with nanosecond
      timestamps and LINKTYPE_LINUX_SLL, so Wireshark, tshark or `tcpdump -r` open it. Uses an
      AF_PACKET socket with a TPACKET_V3 memory ring (N MiB), which needs CAP_NET_RAW in the
      user namespace that owns the network namespace (the harness is uid 0 in its own user
      namespace; no host privilege). Kernel timestamps, kernel drop counters
      (PACKET_STATISTICS) and truncation are recorded; any drop fails the run.
      --skip-outgoing drops the PACKET_OUTGOING copy of each packet with a kernel BPF filter
      (loopback shows every packet twice, once leaving and once arriving; libpcap does the same).
      --tun-nic creates IF as a TUN device and reads its packets from the device itself: the
      fake NIC for hosts where the dummy driver is not loaded.
      WireGuard configuration keys that pass through a captured API request (the lab profile
      import) are overwritten with 'X' before writing (counted in the stats).
      Writes DIR/NAME.ready once it records and DIR/NAME.stats.json when stopped (TERM/INT).

  analyze --out OUT
      Classify every captured packet, attribute it to the scenario window it falls in
      (OUT/results/events.jsonl), write OUT/results/summary.json, flows-<capture>.json and
      report.txt, print PASS/FAIL per scenario and per acceptance criterion. Exit status 1 if
      anything fails.
"""

# --------------------------------------------------------------------------------------------
# Capture
# --------------------------------------------------------------------------------------------

ETH_P_ALL = 0x0003
SOL_PACKET = 263
PACKET_STATISTICS = 6
PACKET_OUTGOING = 4
SO_RCVBUFFORCE = 33
SO_TIMESTAMPNS = 35  # == SCM_TIMESTAMPNS (asm-generic, x86_64, arm64)
LINKTYPE_LINUX_SLL = 113
PCAP_MAGIC_NS = 0xA1B23C4D
PCAP_MAGIC_US = 0xA1B2C3D4
PCAP_HEADER_LEN = 24
PCAP_RECORD_HEADER_LEN = 16
SLL_HEADER_LEN = 16
SNAPLEN = 262144
ARPHRD_NONE = 0xFFFE

TUNSETIFF = 0x400454CA
IFF_TUN = 0x0001
IFF_NO_PI = 0x1000

# Once stopping, keep reading this long: the kernel retires a pending block within 50 ms.
DRAIN_SECONDS = 0.4
FLUSH_EVERY_SECONDS = 0.5
STATS_EVERY_SECONDS = 1.0

KEY_RE = re.compile(rb"((?:Private|Preshared)Key\s*=\s*)([A-Za-z0-9+/]{42,44}={0,2})")


def redact(data: bytes) -> tuple[bytes, int]:
    """Overwrite WireGuard keys of a .conf text inside a packet; returns (data, count)."""
    if b"Key" not in data:
        return data, 0
    count = 0

    def sub(m: re.Match[bytes]) -> bytes:
        nonlocal count
        count += 1
        return m.group(1) + b"X" * len(m.group(2))

    return KEY_RE.sub(sub, data), count


SO_ATTACH_FILTER = 26
PACKET_RX_RING = 5
PACKET_VERSION = 10
TPACKET_V3 = 2
TP_STATUS_USER = 1
TPACKET3_HDRLEN = 48  # TPACKET_ALIGN(sizeof(struct tpacket3_hdr))


def bpf_skip_outgoing() -> tuple[bytes, int]:
    """Classic BPF: drop PACKET_OUTGOING copies in the kernel, accept the rest whole."""
    ins = [
        (0x20, 0, 0, 0xFFFFF004),  # load the packet type (SKF_AD_OFF + SKF_AD_PKTTYPE)
        (0x15, 0, 1, PACKET_OUTGOING),  # jump if equal to PACKET_OUTGOING
        (0x06, 0, 0, 0),  # return 0: drop
        (0x06, 0, 0, SNAPLEN),  # return the snap length: accept
    ]
    return b"".join(struct.pack("HBBI", *i) for i in ins), len(ins)


class PacketSource:
    """AF_PACKET socket bound to one interface, read through a TPACKET_V3 memory ring.

    SOCK_DGRAM: the kernel strips the link header and reports packet type, hardware type and
    protocol (they go into the SLL header). The ring is kernel memory mapped into this process; its
    size does not depend on net.core.rmem_max, which a user namespace cannot raise (SO_RCVBUFFORCE
    needs CAP_NET_ADMIN in the initial namespace), so bursts on loopback are absorbed instead of
    dropped. Whatever still does not fit is counted by the kernel and reported.
    """

    def __init__(self, iface: str, *, skip_outgoing: bool, ring_mb: int) -> None:
        """Open the socket and its ring, bound to `iface`."""
        # Protocol 0 at creation, ETH_P_ALL at bind: nothing from other interfaces gets queued
        # before the socket is bound (what libpcap does).
        self.sock = socket.socket(socket.AF_PACKET, socket.SOCK_DGRAM, 0)
        self.filter_outgoing = False
        if skip_outgoing:
            prog, n = bpf_skip_outgoing()
            buf = ctypes.create_string_buffer(prog)
            self.sock.setsockopt(
                socket.SOL_SOCKET, SO_ATTACH_FILTER, struct.pack("HL", n, ctypes.addressof(buf))
            )
            self.filter_outgoing = True
        self.block_size = 4 << 20
        self.block_nr = max(2, ring_mb // 4)
        frame_size = 2048
        self.sock.setsockopt(SOL_PACKET, PACKET_VERSION, TPACKET_V3)
        req = struct.pack(
            "7I",
            self.block_size,
            self.block_nr,
            frame_size,
            (self.block_size // frame_size) * self.block_nr,
            50,  # retire a block after 50 ms even when it is not full
            0,
            0,
        )
        self.sock.setsockopt(SOL_PACKET, PACKET_RX_RING, req)
        self.ring = mmap.mmap(
            self.sock.fileno(),
            self.block_size * self.block_nr,
            mmap.MAP_SHARED,
            mmap.PROT_READ | mmap.PROT_WRITE,
        )
        self.sock.bind((iface, ETH_P_ALL))
        self.poller = select.poll()
        self.poller.register(self.sock.fileno(), select.POLLIN | select.POLLERR)
        self.block = 0
        self.pending: collections.deque[RawPacket] = collections.deque()
        self.kernel_packets = 0
        self.kernel_drops = 0
        self.freezes = 0

    def _take_block(self) -> bool:
        off = self.block * self.block_size
        status = struct.unpack_from("I", self.ring, off + 8)[0]
        if not status & TP_STATUS_USER:
            return False
        num, first = struct.unpack_from("II", self.ring, off + 12)
        p = off + first
        out: list[RawPacket] = []
        for _ in range(num):
            nxt, sec, nsec, snaplen, plen, _st, mac, _net = struct.unpack_from(
                "IIIIIIHH", self.ring, p
            )
            sll = p + TPACKET3_HDRLEN
            proto = struct.unpack_from(">H", self.ring, sll + 2)[0]
            hatype, pkttype, halen = struct.unpack_from("HBB", self.ring, sll + 8)
            hwaddr = bytes(self.ring[sll + 12 : sll + 12 + min(halen, 8)])
            data = bytes(self.ring[p + mac : p + mac + snaplen])
            out.append(
                (sec * 1_000_000_000 + nsec, pkttype, hatype, proto, hwaddr, data, snaplen < plen)
            )
            p += nxt
        # Hand the block back to the kernel.
        struct.pack_into("I", self.ring, off + 8, 0)
        self.block = (self.block + 1) % self.block_nr
        self.pending.extend(out)
        return True

    def read(self) -> RawPacket | None:
        """One packet as (ts_ns, pkttype, hatype, proto, hwaddr, data, truncated), or None."""
        if not self.pending and not self._take_block():
            self.poller.poll(200)
            if not self._take_block():
                return None
        return self.pending.popleft() if self.pending else None

    def poll_stats(self) -> None:
        """Add the kernel's packet and drop counters since the last call."""
        # Reading PACKET_STATISTICS resets the kernel's counters: accumulate (tpacket_stats_v3).
        packets, drops, freezes = struct.unpack(
            "III", self.sock.getsockopt(SOL_PACKET, PACKET_STATISTICS, 12)
        )
        self.kernel_packets += packets
        self.kernel_drops += drops
        self.freezes += freezes

    def stats(self) -> dict[str, object]:
        """Return the final counters for the stats file."""
        self.poll_stats()
        return {
            "kind": "af_packet_tpacket_v3",
            "kernel_packets": self.kernel_packets,
            "kernel_drops": self.kernel_drops,
            "ring_bytes": self.block_size * self.block_nr,
            "outgoing_copies_filtered_in_kernel": self.filter_outgoing,
        }

    def close(self) -> None:
        """Release the ring and the socket."""
        self.ring.close()
        self.sock.close()


class TunNicSource:
    """A TUN device that plays the host NIC: every packet routed to it is read here."""

    def __init__(self, iface: str) -> None:
        """Create the TUN device `iface`."""
        self.fd = os.open("/dev/net/tun", os.O_RDWR | os.O_NONBLOCK)
        # Imported here: fcntl is POSIX-only, and `analyze` must not need it.
        import fcntl  # noqa: PLC0415

        ifr = struct.pack("16sH22s", iface.encode(), IFF_TUN | IFF_NO_PI, b"")
        fcntl.ioctl(self.fd, TUNSETIFF, ifr)
        self.kernel_packets = 0

    def read(self) -> RawPacket | None:
        """One packet as (ts_ns, pkttype, hatype, proto, hwaddr, data, truncated), or None."""
        ready, _, _ = select.select([self.fd], [], [], 0.2)
        if not ready:
            return None
        try:
            data = os.read(self.fd, SNAPLEN)
        except BlockingIOError:
            return None
        ts = time.time_ns()
        self.kernel_packets += 1
        proto = ETHERTYPE_IPV6 if data and data[0] >> 4 == IP_VERSION_6 else ETHERTYPE_IPV4
        return ts, PACKET_OUTGOING, ARPHRD_NONE, proto, b"", data, False

    def poll_stats(self) -> None:
        """Do nothing: the device has no kernel counters to collect here."""

    def stats(self) -> dict[str, object]:
        """Return the final counters for the stats file."""
        # Drops in the device queue show in `ip -s link` (recorded by the harness).
        return {"kind": "tun_nic", "kernel_packets": self.kernel_packets, "kernel_drops": 0}

    def close(self) -> None:
        """Close the device."""
        os.close(self.fd)


class Recorded(NamedTuple):
    """What one capture wrote."""

    written: int
    truncated: int
    redactions: int
    error: str | None


def write_record(out: BinaryIO, pkt: RawPacket) -> tuple[int, bool]:
    """Append one packet to the pcap; returns (keys redacted, truncated)."""
    ts, pkttype, hatype, proto, hwaddr, data, trunc = pkt
    data, n = redact(data)
    sll = struct.pack(">HHH8sH", pkttype, hatype, len(hwaddr), hwaddr[:8], proto)
    record = sll + data
    out.write(
        struct.pack("<IIII", ts // 1_000_000_000, ts % 1_000_000_000, len(record), len(record))
    )
    out.write(record)
    return n, trunc


def record_until_stopped(
    source: PacketSource | TunNicSource, out: BinaryIO, stopping: list[int]
) -> Recorded:
    """Write packets until a stop signal arrives (then drain briefly) or the interface goes."""
    written = truncated = redactions = 0
    error = None
    last_flush = last_stats = time.monotonic()
    drain_until = None
    while True:
        if stopping and drain_until is None:
            # Blocks the kernel has not retired yet are retired within 50 ms: keep reading a
            # little so the last packets reach the file.
            drain_until = time.monotonic() + DRAIN_SECONDS
        if drain_until is not None and time.monotonic() > drain_until:
            break
        try:
            pkt = source.read()
        except OSError as e:
            # The interface went away (a sandbox torn down while still recorded).
            if e.errno in (errno.ENETDOWN, errno.ENXIO, errno.ENODEV, errno.EBADFD):
                error = f"interface gone: {e}"
                break
            raise
        now = time.monotonic()
        if pkt is not None:
            n, trunc = write_record(out, pkt)
            redactions += n
            truncated += trunc
            written += 1
        if now - last_flush > FLUSH_EVERY_SECONDS:
            out.flush()
            last_flush = now
        if now - last_stats > STATS_EVERY_SECONDS:
            source.poll_stats()
            last_stats = now
    return Recorded(written, truncated, redactions, error)


def cmd_capture(a: argparse.Namespace) -> int:
    """Run the `capture` subcommand."""
    directory = Path(a.dir)
    directory.mkdir(parents=True, exist_ok=True)
    stopping: list[int] = []
    for s in (signal.SIGTERM, signal.SIGINT):
        signal.signal(s, lambda *_: stopping.append(1))
    source = (
        TunNicSource(a.iface)
        if a.tun_nic
        else PacketSource(a.iface, skip_outgoing=a.skip_outgoing, ring_mb=a.ring_mb)
    )
    pcap_path = directory / (a.name + ".pcap")
    with pcap_path.open("wb", buffering=1 << 20) as out:
        out.write(struct.pack("<IHHiIII", PCAP_MAGIC_NS, 2, 4, 0, 0, SNAPLEN, LINKTYPE_LINUX_SLL))
        out.flush()
        started = time.time()
        with (directory / (a.name + ".ready")).open("w") as f:
            json.dump({"pid": os.getpid(), "iface": a.iface, "started": started}, f)
        rec = record_until_stopped(source, out, stopping)
        stats = source.stats()
        source.close()
    stats.update(
        {
            "name": a.name,
            "iface": a.iface,
            "pcap": pcap_path.name,
            "packets_written": rec.written,
            "truncated": rec.truncated,
            "redacted_keys": rec.redactions,
            "started": started,
            "stopped": time.time(),
            "error": rec.error,
        }
    )
    with (directory / (a.name + ".stats.json")).open("w") as f:
        json.dump(stats, f, indent=1)
    return 0


# --------------------------------------------------------------------------------------------
# Packet parsing
# --------------------------------------------------------------------------------------------

ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_IPV6 = 0x86DD
ETHERTYPE_ARP = 0x0806
IP_VERSION_4 = 4
IP_VERSION_6 = 6
IPV4_MIN_HEADER_LEN = 20
IPV6_HEADER_LEN = 40
IPPROTO_ICMP = 1
IPPROTO_IGMP = 2
IPPROTO_TCP = 6
IPPROTO_UDP = 17
IPPROTO_ICMPV6 = 58
IPV6_FRAGMENT = 44
IPV6_AH = 51
# Hop-by-hop, routing, fragment, destination options, authentication header.
IPV6_EXT_HEADERS = (0, 43, IPV6_FRAGMENT, 60, IPV6_AH)
PORTS_LEN = 4  # source and destination port
TCP_FLAGS_END = 14
UDP_LENGTH_END = 6
ICMP_TYPE_CODE_LEN = 2
ICMP_HEADER_LEN = 8
UDP_HEADER_LEN = 8


class Pkt:
    """One parsed packet (or the copy of one quoted in an ICMP error)."""

    __slots__ = (
        "dport",
        "dst",
        "fam",
        "flags",
        "icmp_code",
        "icmp_type",
        "inner",
        "l4",
        "length",
        "payload",
        "pkttype",
        "quoted",
        "raw",
        "sport",
        "src",
        "t",
        "ulen",
    )

    t: float
    fam: str
    src: str
    dst: str
    l4: str
    sport: int | None
    dport: int | None
    flags: int
    payload: bytes
    raw: bytes
    icmp_type: int | None
    icmp_code: int | None
    inner: Pkt | None
    pkttype: int
    length: int
    ulen: int | None
    quoted: bool

    def __init__(self) -> None:
        """Start with an empty, unclassified packet."""
        self.t = 0.0
        self.fam = "other"
        self.src = self.dst = ""
        self.l4 = ""
        self.sport = self.dport = None
        self.flags = 0
        self.payload = b""
        self.raw = b""
        self.icmp_type = self.icmp_code = None
        self.inner = None
        self.pkttype = 0
        self.length = 0
        self.ulen = None  # UDP length field
        self.quoted = False  # the copy of a packet inside an ICMP error (may be truncated)

    def key(self) -> FlowKey:
        """Return the flow this packet belongs to."""
        return (self.l4, self.src, self.dst, self.sport, self.dport)

    def describe(self) -> str:
        """Return a one-line description of the packet."""
        s = f"{self.l4} {self.src}"
        if self.sport is not None:
            s += f":{self.sport}"
        s += f" -> {self.dst}"
        if self.dport is not None:
            s += f":{self.dport}"
        if self.icmp_type is not None:
            s += f" type={self.icmp_type} code={self.icmp_code}"
        return s


ICMP4_ERRORS = {3, 4, 5, 11, 12}
ICMP6_ERRORS = {1, 2, 3, 4}
ND_MLD_TYPES = {130, 131, 132, 133, 134, 135, 136, 137, 143}


def parse_icmp(p: Pkt, proto: int, b: bytes, *, quoted: bool) -> None:
    """Fill in an ICMP or ICMPv6 header, and the packet an ICMP error quotes."""
    p.l4 = "icmp" if proto == IPPROTO_ICMP else "icmp6"
    p.icmp_type, p.icmp_code = b[0], b[1]
    p.payload = b[4:]
    errors = ICMP4_ERRORS if proto == IPPROTO_ICMP else ICMP6_ERRORS
    if p.icmp_type in errors and not quoted and len(b) > ICMP_HEADER_LEN:
        p.inner = parse_ip(
            ETHERTYPE_IPV4 if proto == IPPROTO_ICMP else ETHERTYPE_IPV6, b[8:], quoted=True
        )


def parse_l4(p: Pkt, proto: int, b: bytes, *, quoted: bool) -> None:
    """Fill in the transport header of `p` from the IP payload `b`."""
    if proto == IPPROTO_TCP and len(b) >= PORTS_LEN:
        p.l4 = "tcp"
        p.sport, p.dport = struct.unpack(">HH", b[:4])
        if len(b) >= TCP_FLAGS_END:
            off = (b[12] >> 4) * 4
            p.flags = b[13]
            p.payload = b[off:]
    elif proto == IPPROTO_UDP and len(b) >= PORTS_LEN:
        p.l4 = "udp"
        p.sport, p.dport = struct.unpack(">HH", b[:4])
        if len(b) >= UDP_LENGTH_END:
            p.ulen = struct.unpack(">H", b[4:6])[0]
        p.payload = b[8:]
    elif proto in (IPPROTO_ICMP, IPPROTO_ICMPV6) and len(b) >= ICMP_TYPE_CODE_LEN:
        parse_icmp(p, proto, b, quoted=quoted)
    elif proto == IPPROTO_IGMP:
        p.l4 = "igmp"
        p.payload = b
    else:
        p.l4 = f"ip-proto-{proto}"
        p.payload = b


def parse_ipv4(p: Pkt, b: bytes, *, quoted: bool) -> None:
    """Fill in an IPv4 packet."""
    p.fam = "ipv4"
    ihl = (b[0] & 0x0F) * 4
    total = struct.unpack(">H", b[2:4])[0]
    proto = b[9]
    p.src = socket.inet_ntop(socket.AF_INET, b[12:16])
    p.dst = socket.inet_ntop(socket.AF_INET, b[16:20])
    frag = struct.unpack(">H", b[6:8])[0] & 0x1FFF
    body = b[ihl:total] if not quoted and total >= ihl else b[ihl:]
    if frag:
        p.l4 = "ipv4-fragment"
        p.payload = body
    else:
        parse_l4(p, proto, body, quoted=quoted)


def parse_ipv6(p: Pkt, b: bytes, *, quoted: bool) -> None:
    """Fill in an IPv6 packet, walking its extension headers."""
    p.fam = "ipv6"
    p.src = socket.inet_ntop(socket.AF_INET6, b[8:24])
    p.dst = socket.inet_ntop(socket.AF_INET6, b[24:40])
    nh = b[6]
    off = 40
    while nh in IPV6_EXT_HEADERS and off + 8 <= len(b):
        if nh == IPV6_FRAGMENT:
            if struct.unpack(">H", b[off + 2 : off + 4])[0] & 0xFFF8:
                p.l4 = "ipv6-fragment"
                p.payload = b[off + 8 :]
                return
            nh, off = b[off], off + 8
        elif nh == IPV6_AH:
            nh, off = b[off], off + (b[off + 1] + 2) * 4
        else:
            nh, off = b[off], off + (b[off + 1] + 1) * 8
    parse_l4(p, nh, b[off:], quoted=quoted)


def parse_ip(ethertype: int, b: bytes, *, quoted: bool = False) -> Pkt:
    """Parse one packet of the given ethertype."""
    p = Pkt()
    p.raw = b
    p.length = len(b)
    p.quoted = quoted
    if ethertype == ETHERTYPE_IPV4 and len(b) >= IPV4_MIN_HEADER_LEN and b[0] >> 4 == IP_VERSION_4:
        parse_ipv4(p, b, quoted=quoted)
    elif ethertype == ETHERTYPE_IPV6 and len(b) >= IPV6_HEADER_LEN and b[0] >> 4 == IP_VERSION_6:
        parse_ipv6(p, b, quoted=quoted)
    elif ethertype == ETHERTYPE_ARP:
        p.fam = "arp"
        p.l4 = "arp"
        p.payload = b
    else:
        p.fam = f"ethertype-{ethertype:#06x}"
        p.l4 = p.fam
        p.payload = b
    return p


def read_pcap(path: Path) -> Iterator[Pkt]:
    """Yield Pkt for each record of a pcap written by `capture` (or any LINUX_SLL pcap)."""
    with path.open("rb") as f:
        head = f.read(24)
        if len(head) < PCAP_HEADER_LEN:
            return
        magic = struct.unpack("<I", head[:4])[0]
        if magic == PCAP_MAGIC_NS:
            scale = 1e-9
        elif magic == PCAP_MAGIC_US:
            scale = 1e-6
        else:
            msg = f"{path}: not a little-endian pcap"
            raise ValueError(msg)
        linktype = struct.unpack("<I", head[20:24])[0]
        if linktype != LINKTYPE_LINUX_SLL:
            msg = f"{path}: link type {linktype}, expected LINUX_SLL"
            raise ValueError(msg)
        while True:
            rh = f.read(16)
            if len(rh) < PCAP_RECORD_HEADER_LEN:
                return
            sec, frac, incl, _orig = struct.unpack("<IIII", rh)
            rec = f.read(incl)
            if len(rec) < incl or incl < SLL_HEADER_LEN:
                return
            pkttype, _hatype, _halen = struct.unpack(">HHH", rec[:6])
            proto = struct.unpack(">H", rec[14:16])[0]
            p = parse_ip(proto, rec[16:])
            p.t = sec + frac * scale
            p.pkttype = pkttype
            yield p


WG_INITIATION = 1
WG_RESPONSE = 2
WG_COOKIE_REPLY = 3
WG_TRANSPORT = 4
WG_INITIATION_SIZE = 148
WG_RESPONSE_SIZE = 92
WG_COOKIE_REPLY_SIZE = 64
WG_TRANSPORT_MIN_SIZE = 32
WG_HEADER_LEN = 4  # type and three reserved bytes
WG_SENDER_END = 8
WG_RECEIVER_END = 12


def is_wireguard(payload: bytes, size: int | None = None) -> bool:
    """Tell whether `payload` has WireGuard message framing.

    Type 1-4, three zero reserved bytes, the type's size (handshake initiation 148, response 92,
    cookie reply 64; transport data at least 32: header, receiver index, counter, tag — its
    padding stops at the MTU, so no alignment rule holds for full-size packets). `size`: the
    message's real size when `payload` is a truncated copy (quoted in an ICMP error, from the
    quoted UDP header's length field).
    """
    if len(payload) < WG_HEADER_LEN or payload[1:4] != b"\0\0\0":
        return False
    kind, n = payload[0], len(payload) if size is None else size
    if kind == WG_INITIATION:
        return n == WG_INITIATION_SIZE
    if kind == WG_RESPONSE:
        return n == WG_RESPONSE_SIZE
    if kind == WG_COOKIE_REPLY:
        return n == WG_COOKIE_REPLY_SIZE
    if kind == WG_TRANSPORT:
        return n >= WG_TRANSPORT_MIN_SIZE
    return False


class WgSessions:
    """Session indices announced in the handshakes of one capture.

    Framing alone is four bytes; a cookie reply or transport message must also name a receiver
    index that a handshake message in the same capture announced (the captures start before the
    product does).
    """

    def __init__(self) -> None:
        """Start with no known session."""
        self.indices: set[bytes] = set()

    def classify(self, payload: bytes, size: int | None = None) -> str:
        """Classify one UDP payload on a WireGuard port."""
        if not is_wireguard(payload, size) or len(payload) < WG_SENDER_END:
            return "wireguard_malformed"
        kind = payload[0]
        if kind == WG_INITIATION:
            self.indices.add(payload[4:8])
            return "wireguard"
        if kind == WG_RESPONSE:
            self.indices.add(payload[4:8])
            known = len(payload) >= WG_RECEIVER_END and payload[8:12] in self.indices
            return "wireguard" if known else "wireguard_unknown_session"
        return "wireguard" if payload[4:8] in self.indices else "wireguard_unknown_session"


# --------------------------------------------------------------------------------------------
# Classification
# --------------------------------------------------------------------------------------------

LOOPBACK4 = ipaddress.ip_network("127.0.0.0/8")
LINK_LOCAL6 = ipaddress.ip_network("fe80::/10")

# Allowed (True), listed but not counted ("listed"), or a violation (False).
OK, LISTED, BAD = True, "listed", False

DNS_PORT = 53
HTTP_PORT = 80
DISCARD_PORT = 9
TCP_SYN = 0x02


class Context:
    """What the run says about its own ports and addresses (from meta.json and events)."""

    def __init__(self, meta: JsonObj, events: list[JsonObj]) -> None:
        """Read the ports, addresses and tokens of the run."""
        self.api_ports: set[int] = set(meta["api_ports"])
        self.gateway_ports: set[int] = set(meta["gateway_ports"])
        self.labpeer_api_ports: set[int] = set(meta["labpeer_api_ports"])
        self.wg_ports: set[int] = set(meta["wg_ports"])
        self.tunnel_addrs: set[str] = set(meta["tunnel_addresses"])
        self.relay_ports: set[int] = set()
        for e in events:
            if e.get("kind") == "relay":
                self.relay_ports.add(int(e["addr"].rsplit(":", 1)[1]))
            if e.get("kind") == "gateway_port":
                self.gateway_ports.add(int(e["port"]))
        self.token: bytes = meta["token"].encode()
        self.control_token: bytes = meta["control_token"].encode()
        self.wg = WgSessions()


def is_loopback(addr: str) -> bool:
    """Tell whether `addr` is a loopback address (False when it is no address)."""
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return False
    return ip.is_loopback


def classify_lo_udp(p: Pkt, ports: set[int | None], ctx: Context) -> tuple[str, Verdict]:
    """Classify a UDP packet on loopback."""
    if ports & ctx.wg_ports:
        size = p.ulen - UDP_HEADER_LEN if p.quoted and p.ulen else None
        cls = ctx.wg.classify(p.payload, size)
        return cls, (OK if cls == "wireguard" else BAD)
    if DNS_PORT in ports:
        return "plaintext_dns", BAD
    if ports & ctx.relay_ports:
        return "socks5_udp_relay", OK
    return "unexpected_local_udp", BAD


def classify_lo_tcp(ports: set[int | None], ctx: Context) -> tuple[str, Verdict]:
    """Classify a TCP packet on loopback by its ports."""
    if DNS_PORT in ports:
        return "plaintext_dns", BAD
    if ports & ctx.api_ports:
        return "api", OK
    if ports & ctx.gateway_ports:
        return "gateway", OK
    if ports & ctx.labpeer_api_ports:
        return "labpeer_api", OK
    return "unexpected_local_tcp", BAD


def classify_lo(p: Pkt, ctx: Context) -> tuple[str, Verdict]:
    """Classify a packet captured on loopback."""
    if p.fam not in ("ipv4", "ipv6"):
        return "non_ip", BAD
    if not (is_loopback(p.src) and is_loopback(p.dst)):
        return "non_loopback_address", BAD
    ports = {p.sport, p.dport}
    if p.l4 == "udp":
        return classify_lo_udp(p, ports, ctx)
    if p.l4 == "tcp":
        return classify_lo_tcp(ports, ctx)
    if p.l4 in ("icmp", "icmp6") and p.inner is not None:
        cls, ok = classify_lo(p.inner, ctx)
        return ("icmp_error_about_" + cls, OK) if ok is OK else ("icmp_error_about_" + cls, BAD)
    return "unexpected_local_" + p.l4, BAD


def classify_nic(p: Pkt, _ctx: Context) -> tuple[str, Verdict]:
    """Classify a packet captured on the host NIC."""
    if p.l4 == "icmp6" and p.icmp_type in ND_MLD_TYPES:
        src = ipaddress.ip_address(p.src)
        if src.is_unspecified or src in LINK_LOCAL6:
            return "kernel_nd_mld", LISTED
    return "leaves_host_nic", BAD


def classify_vpn0(p: Pkt, ctx: Context) -> tuple[str, Verdict]:
    """Classify a packet captured on a sandbox's tunnel device."""
    if p.src in ctx.tunnel_addrs or p.dst in ctx.tunnel_addrs:
        return "in_tunnel", OK
    if p.l4 == "icmp6" and p.icmp_type in ND_MLD_TYPES:
        return "sandbox_kernel_nd_mld", LISTED
    # The worker drops what does not come from the tunnel address: not a leak, but listed.
    return "in_sandbox_not_tunnel_address", LISTED


ROLE_CLASSIFIERS: dict[str, Callable[[Pkt, Context], tuple[str, Verdict]]] = {
    "lo": classify_lo,
    "nic": classify_nic,
    "vpn0": classify_vpn0,
}

# Where the run's payload markers may appear: client <-> local proxy plaintext on loopback (and
# the kernel's ICMP errors quoting such a packet, e.g. a relayed datagram for a client socket that
# has closed), and inside the tunnel (the sandbox's TUN device). Anywhere else is a leak.
MARKER_ALLOWED = {("lo", "gateway"), ("lo", "socks5_udp_relay")}


def marker_allowed(role: str, cls: str) -> bool:
    """Tell whether a payload marker may appear in this class of packet on this capture."""
    if role == "vpn0":
        return True
    cls = cls.removeprefix("icmp_error_about_")
    return (role, cls) in MARKER_ALLOWED


# --------------------------------------------------------------------------------------------
# Controls: traffic the harness sends on purpose, to prove the captures see what they must
# --------------------------------------------------------------------------------------------

CONTROL_TCP_DST = "192.0.2.80"

CONTROL_SPECS: list[tuple[str, str, str, Callable[[Pkt, Context], object]]] = [
    # Control id, capture role, description, predicate on the packet.
    (
        "system_resolver_query",
        "nic",
        "system resolver query to 192.0.2.53:53 (getent)",
        lambda p, c: (
            p.l4 == "udp"
            and p.dst == "192.0.2.53"
            and p.dport == DNS_PORT
            and c.control_token in p.payload
        ),
    ),
    (
        "direct_tcp_v4",
        "nic",
        "direct TCP SYN to 192.0.2.80:80",
        lambda p, _c: (
            p.l4 == "tcp"
            and p.dst == CONTROL_TCP_DST
            and p.dport == HTTP_PORT
            and p.flags & TCP_SYN
        ),
    ),
    (
        "direct_udp_v4",
        "nic",
        "direct UDP to 192.0.2.80:9",
        lambda p, c: p.l4 == "udp" and p.dst == CONTROL_TCP_DST and c.control_token in p.payload,
    ),
    (
        "direct_udp_v6",
        "nic",
        "direct UDP to [2001:db8:2::80]:9",
        lambda p, c: p.l4 == "udp" and p.dst == "2001:db8:2::80" and c.control_token in p.payload,
    ),
    (
        "loopback_dns",
        "lo",
        "plaintext UDP to 127.0.0.1:53 flagged",
        lambda p, c: p.l4 == "udp" and p.dport == DNS_PORT and c.control_token in p.payload,
    ),
    (
        "loopback_unknown_port",
        "lo",
        "UDP to an unknown loopback port flagged",
        lambda p, c: p.l4 == "udp" and p.dport == DISCARD_PORT and c.control_token in p.payload,
    ),
]


# --------------------------------------------------------------------------------------------
# Analysis
# --------------------------------------------------------------------------------------------

AC_SCENARIOS = {
    "AC-16": ["a_baseline", "b_strict"],
    "AC-20": ["a_baseline", "b_strict", "e_v6_block"],
    "AC-26": ["c_fault_gateway", "c_fault_strict"],
    "AC-31": ["d_dns_down_gateway", "d_dns_down_strict"],
    "AC-70": ["f_host_state"],
}

BETWEEN = "(between scenarios)"
REPORT_DETAIL_MAX = 300


def load_events(path: Path) -> list[JsonObj]:
    """Read events.jsonl (an absent file is no events)."""
    events = []
    if path.exists():
        with path.open() as f:
            for line in f:
                stripped = line.strip()
                if stripped:
                    events.append(json.loads(stripped))
    return events


def scenario_windows(events: list[JsonObj]) -> list[Window]:
    """[(name, begin, end, info)] in order; an unterminated scenario ends at the last event."""
    wins: list[Window] = []
    open_: dict[str, JsonObj] = {}
    last_t = max((e["t"] for e in events), default=0.0)
    for e in events:
        if e.get("kind") != "scenario":
            continue
        if e["phase"] == "begin":
            open_[e["name"]] = e
        elif e["phase"] == "end" and e["name"] in open_:
            b = open_.pop(e["name"])
            wins.append((e["name"], b["t"], e["t"], b))
    wins.extend((name, b["t"], last_t, b) for name, b in open_.items())
    wins.sort(key=lambda w: w[1])
    return wins


def window_of(t: float, wins: list[Window]) -> str:
    """Return the scenario whose window holds time `t`."""
    for name, b, e, _ in wins:
        if b <= t <= e:
            return name
    return BETWEEN


class Flow(TypedDict):
    """One flow of a capture, as written to flows-<capture>.json."""

    proto: str
    src: str
    dst: str
    sport: int | None
    dport: int | None
    packets: int
    bytes: int
    first: float
    last: float
    classes: dict[str, int]
    scenarios: dict[str, int]


class Tally:
    """Counts of every capture, by role, scenario and class."""

    def __init__(self) -> None:
        """Start with nothing counted."""
        self.classes: dict[tuple[str, str, str], int] = {}  # (role, scenario, cls) -> count
        # (role, scenario) -> {flow description: count}
        self.bad: dict[tuple[str, str], dict[str, int]] = {}
        self.listed: dict[tuple[str, str], dict[str, int]] = {}
        self.markers_bad: dict[str, list[str]] = {}  # scenario -> [descriptions]
        self.markers_seen: dict[tuple[str, str], int] = {}  # (role, scenario) -> count
        self.controls: dict[tuple[str, str], int] = {}  # (scenario, control id) -> count
        # (role, scenario, ipv4|ipv6|...) -> count
        self.families: dict[tuple[str, str, str], int] = {}
        self.flows: dict[str, dict[FlowKey, Flow]] = {}  # capture name -> {key: {...}}

    def add_flow(self, cap: str, p: Pkt, cls: str, scen: str) -> None:
        """Count `p` in its flow of capture `cap`."""
        flows = self.flows.setdefault(cap, {})
        k = p.key()
        f = flows.get(k)
        if f is None:
            f = flows[k] = {
                "proto": p.l4,
                "src": p.src,
                "dst": p.dst,
                "sport": p.sport,
                "dport": p.dport,
                "packets": 0,
                "bytes": 0,
                "first": p.t,
                "last": p.t,
                "classes": {},
                "scenarios": {},
            }
        f["packets"] += 1
        f["bytes"] += p.length
        f["last"] = p.t
        f["classes"][cls] = f["classes"].get(cls, 0) + 1
        f["scenarios"][scen] = f["scenarios"].get(scen, 0) + 1


class CaptureRef(NamedTuple):
    """One capture file and the role of its interface."""

    name: str
    role: str
    path: Path


class CaptureAnalysis:
    """Classification of the packets of one capture into a Tally."""

    def __init__(self, cap: CaptureRef, ctx: Context, wins: list[Window], tally: Tally) -> None:
        """Prepare to analyze `cap`."""
        self.cap = cap
        self.ctx = ctx
        self.wins = wins
        self.tally = tally
        self.classify = ROLE_CLASSIFIERS[cap.role]
        self.control_windows = {w[0] for w in wins if w[0].startswith("control")}

    def run(self) -> int:
        """Classify every packet of the capture; returns how many were read."""
        self.ctx.wg = WgSessions()
        n = 0
        for p in read_pcap(self.cap.path):
            n += 1
            scen = window_of(p.t, self.wins)
            cls, ok = self.classify(p, self.ctx)
            if scen in self.control_windows:
                cls, ok = self.control(p, scen, cls, ok)
            self.record(p, scen, cls, ok)
        return n

    def control(self, p: Pkt, scen: str, cls: str, ok: Verdict) -> tuple[str, Verdict]:
        """Reclassify a packet of a control window that is the harness's own control traffic."""
        # The harness's own control traffic: recorded as such, never as product traffic.
        # An ICMP error the kernel returns about a control packet (no listener on the
        # loopback port) belongs to that control packet.
        role, ctx = self.cap.role, self.ctx
        target = p.inner if p.inner is not None else p
        if not (
            ctx.control_token in p.raw
            or (role == "nic" and target.l4 == "tcp" and target.dst == CONTROL_TCP_DST)
        ):
            return cls, ok
        matched = [
            cid for cid, crole, _d, pred in CONTROL_SPECS if crole == role and pred(target, ctx)
        ]
        if target is p:
            for cid in matched:
                self.tally.controls[scen, cid] = self.tally.controls.get((scen, cid), 0) + 1
        return "control:" + cls, OK if matched else BAD

    def record(self, p: Pkt, scen: str, cls: str, ok: Verdict) -> None:
        """Count one classified packet."""
        tally, name, role = self.tally, self.cap.name, self.cap.role
        key = (role, scen, cls)
        tally.classes[key] = tally.classes.get(key, 0) + 1
        fkey = (role, scen, p.fam)
        tally.families[fkey] = tally.families.get(fkey, 0) + 1
        tally.add_flow(name, p, cls, scen)
        desc = p.describe()
        if ok is BAD:
            d = tally.bad.setdefault((role, scen), {})
            d[f"[{name}] {cls}: {desc}"] = d.get(f"[{name}] {cls}: {desc}", 0) + 1
        elif ok is LISTED:
            d = tally.listed.setdefault((role, scen), {})
            d[f"[{name}] {cls}: {desc}"] = d.get(f"[{name}] {cls}: {desc}", 0) + 1
        if self.ctx.token in p.raw:
            mk = (role, scen)
            tally.markers_seen[mk] = tally.markers_seen.get(mk, 0) + 1
            if not marker_allowed(role, cls):
                tally.markers_bad.setdefault(scen, []).append(f"[{name}] {cls}: {desc}")


def snapshot_diff(first: Path, other: Path, names: tuple[str, str]) -> list[str]:
    """Return the unified diff (no context) of two snapshot files."""
    a, b = first.read_text().splitlines(), other.read_text().splitlines()
    return list(difflib.unified_diff(a, b, names[0], names[1], lineterm="", n=0))


def snapshot_check(out: Path) -> list[JsonObj]:
    """AC-70: compare the snapshots.

    Every snapshot of the harness's network namespace equals the first; the host's after-snapshot
    equals its before-snapshot.
    """
    checks: list[JsonObj] = []
    snaps = sorted((out / "snapshots").glob("netns-*.txt"))
    if snaps:
        first = snaps[0]
        for s in snaps[1:]:
            diff = snapshot_diff(first, s, (first.name, s.name))
            checks.append(
                {
                    "name": f"{first.name} == {s.name}",
                    "ok": not diff,
                    "detail": {"diff": diff[:60]},
                }
            )
    else:
        checks.append({"name": "netns snapshots present", "ok": False, "detail": {}})
    before = out / "snapshots" / "host-before.txt"
    after = out / "snapshots" / "host-after.txt"
    if before.exists() and after.exists():
        diff = snapshot_diff(before, after, ("host-before", "host-after"))
        checks.append(
            {"name": "host-before == host-after", "ok": not diff, "detail": {"diff": diff[:60]}}
        )
    else:
        checks.append({"name": "host snapshots present", "ok": False, "detail": {}})
    return checks


def capture_integrity(st: JsonObj, role: str, n: int, wins: list[Window]) -> list[JsonObj]:
    """Integrity checks of one capture: no drops, no truncation, full coverage of the run."""
    name = st["name"]
    checks: list[JsonObj] = [
        {
            "name": f"{name}: no kernel drops",
            "ok": st["kernel_drops"] == 0,
            "detail": {"drops": st["kernel_drops"], "kernel_packets": st["kernel_packets"]},
        },
        {
            "name": f"{name}: no truncated packets",
            "ok": st["truncated"] == 0,
            "detail": {"truncated": st["truncated"]},
        },
        {
            "name": f"{name}: every packet parsed into the pcap",
            "ok": n == st["packets_written"],
            "detail": {"read": n, "written": st["packets_written"]},
        },
    ]
    if role != "vpn0":
        # The host-side captures must cover the whole run.
        first = wins[0][1] if wins else 0
        last = wins[-1][2] if wins else 0
        covered = st["started"] < first and st["stopped"] > last and not st.get("error")
        checks.append(
            {
                "name": f"{name}: recorded from before the first scenario to after the last",
                "ok": covered,
                "detail": {
                    "started": st["started"],
                    "stopped": st["stopped"],
                    "error": st.get("error"),
                },
            }
        )
    return checks


def analyze_captures(
    out: Path, ctx: Context, wins: list[Window], tally: Tally
) -> tuple[list[JsonObj], list[JsonObj]]:
    """Analyze every capture of the run; returns (captures, integrity checks)."""
    integrity: list[JsonObj] = []
    captures: list[JsonObj] = []
    for stats_path in sorted((out / "captures").glob("*.stats.json")):
        st = json.loads(stats_path.read_text())
        name = st["name"]
        role = "lo" if name == "lo" else "nic" if name == "nic" else "vpn0"
        pcap = out / "captures" / st["pcap"]
        n = CaptureAnalysis(CaptureRef(name, role, pcap), ctx, wins, tally).run()
        captures.append(
            {
                "name": name,
                "role": role,
                "iface": st["iface"],
                "pcap": str(pcap),
                "packets": n,
                "stats": st,
            }
        )
        integrity.extend(capture_integrity(st, role, n, wins))
    return captures, integrity


def scenario_counts(tally: Tally, name: str) -> dict[str, dict[str, int]]:
    """Return the class counts of one scenario, by role."""
    counts: dict[str, dict[str, int]] = {}
    for (role, scen, cls), cnt in tally.classes.items():
        if scen == name:
            counts.setdefault(role, {})[cls] = cnt
    return counts


def expected_checks(r: JsonObj, expect: list[str], tally: Tally) -> list[JsonObj]:
    """Return the checks a scenario asks for in its `expect` list."""
    name = r["scenario"]
    checks: list[JsonObj] = []
    if "wireguard" in expect:
        checks.append(
            {
                "name": "WireGuard packets on lo during the scenario",
                "ok": r["lo_wireguard"] > 0,
                "detail": {"packets": r["lo_wireguard"]},
            }
        )
    if "vpn0_markers" in expect:
        checks.append(
            {
                "name": "payload markers seen inside the tunnel (sandbox vpn0)",
                "ok": r["markers_seen"]["vpn0"] > 0,
                "detail": {"packets": r["markers_seen"]["vpn0"]},
            }
        )
    if "vpn0_ipv4_only" in expect:
        v4 = tally.families.get(("vpn0", name, "ipv4"), 0)
        v6 = tally.families.get(("vpn0", name, "ipv6"), 0)
        checks.append(
            {
                "name": "IPv4-only sandbox: traffic on its vpn0, none of it IPv6",
                "ok": v4 > 0 and v6 == 0,
                "detail": {"ipv4": v4, "ipv6": v6},
            }
        )
    return checks


def control_checks(name: str, bad: dict[str, list[tuple[str, int]]], tally: Tally) -> list[JsonObj]:
    """Return the checks of a control window: every control seen, nothing else on nic and lo."""
    checks: list[JsonObj] = []
    for cid, _role, desc, _pred in CONTROL_SPECS:
        seen = tally.controls.get((name, cid), 0)
        checks.append(
            {"name": f"control seen: {desc}", "ok": seen > 0, "detail": {"packets": seen}}
        )
    # In a control window everything on the NIC and lo must be control traffic.
    for role in ("nic", "lo"):
        items = bad.get(role, [])
        checks.append(
            {
                "name": f"control window: nothing on {role} but the controls",
                "ok": not items,
                "detail": {"examples": items[:5]},
            }
        )
    return checks


def product_checks(r: JsonObj, tally: Tally) -> list[JsonObj]:
    """Return the leak checks of a scenario window."""
    return [
        {
            "name": "no packet attributable to the product on the host NIC",
            "ok": r["nic_product_packets"] == 0,
            "detail": {"packets": r["nic_product_packets"]},
        },
        {
            "name": "loopback carries only WireGuard and the product's local ports",
            "ok": r["lo_violations"] == 0,
            "detail": {"packets": r["lo_violations"]},
        },
        {
            "name": "payload markers only on client<->proxy loopback or in the tunnel",
            "ok": not r["markers_outside_allowed"],
            "detail": {"count": len(tally.markers_bad.get(r["scenario"], []))},
        },
    ]


def scenario_result(win: Window, tally: Tally, recorded_checks: list[JsonObj]) -> JsonObj:
    """Return the result of one scenario window."""
    name, b, e_t, info = win
    r: JsonObj = {
        "scenario": name,
        "title": info.get("title", ""),
        "begin": b,
        "end": e_t,
        "seconds": round(e_t - b, 1),
    }
    counts = scenario_counts(tally, name)
    r["counts"] = counts
    bad: dict[str, list[tuple[str, int]]] = {}
    for role in ("nic", "lo", "vpn0"):
        items = tally.bad.get((role, name), {})
        if items:
            bad[role] = sorted(items.items(), key=lambda kv: -kv[1])[:40]
    r["violations"] = bad
    r["listed"] = {
        role: sorted(tally.listed.get((role, name), {}).items(), key=lambda kv: -kv[1])[:20]
        for role in ("nic", "lo", "vpn0")
        if tally.listed.get((role, name))
    }
    r["markers_outside_allowed"] = tally.markers_bad.get(name, [])[:40]
    r["markers_seen"] = {
        role: tally.markers_seen.get((role, name), 0) for role in ("lo", "nic", "vpn0")
    }
    nic = counts.get("nic", {})
    lo = counts.get("lo", {})
    r["nic_product_packets"] = sum(v for k, v in nic.items() if k == "leaves_host_nic")
    r["nic_kernel_nd_mld"] = nic.get("kernel_nd_mld", 0)
    r["lo_wireguard"] = lo.get("wireguard", 0)
    r["lo_violations"] = sum(tally.bad.get(("lo", name), {}).values())
    checks = list(recorded_checks)
    checks.extend(expected_checks(r, info.get("expect", []), tally))
    if name.startswith("control"):
        checks.extend(control_checks(name, bad, tally))
    else:
        checks.extend(product_checks(r, tally))
    r["checks"] = checks
    # Observations are product behaviour worth reporting; they are not part of the verdict.
    r["ok"] = all(c["ok"] for c in checks if not c.get("observation"))
    return r


def between_result(tally: Tally) -> JsonObj:
    """Return the result of the gaps between scenario windows."""
    # Packets outside every window (stack start-up is a window; this is the gap between them).
    between: JsonObj = {"scenario": BETWEEN, "counts": {}, "checks": []}
    for (role, scen, cls), cnt in tally.classes.items():
        if scen == BETWEEN:
            between["counts"].setdefault(role, {})[cls] = cnt
    bv = sum(sum(v for v in tally.bad.get((role, BETWEEN), {}).values()) for role in ("nic", "lo"))
    examples = sorted(
        [*tally.bad.get(("nic", BETWEEN), {}).items(), *tally.bad.get(("lo", BETWEEN), {}).items()],
        key=lambda kv: -kv[1],
    )[:10]
    between["checks"].append(
        {
            "name": "no violation between scenario windows",
            "ok": bv == 0,
            "detail": {"examples": examples},
        }
    )
    between["ok"] = bv == 0 and not tally.markers_bad.get(BETWEEN)
    stray = tally.markers_bad.get(BETWEEN)
    if stray:
        between["checks"].append(
            {
                "name": "no payload markers outside allowed places",
                "ok": False,
                "detail": {"examples": stray[:5]},
            }
        )
    return between


def acceptance(all_results: list[JsonObj], *, integrity_ok: bool) -> JsonObj:
    """Return the verdict per acceptance criterion."""
    by_name = {r["scenario"]: r for r in all_results}
    ac: JsonObj = {}
    controls_ok = all(by_name.get(c, {}).get("ok", False) for c in ("control_pre", "control_post"))
    for acid, names in AC_SCENARIOS.items():
        parts = [by_name.get(n) for n in names]
        ok = all(p is not None and p["ok"] for p in parts) and integrity_ok and controls_ok
        ac[acid] = {
            "ok": ok,
            "scenarios": {n: (by_name[n]["ok"] if n in by_name else None) for n in names},
        }
    return ac


def cmd_analyze(a: argparse.Namespace) -> int:
    """Run the `analyze` subcommand."""
    out = Path(a.out)
    res = out / "results"
    meta = json.loads((res / "meta.json").read_text())
    events = load_events(res / "events.jsonl")
    ctx = Context(meta, events)
    wins = scenario_windows(events)
    tally = Tally()
    captures, integrity = analyze_captures(out, ctx, wins, tally)
    integrity.extend(
        {
            "name": f"NIC device {e.get('dev')}: no transmit drops",
            "ok": e["dropped"] == 0,
            "detail": e,
        }
        for e in events
        if e.get("kind") == "nic_queue_drops"
    )
    have = {c["role"] for c in captures}
    integrity.extend(
        {"name": f"capture of {role} present", "ok": False, "detail": {}}
        for role in ("lo", "nic")
        if role not in have
    )

    checks_by_scen: dict[str, list[JsonObj]] = {}
    for e in events:
        if e.get("kind") == "check":
            checks_by_scen.setdefault(e.get("scenario") or "(none)", []).append(e)

    scen_results = [scenario_result(w, tally, checks_by_scen.get(w[0], [])) for w in wins]
    between = between_result(tally)

    snap = snapshot_check(out)
    f_result = {
        "scenario": "f_host_state",
        "title": "AC-70: host/netns routes, rules, DNS, proxy before/after",
        "checks": snap,
        "ok": all(c["ok"] for c in snap),
    }

    integrity_ok = all(c["ok"] for c in integrity)
    all_results = [*scen_results, f_result]
    ac = acceptance(all_results, integrity_ok=integrity_ok)
    overall = integrity_ok and all(r["ok"] for r in all_results) and between["ok"]

    for cap in tally.flows:
        flows = sorted(tally.flows[cap].values(), key=lambda f: -f["packets"])
        with (res / f"flows-{cap}.json").open("w") as f:
            json.dump(flows, f, indent=1)
    summary = {
        "overall_ok": overall,
        "integrity": integrity,
        "captures": captures,
        "scenarios": all_results,
        "between": between,
        "acceptance": ac,
        "events": len(events),
        "meta": meta,
    }
    with (res / "summary.json").open("w") as f:
        json.dump(summary, f, indent=1, default=str)
    text = render_report(summary, events)
    with (res / "report.txt").open("w") as f:
        f.write(text)
    sys.stdout.write(text)
    return 0 if overall else 1


def fmt_counts(d: dict[str, int]) -> str:
    """Format class counts, largest first."""
    return ", ".join(f"{k}={v}" for k, v in sorted(d.items(), key=lambda kv: -kv[1])) or "-"


def check_tag(c: JsonObj) -> str:
    """Return the report tag of a check."""
    if c.get("observation"):
        return "NOTE" if c["ok"] else "NOTE: does not hold"
    return "PASS" if c["ok"] else "FAIL"


def pass_fail(ok: object) -> str:
    """Return PASS or FAIL."""
    return "PASS" if ok else "FAIL"


TIMELINE_KINDS = {
    "kill",
    "labpeer",
    "route_state",
    "dns_timing",
    "traffic",
    "app_loop",
    "sandbox",
    "instance_action",
    "dns_down_state",
}


def ok_fail_stats(stats: dict[str, JsonObj]) -> str:
    """Format per-target ok/fail counters."""
    return ", ".join(f"{n} ok={v['ok']} fail={v['fail']}" for n, v in stats.items())


EVENT_FORMATS: dict[str, Callable[[JsonObj], str]] = {
    "kill": lambda e: (
        f"SIGKILL {e['target']} pid {e['pid']} (generation {e['generation']}) in phase "
        f"{e['phase']} [{e.get('label', '')}]"
    ),
    "labpeer": lambda e: (
        f"lab peer {e['action']}" + (f" (pids {e.get('pids')})" if e.get("pids") else "")
    ),
    "route_state": lambda e: f"sandbox routes {e['state']}: v4 {e.get('v4')} v6 {e.get('v6')}",
    "dns_timing": lambda e: (
        f"DNS-down {e['round']}: {e['what']} -> {e['outcome']} after {e['seconds']} s"
    ),
    "traffic": lambda e: (
        f"Gateway traffic [{e['label']}] {e['attempts']} attempts: {ok_fail_stats(e['stats'])}"
    ),
    "app_loop": lambda e: f"App traffic in the sandbox: {ok_fail_stats(e['results'])}",
    "sandbox": lambda e: (
        f"sandbox {e['label']}: holder {e.get('holder_pid')} worker {e.get('worker')} "
        f"interfaces {e.get('interfaces')} addresses {e.get('addresses')}"
    ),
    "instance_action": lambda e: f"connection action {e['action']}",
    "dns_down_state": lambda e: f"connection {e['phase']} {e['after']} s after the peer went away",
}


def describe_event(e: JsonObj) -> str:
    """Return a one-line description of a timeline event."""
    fmt = EVENT_FORMATS.get(e["kind"])
    if fmt is not None:
        return fmt(e)
    return json.dumps(e, default=str)[:200]


def report_header(s: JsonObj) -> list[str]:
    """Return the report's header, capture list and integrity checks."""
    meta = s["meta"]
    lines = [
        "=" * 100,
        "VPN Manager leak capture (Linux, rootless) — results",
        (
            f"source: {meta.get('source', '?')}  commit: {meta.get('commit', '?')}  base port: "
            f"{meta.get('base')}  NIC: {meta.get('nic')}"
        ),
        f"output: {meta.get('out')}",
        "=" * 100,
        "",
        "Captures",
    ]
    for c in s["captures"]:
        st = c["stats"]
        lines.append(
            f"  {c['name']:<22} iface={c['iface']:<8} packets={c['packets']:<8} "
            f"kernel_drops={st['kernel_drops']} truncated={st['truncated']} "
            f"redacted_keys={st.get('redacted_keys', 0)}  {c['pcap']}"
        )
    lines += ["", "Capture integrity"]
    lines.extend(
        f"  [{pass_fail(c['ok'])}] {c['name']}  {json.dumps(c['detail'])}" for c in s["integrity"]
    )
    lines.append("")
    return lines


def report_table(s: JsonObj) -> list[str]:
    """Return the report's one-line-per-scenario table."""
    lines = [
        (
            f"{'scenario':<22} {'secs':>5} {'NIC prod':>8} {'NIC nd':>6} {'lo WG':>7} "
            f"{'lo bad':>6} {'mk bad':>6} {'vpn0 mk':>7} {'checks':>9}  verdict"
        )
    ]
    for r in s["scenarios"]:
        if r["scenario"] == "f_host_state":
            continue
        checks = [c for c in r["checks"] if not c.get("observation")]
        okc = sum(1 for c in checks if c["ok"])
        lines.append(
            f"{r['scenario']:<22} {r.get('seconds', 0):>5} {r.get('nic_product_packets', 0):>8} "
            f"{r.get('nic_kernel_nd_mld', 0):>6} {r.get('lo_wireguard', 0):>7} "
            f"{r.get('lo_violations', 0):>6} {len(r.get('markers_outside_allowed', [])):>6} "
            f"{r.get('markers_seen', {}).get('vpn0', 0):>7} {okc:>4}/{len(checks):<4}  "
            f"{pass_fail(r['ok'])}"
        )
    f = next(r for r in s["scenarios"] if r["scenario"] == "f_host_state")
    lines.append(
        f"{'f_host_state':<22} {'':>5} {'':>8} {'':>6} {'':>7} {'':>6} {'':>6} {'':>7} "
        f"{sum(1 for c in f['checks'] if c['ok']):>4}/{len(f['checks']):<4}  "
        f"{pass_fail(f['ok'])}"
    )
    lines.append(
        f"{BETWEEN:<22} lo/nic: {fmt_counts(s['between']['counts'].get('lo', {}))} | "
        f"{fmt_counts(s['between']['counts'].get('nic', {}))}  "
        f"{pass_fail(s['between']['ok'])}"
    )
    lines += [
        "",
        (
            "Columns: NIC prod = packets on the host NIC attributable to the product (must be 0); "
            "NIC nd = kernel ND/MLD/RS (listed, not counted); lo WG = WireGuard packets on lo "
            "(framing and session index checked); lo bad = loopback packets that are neither "
            "WireGuard nor the product's local ports; mk bad = payload markers outside "
            "client<->proxy loopback; vpn0 mk = marker packets inside the sandbox tunnel device; "
            "checks exclude observations."
        ),
        "",
    ]
    return lines


def report_scenario(r: JsonObj, timeline: list[JsonObj]) -> list[str]:
    """Return the report's section of one scenario."""
    lines = ["-" * 100, f"{r['scenario']}: {r.get('title', '')}  [{pass_fail(r['ok'])}]"]
    lines.extend(
        f"  {role:<5} {fmt_counts(cnts)}" for role, cnts in sorted(r.get("counts", {}).items())
    )
    t0 = r.get("begin", 0)
    lines.extend(f"  t+{e['t'] - t0:7.2f}s {describe_event(e)}" for e in timeline)
    for role, items in r.get("violations", {}).items():
        lines.append(f"  VIOLATIONS on {role}:")
        lines.extend(f"    {cnt:>6} x {desc}" for desc, cnt in items[:15])
    for role, items in r.get("listed", {}).items():
        lines.append(f"  listed (not counted) on {role}:")
        lines.extend(f"    {cnt:>6} x {desc}" for desc, cnt in items[:10])
    lines.extend(
        f"  MARKER OUTSIDE ALLOWED PLACES: {m}" for m in r.get("markers_outside_allowed", [])[:10]
    )
    for c in r["checks"]:
        detail = c.get("detail", {})
        text = json.dumps(detail, ensure_ascii=False, default=str)
        if len(text) > REPORT_DETAIL_MAX:
            text = text[:297] + "..."
        lines.append(f"  [{check_tag(c)}] {c['name']}  {text}")
    return lines


def report_tail(s: JsonObj) -> list[str]:
    """Return the report's observations, acceptance criteria and overall verdict."""
    lines = ["-" * 100, "Product observations (reported, not part of the leak verdict)"]
    for r in s["scenarios"]:
        for c in r["checks"]:
            if c.get("observation"):
                text = json.dumps(c.get("detail", {}), ensure_ascii=False, default=str)
                lines.append(f"  [{check_tag(c)}] {r['scenario']}: {c['name']}  {text[:700]}")
    lines += ["-" * 100, "Acceptance criteria"]
    for acid, v in s["acceptance"].items():
        parts = ", ".join(
            f"{n}={'PASS' if ok else 'FAIL' if ok is False else 'missing'}"
            for n, ok in v["scenarios"].items()
        )
        lines.append(
            f"  {acid}: {pass_fail(v['ok'])}  ({parts}; plus capture integrity and controls)"
        )
    lines += ["", f"OVERALL: {pass_fail(s['overall_ok'])}", ""]
    return lines


def render_report(s: JsonObj, events: list[JsonObj]) -> str:
    """Render report.txt from the summary and the events."""
    lines = report_header(s) + report_table(s)
    timeline: dict[str, list[JsonObj]] = {}
    for e in events:
        if e.get("kind") in TIMELINE_KINDS and e.get("scenario"):
            timeline.setdefault(e["scenario"], []).append(e)
    for r in s["scenarios"]:
        lines += report_scenario(r, timeline.get(r["scenario"], []))
    lines += report_tail(s)
    return "\n".join(lines) + "\n"


def main() -> int:
    """Parse the command line and run the subcommand."""
    ap = argparse.ArgumentParser(description=HELP, formatter_class=argparse.RawTextHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("capture")
    c.add_argument("--iface", required=True)
    c.add_argument("--name", required=True)
    c.add_argument("--dir", required=True)
    c.add_argument("--skip-outgoing", action="store_true")
    c.add_argument("--tun-nic", action="store_true")
    c.add_argument("--ring-mb", type=int, default=64, help="capture ring size (MiB)")
    an = sub.add_parser("analyze")
    an.add_argument("--out", required=True)
    a = ap.parse_args()
    if a.cmd == "capture":
        return cmd_capture(a)
    return cmd_analyze(a)


if __name__ == "__main__":
    sys.exit(main())
