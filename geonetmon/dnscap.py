"""Parse DNS responses to learn the hostname an app actually asked for.

The daemon queues outbound DNS responses (UDP source port 53) through the same
NFQUEUE path and feeds their payloads here. We extract A / AAAA answers and
build an IP -> hostname map, so a connection prompt can say "firefox wants to
connect to github.com" on the very first packet instead of guessing via
reverse DNS (which often differs from the name the app used).

Blind spot, same as Little Snitch: DNS-over-HTTPS / DNS-over-TLS is encrypted
on 443/853 and invisible here.

Only the parser touches untrusted packet bytes; it is defensive and pure, so
it is unit-tested directly.
"""

import struct
import socket
import time

_TYPE_A = 1
_TYPE_AAAA = 28
_CLASS_IN = 1


def _read_name(data, offset):
    """Decode a DNS name (with compression pointers). Returns (name, next)."""
    labels = []
    jumped = False
    next_off = offset
    seen = 0
    while True:
        if offset >= len(data):
            break
        length = data[offset]
        if length == 0:
            offset += 1
            if not jumped:
                next_off = offset
            break
        if (length & 0xC0) == 0xC0:               # compression pointer
            if offset + 1 >= len(data):
                break
            pointer = ((length & 0x3F) << 8) | data[offset + 1]
            if not jumped:
                next_off = offset + 2
            offset = pointer
            jumped = True
            seen += 1
            if seen > 128:                        # loop guard
                break
            continue
        offset += 1
        labels.append(data[offset:offset + length].decode("ascii", "replace"))
        offset += length
    return ".".join(labels), next_off


def parse_dns_answers(payload):
    """From a raw DNS message, return (qname, [ip, ...]).

    Returns ("", []) for anything that isn't a parseable response with answers.
    """
    try:
        if len(payload) < 12:
            return "", []
        flags, qd, an = struct.unpack("!HHH", payload[2:8])
        if not (flags & 0x8000):                  # QR bit: must be a response
            return "", []
        if an == 0:
            return "", []
        offset = 12
        qname = ""
        for i in range(qd):
            name, offset = _read_name(payload, offset)
            if i == 0:
                qname = name
            offset += 4                           # qtype + qclass
        ips = []
        for _ in range(an):
            _name, offset = _read_name(payload, offset)
            if offset + 10 > len(payload):
                break
            rtype, rclass, _ttl, rdlen = struct.unpack(
                "!HHIH", payload[offset:offset + 10])
            offset += 10
            rdata = payload[offset:offset + rdlen]
            offset += rdlen
            if rclass != _CLASS_IN:
                continue
            if rtype == _TYPE_A and rdlen == 4:
                ips.append(socket.inet_ntop(socket.AF_INET, rdata))
            elif rtype == _TYPE_AAAA and rdlen == 16:
                ips.append(socket.inet_ntop(socket.AF_INET6, rdata))
        return qname, ips
    except (struct.error, OSError, IndexError, UnicodeDecodeError):
        return "", []


def dns_payload_from_frame(frame):
    """From a raw ethernet frame, return the UDP payload of a source-port-53
    packet, or b"" for anything else. IPv4 and IPv6, no extension headers or
    fragments (the sniffer's kernel BPF filter pre-selects the same shapes,
    so this is a defensive re-check, not the primary filter)."""
    try:
        if len(frame) < 14 + 20:
            return b""
        ethertype = int.from_bytes(frame[12:14], "big")
        off = 14
        if ethertype == 0x0800:                       # IPv4
            ihl = (frame[off] & 0x0F) * 4
            if ihl < 20 or frame[off + 9] != 17:      # protocol UDP
                return b""
            if int.from_bytes(frame[off + 6:off + 8], "big") & 0x1FFF:
                return b""                            # non-first fragment
            udp = off + ihl
        elif ethertype == 0x86DD:                     # IPv6
            if len(frame) < off + 40 or frame[off + 6] != 17:
                return b""                            # next-header UDP only
            udp = off + 40
        else:
            return b""
        if len(frame) < udp + 8:
            return b""
        if int.from_bytes(frame[udp:udp + 2], "big") != 53:
            return b""
        return bytes(frame[udp + 8:])
    except (IndexError, ValueError):
        return b""


class DNSCache:
    """IP -> (hostname, expiry). Most recent answer wins. Size-capped so a
    flood of forged responses can't balloon daemon memory."""

    def __init__(self, ttl=900, max_entries=4096):
        self.ttl = ttl
        self.max_entries = max_entries
        self._map = {}

    def ingest(self, payload):
        qname, ips = parse_dns_answers(payload)
        if not qname or not ips:
            return None
        now = time.time()
        for ip in ips:
            self._map[ip] = (qname, now + self.ttl)
        if len(self._map) > self.max_entries:
            self.prune()
            while len(self._map) > self.max_entries:   # still over: drop oldest
                oldest = min(self._map, key=lambda k: self._map[k][1])
                del self._map[oldest]
        return qname, ips

    def hostname(self, ip):
        entry = self._map.get(ip)
        if not entry:
            return ""
        name, expiry = entry
        if expiry < time.time():
            self._map.pop(ip, None)
            return ""
        return name

    def prune(self):
        now = time.time()
        for ip in [k for k, (_n, e) in self._map.items() if e < now]:
            self._map.pop(ip, None)

    def snapshot(self):
        """Fresh {ip: hostname} dict (expired entries dropped) for the GUI."""
        self.prune()
        return {ip: name for ip, (name, _e) in self._map.items()}
