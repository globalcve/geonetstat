"""Passive DNS response sniffer (daemon-side, root).

Opens a receive-only AF_PACKET socket with a kernel BPF filter for
"udp and src port 53" attached, so only DNS response packets ever reach
Python — bulk traffic is filtered in the kernel. Sees every interface
including loopback, which is what makes local resolvers (dnscrypt-proxy,
systemd-resolved stubs) visible: the app <-> 127.0.0.1:53 leg is plaintext
even when the resolver's upstream is encrypted.

This is completely independent of enforcement: it never installs firewall
rules and never verdicts a packet. It feeds the same DNSCache the
enforcement engine uses, and the daemon serves the ip->hostname map to the
GUI over the existing group-gated Unix socket (no file is written).

Known blind spot: interfaces without ethernet framing (tun VPNs) — the BPF
offsets assume an ethernet header, so DNS routed through a tun device is
simply not matched.
"""

import ctypes
import socket
import struct
import threading

from .dnscap import dns_payload_from_frame

_ETH_P_ALL = 0x0003
_SO_ATTACH_FILTER = 26

# tcpdump -y EN10MB -dd "udp and src port 53"
# (IPv4 with fragment check + IPv6, ethernet linktype)
_BPF_FILTER = [
    (0x28, 0, 0, 0x0000000c),
    (0x15, 0, 7, 0x00000800),
    (0x30, 0, 0, 0x00000017),
    (0x15, 0, 11, 0x00000011),
    (0x28, 0, 0, 0x00000014),
    (0x45, 9, 0, 0x00001fff),
    (0xb1, 0, 0, 0x0000000e),
    (0x48, 0, 0, 0x0000000e),
    (0x15, 5, 6, 0x00000035),
    (0x15, 0, 5, 0x000086dd),
    (0x30, 0, 0, 0x00000014),
    (0x15, 0, 3, 0x00000011),
    (0x28, 0, 0, 0x00000036),
    (0x15, 0, 1, 0x00000035),
    (0x06, 0, 0, 0x00040000),
    (0x06, 0, 0, 0x00000000),
]


class DNSSniffer:
    """Feed sniffed DNS responses into a DNSCache. start() needs root."""

    def __init__(self, dnscache):
        self.dns = dnscache
        self._sock = None
        self._thread = None
        self._running = False
        self._bpf_buf = None      # must outlive the socket (kernel reads it)

    @property
    def running(self):
        return self._running

    def start(self):
        if self._running:
            return True
        try:
            s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                              socket.htons(_ETH_P_ALL))
            prog = b"".join(struct.pack("HBBI", *ins) for ins in _BPF_FILTER)
            self._bpf_buf = ctypes.create_string_buffer(prog)
            fprog = struct.pack("HL", len(_BPF_FILTER),
                                ctypes.addressof(self._bpf_buf))
            s.setsockopt(socket.SOL_SOCKET, _SO_ATTACH_FILTER, fprog)
            # Drain anything queued between socket creation and filter attach.
            s.setblocking(False)
            try:
                while True:
                    s.recv(65535)
            except (BlockingIOError, OSError):
                pass
            s.settimeout(1.0)     # so stop() is honoured promptly
        except (OSError, AttributeError):
            # No AF_PACKET / no CAP_NET_RAW — degrade silently.
            return False
        self._sock = s
        self._running = True
        self._thread = threading.Thread(target=self._loop, daemon=True,
                                        name="dns-sniffer")
        self._thread.start()
        return True

    def _loop(self):
        while self._running:
            try:
                frame = self._sock.recv(65535)
            except socket.timeout:
                continue
            except OSError:
                break
            # Crash barrier: a malformed packet must never kill the thread.
            try:
                payload = dns_payload_from_frame(frame)
                if payload:
                    self.dns.ingest(payload)
            except Exception:  # noqa: BLE001
                pass

    def stop(self):
        self._running = False
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None
