"""Map a connection (proto, local ip:port) to the owning process via /proc.

This is the same technique OpenSnitch's "procmon" fallback uses: read
``/proc/net/{tcp,tcp6,udp,udp6}`` to find the socket inode for a local
endpoint, then scan ``/proc/[pid]/fd`` for a symlink to ``socket:[inode]``.
Results are cached briefly so an interactive prompt doesn't rescan every fd
on the system per packet. It is best-effort: very short-lived sockets can be
gone before we look, in which case the process is reported as unknown.
"""

import glob
import os
import socket
import struct
import time

_PROTO_FILES = {
    "tcp": ["/proc/net/tcp", "/proc/net/tcp6"],
    "udp": ["/proc/net/udp", "/proc/net/udp6"],
}


def _hex_to_ip(h):
    """Convert a /proc/net hex address to a printable IP."""
    try:
        if len(h) == 8:                       # IPv4, little-endian
            packed = struct.pack("<I", int(h, 16))
            return socket.inet_ntop(socket.AF_INET, packed)
        if len(h) == 32:                      # IPv6, little-endian per word
            raw = bytes.fromhex(h)
            reordered = b"".join(raw[i:i + 4][::-1] for i in range(0, 16, 4))
            return socket.inet_ntop(socket.AF_INET6, reordered)
    except (ValueError, OSError):
        return ""
    return ""


def _normalize(ip):
    """Canonical form so 127.0.0.1 and ::ffff:127.0.0.1 compare equal-ish."""
    try:
        return socket.inet_ntop(*_unpack(ip))
    except (ValueError, OSError):
        return ip


def _unpack(ip):
    if ":" in ip:
        return socket.AF_INET6, socket.inet_pton(socket.AF_INET6, ip)
    return socket.AF_INET, socket.inet_pton(socket.AF_INET, ip)


def parse_net_file(path):
    """Yield (local_ip, local_port, inode) tuples from a /proc/net/* file."""
    try:
        with open(path, "r", encoding="utf-8") as fh:
            next(fh, None)  # header
            for line in fh:
                parts = line.split()
                if len(parts) < 10:
                    continue
                local = parts[1]
                inode = parts[9]
                if ":" not in local:
                    continue
                addr_hex, port_hex = local.rsplit(":", 1)
                ip = _hex_to_ip(addr_hex)
                try:
                    port = int(port_hex, 16)
                    inode = int(inode)
                except ValueError:
                    continue
                if ip and inode:
                    yield ip, port, inode
    except OSError:
        return


class ProcMap:
    def __init__(self, cache_ttl=1.0):
        self.cache_ttl = cache_ttl
        self._endpoint_inode = {}   # (proto, ip, port) -> inode
        self._inode_pid = {}        # inode -> pid
        self._endpoint_ts = 0
        self._inode_ts = 0
        self._exe_cache = {}        # pid -> (path, name)

    # ---- socket tables --------------------------------------------------
    def _refresh_endpoints(self):
        m = {}
        for proto, files in _PROTO_FILES.items():
            for path in files:
                for ip, port, inode in parse_net_file(path):
                    m[(proto, _normalize(ip), port)] = inode
        self._endpoint_inode = m
        self._endpoint_ts = time.time()

    def _refresh_inode_pids(self):
        m = {}
        for fd_link in glob.glob("/proc/[0-9]*/fd/*"):
            try:
                target = os.readlink(fd_link)
            except OSError:
                continue
            if not target.startswith("socket:["):
                continue
            try:
                inode = int(target[8:-1])
                pid = int(fd_link.split("/", 3)[2])
            except (ValueError, IndexError):
                continue
            m[inode] = pid
        self._inode_pid = m
        self._inode_ts = time.time()

    # ---- process info ---------------------------------------------------
    def _process_for_pid(self, pid):
        cached = self._exe_cache.get(pid)
        if cached:
            return cached
        path, name = "", ""
        try:
            path = os.readlink(f"/proc/{pid}/exe")
        except OSError:
            path = ""
        try:
            with open(f"/proc/{pid}/comm", "r", encoding="utf-8") as fh:
                name = fh.read().strip()
        except OSError:
            name = os.path.basename(path)
        result = (path, name or os.path.basename(path) or f"pid {pid}")
        self._exe_cache[pid] = result
        return result

    # ---- public ---------------------------------------------------------
    def resolve(self, proto, local_ip, local_port):
        """Return dict(pid, process_path, process) for a local endpoint."""
        now = time.time()
        key = (proto, _normalize(local_ip), int(local_port))
        if now - self._endpoint_ts > self.cache_ttl:
            self._refresh_endpoints()
        inode = self._endpoint_inode.get(key)
        if inode is None:
            self._refresh_endpoints()
            inode = self._endpoint_inode.get(key)
        if inode is None:
            return {"pid": 0, "process_path": "", "process": ""}

        if now - self._inode_ts > self.cache_ttl:
            self._refresh_inode_pids()
        pid = self._inode_pid.get(inode)
        if pid is None:
            self._refresh_inode_pids()
            pid = self._inode_pid.get(inode)
        if not pid:
            return {"pid": 0, "process_path": "", "process": ""}

        path, name = self._process_for_pid(pid)
        return {"pid": pid, "process_path": path, "process": name}
