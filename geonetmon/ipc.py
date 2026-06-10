"""Tiny newline-delimited-JSON protocol for the daemon <-> GUI socket.

Each message is a JSON object on its own line. One side never blocks the other:
the daemon pushes ``prompt`` and ``event`` messages; the GUI pushes commands
and ``decide`` responses. No third-party deps — just json + sockets, which
keeps the privileged daemon's attack surface and dependency footprint small.

Message shape: ``{"type": "<name>", ...payload}``. Types are documented in
daemon.py (server side) and client.py (GUI side).
"""

import json
import os


SYSTEM_SOCKET = "/run/geonetmon.sock"


def default_socket_path():
    """Where the daemon listens.

    The system daemon runs as root and always listens on the well-known
    ``/run/geonetmon.sock``. Both the daemon and the unprivileged GUI must
    agree on this path, so prefer it whenever it exists (GUI side) or whenever
    we are root and can create it (daemon side). Only a per-user daemon with
    no access to /run falls back to the runtime dir.
    """
    if os.path.exists(SYSTEM_SOCKET):
        return SYSTEM_SOCKET
    if _is_root() and os.path.isdir("/run"):
        return SYSTEM_SOCKET
    base = os.environ.get("XDG_RUNTIME_DIR") or "/tmp"
    return os.path.join(base, "geonetmon.sock")


def _is_root():
    try:
        return os.geteuid() == 0
    except AttributeError:
        return False


def encode(msg):
    """Serialize one message to bytes including the newline terminator."""
    return (json.dumps(msg, separators=(",", ":")) + "\n").encode("utf-8")


def send_msg(sock, msg):
    """Send one message. Returns True on success."""
    try:
        sock.sendall(encode(msg))
        return True
    except (OSError, TypeError, ValueError):
        return False


class MessageReader:
    """Accumulates bytes from a stream socket and yields complete messages.

    Usage:
        reader = MessageReader()
        data = sock.recv(4096)
        for msg in reader.feed(data):
            handle(msg)
    A returned ``None`` sentinel is never yielded; malformed lines are skipped.
    """

    # Legitimate control messages are tiny; cap the accumulator so a peer that
    # never sends a newline can't grow it without bound and exhaust the
    # (root) daemon's memory. On overflow we drop the buffered garbage.
    MAX_BUF = 1 << 20  # 1 MiB

    def __init__(self):
        self._buf = bytearray()

    def feed(self, data):
        if not data:
            return
        self._buf.extend(data)
        if len(self._buf) > self.MAX_BUF and self._buf.find(b"\n") < 0:
            del self._buf[:]            # no frame in sight — discard the flood
            return
        while True:
            nl = self._buf.find(b"\n")
            if nl < 0:
                break
            line = bytes(self._buf[:nl])
            del self._buf[:nl + 1]
            line = line.strip()
            if not line:
                continue
            try:
                msg = json.loads(line.decode("utf-8"))
            except (ValueError, UnicodeDecodeError):
                continue
            if isinstance(msg, dict) and "type" in msg:
                yield msg

    def feed_recv(self, sock, bufsize=8192):
        """Recv once and yield any complete messages; '' recv means closed."""
        try:
            data = sock.recv(bufsize)
        except (OSError, ValueError):
            return
        if not data:
            return
        yield from self.feed(data)
