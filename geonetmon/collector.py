"""Socket collection via `ss`, parsed into Connection records.

Process-name attribution needs root to see *other* users' sockets. So the GUI
never runs as root: the privileged daemon publishes a key->process map to a
world-readable file (write_proc_map), and the unprivileged GUI fills in the
names it couldn't see (enrich_from_daemon). If the daemon isn't running the GUI
simply shows the processes it owns — no root, ever.
"""

import json
import os
import re
import shutil
import subprocess
import time
from dataclasses import dataclass

from . import ports

_PROC_RE = re.compile(r'\("([^"]+)",pid=(\d+)')
_BYTES_SENT_RE = re.compile(r'\bbytes_sent:(\d+)')
_BYTES_ACKED_RE = re.compile(r'\bbytes_acked:(\d+)')
_BYTES_RECV_RE = re.compile(r'\bbytes_received:(\d+)')

# The root daemon publishes process attribution here for the unprivileged GUI.
DAEMON_PROC_FILE = "/run/geonetmon-procs.json"
_PROC_CACHE = {"mtime": -1.0, "map": {}}


@dataclass
class Connection:
    key: str
    proto: str               # "tcp" / "udp"
    state: str               # ESTAB, LISTEN, TIME-WAIT, UNCONN, ...
    local_ip: str
    local_port: int
    remote_ip: str           # may be "*" / "0.0.0.0" / "::"
    remote_port: int
    app: str
    pid: int
    direction: str           # INCOMING / OUTGOING / LISTEN
    service_port: int        # the port we treat as "the service"
    service: str = ""
    encryption: str = ""
    geo_ip: str = ""         # the IP we geolocate ("" when not applicable)
    bytes_sent: int = 0      # cumulative, from ss -i (0 if unknown)
    bytes_recv: int = 0      # cumulative, from ss -i (0 if unknown)
    raw: str = ""


def ss_available() -> bool:
    return shutil.which("ss") is not None


def is_root() -> bool:
    try:
        return os.geteuid() == 0
    except AttributeError:
        return False


def _split_hostport(token: str):
    """Split 'host:port' handling IPv6 '[::1]:443' and wildcards."""
    token = token.strip()
    if token.startswith("["):
        host, _, port = token.rpartition("]:")
        host = host.lstrip("[").rstrip("]")
    else:
        host, _, port = token.rpartition(":")
        if not host:  # no colon at all
            host, port = token, ""
    host = host.strip()
    try:
        portnum = int(port)
    except (ValueError, TypeError):
        portnum = 0
    return host, portnum


def _classify(proto, lip, lport, rip, rport, state):
    """Return (direction, service_port, geo_ip)."""
    wildcard = rip in ("*", "0.0.0.0", "::", "[::]", "")
    if state == "LISTEN" or (proto == "udp" and state == "UNCONN" and wildcard):
        return "LISTEN", lport, ""

    known = ports.PORTMAP
    if rport and (rport in known or rport < 1024):
        direction, svc = "OUTGOING", rport
    elif lport and (lport in known or lport < 1024):
        direction, svc = "INCOMING", lport
    else:
        direction, svc = "OUTGOING", (rport or lport)

    geo_ip = "" if wildcard else rip
    return direction, svc, geo_ip


def collect():
    """Run ss and return a list of Connection records.

    Always queries both TCP and UDP so the Netid column is present and parsing
    is uniform; protocol filtering happens later in the UI layer.
    """
    args = ["ss", "-n", "-a", "-p", "-t", "-u", "-i"]
    try:
        proc = subprocess.run(
            args, capture_output=True, text=True, timeout=15, check=False
        )
    except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
        raise RuntimeError(f"failed to run ss: {exc}") from exc

    out = proc.stdout.splitlines()
    conns = []
    last = None  # most recent Connection, for attaching its tcp_info line
    for line in out:
        if not line:
            continue
        # tcp_info continuation lines are whitespace-indented; attach to prev.
        if line[0].isspace():
            if last is not None:
                _attach_info(last, line)
            continue
        if not line.strip():
            continue
        parts = line.split()
        if parts[0].lower() in ("netid", "state"):
            continue
        # Expected: Netid State Recv-Q Send-Q Local Peer [Process]
        if len(parts) < 6:
            continue
        proto = parts[0].lower()
        if proto not in ("tcp", "udp", "udp6", "tcp6"):
            continue
        proto = "udp" if proto.startswith("udp") else "tcp"
        state = parts[1]
        local_tok = parts[4]
        peer_tok = parts[5]
        process = " ".join(parts[6:]) if len(parts) > 6 else ""

        lip, lport = _split_hostport(local_tok)
        rip, rport = _split_hostport(peer_tok)

        app, pid = "", 0
        m = _PROC_RE.search(process)
        if m:
            app, pid = m.group(1), int(m.group(2))

        direction, svc_port, geo_ip = _classify(
            proto, lip, lport, rip, rport, state
        )
        service = ports.service_for(svc_port)
        encryption = ports.encryption_for(svc_port, app or "")

        key = f"{proto}|{lip}:{lport}|{rip}:{rport}"
        last = Connection(
            key=key, proto=proto, state=state,
            local_ip=lip, local_port=lport,
            remote_ip=rip, remote_port=rport,
            app=app or "", pid=pid,
            direction=direction, service_port=svc_port,
            service=service, encryption=encryption,
            geo_ip=geo_ip, raw=line.strip(),
        )
        conns.append(last)
    return conns


# ---- daemon process-attribution feed (so the GUI never needs root) ---------

def write_proc_map(conns):
    """Daemon (root) call: publish key->[app, pid] for every socket it can see,
    so the unprivileged GUI can fill in names. Written world-readable, atomically."""
    m = {c.key: [c.app, c.pid] for c in conns if c.app}
    tmp = DAEMON_PROC_FILE + ".tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(m, fh)
        os.chmod(tmp, 0o644)
        os.replace(tmp, DAEMON_PROC_FILE)
    except OSError:
        pass


def _load_proc_map():
    """The daemon's map, cached by mtime. Empty if the file is missing or stale
    (daemon not running) so the GUI silently falls back to its own attribution."""
    try:
        st = os.stat(DAEMON_PROC_FILE)
    except OSError:
        return {}
    if time.time() - st.st_mtime > 8:   # stale -> treat daemon as gone
        return {}
    if st.st_mtime != _PROC_CACHE["mtime"]:
        try:
            with open(DAEMON_PROC_FILE, encoding="utf-8") as fh:
                _PROC_CACHE["map"] = json.load(fh)
            _PROC_CACHE["mtime"] = st.st_mtime
        except (OSError, ValueError):
            pass
    return _PROC_CACHE["map"]


def daemon_procs_available():
    """True when the root daemon is publishing process names (so no root needed)."""
    return bool(_load_proc_map())


def enrich_from_daemon(conns):
    """Fill in app/pid the unprivileged GUI couldn't see, from the daemon's map.
    No-op (returns False) if the daemon isn't running."""
    m = _load_proc_map()
    if not m:
        return False
    for c in conns:
        if not c.app:
            hit = m.get(c.key)
            if hit:
                c.app = hit[0] or ""
                try:
                    c.pid = int(hit[1])
                except (TypeError, ValueError):
                    pass
    return True


def _attach_info(conn, info_line):
    """Pull cumulative byte counters from a `ss -i` tcp_info line."""
    m = _BYTES_SENT_RE.search(info_line)
    if m:
        conn.bytes_sent = int(m.group(1))
    elif conn.bytes_sent == 0:
        m = _BYTES_ACKED_RE.search(info_line)   # older iproute2 fallback
        if m:
            conn.bytes_sent = int(m.group(1))
    m = _BYTES_RECV_RE.search(info_line)
    if m:
        conn.bytes_recv = int(m.group(1))
