"""Rule engine for the interactive outbound firewall (OpenSnitch-style).

A *rule* matches some subset of a connection's attributes and carries an
action (allow / deny). Rules are evaluated in order; the first enabled rule
that matches wins. ``None`` means "no rule matched" — the caller then applies
the configured default (prompt / allow / deny).

Scopes:
  * ``forever``  — persisted to rules.json, survives restarts
  * ``session``  — kept only for this process run
  * ``once``     — consumed after a single match (one-shot allow/deny)

A *flow* passed to :meth:`Rules.decide` is a plain dict with keys:
    proto, direction, src_ip, src_port, dst_ip, dst_port,
    dst_host (may be ""), process (basename), process_path (may be "")
"""

import ipaddress
import json
import os
import time
import uuid

from . import config as cfg

ALLOW = "allow"
DENY = "deny"
# once     — consumed after a single match
# process  — lasts while the program is running (pruned when its exe exits)
# session  — lasts until the daemon restarts (reboot); not persisted
# forever  — persisted to rules.json
SCOPES = ("once", "process", "session", "forever")

# What a remembered decision applies to — mirrors Little Snitch's choices.
SCOPE_BY = {
    "app_host": "this app to this host",
    "app_port": "this app on this port",
    "app_any": "this app, any destination",
    "host_any": "any app to this host",
    "port_any": "any app on this port",
    "exact": "this exact connection",
}


class Rule:
    __slots__ = ("id", "action", "enabled", "scope", "process", "process_path",
                 "dst_ip", "dst_host", "dst_port", "proto", "direction",
                 "created", "hits", "note", "expires", "_consumed")

    def __init__(self, action, scope="forever", process=None, process_path=None,
                 dst_ip=None, dst_host=None, dst_port=None, proto=None,
                 direction=None, note="", rid=None, created=None, hits=0,
                 expires=None):
        self.id = rid or uuid.uuid4().hex[:12]
        self.action = action
        self.enabled = True
        self.scope = scope if scope in SCOPES else "forever"
        self.process = process or None
        self.process_path = process_path or None
        self.dst_ip = dst_ip or None        # exact IP or CIDR string
        self.dst_host = dst_host or None     # suffix match, e.g. "example.com"
        self.dst_port = dst_port if dst_port else None
        self.proto = proto or None
        self.direction = direction or None
        self.created = created or time.time()
        self.hits = hits
        self.note = note
        self.expires = expires
        self._consumed = False

    # ---- matching -------------------------------------------------------
    def matches(self, flow):
        if not self.enabled or self._consumed:
            return False
        if self.expires is not None and time.time() > self.expires:
            return False
        if self.proto and flow.get("proto") != self.proto:
            return False
        if self.direction and flow.get("direction") != self.direction:
            return False
        if self.dst_port and int(flow.get("dst_port") or 0) != int(self.dst_port):
            return False
        # App identity is the EXECUTABLE, not the comm name. An app's child
        # processes share one exe path but carry different /proc/comm names
        # (e.g. Firefox's "Socket Process", "Isolated Web Co", GPU/RDD procs),
        # and most connections originate in those children — so a rule keyed on
        # comm would re-prompt and "any connection from <app>" wouldn't hold.
        # When the rule pins a path, match strictly on the path (covers the
        # whole app); fall back to the comm name only when there is no path.
        if self.process_path:
            if flow.get("process_path") != self.process_path:
                return False
        elif self.process:
            if _basename(flow.get("process")) != self.process:
                return False
        if self.dst_host:
            host = (flow.get("dst_host") or "").lower()
            want = self.dst_host.lower()
            if not (host == want or host.endswith("." + want)):
                return False
        if self.dst_ip and not _ip_in(flow.get("dst_ip"), self.dst_ip):
            return False
        return True

    # ---- serialization --------------------------------------------------
    def to_dict(self):
        return {
            "id": self.id, "action": self.action, "enabled": self.enabled,
            "scope": self.scope, "process": self.process,
            "process_path": self.process_path, "dst_ip": self.dst_ip,
            "dst_host": self.dst_host, "dst_port": self.dst_port,
            "proto": self.proto, "direction": self.direction,
            "created": self.created, "hits": self.hits, "note": self.note,
            "expires": self.expires,
        }

    @classmethod
    def from_dict(cls, d):
        r = cls(
            action=d.get("action", DENY), scope=d.get("scope", "forever"),
            process=d.get("process"), process_path=d.get("process_path"),
            dst_ip=d.get("dst_ip"), dst_host=d.get("dst_host"),
            dst_port=d.get("dst_port"), proto=d.get("proto"),
            direction=d.get("direction"), note=d.get("note", ""),
            rid=d.get("id"), created=d.get("created"), hits=d.get("hits", 0),
            expires=d.get("expires"),
        )
        r.enabled = bool(d.get("enabled", True))
        return r

    def summary(self):
        who = self.process or "any app"
        if self.dst_host:
            where = self.dst_host
        elif self.dst_ip:
            where = self.dst_ip
        else:
            where = "any host"
        port = f":{self.dst_port}" if self.dst_port else ""
        proto = f"/{self.proto}" if self.proto else ""
        return f"{self.action.upper()}  {who} → {where}{port}{proto}"

    def specificity(self):
        """Higher = more specific. Used to order rules so a broad rule never
        shadows a more specific one regardless of when it was added."""
        return (bool(self.process or self.process_path)
                + bool(self.dst_host) + bool(self.dst_ip)
                + bool(self.dst_port))


def _basename(p):
    if not p:
        return None
    return os.path.basename(p)


def _exe_running(path):
    """True if any live process is running the executable at `path`.

    Backs the 'while the app is running' rule duration. Reads /proc (the daemon
    is root). If we genuinely can't tell, return True so we never expire a rule
    by mistake.
    """
    if not path:
        return True
    try:
        entries = os.scandir("/proc")
    except OSError:
        return True
    with entries:
        for entry in entries:
            if not entry.name.isdigit():
                continue
            try:
                exe = os.readlink(f"/proc/{entry.name}/exe")
            except OSError:
                continue
            # a replaced binary shows up as "/path (deleted)"
            if exe == path or exe == path + " (deleted)":
                return True
    return False


def _ip_in(ip, spec):
    if not ip:
        return False
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    try:
        if "/" in spec:
            return addr in ipaddress.ip_network(spec, strict=False)
        return addr == ipaddress.ip_address(spec)
    except ValueError:
        return False


class Rules:
    def __init__(self, config=None):
        self.config = config
        self.rules = []     # ordered
        self._path = os.path.join(cfg.config_dir(), "rules.json")
        self.load()

    # ---- persistence ----------------------------------------------------
    def load(self):
        try:
            with open(self._path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            self.rules = [Rule.from_dict(d) for d in data.get("rules", [])
                          if isinstance(d, dict)]
        except (OSError, ValueError):
            self.rules = []

    def save(self):
        # only 'forever' rules are persisted
        keep = [r.to_dict() for r in self.rules if r.scope == "forever"]
        try:
            tmp = self._path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump({"rules": keep}, fh, indent=2)
            os.replace(tmp, self._path)
        except OSError:
            pass

    # ---- evaluation -----------------------------------------------------
    def decide(self, flow):
        """Return (action, rule) for the first match, or (None, None)."""
        for r in self.rules:
            if r.matches(flow):
                r.hits += 1
                if r.scope == "once":
                    r._consumed = True
                return r.action, r
        return None, None

    # ---- mutation -------------------------------------------------------
    def add(self, rule, top=False):
        if top:
            self.rules.insert(0, rule)
        else:
            self.rules.append(rule)
        if rule.scope == "forever":
            self.save()
        return rule

    def insert_by_specificity(self, rule):
        """Place rule so more-specific rules sort before broader ones; among
        equal specificity, the newest wins (placed first)."""
        score = rule.specificity()
        idx = next((i for i, r in enumerate(self.rules)
                    if r.specificity() <= score), len(self.rules))
        self.rules.insert(idx, rule)
        if rule.scope == "forever":
            self.save()
        return rule

    def remove(self, rid):
        before = len(self.rules)
        self.rules = [r for r in self.rules if r.id != rid]
        if len(self.rules) != before:
            self.save()

    def set_enabled(self, rid, enabled):
        for r in self.rules:
            if r.id == rid:
                r.enabled = bool(enabled)
        self.save()

    def move(self, rid, delta):
        idx = next((i for i, r in enumerate(self.rules) if r.id == rid), None)
        if idx is None:
            return
        new = max(0, min(len(self.rules) - 1, idx + delta))
        self.rules.insert(new, self.rules.pop(idx))
        self.save()

    def clear_session(self):
        """Drop session/once rules (called on quit or on demand)."""
        self.rules = [r for r in self.rules if r.scope == "forever"]

    def prune_expired(self):
        """Drop timed rules whose expiry has passed. Returns True if anything changed."""
        now = time.time()
        keep = [r for r in self.rules if r.expires is None or r.expires > now]
        if len(keep) != len(self.rules):
            self.rules = keep
            return True
        return False

    def prune_processes(self):
        """Drop 'while the app is running' rules whose program has exited.

        Called periodically by the daemon. Returns True if anything changed.
        """
        keep = [r for r in self.rules
                if not (r.scope == "process" and not _exe_running(r.process_path))]
        if len(keep) != len(self.rules):
            self.rules = keep
            return True
        return False

    def build_from_choice(self, flow, action, scope, scope_by):
        """Create a Rule from a prompt decision and add it.

        App/host/port rules carry NO proto or direction, so an "Any connection"
        allow covers all of an app's traffic — TCP *and* UDP/QUIC (Firefox's
        HTTP/3), in and out. Only "exact" pins proto + direction.
        """
        expires = None
        if scope.lstrip("-").isdigit():
            expires = time.time() + int(scope)
            scope = "session"
        kw = {"action": action, "scope": scope, "expires": expires}
        proc = _basename(flow.get("process"))
        path = flow.get("process_path")
        if scope_by == "app_host":
            kw.update(process=proc, process_path=path,
                      dst_host=flow.get("dst_host") or None,
                      dst_ip=None if flow.get("dst_host") else flow.get("dst_ip"))
        elif scope_by == "app_port":
            kw.update(process=proc, process_path=path, dst_port=flow.get("dst_port"))
        elif scope_by == "app_any":
            kw.update(process=proc, process_path=path)
        elif scope_by == "host_any":
            kw.update(dst_host=flow.get("dst_host") or None,
                      dst_ip=None if flow.get("dst_host") else flow.get("dst_ip"))
        elif scope_by == "port_any":
            kw.update(dst_port=flow.get("dst_port"))
        else:  # exact
            kw.update(process=proc, process_path=path,
                      dst_ip=flow.get("dst_ip"), dst_port=flow.get("dst_port"))
        rule = Rule(**kw)
        # order by specificity so a broad rule can't shadow a specific one
        self.insert_by_specificity(rule)
        return rule
