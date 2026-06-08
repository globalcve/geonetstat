"""Block / unblock remote IPs via ufw, nftables, or iptables.

GeoNetMon keeps its own JSON record of blocked IPs (``blocked.json`` in the
config dir) as the source of truth, so the UI can list and reverse blocks no
matter which backend applied them. Privileged commands are bundled into a
single ``sh -c`` snippet and run through ``pkexec`` (one auth prompt) unless
GeoNetMon is already root.

Backends:
  * ufw       — ``ufw deny`` rules (persist across reboot)
  * nftables  — a dedicated ``inet geonetmon`` table, reapplied declaratively
  * iptables  — ``-I INPUT/OUTPUT ... -j DROP`` (also ip6tables for IPv6)

IP arguments are validated with :mod:`ipaddress` before ever reaching a shell,
so the snippets cannot be used for command injection.
"""

import ipaddress
import json
import os
import shutil
import subprocess
import threading
import time

from gi.repository import GLib

from . import config as cfg

NFT_TABLE = "geonetmon"


def _which(name):
    return shutil.which(name) is not None


def available_backends():
    """Backends whose CLI is present, in preference order."""
    found = []
    if _which("ufw"):
        found.append("ufw")
    if _which("nft"):
        found.append("nftables")
    if _which("iptables"):
        found.append("iptables")
    return found


def _valid_ip(ip):
    """Return an ipaddress object or None."""
    try:
        return ipaddress.ip_address(ip)
    except ValueError:
        return None


def is_root():
    try:
        return os.geteuid() == 0
    except AttributeError:
        return False


class Firewall:
    def __init__(self, config):
        self.config = config
        self._path = os.path.join(cfg.config_dir(), "blocked.json")
        self.blocked = {}          # ip -> {"ts", "backend", "note"}
        self._load()

    # ---- backend resolution --------------------------------------------
    def resolve_backend(self):
        choice = self.config.get("firewall_backend", "auto")
        avail = available_backends()
        if choice != "auto" and choice in avail:
            return choice
        return avail[0] if avail else None

    def usable(self):
        return self.resolve_backend() is not None

    # ---- record persistence --------------------------------------------
    def _load(self):
        try:
            with open(self._path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            if isinstance(data, dict):
                self.blocked = data
        except (OSError, ValueError):
            self.blocked = {}

    def save(self):
        try:
            tmp = self._path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(self.blocked, fh, indent=2)
            os.replace(tmp, self._path)
        except OSError:
            pass

    def is_blocked(self, ip):
        return ip in self.blocked

    def list_blocked(self):
        return sorted(self.blocked.items(), key=lambda kv: kv[1].get("ts", 0),
                      reverse=True)

    # ---- script construction (pure + unit-testable) --------------------
    def _ufw_block(self, ip):
        # insert at top so the deny wins over broad allows; fall back to append
        return (f"ufw insert 1 deny out to {ip} 2>/dev/null || ufw deny out to {ip}; "
                f"ufw insert 1 deny from {ip} 2>/dev/null || ufw deny from {ip}")

    def _ufw_unblock(self, ip):
        return (f"ufw delete deny out to {ip}; "
                f"ufw delete deny from {ip}")

    def _ipt_bins(self, ip):
        v6 = _valid_ip(ip).version == 6
        return "ip6tables" if v6 else "iptables"

    def _iptables_block(self, ip):
        b = self._ipt_bins(ip)
        return (f"{b} -I OUTPUT -d {ip} -j DROP; "
                f"{b} -I INPUT -s {ip} -j DROP")

    def _iptables_unblock(self, ip):
        b = self._ipt_bins(ip)
        # -D is idempotent enough; ignore failures so a missing rule is harmless
        return (f"{b} -D OUTPUT -d {ip} -j DROP 2>/dev/null; "
                f"{b} -D INPUT -s {ip} -j DROP 2>/dev/null; true")

    def _nft_apply_all(self):
        """Declarative: tear down our table and rebuild from the record."""
        lines = [
            f"nft delete table inet {NFT_TABLE} 2>/dev/null; true",
            f"nft add table inet {NFT_TABLE}",
            (f"nft add chain inet {NFT_TABLE} output "
             f"'{{ type filter hook output priority -10 ; }}'"),
            (f"nft add chain inet {NFT_TABLE} input "
             f"'{{ type filter hook input priority -10 ; }}'"),
        ]
        for ip in self.blocked:
            addr = _valid_ip(ip)
            if not addr:
                continue
            fam = "ip6" if addr.version == 6 else "ip"
            lines.append(f"nft add rule inet {NFT_TABLE} output {fam} daddr {ip} drop")
            lines.append(f"nft add rule inet {NFT_TABLE} input {fam} saddr {ip} drop")
        return "; ".join(lines)

    def block_script(self, ip, backend):
        if backend == "ufw":
            return self._ufw_block(ip)
        if backend == "iptables":
            return self._iptables_block(ip)
        if backend == "nftables":
            return self._nft_apply_all()
        return ""

    def unblock_script(self, ip, backend):
        if backend == "ufw":
            return self._ufw_unblock(ip)
        if backend == "iptables":
            return self._iptables_unblock(ip)
        if backend == "nftables":
            return self._nft_apply_all()
        return ""

    # ---- execution ------------------------------------------------------
    def _wrap(self, script):
        """argv for running a privileged shell snippet."""
        if is_root():
            return ["sh", "-c", script]
        return ["pkexec", "sh", "-c", script]

    def _run_async(self, argv, on_done):
        def worker():
            ok, msg = self._run(argv)
            if on_done:
                GLib.idle_add(on_done, ok, msg)
        threading.Thread(target=worker, daemon=True).start()

    @staticmethod
    def _run(argv):
        try:
            proc = subprocess.run(argv, capture_output=True, text=True,
                                  timeout=30, check=False)
        except FileNotFoundError:
            return False, "pkexec not found — install policykit-1"
        except subprocess.TimeoutExpired:
            return False, "command timed out (auth prompt dismissed?)"
        if proc.returncode == 0:
            return True, "ok"
        if proc.returncode == 126:
            return False, "authorization cancelled"
        err = (proc.stderr or proc.stdout or "").strip().splitlines()
        return False, (err[-1] if err else f"exit {proc.returncode}")

    def block(self, ip, on_done=None, note=""):
        addr = _valid_ip(ip)
        if not addr:
            if on_done:
                on_done(False, "not a valid IP")
            return
        backend = self.resolve_backend()
        if not backend:
            if on_done:
                on_done(False, "no firewall backend found (ufw/nft/iptables)")
            return
        # record first so nft's declarative reapply includes this IP
        self.blocked[ip] = {"ts": time.time(), "backend": backend, "note": note}
        self.save()
        script = self.block_script(ip, backend)

        def done(ok, msg):
            if not ok:
                self.blocked.pop(ip, None)
                self.save()
            if on_done:
                on_done(ok, msg)
        self._run_async(self._wrap(script), done)

    def unblock(self, ip, on_done=None):
        backend = self.blocked.get(ip, {}).get("backend") or self.resolve_backend()
        existed = self.blocked.pop(ip, None)
        self.save()
        if not backend:
            if on_done:
                on_done(bool(existed), "removed from list (no backend)")
            return
        script = self.unblock_script(ip, backend)

        def done(ok, msg):
            if not ok and existed:
                # restore record if the system command failed
                self.blocked[ip] = existed
                self.save()
            if on_done:
                on_done(ok, msg)
        self._run_async(self._wrap(script), done)
