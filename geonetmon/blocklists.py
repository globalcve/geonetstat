"""Blocklist subscriptions + rule import/export.

Blocklists are fetched from URLs in hosts-file or plain-domain format (the same
lists OpenSnitch and Pi-hole use: StevenBlack, etc.) and converted into deny
rules matched by destination host suffix. Parsing is pure and unit-tested;
fetching uses urllib with a timeout and degrades gracefully offline.

Rule import/export round-trips the rule set as JSON so you can back up or share
a configuration.
"""

import json
import os
import time
import urllib.request

from . import config as cfg
from .rules import Rule, DENY


def parse_blocklist(text, limit=200000):
    """Extract domains from hosts-file or domain-list text.

    Handles lines like ``0.0.0.0 ads.example.com`` / ``127.0.0.1 x.test`` and
    bare ``ads.example.com``. Skips comments, localhost entries, and junk.
    Returns a de-duplicated list of domains (order preserved).
    """
    seen = set()
    out = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith(("#", "!", ";")):
            continue
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) >= 2 and _looks_like_ip(parts[0]):
            domain = parts[1]
        elif len(parts) == 1:
            domain = parts[0]
        else:
            continue
        domain = domain.strip().lower().rstrip(".")
        if not domain or "." not in domain:
            continue
        if domain in ("localhost", "localhost.localdomain", "local",
                      "broadcasthost", "ip6-localhost", "ip6-loopback"):
            continue
        if any(ch in domain for ch in " \t/\\"):
            continue
        if domain not in seen:
            seen.add(domain)
            out.append(domain)
            if len(out) >= limit:
                break
    return out


def _looks_like_ip(tok):
    if tok.count(".") == 3 and all(p.isdigit() for p in tok.split(".")):
        return True
    return tok in ("0.0.0.0", "::", "::1") or ":" in tok


def fetch_blocklist(url, timeout=15):
    """Download and parse a blocklist URL -> (domains, error)."""
    try:
        req = urllib.request.Request(url, headers={
            "User-Agent": "GeoNetMon/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            text = resp.read().decode("utf-8", "replace")
        return parse_blocklist(text), ""
    except Exception as exc:  # noqa: BLE001
        return [], str(exc)


class Blocklists:
    """Tracks subscribed blocklist URLs and the deny rules they generate."""

    def __init__(self, config, rules):
        self.config = config
        self.rules = rules
        self._state_path = os.path.join(cfg.config_dir(), "blocklists.json")
        self.subs = {}      # url -> {"count", "updated", "note"}
        self._load()

    def _load(self):
        try:
            with open(self._state_path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            if isinstance(data, dict):
                self.subs = data.get("subs", {})
        except (OSError, ValueError):
            self.subs = {}

    def save(self):
        try:
            tmp = self._state_path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump({"subs": self.subs}, fh, indent=2)
            os.replace(tmp, self._state_path)
        except OSError:
            pass

    def apply_domains(self, url, domains):
        """Replace the deny rules for this URL's tag with fresh ones."""
        tag = f"blocklist:{url}"
        # remove existing rules from this list
        self.rules.rules = [r for r in self.rules.rules if r.note != tag]
        for d in domains:
            r = Rule(action=DENY, scope="forever", dst_host=d, note=tag)
            # appended low-priority; specific user allows still win by ordering
            self.rules.rules.append(r)
        self.rules.save()
        self.subs[url] = {"count": len(domains), "updated": time.time(),
                          "note": tag}
        self.save()

    def remove(self, url):
        tag = f"blocklist:{url}"
        self.rules.rules = [r for r in self.rules.rules if r.note != tag]
        self.rules.save()
        self.subs.pop(url, None)
        self.save()

    def refresh(self, url):
        domains, err = fetch_blocklist(url)
        if err:
            return False, err
        self.apply_domains(url, domains)
        return True, f"{len(domains)} domains"

    def refresh_all(self):
        results = {}
        for url in list(self.subs):
            ok, msg = self.refresh(url)
            results[url] = (ok, msg)
        return results


# ---- rule import / export ----------------------------------------------
def export_rules(rules, path):
    data = {"version": 1, "exported": time.time(),
            "rules": [r.to_dict() for r in rules.rules]}
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)
    return len(data["rules"])


def import_rules(rules, path, replace=False):
    """Import rules from a JSON file. Returns count imported."""
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    incoming = [Rule.from_dict(d) for d in data.get("rules", [])
                if isinstance(d, dict)]
    if replace:
        rules.rules = incoming
    else:
        existing = {(r.action, r.process, r.dst_host, r.dst_ip, r.dst_port)
                    for r in rules.rules}
        for r in incoming:
            key = (r.action, r.process, r.dst_host, r.dst_ip, r.dst_port)
            if key not in existing:
                rules.rules.append(r)
                existing.add(key)
    rules.save()
    return len(incoming)
