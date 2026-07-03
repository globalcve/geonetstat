"""Alert logic: detects notable connections and raises desktop notifications."""

import json
import os
import time

from gi.repository import Gio

from . import config as cfg
from . import ports


class Alert:
    __slots__ = ("ts", "level", "title", "body", "flow")

    def __init__(self, level, title, body, flow=None):
        self.ts = time.time()
        self.level = level          # "info" / "warn"
        self.title = title
        self.body = body
        # optional connection info so the log can offer allow/deny:
        # {process, process_path, dst_ip, dst_port, proto}
        self.flow = flow


class AlertManager:
    def __init__(self, app, config, on_alert=None):
        self.app = app
        self.config = config
        self.on_alert = on_alert     # UI callback(Alert)
        self.log = []
        self.seen_apps = set()
        self.seen_countries = set()
        self.seen_ips = set()
        self._state_path = os.path.join(cfg.cache_dir(), "seen.json")
        self._load()
        self._primed = False
        self._risk_seen = set()

    def _load(self):
        try:
            with open(self._state_path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            self.seen_apps = set(data.get("apps", []))
            self.seen_countries = set(data.get("countries", []))
            self.seen_ips = set(data.get("ips", []))
        except (OSError, ValueError):
            pass

    def save(self):
        try:
            with open(self._state_path, "w", encoding="utf-8") as fh:
                json.dump({
                    "apps": sorted(self.seen_apps),
                    "countries": sorted(self.seen_countries),
                    "ips": sorted(self.seen_ips),
                }, fh)
            os.chmod(self._state_path, 0o600)   # seen-IP list — owner-only
        except OSError:
            pass

    def prime_done(self):
        """Called after the first refresh so the initial snapshot isn't alerted."""
        self._primed = True

    def reset_seen(self):
        """Forget every known app/country/IP so 'new X' alerts re-prime."""
        self.seen_apps.clear()
        self.seen_countries.clear()
        self.seen_ips.clear()
        self._risk_seen.clear()
        self.save()

    # ---- checks ---------------------------------------------------------
    def on_appear(self, obj):
        """Called once when a connection key is first observed this run."""
        app = (obj.application or "").strip()
        if app and app not in ("Unknown", "-"):
            new_app = app not in self.seen_apps
            self.seen_apps.add(app)
            if new_app and self._primed and self.config["alert_new_app"]:
                self._raise("warn", "New application online",
                            f"{app} opened a connection "
                            f"({obj.direction.lower()} :{obj.port} {obj.service})",
                            flow={"process": app, "process_path": "",
                                  "dst_ip": obj.ip, "dst_port": obj.port,
                                  "proto": (obj.proto or "").lower()})

        if obj.direction == "INCOMING" and self._primed \
                and self.config["alert_incoming"]:
            self._raise("warn", "Incoming connection",
                        f"{obj.application} accepted from {obj.ip} :{obj.port}")

    def on_enriched(self, obj):
        """Called after geo/rdns resolves for a connection."""
        cc = (obj.country or "").upper()
        if cc:
            new_cc = cc not in self.seen_countries
            self.seen_countries.add(cc)
            if new_cc and self._primed and self.config["alert_new_country"]:
                name = ports.country_name(cc)
                flag = ports.flag_emoji(cc)
                self._raise("warn", "Connection to a new country",
                            f"{obj.application} → {flag} {name} ({obj.org})")

        ip = obj.geo_ip
        if ip:
            new_ip = ip not in self.seen_ips
            self.seen_ips.add(ip)
            if new_ip and self._primed and self.config["alert_new_ip"]:
                self._raise("info", "New remote host",
                            f"{obj.application} → {ip} ({obj.org})")

        if self._primed and self.config["alert_unencrypted_foreign"] \
                and obj.is_foreign and obj.encryption.startswith("Plain"):
            self._raise("warn", "Unencrypted foreign traffic",
                        f"{obj.application} → {obj.location} on "
                        f":{obj.port} ({obj.service}) is not encrypted")

        if self._primed and self.config.get("alert_high_risk", True) \
                and getattr(obj, "risk", -1) >= 50 and ip not in self._risk_seen:
            self._risk_seen.add(ip)
            self._raise("warn", "High-risk remote host",
                        f"{obj.application} → {ip} has AbuseIPDB score "
                        f"{obj.risk}/100 ({obj.org})")

    # ---- emit -----------------------------------------------------------
    def _raise(self, level, title, body, flow=None):
        alert = Alert(level, title, body, flow)
        self.log.insert(0, alert)
        del self.log[200:]
        if self.on_alert:
            self.on_alert(alert)
        if (self.config["desktop_notifications"]
                and not self.config.get("silent_mode")):
            self._notify(level, title, body)

    def _notify(self, level, title, body):
        try:
            n = Gio.Notification.new(title)
            n.set_body(body)
            n.set_priority(
                Gio.NotificationPriority.HIGH if level == "warn"
                else Gio.NotificationPriority.NORMAL
            )
            self.app.send_notification(None, n)
        except Exception:  # noqa: BLE001
            pass

    def clear(self):
        self.log.clear()
