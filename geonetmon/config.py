"""Persistent configuration, stored as JSON under XDG config dir."""

import json
import os

DEFAULTS = {
    # Polling
    "refresh_ms": 2000,
    "paused_on_start": False,

    # What to show
    "show_tcp": True,
    "show_udp": True,
    "show_listen": True,
    "show_timewait": False,        # hide TIME-WAIT / CLOSE-WAIT churn by default
    "hide_loopback": False,        # hide 127.0.0.0/8 + ::1
    "max_rows": 0,                 # 0 = unlimited

    # Enrichment
    "resolve_geo": True,
    "resolve_rdns": True,
    "dns_sniff": True,             # daemon: passively capture DNS responses
                                   # (hostnames without enforcement)
    "ipinfo_token": "",
    "home_country": "",            # e.g. "GB" — anything else is flagged foreign
    "cache_ttl_hours": 168,        # 7 days
    "lookup_timeout_s": 3,

    # Offline GeoLite2 (preferred over ipinfo when set + maxminddb installed)
    "geoip_db_path": "",           # GeoLite2-City.mmdb or -Country.mmdb
    "geoip_asn_db_path": "",       # GeoLite2-ASN.mmdb (optional, for org)

    # Threat intelligence
    "abuseipdb_token": "",         # optional AbuseIPDB API key

    # Firewall
    "firewall_backend": "auto",    # auto | ufw | nftables | iptables

    # Enforcement (interactive outbound firewall — needs root + nftables + NFQUEUE)
    "enforce_enabled": False,          # master switch
    "enforce_direction": "outbound",   # outbound | both
    "enforce_default_action": "prompt",  # prompt | allow | deny (unmatched flows)
    "enforce_prompt_timeout_s": 90,    # auto-decide if no answer (generous)
    "enforce_timeout_action": "deny",  # allow | deny on timeout
    "enforce_apply_tcp": True,
    "enforce_apply_udp": True,
    "enforce_default_scope": "forever",  # once | process | session | forever
    "enforce_default_scope_by": "app_any",  # see rules.SCOPE_BY — app-level by
                                            # default: one answer silences an app
    "enforce_notify_prompt": True,     # GNOME notification when allow/deny prompt fires
    "enforce_notify_allow": True,      # notify when user manually allows
    "enforce_notify_allow_auto": False, # notify on auto-allow (repeat connections)
    "enforce_notify_deny": True,       # notify when user manually denies
    "enforce_notify_deny_auto": False,  # notify on auto-deny (existing rule matched)
    "enforce_nfqueue_num": 0,
    "enforce_fail_open": True,         # accept traffic if the engine dies
    "enforce_max_pending": 30,         # max distinct apps awaiting a decision
    "enforce_max_per_group": 200,      # max held connections per app group
    "enforce_dns_capture": True,       # sniff DNS responses for hostnames
    "enforce_skip_dns": True,          # never prompt on DNS queries (port 53)
    "enforce_skip_loopback": True,     # never enforce 127.0.0.0/8 + ::1

    # History
    "log_history": True,
    "history_keep_days": 30,

    # Alerts
    "desktop_notifications": True,
    "alert_new_app": True,
    "alert_new_country": True,
    "alert_new_ip": False,
    "alert_incoming": False,
    "alert_unencrypted_foreign": False,
    "alert_high_risk": True,       # AbuseIPDB score above threshold

    # Security
    "app_lock_enabled": False,     # ask for a password when the GUI starts
    "app_lock_hash": "",           # PBKDF2 hash (see applock.py); "" = unset
    "app_lock_idle_min": 0,        # re-lock after N idle minutes (0 = off)

    # UI
    "theme": "system",            # system | dracula | catppuccin-* | …
    "accent": "",                 # "" = theme default, else a themes.ACCENT_PALETTE name
    "highlight_seconds": 5,
    "show_pid_column": True,
    "show_rate_columns": True,    # live ↑/↓ throughput columns
    "show_risk_column": False,    # AbuseIPDB risk column (needs token)
    "show_sparkline": True,       # connection-count sparkline in status bar
    "run_in_background": False,    # keep running when window closed
    "silent_mode": False,          # suppress all desktop notifications
    "win_width": 0,                # last window size (0 = default)
    "win_height": 0,
    "win_maximized": False,
}


def config_dir() -> str:
    base = os.environ.get("XDG_CONFIG_HOME") or os.path.expanduser("~/.config")
    d = os.path.join(base, "geonetmon")
    os.makedirs(d, exist_ok=True)
    return d


def cache_dir() -> str:
    base = os.environ.get("XDG_CACHE_HOME") or os.path.expanduser("~/.cache")
    d = os.path.join(base, "geonetmon")
    os.makedirs(d, exist_ok=True)
    return d


# ---- login autostart (XDG) -----------------------------------------------
# The autostart .desktop file itself is the source of truth (no config key),
# so the switch stays honest even if the user removes the file by hand.

_AUTOSTART_DESKTOP = """[Desktop Entry]
Type=Application
Name=GeoNetMon
Comment=Real-time geo-aware network monitor & interactive firewall
Exec=geonetmon
Icon=geonetmon
Terminal=false
X-GNOME-Autostart-enabled=true
"""


def autostart_path() -> str:
    base = os.environ.get("XDG_CONFIG_HOME") or os.path.expanduser("~/.config")
    return os.path.join(base, "autostart", "com.jegly.GeoNetMon.desktop")


def autostart_enabled() -> bool:
    return os.path.isfile(autostart_path())


def set_autostart(enabled: bool) -> bool:
    path = autostart_path()
    try:
        if enabled:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(_AUTOSTART_DESKTOP)
        elif os.path.isfile(path):
            os.remove(path)
        return True
    except OSError:
        return False


class Config:
    def __init__(self):
        self.path = os.path.join(config_dir(), "config.json")
        self.data = dict(DEFAULTS)
        self.load()

    def load(self):
        try:
            with open(self.path, "r", encoding="utf-8") as fh:
                stored = json.load(fh)
            if isinstance(stored, dict):
                for key, val in stored.items():
                    if key in DEFAULTS and isinstance(val, type(DEFAULTS[key])):
                        self.data[key] = val
        except (OSError, ValueError):
            pass

    def save(self):
        try:
            tmp = self.path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(self.data, fh, indent=2)
            # Owner-only: the config holds API tokens and the app-lock hash.
            os.chmod(tmp, 0o600)
            os.replace(tmp, self.path)
        except OSError:
            pass

    # dict-like sugar
    def __getitem__(self, key):
        return self.data[key]

    def __setitem__(self, key, val):
        self.data[key] = val

    def get(self, key, default=None):
        return self.data.get(key, default)

    def __contains__(self, key):
        return key in self.data
