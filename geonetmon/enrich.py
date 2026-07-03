"""Asynchronous geolocation + reverse-DNS enrichment with an on-disk cache.

Geo resolution prefers a local MaxMind GeoLite2 database (no network) when one
is configured and the ``maxminddb`` module is available; otherwise it falls
back to ipinfo.io. Optional AbuseIPDB threat scoring is included when a token
is set. All of it runs off the UI thread and is cached on disk.
"""

import json
import os
import socket
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor

from gi.repository import GLib

from . import config as cfg
from .models import classify_ip

try:
    import maxminddb
    _HAVE_MMDB = True
except ImportError:
    maxminddb = None
    _HAVE_MMDB = False


class Enricher:
    def __init__(self, config, on_update):
        """on_update(ip, data_dict) is invoked on the GTK main thread."""
        self.config = config
        self.on_update = on_update
        self.pool = ThreadPoolExecutor(max_workers=8)
        self.cache = {}
        self.inflight = set()
        self._cache_path = os.path.join(cfg.cache_dir(), "ipcache.json")
        self._load_cache()
        self._dirty = 0
        self._city_reader = None
        self._asn_reader = None
        self.reload_geoip()

    # ---- offline GeoLite2 ----------------------------------------------
    def geoip_status(self):
        """Human-readable description of the active geo source."""
        if self._city_reader:
            extra = " + ASN" if self._asn_reader else ""
            return f"offline GeoLite2{extra}"
        if not _HAVE_MMDB and self.config.get("geoip_db_path"):
            return "ipinfo.io (install 'maxminddb' for offline)"
        return "ipinfo.io"

    def reload_geoip(self):
        for attr in ("_city_reader", "_asn_reader"):
            r = getattr(self, attr)
            if r is not None:
                try:
                    r.close()
                except Exception:  # noqa: BLE001
                    pass
                setattr(self, attr, None)
        if not _HAVE_MMDB:
            return
        city = (self.config.get("geoip_db_path") or "").strip()
        asn = (self.config.get("geoip_asn_db_path") or "").strip()
        if city and os.path.isfile(city):
            try:
                self._city_reader = maxminddb.open_database(city)
            except (OSError, ValueError):
                self._city_reader = None
        if asn and os.path.isfile(asn):
            try:
                self._asn_reader = maxminddb.open_database(asn)
            except (OSError, ValueError):
                self._asn_reader = None

    # ---- cache ----------------------------------------------------------
    def _load_cache(self):
        try:
            with open(self._cache_path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            if isinstance(data, dict):
                self.cache = data
        except (OSError, ValueError):
            self.cache = {}

    def save_cache(self):
        try:
            tmp = self._cache_path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(self.cache, fh)
            os.chmod(tmp, 0o600)    # visited-IP history — owner-only
            os.replace(tmp, self._cache_path)
        except OSError:
            pass

    def _fresh(self, entry):
        ttl = self.config["cache_ttl_hours"] * 3600
        return entry and (time.time() - entry.get("ts", 0)) < ttl

    # ---- public API -----------------------------------------------------
    def request(self, ip):
        if not ip:
            return
        entry = self.cache.get(ip)
        if self._fresh(entry):
            GLib.idle_add(self.on_update, ip, dict(entry))
            return
        if ip in self.inflight:
            return
        self.inflight.add(ip)
        self.pool.submit(self._worker, ip)

    # ---- worker thread --------------------------------------------------
    def _worker(self, ip):
        kind = classify_ip(ip)
        data = {"org": "", "city": "", "country": "", "rdns": "", "kind": kind}
        timeout = max(1, int(self.config["lookup_timeout_s"]))

        if kind == "public" and self.config["resolve_geo"]:
            if self._city_reader:
                data.update(self._geo_offline(ip))
            else:
                data.update(self._geo(ip, timeout))

        if kind == "public" and self.config.get("abuseipdb_token", "").strip():
            data.update(self._abuse(ip, timeout))

        if self.config["resolve_rdns"]:
            data["rdns"] = self._rdns(ip)

        data["ts"] = time.time()
        self.cache[ip] = data
        self._dirty += 1
        if self._dirty >= 25:
            self._dirty = 0
            self.save_cache()
        GLib.idle_add(self.on_update, ip, dict(data))

    def _geo_offline(self, ip):
        out = {"org": "", "city": "", "country": ""}
        try:
            rec = self._city_reader.get(ip) or {}
        except (ValueError, KeyError):
            rec = {}
        if isinstance(rec, dict):
            country = rec.get("country") or rec.get("registered_country") or {}
            iso = country.get("iso_code", "") if isinstance(country, dict) else ""
            city = rec.get("city") or {}
            names = city.get("names", {}) if isinstance(city, dict) else {}
            out["country"] = iso or ""
            out["city"] = names.get("en", "") if isinstance(names, dict) else ""
            location = rec.get("location") or {}
            if isinstance(location, dict):
                if location.get("latitude") is not None:
                    out["lat"] = float(location["latitude"])
                if location.get("longitude") is not None:
                    out["lng"] = float(location["longitude"])
        if self._asn_reader is not None:
            try:
                asn = self._asn_reader.get(ip) or {}
            except (ValueError, KeyError):
                asn = {}
            if isinstance(asn, dict):
                out["org"] = asn.get("autonomous_system_organization", "") or ""
        if not out["org"]:
            out["org"] = out["country"] and "GeoLite2" or "(no offline match)"
        return out

    def _abuse(self, ip, timeout):
        token = self.config["abuseipdb_token"].strip()
        url = ("https://api.abuseipdb.com/api/v2/check?"
               + urllib.parse.urlencode({"ipAddress": ip, "maxAgeInDays": 90}))
        req = urllib.request.Request(url, headers={
            "Key": token, "Accept": "application/json",
            "User-Agent": "GeoNetMon/1.0",
        })
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                payload = json.loads(resp.read().decode("utf-8", "replace"))
            d = payload.get("data", {})
            return {
                "abuse_score": int(d.get("abuseConfidenceScore", 0) or 0),
                "abuse_reports": int(d.get("totalReports", 0) or 0),
            }
        except Exception:  # noqa: BLE001 — degrade gracefully
            return {}

    def _geo(self, ip, timeout):
        # Default to ipwho.is: free, HTTPS, NO token, returns lat/lon + org, and
        # tolerates continuous polling far better than ipinfo's unauthenticated
        # tier (which rate-limits to 429 within seconds under our load). Use
        # ipinfo only when the user has supplied a token (higher accuracy).
        token = self.config["ipinfo_token"].strip()
        if token:
            return self._geo_ipinfo(ip, timeout, token)
        return self._geo_ipwhois(ip, timeout)

    def _geo_ipwhois(self, ip, timeout):
        url = f"https://ipwho.is/{urllib.parse.quote(ip)}"
        req = urllib.request.Request(url, headers={
            "User-Agent": "GeoNetMon/1.0", "Accept": "application/json",
        })
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                payload = json.loads(resp.read().decode("utf-8", "replace"))
        except urllib.error.HTTPError as e:
            return {"org": "(rate limited)" if e.code == 429 else f"(geo HTTP {e.code})"}
        except Exception:  # noqa: BLE001 — network/parse failures degrade gracefully
            return {"org": "(geo unreachable)"}
        if not payload.get("success", False):
            msg = (payload.get("message") or "no data")[:48]
            return {"org": f"(geo: {msg})"}
        conn = payload.get("connection") if isinstance(payload.get("connection"), dict) else {}
        out = {
            "org": (conn.get("org") or conn.get("isp") or "") or "",
            "city": payload.get("city", "") or "",
            "country": payload.get("country_code", "") or "",
            "hostname": "",
        }
        lat, lng = payload.get("latitude"), payload.get("longitude")
        if isinstance(lat, (int, float)) and isinstance(lng, (int, float)):
            out["lat"] = float(lat)
            out["lng"] = float(lng)
        return out

    def _geo_ipinfo(self, ip, timeout, token):
        url = f"https://ipinfo.io/{urllib.parse.quote(ip)}/json?token=" + urllib.parse.quote(token)
        req = urllib.request.Request(url, headers={
            "User-Agent": "GeoNetMon/1.0", "Accept": "application/json",
        })
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                payload = json.loads(resp.read().decode("utf-8", "replace"))
        except urllib.error.HTTPError as e:
            return {"org": "(ipinfo rate limited)" if e.code == 429 else f"(ipinfo HTTP {e.code})"}
        except Exception:  # noqa: BLE001 — network/parse failures degrade gracefully
            return {"org": "(geo unreachable)"}
        out = {
            "org": payload.get("org", "") or "",
            "city": payload.get("city", "") or "",
            "country": payload.get("country", "") or "",
            "hostname": payload.get("hostname", "") or "",
        }
        loc = payload.get("loc", "")
        if loc and "," in loc:
            try:
                lat, lng = loc.split(",", 1)
                out["lat"] = float(lat)
                out["lng"] = float(lng)
            except ValueError:
                pass
        return out

    @staticmethod
    def _rdns(ip):
        # "" (not "Unknown") on failure: many CDN/cloud IPs — especially the
        # ones behind HTTPS on 443 — publish no PTR record at all, and the
        # display layer wants to fall back to other hostname sources.
        try:
            return socket.gethostbyaddr(ip)[0]
        except (OSError, socket.herror, socket.gaierror):
            return ""

    def shutdown(self):
        self.save_cache()
        for r in (self._city_reader, self._asn_reader):
            if r is not None:
                try:
                    r.close()
                except Exception:  # noqa: BLE001
                    pass
        self.pool.shutdown(wait=False, cancel_futures=True)
