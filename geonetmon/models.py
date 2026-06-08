"""GObject model for a connection row, plus geo/display helpers."""

import ipaddress
import time

from gi.repository import GObject

from . import ports


def human_bytes(n):
    """Compact size, e.g. 1.2 MB."""
    try:
        n = float(n)
    except (TypeError, ValueError):
        return ""
    if n < 1:
        return "0"
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return (f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}")
        n /= 1024
    return f"{n:.1f} TB"


def human_rate(bps):
    """bytes/sec -> compact rate, e.g. 1.2 MB/s. Blank when idle."""
    if not bps or bps < 1:
        return ""
    return human_bytes(bps) + "/s"


def classify_ip(ip: str) -> str:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return "invalid"
    if addr.is_loopback:
        return "loopback"
    if addr.is_link_local:
        return "link-local"
    if addr.is_multicast:
        return "multicast"
    if addr.is_unspecified:
        return "unspecified"
    if addr.is_private:
        return "private"
    return "public"


class ConnectionObject(GObject.Object):
    __gtype_name__ = "ConnectionObject"

    ip = GObject.Property(type=str, default="")
    proto = GObject.Property(type=str, default="")
    org = GObject.Property(type=str, default="…")
    location = GObject.Property(type=str, default="…")
    rdns = GObject.Property(type=str, default="…")
    direction = GObject.Property(type=str, default="")
    application = GObject.Property(type=str, default="")
    port = GObject.Property(type=int, default=0)
    service = GObject.Property(type=str, default="")
    encryption = GObject.Property(type=str, default="")
    state = GObject.Property(type=str, default="")
    pid = GObject.Property(type=int, default=0)
    country = GObject.Property(type=str, default="")
    is_new = GObject.Property(type=bool, default=False)
    is_foreign = GObject.Property(type=bool, default=False)
    rate_up = GObject.Property(type=GObject.TYPE_DOUBLE, default=0.0)    # bytes/s
    rate_down = GObject.Property(type=GObject.TYPE_DOUBLE, default=0.0)  # bytes/s
    total_up = GObject.Property(type=GObject.TYPE_INT64, default=0)
    total_down = GObject.Property(type=GObject.TYPE_INT64, default=0)
    risk = GObject.Property(type=int, default=-1)   # -1 unknown, 0..100 abuse score
    is_risky = GObject.Property(type=bool, default=False)
    lat = GObject.Property(type=GObject.TYPE_DOUBLE, default=0.0)
    lng = GObject.Property(type=GObject.TYPE_DOUBLE, default=0.0)
    has_geo = GObject.Property(type=bool, default=False)
    verdict = GObject.Property(type=str, default="")   # "allow"/"deny" from firewall

    def __init__(self, conn):
        super().__init__()
        self.key = conn.key
        self.local_ip = conn.local_ip
        self.local_port = conn.local_port
        self.remote_ip = conn.remote_ip
        self.remote_port = conn.remote_port
        self.geo_ip = conn.geo_ip
        self.raw = conn.raw
        self.first_seen = time.time()
        self.last_seen = self.first_seen
        self.enriched = False
        self._prev_sent = conn.bytes_sent
        self._prev_recv = conn.bytes_recv
        self._prev_ts = self.first_seen
        self.apply(conn)
        # IP shown is the remote when there is one, else the local bind.
        shown = conn.geo_ip or conn.local_ip
        self.set_property("ip", shown)
        self._init_local_labels()

    def apply(self, conn):
        """Update the volatile fields from a fresh collection."""
        self.set_property("proto", conn.proto)
        self.set_property("state", conn.state)
        self.set_property("direction", conn.direction)
        self.set_property("application", conn.app or "Unknown")
        self.set_property("port", conn.service_port)
        self.set_property("service", conn.service or "Ephemeral/Unknown")
        self.set_property("encryption", conn.encryption)
        self.set_property("pid", conn.pid)
        self._update_rates(conn)
        self.last_seen = time.time()

    def _update_rates(self, conn):
        """Derive bytes/sec from the change in cumulative counters."""
        now = time.time()
        dt = now - self._prev_ts
        sent, recv = conn.bytes_sent, conn.bytes_recv
        if dt > 0.05:
            # Counters reset (e.g. socket reused) -> treat negative delta as 0.
            up = max(0, sent - self._prev_sent) / dt
            down = max(0, recv - self._prev_recv) / dt
            self.set_property("rate_up", up)
            self.set_property("rate_down", down)
            self._prev_ts = now
            self._prev_sent = sent
            self._prev_recv = recv
        if sent:
            self.set_property("total_up", sent)
        if recv:
            self.set_property("total_down", recv)

    def _init_local_labels(self):
        """Set placeholder org/location for IPs we won't geolocate."""
        kind = classify_ip(self.geo_ip) if self.geo_ip else "none"
        if kind in ("none", "unspecified"):
            self.set_property("org", "—")
            self.set_property("location", "—")
            self.set_property("rdns", "—")
            self.set_property("country", "")
            self.enriched = True
        elif kind == "loopback":
            self.set_property("org", "Loopback")
            self.set_property("location", "localhost")
        elif kind == "private":
            self.set_property("org", "Private network")
            self.set_property("location", "LAN")
        elif kind == "link-local":
            self.set_property("org", "Link-local")
            self.set_property("location", "LAN")
        elif kind == "multicast":
            self.set_property("org", "Multicast")
            self.set_property("location", "—")

    def apply_enrichment(self, data, home_country):
        """data: dict with org/city/country/rdns from the Enricher."""
        org = data.get("org") or "Unknown"
        city = data.get("city") or ""
        cc = (data.get("country") or "").upper()
        rdns = data.get("rdns") or "Unknown"

        self.set_property("org", org)
        self.set_property("rdns", rdns)
        self.set_property("country", cc)

        if cc:
            flag = ports.flag_emoji(cc)
            label = f"{flag} {city}, {cc}".strip() if city else f"{flag} {cc}".strip()
            self.set_property("location", label)
            foreign = bool(home_country) and cc != home_country.upper()
            self.set_property("is_foreign", foreign)
        elif data.get("kind") == "public":
            self.set_property("location", "Unknown")

        if "abuse_score" in data:
            score = int(data.get("abuse_score", 0))
            self.set_property("risk", score)
            self.set_property("is_risky", score >= 25)
        if data.get("lat") is not None and data.get("lng") is not None:
            try:
                self.set_property("lat", float(data["lat"]))
                self.set_property("lng", float(data["lng"]))
                self.set_property("has_geo", True)
            except (TypeError, ValueError):
                pass
        self.enriched = True

    def search_blob(self):
        return " ".join((
            self.ip, self.org, self.location, self.rdns,
            self.application, self.service, self.proto, str(self.port),
        )).lower()
