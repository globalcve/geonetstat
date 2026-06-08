"""Static lookups: port->service, encryption classification, country helpers."""

# Port -> human service name. Extends the map from the original shell script.
PORTMAP = {
    20: "FTP-data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 67: "DHCP-server", 68: "DHCP-client", 69: "TFTP",
    80: "HTTP", 110: "POP3", 111: "rpcbind", 123: "NTP",
    137: "NetBIOS-ns", 138: "NetBIOS-dgm", 139: "NetBIOS-ssn",
    143: "IMAP", 161: "SNMP", 389: "LDAP", 443: "HTTPS",
    445: "SMB", 465: "SMTPS", 514: "Syslog", 587: "Submission",
    631: "IPP", 636: "LDAPS", 853: "DoT", 873: "rsync", 993: "IMAPS",
    995: "POP3S", 1080: "SOCKS", 1194: "OpenVPN", 1433: "MSSQL",
    1521: "Oracle", 1883: "MQTT", 2049: "NFS", 3128: "Squid",
    3306: "MySQL", 3389: "RDP", 4433: "HTTPS-alt", 4443: "HTTPS-alt",
    5060: "SIP", 5061: "SIPS", 5222: "XMPP", 5353: "mDNS",
    5432: "PostgreSQL", 5900: "VNC", 6379: "Redis", 6443: "k8s-API",
    8080: "HTTP-proxy", 8443: "HTTPS-alt", 8883: "MQTT-TLS",
    9200: "Elasticsearch", 9300: "ES-Transport", 10000: "Webmin",
    11211: "Memcached", 27017: "MongoDB", 51820: "WireGuard",
}

# Services that are encrypted by design (TLS/SSH/etc.).
ENCRYPTED_SERVICES = {
    "SSH", "HTTPS", "SMTPS", "IMAPS", "POP3S", "LDAPS", "DoT", "SIPS",
    "HTTPS-alt", "RDP", "MQTT-TLS", "OpenVPN", "WireGuard", "k8s-API",
}
# Ports that are encrypted regardless of a named service.
ENCRYPTED_PORTS = {443, 853, 993, 995, 465, 990, 992, 5061, 6443, 8443}

# App names (lowercase, substring match) that are always encrypted regardless
# of which port they happen to use (DNSCrypt, VPN daemons, etc.).
ENCRYPTED_APP_SUBSTRINGS = {
    "dnscrypt", "dnscrypt-proxy", "cloudflared", "stubby",
    "unbound", "coredns", "pihole",
}


def service_for(port: int) -> str:
    return PORTMAP.get(port, "")


def encryption_for(port: int, app: str = "") -> str:
    if app and any(s in app.lower() for s in ENCRYPTED_APP_SUBSTRINGS):
        return "Encrypted"
    service = service_for(port)
    if service in ENCRYPTED_SERVICES or port in ENCRYPTED_PORTS:
        return "Encrypted"
    if service:
        return "Plain"
    return "Unknown"


def flag_emoji(cc: str) -> str:
    """Convert a 2-letter ISO country code into a flag emoji."""
    cc = (cc or "").strip().upper()
    if len(cc) != 2 or not cc.isalpha():
        return ""
    base = 0x1F1E6
    return chr(base + ord(cc[0]) - ord("A")) + chr(base + ord(cc[1]) - ord("A"))


# Common subset; falls back to the raw code for anything not listed.
COUNTRY_NAMES = {
    "US": "United States", "GB": "United Kingdom", "DE": "Germany",
    "FR": "France", "NL": "Netherlands", "IE": "Ireland", "CA": "Canada",
    "AU": "Australia", "JP": "Japan", "CN": "China", "RU": "Russia",
    "IN": "India", "BR": "Brazil", "SG": "Singapore", "KR": "South Korea",
    "SE": "Sweden", "NO": "Norway", "FI": "Finland", "DK": "Denmark",
    "PL": "Poland", "ES": "Spain", "IT": "Italy", "CH": "Switzerland",
    "AT": "Austria", "BE": "Belgium", "CZ": "Czechia", "RO": "Romania",
    "UA": "Ukraine", "TR": "Turkey", "ZA": "South Africa", "MX": "Mexico",
    "AR": "Argentina", "HK": "Hong Kong", "TW": "Taiwan", "ID": "Indonesia",
    "VN": "Vietnam", "TH": "Thailand", "IL": "Israel", "AE": "UAE",
    "SA": "Saudi Arabia", "NZ": "New Zealand", "PT": "Portugal",
    "GR": "Greece", "HU": "Hungary", "BG": "Bulgaria", "LU": "Luxembourg",
}


def country_name(cc: str) -> str:
    cc = (cc or "").upper()
    return COUNTRY_NAMES.get(cc, cc)


# Approx capital-city coordinates (lon, lat) for placing the "home" marker on
# the map when a home country is set. Covers common cases; extend as needed.
CAPITAL_COORDS = {
    "US": (-77.04, 38.91), "GB": (-0.13, 51.51), "CA": (-75.70, 45.42),
    "AU": (149.13, -35.28), "DE": (13.40, 52.52), "FR": (2.35, 48.86),
    "NL": (4.90, 52.37), "ES": (-3.70, 40.42), "IT": (12.50, 41.90),
    "SE": (18.07, 59.33), "NO": (10.75, 59.91), "FI": (24.94, 60.17),
    "DK": (12.57, 55.68), "IE": (-6.26, 53.35), "CH": (7.45, 46.95),
    "AT": (16.37, 48.21), "BE": (4.35, 50.85), "PL": (21.01, 52.23),
    "PT": (-9.14, 38.72), "RU": (37.62, 55.75), "UA": (30.52, 50.45),
    "JP": (139.69, 35.69), "CN": (116.41, 39.90), "KR": (126.98, 37.57),
    "IN": (77.21, 28.61), "SG": (103.82, 1.35), "HK": (114.17, 22.32),
    "BR": (-47.93, -15.78), "MX": (-99.13, 19.43), "AR": (-58.38, -34.60),
    "ZA": (28.05, -26.20), "NG": (7.49, 9.06), "EG": (31.24, 30.04),
    "AE": (54.37, 24.45), "IL": (34.78, 32.08), "TR": (32.85, 39.93),
    "NZ": (174.78, -41.29), "TW": (121.56, 25.03), "TH": (100.50, 13.75),
    "ID": (106.85, -6.21), "MY": (101.69, 3.14), "PH": (120.98, 14.60),
    "CZ": (14.42, 50.08), "GR": (23.73, 37.98), "RO": (26.10, 44.43),
    "HU": (19.04, 47.50), "CL": (-70.65, -33.45), "CO": (-74.07, 4.71),
}


def capital_coords(cc):
    """(lon, lat) for a country's capital, or None if unknown/blank."""
    cc = (cc or "").upper()
    return CAPITAL_COORDS.get(cc)
