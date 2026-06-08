<p align="center">
  <img src="https://raw.githubusercontent.com/jegly/GeoNetMon/main/images/geonetmon-banner.svg" alt="GeoNetMon" width="88%" />
</p>

[![Python](https://img.shields.io/badge/Python-3.10%2B-BD93F9.svg?logo=python&logoColor=white)](https://www.python.org)
[![GTK4](https://img.shields.io/badge/GTK4-PyGObject-8BE9FD.svg)](https://www.gtk.org)
[![Platform](https://img.shields.io/badge/Platform-Linux-FFB86C.svg?logo=linux&logoColor=white)]()
[![Wayland](https://img.shields.io/badge/Wayland-native-6272A4.svg)]()
[![Firewall](https://img.shields.io/badge/Firewall-nftables%20%2B%20NFQUEUE-FF5555.svg)]()
[![GeoIP](https://img.shields.io/badge/GeoIP-GeoLite2%20%2B%20ipinfo-50FA7B.svg)]()
[![Package](https://img.shields.io/badge/Package-.deb-6272A4.svg)]()

## Download

[![Download GeoNetMon .deb](https://img.shields.io/badge/Download-Latest_.deb-A6E3A1?style=for-the-badge&logo=linux&logoColor=1E1E2E)](https://github.com/jegly/GeoNetMon/releases/latest)

```bash
sudo dpkg -i geonetmon_<version>_all.deb
```

The package installs dependencies, creates the `geonetmon` system group, adds your user to it, and starts the background daemon. Log out and back in after install, then launch from your application menu or run `geonetmon`.

---

## What is GeoNetMon?

GeoNetMon is a GTK4 network monitor and interactive firewall for Linux. It has two modes:

**Monitor mode (shield off)** — a passive live view of every TCP and UDP connection on the machine. No packets are intercepted. Process name, destination country, organisation, reverse hostname, bandwidth, and risk score are shown per connection. This mode works without the daemon and without root.

**Enforcement mode (shield on)** — outbound connections are held in the kernel queue before they go through. A prompt window asks you to allow or deny, exactly like Little Snitch or OpenSnitch. Rules you create persist and auto-apply to future connections so you only see a prompt once per app (or per host/port, depending on how you configure it).

The GUI runs as your normal user in both modes. A small privileged daemon (`geonetmond`) handles packet interception via nftables and NFQUEUE and publishes process names to a world-readable file — the GUI never needs root.

> [!TIP]
> GeoNetMon works well alongside a traditional firewall. Use GeoNetMon for real-time interactive decisions — allow or deny a specific app's connection the moment it happens — and your firewall for persistent blanket rules (block a port, restrict a range). GeoNetMon supports **UFW**, **nftables**, and **iptables** as backends for its manual IP block feature. UFW is recommended for most users as blocks are written as proper UFW rules and survive reboots; nftables and iptables blocks are re-applied from GeoNetMon's own record on each change.

---

## Screenshots

<div align="center">

<table>
  <tr>
    <td align="center"><img src="https://raw.githubusercontent.com/jegly/GeoNetMon/main/images/overview.png" width="420"/><br/><sub>Overview — light mode</sub></td>
    <td align="center"><img src="https://raw.githubusercontent.com/jegly/GeoNetMon/main/images/overview_darkmode.png" width="420"/><br/><sub>Overview — dark mode with past connections</sub></td>
  </tr>
  <tr>
    <td align="center"><img src="https://raw.githubusercontent.com/jegly/GeoNetMon/main/images/allow_deny_popup.png" width="420"/><br/><sub>Allow / deny prompt</sub></td>
    <td align="center"><img src="https://raw.githubusercontent.com/jegly/GeoNetMon/main/images/overview_connection_allowed_notification.png" width="420"/><br/><sub>Connection allowed — GNOME notification</sub></td>
  </tr>
  <tr>
    <td align="center"><img src="https://raw.githubusercontent.com/jegly/GeoNetMon/main/images/connection_Details_darkmode.png" width="420"/><br/><sub>Connection details</sub></td>
    <td align="center"><img src="https://raw.githubusercontent.com/jegly/GeoNetMon/main/images/darkmode_statistics.png" width="420"/><br/><sub>Statistics</sub></td>
  </tr>
  <tr>
    <td align="center"><img src="https://raw.githubusercontent.com/jegly/GeoNetMon/main/images/blocklist.png" width="420"/><br/><sub>Blocklist subscriptions</sub></td>
    <td align="center"><img src="https://raw.githubusercontent.com/jegly/GeoNetMon/main/images/darkmode_overview_preferences.png" width="420"/><br/><sub>Preferences — appearance</sub></td>
  </tr>
  <tr>
    <td align="center"><img src="https://raw.githubusercontent.com/jegly/GeoNetMon/main/images/overview_darkmode_pref.png" width="420"/><br/><sub>Preferences — alerts and history</sub></td>
    <td></td>
  </tr>
</table>

</div>

---

## Core Features

### Live connection table

All active TCP and UDP sockets, refreshed on a configurable interval. Each row shows:

- Process name and PID
- Local and remote address
- Destination hostname (reverse DNS)
- Country and organisation (GeoIP)
- Country flag
- Protocol and port service name
- Direction (outbound / incoming / listening)
- Encryption status
- Live upload and download rate
- Risk score (AbuseIPDB — requires API key)
- Enforcement verdict (allowed / blocked / pending)
- Connection state

Columns are individually toggleable. New connections flash briefly on arrival. A search bar and quick-filter pills (TCP, UDP, outgoing, incoming, listening) let you narrow the table in real time. The status bar shows live aggregate throughput and a sparkline of connection count over time.

### Monitor mode vs enforcement mode

| | Monitor (shield off) | Enforcement (shield on) |
|---|---|---|
| Daemon required | No — degrades gracefully | Yes |
| Packets intercepted | No | Yes — held until you decide |
| Rules applied | No | Yes |
| Process names visible | Yes (via `/run/geonetmon-procs.json`) | Yes |
| Works without root | Yes | Yes (daemon runs as root, GUI does not) |

Switching the shield on without the daemon running shows a status message and leaves the app in monitor mode.

### Interactive firewall (enforcement mode)

Outbound connections are held in the kernel queue until you respond. A prompt window appears with the process name, destination, country, and port. If the window is minimised or behind another window, a GNOME desktop notification fires — clicking it raises the prompt directly, with no lag.

**How long the rule lasts:**

| Scope | Meaning |
|---|---|
| Once | This connection only — not saved |
| Until the app quits | Active while the process is running |
| Until restart | Survives app restarts, cleared on reboot |
| Forever | Written to disk, applied automatically from then on |

**What the rule covers:**

| Apply to | Meaning |
|---|---|
| Any connection | Any outbound connection from this app |
| Connections to this host | This app to this destination only |
| Connections on this port | This app on this port, any host |
| Only this connection | Exact — this app, this host, this port |

A plain-English summary under the dropdowns describes the exact rule before you confirm. An auto-timeout acts if you don't answer — the action (allow or deny) and duration are configurable.

### DNS-aware prompts

The daemon sniffs DNS responses so prompts say `firefox → github.com` on the very first packet, not a bare IP. Blind spot: DNS-over-HTTPS/TLS is encrypted and invisible, same limitation as Little Snitch.

### Binary integrity

When you allow an application, its executable is SHA-256-pinned. If that binary changes later, the prompt flags it — a replaced binary cannot inherit an existing allow rule.

### Manual IP blocking

Separate from enforcement. Right-click any row in the connection table and choose **Block IP** to immediately drop all traffic to and from that remote address. The block goes through whichever firewall backend is configured in Settings (ufw, nftables, or iptables — auto-detected by default). UFW blocks survive reboots; nftables blocks are re-applied declaratively from GeoNetMon's own record. Blocked IPs are listed and removable from the Firewall manager.

### Right-click context menu

Right-clicking any connection row opens a context menu with:

- **Allow / Deny** — create a quick permanent rule for this connection without going through the full prompt
- **Filter to this app** — narrow the table to show only connections from this process
- **Block / Unblock IP** — immediate firewall block on the remote IP
- **Whois** — open an in-app whois lookup for the remote IP
- **Kill process** — send SIGTERM to the owning process

### GNOME notifications

Notifications for allow/deny prompts appear at the desktop level — visible even when the app is minimised or behind other windows. Clicking the notification raises only the small prompt window directly. Notification behaviour for manual decisions, auto-allowed connections, and auto-denied connections are each independently toggled in Settings.

### Alerts

GNOME desktop notifications and an in-app alert log for:

- A new application making its first outbound connection
- A connection to a new country
- A connection flagged high-risk by AbuseIPDB
- Incoming connections
- Unencrypted connections to foreign hosts

Each alert type is individually toggled in Settings.

### Blocklist subscriptions

Subscribe to domain blocklists in hosts or plain-domain format. Subscribed domains become deny rules matched before any outbound connection is allowed. Your own allow rules always take priority.

Fourteen presets included:

| Category | Lists |
|---|---|
| Ads and tracking | StevenBlack, AdGuard DNS, OISD basic, OISD big, Hagezi Pro, Hagezi Ultimate, Peter Lowe, Disconnect.me, EasyPrivacy, Fanboy Annoyances |
| Malware and phishing | URLhaus, Phishing Army, Hagezi Threat Intelligence Feeds |
| Combined | StevenBlack (ads + malware + social + explicit) |

Any hosts-format or plain-domain URL can be added.

### Firewall rules

A rules table for viewing, adding, editing, and deleting named allow/deny rules. Rules can target a process binary, destination host, destination port, or any combination. Specificity ordering is automatic — more specific rules win over broader ones. Rules persist to `~/.config/geonetmon/rules.json` and can be exported and imported as JSON.

### Past connections panel

A collapsible in-session panel below the live table shows connections that appeared and then closed during the current session. Each entry can be expanded for full detail. The list can be cleared manually and does not persist across restarts (connection history is in the History tab instead).

### World connection map

An equirectangular map with great-circle arcs from your location to each geolocated remote, coloured by direction, foreign, or high-risk status. A CC0 coastline is bundled — no network calls or extra assets required. Set your home country in Settings to place the origin marker.

### Statistics

Top applications, remote hosts, and countries over a selectable window (hour / day / week / month), plus an activity graph, all from the local history database.

### Connection history

Past connections logged to a local SQLite database. Retention defaults to 30 days.

### GeoIP

Two backends:

- **GeoLite2 (offline)** — point the app at a local `GeoLite2-City.mmdb` and optionally `GeoLite2-ASN.mmdb`. No internet required after download. Preferred when configured.
- **ipinfo.io (online)** — optional API token for higher rate limits.

Both backends cache results locally for 7 days. Private, loopback, and link-local IPs are resolved locally and never sent to any external service.

### CSV export

The **Export** option in the menu saves all currently visible rows to a CSV file, including every column.

### Pause and resume

A pause button in the header stops the table from refreshing without closing the app. Useful when inspecting a specific connection without the list moving under you.

### Themes

System (follows your GTK dark/light setting), Dracula, and all four Catppuccin flavours — Latte, Frappé, Macchiato, Mocha — with configurable accent colours. Switch live in Settings, no restart needed.

### System tray

Optional system tray icon with show/hide, toggle enforcement, and quit. Requires `gir1.2-ayatanaappindicator3-0.1`.

---

## Architecture

```
geonetmond  (root daemon, systemd service)
  ├── nftables NFQUEUE hook — holds outbound packets pending a decision
  ├── procmap — resolves PIDs via /proc/net/tcp and /proc/net/udp socket inodes
  ├── DNS sniffer — caches hostname from DNS responses before the first packet
  ├── publishes process names → /run/geonetmon-procs.json  (world-readable)
  └── Unix socket /run/geonetmon.sock  (NDJSON, group geonetmon, mode 0660)

geonetmon  (GUI, unprivileged, geonetmon group required for enforcement)
  ├── reads /run/geonetmon-procs.json for process names without needing root
  ├── connects to /run/geonetmon.sock to send allow/deny verdicts
  └── GeoIP enrichment, rDNS, bandwidth tracking, rule evaluation, UI
```

If the daemon is not running, the GUI starts in monitor mode automatically — all passive features work, enforcement is unavailable.

---

## Install

### From the .deb

```bash
sudo dpkg -i geonetmon_<version>_all.deb
```

If `dpkg` reports missing dependencies:

```bash
sudo apt install -f
```

Log out and back in after install for group membership to take effect.

### Dependencies

**Required (installed automatically by the .deb):**

| Package | Purpose |
|---|---|
| `python3 >= 3.10` | Runtime |
| `python3-gi` | GTK bindings (PyGObject) |
| `python3-gi-cairo` | Cairo renderer |
| `gir1.2-gtk-4.0` | GTK4 typelib |
| `iproute2` | `ss` for socket enumeration |

**Recommended (required for enforcement and offline GeoIP):**

| Package | Purpose |
|---|---|
| `nftables` | Required for the allow/deny enforcement engine (NFQUEUE) |
| `python3-netfilterqueue` | NFQUEUE Python bindings (enforcement only) |
| `python3-maxminddb` | Offline GeoLite2 database support |
| `pkexec` or `policykit-1` | Privilege escalation for daemon management |
| `ufw` | Optional backend for manual IP blocking |

**Optional:**

| Package | Purpose |
|---|---|
| `gir1.2-ayatanaappindicator3-0.1` | System tray icon |

### Enabling enforcement

The .deb postinst enables the daemon automatically. To manage it manually:

```bash
sudo systemctl start geonetmond
sudo systemctl enable geonetmond
```

Then click the shield button in the app header to begin intercepting connections.

### GeoLite2 (offline GeoIP)

1. Download `GeoLite2-City.mmdb` (and optionally `GeoLite2-ASN.mmdb`) from [MaxMind](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data) — free account required
2. Open Settings and set the path under GeoIP

---

## Settings reference

| Key | Default | Description |
|---|---|---|
| `refresh_ms` | 2000 | Connection table refresh interval in milliseconds |
| `paused_on_start` | false | Start with monitoring paused |
| `max_rows` | 0 | Maximum rows in the live table (0 = unlimited) |
| `show_tcp` / `show_udp` | true | Show TCP / UDP connections |
| `show_listen` | true | Show listening sockets |
| `show_timewait` | false | Show TIME-WAIT and CLOSE-WAIT sockets |
| `hide_loopback` | false | Hide loopback connections |
| `resolve_geo` | true | Resolve country and organisation per connection |
| `resolve_rdns` | true | Resolve reverse hostnames |
| `ipinfo_token` | "" | ipinfo.io API token (optional, for higher rate limits) |
| `abuseipdb_token` | "" | AbuseIPDB API key (required for risk scoring) |
| `geoip_db_path` | "" | Path to local GeoLite2-City.mmdb |
| `geoip_asn_db_path` | "" | Path to local GeoLite2-ASN.mmdb |
| `home_country` | "" | Your two-letter country code — foreign connections are flagged |
| `cache_ttl_hours` | 168 | GeoIP and rDNS cache lifetime in hours (default 7 days) |
| `firewall_backend` | auto | Backend for manual IP blocking: `auto` / `ufw` / `nftables` / `iptables` — does not affect the enforcement engine, which always uses nftables + NFQUEUE |
| `enforce_enabled` | false | Enable the interactive firewall |
| `enforce_default_action` | prompt | What to do with unmatched connections: `prompt` / `allow` / `deny` |
| `enforce_prompt_timeout_s` | 90 | Seconds before auto-deciding if a prompt is not answered |
| `enforce_timeout_action` | deny | Action on prompt timeout: `allow` or `deny` |
| `enforce_default_scope` | forever | Default rule duration shown in prompts |
| `enforce_default_scope_by` | app_any | Default rule scope shown in prompts |
| `enforce_skip_dns` | true | Never prompt on DNS queries (port 53) |
| `enforce_skip_loopback` | true | Never enforce on loopback traffic |
| `enforce_fail_open` | true | Accept traffic if the enforcement engine dies |
| `enforce_notify_prompt` | true | GNOME notification when a prompt fires |
| `enforce_notify_allow` | true | GNOME notification on manual allow decisions |
| `enforce_notify_allow_auto` | false | GNOME notification on auto-allowed connections (existing rule matched) |
| `enforce_notify_deny` | true | GNOME notification on manual deny decisions |
| `enforce_notify_deny_auto` | false | GNOME notification on auto-denied connections (off by default to avoid spam) |
| `history_keep_days` | 30 | Connection history retention in days |
| `highlight_seconds` | 5 | How long new connection rows flash before settling |
| `theme` | system | UI theme: `system` / `dracula` / `catppuccin-mocha` / etc. |
| `run_in_background` | false | Keep running when the window is closed |
| `silent_mode` | false | Suppress all desktop notifications |

Config is stored at `~/.config/geonetmon/config.json`.

---

## Build from source

```bash
git clone https://github.com/jegly/GeoNetMon
cd GeoNetMon
bash packaging/build-deb.sh
sudo dpkg -i geonetmon_1.0.0_all.deb
```

Requires `dpkg-deb` and Python 3.10+ on the build machine. No compiled components — the package is pure Python.

---

## Technology stack

| Component | Technology |
|---|---|
| GUI | Python 3, GTK4 (PyGObject) |
| Packet interception | nftables + NFQUEUE (`python3-netfilterqueue`) |
| Process resolution | `/proc/net/tcp` and `/proc/net/udp` socket inode scanning |
| GeoIP offline | MaxMind GeoLite2 (`python3-maxminddb`) |
| GeoIP online | ipinfo.io |
| Risk scoring | AbuseIPDB API |
| Manual IP blocking | ufw / nftables / iptables (auto-detected) |
| Rule storage | JSON (`~/.config/geonetmon/rules.json`) |
| Connection history | SQLite |
| IPC protocol | Unix socket, NDJSON |
| System integration | systemd, `Gio.Notification` (GNOME), AppIndicator |
| Themes | Pure GTK4 CSS with `@define-color` palettes |

---

## License

GPL 3.0 
