 <p align="center">
  <img src="https://github.com/globalcve/geonetstat/blob/main/GeoNetstat.png" alt="GeoNetstat Banner" />
</p>



<p align="center">
  <img src="https://img.shields.io/badge/Shell-Bash-4EAA25?logo=gnu-bash&logoColor=white" />
  <img src="https://img.shields.io/badge/Tool-Netstat%2Fss-blue" />
  <img src="https://img.shields.io/badge/GeoIP-ipinfo.io-lightgrey" />
  <img src="https://img.shields.io/github/license/globalcve/geonetstat" />
  <img src="https://img.shields.io/badge/Branch-Stable-green?logo=github&logoColor=white" />
  <img src="https://img.shields.io/github/last-commit/globalcve/geonetstat" />
</p>


**See who your system is talking to — and where they are.**



## Why GeoNetstat vs. nmap/Wireshark

GeoNetstat isn’t meant to replace heavyweight tools like **nmap** or **Wireshark** — it’s designed as a **lightweight edition** for everyday visibility:

| Tool        | Typical Use Case              | What You Get                                                                 | Overhead                                                   |
|-------------|-------------------------------|-------------------------------------------------------------------------------|------------------------------------------------------------|
| **nmap**    | Active scanning of hosts/networks | Port scans, service detection, vulnerability probing                          | Requires elevated privileges, can be intrusive             |
| **Wireshark** | Full packet capture & analysis | Deep protocol inspection, traffic replay, forensic detail                      | Heavy GUI, large captures, steep learning curve            |
| **GeoNetstat** | Quick connection awareness    | IP, Org, Location, Reverse DNS, Direction, Application, Port→Service mapping, Encryption flag, STE (A/L/I) | Lightweight, terminal‑only, no packet capture, no intrusive scans |

### > Lightweight / Minimal Dependencies 

- **No root scans or packet captures** — it simply enriches what your system already knows (`ss`/`netstat`).
- **Human‑readable enrichment** — org, geo, reverse DNS, service mapping, encryption flags.
- **Compact state indicator (STE)** — shows Active, Listening, or Inactive at a glance.
- **Menu‑driven workflow** — ncurses interface makes it easy to run multiple views without memorizing flags.
- **Contributor‑friendly** — simple Bash, clear dependencies, easy to extend.

Think of GeoNetstat as the **“fast visibility layer”**: when you don’t need a full scan or packet dump, but you *do* want to know who you’re talking to, what port, what service, and whether it’s encrypted — instantly, in your terminal.


GeoNetstat isn't just another netstat wrapper. It's a geo-aware connection analyzer that brings transparency to your network traffic with geolocation, organization lookup, and reverse DNS — all in a clean, interactive interface.
![GeoNetStat Menu](https://github.com/globalcve/geonetstat/raw/main/geonetstat_menu.png)


---

## > Simple, yet powerful

- **Multi-layer visibility**  
  We combine `ss` and `netstat` outputs with IP geolocation, organization data, and reverse DNS — with full process attribution.

- **Interactive by design**  
  Whiptail-powered GUI menu for quick connection analysis, plus full command-line support for automation.

- **Security-first approach**  
  Know exactly which processes are talking to which organizations, in which countries — essential for security audits and monitoring.

- **Lightweight and fast**  
  Pure Bash with minimal dependencies. Works on any Ubuntu/Debian system out of the box.

- **Built for sysadmins**  
  No bloat, no complexity. Just clean, actionable network intelligence when you need it.

---

## > Quick Start

A network connection analyzer that shows geolocation, organization info, and process details for every active connection on your system.

**Features:**
- 🧭 Interactive Whiptail GUI menu for connection mode selection
- 🌍 IP geolocation and organization info via [ipinfo.io](https://ipinfo.io)
- 🔎 Reverse DNS resolution for remote hosts
- 🔄 Combines `ss` and `netstat` outputs for full coverage
- 🧩 Process/application names linked to each connection
- 📡 Connection direction detection (incoming vs outgoing)
- ⚡ Works on Ubuntu/Debian-based systems
- 🔒 Port dictionary & encryption detection — maps common ports to services and flags encrypted protocols.
- 📊 Compact state indicator (STE) — shows connection state as Active (A), Listening (L), or Inactive (I).

---

## > Installation

**Dependencies:**

```bash
sudo apt install curl jq net-tools iproute2 dnsutils whiptail
```

**Download and run:**

```bash
# Clone the repository
git clone https://github.com/yourusername/geonetstat.git
cd geonetstat

# Make executable
chmod +x geonetstat.sh

# Run with sudo for full visibility
sudo ./geonetstat.sh
```

---

## > Usage

### Interactive Menu Mode

Run without arguments to launch the interactive menu:

```bash
sudo ./geonetstat.sh
```

You'll see options for:
- `ss -tn` — Show TCP connections (ss)
- `ss -un` — Show UDP connections (ss)
- `ss -tulnp` — Show all listening connections (ss)
- `netstat -tn` — Show TCP connections (netstat)
- `netstat -un` — Show UDP connections (netstat)
- `netstat -tulnp` — Show all listening connections (netstat)
- `all` — Run all above sequentially

### Command-Line Mode

Run specific modes directly:

```bash
sudo ./geonetstat.sh ss -un
sudo ./geonetstat.sh netstat -tulnp
```

---

## > Example Output

| IP Address | Organization | Location | Reverse DNS | Direction | Application |
|------------|--------------|----------|-------------|-----------|-------------|
| 8.8.8.8 | AS15169 Google LLC | Mountain View, US | dns.google | OUTGOING | systemd-resolve |
| 192.168.0.5 | Local Network | Local, LAN | router.local | INCOMING | sshd |
| 104.16.132.229 | AS13335 Cloudflare | San Francisco, US | cloudflare.com | OUTGOING | firefox |

**How it works:**
1. Collects active connections from `ss` or `netstat`
2. Identifies local vs remote IPs to determine direction
3. Queries ipinfo.io for organization, city, and country
4. Performs reverse DNS lookups with `host`
5. Extracts process/application names
6. Displays results in a clean, aligned table

---

## > Contributing

We welcome PRs, bug fixes, and feature improvements. Whether you're adding new functionality, improving performance, or fixing issues — we'd love your help.

**Areas we'd love help with:**
- Additional geolocation providers
- Export options (CSV, JSON)
- Connection filtering and search
- Performance optimizations

---

## > Hot Tips

- Run as root (`sudo`) for full process visibility
- Use `all` from the menu to aggregate all connection types
- Great for quick network audits and security monitoring
- Combine with other tools like `iptables` or `tcpdump` for deeper analysis

---

## > Contact :D

- GitHub: [@globalcve](https://github.com/globalcve)
- Email: globalcve@gmail.com

---

Built with transparency, minimalism, and respect for network visibility.
