🌍 GeoNetstat


A Bash-based geo-aware connection analyzer for Ubuntu/Debian systems



📖 Overview


GeoNetstat extends traditional netstat and ss functionality by adding geolocation, organization lookup, reverse DNS, and process information for each active network connection.


It provides both a whiptail-powered interactive menu and command-line mode, making it easy to explore your system's incoming and outgoing connections — and see where they lead.



✨ Features


🧭 Interactive menu (Whiptail GUI) for connection mode selection
🌍 IP geolocation and organization info via ipinfo.io
🔎 Reverse DNS resolution for remote hosts
🔄 Combines ss and netstat outputs for full coverage
🧩 Displays process/application names linked to each connection
📡 Detects connection direction (incoming vs outgoing)
⚡ Works on Ubuntu/Debian-based systems out of the box



🧰 Dependencies


Install required packages:


sudo apt install curl jq net-tools iproute2 dnsutils whiptail




🚀 Usage


🪟 Interactive Menu Mode


Run without arguments to launch the GeoNetstat Whiptail GUI menu:


sudo /path/to/geonetstat.sh



You'll see an interactive menu like this:


Choose a connection type:

  ss -tn          Show TCP connections (ss)
  ss -un          Show UDP connections (ss)
  ss -tulnp       Show all listening connections (ss)
  netstat -tn     Show TCP connections (netstat)
  netstat -un     Show UDP connections (netstat)
  netstat -tulnp  Show all listening connections (netstat)
  all             Run all above sequentially



💻 Command-Line Mode


You can also run specific modes directly (bypassing the menu):


sudo /path/to/geonetstat.sh ss -un



Or using netstat:


sudo /path/to/geonetstat.sh netstat -tulnp




📋 Example Output




IP Address
Organization
Location
Reverse DNS
Direction
Application




8.8.8.8
AS15169 Google LLC
Mountain View, US
dns.google
OUTGOING
systemd-resolve


192.168.0.5
Local Network
Local, LAN
router.local
INCOMING
sshd





🧠 How It Works


Collects active connections from ss or netstat
Identifies local vs remote IPs to determine direction
Queries ipinfo.io for organization, city, and country
Performs reverse DNS lookups with host
Extracts process/application names
Displays results in a clean, aligned table



👨‍💻 Author


Developed by GLOBALCVE


"See who your system is talking to — and where they are."



💡 Tips


Run as root for full process visibility
Use all from the menu to aggregate all connection types
Useful for quick network audits or security monitoring
