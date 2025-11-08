#!/bin/bash

## Dependencies:
## - curl: for querying ipinfo.io
## - jq: for parsing JSON responses
## - net-tools: for netstat
## - iproute2: for ss and ip
## - dnsutils: for reverse DNS via host
## - grep (with Perl regex support): for extracting process names
## - whiptail: for interactive menu (install via: sudo apt install whiptail)

# If no arguments, show menu
if [[ $# -eq 0 ]]; then
  CHOICE=$(whiptail --title "Connection Lookup Menu" --menu "Choose a connection type:" 20 78 10 \
    "ss -tn"        "Show TCP connections (ss)" \
    "ss -un"        "Show UDP connections (ss)" \
    "ss -tulnp"     "Show all listening connections with process info (ss)" \
    "netstat -tn"   "Show TCP connections (netstat)" \
    "netstat -un"   "Show UDP connections (netstat)" \
    "netstat -tulnp" "Show all listening connections with process info (netstat)" \
    "all"           "Run all above sequentially" \
    3>&1 1>&2 2>&3)

  [[ $? -ne 0 ]] && echo "Cancelled." && exit 1

  if [[ "$CHOICE" == "all" ]]; then
    for CMD in "ss -tn" "ss -un" "ss -tulnp" "netstat -tn" "netstat -un" "netstat -tulnp"; do
      echo -e "\nRunning: $CMD"
      "$0" $CMD
    done
    exit 0
  fi

  set -- $CHOICE  # Reassign arguments for lookup logic
fi

# Parse command and args
CMD="$1"
ARGS="${@:2}"

# Get local IPs to compare against
LOCAL_IPS=$(ip -4 addr | awk '/inet/ {print $2}' | cut -d/ -f1)

# Extract full connection info including process name
if [[ "$CMD" == "netstat" ]]; then
  # Proto Local Remote State PID/Program
  CONNS=$(netstat $ARGS -p | awk 'NR>2 {print $1, $4, $5, $6, $7}')
else
  # Proto Local Remote State users:(("proc",pid,...))
  CONNS=$(ss $ARGS -p | awk 'NR>1 {print $1, $4, $5, $6}')
fi

# Port→Service dictionary
declare -A portmap=(
  [20]="FTP-data" [21]="FTP" [22]="SSH" [23]="Telnet" [25]="SMTP"
  [53]="DNS" [67]="DHCP-server" [68]="DHCP-client" [69]="TFTP"
  [80]="HTTP" [110]="POP3" [111]="rpcbind" [123]="NTP"
  [137]="NetBIOS-ns" [138]="NetBIOS-dgm" [139]="NetBIOS-ssn"
  [143]="IMAP" [161]="SNMP" [389]="LDAP" [443]="HTTPS"
  [445]="SMB" [465]="SMTPS" [514]="Syslog" [587]="Submission"
  [631]="IPP" [636]="LDAPS" [873]="rsync" [993]="IMAPS"
  [995]="POP3S" [1080]="SOCKS" [1433]="MSSQL" [1521]="Oracle"
  [2049]="NFS" [3128]="Squid" [3306]="MySQL" [3389]="RDP"
  [5432]="PostgreSQL" [5900]="VNC" [6379]="Redis" [8080]="HTTP-proxy"
  [8443]="HTTPS-alt" [9200]="Elasticsearch" [9300]="ES-Transport"
  [10000]="Webmin" [11211]="Memcached"
)

# Map full state to compact STE flag
short_state() {
  case "$1" in
    ESTAB|CLOSE-WAIT|TIME-WAIT) echo "A" ;;   # Active
    LISTEN) echo "L" ;;                       # Listening
    *) echo "I" ;;                            # Inactive/other
  esac
}

# Print header (fixed widths, no truncation)
printf "%-16s %-8s %-30s %-20s %-30s %-10s %-20s %-6s %-15s %-12s %-3s\n" \
"IP Address" "Proto" "Organization" "Location" "Reverse DNS" "Direction" "Application" "Port" "Service" "Encryption" "STE"
echo "----------------------------------------------------------------------------------------------------------------------------------------------------------------------"

# Loop through connections
echo "$CONNS" | while read PROTO LOCAL REMOTE STATE PROC; do
  IP=$(echo "$REMOTE" | cut -d: -f1)
  PORT=$(echo "$REMOTE" | awk -F: '{print $NF}')
  [[ "$IP" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || continue

  INFO=$(curl -s "https://ipinfo.io/$IP/json")
  ORG=$(echo "$INFO" | jq -r '.org // "Unknown"')
  CITY=$(echo "$INFO" | jq -r '.city // "Unknown"')
  COUNTRY=$(echo "$INFO" | jq -r '.country // "Unknown"')

  RDNS=$(host "$IP" 2>/dev/null | awk '/domain name pointer/ {print $5}' | sed 's/\.$//' )
  [[ -z "$RDNS" ]] && RDNS="Unknown"

  DIR="OUTGOING"
  for LIP in $LOCAL_IPS; do
    if [[ "$IP" == "$LIP" ]]; then
      DIR="INCOMING"
      break
    fi
  done

  if [[ "$CMD" == "netstat" ]]; then
    APP=$(echo "$PROC" | cut -d/ -f2)
  else
    APP=$(echo "$PROC" | grep -oP 'users:\(\("\K[^"]+')
  fi
  [[ -z "$APP" || "$APP" == "-" ]] && APP="Unknown"

  SERVICE=${portmap[$PORT]:-"Ephemeral/Unknown"}
  case "$SERVICE" in
    HTTPS|IMAPS|POP3S|SMTPS) ENC="Encrypted" ;;
    *) ENC="Plain/Unknown" ;;
  esac

  STE=$(short_state "$STATE")

  printf "%-16s %-8s %-30s %-20s %-30s %-10s %-20s %-6s %-15s %-12s %-3s\n" \
  "$IP" "$PROTO" "$ORG" "$CITY, $COUNTRY" "$RDNS" "$DIR" "$APP" "$PORT" "$SERVICE" "$ENC" "$STE"
done
