#!/bin/bash

# ==========================================================
# Connection Inspector (Final Version)
# ==========================================================

# 1. DEPENDENCY CHECK
for cmd in curl jq ss ip host grep whiptail awk; do
    if ! command -v $cmd &> /dev/null; then
        echo "Error: Missing dependency '$cmd'. Please install it."
        exit 1
    fi
done

# 2. INITIALIZE CACHE
declare -A IP_CACHE

# 3. MENU SYSTEM
if [[ $# -eq 0 ]]; then
  CHOICE=$(whiptail --title "Connection Lookup Menu" --menu "Choose a connection type:" 20 78 10 \
    "ss -tn"        "Show TCP connections (Established)" \
    "ss -un"        "Show UDP connections (Stateless)" \
    "ss -tulnp"     "Show all listening ports" \
    "netstat -tn"   "Show TCP connections (Legacy)" \
    "netstat -un"   "Show UDP connections (Legacy)" \
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
  set -- $CHOICE
fi

CMD="$1"
ARGS="${@:2}"

# 4. GET LOCAL IPS
LOCAL_IPS=$(ip addr | awk '/inet6? / {print $2}' | cut -d/ -f1)

# 5. RUN COMMAND
if [[ "$CMD" == "netstat" ]]; then
  CONNS=$(netstat $ARGS -p 2>/dev/null | awk 'NR>2 {print $1, $4, $5, $6, $7}')
else
  CONNS=$(ss $ARGS -p | awk 'NR>1 {print $1, $4, $5, $6}')
fi

# 6. PORT MAP
declare -A portmap=(
  [20]="FTP-Data" [21]="FTP" [22]="SSH" [23]="Telnet" 
  [53]="DNS" [67]="DHCP-s" [68]="DHCP-c" [69]="TFTP" [123]="NTP" [161]="SNMP"
  [80]="HTTP" [443]="HTTPS" [8080]="HTTP-Proxy" [8443]="HTTPS-Alt" [3128]="Squid"
  [25]="SMTP" [110]="POP3" [143]="IMAP" 
  [465]="SMTPS" [587]="Submission" [993]="IMAPS" [995]="POP3S"
  [135]="RPC" [137]="NetBIOS" [138]="NetBIOS" [139]="NetBIOS" 
  [389]="LDAP" [445]="SMB" [636]="LDAPS" [3389]="RDP"
  [1433]="MSSQL" [1521]="Oracle" [3306]="MySQL" [5432]="Postgres" 
  [6379]="Redis" [27017]="MongoDB" [9200]="Elastic" [9042]="Cassandra"
  [1194]="OpenVPN" [51820]="WireGuard" [500]="IKEv2" [4500]="IPSec"
  [2375]="Docker" [2376]="Docker-S" [6443]="K8s-API" [10250]="Kubelet"
  [5900]="VNC" [10050]="Zabbix"
)

# --- STATE LOGIC ---
short_state() {
  local s=$1
  case "$s" in
    *ESTAB*|*ESTABLISHED*) echo "Active" ;;    # TCP Active
    *LISTEN*)              echo "Listen" ;;    # TCP Listen
    *TIME*|*CLOSE*|*FIN*)  echo "Closing" ;;   # TCP Closing
    *UNCONN*)              echo "Stateless" ;; # UDP (Fixed)
    *)                     echo "Unknown" ;;   # Catch-all
  esac
}

is_public_ip() {
    local ip=$1
    [[ "$ip" =~ ^127\. ]] && return 1
    [[ "$ip" =~ ^10\. ]] && return 1
    [[ "$ip" =~ ^192\.168\. ]] && return 1
    [[ "$ip" =~ ^172\.(1[6-9]|2[0-9]|3[0-1])\. ]] && return 1
    [[ "$ip" == "0.0.0.0" ]] && return 1
    [[ "$ip" == "::1" ]] && return 1
    [[ "$ip" =~ ^fe80: ]] && return 1
    [[ "$ip" =~ ^fd ]] && return 1 
    [[ "$ip" == "::" ]] && return 1
    return 0 
}

# 7. PRINT HEADER
printf "%-26s %-6s %-22s %-20s %-22s %-8s %-15s %-6s %-12s %-12s %-6s\n" \
"IP Address" "Proto" "Organization" "Location" "Reverse DNS" "Dir" "App" "Port" "Service" "Encrypt" "State"
echo "---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------"

# 8. PROCESS LOOP
echo "$CONNS" | while read PROTO LOCAL REMOTE STATE PROC; do
  [[ -z "$PROTO" ]] && continue

  # UDP Fix: Force UDP to be "Stateless" if state is weird
  if [[ "$PROTO" =~ udp ]]; then
     # If state column is empty or confusing, fix variables
     if [[ "$STATE" =~ ^[0-9]+$ ]] || [[ "$STATE" =~ "/" ]]; then
        PROC="$STATE"
        STATE="UNCONN"
     fi
     if [[ -z "$STATE" ]] || [[ "$STATE" == "Unknown" ]]; then
        STATE="UNCONN"
     fi
  fi

  if [[ "$STATE" == "LISTEN" || "$STATE" == *"LISTEN"* ]]; then
    RAW_ADDR="$LOCAL"
    DIR="INCOMING"
  else
    RAW_ADDR="$REMOTE"
    DIR="OUTGOING"
  fi

  PORT=$(echo "$RAW_ADDR" | awk -F: '{print $NF}')
  IP=$(echo "$RAW_ADDR" | sed 's/:[0-9]*$//')
  IP=$(echo "$IP" | tr -d '[]')

  for LIP in $LOCAL_IPS; do
    if [[ "$IP" == "$LIP" ]]; then
      DIR="INCOMING"
      break
    fi
  done

  if is_public_ip "$IP"; then
    if [[ -n "${IP_CACHE[$IP]}" ]]; then
        IFS='|' read -r ORG CITY <<< "${IP_CACHE[$IP]}"
    else
        INFO=$(curl -s --connect-timeout 2 "https://ipinfo.io/$IP/json")
        if echo "$INFO" | jq -e . >/dev/null 2>&1; then
            ORG=$(echo "$INFO" | jq -r '.org // "Unknown"' | cut -c1-20)
            CITY=$(echo "$INFO" | jq -r '"\(.city), \(.country)"' | sed 's/null, null/-/' | cut -c1-20)
        else
            ORG="API Error"
            CITY="-"
        fi
        IP_CACHE[$IP]="$ORG|$CITY"
    fi
    RDNS=$(host "$IP" 2>/dev/null | awk '/domain name pointer/ {print $5}' | sed 's/\.$//' | head -n1 | cut -c1-20)
    [[ -z "$RDNS" ]] && RDNS="-"
  else
    ORG="Local/Private"
    CITY="-"
    RDNS="-"
  fi

  if [[ "$CMD" == "netstat" ]]; then
    APP=$(echo "$PROC" | cut -d/ -f2)
  else
    APP=$(echo "$PROC" | grep -oP 'users:\(\("\K[^"]+')
  fi
  [[ -z "$APP" || "$APP" == "-" ]] && APP="Unknown"

  SERVICE=${portmap[$PORT]:-"$PORT"}
  
  case "$SERVICE" in
    *HTTPS*|*SSL*|*SSH*|*IMAPS*|*POP3S*|*SMTPS*|*LDAPS*|*OpenVPN*|*WireGuard*|*IPSec*|*Submission*|*RDP*) 
        ENC="Encrypted" ;;
    443|22|993|995|465|636|2376|6443|587|3389) 
        ENC="Encrypted" ;;
    *HTTP*|*FTP*|*Telnet*|*VNC*|*DNS*) 
        ENC="Plain" ;;
    21|23|80|5900|389)
        ENC="Plain" ;;
    *) ENC="Unknown" ;;
  esac

  STE=$(short_state "$STATE")

  printf "%-26s %-6s %-22s %-20s %-22s %-8s %-15s %-6s %-12s %-12s %-6s\n" \
  "$IP" "$PROTO" "$ORG" "$CITY" "$RDNS" "$DIR" "$APP" "$PORT" "$SERVICE" "$ENC" "$STE"

done
