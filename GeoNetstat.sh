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
  CONNS=$(netstat $ARGS -p | awk 'NR>2 {print $4, $5, $7}')
else
  CONNS=$(ss $ARGS -p | awk 'NR>1 {print $4, $5, $6}')
fi

# Print header
printf "%-16s %-30s %-20s %-30s %-10s %-20s\n" "IP Address" "Organization" "Location" "Reverse DNS" "Direction" "Application"
echo "-------------------------------------------------------------------------------------------------------------------------------"

# Loop through connections
echo "$CONNS" | while read LOCAL REMOTE PROC; do
  IP=$(echo "$REMOTE" | cut -d: -f1)
  [[ "$IP" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || continue

  INFO=$(curl -s "https://ipinfo.io/$IP/json")
  ORG=$(echo "$INFO" | jq -r '.org // "Unknown"')
  CITY=$(echo "$INFO" | jq -r '.city // "Unknown"')
  COUNTRY=$(echo "$INFO" | jq -r '.country // "Unknown"')

  RDNS=$(host "$IP" 2>/dev/null | awk '/domain name pointer/ {print $5}' | sed 's/\.$//' || echo "Unknown")
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

  printf "%-16s %-30s %-20s %-30s %-10s %-20s\n" "$IP" "$ORG" "$CITY, $COUNTRY" "$RDNS" "$DIR" "$APP"
done

