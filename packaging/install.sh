#!/usr/bin/env bash
#
# GeoNetMon installer — sets up the privilege-separated daemon + GUI.
#
#   sudo ./install.sh            # install daemon, service, group, GUI
#   sudo ./install.sh --uninstall
#
# After install: add yourself to the 'geonetmon' group and re-login:
#   sudo usermod -aG geonetmon "$USER"
#
set -euo pipefail

PREFIX="/opt/geonetmon"
BIN="/usr/local/bin"
SERVICE="geonetmond.service"
GROUP="geonetmon"
HERE="$(cd "$(dirname "$0")/.." && pwd)"   # repo root (packaging/..)

need_root() {
    if [[ $EUID -ne 0 ]]; then
        echo "Please run as root (sudo $0)." >&2
        exit 1
    fi
}

uninstall() {
    need_root
    echo "==> Stopping and disabling service"
    systemctl stop "$SERVICE" 2>/dev/null || true
    systemctl disable "$SERVICE" 2>/dev/null || true
    rm -f "/etc/systemd/system/$SERVICE"
    systemctl daemon-reload 2>/dev/null || true
    echo "==> Removing files"
    rm -rf "$PREFIX"
    rm -f "$BIN/geonetmon" "$BIN/geonetmond"
    rm -f /usr/share/applications/com.jegly.GeoNetMon.desktop
    echo "==> Leaving the '$GROUP' group in place (remove manually if desired:"
    echo "    sudo groupdel $GROUP )"
    echo "Done."
}

install() {
    need_root

    echo "==> Checking dependencies"
    local missing=()
    command -v nft >/dev/null    || missing+=("nftables")
    python3 -c "import gi" 2>/dev/null || missing+=("python3-gi gir1.2-gtk-4.0")
    python3 -c "import netfilterqueue" 2>/dev/null \
        || missing+=("python3-netfilterqueue")
    command -v ss >/dev/null     || missing+=("iproute2")
    if (( ${#missing[@]} )); then
        echo "    Missing (install via apt):  ${missing[*]}"
        echo "    e.g.: sudo apt install ${missing[*]}"
        echo "    Optional: python3-maxminddb (offline GeoLite2)"
    fi

    echo "==> Creating '$GROUP' group"
    getent group "$GROUP" >/dev/null || groupadd --system "$GROUP"

    echo "==> Installing package to $PREFIX"
    mkdir -p "$PREFIX"
    cp -r "$HERE/geonetmon" "$PREFIX/"

    echo "==> Installing launchers"
    cat > "$BIN/geonetmon" <<EOF
#!/usr/bin/env bash
cd "$PREFIX" && exec python3 -m geonetmon "\$@"
EOF
    cat > "$BIN/geonetmond" <<EOF
#!/usr/bin/env bash
cd "$PREFIX" && exec python3 -m geonetmon.daemon_main "\$@"
EOF
    chmod +x "$BIN/geonetmon" "$BIN/geonetmond"

    echo "==> Installing desktop entry"
    if [[ -f "$HERE/geonetmon.desktop" ]]; then
        install -Dm644 "$HERE/geonetmon.desktop" \
            /usr/share/applications/com.jegly.GeoNetMon.desktop
    fi

    echo "==> Installing systemd service"
    install -Dm644 "$HERE/packaging/$SERVICE" "/etc/systemd/system/$SERVICE"
    systemctl daemon-reload
    systemctl enable "$SERVICE"
    systemctl restart "$SERVICE"

    echo
    echo "Done. Final step — add yourself to the group and re-login:"
    echo "    sudo usermod -aG $GROUP \"\$USER\""
    echo
    echo "Then launch the GUI with:  geonetmon"
    echo "Daemon status:  systemctl status $SERVICE"
}

case "${1:-}" in
    --uninstall|-u) uninstall ;;
    *)              install ;;
esac
