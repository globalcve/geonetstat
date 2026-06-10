#!/usr/bin/env bash
#
# Build a single self-contained geonetmon .deb. No manual post-install steps:
# the package's own postinst creates the group, enables the root daemon (which
# publishes process names so the GUI never needs root), and refreshes caches.
#
#   ./packaging/build-deb.sh
#
set -euo pipefail

BASE_VERSION="1.0.2"
# Unique, monotonically-increasing version per build. dpkg/apt compare VERSION
# strings, so without this an "install" over the same 1.0.0 is a silent no-op
# (old code keeps running). The +buildTIMESTAMP suffix forces a real upgrade.
VERSION="${BASE_VERSION}+build$(date +%Y%m%d%H%M%S)"
ARCH="all"
HERE="$(cd "$(dirname "$0")/.." && pwd)"          # repo root (packaging/..)
PKG="geonetmon"
STAGE="$(mktemp -d)/${PKG}_${BASE_VERSION}"
OUT="${HERE}/${PKG}_${BASE_VERSION}_${ARCH}.deb"  # stable filename for installs

echo "==> Staging in $STAGE"
mkdir -p \
  "$STAGE/DEBIAN" \
  "$STAGE/opt/geonetmon" \
  "$STAGE/usr/bin" \
  "$STAGE/usr/share/applications" \
  "$STAGE/usr/share/icons/hicolor/256x256/apps" \
  "$STAGE/usr/lib/systemd/system"

echo "==> Copying the Python package"
cp -r "$HERE/geonetmon" "$STAGE/opt/geonetmon/"
find "$STAGE/opt/geonetmon" -name '__pycache__' -type d -prune -exec rm -rf {} +
find "$STAGE/opt/geonetmon" -name '_orig_*' -delete 2>/dev/null || true

echo "==> Launchers"
cat > "$STAGE/usr/bin/geonetmon" <<'EOF'
#!/bin/sh
cd /opt/geonetmon && exec python3 -m geonetmon "$@"
EOF
cat > "$STAGE/usr/bin/geonetmond" <<'EOF'
#!/bin/sh
cd /opt/geonetmon && exec python3 -m geonetmon.daemon_main "$@"
EOF
chmod 0755 "$STAGE/usr/bin/geonetmon" "$STAGE/usr/bin/geonetmond"

echo "==> Desktop entry + icon"
cat > "$STAGE/usr/share/applications/com.jegly.GeoNetMon.desktop" <<'EOF'
[Desktop Entry]
Type=Application
Name=GeoNetMon
Comment=Real-time geo-aware network monitor & interactive firewall
Exec=geonetmon
Icon=geonetmon
Terminal=false
Categories=Network;Monitor;Security;
Keywords=network;connections;firewall;monitor;security;geoip;
StartupWMClass=com.jegly.GeoNetMon
EOF
python3 "$HERE/packaging/gen_icon.py" \
  "$STAGE/usr/share/icons/hicolor/256x256/apps/geonetmon.png"

echo "==> systemd service"
install -Dm644 "$HERE/packaging/geonetmond.service" \
  "$STAGE/usr/lib/systemd/system/geonetmond.service"

echo "==> DEBIAN/control"
cat > "$STAGE/DEBIAN/control" <<EOF
Package: geonetmon
Version: ${VERSION}
Section: net
Priority: optional
Architecture: ${ARCH}
Depends: python3 (>= 3.10), python3-gi, python3-gi-cairo, gir1.2-gtk-4.0, iproute2
Recommends: nftables, python3-netfilterqueue, python3-maxminddb, pkexec | policykit-1, ufw
Suggests: gir1.2-ayatanaappindicator3-0.1, iptables
Maintainer: jegly <https://github.com/jegly>
Description: GeoNetMon — geo-aware network monitor and interactive firewall
 Live TCP/UDP socket monitor with geolocation, reverse DNS, per-connection
 bandwidth and risk scoring, plus an optional OpenSnitch-style interactive
 firewall (allow/deny prompts) backed by a privilege-separated root daemon.
 .
 The GUI runs unprivileged; the geonetmond daemon publishes process names so
 every process is visible without ever launching the GUI as root.
EOF

echo "==> Maintainer scripts"
cat > "$STAGE/DEBIAN/postinst" <<'EOF'
#!/bin/sh
set -e
# Group only gates the optional enforcement socket; process-name visibility
# does NOT need it (the daemon publishes a world-readable file).
getent group geonetmon >/dev/null || groupadd --system geonetmon || true
if [ -n "${SUDO_USER:-}" ] && [ "${SUDO_USER}" != "root" ]; then
    usermod -aG geonetmon "$SUDO_USER" 2>/dev/null || true
fi
if [ -d /run/systemd/system ]; then
    systemctl daemon-reload || true
    systemctl enable geonetmond.service || true
    # restart (not just --now) so an upgrade actually loads the new daemon code
    systemctl restart geonetmond.service || true
fi
update-desktop-database -q 2>/dev/null || true
gtk-update-icon-cache -q -f /usr/share/icons/hicolor 2>/dev/null || true
exit 0
EOF
cat > "$STAGE/DEBIAN/prerm" <<'EOF'
#!/bin/sh
set -e
if [ "$1" = remove ] || [ "$1" = purge ] || [ "$1" = upgrade ]; then
    pkill -f 'python3 -m geonetmon$' 2>/dev/null || true
    if [ -d /run/systemd/system ]; then
        systemctl disable --now geonetmond.service 2>/dev/null || true
    fi
    # Always flush nft tables so traffic is never silently blocked after removal
    nft delete table inet geonetmon_enforce 2>/dev/null || true
    nft delete table inet geonetmon 2>/dev/null || true
fi
exit 0
EOF
cat > "$STAGE/DEBIAN/postrm" <<'EOF'
#!/bin/sh
set -e
# Belt-and-braces: flush nft tables even if prerm didn't run (e.g. after a crash)
nft delete table inet geonetmon_enforce 2>/dev/null || true
nft delete table inet geonetmon 2>/dev/null || true
if [ "$1" = purge ]; then
    rm -f /run/geonetmon-procs.json /run/geonetmon.sock 2>/dev/null || true
fi
if [ -d /run/systemd/system ]; then systemctl daemon-reload 2>/dev/null || true; fi
exit 0
EOF
chmod 0755 "$STAGE/DEBIAN/postinst" "$STAGE/DEBIAN/prerm" "$STAGE/DEBIAN/postrm"

echo "==> Building $OUT"
dpkg-deb --root-owner-group --build "$STAGE" "$OUT" >/dev/null
echo "Built: $OUT"
dpkg-deb -I "$OUT" | sed -n '1,20p'
