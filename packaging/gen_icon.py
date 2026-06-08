#!/usr/bin/env python3
"""Generate the GeoNetMon app icon — a Catppuccin Mocha network/geo motif:
a central host node with connections radiating to geolocated peers."""
import sys
import cairosvg

# Catppuccin Mocha
BASE = "#1e1e2e"
CRUST = "#11111b"
MAUVE = "#cba6f7"
BLUE = "#89b4fa"
GREEN = "#a6e3a1"
PEACH = "#fab387"
TEAL = "#94e2d5"
TEXT = "#cdd6f4"

CX, CY = 128, 128
# (x, y, r, colour) satellite peers
PEERS = [
    (62, 72, 15, BLUE),
    (196, 62, 15, GREEN),
    (202, 178, 15, PEACH),
    (66, 198, 15, TEAL),
]

lines = []
for x, y, r, col in PEERS:
    lines.append(
        f'<line x1="{CX}" y1="{CY}" x2="{x}" y2="{y}" stroke="{col}" '
        f'stroke-width="5" stroke-linecap="round" opacity="0.55"/>'
    )
peers = []
for x, y, r, col in PEERS:
    peers.append(
        f'<circle cx="{x}" cy="{y}" r="{r}" fill="{col}"/>'
        f'<circle cx="{x}" cy="{y}" r="{r}" fill="none" stroke="{BASE}" stroke-width="3"/>'
    )

svg = f"""<svg xmlns="http://www.w3.org/2000/svg" width="256" height="256" viewBox="0 0 256 256">
  <rect x="0" y="0" width="256" height="256" rx="58" fill="{CRUST}"/>
  <rect x="6" y="6" width="244" height="244" rx="52" fill="{BASE}"/>
  <!-- subtle orbit ring suggesting "geo" -->
  <circle cx="{CX}" cy="{CY}" r="84" fill="none" stroke="{TEXT}" stroke-width="2" opacity="0.10"/>
  <circle cx="{CX}" cy="{CY}" r="58" fill="none" stroke="{TEXT}" stroke-width="2" opacity="0.07"/>
  {''.join(lines)}
  {''.join(peers)}
  <!-- central host node -->
  <circle cx="{CX}" cy="{CY}" r="30" fill="{MAUVE}"/>
  <circle cx="{CX}" cy="{CY}" r="30" fill="none" stroke="{BASE}" stroke-width="4"/>
  <circle cx="{CX}" cy="{CY}" r="11" fill="{BASE}"/>
</svg>"""

out = sys.argv[1] if len(sys.argv) > 1 else "geonetmon.png"
cairosvg.svg2png(bytestring=svg.encode(), write_to=out, output_width=256, output_height=256)
print("wrote", out)
