#!/usr/bin/env bash
# Launch GeoNetMon. Run from anywhere; it locates its own package.
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$DIR"
exec python3 -m geonetmon "$@"
