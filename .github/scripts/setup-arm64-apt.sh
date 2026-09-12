#!/usr/bin/env bash
# Configure apt for arm64 cross-compilation on Ubuntu.
#
# Problem: after `dpkg --add-architecture arm64`, apt tries to fetch arm64
# package lists from ALL configured sources including security.ubuntu.com and
# archive.ubuntu.com — neither of which carries arm64 packages.  The result is
# a cascade of 404 errors that abort `apt-get update`.
#
# Fix:
#   1. Restrict existing sources to amd64 only.
#   2. Add ports.ubuntu.com as the authoritative arm64 source.
#
# Handles both legacy one-line format (sources.list / *.list) and the deb822
# format used by Ubuntu 22.04+ (ubuntu.sources).
set -euo pipefail

CODENAME="${1:-$(lsb_release -cs)}"

# --- deb822 format (Ubuntu 22.04+) ---
DEB822="/etc/apt/sources.list.d/ubuntu.sources"
if [ -f "$DEB822" ]; then
    python3 - "$DEB822" << 'PYEOF'
import sys, pathlib

path = pathlib.Path(sys.argv[1])
lines = path.read_text().splitlines(keepends=True)
out = []
for i, line in enumerate(lines):
    out.append(line)
    # After every "Types: deb" line, inject "Architectures: amd64" if absent
    if line.startswith("Types:") and "deb" in line:
        nxt = lines[i + 1] if i + 1 < len(lines) else ""
        if not nxt.startswith("Architectures:"):
            out.append("Architectures: amd64\n")
path.write_text("".join(out))
PYEOF
fi

# --- legacy one-line format ---
if [ -f /etc/apt/sources.list ]; then
    sed -i "s|^deb |deb [arch=amd64] |" /etc/apt/sources.list
fi
for f in /etc/apt/sources.list.d/*.list; do
    [ -f "$f" ] && sed -i "s|^deb |deb [arch=amd64] |" "$f" || true
done

# --- arm64-only source: ports.ubuntu.com ---
cat > /etc/apt/sources.list.d/arm64-ports.list << EOF
deb [arch=arm64] http://ports.ubuntu.com/ubuntu-ports ${CODENAME} main restricted universe multiverse
deb [arch=arm64] http://ports.ubuntu.com/ubuntu-ports ${CODENAME}-updates main restricted universe multiverse
deb [arch=arm64] http://ports.ubuntu.com/ubuntu-ports ${CODENAME}-security main restricted universe multiverse
EOF

echo "apt sources restricted to amd64; arm64 routed to ports.ubuntu.com (${CODENAME})"
