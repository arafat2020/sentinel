#!/usr/bin/env bash
# sentinel installer
# Usage:  curl -fsSL https://raw.githubusercontent.com/arafat2020/sentinel/main/install.sh | sudo bash
set -euo pipefail

REPO="arafat2020/sentinel"
INSTALL_DIR="/usr/local/bin"
BINARY_NAME="sentinel"
SERVICE_NAME="sentinel"

# ── helpers ──────────────────────────────────────────────────────────────────

red()   { printf '\033[0;31m%s\033[0m\n' "$*"; }
green() { printf '\033[0;32m%s\033[0m\n' "$*"; }
blue()  { printf '\033[0;34m%s\033[0m\n' "$*"; }
die()   { red "error: $*" >&2; exit 1; }

require() {
  command -v "$1" >/dev/null 2>&1 || die "'$1' is required but not installed"
}

# ── checks ────────────────────────────────────────────────────────────────────

[[ "$(uname -s)" == "Linux" ]] || die "This installer only supports Linux"
[[ "$EUID" -eq 0 ]]            || die "Run as root: sudo bash install.sh (or pipe through sudo)"

require curl
require tar

ARCH="$(uname -m)"
case "$ARCH" in
  x86_64)           ARCH_SLUG="amd64" ;;
  aarch64|arm64)    ARCH_SLUG="arm64" ;;
  *) die "Unsupported architecture: $ARCH (supported: x86_64, aarch64)" ;;
esac

KERNEL="$(uname -r)"
KERNEL_MAJOR="${KERNEL%%.*}"
KERNEL_MINOR="${KERNEL#*.}"; KERNEL_MINOR="${KERNEL_MINOR%%.*}"
if [[ "$KERNEL_MAJOR" -lt 5 ]] || { [[ "$KERNEL_MAJOR" -eq 5 ]] && [[ "$KERNEL_MINOR" -lt 9 ]]; }; then
  red "Warning: kernel $KERNEL detected. Sentinel file telemetry requires kernel 5.9+."
  red "         DNS and process/network telemetry will still work."
fi

# ── resolve version ───────────────────────────────────────────────────────────

blue "Fetching latest release …"
LATEST_JSON="$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest")"
VERSION="$(printf '%s' "$LATEST_JSON" | grep '"tag_name"' | head -1 | sed 's/.*"tag_name": *"\([^"]*\)".*/\1/')"
[[ -n "$VERSION" ]] || die "Could not determine latest release version"
blue "Installing sentinel ${VERSION} (linux/${ARCH_SLUG})"

# ── download ──────────────────────────────────────────────────────────────────

BINARY_URL="https://github.com/${REPO}/releases/download/${VERSION}/sentinel-linux-${ARCH_SLUG}"
CHECKSUM_URL="https://github.com/${REPO}/releases/download/${VERSION}/checksums.txt"

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

blue "Downloading binary …"
curl -fsSL --progress-bar -o "${TMP_DIR}/${BINARY_NAME}" "$BINARY_URL"

blue "Verifying checksum …"
CHECKSUM_FILE="${TMP_DIR}/checksums.txt"
curl -fsSL -o "$CHECKSUM_FILE" "$CHECKSUM_URL"

EXPECTED="$(grep "sentinel-linux-${ARCH_SLUG}" "$CHECKSUM_FILE" | awk '{print $1}')"
[[ -n "$EXPECTED" ]] || die "Checksum not found in checksums.txt"

ACTUAL="$(sha256sum "${TMP_DIR}/${BINARY_NAME}" | awk '{print $1}')"
[[ "$EXPECTED" == "$ACTUAL" ]] || die "Checksum mismatch! expected=$EXPECTED actual=$ACTUAL"
green "Checksum OK"

# ── install binary ────────────────────────────────────────────────────────────

chmod 755 "${TMP_DIR}/${BINARY_NAME}"
mv "${TMP_DIR}/${BINARY_NAME}" "${INSTALL_DIR}/${BINARY_NAME}"
green "Installed ${INSTALL_DIR}/${BINARY_NAME}"

# ── runtime dependency check ──────────────────────────────────────────────────

if ! ldconfig -p 2>/dev/null | grep -q "libpcap"; then
  red "Warning: libpcap not found — DNS telemetry requires it."
  if command -v apt-get >/dev/null 2>&1; then
    read -r -p "Install libpcap now? [Y/n] " ans
    if [[ "${ans,,}" != "n" ]]; then
      apt-get install -y libpcap0.8 >/dev/null
      green "libpcap installed"
    fi
  elif command -v dnf >/dev/null 2>&1; then
    read -r -p "Install libpcap now? [Y/n] " ans
    if [[ "${ans,,}" != "n" ]]; then
      dnf install -y libpcap >/dev/null
      green "libpcap installed"
    fi
  else
    red "Install libpcap manually (e.g. 'apt install libpcap0.8' or 'dnf install libpcap')"
  fi
fi

# ── systemd service (optional) ───────────────────────────────────────────────

if command -v systemctl >/dev/null 2>&1; then
  read -r -p "Install and enable systemd service? [Y/n] " ans
  if [[ "${ans,,}" != "n" ]]; then
    cat > "/etc/systemd/system/${SERVICE_NAME}.service" <<EOF
[Unit]
Description=Sentinel — host telemetry and behavioral detection
After=network.target
Documentation=https://github.com/${REPO}

[Service]
Type=simple
ExecStart=${INSTALL_DIR}/${BINARY_NAME}
Restart=on-failure
RestartSec=5s
# fanotify and libpcap both require elevated privilege
User=root

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable --now "${SERVICE_NAME}"
    green "Service enabled and started"
    green "  sudo systemctl status sentinel"
    green "  sudo journalctl -fu sentinel"
  fi
fi

# ── done ──────────────────────────────────────────────────────────────────────

green ""
green "sentinel ${VERSION} installed successfully!"
green ""
green "Run it:"
green "  sudo sentinel                  # interactive TUI"
green ""
green "Tabs: 1=Process  2=Network  3=DNS  4=File  5=Findings"
green "Keys: 1-5 or ←/→ to switch,  Ctrl+C to quit"
