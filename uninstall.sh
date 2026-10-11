#!/usr/bin/env bash
# Sentinel uninstaller
# Usage: curl -fsSL https://raw.githubusercontent.com/arafat2020/sentinel/main/uninstall.sh | sudo bash
set -euo pipefail

INSTALL_DIR="/usr/local/bin"
BINARY_NAME="sentinel"
SERVICE_NAME="sentinel"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
ASSUME_YES=false

red()   { printf '\033[0;31m%s\033[0m\n' "$*"; }
green() { printf '\033[0;32m%s\033[0m\n' "$*"; }
die()   { red "error: $*" >&2; exit 1; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    -y|--yes) ASSUME_YES=true ;;
    -h|--help)
      printf 'Usage: sudo bash uninstall.sh [--yes]\n'
      printf 'Removes the Sentinel binary and systemd service; leaves Sentinel data untouched.\n'
      exit 0
      ;;
    *) die "unknown option: $1 (use --help)" ;;
  esac
  shift
done

[[ "$(uname -s)" == "Linux" ]] || die "This uninstaller only supports Linux"
[[ "$EUID" -eq 0 ]] || die "Run as root: sudo bash uninstall.sh"

printf 'This will stop and remove the Sentinel systemd service and %s/%s.\n' "$INSTALL_DIR" "$BINARY_NAME"
printf 'Sentinel data files, including sentinel.db and configs, will be left untouched.\n'

if [[ "$ASSUME_YES" != true ]]; then
  [[ -r /dev/tty ]] || die "no terminal available; rerun with --yes to confirm removal"
  read -r -p "Continue? [y/N] " answer </dev/tty
  [[ "${answer,,}" == "y" || "${answer,,}" == "yes" ]] || {
    printf 'Uninstall cancelled.\n'
    exit 0
  }
fi

if command -v systemctl >/dev/null 2>&1 && [[ -d /run/systemd/system ]]; then
  systemctl disable --now "${SERVICE_NAME}.service" >/dev/null 2>&1 || true
fi

rm -f "$SERVICE_FILE"
rm -f "/etc/systemd/system/multi-user.target.wants/${SERVICE_NAME}.service"
rm -f "${INSTALL_DIR}/${BINARY_NAME}"

if command -v systemctl >/dev/null 2>&1 && [[ -d /run/systemd/system ]]; then
  systemctl daemon-reload
fi

green "Sentinel binary and systemd service removed."
printf 'Sentinel data files were preserved.\n'