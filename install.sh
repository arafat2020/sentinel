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

# ── process collector check ───────────────────────────────────────────────────
# Sentinel picks how it watches processes at startup (--process-collector=auto):
# eBPF if the kernel supports it, else the netlink process connector, else
# polling /proc every two seconds. This only reports what it will most likely
# choose here; nothing is configured.

KERNEL_RELEASE="$(uname -r)"
KERNEL_MAJOR="${KERNEL_RELEASE%%.*}"
KERNEL_REST="${KERNEL_RELEASE#*.}"
KERNEL_MINOR="${KERNEL_REST%%[!0-9]*}"

kernel_at_least() {
  [[ "$KERNEL_MAJOR" =~ ^[0-9]+$ && "$KERNEL_MINOR" =~ ^[0-9]+$ ]] || return 1
  (( KERNEL_MAJOR > $1 || (KERNEL_MAJOR == $1 && KERNEL_MINOR >= $2) ))
}

blue "Checking process collection support (kernel ${KERNEL_RELEASE}) …"
if kernel_at_least 5 8 && [[ -r /sys/kernel/btf/vmlinux ]]; then
  green "Process collector: ebpf — kernel is 5.8 or newer and has BTF."
  green "  Short-lived processes are captured in full, as they happen."
else
  if ! kernel_at_least 5 8; then
    red "eBPF process collection needs kernel 5.8 or newer (this is ${KERNEL_RELEASE})."
  else
    red "eBPF process collection needs BTF, and /sys/kernel/btf/vmlinux is missing"
    red "  (the kernel was built without CONFIG_DEBUG_INFO_BTF)."
  fi

  if [[ -e /proc/net/connector ]]; then
    green "Process collector: proc-connector — every start and exit is reported,"
    green "  but a process that exits within a millisecond may lack its command line."
  else
    red "The kernel has no process connector either (CONFIG_PROC_EVENTS)."
    green "Process collector: poll — the process table is compared every 2 seconds;"
    green "  processes that start and exit between two polls are not seen."
  fi
fi
green "  Sentinel logs the collector it chose, and why, when it starts."
green "  Override with: sentinel --process-collector=ebpf|proc-connector|poll"

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
# Headless: findings go to the journal. Started this way, with no terminal,
# Sentinel does not ask for its password (there is nobody to ask); the
# password still guards the TUI and the desktop UI.
ExecStart=${INSTALL_DIR}/${BINARY_NAME} --headless
# sentinel.db and configs/patterns.yaml are kept relative to the working
# directory. systemd creates /var/lib/sentinel.
StateDirectory=sentinel
WorkingDirectory=/var/lib/sentinel
Restart=on-failure
RestartSec=5s
# Sentinel runs as root, which is sufficient for every collector. What each
# one needs, for anyone running it under a restricted account instead:
#   eBPF process events       CAP_BPF and CAP_PERFMON (CAP_SYS_ADMIN before 5.8)
#   process connector         CAP_NET_ADMIN
#   other users' /proc entries CAP_SYS_PTRACE
#   fanotify file events      CAP_SYS_ADMIN
#   libpcap DNS capture       CAP_NET_RAW and CAP_NET_ADMIN
# CAP_SYS_RESOURCE is also needed on kernels before 5.11, where eBPF maps
# count against RLIMIT_MEMLOCK.
User=root
# eBPF maps are locked memory on kernels before 5.11.
LimitMEMLOCK=infinity

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable --now "${SERVICE_NAME}"
    green "Service enabled and started"
    green "  sudo systemctl status sentinel"
    green "  sudo journalctl -fu sentinel"
    green "The service runs headless and keeps its data in /var/lib/sentinel:"
    green "  cd /var/lib/sentinel && sudo sentinel --query --tab Findings"
  fi
fi

# ── done ──────────────────────────────────────────────────────────────────────

green ""
green "sentinel ${VERSION} installed successfully!"
green ""
green "Run it:"
green "  sudo sentinel                  # interactive TUI"
green ""
green "Tabs: 1=Process  2=Network  3=DNS  4=File  5=Findings  …  9=Health"
green "Keys: 1-9 or ←/→ to switch,  Ctrl+C to quit"
