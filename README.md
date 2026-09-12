# Sentinel

A host-based telemetry and behavioral detection agent for Linux and macOS. Sentinel collects process, network, DNS, and file events from the OS kernel, routes them through an in-process event bus, and runs a correlation engine that fires findings when multi-step behavioral patterns match.

Everything is visible in a live terminal TUI with five tabs — no external services required.

---

## Features

- **Process telemetry** — start/exit events, PID/PPID, executable path (all platforms via gopsutil)
- **Network telemetry** — TCP/UDP connection open/close with remote address and port
- **DNS telemetry** — per-query domain, record type, resolver IP, and attribution to originating process
- **File telemetry** — create, write, delete, and rename events with path and PID
  - Linux: fanotify (kernel ≥ 5.9, `CAP_SYS_ADMIN`)
  - macOS: Endpoint Security framework (requires entitlement + root)
- **Correlation engine** — cross-process behavioral pattern matching with 5-minute deduplication window
- **Terminal TUI** — five live tabs (Process · Network · DNS · File · Findings) navigable by keyboard

---

## Quick Start

### Linux (one-liner install)

```bash
curl -fsSL https://raw.githubusercontent.com/arafat2020/sentinel/main/install.sh | sudo bash
```

The installer:
1. Detects architecture (`x86_64` / `aarch64`)
2. Warns if kernel < 5.9 (file telemetry requires fanotify)
3. Fetches the latest release binary from GitHub
4. Verifies the SHA-256 checksum
5. Installs to `/usr/local/bin/sentinel`
6. Offers to install `libpcap` (required for DNS telemetry)
7. Offers to create and enable a systemd service

After install:

```bash
sudo sentinel
```

### Linux (build from source)

```bash
sudo apt install libpcap-dev   # Debian/Ubuntu
# sudo dnf install libpcap-devel  # Fedora/RHEL

git clone https://github.com/arafat2020/sentinel.git
cd sentinel
go build -o sentinel ./cmd/sentinel
sudo ./sentinel
```

### macOS (DNS + process + network)

```bash
git clone https://github.com/arafat2020/sentinel.git
cd sentinel
go build -o sentinel ./cmd/sentinel
sudo ./sentinel
```

### macOS (full — file telemetry via Endpoint Security)

File telemetry on macOS requires the `com.apple.developer.endpoint-security.client` entitlement and must run as root.

```bash
# 1. Create entitlements.plist
cat > entitlements.plist <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>com.apple.developer.endpoint-security.client</key>
  <true/>
</dict>
</plist>
EOF

# 2. Build and sign
go build -o sentinel ./cmd/sentinel
codesign -s - --entitlements entitlements.plist ./sentinel

# 3. Run as root
sudo ./sentinel
```

Without the entitlement, file telemetry is silently skipped — all other tabs still work.

---

## TUI Keyboard Controls

| Key | Action |
|-----|--------|
| `1` | Process tab |
| `2` | Network tab |
| `3` | DNS tab |
| `4` | File tab |
| `5` | Findings tab |
| `←` / `→` | Cycle tabs left/right |
| `Ctrl+C` | Quit |

---

## Architecture

```
OS Kernel
  ├── fanotify (Linux file)           ─┐
  ├── Endpoint Security (macOS file)   │
  ├── libpcap (DNS — Linux & macOS)    ├─► Collectors ─► Monitors ─► Event Bus
  ├── gopsutil (process — all OS)      │                                  │
  └── gopsutil (network — all OS)     ─┘                                  │
                                                                           ▼
                                                              Correlation Engine
                                                                           │
                                                                           ▼
                                                                 Finding Sink ─► TUI (Findings tab)
```

| Layer | Package | Role |
|-------|---------|------|
| Core types | `internal/core/` | Shared event, process, network, DNS, file, finding structs |
| Event bus | `internal/eventbus/` | Bounded fan-out pub/sub queue (capacity 1000) |
| Collectors | `internal/collector/` | OS-specific data sources (process, network, DNS, file) |
| Monitors | `internal/monitor/` | Collector → bus adapters |
| Detection | `internal/detection/` | Process rules, network lifecycle, correlation engine |
| Finding sink | `internal/finding/` | Routes findings to TUI or console |
| TUI | `cmd/sentinel/ui.go` | tview-based terminal UI |
| Platform wiring | `cmd/sentinel/platform_*.go` | Build-tag-gated OS-specific setup |

---

## Requirements

### Linux
| Requirement | Purpose |
|-------------|---------|
| Go 1.21+ | Build |
| `libpcap-dev` | DNS telemetry (build-time) |
| `libpcap0.8` | DNS telemetry (runtime) |
| Kernel ≥ 5.9 | File telemetry (fanotify FID) |
| `CAP_SYS_ADMIN` or root | fanotify + libpcap |

### macOS
| Requirement | Purpose |
|-------------|---------|
| Go 1.21+ | Build |
| Xcode Command Line Tools | CGo (libpcap + Endpoint Security) |
| root | libpcap + Endpoint Security |
| ES entitlement | File telemetry (optional) |

---

## Release Binaries

Pre-built Linux binaries are published on every `v*` tag via GitHub Actions:

| Asset | Platform |
|-------|----------|
| `sentinel-linux-amd64` | Linux x86_64 |
| `sentinel-linux-arm64` | Linux aarch64 |
| `checksums.txt` | SHA-256 checksums |

Download from [Releases](https://github.com/arafat2020/sentinel/releases).

---

## Upcoming

| Feature | Status |
|---------|--------|
| Windows support (ETW-based collectors) | Planned |
| macOS App Store / notarized build | Planned |
| Findings log file export | Planned |
| SIEM / JSON output mode | Planned |
| Config file (watch paths, rule toggles, severity) | Planned |
| More behavioral detection patterns | In progress |
| eBPF-based collectors (alternative to fanotify) | Research |

---

## Project Structure

```
sentinel/
├── cmd/sentinel/
│   ├── main.go               # Platform-neutral entry point
│   ├── ui.go                 # Terminal TUI (tview)
│   ├── platform_linux.go     # Linux: fanotify + libpcap wiring
│   └── platform_darwin.go    # macOS: Endpoint Security + libpcap wiring
├── internal/
│   ├── core/                 # Shared domain types
│   ├── eventbus/             # Bounded pub/sub event bus
│   ├── collector/
│   │   ├── process/          # gopsutil process collector
│   │   ├── network/          # gopsutil network collector
│   │   ├── dns/              # libpcap DNS collector (Linux + macOS)
│   │   └── file/             # fanotify (Linux) + ES (macOS) file collector
│   ├── monitor/              # Collector → bus adapters
│   ├── detection/
│   │   ├── process/          # Process lifecycle + suspicious child rules
│   │   ├── network/          # Network lifecycle detector
│   │   └── correlation/      # Cross-process behavioral engine
│   └── finding/              # Finding sink interface + adapters
├── docs/
│   └── implementation-log.md # Detailed component reference
├── install.sh                # Linux one-liner installer
└── .github/workflows/
    └── release.yml           # Multi-arch CI release pipeline
```

---

## License

MIT
