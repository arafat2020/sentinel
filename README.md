# Sentinel

A host-based telemetry and behavioral detection agent for Linux, macOS, and Windows. Sentinel collects process, network, DNS, and file events from the OS kernel, routes them through an in-process event bus, and runs a correlation engine that fires findings when multi-step behavioral patterns match.

Everything is visible in a live terminal TUI with seven tabs — no external services required.

---

## Features

- **Process telemetry** — start/exit events, PID/PPID, executable path (all platforms via gopsutil)
- **Network telemetry** — TCP/UDP connection open/close with remote address and port
- **DNS telemetry** — per-query domain, record type, resolver IP, attribution to originating process; captured across all active network interfaces simultaneously
- **File telemetry** ⚠️ *under development* — create, write, delete, and rename events with path and PID
  - Linux: fanotify (kernel ≥ 5.9, `CAP_SYS_ADMIN`) — *working*
  - macOS: Endpoint Security framework (CGo bridge incomplete) — *not yet active*
  - Windows: `ReadDirectoryChangesW` (Administrator required) — *working*
- **Correlation engine** — YAML-defined cross-process behavioral patterns, hot-reloaded without restart
- **Persistent event store** — all telemetry written to `sentinel.db` (SQLite); bounded 500-line ring buffer per tab prevents RAM growth
- **Log query** — filter stored events by tab and date range from the CLI (`--query`)
- **Headless mode** — run without a TUI for server/systemd deployments (`--headless`)
- **Password protection** — bcrypt-hashed password gate; prompted on first install and every subsequent launch
- **Settings tab** — configure log retention and SSH remote-access kill-switch from inside the TUI
- **Terminal TUI** — seven live tabs (Process · Network · DNS · File · Findings · Patterns · Settings) navigable by keyboard

---

## Password Protection

Sentinel requires a password to start. The first time the binary runs it prompts
you to create one; every subsequent launch requires it before the TUI opens.

```
Welcome to Sentinel. Please create a password to protect the TUI.

New password:
Confirm password:
Password set. Starting Sentinel...
```

Passwords are stored as **bcrypt hashes** (cost 12) inside `sentinel.db` — the
plaintext is never written to disk.

### Reset the password

```bash
sudo sentinel --reset-password
```

You will be asked for the current password (if one is set), then prompted to
enter and confirm the new one. The command exits after a successful reset.

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

### Windows (one-liner install)

Open **PowerShell as Administrator** and run:

```powershell
powershell -ExecutionPolicy Bypass -c "irm https://raw.githubusercontent.com/arafat2020/sentinel/main/install.ps1 | iex"
```

The installer:
1. Fetches the latest `sentinel-windows-amd64.exe` from GitHub Releases
2. Verifies the SHA-256 checksum
3. Installs to `C:\Program Files\Sentinel\sentinel.exe`
4. Adds the install directory to the system `PATH`
5. Checks whether Npcap is installed (required for DNS telemetry)

After install, open an **elevated terminal** and run:

```powershell
sentinel.exe
```

> **DNS telemetry prerequisite:** install [Npcap](https://npcap.com/#download) with
> "WinPcap API-compatible Mode" enabled before running Sentinel.

### Windows (build from source)

```powershell
# 1. Install Npcap SDK: https://npcap.com/dist/npcap-sdk-1.13.zip
# 2. Set CGo flags (adjust path to where you extracted the SDK):
$env:CGO_CFLAGS  = "-IC:\npcap-sdk\Include"
$env:CGO_LDFLAGS = "-LC:\npcap-sdk\Lib\x64 -lwpcap"

git clone https://github.com/arafat2020/sentinel.git
cd sentinel
go build -o sentinel.exe ./cmd/sentinel

# Run as Administrator:
.\sentinel.exe
```

### macOS (one-liner)

```bash
git clone https://github.com/arafat2020/sentinel.git && cd sentinel && make build && sudo ./sentinel
```

`make build` compiles the binary and runs `codesign --force --sign -` automatically.
This step is **required** on macOS — skipping it leaves an Endpoint Security
entitlement in the signature that causes the OS to kill the process on launch.

### macOS (full — file telemetry via Endpoint Security) ⚠️ under development

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

## CLI Flags

| Flag | Description |
|------|-------------|
| `--headless` | Run without TUI; log findings to stdout (servers / systemd) |
| `--reset-password` | Interactively reset the Sentinel password and exit |
| `--query` | Query stored events and exit (see filters below) |
| `--tab` | Filter `--query` by tab: `Process\|Network\|DNS\|File\|Findings` |
| `--since` | Start date/time for `--query`, e.g. `2026-09-14T08:00:00` |
| `--until` | End date/time for `--query` (default: now) |
| `--limit` | Max rows for `--query` (default: 200) |

---

## TUI Keyboard Controls

| Key | Action |
|-----|--------|
| `1` | Process tab |
| `2` | Network tab |
| `3` | DNS tab |
| `4` | File tab |
| `5` | Findings tab |
| `6` | Patterns tab (YAML behavioral pattern editor) |
| `7` | Settings tab (retention · SSH kill-switch) |
| `←` / `→` | Cycle tabs left/right |
| `Ctrl+C` | Quit |

### Settings tab shortcuts

| Key | Action |
|-----|--------|
| `Tab` / `Enter` | Navigate fields and buttons |
| `Ctrl+S` | Save log retention days |
| `Ctrl+F` | Flush events older than retention window now |
| `Ctrl+D` | Disable SSH (confirmation required) |
| `Ctrl+E` | Enable SSH (confirmation required) |

---

## Architecture

```
OS Kernel
  ├── fanotify (Linux file)                   ─┐
  ├── Endpoint Security (macOS file)           │
  ├── ReadDirectoryChangesW (Windows file)     │
  ├── libpcap / Npcap (DNS — all OS)           ├─► Collectors ─► Monitors ─► Event Bus
  ├── gopsutil (process — all OS)              │                                  │
  └── gopsutil (network — all OS)             ─┘                                  │
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

### Windows
| Requirement | Purpose |
|-------------|---------|
| Go 1.21+ | Build from source |
| Npcap (WinPcap-compatible mode) | DNS telemetry (runtime) |
| Npcap SDK | DNS telemetry (build from source) |
| Administrator | Packet capture + directory watching |
| Windows 10 / Server 2016+ | `ReadDirectoryChangesW` + socket table APIs |

---

## Release Binaries

Pre-built binaries are published on every `v*` tag via GitHub Actions:

| Asset | Platform |
|-------|----------|
| `sentinel-linux-amd64` | Linux x86_64 |
| `sentinel-linux-arm64` | Linux aarch64 |
| `sentinel-windows-amd64.exe` | Windows x86_64 |
| `checksums.txt` | SHA-256 checksums |

Download from [Releases](https://github.com/arafat2020/sentinel/releases).

---

## Upcoming

| Feature | Status |
|---------|--------|
| macOS file telemetry (Endpoint Security CGo bridge) | **In progress** |
| Script execution collector (`EventScriptExecution`) | Planned |
| Persistence-path collector (`EventPersistenceChange`) | Planned |
| Rich finding evidence (network, DNS, file in one finding) | Planned |
| New correlation relationship types (COMMUNICATED_WITH, RESOLVED, MODIFIED) | Planned |
| NDJSON finding log (machine-readable output) | Planned |
| Per-pattern correlation window in YAML | Planned |
| Allowlist / suppressions in YAML | Planned |
| eBPF-based collectors (alternative to fanotify) | Research |

See [`docs/roadmap.md`](docs/roadmap.md) for full detail and architectural rationale.

---

## Project Structure

```
sentinel/
├── cmd/sentinel/
│   ├── main.go               # Platform-neutral entry point
│   ├── password.go           # Password gate (first-run setup + login prompt)
│   ├── ui.go                 # Terminal TUI (tview)
│   ├── platform_linux.go     # Linux: fanotify + libpcap wiring
│   ├── platform_darwin.go    # macOS: Endpoint Security + libpcap wiring
│   └── platform_windows.go   # Windows: ReadDirectoryChangesW + Npcap wiring
├── internal/
│   ├── auth/                 # bcrypt Hash / Verify helpers
│   ├── core/                 # Shared domain types
│   ├── eventbus/             # Bounded pub/sub event bus
│   ├── collector/
│   │   ├── process/          # gopsutil process collector
│   │   ├── network/          # gopsutil network collector
│   │   ├── dns/              # libpcap/Npcap DNS collector (Linux + macOS + Windows)
│   │   └── file/             # fanotify (Linux) + ES (macOS) + RDC (Windows)
│   ├── monitor/              # Collector → bus adapters
│   ├── detection/
│   │   ├── process/          # Process lifecycle + suspicious child rules
│   │   ├── network/          # Network lifecycle detector
│   │   └── correlation/      # Cross-process behavioral engine
│   └── finding/              # Finding sink interface + adapters
├── docs/
│   └── implementation-log.md # Detailed component reference
├── configs/
│   └── patterns.yaml         # YAML behavioral pattern definitions (hot-reloaded)
├── install.sh                # Linux one-liner installer
├── install.ps1               # Windows one-liner installer (PowerShell)
└── .github/workflows/
    └── release.yml           # Multi-arch CI release pipeline
```

> **Note:** `sentinel.db` (the SQLite event store and password hash) is created at
> runtime in the working directory and is listed in `.gitignore` — it is never
> committed to the repository.

---

## License

MIT
