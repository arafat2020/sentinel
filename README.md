# Sentinel

A host-based telemetry and behavioral detection agent for Linux, macOS, and Windows. Sentinel collects process, network, DNS, and file events from the OS kernel, routes them through an in-process event bus, and runs a correlation engine that fires findings when multi-step behavioral patterns match.

Everything is visible in a live terminal TUI with eight tabs — no external services required.

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
- **Resources tab** — live, htop-style process table (PID, name, CPU %, resident memory) with system CPU and memory totals; display-only, never written to the database or the event bus
- **Terminal TUI** — eight live tabs (Process · Network · DNS · File · Findings · Patterns · Settings · Resources) navigable by keyboard

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
| `8` | Resources tab (live process monitor) |
| `←` / `→` | Cycle tabs left/right (wraps around) |
| `Ctrl+C` | Quit |

The number keys switch tabs from the telemetry tabs (1–5), from Resources, and
from Settings while focus is on the tab bar. On the Patterns tab, and inside
the Settings form, digits are text input — use `←` / `→` there (after `Esc` in
the Settings form).

On terminals narrower than the tab bar, the bar scrolls sideways to keep the
active tab visible.

### Settings tab shortcuts

Arriving on the Settings tab leaves focus on the tab bar, so `←` / `→` and the
number keys keep working. The hint line at the bottom of the tab always shows
the keys that apply to the current focus.

| Key | Where | Action |
|-----|-------|--------|
| `Enter` (or `Tab` / `↓`) | Tab bar | Step into the form (retention field) |
| `Esc` | Form | Step back out to the tab bar |
| `Tab` / `Shift+Tab` | Form | Move between the field and the buttons |
| `Enter` | Form | Activate the focused button |
| `Ctrl+S` | Tab bar or form | Save log retention days |
| `Ctrl+F` | Tab bar or form | Flush events older than retention window now |
| `Ctrl+D` | Tab bar or form | Disable SSH (confirmation required) |
| `Ctrl+E` | Tab bar or form | Enable SSH (confirmation required) |

### Resources tab

A live process table, refreshed every 2 seconds.

| Key | Action |
|-----|--------|
| `↑` / `↓` | Move the highlighted row |
| `PgUp` / `PgDn` | Move a page |
| `Home` / `End` | First / last process |
| `c` | Sort by CPU (highest first) |
| `m` | Sort by RSS (highest first) |

| Column | Meaning |
|--------|---------|
| `PID` | Process ID |
| `NAME` | Process name; falls back to the executable's file name when the name itself is not readable |
| `CPU%` | CPU used since the previous refresh, relative to **one core** — a process using two full cores shows `200.0` |
| `RSS` | Resident set size: physical memory currently mapped by the process, including pages shared with other processes |

The two bars above the table are host-wide: `CPU` is the share of **all cores**
in use (0–100 %), and `Mem` is used system RAM out of total RAM as reported by
the OS. Because RSS counts shared pages once per process, the RSS column does
not add up to the `Mem` figure.

Behavior worth knowing:

- **`—` means "not readable", never zero.** A value the OS would not provide is
  shown as `—` and sorted after every real value, including a genuine `0.0`.
- **First sample.** CPU % is a difference between two refreshes, so every
  process shows `—` for CPU on the first refresh (about 2 seconds), a newly
  started process shows `—` once, and the system `CPU` bar shows `n/a` until
  the second sample.
- **Permissions.** Without root, macOS does not expose CPU time or memory for
  other users' processes; they stay in the table with `—`. Run with `sudo` to
  see them. Sentinel does not estimate values it cannot read.
- **Selection** follows the highlighted process as rows reorder (matched by PID
  and start time, so a recycled PID is not followed). A highlight left on the
  first row stays on the first row. Changing the sort returns to the first row.
- **Not persisted.** Resource samples are display-only: they are not written to
  `sentinel.db`, not sent through the event bus, and not available to
  `--query`. The tab exists only in the terminal TUI, not in `--headless` or
  `--desktop` mode.
- **Platform status.** The Resources tab has been run and tested on macOS
  only. It is built on gopsutil and cross-compiles for Linux and Windows, but
  it has not been run on either; treat the figures there as unverified.

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
| Collectors | `internal/collector/` | OS-specific data sources (process, network, DNS, file, resource usage) |
| Monitors | `internal/monitor/` | Collector → bus adapters (the resource monitor feeds the TUI directly, bypassing the bus) |
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
│   ├── ui_resources.go       # Resources tab (live process monitor)
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
│   │   ├── file/             # fanotify (Linux) + ES (macOS) + RDC (Windows)
│   │   └── resource/         # gopsutil CPU / memory usage for the Resources tab
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
