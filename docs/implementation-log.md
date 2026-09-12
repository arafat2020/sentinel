# Sentinel — Implementation Log

This document tracks every component built, the decisions behind each, and the current state of the project.

---

## Project Overview

**Sentinel** is a host-based telemetry and behavioral detection agent written in Go. It collects process, network, DNS, and file events from the OS, routes them through an event bus, and runs a correlation engine that emits findings when behavioral patterns match.

**Module:** `github.com/arafat2020/sentinel`  
**Go version:** 1.25.5  
**Repo:** https://github.com/arafat2020/sentinel

---

## Full Detection Cycle

```
OS Kernel
  ├── fanotify (Linux file)          ─┐
  ├── Endpoint Security (macOS file)  │
  ├── libpcap (DNS — Linux & macOS)   ├─► Collectors ─► Monitors ─► Event Bus
  ├── gopsutil (process — all OS)     │                               │
  └── gopsutil (network — all OS)    ─┘                               │
                                                                       ▼
                                                          Correlation Engine
                                                                       │
                                                                       ▼
                                                             Finding Sink ─► TUI
```

---

## Components Built

### 1. Core Domain (`internal/core/`)

Shared types used across all packages.

| File | Contents |
|------|----------|
| `event.go` | `Event` struct — the unified bus message; `EventType` constants |
| `process.go` | `Process` struct (PID, PPID, Name, Executable, Identity) |
| `network.go` | `NetworkConnection` struct (PID, Protocol, RemoteAddress, RemotePort, State) |
| `dns.go` | `DNSEvent` struct (Domain, Type, Resolver, PID) |
| `file.go` | `FileEvent` struct (PID, PPID, Path, OldPath, Operation, Timestamp) |
| `finding.go` | `Finding` struct (Timestamp, Rule, Severity, Title, Description) |
| `evidence.go` | `Evidence` supporting type |

---

### 2. Event Bus (`internal/eventbus/`)

Bounded, fan-out pub/sub queue.

- `New(capacity int) *Bus` — creates a buffered channel bus (capacity 1000 in production)
- `Subscribe(func(Event))` — registers a handler; all handlers run for every event
- `Publish(Event)` — non-blocking; drops events when queue is full
- `Start(ctx)` / `Shutdown()` / `Wait()` — lifecycle management
- Fully tested (`bus_test.go`)

---

### 3. Process Collector (`internal/collector/process/`)

Cross-platform via **gopsutil** — no build tags needed.

- `NewCollector()` — polls running processes
- `NewResolver()` — resolves a PID to a `*core.Process`; used by DNS and file collectors for attribution
- Linux-specific extensions in `linux.go` (PPID resolution via `/proc`)
- Tested with unit tests + Linux integration tests

---

### 4. Network Collector (`internal/collector/network/`)

Cross-platform via **gopsutil**.

- `NewCollector()` — polls open TCP/UDP connections
- Linux-specific socket stats in `linux.go`
- Tested

---

### 5. DNS Collector (`internal/collector/dns/`)

Platform-specific via **libpcap** (CGo, `google/gopacket`).

| File | Platform | Role |
|------|----------|------|
| `packet.go` | all | DNS packet parser (UDP/TCP port 53) |
| `linux.go` | linux | `NewLinuxCollector(iface, attributor)` — captures on "any" interface |
| `linux_attributor.go` | linux | Attributes DNS queries to PIDs via `/proc/net/udp` |
| `linux_socket_lookup.go` | linux | `NewLinuxSocketLookup()` — parses `/proc/net/udp` |
| `darwin.go` | darwin | `NewMacOSCollector(iface, attributor)` — captures on en0 |
| `darwin_attributor.go` | darwin | Attributes DNS queries on macOS |
| `darwin_socket_lookup.go` | darwin | macOS socket table lookup |

All platform variants implement the `dns.Collector` interface consumed by `monitor.DNSMonitor`.

---

### 6. File Collector (`internal/collector/file/`)

Platform-specific — two independent implementations.

#### Linux (`linux.go`, `linux_fanotify.go`, `linux_event.go`)

Uses **fanotify** (kernel 5.9+, `CAP_SYS_ADMIN`).

| File | Role |
|------|------|
| `linux_event.go` | Pure event conversion (mask → `FileOperation`); no syscalls; fully unit-testable |
| `linux_fanotify.go` | `fanotifyBackend` interface + `realFanotifyBackend`; kernel ring-buffer parsing |
| `linux.go` | `linuxCollector` — wires backend + process resolver; exported as `NewLinuxCollector` |
| `linux_test.go` | 13 tests using `fakeBackend` and `fakeLinuxProcessResolver` |

**fanotify init flags:** `FAN_CLASS_NOTIF | FAN_REPORT_FID | FAN_REPORT_DIR_FID | FAN_REPORT_NAME | FAN_NONBLOCK | FAN_CLOEXEC`

**Event mask:** `FAN_CLOSE_WRITE | FAN_CREATE | FAN_DELETE | FAN_MOVED_FROM | FAN_MOVED_TO | FAN_ONDIR`

**Path resolution:**
- `FAN_CLOSE_WRITE` (Fd ≥ 0): `os.Readlink("/proc/self/fd/{fd}")`
- `FAN_CREATE/DELETE/MOVE` (Fd = -1): FID record parsing → `unix.OpenByHandleAt` → readlink

#### macOS (`darwin.go`, `es_cgo.go`, `es_callback.go`, `es_bridge.h/m`)

Uses **Endpoint Security** framework (CGo, requires entitlement).

| File | Build tag | Role |
|------|-----------|------|
| `darwin.go` | `darwin` | `macOSCollector` struct, `Run`, `Close`, `enqueueEvent` |
| `darwin_es_init.go` | `darwin && cgo` | `NewMacOSCollector()` — creates real ES client, sets `activeCollector` |
| `darwin_es_nocgo.go` | `darwin && !cgo` | Stub returning error (ES requires CGo) |
| `es_cgo.go` | `darwin && cgo` | Go wrapper around `es_bridge.h` (`newESClient`, `subscribe`, `close`) |
| `es_callback.go` | `darwin && cgo` | `sentinelGoESEvent` — C→Go callback; routes events via `atomic.Pointer[macOSCollector]` |
| `es_bridge.h` | C | Header declaring `sentinel_es_client_*` functions |
| `es_bridge.m` | Objective-C | `es_new_client` + `es_subscribe` bridge; passes normalized event types 1–4 to Go |

**Normalized event type constants** (must match `es_event.go`):
- 1 = Create, 2 = Write, 3 = Unlink, 4 = Rename

**Requirement:** `com.apple.developer.endpoint-security.client` entitlement + root.  
**Sign for dev:** `codesign -s - --entitlements entitlements.plist ./sentinel`

---

### 7. Monitors (`internal/monitor/`)

Thin adapter layer: collector → event bus. One monitor per telemetry type.

| Monitor | Constructor | Runs |
|---------|-------------|------|
| `ProcessMonitor` | `NewProcessMonitor(collector, detector, interval, bus, coordinator)` | polls on interval |
| `NetworkMonitor` | `NewNetworkMonitor(collector, detector, interval, bus)` | polls on interval |
| `DNSMonitor` | `NewDNSMonitor(collector, bus)` | blocking collector loop |
| `FileMonitor` | `NewFileMonitor(collector, bus)` | blocking collector loop |

All monitors convert domain structs into `core.Event` and call `bus.Publish`.

---

### 8. Detection — Process (`internal/detection/process/`)

Rule-based detection on process events.

- `LifecycleDetector` — tracks process start/exit events
- `Registry` + `Rule` interface — pluggable rule system
- `SuspiciousChildProcessRule` — fires when a high-value parent (bash, python, curl…) spawns a child
- `Engine` — evaluates registered rules against each event
- `Coordinator` — connects Engine to a Sink; called from both bus subscriber and ProcessMonitor

---

### 9. Detection — Network (`internal/detection/network/`)

- `LifecycleDetector` — detects new connections and disconnects

---

### 10. Correlation Engine (`internal/detection/correlation/`)

Cross-process behavioral pattern matching.

| File | Role |
|------|------|
| `engine.go` | `Engine` — accumulates state; `Process(event)`; `DetectBehaviors()` |
| `pattern.go` | `BehaviorPattern` struct; `DefaultPatterns()` |
| `matcher.go` | `Matcher.MatchPattern` — evaluates a pattern against relationships + chains |
| `chain.go` | `Chain` — ordered event sequence for one process |
| `relationship.go` | `ProcessRelationship` — parent→child edge |
| `state.go` | `State` — time-windowed event accumulator |

**Deduplication:** `emitted map[string]time.Time` — a finding for rule X is suppressed until one full `window` (5 min) has elapsed since it last fired.

**DefaultPatterns** watch for: process spawning children that make network connections, and similar multi-step behavioral chains.

---

### 11. Finding Sink (`internal/finding/`)

| Type | Role |
|------|------|
| `Sink` interface | `Handle(*core.Finding)` |
| `ConsoleSink` | Prints findings to stdout (used before TUI) |
| `SinkFunc` | Adapts any `func(*core.Finding)` to `Sink` — used by main to route findings into the TUI |

---

### 12. Terminal UI (`cmd/sentinel/ui.go`)

Built with **tview** (tcell backend).

- 5 tabs: Process · Network · DNS · File · Findings
- Each tab is a scrolling `tview.TextView` that auto-scrolls on new events
- Tab bar rendered as colored text; active tab highlighted white-on-white
- Navigation: keys `1`–`5` or `←`/`→` arrows
- Thread-safe: `Add*` methods use `app.QueueUpdateDraw` to safely call from bus subscriber goroutines

| Method | Tab | Color |
|--------|-----|-------|
| `AddProcess(line)` | 1 | green |
| `AddNetwork(line)` | 2 | cyan |
| `AddDNS(line)` | 3 | yellow |
| `AddFile(line)` | 4 | orange |
| `AddFinding(line)` | 5 | red |

---

### 13. Platform Entry Points (`cmd/sentinel/`)

`main.go` is fully platform-neutral. Platform-specific wiring lives in build-tag-gated files.

#### `platform_linux.go` (`//go:build linux`)
- DNS: `NewLinuxSocketLookup` → `NewLinuxAttributor` → `NewLinuxCollector("any")` → `DNSMonitor`
- File: `NewLinuxCollector("/")` → `FileMonitor`
- Returns closers slice; errors from file monitor logged but non-fatal (CAP_SYS_ADMIN may be absent)

#### `platform_darwin.go` (`//go:build darwin`)
- DNS: `NewDarwinSocketLookup` → `NewDarwinAttributor` → `NewMacOSCollector("en0")` → `DNSMonitor`
- File: `NewMacOSCollector()` → `FileMonitor` (gracefully skipped if ES entitlement missing)

#### `main.go`
- Creates `EventBus(1000)`, `CorrelationEngine(5min)`, `ProcessMonitor`, `NetworkMonitor`
- Wires 6 bus subscribers: process log, network log, DNS log, file log, process detection coordinator, correlation engine
- Calls `buildPlatformMonitors(ctx, bus)` for platform-specific DNS + file
- Blocks on `ui.Run()`; on Ctrl+C: `bus.Shutdown()` → `bus.Wait()` → `ui.Stop()`

#### Adding a new OS
Create `cmd/sentinel/platform_windows.go` with `//go:build windows` implementing the same `buildPlatformMonitors(ctx, bus) ([]func(), error)` signature. Nothing else needs to change.

---

### 14. Installer & Release (`install.sh`, `.github/workflows/release.yml`)

#### GitHub Actions release workflow
Triggered on `v*` tags. Two parallel jobs:
- `build-amd64` on `ubuntu-latest` with `libpcap-dev`
- `build-arm64` on `ubuntu-latest` with `gcc-aarch64-linux-gnu` + `libpcap-dev:arm64` (multi-arch)

Both upload artifacts to a `release` job that checksums and publishes to GitHub Releases.

#### `install.sh`
One-liner installer:
```bash
curl -fsSL https://raw.githubusercontent.com/arafat2020/sentinel/main/install.sh | sudo bash
```
Steps: OS/arch check → kernel version warning (< 5.9) → fetch latest version from GitHub API → download binary → SHA-256 verify → install to `/usr/local/bin` → offer libpcap install → offer systemd service setup.

Supported architectures: `x86_64` (amd64), `aarch64` / `arm64`.

---

## Running

### macOS (DNS + process + network)
```bash
go build -o sentinel ./cmd/sentinel
sudo ./sentinel
```

### macOS with file telemetry (requires entitlement)
```bash
# Create entitlements.plist with com.apple.developer.endpoint-security.client
go build -o sentinel ./cmd/sentinel
codesign -s - --entitlements entitlements.plist ./sentinel
sudo ./sentinel
```

### Linux (full cycle)
```bash
sudo apt install libpcap-dev
go build -o sentinel ./cmd/sentinel
sudo ./sentinel        # needs CAP_SYS_ADMIN for fanotify, libpcap for DNS
```

### Install from GitHub (Linux)
```bash
curl -fsSL https://raw.githubusercontent.com/arafat2020/sentinel/main/install.sh | sudo bash
```

---

## Keyboard Controls (TUI)

| Key | Action |
|-----|--------|
| `1` | Process tab |
| `2` | Network tab |
| `3` | DNS tab |
| `4` | File tab |
| `5` | Findings tab |
| `←` / `→` | Cycle tabs |
| `Ctrl+C` | Quit |

---

## Changelog

### Post-initial-release fixes

#### README overhaul
`README.md` was empty. Replaced with a full project readme covering:
- Feature list, quick-start for Linux (one-liner) and macOS (with/without ES entitlement)
- Architecture diagram and layer table
- Requirements tables per platform
- Release binary asset table
- Upcoming features section
- Full project directory tree

#### `.gitignore` — root binary
Added `/sentinel` (leading slash = repo root only) so the locally-built dev binary is not accidentally staged.

#### CI/CD — CGo files included on Linux (amd64 build broken)

**Root cause:** Go's filename-based OS filtering only excludes files that *end* with `_GOOS.ext` (e.g. `foo_darwin.c`). Files that *start* with `darwin_` are compiled on all platforms. CGo compiled `darwin_socket_lookup_bridge.c` and `es_bridge.m` on Linux, producing:
```
C source files not allowed when not using cgo or SWIG: darwin_socket_lookup_bridge.c
```

**Fix:** renamed all four darwin-only C/ObjC files:
| Old name | New name |
|----------|----------|
| `internal/collector/dns/darwin_socket_lookup_bridge.c` | `socket_lookup_bridge_darwin.c` |
| `internal/collector/dns/darwin_socket_lookup_bridge.h` | `socket_lookup_bridge_darwin.h` |
| `internal/collector/file/es_bridge.m` | `es_bridge_darwin.m` |
| `internal/collector/file/es_bridge.h` | `es_bridge_darwin.h` |

Updated the four `#include` lines in `es_bridge_darwin.m`, `es_cgo.go`, `socket_lookup_bridge_darwin.c`, and `darwin_socket_lookup.go`.

#### CI/CD — arm64 cross-compilation broken (three iterations)

**Iteration 1 — apt 404s on security.ubuntu.com**

Ubuntu 24.04 uses deb822 format (`/etc/apt/sources.list.d/ubuntu.sources`) instead of the legacy one-line format. After `dpkg --add-architecture arm64`, apt fetches arm64 package lists from ALL configured sources including `security.ubuntu.com`, which does not carry arm64. The original inline `sed` command silently failed to patch the deb822 file, so the 404s remained.

**Fix:** extracted arm64 apt setup to `.github/scripts/setup-arm64-apt.sh`:
- Handles deb822 format via Python3 (injects `Architectures: amd64` after each `Types: deb` stanza)
- Handles legacy `.list` format via `sed`
- Writes arm64-only source pointing exclusively to `ports.ubuntu.com`
- Called from workflow as `sudo bash .github/scripts/setup-arm64-apt.sh`

**Iteration 2 — Microsoft prod list corrupted**

The `sed` pattern `s|^deb |deb [arch=amd64] |` matched lines that already carried options (e.g. `deb [arch=amd64,arm64 signed-by=...] https://packages.microsoft.com/...`), prepending a second `[arch=amd64]` and producing a malformed entry:
```
E: Malformed entry 1 in list file /etc/apt/sources.list.d/microsoft-prod.list
```

**Fix:** changed the pattern to only match `deb ` when the next character is NOT `[`:
```bash
sed -i "s|^deb \([^[]\)|deb [arch=amd64] \1|"
```

**Iteration 3 — libpcap-dev:arm64 not found**

The setup script added `ports.ubuntu.com` to the apt sources but didn't call `apt-get update` after adding them, so the package index had no knowledge of arm64 packages.

**Fix:** added `apt-get update -qq` as the second-to-last line of `setup-arm64-apt.sh`.

#### Linux file telemetry — paths blank in File tab

**Root cause:** with `FAN_REPORT_FID` set in `fanotify_init`, the kernel does NOT open a file descriptor for events — it sends FID records instead, and `meta.Fd` is `FAN_NOFD (-1)` for ALL events including `FAN_CLOSE_WRITE`. The FID record type for `FAN_CLOSE_WRITE` is type 1 (`FAN_EVENT_INFO_TYPE_FID` — the file's own handle). `resolvePathFromFID` only handled type 2 (`DFID_NAME`) and type 3 (`DFID`), so every `FAN_CLOSE_WRITE` event returned an empty path.

**Fix:** in `linux_fanotify.go`, merged `infoTypeFID` (1) into the `infoTypeDFID` (3) case:
```go
case infoTypeDFID, infoTypeFID:
    // infoTypeFID: file's own FID sent for FAN_CLOSE_WRITE when FAN_REPORT_FID is set.
    if path := parseFIDRecord(infoBuf[offset:offset+infoLen], mountFd, false); path != "" {
        return path
    }
```
`parseFIDRecord` calls `OpenByHandleAt` on any file handle (file or directory) and resolves the absolute path via `/proc/self/fd`, so the same code path works for both.

---

## Known Gaps / Next Steps

| Area | Status | Notes |
|------|--------|-------|
| Windows support | Not started | Add `platform_windows.go` with ETW-based collectors |
| macOS file entitlement | Needs signing | ES client returns `ERR_NOT_ENTITLED` without `com.apple.developer.endpoint-security.client` |
| `DefaultPatterns` coverage | Minimal | Only basic parent→child→network chain; more behavioral rules needed |
| `es_event.go` test leak | Tech debt | `TestMacOSEventChannel` is in a non-test file; should move to `_test.go` |
| Findings persistence | Not started | Findings only go to TUI; no log file or SIEM export |
| Config file | Not started | Watch paths, rule toggles, severity thresholds all hardcoded |
| First release tag | Pending | No `v*` tag pushed yet; installer returns 404 until one exists |
