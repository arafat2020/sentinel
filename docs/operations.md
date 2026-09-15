# Sentinel — Operations Guide

Covers everything added beyond the core detection engine: persistent storage,
server deployment, log querying, and the Settings tab.

---

## Building

```bash
make build       # standard build + ad-hoc codesign (required on macOS)
make run         # sudo ./sentinel
make clean       # remove binary
```

Always use `make build`, never bare `go build`. The Makefile runs
`codesign --force --sign -` after every build to strip any leftover
Endpoint Security entitlement from the signature; without this step macOS
AMFI kills the binary on launch.

---

## Running modes

### Interactive (default)

```bash
sudo ./sentinel
```

Full TUI with 7 tabs. Requires a real terminal (TTY).

### Headless — server / systemd

```bash
sudo ./sentinel --headless
```

No TUI. Findings are written to stdout as plain log lines:

```
2026/09/15 10:03:12 FINDING severity=HIGH rule=webserver-spawns-shell  nginx spawned bash
```

All events are still persisted to `sentinel.db` (same database as the
interactive mode). Suitable for:

```bash
# Background daemon, survives SSH logout
nohup sudo ./sentinel --headless >> /var/log/sentinel.log 2>&1 &

# systemd unit
[Unit]
Description=Sentinel endpoint monitor

[Service]
ExecStart=/usr/local/bin/sentinel --headless
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

### Graceful shutdown on terminal close

`SIGHUP` (sent when an SSH session closes or a terminal window is killed) is
handled the same as `SIGTERM` — the engine drains, the database is flushed,
and the process exits cleanly. Without this, a TUI process left in the
foreground of a closing terminal would hang indefinitely writing to a dead TTY.

---

## Persistent event store

All telemetry is written to **`sentinel.db`** (SQLite, WAL mode) in the
working directory. Events are batched in groups of 100 or flushed every 200 ms,
so disk I/O never blocks the collectors.

### What is stored

| Tab | Content |
|---|---|
| Process | Every `PROCESS_START` / `PROCESS_EXIT` line |
| Network | Every `NETWORK_CONNECT` / `NETWORK_CLOSE` line |
| DNS | Every `DNS_QUERY` line |
| File | Every file event line |
| Findings | Every behavioral finding |

### RAM usage

The TUI keeps at most **500 lines per tab** in memory (ring buffer). When a
tab exceeds 500 events, the oldest lines are evicted from the display but
remain in the database. Total display memory is bounded at ~2 500 lines
regardless of uptime.

---

## Querying stored events

Use the `--query` flag to filter `sentinel.db` from the command line. The
binary opens the database, prints matching rows, and exits — no collectors
start.

```bash
# All events today
./sentinel --query --since 2026-09-15

# Findings only, last 24 hours
./sentinel --query --tab Findings --since 2026-09-14T10:00

# Network events in a time window
./sentinel --query --tab Network \
    --since 2026-09-14T08:00 \
    --until 2026-09-14T18:00

# DNS events, newest 50
./sentinel --query --tab DNS --limit 50

# All tabs, specific day
./sentinel --query --since 2026-09-14 --until 2026-09-14T23:59:59
```

### Flags

| Flag | Default | Description |
|---|---|---|
| `--tab` | all tabs | Filter by tab name: `Process` `Network` `DNS` `File` `Findings` |
| `--since` | none | Earliest timestamp. Accepts `YYYY-MM-DD` or `YYYY-MM-DDTHH:MM:SS` |
| `--until` | none | Latest timestamp. Same formats as `--since` |
| `--limit` | 200 | Maximum rows to print |

Output format:
```
2026-09-15 10:03:12  [Findings]   severity=HIGH rule=webserver-spawns-shell  nginx spawned bash
```

### Raw SQL (sqlite3)

Because `sentinel.db` is a plain SQLite file, any `sqlite3` client works:

```bash
# Count events by tab
sqlite3 sentinel.db "SELECT tab, COUNT(*) FROM events GROUP BY tab"

# All findings this week
sqlite3 sentinel.db \
  "SELECT ts, line FROM events WHERE tab='Findings' AND ts >= '2026-09-09' ORDER BY ts"
```

Schema:
```sql
events   (id INTEGER, ts DATETIME, tab TEXT, line TEXT)
settings (key TEXT PRIMARY KEY, value TEXT)
```

---

## Settings tab (key `7`)

Press `7` or cycle with `←` / `→` to reach the Settings tab.

### Log retention

Controls how long events are kept in `sentinel.db`.

| Control | Action |
|---|---|
| **Retention (days)** field | Type the number of days |
| **Save (Ctrl+S)** | Persist the new value to the database |
| **Flush Now (Ctrl+F)** | Immediately delete events older than the current setting |

The default is **7 days**. Deletion runs once at startup and then every 24
hours automatically — no manual flush required in normal operation.

### SSH remote access kill-switch

Designed for incident response: quickly cut off remote shell access if an
attacker has gained SSH access to the machine.

| Control | Shortcut | Action |
|---|---|---|
| **Refresh Status** | — | Re-check whether sshd is accepting connections |
| **Disable SSH** | `Ctrl+D` | Stop sshd immediately + persist disabled across reboots |
| **Enable SSH** | `Ctrl+E` | Start sshd + persist enabled across reboots |

Both Disable and Enable show a **confirmation modal** before acting. Navigate
modal buttons with `Tab` and confirm with `Enter`.

Status is determined by attempting a TCP connection to `127.0.0.1:22` — the
ground truth regardless of process names or launchd state.

After enabling, Sentinel polls port 22 for up to 5 seconds before reporting
success, so the status display is always accurate.

**Platform implementation:**

| OS | Mechanism |
|---|---|
| macOS | `launchctl enable/disable` + `bootstrap`/`kickstart`/`bootout` |
| Linux | `systemctl start/stop sshd` (falls back to `ssh` service name) |
| Windows | `sc start/stop sshd` |

Sentinel runs as root (`sudo`), so no extra elevation is needed.

**⚠ Warning:** Disabling SSH terminates all active SSH sessions immediately,
including your own if you are connected remotely. The confirmation modal
repeats this warning before every disable action.

---

## DNS telemetry — multi-interface capture

On macOS, DNS traffic can leave on any active network interface: Ethernet,
Wi-Fi, or a VPN tunnel (`utun*`). Sentinel enumerates all UP non-loopback
interfaces with a real IP address at startup and opens a libpcap capture on
each one that succeeds.

At startup you will see:
```
[sentinel] DNS monitor active on 3 interface(s)
```

If you see `0 interface(s)`, the binary is not running as root — libpcap
requires BPF device access, which needs `sudo`.

---

## Key reference

### Global (all tabs)

| Key | Action |
|---|---|
| `1` – `7` | Jump to tab (only from telemetry tabs 1–5) |
| `←` / `→` | Cycle tabs |

### Settings tab

| Key | Action |
|---|---|
| `Tab` | Move between form fields and buttons |
| `Enter` | Press the focused button |
| `Ctrl+S` | Save retention days |
| `Ctrl+F` | Flush old events now |
| `Ctrl+D` | Disable SSH (with confirmation) |
| `Ctrl+E` | Enable SSH (with confirmation) |
