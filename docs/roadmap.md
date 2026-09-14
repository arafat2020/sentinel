# Sentinel — Roadmap

Each item below is ordered by architectural proximity to the existing pipeline.
Every entry answers two questions: **what** gets built and **why it belongs**
inside Sentinel's layered design.

---

## Phase 1 — Close the declared event-type gaps

These event types exist in `core.EventType` and the YAML pattern schema already
accepts them, but nothing in the pipeline produces them yet. Closing these gaps
costs almost no new code — they slot into the existing Bus → Monitor → Collector
chain.

---

### 1.1 Script collector (`EventScriptExecution`)

**What:** A bus subscriber that listens for `PROCESS_START` events. Whenever the
new process name matches a known interpreter (`python`, `python3`, `bash`, `sh`,
`zsh`, `perl`, `ruby`, `node`, `php`, `pwsh`), it re-publishes the event as
`SCRIPT_EXECUTION` with the full command line attached.

**Why it belongs:**
- `EventScriptExecution` is already declared in `core/event.go` and referenced
  in the MVP scope document — the type slot is reserved, just not filled.
- It requires zero new OS API calls; it filters existing `PROCESS_START` events,
  so it is a pure Bus subscriber — the cleanest possible addition at the Monitor
  layer.
- It immediately unlocks a high-value class of patterns: "web server spawned a
  Python script with a suspicious argument", "bash -i is launched by a non-shell
  parent", etc.
- Fits the collector rule: answers *What happened?* (`script X ran with args Y`)
  and delegates *Is this suspicious?* to the detection layer.

**New files:** `internal/monitor/script.go`
**Modified files:** `cmd/sentinel/main.go` (subscribe + publish), `cmd/sentinel/ui.go` (optional script tab or reuse Process tab)

---

### 1.2 Persistence collector (`EventPersistenceChange`)

**What:** A monitor that watches OS-specific persistence directories for
`FILE_CREATE` and `FILE_MODIFY` events, then re-publishes them as
`PERSISTENCE_CHANGE`.

| Platform | Paths watched |
|---|---|
| macOS | `~/Library/LaunchAgents/`, `/Library/LaunchDaemons/`, `/Library/StartupItems/` |
| Linux | `~/.config/systemd/user/`, `/etc/cron.d/`, `/etc/cron.daily/`, `/etc/rc.d/` |
| Windows | `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` (registry) |

macOS and Linux only need a path-prefix filter on existing `FILE_CREATE/MODIFY`
events from the file collector — no new OS API. Windows needs a registry watcher
(a small `golang.org/x/sys/windows/registry` addition).

**Why it belongs:**
- `EventPersistenceChange` is declared in `core/event.go` and listed in the
  MVP scope — same gap-closing rationale as the script collector.
- Persistence is one of the highest-signal indicators in endpoint security:
  legitimate software rarely modifies LaunchDaemon plists or cron.d files at
  runtime without user interaction.
- It reuses the existing file collector and event bus without introducing new
  dependencies on macOS and Linux.
- The detection layer can immediately correlate it: "process A wrote a LaunchAgent
  plist *and* that same process had a prior `NETWORK_CONNECT`" is a strong signal.

**New files:** `internal/monitor/persistence.go`, `internal/monitor/persistence_darwin.go`, `internal/monitor/persistence_linux.go`, `internal/monitor/persistence_windows.go`
**Modified files:** `cmd/sentinel/platform_*.go`

---

## Phase 2 — Rich, explainable findings

The current `core.Evidence` struct holds only `Process *Process` and
`Processes []Process`. The correlation engine already accumulates chains,
network connections, DNS queries, file events, and relationships — but throws
all of it away when it writes a finding. This phase makes findings actionable.

---

### 2.1 Expand `core.Evidence`

**What:** Add the full set of evidence fields the docs describe in section 25:

```go
type Evidence struct {
    Process       *Process
    Processes     []Process
    Network       []NetworkConnection
    DNS           []DNSQuery
    File          []FileEvent
    Relationships []ProcessRelationship
    Explanation   string  // human-readable summary of why the pattern matched
}
```

**Why it belongs:**
- Section 25 of `project-context.md` explicitly defines this richer model and
  states: *"Evidence makes the system easier to debug, test, investigate,
  explain, and extend."*
- The correlation engine already owns all this data (in `chains`, `relationships`,
  `state`). Populating `Evidence` is wiring, not new logic.
- A finding that answers *What happened? Who was involved? What evidence supports
  it?* is the core product promise — without this, the Findings tab is a one-liner
  with no investigative value.
- No layer boundary is crossed: `Evidence` stays in `core`, the correlation
  engine populates it, the finding sink consumes it.

**Modified files:** `internal/core/evidence.go`, `internal/detection/correlation/engine.go` (`DetectBehaviors` populates evidence from chains)

---

### 2.2 Findings detail view in the TUI

**What:** Replace the single-line red text in the Findings tab with an
expandable detail view. Selecting a finding shows: rule name, severity,
timestamp, matched processes, network connections, DNS queries, file events,
and the explanation string.

**Why it belongs:**
- The TUI is the only consumer of findings right now. If evidence is collected
  but not displayed, the improvement in 2.1 is invisible to the user.
- Stays within the `cmd/sentinel` UI layer — no change to core or detection.
- Uses the existing `tview.Pages` pattern already established by the pattern
  editor: a list on the left, detail on the right.

**New files:** `cmd/sentinel/ui_findings.go`
**Modified files:** `cmd/sentinel/ui.go`

---

## Phase 3 — New correlation relationship types

The docs (section 21) list future relationship types. Each one unlocks a new
class of pattern that cannot be expressed today.

---

### 3.1 `COMMUNICATED_WITH`

**What:** Two processes that both established a `NETWORK_CONNECT` to the same
remote `(IP, port)` pair within the correlation window are linked by a
`COMMUNICATED_WITH` relationship.

**Why it belongs:**
- Detects C2 beaconing shared between a parent and child: "process A and process
  B both connected to 203.0.113.5:4444".
- The data is already in the network lifecycle state — this is a new join query
  on existing state, not a new data source.
- Expressed as a new `RelationshipType` constant and a new pass in
  `correlation.Engine.Process()`, it touches only the correlation layer and
  leaves the detection/pattern layer unchanged.

---

### 3.2 `RESOLVED`

**What:** When a `DNS_QUERY` event for domain X is followed within a short
window by a `NETWORK_CONNECT` to the resolved IP, link the process's DNS chain
entry to its network chain entry with a `RESOLVED` relationship.

**Why it belongs:**
- DNS-then-connect is the canonical lateral movement pattern. A process that
  resolves `evil.example.com` and then connects to the returned IP is meaningfully
  different from one that connects directly by IP.
- The data (DNS queries + network connections per process) is already accumulated
  in `State` and `Chain`. This is correlation logic, not collection.

---

### 3.3 `MODIFIED`

**What:** When process A writes a file (`FILE_CREATE` or `FILE_MODIFY`) that
process B later executes (detected as `PROCESS_START` where the executable path
matches the written file), link them with a `MODIFIED` relationship.

**Why it belongs:**
- Detects the dropper → payload pattern: process A downloads and writes a
  binary, process B executes it.
- Stays in the correlation layer — no new OS APIs.
- Directly referenced in the docs as a planned relationship type.

---

## Phase 4 — Operationalize findings

These items make findings useful outside the TUI without changing the detection
architecture.

---

### 4.1 NDJSON finding log

**What:** A second `finding.Sink` implementation that appends one JSON line per
finding to `findings.ndjson` in the working directory.

```json
{"ts":"2026-09-14T10:00:00Z","rule":"webserver-spawns-shell","severity":"HIGH","process":{"pid":1234,"name":"nginx"},"evidence":{...}}
```

**Why it belongs:**
- `finding.Sink` is an interface — adding a second implementation requires zero
  changes to the detection or correlation layers.
- Machine-readable findings let external tools (SIEM, Splunk, a simple `jq`
  query) consume Sentinel output without screen-scraping the TUI.
- Directly follows the architecture's principle that the Finding layer's job is
  to route findings to consumers — logging is a first-class consumer.

**New files:** `internal/finding/ndjson.go`
**Modified files:** `cmd/sentinel/main.go` (register second sink)

---

### 4.2 Per-pattern correlation window

**What:** Add an optional `window` field to the YAML pattern schema:

```yaml
- name: persistent-dns-beaconing
  window: 15m       # overrides the global 5-minute default
  severity: HIGH
  ...
```

**Why it belongs:**
- Persistence events should fire immediately every time (window of 0 or very
  small). DNS beaconing needs a longer window to accumulate evidence. The global
  5-minute default is a blunt instrument.
- The change is entirely within `internal/config/patterns.go` (add field) and
  `internal/detection/correlation/engine.go` (use per-pattern window in
  `DetectBehaviors`). No other layer is touched.

---

### 4.3 Allowlist / suppressions in YAML

**What:** Add a top-level `suppressions` section to `configs/patterns.yaml`:

```yaml
suppressions:
  - pattern: network-active-parent-spawns-python
    process_name: node          # suppress only for this process name
  - path_prefix: /usr/local/bin/
    pattern: "*"               # suppress all patterns for files in this path
```

**Why it belongs:**
- Every detection system generates false positives. Sentinel's architecture
  separates detection logic from suppression policy — suppressions belong in
  config (alongside patterns), not hard-coded in rules.
- Implemented as a filter in `DetectBehaviors()` after pattern matching — a
  single additional check that does not touch the matcher or the pattern structs.
- Editable through the same TUI pattern editor (a new Suppressions tab or section).

---

## Implementation order

```text
Phase 1  ──── Script collector          ← closes declared gap, low effort
         └─── Persistence collector     ← closes declared gap, low effort

Phase 2  ──── Expand Evidence struct    ← must precede findings detail view
         └─── Findings detail view      ← depends on richer Evidence

Phase 3  ──── COMMUNICATED_WITH         ← independent, medium effort
         ├─── RESOLVED                  ← independent, small effort
         └─── MODIFIED                  ← independent, medium effort

Phase 4  ──── NDJSON log                ← independent, very small
         ├─── Per-pattern window        ← independent, small
         └─── Allowlist / suppressions  ← independent, small
```

Phases 1 and 4 are independent of each other and can be interleaved.
Phase 2 must precede the findings detail view but is otherwise independent.
Phase 3 items are each independent and can be picked in any order.
