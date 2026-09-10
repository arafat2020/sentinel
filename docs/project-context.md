# Sentinel — Project Context

> This document is the authoritative reference for any AI model or contributor working on the Sentinel project.
> It covers the project objective, high-level and layered architecture, the current implementation state, and all engineering conventions.

---

## Table of Contents

1. [Project Identity](#1-project-identity)
2. [Project Objective](#2-project-objective)
3. [Core Problem Being Solved](#3-core-problem-being-solved)
4. [Core Concepts](#4-core-concepts)
5. [Project Goals](#5-project-goals)
6. [Non-Goals](#6-non-goals)
7. [MVP Scope](#7-mvp-scope)
8. [High-Level Architecture](#8-high-level-architecture)
9. [Layered Architecture](#9-layered-architecture)
10. [Collector Layer](#10-collector-layer)
11. [Core Model Layer](#11-core-model-layer)
12. [Event Model](#12-event-model)
13. [Event Bus](#13-event-bus)
14. [Process Identity](#14-process-identity)
15. [Process Lifecycle](#15-process-lifecycle)
16. [Network Lifecycle](#16-network-lifecycle)
17. [DNS Architecture](#17-dns-architecture)
18. [File Telemetry Architecture](#18-file-telemetry-architecture)
19. [Platform Abstraction](#19-platform-abstraction)
20. [Correlation Engine](#20-correlation-engine)
21. [Process Relationships](#21-process-relationships)
22. [Behavioral Patterns](#22-behavioral-patterns)
23. [Detection Rules](#23-detection-rules)
24. [Findings](#24-findings)
25. [Evidence Model](#25-evidence-model)
26. [Current Implementation State](#26-current-implementation-state)
27. [Development Order](#27-development-order)
28. [Engineering Conventions](#28-engineering-conventions)
29. [Definition of Done](#29-definition-of-done)
30. [Guiding Principles](#30-guiding-principles)
31. [Final Mental Model](#31-final-mental-model)

---

## 1. Project Identity

**Sentinel** is a telemetry and behavioral-pattern detection project.

> **Important:** Sentinel is separate from the *Sentinal Agent* project, which deals with central-server management, offline updates, and remote agent version control. These are distinct projects with different purposes.

---

## 2. Project Objective

Sentinel is a **cross-platform endpoint telemetry and behavioral detection system** written primarily in Go.

Its purpose is to:

1. Observe activity occurring on an endpoint.
2. Normalize platform-specific activity into a common event model.
3. Correlate related events.
4. Match correlated activity against predefined behavioral patterns.
5. Produce explainable findings with supporting evidence.

### Core Pipeline

```text
Operating System
       ↓
   Telemetry
       ↓
   Collectors
       ↓
  Core Events
       ↓
   Event Bus
       ↓
  Correlation
       ↓
Behavioral Patterns
       ↓
   Detection
       ↓
   Findings
       ↓
Evidence / Explanation
```

The primary focus is **behavioral telemetry**, not malware signatures.

---

## 3. Core Problem Being Solved

A single event often carries little meaning in isolation.

```text
NETWORK_CONNECT                 <- not inherently suspicious
PROCESS_START: python           <- not inherently suspicious
```

But a **sequence** of events can represent a meaningful behavioral pattern:

```text
node
  ↓
NETWORK_CONNECT
  ↓
SPAWN python
  ↓
python
  ↓
NETWORK_CONNECT
  ↓
FILE_MODIFY
```

Therefore Sentinel asks:

> **"Does the sequence of observed behaviors match a predefined suspicious pattern?"**

rather than:

> **"Is this specific file or process malware?"**

---

## 4. Core Concepts

### Telemetry

Record what actually happened on the endpoint:

```text
Process started / exited
Network connection occurred
DNS query occurred
File created / modified / deleted / renamed
Script/interpreter executed
Persistence-related change occurred
```

### Behavioral Detection

Interpret combinations of those events. Example:

```text
NETWORK_CONNECT
       +
PROCESS_START
       +
SPAWNED
       +
Child = python
       +
Python NETWORK_CONNECT
```

> Telemetry should remain useful even when no detection rule matches.

---

## 5. Project Goals

| Goal | Description |
|------|-------------|
| **Reliable Telemetry** | Capture useful endpoint activity with timestamps and relevant context. |
| **Cross-Platform Core** | Use a common event/domain model while allowing platform-specific collectors. |
| **Process Attribution** | Identify the process responsible for an event whenever technically possible. |
| **Event Correlation** | Connect related events belonging to the same process or process tree. |
| **Behavioral Pattern Detection** | Detect predefined suspicious combinations of events. |
| **Explainable Findings** | Every detection must explain what, who, which events, which relationships, and why. |
| **Extensibility** | Adding a new collector or pattern must not require rewriting unrelated components. |
| **Correctness Before Optimization** | Correctness and reliable telemetry take priority over performance. |

---

## 6. Non-Goals

Sentinel is **not** intended to be:

- A traditional antivirus
- A malware signature database
- A full enterprise EDR platform
- A machine-learning malware classifier
- A threat-intelligence platform
- A cloud dashboard
- A remediation engine
- A fleet-management platform
- A remote software-update system
- A billing or multi-tenant SaaS platform

These may belong to separate projects or future extensions.

---

## 7. MVP Scope

```text
Process telemetry
Process lifecycle
Network telemetry
Network lifecycle
DNS telemetry
File telemetry
Script/interpreter telemetry
Persistence telemetry
Event Bus
Correlation
Behavioral patterns
Detection rules
Findings
Explainable evidence
```

Implementation proceeds incrementally, one stable vertical slice at a time.

---

## 8. High-Level Architecture

```text
                    ┌─────────────────────┐
                    │   Operating System  │
                    └──────────┬──────────┘
                               │
                         Native Telemetry
                               │
                               ▼
                    ┌─────────────────────┐
                    │      Collectors     │
                    │                     │
                    │ Process             │
                    │ Network             │
                    │ DNS                 │
                    │ File                │
                    │ Script              │
                    │ Persistence         │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │    Core Models      │
                    │                     │
                    │ Process             │
                    │ NetworkConnection   │
                    │ DNSQuery            │
                    │ FileEvent           │
                    │ Event               │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │      Event Bus      │
                    └──────────┬──────────┘
                               │
                ┌──────────────┼──────────────┐
                ▼              ▼              ▼
          Lifecycle       Correlation      Logging
             State           Engine
                │              │
                └──────────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │ Behavioral Patterns │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │   Detection Rules   │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │ Findings + Evidence │
                    └─────────────────────┘
```

---

## 9. Layered Architecture

```text
┌─────────────────────────────────────────┐
│              Finding Layer              │
├─────────────────────────────────────────┤
│            Detection Layer              │
├─────────────────────────────────────────┤
│          Behavioral Pattern Layer       │
├─────────────────────────────────────────┤
│            Correlation Layer            │
├─────────────────────────────────────────┤
│              Event Bus                  │
├─────────────────────────────────────────┤
│             Core Models                 │
├─────────────────────────────────────────┤
│             Collector Layer             │
├─────────────────────────────────────────┤
│            Platform APIs                │
└─────────────────────────────────────────┘
```

Each layer has a single, clear responsibility. Layers only depend on layers below them.

---

## 10. Collector Layer

Collectors translate OS-specific telemetry into Sentinel domain models.

**Examples:**
- Process Collector
- Network Collector
- DNS Collector
- File Collector
- Script Collector
- Persistence Collector

A collector answers:
> **"What happened?"**

It does **not** answer:
> **"Is this suspicious?"**

Detection belongs exclusively to the detection layer.

---

## 11. Core Model Layer

The `core` package contains **platform-neutral** domain models.

```go
type Process struct {
    PID         int32
    PPID        int32
    StartTime   time.Time
    Name        string
    Executable  string
    CommandLine string
    User        string
}
```

**Core models include:**
- `Process`
- `NetworkConnection`
- `DNSQuery`
- `FileEvent`
- `Event`

Core models must **not** contain platform-specific implementation details.

---

## 12. Event Model

Collectors normalize telemetry into `core.Event`:

```text
Platform Observation
        ↓
Domain Model
        ↓
core.Event
```

**Current event types:**

| Category | Event Type |
|----------|------------|
| Process | `PROCESS_START`, `PROCESS_EXIT`, `PROCESS_SNAPSHOT` |
| Network | `NETWORK_CONNECT`, `NETWORK_CLOSE` |
| DNS | `DNS_QUERY` |
| File | `FILE_CREATE`, `FILE_MODIFY`, `FILE_DELETE`, `FILE_RENAME` |
| Persistence | `PERSISTENCE_CHANGE` |
| Script | `SCRIPT_EXECUTION` |

Events must contain enough information for correlation and detection.

---

## 13. Event Bus

The Event Bus is the internal transport layer decoupling producers from consumers.

```text
Collector
    ↓
Publish(Event)
    ↓
Bounded Queue
    ↓
Worker
    ↓
Handlers
```

**Potential consumers:**
- Lifecycle Detector
- Correlation Engine
- Detection Engine
- Finding Sink
- Logger

### Event Bus Requirements

| Requirement | Description |
|-------------|-------------|
| Bounded buffering | Queue capacity is finite and explicit |
| Backpressure | Producers are signaled when the queue is full |
| Safe concurrent publishing | Multiple goroutines can publish safely |
| Graceful shutdown | In-flight events are drained before exit |
| Blocked-publisher unblocking | Shutdown unblocks any waiting producers |
| Queue draining | Events are drained on shutdown where appropriate |
| Idempotent shutdown | Calling shutdown multiple times is safe |
| Explicit worker lifecycle | Worker start/stop is explicit and observable |
| Race-safe behavior | Verified with `go test -race` |

> The Event Bus must **not** contain detection logic.

### Event Loss Policy

Because queues are bounded, event-loss behavior must be **explicit and intentional**. Possible policies:

```text
Block producer
Drop event
Drop oldest
Prioritize event classes
```

Security-relevant telemetry must never silently disappear without a defined, documented reason.

---

## 14. Process Identity

PID alone is **not** a reliable identity due to PID reuse:

```text
PID 100 -> Process A exits -> PID 100 is reused -> Process B starts
```

Sentinel uses a composite identity:

```text
ProcessIdentity
├── PID
└── StartTime
```

This identity is used for lifecycle detection and correlation throughout the system.

---

## 15. Process Lifecycle

The lifecycle detector compares process observations over time:

```text
Previous Snapshot
        ↓
Current Snapshot
        ↓
Compare ProcessIdentity
        ↓
 ┌──────┴───────┐
 ▼              ▼
New process   Missing process
    │              │
    ▼              ▼
PROCESS_START  PROCESS_EXIT
```

PID reuse must **never** produce false lifecycle relationships.

---

## 16. Network Lifecycle

Network connections have their own identity:

```text
Previous Connections
        ↓
Current Connections
        ↓
Compare ConnectionIdentity
        ↓
 ┌──────┴──────┐
 ▼             ▼
New connection  Missing connection
 ▼             ▼
CONNECT         CLOSE
```

The connection identity must distinguish materially different connections.

---

## 17. DNS Architecture

The current macOS MVP uses packet capture:

```text
Network Interface
       ↓
    libpcap
       ↓
    GoPacket
       ↓
    DNS Parser
       ↓
Socket Attribution
       ↓
      PID
       ↓
Process Resolver
       ↓
    DNSQuery
       ↓
  EventDNSQuery
```

### Attribution Rules

Attribution must **never be fabricated**. When attribution cannot be established:

```text
PID = 0
Process = nil
```

This is a valid and expected outcome. The system must always distinguish **Observed** from **Inferred**.

**Known limitations** (must be documented, not worked around with fabrication):
- Encrypted DNS (DoH/DoT)
- OS-level DNS caching
- Local resolver architecture

---

## 18. File Telemetry Architecture

General model:

```text
Operating System
       ↓
Platform File API
       ↓
Platform Adapter
       ↓
FileEvent
       ↓
core.Event
       ↓
Event Bus
```

On **macOS**, Endpoint Security is used because Sentinel needs filesystem activity together with process context:

```text
Endpoint Security
       ↓
C / Objective-C Bridge
       ↓
Go Callback Boundary
       ↓
esEvent
       ↓
convertESEvent()
       ↓
core.FileEvent
       ↓
FileMonitor
       ↓
EventBus
```

Native code must remain **minimal**. No business logic in native callbacks.

---

## 19. Platform Abstraction

The core system must remain platform-neutral:

```text
                 Core Models
                     ▲
                     │
          ┌──────────┼──────────┐
          │          │          │
        macOS      Linux      Windows
       Adapter    Adapter     Adapter
          │          │          │
       Native      Native     Native
        APIs        APIs       APIs
```

Platform-specific implementation belongs **only** at the collector/platform boundary.

The detection engine must receive normalized events regardless of whether they came from Endpoint Security, `/proc`, Windows APIs, or libpcap.

---

## 20. Correlation Engine

Correlation gives individual events context by maintaining short-lived state:

- Process state
- Process relationships
- Event chains
- Temporal windows
- Relevant process metadata

**Example correlation context:**

```text
Process A
    │
    ├── NETWORK_CONNECT
    │
    └── SPAWNED
          │
          ▼
       Process B
          │
          ├── NETWORK_CONNECT
          │
          └── FILE_MODIFY
```

> The correlation engine creates context. It does **not** decide that behavior is malicious — that belongs to the detection layer.

---

## 21. Process Relationships

Relationships are first-class correlation information.

**Current relationship:**
```text
Parent
  └── SPAWNED -> Child
```

**Future relationships (introduced only when a concrete need exists):**
```text
SPAWNED
COMMUNICATED_WITH
RESOLVED
MODIFIED
LOADED
```

New relationship types should only be introduced when an actual correlation or detection requirement needs them.

---

## 22. Behavioral Patterns

Patterns describe combinations or sequences of observable behavior.

**Example pattern:** `network-active-parent-spawns-python`

```text
Parent has NETWORK_CONNECT
        +
Parent SPAWNED child
        +
Child name = python
        +
Child has NETWORK_CONNECT
```

Patterns describe **behavior**, not a specific malware family.

---

## 23. Detection Rules

Detection evaluates correlated state against behavioral patterns:

```text
Correlation State
       ↓
Pattern Matcher
       ↓
Detection Rule
       ↓
Match / No Match
```

Rules must be:
- **Deterministic** — same input always produces same result
- **Testable** — can be verified in isolation
- **Explainable** — the reason for a match is clear
- **Platform-independent** — work on normalized events, not raw OS data

---

## 24. Findings

A finding represents a meaningful detection result:

```text
Finding
├── Rule
├── Severity
├── Timestamp
├── Process
├── Evidence
├── Relationships
└── Explanation
```

A finding must answer:
- What happened?
- Who was involved?
- What pattern matched?
- What evidence supports it?
- Why did it match?

---

## 25. Evidence Model

Detection must preserve evidence rather than returning only a boolean.

**Bad:**
```text
suspicious = true
```

**Better:**
```text
Pattern:
    network-active-parent-spawns-python

Evidence:
    1. node connected to a remote endpoint.
    2. node spawned python.
    3. python connected to a remote endpoint.
    4. python modified a file.
```

Evidence makes the system easier to debug, test, investigate, explain, and extend.

---

## 26. Current Implementation State

```text
Process telemetry                   ✅
Process lifecycle                   ✅
Process identity                    ✅
Process tree                        ✅

Event Bus                           ✅
Backpressure                        ✅
Graceful shutdown                   ✅
Race-safe behavior                  ✅

Network telemetry                   ✅
Network lifecycle                   ✅

DNS telemetry                       ✅
DNS packet parsing                  ✅
DNS socket attribution              ✅
DNS process resolution              ✅

File core model                     ✅
File monitor                        ✅
File event conversion               ✅
macOS ES collector foundation       ✅
ES event queue                      ✅
Go-side event processing            ✅

Native ES callback -> Go            ⏳
Real Endpoint Security integration  ⏳

Correlation engine                  ⏳
Behavioral patterns                 ⏳
Detection rules                     ⏳
Explainable findings                ⏳
```

---

## 27. Development Order

```text
Core Models
    ↓
Process Collector
    ↓
Process Lifecycle
    ↓
Event Bus
    ↓
Network Collector
    ↓
Network Lifecycle
    ↓
DNS Collector
    ↓
DNS Attribution
    ↓
File Collector
    ↓
Script/Interpreter Telemetry
    ↓
Persistence Telemetry
    ↓
Correlation
    ↓
Behavioral Patterns
    ↓
Detection Rules
    ↓
Explainable Findings
```

The exact order can change when dependencies require it, but each stage must establish a stable foundation for the next.

---

## 28. Engineering Conventions

### TDD-First

Sentinel follows **Test-Driven Development** as the default workflow:

```text
RED   -> Write failing test
GREEN -> Implement minimum behavior
REFACTOR -> Validate -> Commit
```

Do not implement an entire subsystem and add tests afterward.

### Vertical Slice Convention

Features are implemented in small, end-to-end slices. Each slice must be green before moving to the next.

**Example for file telemetry:**
```text
1. Define FileEvent
2. Write tests
3. Implement FileMonitor
4. Test monitor
5. Define native event representation
6. Test conversion
7. Implement collector lifecycle
8. Test lifecycle
9. Implement event queue
10. Test event delivery
11. Implement native callback bridge
12. Test callback delivery
13. Real Endpoint Security integration
```

### Test Pyramid

| Level | Scope | Examples |
|-------|-------|---------|
| **Unit** | Pure deterministic logic | `Identity()`, `convertESEvent()`, `dnsTypeName()`, pattern matching |
| **Component** | Go component interactions | Collector → Monitor → EventBus (with fakes) |
| **Integration** | Real OS APIs | Endpoint Security, real process APIs, real socket lookup |
| **Race** | Concurrent components | `go test -race ./...` |

### Test Convention

Use **Given / When / Then** structure. Example:

```text
Given a DNS packet from 192.168.1.100:54321
When socket attribution finds PID 12345
Then DNSQuery.PID == 12345
```

Tests must cover: happy path, empty input, invalid input, dependency failure, context cancellation, shutdown, concurrency.

### Dependency Injection

External/system dependencies are abstracted for test control:

```go
type SocketLookup interface {
    FindOwner(ctx context.Context, sourceIP string, sourcePort uint32) (*SocketOwner, error)
}
```

- Production: `RealSocketLookup`
- Tests: `FakeSocketLookup`

Prefer **narrow interfaces**.

### Error Handling

Errors must describe the operation that failed:

```go
// Correct
return fmt.Errorf("create Endpoint Security client: %w", err)

// Avoid
return err
```

Expected enrichment failures must not destroy underlying telemetry:

```text
DNS Query Observed -> Attribution Fails -> Keep DNS Event (PID = 0)
```

### Context Convention

All long-running operations accept `context.Context`:

```go
func Run(ctx context.Context) error
func Resolve(ctx context.Context, pid int32) (*Process, error)
```

Every long-running goroutine must have a clear termination path.

### Concurrency Convention

For every background goroutine, explicitly know:

```text
Who starts it?
Who owns it?
What stops it?
How is it waited for?
```

Avoid: goroutine leaks, hidden workers, unbounded goroutine creation, shutdown races, permanent channel blocking.

### Native Code Convention

C/Objective-C exists **only where required by the operating system**.

Native code must:
- Remain small
- Avoid business logic, behavioral detection, correlation, network requests, expensive processing
- Copy data whose native lifetime is limited
- Transfer minimal data into Go

Go owns: domain models, event processing, correlation, detection, findings, all business logic.

### Native Callback Convention

A callback must:
1. Receive the native event
2. Extract required fields
3. Copy data whose lifetime is limited
4. Transfer the event safely
5. **Return quickly**

Callbacks must **never** perform: network calls, process enumeration, detection, large processing, or long blocking operations.

### Attribution Convention

Attribution must **never be fabricated**.

```text
Known:    Domain = example.com, Resolver = 8.8.8.8
Unknown:  PID = 0, Process = nil
```

Always distinguish **Observed** (confirmed) from **Inferred** (derived). An inference must never be represented as a confirmed fact.

### Logging Convention

Logs should answer: What happened? Which subsystem? Which process? Which event? What failed?

- Remove temporary debugging output before committing.
- Avoid noisy logs during normal operation.

### Git Convention

Commits are focused around completed TDD slices:

```text
feat: add file telemetry core model
feat: add file monitor event mapping
feat: add macOS Endpoint Security collector foundation
test: add file event conversion coverage
fix: unblock event bus publishers during shutdown
```

**Pre-commit checklist:**
```bash
git status
git diff
gofmt -w <changed-files>
go test ./...
go test -race ./...
go vet ./...
git add <relevant-files>
git commit -m "..."
git status
```

Do not mix unrelated work into a feature commit.

### Code Quality

**Prefer:**
- Small functions
- Explicit dependencies
- Clear names
- Early validation
- Simple control flow
- Narrow interfaces
- Deterministic tests
- Minimal abstractions until needed

**Avoid:**
- Premature generic frameworks
- Large interfaces
- Global mutable state
- Hidden dependencies
- Clever abstractions without a concrete use case
- Optimization before measurement

---

## 29. Definition of Done

A feature is complete when **all** of the following hold:

### Behavior
- [ ] Required behavior is implemented
- [ ] Edge cases are considered
- [ ] Failure behavior is intentional

### Tests
- [ ] Unit tests pass
- [ ] Component tests pass
- [ ] Race tests pass (`go test -race ./...`)
- [ ] Integration tests pass where applicable

### Architecture
- [ ] Platform-specific logic is isolated
- [ ] Dependencies are injectable where useful
- [ ] Unnecessary coupling is avoided

### Reliability
- [ ] Context cancellation works
- [ ] Resources are released
- [ ] Goroutines have clear lifecycles
- [ ] Queue behavior is intentional and documented

### Detection
- [ ] Evidence is retained
- [ ] Findings are explainable
- [ ] Pattern matching is deterministic

### Documentation
- [ ] Important architectural decisions are documented in `docs/`

### Git
- [ ] Code is formatted (`gofmt`)
- [ ] All tests pass
- [ ] Changes are focused on a single slice
- [ ] Commit message describes the completed slice

---

## 30. Guiding Principles

1. **Telemetry first.** Capture what happened reliably before interpreting it.
2. **Behavioral patterns over simple signatures.** Sequences matter, not individual events.
3. **Normalize platform-specific telemetry into common models.** The detection layer must not know the source platform.
4. **Attribution must never be fabricated.** Unknown attribution is represented as `PID = 0`, not a guess.
5. **Correlation provides context; detection provides interpretation.** These are separate responsibilities.
6. **Findings must be explainable.** A finding without evidence is not a finding.
7. **TDD before implementation.** Tests are written before the code that satisfies them.
8. **Small vertical slices over large rewrites.** Each slice must be green before the next begins.
9. **Correctness before optimization.** Measure before optimizing.
10. **Platform-specific code stays at the platform boundary.** Core logic is platform-neutral.
11. **Native callbacks remain lightweight.** Extract, copy, and return quickly.
12. **Concurrency has explicit ownership.** Every goroutine has a known owner and termination path.
13. **External dependencies are injectable where practical.** Enables deterministic testing.
14. **Event-loss behavior must be explicit.** Security telemetry must not silently disappear.
15. **Keep abstractions proportional to the problem.** No abstraction without a concrete use case.

---

## 31. Final Mental Model

```text
                 WHAT HAPPENED?
                       │
                       ▼
                ┌─────────────┐
                │  Telemetry  │  <- Collectors capture raw OS events
                └──────┬──────┘
                       │
                       ▼
                ┌─────────────┐
                │    Events   │  <- Normalized into core.Event
                └──────┬──────┘
                       │
                       ▼
                ┌─────────────┐
                │  Event Bus  │  <- Bounded async transport
                └──────┬──────┘
                       │
                       ▼
                ┌─────────────┐
                │ Correlation │  <- Connects related events
                └──────┬──────┘
                       │
                       ▼
              WHAT HAPPENED TOGETHER?
                       │
                       ▼
                ┌─────────────┐
                │ Behavioral  │  <- Pattern of correlated events
                │   Pattern   │
                └──────┬──────┘
                       │
                       ▼
                 DOES IT MATCH?
                       │
                       ▼
                ┌─────────────┐
                │  Detection  │  <- Evaluates pattern against state
                └──────┬──────┘
                       │
                       ▼
                ┌─────────────┐
                │   Finding   │  <- A meaningful detection result
                └──────┬──────┘
                       │
                       ▼
                  WHY DID IT MATCH?
                       │
                       ▼
                ┌─────────────┐
                │   Evidence  │  <- Retained events and relationships
                │ Explanation │  <- Human-readable reason
                └─────────────┘
```

> **Sentinel observes endpoint behavior, connects related telemetry, and detects predefined behavioral patterns with explainable evidence.**

---

## See Also

- [`event-bus-architecture.md`](./event-bus-architecture.md) — Detailed Event Bus design and implementation reference.
