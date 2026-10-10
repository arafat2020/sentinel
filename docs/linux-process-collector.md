# Linux Process Collection

Sentinel learns about processes on Linux in one of three ways. It picks one at
startup, says which and why, and shows it in the Health view.

| Backend | How it learns of a process | Sees a process that lives 1 ms | Lag | Needs |
|---|---|---|---|---|
| `ebpf` | Scheduler tracepoints, read in the kernel | Yes, in full | Under a millisecond | Linux 5.8+, BTF, root (or `CAP_BPF` + `CAP_PERFMON`) |
| `proc-connector` | Netlink process-event connector, then `/proc` | Yes, but often without its command line | Under a millisecond | `CONFIG_PROC_EVENTS`, root (or `CAP_NET_ADMIN`) |
| `poll` | Comparing the process table every 2 seconds | No | Up to 2 s | Nothing |

```text
sentinel --process-collector=auto            # default: ebpf, else proc-connector, else poll
sentinel --process-collector=ebpf            # or proc-connector, or poll
sentinel --process-exec-grace=50ms           # see "fork and exec" below
sentinel --process-ringbuf-bytes=8388608     # eBPF ring buffer size
sentinel --headless --health-interval=60s    # how often the HEALTH line is logged
```

The flags apply to the TUI, the desktop UI (`--desktop`) and headless mode.

## Choosing a backend

With `auto`, Sentinel tries `ebpf`, then `proc-connector`, and polls if neither
works. Each backend that was passed over is logged with the reason:

```text
process collector: proc-connector (requested: auto)
process collector: skipped ebpf: missing BTF: /sys/kernel/btf/vmlinux does not exist (kernel built without CONFIG_DEBUG_INFO_BTF)
```

The reasons are one of:

| Reason | Meaning |
|---|---|
| `kernel too old: 5.4.0 is older than 5.8` | eBPF ring buffers and `bpf_ktime_get_boot_ns` arrived in 5.8. |
| `missing BTF: …` | The kernel has no `/sys/kernel/btf/vmlinux`. |
| `missing capability: …` | Not root, and without the capabilities listed above. |
| `load error: …` | The kernel refused the programs; the verifier's message follows. |
| `kernel has no process connector …` | Built without `CONFIG_CONNECTOR` / `CONFIG_PROC_EVENTS`. |

Asking for a backend by name is different: if it cannot be started, Sentinel
exits with the reason rather than quietly using another. If an event-driven
backend fails while running, Sentinel logs it and continues by polling.

Whatever the backend, Sentinel still takes one snapshot of the process table at
startup, so that processes already running are known as parents. The
event-driven backend is opened *before* that snapshot, so nothing that starts
in between is missed; a process caught by both is recognised as one.

## fork and exec

A new process is almost always one `fork` followed by one `exec`: a shell forks
a copy of itself, and the copy immediately replaces itself with `curl`.
Reporting the fork alone would describe every new process as its parent;
reporting the exec alone would miss programs that fork without exec. The
event-driven backends therefore emit:

- **`PROCESS_START` once per process.**
  - If the process execs within the *grace period* after its fork (50 ms by
    default, `--process-exec-grace`), the start is emitted at that exec. It
    describes the program that was exec'd and is stamped with the time of the
    exec.
  - Otherwise the start is emitted when the grace period ends. It describes
    the image inherited from the parent and is stamped with the time of the
    fork.
- **`PROCESS_EXEC` for any later exec** by the same process. The process keeps
  its identity (PID and start time); its name, executable and command line
  change. Patterns match a process by its *current* image, and a finding's
  evidence lists up to four earlier images under `previous_images`.
- **A fork that exits inside the grace period without exec'ing** still gets a
  `PROCESS_START` (at its fork) followed by `PROCESS_EXIT`.
- **A parent's start always comes before its child's.** A process that forks
  while still in its own grace period is announced at once.

The grace period is measured between the kernel's own timestamps for the fork
and the exec, not by when Sentinel read them, so a busy collector does not turn
starts into execs. A start is never held longer than the grace period plus the
10 ms the collector waits when idle.

`poll` never reports `PROCESS_EXEC`. It sees a process as whatever it was
running when the poll noticed it.

One consequence for pattern authors: a shell given several commands may run the
last one by exec'ing it in place. `sh -c 'curl … ; /tmp/x'` can make `/tmp/x` a
`PROCESS_EXEC` of the shell rather than the `PROCESS_START` of a child.

## Identity

A process is identified by its PID and its start time, and every part of
Sentinel must agree on both, exactly, or one process's events are split across
two identities and never correlated.

The snapshot, the resolver that attributes file and DNS events, and network
attribution all take the start time from gopsutil, which computes, in integer
arithmetic:

```text
milliseconds = ticks * 1000 / CLK_TCK  +  bootSeconds * 1000
```

`ticks` is field 22 of `/proc/<pid>/stat`; `bootSeconds` is the boot time
gopsutil read once and cached. The kernel derives `ticks` from the task's
`start_boottime` (nanoseconds since boot) by dividing by the length of a tick
and discarding the remainder.

The event-driven backends reproduce this instead of approximating it:

- `ebpf` reads `start_boottime` of the thread-group leader in the kernel,
  divides by `1e9 / CLK_TCK` to get the same `ticks`, and applies the formula.
- `proc-connector` reads `ticks` from `/proc/<pid>/stat` and applies the
  formula.
- The boot time is not read again, because a second reading can differ from
  the cached one. It is recovered from gopsutil: Sentinel's own start time as
  gopsutil reports it, minus Sentinel's own ticks converted the same way.

An integration test starts 220 long-lived processes, and compares the identity
each backend reported with what the snapshot and the resolver report, using
`==`; it also converts the start time of every process already running. Any
difference fails the test. There is no tolerance anywhere.

Two limits to be aware of:

- Sentinel must run in the host's time namespace. In a container with its own
  time namespace `/proc` shifts start times and the kernel value does not.
- When the proc connector cannot read `/proc/<pid>/stat` because the process
  has already exited, the event carries no start time. The correlation engine
  attributes such an event to the process currently holding that PID.

## Timestamps

Events from `ebpf` and `proc-connector` are stamped with when the kernel says
the fork, exec or exit happened, not when Sentinel read it.

The kernel timestamps are on `CLOCK_BOOTTIME` (eBPF, `bpf_ktime_get_boot_ns`)
or `CLOCK_MONOTONIC` (the connector). To convert, Sentinel reads the wall
clock, the kernel clock, and the wall clock again; the kernel clock was read
somewhere between the two wall readings, so their midpoint is off by at most
half the time the three readings took. The best of eight attempts is kept, the
offset is measured again every 10 seconds (the wall clock is steered by NTP),
and the bound is shown in the Health view as the clock error. It is typically a
few hundred nanoseconds.

The process's *start time* (its identity) is deliberately not derived this way:
it uses the cached boot time, as above, so that it never changes.

## What the eBPF backend captures

Three BTF-typed tracepoint programs (`tp_btf`), CO-RE relocated against the
running kernel:

| Program | Tracepoint | Emits |
|---|---|---|
| `on_fork` | `sched_process_fork` | A record for each new thread-group leader. New threads are ignored. |
| `on_exec` | `sched_process_exec` | A record with the path given to `execve` and the arguments. |
| `on_exit` | `sched_process_exit` | A record when the last thread of a process exits. |

Every record carries, read in the kernel at that moment: the PID (thread-group
ID), the real parent's PID, the real UID, the kernel's 16-byte name, the
process's `start_boottime`, and the time on `CLOCK_BOOTTIME`. An exec record
adds the path passed to `execve` (up to 512 bytes) and the arguments as the
kernel stores them (the first 4,096 bytes; a longer command line is cut and the
event is marked `cmdline_truncated`).

In userspace, the UID becomes a user name through the same lookup the poll
collector uses, cached; the arguments are joined by spaces as the poll
collector prints them; and the executable is `/proc/<pid>/exe` when the process
is still there, which is the resolved path every other collector reports, or
otherwise the path that was passed to `execve`.

Which thread's exit ends a process: the tracepoint fires for every thread. The
program reports the exit of the last one, which it recognises from the
thread group's live count. Whether that count has already been decremented at
the tracepoint depends on the kernel version, so the program learns it from the
first single-threaded process it sees exit instead of assuming.

Maps, all bounded:

| Map | Type | Size | When it is full |
|---|---|---|---|
| `events` | ring buffer | 8 MiB by default (`--process-ringbuf-bytes`, rounded up to a power of two) | The record is dropped and counted in `drops` |
| `scratch` | per-CPU array | one exec record per CPU | — |
| `drops` | per-CPU array | three counters: fork, exec, exit | — |

A fork or exit record is 48 bytes. An exec record is 568 bytes plus its
arguments, so the default ring holds roughly ten thousand of them.

## What the proc connector cannot do

The connector says only "PID 1234 exec'd". Sentinel reads the name, parent,
start time, executable, command line and user from `/proc` immediately, but a
process that has already exited has left nothing to read. Such an event is
still emitted, with what is known (the image inherited from the parent, or
nothing), and is marked `partial` in its metadata and counted. In the capture
test below, every one of 2,000 runs of `true` was reported, but fewer than half
could be described as `true`.

It also reports the exit of the thread-group leader as the exit of the process,
which is early for a process whose main thread exits while others run on.

## Lost events and bounds

| What | Bound | When exceeded | Counter |
|---|---|---|---|
| eBPF ring buffer | `--process-ringbuf-bytes` | Record dropped in the kernel | `kernel_drops` |
| Netlink receive buffer | 4 MiB | Messages dropped by the kernel | `kernel_drops` (overruns) |
| Tracked processes | 131,072 | Event ignored | `tracked_cap_hits` |
| Starts held for the grace period | Bounded by the above | — | `pending` |
| User-name cache | 1,024 | Cache emptied | `user_cache_resets` |
| Event bus | 1,000 events | The collector waits | `bus_waited` |
| Exited processes remembered by the engine | 65,536 | Oldest forgotten early | `tombstones_evicted` |

The event bus does not discard events. When it is full the collector waits,
which backs the pressure up into the kernel buffer, where it is absorbed or
counted.

Every 30 seconds the tracked processes are compared with the process table. A
tracked process that is no longer running is reported as exited (marked
`inferred`), and a running process that is not tracked is reported as started
(marked `reconciled`). Both are counted and should be zero unless events were
lost. A PID seen forking while Sentinel still tracks its previous owner is
handled the same way, immediately.

## Health

The Health view shows the active backend, why others were skipped, every
counter above, the bus, and every limit the correlation engine has hit:

- TUI: tab `9`.
- Desktop UI: the Health section of the Settings tab.
- Headless: a `HEALTH key=value …` line every 60 seconds
  (`--health-interval`), and once more at shutdown.

## Privileges and systemd

Running as root is sufficient for everything, and is what `install.sh` sets up.
For a restricted account, the collectors need:

| Collector | Capabilities |
|---|---|
| eBPF process events | `CAP_BPF` and `CAP_PERFMON` (`CAP_SYS_ADMIN` on kernels before 5.8, which are unsupported anyway); `CAP_SYS_RESOURCE` before 5.11 |
| Process connector | `CAP_NET_ADMIN` |
| Reading other users' `/proc/<pid>/exe` | `CAP_SYS_PTRACE` |
| fanotify file events | `CAP_SYS_ADMIN` |
| libpcap DNS capture | `CAP_NET_RAW`, `CAP_NET_ADMIN` |

`install.sh` reports which backend `auto` will most likely choose on the host,
from the kernel version and the presence of BTF.

## Building

`go build` needs no clang: the compiled eBPF objects and their Go bindings
(`internal/collector/process/procevents/process_*_bpfel.{o,go}`, for amd64 and
arm64) are committed.

After changing `bpf/process.bpf.c` or a header, regenerate them on Linux:

```bash
sudo apt-get install clang-18 llvm-18
make generate          # runs bpf2go
make generate-check    # fails if the committed files differ
```

The kernel types the programs use are declared by hand in
`bpf/headers/kernel_types.h` with CO-RE attributes, rather than through a
generated `vmlinux.h`; the libbpf headers are vendored beside it. The output
therefore depends only on the clang version, which CI pins.

## Testing

Unit tests need nothing:

```bash
go test ./internal/collector/process/...
```

Integration tests load the programs and open the connector, so they need a real
kernel and root:

```bash
sudo go test -tags integration ./internal/collector/process/...
```

They cover: capture of 2,000 short-lived processes per backend, identity
equality, arguments of a process that exits within 5 ms, timestamps, fallback
when eBPF cannot load, and the guide's download-and-execute example end to end.

The stress test:

```bash
sudo sentinel --headless --health-interval=10s &
go run ./tools/execstress -rate 5000 -duration 60s
```

## The `/proc` reader (reference)

`LinuxCollector` is a direct `/proc` reader kept in the tree. It is not what
the `poll` backend uses (that is gopsutil, through `process.Collector`), and
nothing below applies to the event-driven backends.

### Overview

The Linux Process Collector (`internal/collector/process/LinuxCollector`) is a platform-specific collector that reads process information from the Linux `/proc` filesystem. It follows the platform abstraction pattern established in Sentinel's architecture, allowing cross-platform process telemetry while using platform-specific APIs where necessary.

### Architecture

```text
/proc filesystem
       ↓
LinuxCollector.Collect()
       ↓
Read /proc/{pid}/stat
Read /proc/{pid}/status
Read /proc/{pid}/cmdline (optional)
Read /proc/{pid}/exe (optional)
       ↓
core.ProcessSnapshot
       ↓
core.Process entities
```

### Implementation Details

### Core Components

#### `LinuxCollector` struct

```go
type LinuxCollector struct {
    procPath string  // Path to /proc (defaults to "/proc", overridable for testing)
}
```

The `procPath` field allows dependency injection for testing without requiring a real `/proc` filesystem.

### Process Information Collection

#### PID and PPID

- Read from `/proc/{pid}/stat` fields 0 (PID) and 3 (PPID)
- These form the process identity used throughout Sentinel

#### Process Name

- Read from `/proc/{pid}/stat` field 1 (comm)
- Extracted from parentheses: `(name)` → `name`
- Limited to 15 characters on most Linux systems

#### User/UID

- Read from `/proc/{pid}/status` Uid field
- Returns the effective UID
- Best-effort: returns empty string if unavailable

#### Start Time

- Read from `/proc/{pid}/stat` field 21 (starttime in jiffies)
- Converted to absolute time using `/proc/uptime` (system boot time)
- Falls back to relative time calculation if `/proc/uptime` is unavailable
- Assumes 100 jiffies per second (HZ=100) on most systems

#### Command Line

- Read from `/proc/{pid}/cmdline` (optional)
- Null-byte separated arguments joined with spaces
- Empty string if unavailable (e.g., zombie processes)

#### Executable Path

- Read from `/proc/{pid}/exe` symlink (optional)
- Points to the actual executable binary
- Empty string if unavailable

### Error Handling

**Principle: Process collection should be resilient.**

- **Mandatory fields fail fast**: PID and PPID failures cause the process to be skipped
- **Optional fields fail gracefully**: cmdline, exe, and uid use empty strings if unavailable
- **Process exit races**: If a process exits during collection, it's silently skipped
- **Status read failures**: Return empty UID rather than failing (status is best-effort metadata)

### Test Coverage

The implementation uses test-driven development with comprehensive test coverage:

### Unit Tests

- `TestLinuxCollectorReturnsSnapshot`: Verifies basic collection returns a snapshot
- `TestLinuxCollectorParsesProcessStat`: Validates stat file parsing with known values
- `TestLinuxCollectorIgnoresNonNumericDirs`: Confirms non-PID directories are skipped
- `TestLinuxCollectorHandlesReadFailures`: Tests graceful handling of missing `/proc`
- `TestLinuxCollectorHandlesProcessesExitingDuringCollection`: Verifies race condition handling
- `TestLinuxCollectorCanHandleRealProcIfAvailable`: Integration test on Linux systems
- `TestLinuxCollectorPreservesProcessHierarchy`: Validates parent-child relationships

### Testing Strategy

Tests use temporary directories to simulate `/proc` filesystem structure:

```go
tmpDir := t.TempDir()
procDir := filepath.Join(tmpDir, "proc")
os.MkdirAll(filepath.Join(procDir, "42"), 0755)
os.WriteFile(filepath.Join(procDir, "42", "stat"), []byte("..."), 0644)
```

This approach:
- Runs on all platforms (not just Linux)
- Has no external dependencies
- Enables deterministic testing
- Tests both happy path and error cases

### Design Decisions

### Why Not Use gopsutil?

The existing `ProcessCollector` uses gopsutil, which provides cross-platform abstractions. The Linux collector complements this by:

1. **Providing direct `/proc` access** for more detailed telemetry
2. **Enabling future event-based monitoring** (inotify, netlink events) without library constraints
3. **Maintaining control over error handling** for security telemetry
4. **Allowing platform-specific optimizations** on Linux

### Why Separate Linux Collector?

Following Sentinel's platform abstraction pattern:
- Core models remain platform-neutral
- Platform-specific logic isolated at the boundary
- Future: Darwin (Endpoint Security), Windows (WMI) collectors can coexist
- Tests verify behavior without requiring target platform

### Dependency Injection via procPath

The `procPath` field:
- Enables testing without a real `/proc` filesystem
- Allows runtime configuration (e.g., container introspection)
- Maintains deterministic test behavior
- Follows Sentinel's convention for testable dependencies

### Known Limitations

1. **Start Time Precision**: Depends on `/proc/uptime` precision. May have 1-2 second variance depending on kernel version.
2. **Process Names**: Truncated to 15 characters by Linux kernel.
3. **Zombie Processes**: cmdline unavailable, exe unavailable. Still collected with PID/PPID/user.
4. **PID Reuse**: Handled by Sentinel's Process Identity model (PID + StartTime).
5. **Thread Isolation**: Collects processes, not individual threads. Thread telemetry would require separate implementation.

### Future Enhancements

### Event-Based Monitoring

Instead of periodic snapshots, use:
- **netlink**: PROC_EVENTS for process start/exit events
- **inotify**: Monitor `/proc` for process creation/deletion
- **ebpf**: Kernel probes for low-overhead monitoring

### Additional Telemetry

- Memory usage (RSS, VSZ from `/proc/{pid}/stat`)
- I/O stats (`/proc/{pid}/io`)
- File descriptors (`/proc/{pid}/fd`)
- Resource limits (`/proc/{pid}/limits`)

### Container Support

- Support alternative proc roots: `/var/lib/docker/containers/{id}/...`
- Namespace awareness (cgroup paths)
- Container runtime integration

### Performance Considerations

### Collection Overhead

Reading `/proc` for all processes:
- ~1-5ms on typical systems (100-500 processes)
- Scales linearly with process count
- No memory allocations during parsing (pre-allocated slice)

### Mitigation Strategies

- **Sampling**: Collect every N intervals, not every interval
- **Filtering**: Only collect processes matching criteria
- **Batching**: Combine with other collectors' intervals
- **Async Collection**: Run in separate goroutine with backpressure

### Testing on Linux

To verify the collector works with your actual `/proc` filesystem:

```bash
go test -v -run TestLinuxCollectorCanHandleRealProcIfAvailable ./internal/collector/process/...
```

This test is skipped on non-Linux systems and validates:
- Real process enumeration
- PID validity
- Expected field population

### Related Documentation

- [Project Context](./project-context.md) — Architecture and conventions
- [Event Bus Architecture](./event-bus-architecture.md) — How collectors feed events
- [Platform Abstraction](./project-context.md#19-platform-abstraction) — Collector layer design
