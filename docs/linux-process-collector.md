# Linux Process Collector

## Overview

The Linux Process Collector (`internal/collector/process/LinuxCollector`) is a platform-specific collector that reads process information from the Linux `/proc` filesystem. It follows the platform abstraction pattern established in Sentinel's architecture, allowing cross-platform process telemetry while using platform-specific APIs where necessary.

## Architecture

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

## Implementation Details

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

## Test Coverage

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

## Design Decisions

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

## Known Limitations

1. **Start Time Precision**: Depends on `/proc/uptime` precision. May have 1-2 second variance depending on kernel version.
2. **Process Names**: Truncated to 15 characters by Linux kernel.
3. **Zombie Processes**: cmdline unavailable, exe unavailable. Still collected with PID/PPID/user.
4. **PID Reuse**: Handled by Sentinel's Process Identity model (PID + StartTime).
5. **Thread Isolation**: Collects processes, not individual threads. Thread telemetry would require separate implementation.

## Future Enhancements

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

## Performance Considerations

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

## Testing on Linux

To verify the collector works with your actual `/proc` filesystem:

```bash
go test -v -run TestLinuxCollectorCanHandleRealProcIfAvailable ./internal/collector/process/...
```

This test is skipped on non-Linux systems and validates:
- Real process enumeration
- PID validity
- Expected field population

## Related Documentation

- [Project Context](./project-context.md) — Architecture and conventions
- [Event Bus Architecture](./event-bus-architecture.md) — How collectors feed events
- [Platform Abstraction](./project-context.md#19-platform-abstraction) — Collector layer design
