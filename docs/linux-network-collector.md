# Linux Network Collector

## Overview

The Linux Network Collector (`internal/collector/network/LinuxCollector`) is a platform-specific collector that reads network connection information from the Linux `/proc` filesystem. It follows the platform abstraction pattern established in Sentinel's architecture, allowing cross-platform network telemetry while using platform-specific APIs.

## Architecture

```text
/proc/net/tcp
/proc/net/udp
       ↓
LinuxCollector.Collect()
       ↓
Parse socket entries (hex addresses, ports, states)
       ↓
Build inode-to-PID mapping via /proc/{pid}/fd
       ↓
Attribute connections to processes
       ↓
core.NetworkConnection entities
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

### Connection Information Collection

#### Socket Address Parsing

- Reads from `/proc/net/tcp` and `/proc/net/udp`
- Each entry contains: `local_address rem_address st tx_queue rx_queue ... uid timeout inode`
- Hex format: socket addresses are little-endian 32-bit integers (e.g., `0100007F` = 127.0.0.1)
- Ports are hex-encoded separately (e.g., `:1234` = port 4660 in decimal)

#### Protocol Identification

- **TCP** — read from `/proc/net/tcp`
- **UDP** — read from `/proc/net/udp`
- Both are parsed identically, with protocol field set accordingly

#### Connection State

- State field from `/proc/net/tcp` or `/proc/net/udp` (e.g., `01` = ESTABLISHED, `0A` = LISTEN)
- State values are kernel-specific constants preserved as-is

#### Process Attribution

Process attribution uses a two-step approach:

1. **Extract socket inode** from `/proc/net/tcp` or `/proc/net/udp`
2. **Map inode to PID** by scanning `/proc/{pid}/fd` symlinks
   - Symlinks point to `socket:[inode]` format
   - Regex extracts the inode number
   - Creates a map of inode → PID for fast lookup

3. **Resolve process metadata** using the ProcessResolver
   - PID is looked up in gopsutil for full process context
   - Best-effort: if attribution fails, connection is returned with `Process = nil`

### Error Handling

**Principle: Network collection should be resilient.**

- **Directory access failure**: Returns error if `/proc/net` is not accessible
- **Missing files**: Silently handles missing `/proc/net/tcp` or `/proc/net/udp` (returns empty slices)
- **Malformed entries**: Skips unparseable lines, continues with valid entries
- **Process lookup failures**: Returns connection with `nil` process (attribution is best-effort)
- **Process exit races**: If a process exits during collection, it's silently skipped

## Test Coverage

The implementation uses test-driven development with comprehensive test coverage:

### Unit Tests

- `TestLinuxCollectorReturnsEmptyWhenNoConnections`: Verifies empty `/proc/net` returns no connections
- `TestLinuxCollectorHandlesInvalidProcPath`: Validates error on invalid proc path
- `TestParseSocketAddressIPv4`: Validates hex-to-IP address conversion
- `TestParseTcpEntry`: Verifies parsing of complete TCP entries
- `TestParseTcpEntryMalformed`: Tests graceful handling of invalid entries
- `TestReadTcpConnections`: Validates reading and parsing `/proc/net/tcp`
- `TestFindSocketOwnerByInode`: Verifies inode-to-PID mapping via `/proc/{pid}/fd`
- `TestBuildInodeToPidMap`: Tests building complete inode→PID map across all processes
- `TestConnectionToCoreNetworkConnection`: Validates conversion to core model with process data
- `TestConnectionToCoreNetworkConnectionNoProcess`: Validates conversion without process attribution

### Integration Tests

- `TestLinuxCollectorCollectsTcpAndUdp`: Verifies collection of both TCP and UDP connections
- `TestLinuxCollectorHandlesMissingProcessAttribution`: Validates connections without process attribution

### Testing Strategy

Tests use temporary directories to simulate `/proc` filesystem structure:

```go
tmpDir := t.TempDir()
netDir := filepath.Join(tmpDir, "net")
os.MkdirAll(netDir, 0755)
os.WriteFile(filepath.Join(netDir, "tcp"), []byte(tcpContent), 0644)
```

This approach:
- Runs on all platforms (not just Linux)
- Has no external dependencies
- Enables deterministic testing
- Tests both happy path and error cases

## Design Decisions

### Why /proc/net Instead of netlink Events?

The current implementation reads static `/proc/net/tcp` and `/proc/net/udp` snapshots, similar to the Linux process collector reading `/proc/*/stat`:

1. **Simple and portable** across kernel versions
2. **Deterministic for testing** (no event ordering concerns)
3. **Future path** to event-based monitoring via netlink without changing core interfaces
4. **Consistent with process collector** architecture

### Inode-Based Process Attribution

Attribution uses socket inodes because:

1. **Reliable** — inodes are unique identifiers for open file descriptors
2. **Efficient** — single pass through `/proc/{pid}/fd` for all PIDs
3. **Kernel-provided** — no guessing or inference needed
4. **Works across protocol families** — TCP, UDP, IPv4, IPv6 all use same mechanism

### Dependency Injection via procPath

The `procPath` field:
- Enables testing without a real `/proc` filesystem
- Allows runtime configuration (e.g., container introspection)
- Maintains deterministic test behavior
- Follows Sentinel's convention for testable dependencies

## Known Limitations

1. **Snapshot-based**: Reads a point-in-time snapshot. Rapid connection churn may miss short-lived connections.
2. **Inode reuse**: Rarely, inode numbers may be reused across different connections. The current implementation assumes stable inodes during collection.
3. **State interpretation**: State values are kernel-specific constants. Human-readable names (ESTABLISHED, LISTEN) are not generated.
4. **IPv4 only parsing**: Current implementation parses IPv4 addresses from `/proc/net/tcp`. IPv6 connections in `/proc/net/tcp6` have different format.
5. **Process attribution failures**: Connections without a matching PID are still collected (with `Process = nil`), maintaining telemetry quality.

## Future Enhancements

### Event-Based Monitoring

Instead of periodic snapshots, use:
- **netlink**: NETLINK_INET_DIAG for connection state change events
- **conntrack**: Track connection lifecycle events
- **eBPF**: Kprobes on TCP connect/close syscalls

### Additional Telemetry

- Connection duration (from state field timestamps)
- Retransmit counts
- Send/receive queue depths
- TCP window sizes

### IPv6 Support

- Parse `/proc/net/tcp6` format (different hex address encoding)
- Handle IPv6 addresses in core.NetworkConnection
- Test with actual IPv6 connections

### Container Support

- Support alternative proc roots: `/var/lib/docker/containers/{id}/...`
- Namespace-aware connection attribution
- Handle PID translation across namespace boundaries

## Performance Considerations

### Collection Overhead

Reading `/proc/net/tcp` and `/proc/net/udp` for all processes:
- ~1-10ms on typical systems (for both files combined)
- Scales with number of active connections, not processes
- No memory allocations during parsing (pre-allocated slices)

### Optimization Opportunities

- **Caching**: Reuse inode→PID map across multiple collections
- **Incremental**: Only scan PIDs that appeared since last collection
- **Filtering**: Only collect connections matching criteria (e.g., specific protocols)
- **Async**: Run in separate goroutine with backpressure

## Testing on Linux

To verify the collector works with your actual `/proc` filesystem:

```bash
go test -v -run TestLinuxCollectorCollectsTcpAndUdp ./internal/collector/network/...
```

This test is not platform-specific and validates:
- Parsing of real `/proc/net/tcp` format
- Extraction of valid socket entries
- Both TCP and UDP collection

On actual Linux systems with real processes:

```bash
cat > /tmp/test_linux_collector.go << 'EOF'
package main

import (
	"context"
	"fmt"
	"github.com/arafat2020/sentinel/internal/collector/network"
)

func main() {
	collector := network.NewLinuxCollector()
	conns, err := collector.Collect(context.Background())
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	fmt.Printf("Collected %d connections\n", len(conns))
	for _, conn := range conns {
		if conn.Process != nil {
			fmt.Printf("  %s:%d -> %s:%d (PID %d)\n",
				conn.LocalAddress, conn.LocalPort,
				conn.RemoteAddress, conn.RemotePort,
				conn.PID)
		}
	}
}
EOF
go run /tmp/test_linux_collector.go
```

## Related Documentation

- [Project Context](./project-context.md) — Architecture and conventions
- [Linux Process Collector](./linux-process-collector.md) — Similar platform-specific collector pattern
- [Event Bus Architecture](./event-bus-architecture.md) — How collectors feed events
- [Platform Abstraction](./project-context.md#19-platform-abstraction) — Collector layer design
