# Linux DNS Collector

## Overview

The Linux DNS Collector (`internal/collector/dns/linuxCollector`, constructed via `dns.NewLinuxCollector`) captures outbound DNS query traffic on Linux by sniffing packets with libpcap, then attributes each query to the process that issued it using the `/proc` filesystem. It follows the same platform-abstraction pattern used elsewhere in Sentinel (see [Linux Network Collector](./linux-network-collector.md) and [Linux Process Collector](./linux-process-collector.md)), and mirrors the existing macOS DNS collector (`darwin.go`) as closely as the two platforms allow.

## Architecture

```text
Network interface (e.g. eth0, or "any")
       ↓
libpcap capture, BPF filter "udp port 53 or tcp port 53"
       ↓
linuxCollector.Run()
       ↓
parseDNSPacket() — shared with macOS (packet.go)
       ↓
linuxAttributor.Attribute()
       ↓
linuxSocketLookup.FindOwner() — /proc/net/{tcp,udp} → inode → /proc/{pid}/fd
       ↓
ProcessResolver.Resolve() (process.Resolver)
       ↓
core.DNSQuery entities, published via DNSMonitor → eventbus
```

## Implementation Details

### Shared Packet Decoding

DNS packet parsing (`parseDNSPacket`, `dnsTypeName`, `localAddress`, `localPort`) has no platform dependency — it only uses `gopacket`/`gopacket/layers` to decode an already-captured packet. This logic was factored out of `darwin.go` into `packet.go` (no build constraint) so both the macOS and Linux collectors share one implementation and one set of tests (`packet_test.go`), instead of maintaining two copies.

### `linuxCollector` (`linux.go`, `//go:build linux`)

```go
type linuxCollector struct {
    handle     *pcap.Handle
    attributor Attributor
}
```

- `NewLinuxCollector(device string, attributor Attributor)` opens a live capture via `pcap.OpenLive` and installs a BPF filter for DNS traffic (`udp port 53 or tcp port 53`), identical to the macOS collector's setup.
- `Run` reads packets from the capture, decodes DNS queries, best-effort attributes them to a process, and invokes the handler — the control flow is line-for-line the same as `macOSCollector.Run`.
- Requires **libpcap** (`libpcap-dev`/`libpcap0.8-dev` on Debian/Ubuntu, `libpcap-devel` on RHEL/Fedora) to be installed on the build and runtime host, and typically requires `CAP_NET_RAW`/`CAP_NET_ADMIN` (or root) to open a live capture.

### Process Attribution via `/proc` (`linux_socket_lookup.go`)

Unlike macOS — which shells out to `libproc` via cgo (`darwin_socket_lookup.go`) to enumerate every process's file descriptors — Linux exposes the same information directly through `/proc`, so attribution here is pure Go with no cgo dependency:

1. **Find the socket inode**: scan `/proc/net/tcp` and `/proc/net/udp` for an entry whose local address matches the source IP:port of the DNS packet. Addresses are little-endian hex-encoded, decoded the same way as the [Linux Network Collector](./linux-network-collector.md).
2. **Map inode → PID**: scan every `/proc/{pid}/fd` directory for a symlink of the form `socket:[inode]` that matches.
3. **Resolve process metadata**: hand the PID to a `ProcessResolver` (satisfied by `process.Resolver` from `internal/collector/process`) for full process context.

Attribution is best-effort throughout: a missing `/proc/net/*` file, an unmatched socket, or a process that exits mid-lookup all resolve to a `nil` owner/process rather than an error, so DNS telemetry is never dropped for lack of attribution.

`linuxSocketLookup` takes an injectable `procPath` (`NewLinuxSocketLookupWithPath`), following the same dependency-injection convention as the process and network Linux collectors, so tests can simulate `/proc` with `t.TempDir()` instead of requiring a real Linux kernel.

### `linuxAttributor` (`linux_attributor.go`)

Identical logic to `darwinAttributor`: look up the socket owner, stamp the query's `PID`, and — if a `ProcessResolver` is configured — attach full process metadata. A failed process resolution still keeps the `PID` that was found, since partial attribution is more useful than none.

### Error Handling

**Principle: DNS collection should be resilient**, matching the project's stance for network and process collectors.

- **Capture setup failure** (bad device, missing libpcap, insufficient privileges): `NewLinuxCollector` returns an error.
- **Malformed or non-DNS packets**: silently skipped.
- **Missing `/proc/net/tcp` or `/proc/net/udp`**: treated as "no match", not an error.
- **Socket inode with no owning process** (race with process exit): returns a `nil` owner; the query is still emitted with `PID = 0`.
- **Process resolution failure**: the query keeps the resolved `PID` even though `Process` stays `nil`.

## Test Coverage

### Shared (any OS) — `packet_test.go`

- `TestParseDNSPacket`, `TestParseDNSPacketIgnoresResponse`, `TestParseDNSPacketWithoutQuestion`
- `TestDNSTypeName`, `TestLocalAddress`, `TestLocalPort`

### Linux-specific — `linux_socket_lookup_test.go`

- `TestLinuxSocketLookupFindsOwnerViaTcp` / `...ViaUdp`: resolves a PID from a synthetic `/proc/net/{tcp,udp}` + `/proc/{pid}/fd` tree.
- `TestLinuxSocketLookupNoMatch`, `TestLinuxSocketLookupMissingProcNetFiles`, `TestLinuxSocketLookupInodeWithoutOwningProcess`: best-effort fallbacks.
- `TestLinuxSocketLookupInvalidIP`, `TestLinuxSocketLookupContextCancelled`: input validation.
- `TestParseHexIP`, `TestFindPidForInode`: unit tests for the low-level parsing helpers.

### Linux-specific — `linux_attributor_test.go`

Mirrors `darwin_attributor_test.go` exactly (success path, missing lookup/resolver, lookup/resolver errors, cancelled context, nil query) using fake `SocketLookup`/`ProcessResolver` doubles.

### Testing Strategy

The `/proc`-based lookup tests use temporary directories exactly like the network and process Linux collectors:

```go
tmpDir := t.TempDir()
netDir := filepath.Join(tmpDir, "net")
os.MkdirAll(netDir, 0755)
os.WriteFile(filepath.Join(netDir, "tcp"), []byte(tcpContent), 0644)
```

This keeps attribution logic fully unit-testable without root privileges or a real socket. The packet-capture path (`linuxCollector.Run`, backed by `pcap.OpenLive`) is not unit tested — same as the macOS collector — since it requires a live capture device; it is exercised the same way `macOSCollector` is, through integration/manual verification on a real host.

## Known Limitations

1. **Requires libpcap and elevated privileges**: unlike the pure-`/proc` network and process collectors, DNS capture needs `libpcap` installed and typically `CAP_NET_RAW` to open a live device.
2. **IPv4 attribution only**: `/proc/net/tcp6` and `/proc/net/udp6` are not yet parsed, matching the same limitation documented for the [Linux Network Collector](./linux-network-collector.md#known-limitations).
3. **Snapshot-based attribution**: a socket that closes between the DNS packet being captured and `/proc` being scanned will not be attributed (returns `nil` process, not an error).
4. **Cross-compilation caveat**: because `linux.go` depends on `gopacket/pcap` (cgo), it can only be compiled with a Linux C toolchain — verified in this change by building on darwin and confirming the pure-Go attribution files (`linux_socket_lookup.go`, `linux_attributor.go`) compile and vet cleanly for `GOOS=linux`. The full `linux.go` build should be verified in CI on an actual Linux host with `libpcap-dev` installed.

## Related Documentation

- [Linux Network Collector](./linux-network-collector.md) — same `/proc`-based attribution pattern
- [Linux Process Collector](./linux-process-collector.md) — process metadata resolution
- [Project Context](./project-context.md) — architecture and conventions
- [Event Bus Architecture](./event-bus-architecture.md) — how collectors feed events
