package network

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/arafat2020/sentinel/internal/core"
)

// Given: A Linux network collector
// When: collecting connections from empty /proc/net directory
// Then: returns empty connection list without error
func TestLinuxCollectorReturnsEmptyWhenNoConnections(t *testing.T) {
	tmpDir := t.TempDir()
	netDir := filepath.Join(tmpDir, "net")
	os.MkdirAll(netDir, 0755)

	collector := NewLinuxCollectorWithPath(tmpDir)
	connections, err := collector.Collect(context.Background())

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(connections) != 0 {
		t.Fatalf("expected empty connections, got %d", len(connections))
	}
}

// Given: A Linux network collector
// When: /proc path does not exist
// Then: returns error describing the failure
func TestLinuxCollectorHandlesInvalidProcPath(t *testing.T) {
	collector := NewLinuxCollectorWithPath("/nonexistent/proc/path")
	_, err := collector.Collect(context.Background())

	if err == nil {
		t.Fatal("expected error for invalid proc path")
	}
}

// Given: A parsed TCP connection entry from /proc/net/tcp
// When: converting hex socket addresses to IP
// Then: correctly parses IPv4 address
func TestParseSocketAddressIPv4(t *testing.T) {
	tests := []struct {
		hexAddr    string
		expectedIP string
	}{
		{"0100007F", "127.0.0.1"},    // localhost
		{"00000000", "0.0.0.0"},      // any address
		{"E80A0A0A", "10.10.10.232"}, // 10.10.10.232
		{"08080808", "8.8.8.8"},      // 8.8.8.8
	}

	for _, tt := range tests {
		ip, _ := parseSocketAddress(tt.hexAddr)

		if ip != tt.expectedIP {
			t.Fatalf("expected IP %s, got %s for %s", tt.expectedIP, ip, tt.hexAddr)
		}
	}
}

// Given: A TCP connection entry in /proc/net/tcp format
// When: parsing the entry
// Then: extracts socket addresses, ports, state, and inode
func TestParseTcpEntry(t *testing.T) {
	tcpLine := "0: 0100007F:1234 08080808:01BB 01 00000000:00000000 00:00000000 00000000 1000 0 54321 1 0000000000000000 100 0 0 10 0"

	entry, err := parseTcpEntry(tcpLine, "tcp")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if entry.LocalIP != "127.0.0.1" {
		t.Fatalf("expected local IP 127.0.0.1, got %s", entry.LocalIP)
	}

	if entry.LocalPort != 4660 { // 0x1234 = 4660
		t.Fatalf("expected local port 4660, got %d", entry.LocalPort)
	}

	if entry.RemoteIP != "8.8.8.8" {
		t.Fatalf("expected remote IP 8.8.8.8, got %s", entry.RemoteIP)
	}

	if entry.RemotePort != 443 { // 0x01BB = 443
		t.Fatalf("expected remote port 443, got %d", entry.RemotePort)
	}

	if entry.State != "01" {
		t.Fatalf("expected state 01, got %s", entry.State)
	}

	if entry.Inode != 54321 {
		t.Fatalf("expected inode 54321, got %d", entry.Inode)
	}

	if entry.Protocol != "tcp" {
		t.Fatalf("expected protocol tcp, got %s", entry.Protocol)
	}
}

// Given: A malformed TCP entry
// When: parsing the entry
// Then: returns error
func TestParseTcpEntryMalformed(t *testing.T) {
	malformedLines := []string{
		"",                               // empty
		"invalid entry",                  // too few fields
		"0: ZZZZZZZZ:XXXX 08080808:01BB", // invalid hex
	}

	for _, line := range malformedLines {
		_, err := parseTcpEntry(line, "tcp")
		if err == nil {
			t.Fatalf("expected error for malformed entry: %s", line)
		}
	}
}

// Given: /proc/net/tcp file with multiple connection entries
// When: reading and parsing the file
// Then: returns all connections with correct metadata
func TestReadTcpConnections(t *testing.T) {
	tmpDir := t.TempDir()
	netDir := filepath.Join(tmpDir, "net")
	os.MkdirAll(netDir, 0755)

	tcpContent := `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
  0: 0100007F:1234 08080808:01BB 01 00000000:00000000 00:00000000 00000000 1000 0 12345 1 0000000000000000 100 0 0 10 0
  1: 00000000:0050 00000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 54321 1 0000000000000000 100 0 0 10 0
`

	os.WriteFile(filepath.Join(netDir, "tcp"), []byte(tcpContent), 0644)

	entries, err := readTcpConnections(netDir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(entries))
	}

	if entries[0].Inode != 12345 {
		t.Fatalf("expected first inode 12345, got %d", entries[0].Inode)
	}

	if entries[1].Inode != 54321 {
		t.Fatalf("expected second inode 54321, got %d", entries[1].Inode)
	}
}

// Given: A PID with file descriptors pointing to network sockets
// When: finding the socket owner
// Then: returns the PID for matching inode
func TestFindSocketOwnerByInode(t *testing.T) {
	tmpDir := t.TempDir()
	pidDir := filepath.Join(tmpDir, "42")
	fdDir := filepath.Join(pidDir, "fd")
	os.MkdirAll(fdDir, 0755)

	// Create symbolic links for file descriptors pointing to sockets
	// Format: socket:[inode]
	os.Symlink("socket:[12345]", filepath.Join(fdDir, "3"))
	os.Symlink("socket:[54321]", filepath.Join(fdDir, "4"))
	os.Symlink("/dev/null", filepath.Join(fdDir, "0"))

	inodeToPid := make(map[uint64]int32)
	err := findSocketOwnerByInode(tmpDir, 42, inodeToPid)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if inodeToPid[12345] != 42 {
		t.Fatalf("expected PID 42 for inode 12345, got %d", inodeToPid[12345])
	}

	if inodeToPid[54321] != 42 {
		t.Fatalf("expected PID 42 for inode 54321, got %d", inodeToPid[54321])
	}
}

// Given: Multiple processes with various file descriptors
// When: building inode to PID map
// Then: correctly maps sockets to their owning processes
func TestBuildInodeToPidMap(t *testing.T) {
	tmpDir := t.TempDir()

	// Create two processes with socket file descriptors
	proc1Dir := filepath.Join(tmpDir, "42")
	fd1Dir := filepath.Join(proc1Dir, "fd")
	os.MkdirAll(fd1Dir, 0755)
	os.Symlink("socket:[11111]", filepath.Join(fd1Dir, "3"))

	proc2Dir := filepath.Join(tmpDir, "43")
	fd2Dir := filepath.Join(proc2Dir, "fd")
	os.MkdirAll(fd2Dir, 0755)
	os.Symlink("socket:[22222]", filepath.Join(fd2Dir, "4"))

	inodeToPid := buildInodeToPidMap(tmpDir)

	if inodeToPid[11111] != 42 {
		t.Fatalf("expected PID 42 for inode 11111, got %d", inodeToPid[11111])
	}

	if inodeToPid[22222] != 43 {
		t.Fatalf("expected PID 43 for inode 22222, got %d", inodeToPid[22222])
	}
}

// Given: Connection entries with mapped PIDs
// When: converting to core.NetworkConnection
// Then: includes all metadata with correct types
func TestConnectionToCoreNetworkConnection(t *testing.T) {
	entry := socketEntry{
		LocalIP:    "127.0.0.1",
		LocalPort:  54321,
		RemoteIP:   "8.8.8.8",
		RemotePort: 443,
		State:      "01",
		Protocol:   "tcp",
		Inode:      12345,
	}

	process := &core.Process{
		PID:         123,
		PPID:        100,
		Name:        "curl",
		Executable:  "/usr/bin/curl",
		CommandLine: "curl https://example.com",
		User:        "testuser",
	}

	conn := connectionToCoreNetworkConnection(entry, process)

	if conn.PID != 123 {
		t.Fatalf("expected PID 123, got %d", conn.PID)
	}

	if conn.PPID != 100 {
		t.Fatalf("expected PPID 100, got %d", conn.PPID)
	}

	if conn.LocalAddress != "127.0.0.1" {
		t.Fatalf("expected local address 127.0.0.1, got %s", conn.LocalAddress)
	}

	if conn.LocalPort != 54321 {
		t.Fatalf("expected local port 54321, got %d", conn.LocalPort)
	}

	if conn.RemoteAddress != "8.8.8.8" {
		t.Fatalf("expected remote address 8.8.8.8, got %s", conn.RemoteAddress)
	}

	if conn.RemotePort != 443 {
		t.Fatalf("expected remote port 443, got %d", conn.RemotePort)
	}

	if conn.Protocol != "tcp" {
		t.Fatalf("expected protocol tcp, got %s", conn.Protocol)
	}

	if conn.State != "01" {
		t.Fatalf("expected state 01, got %s", conn.State)
	}

	if conn.Timestamp.IsZero() {
		t.Fatal("expected timestamp")
	}

	if conn.Timestamp.After(time.Now()) {
		t.Fatal("timestamp cannot be in the future")
	}

	if conn.Process == nil {
		t.Fatal("expected process attribution")
	}

	if conn.Process.Name != "curl" {
		t.Fatalf("expected process name curl, got %s", conn.Process.Name)
	}
}

// Given: Connection entries without process attribution
// When: converting to core.NetworkConnection
// Then: still includes connection metadata with nil process
func TestConnectionToCoreNetworkConnectionNoProcess(t *testing.T) {
	entry := socketEntry{
		LocalIP:    "0.0.0.0",
		LocalPort:  0,
		RemoteIP:   "0.0.0.0",
		RemotePort: 0,
		State:      "0A",
		Protocol:   "tcp",
		Inode:      0,
	}

	conn := connectionToCoreNetworkConnection(entry, nil)

	if conn.LocalAddress != "0.0.0.0" {
		t.Fatalf("expected local address 0.0.0.0, got %s", conn.LocalAddress)
	}

	if conn.Process != nil {
		t.Fatal("expected nil process")
	}
}

// Given: A Linux network collector
// When: collecting connections from /proc/net
// Then: returns all TCP and UDP connections
func TestLinuxCollectorCollectsTcpAndUdp(t *testing.T) {
	tmpDir := t.TempDir()
	netDir := filepath.Join(tmpDir, "net")
	os.MkdirAll(netDir, 0755)

	tcpContent := `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
  0: 0100007F:1234 08080808:01BB 01 00000000:00000000 00:00000000 00000000 1000 0 12345 1 0000000000000000 100 0 0 10 0
`
	udpContent := `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
  0: 00000000:0050 00000000:0000 07 00000000:00000000 00:00000000 00000000 0 0 54321 1 0000000000000000 100 0 0 10 0
`

	os.WriteFile(filepath.Join(netDir, "tcp"), []byte(tcpContent), 0644)
	os.WriteFile(filepath.Join(netDir, "udp"), []byte(udpContent), 0644)

	collector := NewLinuxCollectorWithPath(tmpDir)
	connections, err := collector.Collect(context.Background())

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(connections) != 2 {
		t.Fatalf("expected 2 connections, got %d", len(connections))
	}

	if connections[0].Protocol != "tcp" {
		t.Fatalf("expected first protocol tcp, got %s", connections[0].Protocol)
	}

	if connections[1].Protocol != "udp" {
		t.Fatalf("expected second protocol udp, got %s", connections[1].Protocol)
	}
}

// Given: TCP connection entries with missing /proc/{pid}/fd
// When: collecting connections
// Then: returns connections with nil process (best-effort attribution)
func TestLinuxCollectorHandlesMissingProcessAttribution(t *testing.T) {
	tmpDir := t.TempDir()
	netDir := filepath.Join(tmpDir, "net")
	os.MkdirAll(netDir, 0755)

	// Create a TCP connection with inode 12345
	tcpContent := `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
  0: 0100007F:1234 08080808:01BB 01 00000000:00000000 00:00000000 00000000 1000 0 12345 1 0000000000000000 100 0 0 10 0
`
	os.WriteFile(filepath.Join(netDir, "tcp"), []byte(tcpContent), 0644)

	// Don't create any processes - inode won't be found

	collector := NewLinuxCollectorWithPath(tmpDir)
	connections, err := collector.Collect(context.Background())

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(connections) != 1 {
		t.Fatalf("expected 1 connection, got %d", len(connections))
	}

	if connections[0].Process != nil {
		t.Fatal("expected nil process for unattributed connection")
	}

	// Connection should still have network metadata
	if connections[0].LocalAddress != "127.0.0.1" {
		t.Fatalf("expected local address 127.0.0.1, got %s", connections[0].LocalAddress)
	}
}
