//go:build linux

package dns

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// Given: /proc/net/tcp containing an entry for 127.0.0.1:54321
// When: looking up the owner of that local endpoint
// Then: returns the PID whose /proc/{pid}/fd holds the matching socket inode
func TestLinuxSocketLookupFindsOwnerViaTcp(t *testing.T) {
	tmpDir := t.TempDir()
	netDir := filepath.Join(tmpDir, "net")
	os.MkdirAll(netDir, 0755)

	tcpContent := `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
  0: 0100007F:D431 08080808:0035 01 00000000:00000000 00:00000000 00000000 1000 0 12345 1 0000000000000000 100 0 0 10 0
`
	os.WriteFile(filepath.Join(netDir, "tcp"), []byte(tcpContent), 0644)
	os.WriteFile(filepath.Join(netDir, "udp"), []byte(""), 0644)

	fdDir := filepath.Join(tmpDir, "42", "fd")
	os.MkdirAll(fdDir, 0755)
	os.Symlink("socket:[12345]", filepath.Join(fdDir, "3"))

	lookup := NewLinuxSocketLookupWithPath(tmpDir)

	owner, err := lookup.FindOwner(
		context.Background(),
		"127.0.0.1",
		54321, // 0xD431
	)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if owner == nil {
		t.Fatal("expected owner, got nil")
	}

	if owner.PID != 42 {
		t.Fatalf("expected PID 42, got %d", owner.PID)
	}
}

// Given: /proc/net/udp containing the matching entry (not tcp)
// When: looking up the owner
// Then: falls back to udp and still resolves the owning PID
func TestLinuxSocketLookupFindsOwnerViaUdp(t *testing.T) {
	tmpDir := t.TempDir()
	netDir := filepath.Join(tmpDir, "net")
	os.MkdirAll(netDir, 0755)

	udpContent := `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
  0: 0100007F:D431 08080808:0035 07 00000000:00000000 00:00000000 00000000 1000 0 54321 1 0000000000000000 100 0 0 10 0
`
	os.WriteFile(filepath.Join(netDir, "tcp"), []byte(""), 0644)
	os.WriteFile(filepath.Join(netDir, "udp"), []byte(udpContent), 0644)

	fdDir := filepath.Join(tmpDir, "99", "fd")
	os.MkdirAll(fdDir, 0755)
	os.Symlink("socket:[54321]", filepath.Join(fdDir, "5"))

	lookup := NewLinuxSocketLookupWithPath(tmpDir)

	owner, err := lookup.FindOwner(
		context.Background(),
		"127.0.0.1",
		54321,
	)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if owner == nil {
		t.Fatal("expected owner, got nil")
	}

	if owner.PID != 99 {
		t.Fatalf("expected PID 99, got %d", owner.PID)
	}
}

// Given: no matching socket entry in /proc/net/{tcp,udp}
// When: looking up the owner
// Then: returns nil owner without error (best-effort attribution)
func TestLinuxSocketLookupNoMatch(t *testing.T) {
	tmpDir := t.TempDir()
	netDir := filepath.Join(tmpDir, "net")
	os.MkdirAll(netDir, 0755)
	os.WriteFile(filepath.Join(netDir, "tcp"), []byte(""), 0644)
	os.WriteFile(filepath.Join(netDir, "udp"), []byte(""), 0644)

	lookup := NewLinuxSocketLookupWithPath(tmpDir)

	owner, err := lookup.FindOwner(
		context.Background(),
		"127.0.0.1",
		54321,
	)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if owner != nil {
		t.Fatalf("expected nil owner, got %+v", owner)
	}
}

// Given: /proc/net files are missing entirely
// When: looking up the owner
// Then: treats missing files as no match rather than an error
func TestLinuxSocketLookupMissingProcNetFiles(t *testing.T) {
	tmpDir := t.TempDir()
	os.MkdirAll(filepath.Join(tmpDir, "net"), 0755)

	lookup := NewLinuxSocketLookupWithPath(tmpDir)

	owner, err := lookup.FindOwner(
		context.Background(),
		"127.0.0.1",
		54321,
	)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if owner != nil {
		t.Fatalf("expected nil owner, got %+v", owner)
	}
}

// Given: a matching socket entry but no process fd references its inode
// When: looking up the owner
// Then: returns nil owner (socket exists, but attribution races the exit)
func TestLinuxSocketLookupInodeWithoutOwningProcess(t *testing.T) {
	tmpDir := t.TempDir()
	netDir := filepath.Join(tmpDir, "net")
	os.MkdirAll(netDir, 0755)

	tcpContent := `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
  0: 0100007F:D431 08080808:0035 01 00000000:00000000 00:00000000 00000000 1000 0 12345 1 0000000000000000 100 0 0 10 0
`
	os.WriteFile(filepath.Join(netDir, "tcp"), []byte(tcpContent), 0644)
	os.WriteFile(filepath.Join(netDir, "udp"), []byte(""), 0644)

	lookup := NewLinuxSocketLookupWithPath(tmpDir)

	owner, err := lookup.FindOwner(
		context.Background(),
		"127.0.0.1",
		54321,
	)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if owner != nil {
		t.Fatalf("expected nil owner, got %+v", owner)
	}
}

// Given: an invalid source IP
// When: looking up the owner
// Then: returns an error
func TestLinuxSocketLookupInvalidIP(t *testing.T) {
	lookup := NewLinuxSocketLookupWithPath(t.TempDir())

	_, err := lookup.FindOwner(
		context.Background(),
		"not-an-ip",
		54321,
	)

	if err == nil {
		t.Fatal("expected invalid IP error")
	}
}

// Given: a cancelled context
// When: looking up the owner
// Then: returns the context error immediately
func TestLinuxSocketLookupContextCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	lookup := NewLinuxSocketLookupWithPath(t.TempDir())

	_, err := lookup.FindOwner(
		ctx,
		"127.0.0.1",
		54321,
	)

	if err == nil {
		t.Fatal("expected context cancellation error")
	}
}

// Given: hex-encoded IPv4 addresses from /proc/net/tcp
// When: decoding them
// Then: correctly parses to dotted-decimal form
func TestParseHexIP(t *testing.T) {
	tests := []struct {
		hexAddr string
		wantIP  string
		wantOK  bool
	}{
		{"0100007F", "127.0.0.1", true},
		{"00000000", "0.0.0.0", true},
		{"08080808", "8.8.8.8", true},
		{"E80A0A0A", "10.10.10.232", true},
		{"XYZ", "", false},
		{"0100", "", false},
	}

	for _, tt := range tests {
		ip, ok := parseHexIP(tt.hexAddr)

		if ok != tt.wantOK {
			t.Fatalf("parseHexIP(%s): expected ok=%v, got %v", tt.hexAddr, tt.wantOK, ok)
		}

		if ok && ip.String() != tt.wantIP {
			t.Fatalf("parseHexIP(%s): expected %s, got %s", tt.hexAddr, tt.wantIP, ip.String())
		}
	}
}

// Given: a PID with a file descriptor pointing at a matching socket inode
// When: searching for the owning PID
// Then: returns that PID
func TestFindPidForInode(t *testing.T) {
	tmpDir := t.TempDir()
	fdDir := filepath.Join(tmpDir, "7", "fd")
	os.MkdirAll(fdDir, 0755)
	os.Symlink("socket:[999]", filepath.Join(fdDir, "3"))
	os.Symlink("/dev/null", filepath.Join(fdDir, "0"))

	pid, found, err := findPidForInode(tmpDir, 999)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !found {
		t.Fatal("expected inode to be found")
	}

	if pid != 7 {
		t.Fatalf("expected PID 7, got %d", pid)
	}
}
