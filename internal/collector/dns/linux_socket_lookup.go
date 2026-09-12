//go:build linux

package dns

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/arafat2020/sentinel/internal/core"
)

// SocketOwner identifies the process that owns a network socket.
type SocketOwner struct {
	PID uint32
}

// SocketLookup resolves the process attached to a local IP:port pair.
type SocketLookup interface {
	FindOwner(
		ctx context.Context,
		sourceIP string,
		sourcePort uint32,
	) (*SocketOwner, error)
}

// ProcessResolver resolves full process metadata for a PID.
type ProcessResolver interface {
	Resolve(
		ctx context.Context,
		pid int32,
	) (*core.Process, error)
}

// linuxSocketLookup finds the PID that owns a local socket using the /proc
// filesystem: it looks up the socket inode from /proc/net/{tcp,udp}, then
// scans /proc/{pid}/fd for a symlink to that inode. This mirrors the
// approach used by the Linux network collector (see
// internal/collector/network/linux.go) rather than macOS's libproc-based
// (cgo) lookup, since /proc already exposes this information directly.
type linuxSocketLookup struct {
	procPath string
}

// NewLinuxSocketLookup creates a SocketLookup backed by the real /proc
// filesystem.
func NewLinuxSocketLookup() SocketLookup {
	return &linuxSocketLookup{procPath: "/proc"}
}

// NewLinuxSocketLookupWithPath creates a SocketLookup rooted at a custom
// path, allowing tests to simulate /proc without requiring a real Linux
// kernel.
func NewLinuxSocketLookupWithPath(procPath string) SocketLookup {
	return &linuxSocketLookup{procPath: procPath}
}

func (l *linuxSocketLookup) FindOwner(
	ctx context.Context,
	sourceIP string,
	sourcePort uint32,
) (*SocketOwner, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	targetIP := net.ParseIP(sourceIP)
	if targetIP == nil {
		return nil, fmt.Errorf("invalid source IP: %s", sourceIP)
	}

	netPath := filepath.Join(l.procPath, "net")

	inode, found, err := findInodeForEndpoint(netPath, "tcp", targetIP, sourcePort)
	if err != nil {
		return nil, err
	}

	if !found {
		inode, found, err = findInodeForEndpoint(netPath, "udp", targetIP, sourcePort)
		if err != nil {
			return nil, err
		}
	}

	if !found {
		return nil, nil
	}

	pid, found, err := findPidForInode(l.procPath, inode)
	if err != nil {
		return nil, err
	}

	if !found {
		return nil, nil
	}

	return &SocketOwner{PID: uint32(pid)}, nil
}

// findInodeForEndpoint scans /proc/net/{tcp,udp} for an entry whose local
// address matches targetIP:targetPort and returns its socket inode.
func findInodeForEndpoint(
	netPath string,
	protocol string,
	targetIP net.IP,
	targetPort uint32,
) (uint64, bool, error) {
	file, err := os.Open(filepath.Join(netPath, protocol))
	if err != nil {
		if os.IsNotExist(err) {
			return 0, false, nil
		}

		return 0, false, fmt.Errorf("open /proc/net/%s: %w", protocol, err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)

	// Skip header line.
	if !scanner.Scan() {
		return 0, false, scanner.Err()
	}

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 10 {
			continue
		}

		parts := strings.Split(fields[1], ":")
		if len(parts) != 2 {
			continue
		}

		ip, ok := parseHexIP(parts[0])
		if !ok {
			continue
		}

		port, err := strconv.ParseUint(parts[1], 16, 32)
		if err != nil {
			continue
		}

		if uint32(port) != targetPort || !ip.Equal(targetIP) {
			continue
		}

		inode, err := strconv.ParseUint(fields[9], 10, 64)
		if err != nil {
			continue
		}

		return inode, true, nil
	}

	return 0, false, scanner.Err()
}

// parseHexIP decodes the little-endian hex-encoded IPv4 address format
// used by /proc/net/tcp and /proc/net/udp (e.g. "0100007F" -> 127.0.0.1).
func parseHexIP(hexAddr string) (net.IP, bool) {
	if len(hexAddr) != 8 {
		return nil, false
	}

	b1, err1 := strconv.ParseUint(hexAddr[6:8], 16, 8)
	b2, err2 := strconv.ParseUint(hexAddr[4:6], 16, 8)
	b3, err3 := strconv.ParseUint(hexAddr[2:4], 16, 8)
	b4, err4 := strconv.ParseUint(hexAddr[0:2], 16, 8)

	if err1 != nil || err2 != nil || err3 != nil || err4 != nil {
		return nil, false
	}

	return net.IPv4(byte(b1), byte(b2), byte(b3), byte(b4)), true
}

var socketInodeRegex = regexp.MustCompile(`socket:\[(\d+)\]`)

// findPidForInode scans every /proc/{pid}/fd directory for a symlink
// pointing at socket:[targetInode].
func findPidForInode(procPath string, targetInode uint64) (int32, bool, error) {
	entries, err := os.ReadDir(procPath)
	if err != nil {
		return 0, false, fmt.Errorf("read %s: %w", procPath, err)
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		pid, err := strconv.ParseInt(entry.Name(), 10, 32)
		if err != nil {
			continue
		}

		fdPath := filepath.Join(procPath, entry.Name(), "fd")

		fdEntries, err := os.ReadDir(fdPath)
		if err != nil {
			// Process may have exited, or we lack permission; best-effort.
			continue
		}

		for _, fdEntry := range fdEntries {
			if fdEntry.Type()&os.ModeSymlink == 0 {
				continue
			}

			target, err := os.Readlink(filepath.Join(fdPath, fdEntry.Name()))
			if err != nil {
				continue
			}

			matches := socketInodeRegex.FindStringSubmatch(target)
			if len(matches) != 2 {
				continue
			}

			inode, err := strconv.ParseUint(matches[1], 10, 64)
			if err != nil {
				continue
			}

			if inode == targetInode {
				return int32(pid), true, nil
			}
		}
	}

	return 0, false, nil
}
