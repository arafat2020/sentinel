package network

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/arafat2020/sentinel/internal/collector/process"
	"github.com/arafat2020/sentinel/internal/core"
)

type LinuxCollector struct {
	procPath string
}

func NewLinuxCollector() *LinuxCollector {
	return &LinuxCollector{
		procPath: "/proc",
	}
}

func NewLinuxCollectorWithPath(procPath string) *LinuxCollector {
	return &LinuxCollector{
		procPath: procPath,
	}
}

type socketEntry struct {
	LocalIP    string
	LocalPort  uint32
	RemoteIP   string
	RemotePort uint32
	State      string
	Protocol   string
	Inode      uint64
}

func (c *LinuxCollector) Collect(ctx context.Context) ([]core.NetworkConnection, error) {
	netPath := filepath.Join(c.procPath, "net")

	// Check if /proc/net directory is accessible
	if _, err := os.Stat(netPath); err != nil {
		return nil, fmt.Errorf("read /proc/net: %w", err)
	}

	entries := make([]socketEntry, 0)

	// Read TCP connections (if file exists)
	tcpEntries, _ := readTcpConnections(netPath)
	entries = append(entries, tcpEntries...)

	// Read UDP connections (if file exists)
	udpEntries, _ := readUdpConnections(netPath)
	entries = append(entries, udpEntries...)

	// Build inode to PID mapping for process attribution
	inodeToPid := buildInodeToPidMap(c.procPath)

	// Fetch process resolver for attribution
	resolver := process.NewResolver()

	connections := make([]core.NetworkConnection, 0, len(entries))
	for _, entry := range entries {
		var proc *core.Process

		if pid, ok := inodeToPid[entry.Inode]; ok {
			// Best-effort process attribution via /proc/{pid}
			if p, err := resolver.Resolve(ctx, pid); err == nil {
				proc = p
			}
		}

		conn := connectionToCoreNetworkConnection(entry, proc)
		connections = append(connections, conn)
	}

	return connections, nil
}

func readTcpConnections(netPath string) ([]socketEntry, error) {
	return readNetworkConnections(filepath.Join(netPath, "tcp"), "tcp")
}

func readUdpConnections(netPath string) ([]socketEntry, error) {
	return readNetworkConnections(filepath.Join(netPath, "udp"), "udp")
}

func readNetworkConnections(filePath string, protocol string) ([]socketEntry, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", filePath, err)
	}
	defer file.Close()

	entries := make([]socketEntry, 0)
	scanner := bufio.NewScanner(file)

	// Skip header line
	if !scanner.Scan() {
		return entries, nil
	}

	for scanner.Scan() {
		line := scanner.Text()
		if strings.TrimSpace(line) == "" {
			continue
		}

		entry, err := parseTcpEntry(line, protocol)
		if err != nil {
			continue
		}

		entries = append(entries, entry)
	}

	return entries, scanner.Err()
}

func parseTcpEntry(line string, protocol string) (socketEntry, error) {
	fields := strings.Fields(line)
	if len(fields) < 10 {
		return socketEntry{}, fmt.Errorf("insufficient fields in line: %s", line)
	}

	// Format: sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode ...
	// Index:  0  1            2           3  4         5         6  7         8       9   10      11    ...

	localAddr := fields[1]
	remoteAddr := fields[2]
	state := fields[3]
	inodeStr := fields[9]

	localIP, _ := parseSocketAddress(strings.Split(localAddr, ":")[0])
	localPortStr := strings.Split(localAddr, ":")[1]
	localPort := uint32(0)
	if portVal, err := strconv.ParseUint(localPortStr, 16, 32); err == nil {
		localPort = uint32(portVal)
	}

	remoteIP, _ := parseSocketAddress(strings.Split(remoteAddr, ":")[0])
	remotePortStr := strings.Split(remoteAddr, ":")[1]
	remotePort := uint32(0)
	if portVal, err := strconv.ParseUint(remotePortStr, 16, 32); err == nil {
		remotePort = uint32(portVal)
	}

	inode, err := strconv.ParseUint(inodeStr, 10, 64)
	if err != nil {
		inode = 0
	}

	return socketEntry{
		LocalIP:    localIP,
		LocalPort:  localPort,
		RemoteIP:   remoteIP,
		RemotePort: remotePort,
		State:      state,
		Protocol:   protocol,
		Inode:      inode,
	}, nil
}

func parseSocketAddress(hexAddr string) (string, uint32) {
	if len(hexAddr) < 8 {
		return "0.0.0.0", 0
	}

	// Convert hex address (little-endian) to IP
	// Format: DDDCCCBB AA000000 where AABBCCDD is IP in network order
	b1, _ := strconv.ParseUint(hexAddr[6:8], 16, 8)
	b2, _ := strconv.ParseUint(hexAddr[4:6], 16, 8)
	b3, _ := strconv.ParseUint(hexAddr[2:4], 16, 8)
	b4, _ := strconv.ParseUint(hexAddr[0:2], 16, 8)

	ip := fmt.Sprintf("%d.%d.%d.%d", b1, b2, b3, b4)
	return ip, 0
}

func buildInodeToPidMap(procPath string) map[uint64]int32 {
	inodeToPid := make(map[uint64]int32)

	entries, err := os.ReadDir(procPath)
	if err != nil {
		return inodeToPid
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		pidStr := entry.Name()
		pid, err := strconv.ParseInt(pidStr, 10, 32)
		if err != nil {
			continue
		}

		_ = findSocketOwnerByInode(procPath, int32(pid), inodeToPid)
	}

	return inodeToPid
}

func findSocketOwnerByInode(procPath string, pid int32, inodeToPid map[uint64]int32) error {
	pidStr := strconv.FormatInt(int64(pid), 10)
	fdPath := filepath.Join(procPath, pidStr, "fd")

	entries, err := os.ReadDir(fdPath)
	if err != nil {
		return fmt.Errorf("read fd directory: %w", err)
	}

	socketRegex := regexp.MustCompile(`socket:\[(\d+)\]`)

	for _, entry := range entries {
		if entry.Type()&os.ModeSymlink == 0 {
			continue
		}

		linkPath := filepath.Join(fdPath, entry.Name())
		target, err := os.Readlink(linkPath)
		if err != nil {
			continue
		}

		matches := socketRegex.FindStringSubmatch(target)
		if len(matches) == 2 {
			inode, err := strconv.ParseUint(matches[1], 10, 64)
			if err != nil {
				continue
			}

			inodeToPid[inode] = pid
		}
	}

	return nil
}

func connectionToCoreNetworkConnection(entry socketEntry, process *core.Process) core.NetworkConnection {
	var ppid int32
	if process != nil {
		ppid = process.PPID
	}

	conn := core.NetworkConnection{
		Timestamp:     time.Now(),
		PID:           0,
		PPID:          ppid,
		Protocol:      entry.Protocol,
		LocalAddress:  entry.LocalIP,
		LocalPort:     entry.LocalPort,
		RemoteAddress: entry.RemoteIP,
		RemotePort:    entry.RemotePort,
		State:         entry.State,
		Process:       process,
	}

	if process != nil {
		conn.PID = process.PID
	}

	return conn
}
