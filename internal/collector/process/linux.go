package process

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

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

func (c *LinuxCollector) Collect(ctx context.Context) (*core.ProcessSnapshot, error) {
	procDir := c.procPath

	entries, err := os.ReadDir(procDir)
	if err != nil {
		return nil, fmt.Errorf("read /proc: %w", err)
	}

	snapshot := &core.ProcessSnapshot{
		Processes: make([]core.Process, 0),
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		pid, err := strconv.ParseInt(entry.Name(), 10, 32)
		if err != nil {
			// Not a numeric directory, skip
			continue
		}

		process, err := c.readProcess(ctx, int32(pid))
		if err != nil {
			// Process may have exited during collection, skip
			continue
		}

		snapshot.Processes = append(snapshot.Processes, process)
	}

	return snapshot, nil
}

func (c *LinuxCollector) readProcess(ctx context.Context, pid int32) (core.Process, error) {
	procPath := filepath.Join(c.procPath, strconv.FormatInt(int64(pid), 10))

	stat, err := readStat(procPath)
	if err != nil {
		return core.Process{}, fmt.Errorf("read stat: %w", err)
	}

	status := readStatus(procPath)

	cmdline, err := readCmdline(procPath)
	if err != nil {
		// cmdline might not be available, use empty string
		cmdline = ""
	}

	executable, err := readExecutable(procPath)
	if err != nil {
		// executable might not be available, use empty string
		executable = ""
	}

	return core.Process{
		PID:         pid,
		PPID:        stat.ppid,
		StartTime:   stat.startTime,
		Name:        stat.name,
		Executable:  executable,
		CommandLine: cmdline,
		User:        status.uid,
	}, nil
}

type statInfo struct {
	name      string
	ppid      int32
	startTime time.Time
}

func readStat(procPath string) (*statInfo, error) {
	content, err := os.ReadFile(filepath.Join(procPath, "stat"))
	if err != nil {
		return nil, fmt.Errorf("read stat file: %w", err)
	}

	fields := strings.Fields(string(content))
	if len(fields) < 22 {
		return nil, fmt.Errorf("stat file has insufficient fields")
	}

	name := strings.Trim(fields[1], "()")

	ppid, err := strconv.ParseInt(fields[3], 10, 32)
	if err != nil {
		return nil, fmt.Errorf("parse ppid: %w", err)
	}

	startTicks, err := strconv.ParseInt(fields[21], 10, 64)
	if err != nil {
		return nil, fmt.Errorf("parse start ticks: %w", err)
	}

	// Convert jiffies to time.Time (assuming 100 jiffies per second)
	// This is an approximation; more accurate calculation would use /proc/uptime
	startTime := timeFromStartTicks(startTicks)

	return &statInfo{
		name:      name,
		ppid:      int32(ppid),
		startTime: startTime,
	}, nil
}

type statusInfo struct {
	uid string
}

func readStatus(procPath string) *statusInfo {
	// readStatus does not return an error because uid extraction is best-effort
	content, err := os.ReadFile(filepath.Join(procPath, "status"))
	if err != nil {
		return &statusInfo{uid: ""}
	}

	lines := strings.Split(string(content), "\n")
	uid := ""

	for _, line := range lines {
		if strings.HasPrefix(line, "Uid:") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				uid = parts[1]
				break
			}
		}
	}

	return &statusInfo{uid: uid}
}

func readCmdline(procPath string) (string, error) {
	content, err := os.ReadFile(filepath.Join(procPath, "cmdline"))
	if err != nil {
		return "", fmt.Errorf("read cmdline: %w", err)
	}

	// cmdline uses null bytes as separator
	cmdlineStr := strings.ReplaceAll(string(content), "\x00", " ")
	return strings.TrimSpace(cmdlineStr), nil
}

func readExecutable(procPath string) (string, error) {
	exe, err := os.Readlink(filepath.Join(procPath, "exe"))
	if err != nil {
		return "", fmt.Errorf("read exe symlink: %w", err)
	}

	return exe, nil
}

func timeFromStartTicks(ticks int64) time.Time {
	// Get system uptime to convert jiffies to absolute time
	content, err := os.ReadFile("/proc/uptime")
	if err != nil {
		// Fallback: assume 100 jiffies per second and work backwards from now
		// This is used in tests where /proc/uptime might not exist
		seconds := ticks / 100
		return time.Now().Add(-time.Duration(seconds) * time.Second)
	}

	fields := strings.Fields(string(content))
	if len(fields) < 1 {
		seconds := ticks / 100
		return time.Now().Add(-time.Duration(seconds) * time.Second)
	}

	uptime, err := strconv.ParseFloat(fields[0], 64)
	if err != nil {
		seconds := ticks / 100
		return time.Now().Add(-time.Duration(seconds) * time.Second)
	}

	bootTime := time.Now().Add(-time.Duration(uptime) * time.Second)
	tickDuration := time.Duration(ticks) * time.Second / 100
	startTime := bootTime.Add(tickDuration)

	return startTime
}
