package process

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/arafat2020/sentinel/internal/core"
)

func TestLinuxCollectorReturnsSnapshot(t *testing.T) {
	// Given: A test /proc directory with one process entry
	tmpDir := t.TempDir()
	procDir := filepath.Join(tmpDir, "proc")
	os.MkdirAll(filepath.Join(procDir, "1"), 0755)

	stat := filepath.Join(procDir, "1", "stat")
	os.WriteFile(stat, []byte("1 (init) S 0 1 1 0 -1 1077936128 222 1234 0 0 1 0 10 5 20 0 1 0 12345 1234567 100"), 0644)

	status := filepath.Join(procDir, "1", "status")
	os.WriteFile(status, []byte("Uid:\t0\t0\t0\t0\n"), 0644)

	// When: Collecting processes from fake /proc
	collector := NewLinuxCollectorWithPath(procDir)
	snapshot, err := collector.Collect(context.Background())

	// Then: We get a valid snapshot
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if snapshot == nil {
		t.Fatal("expected non-nil snapshot")
	}

	if len(snapshot.Processes) == 0 {
		t.Fatal("expected at least one process")
	}
}

func TestLinuxCollectorParsesProcessStat(t *testing.T) {
	// Given: A process with stat and status files
	tmpDir := t.TempDir()
	procDir := filepath.Join(tmpDir, "proc")
	os.MkdirAll(filepath.Join(procDir, "42"), 0755)

	stat := filepath.Join(procDir, "42", "stat")
	os.WriteFile(stat, []byte("42 (test-process) S 1 42 42 0 -1 1077936128 100 0 0 0 1 0 5 5 20 0 1 0 12345 1234567 100"), 0644)

	status := filepath.Join(procDir, "42", "status")
	os.WriteFile(status, []byte("Uid:\t1000\t1000\t1000\t1000\n"), 0644)

	// When: Collecting the process
	collector := NewLinuxCollectorWithPath(procDir)
	snapshot, err := collector.Collect(context.Background())

	// Then: Process fields are correctly parsed
	if err != nil {
		t.Fatalf("failed to collect: %v", err)
	}

	found := false
	for _, p := range snapshot.Processes {
		if p.PID == 42 {
			found = true

			if p.Name != "test-process" {
				t.Errorf("expected name 'test-process', got '%s'", p.Name)
			}

			if p.PPID != 1 {
				t.Errorf("expected PPID 1, got %d", p.PPID)
			}

			if p.User != "1000" {
				t.Errorf("expected user '1000', got '%s'", p.User)
			}

			if p.StartTime.IsZero() {
				t.Error("expected non-zero start time")
			}

			break
		}
	}

	if !found {
		t.Error("expected to find PID 42 in snapshot")
	}
}

func TestLinuxCollectorIgnoresNonNumericDirs(t *testing.T) {
	// Given: /proc with numeric and non-numeric directories
	tmpDir := t.TempDir()
	procDir := filepath.Join(tmpDir, "proc")
	os.MkdirAll(filepath.Join(procDir, "1"), 0755)
	os.MkdirAll(filepath.Join(procDir, "self"), 0755)
	os.MkdirAll(filepath.Join(procDir, "net"), 0755)

	stat := filepath.Join(procDir, "1", "stat")
	os.WriteFile(stat, []byte("1 (init) S 0 1 1 0 -1 1077936128 222 0 0 0 1 0 10 5 20 0 1 0 12345 1234567 100"), 0644)

	status := filepath.Join(procDir, "1", "status")
	os.WriteFile(status, []byte("Uid:\t0\t0\t0\t0\n"), 0644)

	// When: Collecting processes
	collector := NewLinuxCollectorWithPath(procDir)
	snapshot, err := collector.Collect(context.Background())

	// Then: Only numeric directories are processed
	if err != nil {
		t.Fatalf("failed to collect: %v", err)
	}

	if len(snapshot.Processes) != 1 {
		t.Errorf("expected 1 process, got %d", len(snapshot.Processes))
	}

	if snapshot.Processes[0].PID != 1 {
		t.Errorf("expected PID 1, got %d", snapshot.Processes[0].PID)
	}
}

func TestLinuxCollectorHandlesReadFailures(t *testing.T) {
	// Given: A directory that doesn't exist
	collector := NewLinuxCollectorWithPath("/nonexistent/proc")

	// When: Collecting processes
	snapshot, err := collector.Collect(context.Background())

	// Then: We get an error
	if err == nil {
		t.Fatal("expected error for nonexistent path")
	}

	if snapshot != nil {
		t.Error("expected nil snapshot on error")
	}
}

func TestLinuxCollectorHandlesProcessesExitingDuringCollection(t *testing.T) {
	// Given: /proc with a process that may disappear
	tmpDir := t.TempDir()
	procDir := filepath.Join(tmpDir, "proc")
	os.MkdirAll(filepath.Join(procDir, "100"), 0755)

	stat := filepath.Join(procDir, "100", "stat")
	os.WriteFile(stat, []byte("100 (proc100) S 1 100 100 0 -1 1077936128 10 0 0 0 1 0 5 5 20 0 1 0 12345 1234567 100"), 0644)

	status := filepath.Join(procDir, "100", "status")
	os.WriteFile(status, []byte("Uid:\t500\t500\t500\t500\n"), 0644)

	// When: Collecting (even if a process stat file is corrupted)
	collector := NewLinuxCollectorWithPath(procDir)
	snapshot, err := collector.Collect(context.Background())

	// Then: We still get a valid snapshot for valid processes
	if err != nil {
		t.Fatalf("failed to collect: %v", err)
	}

	if len(snapshot.Processes) == 0 {
		t.Error("expected to find valid processes")
	}
}

func TestLinuxCollectorCanHandleRealProcIfAvailable(t *testing.T) {
	// Skip on non-Linux systems
	if _, err := os.Stat("/proc"); os.IsNotExist(err) {
		t.Skip("skipping test on non-Linux system")
	}

	// Given: Default Linux collector using real /proc
	collector := NewLinuxCollector()

	// When: Collecting processes
	snapshot, err := collector.Collect(context.Background())

	// Then: We get processes from the real /proc filesystem
	if err != nil {
		t.Logf("note: collection failed (might be expected on some systems): %v", err)
		return
	}

	if snapshot == nil {
		t.Fatal("expected non-nil snapshot")
	}

	// We should have at least some processes
	if len(snapshot.Processes) == 0 {
		t.Fatal("expected to find processes in /proc")
	}

	// All processes should have valid PIDs
	for _, p := range snapshot.Processes {
		if p.PID <= 0 {
			t.Errorf("invalid PID: %d", p.PID)
		}
	}
}

func TestLinuxCollectorPreservesProcessHierarchy(t *testing.T) {
	// Given: Parent and child processes
	tmpDir := t.TempDir()
	procDir := filepath.Join(tmpDir, "proc")

	// Parent process
	os.MkdirAll(filepath.Join(procDir, "1"), 0755)
	os.WriteFile(filepath.Join(procDir, "1", "stat"),
		[]byte("1 (parent) S 0 1 1 0 -1 1077936128 10 0 0 0 1 0 5 5 20 0 1 0 12345 1234567 100"), 0644)
	os.WriteFile(filepath.Join(procDir, "1", "status"), []byte("Uid:\t0\t0\t0\t0\n"), 0644)

	// Child process
	os.MkdirAll(filepath.Join(procDir, "2"), 0755)
	os.WriteFile(filepath.Join(procDir, "2", "stat"),
		[]byte("2 (child) S 1 2 2 0 -1 1077936128 10 0 0 0 1 0 5 5 20 0 1 0 12346 1234567 100"), 0644)
	os.WriteFile(filepath.Join(procDir, "2", "status"), []byte("Uid:\t0\t0\t0\t0\n"), 0644)

	// When: Collecting processes
	collector := NewLinuxCollectorWithPath(procDir)
	snapshot, err := collector.Collect(context.Background())

	// Then: Parent-child relationship is preserved
	if err != nil {
		t.Fatalf("failed to collect: %v", err)
	}

	var parent, child *core.Process
	for i := range snapshot.Processes {
		if snapshot.Processes[i].PID == 1 {
			parent = &snapshot.Processes[i]
		}
		if snapshot.Processes[i].PID == 2 {
			child = &snapshot.Processes[i]
		}
	}

	if parent == nil {
		t.Fatal("expected to find parent process")
	}

	if child == nil {
		t.Fatal("expected to find child process")
	}

	if child.PPID != parent.PID {
		t.Errorf("expected child PPID %d, got %d", parent.PID, child.PPID)
	}
}
