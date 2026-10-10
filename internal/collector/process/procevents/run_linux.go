//go:build linux

package procevents

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"

	"github.com/arafat2020/sentinel/internal/core"
)

const (
	// idleWait is how long a backend waits for an event before reporting
	// that there is none, which is when grace periods are checked against
	// the wall clock.
	idleWait = 10 * time.Millisecond
	// idleSlack is kept back from the wall clock on an idle check, to
	// allow for an event the kernel has stamped but not yet delivered.
	idleSlack = time.Millisecond
	// clockSyncInterval is how often the kernel-to-wall-clock offset is
	// measured again.
	clockSyncInterval = 10 * time.Second
)

// errIdle is returned by a backend that waited idleWait without an event.
var errIdle = errors.New("no event")

// backend reads raw events from the kernel.
type backend interface {
	// next waits up to idleWait for an event.
	next(event *raw) error
	// stats adds the backend's own counters.
	stats(stats *Stats)
	// syncClock measures the kernel-to-wall-clock offset again.
	syncClock()
	close() error
}

// source drives a Tracker from a backend.
type source struct {
	name    Backend
	options Options
	backend backend
	users   *userCache

	tracker atomic.Pointer[Tracker]
}

func (s *source) Backend() Backend { return s.name }

func (s *source) Close() error { return s.backend.close() }

func (s *source) Stats() Stats {
	stats := Stats{Backend: s.name}

	if tracker := s.tracker.Load(); tracker != nil {
		tracker.fill(&stats)
	}
	s.backend.stats(&stats)

	stats.UserCacheSize = int(s.users.size.Load())
	stats.UserCacheResets = s.users.resets.Load()

	return stats
}

// listing is a reading of the process table for reconciliation.
type listing struct {
	processes []core.Process
	takenAt   time.Time
}

func (s *source) Run(ctx context.Context, seed []core.Process, emit func(core.Event)) error {
	tracker := NewTracker(s.options.Grace, s.options.MaxTracked, emit)
	tracker.Seed(seed)
	s.tracker.Store(tracker)

	listings := make(chan listing, 1)
	go s.housekeeping(ctx, listings)

	for ctx.Err() == nil {
		var event raw

		switch err := s.backend.next(&event); {
		case err == nil:
			tracker.handle(event)
		case errors.Is(err, errIdle):
			tracker.Advance(time.Now().Add(-idleSlack))
		default:
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("process collector %s: %w", s.name, err)
		}

		select {
		case found := <-listings:
			tracker.Reconcile(found.processes, found.takenAt)
		default:
		}
	}

	return nil
}

// housekeeping keeps the clock conversion fresh and reads the process table
// for reconciliation, off the goroutine that reads events.
func (s *source) housekeeping(ctx context.Context, listings chan<- listing) {
	clock := time.NewTicker(clockSyncInterval)
	defer clock.Stop()

	var reconcile <-chan time.Time
	if s.options.ReconcileInterval > 0 && s.options.Snapshot != nil {
		ticker := time.NewTicker(s.options.ReconcileInterval)
		defer ticker.Stop()
		reconcile = ticker.C
	}

	for {
		select {
		case <-ctx.Done():
			return

		case <-clock.C:
			s.backend.syncClock()

		case <-reconcile:
			takenAt := time.Now()
			processes, err := s.options.Snapshot(ctx)
			if err != nil {
				continue
			}

			// If the previous listing has not been used yet, the
			// reader is far behind; a newer one would not help.
			select {
			case listings <- listing{processes: processes, takenAt: takenAt}:
			default:
			}
		}
	}
}

// kernelRelease returns the running kernel's major and minor version.
func kernelRelease() (major, minor int, release string, err error) {
	var name unix.Utsname
	if err := unix.Uname(&name); err != nil {
		return 0, 0, "", err
	}

	release = unix.ByteSliceToString(name.Release[:])
	major, minor, ok := parseRelease(release)
	if !ok {
		return 0, 0, release, fmt.Errorf("unrecognised kernel release %q", release)
	}

	return major, minor, release, nil
}

func parseRelease(release string) (major, minor int, ok bool) {
	parts := strings.SplitN(release, ".", 3)
	if len(parts) < 2 {
		return 0, 0, false
	}

	major, err := strconv.Atoi(parts[0])
	if err != nil {
		return 0, 0, false
	}

	// The minor version may run straight into a suffix: "5.10-rc1".
	digits := parts[1]
	for i, c := range digits {
		if c < '0' || c > '9' {
			digits = digits[:i]
			break
		}
	}
	minor, err = strconv.Atoi(digits)
	if err != nil {
		return 0, 0, false
	}

	return major, minor, true
}

// readExe resolves the program a process is running, as the polling
// collector does.
func readExe(pid int32) (string, bool) {
	exe, err := os.Readlink("/proc/" + strconv.Itoa(int(pid)) + "/exe")
	return exe, err == nil && exe != ""
}

// readCmdline reads a process's arguments from /proc.
func readCmdline(pid int32) (cmdline, argv0 string, ok bool) {
	data, err := os.ReadFile("/proc/" + strconv.Itoa(int(pid)) + "/cmdline")
	if err != nil {
		return "", "", false
	}

	cmdline, argv0 = joinArgs(data)
	return cmdline, argv0, true
}

// readUID reads a process's real user ID from /proc/<pid>/status.
func readUID(pid int32) (uint32, bool) {
	data, err := os.ReadFile("/proc/" + strconv.Itoa(int(pid)) + "/status")
	if err != nil {
		return 0, false
	}

	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, "Uid:") {
			continue
		}
		fields := strings.Fields(line[len("Uid:"):])
		if len(fields) == 0 {
			return 0, false
		}
		uid, err := strconv.ParseUint(fields[0], 10, 32)
		return uint32(uid), err == nil
	}

	return 0, false
}
