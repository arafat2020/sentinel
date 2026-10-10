package procevents

import (
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"github.com/arafat2020/sentinel/internal/core"
)

type rawKind uint8

const (
	rawFork rawKind = iota + 1
	rawExec
	rawExit
)

// raw is one kernel event, with its times already converted: at is the
// wall-clock time it happened, and start is the process's start time exactly
// as every other collector reports it (zero when it could not be found out).
type raw struct {
	kind rawKind
	pid  int32
	ppid int32

	start time.Time
	at    time.Time

	// The image, as far as the backend knows it. A fork carries the
	// kernel's short name only; an exec carries everything.
	comm    string
	exe     string
	cmdline string
	argv0   string
	user    string

	// argsTruncated is set when the command line was longer than the
	// backend captures. partial is set when the process was gone before
	// the backend could read what describes it.
	argsTruncated bool
	partial       bool
}

// Metadata keys set on the events a Tracker emits.
const (
	// MetaPartial marks an event whose process description is incomplete.
	MetaPartial = "partial"
	// MetaCmdlineTruncated marks a command line cut at the capture limit.
	MetaCmdlineTruncated = "cmdline_truncated"
	// MetaInferred marks an exit that was not reported by the kernel but
	// deduced, from the PID being reused or from the process table.
	MetaInferred = "inferred"
	// MetaReconciled marks a start found by reading the process table.
	MetaReconciled = "reconciled"
)

// reconcileMargin keeps reconciliation away from anything recent enough that
// its kernel event may still be on its way.
const reconcileMargin = 2 * time.Second

// tracked is a process the tracker is following.
type tracked struct {
	process core.Process
	// pending is set while PROCESS_START is being held back to see whether
	// the process execs within the grace period.
	pending bool
	forkAt  time.Time
	// seen is the stream time at which the process was first tracked; zero
	// for one that was running before the tracker started.
	seen time.Time

	partial   bool
	truncated bool
}

type pendingStart struct {
	pid     int32
	process *tracked
}

// Tracker turns fork, exec and exit into process events.
//
// A new process is one fork followed, almost always, by one exec. Reporting
// the fork alone would describe every new process as a copy of its parent
// ("bash"), and reporting the exec alone would miss programs that fork
// without exec. So:
//
//   - PROCESS_START is emitted exactly once per process. If the process
//     execs within the grace period after its fork, the start is emitted at
//     that exec, describing the program it exec'd and stamped with the time
//     of the exec. Otherwise it is emitted when the grace period ends,
//     describing the image inherited from the parent and stamped with the
//     time of the fork.
//   - Any exec after the start has been emitted is a PROCESS_EXEC, carrying
//     the new image. The process keeps its identity.
//   - A process that exits during the grace period without exec'ing still
//     gets PROCESS_START (at its fork time) and then PROCESS_EXIT.
//   - A parent's start is always emitted before its child's: a fork by a
//     process still in its grace period ends that period.
//
// The grace period is measured between the kernel's own timestamps for the
// fork and the exec, not by when they were read, so a busy reader does not
// turn starts into execs.
//
// A Tracker is driven from one goroutine. Stats may be read from any.
type Tracker struct {
	grace      time.Duration
	maxTracked int
	emit       func(core.Event)

	procs   map[int32]*tracked
	pending []pendingStart
	// clock is the latest time the tracker has been told about.
	clock time.Time

	counters counters
}

type counters struct {
	rawForks, rawExecs, rawExits     atomic.Uint64
	starts, execs, exits             atomic.Uint64
	startsAtExec, startsAtFork       atomic.Uint64
	partial, argsTruncated           atomic.Uint64
	trackedCapHits                   atomic.Uint64
	untrackedExecs, untrackedExits   atomic.Uint64
	pidReuses, duplicateForks        atomic.Uint64
	reconciledStarts, reconciledExit atomic.Uint64
	tracked, pending                 atomic.Int64
}

// NewTracker returns a tracker that hands its events to emit.
func NewTracker(grace time.Duration, maxTracked int, emit func(core.Event)) *Tracker {
	if grace <= 0 {
		grace = DefaultGrace
	}
	if maxTracked <= 0 {
		maxTracked = DefaultMaxTracked
	}

	return &Tracker{
		grace:      grace,
		maxTracked: maxTracked,
		emit:       emit,
		procs:      make(map[int32]*tracked),
	}
}

// Seed records processes that were already running. Nothing is emitted for
// them; they are known so that their children inherit their image and their
// exits are reported.
func (t *Tracker) Seed(processes []core.Process) {
	for _, process := range processes {
		if _, known := t.procs[process.PID]; known {
			continue
		}
		if len(t.procs) >= t.maxTracked {
			t.counters.trackedCapHits.Add(1)
			continue
		}
		t.procs[process.PID] = &tracked{process: process}
	}
	t.counters.tracked.Store(int64(len(t.procs)))
}

// handle processes one kernel event.
func (t *Tracker) handle(event raw) {
	// Anything whose grace period ended before this event happened is
	// settled first, whatever is about to be learned.
	t.Advance(event.at)

	switch event.kind {
	case rawFork:
		t.counters.rawForks.Add(1)
		t.fork(event)
	case rawExec:
		t.counters.rawExecs.Add(1)
		t.exec(event)
	case rawExit:
		t.counters.rawExits.Add(1)
		t.exit(event)
	}

	t.counters.tracked.Store(int64(len(t.procs)))
}

// Advance tells the tracker that time has reached now, and emits the start of
// every process whose grace period has run out.
//
// The backends call it with each event's own timestamp, and with the wall
// clock when no events are arriving, so a start is never held longer than the
// grace period plus the time the reader was idle.
func (t *Tracker) Advance(now time.Time) {
	if now.After(t.clock) {
		t.clock = now
	}

	settled := 0
	for _, held := range t.pending {
		if !held.process.forkAt.Add(t.grace).Before(t.clock) {
			break
		}
		settled++

		// The entry is stale if the process has since exec'd or exited.
		if t.procs[held.pid] == held.process && held.process.pending {
			t.flush(held.process)
		}
	}

	if settled > 0 {
		t.pending = append(t.pending[:0], t.pending[settled:]...)
	}
}

func (t *Tracker) fork(event raw) {
	if existing := t.procs[event.pid]; existing != nil {
		if sameStart(existing.process.StartTime, event.start) {
			// Created while the startup snapshot was being taken:
			// the snapshot already described it.
			t.counters.duplicateForks.Add(1)
			return
		}

		// The PID has a new owner, so the old one exited unnoticed.
		t.counters.pidReuses.Add(1)
		t.gone(existing, event.at)
	}

	if len(t.procs) >= t.maxTracked {
		t.counters.trackedCapHits.Add(1)
		return
	}

	child := &tracked{
		process: core.Process{PID: event.pid, PPID: event.ppid, StartTime: event.start},
		pending: true,
		forkAt:  event.at,
		seen:    t.clock,
		partial: event.partial,
	}

	if parent := t.procs[event.ppid]; parent != nil {
		// The parent is announced before its child.
		if parent.pending {
			t.flush(parent)
		}

		// A forked process runs its parent's program until it execs.
		child.process.Name = parent.process.Name
		child.process.Executable = parent.process.Executable
		child.process.CommandLine = parent.process.CommandLine
		child.process.User = parent.process.User
		child.truncated = parent.truncated
	} else {
		child.process.Name = imageName(event.comm, event.argv0, event.exe)
		child.process.Executable = event.exe
		child.process.CommandLine = event.cmdline
		if event.exe == "" {
			child.partial = true
		}
	}
	if event.user != "" {
		child.process.User = event.user
	}

	t.procs[event.pid] = child
	t.pending = append(t.pending, pendingStart{pid: event.pid, process: child})
	t.counters.pending.Add(1)
}

func (t *Tracker) exec(event raw) {
	process := t.procs[event.pid]

	if process != nil && differentStart(process.process.StartTime, event.start) {
		t.counters.pidReuses.Add(1)
		t.gone(process, event.at)
		process = nil
	}

	if process == nil {
		// The fork was not seen. The exec says everything a start needs.
		t.counters.untrackedExecs.Add(1)
		if len(t.procs) >= t.maxTracked {
			t.counters.trackedCapHits.Add(1)
			return
		}

		process = &tracked{
			process: core.Process{PID: event.pid, PPID: event.ppid, StartTime: event.start},
			seen:    t.clock,
		}
		t.procs[event.pid] = process
		process.image(event)

		t.counters.startsAtExec.Add(1)
		t.send(core.EventProcessStart, process, event.at, nil)
		return
	}

	// A process first described without its start time is completed by the
	// first event that knows it, as long as nothing has been emitted yet.
	if process.pending && !startKnown(process.process.StartTime) && startKnown(event.start) {
		process.process.StartTime = event.start
	}

	process.image(event)

	if process.pending {
		process.pending = false
		t.counters.pending.Add(-1)
		t.counters.startsAtExec.Add(1)
		t.send(core.EventProcessStart, process, event.at, nil)
		return
	}

	t.send(core.EventProcessExec, process, event.at, nil)
}

func (t *Tracker) exit(event raw) {
	process := t.procs[event.pid]
	if process == nil || differentStart(process.process.StartTime, event.start) {
		t.counters.untrackedExits.Add(1)
		return
	}

	if process.pending {
		t.flush(process)
	}

	delete(t.procs, event.pid)
	t.send(core.EventProcessExit, process, event.at, nil)
}

// flush ends a process's grace period: it did not exec, so it is announced as
// it was at its fork.
func (t *Tracker) flush(process *tracked) {
	process.pending = false
	t.counters.pending.Add(-1)
	t.counters.startsAtFork.Add(1)
	t.send(core.EventProcessStart, process, process.forkAt, nil)
}

// gone reports the exit of a process for which no exit event was seen.
func (t *Tracker) gone(process *tracked, at time.Time) {
	if process.pending {
		t.flush(process)
	}

	delete(t.procs, process.process.PID)
	t.send(core.EventProcessExit, process, at, map[string]any{MetaInferred: true})
}

// image replaces the program a process is running with the one it exec'd.
// What the backend could not read is left as it was.
func (p *tracked) image(event raw) {
	p.partial = event.partial
	p.truncated = event.argsTruncated

	if event.comm == "" && event.exe == "" && event.cmdline == "" {
		p.partial = true
		return
	}

	p.process.Name = imageName(event.comm, event.argv0, event.exe)
	p.process.Executable = event.exe
	p.process.CommandLine = event.cmdline
	if event.user != "" {
		p.process.User = event.user
	}
	if event.ppid != 0 && p.process.PPID == 0 {
		p.process.PPID = event.ppid
	}
}

func (t *Tracker) send(eventType core.EventType, process *tracked, at time.Time, metadata map[string]any) {
	described := process.process

	if process.partial {
		if metadata == nil {
			metadata = make(map[string]any, 1)
		}
		metadata[MetaPartial] = true
		t.counters.partial.Add(1)
	}
	if process.truncated && eventType != core.EventProcessExit {
		if metadata == nil {
			metadata = make(map[string]any, 1)
		}
		metadata[MetaCmdlineTruncated] = true
		t.counters.argsTruncated.Add(1)
	}

	switch eventType {
	case core.EventProcessStart:
		t.counters.starts.Add(1)
	case core.EventProcessExec:
		t.counters.execs.Add(1)
	case core.EventProcessExit:
		t.counters.exits.Add(1)
	}

	t.emit(core.Event{
		Timestamp: at,
		Type:      eventType,
		Process:   &described,
		Metadata:  metadata,
	})
}

// Reconcile compares the tracked processes with a listing of the process
// table taken at takenAt, and repairs what lost events left wrong: a tracked
// process that is no longer running is reported as exited, and a running
// process that is not tracked is reported as started.
//
// Anything first seen within reconcileMargin of the listing is left alone,
// because its events may not have been read yet.
func (t *Tracker) Reconcile(running []core.Process, takenAt time.Time) {
	settledBefore := takenAt.Add(-reconcileMargin)

	live := make(map[int32]core.Process, len(running))
	for _, process := range running {
		live[process.PID] = process
	}

	for pid, process := range t.procs {
		if process.pending || !process.seen.Before(settledBefore) {
			continue
		}

		current, alive := live[pid]
		if alive && !differentStart(process.process.StartTime, current.StartTime) {
			continue
		}

		t.counters.reconciledExit.Add(1)
		t.gone(process, takenAt)
	}

	for _, process := range running {
		if _, known := t.procs[process.PID]; known {
			continue
		}
		if !startKnown(process.StartTime) || !process.StartTime.Before(settledBefore) {
			continue
		}
		if len(t.procs) >= t.maxTracked {
			t.counters.trackedCapHits.Add(1)
			continue
		}

		found := &tracked{process: process, seen: t.clock}
		t.procs[process.PID] = found

		t.counters.reconciledStarts.Add(1)
		t.send(core.EventProcessStart, found, process.StartTime, map[string]any{MetaReconciled: true})
	}

	t.counters.tracked.Store(int64(len(t.procs)))
}

// fill copies the tracker's counters into stats.
func (t *Tracker) fill(stats *Stats) {
	c := &t.counters

	stats.RawForks, stats.RawExecs, stats.RawExits = c.rawForks.Load(), c.rawExecs.Load(), c.rawExits.Load()
	stats.Starts, stats.Execs, stats.Exits = c.starts.Load(), c.execs.Load(), c.exits.Load()
	stats.StartsAtExec, stats.StartsAtFork = c.startsAtExec.Load(), c.startsAtFork.Load()
	stats.Partial, stats.ArgsTruncated = c.partial.Load(), c.argsTruncated.Load()
	stats.TrackedCapHits = c.trackedCapHits.Load()
	stats.UntrackedExecs, stats.UntrackedExits = c.untrackedExecs.Load(), c.untrackedExits.Load()
	stats.PIDReuses, stats.DuplicateForks = c.pidReuses.Load(), c.duplicateForks.Load()
	stats.ReconciledStarts, stats.ReconciledExits = c.reconciledStarts.Load(), c.reconciledExit.Load()
	stats.Tracked, stats.Pending = int(c.tracked.Load()), int(c.pending.Load())
}

// imageName is the process name the polling collector would report: the
// kernel's name for the task, which is cut to 15 characters, extended from
// the first argument when that is evidently the same name in full.
func imageName(comm, argv0, exe string) string {
	if comm == "" {
		if exe != "" {
			return filepath.Base(exe)
		}
		return ""
	}

	if len(comm) >= 15 && argv0 != "" {
		if extended := filepath.Base(argv0); strings.HasPrefix(extended, comm) {
			return extended
		}
	}

	return comm
}

// startKnown reports whether t is a real start time. Collectors that could
// not determine one leave it zero, or at the Unix epoch.
func startKnown(t time.Time) bool {
	return !t.IsZero() && t.UnixMilli() != 0
}

// sameStart reports whether two start times are known to be the same.
func sameStart(a, b time.Time) bool {
	return startKnown(a) && startKnown(b) && a.Equal(b)
}

// differentStart reports whether two start times are known to differ. An
// unknown start time is compatible with any other.
func differentStart(a, b time.Time) bool {
	return startKnown(a) && startKnown(b) && !a.Equal(b)
}
