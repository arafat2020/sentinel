package procevents

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/arafat2020/sentinel/internal/core"
)

var t0 = time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

func ms(n int) time.Time { return t0.Add(time.Duration(n) * time.Millisecond) }

// recorder collects what a tracker emits.
type recorder struct {
	*Tracker
	events []core.Event
}

func newRecorder(maxTracked int) *recorder {
	r := &recorder{}
	r.Tracker = NewTracker(50*time.Millisecond, maxTracked, func(event core.Event) {
		r.events = append(r.events, event)
	})
	return r
}

// log renders the emitted events compactly: TYPE pid name @ms.
func (r *recorder) log() string {
	lines := make([]string, len(r.events))
	for i, event := range r.events {
		lines[i] = fmt.Sprintf("%s %d %s @%d",
			strings.TrimPrefix(string(event.Type), "PROCESS_"), event.Process.PID, event.Process.Name,
			event.Timestamp.Sub(t0).Milliseconds())
	}
	return strings.Join(lines, " | ")
}

func (r *recorder) expect(t *testing.T, want string) {
	t.Helper()
	if got := r.log(); got != want {
		t.Fatalf("events:\n got %s\nwant %s", got, want)
	}
}

// started is when the test's processes started, by PID, so identities are
// distinct and stable.
func started(pid int32) time.Time { return t0.Add(-time.Hour).Add(time.Duration(pid) * time.Second) }

func fork(pid, ppid int32, at time.Time) raw {
	return raw{kind: rawFork, pid: pid, ppid: ppid, start: started(pid), at: at, comm: "forked"}
}

func exec(pid int32, name string, at time.Time) raw {
	return raw{
		kind: rawExec, pid: pid, start: started(pid), at: at,
		comm: name, exe: "/usr/bin/" + name, cmdline: name + " --flag", argv0: name,
	}
}

func exit(pid int32, at time.Time) raw {
	return raw{kind: rawExit, pid: pid, start: started(pid), at: at}
}

func shell() core.Process {
	return core.Process{PID: 100, PPID: 1, StartTime: started(100), Name: "bash", Executable: "/bin/bash", CommandLine: "bash -l", User: "alice"}
}

func seeded(maxTracked int) *recorder {
	r := newRecorder(maxTracked)
	r.Seed([]core.Process{shell()})
	return r
}

// The usual case: a shell forks and the child execs the command at once. One
// PROCESS_START, describing the command, at the time of the exec.
func TestExecWithinGraceIsTheStart(t *testing.T) {
	r := seeded(0)

	r.handle(fork(200, 100, ms(0)))
	if len(r.events) != 0 {
		t.Fatalf("a start was emitted at the fork, before the grace period: %s", r.log())
	}

	r.handle(exec(200, "curl", ms(3)))
	r.expect(t, "START 200 curl @3")

	start := r.events[0]
	want := core.Process{PID: 200, PPID: 100, StartTime: started(200), Name: "curl", Executable: "/usr/bin/curl", CommandLine: "curl --flag", User: "alice"}
	if *start.Process != want {
		t.Errorf("start describes %+v\nwant %+v", *start.Process, want)
	}
	if start.Metadata != nil {
		t.Errorf("a complete event has metadata: %v", start.Metadata)
	}

	// Time passing must not announce it a second time.
	r.Advance(ms(500))
	r.handle(exit(200, ms(600)))
	r.expect(t, "START 200 curl @3 | EXIT 200 curl @600")

	stats := Stats{}
	r.fill(&stats)
	if stats.StartsAtExec != 1 || stats.StartsAtFork != 0 || stats.Starts != 1 || stats.Exits != 1 || stats.Execs != 0 {
		t.Errorf("stats = %+v", stats)
	}
	if stats.Tracked != 1 || stats.Pending != 0 {
		t.Errorf("tracked %d pending %d, want only the shell tracked", stats.Tracked, stats.Pending)
	}
}

// The grace period is inclusive and measured on the events' own times.
func TestGraceBoundary(t *testing.T) {
	r := seeded(0)

	r.handle(fork(200, 100, ms(0)))
	r.handle(exec(200, "curl", ms(50)))
	r.expect(t, "START 200 curl @50")

	r = seeded(0)
	r.handle(fork(200, 100, ms(0)))
	r.handle(exec(200, "curl", ms(51)))
	r.expect(t, "START 200 bash @0 | EXEC 200 curl @51")
}

// A slow reader sees the fork and the exec late, but together. The kernel
// said they were 2 ms apart, so it is still one start.
func TestGraceIsNotMeasuredByArrivalTime(t *testing.T) {
	r := seeded(0)

	// Other activity, read much later than it happened, moves stream time
	// only as far as its own timestamps.
	r.handle(fork(200, 100, ms(0)))
	r.handle(fork(300, 100, ms(1)))
	r.handle(exec(200, "curl", ms(2)))
	r.handle(exec(300, "wget", ms(40)))

	r.expect(t, "START 200 curl @2 | START 300 wget @40")
}

// A process that forks and never execs is announced when the grace period
// ends, as a copy of its parent, at the time it was forked.
func TestForkWithoutExec(t *testing.T) {
	r := seeded(0)

	r.handle(fork(200, 100, ms(10)))
	r.Advance(ms(60))
	if len(r.events) != 0 {
		t.Fatalf("emitted at exactly the end of the grace period: %s", r.log())
	}

	r.Advance(ms(61))
	r.expect(t, "START 200 bash @10")

	want := core.Process{PID: 200, PPID: 100, StartTime: started(200), Name: "bash", Executable: "/bin/bash", CommandLine: "bash -l", User: "alice"}
	if got := *r.events[0].Process; got != want {
		t.Errorf("start describes %+v\nwant the parent's image: %+v", got, want)
	}

	// A later exec is then a change of image, not a second start.
	r.handle(exec(200, "python3", ms(900)))
	r.expect(t, "START 200 bash @10 | EXEC 200 python3 @900")
	if got := *r.events[1].Process; got.Identity() != want.Identity() || got.Executable != "/usr/bin/python3" || got.PPID != 100 {
		t.Errorf("exec describes %+v", got)
	}
}

// An event for any process ends every grace period that ran out before it.
func TestLaterEventsSettleEarlierForks(t *testing.T) {
	r := seeded(0)

	r.handle(fork(200, 100, ms(0)))
	r.handle(fork(300, 100, ms(20)))
	r.handle(fork(400, 100, ms(60)))

	// 200's grace ended at 50; 300's has not.
	r.expect(t, "START 200 bash @0")

	r.handle(exec(300, "ls", ms(65)))
	r.expect(t, "START 200 bash @0 | START 300 ls @65")
}

func TestExecChain(t *testing.T) {
	r := seeded(0)

	r.handle(fork(200, 100, ms(0)))
	r.handle(exec(200, "env", ms(1)))
	r.handle(exec(200, "nice", ms(2)))
	r.handle(exec(200, "sleep", ms(3)))
	r.handle(exit(200, ms(4)))

	// The first exec is the start; the others each replace the image, even
	// though they too are within the grace period.
	r.expect(t, "START 200 env @1 | EXEC 200 nice @2 | EXEC 200 sleep @3 | EXIT 200 sleep @4")

	for _, event := range r.events {
		if event.Process.Identity() != (core.ProcessIdentity{PID: 200, StartTime: started(200)}) {
			t.Errorf("%s has identity %+v", event.Type, event.Process.Identity())
		}
	}
	if r.events[3].Process.Executable != "/usr/bin/sleep" {
		t.Errorf("exit describes %+v, want the last image", *r.events[3].Process)
	}
}

// A fork that exits inside the grace period with no exec is still a process
// that ran.
func TestExitBeforeExec(t *testing.T) {
	r := seeded(0)

	r.handle(fork(200, 100, ms(0)))
	r.handle(exit(200, ms(2)))

	r.expect(t, "START 200 bash @0 | EXIT 200 bash @2")

	r.Advance(ms(1000))
	r.expect(t, "START 200 bash @0 | EXIT 200 bash @2")

	stats := Stats{}
	r.fill(&stats)
	if stats.StartsAtFork != 1 || stats.Pending != 0 || stats.Tracked != 1 {
		t.Errorf("stats = %+v", stats)
	}
}

// A new process on a tracked PID means the old one exited unnoticed. It is
// closed first, and the newcomer gets its own identity.
func TestPIDReuseAcrossForks(t *testing.T) {
	r := seeded(0)

	r.handle(fork(200, 100, ms(0)))
	r.handle(exec(200, "old", ms(1)))

	// The exit of 200 is lost; the PID comes round again.
	reused := fork(200, 100, ms(500))
	reused.start = started(200).Add(time.Minute)
	r.handle(reused)

	again := exec(200, "new", ms(501))
	again.start = reused.start
	r.handle(again)

	r.expect(t, "START 200 old @1 | EXIT 200 old @500 | START 200 new @501")

	if r.events[1].Metadata[MetaInferred] != true {
		t.Errorf("the deduced exit is not marked: %v", r.events[1].Metadata)
	}
	if a, b := r.events[0].Process.Identity(), r.events[2].Process.Identity(); a == b {
		t.Errorf("both holders of the PID have identity %+v", a)
	}
	if r.events[1].Process.Identity() != r.events[0].Process.Identity() {
		t.Error("the deduced exit names the wrong process")
	}

	// The same, with the old holder still in its grace period: it gets its
	// start and its exit before the new one.
	r = seeded(0)
	r.handle(fork(200, 100, ms(0)))
	reused = fork(200, 100, ms(10))
	reused.start = started(200).Add(time.Minute)
	r.handle(reused)
	r.Advance(ms(100))
	r.expect(t, "START 200 bash @0 | EXIT 200 bash @10 | START 200 bash @10")

	stats := Stats{}
	r.fill(&stats)
	if stats.PIDReuses != 1 {
		t.Errorf("PIDReuses = %d", stats.PIDReuses)
	}
}

// An exec whose start time differs from the tracked holder's is a different
// process too.
func TestPIDReuseSeenAtExec(t *testing.T) {
	r := seeded(0)
	r.handle(fork(200, 100, ms(0)))
	r.handle(exec(200, "old", ms(1)))

	later := exec(200, "new", ms(300))
	later.start = started(200).Add(time.Minute)
	later.ppid = 100
	r.handle(later)

	r.expect(t, "START 200 old @1 | EXIT 200 old @300 | START 200 new @300")
	if got := r.events[2].Process; got.StartTime != later.start || got.PPID != 100 {
		t.Errorf("new holder described as %+v", *got)
	}
}

// A child is never announced before its parent.
func TestParentStartsBeforeChild(t *testing.T) {
	r := seeded(0)

	r.handle(fork(200, 100, ms(0)))
	r.handle(fork(300, 200, ms(1))) // 200 forks while still in its grace period
	r.handle(exec(300, "worker", ms(2)))

	r.expect(t, "START 200 bash @0 | START 300 worker @2")
	if r.events[1].Process.PPID != 200 {
		t.Errorf("child's parent is %d", r.events[1].Process.PPID)
	}
}

func TestProcessWithUnknownParent(t *testing.T) {
	r := newRecorder(0)

	r.handle(fork(200, 999, ms(0)))
	r.Advance(ms(100))
	r.expect(t, "START 200 forked @0")

	// Only the kernel's short name is known, and the event says so.
	if r.events[0].Metadata[MetaPartial] != true || r.events[0].Process.Executable != "" {
		t.Errorf("event = %+v metadata %v", *r.events[0].Process, r.events[0].Metadata)
	}

	// Its exec then describes it completely.
	r.handle(exec(200, "tool", ms(200)))
	if r.events[1].Metadata != nil || r.events[1].Process.Executable != "/usr/bin/tool" {
		t.Errorf("exec = %+v metadata %v", *r.events[1].Process, r.events[1].Metadata)
	}
}

// A fork that was not seen (events lost, or the process predates the seed)
// still yields a start when the process execs.
func TestExecWithoutFork(t *testing.T) {
	r := seeded(0)

	missed := exec(200, "tool", ms(5))
	missed.ppid = 100
	missed.user = "bob"
	r.handle(missed)
	r.handle(exit(200, ms(6)))

	r.expect(t, "START 200 tool @5 | EXIT 200 tool @6")
	if got := r.events[0].Process; got.PPID != 100 || got.User != "bob" || got.StartTime != started(200) {
		t.Errorf("start describes %+v", *got)
	}

	// An exit for something never reported is not an event.
	r.handle(exit(999, ms(7)))
	r.expect(t, "START 200 tool @5 | EXIT 200 tool @6")

	stats := Stats{}
	r.fill(&stats)
	if stats.UntrackedExecs != 1 || stats.UntrackedExits != 1 {
		t.Errorf("stats = %+v", stats)
	}
}

// A process created while the startup snapshot was being taken is in the
// snapshot and also has a fork event. It is one process.
func TestForkOfSeededProcessIsIgnored(t *testing.T) {
	r := seeded(0)

	duplicate := fork(100, 1, ms(0))
	r.handle(duplicate)
	r.Advance(ms(200))
	if len(r.events) != 0 {
		t.Fatalf("a seeded process was announced again: %s", r.log())
	}

	r.handle(exit(100, ms(300)))
	r.expect(t, "EXIT 100 bash @300")
}

// A set-user-ID program runs as someone else.
func TestExecChangesUser(t *testing.T) {
	r := seeded(0)
	r.handle(fork(200, 100, ms(0)))

	sudo := exec(200, "sudo", ms(1))
	sudo.user = "root"
	r.handle(sudo)

	if got := r.events[0].Process.User; got != "root" {
		t.Errorf("user = %q, want root", got)
	}
}

func TestPartialAndTruncatedAreMarkedAndCounted(t *testing.T) {
	r := seeded(0)
	r.handle(fork(200, 100, ms(0)))

	// The proc connector's view of a process that had already exited: it
	// exec'd, but nothing about the new image could be read.
	gone := raw{kind: rawExec, pid: 200, start: started(200), at: ms(1), partial: true}
	r.handle(gone)
	r.handle(exit(200, ms(2)))

	r.expect(t, "START 200 bash @1 | EXIT 200 bash @2")
	for _, event := range r.events {
		if event.Metadata[MetaPartial] != true {
			t.Errorf("%s is not marked partial: %v", event.Type, event.Metadata)
		}
	}

	r.handle(fork(300, 100, ms(10)))
	long := exec(300, "java", ms(11))
	long.argsTruncated = true
	r.handle(long)
	if r.events[2].Metadata[MetaCmdlineTruncated] != true {
		t.Errorf("truncated command line is not marked: %v", r.events[2].Metadata)
	}

	stats := Stats{}
	r.fill(&stats)
	if stats.Partial != 2 || stats.ArgsTruncated != 1 {
		t.Errorf("partial %d truncated %d", stats.Partial, stats.ArgsTruncated)
	}
}

// A process whose start time could not be read at its fork takes it from its
// exec, before anything has been emitted under the incomplete identity.
func TestStartTimeLearnedAtExec(t *testing.T) {
	r := seeded(0)

	unknown := fork(200, 100, ms(0))
	unknown.start = time.Time{}
	r.handle(unknown)
	r.handle(exec(200, "curl", ms(1)))

	if got := r.events[0].Process.StartTime; got != started(200) {
		t.Errorf("start time = %v, want the one the exec reported", got)
	}
}

func TestTrackedProcessesAreCapped(t *testing.T) {
	r := seeded(3)

	r.handle(fork(200, 100, ms(0)))
	r.handle(fork(300, 100, ms(1)))
	r.handle(fork(400, 100, ms(2))) // over the cap
	r.handle(exec(500, "x", ms(3))) // over the cap
	r.Advance(ms(200))

	r.expect(t, "START 200 bash @0 | START 300 bash @1")

	stats := Stats{}
	r.fill(&stats)
	if stats.Tracked != 3 || stats.TrackedCapHits != 2 {
		t.Errorf("tracked %d, cap hits %d", stats.Tracked, stats.TrackedCapHits)
	}

	// Room is made by exits.
	r.handle(exit(200, ms(300)))
	r.handle(fork(600, 100, ms(301)))
	r.Advance(ms(500))
	if !strings.HasSuffix(r.log(), "START 600 bash @301") {
		t.Errorf("no room after an exit: %s", r.log())
	}
}

func TestImageName(t *testing.T) {
	cases := []struct{ comm, argv0, exe, want string }{
		{"curl", "curl", "/usr/bin/curl", "curl"},
		{"chrome_crashpad", "/opt/chrome/chrome_crashpad_handler", "", "chrome_crashpad_handler"},
		{"exactly15chars_", "something-else", "", "exactly15chars_"},
		{"sh", "/tmp/x", "/bin/dash", "sh"},
		{"", "", "/usr/bin/tool", "tool"},
		{"", "", "", ""},
	}
	for _, c := range cases {
		if got := imageName(c.comm, c.argv0, c.exe); got != c.want {
			t.Errorf("imageName(%q, %q, %q) = %q, want %q", c.comm, c.argv0, c.exe, got, c.want)
		}
	}
}

func TestReconcileRepairsLostEvents(t *testing.T) {
	r := seeded(0)

	r.handle(fork(200, 100, ms(0)))
	r.handle(exec(200, "lost-exit", ms(1)))
	r.handle(fork(300, 100, ms(2)))
	r.handle(exec(300, "alive", ms(3)))

	takenAt := ms(10_000)
	recent := core.Process{PID: 500, StartTime: takenAt.Add(-time.Second), Name: "just-started"}
	unseen := core.Process{PID: 400, PPID: 1, StartTime: ms(100), Name: "lost-start", Executable: "/usr/bin/lost-start"}
	alive := core.Process{PID: 300, StartTime: started(300), Name: "alive"}

	// Tracked just before the listing: its exit may simply not have been
	// read yet, so it is left alone although the listing lacks it.
	r.handle(fork(700, 100, ms(9_500)))
	r.handle(exec(700, "recent", ms(9_501)))
	before := len(r.events)

	r.Reconcile([]core.Process{shell(), alive, unseen, recent}, takenAt)

	got := (&recorder{events: r.events[before:]}).log()
	want := "EXIT 200 lost-exit @10000 | START 400 lost-start @100"
	if got != want {
		t.Fatalf("reconcile emitted:\n got %s\nwant %s", got, want)
	}
	if r.events[before].Metadata[MetaInferred] != true || r.events[before+1].Metadata[MetaReconciled] != true {
		t.Errorf("reconciled events are not marked: %v %v", r.events[before].Metadata, r.events[before+1].Metadata)
	}

	stats := Stats{}
	r.fill(&stats)
	if stats.ReconciledExits != 1 || stats.ReconciledStarts != 1 {
		t.Errorf("stats = %+v", stats)
	}

	// Agreeing with the table changes nothing.
	before = len(r.events)
	r.Reconcile([]core.Process{shell(), alive, unseen, recent}, takenAt)
	if len(r.events) != before {
		t.Errorf("a second reconcile emitted %d more events", len(r.events)-before)
	}

	// A tracked PID now held by a different process: the old one is gone.
	impostor := alive
	impostor.StartTime = alive.StartTime.Add(time.Hour)
	before = len(r.events)
	r.Reconcile([]core.Process{shell(), impostor, unseen, {PID: 700, StartTime: started(700)}}, ms(60_000))
	if got := (&recorder{events: r.events[before:]}).log(); got != "EXIT 300 alive @60000" {
		t.Errorf("a replaced process was not closed; reconcile emitted: %s", got)
	}
}

func TestParseBackend(t *testing.T) {
	for value, want := range map[string]Backend{
		"": BackendAuto, "auto": BackendAuto, "EBPF": BackendEBPF, " proc-connector ": BackendProcConnector, "poll": BackendPoll,
	} {
		if got, err := ParseBackend(value); err != nil || got != want {
			t.Errorf("ParseBackend(%q) = %q, %v", value, got, err)
		}
	}
	if _, err := ParseBackend("kprobe"); err == nil || !strings.Contains(err.Error(), "auto, ebpf, proc-connector, poll") {
		t.Errorf("an unknown backend gave %v", err)
	}
}
