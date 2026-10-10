package resource

import (
	"context"
	"errors"
	"testing"
)

var errDenied = errors.New("operation not permitted")

// fakeProc is a scripted procHandle. A nil error field means the call works.
type fakeProc struct {
	id        int32
	startMs   int64
	startErr  error
	procName  string
	nameErr   error
	exePath   string
	exeErr    error
	cpu       float64
	cpuErr    error
	rss, vms  uint64
	memErr    error
	aliveness bool
	aliveAsks int
}

func (f *fakeProc) pid() int32 { return f.id }
func (f *fakeProc) createTimeMs(context.Context) (int64, error) {
	return f.startMs, f.startErr
}
func (f *fakeProc) name(context.Context) (string, error)        { return f.procName, f.nameErr }
func (f *fakeProc) exe(context.Context) (string, error)         { return f.exePath, f.exeErr }
func (f *fakeProc) cpuSeconds(context.Context) (float64, error) { return f.cpu, f.cpuErr }
func (f *fakeProc) memory(context.Context) (uint64, uint64, error) {
	return f.rss, f.vms, f.memErr
}

func (f *fakeProc) alive(context.Context, int32) bool {
	f.aliveAsks++
	return f.aliveness
}

func sample(f *fakeProc, zeroMeansDenied bool) (procSample, bool) {
	return sampleProcess(context.Background(), f, f.alive, zeroMeansDenied)
}

func TestSampleProcessReadable(t *testing.T) {
	f := &fakeProc{id: 10, startMs: 1234, procName: "nginx", cpu: 2.5, rss: 4096, vms: 8192}

	got, ok := sample(f, true)
	want := procSample{pid: 10, startMs: 1234, name: "nginx", cpuSeconds: 2.5, cpuOK: true, rss: 4096, memOK: true}
	if !ok || got != want {
		t.Errorf("sample = %+v, %v; want %+v, true", got, ok, want)
	}
	if f.aliveAsks != 0 {
		t.Errorf("healthy process triggered %d liveness checks, want 0", f.aliveAsks)
	}
}

// Regression: on macOS the name lookup also reads the command line, which is
// denied for other users' processes. That must not make the process vanish.
func TestSampleProcessKeepsLiveProcessWhenNameUnreadable(t *testing.T) {
	f := &fakeProc{
		id: 390, startMs: 99,
		nameErr: errors.New("invalid argument"),
		exePath: "/usr/libexec/diskarbitrationd",
		cpu:     1, rss: 100, vms: 200,
		aliveness: true,
	}

	got, ok := sample(f, true)
	if !ok {
		t.Fatal("live process with an unreadable name was dropped")
	}
	if got.name != "diskarbitrationd" {
		t.Errorf("name = %q, want the executable's base name", got.name)
	}
	if got.startMs != 99 || !got.cpuOK || !got.memOK {
		t.Errorf("readable fields were lost: %+v", got)
	}

	// Nothing at all readable, but the PID still exists: keep it, nameless.
	f = &fakeProc{id: 4, nameErr: errDenied, exeErr: errDenied, startErr: errDenied, cpuErr: errDenied, memErr: errDenied, aliveness: true}
	got, ok = sample(f, false)
	if !ok {
		t.Fatal("live but fully unreadable process was dropped")
	}
	if got != (procSample{pid: 4}) {
		t.Errorf("sample = %+v, want only the PID", got)
	}
}

func TestSampleProcessDropsExitedProcess(t *testing.T) {
	gone := errors.New("no such process")

	// Every lookup fails and the PID no longer exists.
	f := &fakeProc{id: 77, nameErr: gone, exeErr: gone, startErr: gone, cpuErr: gone, memErr: gone}
	if _, ok := sample(f, false); ok {
		t.Error("exited process was kept")
	}

	// Exits after its name was read: macOS then returns zeros, not errors.
	f = &fakeProc{id: 78, startMs: 5, procName: "short-lived"}
	if _, ok := sample(f, true); ok {
		t.Error("process that exited mid-read was kept")
	}
	if f.aliveAsks != 1 {
		t.Errorf("liveness checked %d times, want 1", f.aliveAsks)
	}
}

func TestSampleProcessZeroReadings(t *testing.T) {
	// macOS: proc_pidinfo was refused, gopsutil reports zeros and no error.
	f := &fakeProc{id: 1, startMs: 5, procName: "launchd", aliveness: true}
	got, ok := sample(f, true)
	if !ok {
		t.Fatal("unreadable live process was dropped")
	}
	if got.cpuOK || got.memOK {
		t.Errorf("all-zero macOS reading treated as measured: %+v", got)
	}

	// Elsewhere zeros are genuine (e.g. an idle Linux kernel thread).
	f = &fakeProc{id: 2, startMs: 5, procName: "kthreadd", aliveness: true}
	got, _ = sample(f, false)
	if !got.cpuOK || !got.memOK {
		t.Errorf("genuine zero reading treated as unavailable: %+v", got)
	}

	// A process that simply has not used any CPU yet still has memory.
	f = &fakeProc{id: 3, procName: "fresh", rss: 4096, vms: 8192}
	got, _ = sample(f, true)
	if !got.cpuOK || !got.memOK || got.cpuSeconds != 0 {
		t.Errorf("idle process with memory treated as unavailable: %+v", got)
	}
}

func TestSampleProcessPartialFailures(t *testing.T) {
	f := &fakeProc{id: 9, procName: "p", cpuErr: errDenied, cpu: 99, rss: 10, vms: 20, startErr: errDenied, startMs: 123}
	got, ok := sample(f, false)
	if !ok {
		t.Fatal("process dropped")
	}
	if got.cpuOK || got.cpuSeconds != 0 {
		t.Errorf("failed CPU read leaked a value: %+v", got)
	}
	if !got.memOK || got.rss != 10 {
		t.Errorf("memory should still be reported: %+v", got)
	}
	if got.startMs != 0 {
		t.Errorf("failed start-time read leaked a value: %+v", got)
	}

	f = &fakeProc{id: 9, procName: "p", cpu: 1, memErr: errDenied, rss: 55}
	got, _ = sample(f, false)
	if !got.cpuOK || got.memOK || got.rss != 0 {
		t.Errorf("memory-only failure: %+v", got)
	}
}
