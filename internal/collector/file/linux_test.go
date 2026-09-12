//go:build linux

package file

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/arafat2020/sentinel/internal/core"
)

// fakeBackend feeds synthetic linuxFileEvents via a channel, letting tests
// drive the collector without a real fanotify kernel subsystem.
type fakeBackend struct {
	events  chan linuxFileEvent
	started bool
	closed  bool
}

func newFakeBackend() *fakeBackend {
	return &fakeBackend{
		events: make(chan linuxFileEvent, 16),
	}
}

func (f *fakeBackend) start(enqueue func(linuxFileEvent)) error {
	f.started = true

	go func() {
		for event := range f.events {
			enqueue(event)
		}
	}()

	return nil
}

func (f *fakeBackend) close() {
	f.closed = true
	close(f.events)
}

// failingBackend always returns an error from start, simulating fanotify
// unavailability (e.g. missing capability or kernel too old).
type failingBackend struct{}

func (f *failingBackend) start(_ func(linuxFileEvent)) error {
	return errors.New("fanotify not available")
}

func (f *failingBackend) close() {}

// fakeLinuxProcessResolver is an injectable stub for processResolver.
type fakeLinuxProcessResolver struct {
	process *core.Process
	err     error
	lastPID int32
}

func (f *fakeLinuxProcessResolver) Resolve(
	ctx context.Context,
	pid int32,
) (*core.Process, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	f.lastPID = pid

	if f.err != nil {
		return nil, f.err
	}

	return f.process, nil
}

func TestLinuxCollectorNilHandler(t *testing.T) {
	c := newLinuxCollectorWithBackend(newFakeBackend(), nil)
	defer c.Close()

	err := c.Run(context.Background(), nil)

	if err == nil {
		t.Fatal("expected error for nil handler, got nil")
	}
}

func TestLinuxCollectorContextCancellation(t *testing.T) {
	c := newLinuxCollectorWithBackend(newFakeBackend(), nil)
	defer c.Close()

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)

	go func() {
		done <- c.Run(ctx, func(_ core.FileEvent) {})
	}()

	cancel()

	select {
	case err := <-done:
		if err != context.Canceled {
			t.Fatalf("Run() error = %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Run() did not stop after context cancellation")
	}
}

func TestLinuxCollectorAlreadyClosed(t *testing.T) {
	c := newLinuxCollectorWithBackend(newFakeBackend(), nil)
	c.Close()

	err := c.Run(context.Background(), func(_ core.FileEvent) {})

	if err == nil {
		t.Fatal("expected error for closed collector, got nil")
	}
}

func TestLinuxCollectorBackendStartError(t *testing.T) {
	c := newLinuxCollectorWithBackend(&failingBackend{}, nil)
	defer c.Close()

	err := c.Run(context.Background(), func(_ core.FileEvent) {})

	if err == nil {
		t.Fatal("expected error when backend fails to start, got nil")
	}
}

func TestLinuxCollectorDispatchesEvents(t *testing.T) {
	backend := newFakeBackend()
	c := newLinuxCollectorWithBackend(backend, nil)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	defer c.Close()

	received := make(chan core.FileEvent, 1)
	done := make(chan error, 1)

	go func() {
		done <- c.Run(ctx, func(e core.FileEvent) {
			received <- e
		})
	}()

	waitForBackendStart(t, backend)

	backend.events <- linuxFileEvent{
		Mask: maskCloseWrite,
		PID:  4242,
		Path: "/tmp/sentinel_test.txt",
	}

	select {
	case event := <-received:
		if event.Operation != core.FileModify {
			t.Fatalf("Operation = %q, want FileModify", event.Operation)
		}
		if event.PID != 4242 {
			t.Fatalf("PID = %d, want 4242", event.PID)
		}
		if event.Path != "/tmp/sentinel_test.txt" {
			t.Fatalf("Path = %q, want /tmp/sentinel_test.txt", event.Path)
		}
	case <-time.After(time.Second):
		t.Fatal("event was not delivered to handler")
	}

	cancel()

	select {
	case err := <-done:
		if err != context.Canceled {
			t.Fatalf("Run() error = %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Run() did not stop after context cancellation")
	}
}

func TestLinuxCollectorProcessAttribution(t *testing.T) {
	backend := newFakeBackend()

	resolver := &fakeLinuxProcessResolver{
		process: &core.Process{
			PID:        4242,
			PPID:       1,
			Name:       "vim",
			Executable: "/usr/bin/vim",
		},
	}

	c := newLinuxCollectorWithBackend(backend, resolver)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	defer c.Close()

	received := make(chan core.FileEvent, 1)

	go func() {
		c.Run(ctx, func(e core.FileEvent) { //nolint:errcheck
			received <- e
		})
	}()

	waitForBackendStart(t, backend)

	backend.events <- linuxFileEvent{
		Mask: maskCreate,
		PID:  4242,
		Path: "/home/user/document.txt",
	}

	select {
	case event := <-received:
		if event.PPID != 1 {
			t.Fatalf("PPID = %d, want 1", event.PPID)
		}
		if event.Process == nil {
			t.Fatal("expected Process to be populated")
		}
		if event.Process.Name != "vim" {
			t.Fatalf("Process.Name = %q, want vim", event.Process.Name)
		}
		if resolver.lastPID != 4242 {
			t.Fatalf("resolver called with PID %d, want 4242", resolver.lastPID)
		}
	case <-time.After(time.Second):
		t.Fatal("event was not delivered")
	}
}

func TestLinuxCollectorAttributionErrorIsNonFatal(t *testing.T) {
	backend := newFakeBackend()

	resolver := &fakeLinuxProcessResolver{
		err: errors.New("process not found"),
	}

	c := newLinuxCollectorWithBackend(backend, resolver)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	defer c.Close()

	received := make(chan core.FileEvent, 1)

	go func() {
		c.Run(ctx, func(e core.FileEvent) { //nolint:errcheck
			received <- e
		})
	}()

	waitForBackendStart(t, backend)

	backend.events <- linuxFileEvent{
		Mask: maskDelete,
		PID:  99,
		Path: "/var/log/app.log",
	}

	select {
	case event := <-received:
		if event.Operation != core.FileDelete {
			t.Fatalf("Operation = %q, want FileDelete", event.Operation)
		}
		if event.Process != nil {
			t.Fatal("expected Process to be nil when resolver fails")
		}
	case <-time.After(time.Second):
		t.Fatal("event was not delivered despite resolver error")
	}
}

func TestLinuxCollectorNilResolver(t *testing.T) {
	backend := newFakeBackend()
	c := newLinuxCollectorWithBackend(backend, nil)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	defer c.Close()

	received := make(chan core.FileEvent, 1)

	go func() {
		c.Run(ctx, func(e core.FileEvent) { //nolint:errcheck
			received <- e
		})
	}()

	waitForBackendStart(t, backend)

	backend.events <- linuxFileEvent{
		Mask: maskMovedFrom,
		PID:  7,
		Path: "/tmp/old_name.txt",
	}

	select {
	case event := <-received:
		if event.Operation != core.FileRename {
			t.Fatalf("Operation = %q, want FileRename", event.Operation)
		}
		if event.Process != nil {
			t.Fatal("expected Process to be nil with no resolver")
		}
	case <-time.After(time.Second):
		t.Fatal("event was not delivered")
	}
}

func TestLinuxCollectorDoubleCloseIsIdempotent(t *testing.T) {
	c := newLinuxCollectorWithBackend(newFakeBackend(), nil)
	c.Close()
	c.Close() // must not panic or deadlock
}

func TestConvertLinuxEventOperations(t *testing.T) {
	tests := []struct {
		mask uint64
		want core.FileOperation
	}{
		{maskCloseWrite, core.FileModify},
		{maskCreate, core.FileCreate},
		{maskDelete, core.FileDelete},
		{maskMovedFrom, core.FileRename},
		{maskMovedTo, core.FileRename},
	}

	for _, tt := range tests {
		event := linuxFileEvent{Mask: tt.mask, PID: 1, Path: "/some/path"}

		fe, ok := convertLinuxEvent(event, time.Now())

		if !ok {
			t.Fatalf("convertLinuxEvent(mask=%#x) returned ok=false", tt.mask)
		}

		if fe.Operation != tt.want {
			t.Fatalf(
				"mask %#x: Operation = %q, want %q",
				tt.mask, fe.Operation, tt.want,
			)
		}
	}
}

func TestConvertLinuxEventUnknownMask(t *testing.T) {
	event := linuxFileEvent{Mask: 0xDEADBEEF, PID: 1, Path: "/some/path"}

	_, ok := convertLinuxEvent(event, time.Now())

	if ok {
		t.Fatal("expected ok=false for unknown mask")
	}
}

func TestConvertLinuxEventFields(t *testing.T) {
	ts := time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC)

	event := linuxFileEvent{
		Mask: maskCreate,
		PID:  999,
		Path: "/etc/sentinel/config.yaml",
	}

	fe, ok := convertLinuxEvent(event, ts)

	if !ok {
		t.Fatal("expected ok=true")
	}

	if !fe.Timestamp.Equal(ts) {
		t.Fatalf("Timestamp = %v, want %v", fe.Timestamp, ts)
	}

	if fe.PID != 999 {
		t.Fatalf("PID = %d, want 999", fe.PID)
	}

	if fe.Path != "/etc/sentinel/config.yaml" {
		t.Fatalf("Path = %q, want /etc/sentinel/config.yaml", fe.Path)
	}
}

func TestCString(t *testing.T) {
	tests := []struct {
		input []byte
		want  string
	}{
		{[]byte("hello\x00world"), "hello"},
		{[]byte("no-null"), "no-null"},
		{[]byte("\x00"), ""},
		{[]byte{}, ""},
	}

	for _, tt := range tests {
		got := cString(tt.input)
		if got != tt.want {
			t.Fatalf("cString(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

// waitForBackendStart polls until the fake backend's start method has been
// called, ensuring the goroutine that forwards events is running.
func waitForBackendStart(t *testing.T, backend *fakeBackend) {
	t.Helper()

	deadline := time.After(time.Second)
	for !backend.started {
		select {
		case <-deadline:
			t.Fatal("backend did not start within 1s")
		default:
			time.Sleep(time.Millisecond)
		}
	}
}
