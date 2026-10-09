package monitor

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/arafat2020/sentinel/internal/core"
)

// scriptedResourceCollector fails on the calls listed in failOn (1-based).
type scriptedResourceCollector struct {
	mu     sync.Mutex
	calls  int
	failOn map[int]bool
}

func (c *scriptedResourceCollector) Collect(
	ctx context.Context,
) (*core.ResourceSnapshot, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.calls++
	if c.failOn[c.calls] {
		return nil, errors.New("collect failed")
	}

	return &core.ResourceSnapshot{
		Processes: []core.ProcessUsage{{PID: int32(c.calls)}},
	}, nil
}

func TestResourceMonitorDeliversSnapshots(t *testing.T) {
	collector := &scriptedResourceCollector{}
	received := make(chan *core.ResourceSnapshot, 8)

	m := NewResourceMonitor(collector, 5*time.Millisecond, func(s *core.ResourceSnapshot) {
		received <- s
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go m.Run(ctx)

	for want := int32(1); want <= 2; want++ {
		select {
		case s := <-received:
			if got := s.Processes[0].PID; got != want {
				t.Fatalf("snapshot %d arrived out of order (got %d)", want, got)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("timed out waiting for snapshot %d", want)
		}
	}
}

func TestResourceMonitorSkipsFailedCollections(t *testing.T) {
	collector := &scriptedResourceCollector{failOn: map[int]bool{1: true, 2: true}}
	received := make(chan *core.ResourceSnapshot, 8)

	m := NewResourceMonitor(collector, 5*time.Millisecond, func(s *core.ResourceSnapshot) {
		received <- s
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go m.Run(ctx)

	select {
	case s := <-received:
		if got := s.Processes[0].PID; got != 3 {
			t.Fatalf("first delivered snapshot came from call %d, want 3", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("monitor did not recover after collection errors")
	}
}

func TestResourceMonitorStopsOnCancel(t *testing.T) {
	m := NewResourceMonitor(&scriptedResourceCollector{}, time.Millisecond, func(*core.ResourceSnapshot) {})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		m.Run(ctx)
		close(done)
	}()

	cancel()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after cancellation")
	}
}
