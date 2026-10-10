package main

import (
	"context"
	"flag"
	"fmt"
	"sync"
	"time"

	processCollector "github.com/arafat2020/sentinel/internal/collector/process"
	"github.com/arafat2020/sentinel/internal/collector/process/procevents"
	"github.com/arafat2020/sentinel/internal/core"
	"github.com/arafat2020/sentinel/internal/detection/correlation"
	processDetector "github.com/arafat2020/sentinel/internal/detection/process"
	"github.com/arafat2020/sentinel/internal/eventbus"
	"github.com/arafat2020/sentinel/internal/monitor"
)

// processPollInterval is how often the poll backend compares snapshots.
const processPollInterval = 2 * time.Second

// collectorFlags are the command-line options that choose and tune process
// collection. They apply to the TUI, the desktop UI and headless mode alike.
type collectorFlags struct {
	backend   *string
	grace     *time.Duration
	ringBytes *int
}

func registerCollectorFlags() collectorFlags {
	return collectorFlags{
		backend: flag.String("process-collector", string(procevents.BackendAuto),
			"how process events are collected: auto|ebpf|proc-connector|poll (auto tries ebpf, then proc-connector, then poll)"),
		grace: flag.Duration("process-exec-grace", procevents.DefaultGrace,
			"how long after a fork an exec still counts as the process starting (event-driven collectors)"),
		ringBytes: flag.Int("process-ringbuf-bytes", procevents.DefaultRingBufferBytes,
			"size of the eBPF ring buffer for process events, rounded up to a power of two"),
	}
}

// processCollection is how process events are collected in this run.
type processCollection struct {
	requested procevents.Backend
	skipped   []procevents.Skip
	collector *processCollector.Collector

	mu sync.Mutex
	// source is nil when polling.
	source procevents.Source
	// failure is why an event-driven backend that was running gave up.
	failure string
}

// openProcessCollection starts the backend the flags ask for. It is called
// before anything else is collected, so that no process is missed between
// the startup snapshot and the first event.
//
// A backend asked for by name that cannot be started is an error. With auto,
// whatever does not work is skipped and the reasons are kept.
func openProcessCollection(flags collectorFlags, collector *processCollector.Collector) (*processCollection, error) {
	requested, err := procevents.ParseBackend(*flags.backend)
	if err != nil {
		return nil, err
	}

	source, skipped, err := procevents.Open(requested, procevents.Options{
		Grace:           *flags.grace,
		RingBufferBytes: *flags.ringBytes,
		Snapshot: func(ctx context.Context) ([]core.Process, error) {
			snapshot, err := collector.Collect(ctx)
			if err != nil {
				return nil, err
			}
			return snapshot.Processes, nil
		},
	})
	if err != nil {
		return nil, err
	}

	return &processCollection{requested: requested, skipped: skipped, collector: collector, source: source}, nil
}

// Active is the backend in use now.
func (p *processCollection) Active() procevents.Backend {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.source == nil {
		return procevents.BackendPoll
	}
	return p.source.Backend()
}

// Stats returns the collector's counters. Polling has none.
func (p *processCollection) Stats() procevents.Stats {
	p.mu.Lock()
	source := p.source
	p.mu.Unlock()

	if source == nil {
		return procevents.Stats{Backend: procevents.BackendPoll}
	}
	return source.Stats()
}

// Describe says which backend is active and why any other was passed over,
// one line each, for startup logs.
func (p *processCollection) Describe() []string {
	p.mu.Lock()
	failure := p.failure
	p.mu.Unlock()

	lines := []string{fmt.Sprintf("process collector: %s (requested: %s)", p.Active(), p.requested)}
	for _, skip := range p.skipped {
		lines = append(lines, fmt.Sprintf("process collector: skipped %s", skip))
	}
	if failure != "" {
		lines = append(lines, "process collector: "+failure)
	}
	return lines
}

// Start seeds the detectors with the processes already running and begins
// delivering process events to the bus. report is told if an event-driven
// backend fails later; collection then continues by polling.
func (p *processCollection) Start(
	ctx context.Context,
	bus *eventbus.Bus,
	detector *processDetector.LifecycleDetector,
	coordinator *processDetector.Coordinator,
	engine *correlation.Engine,
	report func(string),
) {
	// Tell the correlation engine about processes that are already running,
	// so they can be recognised as parents of what they spawn from now on.
	var running []core.Process
	if snapshot, err := p.collector.Collect(ctx); err == nil {
		running = snapshot.Processes
		engine.Seed(running)
	}

	poll := func() {
		monitor.NewProcessMonitor(p.collector, detector, processPollInterval, bus, coordinator).Run(ctx)
	}

	p.mu.Lock()
	source := p.source
	p.mu.Unlock()

	if source == nil {
		go poll()
		return
	}

	// There are no snapshots from here on; the legacy process rules follow
	// the events instead.
	coordinator.Track(running)

	go func() {
		err := monitor.NewProcessEventMonitor(source, bus).Run(ctx, running)
		source.Close()

		if err == nil || ctx.Err() != nil {
			return
		}

		message := fmt.Sprintf("%v; falling back to poll", err)
		p.mu.Lock()
		p.source = nil
		p.failure = message
		p.mu.Unlock()

		if report != nil {
			report("process collector: " + message)
		}
		poll()
	}()
}
