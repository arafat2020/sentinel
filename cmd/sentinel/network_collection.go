package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"runtime"
	"sync"
	"time"

	gopsprocess "github.com/shirou/gopsutil/v4/process"

	networkcollector "github.com/arafat2020/sentinel/internal/collector/network"
	"github.com/arafat2020/sentinel/internal/collector/network/netevents"
	processCollector "github.com/arafat2020/sentinel/internal/collector/process"
	"github.com/arafat2020/sentinel/internal/core"
	"github.com/arafat2020/sentinel/internal/detection/correlation"
	networkdetector "github.com/arafat2020/sentinel/internal/detection/network"
	"github.com/arafat2020/sentinel/internal/eventbus"
	"github.com/arafat2020/sentinel/internal/monitor"
)

// networkPollInterval is how often the poll backend compares socket tables.
const networkPollInterval = 2 * time.Second

// networkFlags choose and tune network collection.
type networkFlags struct {
	backend   *string
	ringBytes *int
}

func registerNetworkFlags() networkFlags {
	return networkFlags{
		backend: flag.String("network-collector", string(netevents.BackendAuto),
			"how network connections are collected: auto|ebpf|poll (auto uses ebpf where it works, else poll)"),
		ringBytes: flag.Int("network-ringbuf-bytes", netevents.DefaultRingBufferBytes,
			"size of the eBPF ring buffer for network events, rounded up to a power of two"),
	}
}

// networkCollection is how network connections are collected in this run.
type networkCollection struct {
	requested netevents.Backend
	skipped   []netevents.Skip
	// processes describes a process the kernel named: from the process
	// collector while it knows it, from /proc otherwise.
	processes *processCollection

	mu sync.Mutex
	// source is nil when polling.
	source  netevents.Source
	failure string
}

// openNetworkCollection starts the backend the flags ask for. With auto, a
// backend that does not work is skipped and the reason kept; one asked for by
// name that cannot start is an error.
func openNetworkCollection(flags networkFlags, processes *processCollection) (*networkCollection, error) {
	requested, err := netevents.ParseBackend(*flags.backend)
	if err != nil {
		return nil, err
	}

	n := &networkCollection{requested: requested, processes: processes}

	source, skipped, err := netevents.Open(requested, netevents.Options{
		RingBufferBytes: *flags.ringBytes,
		Describe:        n.describe,
	})
	if err != nil {
		return nil, err
	}
	n.source, n.skipped = source, skipped

	return n, nil
}

// describe fills in what the kernel record of a network event does not say
// about its process. The process collector is asked first: it knows a process
// that has already exited. Its answer is used only if it is about the very
// same process, by identity; otherwise /proc is read, and its answer held to
// the same test by the caller.
func (n *networkCollection) describe(ctx context.Context, known core.Process) (core.Process, bool) {
	if n.processes != nil {
		if tracked, ok := n.processes.Lookup(known.PID); ok && tracked.Identity() == known.Identity() && tracked.Executable != "" {
			return tracked, true
		}
	}

	handle, err := gopsprocess.NewProcessWithContext(ctx, known.PID)
	if err != nil {
		return core.Process{}, false
	}
	return processCollector.FromGopsutil(ctx, handle), true
}

// Active is the backend in use now.
func (n *networkCollection) Active() netevents.Backend {
	n.mu.Lock()
	defer n.mu.Unlock()

	if n.source == nil {
		return netevents.BackendPoll
	}
	return n.source.Backend()
}

// EventDriven reports whether connections are reported as they happen.
func (n *networkCollection) EventDriven() bool { return n.Active() != netevents.BackendPoll }

// Stats returns the collector's counters. Polling has none.
func (n *networkCollection) Stats() netevents.Stats {
	n.mu.Lock()
	source := n.source
	n.mu.Unlock()

	if source == nil {
		return netevents.Stats{Backend: netevents.BackendPoll}
	}
	return source.Stats()
}

// PortOwner returns the process that last sent from a local port, when an
// event-driven backend is recording that.
func (n *networkCollection) PortOwner(protocol string, port uint16) (core.Process, bool) {
	n.mu.Lock()
	source := n.source
	n.mu.Unlock()

	if source == nil {
		return core.Process{}, false
	}
	return source.PortOwner(protocol, port)
}

// Describe says which backend is active and why another was passed over.
func (n *networkCollection) Describe() []string {
	n.mu.Lock()
	failure := n.failure
	n.mu.Unlock()

	lines := []string{fmt.Sprintf("network collector: %s (requested: %s)", n.Active(), n.requested)}
	for _, skip := range n.skipped {
		lines = append(lines, fmt.Sprintf("network collector: skipped %s", skip))
	}
	if failure != "" {
		lines = append(lines, "network collector: "+failure)
	}
	return lines
}

// Start begins delivering network events to the bus. report is told if the
// event-driven backend fails later; collection then continues by polling.
func (n *networkCollection) Start(ctx context.Context, bus *eventbus.Bus, report func(string)) {
	poll := func() {
		monitor.NewNetworkMonitor(networkcollector.NewCollector(), networkdetector.NewLifecycleDetector(), networkPollInterval, bus).Run(ctx)
	}

	n.mu.Lock()
	source := n.source
	n.mu.Unlock()

	if source == nil {
		go poll()
		return
	}

	go func() {
		err := source.Run(ctx, func(event core.Event) { bus.Publish(event) })
		source.Close()

		if err == nil || ctx.Err() != nil {
			return
		}

		message := fmt.Sprintf("%v; falling back to poll", err)
		n.mu.Lock()
		n.source = nil
		n.failure = message
		n.mu.Unlock()

		if report != nil {
			report("network collector: " + message)
		}
		poll()
	}()
}

// dnsPortOwner is how the platform's DNS collector may ask which process
// sent from a local port. It is set, before the platform monitors are built,
// when the network collector records that; nil otherwise.
var dnsPortOwner func(protocol string, port uint16) (core.Process, bool)

// mustOpenNetwork opens network collection beside process collection and tells
// the DNS collector where to ask about ports. It exits with the reason when a
// backend that was asked for by name cannot start.
func mustOpenNetwork(flags collectorFlags, processes *processCollection) *networkCollection {
	network, err := openNetworkCollection(flags.network, processes)
	if err != nil {
		fmt.Fprintf(os.Stderr, "sentinel: %v\n", err)
		os.Exit(1)
	}

	if network.EventDriven() {
		dnsPortOwner = network.PortOwner
	}
	return network
}

// applyOrderTolerance gives the engine the default order_tolerance that fits
// how events are being collected: the small one only when nothing polls.
//
// On Linux, DNS queries (packet capture) and file events (fanotify) are
// always reported as they happen, so the question is whether processes and
// connections are too. Elsewhere, and whenever either of them is polled, the
// default stays at the three seconds that cover a two-second poll.
func applyOrderTolerance(engine *correlation.Engine, processes *processCollection, network *networkCollection) time.Duration {
	tolerance := chooseOrderTolerance(runtime.GOOS, processes.EventDriven(), network.EventDriven())
	engine.SetDefaultOrderTolerance(tolerance)
	return tolerance
}

// chooseOrderTolerance is the rule applyOrderTolerance applies.
func chooseOrderTolerance(goos string, processesEventDriven, networkEventDriven bool) time.Duration {
	if goos == "linux" && processesEventDriven && networkEventDriven {
		return correlation.EventDrivenOrderTolerance
	}
	return correlation.DefaultOrderTolerance
}
