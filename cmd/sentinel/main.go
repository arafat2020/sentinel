package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/arafat2020/sentinel/internal/core"
	"github.com/arafat2020/sentinel/internal/detection/correlation"
	"github.com/arafat2020/sentinel/internal/eventbus"
	"github.com/arafat2020/sentinel/internal/finding"
	"github.com/arafat2020/sentinel/internal/monitor"

	networkcollector "github.com/arafat2020/sentinel/internal/collector/network"
	processCollector "github.com/arafat2020/sentinel/internal/collector/process"
	networkdetector "github.com/arafat2020/sentinel/internal/detection/network"
	processDetector "github.com/arafat2020/sentinel/internal/detection/process"
)

// version is set at build time: -ldflags "-X main.version=vX.Y.Z"
var version = "dev"

func main() {
	ctx, stop := signal.NotifyContext(
		context.Background(),
		os.Interrupt,
		syscall.SIGTERM,
	)
	defer stop()

	ui := NewUI()

	bus := eventbus.New(1000)

	// ── Process detection (gopsutil — cross-platform) ────────────────────────

	procCollector := processCollector.NewCollector()
	lifecycleDetector := processDetector.NewLifecycleDetector()

	registry := processDetector.NewRegistry()
	registry.Register(processDetector.NewSuspiciousChildProcessRule())
	procEngine := processDetector.NewEngine(registry)

	sink := finding.NewSinkFunc(func(f *core.Finding) {
		ui.AddFinding(fmt.Sprintf("[%s] %s — %s", f.Rule, f.Title, f.Description))
	})
	coordinator := processDetector.NewCoordinator(procEngine, sink)

	// ── Correlation engine ────────────────────────────────────────────────────

	corrEngine := correlation.NewEngine(5 * time.Minute)

	// ── Bus subscribers → UI tabs ─────────────────────────────────────────────

	bus.Subscribe(func(event core.Event) {
		if event.Process == nil {
			return
		}
		if event.Type == core.EventProcessStart || event.Type == core.EventProcessExit {
			ui.AddProcess(fmt.Sprintf("%s  PID=%-6d  %-20s  %s",
				event.Type,
				event.Process.PID,
				event.Process.Name,
				event.Process.Executable,
			))
		}
	})

	bus.Subscribe(func(event core.Event) {
		if (event.Type != core.EventNetworkConnect && event.Type != core.EventNetworkClose) ||
			event.Network == nil {
			return
		}
		ui.AddNetwork(fmt.Sprintf("%s  PID=%-6d  %-5s  %s:%d  %s",
			event.Type,
			event.Network.PID,
			event.Network.Protocol,
			event.Network.RemoteAddress,
			event.Network.RemotePort,
			event.Network.State,
		))
	})

	bus.Subscribe(func(event core.Event) {
		if event.Type != core.EventDNSQuery || event.DNS == nil {
			return
		}
		proc := "<unknown>"
		if event.Process != nil && event.Process.Name != "" {
			proc = fmt.Sprintf("PID=%-6d %s", event.Process.PID, event.Process.Name)
		} else if event.DNS.PID != 0 {
			proc = fmt.Sprintf("PID=%-6d", event.DNS.PID)
		}
		ui.AddDNS(fmt.Sprintf("%-40s  %-6s  resolver=%-16s  %s",
			event.DNS.Domain,
			event.DNS.Type,
			event.DNS.Resolver,
			proc,
		))
	})

	bus.Subscribe(func(event core.Event) {
		if event.File == nil {
			return
		}
		switch event.Type {
		case core.EventFileCreate, core.EventFileModify, core.EventFileDelete, core.EventFileRename:
			ui.AddFile(fmt.Sprintf("%s  PID=%-6d  %s",
				event.Type,
				event.File.PID,
				event.File.Path,
			))
		}
	})

	bus.Subscribe(func(event core.Event) {
		coordinator.Handle(event)
	})

	bus.Subscribe(func(event core.Event) {
		corrEngine.Process(event)
		for _, f := range corrEngine.DetectBehaviors() {
			f := f
			sink.Handle(&f)
		}
	})

	// ── Platform-specific collectors (DNS + file) ─────────────────────────────

	closers, err := buildPlatformMonitors(ctx, bus)
	if err != nil {
		fmt.Fprintf(os.Stderr, "sentinel: platform setup failed: %v\n", err)
		os.Exit(1)
	}
	defer func() {
		for _, c := range closers {
			c()
		}
	}()

	// ── Platform-neutral monitors (process + network) ─────────────────────────

	netCollector := networkcollector.NewCollector()
	netDetector := networkdetector.NewLifecycleDetector()
	netMonitor := monitor.NewNetworkMonitor(netCollector, netDetector, 2*time.Second, bus)

	processMonitor := monitor.NewProcessMonitor(
		procCollector,
		lifecycleDetector,
		2*time.Second,
		bus,
		coordinator,
	)

	bus.Start(ctx)
	go processMonitor.Run(ctx)
	go netMonitor.Run(ctx)

	// Stop the UI when the OS signal fires.
	go func() {
		<-ctx.Done()
		bus.Shutdown()
		bus.Wait()
		ui.Stop()
	}()

	// Blocks until ui.Stop() is called (Ctrl+C or SIGTERM).
	if err := ui.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "sentinel: UI error: %v\n", err)
		os.Exit(1)
	}
}
