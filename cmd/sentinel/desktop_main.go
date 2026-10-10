package main

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"time"

	"github.com/arafat2020/sentinel/internal/config"
	"github.com/arafat2020/sentinel/internal/core"
	"github.com/arafat2020/sentinel/internal/detection/correlation"
	"github.com/arafat2020/sentinel/internal/eventbus"
	"github.com/arafat2020/sentinel/internal/finding"
	"github.com/arafat2020/sentinel/internal/monitor"
	"github.com/arafat2020/sentinel/internal/store"

	networkcollector "github.com/arafat2020/sentinel/internal/collector/network"
	processCollector "github.com/arafat2020/sentinel/internal/collector/process"
	networkdetector "github.com/arafat2020/sentinel/internal/detection/network"
	processDetector "github.com/arafat2020/sentinel/internal/detection/process"
)

// checkDisplayAvailable returns an error if the current environment cannot
// render a GUI window. On Linux a display server (X11 or Wayland) is required;
// macOS and Windows always have one.
func checkDisplayAvailable() error {
	if runtime.GOOS != "linux" {
		return nil
	}
	if os.Getenv("DISPLAY") != "" || os.Getenv("WAYLAND_DISPLAY") != "" {
		return nil
	}
	return fmt.Errorf(
		"no display server detected (DISPLAY and WAYLAND_DISPLAY are unset)\n" +
			"  Run with --headless for server environments, or set up X11/Wayland forwarding.\n" +
			"  Example with SSH X11 forwarding: ssh -X user@host sentinel --desktop",
	)
}

// runDesktopMode starts the Fyne-based desktop UI with all collectors wired up.
// It mirrors the TUI setup in main() but uses DesktopUI instead of tview.
func runDesktopMode(
	ctx context.Context,
	patterns config.PatternSet,
	patternsPath string,
	eventStore *store.Store,
	collectors collectorFlags,
) {
	if err := checkDisplayAvailable(); err != nil {
		fmt.Fprintln(os.Stderr, "sentinel: --desktop is unavailable:", err)
		os.Exit(1)
	}

	// Opened first, so that nothing starts unobserved while the rest is set
	// up, and a backend that cannot start is reported before a window opens.
	procCol := processCollector.NewCollector()
	collection, err := openProcessCollection(collectors, procCol)
	if err != nil {
		fmt.Fprintf(os.Stderr, "sentinel: %v\n", err)
		os.Exit(1)
	}

	corrEngine := correlation.NewEngine(correlation.DefaultWindow)
	corrEngine.SetPatterns(patterns.Patterns)
	_ = corrEngine.SetExclusions(patterns.Exclusions)

	dui := NewDesktopUI()
	dui.SetStore(eventStore)
	dui.SetPatternErrors(patterns.Errors)
	dui.SetPatterns(patternsPath, patterns.Patterns, func(updated []correlation.BehaviorPattern) {
		corrEngine.SetPatterns(updated)
	})

	bus := eventbus.New(1000)
	dui.SetHealth((&health{collection: collection, bus: bus, engine: corrEngine}).Text)

	// ── Process detection ─────────────────────────────────────────────────────

	lifecycleDetector := processDetector.NewLifecycleDetector()
	registry := processDetector.NewRegistry()
	// No Go-coded process rule is registered: what used to be one (node
	// spawning Python) is the suspicious-child-process YAML pattern.
	procEngine := processDetector.NewEngine(registry)

	sink := finding.NewSinkFunc(func(f *core.Finding) {
		dui.AddFindingWithEvidence(findingLine(f), f.Evidence)
	})
	coordinator := processDetector.NewCoordinator(procEngine, sink)

	// ── Bus subscribers ───────────────────────────────────────────────────────

	bus.Subscribe(func(event core.Event) {
		if event.Process == nil {
			return
		}
		if event.Type == core.EventProcessStart || event.Type == core.EventProcessExit || event.Type == core.EventProcessExec {
			dui.AddProcess(fmt.Sprintf("%s  PID=%-6d  %-20s  %s",
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
		dui.AddNetwork(fmt.Sprintf("%s  PID=%-6d  %-5s  %s:%d  %s",
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
		dui.AddDNS(fmt.Sprintf("%-40s  %-6s  resolver=%-16s  %s",
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
			dui.AddFile(fmt.Sprintf("%s  PID=%-6d  %s",
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

	// ── Platform-specific collectors ──────────────────────────────────────────

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

	// ── Platform-neutral monitors ─────────────────────────────────────────────

	netCol := networkcollector.NewCollector()
	netDetector := networkdetector.NewLifecycleDetector()
	netMonitor := monitor.NewNetworkMonitor(netCol, netDetector, 2*time.Second, bus)

	bus.Start(ctx)
	for _, line := range collection.Describe() {
		dui.AddProcess(line)
	}
	collection.Start(ctx, bus, lifecycleDetector, coordinator, corrEngine, dui.AddProcess)
	go netMonitor.Run(ctx)

	go func() {
		<-ctx.Done()
		bus.Shutdown()
		bus.Wait()
		dui.Stop()
	}()

	if err := dui.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "sentinel: desktop UI error: %v\n", err)
		os.Exit(1)
	}
}
