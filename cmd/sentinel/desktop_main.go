package main

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"time"

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
	initialPatterns []correlation.BehaviorPattern,
	patternsPath string,
	eventStore *store.Store,
) {
	if err := checkDisplayAvailable(); err != nil {
		fmt.Fprintln(os.Stderr, "sentinel: --desktop is unavailable:", err)
		os.Exit(1)
	}

	corrEngine := correlation.NewEngine(5 * time.Minute)
	corrEngine.SetPatterns(initialPatterns)

	dui := NewDesktopUI()
	dui.SetStore(eventStore)
	dui.SetPatterns(patternsPath, initialPatterns, func(updated []correlation.BehaviorPattern) {
		corrEngine.SetPatterns(updated)
	})

	bus := eventbus.New(1000)

	// ── Process detection ─────────────────────────────────────────────────────

	procCol := processCollector.NewCollector()
	lifecycleDetector := processDetector.NewLifecycleDetector()
	registry := processDetector.NewRegistry()
	registry.Register(processDetector.NewSuspiciousChildProcessRule())
	procEngine := processDetector.NewEngine(registry)

	sink := finding.NewSinkFunc(func(f *core.Finding) {
		dui.AddFinding(fmt.Sprintf("[%s] %s — %s", f.Rule, f.Title, f.Description))
	})
	coordinator := processDetector.NewCoordinator(procEngine, sink)

	// ── Bus subscribers ───────────────────────────────────────────────────────

	bus.Subscribe(func(event core.Event) {
		if event.Process == nil {
			return
		}
		if event.Type == core.EventProcessStart || event.Type == core.EventProcessExit {
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

	processMonitor := monitor.NewProcessMonitor(
		procCol,
		lifecycleDetector,
		2*time.Second,
		bus,
		coordinator,
	)

	bus.Start(ctx)
	go processMonitor.Run(ctx)
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
