package main

import (
	"context"
	"fmt"
	"log"
	"os"
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

// runHeadless runs all collectors and the detection engine without a TUI.
// Findings are written to stdout as plain log lines. This is intended for
// server deployments where there is no interactive terminal (e.g. systemd,
// nohup, SSH sessions where the user will log out).
//
// Usage:
//
//	sentinel --headless
//	nohup sudo sentinel --headless >> /var/log/sentinel.log 2>&1 &
func runHeadless(ctx context.Context, initialPatterns []correlation.BehaviorPattern, patternsPath string) {
	logger := log.New(os.Stdout, "", log.LstdFlags)
	logger.Printf("sentinel %s starting in headless mode", version)

	bus := eventbus.New(1000)

	// ── Process detection ────────────────────────────────────────────────────

	procCollector := processCollector.NewCollector()
	lifecycleDetector := processDetector.NewLifecycleDetector()

	registry := processDetector.NewRegistry()
	registry.Register(processDetector.NewSuspiciousChildProcessRule())
	procEngine := processDetector.NewEngine(registry)

	sink := finding.NewSinkFunc(func(f *core.Finding) {
		logger.Printf("FINDING severity=%s rule=%s  %s — %s", f.Severity, f.Rule, f.Title, f.Description)
	})
	coordinator := processDetector.NewCoordinator(procEngine, sink)

	// ── Correlation engine ───────────────────────────────────────────────────

	corrEngine := correlation.NewEngine(5 * time.Minute)
	corrEngine.SetPatterns(initialPatterns)

	// ── Bus subscribers ──────────────────────────────────────────────────────

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

	// ── Platform monitors ────────────────────────────────────────────────────

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

	// ── Platform-neutral monitors ────────────────────────────────────────────

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

	logger.Printf("sentinel running — waiting for events (SIGTERM/SIGHUP/Ctrl+C to stop)")
	<-ctx.Done()

	bus.Shutdown()
	bus.Wait()
	logger.Printf("sentinel stopped")
}
