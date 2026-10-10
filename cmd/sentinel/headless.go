package main

import (
	"context"
	"fmt"
	"log"
	"os"
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

// runHeadless runs all collectors and the detection engine without a TUI.
// Findings are written to stdout as plain log lines. This is intended for
// server deployments where there is no interactive terminal (e.g. systemd,
// nohup, SSH sessions where the user will log out).
//
// Usage:
//
//	sentinel --headless
//	nohup sudo sentinel --headless >> /var/log/sentinel.log 2>&1 &
func runHeadless(ctx context.Context, patterns config.PatternSet, patternsPath string, s *store.Store, collectors collectorFlags) {
	logger := log.New(os.Stdout, "", log.LstdFlags)
	logger.Printf("sentinel %s starting in headless mode", version)

	// ── Process collection ───────────────────────────────────────────────────
	// Opened first, so that nothing starts unobserved while the rest is set
	// up.

	procCollector := processCollector.NewCollector()
	collection, err := openProcessCollection(collectors, procCollector)
	if err != nil {
		fmt.Fprintf(os.Stderr, "sentinel: %v\n", err)
		os.Exit(1)
	}
	for _, line := range collection.Describe() {
		logger.Print(line)
	}

	bus := eventbus.New(1000)

	// ── Process detection ────────────────────────────────────────────────────

	lifecycleDetector := processDetector.NewLifecycleDetector()

	registry := processDetector.NewRegistry()
	registry.Register(processDetector.NewSuspiciousChildProcessRule())
	procEngine := processDetector.NewEngine(registry)

	sink := finding.NewSinkFunc(func(f *core.Finding) {
		line := fmt.Sprintf("severity=%s rule=%s  %s — %s", f.Severity, f.Rule, f.Title, f.Description)
		if roles := finding.FormatRoles(f.Evidence); roles != "" {
			line += fmt.Sprintf("  roles=[%s] events=%d", roles, len(f.Evidence.Events))
		}
		logger.Printf("FINDING %s", line)
		if s != nil {
			s.WriteFinding(line, f.Evidence)
		}
	})
	coordinator := processDetector.NewCoordinator(procEngine, sink)

	// ── Correlation engine ───────────────────────────────────────────────────

	corrEngine := correlation.NewEngine(correlation.DefaultWindow)
	corrEngine.SetPatterns(patterns.Patterns)
	_ = corrEngine.SetExclusions(patterns.Exclusions)

	for _, warning := range patterns.Warnings {
		logger.Printf("PATTERN WARNING %s: %s", patternsPath, warning)
	}
	for _, problem := range patternProblems(patterns.Errors, patterns.Patterns) {
		logger.Printf("PATTERN ERROR %s: %s (pattern skipped)", patternsPath, problem)
	}
	logger.Printf("loaded %d pattern(s) and %d exclusion(s) from %s",
		len(patterns.Patterns), len(patterns.Exclusions), patternsPath)

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

	bus.Start(ctx)
	collection.Start(ctx, bus, lifecycleDetector, coordinator, corrEngine, func(message string) {
		logger.Print(message)
	})
	go netMonitor.Run(ctx)

	// One line a minute says whether Sentinel is keeping up.
	report := &health{collection: collection, bus: bus, engine: corrEngine}
	go func() {
		ticker := time.NewTicker(healthLogInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				logger.Printf("HEALTH %s", report.Report().LogLine())
			}
		}
	}()

	logger.Printf("sentinel running — waiting for events (SIGTERM/SIGHUP/Ctrl+C to stop)")
	<-ctx.Done()

	bus.Shutdown()
	bus.Wait()
	logger.Printf("HEALTH %s", report.Report().LogLine())
	logger.Printf("sentinel stopped")
}
