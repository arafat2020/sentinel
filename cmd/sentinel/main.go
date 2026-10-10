package main

import (
	"context"
	"flag"
	"fmt"
	"golang.org/x/term"
	"net/http"
	_ "net/http/pprof" // registers on the default mux, served only with --pprof-addr
	"os"
	"os/signal"
	"syscall"
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
	resourcecollector "github.com/arafat2020/sentinel/internal/collector/resource"
	networkdetector "github.com/arafat2020/sentinel/internal/detection/network"
	processDetector "github.com/arafat2020/sentinel/internal/detection/process"
)

// version is set at build time: -ldflags "-X main.version=vX.Y.Z"
var version = "dev"

func main() {
	headless := flag.Bool("headless", false, "run without TUI; log findings to stdout (suitable for servers / systemd)")
	desktop := flag.Bool("desktop", false, "run with Fyne native desktop UI instead of the TUI")
	resetPW := flag.Bool("reset-password", false, "interactively reset the Sentinel password and exit")

	// Query mode — reads from the DB and exits. Does not start any collectors.
	queryMode := flag.Bool("query", false, "query stored events and exit")
	queryTab := flag.String("tab", "", "filter by tab name: Process|Network|DNS|File|Findings (default: all)")
	querySince := flag.String("since", "", "start date/time, e.g. 2026-09-14 or 2026-09-14T08:00:00")
	queryUntil := flag.String("until", "", "end date/time (default: now)")
	queryLimit := flag.Int("limit", 200, "maximum rows to return")
	collectors := registerCollectorFlags()
	pprofAddr := flag.String("pprof-addr", "", "serve Go profiling data (net/http/pprof) on this address, e.g. 127.0.0.1:6060; off by default")
	flag.Parse()

	if *pprofAddr != "" {
		go func() {
			if err := http.ListenAndServe(*pprofAddr, nil); err != nil {
				fmt.Fprintf(os.Stderr, "sentinel: pprof: %v\n", err)
			}
		}()
	}

	if *queryMode {
		runQuery(*queryTab, *querySince, *queryUntil, *queryLimit)
		return
	}

	// SIGHUP is sent when the controlling terminal closes (e.g. SSH disconnect).
	// Without it the process hangs inside tview waiting for a TTY that no
	// longer exists. Handle it the same as SIGTERM: clean shutdown.
	ctx, stop := signal.NotifyContext(
		context.Background(),
		os.Interrupt,
		syscall.SIGTERM,
		syscall.SIGHUP,
	)
	defer stop()

	const patternsPath = "configs/patterns.yaml"

	if err := config.EnsureDefaultFile(patternsPath); err != nil {
		fmt.Fprintf(os.Stderr, "sentinel: could not create default patterns file: %v\n", err)
	}

	// A file that cannot be read or parsed falls back to the defaults. A
	// file with some bad entries loads the good ones; the bad ones are
	// reported here and again inside each interface.
	patternSet, err := loadPatternSet(patternsPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "sentinel: could not load patterns (%v), using defaults\n", err)
	}
	for _, warning := range patternSet.Warnings {
		fmt.Fprintf(os.Stderr, "sentinel: %s: warning: %s\n", patternsPath, warning)
	}
	for _, patternErr := range patternSet.Errors {
		fmt.Fprintf(os.Stderr, "sentinel: %s: %v (skipped)\n", patternsPath, patternErr)
	}

	// ── SQLite event store ────────────────────────────────────────────────────

	eventStore, err := store.Open(dbPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "sentinel: could not open store (%v); events will not be persisted\n", err)
		eventStore = nil
	} else {
		defer eventStore.Close()
		go eventStore.RunRetention(ctx)
	}

	// ── Password gate ─────────────────────────────────────────────────────────
	// Desktop mode handles its own GUI password gate; TUI/headless use the
	// terminal-based gate. --reset-password is not supported in desktop mode.
	if *desktop {
		if *resetPW {
			fmt.Fprintln(os.Stderr, "sentinel: --reset-password is not supported with --desktop; run without --desktop to reset")
			os.Exit(1)
		}
		// password gate handled inside DesktopUI.Run()
	} else if eventStore != nil {
		if passwordGateApplies(*headless, *resetPW, term.IsTerminal(int(os.Stdin.Fd()))) {
			runPasswordGate(eventStore, *resetPW)
		} else {
			fmt.Println("sentinel: no terminal on standard input; starting headless without the password prompt")
		}
	} else if *resetPW {
		fmt.Fprintln(os.Stderr, "sentinel: cannot reset password — database unavailable")
		os.Exit(1)
	}

	if *headless {
		runHeadless(ctx, patternSet, patternsPath, eventStore, collectors)
		return
	}

	if *desktop {
		runDesktopMode(ctx, patternSet, patternsPath, eventStore, collectors)
		return
	}

	// ── Process collection ───────────────────────────────────────────────────
	// Opened before the terminal is taken over, so that a backend that was
	// asked for by name and cannot start is reported where it can be read,
	// and before anything else, so that nothing starts unobserved.

	procCollector := processCollector.NewCollector()
	collection, err := openProcessCollection(collectors, procCollector)
	if err != nil {
		fmt.Fprintf(os.Stderr, "sentinel: %v\n", err)
		os.Exit(1)
	}

	ui := NewUI()
	ui.SetStore(eventStore)

	bus := eventbus.New(1000)

	// ── Process detection ────────────────────────────────────────────────────

	lifecycleDetector := processDetector.NewLifecycleDetector()

	registry := processDetector.NewRegistry()
	// No Go-coded process rule is registered: what used to be one (node
	// spawning Python) is the suspicious-child-process YAML pattern.
	procEngine := processDetector.NewEngine(registry)

	sink := finding.NewSinkFunc(func(f *core.Finding) {
		ui.AddFindingWithEvidence(findingLine(f), f.Evidence)
	})
	coordinator := processDetector.NewCoordinator(procEngine, sink)

	// ── Correlation engine ────────────────────────────────────────────────────

	corrEngine := correlation.NewEngine(correlation.DefaultWindow)
	corrEngine.SetPatterns(patternSet.Patterns)
	// Invalid exclusions were already reported with the load errors.
	_ = corrEngine.SetExclusions(patternSet.Exclusions)

	// ── Settings page ─────────────────────────────────────────────────────────

	settingsPage := NewSettingsPage(ui.app, eventStore)
	ui.SetSettingsPage(settingsPage)
	ui.SetHealth((&health{collection: collection, bus: bus, engine: corrEngine}).Text)

	// ── Pattern editor TUI page ───────────────────────────────────────────────

	patternsPage := NewPatternsPage(
		ui.app,
		ui.pages,
		patternsPath,
		patternSet.Patterns,
		func(updated []correlation.BehaviorPattern) {
			corrEngine.SetPatterns(updated)
		},
	)
	patternsPage.SetLoadErrors(patternSet.Errors)
	ui.SetPatternsPage(patternsPage)

	// ── Bus subscribers → UI tabs ─────────────────────────────────────────────

	bus.Subscribe(func(event core.Event) {
		if event.Process == nil {
			return
		}
		if event.Type == core.EventProcessStart || event.Type == core.EventProcessExit || event.Type == core.EventProcessExec {
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

	// Live resource usage feeds the Resources tab directly: it bypasses the
	// event bus and the store so samples never reach detection or SQLite.
	resourceMonitor := monitor.NewResourceMonitor(
		resourcecollector.NewCollector(),
		2*time.Second,
		ui.UpdateResources,
	)

	bus.Start(ctx)
	for _, line := range collection.Describe() {
		ui.AddProcess(line)
	}
	collection.Start(ctx, bus, lifecycleDetector, coordinator, corrEngine, ui.AddProcess)
	go netMonitor.Run(ctx)
	go resourceMonitor.Run(ctx)

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
