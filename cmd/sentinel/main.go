package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/arafat2020/sentinel/internal/core"
	"github.com/arafat2020/sentinel/internal/eventbus"
	"github.com/arafat2020/sentinel/internal/finding"

	processCollector "github.com/arafat2020/sentinel/internal/collector/process"
	processDetector "github.com/arafat2020/sentinel/internal/detection/process"
	"github.com/arafat2020/sentinel/internal/monitor"
)

func main() {
	ctx, stop := signal.NotifyContext(
		context.Background(),
		os.Interrupt,
		syscall.SIGTERM,
	)
	defer stop()

	bus := eventbus.New(1000)

	collector := processCollector.NewCollector()
	detector := processDetector.NewLifecycleDetector()

	registry := processDetector.NewRegistry()
	registry.Register(
		processDetector.NewSuspiciousChildProcessRule(),
	)

	engine := processDetector.NewEngine(registry)

	sink := finding.NewConsoleSink()

	coordinator := processDetector.NewCoordinator(
		engine,
		sink,
	)

	bus.Subscribe(func(event core.Event) {
		if event.Process == nil {
			return
		}

		fmt.Printf(
			"[%s] PID=%d NAME=%s EXE=%s\n",
			event.Type,
			event.Process.PID,
			event.Process.Name,
			event.Process.Executable,
		)
	})

	bus.Subscribe(func(event core.Event) {
		coordinator.Handle(event)
	})

	bus.Start(ctx)

	processMonitor := monitor.NewProcessMonitor(
		collector,
		detector,
		2*time.Second,
		bus,
		coordinator,
	)

	processMonitor.Run(ctx)
}
