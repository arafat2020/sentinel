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

	networkcollector "github.com/arafat2020/sentinel/internal/collector/network"
	processCollector "github.com/arafat2020/sentinel/internal/collector/process"
	networkdetector "github.com/arafat2020/sentinel/internal/detection/network"
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
		if event.Type == core.EventNetworkConnect ||
			event.Type == core.EventNetworkClose {
			fmt.Printf(
				"[%s] PID=%d PROTOCOL=%s REMOTE=%s:%d STATE=%s\n",
				event.Type,
				event.Network.PID,
				event.Network.Protocol,
				event.Network.RemoteAddress,
				event.Network.RemotePort,
				event.Network.State,
			)
		}
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

	networkCollector := networkcollector.NewCollector()
	networkDetector := networkdetector.NewLifecycleDetector()

	networkMonitor := monitor.NewNetworkMonitor(
		networkCollector,
		networkDetector,
		2*time.Second,
		bus,
	)

	go processMonitor.Run(ctx)
	go networkMonitor.Run(ctx)

	<-ctx.Done()
}
