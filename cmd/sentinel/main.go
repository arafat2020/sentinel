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

	dnscollector "github.com/arafat2020/sentinel/internal/collector/dns"
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

		if event.Type == core.EventProcessStart ||
			event.Type == core.EventProcessExit {
			fmt.Printf(
				"[%s] PID=%d NAME=%s EXE=%s\n",
				event.Type,
				event.Process.PID,
				event.Process.Name,
				event.Process.Executable,
			)
		}
	})

	bus.Subscribe(func(event core.Event) {
		if event.Type == core.EventNetworkConnect ||
			event.Type == core.EventNetworkClose {
			if event.Network == nil {
				return
			}
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
		if event.Type == core.EventDNSQuery && event.DNS != nil {
			procInfo := "<unknown>"
			if event.Process != nil && event.Process.Name != "" {
				procInfo = fmt.Sprintf("PID=%d NAME=%s EXE=%s", event.Process.PID, event.Process.Name, event.Process.Executable)
			} else if event.DNS.PID != 0 {
				procInfo = fmt.Sprintf("PID=%d", event.DNS.PID)
			}
			fmt.Printf(
				"[%s] DOMAIN=%s TYPE=%s RESOLVER=%s %s\n",
				event.Type,
				event.DNS.Domain,
				event.DNS.Type,
				event.DNS.Resolver,
				procInfo,
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

	processResolver := processCollector.NewResolver()
	socketLookup := dnscollector.NewDarwinSocketLookup()
	attributor := dnscollector.NewDarwinAttributor(
		socketLookup,
		processResolver,
	)

	dnsCollector, err := dnscollector.NewMacOSCollector(
		"en0",
		attributor,
	)
	if err != nil {
		fmt.Printf("failed to create DNS collector: %v\n", err)
		return
	}

	dnsMonitor := monitor.NewDNSMonitor(
		dnsCollector,
		bus,
	)

	go func() {
		if err := dnsMonitor.Run(ctx); err != nil && ctx.Err() == nil {
			fmt.Printf("DNS monitor stopped: %v\n", err)
		}
	}()

	defer dnsMonitor.Close()

	go processMonitor.Run(ctx)
	go networkMonitor.Run(ctx)

	<-ctx.Done()
}
