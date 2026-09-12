//go:build linux

package main

import (
	"context"
	"fmt"

	filecollector "github.com/arafat2020/sentinel/internal/collector/file"
	processCollector "github.com/arafat2020/sentinel/internal/collector/process"

	dnscollector "github.com/arafat2020/sentinel/internal/collector/dns"
	"github.com/arafat2020/sentinel/internal/eventbus"
	"github.com/arafat2020/sentinel/internal/monitor"
)

// buildPlatformMonitors wires the Linux-specific collectors (DNS via libpcap,
// file events via fanotify) to the event bus and starts their event loops.
// It returns a list of Close functions that must be called on shutdown.
//
// Requirements:
//   - libpcap installed (for DNS capture)
//   - CAP_SYS_ADMIN or root (for fanotify file events)
//   - kernel 5.9+ (for full fanotify DFID_NAME support)
func buildPlatformMonitors(
	ctx context.Context,
	bus *eventbus.Bus,
) (closers []func(), err error) {
	processResolver := processCollector.NewResolver()

	// --- DNS collector (libpcap on "any" interface) ---
	socketLookup := dnscollector.NewLinuxSocketLookup()
	attributor := dnscollector.NewLinuxAttributor(socketLookup, processResolver)

	dnsCollector, err := dnscollector.NewLinuxCollector("any", attributor)
	if err != nil {
		return nil, fmt.Errorf("create Linux DNS collector: %w", err)
	}

	dnsMonitor := monitor.NewDNSMonitor(dnsCollector, bus)

	go func() {
		if err := dnsMonitor.Run(ctx); err != nil && ctx.Err() == nil {
			fmt.Printf("[sentinel] DNS monitor stopped: %v\n", err)
		}
	}()

	closers = append(closers, dnsMonitor.Close)

	// --- File collector (fanotify, watches root filesystem) ---
	fileCollector, err := filecollector.NewLinuxCollector("/", processResolver)
	if err != nil {
		return nil, fmt.Errorf("create Linux file collector: %w", err)
	}

	fileMonitor := monitor.NewFileMonitor(fileCollector, bus)

	go func() {
		if err := fileMonitor.Run(ctx); err != nil && ctx.Err() == nil {
			// fanotify requires CAP_SYS_ADMIN; log and continue without file telemetry.
			fmt.Printf("[sentinel] file monitor stopped: %v\n", err)
		}
	}()

	closers = append(closers, fileMonitor.Close)

	return closers, nil
}
