//go:build darwin

package main

import (
	"context"
	"fmt"

	dnscollector "github.com/arafat2020/sentinel/internal/collector/dns"
	filecollector "github.com/arafat2020/sentinel/internal/collector/file"
	processCollector "github.com/arafat2020/sentinel/internal/collector/process"
	"github.com/arafat2020/sentinel/internal/eventbus"
	"github.com/arafat2020/sentinel/internal/monitor"
)

// buildPlatformMonitors wires the macOS-specific collectors (DNS via libpcap)
// to the event bus and starts their event loops.
// It returns a list of Close functions that must be called on shutdown.
//
// NOTE: macOS file telemetry (Endpoint Security) is not yet wired here because
// the real ES client (es_cgo.go CGo bridge) is still incomplete. The file
// collector foundation and core model are in place; once the ES callback bridge
// is finished, add NewMacOSCollector + FileMonitor here exactly as Linux does.
func buildPlatformMonitors(
	ctx context.Context,
	bus *eventbus.Bus,
) (closers []func(), err error) {
	processResolver := processCollector.NewResolver()

	// --- DNS collector (libpcap) ---
	socketLookup := dnscollector.NewDarwinSocketLookup()
	attributor := dnscollector.NewDarwinAttributor(socketLookup, processResolver)

	dnsCollector, err := dnscollector.NewMacOSCollector("en0", attributor)
	if err != nil {
		return nil, fmt.Errorf("create macOS DNS collector: %w", err)
	}

	dnsMonitor := monitor.NewDNSMonitor(dnsCollector, bus)

	go func() {
		if err := dnsMonitor.Run(ctx); err != nil && ctx.Err() == nil {
			fmt.Printf("[sentinel] DNS monitor stopped: %v\n", err)
		}
	}()

	closers = append(closers, dnsMonitor.Close)

	// --- File collector (Endpoint Security) ---
	// Requires: com.apple.developer.endpoint-security.client entitlement + root.
	fileCollector, err := filecollector.NewMacOSCollector()
	if err != nil {
		fmt.Printf("[sentinel] file collector unavailable: %v\n", err)
	} else {
		fileMonitor := monitor.NewFileMonitor(fileCollector, bus)
		go func() {
			if err := fileMonitor.Run(ctx); err != nil && ctx.Err() == nil {
				fmt.Printf("[sentinel] file monitor stopped: %v\n", err)
			}
		}()
		closers = append(closers, fileMonitor.Close)
	}

	return closers, nil
}
