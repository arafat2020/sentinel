//go:build windows

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

// buildPlatformMonitors wires the Windows-specific collectors (DNS via Npcap,
// file events via ReadDirectoryChangesW) to the event bus and starts their
// event loops. It returns a list of Close functions that must be called on
// shutdown.
//
// Requirements:
//   - Npcap installed with "WinPcap API-compatible Mode" enabled (for DNS)
//   - Sentinel running as Administrator (for packet capture + directory watching)
func buildPlatformMonitors(
	ctx context.Context,
	bus *eventbus.Bus,
) (closers []func(), err error) {
	processResolver := processCollector.NewResolver()

	// --- DNS collector (Npcap on the first active interface) ---
	// Non-fatal: Npcap may not be installed. Sentinel runs without DNS telemetry
	// in that case. Install Npcap from https://npcap.com with
	// "WinPcap API-compatible Mode" enabled to enable DNS capture.
	socketLookup := dnscollector.NewWindowsSocketLookup()
	attributor := dnscollector.NewWindowsAttributor(socketLookup, processResolver)

	dnsCollector, err := dnscollector.NewWindowsCollector("", attributor)
	if err != nil {
		fmt.Printf("[sentinel] DNS telemetry unavailable: %v\n", err)
		fmt.Printf("[sentinel] Install Npcap (https://npcap.com) with WinPcap API-compatible Mode to enable DNS capture.\n")
	} else {
		dnsMonitor := monitor.NewDNSMonitor(dnsCollector, bus)
		go func() {
			if err := dnsMonitor.Run(ctx); err != nil && ctx.Err() == nil {
				fmt.Printf("[sentinel] DNS monitor stopped: %v\n", err)
			}
		}()
		closers = append(closers, dnsMonitor.Close)
	}

	// --- File collector (ReadDirectoryChangesW on the system drive) ---
	watchRoot := filecollector.DefaultWatchRoot()
	fileCollector, err := filecollector.NewWindowsCollector(watchRoot)
	if err != nil {
		// Non-fatal: log and continue without file telemetry.
		fmt.Printf("[sentinel] file collector unavailable (%s): %v\n", watchRoot, err)
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
