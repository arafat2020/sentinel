//go:build darwin

package main

import (
	"context"
	"fmt"
	"net"

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

	// --- DNS collectors (libpcap, one per active interface) ---
	//
	// macOS pcap does not support the Linux "any" pseudo-device, so we must
	// open one handle per interface. DNS traffic can leave on whichever NIC
	// the OS chooses (Ethernet, Wi-Fi, VPN tunnel), so we listen on all of
	// them. Interfaces that fail to open (e.g. no BPF access, no address) are
	// silently skipped.
	socketLookup := dnscollector.NewDarwinSocketLookup()
	attributor := dnscollector.NewDarwinAttributor(socketLookup, processResolver)

	started := 0
	ifaces, _ := net.Interfaces()
	for _, iface := range ifaces {
		// Skip loopback and interfaces that are not up.
		if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
			continue
		}
		// Skip interfaces without an IP address — no real traffic there.
		addrs, _ := iface.Addrs()
		hasIP := false
		for _, a := range addrs {
			if ip, ok := a.(*net.IPNet); ok && !ip.IP.IsLinkLocalUnicast() {
				hasIP = true
				break
			}
		}
		if !hasIP {
			continue
		}

		col, openErr := dnscollector.NewMacOSCollector(iface.Name, attributor)
		if openErr != nil {
			// Fails silently for interfaces pcap cannot open (e.g. utun without BPF).
			continue
		}

		dnsMonitor := monitor.NewDNSMonitor(col, bus)
		name := iface.Name
		go func() {
			if runErr := dnsMonitor.Run(ctx); runErr != nil && ctx.Err() == nil {
				fmt.Printf("[sentinel] DNS monitor (%s) stopped: %v\n", name, runErr)
			}
		}()
		closers = append(closers, dnsMonitor.Close)
		started++
	}

	if started == 0 {
		fmt.Println("[sentinel] DNS monitor unavailable — run as root for packet capture")
	} else {
		fmt.Printf("[sentinel] DNS monitor active on %d interface(s)\n", started)
	}

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
