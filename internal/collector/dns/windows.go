//go:build windows

package dns

import (
	"context"
	"fmt"

	"github.com/arafat2020/sentinel/internal/core"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

// windowsCollector captures DNS query traffic on Windows via libpcap (Npcap).
// It mirrors the macOS and Linux collectors: same BPF filter, same gopacket
// decoding; only the network-interface naming and socket-lookup backend differ.
//
// Prerequisites on the target machine:
//   - Npcap installed (https://npcap.com) with "WinPcap API-compatible Mode"
//   - Sentinel running with Administrator privileges
type windowsCollector struct {
	handle     *pcap.Handle
	attributor Attributor
}

// NewWindowsCollector opens a live packet capture on the named device
// (e.g. `\Device\NPF_{GUID}`) and filters for DNS traffic.
// Pass an empty device string to use the first active interface found by
// pcap.FindAllDevs().
func NewWindowsCollector(
	device string,
	attributor Attributor,
) (*windowsCollector, error) {
	if device == "" {
		var err error
		device, err = firstActiveDevice()
		if err != nil {
			return nil, err
		}
	}

	handle, err := pcap.OpenLive(
		device,
		1600,
		true,
		pcap.BlockForever,
	)
	if err != nil {
		return nil, fmt.Errorf("open packet capture: %w", err)
	}

	if err := handle.SetBPFFilter("udp port 53 or tcp port 53"); err != nil {
		handle.Close()
		return nil, fmt.Errorf("set DNS filter: %w", err)
	}

	return &windowsCollector{
		handle:     handle,
		attributor: attributor,
	}, nil
}

// firstActiveDevice returns the name of the first non-loopback pcap device
// that has at least one address. Npcap uses `\Device\NPF_{GUID}` names.
func firstActiveDevice() (string, error) {
	devs, err := pcap.FindAllDevs()
	if err != nil {
		return "", fmt.Errorf("list network devices: %w", err)
	}
	for _, d := range devs {
		if len(d.Addresses) > 0 {
			return d.Name, nil
		}
	}
	return "", fmt.Errorf("no active network interfaces found")
}

func (c *windowsCollector) Run(
	ctx context.Context,
	handler func(core.DNSQuery),
) error {
	if handler == nil {
		return fmt.Errorf("DNS handler cannot be nil")
	}

	packetSource := gopacket.NewPacketSource(c.handle, c.handle.LinkType())

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()

		case packet, ok := <-packetSource.Packets():
			if !ok {
				return nil
			}

			query := parseDNSPacket(packet)
			if query == nil {
				continue
			}

			if c.attributor != nil {
				if srcIP := localAddress(packet); srcIP != nil {
					if srcPort := localPort(packet); srcPort != 0 {
						_ = c.attributor.Attribute(ctx, query, srcIP.String(), srcPort)
					}
				}
			}

			handler(*query)
		}
	}
}

func (c *windowsCollector) Close() {
	if c.handle != nil {
		c.handle.Close()
	}
}
