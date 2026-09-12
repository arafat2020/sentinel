//go:build darwin

package dns

import (
	"context"
	"fmt"

	"github.com/arafat2020/sentinel/internal/core"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

type macOSCollector struct {
	handle     *pcap.Handle
	attributor Attributor
}

func NewMacOSCollector(
	device string,
	attributor Attributor,
) (*macOSCollector, error) {
	handle, err := pcap.OpenLive(
		device,
		1600,
		true,
		pcap.BlockForever,
	)

	if err != nil {
		return nil, fmt.Errorf("open packet capture: %w", err)
	}

	if err := handle.SetBPFFilter(
		"udp port 53 or tcp port 53",
	); err != nil {
		handle.Close()
		return nil, fmt.Errorf("set DNS filter: %w", err)
	}

	return &macOSCollector{
		handle:     handle,
		attributor: attributor,
	}, nil
}

func (c *macOSCollector) Run(
	ctx context.Context,
	handler func(core.DNSQuery),
) error {
	if handler == nil {
		return fmt.Errorf("DNS handler cannot be nil")
	}

	packetSource := gopacket.NewPacketSource(
		c.handle,
		c.handle.LinkType(),
	)

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
				srcIP := localAddress(packet)

				if srcIP != nil {
					srcPort := localPort(packet)

					if srcPort != 0 {
						if err := c.attributor.Attribute(
							ctx,
							query,
							srcIP.String(),
							srcPort,
						); err != nil {
							// DNS telemetry remains valid even if attribution fails.
						}
					}
				}
			}

			handler(*query)
		}
	}
}

// parseDNSPacket, dnsTypeName, localAddress, and localPort are shared
// packet-decoding helpers defined in packet.go so they can be reused by
// every platform-specific collector (see linux.go).

func (c *macOSCollector) Close() {
	if c.handle != nil {
		c.handle.Close()
	}
}
