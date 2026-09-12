//go:build linux

package dns

import (
	"context"
	"fmt"

	"github.com/arafat2020/sentinel/internal/core"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

// linuxCollector captures DNS query traffic on Linux via libpcap, mirroring
// the macOS collector (darwin.go). The two only differ in the platform used
// to resolve the observing process (see linux_socket_lookup.go), since
// packet capture and decoding are handled identically by libpcap/gopacket
// on both platforms.
type linuxCollector struct {
	handle     *pcap.Handle
	attributor Attributor
}

// NewLinuxCollector opens a live packet capture on the given network
// device (e.g. "eth0", or "any" to capture on all interfaces) and filters
// for DNS traffic. Requires libpcap to be installed on the host.
func NewLinuxCollector(
	device string,
	attributor Attributor,
) (*linuxCollector, error) {
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

	return &linuxCollector{
		handle:     handle,
		attributor: attributor,
	}, nil
}

func (c *linuxCollector) Run(
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

func (c *linuxCollector) Close() {
	if c.handle != nil {
		c.handle.Close()
	}
}
