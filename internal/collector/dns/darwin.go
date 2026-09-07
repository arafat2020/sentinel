//go:build darwin

package dns

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/arafat2020/sentinel/internal/core"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
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

func parseDNSPacket(
	packet gopacket.Packet,
) *core.DNSQuery {
	dnsLayer := packet.Layer(layers.LayerTypeDNS)

	if dnsLayer == nil {
		return nil
	}

	dns, ok := dnsLayer.(*layers.DNS)
	if !ok {
		return nil
	}

	// We only care about DNS queries here.
	if dns.QR {
		return nil
	}

	if len(dns.Questions) == 0 {
		return nil
	}

	question := dns.Questions[0]

	domain := string(question.Name)

	resolver := ""

	if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		ip := ipLayer.(*layers.IPv4)
		resolver = ip.DstIP.String()
	}

	if ipLayer := packet.Layer(layers.LayerTypeIPv6); ipLayer != nil {
		ip := ipLayer.(*layers.IPv6)
		resolver = ip.DstIP.String()
	}

	return &core.DNSQuery{
		Timestamp: time.Now(),

		Domain:   domain,
		Type:     dnsTypeName(question.Type),
		Resolver: resolver,
	}
}

func dnsTypeName(
	dnsType layers.DNSType,
) string {
	switch dnsType {
	case layers.DNSTypeA:
		return "A"

	case layers.DNSTypeAAAA:
		return "AAAA"

	case layers.DNSTypeCNAME:
		return "CNAME"

	case layers.DNSTypeMX:
		return "MX"

	case layers.DNSTypeTXT:
		return "TXT"

	case layers.DNSTypeNS:
		return "NS"

	default:
		return fmt.Sprintf("TYPE%d", uint16(dnsType))
	}
}

func localAddress(
	packet gopacket.Packet,
) net.IP {
	if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		return ipLayer.(*layers.IPv4).SrcIP
	}

	if ipLayer := packet.Layer(layers.LayerTypeIPv6); ipLayer != nil {
		return ipLayer.(*layers.IPv6).SrcIP
	}

	return nil
}

func localPort(
	packet gopacket.Packet,
) uint32 {
	if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp := udpLayer.(*layers.UDP)
		return uint32(udp.SrcPort)
	}

	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp := tcpLayer.(*layers.TCP)
		return uint32(tcp.SrcPort)
	}

	return 0
}

func (c *macOSCollector) Close() {
	if c.handle != nil {
		c.handle.Close()
	}
}
