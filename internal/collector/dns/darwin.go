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
	handle *pcap.Handle
}

func NewMacOSCollector(device string) (*macOSCollector, error) {
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
		handle: handle,
	}, nil
}

func (c *macOSCollector) Collect(
	ctx context.Context,
) ([]core.DNSQuery, error) {
	packetSource := gopacket.NewPacketSource(
		c.handle,
		c.handle.LinkType(),
	)

	var queries []core.DNSQuery

	for {
		select {
		case <-ctx.Done():
			return queries, ctx.Err()

		case packet, ok := <-packetSource.Packets():
			if !ok {
				return queries, nil
			}

			query := parseDNSPacket(packet)

			if query == nil {
				continue
			}

			queries = append(queries, *query)
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

func (c *macOSCollector) Close() {
	if c.handle != nil {
		c.handle.Close()
	}
}
