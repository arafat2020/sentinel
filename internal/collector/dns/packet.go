package dns

import (
	"fmt"
	"net"
	"time"

	"github.com/arafat2020/sentinel/internal/core"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// parseDNSPacket, dnsTypeName, localAddress, and localPort are pure
// packet-decoding helpers shared by every platform-specific collector
// (darwin.go, linux.go, ...). They depend only on gopacket, never on a
// platform-specific capture backend, so they live here without a build
// constraint and are exercised directly by packet_test.go on any OS.

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
