package dns

import (
	"testing"

	"github.com/arafat2020/sentinel/internal/core"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func TestParseDNSPacket(t *testing.T) {
	eth := &layers.Ethernet{
		SrcMAC:       []byte{0, 1, 2, 3, 4, 5},
		DstMAC:       []byte{6, 7, 8, 9, 10, 11},
		EthernetType: layers.EthernetTypeIPv4,
	}

	ip := &layers.IPv4{
		SrcIP:    []byte{192, 168, 1, 10},
		DstIP:    []byte{8, 8, 8, 8},
		Protocol: layers.IPProtocolUDP,
	}

	udp := &layers.UDP{
		SrcPort: 54321,
		DstPort: 53,
	}

	dns := &layers.DNS{
		ID:     1234,
		QR:     false,
		OpCode: layers.DNSOpCodeQuery,
		Questions: []layers.DNSQuestion{
			{
				Name:  []byte("example.com"),
				Type:  layers.DNSTypeA,
				Class: layers.DNSClassIN,
			},
		},
	}

	if err := udp.SetNetworkLayerForChecksum(ip); err != nil {
		t.Fatalf("failed to set network layer: %v", err)
	}

	buffer := gopacket.NewSerializeBuffer()

	options := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	err := gopacket.SerializeLayers(
		buffer,
		options,
		eth,
		ip,
		udp,
		dns,
	)

	if err != nil {
		t.Fatalf("failed to serialize packet: %v", err)
	}

	packet := gopacket.NewPacket(
		buffer.Bytes(),
		layers.LayerTypeEthernet,
		gopacket.Default,
	)

	query := parseDNSPacket(packet)

	if query == nil {
		t.Fatal("expected DNS query, got nil")
	}

	if query.Domain != "example.com" {
		t.Fatalf(
			"expected domain example.com, got %s",
			query.Domain,
		)
	}

	if query.Type != "A" {
		t.Fatalf(
			"expected type A, got %s",
			query.Type,
		)
	}

	if query.Resolver != "8.8.8.8" {
		t.Fatalf(
			"expected resolver 8.8.8.8, got %s",
			query.Resolver,
		)
	}

	if query.PID != 0 {
		t.Fatalf(
			"expected PID 0 before attribution, got %d",
			query.PID,
		)
	}

	if query.Process != nil {
		t.Fatal("expected Process to be nil before attribution")
	}
}

func TestParseDNSPacketIgnoresResponse(t *testing.T) {
	dns := &layers.DNS{
		ID: 1234,
		QR: true,
		Questions: []layers.DNSQuestion{
			{
				Name:  []byte("example.com"),
				Type:  layers.DNSTypeA,
				Class: layers.DNSClassIN,
			},
		},
	}

	packet := gopacket.NewPacket(
		serializeDNSOnly(t, dns),
		layers.LayerTypeDNS,
		gopacket.Default,
	)

	query := parseDNSPacket(packet)

	if query != nil {
		t.Fatal("expected DNS response to be ignored")
	}
}

func TestParseDNSPacketWithoutQuestion(t *testing.T) {
	dns := &layers.DNS{
		ID:        1234,
		QR:        false,
		Questions: nil,
	}

	packet := gopacket.NewPacket(
		serializeDNSOnly(t, dns),
		layers.LayerTypeDNS,
		gopacket.Default,
	)

	query := parseDNSPacket(packet)

	if query != nil {
		t.Fatal("expected packet without question to be ignored")
	}
}

func TestDNSTypeName(t *testing.T) {
	tests := []struct {
		dnsType layers.DNSType
		want    string
	}{
		{
			dnsType: layers.DNSTypeA,
			want:    "A",
		},
		{
			dnsType: layers.DNSTypeAAAA,
			want:    "AAAA",
		},
		{
			dnsType: layers.DNSTypeCNAME,
			want:    "CNAME",
		},
		{
			dnsType: layers.DNSTypeMX,
			want:    "MX",
		},
		{
			dnsType: layers.DNSTypeTXT,
			want:    "TXT",
		},
		{
			dnsType: layers.DNSTypeNS,
			want:    "NS",
		},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := dnsTypeName(tt.dnsType)

			if got != tt.want {
				t.Fatalf(
					"expected %s, got %s",
					tt.want,
					got,
				)
			}
		})
	}
}

func serializeDNSOnly(
	t *testing.T,
	dns *layers.DNS,
) []byte {
	t.Helper()

	buffer := gopacket.NewSerializeBuffer()

	options := gopacket.SerializeOptions{
		FixLengths: true,
	}

	if err := gopacket.SerializeLayers(
		buffer,
		options,
		dns,
	); err != nil {
		t.Fatalf("failed to serialize DNS packet: %v", err)
	}

	return buffer.Bytes()
}

// Compile-time check that DNSQuery is still the output model.
var _ core.DNSQuery
