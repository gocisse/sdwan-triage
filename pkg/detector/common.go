package detector

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// PacketIPInfo holds extracted IP information from a packet
type PacketIPInfo struct {
	SrcIP    string
	DstIP    string
	TTL      uint8
	IsIPv6   bool
	Protocol uint8 // Next header for IPv6, Protocol for IPv4
}

// ExtractIPInfo extracts IP information from a packet (supports IPv4 and IPv6)
// Returns nil if packet is nil or has no IP layer
func ExtractIPInfo(packet gopacket.Packet) *PacketIPInfo {
	if packet == nil {
		return nil
	}

	// Try IPv4 first with safe type assertion
	if ip4Layer := packet.Layer(layers.LayerTypeIPv4); ip4Layer != nil {
		ip4, ok := ip4Layer.(*layers.IPv4)
		if !ok || ip4 == nil {
			return nil
		}
		// Validate IP addresses exist
		if ip4.SrcIP == nil || ip4.DstIP == nil {
			return nil
		}
		return &PacketIPInfo{
			SrcIP:    ip4.SrcIP.String(),
			DstIP:    ip4.DstIP.String(),
			TTL:      ip4.TTL,
			IsIPv6:   false,
			Protocol: uint8(ip4.Protocol),
		}
	}

	// Try IPv6 with safe type assertion
	if ip6Layer := packet.Layer(layers.LayerTypeIPv6); ip6Layer != nil {
		ip6, ok := ip6Layer.(*layers.IPv6)
		if !ok || ip6 == nil {
			return nil
		}
		// Validate IP addresses exist
		if ip6.SrcIP == nil || ip6.DstIP == nil {
			return nil
		}
		return &PacketIPInfo{
			SrcIP:    ip6.SrcIP.String(),
			DstIP:    ip6.DstIP.String(),
			TTL:      ip6.HopLimit,
			IsIPv6:   true,
			Protocol: uint8(ip6.NextHeader),
		}
	}

	return nil
}

// GetTransportPorts extracts source and destination ports from TCP or UDP layers
// Returns empty values if packet is nil or has no transport layer
func GetTransportPorts(packet gopacket.Packet) (srcPort, dstPort uint16, protocol string) {
	if packet == nil {
		return 0, 0, ""
	}

	// Try TCP with safe type assertion
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp, ok := tcpLayer.(*layers.TCP)
		if ok && tcp != nil {
			return uint16(tcp.SrcPort), uint16(tcp.DstPort), "TCP"
		}
	}

	// Try UDP with safe type assertion
	if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp, ok := udpLayer.(*layers.UDP)
		if ok && udp != nil {
			return uint16(udp.SrcPort), uint16(udp.DstPort), "UDP"
		}
	}

	return 0, 0, ""
}

// SafeGetTCPLayer safely extracts TCP layer from a packet
func SafeGetTCPLayer(packet gopacket.Packet) *layers.TCP {
	if packet == nil {
		return nil
	}
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		return nil
	}
	tcp, ok := tcpLayer.(*layers.TCP)
	if !ok {
		return nil
	}
	return tcp
}

// SafeGetUDPLayer safely extracts UDP layer from a packet
func SafeGetUDPLayer(packet gopacket.Packet) *layers.UDP {
	if packet == nil {
		return nil
	}
	udpLayer := packet.Layer(layers.LayerTypeUDP)
	if udpLayer == nil {
		return nil
	}
	udp, ok := udpLayer.(*layers.UDP)
	if !ok {
		return nil
	}
	return udp
}

// SafeGetDNSLayer safely extracts DNS layer from a packet
func SafeGetDNSLayer(packet gopacket.Packet) *layers.DNS {
	if packet == nil {
		return nil
	}
	dnsLayer := packet.Layer(layers.LayerTypeDNS)
	if dnsLayer == nil {
		return nil
	}
	dns, ok := dnsLayer.(*layers.DNS)
	if !ok {
		return nil
	}
	return dns
}

// SafeGetARPLayer safely extracts ARP layer from a packet
func SafeGetARPLayer(packet gopacket.Packet) *layers.ARP {
	if packet == nil {
		return nil
	}
	arpLayer := packet.Layer(layers.LayerTypeARP)
	if arpLayer == nil {
		return nil
	}
	arp, ok := arpLayer.(*layers.ARP)
	if !ok {
		return nil
	}
	return arp
}

// SafeGetEthernetLayer safely extracts Ethernet layer from a packet
func SafeGetEthernetLayer(packet gopacket.Packet) *layers.Ethernet {
	if packet == nil {
		return nil
	}
	ethLayer := packet.Layer(layers.LayerTypeEthernet)
	if ethLayer == nil {
		return nil
	}
	eth, ok := ethLayer.(*layers.Ethernet)
	if !ok {
		return nil
	}
	return eth
}

// SafeGetTimestamp safely extracts timestamp from packet metadata
func SafeGetTimestamp(packet gopacket.Packet) float64 {
	if packet == nil || packet.Metadata() == nil {
		return 0
	}
	return float64(packet.Metadata().Timestamp.UnixNano()) / 1e9
}
