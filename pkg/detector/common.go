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
func ExtractIPInfo(packet gopacket.Packet) *PacketIPInfo {
	// Try IPv4 first
	if ip4Layer := packet.Layer(layers.LayerTypeIPv4); ip4Layer != nil {
		ip4 := ip4Layer.(*layers.IPv4)
		return &PacketIPInfo{
			SrcIP:    ip4.SrcIP.String(),
			DstIP:    ip4.DstIP.String(),
			TTL:      ip4.TTL,
			IsIPv6:   false,
			Protocol: uint8(ip4.Protocol),
		}
	}

	// Try IPv6
	if ip6Layer := packet.Layer(layers.LayerTypeIPv6); ip6Layer != nil {
		ip6 := ip6Layer.(*layers.IPv6)
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
func GetTransportPorts(packet gopacket.Packet) (srcPort, dstPort uint16, protocol string) {
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp := tcpLayer.(*layers.TCP)
		return uint16(tcp.SrcPort), uint16(tcp.DstPort), "TCP"
	}

	if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp := udpLayer.(*layers.UDP)
		return uint16(udp.SrcPort), uint16(udp.DstPort), "UDP"
	}

	return 0, 0, ""
}
