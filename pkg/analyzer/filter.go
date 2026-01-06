package analyzer

import (
	"strings"

	"github.com/gocisse/sdwan-triage/pkg/models"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// MatchesFilter checks if a packet matches the specified filter criteria
func MatchesFilter(packet gopacket.Packet, filter *models.Filter) bool {
	if filter.IsEmpty() {
		return true
	}

	netLayer := packet.NetworkLayer()
	if netLayer == nil {
		return false
	}

	var srcIP, dstIP string
	if ip4, ok := netLayer.(*layers.IPv4); ok {
		srcIP = ip4.SrcIP.String()
		dstIP = ip4.DstIP.String()
	} else {
		return false
	}

	// Check source IP filter
	if filter.SrcIP != "" && srcIP != filter.SrcIP {
		return false
	}

	// Check destination IP filter
	if filter.DstIP != "" && dstIP != filter.DstIP {
		return false
	}

	// Check protocol filter
	if filter.Protocol != "" {
		transportLayer := packet.TransportLayer()
		if transportLayer == nil {
			return false
		}

		protocol := strings.ToLower(filter.Protocol)
		switch protocol {
		case "tcp":
			if _, ok := transportLayer.(*layers.TCP); !ok {
				return false
			}
		case "udp":
			if _, ok := transportLayer.(*layers.UDP); !ok {
				return false
			}
		default:
			return false
		}
	}

	// Check service/port filter
	if filter.Service != "" {
		transportLayer := packet.TransportLayer()
		if transportLayer == nil {
			return false
		}

		// Resolve service name to port if needed
		targetPort, ok := models.ResolveServiceToPort(filter.Service)
		if !ok {
			return false
		}

		// Check both source and destination ports
		matched := false
		if tcp, ok := transportLayer.(*layers.TCP); ok {
			if uint16(tcp.SrcPort) == targetPort || uint16(tcp.DstPort) == targetPort {
				matched = true
			}
		} else if udp, ok := transportLayer.(*layers.UDP); ok {
			if uint16(udp.SrcPort) == targetPort || uint16(udp.DstPort) == targetPort {
				matched = true
			}
		}

		if !matched {
			return false
		}
	}

	return true
}
