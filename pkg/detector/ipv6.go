package detector

import (
	"encoding/binary"
	"fmt"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// IPv6ExtensionHeader represents an IPv6 extension header
type IPv6ExtensionHeader struct {
	Type       layers.IPProtocol
	Length     uint8
	NextHeader layers.IPProtocol
	Data       []byte
}

// IPv6PacketInfo contains parsed IPv6 packet information including extension headers
type IPv6PacketInfo struct {
	SrcIP            net.IP
	DstIP            net.IP
	NextHeader       layers.IPProtocol
	HopLimit         uint8
	FlowLabel        uint32
	TrafficClass     uint8
	PayloadLength    uint16
	ExtensionHeaders []IPv6ExtensionHeader
	FinalPayload     []byte
	FinalProtocol    layers.IPProtocol
}

// ParseIPv6Packet parses an IPv6 packet including all extension headers
func ParseIPv6Packet(packet gopacket.Packet) *IPv6PacketInfo {
	ipv6Layer := packet.Layer(layers.LayerTypeIPv6)
	if ipv6Layer == nil {
		return nil
	}

	ipv6, ok := ipv6Layer.(*layers.IPv6)
	if !ok {
		return nil
	}

	info := &IPv6PacketInfo{
		SrcIP:            ipv6.SrcIP,
		DstIP:            ipv6.DstIP,
		NextHeader:       ipv6.NextHeader,
		HopLimit:         ipv6.HopLimit,
		FlowLabel:        ipv6.FlowLabel,
		TrafficClass:     ipv6.TrafficClass,
		PayloadLength:    ipv6.Length,
		ExtensionHeaders: []IPv6ExtensionHeader{},
	}

	// Parse extension headers
	payload := ipv6.Payload
	nextHeader := ipv6.NextHeader

	for isExtensionHeader(nextHeader) && len(payload) > 0 {
		extHeader, remaining, err := parseExtensionHeader(nextHeader, payload)
		if err != nil {
			break
		}

		info.ExtensionHeaders = append(info.ExtensionHeaders, *extHeader)
		nextHeader = extHeader.NextHeader
		payload = remaining
	}

	info.FinalPayload = payload
	info.FinalProtocol = nextHeader

	return info
}

// isExtensionHeader checks if the protocol is an IPv6 extension header
func isExtensionHeader(protocol layers.IPProtocol) bool {
	switch protocol {
	case layers.IPProtocolIPv6HopByHop: // 0
		return true
	case layers.IPProtocolIPv6Routing: // 43
		return true
	case layers.IPProtocolIPv6Fragment: // 44
		return true
	case layers.IPProtocolIPv6Destination: // 60
		return true
	case layers.IPProtocolAH: // 51 - Authentication Header
		return true
	case 59: // IPv6-NoNxt - No Next Header
		return true
	default:
		return false
	}
}

// parseExtensionHeader parses a single IPv6 extension header
func parseExtensionHeader(headerType layers.IPProtocol, data []byte) (*IPv6ExtensionHeader, []byte, error) {
	if len(data) < 2 {
		return nil, nil, fmt.Errorf("insufficient data for extension header")
	}

	header := &IPv6ExtensionHeader{
		Type:       headerType,
		NextHeader: layers.IPProtocol(data[0]),
	}

	var headerLen int

	switch headerType {
	case layers.IPProtocolIPv6Fragment:
		// Fragment header is always 8 bytes
		if len(data) < 8 {
			return nil, nil, fmt.Errorf("insufficient data for fragment header")
		}
		headerLen = 8
		header.Length = 8
		header.Data = data[0:8]

	case layers.IPProtocolIPv6HopByHop, layers.IPProtocolIPv6Routing, layers.IPProtocolIPv6Destination:
		// These headers have length field in second byte (in 8-byte units, excluding first 8 bytes)
		hdrExtLen := int(data[1])
		headerLen = (hdrExtLen + 1) * 8
		if len(data) < headerLen {
			return nil, nil, fmt.Errorf("insufficient data for extension header")
		}
		header.Length = uint8(headerLen)
		header.Data = data[0:headerLen]

	case layers.IPProtocolAH:
		// Authentication Header: length field is in 4-byte units, minus 2
		if len(data) < 8 {
			return nil, nil, fmt.Errorf("insufficient data for AH header")
		}
		ahLen := int(data[1])
		headerLen = (ahLen + 2) * 4
		if len(data) < headerLen {
			return nil, nil, fmt.Errorf("insufficient data for AH header")
		}
		header.Length = uint8(headerLen)
		header.Data = data[0:headerLen]

	case 59: // IPv6-NoNxt - No Next Header
		// No next header - end of chain
		return header, []byte{}, nil

	default:
		return nil, nil, fmt.Errorf("unknown extension header type: %d", headerType)
	}

	remaining := data[headerLen:]
	return header, remaining, nil
}

// ExtractFragmentInfo extracts fragment information from IPv6 fragment header
func ExtractFragmentInfo(extHeaders []IPv6ExtensionHeader) (isFragment bool, fragOffset uint16, moreFragments bool, fragID uint32) {
	for _, header := range extHeaders {
		if header.Type == layers.IPProtocolIPv6Fragment && len(header.Data) >= 8 {
			// Fragment header format:
			// 0: Next Header
			// 1: Reserved
			// 2-3: Fragment Offset (13 bits) + Res (2 bits) + M flag (1 bit)
			// 4-7: Identification
			isFragment = true

			fragOffsetAndFlags := binary.BigEndian.Uint16(header.Data[2:4])
			fragOffset = (fragOffsetAndFlags >> 3) * 8 // Convert to bytes
			moreFragments = (fragOffsetAndFlags & 0x0001) != 0
			fragID = binary.BigEndian.Uint32(header.Data[4:8])
			return
		}
	}
	return false, 0, false, 0
}

// ExtractRoutingInfo extracts routing information from IPv6 routing header
func ExtractRoutingInfo(extHeaders []IPv6ExtensionHeader) (hasRouting bool, routingType uint8, segmentsLeft uint8, addresses []net.IP) {
	for _, header := range extHeaders {
		if header.Type == layers.IPProtocolIPv6Routing && len(header.Data) >= 4 {
			hasRouting = true
			routingType = header.Data[2]
			segmentsLeft = header.Data[3]

			// Parse addresses based on routing type
			if routingType == 0 && len(header.Data) >= 8 {
				// Type 0 routing header (deprecated but still seen)
				addrData := header.Data[8:]
				for i := 0; i+16 <= len(addrData); i += 16 {
					addr := net.IP(addrData[i : i+16])
					addresses = append(addresses, addr)
				}
			}
			return
		}
	}
	return false, 0, 0, nil
}

// HasESPHeader checks if packet has ESP (Encrypted Security Payload) header
func HasESPHeader(extHeaders []IPv6ExtensionHeader) bool {
	for _, header := range extHeaders {
		if header.Type == layers.IPProtocolESP {
			return true
		}
	}
	return false
}

// HasAHHeader checks if packet has AH (Authentication Header)
func HasAHHeader(extHeaders []IPv6ExtensionHeader) bool {
	for _, header := range extHeaders {
		if header.Type == layers.IPProtocolAH {
			return true
		}
	}
	return false
}

// GetTransportLayer extracts the transport layer from parsed IPv6 info
func GetTransportLayer(packet gopacket.Packet, ipv6Info *IPv6PacketInfo) gopacket.Layer {
	switch ipv6Info.FinalProtocol {
	case layers.IPProtocolTCP:
		return packet.Layer(layers.LayerTypeTCP)
	case layers.IPProtocolUDP:
		return packet.Layer(layers.LayerTypeUDP)
	case layers.IPProtocolICMPv6:
		return packet.Layer(layers.LayerTypeICMPv6)
	case layers.IPProtocolSCTP:
		return packet.Layer(layers.LayerTypeSCTP)
	default:
		return nil
	}
}

// NormalizeIPv6Address normalizes an IPv6 address to its canonical form
func NormalizeIPv6Address(ip net.IP) string {
	// Convert to 16-byte representation
	ip = ip.To16()
	if ip == nil {
		return ""
	}

	// Check if it's an IPv4-mapped IPv6 address (::ffff:a.b.c.d)
	if ip.To4() != nil {
		return ip.To4().String()
	}

	return ip.String()
}

// IsIPv6LinkLocal checks if an IPv6 address is link-local (fe80::/10)
func IsIPv6LinkLocal(ip net.IP) bool {
	ip = ip.To16()
	if ip == nil {
		return false
	}
	return ip[0] == 0xfe && (ip[1]&0xc0) == 0x80
}

// IsIPv6UniqueLocal checks if an IPv6 address is unique local (fc00::/7)
func IsIPv6UniqueLocal(ip net.IP) bool {
	ip = ip.To16()
	if ip == nil {
		return false
	}
	return (ip[0] & 0xfe) == 0xfc
}

// IsIPv6Multicast checks if an IPv6 address is multicast (ff00::/8)
func IsIPv6Multicast(ip net.IP) bool {
	ip = ip.To16()
	if ip == nil {
		return false
	}
	return ip[0] == 0xff
}

// IsIPv6Global checks if an IPv6 address is global unicast
func IsIPv6Global(ip net.IP) bool {
	ip = ip.To16()
	if ip == nil {
		return false
	}
	// Not link-local, not unique local, not multicast, not loopback
	return !IsIPv6LinkLocal(ip) && !IsIPv6UniqueLocal(ip) && !IsIPv6Multicast(ip) && !ip.IsLoopback()
}

// GetIPv6AddressType returns the type of IPv6 address
func GetIPv6AddressType(ip net.IP) string {
	ip = ip.To16()
	if ip == nil {
		return "Invalid"
	}

	if ip.IsLoopback() {
		return "Loopback"
	}
	if IsIPv6LinkLocal(ip) {
		return "Link-Local"
	}
	if IsIPv6UniqueLocal(ip) {
		return "Unique-Local"
	}
	if IsIPv6Multicast(ip) {
		return "Multicast"
	}
	if IsIPv6Global(ip) {
		return "Global"
	}
	return "Unknown"
}
