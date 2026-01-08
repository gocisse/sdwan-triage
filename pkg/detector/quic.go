package detector

import (
	"github.com/gocisse/sdwan-triage/pkg/models"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// QUICAnalyzer handles QUIC packet analysis
type QUICAnalyzer struct{}

// NewQUICAnalyzer creates a new QUIC analyzer
func NewQUICAnalyzer() *QUICAnalyzer {
	return &QUICAnalyzer{}
}

// Analyze processes UDP packets for QUIC traffic
func (q *QUICAnalyzer) Analyze(packet gopacket.Packet, state *models.AnalysisState, report *models.TriageReport) {
	udpLayer := packet.Layer(layers.LayerTypeUDP)
	if udpLayer == nil {
		return
	}

	udp, ok := udpLayer.(*layers.UDP)
	if !ok || len(udp.Payload) < 5 {
		return
	}

	// Get IP info (supports IPv4 and IPv6)
	ipInfo := ExtractIPInfo(packet)
	if ipInfo == nil {
		return
	}
	srcIP := ipInfo.SrcIP
	dstIP := ipInfo.DstIP

	srcPort := uint16(udp.SrcPort)
	dstPort := uint16(udp.DstPort)

	// Check for QUIC traffic (typically on port 443)
	if !isQUICPacket(udp.Payload) {
		return
	}

	// Extract server name from QUIC Initial packet
	serverName := extractQUICServerName(udp.Payload)

	// Check if already recorded
	for _, existing := range report.QUICFlows {
		if existing.SrcIP == srcIP && existing.DstIP == dstIP &&
			existing.SrcPort == srcPort && existing.DstPort == dstPort {
			return
		}
	}

	flow := models.UDPFlow{
		SrcIP:      srcIP,
		SrcPort:    srcPort,
		DstIP:      dstIP,
		DstPort:    dstPort,
		ServerName: serverName,
	}

	report.QUICFlows = append(report.QUICFlows, flow)

	// Add timeline event
	timestamp := float64(packet.Metadata().Timestamp.UnixNano()) / 1e9
	event := models.TimelineEvent{
		Timestamp:     timestamp,
		EventType:     "QUIC Connection",
		SourceIP:      srcIP,
		DestinationIP: dstIP,
		Protocol:      "QUIC",
		Detail:        "QUIC connection to " + serverName,
	}
	srcPortPtr := srcPort
	dstPortPtr := dstPort
	event.SourcePort = &srcPortPtr
	event.DestinationPort = &dstPortPtr
	report.Timeline = append(report.Timeline, event)
}

// isQUICPacket checks if payload looks like QUIC
func isQUICPacket(payload []byte) bool {
	if len(payload) < 5 {
		return false
	}

	// QUIC packets have specific header formats
	// Long header: first bit is 1
	// Short header: first bit is 0
	firstByte := payload[0]

	// Check for QUIC long header (Initial, 0-RTT, Handshake, Retry)
	if firstByte&0x80 != 0 {
		// Long header - check version field
		if len(payload) >= 5 {
			// Version is at bytes 1-4
			// QUIC v1: 0x00000001
			// QUIC v2: 0x6b3343cf
			version := uint32(payload[1])<<24 | uint32(payload[2])<<16 | uint32(payload[3])<<8 | uint32(payload[4])
			if version == 0x00000001 || version == 0x6b3343cf || version == 0xff000000 {
				return true
			}
		}
	}

	return false
}

// extractQUICServerName extracts SNI from QUIC Initial packet
func extractQUICServerName(payload []byte) string {
	if len(payload) < 1200 { // QUIC Initial packets are typically padded to 1200+ bytes
		return ""
	}

	// This is a simplified extraction - full QUIC parsing is complex
	// Look for TLS ClientHello SNI extension within the QUIC payload

	// Skip QUIC header and look for TLS ClientHello pattern
	for i := 0; i < len(payload)-50; i++ {
		// Look for TLS handshake marker (0x16 0x03)
		if payload[i] == 0x16 && i+1 < len(payload) && payload[i+1] == 0x03 {
			// Try to extract SNI from this position
			if sni := extractSNIFromOffset(payload, i); sni != "" {
				return sni
			}
		}

		// Also look for ClientHello type (0x01) after crypto frame
		if payload[i] == 0x01 && i+4 < len(payload) {
			// Check if this looks like a ClientHello
			length := int(payload[i+1])<<16 | int(payload[i+2])<<8 | int(payload[i+3])
			if length > 0 && length < 10000 && i+4+length <= len(payload) {
				if sni := extractSNIFromClientHello(payload[i:], length+4); sni != "" {
					return sni
				}
			}
		}
	}

	return ""
}

// extractSNIFromOffset tries to extract SNI from a TLS record at given offset
func extractSNIFromOffset(payload []byte, offset int) string {
	if offset+5 >= len(payload) {
		return ""
	}

	// Skip TLS record header
	recordLen := int(payload[offset+3])<<8 | int(payload[offset+4])
	if offset+5+recordLen > len(payload) {
		return ""
	}

	return extractSNIFromClientHello(payload[offset+5:], recordLen)
}

// extractSNIFromClientHello extracts SNI from ClientHello message
func extractSNIFromClientHello(data []byte, maxLen int) string {
	if len(data) < 4 || data[0] != 0x01 { // ClientHello
		return ""
	}

	// Skip handshake header (4 bytes) + version (2) + random (32)
	pos := 38
	if pos >= len(data) || pos >= maxLen {
		return ""
	}

	// Skip session ID
	sessionIDLen := int(data[pos])
	pos += 1 + sessionIDLen
	if pos+2 >= len(data) || pos >= maxLen {
		return ""
	}

	// Skip cipher suites
	cipherSuitesLen := int(data[pos])<<8 | int(data[pos+1])
	pos += 2 + cipherSuitesLen
	if pos >= len(data) || pos >= maxLen {
		return ""
	}

	// Skip compression methods
	compressionLen := int(data[pos])
	pos += 1 + compressionLen
	if pos+2 >= len(data) || pos >= maxLen {
		return ""
	}

	// Parse extensions
	extensionsLen := int(data[pos])<<8 | int(data[pos+1])
	pos += 2

	extensionsEnd := pos + extensionsLen
	if extensionsEnd > len(data) {
		extensionsEnd = len(data)
	}
	if extensionsEnd > maxLen {
		extensionsEnd = maxLen
	}

	for pos+4 <= extensionsEnd {
		extType := int(data[pos])<<8 | int(data[pos+1])
		extLen := int(data[pos+2])<<8 | int(data[pos+3])
		pos += 4

		if extType == 0 { // SNI extension
			if pos+extLen <= extensionsEnd && extLen > 5 {
				// Skip SNI list length (2 bytes) and type (1 byte)
				sniLen := int(data[pos+3])<<8 | int(data[pos+4])
				if pos+5+sniLen <= extensionsEnd && sniLen > 0 && sniLen < 256 {
					return string(data[pos+5 : pos+5+sniLen])
				}
			}
		}

		pos += extLen
	}

	return ""
}
