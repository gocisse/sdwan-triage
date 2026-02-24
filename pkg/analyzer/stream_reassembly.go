package analyzer

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/gocisse/sdwan-triage/pkg/models"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// StreamReassembler handles TCP/UDP stream reassembly
type StreamReassembler struct {
	state           *models.StreamReassemblyState
	maxBytesPerFlow int
	verbose         bool
	lastSeqNum      map[string]uint32 // Track last sequence number per flow for retransmit detection
	lastTimestamp   map[string]int64  // Track last timestamp per flow for gap detection
	mu              sync.RWMutex      // Protects state and maps for concurrent access
}

// NewStreamReassembler creates a new stream reassembler
func NewStreamReassembler(verbose bool) *StreamReassembler {
	return &StreamReassembler{
		state:           models.NewStreamReassemblyState(),
		maxBytesPerFlow: 10 * 1024, // 10KB per direction
		verbose:         verbose,
		lastSeqNum:      make(map[string]uint32),
		lastTimestamp:   make(map[string]int64),
	}
}

// SetMaxBytesPerFlow sets the maximum bytes to capture per flow direction
func (sr *StreamReassembler) SetMaxBytesPerFlow(maxBytes int) {
	sr.maxBytesPerFlow = maxBytes
	sr.state.MaxBytesPerFlow = maxBytes
}

// CleanupStaleFlows removes streams that haven't been seen for the specified duration
// This should be called periodically (e.g., every 10,000 packets) to prevent memory bloat
func (sr *StreamReassembler) CleanupStaleFlows(maxAge time.Duration) int {
	sr.mu.Lock()
	defer sr.mu.Unlock()

	now := time.Now()
	evicted := 0

	for flowID, stream := range sr.state.Streams {
		if now.Sub(stream.LastSeen) > maxAge {
			delete(sr.state.Streams, flowID)
			delete(sr.lastSeqNum, flowID)
			delete(sr.lastTimestamp, flowID)
			evicted++
		}
	}

	// Also clean up direction-specific entries in tracking maps
	for dirFlowKey := range sr.lastSeqNum {
		// Extract base flowID (remove direction suffix)
		baseFlowID := dirFlowKey
		if idx := strings.LastIndex(dirFlowKey, "/"); idx > 0 {
			baseFlowID = dirFlowKey[:idx]
		}
		if _, exists := sr.state.Streams[baseFlowID]; !exists {
			delete(sr.lastSeqNum, dirFlowKey)
		}
	}

	return evicted
}

// GetStreamCount returns the number of streams currently being tracked
func (sr *StreamReassembler) GetStreamCount() int {
	sr.mu.RLock()
	defer sr.mu.RUnlock()
	return len(sr.state.Streams)
}

// ProcessPacket processes a packet for stream reassembly
func (sr *StreamReassembler) ProcessPacket(packet gopacket.Packet) {
	// Get network layer
	networkLayer := packet.NetworkLayer()
	if networkLayer == nil {
		return
	}

	srcIP := networkLayer.NetworkFlow().Src().String()
	dstIP := networkLayer.NetworkFlow().Dst().String()

	// Get transport layer
	transportLayer := packet.TransportLayer()
	if transportLayer == nil {
		return
	}

	var srcPort, dstPort uint16
	var protocol string
	var seqNum uint32
	var payload []byte

	switch t := transportLayer.(type) {
	case *layers.TCP:
		srcPort = uint16(t.SrcPort)
		dstPort = uint16(t.DstPort)
		protocol = "TCP"
		seqNum = t.Seq
		payload = t.Payload
	case *layers.UDP:
		srcPort = uint16(t.SrcPort)
		dstPort = uint16(t.DstPort)
		protocol = "UDP"
		payload = t.Payload
	default:
		return
	}

	if len(payload) == 0 {
		return
	}

	// Create flow ID (bidirectional - normalize to lower IP:port first)
	flowID := sr.createFlowID(srcIP, srcPort, dstIP, dstPort, protocol)
	reverseFlowID := sr.createFlowID(dstIP, dstPort, srcIP, srcPort, protocol)

	// Check if we already have this flow (in either direction)
	stream, exists := sr.state.Streams[flowID]
	if !exists {
		stream, exists = sr.state.Streams[reverseFlowID]
		if exists {
			flowID = reverseFlowID
		}
	}

	// Create new stream if needed
	if !exists {
		if len(sr.state.Streams) >= sr.state.MaxFlowsToTrack {
			return // Don't track more flows
		}

		stream = &models.StreamData{
			FlowID:      flowID,
			SrcIP:       srcIP,
			SrcPort:     srcPort,
			DstIP:       dstIP,
			DstPort:     dstPort,
			Protocol:    protocol,
			Application: sr.detectApplication(srcPort, dstPort, payload),
			Segments:    make([]models.StreamSegment, 0),
			FirstSeen:   packet.Metadata().Timestamp,
			LastSeen:    packet.Metadata().Timestamp,
		}
		sr.state.Streams[flowID] = stream
	}

	// Determine direction
	direction := "client_to_server"
	if srcIP == stream.DstIP && srcPort == stream.DstPort {
		direction = "server_to_client"
	}

	// Check if we've exceeded the byte limit for this direction
	directionBytes := sr.getDirectionBytes(stream, direction)
	if directionBytes >= sr.maxBytesPerFlow {
		if stream.TruncatedAt == 0 {
			stream.TruncatedAt = int(stream.TotalBytes)
		}
		return
	}

	// Truncate payload if needed
	remainingBytes := sr.maxBytesPerFlow - directionBytes
	if len(payload) > remainingBytes {
		payload = payload[:remainingBytes]
	}

	// Detect anomalies
	dirFlowKey := flowID + "/" + direction
	var isRetransmit, isOutOfOrder bool
	var gapFromPrev float64
	var anomalyReason string

	// Check for retransmission (same or lower seq num for TCP)
	if protocol == "TCP" && seqNum > 0 {
		if lastSeq, ok := sr.lastSeqNum[dirFlowKey]; ok {
			if seqNum <= lastSeq && seqNum != 0 {
				isRetransmit = true
				anomalyReason = "Retransmission detected"
			} else if seqNum > lastSeq+uint32(len(payload))+1000 {
				isOutOfOrder = true
				anomalyReason = "Out-of-order packet"
			}
		}
		sr.lastSeqNum[dirFlowKey] = seqNum
	}

	// Check for time gaps (>1 second gap is notable)
	currentTs := packet.Metadata().Timestamp.UnixNano()
	if lastTs, ok := sr.lastTimestamp[flowID]; ok {
		gapFromPrev = float64(currentTs-lastTs) / 1e9 // Convert to seconds
		if gapFromPrev > 1.0 && anomalyReason == "" {
			anomalyReason = fmt.Sprintf("%.1fs gap from previous packet", gapFromPrev)
		}
	}
	sr.lastTimestamp[flowID] = currentTs

	// Check for TCP RST flag
	var hasReset bool
	if tcpLayer, ok := transportLayer.(*layers.TCP); ok && tcpLayer.RST {
		hasReset = true
		anomalyReason = "Connection reset (RST)"
	}

	// Generate plain English summary
	plainEnglish := sr.generatePlainEnglish(stream.Application, payload, direction)

	// Create segment
	segment := models.StreamSegment{
		Direction:     direction,
		Timestamp:     packet.Metadata().Timestamp,
		SeqNum:        seqNum,
		Data:          payload,
		DataHex:       sr.formatHex(payload),
		DataASCII:     sr.formatASCII(payload),
		DataDecoded:   sr.decodePayload(stream.Application, payload, direction),
		PlainEnglish:  plainEnglish,
		Length:        len(payload),
		IsRetransmit:  isRetransmit,
		IsOutOfOrder:  isOutOfOrder,
		HasReset:      hasReset,
		GapFromPrev:   gapFromPrev,
		AnomalyReason: anomalyReason,
	}

	stream.Segments = append(stream.Segments, segment)
	stream.TotalBytes += uint64(len(payload))
	stream.PacketCount++
	stream.LastSeen = packet.Metadata().Timestamp
	stream.Duration = stream.LastSeen.Sub(stream.FirstSeen).Seconds()
}

// createFlowID creates a normalized flow ID
func (sr *StreamReassembler) createFlowID(srcIP string, srcPort uint16, dstIP string, dstPort uint16, protocol string) string {
	// Normalize: lower IP:port comes first
	src := fmt.Sprintf("%s:%d", srcIP, srcPort)
	dst := fmt.Sprintf("%s:%d", dstIP, dstPort)
	if src < dst {
		return fmt.Sprintf("%s->%s/%s", src, dst, protocol)
	}
	return fmt.Sprintf("%s->%s/%s", dst, src, protocol)
}

// getDirectionBytes returns total bytes for a direction
func (sr *StreamReassembler) getDirectionBytes(stream *models.StreamData, direction string) int {
	total := 0
	for _, seg := range stream.Segments {
		if seg.Direction == direction {
			total += seg.Length
		}
	}
	return total
}

// detectApplication detects the application protocol
func (sr *StreamReassembler) detectApplication(srcPort, dstPort uint16, payload []byte) string {
	// Check well-known ports
	ports := []uint16{srcPort, dstPort}
	for _, port := range ports {
		switch port {
		case 80:
			return "HTTP"
		case 443:
			if len(payload) > 0 && payload[0] == 0x16 {
				return "TLS"
			}
			return "HTTPS"
		case 53:
			return "DNS"
		case 22:
			return "SSH"
		case 21:
			return "FTP"
		case 25, 587:
			return "SMTP"
		case 110:
			return "POP3"
		case 143:
			return "IMAP"
		case 5060, 5061:
			return "SIP"
		case 3389:
			return "RDP"
		case 445:
			return "SMB"
		case 389, 636:
			return "LDAP"
		case 88:
			return "Kerberos"
		}
	}

	// Check payload signatures
	if len(payload) >= 4 {
		// HTTP methods
		if strings.HasPrefix(string(payload), "GET ") ||
			strings.HasPrefix(string(payload), "POST ") ||
			strings.HasPrefix(string(payload), "PUT ") ||
			strings.HasPrefix(string(payload), "DELETE ") ||
			strings.HasPrefix(string(payload), "HEAD ") ||
			strings.HasPrefix(string(payload), "HTTP/") {
			return "HTTP"
		}
		// TLS ClientHello
		if payload[0] == 0x16 && payload[1] == 0x03 {
			return "TLS"
		}
		// SSH
		if strings.HasPrefix(string(payload), "SSH-") {
			return "SSH"
		}
		// SIP
		if strings.HasPrefix(string(payload), "SIP/") ||
			strings.HasPrefix(string(payload), "INVITE ") ||
			strings.HasPrefix(string(payload), "REGISTER ") {
			return "SIP"
		}
	}

	return "Unknown"
}

// formatHex formats payload as hex dump
func (sr *StreamReassembler) formatHex(data []byte) string {
	if len(data) == 0 {
		return ""
	}

	var sb strings.Builder
	for i := 0; i < len(data); i += 16 {
		// Offset
		sb.WriteString(fmt.Sprintf("%08x  ", i))

		// Hex bytes
		for j := 0; j < 16; j++ {
			if i+j < len(data) {
				sb.WriteString(fmt.Sprintf("%02x ", data[i+j]))
			} else {
				sb.WriteString("   ")
			}
			if j == 7 {
				sb.WriteString(" ")
			}
		}

		// ASCII
		sb.WriteString(" |")
		for j := 0; j < 16 && i+j < len(data); j++ {
			b := data[i+j]
			if b >= 32 && b < 127 {
				sb.WriteByte(b)
			} else {
				sb.WriteByte('.')
			}
		}
		sb.WriteString("|\n")
	}

	return sb.String()
}

// formatASCII formats payload as ASCII with non-printables as dots
func (sr *StreamReassembler) formatASCII(data []byte) string {
	var sb strings.Builder
	for _, b := range data {
		if b >= 32 && b < 127 {
			sb.WriteByte(b)
		} else if b == '\n' || b == '\r' || b == '\t' {
			sb.WriteByte(b)
		} else {
			sb.WriteByte('.')
		}
	}
	return sb.String()
}

// decodePayload attempts to decode payload based on application protocol
func (sr *StreamReassembler) decodePayload(app string, data []byte, direction string) string {
	if len(data) == 0 {
		return ""
	}

	switch app {
	case "HTTP":
		return sr.decodeHTTP(data, direction)
	case "TLS", "HTTPS":
		return sr.decodeTLS(data, direction)
	case "DNS":
		return sr.decodeDNS(data)
	case "SIP":
		return sr.decodeSIP(data)
	default:
		// Return first line if it looks like text
		if sr.isTextData(data) {
			lines := strings.SplitN(string(data), "\n", 2)
			if len(lines) > 0 && len(lines[0]) > 0 {
				return strings.TrimSpace(lines[0])
			}
		}
		return fmt.Sprintf("[Binary data: %d bytes]", len(data))
	}
}

// isTextData checks if data appears to be text
func (sr *StreamReassembler) isTextData(data []byte) bool {
	if len(data) == 0 {
		return false
	}
	textChars := 0
	for _, b := range data[:min(len(data), 100)] {
		if unicode.IsPrint(rune(b)) || b == '\n' || b == '\r' || b == '\t' {
			textChars++
		}
	}
	return float64(textChars)/float64(min(len(data), 100)) > 0.8
}

// decodeHTTP decodes HTTP request/response
func (sr *StreamReassembler) decodeHTTP(data []byte, direction string) string {
	lines := strings.SplitN(string(data), "\r\n", 10)
	if len(lines) == 0 {
		return ""
	}

	var sb strings.Builder
	if direction == "client_to_server" {
		// Request
		sb.WriteString("📤 ")
	} else {
		// Response
		sb.WriteString("📥 ")
	}
	sb.WriteString(strings.TrimSpace(lines[0]))

	// Add important headers
	for i := 1; i < len(lines) && i < 5; i++ {
		line := strings.TrimSpace(lines[i])
		if line == "" {
			break
		}
		if strings.HasPrefix(strings.ToLower(line), "host:") ||
			strings.HasPrefix(strings.ToLower(line), "content-type:") ||
			strings.HasPrefix(strings.ToLower(line), "content-length:") {
			sb.WriteString("\n  " + line)
		}
	}

	return sb.String()
}

// decodeTLS decodes TLS handshake messages
func (sr *StreamReassembler) decodeTLS(data []byte, direction string) string {
	if len(data) < 5 {
		return "[TLS: Incomplete]"
	}

	contentType := data[0]
	version := uint16(data[1])<<8 | uint16(data[2])

	var versionStr string
	switch version {
	case 0x0301:
		versionStr = "TLS 1.0"
	case 0x0302:
		versionStr = "TLS 1.1"
	case 0x0303:
		versionStr = "TLS 1.2"
	case 0x0304:
		versionStr = "TLS 1.3"
	default:
		versionStr = fmt.Sprintf("0x%04x", version)
	}

	var typeStr string
	switch contentType {
	case 0x14:
		typeStr = "ChangeCipherSpec"
	case 0x15:
		typeStr = "Alert"
	case 0x16:
		typeStr = "Handshake"
		if len(data) > 5 {
			hsType := data[5]
			switch hsType {
			case 0x01:
				typeStr = "ClientHello"
				// Try to extract SNI
				if sni := sr.extractSNI(data); sni != "" {
					typeStr += " (SNI: " + sni + ")"
				}
			case 0x02:
				typeStr = "ServerHello"
			case 0x0b:
				typeStr = "Certificate"
			case 0x0c:
				typeStr = "ServerKeyExchange"
			case 0x0d:
				typeStr = "CertificateRequest"
			case 0x0e:
				typeStr = "ServerHelloDone"
			case 0x10:
				typeStr = "ClientKeyExchange"
			case 0x14:
				typeStr = "Finished"
			}
		}
	case 0x17:
		typeStr = "ApplicationData"
	default:
		typeStr = fmt.Sprintf("Type 0x%02x", contentType)
	}

	icon := "🔒"
	if direction == "client_to_server" {
		icon = "📤🔒"
	} else {
		icon = "📥🔒"
	}

	return fmt.Sprintf("%s %s %s", icon, versionStr, typeStr)
}

// extractSNI extracts Server Name Indication from TLS ClientHello
func (sr *StreamReassembler) extractSNI(data []byte) string {
	// Simplified SNI extraction - look for the SNI extension
	if len(data) < 50 {
		return ""
	}

	// Search for SNI extension (type 0x0000)
	for i := 0; i < len(data)-10; i++ {
		if data[i] == 0x00 && data[i+1] == 0x00 { // SNI extension type
			// Check if this looks like an SNI extension
			if i+4 < len(data) {
				extLen := int(data[i+2])<<8 | int(data[i+3])
				if extLen > 0 && extLen < 256 && i+4+extLen <= len(data) {
					// Try to extract the hostname
					if i+9 < len(data) {
						nameLen := int(data[i+7])<<8 | int(data[i+8])
						if nameLen > 0 && nameLen < 256 && i+9+nameLen <= len(data) {
							name := string(data[i+9 : i+9+nameLen])
							if sr.isValidHostname(name) {
								return name
							}
						}
					}
				}
			}
		}
	}
	return ""
}

// isValidHostname checks if a string looks like a valid hostname
func (sr *StreamReassembler) isValidHostname(s string) bool {
	if len(s) < 3 || len(s) > 253 {
		return false
	}
	for _, c := range s {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') || c == '.' || c == '-') {
			return false
		}
	}
	return strings.Contains(s, ".")
}

// decodeDNS decodes DNS query/response
func (sr *StreamReassembler) decodeDNS(data []byte) string {
	if len(data) < 12 {
		return "[DNS: Incomplete]"
	}

	// Check if it's a query or response
	flags := uint16(data[2])<<8 | uint16(data[3])
	isResponse := (flags & 0x8000) != 0

	// Extract question count
	qdCount := int(data[4])<<8 | int(data[5])

	if qdCount > 0 && len(data) > 12 {
		// Try to extract the query name
		name := sr.extractDNSName(data, 12)
		if name != "" {
			if isResponse {
				rcode := flags & 0x000F
				var status string
				switch rcode {
				case 0:
					status = "OK"
				case 1:
					status = "Format Error"
				case 2:
					status = "Server Failure"
				case 3:
					status = "NXDOMAIN"
				case 5:
					status = "Refused"
				default:
					status = fmt.Sprintf("RCODE %d", rcode)
				}
				return fmt.Sprintf("📥 DNS Response: %s (%s)", name, status)
			}
			return fmt.Sprintf("📤 DNS Query: %s", name)
		}
	}

	if isResponse {
		return "📥 DNS Response"
	}
	return "📤 DNS Query"
}

// extractDNSName extracts a DNS name from the packet
func (sr *StreamReassembler) extractDNSName(data []byte, offset int) string {
	var name strings.Builder
	i := offset
	for i < len(data) && i < offset+256 {
		labelLen := int(data[i])
		if labelLen == 0 {
			break
		}
		if labelLen > 63 || i+1+labelLen > len(data) {
			break
		}
		if name.Len() > 0 {
			name.WriteByte('.')
		}
		name.Write(data[i+1 : i+1+labelLen])
		i += 1 + labelLen
	}
	return name.String()
}

// decodeSIP decodes SIP message
func (sr *StreamReassembler) decodeSIP(data []byte) string {
	lines := strings.SplitN(string(data), "\r\n", 5)
	if len(lines) == 0 {
		return "[SIP: Empty]"
	}

	firstLine := strings.TrimSpace(lines[0])
	if strings.HasPrefix(firstLine, "SIP/") {
		// Response
		return "📥 " + firstLine
	}
	// Request
	return "📤 " + firstLine
}

// decodeSMB decodes SMB/CIFS messages
func (sr *StreamReassembler) decodeSMB(data []byte, direction string) string {
	if len(data) < 4 {
		return "[SMB: Incomplete]"
	}

	// Check for SMB header (0xFF 'S' 'M' 'B' for SMB1, 0xFE 'S' 'M' 'B' for SMB2/3)
	isSMB1 := len(data) >= 4 && data[0] == 0xFF && data[1] == 'S' && data[2] == 'M' && data[3] == 'B'
	isSMB2 := len(data) >= 4 && data[0] == 0xFE && data[1] == 'S' && data[2] == 'M' && data[3] == 'B'

	icon := "📁"
	if direction == "client_to_server" {
		icon = "📤📁"
	} else {
		icon = "📥📁"
	}

	if isSMB2 && len(data) >= 16 {
		// SMB2/3 command at offset 12
		cmd := binary.LittleEndian.Uint16(data[12:14])
		cmdName := sr.getSMB2CommandName(cmd)
		return fmt.Sprintf("%s SMB2 %s", icon, cmdName)
	}

	if isSMB1 && len(data) >= 5 {
		// SMB1 command at offset 4
		cmd := data[4]
		cmdName := sr.getSMB1CommandName(cmd)
		return fmt.Sprintf("%s SMB1 %s", icon, cmdName)
	}

	return fmt.Sprintf("%s SMB Data (%d bytes)", icon, len(data))
}

// getSMB2CommandName returns human-readable SMB2 command name
func (sr *StreamReassembler) getSMB2CommandName(cmd uint16) string {
	commands := map[uint16]string{
		0x0000: "Negotiate",
		0x0001: "Session Setup",
		0x0002: "Session Logoff",
		0x0003: "Tree Connect",
		0x0004: "Tree Disconnect",
		0x0005: "Create (Open File)",
		0x0006: "Close",
		0x0007: "Flush",
		0x0008: "Read",
		0x0009: "Write",
		0x000A: "Lock",
		0x000B: "IOCTL",
		0x000C: "Cancel",
		0x000D: "Echo",
		0x000E: "Query Directory",
		0x000F: "Change Notify",
		0x0010: "Query Info",
		0x0011: "Set Info",
		0x0012: "Oplock Break",
	}
	if name, ok := commands[cmd]; ok {
		return name
	}
	return fmt.Sprintf("Command 0x%04X", cmd)
}

// getSMB1CommandName returns human-readable SMB1 command name
func (sr *StreamReassembler) getSMB1CommandName(cmd byte) string {
	commands := map[byte]string{
		0x00: "Create Directory",
		0x01: "Delete Directory",
		0x02: "Open",
		0x03: "Create",
		0x04: "Close",
		0x05: "Flush",
		0x06: "Delete",
		0x07: "Rename",
		0x08: "Query Info",
		0x09: "Set Info",
		0x0A: "Read",
		0x0B: "Write",
		0x24: "Locking AndX",
		0x25: "Transaction",
		0x2B: "Echo",
		0x2D: "Open AndX",
		0x2E: "Read AndX",
		0x2F: "Write AndX",
		0x32: "Transaction2",
		0x72: "Negotiate",
		0x73: "Session Setup AndX",
		0x74: "Logoff AndX",
		0x75: "Tree Connect AndX",
		0x71: "Tree Disconnect",
	}
	if name, ok := commands[cmd]; ok {
		return name
	}
	return fmt.Sprintf("Command 0x%02X", cmd)
}

// decodeSNMP decodes SNMP messages
func (sr *StreamReassembler) decodeSNMP(data []byte, direction string) string {
	if len(data) < 10 {
		return "[SNMP: Incomplete]"
	}

	// SNMP uses ASN.1 BER encoding
	// First byte should be 0x30 (SEQUENCE)
	if data[0] != 0x30 {
		return fmt.Sprintf("[SNMP: Invalid header (%d bytes)]", len(data))
	}

	icon := "📊"
	if direction == "client_to_server" {
		icon = "📤📊"
	} else {
		icon = "📥📊"
	}

	// Try to find the PDU type (GetRequest, GetResponse, etc.)
	// This is a simplified parser - real SNMP parsing is complex
	for i := 2; i < len(data)-2 && i < 50; i++ {
		pduType := data[i]
		switch pduType {
		case 0xA0:
			return fmt.Sprintf("%s SNMP GetRequest", icon)
		case 0xA1:
			return fmt.Sprintf("%s SNMP GetNextRequest", icon)
		case 0xA2:
			return fmt.Sprintf("%s SNMP GetResponse", icon)
		case 0xA3:
			return fmt.Sprintf("%s SNMP SetRequest", icon)
		case 0xA4:
			return fmt.Sprintf("%s SNMP Trap", icon)
		case 0xA5:
			return fmt.Sprintf("%s SNMP GetBulkRequest", icon)
		case 0xA6:
			return fmt.Sprintf("%s SNMP InformRequest", icon)
		case 0xA7:
			return fmt.Sprintf("%s SNMP SNMPv2-Trap", icon)
		}
	}

	return fmt.Sprintf("%s SNMP Message (%d bytes)", icon, len(data))
}

// generatePlainEnglish generates a human-readable summary of the payload
func (sr *StreamReassembler) generatePlainEnglish(app string, data []byte, direction string) string {
	if len(data) == 0 {
		return "[Empty payload]"
	}

	dirLabel := "Client → Server"
	if direction == "server_to_client" {
		dirLabel = "Server → Client"
	}

	switch app {
	case "HTTP":
		return sr.generateHTTPPlainEnglish(data, direction)
	case "TLS", "HTTPS":
		return sr.generateTLSPlainEnglish(data, direction)
	case "DNS":
		return sr.generateDNSPlainEnglish(data)
	case "SMB":
		return sr.decodeSMB(data, direction)
	case "SIP":
		return sr.generateSIPPlainEnglish(data, direction)
	case "SSH":
		return sr.generateSSHPlainEnglish(data, direction)
	case "LDAP":
		return fmt.Sprintf("%s: LDAP Message (%d bytes)", dirLabel, len(data))
	case "Kerberos":
		return fmt.Sprintf("%s: Kerberos Authentication (%d bytes)", dirLabel, len(data))
	case "RDP":
		return fmt.Sprintf("%s: Remote Desktop Data (%d bytes)", dirLabel, len(data))
	default:
		// Check if it's text or binary
		if sr.isTextData(data) {
			preview := strings.TrimSpace(string(data))
			if len(preview) > 60 {
				preview = preview[:60] + "..."
			}
			// Replace newlines for display
			preview = strings.ReplaceAll(preview, "\r\n", " ")
			preview = strings.ReplaceAll(preview, "\n", " ")
			return fmt.Sprintf("%s: \"%s\"", dirLabel, preview)
		}
		return fmt.Sprintf("%s: [Binary data: %d bytes]", dirLabel, len(data))
	}
}

// generateHTTPPlainEnglish generates plain English for HTTP
func (sr *StreamReassembler) generateHTTPPlainEnglish(data []byte, direction string) string {
	lines := strings.SplitN(string(data), "\r\n", 5)
	if len(lines) == 0 {
		return "[HTTP: Empty]"
	}

	firstLine := strings.TrimSpace(lines[0])

	if direction == "client_to_server" {
		// Request - extract method and path
		parts := strings.SplitN(firstLine, " ", 3)
		if len(parts) >= 2 {
			method := parts[0]
			path := parts[1]
			if len(path) > 50 {
				path = path[:50] + "..."
			}
			// Find Host header
			host := ""
			for _, line := range lines[1:] {
				if strings.HasPrefix(strings.ToLower(line), "host:") {
					host = strings.TrimSpace(strings.TrimPrefix(line, "Host:"))
					host = strings.TrimSpace(strings.TrimPrefix(host, "host:"))
					break
				}
			}
			if host != "" {
				return fmt.Sprintf("Client → Server: HTTP %s %s (Host: %s)", method, path, host)
			}
			return fmt.Sprintf("Client → Server: HTTP %s %s", method, path)
		}
	} else {
		// Response - extract status
		if strings.HasPrefix(firstLine, "HTTP/") {
			parts := strings.SplitN(firstLine, " ", 3)
			if len(parts) >= 2 {
				status := parts[1]
				reason := ""
				if len(parts) >= 3 {
					reason = parts[2]
				}
				// Find Content-Type
				contentType := ""
				for _, line := range lines[1:] {
					if strings.HasPrefix(strings.ToLower(line), "content-type:") {
						contentType = strings.TrimSpace(strings.SplitN(line, ":", 2)[1])
						if idx := strings.Index(contentType, ";"); idx > 0 {
							contentType = contentType[:idx]
						}
						break
					}
				}
				if contentType != "" {
					return fmt.Sprintf("Server → Client: HTTP %s %s (%s)", status, reason, contentType)
				}
				return fmt.Sprintf("Server → Client: HTTP %s %s", status, reason)
			}
		}
	}

	return fmt.Sprintf("HTTP Data (%d bytes)", len(data))
}

// generateTLSPlainEnglish generates plain English for TLS
func (sr *StreamReassembler) generateTLSPlainEnglish(data []byte, direction string) string {
	if len(data) < 5 {
		return "[TLS: Incomplete]"
	}

	dirLabel := "Client → Server"
	if direction == "server_to_client" {
		dirLabel = "Server → Client"
	}

	contentType := data[0]
	version := uint16(data[1])<<8 | uint16(data[2])

	var versionStr string
	switch version {
	case 0x0301:
		versionStr = "TLS 1.0"
	case 0x0302:
		versionStr = "TLS 1.1"
	case 0x0303:
		versionStr = "TLS 1.2"
	case 0x0304:
		versionStr = "TLS 1.3"
	default:
		versionStr = "TLS"
	}

	switch contentType {
	case 0x14:
		return fmt.Sprintf("%s: %s ChangeCipherSpec (encryption starting)", dirLabel, versionStr)
	case 0x15:
		alertLevel := "warning"
		if len(data) > 5 && data[5] == 2 {
			alertLevel = "fatal"
		}
		return fmt.Sprintf("%s: %s Alert (%s)", dirLabel, versionStr, alertLevel)
	case 0x16:
		if len(data) > 5 {
			hsType := data[5]
			switch hsType {
			case 0x01:
				sni := sr.extractSNI(data)
				if sni != "" {
					return fmt.Sprintf("%s: %s ClientHello → %s", dirLabel, versionStr, sni)
				}
				return fmt.Sprintf("%s: %s ClientHello (initiating connection)", dirLabel, versionStr)
			case 0x02:
				return fmt.Sprintf("%s: %s ServerHello (accepting connection)", dirLabel, versionStr)
			case 0x0b:
				return fmt.Sprintf("%s: %s Certificate (server identity)", dirLabel, versionStr)
			case 0x0c:
				return fmt.Sprintf("%s: %s ServerKeyExchange", dirLabel, versionStr)
			case 0x0d:
				return fmt.Sprintf("%s: %s CertificateRequest (client auth required)", dirLabel, versionStr)
			case 0x0e:
				return fmt.Sprintf("%s: %s ServerHelloDone", dirLabel, versionStr)
			case 0x10:
				return fmt.Sprintf("%s: %s ClientKeyExchange", dirLabel, versionStr)
			case 0x14:
				return fmt.Sprintf("%s: %s Finished (handshake complete)", dirLabel, versionStr)
			default:
				return fmt.Sprintf("%s: %s Handshake (type %d)", dirLabel, versionStr, hsType)
			}
		}
		return fmt.Sprintf("%s: %s Handshake", dirLabel, versionStr)
	case 0x17:
		return fmt.Sprintf("%s: %s ApplicationData [encrypted: %d bytes]", dirLabel, versionStr, len(data)-5)
	default:
		return fmt.Sprintf("%s: %s Record (type 0x%02X)", dirLabel, versionStr, contentType)
	}
}

// generateDNSPlainEnglish generates plain English for DNS
func (sr *StreamReassembler) generateDNSPlainEnglish(data []byte) string {
	if len(data) < 12 {
		return "[DNS: Incomplete]"
	}

	flags := uint16(data[2])<<8 | uint16(data[3])
	isResponse := (flags & 0x8000) != 0
	qdCount := int(data[4])<<8 | int(data[5])

	if qdCount > 0 && len(data) > 12 {
		name := sr.extractDNSName(data, 12)
		if name != "" {
			if isResponse {
				rcode := flags & 0x000F
				switch rcode {
				case 0:
					return fmt.Sprintf("Server → Client: DNS Response for %s (found)", name)
				case 3:
					return fmt.Sprintf("Server → Client: DNS Response for %s (NOT FOUND)", name)
				default:
					return fmt.Sprintf("Server → Client: DNS Response for %s (error %d)", name, rcode)
				}
			}
			return fmt.Sprintf("Client → Server: DNS Query for %s", name)
		}
	}

	if isResponse {
		return "Server → Client: DNS Response"
	}
	return "Client → Server: DNS Query"
}

// generateSIPPlainEnglish generates plain English for SIP
func (sr *StreamReassembler) generateSIPPlainEnglish(data []byte, direction string) string {
	lines := strings.SplitN(string(data), "\r\n", 3)
	if len(lines) == 0 {
		return "[SIP: Empty]"
	}

	dirLabel := "Client → Server"
	if direction == "server_to_client" {
		dirLabel = "Server → Client"
	}

	firstLine := strings.TrimSpace(lines[0])

	if strings.HasPrefix(firstLine, "SIP/") {
		// Response
		parts := strings.SplitN(firstLine, " ", 3)
		if len(parts) >= 2 {
			return fmt.Sprintf("%s: SIP Response %s", dirLabel, strings.Join(parts[1:], " "))
		}
	} else {
		// Request
		parts := strings.SplitN(firstLine, " ", 2)
		if len(parts) >= 1 {
			method := parts[0]
			switch method {
			case "INVITE":
				return fmt.Sprintf("%s: SIP INVITE (starting call)", dirLabel)
			case "ACK":
				return fmt.Sprintf("%s: SIP ACK (call confirmed)", dirLabel)
			case "BYE":
				return fmt.Sprintf("%s: SIP BYE (ending call)", dirLabel)
			case "CANCEL":
				return fmt.Sprintf("%s: SIP CANCEL (canceling call)", dirLabel)
			case "REGISTER":
				return fmt.Sprintf("%s: SIP REGISTER (registering)", dirLabel)
			case "OPTIONS":
				return fmt.Sprintf("%s: SIP OPTIONS (capability query)", dirLabel)
			default:
				return fmt.Sprintf("%s: SIP %s", dirLabel, method)
			}
		}
	}

	return fmt.Sprintf("%s: SIP Message", dirLabel)
}

// generateSSHPlainEnglish generates plain English for SSH
func (sr *StreamReassembler) generateSSHPlainEnglish(data []byte, direction string) string {
	dirLabel := "Client → Server"
	if direction == "server_to_client" {
		dirLabel = "Server → Client"
	}

	if strings.HasPrefix(string(data), "SSH-") {
		// Version exchange
		version := strings.TrimSpace(strings.SplitN(string(data), "\n", 2)[0])
		return fmt.Sprintf("%s: %s (version exchange)", dirLabel, version)
	}

	// After version exchange, SSH is encrypted
	return fmt.Sprintf("%s: SSH Encrypted Data [%d bytes]", dirLabel, len(data))
}

// GetStreams returns all reassembled streams
func (sr *StreamReassembler) GetStreams() map[string]*models.StreamData {
	return sr.state.Streams
}

// GetStreamsSorted returns streams sorted by total bytes (descending)
func (sr *StreamReassembler) GetStreamsSorted() []*models.StreamData {
	streams := make([]*models.StreamData, 0, len(sr.state.Streams))
	for _, stream := range sr.state.Streams {
		streams = append(streams, stream)
	}
	sort.Slice(streams, func(i, j int) bool {
		return streams[i].TotalBytes > streams[j].TotalBytes
	})
	return streams
}

// GetTopStreams returns the top N streams by bytes
func (sr *StreamReassembler) GetTopStreams(n int) []*models.StreamData {
	sorted := sr.GetStreamsSorted()
	if len(sorted) > n {
		return sorted[:n]
	}
	return sorted
}

// FormatStreamForDisplay formats a stream for HTML display
func (sr *StreamReassembler) FormatStreamForDisplay(stream *models.StreamData) models.StreamViewData {
	view := models.StreamViewData{
		FlowID:      stream.FlowID,
		SrcIP:       stream.SrcIP,
		SrcPort:     stream.SrcPort,
		DstIP:       stream.DstIP,
		DstPort:     stream.DstPort,
		Protocol:    stream.Protocol,
		Application: stream.Application,
		Duration:    formatDuration(stream.Duration),
		TotalBytes:  formatBytes(stream.TotalBytes),
		PacketCount: stream.PacketCount,
		Segments:    make([]models.StreamSegmentView, 0, len(stream.Segments)),
	}

	// Create label
	appLabel := ""
	if stream.Application != "" && stream.Application != "Unknown" {
		appLabel = " (" + stream.Application + ")"
	}
	view.Label = fmt.Sprintf("%s:%d → %s:%d%s",
		stream.SrcIP, stream.SrcPort,
		stream.DstIP, stream.DstPort,
		appLabel)

	// Generate Wireshark filter
	if stream.Protocol == "TCP" {
		view.WiresharkFilter = fmt.Sprintf("(ip.addr == %s && ip.addr == %s && tcp.port == %d && tcp.port == %d)",
			stream.SrcIP, stream.DstIP, stream.SrcPort, stream.DstPort)
	} else {
		view.WiresharkFilter = fmt.Sprintf("(ip.addr == %s && ip.addr == %s && udp.port == %d && udp.port == %d)",
			stream.SrcIP, stream.DstIP, stream.SrcPort, stream.DstPort)
	}

	// Generate export filename
	view.ExportFilename = fmt.Sprintf("stream_%s_%d_to_%s_%d.pcap",
		strings.ReplaceAll(stream.SrcIP, ":", "-"), stream.SrcPort,
		strings.ReplaceAll(stream.DstIP, ":", "-"), stream.DstPort)

	// Format segments
	for i, seg := range stream.Segments {
		segView := models.StreamSegmentView{
			Timestamp:     seg.Timestamp.Format("15:04:05.000"),
			Length:        seg.Length,
			LengthDisplay: formatBytes(uint64(seg.Length)),
		}

		// Direction with clear labels
		if seg.Direction == "client_to_server" {
			segView.Direction = "→"
			segView.DirectionCSS = "client-to-server"
			segView.DirectionLabel = "Client → Server"
		} else {
			segView.Direction = "←"
			segView.DirectionCSS = "server-to-client"
			segView.DirectionLabel = "Server → Client"
		}

		// Relative timestamp
		if i == 0 {
			segView.TimestampRel = "+0.000s"
		} else {
			relTime := seg.Timestamp.Sub(stream.FirstSeen).Seconds()
			segView.TimestampRel = fmt.Sprintf("+%.3fs", relTime)
		}

		// Plain English summary (primary display)
		segView.PlainEnglish = seg.PlainEnglish
		if segView.PlainEnglish == "" {
			segView.PlainEnglish = seg.DataDecoded
		}

		// Data summary - clean format for binary data
		if sr.isTextData(seg.Data) {
			// For text data, show preview
			if len(seg.DataASCII) > 100 {
				segView.DataPreview = seg.DataASCII[:100] + "..."
			} else {
				segView.DataPreview = seg.DataASCII
			}
			segView.DataSummary = "" // No summary needed for text
			segView.ShowHexToggle = true
		} else {
			// For binary data, show clean summary instead of raw data
			segView.DataSummary = fmt.Sprintf("[Binary data: %d bytes]", seg.Length)
			segView.DataPreview = "" // Don't show garbled preview
			segView.ShowHexToggle = true
		}

		segView.DataFull = seg.DataASCII
		segView.DataHex = seg.DataHex
		segView.DataDecoded = seg.DataDecoded

		// Anomaly detection
		if seg.IsRetransmit || seg.IsOutOfOrder || seg.HasReset || seg.GapFromPrev > 1.0 {
			segView.IsAnomaly = true
			segView.AnomalyReason = seg.AnomalyReason

			// Set appropriate icon
			if seg.HasReset {
				segView.AnomalyIcon = "🔴" // Red for reset
			} else if seg.IsRetransmit {
				segView.AnomalyIcon = "🔁" // Retransmit
			} else if seg.IsOutOfOrder {
				segView.AnomalyIcon = "⚠️" // Warning for out of order
			} else if seg.GapFromPrev > 1.0 {
				segView.AnomalyIcon = "⏱️" // Clock for time gap
			}
		}

		view.Segments = append(view.Segments, segView)
	}

	return view
}

// formatDuration formats duration in human-readable form
func formatDuration(seconds float64) string {
	if seconds < 0.001 {
		return "<1ms"
	}
	if seconds < 1 {
		return fmt.Sprintf("%.0fms", seconds*1000)
	}
	if seconds < 60 {
		return fmt.Sprintf("%.2fs", seconds)
	}
	if seconds < 3600 {
		return fmt.Sprintf("%.1fm", seconds/60)
	}
	return fmt.Sprintf("%.1fh", seconds/3600)
}

// formatBytes formats bytes in human-readable form
func formatBytes(bytes uint64) string {
	if bytes < 1024 {
		return fmt.Sprintf("%d B", bytes)
	}
	if bytes < 1024*1024 {
		return fmt.Sprintf("%.1f KB", float64(bytes)/1024)
	}
	if bytes < 1024*1024*1024 {
		return fmt.Sprintf("%.1f MB", float64(bytes)/(1024*1024))
	}
	return fmt.Sprintf("%.1f GB", float64(bytes)/(1024*1024*1024))
}

// min returns the minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// Unused import placeholder to avoid compilation error
var _ = hex.EncodeToString
