package detector

import (
	"encoding/binary"
	"fmt"
	"net"

	"github.com/gocisse/sdwan-triage/pkg/models"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// BGPAnalyzer handles BGP protocol analysis and hijack detection
type BGPAnalyzer struct {
	bgpSessions map[string]*BGPSession
}

// BGPSession tracks BGP session state
type BGPSession struct {
	LocalIP     string
	RemoteIP    string
	LocalAS     uint32
	RemoteAS    uint32
	State       string
	UpdatesSeen int
	LastUpdate  float64
}

// BGPMessageType represents BGP message types
type BGPMessageType uint8

const (
	BGPOpen         BGPMessageType = 1
	BGPUpdate       BGPMessageType = 2
	BGPNotification BGPMessageType = 3
	BGPKeepAlive    BGPMessageType = 4
)

// NewBGPAnalyzer creates a new BGP analyzer
func NewBGPAnalyzer() *BGPAnalyzer {
	return &BGPAnalyzer{
		bgpSessions: make(map[string]*BGPSession),
	}
}

// Analyze processes BGP packets and detects anomalies
func (b *BGPAnalyzer) Analyze(packet gopacket.Packet, state *models.AnalysisState, report *models.TriageReport) {
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		return
	}

	tcp, ok := tcpLayer.(*layers.TCP)
	if !ok {
		return
	}

	// BGP runs on TCP port 179
	if tcp.SrcPort != 179 && tcp.DstPort != 179 {
		return
	}

	// Get IP info
	ipInfo := ExtractIPInfo(packet)
	if ipInfo == nil {
		return
	}

	payload := tcp.Payload
	if len(payload) < 19 {
		// BGP header is 19 bytes minimum
		return
	}

	// Parse BGP message
	bgpMsg := b.parseBGPMessage(payload)
	if bgpMsg == nil {
		return
	}

	timestamp := float64(packet.Metadata().Timestamp.UnixNano()) / 1e9
	sessionKey := fmt.Sprintf("%s-%s", ipInfo.SrcIP, ipInfo.DstIP)

	// Track BGP session
	session, exists := b.bgpSessions[sessionKey]
	if !exists {
		session = &BGPSession{
			LocalIP:  ipInfo.SrcIP,
			RemoteIP: ipInfo.DstIP,
			State:    "Unknown",
		}
		b.bgpSessions[sessionKey] = session
	}

	// Process based on message type
	switch bgpMsg.Type {
	case BGPOpen:
		b.handleBGPOpen(bgpMsg, session, ipInfo, timestamp, report)
	case BGPUpdate:
		b.handleBGPUpdate(bgpMsg, session, ipInfo, timestamp, report)
	case BGPNotification:
		b.handleBGPNotification(bgpMsg, session, ipInfo, timestamp, report)
	case BGPKeepAlive:
		session.State = "Established"
	}
}

// BGPMessage represents a parsed BGP message
type BGPMessage struct {
	Type   BGPMessageType
	Length uint16
	Data   []byte
}

// parseBGPMessage parses a BGP message from payload
func (b *BGPAnalyzer) parseBGPMessage(payload []byte) *BGPMessage {
	if len(payload) < 19 {
		return nil
	}

	// BGP marker (16 bytes of 0xFF)
	marker := payload[0:16]
	for _, b := range marker {
		if b != 0xFF {
			return nil
		}
	}

	// Length (2 bytes)
	length := binary.BigEndian.Uint16(payload[16:18])
	if length < 19 || length > uint16(len(payload)) {
		return nil
	}

	// Type (1 byte)
	msgType := BGPMessageType(payload[18])

	return &BGPMessage{
		Type:   msgType,
		Length: length,
		Data:   payload[19:length],
	}
}

// handleBGPOpen processes BGP OPEN messages
func (b *BGPAnalyzer) handleBGPOpen(msg *BGPMessage, session *BGPSession, ipInfo *PacketIPInfo, timestamp float64, report *models.TriageReport) {
	if len(msg.Data) < 10 {
		return
	}

	// Parse OPEN message
	// Version (1 byte) + My AS (2 bytes) + Hold Time (2 bytes) + BGP ID (4 bytes)
	myAS := uint32(binary.BigEndian.Uint16(msg.Data[1:3]))
	bgpID := net.IP(msg.Data[5:9])

	session.State = "OpenSent"
	if ipInfo.SrcIP == session.LocalIP {
		session.LocalAS = myAS
	} else {
		session.RemoteAS = myAS
	}

	// Check for AS number anomalies (AS 0 is reserved/invalid)
	if myAS == 0 {
		b.reportBGPAnomaly(report, "Invalid AS Number", ipInfo, timestamp,
			fmt.Sprintf("BGP OPEN with invalid AS number: %d from %s", myAS, bgpID.String()))
	}
}

// handleBGPUpdate processes BGP UPDATE messages
func (b *BGPAnalyzer) handleBGPUpdate(msg *BGPMessage, session *BGPSession, ipInfo *PacketIPInfo, timestamp float64, report *models.TriageReport) {
	session.UpdatesSeen++
	session.LastUpdate = timestamp
	session.State = "Established"

	if len(msg.Data) < 4 {
		return
	}

	// Parse UPDATE message
	withdrawnLen := binary.BigEndian.Uint16(msg.Data[0:2])
	if len(msg.Data) < int(2+withdrawnLen+2) {
		return
	}

	// Skip withdrawn routes
	pos := 2 + withdrawnLen

	// Path attributes length
	pathAttrLen := binary.BigEndian.Uint16(msg.Data[pos : pos+2])
	pos += 2

	if len(msg.Data) < int(pos+pathAttrLen) {
		return
	}

	// Parse path attributes
	pathAttrs := msg.Data[pos : pos+pathAttrLen]
	asPath := b.parseASPath(pathAttrs)

	// Check for BGP hijack indicators
	b.detectBGPHijack(asPath, ipInfo, timestamp, report)
}

// parseASPath extracts AS_PATH from path attributes
func (b *BGPAnalyzer) parseASPath(attrs []byte) []uint32 {
	var asPath []uint32
	pos := 0

	for pos+3 < len(attrs) {
		// Attribute flags (1 byte) + Type code (1 byte) + Length (1 byte)
		attrType := attrs[pos+1]
		attrLen := int(attrs[pos+2])
		pos += 3

		if pos+attrLen > len(attrs) {
			break
		}

		// AS_PATH attribute type is 2
		if attrType == 2 {
			// Parse AS_PATH segments
			segPos := 0
			for segPos+2 < attrLen {
				segType := attrs[pos+segPos]
				segLen := int(attrs[pos+segPos+1])
				segPos += 2

				// AS_SEQUENCE (type 2) or AS_SET (type 1)
				if segType == 1 || segType == 2 {
					for i := 0; i < segLen && segPos+4 <= attrLen; i++ {
						asNum := binary.BigEndian.Uint32(attrs[pos+segPos : pos+segPos+4])
						asPath = append(asPath, asNum)
						segPos += 4
					}
				}
			}
		}

		pos += attrLen
	}

	return asPath
}

// detectBGPHijack detects potential BGP hijacking using 6 heuristics
func (b *BGPAnalyzer) detectBGPHijack(asPath []uint32, ipInfo *PacketIPInfo, timestamp float64, report *models.TriageReport) {
	if len(asPath) == 0 {
		return
	}

	// Heuristic 1: Unusually short AS path (potential hijack)
	// A path length of 1 from an external peer is suspicious
	if len(asPath) == 1 {
		b.reportBGPAnomaly(report, "Suspicious Short AS Path", ipInfo, timestamp,
			fmt.Sprintf("AS path length of 1 detected from %s (AS%d) - potential route hijack", ipInfo.SrcIP, asPath[0]))
	}

	// Heuristic 2: AS path prepending detection (potential traffic engineering or hijack)
	if len(asPath) > 3 {
		asCounts := make(map[uint32]int)
		for _, as := range asPath {
			asCounts[as]++
		}
		for as, count := range asCounts {
			if count > 3 {
				b.reportBGPAnomaly(report, "AS Path Prepending Detected", ipInfo, timestamp,
					fmt.Sprintf("AS%d appears %d times in path from %s - verify if intentional", as, count, ipInfo.SrcIP))
			}
		}
	}

	// Heuristic 3: Private AS numbers in public internet (potential misconfiguration or leak)
	for _, as := range asPath {
		// RFC 6996: Private AS ranges
		if (as >= 64512 && as <= 65534) || (as >= 4200000000 && as <= 4294967294) {
			b.reportBGPAnomaly(report, "Private AS in Public Path", ipInfo, timestamp,
				fmt.Sprintf("Private AS%d detected in path from %s - should be stripped at edge", as, ipInfo.SrcIP))
			break // Report only once per path
		}
	}

	// Heuristic 4: Reserved AS numbers (RFC 7607)
	for _, as := range asPath {
		if as == 0 || as == 23456 || as == 65535 || as == 4294967295 {
			b.reportBGPAnomaly(report, "Reserved AS Number", ipInfo, timestamp,
				fmt.Sprintf("Reserved AS%d detected in path from %s - invalid route", as, ipInfo.SrcIP))
			break // Report only once per path
		}
	}

	// Heuristic 5: AS path loop detection (same AS appears non-consecutively)
	if len(asPath) >= 3 {
		seen := make(map[uint32]int)
		for i, as := range asPath {
			if prevIdx, exists := seen[as]; exists {
				// Check if it's not consecutive (which would be prepending)
				if i-prevIdx > 1 {
					b.reportBGPAnomaly(report, "AS Path Loop Detected", ipInfo, timestamp,
						fmt.Sprintf("AS%d appears at positions %d and %d in path from %s - potential routing loop or hijack", as, prevIdx+1, i+1, ipInfo.SrcIP))
					break
				}
			}
			seen[as] = i
		}
	}

	// Heuristic 6: Unusually long AS path (potential hijack with path inflation)
	if len(asPath) > 15 {
		b.reportBGPAnomaly(report, "Unusually Long AS Path", ipInfo, timestamp,
			fmt.Sprintf("AS path length of %d detected from %s - potential path manipulation", len(asPath), ipInfo.SrcIP))
	}
}

// handleBGPNotification processes BGP NOTIFICATION messages
func (b *BGPAnalyzer) handleBGPNotification(msg *BGPMessage, session *BGPSession, ipInfo *PacketIPInfo, timestamp float64, report *models.TriageReport) {
	if len(msg.Data) < 2 {
		return
	}

	errorCode := msg.Data[0]
	errorSubcode := msg.Data[1]

	session.State = "Idle"

	b.reportBGPAnomaly(report, "BGP Session Error", ipInfo, timestamp,
		fmt.Sprintf("BGP NOTIFICATION: Error %d/%d from %s", errorCode, errorSubcode, ipInfo.SrcIP))
}

// reportBGPAnomaly adds a BGP anomaly to the report
func (b *BGPAnalyzer) reportBGPAnomaly(report *models.TriageReport, reason string, ipInfo *PacketIPInfo, timestamp float64, detail string) {
	indicator := models.BGPIndicator{
		IPAddress:  ipInfo.SrcIP,
		IPPrefix:   ipInfo.DstIP,
		Reason:     reason,
		Confidence: "Medium",
		IsAnomaly:  true,
	}

	// Increase confidence for critical issues
	if reason == "BGP Session Error" || reason == "Reserved AS Number" {
		indicator.Confidence = "High"
	}

	report.BGPHijackIndicators = append(report.BGPHijackIndicators, indicator)
}

// Finalize completes BGP analysis
func (b *BGPAnalyzer) Finalize(state *models.AnalysisState, report *models.TriageReport) {
	// Add BGP session summary to report
	for _, session := range b.bgpSessions {
		if session.UpdatesSeen > 0 {
			// Could add BGP session statistics to report if needed
		}
	}
}
