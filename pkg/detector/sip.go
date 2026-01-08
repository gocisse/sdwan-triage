package detector

import (
	"regexp"
	"strings"
	"time"

	"github.com/gocisse/sdwan-triage/pkg/models"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// SIP method patterns
var sipMethodPattern = regexp.MustCompile(`^(INVITE|ACK|BYE|CANCEL|REGISTER|OPTIONS|PRACK|SUBSCRIBE|NOTIFY|PUBLISH|INFO|REFER|MESSAGE|UPDATE)\s`)
var sipResponsePattern = regexp.MustCompile(`^SIP/2\.0\s+(\d{3})\s+`)

// Common SIP ports
var sipPorts = map[uint16]bool{
	5060: true, // SIP (UDP/TCP)
	5061: true, // SIP TLS
	5062: true, // Alternative SIP
	5063: true, // Alternative SIP TLS
}

// SIPAnalyzer handles SIP/VoIP traffic analysis
type SIPAnalyzer struct {
	calls         map[string]*SIPCall
	registrations map[string]*SIPRegistration
}

// SIPCall represents a SIP call session
type SIPCall struct {
	CallID      string
	FromURI     string
	ToURI       string
	Method      string
	State       string
	StartTime   time.Time
	EndTime     time.Time
	SrcIP       string
	DstIP       string
	SrcPort     uint16
	DstPort     uint16
	Codec       string
	PacketCount int
}

// SIPRegistration represents a SIP registration
type SIPRegistration struct {
	UserAgent string
	Contact   string
	Expires   int
	Timestamp time.Time
	SrcIP     string
}

// NewSIPAnalyzer creates a new SIP analyzer
func NewSIPAnalyzer() *SIPAnalyzer {
	return &SIPAnalyzer{
		calls:         make(map[string]*SIPCall),
		registrations: make(map[string]*SIPRegistration),
	}
}

// Analyze processes packets for SIP traffic
func (s *SIPAnalyzer) Analyze(packet gopacket.Packet, state *models.AnalysisState, report *models.TriageReport) {
	var payload []byte
	var srcPort, dstPort uint16

	// Check UDP
	if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp := udpLayer.(*layers.UDP)
		srcPort = uint16(udp.SrcPort)
		dstPort = uint16(udp.DstPort)
		payload = udp.Payload
	}

	// Check TCP
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp := tcpLayer.(*layers.TCP)
		srcPort = uint16(tcp.SrcPort)
		dstPort = uint16(tcp.DstPort)
		payload = tcp.Payload
	}

	// Check if this is a SIP port or SIP content
	if !sipPorts[srcPort] && !sipPorts[dstPort] && !s.isSIPPayload(payload) {
		return
	}

	if len(payload) < 10 {
		return
	}

	ipInfo := ExtractIPInfo(packet)
	if ipInfo == nil {
		return
	}

	timestamp := packet.Metadata().Timestamp
	s.parseSIPMessage(payload, ipInfo.SrcIP, ipInfo.DstIP, srcPort, dstPort, timestamp)
}

func (s *SIPAnalyzer) isSIPPayload(payload []byte) bool {
	if len(payload) < 4 {
		return false
	}
	str := string(payload[:min(100, len(payload))])
	return strings.HasPrefix(str, "SIP/") || sipMethodPattern.MatchString(str)
}

func (s *SIPAnalyzer) parseSIPMessage(payload []byte, srcIP, dstIP string, srcPort, dstPort uint16, timestamp time.Time) {
	payloadStr := string(payload)
	lines := strings.Split(payloadStr, "\r\n")
	if len(lines) == 0 {
		return
	}

	firstLine := lines[0]

	// Parse headers
	headers := make(map[string]string)
	for _, line := range lines[1:] {
		if line == "" {
			break
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) == 2 {
			headers[strings.ToLower(strings.TrimSpace(parts[0]))] = strings.TrimSpace(parts[1])
		}
	}

	callID := headers["call-id"]
	if callID == "" {
		callID = headers["i"] // Short form
	}

	// Check if it's a request or response
	if matches := sipMethodPattern.FindStringSubmatch(firstLine); len(matches) > 1 {
		method := matches[1]
		s.handleSIPRequest(method, callID, headers, srcIP, dstIP, srcPort, dstPort, timestamp)
	} else if matches := sipResponsePattern.FindStringSubmatch(firstLine); len(matches) > 1 {
		statusCode := matches[1]
		s.handleSIPResponse(statusCode, callID, headers, srcIP, dstIP, timestamp)
	}
}

func (s *SIPAnalyzer) handleSIPRequest(method, callID string, headers map[string]string, srcIP, dstIP string, srcPort, dstPort uint16, timestamp time.Time) {
	switch method {
	case "INVITE":
		// New call setup
		call := &SIPCall{
			CallID:      callID,
			FromURI:     headers["from"],
			ToURI:       headers["to"],
			Method:      method,
			State:       "INVITE_SENT",
			StartTime:   timestamp,
			SrcIP:       srcIP,
			DstIP:       dstIP,
			SrcPort:     srcPort,
			DstPort:     dstPort,
			PacketCount: 1,
		}
		s.calls[callID] = call

	case "BYE":
		// Call termination
		if call, exists := s.calls[callID]; exists {
			call.State = "BYE_SENT"
			call.EndTime = timestamp
			call.PacketCount++
		}

	case "REGISTER":
		// Registration
		reg := &SIPRegistration{
			UserAgent: headers["user-agent"],
			Contact:   headers["contact"],
			Timestamp: timestamp,
			SrcIP:     srcIP,
		}
		s.registrations[srcIP] = reg

	case "ACK", "CANCEL", "OPTIONS", "PRACK", "SUBSCRIBE", "NOTIFY", "PUBLISH", "INFO", "REFER", "MESSAGE", "UPDATE":
		// Update existing call if present
		if call, exists := s.calls[callID]; exists {
			call.PacketCount++
			if method == "ACK" {
				call.State = "ESTABLISHED"
			} else if method == "CANCEL" {
				call.State = "CANCELLED"
			}
		}
	}
}

func (s *SIPAnalyzer) handleSIPResponse(statusCode, callID string, headers map[string]string, srcIP, dstIP string, timestamp time.Time) {
	if call, exists := s.calls[callID]; exists {
		call.PacketCount++

		switch {
		case strings.HasPrefix(statusCode, "1"):
			// Provisional response (100 Trying, 180 Ringing, etc.)
			if statusCode == "180" || statusCode == "183" {
				call.State = "RINGING"
			}
		case strings.HasPrefix(statusCode, "2"):
			// Success (200 OK)
			call.State = "ESTABLISHED"
		case strings.HasPrefix(statusCode, "3"):
			// Redirection
			call.State = "REDIRECTED"
		case strings.HasPrefix(statusCode, "4"):
			// Client error (401, 403, 404, etc.)
			call.State = "FAILED_CLIENT"
		case strings.HasPrefix(statusCode, "5"):
			// Server error
			call.State = "FAILED_SERVER"
		case strings.HasPrefix(statusCode, "6"):
			// Global failure
			call.State = "FAILED_GLOBAL"
		}
	}
}

// GetCalls returns all tracked SIP calls
func (s *SIPAnalyzer) GetCalls() map[string]*SIPCall {
	return s.calls
}

// GetRegistrations returns all tracked SIP registrations
func (s *SIPAnalyzer) GetRegistrations() map[string]*SIPRegistration {
	return s.registrations
}

// GetCallStats returns call statistics
func (s *SIPAnalyzer) GetCallStats() (total, established, failed int) {
	for _, call := range s.calls {
		total++
		switch call.State {
		case "ESTABLISHED":
			established++
		case "FAILED_CLIENT", "FAILED_SERVER", "FAILED_GLOBAL":
			failed++
		}
	}
	return
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
