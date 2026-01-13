package detector

import (
	"fmt"
	"time"

	"github.com/gocisse/sdwan-triage/pkg/models"
	"github.com/google/gopacket"
)

// TCPHandshakeTracker tracks TCP handshake state per flow
type TCPHandshakeTracker struct {
	flows map[string]*HandshakeFlow
}

// HandshakeFlow represents the state of a TCP handshake
type HandshakeFlow struct {
	SrcIP         string
	SrcPort       uint16
	DstIP         string
	DstPort       uint16
	State         HandshakeState
	SynTime       time.Time
	SynAckTime    time.Time
	AckTime       time.Time
	CompleteTime  time.Time
	FailureReason string
	IsIPv6        bool
}

// HandshakeState represents the current state of a TCP handshake
type HandshakeState int

const (
	StateNone HandshakeState = iota
	StateSynSent
	StateSynAckReceived
	StateEstablished
	StateFailed
)

// String returns the string representation of HandshakeState
func (s HandshakeState) String() string {
	switch s {
	case StateNone:
		return "None"
	case StateSynSent:
		return "SYN"
	case StateSynAckReceived:
		return "SYN-ACK"
	case StateEstablished:
		return "Handshake Complete"
	case StateFailed:
		return "Handshake Failed"
	default:
		return "Unknown"
	}
}

// NewTCPHandshakeTracker creates a new TCP handshake tracker
func NewTCPHandshakeTracker() *TCPHandshakeTracker {
	return &TCPHandshakeTracker{
		flows: make(map[string]*HandshakeFlow),
	}
}

// TrackHandshake processes a packet and updates handshake state
func (t *TCPHandshakeTracker) TrackHandshake(packet gopacket.Packet, state *models.AnalysisState, report *models.TriageReport) {
	tcp := SafeGetTCPLayer(packet)
	if tcp == nil {
		return
	}

	ipInfo := ExtractIPInfo(packet)
	if ipInfo == nil {
		return
	}

	timestamp := packet.Metadata().Timestamp

	// Create flow key (use canonical direction: client -> server)
	srcIP := ipInfo.SrcIP
	dstIP := ipInfo.DstIP
	srcPort := uint16(tcp.SrcPort)
	dstPort := uint16(tcp.DstPort)

	// Track SYN packets (connection initiation)
	if tcp.SYN && !tcp.ACK {
		flowKey := fmt.Sprintf("%s:%d->%s:%d", srcIP, srcPort, dstIP, dstPort)

		flow := &HandshakeFlow{
			SrcIP:   srcIP,
			SrcPort: srcPort,
			DstIP:   dstIP,
			DstPort: dstPort,
			State:   StateSynSent,
			SynTime: timestamp,
			IsIPv6:  ipInfo.IsIPv6,
		}
		t.flows[flowKey] = flow
		return
	}

	// Track SYN-ACK packets (server response)
	if tcp.SYN && tcp.ACK {
		// Look for the original SYN flow (reverse direction)
		flowKey := fmt.Sprintf("%s:%d->%s:%d", dstIP, dstPort, srcIP, srcPort)

		if flow, exists := t.flows[flowKey]; exists {
			if flow.State == StateSynSent {
				flow.State = StateSynAckReceived
				flow.SynAckTime = timestamp
			}
		}
		return
	}

	// Track ACK packets (handshake completion)
	if tcp.ACK && !tcp.SYN {
		// Look for the SYN-ACK flow
		flowKey := fmt.Sprintf("%s:%d->%s:%d", srcIP, srcPort, dstIP, dstPort)

		if flow, exists := t.flows[flowKey]; exists {
			if flow.State == StateSynAckReceived {
				flow.State = StateEstablished
				flow.AckTime = timestamp
				flow.CompleteTime = timestamp

				// Add to report's handshake tracking
				t.addToReport(flow, report)
			}
		}
		return
	}
}

// CheckTimeouts marks flows as failed if they timeout
func (t *TCPHandshakeTracker) CheckTimeouts(currentTime time.Time, timeout time.Duration, report *models.TriageReport) {
	for flowKey, flow := range t.flows {
		if flow.State == StateEstablished || flow.State == StateFailed {
			continue
		}

		var timeoutOccurred bool
		var reason string

		switch flow.State {
		case StateSynSent:
			if currentTime.Sub(flow.SynTime) > timeout {
				timeoutOccurred = true
				reason = "SYN-ACK timeout (no server response)"
			}
		case StateSynAckReceived:
			if currentTime.Sub(flow.SynAckTime) > timeout {
				timeoutOccurred = true
				reason = "ACK timeout (client did not complete handshake)"
			}
		}

		if timeoutOccurred {
			flow.State = StateFailed
			flow.FailureReason = reason
			t.addToReport(flow, report)
			delete(t.flows, flowKey)
		}
	}
}

// addToReport adds the handshake flow to the report
func (t *TCPHandshakeTracker) addToReport(flow *HandshakeFlow, report *models.TriageReport) {
	handshake := models.TCPHandshakeFlow{
		SrcIP:         flow.SrcIP,
		SrcPort:       flow.SrcPort,
		DstIP:         flow.DstIP,
		DstPort:       flow.DstPort,
		State:         flow.State.String(),
		SynTime:       flow.SynTime,
		SynAckTime:    flow.SynAckTime,
		AckTime:       flow.AckTime,
		FailureReason: flow.FailureReason,
		IsIPv6:        flow.IsIPv6,
	}

	// Calculate timing if handshake completed
	if flow.State == StateEstablished {
		handshake.SynToSynAckMs = float64(flow.SynAckTime.Sub(flow.SynTime).Microseconds()) / 1000.0
		handshake.SynAckToAckMs = float64(flow.AckTime.Sub(flow.SynAckTime).Microseconds()) / 1000.0
		handshake.TotalHandshakeMs = float64(flow.CompleteTime.Sub(flow.SynTime).Microseconds()) / 1000.0
	}

	report.TCPHandshakeFlows = append(report.TCPHandshakeFlows, handshake)
}

// GetFlows returns all tracked flows
func (t *TCPHandshakeTracker) GetFlows() map[string]*HandshakeFlow {
	return t.flows
}

// GetStatistics returns handshake statistics
func (t *TCPHandshakeTracker) GetStatistics(report *models.TriageReport) HandshakeStatistics {
	stats := HandshakeStatistics{}

	for _, flow := range report.TCPHandshakeFlows {
		stats.Total++

		switch flow.State {
		case "Handshake Complete":
			stats.Successful++
			stats.TotalHandshakeTime += flow.TotalHandshakeMs
		case "Handshake Failed":
			stats.Failed++
			stats.FailureReasons = append(stats.FailureReasons, flow.FailureReason)
		case "SYN":
			stats.Incomplete++
		case "SYN-ACK":
			stats.Incomplete++
		}
	}

	if stats.Successful > 0 {
		stats.AverageHandshakeTime = stats.TotalHandshakeTime / float64(stats.Successful)
	}

	if stats.Total > 0 {
		stats.SuccessRate = float64(stats.Successful) / float64(stats.Total) * 100.0
	}

	return stats
}

// HandshakeStatistics contains summary statistics for handshakes
type HandshakeStatistics struct {
	Total                int
	Successful           int
	Failed               int
	Incomplete           int
	SuccessRate          float64
	AverageHandshakeTime float64
	TotalHandshakeTime   float64
	FailureReasons       []string
}

// GetTroubleshootingSuggestion returns a suggestion based on failure reason
func GetTroubleshootingSuggestion(reason string) string {
	suggestions := map[string]string{
		"SYN-ACK timeout (no server response)":            "Check if server is reachable, verify firewall rules, ensure service is listening on the destination port",
		"ACK timeout (client did not complete handshake)": "Check client-side network connectivity, verify no packet loss, inspect client firewall rules",
		"RST received":     "Connection refused by server - verify service is running and accepting connections",
		"Connection reset": "Connection was forcibly closed - check for security policies or connection limits",
	}

	for key, suggestion := range suggestions {
		if reason == key {
			return suggestion
		}
	}

	return "Check network connectivity and firewall rules on both client and server"
}

// GetFailurePattern identifies common failure patterns
func GetFailurePattern(flows []models.TCPHandshakeFlow) string {
	if len(flows) == 0 {
		return "No handshake data available"
	}

	synTimeouts := 0
	ackTimeouts := 0
	successful := 0

	for _, flow := range flows {
		if flow.State == "Handshake Complete" {
			successful++
		} else if flow.FailureReason == "SYN-ACK timeout (no server response)" {
			synTimeouts++
		} else if flow.FailureReason == "ACK timeout (client did not complete handshake)" {
			ackTimeouts++
		}
	}

	total := len(flows)

	if synTimeouts > total/2 {
		return "⚠️  Pattern: High SYN-ACK timeout rate - Server may be unreachable or overloaded"
	}

	if ackTimeouts > total/2 {
		return "⚠️  Pattern: High ACK timeout rate - Client-side network issues or packet loss"
	}

	if successful == total {
		return "✅ Pattern: All handshakes successful - No connection issues detected"
	}

	if successful > total*3/4 {
		return "✅ Pattern: Most handshakes successful - Minor intermittent issues"
	}

	if successful < total/4 {
		return "🔴 Pattern: High failure rate - Critical connectivity issues"
	}

	return "⚠️  Pattern: Mixed results - Intermittent connectivity issues"
}
