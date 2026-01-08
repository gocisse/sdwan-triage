package detector

import (
	"fmt"

	"github.com/gocisse/sdwan-triage/pkg/models"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// TrafficAnalyzer handles traffic volume and suspicious traffic analysis
type TrafficAnalyzer struct{}

// NewTrafficAnalyzer creates a new traffic analyzer
func NewTrafficAnalyzer() *TrafficAnalyzer {
	return &TrafficAnalyzer{}
}

// Analyze processes packets for traffic analysis and suspicious activity detection
func (t *TrafficAnalyzer) Analyze(packet gopacket.Packet, state *models.AnalysisState, report *models.TriageReport) {
	// Get IP layer info (supports IPv4 and IPv6)
	ipInfo := ExtractIPInfo(packet)
	if ipInfo == nil {
		return
	}
	srcIP := ipInfo.SrcIP
	dstIP := ipInfo.DstIP

	// Get payload length from packet metadata
	var payloadLen uint64
	if ip4Layer := packet.Layer(layers.LayerTypeIPv4); ip4Layer != nil {
		ip4 := ip4Layer.(*layers.IPv4)
		payloadLen = uint64(ip4.Length)
	} else if ip6Layer := packet.Layer(layers.LayerTypeIPv6); ip6Layer != nil {
		ip6 := ip6Layer.(*layers.IPv6)
		payloadLen = uint64(ip6.Length) + 40 // Add IPv6 header size
	}

	// Get transport layer info
	srcPort, dstPort, protocol := GetTransportPorts(packet)

	// Track UDP flows for byte counting (TCP is tracked in tcp.go)
	if protocol == "UDP" {
		flowKey := fmt.Sprintf("%s:%d->%s:%d", srcIP, srcPort, dstIP, dstPort)
		if state.UDPFlows[flowKey] == nil {
			state.UDPFlows[flowKey] = &models.UDPFlowState{}
		}
		state.UDPFlows[flowKey].TotalBytes += payloadLen
		report.TotalBytes += payloadLen
	} else if protocol == "" {
		// Non-TCP/UDP traffic (ICMP, etc.) - still count bytes
		report.TotalBytes += payloadLen
	}

	// Track application statistics
	t.trackAppStats(srcPort, dstPort, protocol, payloadLen, state, report)

	// Check for suspicious ports
	t.checkSuspiciousPorts(srcIP, dstIP, srcPort, dstPort, protocol, packet, report)
}

// trackAppStats tracks application-level statistics
func (t *TrafficAnalyzer) trackAppStats(srcPort, dstPort uint16, protocol string, payloadLen uint64, state *models.AnalysisState, report *models.TriageReport) {
	// Determine the application based on port
	port := dstPort
	if dstPort > 1024 && srcPort <= 1024 {
		port = srcPort
	}

	appName := models.CategorizePort(port, protocol)
	appKey := fmt.Sprintf("%s/%d", protocol, port)

	if state.AppStats[appKey] == nil {
		state.AppStats[appKey] = &models.AppCategory{
			Name:     appName,
			Port:     port,
			Protocol: protocol,
		}
	}

	state.AppStats[appKey].PacketCount++
	state.AppStats[appKey].ByteCount += payloadLen
}

// checkSuspiciousPorts checks for suspicious port usage
func (t *TrafficAnalyzer) checkSuspiciousPorts(srcIP, dstIP string, srcPort, dstPort uint16, protocol string, packet gopacket.Packet, report *models.TriageReport) {
	timestamp := float64(packet.Metadata().Timestamp.UnixNano()) / 1e9

	// Check destination port
	if suspicious, reason := models.IsSuspiciousPort(dstPort); suspicious {
		t.addSuspiciousFlow(srcIP, dstIP, srcPort, dstPort, protocol, reason, timestamp, report)
	}

	// Check source port
	if suspicious, reason := models.IsSuspiciousPort(srcPort); suspicious {
		t.addSuspiciousFlow(srcIP, dstIP, srcPort, dstPort, protocol, reason, timestamp, report)
	}
}

// addSuspiciousFlow adds a suspicious flow to the report
func (t *TrafficAnalyzer) addSuspiciousFlow(srcIP, dstIP string, srcPort, dstPort uint16, protocol, reason string, timestamp float64, report *models.TriageReport) {
	// Check if already recorded
	for _, existing := range report.SuspiciousTraffic {
		if existing.SrcIP == srcIP && existing.DstIP == dstIP &&
			existing.SrcPort == srcPort && existing.DstPort == dstPort {
			return
		}
	}

	flow := models.SuspiciousFlow{
		SrcIP:       srcIP,
		SrcPort:     srcPort,
		DstIP:       dstIP,
		DstPort:     dstPort,
		Protocol:    protocol,
		Reason:      reason,
		Description: fmt.Sprintf("Suspicious port detected: %s", reason),
	}

	report.SuspiciousTraffic = append(report.SuspiciousTraffic, flow)

	// Add timeline event
	event := models.TimelineEvent{
		Timestamp:     timestamp,
		EventType:     "Suspicious Traffic",
		SourceIP:      srcIP,
		DestinationIP: dstIP,
		Protocol:      protocol,
		Detail:        reason,
	}
	srcPortPtr := srcPort
	dstPortPtr := dstPort
	event.SourcePort = &srcPortPtr
	event.DestinationPort = &dstPortPtr
	report.Timeline = append(report.Timeline, event)
}
