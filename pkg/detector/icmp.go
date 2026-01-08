package detector

import (
	"fmt"
	"time"

	"github.com/gocisse/sdwan-triage/pkg/models"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// ICMP type names
var icmpv4TypeNames = map[uint8]string{
	0:  "Echo Reply",
	3:  "Destination Unreachable",
	4:  "Source Quench",
	5:  "Redirect",
	8:  "Echo Request",
	9:  "Router Advertisement",
	10: "Router Solicitation",
	11: "Time Exceeded",
	12: "Parameter Problem",
	13: "Timestamp Request",
	14: "Timestamp Reply",
	17: "Address Mask Request",
	18: "Address Mask Reply",
}

var icmpv6TypeNames = map[uint8]string{
	1:   "Destination Unreachable",
	2:   "Packet Too Big",
	3:   "Time Exceeded",
	4:   "Parameter Problem",
	128: "Echo Request",
	129: "Echo Reply",
	130: "Multicast Listener Query",
	131: "Multicast Listener Report",
	133: "Router Solicitation",
	134: "Router Advertisement",
	135: "Neighbor Solicitation",
	136: "Neighbor Advertisement",
	137: "Redirect",
}

// ICMPAnalyzer handles ICMP packet analysis
type ICMPAnalyzer struct {
	pingFloodThreshold int
}

// NewICMPAnalyzer creates a new ICMP analyzer
func NewICMPAnalyzer() *ICMPAnalyzer {
	return &ICMPAnalyzer{
		pingFloodThreshold: 50,
	}
}

// Analyze processes ICMP packets
func (i *ICMPAnalyzer) Analyze(packet gopacket.Packet, state *models.AnalysisState, report *models.TriageReport) {
	// Try ICMPv4 first
	if icmpLayer := packet.Layer(layers.LayerTypeICMPv4); icmpLayer != nil {
		i.analyzeICMPv4(packet, icmpLayer.(*layers.ICMPv4), state, report)
		return
	}

	// Try ICMPv6
	if icmpLayer := packet.Layer(layers.LayerTypeICMPv6); icmpLayer != nil {
		i.analyzeICMPv6(packet, icmpLayer.(*layers.ICMPv6), state, report)
	}
}

func (i *ICMPAnalyzer) analyzeICMPv4(packet gopacket.Packet, icmp *layers.ICMPv4, state *models.AnalysisState, report *models.TriageReport) {
	ipInfo := ExtractIPInfo(packet)
	if ipInfo == nil {
		return
	}

	srcIP := ipInfo.SrcIP
	dstIP := ipInfo.DstIP
	timestamp := packet.Metadata().Timestamp
	icmpType := uint8(icmp.TypeCode.Type())
	icmpCode := uint8(icmp.TypeCode.Code())

	typeName := icmpv4TypeNames[icmpType]
	if typeName == "" {
		typeName = fmt.Sprintf("Unknown (%d)", icmpType)
	}

	// Track ICMP statistics
	i.trackICMPStats(srcIP, icmpType, timestamp, state)

	// Check for anomalies
	isAnomaly := false
	description := ""

	switch icmpType {
	case 3: // Destination Unreachable
		isAnomaly = true
		description = i.getUnreachableDescription(icmpCode)
	case 11: // Time Exceeded
		isAnomaly = true
		description = "Time exceeded - possible routing loop or traceroute"
	case 5: // Redirect
		isAnomaly = true
		description = "ICMP Redirect - potential MITM attack vector"
	}

	// Check for ping flood
	stats := state.SecurityState.ICMPStats[srcIP]
	if stats != nil && stats.TotalCount > i.pingFloodThreshold {
		if icmpType == 8 { // Echo Request
			isAnomaly = true
			description = fmt.Sprintf("Possible ping flood: %d ICMP packets from source", stats.TotalCount)
		}
	}

	// Record finding
	i.recordFinding(srcIP, dstIP, icmpType, icmpCode, typeName, timestamp, isAnomaly, description, report)
}

func (i *ICMPAnalyzer) analyzeICMPv6(packet gopacket.Packet, icmp *layers.ICMPv6, state *models.AnalysisState, report *models.TriageReport) {
	ipInfo := ExtractIPInfo(packet)
	if ipInfo == nil {
		return
	}

	srcIP := ipInfo.SrcIP
	dstIP := ipInfo.DstIP
	timestamp := packet.Metadata().Timestamp
	icmpType := uint8(icmp.TypeCode.Type())
	icmpCode := uint8(icmp.TypeCode.Code())

	typeName := icmpv6TypeNames[icmpType]
	if typeName == "" {
		typeName = fmt.Sprintf("Unknown (%d)", icmpType)
	}

	// Track ICMP statistics
	i.trackICMPStats(srcIP, icmpType, timestamp, state)

	// Check for anomalies
	isAnomaly := false
	description := ""

	switch icmpType {
	case 1: // Destination Unreachable
		isAnomaly = true
		description = "ICMPv6 Destination Unreachable"
	case 3: // Time Exceeded
		isAnomaly = true
		description = "ICMPv6 Time Exceeded - possible routing issue"
	case 137: // Redirect
		isAnomaly = true
		description = "ICMPv6 Redirect - potential security concern"
	}

	// Record finding
	i.recordFinding(srcIP, dstIP, icmpType, icmpCode, typeName, timestamp, isAnomaly, description, report)
}

func (i *ICMPAnalyzer) trackICMPStats(srcIP string, icmpType uint8, timestamp time.Time, state *models.AnalysisState) {
	stats := state.SecurityState.ICMPStats[srcIP]
	if stats == nil {
		stats = &models.ICMPStats{
			TypeCounts: make(map[uint8]int),
			FirstSeen:  timestamp,
		}
		state.SecurityState.ICMPStats[srcIP] = stats
	}

	stats.TypeCounts[icmpType]++
	stats.TotalCount++
	stats.LastSeen = timestamp
}

func (i *ICMPAnalyzer) getUnreachableDescription(code uint8) string {
	switch code {
	case 0:
		return "Network Unreachable"
	case 1:
		return "Host Unreachable"
	case 2:
		return "Protocol Unreachable"
	case 3:
		return "Port Unreachable"
	case 4:
		return "Fragmentation Needed but DF set"
	case 5:
		return "Source Route Failed"
	case 6:
		return "Destination Network Unknown"
	case 7:
		return "Destination Host Unknown"
	case 9:
		return "Network Administratively Prohibited"
	case 10:
		return "Host Administratively Prohibited"
	case 13:
		return "Communication Administratively Prohibited"
	default:
		return fmt.Sprintf("Destination Unreachable (code %d)", code)
	}
}

func (i *ICMPAnalyzer) recordFinding(srcIP, dstIP string, icmpType, icmpCode uint8, typeName string, timestamp time.Time, isAnomaly bool, description string, report *models.TriageReport) {
	// Aggregate findings by source IP and type to avoid duplicates
	for idx, finding := range report.ICMPAnalysis {
		if finding.SourceIP == srcIP && finding.Type == icmpType {
			// Update existing finding
			report.ICMPAnalysis[idx].Count++
			if isAnomaly && !finding.IsAnomaly {
				report.ICMPAnalysis[idx].IsAnomaly = true
				report.ICMPAnalysis[idx].Description = description
			}
			return
		}
	}

	// Add new finding
	finding := models.ICMPFinding{
		Timestamp:   float64(timestamp.UnixNano()) / 1e9,
		SourceIP:    srcIP,
		DestIP:      dstIP,
		Type:        icmpType,
		Code:        icmpCode,
		TypeName:    typeName,
		Count:       1,
		IsAnomaly:   isAnomaly,
		Description: description,
	}

	report.ICMPAnalysis = append(report.ICMPAnalysis, finding)
}
