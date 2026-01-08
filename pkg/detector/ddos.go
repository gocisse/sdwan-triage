package detector

import (
	"time"

	"github.com/gocisse/sdwan-triage/pkg/models"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// DDoS detection thresholds
const (
	SYNFloodThreshold  = 100  // SYN packets per IP in detection window
	UDPFloodThreshold  = 200  // UDP packets per IP in detection window
	ICMPFloodThreshold = 100  // ICMP packets per IP in detection window
	DetectionWindowSec = 10.0 // Detection window in seconds
)

// DDoSAnalyzer handles DDoS attack detection
type DDoSAnalyzer struct {
	synThreshold  int
	udpThreshold  int
	icmpThreshold int
}

// NewDDoSAnalyzer creates a new DDoS analyzer with default thresholds
func NewDDoSAnalyzer() *DDoSAnalyzer {
	return &DDoSAnalyzer{
		synThreshold:  SYNFloodThreshold,
		udpThreshold:  UDPFloodThreshold,
		icmpThreshold: ICMPFloodThreshold,
	}
}

// AnalyzeTCP processes TCP packets for SYN flood detection
func (d *DDoSAnalyzer) AnalyzeTCP(packet gopacket.Packet, state *models.AnalysisState, report *models.TriageReport) {
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		return
	}

	tcp, ok := tcpLayer.(*layers.TCP)
	if !ok {
		return
	}

	// Only track SYN packets (without ACK) for SYN flood detection
	if !tcp.SYN || tcp.ACK {
		return
	}

	ipInfo := ExtractIPInfo(packet)
	if ipInfo == nil {
		return
	}

	srcIP := ipInfo.SrcIP
	dstIP := ipInfo.DstIP
	timestamp := packet.Metadata().Timestamp

	d.trackSYNPacket(srcIP, dstIP, timestamp, state, report)
}

// AnalyzeUDP processes UDP packets for UDP flood detection
func (d *DDoSAnalyzer) AnalyzeUDP(packet gopacket.Packet, state *models.AnalysisState, report *models.TriageReport) {
	udpLayer := packet.Layer(layers.LayerTypeUDP)
	if udpLayer == nil {
		return
	}

	ipInfo := ExtractIPInfo(packet)
	if ipInfo == nil {
		return
	}

	srcIP := ipInfo.SrcIP
	dstIP := ipInfo.DstIP
	timestamp := packet.Metadata().Timestamp

	d.trackUDPPacket(srcIP, dstIP, timestamp, state, report)
}

// AnalyzeICMP processes ICMP packets for ICMP flood detection
func (d *DDoSAnalyzer) AnalyzeICMP(packet gopacket.Packet, state *models.AnalysisState, report *models.TriageReport) {
	// Check for ICMPv4
	icmpLayer := packet.Layer(layers.LayerTypeICMPv4)
	if icmpLayer == nil {
		// Check for ICMPv6
		icmpLayer = packet.Layer(layers.LayerTypeICMPv6)
	}
	if icmpLayer == nil {
		return
	}

	ipInfo := ExtractIPInfo(packet)
	if ipInfo == nil {
		return
	}

	srcIP := ipInfo.SrcIP
	dstIP := ipInfo.DstIP
	timestamp := packet.Metadata().Timestamp

	d.trackICMPPacket(srcIP, dstIP, timestamp, state, report)
}

func (d *DDoSAnalyzer) trackSYNPacket(srcIP, dstIP string, timestamp time.Time, state *models.AnalysisState, report *models.TriageReport) {
	secState := state.SecurityState
	d.maybeResetCounters(timestamp, secState)

	counter, exists := secState.SYNCountPerIP[srcIP]
	if !exists {
		counter = models.NewFloodCounter(timestamp)
		secState.SYNCountPerIP[srcIP] = counter
	}

	counter.Count++
	counter.LastSeen = timestamp
	counter.TargetIPs[dstIP]++

	// Check threshold
	if counter.Count >= d.synThreshold {
		d.reportDDoS(srcIP, dstIP, "SYN Flood", counter, timestamp, report)
	}
}

func (d *DDoSAnalyzer) trackUDPPacket(srcIP, dstIP string, timestamp time.Time, state *models.AnalysisState, report *models.TriageReport) {
	secState := state.SecurityState
	d.maybeResetCounters(timestamp, secState)

	counter, exists := secState.UDPCountPerIP[srcIP]
	if !exists {
		counter = models.NewFloodCounter(timestamp)
		secState.UDPCountPerIP[srcIP] = counter
	}

	counter.Count++
	counter.LastSeen = timestamp
	counter.TargetIPs[dstIP]++

	// Check threshold
	if counter.Count >= d.udpThreshold {
		d.reportDDoS(srcIP, dstIP, "UDP Flood", counter, timestamp, report)
	}
}

func (d *DDoSAnalyzer) trackICMPPacket(srcIP, dstIP string, timestamp time.Time, state *models.AnalysisState, report *models.TriageReport) {
	secState := state.SecurityState
	d.maybeResetCounters(timestamp, secState)

	counter, exists := secState.ICMPCountPerIP[srcIP]
	if !exists {
		counter = models.NewFloodCounter(timestamp)
		secState.ICMPCountPerIP[srcIP] = counter
	}

	counter.Count++
	counter.LastSeen = timestamp
	counter.TargetIPs[dstIP]++

	// Check threshold
	if counter.Count >= d.icmpThreshold {
		d.reportDDoS(srcIP, dstIP, "ICMP Flood", counter, timestamp, report)
	}
}

func (d *DDoSAnalyzer) maybeResetCounters(timestamp time.Time, secState *models.SecurityState) {
	elapsed := timestamp.Sub(secState.LastResetTime).Seconds()
	if elapsed >= secState.ResetIntervalSecs {
		// Reset all counters
		secState.SYNCountPerIP = make(map[string]*models.FloodCounter)
		secState.UDPCountPerIP = make(map[string]*models.FloodCounter)
		secState.ICMPCountPerIP = make(map[string]*models.FloodCounter)
		secState.LastResetTime = timestamp
	}
}

func (d *DDoSAnalyzer) reportDDoS(srcIP, dstIP, attackType string, counter *models.FloodCounter, timestamp time.Time, report *models.TriageReport) {
	// Check if we already reported this attack in current window
	for _, finding := range report.Security.DDoSFindings {
		if finding.SourceIP == srcIP && finding.Type == attackType {
			return // Already reported
		}
	}

	duration := counter.LastSeen.Sub(counter.FirstSeen).Seconds()
	severity := d.calculateSeverity(counter.Count, attackType)

	// Find most targeted IP
	targetIP := dstIP
	maxCount := 0
	for ip, count := range counter.TargetIPs {
		if count > maxCount {
			maxCount = count
			targetIP = ip
		}
	}

	finding := models.DDoSFinding{
		Timestamp:   float64(timestamp.UnixNano()) / 1e9,
		SourceIP:    srcIP,
		TargetIP:    targetIP,
		Type:        attackType,
		PacketCount: counter.Count,
		Threshold:   d.getThreshold(attackType),
		Duration:    duration,
		Severity:    severity,
	}

	report.Security.DDoSFindings = append(report.Security.DDoSFindings, finding)
}

func (d *DDoSAnalyzer) calculateSeverity(count int, attackType string) string {
	threshold := d.getThreshold(attackType)
	ratio := float64(count) / float64(threshold)

	switch {
	case ratio >= 10:
		return "Critical"
	case ratio >= 5:
		return "High"
	case ratio >= 2:
		return "Medium"
	default:
		return "Low"
	}
}

func (d *DDoSAnalyzer) getThreshold(attackType string) int {
	switch attackType {
	case "SYN Flood":
		return d.synThreshold
	case "UDP Flood":
		return d.udpThreshold
	case "ICMP Flood":
		return d.icmpThreshold
	default:
		return 100
	}
}
