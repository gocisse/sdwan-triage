package detector

import (
	"fmt"
	"time"

	"github.com/gocisse/sdwan-triage/pkg/models"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// Port scan detection thresholds
const (
	HorizontalScanThreshold = 25  // Unique ports scanned on single target
	VerticalScanThreshold   = 15  // Unique targets on same port
	TotalScanThreshold      = 100 // Total connection attempts from single IP
)

// PortScanAnalyzer handles port scanning detection
type PortScanAnalyzer struct {
	horizontalThreshold int
	verticalThreshold   int
	totalThreshold      int
}

// NewPortScanAnalyzer creates a new port scan analyzer
func NewPortScanAnalyzer() *PortScanAnalyzer {
	return &PortScanAnalyzer{
		horizontalThreshold: HorizontalScanThreshold,
		verticalThreshold:   VerticalScanThreshold,
		totalThreshold:      TotalScanThreshold,
	}
}

// Analyze processes TCP SYN packets for port scan detection
func (p *PortScanAnalyzer) Analyze(packet gopacket.Packet, state *models.AnalysisState, report *models.TriageReport) {
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		return
	}

	tcp, ok := tcpLayer.(*layers.TCP)
	if !ok {
		return
	}

	// Only track SYN packets (connection attempts)
	if !tcp.SYN || tcp.ACK {
		return
	}

	ipInfo := ExtractIPInfo(packet)
	if ipInfo == nil {
		return
	}

	srcIP := ipInfo.SrcIP
	dstIP := ipInfo.DstIP
	dstPort := uint16(tcp.DstPort)
	timestamp := packet.Metadata().Timestamp

	p.trackConnectionAttempt(srcIP, dstIP, dstPort, timestamp, state, report)
}

func (p *PortScanAnalyzer) trackConnectionAttempt(srcIP, dstIP string, dstPort uint16, timestamp time.Time, state *models.AnalysisState, report *models.TriageReport) {
	secState := state.SecurityState

	// Initialize nested maps if needed
	if secState.ScannedPortsPerIP[srcIP] == nil {
		secState.ScannedPortsPerIP[srcIP] = make(map[string]map[uint16]bool)
	}
	if secState.ScannedPortsPerIP[srcIP][dstIP] == nil {
		secState.ScannedPortsPerIP[srcIP][dstIP] = make(map[uint16]bool)
	}

	// Track the port
	secState.ScannedPortsPerIP[srcIP][dstIP][dstPort] = true

	// Track total attempts
	pairKey := fmt.Sprintf("%s->%s", srcIP, dstIP)
	secState.ConnectionsPerIPPair[pairKey]++
	secState.ScanAttemptsPerIP[srcIP]++

	// Check for horizontal scan (many ports on single target)
	portsScanned := len(secState.ScannedPortsPerIP[srcIP][dstIP])
	if portsScanned >= p.horizontalThreshold {
		p.reportPortScan(srcIP, dstIP, "Horizontal", portsScanned, secState.ScannedPortsPerIP[srcIP][dstIP], timestamp, report)
	}

	// Check for vertical scan (same port on many targets)
	targetsOnPort := p.countTargetsOnPort(srcIP, dstPort, secState)
	if targetsOnPort >= p.verticalThreshold {
		p.reportVerticalScan(srcIP, dstPort, targetsOnPort, timestamp, report)
	}

	// Check for block scan (many attempts overall)
	if secState.ScanAttemptsPerIP[srcIP] >= p.totalThreshold {
		totalPorts := p.countTotalPorts(srcIP, secState)
		p.reportPortScan(srcIP, "", "Block", totalPorts, nil, timestamp, report)
	}
}

func (p *PortScanAnalyzer) countTargetsOnPort(srcIP string, port uint16, secState *models.SecurityState) int {
	count := 0
	for _, dstPorts := range secState.ScannedPortsPerIP[srcIP] {
		if dstPorts[port] {
			count++
		}
	}
	return count
}

func (p *PortScanAnalyzer) countTotalPorts(srcIP string, secState *models.SecurityState) int {
	uniquePorts := make(map[uint16]bool)
	for _, dstPorts := range secState.ScannedPortsPerIP[srcIP] {
		for port := range dstPorts {
			uniquePorts[port] = true
		}
	}
	return len(uniquePorts)
}

func (p *PortScanAnalyzer) reportPortScan(srcIP, dstIP, scanType string, portsScanned int, ports map[uint16]bool, timestamp time.Time, report *models.TriageReport) {
	// Check if already reported
	for _, finding := range report.Security.PortScanFindings {
		if finding.SourceIP == srcIP && finding.Type == scanType && finding.TargetIP == dstIP {
			return
		}
	}

	// Get sample ports
	var samplePorts []uint16
	count := 0
	for port := range ports {
		if count >= 10 {
			break
		}
		samplePorts = append(samplePorts, port)
		count++
	}

	severity := p.calculateSeverity(portsScanned, scanType)

	finding := models.PortScanFinding{
		Timestamp:    float64(timestamp.UnixNano()) / 1e9,
		SourceIP:     srcIP,
		TargetIP:     dstIP,
		Type:         scanType,
		PortsScanned: portsScanned,
		SamplePorts:  samplePorts,
		Severity:     severity,
	}

	report.Security.PortScanFindings = append(report.Security.PortScanFindings, finding)
}

func (p *PortScanAnalyzer) reportVerticalScan(srcIP string, port uint16, targetCount int, timestamp time.Time, report *models.TriageReport) {
	// Check if already reported
	for _, finding := range report.Security.PortScanFindings {
		if finding.SourceIP == srcIP && finding.Type == "Vertical" {
			return
		}
	}

	severity := p.calculateSeverity(targetCount, "Vertical")

	finding := models.PortScanFinding{
		Timestamp:    float64(timestamp.UnixNano()) / 1e9,
		SourceIP:     srcIP,
		Type:         "Vertical",
		PortsScanned: targetCount,
		SamplePorts:  []uint16{port},
		Severity:     severity,
	}

	report.Security.PortScanFindings = append(report.Security.PortScanFindings, finding)
}

func (p *PortScanAnalyzer) calculateSeverity(count int, scanType string) string {
	var threshold int
	switch scanType {
	case "Horizontal":
		threshold = p.horizontalThreshold
	case "Vertical":
		threshold = p.verticalThreshold
	case "Block":
		threshold = p.totalThreshold
	default:
		threshold = 25
	}

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
