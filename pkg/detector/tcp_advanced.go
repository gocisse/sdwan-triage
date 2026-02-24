package detector

import (
	"fmt"

	"github.com/gocisse/sdwan-triage/pkg/models"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// TCP Advanced analysis thresholds
const (
	ZeroWindowThreshold    = 3   // Number of zero-window events to report
	SmallWindowThreshold   = 5   // Number of small-window events to report
	SmallWindowSize        = 1024 // Window size considered "small"
	OutOfOrderMinCount     = 10  // Minimum OOO packets to report
	OutOfOrderMinPercent   = 2.0 // Minimum OOO percentage to report
)

// TCPAdvancedAnalyzer detects TCP window issues and out-of-order packets
type TCPAdvancedAnalyzer struct {
	windowIssues map[string]*tcpWindowTracker
	oooFlows     map[string]*tcpOOOTracker
}

type tcpWindowTracker struct {
	SrcIP       string
	DstIP       string
	SrcPort     uint16
	DstPort     uint16
	ZeroCount   int
	SmallCount  int
	LastWindow  uint16
}

type tcpOOOTracker struct {
	SrcIP        string
	DstIP        string
	SrcPort      uint16
	DstPort      uint16
	LastSeq      uint32
	TotalPackets int
	OOOCount     int
	Initialized  bool
}

// NewTCPAdvancedAnalyzer creates a new TCP advanced analyzer
func NewTCPAdvancedAnalyzer() *TCPAdvancedAnalyzer {
	return &TCPAdvancedAnalyzer{
		windowIssues: make(map[string]*tcpWindowTracker),
		oooFlows:     make(map[string]*tcpOOOTracker),
	}
}

// Analyze processes TCP packets for window issues and out-of-order detection
func (t *TCPAdvancedAnalyzer) Analyze(packet gopacket.Packet, state *models.AnalysisState, report *models.TriageReport) {
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		return
	}

	tcp, ok := tcpLayer.(*layers.TCP)
	if !ok {
		return
	}

	ipInfo := ExtractIPInfo(packet)
	if ipInfo == nil {
		return
	}

	srcPort := uint16(tcp.SrcPort)
	dstPort := uint16(tcp.DstPort)
	flowKey := fmt.Sprintf("%s:%d->%s:%d", ipInfo.SrcIP, srcPort, ipInfo.DstIP, dstPort)
	ts := float64(packet.Metadata().Timestamp.UnixNano()) / 1e9

	// --- Window Size Analysis ---
	t.analyzeWindow(tcp, ipInfo, srcPort, dstPort, flowKey, ts, report)

	// --- Out-of-Order Detection ---
	if len(tcp.Payload) > 0 {
		t.analyzeOutOfOrder(tcp, ipInfo, srcPort, dstPort, flowKey, report)
	}
}

func (t *TCPAdvancedAnalyzer) analyzeWindow(tcp *layers.TCP, ipInfo *PacketIPInfo, srcPort, dstPort uint16, flowKey string, ts float64, report *models.TriageReport) {
	// Skip SYN/FIN/RST packets for window analysis
	if tcp.SYN || tcp.FIN || tcp.RST {
		return
	}

	tracker, exists := t.windowIssues[flowKey]
	if !exists {
		tracker = &tcpWindowTracker{
			SrcIP:   ipInfo.SrcIP,
			DstIP:   ipInfo.DstIP,
			SrcPort: srcPort,
			DstPort: dstPort,
		}
		t.windowIssues[flowKey] = tracker
	}

	tracker.LastWindow = tcp.Window

	// Zero Window detection
	if tcp.Window == 0 {
		tracker.ZeroCount++
		if tracker.ZeroCount == ZeroWindowThreshold {
			report.TCPWindowFindings = append(report.TCPWindowFindings, models.TCPWindowFinding{
				Timestamp:   ts,
				SrcIP:       ipInfo.SrcIP,
				DstIP:       ipInfo.DstIP,
				SrcPort:     srcPort,
				DstPort:     dstPort,
				Type:        "Zero Window",
				WindowSize:  0,
				Severity:    "Critical",
				Description: fmt.Sprintf("TCP Zero Window from %s:%d — receiver buffer is full, sender must stop transmitting. This causes application stalls.", ipInfo.SrcIP, srcPort),
				Count:       tracker.ZeroCount,
			})
		}
	}

	// Small Window detection
	if tcp.Window > 0 && tcp.Window <= SmallWindowSize {
		tracker.SmallCount++
		if tracker.SmallCount == SmallWindowThreshold {
			report.TCPWindowFindings = append(report.TCPWindowFindings, models.TCPWindowFinding{
				Timestamp:   ts,
				SrcIP:       ipInfo.SrcIP,
				DstIP:       ipInfo.DstIP,
				SrcPort:     srcPort,
				DstPort:     dstPort,
				Type:        "Small Window",
				WindowSize:  tcp.Window,
				Severity:    "Warning",
				Description: fmt.Sprintf("TCP Small Window (%d bytes) from %s:%d — receiver is struggling to keep up, throughput will be limited.", tcp.Window, ipInfo.SrcIP, srcPort),
				Count:       tracker.SmallCount,
			})
		}
	}
}

func (t *TCPAdvancedAnalyzer) analyzeOutOfOrder(tcp *layers.TCP, ipInfo *PacketIPInfo, srcPort, dstPort uint16, flowKey string, report *models.TriageReport) {
	tracker, exists := t.oooFlows[flowKey]
	if !exists {
		tracker = &tcpOOOTracker{
			SrcIP:   ipInfo.SrcIP,
			DstIP:   ipInfo.DstIP,
			SrcPort: srcPort,
			DstPort: dstPort,
		}
		t.oooFlows[flowKey] = tracker
	}

	tracker.TotalPackets++

	if !tracker.Initialized {
		tracker.LastSeq = tcp.Seq
		tracker.Initialized = true
		return
	}

	// Detect out-of-order: sequence number is less than expected
	// (accounting for wraparound)
	expectedSeq := tracker.LastSeq + uint32(len(tcp.Payload))
	if tcp.Seq < tracker.LastSeq && (tracker.LastSeq-tcp.Seq) < 0x80000000 {
		tracker.OOOCount++
	}

	// Update last seen sequence
	if tcp.Seq > tracker.LastSeq || (tcp.Seq < tracker.LastSeq && (tracker.LastSeq-tcp.Seq) > 0x80000000) {
		tracker.LastSeq = tcp.Seq
	}
	_ = expectedSeq
}

// Finalize generates findings from accumulated out-of-order data
func (t *TCPAdvancedAnalyzer) Finalize(report *models.TriageReport) {
	for _, tracker := range t.oooFlows {
		if tracker.OOOCount < OutOfOrderMinCount || tracker.TotalPackets < 20 {
			continue
		}

		pct := float64(tracker.OOOCount) / float64(tracker.TotalPackets) * 100
		if pct < OutOfOrderMinPercent {
			continue
		}

		severity := "Warning"
		if pct > 10.0 {
			severity = "Critical"
		}

		report.TCPOutOfOrderFlows = append(report.TCPOutOfOrderFlows, models.TCPOutOfOrderFlow{
			SrcIP:           tracker.SrcIP,
			DstIP:           tracker.DstIP,
			SrcPort:         tracker.SrcPort,
			DstPort:         tracker.DstPort,
			OutOfOrderCount: tracker.OOOCount,
			TotalPackets:    tracker.TotalPackets,
			Percentage:      pct,
			Severity:        severity,
		})
	}
}
