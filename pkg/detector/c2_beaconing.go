package detector

import (
	"fmt"
	"math"
	"time"

	"github.com/gocisse/sdwan-triage/pkg/models"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// C2 Beaconing detection thresholds
const (
	C2MinConnections     = 15     // Minimum connections to analyze
	C2MaxJitterPercent   = 15.0   // Maximum jitter percentage for beaconing
	C2MinInterval        = 10.0   // Minimum beacon interval in seconds
	C2MaxInterval        = 3600.0 // Maximum beacon interval (1 hour)
	C2MaxPayloadVariance = 0.15   // Maximum payload size variance (coefficient of variation)
	C2DetectionWindowSec = 300.0  // 5-minute detection window
)

// C2BeaconingAnalyzer detects C2 beaconing patterns
type C2BeaconingAnalyzer struct {
	flows     map[string]*c2FlowTracker
	lastReset time.Time
}

type c2FlowTracker struct {
	SrcIP        string
	DstIP        string
	DstPort      uint16
	Protocol     string
	Timestamps   []time.Time
	PayloadSizes []int
	FirstSeen    time.Time
	LastSeen     time.Time
}

// NewC2BeaconingAnalyzer creates a new C2 beaconing analyzer
func NewC2BeaconingAnalyzer() *C2BeaconingAnalyzer {
	return &C2BeaconingAnalyzer{
		flows: make(map[string]*c2FlowTracker),
	}
}

// AnalyzeTCP processes TCP packets for C2 beaconing patterns
func (c *C2BeaconingAnalyzer) AnalyzeTCP(packet gopacket.Packet, state *models.AnalysisState, report *models.TriageReport) {
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		return
	}

	tcp := tcpLayer.(*layers.TCP)

	// Only track SYN packets (new connections) or data packets
	if !tcp.SYN && len(tcp.Payload) == 0 {
		return
	}

	ipInfo := ExtractIPInfo(packet)
	if ipInfo == nil {
		return
	}

	timestamp := packet.Metadata().Timestamp
	c.maybeReset(timestamp)

	// C2 beaconing: internal host -> external server (outbound only)
	// Skip if source is external (server responses are not beaconing)
	if !models.IsPrivateOrReservedIP(ipInfo.SrcIP) {
		return
	}
	// Skip if destination is internal
	if models.IsPrivateOrReservedIP(ipInfo.DstIP) {
		return
	}

	dstPort := uint16(tcp.DstPort)
	// Skip well-known service ports that commonly have keep-alive patterns
	if dstPort == 80 || dstPort == 443 || dstPort == 8080 || dstPort == 8443 {
		return
	}
	payloadSize := len(tcp.Payload)

	key := fmt.Sprintf("%s->%s:%d", ipInfo.SrcIP, ipInfo.DstIP, dstPort)

	flow, exists := c.flows[key]
	if !exists {
		flow = &c2FlowTracker{
			SrcIP:     ipInfo.SrcIP,
			DstIP:     ipInfo.DstIP,
			DstPort:   dstPort,
			Protocol:  "TCP",
			FirstSeen: timestamp,
		}
		c.flows[key] = flow
	}

	flow.Timestamps = append(flow.Timestamps, timestamp)
	if payloadSize > 0 {
		flow.PayloadSizes = append(flow.PayloadSizes, payloadSize)
	}
	flow.LastSeen = timestamp

	// Check for beaconing when we have enough data
	if len(flow.Timestamps) >= C2MinConnections {
		c.checkBeaconing(key, flow, report)
	}
}

// AnalyzeUDP processes UDP packets for C2 beaconing patterns
func (c *C2BeaconingAnalyzer) AnalyzeUDP(packet gopacket.Packet, state *models.AnalysisState, report *models.TriageReport) {
	udpLayer := packet.Layer(layers.LayerTypeUDP)
	if udpLayer == nil {
		return
	}

	udp := udpLayer.(*layers.UDP)
	ipInfo := ExtractIPInfo(packet)
	if ipInfo == nil {
		return
	}

	timestamp := packet.Metadata().Timestamp

	// C2 beaconing: internal host -> external server (outbound only)
	if !models.IsPrivateOrReservedIP(ipInfo.SrcIP) {
		return
	}
	if models.IsPrivateOrReservedIP(ipInfo.DstIP) {
		return
	}

	dstPort := uint16(udp.DstPort)
	// Skip common services
	if dstPort == 53 || dstPort == 123 || dstPort == 161 || dstPort == 514 || dstPort == 67 || dstPort == 68 || dstPort == 443 {
		return
	}

	payloadSize := len(udp.Payload)
	key := fmt.Sprintf("%s->%s:%d/udp", ipInfo.SrcIP, ipInfo.DstIP, dstPort)

	flow, exists := c.flows[key]
	if !exists {
		flow = &c2FlowTracker{
			SrcIP:     ipInfo.SrcIP,
			DstIP:     ipInfo.DstIP,
			DstPort:   dstPort,
			Protocol:  "UDP",
			FirstSeen: timestamp,
		}
		c.flows[key] = flow
	}

	flow.Timestamps = append(flow.Timestamps, timestamp)
	if payloadSize > 0 {
		flow.PayloadSizes = append(flow.PayloadSizes, payloadSize)
	}
	flow.LastSeen = timestamp

	if len(flow.Timestamps) >= C2MinConnections {
		c.checkBeaconing(key, flow, report)
	}
}

func (c *C2BeaconingAnalyzer) checkBeaconing(key string, flow *c2FlowTracker, report *models.TriageReport) {
	// Already reported?
	for _, f := range report.C2BeaconingFindings {
		if f.SourceIP == flow.SrcIP && f.DestIP == flow.DstIP && f.DestPort == flow.DstPort {
			return
		}
	}

	// Calculate inter-arrival intervals
	intervals := make([]float64, 0, len(flow.Timestamps)-1)
	for i := 1; i < len(flow.Timestamps); i++ {
		interval := flow.Timestamps[i].Sub(flow.Timestamps[i-1]).Seconds()
		if interval > 0 && interval <= C2MaxInterval {
			intervals = append(intervals, interval)
		}
	}

	if len(intervals) < C2MinConnections-1 {
		return
	}

	// Calculate mean interval
	var sumInterval float64
	for _, iv := range intervals {
		sumInterval += iv
	}
	meanInterval := sumInterval / float64(len(intervals))

	if meanInterval < C2MinInterval || meanInterval > C2MaxInterval {
		return
	}

	// Calculate jitter (coefficient of variation of intervals)
	var sumSquaredDiff float64
	for _, iv := range intervals {
		diff := iv - meanInterval
		sumSquaredDiff += diff * diff
	}
	stdDev := math.Sqrt(sumSquaredDiff / float64(len(intervals)))
	jitterPct := (stdDev / meanInterval) * 100

	if jitterPct > C2MaxJitterPercent {
		return // Too much jitter, not beaconing
	}

	// Calculate payload size consistency
	avgPayload := 0
	payloadVariance := 0.0
	if len(flow.PayloadSizes) > 0 {
		var sumPayload int
		for _, s := range flow.PayloadSizes {
			sumPayload += s
		}
		avgPayload = sumPayload / len(flow.PayloadSizes)

		if avgPayload > 0 {
			var sumSqDiff float64
			for _, s := range flow.PayloadSizes {
				diff := float64(s) - float64(avgPayload)
				sumSqDiff += diff * diff
			}
			payloadStdDev := math.Sqrt(sumSqDiff / float64(len(flow.PayloadSizes)))
			payloadVariance = payloadStdDev / float64(avgPayload)
		}
	}

	// Determine confidence
	confidence := "Low"
	severity := "Warning"
	if jitterPct < 5.0 && payloadVariance < 0.05 {
		confidence = "High"
		severity = "Critical"
	} else if jitterPct < 10.0 && payloadVariance < C2MaxPayloadVariance {
		confidence = "Medium"
		severity = "Warning"
	} else if jitterPct < C2MaxJitterPercent {
		confidence = "Low"
		severity = "Info"
	} else {
		return // Not confident enough
	}

	ts := float64(flow.LastSeen.UnixNano()) / 1e9

	report.C2BeaconingFindings = append(report.C2BeaconingFindings, models.C2BeaconingFinding{
		Timestamp:       ts,
		SourceIP:        flow.SrcIP,
		DestIP:          flow.DstIP,
		DestPort:        flow.DstPort,
		Protocol:        flow.Protocol,
		Severity:        severity,
		Description:     fmt.Sprintf("Suspected C2 beaconing: %s -> %s:%d every ~%.0fs (jitter: %.1f%%, %d connections, avg payload: %d bytes)", flow.SrcIP, flow.DstIP, flow.DstPort, meanInterval, jitterPct, len(flow.Timestamps), avgPayload),
		BeaconInterval:  meanInterval,
		IntervalJitter:  jitterPct,
		ConnectionCount: len(flow.Timestamps),
		AvgPayloadSize:  avgPayload,
		PayloadVariance: payloadVariance,
		Confidence:      confidence,
	})
}

func (c *C2BeaconingAnalyzer) maybeReset(timestamp time.Time) {
	if c.lastReset.IsZero() {
		c.lastReset = timestamp
		return
	}
	if timestamp.Sub(c.lastReset).Seconds() >= C2DetectionWindowSec {
		c.flows = make(map[string]*c2FlowTracker)
		c.lastReset = timestamp
	}
}
