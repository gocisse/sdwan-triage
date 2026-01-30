package analyzer

import (
	"fmt"
	"sort"
	"time"

	"github.com/gocisse/sdwan-triage/pkg/models"
	"github.com/google/gopacket"
)

// BandwidthAnalyzer tracks bandwidth over time
type BandwidthAnalyzer struct {
	buckets      map[int64]*bandwidthBucket
	intervalMs   int64
	referenceIPs map[string]bool // IPs considered "local" for in/out classification
	verbose      bool
	firstPacket  time.Time
	lastPacket   time.Time
	totalBytes   uint64
	totalPackets uint64
}

// bandwidthBucket holds data for a single time bucket
type bandwidthBucket struct {
	timestamp     time.Time
	bytesIn       uint64
	bytesOut      uint64
	packetsIn     uint64
	packetsOut    uint64
	activeFlows   map[string]bool
	protocolBytes map[string]uint64
	srcBytes      map[string]uint64
	dstBytes      map[string]uint64
}

// NewBandwidthAnalyzer creates a new bandwidth analyzer
func NewBandwidthAnalyzer(intervalMs int64, verbose bool) *BandwidthAnalyzer {
	if intervalMs <= 0 {
		intervalMs = 1000 // Default 1 second buckets
	}
	return &BandwidthAnalyzer{
		buckets:      make(map[int64]*bandwidthBucket),
		intervalMs:   intervalMs,
		referenceIPs: make(map[string]bool),
		verbose:      verbose,
	}
}

// SetReferenceIPs sets the IPs considered "local" for in/out classification
func (ba *BandwidthAnalyzer) SetReferenceIPs(ips []string) {
	for _, ip := range ips {
		ba.referenceIPs[ip] = true
	}
}

// ProcessPacket processes a packet for bandwidth analysis
func (ba *BandwidthAnalyzer) ProcessPacket(packet gopacket.Packet) {
	metadata := packet.Metadata()
	if metadata == nil {
		return
	}

	timestamp := metadata.Timestamp
	packetLen := uint64(metadata.Length)
	if packetLen == 0 {
		packetLen = uint64(metadata.CaptureLength)
	}

	// Track first/last packet times
	if ba.firstPacket.IsZero() || timestamp.Before(ba.firstPacket) {
		ba.firstPacket = timestamp
	}
	if timestamp.After(ba.lastPacket) {
		ba.lastPacket = timestamp
	}

	ba.totalBytes += packetLen
	ba.totalPackets++

	// Get bucket key (timestamp rounded to interval)
	bucketKey := timestamp.UnixMilli() / ba.intervalMs

	// Get or create bucket
	bucket, exists := ba.buckets[bucketKey]
	if !exists {
		bucket = &bandwidthBucket{
			timestamp:     time.UnixMilli(bucketKey * ba.intervalMs),
			activeFlows:   make(map[string]bool),
			protocolBytes: make(map[string]uint64),
			srcBytes:      make(map[string]uint64),
			dstBytes:      make(map[string]uint64),
		}
		ba.buckets[bucketKey] = bucket
	}

	// Get network layer info
	networkLayer := packet.NetworkLayer()
	if networkLayer == nil {
		return
	}

	srcIP := networkLayer.NetworkFlow().Src().String()
	dstIP := networkLayer.NetworkFlow().Dst().String()

	// Determine direction based on reference IPs
	isOutbound := ba.isOutbound(srcIP, dstIP)

	if isOutbound {
		bucket.bytesOut += packetLen
		bucket.packetsOut++
	} else {
		bucket.bytesIn += packetLen
		bucket.packetsIn++
	}

	// Track flow
	flowKey := fmt.Sprintf("%s->%s", srcIP, dstIP)
	bucket.activeFlows[flowKey] = true

	// Track protocol
	protocol := "Other"
	if transportLayer := packet.TransportLayer(); transportLayer != nil {
		protocol = transportLayer.LayerType().String()
	}
	bucket.protocolBytes[protocol] += packetLen

	// Track top talkers
	bucket.srcBytes[srcIP] += packetLen
	bucket.dstBytes[dstIP] += packetLen
}

// isOutbound determines if traffic is outbound based on reference IPs
func (ba *BandwidthAnalyzer) isOutbound(srcIP, dstIP string) bool {
	// If we have reference IPs, use them
	if len(ba.referenceIPs) > 0 {
		srcIsLocal := ba.referenceIPs[srcIP]
		dstIsLocal := ba.referenceIPs[dstIP]
		if srcIsLocal && !dstIsLocal {
			return true
		}
		if !srcIsLocal && dstIsLocal {
			return false
		}
	}

	// Default heuristic: private IPs are "local"
	srcIsPrivate := isPrivateIP(srcIP)
	dstIsPrivate := isPrivateIP(dstIP)

	if srcIsPrivate && !dstIsPrivate {
		return true
	}
	return false
}

// isPrivateIP checks if an IP is in a private range
func isPrivateIP(ip string) bool {
	// Simple check for common private ranges
	if len(ip) < 7 {
		return false
	}
	return ip[:3] == "10." ||
		ip[:4] == "192." ||
		ip[:4] == "172." ||
		ip[:3] == "fc0" || ip[:3] == "fd0" || // IPv6 ULA
		ip == "127.0.0.1" ||
		ip == "::1"
}

// GetTimeSeries returns the bandwidth time series data
func (ba *BandwidthAnalyzer) GetTimeSeries() *models.BandwidthTimeSeries {
	if len(ba.buckets) == 0 {
		return nil
	}

	// Sort bucket keys
	keys := make([]int64, 0, len(ba.buckets))
	for k := range ba.buckets {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })

	// Build result
	result := &models.BandwidthTimeSeries{
		Buckets:      make([]models.BandwidthBucket, 0, len(keys)),
		IntervalMs:   ba.intervalMs,
		StartTime:    ba.firstPacket,
		EndTime:      ba.lastPacket,
		TotalBytes:   ba.totalBytes,
		TotalPackets: ba.totalPackets,
	}

	var peakBytesPerSec uint64
	var totalBytesPerSec uint64

	for _, key := range keys {
		bucket := ba.buckets[key]

		// Find top protocol
		topProtocol := ""
		topProtocolBytes := uint64(0)
		for proto, bytes := range bucket.protocolBytes {
			if bytes > topProtocolBytes {
				topProtocol = proto
				topProtocolBytes = bytes
			}
		}

		// Find top talkers
		topSrc := ""
		topSrcBytes := uint64(0)
		for src, bytes := range bucket.srcBytes {
			if bytes > topSrcBytes {
				topSrc = src
				topSrcBytes = bytes
			}
		}

		topDst := ""
		topDstBytes := uint64(0)
		for dst, bytes := range bucket.dstBytes {
			if bytes > topDstBytes {
				topDst = dst
				topDstBytes = bytes
			}
		}

		// Calculate bytes per second for this bucket
		bucketTotal := bucket.bytesIn + bucket.bytesOut
		bytesPerSec := bucketTotal * 1000 / uint64(ba.intervalMs)
		if bytesPerSec > peakBytesPerSec {
			peakBytesPerSec = bytesPerSec
		}
		totalBytesPerSec += bytesPerSec

		modelBucket := models.BandwidthBucket{
			Timestamp:     bucket.timestamp,
			TimestampUnix: float64(bucket.timestamp.UnixNano()) / 1e9,
			BytesIn:       bucket.bytesIn,
			BytesOut:      bucket.bytesOut,
			PacketsIn:     bucket.packetsIn,
			PacketsOut:    bucket.packetsOut,
			ActiveFlows:   len(bucket.activeFlows),
			TopProtocol:   topProtocol,
			TopTalkerSrc:  topSrc,
			TopTalkerDst:  topDst,
			ProtocolBytes: bucket.protocolBytes,
		}

		result.Buckets = append(result.Buckets, modelBucket)
	}

	result.PeakBytesPerSec = peakBytesPerSec
	if len(keys) > 0 {
		result.AvgBytesPerSec = totalBytesPerSec / uint64(len(keys))
	}

	return result
}

// DetectTrafficGaps finds significant gaps in traffic
func (ba *BandwidthAnalyzer) DetectTrafficGaps(minGapSeconds float64) []TrafficGap {
	if len(ba.buckets) < 2 {
		return nil
	}

	// Sort bucket keys
	keys := make([]int64, 0, len(ba.buckets))
	for k := range ba.buckets {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })

	var gaps []TrafficGap
	minGapMs := int64(minGapSeconds * 1000)

	for i := 1; i < len(keys); i++ {
		gapMs := (keys[i] - keys[i-1]) * ba.intervalMs
		if gapMs >= minGapMs {
			gap := TrafficGap{
				StartTime:   time.UnixMilli(keys[i-1] * ba.intervalMs),
				EndTime:     time.UnixMilli(keys[i] * ba.intervalMs),
				DurationSec: float64(gapMs) / 1000,
			}
			gaps = append(gaps, gap)
		}
	}

	return gaps
}

// TrafficGap represents a gap in traffic
type TrafficGap struct {
	StartTime   time.Time
	EndTime     time.Time
	DurationSec float64
}

// GetPlainEnglishSummary generates human-readable summaries
func (ba *BandwidthAnalyzer) GetPlainEnglishSummary(report *models.TriageReport, gaps []TrafficGap) *models.PlainEnglishSummary {
	summary := &models.PlainEnglishSummary{
		KeyFindings:       make([]string, 0),
		QuickActions:      make([]string, 0),
		TrafficGaps:       make([]string, 0),
		PerformanceIssues: make([]string, 0),
		SecurityAlerts:    make([]string, 0),
	}

	// Determine overall health
	if report.RiskScore == 0 {
		summary.OverallHealth = "Healthy"
		summary.HealthIcon = "🟢"
		summary.HealthColor = "health-good"
	} else if report.RiskScore <= 20 {
		summary.OverallHealth = "Warning"
		summary.HealthIcon = "🟡"
		summary.HealthColor = "health-warning"
	} else {
		summary.OverallHealth = "Critical"
		summary.HealthIcon = "🔴"
		summary.HealthColor = "health-critical"
	}

	// DNS findings
	if len(report.DNSAnomalies) > 0 {
		topDomain := ""
		if len(report.DNSAnomalies) > 0 {
			topDomain = report.DNSAnomalies[0].Query
		}
		summary.KeyFindings = append(summary.KeyFindings,
			fmt.Sprintf("⚠️ %d DNS timeouts/anomalies detected. Top affected domain: %s",
				len(report.DNSAnomalies), topDomain))
	}

	// TLS findings
	tlsGood := 0
	tlsBad := 0
	for _, finding := range report.Security.TLSSecurityFindings {
		if finding.Severity == "High" || finding.Severity == "Critical" {
			tlsBad++
		}
	}
	if len(report.TLSFlows) > 0 {
		tlsGood = len(report.TLSFlows) - tlsBad
		if tlsBad == 0 {
			summary.KeyFindings = append(summary.KeyFindings,
				fmt.Sprintf("✅ TLS 1.2/1.3 used in %d connections. No weak ciphers found.", tlsGood))
		} else {
			summary.SecurityAlerts = append(summary.SecurityAlerts,
				fmt.Sprintf("🔴 %d TLS connections using weak ciphers or outdated protocols", tlsBad))
		}
	}

	// Traffic gaps
	for _, gap := range gaps {
		summary.TrafficGaps = append(summary.TrafficGaps,
			fmt.Sprintf("📉 %.1f-second gap in traffic between %s–%s — possible path failover or outage",
				gap.DurationSec,
				gap.StartTime.Format("15:04:05"),
				gap.EndTime.Format("15:04:05")))
	}

	// TCP retransmissions
	if len(report.TCPRetransmissions) > 10 {
		summary.PerformanceIssues = append(summary.PerformanceIssues,
			fmt.Sprintf("🟡 %d TCP retransmissions detected — indicates packet loss or congestion",
				len(report.TCPRetransmissions)))
	}

	// Failed handshakes
	if len(report.FailedHandshakes) > 0 {
		summary.PerformanceIssues = append(summary.PerformanceIssues,
			fmt.Sprintf("🔴 %d failed TCP connections — services may be unreachable or blocked",
				len(report.FailedHandshakes)))
	}

	// High RTT
	if len(report.RTTAnalysis) > 0 {
		maxRTT := float64(0)
		for _, rtt := range report.RTTAnalysis {
			if rtt.AvgRTT > maxRTT {
				maxRTT = rtt.AvgRTT
			}
		}
		if maxRTT > 200 {
			summary.PerformanceIssues = append(summary.PerformanceIssues,
				fmt.Sprintf("🟡 High latency detected — up to %.0fms RTT on some connections", maxRTT))
		}
	}

	// Security alerts
	if len(report.Security.DDoSFindings) > 0 {
		summary.SecurityAlerts = append(summary.SecurityAlerts,
			fmt.Sprintf("🔴 Potential DDoS attack detected — %d flood patterns identified",
				len(report.Security.DDoSFindings)))
	}

	if len(report.Security.PortScanFindings) > 0 {
		summary.SecurityAlerts = append(summary.SecurityAlerts,
			fmt.Sprintf("🟡 Port scanning activity from %d sources",
				len(report.Security.PortScanFindings)))
	}

	if len(report.Security.IOCFindings) > 0 {
		summary.SecurityAlerts = append(summary.SecurityAlerts,
			fmt.Sprintf("🔴 %d Indicators of Compromise matched — investigate immediately",
				len(report.Security.IOCFindings)))
	}

	// Quick actions
	if len(summary.SecurityAlerts) > 0 {
		summary.QuickActions = append(summary.QuickActions,
			"Review security alerts and isolate affected systems if needed")
	}
	if len(summary.PerformanceIssues) > 0 {
		summary.QuickActions = append(summary.QuickActions,
			"Check network links between hosts with high retransmissions")
	}
	if len(summary.TrafficGaps) > 0 {
		summary.QuickActions = append(summary.QuickActions,
			"Investigate traffic gaps for potential failover or connectivity issues")
	}
	if len(summary.QuickActions) == 0 {
		summary.QuickActions = append(summary.QuickActions,
			"No immediate actions required — continue monitoring")
	}

	return summary
}
