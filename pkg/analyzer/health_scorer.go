package analyzer

import (
	"github.com/gocisse/sdwan-triage/pkg/models"
)

// HealthStatus represents the health state of a stream
type HealthStatus string

const (
	HealthStatusHealthy  HealthStatus = "Healthy"
	HealthStatusDegraded HealthStatus = "Degraded"
	HealthStatusCritical HealthStatus = "Critical"
	HealthStatusUnknown  HealthStatus = "Unknown"
)

// HealthScore contains the health assessment of a stream
type HealthScore struct {
	Status           HealthStatus
	Score            float64 // 0.0 (critical) to 100.0 (perfect)
	Icon             string
	Color            string
	PrimaryIssue     string
	SecondaryIssues  []string
	PerformanceFlags []PerformanceFlag
	Recommendation   string
}

// PerformanceFlag indicates specific performance issues
type PerformanceFlag struct {
	Type        string
	Severity    string // "info", "warning", "critical"
	Description string
	Metric      string
	Expected    string
	Actual      string
}

// HealthScorer evaluates stream health based on protocol-specific criteria
type HealthScorer struct {
	classifier *AdvancedClassifier
}

// NewHealthScorer creates a new health scorer
func NewHealthScorer() *HealthScorer {
	return &HealthScorer{
		classifier: NewAdvancedClassifier(),
	}
}

// ScoreStream evaluates the health of a stream
func (hs *HealthScorer) ScoreStream(stream *models.StreamData) HealthScore {
	// Get service classification first
	classification := hs.classifier.ClassifyStream(stream)

	// Initialize score
	score := HealthScore{
		Status:           HealthStatusHealthy,
		Score:            100.0,
		Icon:             "🟢",
		Color:            "green",
		SecondaryIssues:  []string{},
		PerformanceFlags: []PerformanceFlag{},
	}

	// Evaluate based on service category
	switch classification.Category {
	case CategoryM365Exchange, CategoryM365Teams, CategoryM365SharePoint, CategoryM365OneDrive:
		hs.evaluateMicrosoft365(stream, &classification, &score)
	case CategoryDNS:
		hs.evaluateDNS(stream, &classification, &score)
	case CategoryNTP:
		hs.evaluateNTP(stream, &classification, &score)
	case CategoryLDAP, CategoryKerberos:
		hs.evaluateInfrastructure(stream, &classification, &score)
	case CategoryVoIP:
		hs.evaluateVoIP(stream, &classification, &score)
	case CategoryFileSharing:
		hs.evaluateSMB(stream, &classification, &score)
	case CategoryCiscoViptela, CategoryVeloCloud, CategoryAruba, CategoryPaloAlto, CategorySilverPeak, CategoryFortinet:
		hs.evaluateSDWANControl(stream, &classification, &score)
	default:
		hs.evaluateGenericTCP(stream, &classification, &score)
	}

	// Update status based on final score
	if score.Score >= 80 {
		score.Status = HealthStatusHealthy
		score.Icon = "🟢"
		score.Color = "green"
	} else if score.Score >= 50 {
		score.Status = HealthStatusDegraded
		score.Icon = "🟡"
		score.Color = "yellow"
	} else {
		score.Status = HealthStatusCritical
		score.Icon = "🔴"
		score.Color = "red"
	}

	// Set primary issue if not already set
	if score.PrimaryIssue == "" {
		if score.Status == HealthStatusHealthy {
			score.PrimaryIssue = "Stream operating within normal parameters"
		} else if len(score.PerformanceFlags) > 0 {
			score.PrimaryIssue = score.PerformanceFlags[0].Description
		} else {
			score.PrimaryIssue = "Performance degradation detected"
		}
	}

	return score
}

// evaluateMicrosoft365 checks Microsoft 365 service health
func (hs *HealthScorer) evaluateMicrosoft365(stream *models.StreamData, classification *ServiceClassification, score *HealthScore) {
	baseline := classification.TypicalBaseline

	// Check duration for handshake completion
	if stream.Duration < 1.0 {
		// Still establishing connection
		if stream.Duration > float64(baseline.HandshakeTimeoutSec) {
			score.Score -= 30
			score.PerformanceFlags = append(score.PerformanceFlags, PerformanceFlag{
				Type:        "handshake_timeout",
				Severity:    "critical",
				Description: "TLS handshake exceeding expected time",
				Metric:      "Handshake Duration",
				Expected:    "< 3 seconds",
				Actual:      fmtDuration(stream.Duration),
			})
			score.PrimaryIssue = "Microsoft 365 connection slow to establish"
		}
	}

	// Check for retransmissions
	retransmitCount := hs.countRetransmissions(stream)
	if retransmitCount > 0 {
		retransmitRate := float64(retransmitCount) / float64(stream.PacketCount)
		if retransmitRate > 0.05 {
			score.Score -= 25
			score.PerformanceFlags = append(score.PerformanceFlags, PerformanceFlag{
				Type:        "high_retransmits",
				Severity:    "warning",
				Description: "High packet retransmission rate",
				Metric:      "Retransmit Rate",
				Expected:    "< 1%",
				Actual:      fmtPercent(retransmitRate),
			})
			score.SecondaryIssues = append(score.SecondaryIssues, "Network reliability issues detected")
		}
	}

	// Check for resets
	if hs.hasReset(stream) {
		score.Score -= 40
		score.PerformanceFlags = append(score.PerformanceFlags, PerformanceFlag{
			Type:        "connection_reset",
			Severity:    "critical",
			Description: "Connection terminated unexpectedly",
			Metric:      "TCP Reset",
			Expected:    "Clean closure",
			Actual:      "RST packet detected",
		})
		score.PrimaryIssue = "Microsoft 365 connection aborted"
	}

	// Teams-specific checks
	if classification.Category == CategoryM365Teams {
		// Teams requires low latency
		if baseline.ExpectedLatencyMs < 50 {
			// Check for large gaps between packets (indicates jitter)
			maxGap := hs.getMaxGap(stream)
			if maxGap > 0.1 { // 100ms gap
				score.Score -= 20
				score.PerformanceFlags = append(score.PerformanceFlags, PerformanceFlag{
					Type:        "high_jitter",
					Severity:    "warning",
					Description: "Packet timing inconsistency detected",
					Metric:      "Max Gap",
					Expected:    "< 50ms",
					Actual:      fmtDuration(maxGap),
				})
				score.SecondaryIssues = append(score.SecondaryIssues, "May impact Teams call quality")
			}
		}
	}

	score.Recommendation = "Monitor Microsoft 365 connectivity and check network path quality"
}

// evaluateDNS checks DNS resolution health
func (hs *HealthScorer) evaluateDNS(stream *models.StreamData, classification *ServiceClassification, score *HealthScore) {
	baseline := classification.TypicalBaseline

	// DNS should be fast
	if stream.Duration > float64(baseline.HandshakeTimeoutSec) {
		score.Score -= 40
		score.PerformanceFlags = append(score.PerformanceFlags, PerformanceFlag{
			Type:        "dns_timeout",
			Severity:    "critical",
			Description: "DNS query taking too long",
			Metric:      "Query Duration",
			Expected:    "< 2 seconds",
			Actual:      fmtDuration(stream.Duration),
		})
		score.PrimaryIssue = "DNS resolution timeout"
	}

	// Check for retries (multiple queries)
	if stream.PacketCount > 4 { // Normal DNS is 2 packets (query + response)
		score.Score -= 20
		score.PerformanceFlags = append(score.PerformanceFlags, PerformanceFlag{
			Type:        "dns_retries",
			Severity:    "warning",
			Description: "Multiple DNS queries detected",
			Metric:      "Packet Count",
			Expected:    "2-4 packets",
			Actual:      fmtCount(stream.PacketCount),
		})
		score.SecondaryIssues = append(score.SecondaryIssues, "DNS server may be unresponsive")
	}

	score.Recommendation = "Verify DNS server reachability and response times"
}

// evaluateNTP checks NTP time synchronization health
func (hs *HealthScorer) evaluateNTP(stream *models.StreamData, classification *ServiceClassification, score *HealthScore) {
	// NTP should be very quick
	if stream.Duration > 2.0 {
		score.Score -= 30
		score.PerformanceFlags = append(score.PerformanceFlags, PerformanceFlag{
			Type:        "ntp_slow",
			Severity:    "warning",
			Description: "NTP synchronization taking too long",
			Metric:      "Sync Duration",
			Expected:    "< 1 second",
			Actual:      fmtDuration(stream.Duration),
		})
		score.PrimaryIssue = "NTP time sync delayed"
	}

	// Check for excessive packets (indicates retries)
	if stream.PacketCount > 6 {
		score.Score -= 20
		score.PerformanceFlags = append(score.PerformanceFlags, PerformanceFlag{
			Type:        "ntp_retries",
			Severity:    "warning",
			Description: "Multiple NTP sync attempts",
			Metric:      "Packet Count",
			Expected:    "2-4 packets",
			Actual:      fmtCount(stream.PacketCount),
		})
		score.SecondaryIssues = append(score.SecondaryIssues, "NTP server may be unreachable")
	}

	score.Recommendation = "Check NTP server availability and network path"
}

// evaluateInfrastructure checks infrastructure service health (LDAP, Kerberos)
func (hs *HealthScorer) evaluateInfrastructure(stream *models.StreamData, classification *ServiceClassification, score *HealthScore) {
	baseline := classification.TypicalBaseline

	// Check handshake time
	if stream.Duration > float64(baseline.HandshakeTimeoutSec) {
		score.Score -= 35
		score.PerformanceFlags = append(score.PerformanceFlags, PerformanceFlag{
			Type:        "auth_timeout",
			Severity:    "critical",
			Description: "Authentication service timeout",
			Metric:      "Response Time",
			Expected:    "< 5 seconds",
			Actual:      fmtDuration(stream.Duration),
		})
		score.PrimaryIssue = "Infrastructure service unresponsive"
	}

	// Check for connection failures
	if hs.hasReset(stream) {
		score.Score -= 50
		score.PrimaryIssue = "Authentication service connection failed"
	}

	score.Recommendation = "Verify infrastructure service availability and credentials"
}

// evaluateVoIP checks VoIP/RTP stream health
func (hs *HealthScorer) evaluateVoIP(stream *models.StreamData, classification *ServiceClassification, score *HealthScore) {
	baseline := classification.TypicalBaseline

	// Check for packet loss indicators
	retransmitCount := hs.countRetransmissions(stream)
	if retransmitCount > 0 {
		retransmitRate := float64(retransmitCount) / float64(stream.PacketCount)
		if retransmitRate > baseline.ExpectedPacketLossRate {
			score.Score -= 30
			score.PerformanceFlags = append(score.PerformanceFlags, PerformanceFlag{
				Type:        "voip_packet_loss",
				Severity:    "critical",
				Description: "VoIP packet loss detected",
				Metric:      "Packet Loss",
				Expected:    "< 1%",
				Actual:      fmtPercent(retransmitRate),
			})
			score.PrimaryIssue = "VoIP call quality degraded"
		}
	}

	// Check for jitter (large gaps between packets)
	maxGap := hs.getMaxGap(stream)
	if maxGap > 0.03 { // 30ms
		score.Score -= 25
		score.PerformanceFlags = append(score.PerformanceFlags, PerformanceFlag{
			Type:        "voip_jitter",
			Severity:    "warning",
			Description: "High jitter detected",
			Metric:      "Max Jitter",
			Expected:    "< 30ms",
			Actual:      fmtDuration(maxGap),
		})
		score.SecondaryIssues = append(score.SecondaryIssues, "Audio quality may be impacted")
	}

	score.Recommendation = "Check QoS settings and network congestion"
}

// evaluateSMB checks SMB file sharing health
func (hs *HealthScorer) evaluateSMB(stream *models.StreamData, classification *ServiceClassification, score *HealthScore) {
	// Check for excessive small packets (chattiness)
	if stream.PacketCount > 100 {
		avgPacketSize := float64(stream.TotalBytes) / float64(stream.PacketCount)
		if avgPacketSize < 500 { // Small packets
			score.Score -= 20
			score.PerformanceFlags = append(score.PerformanceFlags, PerformanceFlag{
				Type:        "smb_chattiness",
				Severity:    "warning",
				Description: "SMB chattiness detected",
				Metric:      "Avg Packet Size",
				Expected:    "> 1KB",
				Actual:      fmtBytes(uint64(avgPacketSize)),
			})
			score.SecondaryIssues = append(score.SecondaryIssues, "File transfer inefficient")
		}
	}

	// Check for retransmissions
	retransmitCount := hs.countRetransmissions(stream)
	if retransmitCount > 5 {
		score.Score -= 25
		score.PerformanceFlags = append(score.PerformanceFlags, PerformanceFlag{
			Type:        "smb_retransmits",
			Severity:    "warning",
			Description: "Network reliability issues",
			Metric:      "Retransmits",
			Expected:    "< 5",
			Actual:      fmtCount(uint64(retransmitCount)),
		})
		score.SecondaryIssues = append(score.SecondaryIssues, "Check network path quality")
	}

	score.Recommendation = "Optimize SMB settings and check network performance"
}

// evaluateSDWANControl checks SD-WAN control plane health
func (hs *HealthScorer) evaluateSDWANControl(stream *models.StreamData, classification *ServiceClassification, score *HealthScore) {
	baseline := classification.TypicalBaseline

	// Control plane should establish quickly
	if stream.Duration > float64(baseline.HandshakeTimeoutSec) {
		score.Score -= 40
		score.PerformanceFlags = append(score.PerformanceFlags, PerformanceFlag{
			Type:        "control_plane_timeout",
			Severity:    "critical",
			Description: "SD-WAN control plane connection timeout",
			Metric:      "Connection Time",
			Expected:    "< 5 seconds",
			Actual:      fmtDuration(stream.Duration),
		})
		score.PrimaryIssue = "SD-WAN controller unreachable"
	}

	// Check for connection failures
	if hs.hasReset(stream) {
		score.Score -= 50
		score.PrimaryIssue = "SD-WAN control plane connection failed"
		score.SecondaryIssues = append(score.SecondaryIssues, "Site may lose policy updates")
	}

	score.Recommendation = "Verify SD-WAN controller reachability and credentials"
}

// evaluateGenericTCP checks generic TCP stream health
func (hs *HealthScorer) evaluateGenericTCP(stream *models.StreamData, classification *ServiceClassification, score *HealthScore) {
	// Check for basic connectivity issues
	if hs.hasReset(stream) {
		score.Score -= 40
		score.PrimaryIssue = "Connection terminated unexpectedly"
	}

	retransmitCount := hs.countRetransmissions(stream)
	if retransmitCount > 0 {
		retransmitRate := float64(retransmitCount) / float64(stream.PacketCount)
		if retransmitRate > 0.05 {
			score.Score -= 20
			score.SecondaryIssues = append(score.SecondaryIssues, "Network reliability issues")
		}
	}

	score.Recommendation = "Monitor connection stability and network path"
}

// Helper functions

func (hs *HealthScorer) countRetransmissions(stream *models.StreamData) int {
	count := 0
	for _, segment := range stream.Segments {
		if segment.IsRetransmit {
			count++
		}
	}
	return count
}

func (hs *HealthScorer) hasReset(stream *models.StreamData) bool {
	for _, segment := range stream.Segments {
		if segment.HasReset {
			return true
		}
	}
	return false
}

func (hs *HealthScorer) getMaxGap(stream *models.StreamData) float64 {
	maxGap := 0.0
	for _, segment := range stream.Segments {
		if segment.GapFromPrev > maxGap {
			maxGap = segment.GapFromPrev
		}
	}
	return maxGap
}

func fmtDuration(seconds float64) string {
	if seconds < 1.0 {
		return fmtFloat(seconds*1000) + " ms"
	}
	return fmtFloat(seconds) + " sec"
}

func fmtPercent(rate float64) string {
	return fmtFloat(rate*100) + "%"
}

func fmtCount(count uint64) string {
	return fmtUint64(count)
}

func fmtBytes(bytes uint64) string {
	if bytes < 1024 {
		return fmtUint64(bytes) + " B"
	}
	return fmtFloat(float64(bytes)/1024) + " KB"
}

func fmtFloat(f float64) string {
	return fmtFloatPrec(f, 2)
}

func fmtFloatPrec(f float64, prec int) string {
	s := ""
	if prec == 0 {
		s = fmtInt(int(f))
	} else if prec == 1 {
		s = fmtInt(int(f * 10))
		if len(s) > 0 {
			s = s[:len(s)-1] + "." + s[len(s)-1:]
		}
	} else {
		s = fmtInt(int(f * 100))
		if len(s) > 1 {
			s = s[:len(s)-2] + "." + s[len(s)-2:]
		}
	}
	return s
}

func fmtInt(i int) string {
	if i == 0 {
		return "0"
	}
	neg := i < 0
	if neg {
		i = -i
	}
	s := ""
	for i > 0 {
		s = string(rune('0'+i%10)) + s
		i /= 10
	}
	if neg {
		s = "-" + s
	}
	return s
}

func fmtUint64(u uint64) string {
	if u == 0 {
		return "0"
	}
	s := ""
	for u > 0 {
		s = string(rune('0'+u%10)) + s
		u /= 10
	}
	return s
}
