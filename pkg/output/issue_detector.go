package output

import (
	"fmt"
	"strings"

	"github.com/gocisse/sdwan-triage/pkg/models"
)

// StreamIssue represents a detected problem in a stream
type StreamIssue struct {
	Icon        string // 🔄, ⏱️, 💥, ⚠️, 🔚
	Description string // "45s gap - possible timeout"
	Severity    string // "Critical", "Warning", "Info"
	Timestamp   string // When the issue occurred
	Details     string // Additional context
}

// IssueDetector detects problems in network streams
type IssueDetector struct{}

// NewIssueDetector creates a new issue detector
func NewIssueDetector() *IssueDetector {
	return &IssueDetector{}
}

// DetectIssues analyzes a stream and returns detected issues
func (id *IssueDetector) DetectIssues(stream *models.StreamData) []StreamIssue {
	issues := make([]StreamIssue, 0)

	// Track state for analysis
	var lastTimestamp int64
	var retransmitCount int
	var gapCount int
	var resetDetected bool
	var weakTLSDetected bool

	for i, seg := range stream.Segments {
		currentTs := seg.Timestamp.UnixNano()

		// Check for retransmissions
		if seg.IsRetransmit {
			retransmitCount++
			if retransmitCount <= 3 { // Only report first few
				issues = append(issues, StreamIssue{
					Icon:        "🔄",
					Description: "RETRY - Packet retransmission",
					Severity:    "Warning",
					Timestamp:   seg.Timestamp.Format("15:04:05.000"),
					Details:     "Network congestion or packet loss",
				})
			}
		}

		// Check for time gaps
		if i > 0 && lastTimestamp > 0 {
			gapSec := float64(currentTs-lastTimestamp) / 1e9
			if gapSec > 5.0 {
				gapCount++
				severity := "Warning"
				if gapSec > 30.0 {
					severity = "Critical"
				}
				issues = append(issues, StreamIssue{
					Icon:        "⏱️",
					Description: fmt.Sprintf("GAP+%.1fs - Possible timeout", gapSec),
					Severity:    severity,
					Timestamp:   seg.Timestamp.Format("15:04:05.000"),
					Details:     id.diagnoseGap(gapSec, stream.Application),
				})
			}
		}
		lastTimestamp = currentTs

		// Check for TCP RST
		if seg.HasReset && !resetDetected {
			resetDetected = true
			issues = append(issues, StreamIssue{
				Icon:        "💥",
				Description: "RESET - Connection forcibly closed",
				Severity:    "Critical",
				Timestamp:   seg.Timestamp.Format("15:04:05.000"),
				Details:     "Server or firewall rejected connection",
			})
		}

		// Check for TLS version issues
		if len(seg.Data) >= 3 && seg.Data[0] == 0x16 && !weakTLSDetected {
			version := uint16(seg.Data[1])<<8 | uint16(seg.Data[2])
			switch version {
			case 0x0300:
				weakTLSDetected = true
				issues = append(issues, StreamIssue{
					Icon:        "⚠️",
					Description: "WEAK_TLS - SSLv3 is VULNERABLE",
					Severity:    "Critical",
					Timestamp:   seg.Timestamp.Format("15:04:05.000"),
					Details:     "SSLv3 is vulnerable to POODLE attack. Upgrade immediately.",
				})
			case 0x0301:
				weakTLSDetected = true
				issues = append(issues, StreamIssue{
					Icon:        "⚠️",
					Description: "WEAK_TLS - TLS 1.0 deprecated",
					Severity:    "Warning",
					Timestamp:   seg.Timestamp.Format("15:04:05.000"),
					Details:     "TLS 1.0 is deprecated. Upgrade to TLS 1.2+",
				})
			case 0x0302:
				weakTLSDetected = true
				issues = append(issues, StreamIssue{
					Icon:        "⚠️",
					Description: "WEAK_TLS - TLS 1.1 deprecated",
					Severity:    "Warning",
					Timestamp:   seg.Timestamp.Format("15:04:05.000"),
					Details:     "TLS 1.1 is deprecated. Upgrade to TLS 1.2+",
				})
			}
		}

		// Check for out-of-order packets
		if seg.IsOutOfOrder {
			issues = append(issues, StreamIssue{
				Icon:        "⚠️",
				Description: "OUT_OF_ORDER - Packet sequence issue",
				Severity:    "Warning",
				Timestamp:   seg.Timestamp.Format("15:04:05.000"),
				Details:     "Possible asymmetric routing or network instability",
			})
		}
	}

	// Summary issues for high counts
	if retransmitCount > 3 {
		issues = append(issues, StreamIssue{
			Icon:        "🔄",
			Description: fmt.Sprintf("HIGH_RETRANSMIT - %d retransmissions total", retransmitCount),
			Severity:    "Warning",
			Details:     "Significant packet loss on this flow. Check SD-WAN path quality.",
		})
	}

	if gapCount > 2 {
		issues = append(issues, StreamIssue{
			Icon:        "⏱️",
			Description: fmt.Sprintf("MULTIPLE_GAPS - %d gaps detected", gapCount),
			Severity:    "Warning",
			Details:     "Intermittent connectivity. Check SD-WAN failover or ISP stability.",
		})
	}

	// Check for incomplete handshake (TLS)
	if stream.Application == "TLS" || stream.Application == "HTTPS" {
		if !id.hasCompleteTLSHandshake(stream) && stream.PacketCount > 2 {
			issues = append(issues, StreamIssue{
				Icon:        "⚠️",
				Description: "INCOMPLETE_HANDSHAKE - TLS setup failed",
				Severity:    "Warning",
				Details:     "TLS handshake did not complete. Check firewall or certificate issues.",
			})
		}
	}

	// Check for zero-window stalls (simplified)
	if id.detectZeroWindowStall(stream) {
		issues = append(issues, StreamIssue{
			Icon:        "⏱️",
			Description: "STALL - Zero window detected",
			Severity:    "Warning",
			Details:     "Receiver buffer full. Application not consuming data fast enough.",
		})
	}

	return issues
}

// diagnoseGap provides context for a time gap
func (id *IssueDetector) diagnoseGap(gapSec float64, application string) string {
	if gapSec > 60 {
		return "Very long gap - possible session timeout or network outage"
	}
	if gapSec > 30 {
		return "Long gap - check SD-WAN path failover or ISP issues"
	}
	if gapSec > 10 {
		return "Moderate gap - possible application delay or network congestion"
	}

	switch application {
	case "TLS", "HTTPS":
		return "Gap during TLS session - check server response time"
	case "SMB":
		return "Gap during file transfer - check storage or network latency"
	case "DNS":
		return "DNS response delay - check resolver performance"
	default:
		return "Network delay detected"
	}
}

// hasCompleteTLSHandshake checks if TLS handshake completed
func (id *IssueDetector) hasCompleteTLSHandshake(stream *models.StreamData) bool {
	hasClientHello := false
	hasServerHello := false
	hasFinished := false

	for _, seg := range stream.Segments {
		if len(seg.Data) < 6 {
			continue
		}
		if seg.Data[0] == 0x16 { // Handshake
			hsType := seg.Data[5]
			switch hsType {
			case 0x01:
				hasClientHello = true
			case 0x02:
				hasServerHello = true
			case 0x14:
				hasFinished = true
			}
		}
		if seg.Data[0] == 0x17 { // Application data = handshake complete
			return true
		}
	}

	return hasClientHello && hasServerHello && hasFinished
}

// detectZeroWindowStall detects zero-window conditions (simplified)
func (id *IssueDetector) detectZeroWindowStall(stream *models.StreamData) bool {
	// This is a simplified check - real detection would need TCP window tracking
	// Look for patterns suggesting stalls
	consecutiveSmallPackets := 0
	for _, seg := range stream.Segments {
		if seg.Length < 10 && seg.Direction == "server_to_client" {
			consecutiveSmallPackets++
			if consecutiveSmallPackets > 5 {
				return true
			}
		} else {
			consecutiveSmallPackets = 0
		}
	}
	return false
}

// GetIssueSummary returns a one-line summary of all issues
func (id *IssueDetector) GetIssueSummary(issues []StreamIssue) string {
	if len(issues) == 0 {
		return "✅ No issues detected"
	}

	criticalCount := 0
	warningCount := 0
	for _, issue := range issues {
		switch issue.Severity {
		case "Critical":
			criticalCount++
		case "Warning":
			warningCount++
		}
	}

	var parts []string
	if criticalCount > 0 {
		parts = append(parts, fmt.Sprintf("🔴 %d critical", criticalCount))
	}
	if warningCount > 0 {
		parts = append(parts, fmt.Sprintf("🟡 %d warnings", warningCount))
	}

	return strings.Join(parts, ", ")
}

// GetHealthStatus returns overall health status
func (id *IssueDetector) GetHealthStatus(issues []StreamIssue) (status string, color string) {
	for _, issue := range issues {
		if issue.Severity == "Critical" {
			return "Critical", "red"
		}
	}
	for _, issue := range issues {
		if issue.Severity == "Warning" {
			return "Warning", "yellow"
		}
	}
	return "Healthy", "green"
}

// FormatIssuesForDisplay formats issues for HTML display
func (id *IssueDetector) FormatIssuesForDisplay(issues []StreamIssue) string {
	if len(issues) == 0 {
		return ""
	}

	var sb strings.Builder
	for _, issue := range issues {
		severityClass := "info"
		switch issue.Severity {
		case "Critical":
			severityClass = "critical"
		case "Warning":
			severityClass = "warning"
		}

		sb.WriteString(fmt.Sprintf(`<div class="stream-issue %s">`, severityClass))
		sb.WriteString(fmt.Sprintf(`<span class="issue-icon">%s</span>`, issue.Icon))
		sb.WriteString(fmt.Sprintf(`<span class="issue-desc">%s</span>`, issue.Description))
		if issue.Timestamp != "" {
			sb.WriteString(fmt.Sprintf(`<span class="issue-time">%s</span>`, issue.Timestamp))
		}
		sb.WriteString(`</div>`)
	}

	return sb.String()
}

// FormatIssuesForCLI formats issues for terminal display
func (id *IssueDetector) FormatIssuesForCLI(issues []StreamIssue) string {
	if len(issues) == 0 {
		return "  ✅ No issues detected\n"
	}

	var sb strings.Builder
	for _, issue := range issues {
		sb.WriteString(fmt.Sprintf("  %s %s", issue.Icon, issue.Description))
		if issue.Timestamp != "" {
			sb.WriteString(fmt.Sprintf(" @ %s", issue.Timestamp))
		}
		sb.WriteString("\n")
		if issue.Details != "" {
			sb.WriteString(fmt.Sprintf("     └─ %s\n", issue.Details))
		}
	}

	return sb.String()
}
