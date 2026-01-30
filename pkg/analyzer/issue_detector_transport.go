package analyzer

import (
	"github.com/gocisse/sdwan-triage/pkg/models"
)

// TCP Issue Detection
func detectTCPIssues(stream *models.StreamData, classification ServiceClassification, health HealthScore) []DetectedIssue {
	if stream.Protocol != "TCP" {
		return nil
	}

	issues := []DetectedIssue{}

	// Zero-window stall detection
	hasZeroWindow := false
	for _, segment := range stream.Segments {
		if segment.AnomalyReason != "" && containsString(segment.AnomalyReason, "window") {
			hasZeroWindow = true
			break
		}
	}

	if hasZeroWindow {
		issue := DetectedIssue{
			ID:              "TCP-001",
			Title:           "TCP Zero-Window Stall Detected",
			TechnicalDesc:   "Receiver advertising zero window size, indicating buffer exhaustion",
			BusinessImpact:  "Data transfer stalled, application performance severely degraded",
			Severity:        SeverityCritical,
			Confidence:      0.90,
			Category:        CategoryTCPIssues,
			RootCause:       "Receiver overload, slow application processing, or insufficient buffer space",
			AffectedService: "TCP Connection",

			BaseFilter:      buildStreamFilter(stream),
			ExpandedFilter:  buildExpandedFilter(stream),
			OptimizedFilter: buildOptimizedFilter(stream),

			InvestigationSteps: []InvestigationStep{
				{
					Order:          1,
					Purpose:        "Identify zero-window advertisements",
					DisplayFilter:  buildStreamFilter(stream) + " && tcp.window_size == 0",
					ExpectedNormal: "No zero-window packets",
					AbnormalSign:   "Multiple zero-window advertisements",
					CustomColumns:  []string{"tcp.window_size", "tcp.seq", "tcp.ack"},
				},
				{
					Order:          2,
					Purpose:        "Check window update timing",
					DisplayFilter:  buildStreamFilter(stream) + " && tcp.window_size > 0",
					ExpectedNormal: "Window opens within 1 second",
					AbnormalSign:   "Prolonged zero-window state (>5 seconds)",
				},
			},

			ImmediateActions: []RemediationAction{
				{
					Description:    "Check receiver system resources",
					Commands:       []string{"Check CPU and memory usage on receiving host", "Monitor application processing rate"},
					Verification:   "System resources not exhausted",
					EstimatedTime:  "2 minutes",
					RequiresChange: false,
					SuccessRate:    0.80,
				},
			},

			ShortTermFixes: []RemediationAction{
				{
					Description:    "Increase TCP receive buffer size",
					Commands:       []string{"sysctl -w net.ipv4.tcp_rmem='4096 87380 16777216'", "sysctl -w net.core.rmem_max=16777216"},
					Verification:   "Larger receive window advertised",
					EstimatedTime:  "5 minutes",
					RequiresChange: true,
					SuccessRate:    0.75,
					RollbackSteps:  []string{"Restore previous sysctl values"},
				},
			},

			LongTermSolutions: []RemediationAction{
				{
					Description:    "Optimize application data processing or scale receiver capacity",
					Verification:   "No zero-window stalls under normal load",
					EstimatedTime:  "2 weeks",
					RequiresChange: true,
					SuccessRate:    0.90,
				},
			},

			KnowledgeBaseRef: "KB-TCP-001",
		}
		issues = append(issues, issue)
	}

	// High retransmission rate
	retransmitCount := 0
	for _, segment := range stream.Segments {
		if segment.IsRetransmit {
			retransmitCount++
		}
	}

	if retransmitCount > 0 {
		retransmitRate := float64(retransmitCount) / float64(stream.PacketCount)
		if retransmitRate > 0.05 { // > 5%
			issue := DetectedIssue{
				ID:              "TCP-002",
				Title:           "High TCP Retransmission Rate",
				TechnicalDesc:   "Excessive packet retransmissions indicating network reliability issues",
				BusinessImpact:  "Slow data transfer, increased latency, poor application performance",
				Severity:        SeverityHigh,
				Confidence:      0.85,
				Category:        CategoryTCPIssues,
				RootCause:       "Network packet loss, congestion, or path instability",
				AffectedService: "TCP Connection",

				BaseFilter:      buildStreamFilter(stream),
				ExpandedFilter:  buildExpandedFilter(stream),
				OptimizedFilter: buildOptimizedFilter(stream),

				InvestigationSteps: []InvestigationStep{
					{
						Order:          1,
						Purpose:        "Analyze retransmission patterns",
						DisplayFilter:  buildStreamFilter(stream) + " && tcp.analysis.retransmission",
						ExpectedNormal: "< 1% retransmission rate",
						AbnormalSign:   "> 5% retransmission rate",
						CustomColumns:  []string{"tcp.analysis.retransmission", "tcp.seq"},
					},
				},

				ImmediateActions: []RemediationAction{
					{
						Description:    "Check network path quality",
						Commands:       []string{"pathping " + stream.DstIP, "mtr " + stream.DstIP},
						Verification:   "Low packet loss (<1%) on path",
						EstimatedTime:  "3 minutes",
						RequiresChange: false,
						SuccessRate:    0.85,
					},
				},

				ShortTermFixes: []RemediationAction{
					{
						Description:    "Verify QoS and traffic shaping policies",
						Commands:       []string{"Check QoS configuration", "Review traffic shaping rules"},
						Verification:   "Critical traffic prioritized correctly",
						EstimatedTime:  "15 minutes",
						RequiresChange: false,
						SuccessRate:    0.70,
					},
				},

				LongTermSolutions: []RemediationAction{
					{
						Description:    "Upgrade network capacity or implement WAN optimization",
						Verification:   "Retransmission rate < 1%",
						EstimatedTime:  "2-4 weeks",
						RequiresChange: true,
						SuccessRate:    0.90,
					},
				},

				KnowledgeBaseRef: "KB-TCP-002",
			}
			issues = append(issues, issue)
		}
	}

	return issues
}

// TLS Issue Detection
func detectTLSIssues(stream *models.StreamData, classification ServiceClassification, health HealthScore) []DetectedIssue {
	if stream.Application != "TLS" && stream.DstPort != 443 && stream.SrcPort != 443 {
		return nil
	}

	issues := []DetectedIssue{}

	// TLS handshake timeout
	if stream.Duration > 5 && stream.PacketCount < 20 {
		issue := DetectedIssue{
			ID:              "TLS-001",
			Title:           "TLS Handshake Timeout",
			TechnicalDesc:   "TLS handshake taking excessive time or failing to complete",
			BusinessImpact:  "HTTPS connection failures, application unavailability, user frustration",
			Severity:        SeverityCritical,
			Confidence:      0.85,
			Category:        CategoryTLSIssues,
			RootCause:       "Certificate validation delay, OCSP timeout, or network latency",
			AffectedService: "TLS/SSL Connection",

			BaseFilter:      buildStreamFilter(stream),
			ExpandedFilter:  buildExpandedFilter(stream),
			OptimizedFilter: buildOptimizedFilter(stream),

			InvestigationSteps: []InvestigationStep{
				{
					Order:          1,
					Purpose:        "Verify TLS ClientHello sent",
					DisplayFilter:  buildStreamFilter(stream) + " && ssl.handshake.type == 1",
					ExpectedNormal: "ClientHello packet present",
					AbnormalSign:   "No ClientHello or delayed",
				},
				{
					Order:          2,
					Purpose:        "Check for ServerHello response",
					DisplayFilter:  buildStreamFilter(stream) + " && ssl.handshake.type == 2",
					ExpectedNormal: "ServerHello within 500ms",
					AbnormalSign:   "No ServerHello or timeout",
					CustomColumns:  []string{"ssl.handshake.version", "ssl.handshake.cipher_suite"},
				},
				{
					Order:          3,
					Purpose:        "Examine certificate exchange",
					DisplayFilter:  buildStreamFilter(stream) + " && ssl.handshake.type == 11",
					ExpectedNormal: "Certificate message present",
					AbnormalSign:   "Missing certificate or validation failure",
				},
			},

			ImmediateActions: []RemediationAction{
				{
					Description:    "Test TLS connection with openssl",
					Commands:       []string{"openssl s_client -connect " + stream.DstIP + ":443 -showcerts"},
					Verification:   "TLS handshake completes successfully",
					EstimatedTime:  "2 minutes",
					RequiresChange: false,
					SuccessRate:    0.85,
				},
				{
					Description:    "Check certificate validity",
					Commands:       []string{"openssl s_client -connect " + stream.DstIP + ":443 | openssl x509 -noout -dates"},
					Verification:   "Certificate not expired",
					EstimatedTime:  "1 minute",
					RequiresChange: false,
					SuccessRate:    0.90,
				},
			},

			ShortTermFixes: []RemediationAction{
				{
					Description:    "Disable OCSP stapling temporarily",
					Commands:       []string{"Configure web server to disable OCSP stapling", "Restart web service"},
					Verification:   "TLS handshakes complete faster",
					EstimatedTime:  "10 minutes",
					RequiresChange: true,
					SuccessRate:    0.70,
					RollbackSteps:  []string{"Re-enable OCSP stapling"},
				},
			},

			LongTermSolutions: []RemediationAction{
				{
					Description:    "Implement certificate caching and optimize TLS configuration",
					Verification:   "TLS handshakes complete within 1 second",
					EstimatedTime:  "1 week",
					RequiresChange: true,
					SuccessRate:    0.90,
				},
			},

			KnowledgeBaseRef: "KB-TLS-001",
		}
		issues = append(issues, issue)
	}

	// Certificate validation failure (detected via resets)
	hasReset := false
	for _, segment := range stream.Segments {
		if segment.HasReset {
			hasReset = true
			break
		}
	}

	if hasReset && stream.Duration < 2 {
		issue := DetectedIssue{
			ID:              "TLS-002",
			Title:           "TLS Certificate Validation Failure",
			TechnicalDesc:   "Connection terminated during TLS handshake, likely certificate issue",
			BusinessImpact:  "HTTPS connection blocked, application access denied, security alert",
			Severity:        SeverityCritical,
			Confidence:      0.75,
			Category:        CategoryTLSIssues,
			RootCause:       "Certificate expired, untrusted CA, hostname mismatch, or revoked certificate",
			AffectedService: "TLS/SSL Connection",

			BaseFilter:      buildStreamFilter(stream),
			ExpandedFilter:  buildExpandedFilter(stream),
			OptimizedFilter: buildOptimizedFilter(stream),

			InvestigationSteps: []InvestigationStep{
				{
					Order:          1,
					Purpose:        "Check certificate details",
					DisplayFilter:  buildStreamFilter(stream) + " && ssl.handshake.certificate",
					ExpectedNormal: "Valid certificate chain",
					AbnormalSign:   "Certificate error or missing chain",
					CustomColumns:  []string{"ssl.handshake.certificate"},
				},
			},

			ImmediateActions: []RemediationAction{
				{
					Description:    "Verify certificate validity and chain",
					Commands:       []string{"openssl s_client -connect " + stream.DstIP + ":443 -showcerts", "Check certificate expiration and issuer"},
					Verification:   "Certificate valid and trusted",
					EstimatedTime:  "3 minutes",
					RequiresChange: false,
					SuccessRate:    0.85,
				},
			},

			ShortTermFixes: []RemediationAction{
				{
					Description:     "Renew expired certificate",
					Commands:        []string{"Request new certificate from CA", "Install and configure new certificate"},
					Verification:    "TLS connections succeed",
					EstimatedTime:   "30 minutes",
					RequiresChange:  true,
					SuccessRate:     0.95,
					EscalationPoint: "Engage PKI team for certificate issues",
				},
			},

			LongTermSolutions: []RemediationAction{
				{
					Description:    "Implement certificate monitoring and auto-renewal",
					Verification:   "Certificates renewed before expiration",
					EstimatedTime:  "1 week",
					RequiresChange: true,
					SuccessRate:    0.95,
				},
			},

			KnowledgeBaseRef: "KB-TLS-002",
		}
		issues = append(issues, issue)
	}

	return issues
}

// Helper function
func containsString(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || (len(s) > len(substr) && findSubstring(s, substr)))
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		match := true
		for j := 0; j < len(substr); j++ {
			if s[i+j] != substr[j] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}
