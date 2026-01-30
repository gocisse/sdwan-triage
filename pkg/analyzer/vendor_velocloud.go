package analyzer

import (
	"github.com/gocisse/sdwan-triage/pkg/models"
)

// VMware VeloCloud-specific ports and protocols
const (
	VeloCloudVCMPPort  uint16 = 2426 // VCMP (VeloCloud Management Protocol)
	VeloCloudHTTPPort  uint16 = 8080 // HTTP management
	VeloCloudHTTPSPort uint16 = 8443 // HTTPS management
	VeloCloudNATTPort  uint16 = 4500 // NAT-T for IPsec
	VeloCloudIKEPort   uint16 = 500  // IKE for IPsec
)

// VeloCloudIssueDetector detects VMware VeloCloud-specific issues
type VeloCloudIssueDetector struct {
	classifier   *AdvancedClassifier
	healthScorer *HealthScorer
}

// NewVeloCloudIssueDetector creates a new VeloCloud detector
func NewVeloCloudIssueDetector() *VeloCloudIssueDetector {
	return &VeloCloudIssueDetector{
		classifier:   NewAdvancedClassifier(),
		healthScorer: NewHealthScorer(),
	}
}

// DetectVeloCloudIssues analyzes streams for VeloCloud-specific problems
func (vcd *VeloCloudIssueDetector) DetectVeloCloudIssues(stream *models.StreamData) []DetectedIssue {
	issues := []DetectedIssue{}

	if !vcd.isVeloCloudTraffic(stream) {
		return issues
	}

	// VCMP health monitoring
	if vcmpIssues := vcd.detectVCMPIssues(stream); len(vcmpIssues) > 0 {
		issues = append(issues, vcmpIssues...)
	}

	// Edge activation failures
	if activationIssues := vcd.detectActivationIssues(stream); len(activationIssues) > 0 {
		issues = append(issues, activationIssues...)
	}

	// Cloud gateway selection issues
	if gatewayIssues := vcd.detectGatewayIssues(stream); len(gatewayIssues) > 0 {
		issues = append(issues, gatewayIssues...)
	}

	// QoS policy enforcement problems
	if qosIssues := vcd.detectQoSIssues(stream); len(qosIssues) > 0 {
		issues = append(issues, qosIssues...)
	}

	// Link aggregation balancing
	if lagIssues := vcd.detectLAGIssues(stream); len(lagIssues) > 0 {
		issues = append(issues, lagIssues...)
	}

	return issues
}

// isVeloCloudTraffic checks if stream is VeloCloud-related
func (vcd *VeloCloudIssueDetector) isVeloCloudTraffic(stream *models.StreamData) bool {
	veloCloudPorts := []uint16{VeloCloudVCMPPort, VeloCloudHTTPPort, VeloCloudHTTPSPort, VeloCloudNATTPort, VeloCloudIKEPort}

	for _, port := range veloCloudPorts {
		if stream.DstPort == port || stream.SrcPort == port {
			return true
		}
	}

	return false
}

// detectVCMPIssues detects VCMP (VeloCloud Management Protocol) problems
func (vcd *VeloCloudIssueDetector) detectVCMPIssues(stream *models.StreamData) []DetectedIssue {
	issues := []DetectedIssue{}

	if stream.DstPort != VeloCloudVCMPPort && stream.SrcPort != VeloCloudVCMPPort {
		return issues
	}

	healthScore := vcd.healthScorer.ScoreStream(stream)

	// VCMP connection failure
	if healthScore.Status == HealthStatusCritical {
		issue := DetectedIssue{
			ID:              "VELOCLOUD-VCMP-001",
			Title:           "VCMP Connection Failure",
			TechnicalDesc:   "VeloCloud Management Protocol connection to orchestrator failing",
			BusinessImpact:  "Edge cannot receive configuration updates, monitoring data lost, policy changes blocked",
			Severity:        SeverityCritical,
			Confidence:      0.90,
			Category:        CategorySDWANControl,
			RootCause:       "Orchestrator unreachable, certificate issues, or firewall blocking UDP 2426",
			AffectedService: "VMware VeloCloud VCMP",

			BaseFilter:      buildStreamFilter(stream),
			ExpandedFilter:  buildExpandedFilter(stream) + " || (udp.port == 2426)",
			OptimizedFilter: buildOptimizedFilter(stream),

			InvestigationSteps: []InvestigationStep{
				{
					Order:          1,
					Purpose:        "Analyze VCMP packet flow",
					DisplayFilter:  "udp.port == 2426",
					ExpectedNormal: "Bidirectional VCMP traffic with regular intervals",
					AbnormalSign:   "One-way traffic or no responses from orchestrator",
					CustomColumns:  []string{"udp.srcport", "udp.dstport", "frame.time_delta"},
				},
				{
					Order:          2,
					Purpose:        "Check for ICMP unreachable messages",
					DisplayFilter:  "icmp.type == 3",
					ExpectedNormal: "No ICMP unreachable messages",
					AbnormalSign:   "Port unreachable or host unreachable for orchestrator IP",
				},
			},

			ImmediateActions: []RemediationAction{
				{
					Description:    "Verify orchestrator connectivity from Edge",
					Commands:       []string{"Edge CLI: debug.py --test_cloud", "Check Edge Events in VCO"},
					Verification:   "Cloud connectivity test passes",
					EstimatedTime:  "3 minutes",
					RequiresChange: false,
					SuccessRate:    0.85,
				},
				{
					Description:    "Check Edge management interface status",
					Commands:       []string{"Edge CLI: ifconfig", "Check WAN interface in VCO"},
					Verification:   "Management interface has valid IP and gateway",
					EstimatedTime:  "2 minutes",
					RequiresChange: false,
					SuccessRate:    0.80,
				},
			},

			ShortTermFixes: []RemediationAction{
				{
					Description:    "Restart Edge management services",
					Commands:       []string{"Edge CLI: sudo /opt/vc/bin/vc_procmon restart"},
					Verification:   "VCMP connection re-established",
					EstimatedTime:  "5 minutes",
					RequiresChange: true,
					SuccessRate:    0.75,
					RollbackSteps:  []string{"Services restart automatically on failure"},
				},
				{
					Description:    "Verify firewall allows UDP 2426 outbound",
					Commands:       []string{"Check upstream firewall rules for UDP 2426 to VCO IPs"},
					Verification:   "Firewall permits VCMP traffic",
					EstimatedTime:  "15 minutes",
					RequiresChange: true,
					SuccessRate:    0.85,
				},
			},

			LongTermSolutions: []RemediationAction{
				{
					Description:     "Implement redundant VCO connectivity paths",
					Verification:    "VCMP failover works seamlessly",
					EstimatedTime:   "1 week",
					RequiresChange:  true,
					SuccessRate:     0.95,
					EscalationPoint: "Engage VMware SD-WAN support for persistent VCMP issues",
				},
			},

			KnowledgeBaseRef: "KB-VELOCLOUD-VCMP-001",
		}
		issues = append(issues, issue)
	}

	// VCMP high latency
	if stream.Duration > 5 && healthScore.Status == HealthStatusDegraded {
		issue := DetectedIssue{
			ID:              "VELOCLOUD-VCMP-002",
			Title:           "VCMP High Latency",
			TechnicalDesc:   "VCMP responses taking excessive time, indicating network or orchestrator issues",
			BusinessImpact:  "Delayed configuration updates, stale monitoring data, slow policy enforcement",
			Severity:        SeverityHigh,
			Confidence:      0.80,
			Category:        CategorySDWANControl,
			RootCause:       "Network congestion, orchestrator overload, or suboptimal routing",
			AffectedService: "VMware VeloCloud VCMP",

			BaseFilter:      buildStreamFilter(stream),
			ExpandedFilter:  buildExpandedFilter(stream),
			OptimizedFilter: buildOptimizedFilter(stream),

			ImmediateActions: []RemediationAction{
				{
					Description:    "Check network path to orchestrator",
					Commands:       []string{"traceroute to VCO IP", "Check Edge latency metrics in VCO"},
					Verification:   "Latency within acceptable range (<100ms)",
					EstimatedTime:  "3 minutes",
					RequiresChange: false,
					SuccessRate:    0.80,
				},
			},

			ShortTermFixes: []RemediationAction{
				{
					Description:    "Optimize routing to VCO",
					Commands:       []string{"Review business policy for management traffic", "Consider direct internet breakout for VCO"},
					Verification:   "VCMP latency reduced",
					EstimatedTime:  "30 minutes",
					RequiresChange: true,
					SuccessRate:    0.75,
				},
			},

			KnowledgeBaseRef: "KB-VELOCLOUD-VCMP-002",
		}
		issues = append(issues, issue)
	}

	return issues
}

// detectActivationIssues detects Edge activation problems
func (vcd *VeloCloudIssueDetector) detectActivationIssues(stream *models.StreamData) []DetectedIssue {
	issues := []DetectedIssue{}

	// Activation uses HTTPS to orchestrator
	if stream.DstPort != VeloCloudHTTPSPort && stream.SrcPort != VeloCloudHTTPSPort {
		return issues
	}

	// Check for failed activation (resets during HTTPS)
	hasReset := false
	for _, segment := range stream.Segments {
		if segment.HasReset {
			hasReset = true
			break
		}
	}

	if hasReset && stream.Duration < 30 {
		issue := DetectedIssue{
			ID:              "VELOCLOUD-ACTIVATION-001",
			Title:           "Edge Activation Failure",
			TechnicalDesc:   "Edge failing to complete activation with VeloCloud Orchestrator",
			BusinessImpact:  "New Edge cannot join SD-WAN fabric, site deployment blocked",
			Severity:        SeverityCritical,
			Confidence:      0.80,
			Category:        CategorySDWANControl,
			RootCause:       "Invalid activation key, certificate issues, or network connectivity problems",
			AffectedService: "VMware VeloCloud Activation",

			BaseFilter:      buildStreamFilter(stream),
			ExpandedFilter:  buildExpandedFilter(stream),
			OptimizedFilter: buildOptimizedFilter(stream),

			InvestigationSteps: []InvestigationStep{
				{
					Order:          1,
					Purpose:        "Examine TLS handshake",
					DisplayFilter:  buildStreamFilter(stream) + " && ssl.handshake",
					ExpectedNormal: "Successful TLS handshake with VCO",
					AbnormalSign:   "Certificate validation failure or handshake timeout",
				},
				{
					Order:          2,
					Purpose:        "Check HTTP response codes",
					DisplayFilter:  buildStreamFilter(stream) + " && http.response",
					ExpectedNormal: "HTTP 200 OK responses",
					AbnormalSign:   "HTTP 401, 403, or 500 errors",
					CustomColumns:  []string{"http.response.code", "http.response.phrase"},
				},
			},

			ImmediateActions: []RemediationAction{
				{
					Description:    "Verify activation key is correct",
					Commands:       []string{"Check activation key in VCO matches Edge configuration", "Regenerate activation key if expired"},
					Verification:   "Activation key valid and not expired",
					EstimatedTime:  "5 minutes",
					RequiresChange: false,
					SuccessRate:    0.85,
				},
				{
					Description:    "Check Edge can reach VCO on HTTPS",
					Commands:       []string{"curl -v https://<vco-hostname>:8443", "Check DNS resolution for VCO hostname"},
					Verification:   "HTTPS connection succeeds",
					EstimatedTime:  "3 minutes",
					RequiresChange: false,
					SuccessRate:    0.80,
				},
			},

			ShortTermFixes: []RemediationAction{
				{
					Description:    "Factory reset Edge and re-attempt activation",
					Commands:       []string{"Edge CLI: sudo /opt/vc/bin/vc_reset_device.sh", "Re-enter activation key"},
					Verification:   "Edge activates successfully",
					EstimatedTime:  "15 minutes",
					RequiresChange: true,
					SuccessRate:    0.70,
					RollbackSteps:  []string{"Contact VMware support if reset fails"},
				},
			},

			KnowledgeBaseRef: "KB-VELOCLOUD-ACTIVATION-001",
		}
		issues = append(issues, issue)
	}

	return issues
}

// detectGatewayIssues detects Cloud Gateway selection problems
func (vcd *VeloCloudIssueDetector) detectGatewayIssues(stream *models.StreamData) []DetectedIssue {
	// Gateway selection issues detected through traffic patterns
	return nil
}

// detectQoSIssues detects QoS policy enforcement problems
func (vcd *VeloCloudIssueDetector) detectQoSIssues(stream *models.StreamData) []DetectedIssue {
	// QoS issues require DSCP analysis
	return nil
}

// detectLAGIssues detects Link Aggregation Group problems
func (vcd *VeloCloudIssueDetector) detectLAGIssues(stream *models.StreamData) []DetectedIssue {
	// LAG issues require multi-link analysis
	return nil
}
