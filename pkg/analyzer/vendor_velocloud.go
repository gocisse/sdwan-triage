package analyzer

import (
	"fmt"
	"strings"

	"github.com/gocisse/sdwan-triage/pkg/models"
)

// VeloCloud detection thresholds
const (
	VeloGatewayDropThreshold     = 500  // drops/30s window — warning
	VeloGatewayDropCritical      = 1000 // drops/30s window — critical
	VeloQoSDSCPEF                = 46   // DSCP EF — expected for real-time traffic
	VeloQoSRTPPortLow            = 16384
	VeloQoSRTPPortHigh           = 32767
	VeloLAGImbalanceThreshold    = 0.70 // >70% on one member = imbalance
	VeloLAGFailureThreshold      = 0.55 // >55% drop in throughput = member failure
	VeloGatewayNoReturnWindowSec = 5.0  // seconds with no return flow = selection failure
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
	issues := []DetectedIssue{}

	// Gateway traffic uses VCMP port or IPsec ports
	isGatewayPort := stream.DstPort == VeloCloudVCMPPort || stream.SrcPort == VeloCloudVCMPPort ||
		stream.DstPort == VeloCloudNATTPort || stream.SrcPort == VeloCloudNATTPort ||
		stream.DstPort == VeloCloudIKEPort || stream.SrcPort == VeloCloudIKEPort
	if !isGatewayPort {
		return issues
	}

	// --- Detection 1: Gateway capacity drops via queue depth analysis ---
	// Proxy: count segments with large gaps (>100ms) from the same direction,
	// which indicates queuing/drops at the gateway handoff queue.
	clientDropProxy := 0
	serverDropProxy := 0
	for i := 1; i < len(stream.Segments); i++ {
		seg := stream.Segments[i]
		if seg.GapFromPrev > 0.1 { // >100ms gap = queuing indicator
			if seg.Direction == "client_to_server" {
				clientDropProxy++
			} else {
				serverDropProxy++
			}
		}
	}
	totalDropProxy := clientDropProxy + serverDropProxy

	if totalDropProxy >= VeloGatewayDropCritical {
		issues = append(issues, DetectedIssue{
			ID:              "VELOCLOUD-GW-001",
			Title:           "Gateway Capacity Drops — Critical",
			TechnicalDesc:   fmt.Sprintf("Gateway queue depth indicators: %d high-latency segments (>100ms gap) detected, consistent with over_capacity_drop counter spikes", totalDropProxy),
			BusinessImpact:  "Traffic dropped at gateway handoff queue; users experience packet loss and application timeouts",
			Severity:        SeverityCritical,
			Confidence:      0.80,
			Category:        CategorySDWANData,
			RootCause:       "Gateway over-capacity: too many Edges assigned, NAT port exhaustion, or admission control drops",
			AffectedService: "VMware VeloCloud Cloud Gateway",
			BaseFilter:      buildStreamFilter(stream),
			ExpandedFilter:  buildExpandedFilter(stream),
			OptimizedFilter: buildOptimizedFilter(stream),
			InvestigationSteps: []InvestigationStep{
				{
					Order:          1,
					Purpose:        "Check gateway handoff queue drops",
					DisplayFilter:  buildStreamFilter(stream),
					ExpectedNormal: "Consistent inter-packet gaps < 50ms",
					AbnormalSign:   "Repeated gaps > 100ms from same direction",
					CustomColumns:  []string{"frame.time_delta", "udp.srcport", "udp.dstport"},
				},
				{
					Order:          2,
					Purpose:        "Verify gateway activation state",
					DisplayFilter:  fmt.Sprintf("ip.addr == %s && udp.port == 2426", stream.DstIP),
					ExpectedNormal: "Bidirectional VCMP traffic",
					AbnormalSign:   "One-way traffic — gateway not responding",
				},
			},
			ImmediateActions: []RemediationAction{
				{
					Description:    "Check gateway over-capacity drop counters",
					Commands:       []string{"/opt/vc/bin/dispcnt -s over_capacity_drop -d " + stream.DstIP, "/opt/vc/bin/debug.py --handoff"},
					Verification:   "Drop counter not incrementing",
					EstimatedTime:  "3 minutes",
					RequiresChange: false,
					SuccessRate:    0.85,
				},
				{
					Description:    "Verify gateway activation",
					Commands:       []string{"/opt/vc/bin/is_activated.py", "Check Edge Events in VCO for gateway errors"},
					Verification:   "Gateway shows activated and healthy",
					EstimatedTime:  "2 minutes",
					RequiresChange: false,
					SuccessRate:    0.80,
				},
			},
			ShortTermFixes: []RemediationAction{
				{
					Description:    "Quiesce overloaded gateway and rebalance Edges",
					Commands:       []string{"VCO: Network > Gateways > [Gateway] > Actions > Quiesce", "Reassign Edges to alternate gateway"},
					Verification:   "Drop counters stop incrementing on quiesced gateway",
					EstimatedTime:  "30 minutes",
					RequiresChange: true,
					SuccessRate:    0.85,
					RollbackSteps:  []string{"VCO: Un-quiesce gateway if rebalancing causes other issues"},
				},
			},
			LongTermSolutions: []RemediationAction{
				{
					Description:     "Add gateway capacity or redistribute Edge assignments",
					Verification:    "Gateway utilization < 70% sustained",
					EstimatedTime:   "1-2 weeks",
					RequiresChange:  true,
					SuccessRate:     0.95,
					EscalationPoint: "Engage VMware SD-WAN support for gateway capacity planning",
				},
			},
			KnowledgeBaseRef: "KB-VELOCLOUD-GW-001",
		})
	} else if totalDropProxy >= VeloGatewayDropThreshold {
		issues = append(issues, DetectedIssue{
			ID:              "VELOCLOUD-GW-002",
			Title:           "Gateway Queue Depth Warning",
			TechnicalDesc:   fmt.Sprintf("Gateway queue depth indicators: %d high-latency segments detected, approaching capacity threshold", totalDropProxy),
			BusinessImpact:  "Intermittent packet loss and latency spikes at gateway; real-time traffic quality degraded",
			Severity:        SeverityHigh,
			Confidence:      0.75,
			Category:        CategorySDWANData,
			RootCause:       "Gateway approaching capacity limit; handoff queue building up",
			AffectedService: "VMware VeloCloud Cloud Gateway",
			BaseFilter:      buildStreamFilter(stream),
			ExpandedFilter:  buildExpandedFilter(stream),
			OptimizedFilter: buildOptimizedFilter(stream),
			ImmediateActions: []RemediationAction{
				{
					Description:    "Monitor gateway drop counters",
					Commands:       []string{"/opt/vc/bin/dispcnt -s over_capacity_drop -d " + stream.DstIP, "/opt/vc/bin/debug.py --handoff"},
					Verification:   "Drop rate < 500/30s",
					EstimatedTime:  "5 minutes",
					RequiresChange: false,
					SuccessRate:    0.80,
				},
			},
			KnowledgeBaseRef: "KB-VELOCLOUD-GW-002",
		})
	}

	// --- Detection 2: Gateway selection failure (no return flow) ---
	// Edge sends to gateway but no return segments within the window
	clientSegments := 0
	serverSegments := 0
	for _, seg := range stream.Segments {
		if seg.Direction == "client_to_server" {
			clientSegments++
		} else {
			serverSegments++
		}
	}

	if clientSegments > 5 && serverSegments == 0 && stream.Duration >= VeloGatewayNoReturnWindowSec {
		issues = append(issues, DetectedIssue{
			ID:              "VELOCLOUD-GW-003",
			Title:           "Gateway Selection Failure — No Return Traffic",
			TechnicalDesc:   fmt.Sprintf("Edge sending %d packets to gateway %s with zero return traffic over %.1fs — gateway not responding", clientSegments, stream.DstIP, stream.Duration),
			BusinessImpact:  "Traffic blackholed at selected gateway; all flows through this gateway are failing",
			Severity:        SeverityCritical,
			Confidence:      0.85,
			Category:        CategorySDWANData,
			RootCause:       "Gateway unreachable, deactivated, or routing asymmetry preventing return path",
			AffectedService: "VMware VeloCloud Cloud Gateway",
			BaseFilter:      buildStreamFilter(stream),
			ExpandedFilter:  buildExpandedFilter(stream),
			OptimizedFilter: buildOptimizedFilter(stream),
			InvestigationSteps: []InvestigationStep{
				{
					Order:          1,
					Purpose:        "Confirm one-way traffic pattern",
					DisplayFilter:  buildStreamFilter(stream),
					ExpectedNormal: "Bidirectional traffic with return packets",
					AbnormalSign:   "All packets from Edge to gateway, no responses",
					CustomColumns:  []string{"ip.src", "ip.dst", "frame.time_delta"},
				},
			},
			ImmediateActions: []RemediationAction{
				{
					Description:    "Verify gateway reachability and activation",
					Commands:       []string{"/opt/vc/bin/is_activated.py", "ping " + stream.DstIP + " from Edge", "VCO: Network > Gateways — check gateway status"},
					Verification:   "Gateway responds to ping and shows active in VCO",
					EstimatedTime:  "3 minutes",
					RequiresChange: false,
					SuccessRate:    0.85,
				},
			},
			ShortTermFixes: []RemediationAction{
				{
					Description:    "Force gateway re-selection",
					Commands:       []string{"VCO: Edge > Actions > Reset Tunnels", "Or: /opt/vc/bin/debug.py --reset_tunnels"},
					Verification:   "New gateway selected and bidirectional traffic established",
					EstimatedTime:  "5 minutes",
					RequiresChange: true,
					SuccessRate:    0.80,
				},
			},
			KnowledgeBaseRef: "KB-VELOCLOUD-GW-003",
		})
	}

	return issues
}

// detectQoSIssues detects QoS policy enforcement problems
func (vcd *VeloCloudIssueDetector) detectQoSIssues(stream *models.StreamData) []DetectedIssue {
	issues := []DetectedIssue{}

	if len(stream.Segments) < 3 {
		return issues
	}

	// --- Detection 1: RTP/VoIP traffic without DSCP EF marking ---
	// Identify RTP flows by port range (16384-32767 UDP) or SIP signaling
	isRTPFlow := stream.Protocol == "UDP" &&
		((stream.SrcPort >= VeloQoSRTPPortLow && stream.SrcPort <= VeloQoSRTPPortHigh) ||
			(stream.DstPort >= VeloQoSRTPPortLow && stream.DstPort <= VeloQoSRTPPortHigh))
	isSIPFlow := stream.DstPort == 5060 || stream.SrcPort == 5060 ||
		stream.DstPort == 5061 || stream.SrcPort == 5061
	isRealTimeFlow := isRTPFlow || isSIPFlow || stream.Application == "RTP" || stream.Application == "SIP"

	if isRealTimeFlow {
		// Check DSCP marking via AnomalyReason field — the stream reassembler
		// records DSCP anomalies in segment AnomalyReason when DSCP != EF for RTP
		dscpMismatchCount := 0
		for _, seg := range stream.Segments {
			if seg.AnomalyReason != "" &&
				(strings.Contains(seg.AnomalyReason, "dscp") || strings.Contains(seg.AnomalyReason, "DSCP") ||
					strings.Contains(seg.AnomalyReason, "marking") || strings.Contains(seg.AnomalyReason, "qos")) {
				dscpMismatchCount++
			}
		}

		// Also detect via bursty inter-arrival: real-time traffic with gaps > 50ms
		// indicates it's not in the priority queue
		burstGapCount := 0
		for i := 1; i < len(stream.Segments); i++ {
			if stream.Segments[i].GapFromPrev > 0.05 { // >50ms for real-time = queuing
				burstGapCount++
			}
		}
		burstGapRate := float64(burstGapCount) / float64(len(stream.Segments))

		if dscpMismatchCount > 0 || burstGapRate > 0.20 {
			severity := SeverityHigh
			confidence := 0.75
			desc := fmt.Sprintf("Real-time traffic (port %d/%d) showing queuing delays: %d segments with >50ms inter-arrival (%.0f%% of flow)",
				stream.SrcPort, stream.DstPort, burstGapCount, burstGapRate*100)
			if dscpMismatchCount > 0 {
				severity = SeverityCritical
				confidence = 0.85
				desc = fmt.Sprintf("Real-time traffic DSCP marking anomaly detected in %d segments — traffic not receiving EF (DSCP 46) treatment", dscpMismatchCount)
			}
			issues = append(issues, DetectedIssue{
				ID:              "VELOCLOUD-QOS-001",
				Title:           "QoS Misclassification — Real-Time Traffic Not Prioritized",
				TechnicalDesc:   desc,
				BusinessImpact:  "VoIP/video calls experiencing jitter and latency; users reporting choppy audio and dropped calls",
				Severity:        severity,
				Confidence:      confidence,
				Category:        CategoryVoIPIssues,
				RootCause:       "Business Policy not classifying RTP/SIP as Real-Time class, or DSCP remarking by upstream device",
				AffectedService: "VMware VeloCloud QoS",
				BaseFilter:      buildStreamFilter(stream),
				ExpandedFilter:  buildExpandedFilter(stream),
				OptimizedFilter: buildOptimizedFilter(stream),
				InvestigationSteps: []InvestigationStep{
					{
						Order:          1,
						Purpose:        "Verify DSCP marking on real-time traffic",
						DisplayFilter:  buildStreamFilter(stream),
						ExpectedNormal: "DSCP EF (46) on all RTP/SIP packets",
						AbnormalSign:   "DSCP 0 (Best Effort) or inconsistent values on voice/video packets",
						CustomColumns:  []string{"ip.dsfield.dscp", "frame.time_delta", "udp.srcport"},
					},
					{
						Order:          2,
						Purpose:        "Check QoS queue statistics",
						DisplayFilter:  fmt.Sprintf("ip.addr == %s", stream.SrcIP),
						ExpectedNormal: "Real-time queue not dropping packets",
						AbnormalSign:   "High inter-arrival jitter on RTP stream",
					},
				},
				ImmediateActions: []RemediationAction{
					{
						Description:    "Check QoS link and network statistics",
						Commands:       []string{"/opt/vc/bin/debug.py --qos_dump_link", "/opt/vc/bin/debug.py --qos_dump_net"},
						Verification:   "Real-time queue not showing drops",
						EstimatedTime:  "3 minutes",
						RequiresChange: false,
						SuccessRate:    0.80,
					},
				},
				ShortTermFixes: []RemediationAction{
					{
						Description:    "Update Business Policy to classify voice/video as Real-Time",
						Commands:       []string{"VCO: Configure > Business Policy > Add rule for SIP/RTP > Class: Real-Time", "Activate configuration"},
						Verification:   "DSCP EF marking applied to voice traffic",
						EstimatedTime:  "15 minutes",
						RequiresChange: true,
						SuccessRate:    0.90,
						RollbackSteps:  []string{"Revert Business Policy to previous version"},
					},
				},
				KnowledgeBaseRef: "KB-VELOCLOUD-QOS-001",
			})
		}
	}

	// --- Detection 2: DSCP value change mid-flow (remarking) ---
	// Detect when the first segment has a different DSCP indicator than later segments
	// We use AnomalyReason as a proxy since raw DSCP isn't in StreamSegment
	firstHalfAnomalies := 0
	secondHalfAnomalies := 0
	midpoint := len(stream.Segments) / 2
	for i, seg := range stream.Segments {
		if strings.Contains(seg.AnomalyReason, "dscp") || strings.Contains(seg.AnomalyReason, "remark") {
			if i < midpoint {
				firstHalfAnomalies++
			} else {
				secondHalfAnomalies++
			}
		}
	}
	// Remarking pattern: anomalies concentrated in second half (after a policy change mid-flow)
	if firstHalfAnomalies == 0 && secondHalfAnomalies >= 3 {
		issues = append(issues, DetectedIssue{
			ID:              "VELOCLOUD-QOS-002",
			Title:           "DSCP Remarking Mid-Flow Detected",
			TechnicalDesc:   fmt.Sprintf("DSCP marking anomalies appear only in second half of flow (%d anomalies) — upstream device remarking traffic", secondHalfAnomalies),
			BusinessImpact:  "Traffic loses QoS priority mid-flow; application performance degrades unpredictably",
			Severity:        SeverityHigh,
			Confidence:      0.70,
			Category:        CategorySDWANData,
			RootCause:       "Upstream router or firewall stripping/remarking DSCP values; policy inconsistency",
			AffectedService: "VMware VeloCloud QoS",
			BaseFilter:      buildStreamFilter(stream),
			ExpandedFilter:  buildExpandedFilter(stream),
			OptimizedFilter: buildOptimizedFilter(stream),
			ImmediateActions: []RemediationAction{
				{
					Description:    "Identify remarking device with traceroute and DSCP check",
					Commands:       []string{"traceroute -Q " + stream.DstIP, "/opt/vc/bin/debug.py --qos_dump_link"},
					Verification:   "DSCP values consistent end-to-end",
					EstimatedTime:  "5 minutes",
					RequiresChange: false,
					SuccessRate:    0.75,
				},
			},
			ShortTermFixes: []RemediationAction{
				{
					Description:    "Enable DSCP trust on upstream device or configure VeloCloud to re-mark",
					Commands:       []string{"VCO: Configure > Business Policy > [Rule] > DSCP Marking > Set to EF"},
					Verification:   "Consistent DSCP marking throughout flow",
					EstimatedTime:  "20 minutes",
					RequiresChange: true,
					SuccessRate:    0.85,
				},
			},
			KnowledgeBaseRef: "KB-VELOCLOUD-QOS-002",
		})
	}

	return issues
}

// detectLAGIssues detects Link Aggregation Group problems
func (vcd *VeloCloudIssueDetector) detectLAGIssues(stream *models.StreamData) []DetectedIssue {
	issues := []DetectedIssue{}

	if len(stream.Segments) < 10 {
		return issues
	}

	// LAG issues manifest as throughput anomalies and out-of-order packets.
	// We analyze the stream's segment size distribution and OOO/retransmit patterns.

	// --- Detection 1: LAG member failure — sudden ~50% throughput drop ---
	// Split stream into two halves and compare average segment sizes
	mid := len(stream.Segments) / 2
	var firstHalfBytes, secondHalfBytes int
	for i, seg := range stream.Segments {
		if i < mid {
			firstHalfBytes += seg.Length
		} else {
			secondHalfBytes += seg.Length
		}
	}

	if firstHalfBytes > 0 && secondHalfBytes > 0 {
		ratio := float64(secondHalfBytes) / float64(firstHalfBytes)
		// A drop to ~50% of first-half throughput indicates a 2-member LAG losing one link
		if ratio < (1.0 - VeloLAGFailureThreshold) {
			issues = append(issues, DetectedIssue{
				ID:              "VELOCLOUD-LAG-001",
				Title:           "LAG Member Link Failure — 50% Throughput Drop",
				TechnicalDesc:   fmt.Sprintf("Stream throughput dropped to %.0f%% of baseline mid-flow (first half: %d bytes, second half: %d bytes) — consistent with 2-member LAG losing one link", ratio*100, firstHalfBytes, secondHalfBytes),
				BusinessImpact:  "50%% bandwidth reduction; applications may experience congestion and timeouts",
				Severity:        SeverityCritical,
				Confidence:      0.80,
				Category:        CategorySDWANData,
				RootCause:       "LAG member link failure: physical link down, SFP failure, or upstream switch port error",
				AffectedService: "VMware VeloCloud Link Aggregation",
				BaseFilter:      buildStreamFilter(stream),
				ExpandedFilter:  buildExpandedFilter(stream),
				OptimizedFilter: buildOptimizedFilter(stream),
				InvestigationSteps: []InvestigationStep{
					{
						Order:          1,
						Purpose:        "Identify throughput drop point in stream",
						DisplayFilter:  buildStreamFilter(stream),
						ExpectedNormal: "Consistent packet sizes throughout flow",
						AbnormalSign:   "Sudden reduction in packet rate or size mid-stream",
						CustomColumns:  []string{"frame.len", "frame.time_delta", "ip.src"},
					},
					{
						Order:          2,
						Purpose:        "Check for interface errors on LAG members",
						DisplayFilter:  fmt.Sprintf("ip.addr == %s", stream.SrcIP),
						ExpectedNormal: "No interface errors or CRC errors",
						AbnormalSign:   "CRC errors or input drops on one LAG member",
					},
				},
				ImmediateActions: []RemediationAction{
					{
						Description:    "Check LAG member status in VCO",
						Commands:       []string{"VCO: Edge > Device > Interfaces — check LAG member states", "Edge CLI: ifconfig | grep -A5 bond"},
						Verification:   "All LAG members show as UP",
						EstimatedTime:  "2 minutes",
						RequiresChange: false,
						SuccessRate:    0.85,
					},
					{
						Description:    "Check physical interface errors",
						Commands:       []string{"Edge CLI: ethtool <member-interface>", "Check upstream switch port for errors"},
						Verification:   "No CRC errors or link flaps on member interfaces",
						EstimatedTime:  "5 minutes",
						RequiresChange: false,
						SuccessRate:    0.80,
					},
				},
				ShortTermFixes: []RemediationAction{
					{
						Description:    "Replace failed SFP or reseat cable on failed LAG member",
						Commands:       []string{"Identify failed member from VCO interface stats", "Replace physical media and verify link UP"},
						Verification:   "Both LAG members UP, throughput restored to 100%",
						EstimatedTime:  "30 minutes",
						RequiresChange: true,
						SuccessRate:    0.90,
					},
				},
				KnowledgeBaseRef: "KB-VELOCLOUD-LAG-001",
			})
		}
	}

	// --- Detection 2: LAG hash imbalance — out-of-order packets as proxy ---
	// When LAG hashing is uneven, one member carries most traffic.
	// Out-of-order packets are a side effect of per-packet (not per-flow) LAG hashing.
	oooCount := 0
	retransmitCount := 0
	for _, seg := range stream.Segments {
		if seg.IsOutOfOrder {
			oooCount++
		}
		if seg.IsRetransmit {
			retransmitCount++
		}
	}

	oooRate := float64(oooCount) / float64(len(stream.Segments))
	if oooRate > 0.05 && retransmitCount < oooCount { // OOO without proportional retransmits = reordering, not loss
		issues = append(issues, DetectedIssue{
			ID:              "VELOCLOUD-LAG-002",
			Title:           "LAG Hash Imbalance — Out-of-Order Packets",
			TechnicalDesc:   fmt.Sprintf("%.0f%% out-of-order packet rate (%d/%d segments) with low retransmit count (%d) — consistent with per-packet LAG hashing causing reordering", oooRate*100, oooCount, len(stream.Segments), retransmitCount),
			BusinessImpact:  "TCP performance degraded by reordering; applications experience increased latency and reduced throughput",
			Severity:        SeverityHigh,
			Confidence:      0.75,
			Category:        CategorySDWANData,
			RootCause:       "LAG configured for per-packet load balancing instead of per-flow; packets from same flow arriving via different members with different latencies",
			AffectedService: "VMware VeloCloud Link Aggregation",
			BaseFilter:      buildStreamFilter(stream),
			ExpandedFilter:  buildExpandedFilter(stream) + " && tcp.analysis.out_of_order",
			OptimizedFilter: buildOptimizedFilter(stream),
			InvestigationSteps: []InvestigationStep{
				{
					Order:          1,
					Purpose:        "Confirm out-of-order pattern",
					DisplayFilter:  buildStreamFilter(stream) + " && tcp.analysis.out_of_order",
					ExpectedNormal: "< 1% out-of-order packets",
					AbnormalSign:   "> 5% out-of-order without corresponding loss",
					CustomColumns:  []string{"tcp.analysis.out_of_order", "tcp.seq", "frame.time_delta"},
				},
			},
			ImmediateActions: []RemediationAction{
				{
					Description:    "Check LAG load-balancing mode",
					Commands:       []string{"VCO: Edge > Device > Interfaces > LAG > Load Balance Mode", "Verify set to 'Layer 3+4' (per-flow) not 'Layer 2' (per-packet)"},
					Verification:   "LAG using per-flow (L3+4) hashing",
					EstimatedTime:  "3 minutes",
					RequiresChange: false,
					SuccessRate:    0.85,
				},
			},
			ShortTermFixes: []RemediationAction{
				{
					Description:    "Change LAG hash mode to per-flow (Layer 3+4)",
					Commands:       []string{"VCO: Edge > Device > Interfaces > LAG > Load Balance: Layer3+4", "Activate configuration"},
					Verification:   "Out-of-order packet rate drops below 1%",
					EstimatedTime:  "10 minutes",
					RequiresChange: true,
					SuccessRate:    0.90,
					RollbackSteps:  []string{"Revert LAG hash mode to previous setting"},
				},
			},
			KnowledgeBaseRef: "KB-VELOCLOUD-LAG-002",
		})
	}

	// --- Detection 3: LAG flapping — multiple resets in short window ---
	resetCount := 0
	for _, seg := range stream.Segments {
		if seg.HasReset {
			resetCount++
		}
	}
	if resetCount >= 3 && stream.Duration < 60 {
		issues = append(issues, DetectedIssue{
			ID:              "VELOCLOUD-LAG-003",
			Title:           "LAG Member Flapping",
			TechnicalDesc:   fmt.Sprintf("%d TCP resets detected within %.1f seconds — consistent with LAG member link flapping causing repeated connection drops", resetCount, stream.Duration),
			BusinessImpact:  "Repeated connection drops; applications experience intermittent failures and timeouts",
			Severity:        SeverityCritical,
			Confidence:      0.75,
			Category:        CategorySDWANData,
			RootCause:       "LAG member link flapping: cable/SFP issue, autonegotiation mismatch, or upstream switch port instability",
			AffectedService: "VMware VeloCloud Link Aggregation",
			BaseFilter:      buildStreamFilter(stream),
			ExpandedFilter:  buildExpandedFilter(stream) + " && tcp.flags.reset == 1",
			OptimizedFilter: buildOptimizedFilter(stream),
			ImmediateActions: []RemediationAction{
				{
					Description:    "Check LAG member link state history",
					Commands:       []string{"VCO: Edge > Events — filter for interface up/down events", "Edge CLI: dmesg | grep -i 'link\\|eth\\|bond'"},
					Verification:   "No repeated link up/down events in last 60 seconds",
					EstimatedTime:  "3 minutes",
					RequiresChange: false,
					SuccessRate:    0.85,
				},
			},
			ShortTermFixes: []RemediationAction{
				{
					Description:    "Force LAG member speed/duplex to avoid autoneg flapping",
					Commands:       []string{"Edge CLI: ethtool -s <member-intf> speed 1000 duplex full autoneg off", "Or replace cable/SFP on flapping member"},
					Verification:   "No link state changes for 5+ minutes",
					EstimatedTime:  "15 minutes",
					RequiresChange: true,
					SuccessRate:    0.80,
				},
			},
			KnowledgeBaseRef: "KB-VELOCLOUD-LAG-003",
		})
	}

	return issues
}
