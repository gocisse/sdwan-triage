package analyzer

import (
	"fmt"
	"strings"

	"github.com/gocisse/sdwan-triage/pkg/models"
)

// Aruba EdgeConnect detection thresholds
const (
	ArubaFPIQUnknownRateThreshold = 0.15  // >15% unknown app classification = cache miss issue
	ArubaFPIQSaaSLatencyMultiple  = 2.0   // >2x expected RTT = suboptimal SaaS path
	ArubaBondingOOOThreshold      = 0.05  // >5% OOO = bonding asymmetry
	ArubaBondingAsymmetryRatio    = 0.20  // <20% on one tunnel = imbalance
	ArubaSaaSBackhaulGapSec       = 0.200 // >200ms avg gap on SaaS flow = backhauled
	ArubaMinSegmentsForAnalysis   = 5
)

// Aruba EdgeConnect-specific ports and protocols
const (
	ArubaEdgeConnectPort    uint16 = 4980 // EdgeConnect tunnel
	ArubaEdgeConnectAltPort uint16 = 4981 // EdgeConnect tunnel alternate
	ArubaOrchPort           uint16 = 443  // Orchestrator HTTPS
	ArubaBoostPort          uint16 = 4163 // Boost acceleration
)

// ArubaIssueDetector detects Aruba EdgeConnect-specific issues
type ArubaIssueDetector struct {
	classifier   *AdvancedClassifier
	healthScorer *HealthScorer
}

// NewArubaIssueDetector creates a new Aruba detector
func NewArubaIssueDetector() *ArubaIssueDetector {
	return &ArubaIssueDetector{
		classifier:   NewAdvancedClassifier(),
		healthScorer: NewHealthScorer(),
	}
}

// DetectArubaIssues analyzes streams for Aruba EdgeConnect-specific problems
func (aid *ArubaIssueDetector) DetectArubaIssues(stream *models.StreamData) []DetectedIssue {
	issues := []DetectedIssue{}

	if !aid.isArubaTraffic(stream) {
		return issues
	}

	// Path conditioning failures
	if pathIssues := aid.detectPathConditioningIssues(stream); len(pathIssues) > 0 {
		issues = append(issues, pathIssues...)
	}

	// Boost acceleration issues
	if boostIssues := aid.detectBoostIssues(stream); len(boostIssues) > 0 {
		issues = append(issues, boostIssues...)
	}

	// First Packet iQ classification issues
	if fpiqIssues := aid.detectFirstPacketIQIssues(stream); len(fpiqIssues) > 0 {
		issues = append(issues, fpiqIssues...)
	}

	// Tunnel bonding problems
	if bondingIssues := aid.detectTunnelBondingIssues(stream); len(bondingIssues) > 0 {
		issues = append(issues, bondingIssues...)
	}

	// SaaS optimization path selection
	if saasIssues := aid.detectSaaSOptimizationIssues(stream); len(saasIssues) > 0 {
		issues = append(issues, saasIssues...)
	}

	return issues
}

// isArubaTraffic checks if stream is Aruba EdgeConnect-related
func (aid *ArubaIssueDetector) isArubaTraffic(stream *models.StreamData) bool {
	arubaPorts := []uint16{ArubaEdgeConnectPort, ArubaEdgeConnectAltPort, ArubaBoostPort}

	for _, port := range arubaPorts {
		if stream.DstPort == port || stream.SrcPort == port {
			return true
		}
	}

	return false
}

// detectPathConditioningIssues detects path conditioning failures
func (aid *ArubaIssueDetector) detectPathConditioningIssues(stream *models.StreamData) []DetectedIssue {
	issues := []DetectedIssue{}

	if stream.DstPort != ArubaEdgeConnectPort && stream.SrcPort != ArubaEdgeConnectPort {
		return issues
	}

	healthScore := aid.healthScorer.ScoreStream(stream)

	// High packet loss on tunnel (path conditioning should mitigate)
	retransmitCount := 0
	for _, segment := range stream.Segments {
		if segment.IsRetransmit {
			retransmitCount++
		}
	}

	if retransmitCount > 0 && stream.PacketCount > 0 {
		retransmitRate := float64(retransmitCount) / float64(stream.PacketCount)
		if retransmitRate > 0.05 { // >5% loss despite path conditioning
			issue := DetectedIssue{
				ID:              "ARUBA-PATH-001",
				Title:           "Path Conditioning Ineffective",
				TechnicalDesc:   "High packet loss on EdgeConnect tunnel despite path conditioning enabled",
				BusinessImpact:  "Application performance degraded, real-time traffic quality poor",
				Severity:        SeverityHigh,
				Confidence:      0.85,
				Category:        CategorySDWANData,
				RootCause:       "Underlying WAN quality too poor for FEC/POC to compensate, or path conditioning disabled",
				AffectedService: "Aruba EdgeConnect Path Conditioning",

				BaseFilter:      buildStreamFilter(stream),
				ExpandedFilter:  buildExpandedFilter(stream) + " || (udp.port == 4980)",
				OptimizedFilter: buildOptimizedFilter(stream),

				InvestigationSteps: []InvestigationStep{
					{
						Order:          1,
						Purpose:        "Analyze tunnel packet loss",
						DisplayFilter:  buildStreamFilter(stream) + " && tcp.analysis.retransmission",
						ExpectedNormal: "< 1% retransmission rate",
						AbnormalSign:   "> 5% retransmission rate",
						CustomColumns:  []string{"tcp.analysis.retransmission", "frame.time_delta"},
					},
					{
						Order:          2,
						Purpose:        "Check for FEC packets",
						DisplayFilter:  "udp.port == 4980",
						ExpectedNormal: "FEC packets present in stream",
						AbnormalSign:   "No FEC packets or excessive FEC overhead",
					},
				},

				ImmediateActions: []RemediationAction{
					{
						Description:    "Check path conditioning status in Orchestrator",
						Commands:       []string{"Navigate to Appliance > Deployment > Path Conditioning", "Verify FEC and POC enabled"},
						Verification:   "Path conditioning enabled and active",
						EstimatedTime:  "3 minutes",
						RequiresChange: false,
						SuccessRate:    0.80,
					},
					{
						Description:    "Check underlying WAN link quality",
						Commands:       []string{"Review Tunnel Health in Orchestrator", "Check WAN interface error counters"},
						Verification:   "WAN link quality within acceptable range",
						EstimatedTime:  "5 minutes",
						RequiresChange: false,
						SuccessRate:    0.75,
					},
				},

				ShortTermFixes: []RemediationAction{
					{
						Description:    "Increase FEC ratio for lossy link",
						Commands:       []string{"Orchestrator: Configuration > Overlays > Tunnel > FEC Ratio", "Increase to 1:3 or 1:4"},
						Verification:   "Packet loss reduced after FEC adjustment",
						EstimatedTime:  "15 minutes",
						RequiresChange: true,
						SuccessRate:    0.80,
						RollbackSteps:  []string{"Restore previous FEC ratio"},
					},
					{
						Description:    "Enable Packet Order Correction (POC)",
						Commands:       []string{"Orchestrator: Configuration > Overlays > Tunnel > Enable POC"},
						Verification:   "Out-of-order packets reduced",
						EstimatedTime:  "10 minutes",
						RequiresChange: true,
						SuccessRate:    0.75,
					},
				},

				LongTermSolutions: []RemediationAction{
					{
						Description:     "Upgrade WAN link or add redundant path",
						Verification:    "Baseline packet loss < 0.5%",
						EstimatedTime:   "2-4 weeks",
						RequiresChange:  true,
						SuccessRate:     0.95,
						EscalationPoint: "Engage WAN provider for link quality issues",
					},
				},

				KnowledgeBaseRef: "KB-ARUBA-PATH-001",
			}
			issues = append(issues, issue)
		}
	}

	// Tunnel connection failure
	if healthScore.Status == HealthStatusCritical {
		issue := DetectedIssue{
			ID:              "ARUBA-PATH-002",
			Title:           "EdgeConnect Tunnel Failure",
			TechnicalDesc:   "EdgeConnect tunnel failing to establish or maintain connectivity",
			BusinessImpact:  "Site isolated, traffic forced to local breakout, SD-WAN benefits lost",
			Severity:        SeverityCritical,
			Confidence:      0.90,
			Category:        CategorySDWANData,
			RootCause:       "Peer unreachable, firewall blocking, or configuration mismatch",
			AffectedService: "Aruba EdgeConnect Tunnel",

			BaseFilter:      buildStreamFilter(stream),
			ExpandedFilter:  buildExpandedFilter(stream),
			OptimizedFilter: buildOptimizedFilter(stream),

			ImmediateActions: []RemediationAction{
				{
					Description:    "Check tunnel status in Orchestrator",
					Commands:       []string{"Navigate to Appliance > Tunnels", "Check tunnel state and last up time"},
					Verification:   "Tunnel shows as UP",
					EstimatedTime:  "2 minutes",
					RequiresChange: false,
					SuccessRate:    0.85,
				},
				{
					Description:    "Verify peer reachability",
					Commands:       []string{"Ping peer public IP from EdgeConnect CLI", "Check for ICMP responses"},
					Verification:   "Peer responds to ping",
					EstimatedTime:  "2 minutes",
					RequiresChange: false,
					SuccessRate:    0.80,
				},
			},

			ShortTermFixes: []RemediationAction{
				{
					Description:    "Restart tunnel from Orchestrator",
					Commands:       []string{"Orchestrator: Appliance > Actions > Restart Tunnels"},
					Verification:   "Tunnel re-establishes",
					EstimatedTime:  "5 minutes",
					RequiresChange: true,
					SuccessRate:    0.75,
				},
				{
					Description:    "Check firewall rules for UDP 4980/4981",
					Commands:       []string{"Verify upstream firewall allows UDP 4980, 4981 bidirectionally"},
					Verification:   "Firewall permits tunnel traffic",
					EstimatedTime:  "15 minutes",
					RequiresChange: true,
					SuccessRate:    0.85,
				},
			},

			KnowledgeBaseRef: "KB-ARUBA-PATH-002",
		}
		issues = append(issues, issue)
	}

	return issues
}

// detectBoostIssues detects Boost acceleration problems
func (aid *ArubaIssueDetector) detectBoostIssues(stream *models.StreamData) []DetectedIssue {
	issues := []DetectedIssue{}

	if stream.DstPort != ArubaBoostPort && stream.SrcPort != ArubaBoostPort {
		return issues
	}

	healthScore := aid.healthScorer.ScoreStream(stream)

	// Boost connection failure
	if healthScore.Status == HealthStatusCritical {
		issue := DetectedIssue{
			ID:              "ARUBA-BOOST-001",
			Title:           "Boost Acceleration Failure",
			TechnicalDesc:   "Boost WAN optimization not functioning properly",
			BusinessImpact:  "Reduced WAN efficiency, higher bandwidth consumption, slower file transfers",
			Severity:        SeverityMedium,
			Confidence:      0.80,
			Category:        CategorySDWANData,
			RootCause:       "Boost license expired, peer Boost unavailable, or incompatible traffic",
			AffectedService: "Aruba EdgeConnect Boost",

			BaseFilter:      buildStreamFilter(stream),
			ExpandedFilter:  buildExpandedFilter(stream),
			OptimizedFilter: buildOptimizedFilter(stream),

			ImmediateActions: []RemediationAction{
				{
					Description:    "Check Boost license status",
					Commands:       []string{"Orchestrator: Appliance > Licenses", "Verify Boost license active"},
					Verification:   "Boost license valid and not expired",
					EstimatedTime:  "2 minutes",
					RequiresChange: false,
					SuccessRate:    0.85,
				},
				{
					Description:    "Verify Boost enabled on both peers",
					Commands:       []string{"Check Boost configuration on source and destination EdgeConnect"},
					Verification:   "Boost enabled on both ends of tunnel",
					EstimatedTime:  "5 minutes",
					RequiresChange: false,
					SuccessRate:    0.80,
				},
			},

			ShortTermFixes: []RemediationAction{
				{
					Description:    "Restart Boost service",
					Commands:       []string{"EdgeConnect CLI: restart boost", "Or restart from Orchestrator"},
					Verification:   "Boost service running and optimizing traffic",
					EstimatedTime:  "5 minutes",
					RequiresChange: true,
					SuccessRate:    0.75,
				},
			},

			KnowledgeBaseRef: "KB-ARUBA-BOOST-001",
		}
		issues = append(issues, issue)
	}

	return issues
}

// detectFirstPacketIQIssues detects First Packet iQ classification problems
func (aid *ArubaIssueDetector) detectFirstPacketIQIssues(stream *models.StreamData) []DetectedIssue {
	issues := []DetectedIssue{}

	if len(stream.Segments) < ArubaMinSegmentsForAnalysis {
		return issues
	}

	// Known SaaS destination patterns (SNI/ServerName or well-known IPs)
	// First Packet iQ should classify these on the very first packet
	knownSaaSPatterns := []string{
		"microsoft", "office365", "outlook", "sharepoint", "teams",
		"salesforce", "force.com", "servicenow", "workday",
		"zoom", "webex", "google", "amazonaws", "azure",
	}

	isSaaSFlow := false
	matchedSaaS := ""
	serverName := strings.ToLower(stream.ServerName)
	dstAppLower := strings.ToLower(stream.Application)
	for _, pattern := range knownSaaSPatterns {
		if strings.Contains(serverName, pattern) || strings.Contains(dstAppLower, pattern) {
			isSaaSFlow = true
			matchedSaaS = pattern
			break
		}
	}

	// --- Detection 1: Known SaaS traffic classified as unknown/generic ---
	// If Application field is empty or "unknown" for a flow to a known SaaS SNI,
	// First Packet iQ failed to classify it correctly.
	isUnclassified := stream.Application == "" || stream.Application == "unknown" ||
		stream.Application == "generic" || stream.Application == "TCP" || stream.Application == "UDP"

	if isSaaSFlow && isUnclassified {
		issues = append(issues, DetectedIssue{
			ID:              "ARUBA-FPIQ-001",
			Title:           "First Packet iQ Misclassification — Known SaaS Unrecognized",
			TechnicalDesc:   fmt.Sprintf("Flow to %s (SNI: %s) classified as '%s' — First Packet iQ failed to identify known SaaS application '%s'", stream.DstIP, stream.ServerName, stream.Application, matchedSaaS),
			BusinessImpact:  "SaaS traffic not receiving optimal path selection; may be routed via suboptimal overlay instead of direct internet breakout",
			Severity:        SeverityHigh,
			Confidence:      0.85,
			Category:        CategorySDWANData,
			RootCause:       "First Packet iQ signature cache miss, outdated application signatures, or TLS 1.3 encrypted SNI preventing classification",
			AffectedService: "Aruba EdgeConnect First Packet iQ",
			BaseFilter:      buildStreamFilter(stream),
			ExpandedFilter:  buildExpandedFilter(stream) + " && ssl.handshake.extensions_server_name",
			OptimizedFilter: buildOptimizedFilter(stream),
			InvestigationSteps: []InvestigationStep{
				{
					Order:          1,
					Purpose:        "Verify TLS SNI is visible and matches SaaS pattern",
					DisplayFilter:  buildStreamFilter(stream) + " && ssl.handshake.type == 1",
					ExpectedNormal: "ClientHello with SNI matching known SaaS domain",
					AbnormalSign:   "No SNI present (ESNI/ECH) or SNI not matching signature database",
					CustomColumns:  []string{"ssl.handshake.extensions_server_name", "ip.dst", "frame.time_delta"},
				},
				{
					Order:          2,
					Purpose:        "Check First Packet iQ classification stats",
					DisplayFilter:  buildStreamFilter(stream),
					ExpectedNormal: "Application classified on first packet",
					AbnormalSign:   "Multiple packets before classification or no classification",
				},
			},
			ImmediateActions: []RemediationAction{
				{
					Description:    "Check First Packet iQ statistics and cache",
					Commands:       []string{"show stats first-packet", "show flows | grep " + stream.DstIP},
					Verification:   "First Packet iQ hit rate > 85%",
					EstimatedTime:  "3 minutes",
					RequiresChange: false,
					SuccessRate:    0.80,
				},
				{
					Description:    "Verify application signature database is current",
					Commands:       []string{"Orchestrator: Appliance > Software > Application Signatures — check version", "Compare to latest available version"},
					Verification:   "Signatures up to date",
					EstimatedTime:  "2 minutes",
					RequiresChange: false,
					SuccessRate:    0.85,
				},
			},
			ShortTermFixes: []RemediationAction{
				{
					Description:    "Update application signatures and clear First Packet iQ cache",
					Commands:       []string{"Orchestrator: Appliance > Actions > Update Signatures", "EdgeConnect CLI: restart first-packet-iq"},
					Verification:   "Known SaaS applications classified correctly on first packet",
					EstimatedTime:  "15 minutes",
					RequiresChange: true,
					SuccessRate:    0.85,
					RollbackSteps:  []string{"Revert to previous signature version if classification worsens"},
				},
				{
					Description:    "Add manual application definition for unrecognized SaaS",
					Commands:       []string{"Orchestrator: Configuration > Applications > Add Custom Application > IP/Domain: " + stream.ServerName},
					Verification:   "Custom application matched and routed correctly",
					EstimatedTime:  "10 minutes",
					RequiresChange: true,
					SuccessRate:    0.90,
				},
			},
			KnowledgeBaseRef: "KB-ARUBA-FPIQ-001",
		})
	}

	// --- Detection 2: High rate of anomaly segments on first few packets ---
	// First Packet iQ cache misses cause the first 3-5 packets to be delayed
	// while the appliance waits for more data to classify. This shows as gaps.
	earlyGapCount := 0
	checkUpTo := 5
	if len(stream.Segments) < checkUpTo {
		checkUpTo = len(stream.Segments)
	}
	for i := 1; i < checkUpTo; i++ {
		if stream.Segments[i].GapFromPrev > 0.05 { // >50ms gap in first 5 segments
			earlyGapCount++
		}
	}

	if earlyGapCount >= 2 && !isSaaSFlow {
		issues = append(issues, DetectedIssue{
			ID:              "ARUBA-FPIQ-002",
			Title:           "First Packet iQ Cache Miss — Classification Delay",
			TechnicalDesc:   fmt.Sprintf("Flow %s:%d→%s:%d shows %d gaps >50ms in first 5 segments — consistent with First Packet iQ waiting for additional packets to classify application", stream.SrcIP, stream.SrcPort, stream.DstIP, stream.DstPort, earlyGapCount),
			BusinessImpact:  "Application classification delayed; first few packets may be routed suboptimally before Business Intent Overlay takes effect",
			Severity:        SeverityMedium,
			Confidence:      0.70,
			Category:        CategorySDWANData,
			RootCause:       "Application not in First Packet iQ signature database; appliance waiting for TCP payload to classify",
			AffectedService: "Aruba EdgeConnect First Packet iQ",
			BaseFilter:      buildStreamFilter(stream),
			ExpandedFilter:  buildExpandedFilter(stream),
			OptimizedFilter: buildOptimizedFilter(stream),
			ImmediateActions: []RemediationAction{
				{
					Description:    "Check First Packet iQ miss rate",
					Commands:       []string{"show stats first-packet", "show flows | grep " + stream.DstIP},
					Verification:   "Cache miss rate < 15%",
					EstimatedTime:  "3 minutes",
					RequiresChange: false,
					SuccessRate:    0.75,
				},
			},
			ShortTermFixes: []RemediationAction{
				{
					Description:    "Add IP/subnet-based application definition for frequently missed apps",
					Commands:       []string{"Orchestrator: Configuration > Applications > Add Custom Application > Subnet: " + stream.DstIP + "/24"},
					Verification:   "Application classified on first packet",
					EstimatedTime:  "10 minutes",
					RequiresChange: true,
					SuccessRate:    0.85,
				},
			},
			KnowledgeBaseRef: "KB-ARUBA-FPIQ-002",
		})
	}

	return issues
}

// detectTunnelBondingIssues detects tunnel bonding problems
func (aid *ArubaIssueDetector) detectTunnelBondingIssues(stream *models.StreamData) []DetectedIssue {
	issues := []DetectedIssue{}

	if len(stream.Segments) < ArubaMinSegmentsForAnalysis {
		return issues
	}

	// Tunnel bonding traffic uses EdgeConnect ports
	isBondedTunnel := stream.DstPort == ArubaEdgeConnectPort || stream.SrcPort == ArubaEdgeConnectPort ||
		stream.DstPort == ArubaEdgeConnectAltPort || stream.SrcPort == ArubaEdgeConnectAltPort
	if !isBondedTunnel {
		return issues
	}

	// --- Detection 1: Out-of-order packets indicating bonding asymmetry ---
	// When bonded tunnels have different latencies, packets arrive OOO.
	// POC (Packet Order Correction) should handle this, but if OOO rate is high,
	// POC is overwhelmed or disabled.
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

	if oooRate > ArubaBondingOOOThreshold {
		severity := SeverityHigh
		if oooRate > 0.15 {
			severity = SeverityCritical
		}
		issues = append(issues, DetectedIssue{
			ID:              "ARUBA-BOND-001",
			Title:           "Tunnel Bonding Out-of-Order — POC Overwhelmed",
			TechnicalDesc:   fmt.Sprintf("%.0f%% out-of-order packet rate (%d/%d segments) on bonded tunnel — Packet Order Correction (POC) not keeping up with bonding asymmetry", oooRate*100, oooCount, len(stream.Segments)),
			BusinessImpact:  "TCP performance severely degraded; applications experience high latency and reduced throughput due to reordering",
			Severity:        severity,
			Confidence:      0.85,
			Category:        CategorySDWANData,
			RootCause:       "Large latency differential between bonded tunnel members (>30ms); POC buffer exhausted or disabled",
			AffectedService: "Aruba EdgeConnect Tunnel Bonding",
			BaseFilter:      buildStreamFilter(stream),
			ExpandedFilter:  buildExpandedFilter(stream) + " && tcp.analysis.out_of_order",
			OptimizedFilter: buildOptimizedFilter(stream),
			InvestigationSteps: []InvestigationStep{
				{
					Order:          1,
					Purpose:        "Confirm out-of-order pattern on bonded tunnel",
					DisplayFilter:  buildStreamFilter(stream) + " && tcp.analysis.out_of_order",
					ExpectedNormal: "< 1% out-of-order with POC enabled",
					AbnormalSign:   fmt.Sprintf("> 5%% out-of-order — currently %.0f%%", oooRate*100),
					CustomColumns:  []string{"tcp.analysis.out_of_order", "tcp.seq", "frame.time_delta"},
				},
				{
					Order:          2,
					Purpose:        "Check latency differential between bonded members",
					DisplayFilter:  fmt.Sprintf("udp.port == %d || udp.port == %d", ArubaEdgeConnectPort, ArubaEdgeConnectAltPort),
					ExpectedNormal: "< 30ms latency difference between bonded members",
					AbnormalSign:   "> 30ms differential causing excessive reordering",
				},
			},
			ImmediateActions: []RemediationAction{
				{
					Description:    "Check tunnel bonding status and member latencies",
					Commands:       []string{"show tunnel status", "show stats tunnel", "Orchestrator: Appliance > Tunnels — check per-member latency"},
					Verification:   "Latency differential < 30ms between bonded members",
					EstimatedTime:  "3 minutes",
					RequiresChange: false,
					SuccessRate:    0.80,
				},
			},
			ShortTermFixes: []RemediationAction{
				{
					Description:    "Enable or increase POC buffer size",
					Commands:       []string{"Orchestrator: Configuration > Overlays > Tunnel > Packet Order Correction > Enable", "Increase POC buffer to 100ms"},
					Verification:   "Out-of-order rate drops below 1%",
					EstimatedTime:  "10 minutes",
					RequiresChange: true,
					SuccessRate:    0.85,
					RollbackSteps:  []string{"Disable POC if it increases latency unacceptably"},
				},
				{
					Description:    "Remove high-latency member from bond or use path conditioning instead",
					Commands:       []string{"Orchestrator: Configuration > Overlays > Tunnel > Remove high-latency member", "Or: Use FEC instead of bonding for lossy links"},
					Verification:   "OOO rate drops, throughput maintained",
					EstimatedTime:  "20 minutes",
					RequiresChange: true,
					SuccessRate:    0.80,
				},
			},
			KnowledgeBaseRef: "KB-ARUBA-BOND-001",
		})
	}

	// --- Detection 2: Tunnel bonding member failure — sudden throughput drop ---
	// Split stream into halves and compare byte counts
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
		// Drop to <45% of first-half throughput = one bonded member failed
		if ratio < (1.0 - ArubaBondingAsymmetryRatio*4) {
			issues = append(issues, DetectedIssue{
				ID:              "ARUBA-BOND-002",
				Title:           "Tunnel Bonding Member Failure — Throughput Drop",
				TechnicalDesc:   fmt.Sprintf("Bonded tunnel throughput dropped to %.0f%% of baseline (first half: %d bytes, second half: %d bytes) — consistent with bonded member failure", ratio*100, firstHalfBytes, secondHalfBytes),
				BusinessImpact:  "Reduced bandwidth on bonded tunnel; applications may experience congestion if remaining member is insufficient",
				Severity:        SeverityCritical,
				Confidence:      0.80,
				Category:        CategorySDWANData,
				RootCause:       "One bonded tunnel member failed: WAN link down, peer unreachable, or firewall blocking tunnel port",
				AffectedService: "Aruba EdgeConnect Tunnel Bonding",
				BaseFilter:      buildStreamFilter(stream),
				ExpandedFilter:  buildExpandedFilter(stream),
				OptimizedFilter: buildOptimizedFilter(stream),
				InvestigationSteps: []InvestigationStep{
					{
						Order:          1,
						Purpose:        "Identify which bonded member failed",
						DisplayFilter:  fmt.Sprintf("udp.port == %d || udp.port == %d", ArubaEdgeConnectPort, ArubaEdgeConnectAltPort),
						ExpectedNormal: "Traffic on both tunnel members",
						AbnormalSign:   "Traffic only on one tunnel member after mid-stream",
						CustomColumns:  []string{"ip.dst", "udp.dstport", "frame.len", "frame.time_delta"},
					},
				},
				ImmediateActions: []RemediationAction{
					{
						Description:    "Check tunnel member status in Orchestrator",
						Commands:       []string{"show tunnel status", "Orchestrator: Appliance > Tunnels — check bonded member states"},
						Verification:   "Identify which member is down",
						EstimatedTime:  "2 minutes",
						RequiresChange: false,
						SuccessRate:    0.90,
					},
					{
						Description:    "Verify WAN link for failed member",
						Commands:       []string{"show interface <wan-intf>", "Ping peer IP via failed member WAN interface"},
						Verification:   "WAN link UP and peer reachable",
						EstimatedTime:  "3 minutes",
						RequiresChange: false,
						SuccessRate:    0.85,
					},
				},
				ShortTermFixes: []RemediationAction{
					{
						Description:    "Restart failed tunnel member",
						Commands:       []string{"Orchestrator: Appliance > Tunnels > [Failed Member] > Actions > Restart"},
						Verification:   "Both bonded members UP, throughput restored",
						EstimatedTime:  "5 minutes",
						RequiresChange: true,
						SuccessRate:    0.80,
					},
				},
				KnowledgeBaseRef: "KB-ARUBA-BOND-002",
			})
		}
	}

	// --- Detection 3: Multiple resets indicating bonding flapping ---
	resetCount := 0
	for _, seg := range stream.Segments {
		if seg.HasReset {
			resetCount++
		}
	}
	if resetCount >= 3 && stream.Duration < 60 {
		issues = append(issues, DetectedIssue{
			ID:              "ARUBA-BOND-003",
			Title:           "Tunnel Bonding Member Flapping",
			TechnicalDesc:   fmt.Sprintf("%d TCP resets in %.1fs on bonded tunnel — consistent with bonded member repeatedly going up/down", resetCount, stream.Duration),
			BusinessImpact:  "Intermittent connection drops; applications experience repeated failures as bonding member flaps",
			Severity:        SeverityCritical,
			Confidence:      0.75,
			Category:        CategorySDWANData,
			RootCause:       "WAN link instability on one bonded member; physical layer issue or upstream provider problem",
			AffectedService: "Aruba EdgeConnect Tunnel Bonding",
			BaseFilter:      buildStreamFilter(stream),
			ExpandedFilter:  buildExpandedFilter(stream) + " && tcp.flags.reset == 1",
			OptimizedFilter: buildOptimizedFilter(stream),
			ImmediateActions: []RemediationAction{
				{
					Description:    "Check bonded member tunnel history",
					Commands:       []string{"show tunnel status", "Orchestrator: Appliance > Events — filter for tunnel up/down events"},
					Verification:   "Identify flapping member and frequency",
					EstimatedTime:  "3 minutes",
					RequiresChange: false,
					SuccessRate:    0.85,
				},
			},
			ShortTermFixes: []RemediationAction{
				{
					Description:    "Disable flapping member and investigate WAN link",
					Commands:       []string{"Orchestrator: Configuration > Overlays > Tunnel > Disable flapping member", "Contact WAN provider for link quality report"},
					Verification:   "No further tunnel resets; remaining member stable",
					EstimatedTime:  "15 minutes",
					RequiresChange: true,
					SuccessRate:    0.85,
				},
			},
			KnowledgeBaseRef: "KB-ARUBA-BOND-003",
		})
	}

	return issues
}

// detectSaaSOptimizationIssues detects SaaS optimization path selection problems
func (aid *ArubaIssueDetector) detectSaaSOptimizationIssues(stream *models.StreamData) []DetectedIssue {
	issues := []DetectedIssue{}

	if len(stream.Segments) < ArubaMinSegmentsForAnalysis {
		return issues
	}

	// SaaS optimization applies to HTTPS flows to known SaaS providers
	if stream.DstPort != 443 && stream.DstPort != 8443 {
		return issues
	}

	// Identify known SaaS flows by SNI or Application field
	saaSPatterns := []string{
		"microsoft", "office365", "outlook", "sharepoint", "teams", "onedrive",
		"salesforce", "force.com", "servicenow", "workday", "successfactors",
		"zoom", "webex", "google", "googleapis", "amazonaws", "azure",
		"dropbox", "box.com", "okta", "concur",
	}

	isSaaSFlow := false
	matchedSaaS := ""
	serverNameLower := strings.ToLower(stream.ServerName)
	appLower := strings.ToLower(stream.Application)
	for _, pattern := range saaSPatterns {
		if strings.Contains(serverNameLower, pattern) || strings.Contains(appLower, pattern) {
			isSaaSFlow = true
			matchedSaaS = pattern
			break
		}
	}

	if !isSaaSFlow {
		return issues
	}

	// --- Compute average inter-packet gap as latency proxy ---
	var totalGap float64
	var gapCount int
	for i := 1; i < len(stream.Segments); i++ {
		gap := stream.Segments[i].GapFromPrev
		if gap > 0 && gap < 5.0 { // exclude idle gaps
			totalGap += gap
			gapCount++
		}
	}
	avgGapMs := 0.0
	if gapCount > 0 {
		avgGapMs = (totalGap / float64(gapCount)) * 1000.0
	}

	// --- Detection 1: SaaS traffic backhauled via datacenter (high latency) ---
	// Direct internet breakout to SaaS should have <50ms RTT for most regions.
	// If avg gap > 200ms, traffic is likely being backhauled via MPLS to datacenter.
	if avgGapMs > ArubaSaaSBackhaulGapSec*1000 {
		issues = append(issues, DetectedIssue{
			ID:              "ARUBA-SAAS-001",
			Title:           "SaaS Traffic Backhauled — Not Using Local Internet Breakout",
			TechnicalDesc:   fmt.Sprintf("SaaS flow to %s (matched: %s) showing %.0fms average latency — consistent with traffic being backhauled via datacenter instead of local internet breakout", stream.ServerName, matchedSaaS, avgGapMs),
			BusinessImpact:  "SaaS application performance severely degraded; users experiencing slow page loads, video buffering, and collaboration tool latency",
			Severity:        SeverityCritical,
			Confidence:      0.85,
			Category:        CategorySDWANData,
			RootCause:       "Business Intent Overlay (BIO) not configured for SaaS breakout, or First Packet iQ misclassified traffic preventing BIO enforcement",
			AffectedService: "Aruba EdgeConnect SaaS Optimization",
			BaseFilter:      buildStreamFilter(stream),
			ExpandedFilter:  buildExpandedFilter(stream) + " && ssl.handshake.extensions_server_name",
			OptimizedFilter: buildOptimizedFilter(stream),
			InvestigationSteps: []InvestigationStep{
				{
					Order:          1,
					Purpose:        "Confirm SaaS traffic path via traceroute",
					DisplayFilter:  buildStreamFilter(stream),
					ExpectedNormal: "Direct path to SaaS CDN/datacenter with < 50ms RTT",
					AbnormalSign:   fmt.Sprintf("%.0fms RTT — traffic routed via corporate datacenter", avgGapMs),
					CustomColumns:  []string{"ip.dst", "ssl.handshake.extensions_server_name", "frame.time_delta"},
				},
				{
					Order:          2,
					Purpose:        "Verify Business Intent Overlay assignment",
					DisplayFilter:  buildStreamFilter(stream),
					ExpectedNormal: "Traffic matched to SaaS BIO with direct internet breakout",
					AbnormalSign:   "Traffic using datacenter overlay instead of internet overlay",
				},
				{
					Order:          3,
					Purpose:        "Check route map for SaaS destination",
					DisplayFilter:  fmt.Sprintf("ip.addr == %s", stream.DstIP),
					ExpectedNormal: "Route via local internet interface",
					AbnormalSign:   "Route via MPLS/private WAN to datacenter",
				},
			},
			ImmediateActions: []RemediationAction{
				{
					Description:    "Check current routing and BIO for SaaS traffic",
					Commands:       []string{"show route-map", "show opt-map", "show biz-pol", "show flows | grep " + stream.DstIP},
					Verification:   "SaaS traffic assigned to internet breakout BIO",
					EstimatedTime:  "3 minutes",
					RequiresChange: false,
					SuccessRate:    0.85,
				},
			},
			ShortTermFixes: []RemediationAction{
				{
					Description:    "Create Business Intent Overlay for SaaS direct breakout",
					Commands:       []string{"Orchestrator: Configuration > Business Intent Overlays > Add SaaS Overlay", "Match: Application = " + matchedSaaS, "Path: Internet (local breakout)", "Activate configuration"},
					Verification:   "SaaS latency drops to < 50ms after BIO applied",
					EstimatedTime:  "20 minutes",
					RequiresChange: true,
					SuccessRate:    0.90,
					RollbackSteps:  []string{"Remove SaaS BIO if it causes unexpected routing changes"},
				},
				{
					Description:    "Verify First Packet iQ correctly classifies SaaS application",
					Commands:       []string{"show stats first-packet", "Orchestrator: Configuration > Applications > Verify " + matchedSaaS + " signature present"},
					Verification:   "Application classified on first packet, BIO enforced immediately",
					EstimatedTime:  "10 minutes",
					RequiresChange: false,
					SuccessRate:    0.85,
				},
			},
			LongTermSolutions: []RemediationAction{
				{
					Description:     "Enable SaaS optimization with automatic path testing",
					Verification:    "EdgeConnect automatically selects lowest-latency path to SaaS",
					EstimatedTime:   "1 week",
					RequiresChange:  true,
					SuccessRate:     0.95,
					EscalationPoint: "Engage Aruba support if SaaS optimization not reducing latency after BIO configuration",
				},
			},
			KnowledgeBaseRef: "KB-ARUBA-SAAS-001",
		})
	} else if avgGapMs > ArubaSaaSBackhaulGapSec*500 { // >100ms = suboptimal but not backhauled
		// --- Detection 2: Suboptimal path (not backhauled, but not optimal) ---
		issues = append(issues, DetectedIssue{
			ID:              "ARUBA-SAAS-002",
			Title:           "SaaS Path Suboptimal — Higher Than Expected Latency",
			TechnicalDesc:   fmt.Sprintf("SaaS flow to %s (matched: %s) showing %.0fms average latency — above optimal threshold (50ms) but below backhauling threshold", stream.ServerName, matchedSaaS, avgGapMs),
			BusinessImpact:  "SaaS application performance degraded; users may notice slower response times compared to optimal configuration",
			Severity:        SeverityHigh,
			Confidence:      0.75,
			Category:        CategorySDWANData,
			RootCause:       "SaaS traffic using internet breakout but not via optimal egress point, or SaaS optimization path testing not selecting best path",
			AffectedService: "Aruba EdgeConnect SaaS Optimization",
			BaseFilter:      buildStreamFilter(stream),
			ExpandedFilter:  buildExpandedFilter(stream),
			OptimizedFilter: buildOptimizedFilter(stream),
			InvestigationSteps: []InvestigationStep{
				{
					Order:          1,
					Purpose:        "Compare latency via different egress paths",
					DisplayFilter:  buildStreamFilter(stream),
					ExpectedNormal: "< 50ms RTT to SaaS endpoint",
					AbnormalSign:   fmt.Sprintf("%.0fms RTT — suboptimal egress path selected", avgGapMs),
					CustomColumns:  []string{"frame.time_delta", "ip.dst", "ssl.handshake.extensions_server_name"},
				},
			},
			ImmediateActions: []RemediationAction{
				{
					Description:    "Check SaaS optimization path selection",
					Commands:       []string{"show opt-map", "show biz-pol", "show route-map"},
					Verification:   "SaaS traffic using lowest-latency available egress",
					EstimatedTime:  "3 minutes",
					RequiresChange: false,
					SuccessRate:    0.80,
				},
			},
			ShortTermFixes: []RemediationAction{
				{
					Description:    "Enable SaaS path probing to automatically select best egress",
					Commands:       []string{"Orchestrator: Configuration > Business Intent Overlays > [SaaS BIO] > Enable Path Probing", "Set probe interval: 30 seconds"},
					Verification:   "EdgeConnect selects lower-latency path within 2 probe intervals",
					EstimatedTime:  "15 minutes",
					RequiresChange: true,
					SuccessRate:    0.85,
				},
			},
			KnowledgeBaseRef: "KB-ARUBA-SAAS-002",
		})
	}

	// --- Detection 3: SaaS flow with high retransmit rate (BIO not protecting path) ---
	retransmitCount := 0
	for _, seg := range stream.Segments {
		if seg.IsRetransmit {
			retransmitCount++
		}
	}
	retransmitRate := float64(retransmitCount) / float64(len(stream.Segments))

	if retransmitRate > 0.05 && stream.Duration > 5.0 {
		issues = append(issues, DetectedIssue{
			ID:              "ARUBA-SAAS-003",
			Title:           "SaaS Path Quality Degraded — High Retransmit Rate",
			TechnicalDesc:   fmt.Sprintf("SaaS flow to %s (matched: %s) showing %.1f%% retransmit rate — internet path to SaaS is lossy, SaaS optimization not protecting quality", stream.ServerName, matchedSaaS, retransmitRate*100),
			BusinessImpact:  "SaaS application experiencing packet loss; file uploads/downloads slow, video calls dropping",
			Severity:        SeverityHigh,
			Confidence:      0.80,
			Category:        CategorySDWANData,
			RootCause:       "Internet path to SaaS experiencing packet loss; no alternate path configured in BIO, or FEC not enabled for SaaS overlay",
			AffectedService: "Aruba EdgeConnect SaaS Optimization",
			BaseFilter:      buildStreamFilter(stream),
			ExpandedFilter:  buildExpandedFilter(stream) + " && tcp.analysis.retransmission",
			OptimizedFilter: buildOptimizedFilter(stream),
			ImmediateActions: []RemediationAction{
				{
					Description:    "Check internet link quality and SaaS path health",
					Commands:       []string{"show tunnel status", "show opt-map", "Orchestrator: Appliance > Tunnels — check internet overlay health"},
					Verification:   "Internet overlay showing < 1% loss to SaaS",
					EstimatedTime:  "3 minutes",
					RequiresChange: false,
					SuccessRate:    0.80,
				},
			},
			ShortTermFixes: []RemediationAction{
				{
					Description:    "Add backup internet path or enable FEC on SaaS BIO",
					Commands:       []string{"Orchestrator: Configuration > Business Intent Overlays > [SaaS BIO] > Add secondary internet path", "Or: Enable FEC on SaaS overlay"},
					Verification:   "SaaS retransmit rate drops below 1%",
					EstimatedTime:  "20 minutes",
					RequiresChange: true,
					SuccessRate:    0.85,
				},
			},
			KnowledgeBaseRef: "KB-ARUBA-SAAS-003",
		})
	}

	return issues
}
