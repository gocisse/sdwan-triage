package analyzer

import (
	"github.com/gocisse/sdwan-triage/pkg/models"
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
	// First Packet iQ issues require application classification analysis
	return nil
}

// detectTunnelBondingIssues detects tunnel bonding problems
func (aid *ArubaIssueDetector) detectTunnelBondingIssues(stream *models.StreamData) []DetectedIssue {
	// Tunnel bonding issues require multi-tunnel analysis
	return nil
}

// detectSaaSOptimizationIssues detects SaaS optimization path selection problems
func (aid *ArubaIssueDetector) detectSaaSOptimizationIssues(stream *models.StreamData) []DetectedIssue {
	// SaaS optimization issues require traffic steering analysis
	return nil
}
