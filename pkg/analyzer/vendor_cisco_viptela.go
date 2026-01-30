package analyzer

import (
	"github.com/gocisse/sdwan-triage/pkg/models"
)

// Cisco Viptela-specific ports and protocols
const (
	ViptelaOMPPort     uint16 = 12346 // OMP (Overlay Management Protocol)
	ViptelaDTLSPort    uint16 = 12346 // DTLS control plane
	ViptelaNetconfPort uint16 = 830   // NETCONF
	ViptelaBFDPort     uint16 = 3784  // BFD (Bidirectional Forwarding Detection)
	ViptelaSTUNPort    uint16 = 12366 // STUN for NAT traversal
)

// ViptelaIssueDetector detects Cisco Viptela-specific issues
type ViptelaIssueDetector struct {
	classifier   *AdvancedClassifier
	healthScorer *HealthScorer
}

// NewViptelaIssueDetector creates a new Viptela detector
func NewViptelaIssueDetector() *ViptelaIssueDetector {
	return &ViptelaIssueDetector{
		classifier:   NewAdvancedClassifier(),
		healthScorer: NewHealthScorer(),
	}
}

// DetectViptelaIssues analyzes streams for Viptela-specific problems
func (vid *ViptelaIssueDetector) DetectViptelaIssues(stream *models.StreamData) []DetectedIssue {
	issues := []DetectedIssue{}

	// Check if this is Viptela traffic
	if !vid.isViptelaTraffic(stream) {
		return issues
	}

	// OMP route flap detection
	if ompIssues := vid.detectOMPIssues(stream); len(ompIssues) > 0 {
		issues = append(issues, ompIssues...)
	}

	// vSmart policy deployment failures
	if vsmartIssues := vid.detectVSmartIssues(stream); len(vsmartIssues) > 0 {
		issues = append(issues, vsmartIssues...)
	}

	// BFD session issues
	if bfdIssues := vid.detectBFDIssues(stream); len(bfdIssues) > 0 {
		issues = append(issues, bfdIssues...)
	}

	// vBond orchestrator connectivity
	if vbondIssues := vid.detectVBondIssues(stream); len(vbondIssues) > 0 {
		issues = append(issues, vbondIssues...)
	}

	// Application-aware routing policy conflicts
	if aarIssues := vid.detectAARIssues(stream); len(aarIssues) > 0 {
		issues = append(issues, aarIssues...)
	}

	return issues
}

// isViptelaTraffic checks if stream is Viptela-related
func (vid *ViptelaIssueDetector) isViptelaTraffic(stream *models.StreamData) bool {
	viptelaPorts := []uint16{ViptelaOMPPort, ViptelaDTLSPort, ViptelaNetconfPort, ViptelaBFDPort, ViptelaSTUNPort, 12386, 23456}

	for _, port := range viptelaPorts {
		if stream.DstPort == port || stream.SrcPort == port {
			return true
		}
	}

	return false
}

// detectOMPIssues detects OMP (Overlay Management Protocol) problems
func (vid *ViptelaIssueDetector) detectOMPIssues(stream *models.StreamData) []DetectedIssue {
	issues := []DetectedIssue{}

	// Check for OMP port traffic
	if stream.DstPort != ViptelaOMPPort && stream.SrcPort != ViptelaOMPPort {
		return issues
	}

	// OMP route flap detection - rapid connection changes
	if stream.Duration < 5 && stream.PacketCount > 20 {
		issue := DetectedIssue{
			ID:              "VIPTELA-OMP-001",
			Title:           "OMP Route Flap Detected",
			TechnicalDesc:   "Rapid OMP session state changes indicating route instability",
			BusinessImpact:  "Traffic blackholing, suboptimal routing, application performance degradation",
			Severity:        SeverityCritical,
			Confidence:      0.85,
			Category:        CategorySDWANControl,
			RootCause:       "WAN link instability, BFD timeouts, or vSmart connectivity issues",
			AffectedService: "Cisco Viptela OMP",

			BaseFilter:      buildStreamFilter(stream),
			ExpandedFilter:  buildExpandedFilter(stream) + " || (udp.port == 12346)",
			OptimizedFilter: buildOptimizedFilter(stream),

			InvestigationSteps: []InvestigationStep{
				{
					Order:          1,
					Purpose:        "Analyze OMP session state changes",
					DisplayFilter:  buildStreamFilter(stream),
					ExpectedNormal: "Stable OMP session with periodic keepalives",
					AbnormalSign:   "Rapid session teardown/establishment cycles",
					CustomColumns:  []string{"frame.time_delta", "data.len"},
				},
				{
					Order:          2,
					Purpose:        "Check for BFD failures triggering OMP flaps",
					DisplayFilter:  "udp.port == 3784",
					ExpectedNormal: "Regular BFD echo packets",
					AbnormalSign:   "Missing BFD responses or timeouts",
				},
				{
					Order:          3,
					Purpose:        "Examine DTLS handshake issues",
					DisplayFilter:  buildStreamFilter(stream) + " && dtls",
					ExpectedNormal: "Successful DTLS handshake",
					AbnormalSign:   "Repeated handshake attempts or failures",
				},
			},

			ImmediateActions: []RemediationAction{
				{
					Description:    "Check OMP peer status on vEdge",
					Commands:       []string{"show omp peers", "show omp routes", "show omp tlocs"},
					Verification:   "OMP peers in 'up' state with stable routes",
					EstimatedTime:  "2 minutes",
					RequiresChange: false,
					SuccessRate:    0.80,
				},
				{
					Description:    "Verify WAN transport connectivity",
					Commands:       []string{"show interface | include line protocol", "ping <vsmart-ip> vpn 0"},
					Verification:   "WAN interfaces up, vSmart reachable",
					EstimatedTime:  "2 minutes",
					RequiresChange: false,
					SuccessRate:    0.85,
				},
			},

			ShortTermFixes: []RemediationAction{
				{
					Description:    "Adjust BFD timers to reduce sensitivity",
					Commands:       []string{"bfd color <color> hello-interval 1000 multiplier 6", "commit"},
					Verification:   "Reduced OMP flap frequency",
					EstimatedTime:  "10 minutes",
					RequiresChange: true,
					SuccessRate:    0.75,
					RollbackSteps:  []string{"bfd color <color> hello-interval 300 multiplier 3", "commit"},
				},
				{
					Description:    "Clear OMP sessions to force re-establishment",
					Commands:       []string{"clear omp peer <peer-ip>"},
					Verification:   "OMP session re-established and stable",
					EstimatedTime:  "5 minutes",
					RequiresChange: true,
					SuccessRate:    0.70,
				},
			},

			LongTermSolutions: []RemediationAction{
				{
					Description:     "Implement redundant vSmart controllers",
					Verification:    "OMP sessions failover seamlessly",
					EstimatedTime:   "1 week",
					RequiresChange:  true,
					SuccessRate:     0.95,
					EscalationPoint: "Engage Cisco TAC for persistent OMP instability",
				},
			},

			KnowledgeBaseRef: "KB-VIPTELA-OMP-001",
		}
		issues = append(issues, issue)
	}

	// OMP session timeout
	healthScore := vid.healthScorer.ScoreStream(stream)
	if healthScore.Status == HealthStatusCritical && stream.Duration > 30 {
		issue := DetectedIssue{
			ID:              "VIPTELA-OMP-002",
			Title:           "OMP Session Timeout",
			TechnicalDesc:   "OMP session failing to establish or maintain connectivity",
			BusinessImpact:  "Site isolated from SD-WAN fabric, no policy updates, routing failures",
			Severity:        SeverityCritical,
			Confidence:      0.90,
			Category:        CategorySDWANControl,
			RootCause:       "vSmart unreachable, certificate issues, or network path problems",
			AffectedService: "Cisco Viptela OMP",

			BaseFilter:      buildStreamFilter(stream),
			ExpandedFilter:  buildExpandedFilter(stream),
			OptimizedFilter: buildOptimizedFilter(stream),

			ImmediateActions: []RemediationAction{
				{
					Description:    "Verify vSmart reachability from vEdge",
					Commands:       []string{"ping <vsmart-ip> vpn 0", "traceroute <vsmart-ip> vpn 0"},
					Verification:   "vSmart responds to ping",
					EstimatedTime:  "2 minutes",
					RequiresChange: false,
					SuccessRate:    0.85,
				},
				{
					Description:    "Check certificate validity",
					Commands:       []string{"show certificate installed", "show control connections"},
					Verification:   "Certificates valid and not expired",
					EstimatedTime:  "3 minutes",
					RequiresChange: false,
					SuccessRate:    0.80,
				},
			},

			ShortTermFixes: []RemediationAction{
				{
					Description:    "Restart OMP process",
					Commands:       []string{"request software omp restart"},
					Verification:   "OMP session re-established",
					EstimatedTime:  "5 minutes",
					RequiresChange: true,
					SuccessRate:    0.75,
				},
			},

			KnowledgeBaseRef: "KB-VIPTELA-OMP-002",
		}
		issues = append(issues, issue)
	}

	return issues
}

// detectVSmartIssues detects vSmart controller problems
func (vid *ViptelaIssueDetector) detectVSmartIssues(stream *models.StreamData) []DetectedIssue {
	issues := []DetectedIssue{}

	// Check for NETCONF traffic (policy deployment)
	if stream.DstPort != ViptelaNetconfPort && stream.SrcPort != ViptelaNetconfPort {
		return issues
	}

	// Policy deployment failure - long duration with resets
	hasReset := false
	for _, segment := range stream.Segments {
		if segment.HasReset {
			hasReset = true
			break
		}
	}

	if hasReset && stream.Duration > 10 {
		issue := DetectedIssue{
			ID:              "VIPTELA-VSMART-001",
			Title:           "vSmart Policy Deployment Failure",
			TechnicalDesc:   "NETCONF session terminated during policy push to vEdge",
			BusinessImpact:  "Policy changes not applied, security rules outdated, traffic steering incorrect",
			Severity:        SeverityHigh,
			Confidence:      0.80,
			Category:        CategorySDWANControl,
			RootCause:       "Configuration conflict, resource exhaustion, or connectivity loss",
			AffectedService: "Cisco Viptela vSmart",

			BaseFilter:      buildStreamFilter(stream),
			ExpandedFilter:  buildExpandedFilter(stream),
			OptimizedFilter: buildOptimizedFilter(stream),

			InvestigationSteps: []InvestigationStep{
				{
					Order:          1,
					Purpose:        "Examine NETCONF session",
					DisplayFilter:  buildStreamFilter(stream),
					ExpectedNormal: "Complete NETCONF RPC exchange",
					AbnormalSign:   "Session reset before RPC completion",
					CustomColumns:  []string{"tcp.flags", "frame.time_delta"},
				},
			},

			ImmediateActions: []RemediationAction{
				{
					Description:    "Check vSmart policy status",
					Commands:       []string{"show running-config | include policy", "show omp summary"},
					Verification:   "Policy configuration intact",
					EstimatedTime:  "3 minutes",
					RequiresChange: false,
					SuccessRate:    0.75,
				},
			},

			ShortTermFixes: []RemediationAction{
				{
					Description:    "Re-push policy from vManage",
					Commands:       []string{"Navigate to Configuration > Templates > Push to Devices"},
					Verification:   "Policy successfully applied to all devices",
					EstimatedTime:  "15 minutes",
					RequiresChange: true,
					SuccessRate:    0.85,
				},
			},

			KnowledgeBaseRef: "KB-VIPTELA-VSMART-001",
		}
		issues = append(issues, issue)
	}

	return issues
}

// detectBFDIssues detects BFD session problems
func (vid *ViptelaIssueDetector) detectBFDIssues(stream *models.StreamData) []DetectedIssue {
	issues := []DetectedIssue{}

	// Check for BFD traffic
	if stream.DstPort != ViptelaBFDPort && stream.SrcPort != ViptelaBFDPort {
		return issues
	}

	// BFD session flapping - rapid packet exchanges
	if stream.PacketCount > 50 && stream.Duration < 10 {
		issue := DetectedIssue{
			ID:              "VIPTELA-BFD-001",
			Title:           "BFD Session Flapping",
			TechnicalDesc:   "BFD session rapidly transitioning between up and down states",
			BusinessImpact:  "Tunnel instability, traffic rerouting, application disruption",
			Severity:        SeverityHigh,
			Confidence:      0.85,
			Category:        CategorySDWANData,
			RootCause:       "WAN link quality issues, asymmetric routing, or timer misconfiguration",
			AffectedService: "Cisco Viptela BFD",

			BaseFilter:      buildStreamFilter(stream),
			ExpandedFilter:  buildExpandedFilter(stream),
			OptimizedFilter: buildOptimizedFilter(stream),

			ImmediateActions: []RemediationAction{
				{
					Description:    "Check BFD session status",
					Commands:       []string{"show bfd sessions", "show bfd history"},
					Verification:   "BFD sessions stable",
					EstimatedTime:  "2 minutes",
					RequiresChange: false,
					SuccessRate:    0.80,
				},
			},

			ShortTermFixes: []RemediationAction{
				{
					Description:    "Increase BFD timers to reduce sensitivity",
					Commands:       []string{"bfd color <color> hello-interval 1000 multiplier 6"},
					Verification:   "BFD flapping reduced",
					EstimatedTime:  "10 minutes",
					RequiresChange: true,
					SuccessRate:    0.80,
					RollbackSteps:  []string{"bfd color <color> hello-interval 300 multiplier 3"},
				},
			},

			KnowledgeBaseRef: "KB-VIPTELA-BFD-001",
		}
		issues = append(issues, issue)
	}

	return issues
}

// detectVBondIssues detects vBond orchestrator problems
func (vid *ViptelaIssueDetector) detectVBondIssues(stream *models.StreamData) []DetectedIssue {
	issues := []DetectedIssue{}

	// Check for STUN traffic (vBond NAT traversal)
	if stream.DstPort != ViptelaSTUNPort && stream.SrcPort != ViptelaSTUNPort {
		return issues
	}

	healthScore := vid.healthScorer.ScoreStream(stream)
	if healthScore.Status == HealthStatusCritical {
		issue := DetectedIssue{
			ID:              "VIPTELA-VBOND-001",
			Title:           "vBond Orchestrator Unreachable",
			TechnicalDesc:   "STUN/NAT traversal failing to vBond orchestrator",
			BusinessImpact:  "New devices cannot join fabric, ZTP failures, tunnel establishment blocked",
			Severity:        SeverityCritical,
			Confidence:      0.85,
			Category:        CategorySDWANControl,
			RootCause:       "vBond unreachable, firewall blocking, or DNS resolution failure",
			AffectedService: "Cisco Viptela vBond",

			BaseFilter:      buildStreamFilter(stream),
			ExpandedFilter:  buildExpandedFilter(stream),
			OptimizedFilter: buildOptimizedFilter(stream),

			ImmediateActions: []RemediationAction{
				{
					Description:    "Verify vBond reachability",
					Commands:       []string{"ping <vbond-ip> vpn 0", "show control connections | include vbond"},
					Verification:   "vBond responds and control connection established",
					EstimatedTime:  "2 minutes",
					RequiresChange: false,
					SuccessRate:    0.85,
				},
			},

			ShortTermFixes: []RemediationAction{
				{
					Description:    "Check firewall rules for STUN/DTLS ports",
					Commands:       []string{"Verify UDP 12346, 12366, 12386 allowed to vBond"},
					Verification:   "Firewall rules permit vBond traffic",
					EstimatedTime:  "15 minutes",
					RequiresChange: true,
					SuccessRate:    0.80,
				},
			},

			KnowledgeBaseRef: "KB-VIPTELA-VBOND-001",
		}
		issues = append(issues, issue)
	}

	return issues
}

// detectAARIssues detects Application-Aware Routing problems
func (vid *ViptelaIssueDetector) detectAARIssues(stream *models.StreamData) []DetectedIssue {
	// AAR issues are detected through traffic patterns, not specific ports
	// This would require deeper packet inspection
	return nil
}
