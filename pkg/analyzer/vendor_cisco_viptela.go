package analyzer

import (
	"fmt"
	"strings"

	"github.com/gocisse/sdwan-triage/pkg/models"
)

// Viptela AAR detection thresholds
const (
	ViptelaAARLossThreshold   = 0.05  // >5% loss on primary path = SLA violation
	ViptelaAARLatencyThreshMs = 150.0 // >150ms RTT = latency SLA violation
	ViptelaAARJitterThreshMs  = 30.0  // >30ms jitter = jitter SLA violation
	ViptelaAARMinSegments     = 5     // minimum segments to evaluate AAR
	ViptelaAARBFDGapSec       = 1.0   // gap > 1s on BFD port = BFD down indicator
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
	issues := []DetectedIssue{}

	if len(stream.Segments) < ViptelaAARMinSegments {
		return issues
	}

	// AAR operates on data-plane traffic (not just control ports).
	// We detect SLA violations by analyzing the stream's health metrics,
	// and path selection failures by correlating BFD state with traffic patterns.

	// --- Detection 1: SLA Violation — high loss on primary path, no switchover ---
	// Measure loss rate via retransmit ratio
	retransmitCount := 0
	oooCount := 0
	for _, seg := range stream.Segments {
		if seg.IsRetransmit {
			retransmitCount++
		}
		if seg.IsOutOfOrder {
			oooCount++
		}
	}
	lossRate := float64(retransmitCount) / float64(len(stream.Segments))

	// Measure latency via inter-segment gaps (proxy for RTT on data flows)
	var totalGap float64
	var gapCount int
	var maxGap float64
	for i := 1; i < len(stream.Segments); i++ {
		gap := stream.Segments[i].GapFromPrev
		if gap > 0 && gap < 10.0 { // exclude gaps > 10s (idle periods)
			totalGap += gap
			gapCount++
			if gap > maxGap {
				maxGap = gap
			}
		}
	}
	avgGapMs := 0.0
	if gapCount > 0 {
		avgGapMs = (totalGap / float64(gapCount)) * 1000.0
	}

	// SLA violation: loss > 5% AND stream duration > 10s (long enough to have triggered AAR)
	if lossRate > ViptelaAARLossThreshold && stream.Duration > 10.0 {
		severity := SeverityHigh
		if lossRate > 0.10 {
			severity = SeverityCritical
		}
		issues = append(issues, DetectedIssue{
			ID:              "VIPTELA-AAR-001",
			Title:           "AAR SLA Violation — High Loss, No Path Switchover",
			TechnicalDesc:   fmt.Sprintf("%.1f%% packet loss on flow %s:%d→%s:%d over %.1fs — AAR SLA threshold (5%%) exceeded but traffic remains on degraded path", lossRate*100, stream.SrcIP, stream.SrcPort, stream.DstIP, stream.DstPort, stream.Duration),
			BusinessImpact:  "Business-critical application traffic experiencing packet loss; AAR policy not steering to backup path as configured",
			Severity:        severity,
			Confidence:      0.85,
			Category:        CategorySDWANData,
			RootCause:       "AAR SLA class not applied to this flow, no backup path available, or BFD not detecting path degradation fast enough",
			AffectedService: "Cisco Viptela Application-Aware Routing",
			BaseFilter:      buildStreamFilter(stream),
			ExpandedFilter:  buildExpandedFilter(stream) + " && tcp.analysis.retransmission",
			OptimizedFilter: buildOptimizedFilter(stream),
			InvestigationSteps: []InvestigationStep{
				{
					Order:          1,
					Purpose:        "Confirm packet loss on primary path",
					DisplayFilter:  buildStreamFilter(stream) + " && tcp.analysis.retransmission",
					ExpectedNormal: "< 1% retransmission rate",
					AbnormalSign:   fmt.Sprintf("> 5%% retransmission — currently %.1f%%", lossRate*100),
					CustomColumns:  []string{"tcp.analysis.retransmission", "frame.time_delta", "ip.dsfield.dscp"},
				},
				{
					Order:          2,
					Purpose:        "Verify AAR SLA class assignment for this flow",
					DisplayFilter:  fmt.Sprintf("ip.addr == %s && ip.addr == %s", stream.SrcIP, stream.DstIP),
					ExpectedNormal: "Traffic classified into correct SLA class with backup path",
					AbnormalSign:   "Traffic in default (best-effort) class or no backup path defined",
				},
				{
					Order:          3,
					Purpose:        "Check BFD state on primary path",
					DisplayFilter:  "udp.port == 3784",
					ExpectedNormal: "BFD sessions up with regular echo intervals",
					AbnormalSign:   "BFD session down or missing — path degradation not detected",
				},
			},
			ImmediateActions: []RemediationAction{
				{
					Description:    "Check AAR SLA class status and path selection",
					Commands:       []string{"show sdwan app-route sla-class", "show sdwan app-route stats", "show sdwan policy from-vsmart"},
					Verification:   "SLA class applied to affected application, backup path available",
					EstimatedTime:  "3 minutes",
					RequiresChange: false,
					SuccessRate:    0.85,
				},
				{
					Description:    "Verify BFD sessions on all transport colors",
					Commands:       []string{"show sdwan bfd sessions", "show sdwan bfd history"},
					Verification:   "BFD sessions up on all configured transports",
					EstimatedTime:  "2 minutes",
					RequiresChange: false,
					SuccessRate:    0.80,
				},
			},
			ShortTermFixes: []RemediationAction{
				{
					Description:    "Tighten BFD timers to detect path degradation faster",
					Commands:       []string{"bfd color <color> hello-interval 300 multiplier 3", "commit"},
					Verification:   "BFD detects path degradation within 1 second",
					EstimatedTime:  "10 minutes",
					RequiresChange: true,
					SuccessRate:    0.80,
					RollbackSteps:  []string{"bfd color <color> hello-interval 1000 multiplier 6", "commit"},
				},
				{
					Description:    "Verify AAR policy applied from vSmart",
					Commands:       []string{"show sdwan policy from-vsmart", "show sdwan omp routes | include " + stream.DstIP},
					Verification:   "AAR policy active and backup TLOC available",
					EstimatedTime:  "5 minutes",
					RequiresChange: false,
					SuccessRate:    0.85,
				},
			},
			LongTermSolutions: []RemediationAction{
				{
					Description:     "Add redundant transport color for AAR failover",
					Verification:    "AAR switches to backup path within BFD detection time",
					EstimatedTime:   "1-2 weeks",
					RequiresChange:  true,
					SuccessRate:     0.95,
					EscalationPoint: "Engage Cisco TAC if AAR not switching despite BFD detecting path failure",
				},
			},
			KnowledgeBaseRef: "KB-VIPTELA-AAR-001",
		})
	}

	// --- Detection 2: AAR latency SLA violation ---
	if avgGapMs > ViptelaAARLatencyThreshMs && stream.Duration > 5.0 {
		issues = append(issues, DetectedIssue{
			ID:              "VIPTELA-AAR-002",
			Title:           "AAR Latency SLA Violation — Traffic on High-Latency Path",
			TechnicalDesc:   fmt.Sprintf("Average inter-packet gap %.1fms exceeds AAR latency threshold (%.0fms) for flow %s:%d→%s:%d — traffic not moved to lower-latency path", avgGapMs, ViptelaAARLatencyThreshMs, stream.SrcIP, stream.SrcPort, stream.DstIP, stream.DstPort),
			BusinessImpact:  "Latency-sensitive applications (voice, video, interactive) experiencing degraded performance; AAR not enforcing latency SLA",
			Severity:        SeverityHigh,
			Confidence:      0.75,
			Category:        CategorySDWANData,
			RootCause:       "No lower-latency path available, AAR latency SLA class not configured for this application, or BFD probe interval too long to detect latency change",
			AffectedService: "Cisco Viptela Application-Aware Routing",
			BaseFilter:      buildStreamFilter(stream),
			ExpandedFilter:  buildExpandedFilter(stream),
			OptimizedFilter: buildOptimizedFilter(stream),
			InvestigationSteps: []InvestigationStep{
				{
					Order:          1,
					Purpose:        "Compare latency across available transport colors",
					DisplayFilter:  "udp.port == 3784",
					ExpectedNormal: "BFD probes showing < 150ms RTT on at least one path",
					AbnormalSign:   "All paths showing > 150ms RTT",
					CustomColumns:  []string{"frame.time_delta", "ip.src", "ip.dst"},
				},
				{
					Order:          2,
					Purpose:        "Verify AAR SLA class latency threshold",
					DisplayFilter:  buildStreamFilter(stream),
					ExpectedNormal: "Traffic in SLA class with latency threshold configured",
					AbnormalSign:   "Traffic in default class with no latency SLA",
				},
			},
			ImmediateActions: []RemediationAction{
				{
					Description:    "Check per-path latency metrics",
					Commands:       []string{"show sdwan app-route stats", "show sdwan bfd sessions | include latency"},
					Verification:   "Identify lowest-latency available path",
					EstimatedTime:  "3 minutes",
					RequiresChange: false,
					SuccessRate:    0.80,
				},
			},
			ShortTermFixes: []RemediationAction{
				{
					Description:    "Update AAR SLA class to include latency threshold and assign to application",
					Commands:       []string{"vManage: Configuration > Policies > Application-Aware Routing > SLA Class > Add latency threshold", "Assign SLA class to affected application in data policy"},
					Verification:   "Traffic moves to lower-latency path",
					EstimatedTime:  "20 minutes",
					RequiresChange: true,
					SuccessRate:    0.85,
					RollbackSteps:  []string{"Revert policy to previous version from vManage"},
				},
			},
			KnowledgeBaseRef: "KB-VIPTELA-AAR-002",
		})
	}

	// --- Detection 3: BFD down but traffic still sent to path ---
	// Detect via large gaps on BFD port (BFD echo missing = path down)
	if stream.DstPort == ViptelaBFDPort || stream.SrcPort == ViptelaBFDPort {
		bfdGapCount := 0
		for i := 1; i < len(stream.Segments); i++ {
			if stream.Segments[i].GapFromPrev > ViptelaAARBFDGapSec {
				bfdGapCount++
			}
		}
		if bfdGapCount >= 3 {
			issues = append(issues, DetectedIssue{
				ID:              "VIPTELA-AAR-003",
				Title:           "BFD Path Failure — AAR May Not Reroute",
				TechnicalDesc:   fmt.Sprintf("BFD session showing %d gaps > %.0fs — path declared down, but AAR may not have rerouted if no backup path configured", bfdGapCount, ViptelaAARBFDGapSec),
				BusinessImpact:  "Traffic may be blackholed if AAR has no backup path; BFD failure triggers tunnel teardown",
				Severity:        SeverityCritical,
				Confidence:      0.90,
				Category:        CategorySDWANData,
				RootCause:       "WAN link quality degraded below BFD threshold; AAR needs backup TLOC to reroute",
				AffectedService: "Cisco Viptela BFD / AAR",
				BaseFilter:      buildStreamFilter(stream),
				ExpandedFilter:  buildExpandedFilter(stream),
				OptimizedFilter: buildOptimizedFilter(stream),
				InvestigationSteps: []InvestigationStep{
					{
						Order:          1,
						Purpose:        "Confirm BFD session state",
						DisplayFilter:  "udp.port == 3784",
						ExpectedNormal: "Regular BFD echo packets every 300ms",
						AbnormalSign:   fmt.Sprintf("Gaps > 1s in BFD echo — %d detected", bfdGapCount),
						CustomColumns:  []string{"frame.time_delta", "ip.src", "ip.dst"},
					},
				},
				ImmediateActions: []RemediationAction{
					{
						Description:    "Check BFD session history and AAR path selection",
						Commands:       []string{"show sdwan bfd sessions", "show sdwan bfd history", "show sdwan app-route stats"},
						Verification:   "BFD session re-established or traffic rerouted to backup path",
						EstimatedTime:  "2 minutes",
						RequiresChange: false,
						SuccessRate:    0.85,
					},
				},
				ShortTermFixes: []RemediationAction{
					{
						Description:    "Ensure backup TLOC configured for AAR failover",
						Commands:       []string{"show sdwan omp tlocs", "vManage: Configuration > Policies > AAR > Verify backup TLOC assigned"},
						Verification:   "Backup TLOC available and AAR policy references it",
						EstimatedTime:  "15 minutes",
						RequiresChange: true,
						SuccessRate:    0.85,
					},
				},
				KnowledgeBaseRef: "KB-VIPTELA-AAR-003",
			})
		}
	}

	// --- Detection 4: AAR policy mismatch — DSCP not matching expected SLA class ---
	// Real-time traffic (RTP/SIP) should have DSCP EF; if AnomalyReason mentions DSCP, flag it
	dscpAnomalyCount := 0
	for _, seg := range stream.Segments {
		if strings.Contains(seg.AnomalyReason, "dscp") || strings.Contains(seg.AnomalyReason, "DSCP") {
			dscpAnomalyCount++
		}
	}
	isRealTimePort := (stream.DstPort >= 16384 && stream.DstPort <= 32767) ||
		(stream.SrcPort >= 16384 && stream.SrcPort <= 32767) ||
		stream.DstPort == 5060 || stream.SrcPort == 5060

	if dscpAnomalyCount > 0 && isRealTimePort {
		issues = append(issues, DetectedIssue{
			ID:              "VIPTELA-AAR-004",
			Title:           "AAR Policy Mismatch — DSCP Not Matching SLA Class",
			TechnicalDesc:   fmt.Sprintf("Real-time traffic (port %d/%d) has %d DSCP marking anomalies — traffic may be matched to wrong AAR SLA class", stream.SrcPort, stream.DstPort, dscpAnomalyCount),
			BusinessImpact:  "Voice/video traffic not receiving correct path selection; may be routed via high-latency path instead of real-time optimized path",
			Severity:        SeverityHigh,
			Confidence:      0.75,
			Category:        CategoryVoIPIssues,
			RootCause:       "AAR policy matching on DSCP value that has been remarked by upstream device, or application not setting correct DSCP",
			AffectedService: "Cisco Viptela Application-Aware Routing",
			BaseFilter:      buildStreamFilter(stream),
			ExpandedFilter:  buildExpandedFilter(stream),
			OptimizedFilter: buildOptimizedFilter(stream),
			ImmediateActions: []RemediationAction{
				{
					Description:    "Verify AAR policy matching criteria",
					Commands:       []string{"show sdwan policy from-vsmart", "show sdwan app-route stats | include " + fmt.Sprintf("%d", stream.DstPort)},
					Verification:   "AAR policy matching on correct criteria (app-id, not just DSCP)",
					EstimatedTime:  "5 minutes",
					RequiresChange: false,
					SuccessRate:    0.80,
				},
			},
			ShortTermFixes: []RemediationAction{
				{
					Description:    "Update AAR policy to match on application ID instead of DSCP",
					Commands:       []string{"vManage: Configuration > Policies > Application-Aware Routing > Match: Application (not DSCP)", "Re-push policy"},
					Verification:   "Real-time traffic correctly classified and routed",
					EstimatedTime:  "20 minutes",
					RequiresChange: true,
					SuccessRate:    0.85,
					RollbackSteps:  []string{"Revert policy to previous version from vManage"},
				},
			},
			KnowledgeBaseRef: "KB-VIPTELA-AAR-004",
		})
	}

	return issues
}
