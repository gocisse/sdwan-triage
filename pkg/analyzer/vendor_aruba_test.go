package analyzer

import (
	"testing"
	"time"

	"github.com/gocisse/sdwan-triage/pkg/models"
)

// makeArubaStream builds a minimal StreamData on an Aruba EdgeConnect port
func makeArubaStream(srcPort, dstPort uint16, protocol string) *models.StreamData {
	return &models.StreamData{
		FlowID:    "aruba-test-flow",
		SrcIP:     "10.10.0.1",
		DstIP:     "10.20.0.1",
		SrcPort:   srcPort,
		DstPort:   dstPort,
		Protocol:  protocol,
		FirstSeen: time.Now(),
		LastSeen:  time.Now().Add(10 * time.Second),
		Duration:  10.0,
	}
}

func addArubaSegments(stream *models.StreamData, count int, direction string, gapSec float64, ooo, retransmit, reset bool) {
	for i := 0; i < count; i++ {
		stream.Segments = append(stream.Segments, models.StreamSegment{
			Direction:    direction,
			Timestamp:    time.Now(),
			Length:       512,
			GapFromPrev:  gapSec,
			IsOutOfOrder: ooo,
			IsRetransmit: retransmit,
			HasReset:     reset,
		})
	}
	stream.PacketCount = uint64(len(stream.Segments))
}

// ---- detectFirstPacketIQIssues ----

func TestDetectFirstPacketIQIssues_TooFewSegments_NoIssues(t *testing.T) {
	det := NewArubaIssueDetector()
	stream := makeArubaStream(12345, ArubaEdgeConnectPort, "UDP")
	addArubaSegments(stream, 3, "client_to_server", 0.01, false, false, false)

	issues := det.detectFirstPacketIQIssues(stream)
	if len(issues) != 0 {
		t.Errorf("expected no issues with < %d segments, got %d", ArubaMinSegmentsForAnalysis, len(issues))
	}
}

func TestDetectFirstPacketIQIssues_KnownSaaS_Unclassified(t *testing.T) {
	det := NewArubaIssueDetector()
	stream := makeArubaStream(12345, 443, "TCP")
	stream.ServerName = "teams.microsoft.com"
	stream.Application = "unknown" // misclassified
	addArubaSegments(stream, 10, "client_to_server", 0.01, false, false, false)

	issues := det.detectFirstPacketIQIssues(stream)
	found := false
	for _, iss := range issues {
		if iss.ID == "ARUBA-FPIQ-001" {
			found = true
			if iss.Severity != SeverityHigh {
				t.Errorf("expected High severity for SaaS misclassification, got %s", iss.Severity)
			}
		}
	}
	if !found {
		t.Error("expected ARUBA-FPIQ-001 misclassification issue for known SaaS with unknown classification")
	}
}

func TestDetectFirstPacketIQIssues_KnownSaaS_Classified_NoIssue(t *testing.T) {
	det := NewArubaIssueDetector()
	stream := makeArubaStream(12345, 443, "TCP")
	stream.ServerName = "outlook.office365.com"
	stream.Application = "Microsoft Office 365" // correctly classified
	addArubaSegments(stream, 10, "client_to_server", 0.01, false, false, false)

	issues := det.detectFirstPacketIQIssues(stream)
	for _, iss := range issues {
		if iss.ID == "ARUBA-FPIQ-001" {
			t.Error("unexpected ARUBA-FPIQ-001 for correctly classified SaaS flow")
		}
	}
}

func TestDetectFirstPacketIQIssues_CacheMiss_EarlyGaps(t *testing.T) {
	det := NewArubaIssueDetector()
	stream := makeArubaStream(12345, 443, "TCP")
	stream.ServerName = "internal.corp.example.com" // not a SaaS pattern
	stream.Application = ""
	// First 5 segments with >50ms gaps = cache miss delay
	for i := 0; i < 5; i++ {
		stream.Segments = append(stream.Segments, models.StreamSegment{
			Direction:   "client_to_server",
			Length:      512,
			GapFromPrev: 0.08, // 80ms > 50ms threshold
		})
	}
	addArubaSegments(stream, 10, "client_to_server", 0.01, false, false, false)
	stream.PacketCount = uint64(len(stream.Segments))

	issues := det.detectFirstPacketIQIssues(stream)
	found := false
	for _, iss := range issues {
		if iss.ID == "ARUBA-FPIQ-002" {
			found = true
		}
	}
	if !found {
		t.Error("expected ARUBA-FPIQ-002 cache miss issue for early high-gap segments on non-SaaS flow")
	}
}

func TestDetectFirstPacketIQIssues_SalesforceUnclassified(t *testing.T) {
	det := NewArubaIssueDetector()
	stream := makeArubaStream(12345, 443, "TCP")
	stream.ServerName = "mycompany.salesforce.com"
	stream.Application = "TCP" // generic classification
	addArubaSegments(stream, 10, "client_to_server", 0.01, false, false, false)

	issues := det.detectFirstPacketIQIssues(stream)
	found := false
	for _, iss := range issues {
		if iss.ID == "ARUBA-FPIQ-001" {
			found = true
		}
	}
	if !found {
		t.Error("expected ARUBA-FPIQ-001 for Salesforce flow classified as generic TCP")
	}
}

// ---- detectTunnelBondingIssues ----

func TestDetectTunnelBondingIssues_TooFewSegments_NoIssues(t *testing.T) {
	det := NewArubaIssueDetector()
	stream := makeArubaStream(12345, ArubaEdgeConnectPort, "UDP")
	addArubaSegments(stream, 3, "client_to_server", 0.01, false, false, false)

	issues := det.detectTunnelBondingIssues(stream)
	if len(issues) != 0 {
		t.Errorf("expected no issues with < %d segments, got %d", ArubaMinSegmentsForAnalysis, len(issues))
	}
}

func TestDetectTunnelBondingIssues_WrongPort_NoIssues(t *testing.T) {
	det := NewArubaIssueDetector()
	stream := makeArubaStream(12345, 443, "TCP")
	addArubaSegments(stream, 20, "client_to_server", 0.01, true, false, false)

	issues := det.detectTunnelBondingIssues(stream)
	if len(issues) != 0 {
		t.Errorf("expected no bonding issues for non-EdgeConnect port, got %d", len(issues))
	}
}

func TestDetectTunnelBondingIssues_HighOOO_POCOverwhelmed(t *testing.T) {
	det := NewArubaIssueDetector()
	stream := makeArubaStream(12345, ArubaEdgeConnectPort, "UDP")
	stream.Duration = 10.0
	// 6 OOO out of 20 total = 30% > 5% threshold
	addArubaSegments(stream, 14, "client_to_server", 0.01, false, false, false)
	addArubaSegments(stream, 6, "client_to_server", 0.01, true, false, false)

	issues := det.detectTunnelBondingIssues(stream)
	found := false
	for _, iss := range issues {
		if iss.ID == "ARUBA-BOND-001" {
			found = true
			if iss.Severity != SeverityCritical {
				t.Errorf("expected Critical severity for >15%% OOO, got %s", iss.Severity)
			}
		}
	}
	if !found {
		t.Error("expected ARUBA-BOND-001 tunnel bonding OOO issue")
	}
}

func TestDetectTunnelBondingIssues_MemberFailure_ThroughputDrop(t *testing.T) {
	det := NewArubaIssueDetector()
	stream := makeArubaStream(12345, ArubaEdgeConnectPort, "UDP")
	stream.Duration = 20.0
	// First half: large segments; second half: tiny (< 45% of first)
	for i := 0; i < 10; i++ {
		stream.Segments = append(stream.Segments, models.StreamSegment{
			Direction: "client_to_server", Length: 1400, GapFromPrev: 0.01,
		})
	}
	for i := 0; i < 10; i++ {
		stream.Segments = append(stream.Segments, models.StreamSegment{
			Direction: "client_to_server", Length: 80, GapFromPrev: 0.01,
		})
	}
	stream.PacketCount = uint64(len(stream.Segments))

	issues := det.detectTunnelBondingIssues(stream)
	found := false
	for _, iss := range issues {
		if iss.ID == "ARUBA-BOND-002" {
			found = true
			if iss.Severity != SeverityCritical {
				t.Errorf("expected Critical severity for member failure, got %s", iss.Severity)
			}
		}
	}
	if !found {
		t.Error("expected ARUBA-BOND-002 bonding member failure issue")
	}
}

func TestDetectTunnelBondingIssues_Flapping_MultipleResets(t *testing.T) {
	det := NewArubaIssueDetector()
	stream := makeArubaStream(12345, ArubaEdgeConnectPort, "UDP")
	stream.Duration = 30.0
	addArubaSegments(stream, 10, "client_to_server", 0.01, false, false, false)
	// 3 resets within 60s window
	for i := 0; i < 3; i++ {
		stream.Segments = append(stream.Segments, models.StreamSegment{
			Direction: "client_to_server", Length: 40, GapFromPrev: 0.5, HasReset: true,
		})
	}
	stream.PacketCount = uint64(len(stream.Segments))

	issues := det.detectTunnelBondingIssues(stream)
	found := false
	for _, iss := range issues {
		if iss.ID == "ARUBA-BOND-003" {
			found = true
		}
	}
	if !found {
		t.Error("expected ARUBA-BOND-003 tunnel bonding flapping issue")
	}
}

// ---- detectSaaSOptimizationIssues ----

func TestDetectSaaSOptimizationIssues_TooFewSegments_NoIssues(t *testing.T) {
	det := NewArubaIssueDetector()
	stream := makeArubaStream(12345, 443, "TCP")
	stream.ServerName = "teams.microsoft.com"
	addArubaSegments(stream, 3, "client_to_server", 0.01, false, false, false)

	issues := det.detectSaaSOptimizationIssues(stream)
	if len(issues) != 0 {
		t.Errorf("expected no issues with < %d segments, got %d", ArubaMinSegmentsForAnalysis, len(issues))
	}
}

func TestDetectSaaSOptimizationIssues_NonHTTPS_NoIssues(t *testing.T) {
	det := NewArubaIssueDetector()
	stream := makeArubaStream(12345, 80, "TCP")
	stream.ServerName = "teams.microsoft.com"
	addArubaSegments(stream, 20, "client_to_server", 0.25, false, false, false)

	issues := det.detectSaaSOptimizationIssues(stream)
	if len(issues) != 0 {
		t.Errorf("expected no issues for non-HTTPS SaaS flow, got %d", len(issues))
	}
}

func TestDetectSaaSOptimizationIssues_NonSaaS_NoIssues(t *testing.T) {
	det := NewArubaIssueDetector()
	stream := makeArubaStream(12345, 443, "TCP")
	stream.ServerName = "internal.corp.local"
	addArubaSegments(stream, 20, "client_to_server", 0.25, false, false, false)

	issues := det.detectSaaSOptimizationIssues(stream)
	if len(issues) != 0 {
		t.Errorf("expected no issues for non-SaaS HTTPS flow, got %d", len(issues))
	}
}

func TestDetectSaaSOptimizationIssues_Backhaul_CriticalLatency(t *testing.T) {
	det := NewArubaIssueDetector()
	stream := makeArubaStream(12345, 443, "TCP")
	stream.ServerName = "zoom.us"
	stream.Duration = 10.0
	// All segments with >200ms gap = backhauled
	for i := 0; i < 20; i++ {
		stream.Segments = append(stream.Segments, models.StreamSegment{
			Direction:   "client_to_server",
			Length:      512,
			GapFromPrev: 0.25, // 250ms > 200ms backhauling threshold
		})
	}
	stream.PacketCount = uint64(len(stream.Segments))

	issues := det.detectSaaSOptimizationIssues(stream)
	found := false
	for _, iss := range issues {
		if iss.ID == "ARUBA-SAAS-001" {
			found = true
			if iss.Severity != SeverityCritical {
				t.Errorf("expected Critical severity for backhauled SaaS, got %s", iss.Severity)
			}
		}
	}
	if !found {
		t.Error("expected ARUBA-SAAS-001 SaaS backhauling issue")
	}
}

func TestDetectSaaSOptimizationIssues_SuboptimalPath(t *testing.T) {
	det := NewArubaIssueDetector()
	stream := makeArubaStream(12345, 443, "TCP")
	stream.ServerName = "mycompany.salesforce.com"
	stream.Duration = 10.0
	// 120ms avg gap = suboptimal (>100ms but <200ms)
	for i := 0; i < 20; i++ {
		stream.Segments = append(stream.Segments, models.StreamSegment{
			Direction:   "client_to_server",
			Length:      512,
			GapFromPrev: 0.12, // 120ms
		})
	}
	stream.PacketCount = uint64(len(stream.Segments))

	issues := det.detectSaaSOptimizationIssues(stream)
	found := false
	for _, iss := range issues {
		if iss.ID == "ARUBA-SAAS-002" {
			found = true
			if iss.Severity != SeverityHigh {
				t.Errorf("expected High severity for suboptimal SaaS path, got %s", iss.Severity)
			}
		}
	}
	if !found {
		t.Error("expected ARUBA-SAAS-002 suboptimal SaaS path issue")
	}
}

func TestDetectSaaSOptimizationIssues_HighRetransmit(t *testing.T) {
	det := NewArubaIssueDetector()
	stream := makeArubaStream(12345, 443, "TCP")
	stream.ServerName = "outlook.office365.com"
	stream.Duration = 10.0
	// 15% retransmit rate on SaaS flow
	addArubaSegments(stream, 17, "client_to_server", 0.02, false, false, false)
	addArubaSegments(stream, 3, "client_to_server", 0.02, false, true, false)

	issues := det.detectSaaSOptimizationIssues(stream)
	found := false
	for _, iss := range issues {
		if iss.ID == "ARUBA-SAAS-003" {
			found = true
			if iss.Severity != SeverityHigh {
				t.Errorf("expected High severity for SaaS path quality degradation, got %s", iss.Severity)
			}
		}
	}
	if !found {
		t.Error("expected ARUBA-SAAS-003 SaaS path quality degradation issue")
	}
}

func TestDetectSaaSOptimizationIssues_HealthySaaS_NoIssues(t *testing.T) {
	det := NewArubaIssueDetector()
	stream := makeArubaStream(12345, 443, "TCP")
	stream.ServerName = "teams.microsoft.com"
	stream.Duration = 5.0
	// Low latency, no retransmits = healthy
	addArubaSegments(stream, 20, "client_to_server", 0.02, false, false, false)
	addArubaSegments(stream, 20, "server_to_client", 0.02, false, false, false)

	issues := det.detectSaaSOptimizationIssues(stream)
	for _, iss := range issues {
		if iss.ID == "ARUBA-SAAS-001" || iss.ID == "ARUBA-SAAS-002" {
			t.Errorf("unexpected SaaS issue on healthy low-latency flow: %s", iss.ID)
		}
	}
}

// ---- DetectArubaIssues (integration) ----

func TestDetectArubaIssues_NonArubaPort_Empty(t *testing.T) {
	det := NewArubaIssueDetector()
	stream := makeArubaStream(12345, 80, "TCP")
	addArubaSegments(stream, 20, "client_to_server", 0.01, false, false, false)

	issues := det.DetectArubaIssues(stream)
	if len(issues) != 0 {
		t.Errorf("expected no issues for non-Aruba port, got %d", len(issues))
	}
}

func TestDetectArubaIssues_EdgeConnectPort_PathConditioningDetected(t *testing.T) {
	det := NewArubaIssueDetector()
	stream := makeArubaStream(12345, ArubaEdgeConnectPort, "UDP")
	stream.Duration = 10.0
	// >5% retransmit on EdgeConnect tunnel = path conditioning ineffective
	addArubaSegments(stream, 18, "client_to_server", 0.01, false, false, false)
	addArubaSegments(stream, 2, "client_to_server", 0.01, false, true, false) // 10% retransmit

	issues := det.DetectArubaIssues(stream)
	found := false
	for _, iss := range issues {
		if iss.ID == "ARUBA-PATH-001" {
			found = true
		}
	}
	if !found {
		t.Error("expected ARUBA-PATH-001 path conditioning issue via DetectArubaIssues")
	}
}
