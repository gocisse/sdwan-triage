package analyzer

import (
	"testing"
	"time"

	"github.com/gocisse/sdwan-triage/pkg/models"
)

// makeViptelaStream builds a minimal StreamData on a Viptela port
func makeViptelaStream(srcPort, dstPort uint16, protocol string) *models.StreamData {
	return &models.StreamData{
		FlowID:    "viptela-test-flow",
		SrcIP:     "10.1.0.1",
		DstIP:     "10.2.0.1",
		SrcPort:   srcPort,
		DstPort:   dstPort,
		Protocol:  protocol,
		FirstSeen: time.Now(),
		LastSeen:  time.Now().Add(15 * time.Second),
		Duration:  15.0,
	}
}

func addViptelaSegments(stream *models.StreamData, count int, direction string, gapSec float64, ooo, retransmit, reset bool) {
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

// ---- detectAARIssues ----

func TestDetectAARIssues_TooFewSegments_NoIssues(t *testing.T) {
	det := NewViptelaIssueDetector()
	stream := makeViptelaStream(12345, 443, "TCP")
	addViptelaSegments(stream, 3, "client_to_server", 0.01, false, false, false)

	issues := det.detectAARIssues(stream)
	if len(issues) != 0 {
		t.Errorf("expected no issues with < %d segments, got %d", ViptelaAARMinSegments, len(issues))
	}
}

func TestDetectAARIssues_SLAViolation_HighLoss(t *testing.T) {
	det := NewViptelaIssueDetector()
	stream := makeViptelaStream(12345, 443, "TCP")
	stream.Duration = 15.0
	// 80% normal + 20% retransmit = 20% loss rate (> 5% threshold)
	addViptelaSegments(stream, 16, "client_to_server", 0.01, false, false, false)
	addViptelaSegments(stream, 4, "client_to_server", 0.01, false, true, false)

	issues := det.detectAARIssues(stream)
	found := false
	for _, iss := range issues {
		if iss.ID == "VIPTELA-AAR-001" {
			found = true
			if iss.Severity != SeverityHigh && iss.Severity != SeverityCritical {
				t.Errorf("expected High or Critical severity for SLA violation, got %s", iss.Severity)
			}
		}
	}
	if !found {
		t.Error("expected VIPTELA-AAR-001 SLA violation issue for high loss stream")
	}
}

func TestDetectAARIssues_SLAViolation_CriticalLoss(t *testing.T) {
	det := NewViptelaIssueDetector()
	stream := makeViptelaStream(12345, 443, "TCP")
	stream.Duration = 15.0
	// >10% loss = critical
	addViptelaSegments(stream, 15, "client_to_server", 0.01, false, false, false)
	addViptelaSegments(stream, 5, "client_to_server", 0.01, false, true, false) // 25% retransmit

	issues := det.detectAARIssues(stream)
	found := false
	for _, iss := range issues {
		if iss.ID == "VIPTELA-AAR-001" && iss.Severity == SeverityCritical {
			found = true
		}
	}
	if !found {
		t.Error("expected VIPTELA-AAR-001 with Critical severity for >10% loss")
	}
}

func TestDetectAARIssues_LatencyViolation(t *testing.T) {
	det := NewViptelaIssueDetector()
	stream := makeViptelaStream(12345, 443, "TCP")
	stream.Duration = 10.0
	// All segments with >150ms gap = high latency
	for i := 0; i < 10; i++ {
		stream.Segments = append(stream.Segments, models.StreamSegment{
			Direction:   "client_to_server",
			Length:      512,
			GapFromPrev: 0.20, // 200ms > 150ms threshold
		})
	}
	stream.PacketCount = uint64(len(stream.Segments))

	issues := det.detectAARIssues(stream)
	found := false
	for _, iss := range issues {
		if iss.ID == "VIPTELA-AAR-002" {
			found = true
			if iss.Severity != SeverityHigh {
				t.Errorf("expected High severity for latency violation, got %s", iss.Severity)
			}
		}
	}
	if !found {
		t.Error("expected VIPTELA-AAR-002 latency SLA violation issue")
	}
}

func TestDetectAARIssues_BFDPathFailure(t *testing.T) {
	det := NewViptelaIssueDetector()
	stream := makeViptelaStream(12345, ViptelaBFDPort, "UDP")
	stream.Duration = 10.0
	// Normal BFD segments
	addViptelaSegments(stream, 5, "client_to_server", 0.3, false, false, false)
	// 3 segments with >1s gap = BFD down
	for i := 0; i < 3; i++ {
		stream.Segments = append(stream.Segments, models.StreamSegment{
			Direction:   "client_to_server",
			Length:      24,
			GapFromPrev: ViptelaAARBFDGapSec + 0.5,
		})
	}
	stream.PacketCount = uint64(len(stream.Segments))

	issues := det.detectAARIssues(stream)
	found := false
	for _, iss := range issues {
		if iss.ID == "VIPTELA-AAR-003" {
			found = true
			if iss.Severity != SeverityCritical {
				t.Errorf("expected Critical severity for BFD failure, got %s", iss.Severity)
			}
		}
	}
	if !found {
		t.Error("expected VIPTELA-AAR-003 BFD path failure issue")
	}
}

func TestDetectAARIssues_PolicyMismatch_DSCPAnomaly(t *testing.T) {
	det := NewViptelaIssueDetector()
	// RTP port range with DSCP anomaly
	stream := makeViptelaStream(20000, 20001, "UDP")
	stream.Duration = 5.0
	for i := 0; i < 10; i++ {
		reason := ""
		if i%3 == 0 {
			reason = "DSCP marking inconsistent"
		}
		stream.Segments = append(stream.Segments, models.StreamSegment{
			Direction:     "client_to_server",
			Length:        160,
			GapFromPrev:   0.02,
			AnomalyReason: reason,
		})
	}
	stream.PacketCount = uint64(len(stream.Segments))

	issues := det.detectAARIssues(stream)
	found := false
	for _, iss := range issues {
		if iss.ID == "VIPTELA-AAR-004" {
			found = true
		}
	}
	if !found {
		t.Error("expected VIPTELA-AAR-004 AAR policy mismatch for DSCP anomaly on RTP flow")
	}
}

func TestDetectAARIssues_HealthyStream_NoIssues(t *testing.T) {
	det := NewViptelaIssueDetector()
	stream := makeViptelaStream(12345, 443, "TCP")
	stream.Duration = 5.0
	addViptelaSegments(stream, 20, "client_to_server", 0.01, false, false, false)
	addViptelaSegments(stream, 20, "server_to_client", 0.01, false, false, false)

	issues := det.detectAARIssues(stream)
	for _, iss := range issues {
		if iss.ID == "VIPTELA-AAR-001" || iss.ID == "VIPTELA-AAR-002" {
			t.Errorf("unexpected AAR issue on healthy stream: %s", iss.ID)
		}
	}
}

// ---- DetectViptelaIssues (integration) ----

func TestDetectViptelaIssues_NonViptelaPort_Empty(t *testing.T) {
	det := NewViptelaIssueDetector()
	stream := makeViptelaStream(12345, 80, "TCP")
	addViptelaSegments(stream, 20, "client_to_server", 0.01, false, false, false)

	issues := det.DetectViptelaIssues(stream)
	if len(issues) != 0 {
		t.Errorf("expected no issues for non-Viptela port, got %d", len(issues))
	}
}

func TestDetectViptelaIssues_OMPPort_ReturnsIssues(t *testing.T) {
	det := NewViptelaIssueDetector()
	// OMP flap: short duration with many packets
	stream := makeViptelaStream(12345, ViptelaOMPPort, "UDP")
	stream.Duration = 3.0
	addViptelaSegments(stream, 25, "client_to_server", 0.01, false, false, false)

	issues := det.DetectViptelaIssues(stream)
	found := false
	for _, iss := range issues {
		if iss.ID == "VIPTELA-OMP-001" {
			found = true
		}
	}
	if !found {
		t.Error("expected VIPTELA-OMP-001 OMP flap issue")
	}
}
