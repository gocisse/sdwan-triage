package analyzer

import (
	"testing"
	"time"

	"github.com/gocisse/sdwan-triage/pkg/models"
)

// makeVeloStream builds a minimal StreamData on a VeloCloud port
func makeVeloStream(srcPort, dstPort uint16, protocol string) *models.StreamData {
	return &models.StreamData{
		FlowID:    "test-flow",
		SrcIP:     "10.0.0.1",
		DstIP:     "203.0.113.1",
		SrcPort:   srcPort,
		DstPort:   dstPort,
		Protocol:  protocol,
		FirstSeen: time.Now(),
		LastSeen:  time.Now().Add(10 * time.Second),
		Duration:  10.0,
	}
}

func addSegments(stream *models.StreamData, count int, direction string, gapSec float64, ooo, retransmit, reset bool) {
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

// ---- detectGatewayIssues ----

func TestDetectGatewayIssues_NoIssues_HealthyStream(t *testing.T) {
	det := NewVeloCloudIssueDetector()
	stream := makeVeloStream(12345, VeloCloudVCMPPort, "UDP")
	addSegments(stream, 20, "client_to_server", 0.01, false, false, false)
	addSegments(stream, 20, "server_to_client", 0.01, false, false, false)

	issues := det.detectGatewayIssues(stream)
	for _, iss := range issues {
		if iss.ID == "VELOCLOUD-GW-001" || iss.ID == "VELOCLOUD-GW-003" {
			t.Errorf("unexpected critical gateway issue on healthy stream: %s", iss.ID)
		}
	}
}

func TestDetectGatewayIssues_CriticalDrops(t *testing.T) {
	det := NewVeloCloudIssueDetector()
	stream := makeVeloStream(12345, VeloCloudVCMPPort, "UDP")
	stream.Duration = 30.0
	// Add >1000 high-gap segments to trigger critical threshold
	addSegments(stream, VeloGatewayDropCritical+50, "client_to_server", 0.15, false, false, false)
	addSegments(stream, 10, "server_to_client", 0.01, false, false, false)

	issues := det.detectGatewayIssues(stream)
	found := false
	for _, iss := range issues {
		if iss.ID == "VELOCLOUD-GW-001" {
			found = true
			if iss.Severity != SeverityCritical {
				t.Errorf("expected Critical severity, got %s", iss.Severity)
			}
		}
	}
	if !found {
		t.Error("expected VELOCLOUD-GW-001 critical gateway issue, got none")
	}
}

func TestDetectGatewayIssues_WarningDrops(t *testing.T) {
	det := NewVeloCloudIssueDetector()
	stream := makeVeloStream(12345, VeloCloudVCMPPort, "UDP")
	stream.Duration = 30.0
	addSegments(stream, VeloGatewayDropThreshold+10, "client_to_server", 0.15, false, false, false)
	addSegments(stream, 10, "server_to_client", 0.01, false, false, false)

	issues := det.detectGatewayIssues(stream)
	found := false
	for _, iss := range issues {
		if iss.ID == "VELOCLOUD-GW-002" {
			found = true
			if iss.Severity != SeverityHigh {
				t.Errorf("expected High severity, got %s", iss.Severity)
			}
		}
	}
	if !found {
		t.Error("expected VELOCLOUD-GW-002 warning gateway issue, got none")
	}
}

func TestDetectGatewayIssues_SelectionFailure_NoReturn(t *testing.T) {
	det := NewVeloCloudIssueDetector()
	stream := makeVeloStream(12345, VeloCloudVCMPPort, "UDP")
	stream.Duration = VeloGatewayNoReturnWindowSec + 1.0
	// Only client→server segments, no return
	addSegments(stream, 10, "client_to_server", 0.01, false, false, false)

	issues := det.detectGatewayIssues(stream)
	found := false
	for _, iss := range issues {
		if iss.ID == "VELOCLOUD-GW-003" {
			found = true
			if iss.Severity != SeverityCritical {
				t.Errorf("expected Critical severity, got %s", iss.Severity)
			}
		}
	}
	if !found {
		t.Error("expected VELOCLOUD-GW-003 gateway selection failure, got none")
	}
}

func TestDetectGatewayIssues_WrongPort_NoIssues(t *testing.T) {
	det := NewVeloCloudIssueDetector()
	stream := makeVeloStream(12345, 80, "TCP")
	addSegments(stream, 20, "client_to_server", 0.15, false, false, false)

	issues := det.detectGatewayIssues(stream)
	if len(issues) != 0 {
		t.Errorf("expected no issues for non-gateway port, got %d", len(issues))
	}
}

// ---- detectQoSIssues ----

func TestDetectQoSIssues_RTPWithHighJitter(t *testing.T) {
	det := NewVeloCloudIssueDetector()
	stream := makeVeloStream(20000, 20001, "UDP") // RTP port range
	stream.Application = "RTP"
	// Add segments with >50ms gaps every 3rd = ~33% burst rate (> 20% threshold)
	for i := 0; i < 21; i++ {
		gap := 0.01
		if i%3 == 0 {
			gap = 0.08 // >50ms gap every 3rd segment = 7/21 = 33% burst rate
		}
		stream.Segments = append(stream.Segments, models.StreamSegment{
			Direction:   "client_to_server",
			Length:      160,
			GapFromPrev: gap,
		})
	}
	stream.PacketCount = uint64(len(stream.Segments))

	issues := det.detectQoSIssues(stream)
	found := false
	for _, iss := range issues {
		if iss.ID == "VELOCLOUD-QOS-001" {
			found = true
		}
	}
	if !found {
		t.Error("expected VELOCLOUD-QOS-001 QoS misclassification for RTP with high jitter")
	}
}

func TestDetectQoSIssues_NonRealTime_NoIssues(t *testing.T) {
	det := NewVeloCloudIssueDetector()
	stream := makeVeloStream(12345, 443, "TCP")
	stream.Application = "HTTPS"
	addSegments(stream, 20, "client_to_server", 0.01, false, false, false)

	issues := det.detectQoSIssues(stream)
	if len(issues) != 0 {
		t.Errorf("expected no QoS issues for non-real-time HTTPS flow, got %d", len(issues))
	}
}

func TestDetectQoSIssues_TooFewSegments_NoIssues(t *testing.T) {
	det := NewVeloCloudIssueDetector()
	stream := makeVeloStream(20000, 20001, "UDP")
	stream.Application = "RTP"
	addSegments(stream, 2, "client_to_server", 0.08, false, false, false)

	issues := det.detectQoSIssues(stream)
	if len(issues) != 0 {
		t.Errorf("expected no issues with < 3 segments, got %d", len(issues))
	}
}

// ---- detectLAGIssues ----

func TestDetectLAGIssues_MemberFailure_ThroughputDrop(t *testing.T) {
	det := NewVeloCloudIssueDetector()
	stream := makeVeloStream(12345, VeloCloudVCMPPort, "UDP")
	stream.Duration = 20.0
	// First half: large segments; second half: tiny segments (~50% drop)
	for i := 0; i < 10; i++ {
		stream.Segments = append(stream.Segments, models.StreamSegment{
			Direction: "client_to_server", Length: 1400, GapFromPrev: 0.01,
		})
	}
	for i := 0; i < 10; i++ {
		stream.Segments = append(stream.Segments, models.StreamSegment{
			Direction: "client_to_server", Length: 100, GapFromPrev: 0.01,
		})
	}
	stream.PacketCount = uint64(len(stream.Segments))

	issues := det.detectLAGIssues(stream)
	found := false
	for _, iss := range issues {
		if iss.ID == "VELOCLOUD-LAG-001" {
			found = true
			if iss.Severity != SeverityCritical {
				t.Errorf("expected Critical severity, got %s", iss.Severity)
			}
		}
	}
	if !found {
		t.Error("expected VELOCLOUD-LAG-001 LAG member failure issue")
	}
}

func TestDetectLAGIssues_HashImbalance_OOO(t *testing.T) {
	det := NewVeloCloudIssueDetector()
	stream := makeVeloStream(12345, VeloCloudVCMPPort, "UDP")
	stream.Duration = 10.0
	// >5% OOO with low retransmit = hash imbalance
	for i := 0; i < 18; i++ {
		stream.Segments = append(stream.Segments, models.StreamSegment{
			Direction: "client_to_server", Length: 512, GapFromPrev: 0.01,
		})
	}
	// Add 2 OOO segments (>5% of 20 total)
	stream.Segments = append(stream.Segments, models.StreamSegment{
		Direction: "client_to_server", Length: 512, GapFromPrev: 0.01, IsOutOfOrder: true,
	})
	stream.Segments = append(stream.Segments, models.StreamSegment{
		Direction: "client_to_server", Length: 512, GapFromPrev: 0.01, IsOutOfOrder: true,
	})
	stream.PacketCount = uint64(len(stream.Segments))

	issues := det.detectLAGIssues(stream)
	found := false
	for _, iss := range issues {
		if iss.ID == "VELOCLOUD-LAG-002" {
			found = true
		}
	}
	if !found {
		t.Error("expected VELOCLOUD-LAG-002 LAG hash imbalance issue")
	}
}

func TestDetectLAGIssues_Flapping_MultipleResets(t *testing.T) {
	det := NewVeloCloudIssueDetector()
	stream := makeVeloStream(12345, VeloCloudVCMPPort, "UDP")
	stream.Duration = 30.0
	addSegments(stream, 10, "client_to_server", 0.01, false, false, false)
	// Add 3 reset segments
	for i := 0; i < 3; i++ {
		stream.Segments = append(stream.Segments, models.StreamSegment{
			Direction: "client_to_server", Length: 40, GapFromPrev: 0.5, HasReset: true,
		})
	}
	stream.PacketCount = uint64(len(stream.Segments))

	issues := det.detectLAGIssues(stream)
	found := false
	for _, iss := range issues {
		if iss.ID == "VELOCLOUD-LAG-003" {
			found = true
			if iss.Severity != SeverityCritical {
				t.Errorf("expected Critical severity, got %s", iss.Severity)
			}
		}
	}
	if !found {
		t.Error("expected VELOCLOUD-LAG-003 LAG flapping issue")
	}
}

func TestDetectLAGIssues_TooFewSegments_NoIssues(t *testing.T) {
	det := NewVeloCloudIssueDetector()
	stream := makeVeloStream(12345, VeloCloudVCMPPort, "UDP")
	addSegments(stream, 5, "client_to_server", 0.01, false, false, false)

	issues := det.detectLAGIssues(stream)
	if len(issues) != 0 {
		t.Errorf("expected no issues with < 10 segments, got %d", len(issues))
	}
}

// ---- DetectVeloCloudIssues (integration) ----

func TestDetectVeloCloudIssues_NonVeloPort_Empty(t *testing.T) {
	det := NewVeloCloudIssueDetector()
	stream := makeVeloStream(12345, 80, "TCP")
	addSegments(stream, 20, "client_to_server", 0.01, false, false, false)

	issues := det.DetectVeloCloudIssues(stream)
	if len(issues) != 0 {
		t.Errorf("expected no issues for non-VeloCloud port, got %d", len(issues))
	}
}
