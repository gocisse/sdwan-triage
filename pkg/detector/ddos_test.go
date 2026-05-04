package detector

import (
	"testing"
	"time"

	"github.com/gocisse/sdwan-triage/pkg/models"
)

func newTestState() *models.AnalysisState {
	return models.NewAnalysisState()
}

// ---------- SYN Flood ----------

func TestDDoSAnalyzer_SYNFloodDetection(t *testing.T) {
	d := NewDDoSAnalyzer()
	state := newTestState()
	report := &models.TriageReport{}
	now := time.Now()
	state.SecurityState.LastResetTime = now

	srcIP := "10.0.0.50"
	dstIP := "10.0.0.1"

	for i := 0; i < SYNFloodThreshold; i++ {
		ts := now.Add(time.Duration(i) * time.Millisecond)
		d.trackSYNPacket(srcIP, dstIP, ts, state, report)
	}

	if len(report.Security.DDoSFindings) != 1 {
		t.Fatalf("Expected 1 SYN flood finding, got %d", len(report.Security.DDoSFindings))
	}

	f := report.Security.DDoSFindings[0]
	if f.Type != "SYN Flood" {
		t.Errorf("Expected type 'SYN Flood', got %q", f.Type)
	}
	if f.SourceIP != srcIP {
		t.Errorf("Expected SourceIP %q, got %q", srcIP, f.SourceIP)
	}
	if f.PacketCount < SYNFloodThreshold {
		t.Errorf("Expected PacketCount >= %d, got %d", SYNFloodThreshold, f.PacketCount)
	}
	if f.Threshold != SYNFloodThreshold {
		t.Errorf("Expected Threshold %d, got %d", SYNFloodThreshold, f.Threshold)
	}
}

func TestDDoSAnalyzer_SYNFloodBelowThreshold(t *testing.T) {
	d := NewDDoSAnalyzer()
	state := newTestState()
	report := &models.TriageReport{}
	now := time.Now()
	state.SecurityState.LastResetTime = now

	// NewFloodCounter initializes Count=1 and trackSYNPacket increments,
	// so after N calls Count = N+1. Use threshold-2 to stay below.
	for i := 0; i < SYNFloodThreshold-2; i++ {
		ts := now.Add(time.Duration(i) * time.Millisecond)
		d.trackSYNPacket("10.0.0.50", "10.0.0.1", ts, state, report)
	}

	if len(report.Security.DDoSFindings) != 0 {
		t.Fatalf("Expected 0 findings below threshold, got %d", len(report.Security.DDoSFindings))
	}
}

// ---------- UDP Flood ----------

func TestDDoSAnalyzer_UDPFloodDetection(t *testing.T) {
	d := NewDDoSAnalyzer()
	state := newTestState()
	report := &models.TriageReport{}
	now := time.Now()
	state.SecurityState.LastResetTime = now

	srcIP := "10.0.0.60"
	dstIP := "10.0.0.2"

	for i := 0; i < UDPFloodThreshold; i++ {
		ts := now.Add(time.Duration(i) * time.Millisecond)
		d.trackUDPPacket(srcIP, dstIP, ts, state, report)
	}

	if len(report.Security.DDoSFindings) != 1 {
		t.Fatalf("Expected 1 UDP flood finding, got %d", len(report.Security.DDoSFindings))
	}

	f := report.Security.DDoSFindings[0]
	if f.Type != "UDP Flood" {
		t.Errorf("Expected type 'UDP Flood', got %q", f.Type)
	}
	if f.PacketCount < UDPFloodThreshold {
		t.Errorf("Expected PacketCount >= %d, got %d", UDPFloodThreshold, f.PacketCount)
	}
}

// ---------- ICMP Flood ----------

func TestDDoSAnalyzer_ICMPFloodDetection(t *testing.T) {
	d := NewDDoSAnalyzer()
	state := newTestState()
	report := &models.TriageReport{}
	now := time.Now()
	state.SecurityState.LastResetTime = now

	srcIP := "10.0.0.70"
	dstIP := "10.0.0.3"

	for i := 0; i < ICMPFloodThreshold; i++ {
		ts := now.Add(time.Duration(i) * time.Millisecond)
		d.trackICMPPacket(srcIP, dstIP, ts, state, report)
	}

	if len(report.Security.DDoSFindings) != 1 {
		t.Fatalf("Expected 1 ICMP flood finding, got %d", len(report.Security.DDoSFindings))
	}

	f := report.Security.DDoSFindings[0]
	if f.Type != "ICMP Flood" {
		t.Errorf("Expected type 'ICMP Flood', got %q", f.Type)
	}
}

// ---------- Severity calculation ----------

func TestDDoSAnalyzer_SeverityLevels(t *testing.T) {
	d := NewDDoSAnalyzer()

	tests := []struct {
		count    int
		expected string
	}{
		{SYNFloodThreshold, "Low"},           // ratio = 1
		{SYNFloodThreshold * 2, "Medium"},    // ratio = 2
		{SYNFloodThreshold * 5, "High"},      // ratio = 5
		{SYNFloodThreshold * 10, "Critical"}, // ratio = 10
	}

	for _, tc := range tests {
		got := d.calculateSeverity(tc.count, "SYN Flood")
		if got != tc.expected {
			t.Errorf("count=%d: expected severity %q, got %q", tc.count, tc.expected, got)
		}
	}
}

// ---------- Deduplication ----------

func TestDDoSAnalyzer_ReportedOnce(t *testing.T) {
	d := NewDDoSAnalyzer()
	state := newTestState()
	report := &models.TriageReport{}
	now := time.Now()
	state.SecurityState.LastResetTime = now

	// Send 2x the threshold — should only get 1 finding
	for i := 0; i < SYNFloodThreshold*2; i++ {
		ts := now.Add(time.Duration(i) * time.Millisecond)
		d.trackSYNPacket("10.0.0.50", "10.0.0.1", ts, state, report)
	}

	if len(report.Security.DDoSFindings) != 1 {
		t.Fatalf("Expected exactly 1 finding (deduplicated), got %d", len(report.Security.DDoSFindings))
	}
}

// ---------- Counter reset ----------

func TestDDoSAnalyzer_CounterReset(t *testing.T) {
	d := NewDDoSAnalyzer()
	state := newTestState()
	report := &models.TriageReport{}
	now := time.Now()
	state.SecurityState.LastResetTime = now

	// Send half the threshold
	for i := 0; i < SYNFloodThreshold/2; i++ {
		ts := now.Add(time.Duration(i) * time.Millisecond)
		d.trackSYNPacket("10.0.0.50", "10.0.0.1", ts, state, report)
	}

	// Jump forward past the detection window to trigger reset
	futureTime := now.Add(time.Duration(DetectionWindowSec+1) * time.Second)

	// Send another half — counters should have been reset
	for i := 0; i < SYNFloodThreshold/2; i++ {
		ts := futureTime.Add(time.Duration(i) * time.Millisecond)
		d.trackSYNPacket("10.0.0.50", "10.0.0.1", ts, state, report)
	}

	// Neither batch hit the threshold, so no findings
	if len(report.Security.DDoSFindings) != 0 {
		t.Fatalf("Expected 0 findings after counter reset, got %d", len(report.Security.DDoSFindings))
	}
}

// ---------- Custom thresholds ----------

func TestDDoSAnalyzer_CustomThresholds(t *testing.T) {
	d := NewDDoSAnalyzer()
	d.SetSYNThreshold(5)
	state := newTestState()
	report := &models.TriageReport{}
	now := time.Now()
	state.SecurityState.LastResetTime = now

	for i := 0; i < 5; i++ {
		ts := now.Add(time.Duration(i) * time.Millisecond)
		d.trackSYNPacket("10.0.0.50", "10.0.0.1", ts, state, report)
	}

	if len(report.Security.DDoSFindings) != 1 {
		t.Fatalf("Expected 1 finding with custom threshold=5, got %d", len(report.Security.DDoSFindings))
	}
}
