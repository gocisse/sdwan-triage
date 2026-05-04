package detector

import (
	"testing"
	"time"

	"github.com/gocisse/sdwan-triage/pkg/models"
)

func TestNTPAnalyzer_AmplificationDetection(t *testing.T) {
	n := NewNTPAnalyzer()
	report := &models.TriageReport{}
	now := time.Now()

	srcIP := "203.0.113.10"
	dstIP := "10.0.0.1"
	size := 500 // > NTPAmplificationMinSize (468)

	// Send NTPAmplificationThreshold large responses from the same source
	for i := 0; i < NTPAmplificationThreshold; i++ {
		ts := float64(now.Add(time.Duration(i)*time.Millisecond).UnixNano()) / 1e9
		n.trackLargeResponse(srcIP, dstIP, size, now.Add(time.Duration(i)*time.Millisecond), ts, report)
	}

	if len(report.NTPFindings) != 1 {
		t.Fatalf("Expected 1 NTP amplification finding, got %d", len(report.NTPFindings))
	}

	f := report.NTPFindings[0]
	if f.Type != "Amplification" {
		t.Errorf("Expected type 'Amplification', got %q", f.Type)
	}
	if f.SourceIP != srcIP {
		t.Errorf("Expected SourceIP %q, got %q", srcIP, f.SourceIP)
	}
	if f.PacketCount < NTPAmplificationThreshold {
		t.Errorf("Expected PacketCount >= %d, got %d", NTPAmplificationThreshold, f.PacketCount)
	}
}

func TestNTPAnalyzer_BelowAmplificationThreshold(t *testing.T) {
	n := NewNTPAnalyzer()
	report := &models.TriageReport{}
	now := time.Now()

	for i := 0; i < NTPAmplificationThreshold-1; i++ {
		ts := float64(now.Add(time.Duration(i)*time.Millisecond).UnixNano()) / 1e9
		n.trackLargeResponse("203.0.113.10", "10.0.0.1", 500, now.Add(time.Duration(i)*time.Millisecond), ts, report)
	}

	if len(report.NTPFindings) != 0 {
		t.Fatalf("Expected 0 findings below threshold, got %d", len(report.NTPFindings))
	}
}

func TestNTPAnalyzer_MonlistResponse(t *testing.T) {
	n := NewNTPAnalyzer()
	report := &models.TriageReport{}
	now := time.Now()
	ts := float64(now.UnixNano()) / 1e9

	n.reportMonlist("198.51.100.5", "10.0.0.1", 1024, ts, report)

	if len(report.NTPFindings) != 1 {
		t.Fatalf("Expected 1 monlist finding, got %d", len(report.NTPFindings))
	}

	f := report.NTPFindings[0]
	if f.Type != "Monlist Response" {
		t.Errorf("Expected type 'Monlist Response', got %q", f.Type)
	}
	if f.Severity != "Warning" {
		t.Errorf("Expected severity 'Warning', got %q", f.Severity)
	}
	if f.ResponseSize != 1024 {
		t.Errorf("Expected ResponseSize 1024, got %d", f.ResponseSize)
	}
}

func TestNTPAnalyzer_MonlistReportedOnce(t *testing.T) {
	n := NewNTPAnalyzer()
	report := &models.TriageReport{}
	now := time.Now()
	ts := float64(now.UnixNano()) / 1e9

	n.reportMonlist("198.51.100.5", "10.0.0.1", 1024, ts, report)
	n.reportMonlist("198.51.100.5", "10.0.0.2", 2048, ts+1, report)

	// Same source IP — should only report once
	if len(report.NTPFindings) != 1 {
		t.Fatalf("Expected 1 monlist finding (deduplicated), got %d", len(report.NTPFindings))
	}
}

func TestNTPAnalyzer_StratumTracking(t *testing.T) {
	n := NewNTPAnalyzer()
	report := &models.TriageReport{}
	now := time.Now()

	// Track a server at stratum 2
	ts1 := float64(now.UnixNano()) / 1e9
	n.trackServer("192.168.1.1", 2, now, ts1, report)

	// Same server changes stratum multiple times
	for i := 1; i <= NTPStratumChangeThreshold; i++ {
		t2 := now.Add(time.Duration(i) * time.Second)
		ts2 := float64(t2.UnixNano()) / 1e9
		newStratum := uint8(2 + i)
		n.trackServer("192.168.1.1", newStratum, t2, ts2, report)
	}

	// Should have at least one stratum change finding
	found := false
	for _, f := range report.NTPFindings {
		if f.Type == "Stratum Change" {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected a 'Stratum Change' finding after multiple stratum changes")
	}
}
