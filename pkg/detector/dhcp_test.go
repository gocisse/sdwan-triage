package detector

import (
	"testing"
	"time"

	"github.com/gocisse/sdwan-triage/pkg/models"
)

func TestDHCPAnalyzer_RogueServerDetection(t *testing.T) {
	d := NewDHCPAnalyzer()
	report := &models.TriageReport{}
	now := time.Now()
	ts := float64(now.UnixNano()) / 1e9

	// First server — no finding yet
	d.trackServer("192.168.1.1", "aa:bb:cc:dd:ee:01", now, ts, report)
	if len(report.DHCPFindings) != 0 {
		t.Fatalf("Expected 0 findings after first server, got %d", len(report.DHCPFindings))
	}

	// Second server triggers rogue detection
	d.trackServer("192.168.1.200", "aa:bb:cc:dd:ee:02", now.Add(time.Second), ts+1, report)
	if len(report.DHCPFindings) != 1 {
		t.Fatalf("Expected 1 finding after second server, got %d", len(report.DHCPFindings))
	}

	f := report.DHCPFindings[0]
	if f.Type != "Rogue Server" {
		t.Errorf("Expected type 'Rogue Server', got %q", f.Type)
	}
	if f.Severity != "Critical" {
		t.Errorf("Expected severity 'Critical', got %q", f.Severity)
	}
	if len(f.KnownServers) != 2 {
		t.Errorf("Expected 2 known servers, got %d", len(f.KnownServers))
	}
}

func TestDHCPAnalyzer_RogueServerReportedOnce(t *testing.T) {
	d := NewDHCPAnalyzer()
	report := &models.TriageReport{}
	now := time.Now()
	ts := float64(now.UnixNano()) / 1e9

	d.trackServer("192.168.1.1", "aa:bb:cc:dd:ee:01", now, ts, report)
	d.trackServer("192.168.1.200", "aa:bb:cc:dd:ee:02", now, ts, report)
	d.trackServer("192.168.1.201", "aa:bb:cc:dd:ee:03", now, ts, report)

	// Should only have 1 finding even with 3 servers
	if len(report.DHCPFindings) != 1 {
		t.Fatalf("Expected exactly 1 rogue server finding, got %d", len(report.DHCPFindings))
	}
}

func TestDHCPAnalyzer_StarvationDetection(t *testing.T) {
	d := NewDHCPAnalyzer()
	report := &models.TriageReport{}
	now := time.Now()

	mac := "de:ad:be:ef:00:01"

	// Send DHCPStarvationThreshold DISCOVER packets from same MAC
	for i := 0; i < DHCPStarvationThreshold; i++ {
		ts := float64(now.Add(time.Duration(i) * time.Millisecond).UnixNano()) / 1e9
		d.trackDiscover(mac, now.Add(time.Duration(i)*time.Millisecond), ts, report)
	}

	if len(report.DHCPFindings) != 1 {
		t.Fatalf("Expected 1 starvation finding, got %d", len(report.DHCPFindings))
	}

	f := report.DHCPFindings[0]
	if f.Type != "Starvation" {
		t.Errorf("Expected type 'Starvation', got %q", f.Type)
	}
	if f.Severity != "Critical" {
		t.Errorf("Expected severity 'Critical', got %q", f.Severity)
	}
	if f.ClientMAC != mac {
		t.Errorf("Expected ClientMAC %q, got %q", mac, f.ClientMAC)
	}
	if f.PacketCount < DHCPStarvationThreshold {
		t.Errorf("Expected PacketCount >= %d, got %d", DHCPStarvationThreshold, f.PacketCount)
	}
}

func TestDHCPAnalyzer_BelowStarvationThreshold(t *testing.T) {
	d := NewDHCPAnalyzer()
	report := &models.TriageReport{}
	now := time.Now()

	mac := "de:ad:be:ef:00:02"

	for i := 0; i < DHCPStarvationThreshold-1; i++ {
		ts := float64(now.Add(time.Duration(i) * time.Millisecond).UnixNano()) / 1e9
		d.trackDiscover(mac, now.Add(time.Duration(i)*time.Millisecond), ts, report)
	}

	if len(report.DHCPFindings) != 0 {
		t.Fatalf("Expected 0 findings below threshold, got %d", len(report.DHCPFindings))
	}
}

func TestDHCPAnalyzer_NAKStormDetection(t *testing.T) {
	d := NewDHCPAnalyzer()
	report := &models.TriageReport{}
	now := time.Now()

	for i := 0; i < DHCPNAKStormThreshold; i++ {
		ts := float64(now.Add(time.Duration(i) * time.Millisecond).UnixNano()) / 1e9
		d.trackNAK("192.168.1.1", now.Add(time.Duration(i)*time.Millisecond), ts, report)
	}

	if len(report.DHCPFindings) != 1 {
		t.Fatalf("Expected 1 NAK storm finding, got %d", len(report.DHCPFindings))
	}

	f := report.DHCPFindings[0]
	if f.Type != "NAK Storm" {
		t.Errorf("Expected type 'NAK Storm', got %q", f.Type)
	}
	if f.Severity != "Warning" {
		t.Errorf("Expected severity 'Warning', got %q", f.Severity)
	}
	if f.PacketCount < DHCPNAKStormThreshold {
		t.Errorf("Expected PacketCount >= %d, got %d", DHCPNAKStormThreshold, f.PacketCount)
	}
}

func TestDHCPAnalyzer_EmptyMACIgnored(t *testing.T) {
	d := NewDHCPAnalyzer()
	report := &models.TriageReport{}
	now := time.Now()
	ts := float64(now.UnixNano()) / 1e9

	d.trackDiscover("", now, ts, report)
	if len(report.DHCPFindings) != 0 {
		t.Errorf("Expected 0 findings for empty MAC, got %d", len(report.DHCPFindings))
	}
}

func TestDHCPAnalyzer_EmptyIPIgnored(t *testing.T) {
	d := NewDHCPAnalyzer()
	report := &models.TriageReport{}
	now := time.Now()
	ts := float64(now.UnixNano()) / 1e9

	d.trackServer("", "", now, ts, report)
	if len(d.servers) != 0 {
		t.Errorf("Expected 0 tracked servers for empty IP, got %d", len(d.servers))
	}
}
