package analyzer

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gocisse/sdwan-triage/internal/testpcap"
	"github.com/gocisse/sdwan-triage/pkg/models"
)

const deadlockTestBundle = `{
  "type": "bundle",
  "id": "bundle--deadlock-test",
  "objects": [
    {
      "type": "indicator",
      "id": "indicator--deadlock-1",
      "name": "Test C2",
      "pattern": "[ipv4-addr:value = '45.33.32.156']",
      "pattern_type": "stix",
      "valid_from": "2025-01-01T00:00:00Z",
      "labels": ["malicious-activity", "command-and-control"],
      "confidence": 90
    }
  ]
}`

// Regression: ThreatIntelMatcher.reportMatch used to lock report.Mu while the
// DetectorRegistry already held it around Analyze(), hanging the process on the
// first IOC hit. A single SYN to a feed-listed IP must complete promptly.
func TestThreatIntel_MatchDoesNotDeadlock(t *testing.T) {
	dir := t.TempDir()
	feedPath := filepath.Join(dir, "feed.json")
	if err := os.WriteFile(feedPath, []byte(deadlockTestBundle), 0o644); err != nil {
		t.Fatal(err)
	}
	pcapPath := filepath.Join(dir, "ioc.pcap")
	syn := testpcap.TCPFrame(testpcap.ClientMAC, testpcap.ServerMAC, testpcap.ClientIP, []byte{45, 33, 32, 156},
		40000, 443, 1, 0, testpcap.SYN, nil)
	if err := testpcap.WriteFile(pcapPath, [][]byte{syn}); err != nil {
		t.Fatal(err)
	}

	p := NewProcessorWithOptions(false, false)
	if err := p.LoadThreatIntelFile(feedPath); err != nil {
		t.Fatalf("load feed: %v", err)
	}

	type result struct {
		report *models.TriageReport
		err    error
	}
	done := make(chan result, 1)
	go func() {
		handle, err := OpenCapture(pcapPath)
		if err != nil {
			done <- result{nil, err}
			return
		}
		defer handle.Close()
		report := &models.TriageReport{}
		err = p.Process(handle.Reader, models.NewAnalysisState(), report, nil)
		done <- result{report, err}
	}()

	select {
	case res := <-done:
		if res.err != nil {
			t.Fatalf("process: %v", res.err)
		}
		if len(res.report.ThreatIntelMatches) != 1 {
			t.Fatalf("expected 1 threat intel match, got %d", len(res.report.ThreatIntelMatches))
		}
		if res.report.ThreatIntelMatches[0].Value != "45.33.32.156" {
			t.Errorf("matched value = %q", res.report.ThreatIntelMatches[0].Value)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Process deadlocked on threat-intel match (report.Mu re-entered)")
	}
}
