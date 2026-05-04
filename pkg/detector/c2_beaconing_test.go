package detector

import (
	"testing"
	"time"

	"github.com/gocisse/sdwan-triage/pkg/models"
)

// makeBeaconingFlow creates a c2FlowTracker that simulates a beaconing pattern
// with the given interval (seconds) and jitter factor (0.0 = no jitter).
func makeBeaconingFlow(srcIP, dstIP string, dstPort uint16, protocol string,
	count int, intervalSec float64, jitterFrac float64, payloadSize int) (*c2FlowTracker, string) {

	start := time.Date(2025, 6, 1, 12, 0, 0, 0, time.UTC)
	flow := &c2FlowTracker{
		SrcIP:     srcIP,
		DstIP:     dstIP,
		DstPort:   dstPort,
		Protocol:  protocol,
		FirstSeen: start,
	}

	for i := 0; i < count; i++ {
		jitter := time.Duration(float64(i) * intervalSec * jitterFrac * float64(time.Second) * 0.01)
		ts := start.Add(time.Duration(float64(i)*intervalSec*float64(time.Second)) + jitter)
		flow.Timestamps = append(flow.Timestamps, ts)
		if payloadSize > 0 {
			flow.PayloadSizes = append(flow.PayloadSizes, payloadSize)
		}
		flow.LastSeen = ts
	}

	suffix := ""
	if protocol == "UDP" {
		suffix = "/udp"
	}
	key := srcIP + "->" + dstIP + ":" + itoa(int(dstPort)) + suffix
	return flow, key
}

func itoa(v int) string {
	if v == 0 {
		return "0"
	}
	buf := make([]byte, 0, 8)
	for v > 0 {
		buf = append(buf, byte('0'+v%10))
		v /= 10
	}
	// reverse
	for i, j := 0, len(buf)-1; i < j; i, j = i+1, j-1 {
		buf[i], buf[j] = buf[j], buf[i]
	}
	return string(buf)
}

func TestC2Beaconing_HighConfidence(t *testing.T) {
	c := NewC2BeaconingAnalyzer()
	report := &models.TriageReport{}

	// Perfect beaconing: 30 connections, 60s interval, 0% jitter, constant payload
	flow, key := makeBeaconingFlow("10.0.0.5", "198.51.100.10", 4444, "TCP",
		30, 60.0, 0.0, 256)
	c.flows[key] = flow
	c.checkBeaconing(key, flow, report)

	if len(report.C2BeaconingFindings) != 1 {
		t.Fatalf("Expected 1 C2 finding, got %d", len(report.C2BeaconingFindings))
	}

	f := report.C2BeaconingFindings[0]
	if f.Confidence != "High" {
		t.Errorf("Expected confidence 'High', got %q", f.Confidence)
	}
	if f.Severity != "Critical" {
		t.Errorf("Expected severity 'Critical', got %q", f.Severity)
	}
	if f.SourceIP != "10.0.0.5" {
		t.Errorf("Expected SourceIP '10.0.0.5', got %q", f.SourceIP)
	}
	if f.DestIP != "198.51.100.10" {
		t.Errorf("Expected DestIP '198.51.100.10', got %q", f.DestIP)
	}
	if f.DestPort != 4444 {
		t.Errorf("Expected DestPort 4444, got %d", f.DestPort)
	}
	if f.ConnectionCount != 30 {
		t.Errorf("Expected ConnectionCount 30, got %d", f.ConnectionCount)
	}
	if f.BeaconInterval < 55 || f.BeaconInterval > 65 {
		t.Errorf("Expected BeaconInterval ~60, got %.1f", f.BeaconInterval)
	}
}

func TestC2Beaconing_MediumConfidence(t *testing.T) {
	c := NewC2BeaconingAnalyzer()
	report := &models.TriageReport{}

	// Moderate jitter (~7%), moderate payload variance
	flow, key := makeBeaconingFlow("10.0.0.6", "203.0.113.20", 5555, "TCP",
		20, 30.0, 7.0, 0)

	// Add varied payload sizes
	flow.PayloadSizes = nil
	for i := 0; i < 20; i++ {
		flow.PayloadSizes = append(flow.PayloadSizes, 200+i*3)
	}

	c.flows[key] = flow
	c.checkBeaconing(key, flow, report)

	if len(report.C2BeaconingFindings) != 1 {
		t.Fatalf("Expected 1 finding, got %d", len(report.C2BeaconingFindings))
	}

	f := report.C2BeaconingFindings[0]
	if f.Confidence == "High" {
		t.Errorf("Expected confidence Medium or Low for moderate jitter, got %q", f.Confidence)
	}
}

func TestC2Beaconing_TooMuchJitter(t *testing.T) {
	c := NewC2BeaconingAnalyzer()
	report := &models.TriageReport{}

	// Very high jitter — random-looking traffic
	start := time.Date(2025, 6, 1, 12, 0, 0, 0, time.UTC)
	flow := &c2FlowTracker{
		SrcIP:     "10.0.0.7",
		DstIP:     "198.51.100.30",
		DstPort:   6666,
		Protocol:  "TCP",
		FirstSeen: start,
	}
	// Random-ish intervals: 5s, 120s, 3s, 200s, ...
	intervals := []float64{5, 120, 3, 200, 15, 80, 2, 300, 10, 50, 7, 90, 1, 180, 20}
	accum := 0.0
	for _, iv := range intervals {
		accum += iv
		flow.Timestamps = append(flow.Timestamps, start.Add(time.Duration(accum*float64(time.Second))))
		flow.PayloadSizes = append(flow.PayloadSizes, 128)
	}
	flow.LastSeen = flow.Timestamps[len(flow.Timestamps)-1]

	c.flows["test"] = flow
	c.checkBeaconing("test", flow, report)

	if len(report.C2BeaconingFindings) != 0 {
		t.Errorf("Expected 0 findings for high-jitter traffic, got %d", len(report.C2BeaconingFindings))
	}
}

func TestC2Beaconing_BelowMinConnections(t *testing.T) {
	c := NewC2BeaconingAnalyzer()
	report := &models.TriageReport{}

	flow, key := makeBeaconingFlow("10.0.0.8", "198.51.100.40", 7777, "TCP",
		C2MinConnections-1, 60.0, 0.0, 256)

	c.flows[key] = flow
	c.checkBeaconing(key, flow, report)

	if len(report.C2BeaconingFindings) != 0 {
		t.Errorf("Expected 0 findings below C2MinConnections, got %d", len(report.C2BeaconingFindings))
	}
}

func TestC2Beaconing_Deduplication(t *testing.T) {
	c := NewC2BeaconingAnalyzer()
	report := &models.TriageReport{}

	flow, key := makeBeaconingFlow("10.0.0.5", "198.51.100.10", 4444, "TCP",
		30, 60.0, 0.0, 256)

	c.flows[key] = flow
	c.checkBeaconing(key, flow, report)
	c.checkBeaconing(key, flow, report)
	c.checkBeaconing(key, flow, report)

	if len(report.C2BeaconingFindings) != 1 {
		t.Fatalf("Expected 1 finding (deduplicated), got %d", len(report.C2BeaconingFindings))
	}
}

func TestC2Beaconing_IntervalTooShort(t *testing.T) {
	c := NewC2BeaconingAnalyzer()
	report := &models.TriageReport{}

	// Interval 2s < C2MinInterval (10s)
	flow, key := makeBeaconingFlow("10.0.0.9", "198.51.100.50", 8888, "TCP",
		20, 2.0, 0.0, 256)

	c.flows[key] = flow
	c.checkBeaconing(key, flow, report)

	if len(report.C2BeaconingFindings) != 0 {
		t.Errorf("Expected 0 findings for interval below C2MinInterval, got %d", len(report.C2BeaconingFindings))
	}
}

func TestC2Beaconing_UDPProtocol(t *testing.T) {
	c := NewC2BeaconingAnalyzer()
	report := &models.TriageReport{}

	flow, key := makeBeaconingFlow("10.0.0.10", "198.51.100.60", 9999, "UDP",
		25, 45.0, 0.0, 128)

	c.flows[key] = flow
	c.checkBeaconing(key, flow, report)

	if len(report.C2BeaconingFindings) != 1 {
		t.Fatalf("Expected 1 UDP beaconing finding, got %d", len(report.C2BeaconingFindings))
	}

	f := report.C2BeaconingFindings[0]
	if f.Protocol != "UDP" {
		t.Errorf("Expected protocol 'UDP', got %q", f.Protocol)
	}
}

func TestC2Beaconing_MaybeReset(t *testing.T) {
	c := NewC2BeaconingAnalyzer()

	t0 := time.Date(2025, 6, 1, 12, 0, 0, 0, time.UTC)
	c.lastReset = t0
	c.flows["existing"] = &c2FlowTracker{SrcIP: "1.2.3.4"}

	// Within window — no reset
	c.maybeReset(t0.Add(60 * time.Second))
	if len(c.flows) != 1 {
		t.Fatal("Expected flows to persist within detection window")
	}

	// Past window — reset
	c.maybeReset(t0.Add(time.Duration(C2DetectionWindowSec+1) * time.Second))
	if len(c.flows) != 0 {
		t.Fatal("Expected flows to be cleared after detection window")
	}
}
