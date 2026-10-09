package analyzer

import (
	"strings"
	"testing"

	"github.com/gocisse/sdwan-triage/pkg/models"
)

// Phase 4.27a: OMP-001, AAR-002 and VCMP-002 fire on traffic-pattern proxies
// (short high-rate stream, mean inter-packet interval, long-lived stream), not
// on measured OMP flaps, latency or response times. These tests pin that the
// triggers are unchanged while severity and wording no longer overstate.

// overclaims are phrases asserting conditions the rules never measure.
var heuristicOverclaims = []string{
	"route flap detected",
	"rapid omp session state changes",
	"route instability",
	"sla violation",
	"high-latency path",
	"high latency",
	"responses taking excessive time",
	"indicating network or orchestrator issues",
}

func assertHeuristicIssue(t *testing.T, iss DetectedIssue) {
	t.Helper()
	if iss.Severity != SeverityInfo {
		t.Errorf("%s: severity = %s, want %s", iss.ID, iss.Severity, SeverityInfo)
	}
	text := strings.ToLower(iss.Title + " " + iss.TechnicalDesc + " " + iss.BusinessImpact + " " + iss.RootCause)
	for _, bad := range heuristicOverclaims {
		if strings.Contains(text, bad) {
			t.Errorf("%s: text still asserts %q", iss.ID, bad)
		}
	}
	if !strings.Contains(strings.ToLower(iss.Title), "heuristic") {
		t.Errorf("%s: title %q does not mark the finding as a heuristic observation", iss.ID, iss.Title)
	}
	if !strings.Contains(strings.ToLower(iss.TechnicalDesc), "not") {
		t.Errorf("%s: description should state what was not measured: %q", iss.ID, iss.TechnicalDesc)
	}
	if !strings.Contains(strings.ToLower(iss.RootCause), "not determined") {
		t.Errorf("%s: root cause must not assert a cause: %q", iss.ID, iss.RootCause)
	}
}

func countIssue(issues []DetectedIssue, id string) (int, DetectedIssue) {
	n := 0
	var last DetectedIssue
	for _, i := range issues {
		if i.ID == id {
			n++
			last = i
		}
	}
	return n, last
}

func ompStream(duration float64, packets int) *models.StreamData {
	s := makeViptelaStream(12345, ViptelaOMPPort, "UDP")
	s.Duration = duration
	addViptelaSegments(s, packets, "client_to_server", 0.01, false, false, false)
	return s
}

func TestOMP001_TriggerUnchanged_HeuristicWording(t *testing.T) {
	det := NewViptelaIssueDetector()
	cases := []struct {
		name     string
		duration float64
		packets  int
		want     int
	}{
		{"fires: short and busy", 3.0, 25, 1},
		{"boundary: exactly 20 packets", 3.0, 20, 0},
		{"boundary: 21 packets", 3.0, 21, 1},
		{"boundary: duration exactly 5s", 5.0, 25, 0},
		{"boundary: duration 4.99s", 4.99, 25, 1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			n, iss := countIssue(det.detectOMPIssues(ompStream(c.duration, c.packets)), "VIPTELA-OMP-001")
			if n != c.want {
				t.Fatalf("OMP-001 count = %d, want %d", n, c.want)
			}
			if n == 1 {
				assertHeuristicIssue(t, iss)
			}
		})
	}
}

func aarStream(duration, gapSec float64) *models.StreamData {
	s := makeViptelaStream(12345, 443, "TCP")
	s.Duration = duration
	for i := 0; i < 10; i++ {
		s.Segments = append(s.Segments, models.StreamSegment{Direction: "client_to_server", Length: 512, GapFromPrev: gapSec})
	}
	s.PacketCount = uint64(len(s.Segments))
	return s
}

func TestAAR002_TriggerUnchanged_HeuristicWording(t *testing.T) {
	det := NewViptelaIssueDetector()
	cases := []struct {
		name     string
		duration float64
		gap      float64
		want     int
	}{
		{"fires: 200ms interval over 10s", 10.0, 0.20, 1},
		{"boundary: mean exactly 150ms", 10.0, 0.15, 0},
		{"boundary: mean 151ms", 10.0, 0.151, 1},
		{"boundary: duration exactly 5s", 5.0, 0.20, 0},
		{"boundary: duration 5.01s", 5.01, 0.20, 1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			n, iss := countIssue(det.detectAARIssues(aarStream(c.duration, c.gap)), "VIPTELA-AAR-002")
			if n != c.want {
				t.Fatalf("AAR-002 count = %d, want %d", n, c.want)
			}
			if n == 1 {
				assertHeuristicIssue(t, iss)
				if !strings.Contains(iss.TechnicalDesc, "interval") {
					t.Errorf("description should name the measured quantity (interval): %q", iss.TechnicalDesc)
				}
			}
		})
	}
}

func TestVCMP002_TriggerUnchanged_HeuristicWording(t *testing.T) {
	det := NewVeloCloudIssueDetector()
	cases := []struct {
		name     string
		duration float64
		want     int
	}{
		{"fires: long-lived stream", 10.0, 1},
		{"fires: 60s stream", 60.0, 1},
		{"boundary: duration exactly 5s", 5.0, 0},
		{"boundary: duration 5.01s", 5.01, 1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := makeVeloStream(12345, VeloCloudVCMPPort, "UDP")
			s.Duration = c.duration
			addSegments(s, 30, "client_to_server", 0.01, false, false, false)
			addSegments(s, 30, "server_to_client", 0.01, false, false, false)
			n, iss := countIssue(det.detectVCMPIssues(s), "VELOCLOUD-VCMP-002")
			if n != c.want {
				t.Fatalf("VCMP-002 count = %d, want %d", n, c.want)
			}
			if n == 1 {
				assertHeuristicIssue(t, iss)
				if !strings.Contains(iss.TechnicalDesc, "no VCMP request/response timing was measured") {
					t.Errorf("description must say response time was not measured: %q", iss.TechnicalDesc)
				}
			}
		})
	}
}

func TestHeuristicVendorIssues_Deterministic(t *testing.T) {
	det := NewViptelaIssueDetector()
	a := det.detectOMPIssues(ompStream(3.0, 25))
	b := det.detectOMPIssues(ompStream(3.0, 25))
	if len(a) != len(b) || a[0].Title != b[0].Title || a[0].TechnicalDesc != b[0].TechnicalDesc {
		t.Error("OMP-001 output not deterministic")
	}
}
