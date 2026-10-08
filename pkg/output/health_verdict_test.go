package output

import (
	"strings"
	"testing"

	"github.com/gocisse/sdwan-triage/pkg/models"
)

// healthVerdict: deterministic maximum over per-evidence-class floors.

func hvFailed(n int) []models.TCPHandshakeFlow { return hsFlows("Handshake Failed", reasonSynAck, n) }

func hvLevel(t *testing.T, name string, r *models.TriageReport, want healthLevel) {
	t.Helper()
	if got := healthVerdict(r); got != want {
		t.Errorf("%s: health = %d, want %d", name, got, want)
	}
}

func TestHealth_Clean(t *testing.T) {
	hvLevel(t, "empty report", &models.TriageReport{}, healthGood)
}

func TestHealth_HandshakeClassification(t *testing.T) {
	hvLevel(t, "successful only", &models.TriageReport{TCPHandshakeFlows: hsFlows("Handshake Complete", "", 20)}, healthGood)
	hvLevel(t, "incomplete only", &models.TriageReport{TCPHandshakeFlows: append(hsFlows("SYN", "", 50), hsFlows("SYN-ACK", "", 10)...)}, healthGood)
	hvLevel(t, "1 failed", &models.TriageReport{TCPHandshakeFlows: hvFailed(1)}, healthFair)
	hvLevel(t, "5 failed", &models.TriageReport{TCPHandshakeFlows: hvFailed(5)}, healthFair)
	hvLevel(t, "6 failed", &models.TriageReport{TCPHandshakeFlows: hvFailed(6)}, healthWarning)
	for _, reason := range []string{reasonSynAck, reasonRST, reasonAck, "something else"} {
		hvLevel(t, "1 failed: "+reason, &models.TriageReport{TCPHandshakeFlows: hsFlows("Handshake Failed", reason, 1)}, healthFair)
	}
	// Mixed reasons are summed: 2+2+2 = 6 > 5.
	mixed := append(append(hsFlows("Handshake Failed", reasonSynAck, 2), hsFlows("Handshake Failed", reasonRST, 2)...), hsFlows("Handshake Failed", reasonAck, 2)...)
	hvLevel(t, "mixed reasons total 6", &models.TriageReport{TCPHandshakeFlows: mixed}, healthWarning)
	// Failures plus incomplete flows: only failures count.
	hvLevel(t, "3 failed + 80 incomplete", &models.TriageReport{TCPHandshakeFlows: append(hvFailed(3), hsFlows("SYN", "", 80)...)}, healthFair)
}

func TestHealth_HandshakeTrackerVsLegacy(t *testing.T) {
	// Tracker present: the legacy RST count (a subset) must not be added on top.
	r := &models.TriageReport{TCPHandshakeFlows: hvFailed(3), FailedHandshakes: make([]models.TCPFlow, 3)}
	if got := handshakeFailures(r); got != 3 {
		t.Errorf("tracker + legacy counted %d, want 3 (once)", got)
	}
	hvLevel(t, "3 tracker + 3 legacy", r, healthFair) // would be WARNING (6) if double counted
	// Tracker present but with no failures: legacy ignored.
	r = &models.TriageReport{TCPHandshakeFlows: hsFlows("Handshake Complete", "", 4), FailedHandshakes: make([]models.TCPFlow, 9)}
	if got := handshakeFailures(r); got != 0 {
		t.Errorf("tracker present with 0 failures should win over legacy, got %d", got)
	}
	// Tracker absent: legacy fallback.
	hvLevel(t, "legacy only, 2", &models.TriageReport{FailedHandshakes: make([]models.TCPFlow, 2)}, healthFair)
	hvLevel(t, "legacy only, 6", &models.TriageReport{FailedHandshakes: make([]models.TCPFlow, 6)}, healthWarning)
}

func TestHealth_PerformanceBucketUnchanged(t *testing.T) {
	flows := func(n int) []models.TCPFlow { return make([]models.TCPFlow, n) }
	hvLevel(t, "1 retransmission flow", &models.TriageReport{TCPRetransmissions: flows(1)}, healthFair)
	hvLevel(t, "6 retransmission flows", &models.TriageReport{TCPRetransmissions: flows(6)}, healthWarning)
	hvLevel(t, "RTT flows 6", &models.TriageReport{RTTAnalysis: make([]models.RTTFlow, 6)}, healthWarning)
	// Combined: 2 retransmission flows + 2 RTT flows + 2 failed handshakes = 6.
	hvLevel(t, "combined 6", &models.TriageReport{TCPRetransmissions: flows(2), RTTAnalysis: make([]models.RTTFlow, 2), TCPHandshakeFlows: hvFailed(2)}, healthWarning)
	hvLevel(t, "suspicious traffic", &models.TriageReport{SuspiciousTraffic: make([]models.SuspiciousFlow, 1)}, healthWarning)
	hvLevel(t, "self-signed cert", &models.TriageReport{TLSCerts: []models.TLSCertInfo{{IsSelfSigned: true}}}, healthWarning)
	hvLevel(t, "valid cert only", &models.TriageReport{TLSCerts: []models.TLSCertInfo{{}}}, healthGood)
}

func TestHealth_StabilityFloor(t *testing.T) {
	sf := func(sev string, n int) []models.StabilityFinding {
		out := make([]models.StabilityFinding, n)
		for i := range out {
			out[i] = models.StabilityFinding{Type: "BFD Session Down", Severity: sev}
		}
		return out
	}
	hvLevel(t, "High", &models.TriageReport{StabilityFindings: sf("High", 1)}, healthWarning)
	hvLevel(t, "Critical", &models.TriageReport{StabilityFindings: sf("Critical", 1)}, healthWarning)
	hvLevel(t, "lower severity", &models.TriageReport{StabilityFindings: sf("Warning", 1)}, healthFair)
	hvLevel(t, "two directional High findings", &models.TriageReport{StabilityFindings: sf("High", 2)}, healthWarning)
	hvLevel(t, "20 High findings stay WARNING", &models.TriageReport{StabilityFindings: sf("High", 20)}, healthWarning)
	hvLevel(t, "20 low findings stay FAIR", &models.TriageReport{StabilityFindings: sf("Warning", 20)}, healthFair)
}

func TestHealth_Windows(t *testing.T) {
	hvLevel(t, "Zero Window", &models.TriageReport{TCPWindowFindings: []models.TCPWindowFinding{{Type: "Zero Window", Severity: "Critical"}}}, healthWarning)
	hvLevel(t, "Small Window only", &models.TriageReport{TCPWindowFindings: []models.TCPWindowFinding{{Type: "Small Window", Severity: "Warning"}, {Type: "Small Window"}}}, healthGood)
	hvLevel(t, "Small + Zero", &models.TriageReport{TCPWindowFindings: []models.TCPWindowFinding{{Type: "Small Window"}, {Type: "Zero Window"}}}, healthWarning)
}

func TestHealth_Findings(t *testing.T) {
	f := func(sev models.Severity, basis string) models.Finding {
		return models.Finding{Severity: sev, Basis: basis}
	}
	hvLevel(t, "High", &models.TriageReport{Findings: []models.Finding{f(models.SeverityHigh, models.FindingBasisObserved)}}, healthWarning)
	hvLevel(t, "Critical", &models.TriageReport{Findings: []models.Finding{f(models.SeverityCritical, models.EvidenceSameSession)}}, healthWarning)
	hvLevel(t, "Medium", &models.TriageReport{Findings: []models.Finding{f(models.SeverityMedium, models.FindingBasisObserved)}}, healthGood)
	hvLevel(t, "Low", &models.TriageReport{Findings: []models.Finding{f(models.SeverityLow, models.FindingBasisObserved)}}, healthGood)
	hvLevel(t, "Info", &models.TriageReport{Findings: []models.Finding{f(models.SeverityInfo, models.FindingBasisObserved)}}, healthGood)
	hvLevel(t, "High but time_proximity", &models.TriageReport{Findings: []models.Finding{f(models.SeverityHigh, models.EvidenceTimeProximity)}}, healthGood)
	hvLevel(t, "several Medium/Low", &models.TriageReport{Findings: []models.Finding{
		f(models.SeverityMedium, models.FindingBasisObserved), f(models.SeverityMedium, models.FindingBasisObserved), f(models.SeverityLow, models.FindingBasisObserved)}}, healthGood)
	hvLevel(t, "Low + High", &models.TriageReport{Findings: []models.Finding{f(models.SeverityLow, models.FindingBasisObserved), f(models.SeverityHigh, models.FindingBasisObserved)}}, healthWarning)
}

func TestHealth_ExistingCriticalUnchanged(t *testing.T) {
	hvLevel(t, "DNS", &models.TriageReport{DNSAnomalies: make([]models.DNSAnomaly, 1)}, healthCritical)
	hvLevel(t, "ARP", &models.TriageReport{ARPConflicts: make([]models.ARPConflict, 1)}, healthCritical)
	everything := &models.TriageReport{
		DNSAnomalies:      make([]models.DNSAnomaly, 1),
		TCPHandshakeFlows: hvFailed(10),
		StabilityFindings: []models.StabilityFinding{{Severity: "Critical"}},
		TCPWindowFindings: []models.TCPWindowFinding{{Type: "Zero Window"}},
		Findings:          []models.Finding{{Severity: models.SeverityCritical, Basis: models.FindingBasisObserved}},
	}
	hvLevel(t, "DNS + everything", everything, healthCritical)
}

func TestHealth_MixedCases(t *testing.T) {
	hvLevel(t, "handshake + DNS", &models.TriageReport{TCPHandshakeFlows: hvFailed(2), DNSAnomalies: make([]models.DNSAnomaly, 1)}, healthCritical)
	hvLevel(t, "stability + retransmission", &models.TriageReport{
		StabilityFindings:  []models.StabilityFinding{{Severity: "High"}},
		TCPRetransmissions: make([]models.TCPFlow, 1)}, healthWarning)
	hvLevel(t, "zero window + clean traffic", &models.TriageReport{
		TCPHandshakeFlows: hsFlows("Handshake Complete", "", 10),
		TCPWindowFindings: []models.TCPWindowFinding{{Type: "Zero Window"}}}, healthWarning)
	hvLevel(t, "High finding + existing WARNING", &models.TriageReport{
		Findings:          []models.Finding{{Severity: models.SeverityHigh, Basis: models.FindingBasisObserved}},
		SuspiciousTraffic: make([]models.SuspiciousFlow, 1)}, healthWarning)
	hvLevel(t, "lower stability + 1 handshake failure", &models.TriageReport{
		StabilityFindings: []models.StabilityFinding{{Severity: "Warning"}}, TCPHandshakeFlows: hvFailed(1)}, healthFair)
}

func TestHealth_Deterministic(t *testing.T) {
	r := &models.TriageReport{
		TCPHandshakeFlows:  append(hvFailed(4), hsFlows("SYN", "", 7)...),
		TCPRetransmissions: make([]models.TCPFlow, 2),
		StabilityFindings:  []models.StabilityFinding{{Severity: "High"}, {Severity: "Warning"}},
		Findings:           []models.Finding{{Severity: models.SeverityHigh, Basis: models.EvidenceTimeProximity}},
	}
	first := healthVerdict(r)
	for i := 0; i < 100; i++ {
		if got := healthVerdict(r); got != first {
			t.Fatalf("run %d: %d != %d", i, got, first)
		}
	}
}

// The verdict is a pure function of the report: it must not mutate it.
func TestHealth_DoesNotMutateReport(t *testing.T) {
	r := &models.TriageReport{TCPHandshakeFlows: hvFailed(3), FailedHandshakes: make([]models.TCPFlow, 1)}
	_ = healthVerdict(r)
	if len(r.TCPHandshakeFlows) != 3 || len(r.FailedHandshakes) != 1 {
		t.Error("healthVerdict modified the report")
	}
}

// Formatter integration: each level prints its existing banner string.
func TestHealth_BannerStrings(t *testing.T) {
	cases := []struct {
		name string
		r    *models.TriageReport
		want string
	}{
		{"GOOD", &models.TriageReport{}, "NETWORK HEALTH: GOOD - No significant issues detected"},
		{"FAIR", &models.TriageReport{TCPHandshakeFlows: hvFailed(1)}, "NETWORK HEALTH: FAIR - Minor issues detected"},
		{"WARNING", &models.TriageReport{StabilityFindings: []models.StabilityFinding{{Severity: "High"}}}, "NETWORK HEALTH: WARNING - Issues detected that need review"},
		{"CRITICAL", &models.TriageReport{ARPConflicts: make([]models.ARPConflict, 1)}, "NETWORK HEALTH: CRITICAL - Immediate attention required"},
	}
	for _, tc := range cases {
		out := captureStdout(t, func() { PrintExecutiveSummary(tc.r) })
		if !strings.Contains(out, tc.want) {
			t.Errorf("%s: banner %q not found in:\n%s", tc.name, tc.want, out)
		}
		for _, other := range cases {
			if other.name != tc.name && strings.Contains(out, other.want) {
				t.Errorf("%s: unexpected banner %q", tc.name, other.want)
			}
		}
	}
}
