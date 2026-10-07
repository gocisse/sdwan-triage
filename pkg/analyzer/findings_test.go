package analyzer

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/gocisse/sdwan-triage/internal/testpcap"
	"github.com/gocisse/sdwan-triage/pkg/events"
	"github.com/gocisse/sdwan-triage/pkg/models"
)

// Phase 4.5: Findings are assembled from Events and RootCauseChains only.

func buildHarnessFindings(h *corrHarness) []models.Finding {
	NewUnderlayOverlayCorrelator().Finalize(h.report)
	return BuildFindings(h.report)
}

// scenario used for determinism: BGP session + unrelated flow + a loose flow.
func determinismHarness() *corrHarness {
	h := newCorrHarness()
	h.bgp(corrBase, "10.0.0.1", "10.0.0.2", "Withdrawal", "w")
	for i := 0; i < 6; i++ {
		h.retrans(corrBase.Add(time.Duration(i*100)*time.Millisecond), bgpSessionFlow)
		h.retrans(corrBase.Add(time.Duration(i*100)*time.Millisecond), unrelatedFlowA)
	}
	h.retrans(corrBase, unrelatedFlowB)
	return h
}

func TestFindings_DeterministicIDsAndOrder(t *testing.T) {
	first := buildHarnessFindings(determinismHarness())
	if len(first) == 0 {
		t.Fatal("expected findings")
	}
	for i := 0; i < 20; i++ {
		if again := buildHarnessFindings(determinismHarness()); !reflect.DeepEqual(first, again) {
			t.Fatalf("run %d differs:\n%+v\n%+v", i, first, again)
		}
	}
	for i := 1; i < len(first); i++ {
		a, b := first[i-1], first[i]
		if b.FirstSeen.Before(a.FirstSeen) || (a.FirstSeen.Equal(b.FirstSeen) && (b.Kind < a.Kind || (b.Kind == a.Kind && b.ID < a.ID))) {
			t.Errorf("findings not ordered by (FirstSeen, Kind, ID): %s then %s", a.ID, b.ID)
		}
	}
	seen := map[string]bool{}
	for _, f := range first {
		if seen[f.ID] {
			t.Errorf("duplicate finding ID %s", f.ID)
		}
		seen[f.ID] = true
	}
}

func TestFindings_CleanCaptureHasNone(t *testing.T) {
	r := runGolden(t, testpcap.Handshake())
	if len(r.Findings) != 0 {
		t.Errorf("clean handshake produced findings: %+v", r.Findings)
	}
}

func TestFindings_EmptyReportHasNone(t *testing.T) {
	if f := BuildFindings(&models.TriageReport{}); f != nil {
		t.Errorf("expected nil, got %+v", f)
	}
}

// End to end: PACKET → EVENT → CORRELATION → FINDING on the BGP storm fixture.
func TestFindings_BGPStormEndToEnd(t *testing.T) {
	r := runGolden(t, testpcap.BGPWithdrawalStorm())
	if len(r.RootCauseChains) != 1 {
		t.Fatalf("fixture should yield 1 chain, got %d", len(r.RootCauseChains))
	}
	var chainF, retxF []models.Finding
	for _, f := range r.Findings {
		switch f.Kind {
		case findingKindCoOccurrence, findingKindSameSession:
			chainF = append(chainF, f)
		case findingKindRetransmissions:
			retxF = append(retxF, f)
		}
	}
	if len(chainF) != 1 {
		t.Fatalf("exactly one Finding per RootCauseChain expected, got %+v", chainF)
	}
	c := chainF[0]
	if c.Kind != findingKindCoOccurrence || c.Basis != models.EvidenceTimeProximity || c.Confidence != models.ConfidenceLow {
		t.Errorf("unexpected chain finding %+v", c)
	}
	// Evidence: the BGP trigger plus the retransmissions on the affected flow.
	if c.EvidenceCount != 6 || len(c.Evidence) != 6 || c.Evidence[0].Kind != "bgp.event" {
		t.Errorf("chain evidence = %d/%d, first %+v", c.EvidenceCount, len(c.Evidence), c.Evidence)
	}
	if len(retxF) != 1 || retxF[0].EvidenceCount != 5 || retxF[0].Basis != models.FindingBasisObserved {
		t.Errorf("retransmission findings = %+v", retxF)
	}
	if retxF[0].Severity != models.SeverityLow || retxF[0].Confidence != models.ConfidenceMedium {
		t.Errorf("5 events should be Low/Medium, got %s/%s", retxF[0].Severity, retxF[0].Confidence)
	}
	// Legacy fields untouched by Finding construction.
	if len(r.TCPRetransmissions) != 1 {
		t.Errorf("legacy TCPRetransmissions changed: %d", len(r.TCPRetransmissions))
	}
	// Every cited event exists in the index.
	assertEvidenceTraceable(t, r.Events, r.Findings)
}

func assertEvidenceTraceable(t *testing.T, ix *events.Index, findings []models.Finding) {
	t.Helper()
	for _, f := range findings {
		if len(f.Evidence) > maxEvidenceRefs {
			t.Errorf("%s: %d evidence refs exceed bound", f.ID, len(f.Evidence))
		}
		if f.EvidenceCount < len(f.Evidence) {
			t.Errorf("%s: EvidenceCount %d < refs %d", f.ID, f.EvidenceCount, len(f.Evidence))
		}
		for _, ref := range f.Evidence {
			found := false
			for _, e := range ix.ByKind(events.Kind(ref.Kind)) {
				if e.Timestamp.Equal(ref.Timestamp) && e.FlowKey == ref.FlowKey && e.ID == ref.EventID {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("%s: evidence %+v matches no indexed event", f.ID, ref)
			}
		}
	}
}

func TestFindings_TimeProximityStaysLowAndNonCausal(t *testing.T) {
	h := newCorrHarness()
	h.bfdDown(corrBase, "10.0.0.1", "10.0.0.2")
	for i := 0; i < 25; i++ { // large enough that the chain's own severity is Critical
		h.retrans(corrBase.Add(time.Duration(i*50)*time.Millisecond), unrelatedFlowA)
	}
	h.run()
	if len(h.report.RootCauseChains) != 1 || h.report.RootCauseChains[0].Severity != "Critical" {
		t.Fatalf("setup: expected one Critical chain, got %+v", h.report.RootCauseChains)
	}
	fs := BuildFindings(h.report)
	var f models.Finding
	for _, x := range fs {
		if x.Kind == findingKindCoOccurrence {
			f = x
		}
	}
	if f.ID == "" {
		t.Fatalf("no co-occurrence finding in %+v", fs)
	}
	if f.Confidence != models.ConfidenceLow || f.Basis != models.EvidenceTimeProximity {
		t.Errorf("confidence/basis = %s/%s", f.Confidence, f.Basis)
	}
	if f.Severity != models.SeverityMedium {
		t.Errorf("co-occurrence severity must be capped at Medium, got %s", f.Severity)
	}
	low := strings.ToLower(f.Title + " " + f.Summary)
	for _, bad := range []string{"caused", "triggered", "root cause", "due to"} {
		if strings.Contains(low, bad) {
			t.Errorf("causal wording %q in %q", bad, low)
		}
	}
	if !strings.Contains(f.Summary, "no causal relationship is claimed") {
		t.Errorf("summary = %q", f.Summary)
	}
}

func TestFindings_SameSessionKeepsStrongerBasis(t *testing.T) {
	h := newCorrHarness()
	h.bgp(corrBase, "10.0.0.1", "10.0.0.2", "Notification", "BGP NOTIFICATION")
	for i := 0; i < 12; i++ {
		h.retrans(corrBase.Add(time.Duration(i*50)*time.Millisecond), bgpSessionFlow)
	}
	var f models.Finding
	for _, x := range buildHarnessFindings(h) {
		if x.Kind == findingKindSameSession {
			f = x
		}
	}
	if f.ID == "" {
		t.Fatal("no same_session finding")
	}
	if f.Basis != models.EvidenceSameSession || f.Confidence != models.ConfidenceHigh || f.Severity != models.SeverityHigh {
		t.Errorf("basis/confidence/severity = %s/%s/%s", f.Basis, f.Confidence, f.Severity)
	}
	if f.EvidenceCount != 13 { // trigger + 12 retransmissions
		t.Errorf("EvidenceCount = %d", f.EvidenceCount)
	}
	assertEvidenceTraceable(t, h.report.Events, []models.Finding{f})
}

// The retransmission Finding counts Events (segments), not len(TCPRetransmissions)
// (distinct flows): the legacy slice is deliberately given a misleading length.
func TestFindings_RetransmissionUsesEventsNotLegacySlice(t *testing.T) {
	h := newCorrHarness()
	for i := 0; i < 5; i++ {
		h.retrans(corrBase.Add(time.Duration(i)*time.Second), unrelatedFlowA)
	}
	h.retrans(corrBase, unrelatedFlowB)
	h.retrans(corrBase, unrelatedFlowB) // 2 events: below the rule
	h.report.TCPRetransmissions = make([]models.TCPFlow, 40)

	fs := BuildFindings(h.report)
	if len(fs) != 1 {
		t.Fatalf("expected exactly one finding, got %+v", fs)
	}
	f := fs[0]
	if f.Kind != findingKindRetransmissions || f.EvidenceCount != 5 || !strings.Contains(f.Title, unrelatedFlowA) {
		t.Errorf("unexpected finding %+v", f)
	}
	if !strings.HasPrefix(f.Summary, "5 retransmitted segments") {
		t.Errorf("summary = %q", f.Summary)
	}
}

func TestFindings_RetransmissionSeverityConfidenceTable(t *testing.T) {
	cases := []struct {
		n    int
		sev  models.Severity
		conf models.Confidence
	}{
		{2, "", ""}, {3, models.SeverityLow, models.ConfidenceMedium}, {9, models.SeverityLow, models.ConfidenceMedium},
		{10, models.SeverityMedium, models.ConfidenceHigh}, {99, models.SeverityMedium, models.ConfidenceHigh},
		{100, models.SeverityHigh, models.ConfidenceHigh},
	}
	for _, tc := range cases {
		t.Run(fmt.Sprint(tc.n), func(t *testing.T) {
			h := newCorrHarness()
			for i := 0; i < tc.n; i++ {
				h.retrans(corrBase.Add(time.Duration(i)*time.Millisecond), unrelatedFlowA)
			}
			fs := BuildFindings(h.report)
			if tc.sev == "" {
				if len(fs) != 0 {
					t.Fatalf("expected none, got %+v", fs)
				}
				return
			}
			if len(fs) != 1 || fs[0].Severity != tc.sev || fs[0].Confidence != tc.conf {
				t.Errorf("got %+v, want %s/%s", fs, tc.sev, tc.conf)
			}
		})
	}
}

func TestFindings_EvidenceBounded(t *testing.T) {
	h := newCorrHarness()
	for i := 0; i < 150; i++ {
		h.retrans(corrBase.Add(time.Duration(i)*time.Millisecond), unrelatedFlowA)
	}
	fs := BuildFindings(h.report)
	if len(fs) != 1 {
		t.Fatalf("got %+v", fs)
	}
	f := fs[0]
	if len(f.Evidence) != maxEvidenceRefs || f.EvidenceCount != 150 {
		t.Errorf("evidence %d / count %d", len(f.Evidence), f.EvidenceCount)
	}
	for i := 1; i < len(f.Evidence); i++ {
		if f.Evidence[i].Timestamp.Before(f.Evidence[i-1].Timestamp) {
			t.Error("evidence not chronological")
		}
	}
	assertEvidenceTraceable(t, h.report.Events, fs)
}

func TestFindings_NoDuplicates(t *testing.T) {
	h := newCorrHarness()
	h.bgp(corrBase, "10.0.0.1", "10.0.0.2", "Withdrawal", "w")
	for i := 0; i < 4; i++ {
		h.retrans(corrBase.Add(time.Duration(i*100)*time.Millisecond), unrelatedFlowA)
	}
	NewUnderlayOverlayCorrelator().Finalize(h.report)
	// An accidental duplicate chain must not yield a duplicate Finding.
	h.report.RootCauseChains = append(h.report.RootCauseChains, h.report.RootCauseChains[0])
	fs := BuildFindings(h.report)
	ids := map[string]int{}
	for _, f := range fs {
		ids[f.ID]++
	}
	for id, n := range ids {
		if n != 1 {
			t.Errorf("finding %s appears %d times", id, n)
		}
	}
	if len(fs) != 2 { // one chain finding + one retransmission finding
		t.Errorf("expected 2 findings, got %d", len(fs))
	}
}

// Findings are additive: building them must not alter chains or legacy fields.
func TestFindings_DoNotMutateChains(t *testing.T) {
	h := determinismHarness()
	NewUnderlayOverlayCorrelator().Finalize(h.report)
	before := append([]models.RootCauseChain(nil), h.report.RootCauseChains...)
	_ = BuildFindings(h.report)
	if !reflect.DeepEqual(before, h.report.RootCauseChains) {
		t.Error("BuildFindings modified RootCauseChains")
	}
}
