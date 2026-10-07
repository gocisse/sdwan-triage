package analyzer

import (
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/gocisse/sdwan-triage/pkg/events"
	"github.com/gocisse/sdwan-triage/pkg/models"
)

// Phase 4.6: a RootCauseChain records the exact events the correlator used, and
// its Finding cites exactly that set.

// retransAt emits a retransmission observed at obs whose first transmission was at orig.
func (h *corrHarness) retransAt(flow string, orig, obs time.Time) {
	h.rec.Emit(events.Event{Kind: events.TCPRetransmission, Timestamp: obs, FlowKey: flow, Source: "TCP",
		Values: map[string]float64{"seq": 1, "payload_len": 100, "original_ts_us": float64(orig.UnixMicro())}})
}

// idsOf returns the event IDs cited by refs, sorted.
func idsOf(refs []models.EvidenceRef) []uint64 {
	out := make([]uint64, 0, len(refs))
	for _, r := range refs {
		out = append(out, r.EventID)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// indexIDs returns the IDs of indexed events of kind for which keep is true.
func indexIDs(h *corrHarness, kind events.Kind, keep func(events.Event) bool) []uint64 {
	var out []uint64
	for _, e := range h.report.Events.ByKind(kind) {
		if keep(e) {
			out = append(out, e.ID)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func origOf(e events.Event) time.Time { return time.UnixMicro(int64(e.Values["original_ts_us"])).UTC() }

// legacyEvidenceIDs reproduces the Phase 4.5 reconstruction (removed in 4.6):
// trigger events within ±1 ms of the chain time matching the label, plus
// overlay events on the affected flows observed within 10 s after it.
func legacyEvidenceIDs(report *models.TriageReport, chain models.RootCauseChain) []uint64 {
	ts := time.Unix(0, int64(chain.Timestamp*1e9)).UTC()
	var ids []uint64
	switch {
	case strings.HasPrefix(chain.UnderlayEvent, "BGP "):
		want := strings.TrimPrefix(chain.UnderlayEvent, "BGP ")
		for _, e := range report.Events.ByKindAndTime(events.BGPEvent, ts.Add(-time.Millisecond), ts.Add(time.Millisecond)) {
			if e.Attrs["event_type"] == want {
				ids = append(ids, e.ID)
			}
		}
	case strings.HasPrefix(chain.UnderlayEvent, "BFD "):
		for _, e := range report.Events.ByKindAndTime(events.BFDDown, ts.Add(-time.Millisecond), ts.Add(time.Millisecond)) {
			ids = append(ids, e.ID)
		}
	}
	flows := map[string]bool{}
	for _, f := range chain.AffectedFlows {
		flows[f[:strings.LastIndex(f, " (")]] = true
	}
	for _, e := range report.Events.ByKindAndTime(events.TCPRetransmission, ts, ts.Add(10*time.Second)) {
		if flows[e.FlowKey] {
			ids = append(ids, e.ID)
		}
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	return ids
}

// Scenario: one Withdrawal trigger; flow A has 3 counted retransmissions plus
//   - one whose first send PRECEDES the trigger (observed after it),
//   - one whose first send is OUTSIDE the 5 s window (observed within 10 s);
//
// flow B has a single in-window retransmission (below threshold); a plain
// Update and a different-label Notification sit at the same instant.
func traceabilityHarness() *corrHarness {
	h := newCorrHarness()
	h.bgp(corrBase, "10.0.0.1", "10.0.0.2", "Withdrawal", "w")
	h.bgp(corrBase, "10.0.0.1", "10.0.0.2", "Update", "routine")
	h.bgp(corrBase.Add(500*time.Microsecond), "10.0.0.1", "10.0.0.2", "Notification", "n")
	for i := 0; i < 3; i++ { // counted
		orig := corrBase.Add(time.Duration(1+i) * time.Second)
		h.retransAt(unrelatedFlowA, orig, orig.Add(200*time.Millisecond))
	}
	h.retransAt(unrelatedFlowA, corrBase.Add(-time.Second), corrBase.Add(300*time.Millisecond))   // original before trigger
	h.retransAt(unrelatedFlowA, corrBase.Add(5500*time.Millisecond), corrBase.Add(6*time.Second)) // original after window
	h.retransAt(unrelatedFlowB, corrBase.Add(time.Second), corrBase.Add(1200*time.Millisecond))   // below threshold
	return h
}

func chainByLabel(t *testing.T, chains []models.RootCauseChain, label string) models.RootCauseChain {
	t.Helper()
	for _, c := range chains {
		if c.UnderlayEvent == label {
			return c
		}
	}
	t.Fatalf("no chain for %q in %+v", label, chains)
	return models.RootCauseChain{}
}

func TestTraceability_ChainRecordsExactEvents(t *testing.T) {
	h := traceabilityHarness()
	chains := h.run()
	c := chainByLabel(t, chains, "BGP Withdrawal")

	wantTrigger := indexIDs(h, events.BGPEvent, func(e events.Event) bool { return e.Attrs["event_type"] == "Withdrawal" })
	wantOverlay := indexIDs(h, events.TCPRetransmission, func(e events.Event) bool {
		o := origOf(e)
		return e.FlowKey == unrelatedFlowA && !o.Before(corrBase) && !o.After(corrBase.Add(5*time.Second))
	})
	want := append(append([]uint64{}, wantTrigger...), wantOverlay...)
	sort.Slice(want, func(i, j int) bool { return want[i] < want[j] })

	if len(wantOverlay) != 3 || len(wantTrigger) != 1 {
		t.Fatalf("scenario setup wrong: trigger %v overlay %v", wantTrigger, wantOverlay)
	}
	if got := idsOf(c.Evidence); !reflect.DeepEqual(got, want) || c.EvidenceCount != len(want) {
		t.Errorf("chain evidence IDs = %v (count %d), want %v", got, c.EvidenceCount, want)
	}
}

// The old ±1 ms / +10 s reconstruction produced a different — wrong — set for
// the same chain: it missed nothing here but ADDED the pre-trigger-original and
// out-of-window retransmissions. The Finding now cites exactly the chain's set.
func TestTraceability_OldReconstructionWasIncorrect(t *testing.T) {
	h := traceabilityHarness()
	chains := h.run()
	c := chainByLabel(t, chains, "BGP Withdrawal")

	old := legacyEvidenceIDs(h.report, c)
	exact := idsOf(c.Evidence)
	if reflect.DeepEqual(old, exact) {
		t.Fatalf("scenario does not discriminate: old == exact == %v", exact)
	}
	if len(old) != len(exact)+2 {
		t.Errorf("old reconstruction cited %d events, exact %d (expected 2 extras)", len(old), len(exact))
	}

	var f models.Finding
	for _, x := range BuildFindings(h.report) {
		if x.Kind == findingKindCoOccurrence && strings.HasPrefix(x.Title, "BGP Withdrawal") {
			f = x
		}
	}
	if got := idsOf(f.Evidence); !reflect.DeepEqual(got, exact) {
		t.Errorf("finding evidence %v != chain evidence %v", got, exact)
	}
}

// Coalesced triggers beyond ±1 ms of the chain time were missed by the old
// reconstruction; the chain records every trigger of the episode.
func TestTraceability_CoalescedTriggersAllRecorded(t *testing.T) {
	h := newCorrHarness()
	for i := 0; i < 30; i++ {
		h.bgp(corrBase.Add(time.Duration(i)*100*time.Millisecond), "10.0.0.1", "10.0.0.2", "Withdrawal", "w")
	}
	for i := 0; i < 3; i++ {
		h.retrans(corrBase.Add(time.Duration(1000+i*100)*time.Millisecond), unrelatedFlowA)
	}
	c := chainByLabel(t, h.run(), "BGP Withdrawal")
	if c.EvidenceCount != 33 || len(c.Evidence) != maxEvidenceRefs {
		t.Errorf("evidence %d refs / count %d, want %d / 33", len(c.Evidence), c.EvidenceCount, maxEvidenceRefs)
	}
	if old := legacyEvidenceIDs(h.report, c); len(old) >= 30+3 {
		t.Errorf("expected old reconstruction to miss triggers, cited %d", len(old))
	}
}

func TestTraceability_EvidenceDeterministicAndUnique(t *testing.T) {
	first := chainByLabel(t, traceabilityHarness().run(), "BGP Withdrawal")
	for i := 0; i < 20; i++ {
		again := chainByLabel(t, traceabilityHarness().run(), "BGP Withdrawal")
		if !reflect.DeepEqual(first.Evidence, again.Evidence) || first.EvidenceCount != again.EvidenceCount {
			t.Fatalf("run %d evidence differs", i)
		}
	}
	for i := 1; i < len(first.Evidence); i++ {
		if first.Evidence[i].Timestamp.Before(first.Evidence[i-1].Timestamp) {
			t.Error("evidence not chronological")
		}
	}
	seen := map[uint64]bool{}
	for _, r := range first.Evidence {
		if seen[r.EventID] {
			t.Errorf("duplicate evidence for event %d", r.EventID)
		}
		seen[r.EventID] = true
	}
}

func TestTraceability_DuplicateEventsYieldOneRef(t *testing.T) {
	e := events.Event{ID: 7, Kind: events.TCPRetransmission, Timestamp: corrBase, FlowKey: unrelatedFlowA}
	refs, n := boundedEvidence([]events.Event{e, e, e})
	if len(refs) != 1 || n != 1 {
		t.Errorf("refs %d count %d, want 1/1", len(refs), n)
	}
}

func TestTraceability_FindingMatchesChainExactly(t *testing.T) {
	h := traceabilityHarness()
	h.run()
	for _, c := range h.report.RootCauseChains {
		f := chainFinding(c)
		if !reflect.DeepEqual(f.Evidence, append([]models.EvidenceRef{}, c.Evidence...)) || f.EvidenceCount != c.EvidenceCount {
			t.Errorf("finding evidence != chain evidence for %s", c.UnderlayEvent)
		}
	}
}

// A chain with no recorded evidence yields no evidence: nothing is invented.
func TestTraceability_NoRecordedEvidenceStaysEmpty(t *testing.T) {
	c := models.RootCauseChain{
		Timestamp: float64(corrBase.Unix()), UnderlayEvent: "BGP Withdrawal", OverlayEffect: "TCP Retransmission Burst (co-occurring)",
		AffectedFlows: []string{unrelatedFlowA + " (3 retrans)"}, EvidenceBasis: models.EvidenceTimeProximity, Confidence: "Low", Severity: "Low",
	}
	f := chainFinding(c)
	if f.Evidence == nil || len(f.Evidence) != 0 || f.EvidenceCount != 0 {
		t.Errorf("evidence = %#v count %d, want empty/0", f.Evidence, f.EvidenceCount)
	}
}

// RTT chains cite the trigger and exactly the session-flow spikes used.
func TestTraceability_RTTEvidenceExact(t *testing.T) {
	h := newCorrHarness()
	h.bgp(corrBase, "10.0.0.1", "10.0.0.2", "Notification", "n")
	h.rtt(corrBase.Add(time.Second), bgpSessionFlow, 600)
	h.rtt(corrBase.Add(2*time.Second), bgpSessionFlow, 700)
	h.rtt(corrBase.Add(time.Second), unrelatedFlowA, 900) // unrelated: not used
	c := chainByLabel(t, h.run(), "BGP Notification")

	want := append(indexIDs(h, events.BGPEvent, func(events.Event) bool { return true }),
		indexIDs(h, events.TCPRTTSpike, func(e events.Event) bool { return e.FlowKey == bgpSessionFlow })...)
	sort.Slice(want, func(i, j int) bool { return want[i] < want[j] })
	if c.OverlayEffect != "RTT Spike" || !reflect.DeepEqual(idsOf(c.Evidence), want) || c.EvidenceCount != 3 {
		t.Errorf("RTT chain evidence %v (count %d), want %v", idsOf(c.Evidence), c.EvidenceCount, want)
	}
}

// Recording evidence changes nothing about what the correlator concludes.
func TestTraceability_SemanticsUnchanged(t *testing.T) {
	h := traceabilityHarness()
	chains := h.run()
	c := chainByLabel(t, chains, "BGP Withdrawal")
	if c.EvidenceBasis != models.EvidenceTimeProximity || c.Confidence != "Low" ||
		c.OverlayEffect != "TCP Retransmission Burst (co-occurring)" || len(c.AffectedFlows) != 1 ||
		c.AffectedFlows[0] != unrelatedFlowA+" (3 retrans)" {
		t.Errorf("chain semantics changed: %+v", c)
	}
	for _, f := range BuildFindings(h.report) {
		if f.Kind == findingKindCoOccurrence && f.Confidence != models.ConfidenceLow {
			t.Errorf("co-occurrence finding confidence %s", f.Confidence)
		}
	}
}
