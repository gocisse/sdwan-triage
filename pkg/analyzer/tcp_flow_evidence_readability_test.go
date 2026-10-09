package analyzer

import (
	"encoding/json"
	"fmt"
	"math"
	"strings"
	"testing"

	"github.com/gocisse/sdwan-triage/pkg/models"
)

// Phase 4.31d — presentation of the existing TCP evidence: flow order puts a repeated
// SYN with no observed SYN-ACK first, gap records are listed unresolved → acked_beyond →
// filled before the display bound is applied, repeated-SYN timing and completeness
// explanations are exposed. Nothing here changes detection; the events are the input.

// gapMix builds one connection with: a filled gap, `acked` acked_beyond gaps and one
// final unresolved gap (in that chronological order).
func gapMix(acked int) []seqSpec {
	specs := []seqSpec{
		cData(1001, 100),
		cData(1301, 100), // gap [1101,1301)
		cData(1101, 200), // fills it
	}
	next := uint32(1401)
	for k := 0; k < acked; k++ {
		specs = append(specs, cData(next+100, 100), sAck(next+200, 0)) // gap [next,next+100), then acked beyond
		next += 200
	}
	specs = append(specs, cData(next+100, 100)) // final gap, never filled nor acked beyond
	return specs
}

func TestFlowEvidence_RepeatedSYNWithoutSYNACKListedFirstAndSurvivesFlowBound(t *testing.T) {
	var pk [][]byte
	// 25 richer flows (repeated SYN + gap, handshake completed), earlier in the capture.
	for i := 0; i < 25; i++ {
		pk = append(pk, frames(uint16(fePort+10+i), hs[0], hs[0], hs[1], hs[2], cData(1001, 100), cData(1301, 100))...)
	}
	// One late, single-kind flow: repeated SYN, never answered.
	pk = append(pk, frames(fePort+100, hs[0], hs[0])...)
	s := summaryOf(t, runGolden(t, pk))
	if s.FlowsWithEvidence != 26 || len(s.Flows) != 20 || !s.Truncated {
		t.Fatalf("flows = %d/%d truncated=%v", len(s.Flows), s.FlowsWithEvidence, s.Truncated)
	}
	if !strings.HasSuffix(s.Flows[0].Endpoints, fmt.Sprintf(":%d", fePort+100)) || !s.Flows[0].RepeatedSYNWithoutSYNACK {
		t.Fatalf("unanswered-SYN flow is not first: %+v", s.Flows[0])
	}
	for _, f := range s.Flows[1:] {
		if f.RepeatedSYNWithoutSYNACK {
			t.Errorf("flow %s wrongly flagged", f.Endpoints)
		}
	}
	// The remaining flows keep the volume order (all two-kind flows; earliest first).
	if !strings.HasSuffix(s.Flows[1].Endpoints, fmt.Sprintf(":%d", fePort+10)) {
		t.Errorf("second flow = %s", s.Flows[1].Endpoints)
	}
	if !strings.Contains(s.Order, "no observed SYN-ACK first") || !strings.Contains(s.Order, "not a severity ranking") {
		t.Errorf("order explanation = %q", s.Order)
	}
}

func TestFlowEvidence_SYNACKObservedFlowIsNotPrioritised(t *testing.T) {
	var pk [][]byte
	pk = append(pk, frames(fePort+1, hs[0], hs[0], hs[1], hs[2])...) // answered
	pk = append(pk, frames(fePort+2, hs[0], hs[0], hs[0], hs[0])...) // unanswered, 3 repeats
	s := summaryOf(t, runGolden(t, pk))
	if !s.Flows[0].RepeatedSYNWithoutSYNACK || !strings.HasSuffix(s.Flows[0].Endpoints, ":57002") {
		t.Errorf("order = %+v", s.Flows)
	}
	if s.Flows[1].RepeatedSYNWithoutSYNACK {
		t.Error("answered flow flagged")
	}
}

func TestFlowEvidence_UnresolvedGapsSurviveTheRecordBound(t *testing.T) {
	r := sc(t, fePort, gapMix(12)...) // 1 filled, 12 acked_beyond, 1 unresolved = 14 > 10
	f := summaryOf(t, r).Flows[0]
	if len(f.SequenceGaps) != tcpFlowEvidenceMaxRecordsPerKind {
		t.Fatalf("shown gaps = %d", len(f.SequenceGaps))
	}
	if f.SequenceGaps[0].Resolution != "unresolved" {
		t.Fatalf("first record = %+v (an early acked_beyond hid the unresolved gap)", f.SequenceGaps[0])
	}
	var lastFrame uint64
	for i, g := range f.SequenceGaps[1:] {
		if g.Resolution != "acked_beyond" {
			t.Errorf("record %d = %q, want acked_beyond before filled", i+1, g.Resolution)
		}
		if g.Frame <= lastFrame {
			t.Errorf("acked_beyond records are not chronological: %d after %d", g.Frame, lastFrame)
		}
		lastFrame = g.Frame
	}
	want := models.GapResolutionCounts{Total: 14, Unresolved: 1, AckedBeyond: 12, Filled: 1}
	if f.GapResolutions == nil || *f.GapResolutions != want {
		t.Errorf("flow tally = %+v, want %+v", f.GapResolutions, want)
	}
	if f.Omitted == nil || f.Omitted.SequenceGaps != 4 {
		t.Errorf("omitted = %+v, want 4 gap records omitted", f.Omitted)
	}
	// The omitted ones are the filled gap and the latest acked_beyond ones, never the unresolved one.
	for _, g := range f.SequenceGaps {
		if g.Resolution == "filled" {
			t.Error("filled gap listed ahead of acked_beyond records")
		}
	}
}

func TestFlowEvidence_GapOrderingIsDisplayOnly(t *testing.T) {
	r := sc(t, fePort, gapMix(12)...)
	// Event IDs, kinds and count of the gap events are whatever the detector produced.
	gapEvents := r.Events.ByKind("tcp.sequence_gap")
	if len(gapEvents) != 14 {
		t.Fatalf("gap events = %d", len(gapEvents))
	}
	for i := 1; i < len(gapEvents); i++ {
		if gapEvents[i].ID <= gapEvents[i-1].ID {
			t.Error("event order/IDs changed")
		}
	}
	// A gap's JSON record is a faithful copy of its event.
	var shown *models.SequenceGapEvidence
	f := r.TCPFlowEvidence.Flows[0]
	for i := range f.SequenceGaps {
		if f.SequenceGaps[i].Resolution == "unresolved" {
			shown = &f.SequenceGaps[i]
		}
	}
	var ev = gapEvents[len(gapEvents)-1]
	if shown == nil || shown.GapStart != uint64(ev.Values["gap_start"]) || shown.Frame != eventFrame(ev, 0) {
		t.Errorf("record %+v does not match event %+v", shown, ev)
	}
}

func TestFlowEvidence_CaptureWideGapSummaryIsQuantitativeAndCautious(t *testing.T) {
	g := summaryOf(t, sc(t, fePort, gapMix(12)...)).SequenceGaps
	want := models.GapResolutionCounts{Total: 14, Unresolved: 1, AckedBeyond: 12, Filled: 1}
	if g == nil || g.GapResolutionCounts != want {
		t.Fatalf("summary = %+v", g)
	}
	for _, must := range []string{"Of 14 recorded", "1 unresolved, 12 acked_beyond, 1 filled", "did not observe the range before the peer acknowledged beyond it", "does not by itself show where, or whether, packets were lost"} {
		if !strings.Contains(g.Note, must) {
			t.Errorf("note lacks %q: %s", must, g.Note)
		}
	}
	// The note may NEGATE a loss claim ("does not ... show ... whether packets were lost"); it must not assert one.
	asserted := strings.ReplaceAll(strings.ToLower(g.Note), "does not by itself show where, or whether, packets were lost", "")
	for _, banned := range []string{"capture dropped", "capture is missing", "provider", "confirmed", "was lost", "were lost"} {
		if strings.Contains(asserted, banned) {
			t.Errorf("note contains %q: %s", banned, g.Note)
		}
	}
	// Without acked_beyond records the acked_beyond explanation is absent; without gaps there is no summary.
	only := summaryOf(t, sc(t, fePort, cData(1001, 100), cData(1301, 100))).SequenceGaps
	if only == nil || only.AckedBeyond != 0 || strings.Contains(only.Note, "acknowledged beyond") {
		t.Errorf("unresolved-only summary = %+v", only)
	}
	if s := summaryOf(t, runGolden(t, frames(fePort, hs[0], hs[0]))); s.SequenceGaps != nil {
		t.Errorf("gap summary without gaps: %+v", s.SequenceGaps)
	}
}

func TestFlowEvidence_RepeatedSYNIntervalIsExposed(t *testing.T) {
	f := summaryOf(t, runGolden(t, frames(fePort, hs[0], hs[0], hs[0]))).Flows[0]
	for i, h := range f.RepeatedHandshake {
		if math.Abs(h.SincePreviousMs-100) > 1 {
			t.Errorf("record %d since_previous_ms = %v, want ~100", i, h.SincePreviousMs)
		}
		if !strings.Contains(h.Description, "100 ms after the previous one") || !strings.Contains(h.Description, "No SYN-ACK was observed for this address/port pair") {
			t.Errorf("description = %q", h.Description)
		}
		if strings.Contains(strings.ToLower(h.Description), "retransmi") {
			t.Errorf("a repeat must not be labelled a retransmission: %q", h.Description)
		}
	}
	if math.Abs(f.RepeatedHandshake[1].SinceFirstMs-200) > 1 {
		t.Errorf("since_first_ms = %v", f.RepeatedHandshake[1].SinceFirstMs)
	}
	// The value is the event's own; a repeat after an observed SYN-ACK keeps both facts.
	w := summaryOf(t, runGolden(t, frames(fePort, hs[0], hs[1], hs[0]))).Flows[0].RepeatedHandshake[0]
	if w.SYNACKObserved == nil || !*w.SYNACKObserved || !strings.Contains(w.Description, "A SYN-ACK was observed for this address/port pair") || !strings.Contains(w.Description, "200 ms after the previous one") {
		t.Errorf("repeat after SYN-ACK = %+v", w)
	}
}

func TestFmtInterval(t *testing.T) {
	for in, want := range map[float64]string{0: "less than 1 ms", 0.4: "less than 1 ms", 1: "1.0 ms", 12.34: "12.3 ms", 99.9: "99.9 ms", 100: "100 ms", 1000.4: "1000 ms"} {
		if got := fmtInterval(in); got != want {
			t.Errorf("fmtInterval(%v) = %q, want %q", in, got, want)
		}
	}
}

func TestFlowEvidence_CompletenessDetailsExplainCountersAndKeepJSONObject(t *testing.T) {
	r := runGolden(t, append(frames(fePort, hs[0], hs[0]), frames(fePort+1, srvAck(1101, 100), srvAck(1101, 100), srvAck(1101, 100))...))
	s := summaryOf(t, r)
	var d *models.CompletenessDetail
	for i := range s.CompletenessDetails {
		if s.CompletenessDetails[i].Name == "duplicate_ack_repeats_peer_position_unknown" {
			d = &s.CompletenessDetails[i]
		}
	}
	if d == nil || d.Category != "tracking_limit" || d.Count < 1 {
		t.Fatalf("details = %+v", s.CompletenessDetails)
	}
	for _, must := range []string{"could not be classified as duplicate ACKs", "peer's sequence position was not available", "unknown"} {
		if !strings.Contains(d.Meaning, must) {
			t.Errorf("meaning lacks %q: %s", must, d.Meaning)
		}
	}
	// The machine-readable object keeps its field name and count.
	b, _ := json.Marshal(r.TCPEvidenceCompleteness)
	if !strings.Contains(string(b), `"duplicate_ack_repeats_peer_position_unknown":`+fmt.Sprint(d.Count)) {
		t.Errorf("completeness JSON = %s", b)
	}
	// A clean capture has no details.
	if c := summaryOf(t, sc(t, fePort, cData(1001, 100), cData(1301, 100))); len(c.CompletenessDetails) != 0 {
		t.Errorf("details on a clean capture: %+v", c.CompletenessDetails)
	}
}

func TestFlowEvidence_ReadabilityOrderingIsDeterministic(t *testing.T) {
	var first string
	for i := 0; i < 4; i++ {
		var pk [][]byte
		pk = append(pk, frames(fePort+1, hs[0], hs[0], hs[1], hs[2])...)
		pk = append(pk, frames(fePort+2, hs[0], hs[0])...)
		pk = append(pk, append(frames(fePort+3, hs...), frames(fePort+3, gapMix(12)[3:]...)...)...)
		b, _ := json.Marshal(summaryOf(t, runGolden(t, pk)))
		if i == 0 {
			first = string(b)
		} else if string(b) != first {
			t.Fatalf("run %d differs", i)
		}
	}
}

// Phase 4.31f — the SYN-ACK fact is keyed by address/port pair only (no attempt matching),
// so the text must say so. Reusing a four-tuple (case A of the 4.31e audit) is the case
// where the wording matters: the later, unanswered attempt reads "answered" by tuple, and
// the text must not claim the SYN-ACK belongs to this attempt or connection.
func TestFlowEvidence_SYNACKWordingIsTupleScoped(t *testing.T) {
	cases := map[string][]seqSpec{
		"unanswered": {hs[0], hs[0], hs[0]},
		"answered":   {hs[0], hs[0], hs[1], hs[2]},
		"tuple reuse (earlier connection answered, later attempt not)": {
			hs[0], hs[1], hs[2], {seq: 1001, ack: 5001, flags: 0x01 | 0x10}, // FIN|ACK ends the first connection
			{seq: 7000, flags: 0x02}, {seq: 7000, flags: 0x02}, {seq: 7000, flags: 0x02},
		},
	}
	for name, specs := range cases {
		f := summaryOf(t, runGolden(t, frames(fePort, specs...))).Flows[0]
		if len(f.RepeatedHandshake) == 0 {
			t.Fatalf("%s: no repeated handshake records", name)
		}
		for _, h := range f.RepeatedHandshake {
			d := h.Description
			if strings.Contains(d, "for this connection") || strings.Contains(strings.ToLower(d), "matched to this connection") {
				t.Errorf("%s: description claims connection-level evidence: %s", name, d)
			}
			switch {
			case h.SYNACKObserved != nil && *h.SYNACKObserved:
				for _, must := range []string{"A SYN-ACK was observed for this address/port pair in this capture", "not matched to this attempt", "may precede or follow this repeat"} {
					if !strings.Contains(d, must) {
						t.Errorf("%s: answered text lacks %q: %s", name, must, d)
					}
				}
			default:
				if !strings.Contains(d, "No SYN-ACK was observed for this address/port pair in this capture.") {
					t.Errorf("%s: unanswered text = %s", name, d)
				}
				// Absence from the capture is not presented as proof of non-response.
				for _, banned := range []string{"did not respond", "never sent", "no response", "unreachable", "dropped"} {
					if strings.Contains(strings.ToLower(d), banned) {
						t.Errorf("%s: unanswered text overreaches (%q): %s", name, banned, d)
					}
				}
			}
		}
	}
	// JSON semantics unchanged: tuple reuse still reports the tuple-level fact.
	reuse := summaryOf(t, runGolden(t, frames(fePort, cases["tuple reuse (earlier connection answered, later attempt not)"]...))).Flows[0]
	if reuse.RepeatedSYNWithoutSYNACK || reuse.RepeatedHandshake[0].SYNACKObserved == nil || !*reuse.RepeatedHandshake[0].SYNACKObserved {
		t.Errorf("tuple-level semantics changed: %+v", reuse)
	}
}
