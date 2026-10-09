package output

import (
	"bytes"
	"fmt"
	"regexp"
	"strings"
	"testing"

	"github.com/gocisse/sdwan-triage/pkg/models"
)

// Phase 4.31b: CLI section of the per-flow TCP evidence summary.

func cliText(r *models.TriageReport) string {
	var b bytes.Buffer
	WriteTCPFlowEvidence(&b, r)
	return b.String()
}

func flowWith(i int, gaps, runs, syns int) models.TCPFlowEvidence {
	f := models.TCPFlowEvidence{Endpoints: fmt.Sprintf("10.0.0.1:%d <-> 10.0.0.2:443", 40000+i), EvidenceKinds: []string{"sequence_gap"}}
	for k := 0; k < gaps; k++ {
		f.SequenceGaps = append(f.SequenceGaps, models.SequenceGapEvidence{Frame: uint64(10 + k), Description: fmt.Sprintf("GAP-%d-%d", i, k)})
	}
	for k := 0; k < runs; k++ {
		f.DuplicateACKRuns = append(f.DuplicateACKRuns, models.DuplicateACKRunEvidence{FirstFrame: uint64(100 + k), LastFrame: uint64(103 + k), Description: fmt.Sprintf("RUN-%d-%d", i, k)})
	}
	for k := 0; k < syns; k++ {
		f.RepeatedHandshake = append(f.RepeatedHandshake, models.RepeatedHandshakeEvidence{Frame: uint64(5 + k), Description: fmt.Sprintf("SYN-%d-%d", i, k)})
	}
	return f
}

func TestFlowEvidenceCLI_NothingWithoutSummary(t *testing.T) {
	if got := cliText(&models.TriageReport{}); got != "" {
		t.Errorf("output without a summary: %q", got)
	}
	if got := cliText(&models.TriageReport{TCPFlowEvidence: &models.TCPFlowEvidenceSummary{}}); got != "" {
		t.Errorf("output for an empty summary: %q", got)
	}
}

func TestFlowEvidenceCLI_ShowsRecordsWithFramesAndNeutralFraming(t *testing.T) {
	f := flowWith(1, 1, 1, 1)
	f.EvidenceKinds = []string{"duplicate_ack_run", "repeated_handshake", "sequence_gap"}
	f.RepeatedSegments = &models.RepeatedSegmentEvidence{Count: 2, Frames: []uint64{7, 9}, Description: "REPS"}
	r := &models.TriageReport{TCPFlowEvidence: &models.TCPFlowEvidenceSummary{FlowsWithEvidence: 1, FlowsShown: 1, Flows: []models.TCPFlowEvidence{f}}}
	out := cliText(r)
	for _, want := range []string{
		"TCP EVIDENCE (observations from this capture; not a statement about where or whether packets were lost)",
		"Frame numbers are capture frame numbers; sequence numbers are absolute",
		"Flow 10.0.0.1:40001 <-> 10.0.0.2:443  [duplicate_ack_run, repeated_handshake, sequence_gap]",
		"- REPS (frames 7, 9)", "- SYN-1-0 (frame 5)", "- GAP-1-0 (frame 10)", "- RUN-1-0 (frames 100-103)",
		"an absence of listed evidence does not show that nothing happened",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "Display limited") || strings.Contains(out, "could not be tracked") {
		t.Errorf("caveats shown without a reason:\n%s", out)
	}
	if !strings.HasSuffix(out, "\n\n") {
		t.Error("section should end with a blank line so it is self-delimited")
	}
}

func TestFlowEvidenceCLI_CompletenessCaveatOnlyWhenAffected(t *testing.T) {
	mk := func(affected bool) *models.TriageReport {
		return &models.TriageReport{TCPFlowEvidence: &models.TCPFlowEvidenceSummary{FlowsWithEvidence: 1, FlowsShown: 1, CompletenessAffected: affected,
			Flows: []models.TCPFlowEvidence{flowWith(1, 1, 0, 0)}}}
	}
	if !strings.Contains(cliText(mk(true)), "Some TCP evidence could not be tracked or was omitted; see completeness details (tcp_evidence_completeness") {
		t.Error("caveat missing for an affected capture")
	}
	if strings.Contains(cliText(mk(false)), "could not be tracked") {
		t.Error("caveat shown for an unaffected capture")
	}
}

func TestFlowEvidenceCLI_DisplayBoundsAndTruncationNoticesAreVisible(t *testing.T) {
	var flows []models.TCPFlowEvidence
	for i := 0; i < 14; i++ {
		flows = append(flows, flowWith(i, 5, 0, 0)) // 5 gap records each
	}
	s := &models.TCPFlowEvidenceSummary{FlowsWithEvidence: 14, FlowsShown: 14, Flows: flows}
	out := cliText(&models.TriageReport{TCPFlowEvidence: s})
	if strings.Count(out, "  Flow ") != 10 {
		t.Errorf("flows shown = %d, want the CLI bound of 10", strings.Count(out, "  Flow "))
	}
	if strings.Count(out, "GAP-0-") != 3 || !strings.Contains(out, "... 2 more record(s) for this flow in the JSON report") {
		t.Errorf("per-kind bound / overflow note wrong:\n%s", out)
	}
	if !strings.Contains(out, "Display limited: showing 10 of 14 flows with evidence") {
		t.Errorf("truncation notice missing:\n%s", out)
	}
	// JSON-level truncation is reported as well, even when the CLI shows everything it has.
	s2 := &models.TCPFlowEvidenceSummary{FlowsWithEvidence: 25, FlowsShown: 1, Truncated: true, OmittedFlows: 24, OmittedRecords: 30,
		Flows: []models.TCPFlowEvidence{flowWith(1, 1, 0, 0)}}
	out2 := cliText(&models.TriageReport{TCPFlowEvidence: s2})
	if !strings.Contains(out2, "showing 1 of 25 flows") || !strings.Contains(out2, "24 flows omitted, 30 records omitted") {
		t.Errorf("JSON truncation not reported:\n%s", out2)
	}
	// Records already omitted by the JSON bound are counted in the per-flow note.
	f := flowWith(1, 2, 0, 0)
	f.Omitted = &models.TCPFlowEvidenceOmitted{SequenceGaps: 4}
	out3 := cliText(&models.TriageReport{TCPFlowEvidence: &models.TCPFlowEvidenceSummary{FlowsWithEvidence: 1, FlowsShown: 1, Truncated: true, OmittedRecords: 4, Flows: []models.TCPFlowEvidence{f}}})
	if !strings.Contains(out3, "... 4 more record(s) for this flow in the JSON report") {
		t.Errorf("omitted records not counted:\n%s", out3)
	}
}

func TestFlowEvidenceCLI_DeterministicAndFreeOfUnsupportedClaims(t *testing.T) {
	var flows []models.TCPFlowEvidence
	for i := 0; i < 4; i++ {
		flows = append(flows, flowWith(i, 2, 1, 1))
	}
	r := &models.TriageReport{TCPFlowEvidence: &models.TCPFlowEvidenceSummary{FlowsWithEvidence: 4, FlowsShown: 4, CompletenessAffected: true, Flows: flows}}
	first := cliText(r)
	for i := 0; i < 5; i++ {
		if cliText(r) != first {
			t.Fatal("CLI output is not deterministic")
		}
	}
	// The framing text (not the injected descriptions) must not make unsupported claims.
	l := strings.ToLower(strings.ReplaceAll(first, "where or whether packets were lost", ""))
	for _, banned := range []string{`\bprovider\b`, `\bdropped\b`, `fast retransmit`, `\bconfirmed\b`, `\bfault\b`, `no packet loss`, `tunnel is`} {
		if regexp.MustCompile(banned).MatchString(l) {
			t.Errorf("output contains %q", banned)
		}
	}
}

// The existing summary text is untouched by the new section.
func TestFlowEvidenceCLI_DoesNotChangeTheFindingsSummary(t *testing.T) {
	a := summaryText(&models.TriageReport{})
	b := summaryText(&models.TriageReport{TCPFlowEvidence: &models.TCPFlowEvidenceSummary{FlowsWithEvidence: 1, FlowsShown: 1, Flows: []models.TCPFlowEvidence{flowWith(1, 1, 0, 0)}}})
	if a != b {
		t.Error("the findings summary changed because a flow-evidence summary exists")
	}
}

// ─── Phase 4.31d: readability ───────────────────────────────────────────

func TestFlowEvidenceCLI_CompletenessDetailsAreExplainedAndCaptureWide(t *testing.T) {
	r := &models.TriageReport{TCPFlowEvidence: &models.TCPFlowEvidenceSummary{
		FlowsWithEvidence: 1, FlowsShown: 1, CompletenessAffected: true,
		CompletenessDetails: []models.CompletenessDetail{
			{Name: "duplicate_ack_repeats_peer_position_unknown", Category: "tracking_limit", Count: 50, Meaning: "50 repeated ACK(s) could not be classified. The number of events possibly missed is unknown."},
			{Name: "tcp.sequence_gap/kind_cap", Category: "omitted_events", Count: 2, Meaning: "2 sequence_gap event(s) were detected but not kept."},
		},
		Flows: []models.TCPFlowEvidence{flowWith(1, 1, 0, 0)},
	}}
	out := cliText(r)
	for _, must := range []string{
		"duplicate_ack_repeats_peer_position_unknown [tracking limit]: 50 repeated ACK(s) could not be classified. The number of events possibly missed is unknown.",
		"tcp.sequence_gap/kind_cap [omitted]: 2 sequence_gap",
		"capture-wide; they do not necessarily affect every flow",
	} {
		if !strings.Contains(out, must) {
			t.Errorf("missing %q in:\n%s", must, out)
		}
	}
	// Unaffected: neither the caveat nor the capture-wide sentence.
	r.TCPFlowEvidence.CompletenessAffected, r.TCPFlowEvidence.CompletenessDetails = false, nil
	if o := cliText(r); strings.Contains(o, "capture-wide") || strings.Contains(o, "tracking limit") {
		t.Errorf("completeness text for an unaffected capture:\n%s", o)
	}
}

func TestFlowEvidenceCLI_OrderingGapSummaryAndPerFlowTally(t *testing.T) {
	f := flowWith(1, 5, 0, 1)
	f.GapResolutions = &models.GapResolutionCounts{Total: 514, Unresolved: 2, AckedBeyond: 500, Filled: 12}
	r := &models.TriageReport{TCPFlowEvidence: &models.TCPFlowEvidenceSummary{
		FlowsWithEvidence: 1, FlowsShown: 1,
		SequenceGaps: &models.SequenceGapSummary{GapResolutionCounts: models.GapResolutionCounts{Total: 514, Unresolved: 2, AckedBeyond: 500, Filled: 12}},
		Flows:        []models.TCPFlowEvidence{f},
	}}
	out := cliText(r)
	for _, must := range []string{
		"Listing order is for display only, not severity",
		"repeated SYN and no observed SYN-ACK first",
		"Sequence gaps (all recorded): 2 unresolved, 500 acked_beyond, 12 filled (514 total).",
		"did not observe the range before the peer acknowledged beyond it",
		"does not by itself show where, or whether, packets were lost",
		"Gap records for this flow: 3 shown of 514 (2 unresolved, 500 acked_beyond, 12 filled).",
		"can also result from capture duplicates",
		"encapsulated or encrypted overlay traffic is not inspected",
	} {
		if !strings.Contains(out, must) {
			t.Errorf("missing %q in:\n%s", must, out)
		}
	}
	// No acked_beyond: no acked_beyond explanation; no tally line when everything is shown.
	f2 := flowWith(2, 2, 0, 0)
	f2.GapResolutions = &models.GapResolutionCounts{Total: 2, Unresolved: 2}
	r.TCPFlowEvidence.Flows = []models.TCPFlowEvidence{f2}
	r.TCPFlowEvidence.SequenceGaps = &models.SequenceGapSummary{GapResolutionCounts: *f2.GapResolutions}
	o := cliText(r)
	if strings.Contains(o, "acknowledged beyond") || strings.Contains(o, "Gap records for this flow") {
		t.Errorf("unexpected text:\n%s", o)
	}
	// The capture-duplicate / SYN-after-SYN-ACK caution is printed only when handshake repeats are listed.
	if strings.Contains(o, "capture duplicates, and a SYN can repeat") {
		t.Errorf("handshake caution without handshake records:\n%s", o)
	}
	if strings.Contains(o, "grouped by address/port pair") {
		t.Errorf("tuple note without handshake records:\n%s", o)
	}
	r.TCPFlowEvidence.Flows = []models.TCPFlowEvidence{flowWith(3, 0, 0, 1), flowWith(4, 0, 0, 2)}
	if out := cliText(r); strings.Count(out, "grouped by address/port pair") != 1 ||
		!strings.Contains(out, "several connection attempts that reuse the same pair may be combined") ||
		!strings.Contains(out, "not necessarily matched to the specific repeated SYN") {
		t.Errorf("tuple note must appear exactly once with its three points:\n%s", out)
	}
	r.TCPFlowEvidence.Flows = []models.TCPFlowEvidence{flowWith(3, 0, 0, 1)}
	if !strings.Contains(cliText(r), "capture duplicates, and a SYN can repeat after a SYN-ACK was observed") {
		t.Error("handshake caution missing when a repeated SYN is listed")
	}
}
