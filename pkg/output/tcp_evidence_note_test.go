package output

import (
	"strings"
	"testing"

	"github.com/gocisse/sdwan-triage/pkg/models"
)

// Phase 4.31a: one neutral line, only when TCP evidence collection was limited.

func affected() *models.TCPEvidenceCompleteness {
	return &models.TCPEvidenceCompleteness{
		KnownOmittedEvents: map[string]models.EvidenceOmission{
			"tcp.sequence_gap":      {IndexFull: 3, KindCap: 2},
			"tcp.duplicate_ack_run": {TrackerCapacity: 1},
		},
		TrackingLimits: &models.TCPTrackingLimits{SequenceGapsNotFollowed: 7, DuplicateACKRepeatsPeerPositionUnknown: 50},
		Semantics:      models.TCPEvidenceCompletenessSemantics,
	}
}

func TestEvidenceNote_AbsentWhenNothingWasLimited(t *testing.T) {
	for name, r := range map[string]*models.TriageReport{
		"nil object":   {},
		"empty object": {TCPEvidenceCompleteness: &models.TCPEvidenceCompleteness{Semantics: models.TCPEvidenceCompletenessSemantics}},
	} {
		if got := tcpEvidenceCompletenessNote(r); got != "" {
			t.Errorf("%s: note = %q, want none", name, got)
		}
		if strings.Contains(summaryText(r), "incomplete") {
			t.Errorf("%s: summary mentions incompleteness", name)
		}
	}
}

func TestEvidenceNote_NeutralDeterministicAndSeparatesOmissionsFromLimits(t *testing.T) {
	r := &models.TriageReport{TCPEvidenceCompleteness: affected()}
	want := "TCP evidence may be incomplete: 6 events omitted (duplicate_ack_run 1, sequence_gap 5); " +
		"tracking limits (duplicate_ack_repeats_peer_position_unknown 50, sequence_gaps_not_followed 7) - see tcp_evidence_completeness (JSON)"
	if got := tcpEvidenceCompletenessNote(r); got != want {
		t.Errorf("note =\n%q\nwant\n%q", got, want)
	}
	for i := 0; i < 5; i++ { // map iteration order must not leak
		if tcpEvidenceCompletenessNote(r) != want {
			t.Fatal("note is not deterministic")
		}
	}
	for _, banned := range []string{"loss", "lost", "dropped by", "provider", "fault"} {
		if strings.Contains(strings.ToLower(want), banned) {
			t.Errorf("note contains %q", banned)
		}
	}
	// Only limits, only omissions.
	lim := &models.TriageReport{TCPEvidenceCompleteness: &models.TCPEvidenceCompleteness{TrackingLimits: &models.TCPTrackingLimits{SequenceLengthUnreadableResets: 2}}}
	if got := tcpEvidenceCompletenessNote(lim); strings.Contains(got, "events omitted") || !strings.Contains(got, "sequence_length_unreadable_resets 2") {
		t.Errorf("limits-only note = %q", got)
	}
	om := &models.TriageReport{TCPEvidenceCompleteness: &models.TCPEvidenceCompleteness{KnownOmittedEvents: map[string]models.EvidenceOmission{"tcp.retransmission": {IndexFull: 4}}}}
	if got := tcpEvidenceCompletenessNote(om); strings.Contains(got, "tracking limits") || !strings.Contains(got, "4 events omitted (retransmission 4)") {
		t.Errorf("omissions-only note = %q", got)
	}
}

func TestEvidenceNote_AppearsInTheSummaryOnlyWhenAffected(t *testing.T) {
	plain := summaryText(&models.TriageReport{})
	got := summaryText(&models.TriageReport{TCPEvidenceCompleteness: affected()})
	if strings.Count(got, "TCP evidence may be incomplete") != 1 {
		t.Fatalf("summary should contain the note exactly once:\n%s", got)
	}
	// Removing the single added line must give the unaffected summary back unchanged.
	var kept []string
	for _, l := range strings.Split(got, "\n") {
		if !strings.Contains(l, "TCP evidence may be incomplete") {
			kept = append(kept, l)
		}
	}
	if strings.Join(kept, "\n") != plain {
		t.Errorf("the note changed other summary lines")
	}
}
