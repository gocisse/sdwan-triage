package models

import (
	"strings"
	"testing"
)

// Phase 4.31d — plain-language explanations of the completeness counters. The
// machine-readable object is unchanged; unknown missed-event counts stay "unknown".
func TestCompletenessDetails_ExplainEveryCounter(t *testing.T) {
	c := &TCPEvidenceCompleteness{
		KnownOmittedEvents: map[string]EvidenceOmission{
			"tcp.sequence_gap":      {IndexFull: 3, KindCap: 2},
			"tcp.duplicate_ack_run": {TrackerCapacity: 4},
		},
		TrackingLimits: &TCPTrackingLimits{
			SequenceLengthUnreadableResets: 1, SequenceGapsNotFollowed: 2, SequenceGapsExpired: 3,
			SequenceStateLostFlows: 4, HandshakeRepeatKeysUntracked: 5, DuplicateACKRepeatsPeerPositionUnknown: 6,
		},
	}
	got := c.Details()
	if len(got) != 3+6 {
		t.Fatalf("details = %d: %+v", len(got), got)
	}
	var omitted, limits int
	for _, d := range got {
		if d.Count <= 0 || d.Meaning == "" || d.Name == "" {
			t.Errorf("incomplete detail %+v", d)
		}
		switch d.Category {
		case "omitted_events":
			omitted += d.Count
			if strings.Contains(d.Meaning, "unknown") {
				t.Errorf("known omission described as unknown: %+v", d)
			}
		case "tracking_limit":
			limits += d.Count
			if !strings.Contains(d.Meaning, "unknown") {
				t.Errorf("tracking limit does not say the missed count is unknown: %+v", d)
			}
		default:
			t.Errorf("category %q", d.Category)
		}
	}
	if omitted != c.KnownOmittedTotal() || limits != c.TrackingLimitsTotal() {
		t.Errorf("detail counts %d/%d differ from totals %d/%d", omitted, limits, c.KnownOmittedTotal(), c.TrackingLimitsTotal())
	}
}

func TestCompletenessDetails_DeterministicAndEmptyWhenUnaffected(t *testing.T) {
	var nilC *TCPEvidenceCompleteness
	if nilC.Details() != nil || (&TCPEvidenceCompleteness{}).Details() != nil {
		t.Error("details for an unaffected capture")
	}
	c := &TCPEvidenceCompleteness{
		KnownOmittedEvents: map[string]EvidenceOmission{"tcp.sequence_gap": {IndexFull: 1}, "tcp.syn_retransmission": {KindCap: 1}, "tcp.duplicate_ack_run": {IndexFull: 1}},
		TrackingLimits:     &TCPTrackingLimits{SequenceGapsExpired: 1, DuplicateACKRepeatsPeerPositionUnknown: 1},
	}
	first := c.Details()
	for i := 0; i < 20; i++ {
		next := c.Details()
		for j := range first {
			if first[j] != next[j] {
				t.Fatalf("order differs at %d", j)
			}
		}
	}
	if !strings.Contains(first[0].Name, "tcp.duplicate_ack_run") {
		t.Errorf("first = %+v, want kinds sorted alphabetically", first[0])
	}
}
