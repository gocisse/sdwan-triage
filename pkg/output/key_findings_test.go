package output

import (
	"bytes"
	"testing"
	"time"

	"github.com/gocisse/sdwan-triage/pkg/models"
)

func sampleFindingsReport() *models.TriageReport {
	idx := uint64(14)
	ts := time.Date(2024, 1, 15, 12, 0, 1, 500_000_000, time.UTC)
	return &models.TriageReport{Findings: []models.Finding{{
		ID: "tcp.retransmissions:abc", Kind: "tcp.retransmissions",
		Title:    "TCP retransmissions on 10.0.0.1:1->10.0.0.2:2",
		Summary:  "5 retransmitted segments observed.",
		Severity: models.SeverityLow, Confidence: models.ConfidenceMedium, Basis: models.FindingBasisObserved,
		FirstSeen: ts, LastSeen: ts, EvidenceCount: 5,
		Evidence: []models.EvidenceRef{
			{Kind: "tcp.retransmission", Timestamp: ts, PacketIndex: &idx, FlowKey: "10.0.0.1:1->10.0.0.2:2"},
			{Kind: "tcp.retransmission", Timestamp: ts.Add(time.Second), FlowKey: "10.0.0.1:1->10.0.0.2:2"},
		},
	}}}
}

const wantKeyFindings = `KEY FINDINGS:
  [Low | Medium confidence | observed] TCP retransmissions on 10.0.0.1:1->10.0.0.2:2
    5 retransmitted segments observed.
    Evidence: 5 observation(s)
      - 2024-01-15T12:00:01.500Z tcp.retransmission packet #14 10.0.0.1:1->10.0.0.2:2
      - 2024-01-15T12:00:02.500Z tcp.retransmission 10.0.0.1:1->10.0.0.2:2

`

func TestKeyFindings_Deterministic(t *testing.T) {
	for i := 0; i < 5; i++ {
		var buf bytes.Buffer
		WriteKeyFindings(&buf, sampleFindingsReport())
		if buf.String() != wantKeyFindings {
			t.Fatalf("run %d output:\n%q\nwant:\n%q", i, buf.String(), wantKeyFindings)
		}
	}
}

func TestKeyFindings_EmptyPrintsNothing(t *testing.T) {
	var buf bytes.Buffer
	WriteKeyFindings(&buf, &models.TriageReport{})
	WriteKeyFindings(&buf, nil)
	if buf.Len() != 0 {
		t.Errorf("expected no output, got %q", buf.String())
	}
}

func TestKeyFindings_LimitsShown(t *testing.T) {
	r := &models.TriageReport{}
	for i := 0; i < 12; i++ {
		r.Findings = append(r.Findings, models.Finding{Title: "t", Summary: "s", Severity: models.SeverityLow, Confidence: models.ConfidenceLow, Basis: "observed"})
	}
	var buf bytes.Buffer
	WriteKeyFindings(&buf, r)
	if !bytes.Contains(buf.Bytes(), []byte("... and 2 more")) {
		t.Errorf("missing truncation line:\n%s", buf.String())
	}
}

func TestKeyFindings_OverflowNoteOnlyWhenDropped(t *testing.T) {
	r := sampleFindingsReport()
	var buf bytes.Buffer
	WriteKeyFindings(&buf, r)
	if bytes.Contains(buf.Bytes(), []byte("lower bounds")) {
		t.Error("note printed without dropped events")
	}
	r.EventsDropped = 42
	buf.Reset()
	WriteKeyFindings(&buf, r)
	want := "KEY FINDINGS:\n  Note: event-derived counts are lower bounds; the event index dropped 42 events.\n"
	if !bytes.HasPrefix(buf.Bytes(), []byte(want)) {
		t.Errorf("unexpected output:\n%s", buf.String())
	}
	// No findings: still nothing printed, even with dropped events.
	buf.Reset()
	WriteKeyFindings(&buf, &models.TriageReport{EventsDropped: 42})
	if buf.Len() != 0 {
		t.Errorf("expected no output, got %q", buf.String())
	}
}
