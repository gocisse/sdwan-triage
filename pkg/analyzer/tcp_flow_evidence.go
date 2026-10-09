package analyzer

import (
	"fmt"
	"sort"
	"strings"

	"github.com/gocisse/sdwan-triage/pkg/events"
	"github.com/gocisse/sdwan-triage/pkg/models"
)

// Phase 4.31b — bounded per-flow TCP evidence summary (see models.TCPFlowEvidenceSummary).
//
// Built after every evidence event exists (after TCPAnalyzer.Finalize and the
// completeness accounting). It only RE-GROUPS existing events; it adds no detection,
// uses no threshold, and nothing reads it for verdicts.
const (
	tcpFlowEvidenceMaxFlows          = 20
	tcpFlowEvidenceMaxRecordsPerKind = 10
	tcpFlowEvidenceMaxFrames         = 10
	flowEvidenceTimeFmt              = "2006-01-02T15:04:05.000Z"
)

// SYN-ACK scope wording (Phase 4.31f). The SYN-ACK fact comes from the existing handshake
// list and is keyed by the address/port pair only: it is not matched to a connection
// attempt (no sequence/acknowledgment comparison, no connection generation) and has no
// time relation to the repeat. The text must say exactly that, and no more.
const (
	synAckObservedText    = "A SYN-ACK was observed for this address/port pair in this capture (not matched to this attempt; it may precede or follow this repeat)."
	synAckNotObservedText = "No SYN-ACK was observed for this address/port pair in this capture."
)

// captureFrameNumber converts the recorder's 0-based packet ordinal into the
// 1-based capture frame number. This is the ONLY place the conversion is applied.
func captureFrameNumber(ordinal uint64) uint64 { return ordinal + 1 }

func eventFrame(e events.Event, i int) uint64 {
	if i < len(e.Packets) {
		return captureFrameNumber(e.Packets[i].Index)
	}
	return 0 // no packet reference was recorded
}

// splitFlowEndpoints splits "src:port->dst:port" into its two endpoints.
func splitFlowEndpoints(fk string) (a, b string, ok bool) {
	parts := strings.SplitN(fk, "->", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", false
	}
	return parts[0], parts[1], true
}

func canonicalEndpoints(a, b string) string {
	if b < a {
		a, b = b, a
	}
	return a + " <-> " + b
}

type flowAcc struct {
	endpoints string
	kinds     map[string]bool
	first     events.Event // earliest evidence event (for ordering)
	haveFirst bool
	records   int // all events of this flow, for ordering

	reps    *models.RepeatedSegmentEvidence
	repAll  []uint64
	hand    []models.RepeatedHandshakeEvidence
	gapEv   []events.Event // every gap event of the flow; ordered and bounded after grouping
	dups    []models.DuplicateACKRunEvidence
	handAll int
	dupsAll int

	unansweredSYN bool // a repeated SYN with no SYN-ACK observed for the connection
}

// gapResolutionRank orders gap records for display: the least-recovered state first.
func gapResolutionRank(res string) int {
	switch res {
	case "unresolved":
		return 0
	case "acked_beyond":
		return 1
	case "filled":
		return 2
	}
	return 3
}

func tallyGap(c *models.GapResolutionCounts, res string) {
	c.Total++
	switch res {
	case "unresolved":
		c.Unresolved++
	case "acked_beyond":
		c.AckedBeyond++
	case "filled":
		c.Filled++
	}
}

// fmtInterval renders a capture-time interval compactly and without false precision.
func fmtInterval(ms float64) string {
	switch {
	case ms < 1:
		return "less than 1 ms"
	case ms < 100:
		return fmt.Sprintf("%.1f ms", ms)
	default:
		return fmt.Sprintf("%.0f ms", ms)
	}
}

// BuildTCPFlowEvidence assembles the summary from the report's event index and
// handshake lists; nil when there is no TCP evidence.
func BuildTCPFlowEvidence(report *models.TriageReport) *models.TCPFlowEvidenceSummary {
	if report == nil || report.Events == nil {
		return nil
	}
	// Connections for which any SYN-ACK was observed (existing handshake evidence).
	synack := make(map[string]bool)
	for _, h := range report.TCPHandshakes.SYNACKFlows {
		synack[canonicalEndpoints(fmt.Sprintf("%s:%d", h.SrcIP, h.SrcPort), fmt.Sprintf("%s:%d", h.DstIP, h.DstPort))] = true
	}

	flows := make(map[string]*flowAcc)
	get := func(e events.Event, kind string) *flowAcc {
		a, b, ok := splitFlowEndpoints(e.FlowKey)
		if !ok {
			return nil
		}
		key := canonicalEndpoints(a, b)
		f := flows[key]
		if f == nil {
			f = &flowAcc{endpoints: key, kinds: make(map[string]bool)}
			flows[key] = f
		}
		f.kinds[kind] = true
		f.records++
		if !f.haveFirst || e.Timestamp.Before(f.first.Timestamp) {
			f.first, f.haveFirst = e, true
		}
		return f
	}

	for _, e := range report.Events.ByKind(events.TCPRetransmission) {
		if f := get(e, "retransmission"); f != nil {
			f.repAll = append(f.repAll, eventFrame(e, 0))
		}
	}
	for _, e := range report.Events.ByKind(events.TCPSYNRetransmission) {
		f := get(e, "repeated_handshake")
		if f == nil {
			continue
		}
		f.handAll++
		if e.Attrs["segment"] == "SYN" && !synack[f.endpoints] {
			f.unansweredSYN = true
		}
		if len(f.hand) >= tcpFlowEvidenceMaxRecordsPerKind {
			continue
		}
		rec := models.RepeatedHandshakeEvidence{
			Segment: e.Attrs["segment"], Direction: e.FlowKey, Attempt: int(e.Values["attempt"]),
			Frame: eventFrame(e, 0), Time: e.Timestamp.UTC().Format(flowEvidenceTimeFmt), SinceFirstMs: e.Values["since_first_ms"],
			SincePreviousMs: e.Values["since_previous_ms"],
		}
		since := fmt.Sprintf(", %s after the previous one", fmtInterval(rec.SincePreviousMs))
		if rec.Segment == "SYN" {
			obs := synack[f.endpoints]
			rec.SYNACKObserved = &obs
			if obs {
				rec.Description = fmt.Sprintf("Repeated SYN observed (attempt %d%s). %s", rec.Attempt, since, synAckObservedText)
			} else {
				rec.Description = fmt.Sprintf("Repeated SYN observed (attempt %d%s). %s", rec.Attempt, since, synAckNotObservedText)
			}
		} else {
			rec.Description = fmt.Sprintf("Repeated SYN-ACK observed (attempt %d%s).", rec.Attempt, since)
		}
		f.hand = append(f.hand, rec)
	}
	var gapTotals models.GapResolutionCounts
	for _, e := range report.Events.ByKind(events.TCPSequenceGap) {
		f := get(e, "sequence_gap")
		if f == nil {
			continue
		}
		f.gapEv = append(f.gapEv, e)
		tallyGap(&gapTotals, e.Attrs["resolution"])
	}
	for _, e := range report.Events.ByKind(events.TCPDuplicateACKRun) {
		f := get(e, "duplicate_ack_run")
		if f == nil {
			continue
		}
		f.dupsAll++
		if len(f.dups) >= tcpFlowEvidenceMaxRecordsPerKind {
			continue
		}
		rec := models.DuplicateACKRunEvidence{
			Direction: e.FlowKey, Ack: uint64(e.Values["ack"]), Window: uint64(e.Values["window"]),
			Duplicates: int(e.Values["dup_count"]), DurationMs: e.Values["duration_ms"],
			FirstFrame: eventFrame(e, 0), LastFrame: eventFrame(e, 1), Time: e.Timestamp.UTC().Format(flowEvidenceTimeFmt),
			SACK: e.Attrs["sack"], EndedBy: e.Attrs["ended_by"],
		}
		if rec.SACK == "observed" {
			for i := 0; i < models.MaxSackEdges; i++ {
				l, okL := e.Values[fmt.Sprintf("sack%d_left", i)]
				r, okR := e.Values[fmt.Sprintf("sack%d_right", i)]
				if okL && okR {
					rec.SACKEdges = append(rec.SACKEdges, [2]uint64{uint64(l), uint64(r)})
				}
			}
		}
		rec.Description = dupAckDescription(rec)
		f.dups = append(f.dups, rec)
	}
	if len(flows) == 0 {
		return nil
	}

	// Deterministic display order (not a severity ranking).
	list := make([]*flowAcc, 0, len(flows))
	for _, f := range flows {
		list = append(list, f)
	}
	sort.Slice(list, func(i, j int) bool {
		a, b := list[i], list[j]
		if a.unansweredSYN != b.unansweredSYN {
			return a.unansweredSYN
		}
		if len(a.kinds) != len(b.kinds) {
			return len(a.kinds) > len(b.kinds)
		}
		if a.records != b.records {
			return a.records > b.records
		}
		if !a.first.Timestamp.Equal(b.first.Timestamp) {
			return a.first.Timestamp.Before(b.first.Timestamp)
		}
		return a.endpoints < b.endpoints
	})

	sum := &models.TCPFlowEvidenceSummary{
		FrameNumberBasis:    models.TCPFlowEvidenceFrameBasis,
		SequenceNumberBasis: models.TCPFlowEvidenceSequenceBasis,
		Order:               models.TCPFlowEvidenceOrder,
		Limits: models.TCPFlowEvidenceLimits{
			MaxFlows: tcpFlowEvidenceMaxFlows, MaxRecordsPerKind: tcpFlowEvidenceMaxRecordsPerKind, MaxFramesPerEntry: tcpFlowEvidenceMaxFrames,
		},
		FlowsWithEvidence:    len(list),
		CompletenessAffected: report.TCPEvidenceCompleteness.Affected(),
		CompletenessNote:     models.TCPFlowEvidenceCompletenessNote,
		CompletenessDetails:  report.TCPEvidenceCompleteness.Details(),
		SequenceGaps:         sequenceGapSummary(gapTotals),
		Flows:                []models.TCPFlowEvidence{},
	}
	for i, f := range list {
		if i >= tcpFlowEvidenceMaxFlows {
			sum.OmittedFlows++
			sum.OmittedRecords += f.records
			continue
		}
		out := models.TCPFlowEvidence{Endpoints: f.endpoints}
		for k := range f.kinds {
			out.EvidenceKinds = append(out.EvidenceKinds, k)
		}
		sort.Strings(out.EvidenceKinds)
		if len(f.repAll) > 0 {
			frames := append([]uint64(nil), f.repAll...)
			sort.Slice(frames, func(a, b int) bool { return frames[a] < frames[b] })
			rep := &models.RepeatedSegmentEvidence{Count: len(frames)}
			if len(frames) > tcpFlowEvidenceMaxFrames {
				frames, rep.FramesTruncated = frames[:tcpFlowEvidenceMaxFrames], true
			}
			if frames[0] != 0 { // frame numbers are 1-based; 0 means no reference was recorded
				rep.Frames = frames
			}
			rep.Description = fmt.Sprintf("A segment with an already-seen starting sequence number was observed %d time(s); this can also result from capture duplicates.", rep.Count)
			out.RepeatedSegments = rep
		}
		gaps := orderedGapRecords(f.gapEv)
		if len(f.gapEv) > 0 {
			var c models.GapResolutionCounts
			for _, e := range f.gapEv {
				tallyGap(&c, e.Attrs["resolution"])
			}
			out.GapResolutions = &c
		}
		out.RepeatedSYNWithoutSYNACK = f.unansweredSYN
		out.RepeatedHandshake, out.SequenceGaps, out.DuplicateACKRuns = f.hand, gaps, f.dups
		om := models.TCPFlowEvidenceOmitted{
			RepeatedHandshake: f.handAll - len(f.hand), SequenceGaps: len(f.gapEv) - len(gaps), DuplicateACKRuns: f.dupsAll - len(f.dups),
		}
		if om != (models.TCPFlowEvidenceOmitted{}) {
			out.Omitted = &om
			sum.OmittedRecords += om.RepeatedHandshake + om.SequenceGaps + om.DuplicateACKRuns
		}
		sum.Flows = append(sum.Flows, out)
	}
	sum.FlowsShown = len(sum.Flows)
	sum.Truncated = sum.OmittedFlows > 0 || sum.OmittedRecords > 0
	return sum
}

// orderedGapRecords sorts a flow's gap events for display (unresolved, acked_beyond,
// filled; chronological within each, then frame, gap start, event ID) and builds the
// records for the first tcpFlowEvidenceMaxRecordsPerKind. The sort uses only existing
// event fields; it changes no evidence.
func orderedGapRecords(evs []events.Event) []models.SequenceGapEvidence {
	if len(evs) == 0 {
		return nil
	}
	sorted := append([]events.Event(nil), evs...)
	sort.SliceStable(sorted, func(i, j int) bool {
		a, b := sorted[i], sorted[j]
		if ra, rb := gapResolutionRank(a.Attrs["resolution"]), gapResolutionRank(b.Attrs["resolution"]); ra != rb {
			return ra < rb
		}
		if !a.Timestamp.Equal(b.Timestamp) {
			return a.Timestamp.Before(b.Timestamp)
		}
		if fa, fb := eventFrame(a, 0), eventFrame(b, 0); fa != fb {
			return fa < fb
		}
		if a.Values["gap_start"] != b.Values["gap_start"] {
			return a.Values["gap_start"] < b.Values["gap_start"]
		}
		return a.ID < b.ID
	})
	if len(sorted) > tcpFlowEvidenceMaxRecordsPerKind {
		sorted = sorted[:tcpFlowEvidenceMaxRecordsPerKind]
	}
	out := make([]models.SequenceGapEvidence, 0, len(sorted))
	for _, e := range sorted {
		rec := models.SequenceGapEvidence{
			Direction: e.FlowKey, GapStart: uint64(e.Values["gap_start"]), GapEnd: uint64(e.Values["gap_end"]),
			GapBytes: uint64(e.Values["gap_bytes"]), Resolution: e.Attrs["resolution"],
			FilledBytes: uint64(e.Values["filled_bytes"]), RemainingBytes: uint64(e.Values["remaining_bytes"]),
			Frame: eventFrame(e, 0), Time: e.Timestamp.UTC().Format(flowEvidenceTimeFmt),
			Baseline: e.Attrs["baseline"], Limitation: e.Attrs["limitation"],
		}
		if rec.Resolution == "filled" {
			d := e.Values["fill_delay_ms"]
			rec.FillDelayMs = &d
		}
		rec.Description = gapDescription(rec)
		out = append(out, rec)
	}
	return out
}

// sequenceGapSummary tallies every recorded gap event. The note states the counts and
// what acked_beyond means for THIS capture; it does not claim network loss or a capture
// drop. nil when no gap was recorded.
func sequenceGapSummary(c models.GapResolutionCounts) *models.SequenceGapSummary {
	if c.Total == 0 {
		return nil
	}
	s := &models.SequenceGapSummary{GapResolutionCounts: c}
	s.Note = fmt.Sprintf("Of %d recorded sequence-gap record(s): %d unresolved, %d acked_beyond, %d filled.", c.Total, c.Unresolved, c.AckedBeyond, c.Filled)
	if c.AckedBeyond > 0 {
		s.Note += fmt.Sprintf(" For the %d acked_beyond record(s), this capture did not observe the range before the peer acknowledged beyond it; "+
			"that can reflect data this capture point did not see (for example a one-sided or incomplete capture) and does not by itself show where, or whether, packets were lost.", c.AckedBeyond)
	}
	return s
}

func gapDescription(g models.SequenceGapEvidence) string {
	s := fmt.Sprintf("Sequence range %d-%d (%d bytes) was not observed before later data.", g.GapStart, g.GapEnd, g.GapBytes)
	switch g.Resolution {
	case "filled":
		if g.FillDelayMs != nil {
			s += fmt.Sprintf(" The range was subsequently filled after approximately %.0f ms.", *g.FillDelayMs)
		} else {
			s += " The range was subsequently filled."
		}
	case "acked_beyond":
		s += " The peer's acknowledgment later reached beyond the range although it was not fully observed in this capture."
		if g.FilledBytes > 0 {
			s += fmt.Sprintf(" %d of %d bytes were observed.", g.FilledBytes, g.GapBytes)
		}
	default:
		if g.FilledBytes > 0 {
			s += fmt.Sprintf(" %d of %d bytes were subsequently observed; %d bytes remained unobserved and unacknowledged beyond by the end of this capture.", g.FilledBytes, g.GapBytes, g.RemainingBytes)
		} else {
			s += " It was neither observed later nor acknowledged beyond by the end of this capture."
		}
	}
	if g.Baseline == "midstream" {
		s += " This direction was first seen mid-connection."
	}
	if g.Limitation != "" {
		s += fmt.Sprintf(" Tracking was limited (%s); see completeness details.", g.Limitation)
	}
	return s
}

func dupAckDescription(d models.DuplicateACKRunEvidence) string {
	s := fmt.Sprintf("Peer sent %d duplicate ACK(s) for sequence %d (window %d) while data was outstanding; the run lasted approximately %.0f ms.", d.Duplicates, d.Ack, d.Window, d.DurationMs)
	if d.SACK == "observed" {
		s += " SACK blocks were observed."
	}
	if d.Duplicates >= 3 {
		s += " The duplicate count reached 3."
	}
	return s
}
