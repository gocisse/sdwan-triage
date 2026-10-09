package output

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/gocisse/sdwan-triage/pkg/models"
)

// Phase 4.31b — concise CLI view of the per-flow TCP evidence summary. It writes
// nothing when there is no TCP evidence, so output for such captures is unchanged. The
// wording is observational: it never says where, or whether, packets were lost.
const (
	cliEvidenceMaxFlows          = 10
	cliEvidenceMaxRecordsPerKind = 3
)

// PrintTCPFlowEvidence writes the TCP EVIDENCE section to stdout.
func PrintTCPFlowEvidence(r *models.TriageReport) { WriteTCPFlowEvidence(os.Stdout, r) }

func framesText(first, last uint64) string {
	switch {
	case first == 0:
		return ""
	case last == 0 || last == first:
		return fmt.Sprintf(" (frame %d)", first)
	default:
		return fmt.Sprintf(" (frames %d-%d)", first, last)
	}
}

// WriteTCPFlowEvidence writes the TCP EVIDENCE section (see above).
func WriteTCPFlowEvidence(w io.Writer, r *models.TriageReport) {
	s := r.TCPFlowEvidence
	if s == nil || len(s.Flows) == 0 {
		return
	}
	fmt.Fprintln(w, "TCP EVIDENCE (observations from this capture; not a statement about where or whether packets were lost):")
	fmt.Fprintln(w, "  Frame numbers are capture frame numbers; sequence numbers are absolute (Wireshark shows relative ones by default).")
	if s.CompletenessAffected {
		fmt.Fprintln(w, "  Some TCP evidence could not be tracked or was omitted; see completeness details (tcp_evidence_completeness in the JSON report).")
		fmt.Fprintln(w, "  These limits are capture-wide; they do not necessarily affect every flow listed below.")
		for _, d := range s.CompletenessDetails {
			label := "omitted"
			if d.Category == "tracking_limit" {
				label = "tracking limit"
			}
			fmt.Fprintf(w, "    - %s [%s]: %s\n", d.Name, label, d.Meaning)
		}
	}
	fmt.Fprintln(w, "  Listing order is for display only, not severity: flows with a repeated SYN and no observed SYN-ACK first, then by amount of evidence; gap records unresolved first.")
	if g := s.SequenceGaps; g != nil {
		fmt.Fprintf(w, "  Sequence gaps (all recorded): %d unresolved, %d acked_beyond, %d filled (%d total).", g.Unresolved, g.AckedBeyond, g.Filled, g.Total)
		if g.AckedBeyond > 0 {
			fmt.Fprint(w, " acked_beyond: this capture did not observe the range before the peer acknowledged beyond it; that can reflect data this capture point did not see and does not by itself show where, or whether, packets were lost.")
		}
		fmt.Fprintln(w)
	}
	shown := s.Flows
	cliOmitted := 0
	if len(shown) > cliEvidenceMaxFlows {
		cliOmitted = len(shown) - cliEvidenceMaxFlows
		shown = shown[:cliEvidenceMaxFlows]
	}
	for _, f := range shown {
		fmt.Fprintf(w, "  Flow %s  [%s]\n", f.Endpoints, strings.Join(f.EvidenceKinds, ", "))
		if f.RepeatedSegments != nil {
			var fr []string
			for i, n := range f.RepeatedSegments.Frames {
				if i >= 5 {
					fr = append(fr, "...")
					break
				}
				fr = append(fr, fmt.Sprintf("%d", n))
			}
			suffix := ""
			if len(fr) > 0 {
				suffix = " (frames " + strings.Join(fr, ", ") + ")"
			}
			fmt.Fprintf(w, "    - %s%s\n", f.RepeatedSegments.Description, suffix)
		}
		for i, h := range f.RepeatedHandshake {
			if i >= cliEvidenceMaxRecordsPerKind {
				break
			}
			fmt.Fprintf(w, "    - %s%s\n", h.Description, framesText(h.Frame, 0))
		}
		for i, g := range f.SequenceGaps {
			if i >= cliEvidenceMaxRecordsPerKind {
				break
			}
			fmt.Fprintf(w, "    - %s%s\n", g.Description, framesText(g.Frame, 0))
		}
		for i, d := range f.DuplicateACKRuns {
			if i >= cliEvidenceMaxRecordsPerKind {
				break
			}
			fmt.Fprintf(w, "    - %s%s\n", d.Description, framesText(d.FirstFrame, d.LastFrame))
		}
		if r := f.GapResolutions; r != nil && r.Total > cliEvidenceMaxRecordsPerKind {
			fmt.Fprintf(w, "    Gap records for this flow: %d shown of %d (%d unresolved, %d acked_beyond, %d filled).\n",
				cliEvidenceMaxRecordsPerKind, r.Total, r.Unresolved, r.AckedBeyond, r.Filled)
		}
		if more := moreRecords(f, cliEvidenceMaxRecordsPerKind); more > 0 {
			fmt.Fprintf(w, "    ... %d more record(s) for this flow in the JSON report (tcp_flow_evidence).\n", more)
		}
	}
	if cliOmitted > 0 || s.Truncated {
		fmt.Fprintf(w, "  Display limited: showing %d of %d flows with evidence", len(shown), s.FlowsWithEvidence)
		if s.OmittedFlows > 0 || s.OmittedRecords > 0 {
			fmt.Fprintf(w, "; the JSON list itself is also bounded (%d flows omitted, %d records omitted)", s.OmittedFlows, s.OmittedRecords)
		}
		fmt.Fprintln(w, ". Full bounded list: tcp_flow_evidence in the JSON report.")
	}
	for _, f := range shown {
		if len(f.RepeatedHandshake) > 0 {
			fmt.Fprintln(w, "  Repeated SYN/SYN-ACK records can also result from capture duplicates, and a SYN can repeat after a SYN-ACK was observed.")
			fmt.Fprintln(w, "  Handshake evidence is grouped by address/port pair: several connection attempts that reuse the same pair may be combined, and a SYN-ACK is not necessarily matched to the specific repeated SYN.")
			break
		}
	}
	fmt.Fprintln(w, "  These are observations of the traffic visible in this capture (encapsulated or encrypted overlay traffic is not inspected); an absence of listed evidence does not show that nothing happened.")
	fmt.Fprintln(w)
}

// moreRecords counts records of f beyond the CLI per-kind bound, plus any the JSON bound already omitted.
func moreRecords(f models.TCPFlowEvidence, perKind int) int {
	n := 0
	for _, c := range []int{len(f.RepeatedHandshake), len(f.SequenceGaps), len(f.DuplicateACKRuns)} {
		if c > perKind {
			n += c - perKind
		}
	}
	if f.Omitted != nil {
		n += f.Omitted.RepeatedHandshake + f.Omitted.SequenceGaps + f.Omitted.DuplicateACKRuns
	}
	return n
}
