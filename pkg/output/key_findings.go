package output

import (
	"fmt"
	"io"
	"os"

	"github.com/gocisse/sdwan-triage/pkg/models"
)

const (
	maxKeyFindingsShown   = 10
	maxKeyFindingEvidence = 3
	keyFindingTimeFmt     = "2006-01-02T15:04:05.000Z"
)

// PrintKeyFindings writes the KEY FINDINGS section to stdout.
func PrintKeyFindings(r *models.TriageReport) { WriteKeyFindings(os.Stdout, r) }

// WriteKeyFindings writes the KEY FINDINGS section. It writes nothing when the
// report has no Findings, so output for a clean capture is unchanged. The text
// is plain and deterministic: order follows report.Findings, times are UTC.
func WriteKeyFindings(w io.Writer, r *models.TriageReport) {
	if r == nil || len(r.Findings) == 0 {
		return
	}
	fmt.Fprintln(w, "KEY FINDINGS:")
	for i, f := range r.Findings {
		if i >= maxKeyFindingsShown {
			fmt.Fprintf(w, "  ... and %d more\n", len(r.Findings)-maxKeyFindingsShown)
			break
		}
		fmt.Fprintf(w, "  [%s | %s confidence | %s] %s\n", f.Severity, f.Confidence, f.Basis, f.Title)
		fmt.Fprintf(w, "    %s\n", f.Summary)
		fmt.Fprintf(w, "    Evidence: %d observation(s)\n", f.EvidenceCount)
		for j, e := range f.Evidence {
			if j >= maxKeyFindingEvidence {
				break
			}
			pkt := ""
			if e.PacketIndex != nil {
				pkt = fmt.Sprintf(" packet #%d", *e.PacketIndex)
			}
			flow := ""
			if e.FlowKey != "" {
				flow = " " + e.FlowKey
			}
			fmt.Fprintf(w, "      - %s %s%s%s\n", e.Timestamp.UTC().Format(keyFindingTimeFmt), e.Kind, pkt, flow)
		}
	}
	fmt.Fprintln(w)
}
