package output

import (
	"fmt"
	"io"
	"os"

	"github.com/gocisse/sdwan-triage/pkg/models"
)

// Phase 4.33 — concise CLI view of the ICMP error evidence. It writes nothing when no
// ICMP/ICMPv6 error message was observed. The wording reports what a device sent about
// which packet; it never states a cause, a location or an application outage.
const cliICMPErrorMaxGroups = 8

// PrintICMPErrorEvidence writes the ICMP ERRORS section to stdout.
func PrintICMPErrorEvidence(r *models.TriageReport) { WriteICMPErrorEvidence(os.Stdout, r) }

func quotedText(q models.ICMPQuotedFlow) string {
	switch q.Status {
	case "complete":
		return fmt.Sprintf("about %s from %s to %s:%d", q.Protocol, q.Src, q.Dst, q.DstPort)
	case "no_ports":
		article := "a"
		if len(q.Protocol) > 0 && (q.Protocol[0] == 'I' || q.Protocol[0] == 'U') && q.Protocol != "UDP" {
			article = "an"
		}
		return fmt.Sprintf("about %s %s packet %s -> %s (ports not available in the quoted part)", article, q.Protocol, q.Src, q.Dst)
	}
	return "about an original packet that could not be identified (quote absent or truncated)"
}

// WriteICMPErrorEvidence writes the ICMP ERRORS section (see above).
func WriteICMPErrorEvidence(w io.Writer, r *models.TriageReport) {
	e := r.ICMPErrorEvidence
	if e == nil || len(e.Errors) == 0 {
		return
	}
	fmt.Fprintln(w, "ICMP ERRORS (messages observed in this capture; they show what a device sent, not why or where the problem is):")
	shown := e.Errors
	if len(shown) > cliICMPErrorMaxGroups {
		shown = shown[:cliICMPErrorMaxGroups]
	}
	for _, g := range shown {
		fmt.Fprintf(w, "  %s type %d code %d from %s to %s, %d message(s): %s %s",
			g.Family, g.Type, g.Code, g.Reporter, g.Recipient, g.Count, g.Meaning, quotedText(g.Quoted))
		if g.DistinctSrcPorts > 1 {
			more := ""
			if g.SrcPortsCapped {
				more = "+"
			}
			fmt.Fprintf(w, "; %d%s different source ports", g.DistinctSrcPorts, more)
		} else if g.Quoted.Status == "complete" {
			fmt.Fprintf(w, "; source port %d", g.Quoted.SrcPort)
		}
		if g.MaxMTU > 0 {
			if g.MinMTU == g.MaxMTU {
				fmt.Fprintf(w, "; reported next-hop MTU %d", g.MaxMTU)
			} else {
				fmt.Fprintf(w, "; reported next-hop MTU %d-%d", g.MinMTU, g.MaxMTU)
			}
		}
		switch {
		case g.FirstFrame == 0:
		case g.Count > len(g.Frames) && len(g.Frames) > 0:
			fmt.Fprintf(w, " (first frame %d)", g.FirstFrame)
		case len(g.Frames) > 1:
			fmt.Fprintf(w, " (frames %d..%d)", g.Frames[0], g.Frames[len(g.Frames)-1])
		default:
			fmt.Fprintf(w, " (frame %d)", g.FirstFrame)
		}
		fmt.Fprintln(w)
		if g.QuotedSourceDiffers {
			fmt.Fprintln(w, "    The quoted packet's source is not the address this message was sent to (for example address translation or a tunnel between them).")
		}
	}
	if e.GroupsTotal > len(shown) {
		fmt.Fprintf(w, "  Display limited: showing %d of %d groups (most messages first); the JSON list (icmp_error_evidence) is bounded at %d.\n",
			len(shown), e.GroupsTotal, e.MaxGroups)
	}
	if e.MessagesWithUnusableQuote > 0 {
		fmt.Fprintf(w, "  %d of %d message(s) did not quote a usable original packet, so the affected flow is unknown for them.\n", e.MessagesWithUnusableQuote, e.TotalMessages)
	}
	fmt.Fprintln(w, "  An ICMP error does not by itself show that an application failed; a capture at one point cannot show where the message originated beyond the reporting address.")
	fmt.Fprintln(w)
}
