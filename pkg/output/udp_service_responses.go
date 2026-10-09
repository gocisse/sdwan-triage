package output

import (
	"fmt"
	"io"
	"os"

	"github.com/gocisse/sdwan-triage/pkg/models"
)

// Phase 4.36 — concise CLI view of the UDP request/response visibility. Only groups with
// at least one conversation without an observed reply are listed (the JSON lists all).
// A missing reply is an absence of evidence, never a statement about the server or network.
const cliUDPServiceMaxGroups = 8

// PrintUDPServiceResponses writes the UDP SERVICES section to stdout.
func PrintUDPServiceResponses(r *models.TriageReport) { WriteUDPServiceResponses(os.Stdout, r) }

// WriteUDPServiceResponses writes the section (see above). It prints nothing unless some
// conversation had no observed reply.
func WriteUDPServiceResponses(w io.Writer, r *models.TriageReport) {
	u := r.UDPServiceResponses
	if u == nil {
		return
	}
	var unanswered []models.UDPServiceGroup
	for _, g := range u.Groups {
		if g.ConversationsWithoutReply > 0 {
			unanswered = append(unanswered, g)
		}
	}
	if len(unanswered) == 0 {
		return
	}
	fmt.Fprintln(w, "UDP SERVICES (requests and replies observed in this capture; a missing reply does not show that the server failed or that packets were lost):")
	for _, s := range u.Services {
		fmt.Fprintf(w, "  %s: %d conversation(s), %d with no reply observed.\n", s.Service, s.Conversations, s.ConversationsWithoutReply)
	}
	shown := unanswered
	if len(shown) > cliUDPServiceMaxGroups {
		shown = shown[:cliUDPServiceMaxGroups]
	}
	for _, g := range shown {
		fmt.Fprintf(w, "  %s %s -> %s:%d: %d conversation(s), %d request(s), %d reply(ies) observed; no reply in %d conversation(s)",
			g.Service, g.Client, g.Server, g.ServerPort, g.Conversations, g.Requests, g.Replies, g.ConversationsWithoutReply)
		if g.WithoutReplyNearCaptureEnd > 0 {
			fmt.Fprintf(w, " (%d within 2 s of the end of the capture)", g.WithoutReplyNearCaptureEnd)
		}
		if g.FirstUnansweredFrame > 0 {
			fmt.Fprintf(w, " (first unanswered request: frame %d)", g.FirstUnansweredFrame)
		}
		fmt.Fprintln(w, ".")
		if g.Replies == 0 {
			fmt.Fprintln(w, "    No reply from this server was observed at all: the capture may not contain the return direction, or the replies may have been filtered, lost or never sent.")
		}
	}
	if len(unanswered) > len(shown) {
		fmt.Fprintf(w, "  Display limited: showing %d of %d groups with unanswered conversations; the JSON list (udp_service_responses) is bounded at %d and also lists the answered ones.\n",
			len(shown), len(unanswered), u.MaxGroups)
	}
	if u.DatagramsUntracked > 0 {
		fmt.Fprintf(w, "  %d datagram(s) of conversations beyond the tracking bound were not tracked; their evidence is unknown.\n", u.DatagramsUntracked)
	}
	fmt.Fprintln(w, "  Replies are not matched to individual requests; only SNMP, NTP, RADIUS, Kerberos and LDAP service ports are covered. ICMP errors about this traffic are listed under ICMP ERRORS.")
	fmt.Fprintln(w)
}
