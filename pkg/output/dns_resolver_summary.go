package output

import (
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/gocisse/sdwan-triage/pkg/models"
)

// Phase 4.32 — concise CLI view of the DNS resolver response summary. It writes
// nothing when the capture holds no DNS query. A missing response is reported as
// "no observed response" with its visibility qualifier; it is never attributed to a
// resolver, an ISP or the network.
const cliDNSSummaryMaxResolvers = 5

// PrintDNSResolverSummary writes the DNS RESPONSES section to stdout.
func PrintDNSResolverSummary(r *models.TriageReport) { WriteDNSResolverSummary(os.Stdout, r) }

func dnsStatsLine(s models.DNSResolverStats) string {
	parts := []string{fmt.Sprintf("%d queries", s.Queries)}
	answered := fmt.Sprintf("%d answered", s.Answered)
	if len(s.ResponseCodes) > 0 {
		codes := make([]string, 0, len(s.ResponseCodes))
		for c := range s.ResponseCodes {
			codes = append(codes, c)
		}
		sort.Strings(codes)
		var cs []string
		for _, c := range codes {
			cs = append(cs, fmt.Sprintf("%s %d", c, s.ResponseCodes[c]))
		}
		answered += " (" + strings.Join(cs, ", ") + ")"
	}
	parts = append(parts, answered)
	if s.RetriesOfAnsweredTransactions > 0 {
		parts = append(parts, fmt.Sprintf("%d repeat(s) of already-answered queries", s.RetriesOfAnsweredTransactions))
	}
	parts = append(parts, fmt.Sprintf("%d with no observed response", s.Unanswered))
	if s.RetriedTransactions > 0 {
		parts = append(parts, fmt.Sprintf("%d transaction(s) sent more than once (a retry, or a capture duplicate)", s.RetriedTransactions))
	}
	if s.AmbiguousMatches > 0 {
		parts = append(parts, fmt.Sprintf("%d answer(s) matched by name only or from another address", s.AmbiguousMatches))
	}
	if l := s.Latency; l != nil {
		parts = append(parts, fmt.Sprintf("response time over %d unambiguous answer(s): median %.1f ms, p95 %.1f ms, max %.1f ms", l.Samples, l.MedianMs, l.P95Ms, l.MaxMs))
	}
	return strings.Join(parts, "; ")
}

// WriteDNSResolverSummary writes the DNS RESPONSES section (see above).
func WriteDNSResolverSummary(w io.Writer, r *models.TriageReport) {
	s := r.DNSResolverSummary
	if s == nil || s.Totals.Queries == 0 {
		return
	}
	fmt.Fprintln(w, "DNS RESPONSES (observations from this capture; a missing response does not show where, or whether, a reply was lost):")
	fmt.Fprintf(w, "  All queries (%d address(es) queried): %s\n", s.ResolversWithData, dnsStatsLine(s.Totals))
	if s.Totals.Visibility != "" && s.ResolversWithData > 1 {
		fmt.Fprintf(w, "    %s\n", s.Totals.Visibility)
	}
	shown := s.Resolvers
	if len(shown) > cliDNSSummaryMaxResolvers {
		shown = shown[:cliDNSSummaryMaxResolvers]
	}
	for _, res := range shown {
		fmt.Fprintf(w, "  Queried address %s: %s\n", res.Resolver, dnsStatsLine(res))
		if res.Visibility != "" {
			fmt.Fprintf(w, "    %s\n", res.Visibility)
		}
	}
	if s.ResolversWithData > len(shown) {
		fmt.Fprintf(w, "  Display limited: showing %d of %d queried addresses (most queries first); the JSON list (dns_resolver_summary) is bounded at %d.\n",
			len(shown), s.ResolversWithData, s.MaxResolvers)
	}
	fmt.Fprintln(w, "  Response time counts only answers matched by client, transaction ID, name and responding address to a query sent once; retried and ambiguous matches are excluded.")
	fmt.Fprintln(w)
}
