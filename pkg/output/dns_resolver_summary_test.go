package output

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"github.com/gocisse/sdwan-triage/pkg/models"
)

func dnsText(r *models.TriageReport) string {
	var b bytes.Buffer
	WriteDNSResolverSummary(&b, r)
	return b.String()
}

func dnsReport(n int, answered int) *models.TriageReport {
	s := &models.DNSResolverSummary{ResolversWithData: n, ResolversShown: n, MaxResolvers: 50,
		Totals: models.DNSResolverStats{Resolver: "all", Queries: n * 10, Answered: answered * n, Unanswered: (10 - answered) * n}}
	for i := 0; i < n; i++ {
		st := models.DNSResolverStats{Resolver: fmt.Sprintf("10.0.0.%d", i), Queries: 10, Answered: answered, Unanswered: 10 - answered}
		if answered == 0 {
			st.Visibility = "No response was observed for any of these queries. VIS"
		}
		s.Resolvers = append(s.Resolvers, st)
	}
	return &models.TriageReport{DNSResolverSummary: s}
}

func TestDNSResolverCLI_NothingWithoutSummary(t *testing.T) {
	if out := dnsText(&models.TriageReport{}); out != "" {
		t.Errorf("output without summary: %q", out)
	}
	if out := dnsText(&models.TriageReport{DNSResolverSummary: &models.DNSResolverSummary{}}); out != "" {
		t.Errorf("output for an empty summary: %q", out)
	}
}

func TestDNSResolverCLI_ShowsCountsCodesLatencyAndQualifier(t *testing.T) {
	r := dnsReport(1, 0)
	r.DNSResolverSummary.Resolvers[0] = models.DNSResolverStats{
		Resolver: "8.8.8.8", Queries: 6, Answered: 3, Unanswered: 2, RetriesOfAnsweredTransactions: 1, RetriedTransactions: 1, AmbiguousMatches: 1,
		ResponseCodes: map[string]int{"NXDOMAIN": 1, "NOERROR": 2},
		Latency:       &models.DNSLatency{Samples: 2, MedianMs: 12, P95Ms: 30, MaxMs: 30},
		Visibility:    "2 of 6 queries have no observed response. QUALIFIER",
	}
	out := dnsText(r)
	for _, must := range []string{
		"DNS RESPONSES (observations from this capture; a missing response does not show where, or whether, a reply was lost):",
		"Queried address 8.8.8.8: 6 queries; 3 answered (NOERROR 2, NXDOMAIN 1); 1 repeat(s) of already-answered queries; 2 with no observed response",
		"1 transaction(s) sent more than once (a retry, or a capture duplicate)", "1 answer(s) matched by name only or from another address",
		"response time over 2 unambiguous answer(s): median 12.0 ms, p95 30.0 ms, max 30.0 ms",
		"QUALIFIER", "Response time counts only answers matched by client, transaction ID, name and responding address",
	} {
		if !strings.Contains(out, must) {
			t.Errorf("missing %q in:\n%s", must, out)
		}
	}
	for _, banned := range []string{"failed", "outage", "is down", "dropped", "blocked"} {
		if strings.Contains(strings.ToLower(out), banned) {
			t.Errorf("contains %q:\n%s", banned, out)
		}
	}
	if strings.Contains(out, "Display limited") {
		t.Error("display notice without truncation")
	}
}

func TestDNSResolverCLI_DisplayBoundIsExplicit(t *testing.T) {
	out := dnsText(dnsReport(8, 0))
	if got := strings.Count(out, "Queried address "); got != cliDNSSummaryMaxResolvers {
		t.Errorf("addresses shown = %d, want %d", got, cliDNSSummaryMaxResolvers)
	}
	if !strings.Contains(out, "Display limited: showing 5 of 8 queried addresses (most queries first); the JSON list (dns_resolver_summary) is bounded at 50.") {
		t.Errorf("truncation notice missing:\n%s", out)
	}
	// Totals qualifier is printed only when several addresses were queried (no duplicate for one).
	one := dnsReport(1, 0)
	one.DNSResolverSummary.Totals.Visibility = "TOTALS-VIS"
	if strings.Contains(dnsText(one), "TOTALS-VIS") {
		t.Error("totals qualifier duplicated for a single address")
	}
	many := dnsReport(2, 0)
	many.DNSResolverSummary.Totals.Visibility = "TOTALS-VIS"
	if !strings.Contains(dnsText(many), "TOTALS-VIS") {
		t.Error("totals qualifier missing for several addresses")
	}
}

func TestDNSResolverCLI_Deterministic(t *testing.T) {
	r := dnsReport(3, 2)
	r.DNSResolverSummary.Resolvers[0].ResponseCodes = map[string]int{"SERVFAIL": 1, "NOERROR": 1, "NXDOMAIN": 1, "REFUSED": 1}
	first := dnsText(r)
	for i := 0; i < 20; i++ {
		if dnsText(r) != first {
			t.Fatal("output differs between runs")
		}
	}
}
