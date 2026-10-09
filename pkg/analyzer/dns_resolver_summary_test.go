package analyzer

import (
	"encoding/json"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/gocisse/sdwan-triage/pkg/models"
	"github.com/google/gopacket/layers"
)

// Phase 4.32 — DNS resolver response summary. Packets are 100 ms apart unless
// runGoldenInterval is used. The summary is observational: a missing response is
// "no observed response" with a visibility qualifier, never a server/ISP/network fault.

var drBanned = []string{"failed to respond", "is down", "outage", "dropped", "blocked", "isp", "provider", "unreachable", "faulty", "broken"}

func drNoClaims(t *testing.T, text string) {
	t.Helper()
	l := strings.ToLower(text)
	for _, b := range drBanned {
		if strings.Contains(l, b) {
			t.Errorf("text makes an unsupported claim (%q): %s", b, text)
		}
	}
}

func drSummary(t *testing.T, r *models.TriageReport) *models.DNSResolverSummary {
	t.Helper()
	if r.DNSResolverSummary == nil {
		t.Fatal("no dns_resolver_summary")
	}
	return r.DNSResolverSummary
}

func TestDNSResolverSummary_AbsentWithoutDNSQueries(t *testing.T) {
	r := runGolden(t, handshake(fePort))
	if r.DNSResolverSummary != nil {
		t.Errorf("summary present without DNS: %+v", r.DNSResolverSummary)
	}
	b, _ := json.Marshal(r)
	if strings.Contains(string(b), "dns_resolver_summary") {
		t.Error("key serialized without DNS queries")
	}
}

func TestDNSResolverSummary_AnsweredQueriesReportResponseTimeAndCodes(t *testing.T) {
	c, s := dkClient, dkGoogle
	r := runGolden(t, [][]byte{
		dkQuery(t, c, s, 1, "a.example.net"), dkResponse(t, c, s, 1, 0, "a.example.net", dkWeb),
		dkQuery(t, c, s, 2, "b.example.net"), dkResponse(t, c, s, 2, layers.DNSResponseCodeNXDomain, "b.example.net"),
		dkQuery(t, c, s, 3, "c.example.net"), dkResponse(t, c, s, 3, 0, "c.example.net", dkWeb),
	})
	sum := drSummary(t, r)
	tot := sum.Totals
	if tot.Queries != 3 || tot.Answered != 3 || tot.Unanswered != 0 || tot.AmbiguousMatches != 0 || tot.RetriedTransactions != 0 {
		t.Fatalf("totals = %+v", tot)
	}
	if tot.ResponseCodes["NOERROR"] != 2 || tot.ResponseCodes["NXDOMAIN"] != 1 {
		t.Errorf("codes = %v", tot.ResponseCodes)
	}
	l := tot.Latency
	if l == nil || l.Samples != 3 || math.Abs(l.MedianMs-100) > 1 || math.Abs(l.P95Ms-100) > 1 || math.Abs(l.MaxMs-100) > 1 || l.SamplesTruncated {
		t.Errorf("latency = %+v", l)
	}
	if tot.Visibility != "" {
		t.Errorf("fully answered capture has a visibility note: %q", tot.Visibility)
	}
	if len(sum.Resolvers) != 1 || sum.Resolvers[0].Resolver != "8.8.8.8" || sum.Resolvers[0].Queries != 3 {
		t.Errorf("resolvers = %+v", sum.Resolvers)
	}
}

// A capture holding only the query direction must be reported as "no observed
// response" with the visibility caveat, never as a resolver/network failure.
func TestDNSResolverSummary_OneDirectionCaptureIsQualified(t *testing.T) {
	c, s := dkClient, dkGoogle
	r := runGolden(t, [][]byte{
		dkQuery(t, c, s, 1, "a.example.net"), dkQuery(t, c, s, 2, "b.example.net"), dkQuery(t, c, s, 3, "c.example.net"),
	})
	tot := drSummary(t, r).Totals
	if tot.Queries != 3 || tot.Answered != 0 || tot.Unanswered != 3 || tot.Latency != nil {
		t.Fatalf("totals = %+v", tot)
	}
	for _, must := range []string{"No response was observed for any of these queries", "may not contain the reply direction", "does not by itself show that the resolver did not respond"} {
		if !strings.Contains(tot.Visibility, must) {
			t.Errorf("visibility lacks %q: %s", must, tot.Visibility)
		}
	}
	drNoClaims(t, tot.Visibility)
	drNoClaims(t, models.DNSResolverSummaryBasis)
}

func TestDNSResolverSummary_PartialResponsesAndCaptureEndCutoff(t *testing.T) {
	c, s := dkClient, dkGoogle
	// 1 s apart: q_a (never answered, 5 s before the end), q_b/r_b, q_c/r_c, q_d (never answered, at the end).
	r := runGoldenInterval(t, [][]byte{
		dkQuery(t, c, s, 1, "a.example.net"),
		dkQuery(t, c, s, 2, "b.example.net"), dkResponse(t, c, s, 2, 0, "b.example.net", dkWeb),
		dkQuery(t, c, s, 3, "c.example.net"), dkResponse(t, c, s, 3, 0, "c.example.net", dkWeb),
		dkQuery(t, c, s, 4, "d.example.net"),
	}, time.Second)
	tot := drSummary(t, r).Totals
	if tot.Queries != 4 || tot.Answered != 2 || tot.Unanswered != 2 || tot.UnansweredNearCaptureEnd != 1 {
		t.Fatalf("totals = %+v", tot)
	}
	if !strings.Contains(tot.Visibility, "2 of 4 queries have no observed response") || !strings.Contains(tot.Visibility, "(1 sent within 2 s of the end of the capture)") ||
		!strings.Contains(tot.Visibility, "does not by itself show where, or whether, a response was lost") {
		t.Errorf("visibility = %s", tot.Visibility)
	}
	drNoClaims(t, tot.Visibility)
}

// Same client, transaction ID and name sent three times, answered once: the first
// query gets the response; the repeats are neither "unanswered" nor a latency sample.
func TestDNSResolverSummary_RetriesOfAnAnsweredTransaction(t *testing.T) {
	c, s := dkClient, dkGoogle
	r := runGolden(t, [][]byte{
		dkQuery(t, c, s, 7, "r.example.net"), dkQuery(t, c, s, 7, "r.example.net"), dkQuery(t, c, s, 7, "r.example.net"),
		dkResponse(t, c, s, 7, 0, "r.example.net", dkWeb),
	})
	tot := drSummary(t, r).Totals
	if tot.Queries != 3 || tot.Answered != 1 || tot.RetriesOfAnsweredTransactions != 2 || tot.Unanswered != 0 || tot.RetriedTransactions != 1 {
		t.Fatalf("totals = %+v", tot)
	}
	if tot.Latency != nil {
		t.Errorf("a retried transaction must not produce a response-time sample: %+v", tot.Latency)
	}
	if tot.Queries != tot.Answered+tot.RetriesOfAnsweredTransactions+tot.Unanswered {
		t.Error("query accounting does not add up")
	}
}

func TestDNSResolverSummary_UnansweredRetriesStayUnanswered(t *testing.T) {
	c, s := dkClient, dkGoogle
	r := runGolden(t, [][]byte{
		dkQuery(t, c, s, 9, "u.example.net"), dkQuery(t, c, s, 9, "u.example.net"), dkQuery(t, c, s, 9, "u.example.net"),
	})
	tot := drSummary(t, r).Totals
	if tot.Queries != 3 || tot.Unanswered != 3 || tot.Answered != 0 || tot.RetriesOfAnsweredTransactions != 0 || tot.RetriedTransactions != 1 {
		t.Errorf("totals = %+v", tot)
	}
}

// A response whose transaction ID matches no query is credited by name (existing
// behaviour) but is ambiguous: it is counted, excluded from response time, and does
// not make the other queries "repeats of an answered transaction".
func TestDNSResolverSummary_MismatchedTransactionIDIsAmbiguous(t *testing.T) {
	c, s := dkClient, dkGoogle
	r := runGolden(t, [][]byte{
		dkQuery(t, c, s, 1, "m.example.net"), dkQuery(t, c, s, 1, "m.example.net"),
		dkResponse(t, c, s, 2, layers.DNSResponseCodeServFail, "m.example.net"),
	})
	tot := drSummary(t, r).Totals
	if tot.Answered != 1 || tot.AmbiguousMatches != 1 || tot.Latency != nil || tot.RetriesOfAnsweredTransactions != 0 || tot.Unanswered != 1 {
		t.Errorf("totals = %+v", tot)
	}
	if tot.ResponseCodes["SERVFAIL"] != 1 {
		t.Errorf("codes = %v", tot.ResponseCodes)
	}
}

func TestDNSResolverSummary_ResponseFromAnotherAddressIsAmbiguous(t *testing.T) {
	c := dkClient
	r := runGolden(t, [][]byte{
		dkQuery(t, c, dkGoogle, 1, "x.example.net"),
		dkResponse(t, c, dkLevel3, 1, 0, "x.example.net", dkWeb), // same client/ID/name, other responder
	})
	tot := drSummary(t, r).Totals
	if tot.Answered != 1 || tot.AmbiguousMatches != 1 || tot.Latency != nil {
		t.Errorf("totals = %+v", tot)
	}
	if rs := drSummary(t, r).Resolvers; len(rs) != 1 || rs[0].Resolver != "8.8.8.8" {
		t.Errorf("resolvers = %+v (queries are grouped by the address queried)", rs)
	}
}

// A response for the same ID and name addressed to a different client is never credited.
func TestDNSResolverSummary_OtherClientsResponseIsNotCredited(t *testing.T) {
	s := dkGoogle
	r := runGolden(t, [][]byte{
		dkQuery(t, dkClient, s, 1, "o.example.net"),
		dkResponse(t, dkClientB, s, 1, 0, "o.example.net", dkWeb),
	})
	tot := drSummary(t, r).Totals
	if tot.Answered != 0 || tot.Unanswered != 1 {
		t.Errorf("totals = %+v", tot)
	}
}

func TestDNSResolverSummary_PerResolverOrderAndAccounting(t *testing.T) {
	c := dkClient
	r := runGolden(t, [][]byte{
		dkQuery(t, c, dkInternal, 1, "a.example.net"), dkResponse(t, c, dkInternal, 1, 0, "a.example.net", dkWeb),
		dkQuery(t, c, dkInternal, 2, "b.example.net"), dkQuery(t, c, dkInternal, 3, "c.example.net"),
		dkQuery(t, c, dkGoogle, 4, "d.example.net"),
		dkQuery(t, c, dkLevel3, 5, "e.example.net"),
	})
	sum := drSummary(t, r)
	if sum.ResolversWithData != 3 || sum.ResolversShown != 3 || sum.OmittedResolvers != 0 {
		t.Fatalf("summary = %+v", sum)
	}
	got := []string{sum.Resolvers[0].Resolver, sum.Resolvers[1].Resolver, sum.Resolvers[2].Resolver}
	if strings.Join(got, ",") != "10.160.4.39,4.2.2.1,8.8.8.8" { // most queries first, then address
		t.Errorf("order = %v", got)
	}
	in := sum.Resolvers[0]
	if in.Queries != 3 || in.Answered != 1 || in.Unanswered != 2 {
		t.Errorf("internal resolver = %+v", in)
	}
	var q, a, u int
	for _, x := range sum.Resolvers {
		q, a, u = q+x.Queries, a+x.Answered, u+x.Unanswered
	}
	if q != sum.Totals.Queries || a != sum.Totals.Answered || u != sum.Totals.Unanswered {
		t.Errorf("per-resolver sums %d/%d/%d != totals %+v", q, a, u, sum.Totals)
	}
}

func TestDNSResolverSummary_DeterministicJSON(t *testing.T) {
	c, s := dkClient, dkGoogle
	mk := func() string {
		r := runGolden(t, [][]byte{
			dkQuery(t, c, s, 1, "a.example.net"), dkResponse(t, c, s, 1, 0, "a.example.net", dkWeb),
			dkQuery(t, c, dkInternal, 2, "b.example.net"), dkQuery(t, c, dkInternal, 2, "b.example.net"),
			dkResponse(t, c, s, 9, 0, "zzz.example.net", dkWeb),
		})
		b, _ := json.Marshal(r.DNSResolverSummary)
		return string(b)
	}
	first := mk()
	for i := 0; i < 3; i++ {
		if got := mk(); got != first {
			t.Fatalf("run %d differs:\n%s\n%s", i, first, got)
		}
	}
}

// The summary is a separate view: existing DNS records, anomalies and the existing
// unanswered-query behaviour are untouched by it.
func TestDNSResolverSummary_DoesNotChangeExistingDNSOutput(t *testing.T) {
	c, s := dkClient, dkGoogle
	r := runGolden(t, [][]byte{
		dkQuery(t, c, s, 7, "silent.example.net"), dkQuery(t, c, s, 7, "silent.example.net"),
		dkQuery(t, c, s, 8, "ok.example.net"), dkResponse(t, c, s, 8, 0, "ok.example.net", dkWeb),
	})
	got := kindsByQuery(r)
	if len(got["silent.example.net"]) != 1 || got["silent.example.net"][0] != models.DNSKindNoResponse || len(got["ok.example.net"]) != 0 {
		t.Errorf("anomalies = %v", got)
	}
	if len(r.DNSDetails) != 3 || r.DNSDetails[2].ResponseTimestamp == nil {
		t.Errorf("records = %+v", r.DNSDetails)
	}
}

// A repeat sent after the first query of its transaction was already answered keeps the
// transaction's original group: it is a repeat of an answered query, not a new unanswered one.
func TestDNSResolverSummary_LateRepeatKeepsTheOriginalTransactionGroup(t *testing.T) {
	c, s := dkClient, dkGoogle
	r := runGolden(t, [][]byte{
		dkQuery(t, c, s, 7, "l.example.net"), dkQuery(t, c, s, 7, "l.example.net"),
		dkResponse(t, c, s, 7, 0, "l.example.net", dkWeb), // credited to the first query
		dkQuery(t, c, s, 7, "l.example.net"),              // sent again after the answer
	})
	tot := drSummary(t, r).Totals
	if tot.Queries != 3 || tot.Answered != 1 || tot.RetriesOfAnsweredTransactions != 2 || tot.Unanswered != 0 || tot.RetriedTransactions != 1 {
		t.Errorf("totals = %+v", tot)
	}
}
