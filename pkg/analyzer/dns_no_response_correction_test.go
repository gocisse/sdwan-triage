package analyzer

import (
	"strings"
	"testing"
	"time"

	"github.com/gocisse/sdwan-triage/pkg/models"
)

// Phase 4.32a — a DNS transaction (same client, transaction ID and name) that was sent
// more than once and received an unambiguous response must not produce a no_response
// anomaly. Genuinely unanswered transactions are still reported, other transactions for
// the same name are judged on their own, and an ambiguous (name-only / other-address)
// answer does not establish that a transaction was answered.

func noResponseAnomalies(r *models.TriageReport) []models.DNSAnomaly {
	var out []models.DNSAnomaly
	for _, a := range r.DNSAnomalies {
		if a.Kind == models.DNSKindNoResponse {
			out = append(out, a)
		}
	}
	return out
}

// padPairs appends n answered query/response pairs for unrelated names so that the
// capture lasts long enough for the 2 s single-query timeout to apply.
func padPairs(t *testing.T, pk [][]byte, n int) [][]byte {
	for i := 0; i < n; i++ {
		name := "pad" + string(rune('a'+i)) + ".example.net"
		id := uint16(900 + i)
		pk = append(pk, dkQuery(t, dkClient, dkGoogle, id, name), dkResponse(t, dkClient, dkGoogle, id, 0, name, dkWeb))
	}
	return pk
}

// consistent: the summary and the anomaly agree about unanswered transactions.
func assertSummaryAgrees(t *testing.T, r *models.TriageReport) {
	t.Helper()
	if r.DNSResolverSummary.Totals.Unanswered == 0 && len(noResponseAnomalies(r)) != 0 {
		t.Errorf("summary has no unanswered query but a no_response anomaly was emitted: %+v", noResponseAnomalies(r))
	}
}

func TestDNSNoResponse_RepeatedQueryAnsweredOnceHasNoAnomaly(t *testing.T) {
	c, s := dkClient, dkGoogle
	r := runGolden(t, [][]byte{
		dkQuery(t, c, s, 7, "r.example.net"), dkQuery(t, c, s, 7, "r.example.net"), dkQuery(t, c, s, 7, "r.example.net"),
		dkResponse(t, c, s, 7, 0, "r.example.net", dkWeb),
	})
	if n := noResponseAnomalies(r); len(n) != 0 {
		t.Fatalf("false no_response anomaly for an answered transaction: %+v", n)
	}
	// The repeats are not marked anomalous either; the answered record is untouched.
	for i, d := range r.DNSDetails {
		if d.IsAnomalous || d.Detail != "" {
			t.Errorf("record %d wrongly marked: %+v", i, d)
		}
	}
	if r.DNSDetails[0].ResponseTimestamp == nil {
		t.Error("first query was not credited with the response")
	}
	tot := r.DNSResolverSummary.Totals
	if tot.RetriesOfAnsweredTransactions != 2 || tot.Unanswered != 0 {
		t.Errorf("totals = %+v", tot)
	}
	assertSummaryAgrees(t, r)
}

// Sends that start only AFTER the response are a new transaction as far as the existing
// correlation can tell (the answered one is no longer pending; transaction-ID reuse and
// a repeat look the same). They are not suppressed: a genuinely unanswered transaction
// must still be reported.
func TestDNSNoResponse_SendsStartedAfterTheAnswerAreNotSuppressed(t *testing.T) {
	c, s := dkClient, dkGoogle
	r := runGolden(t, [][]byte{
		dkQuery(t, c, s, 7, "l.example.net"), dkResponse(t, c, s, 7, 0, "l.example.net", dkWeb),
		dkQuery(t, c, s, 7, "l.example.net"), dkQuery(t, c, s, 7, "l.example.net"),
	})
	if n := noResponseAnomalies(r); len(n) != 1 || !strings.Contains(n[0].Reason, "queried l.example.net 2 times without an answer") {
		t.Errorf("anomalies = %+v", n)
	}
	assertSummaryAgrees(t, r)
}

// A repeat sent while the transaction was still pending, and another after the answer
// (the answer being credited to the first query), belong to the answered transaction.
func TestDNSNoResponse_RepeatAfterTheAnswerOfAPendingGroupHasNoAnomaly(t *testing.T) {
	c, s := dkClient, dkGoogle
	r := runGolden(t, [][]byte{
		dkQuery(t, c, s, 7, "g.example.net"), dkQuery(t, c, s, 7, "g.example.net"),
		dkResponse(t, c, s, 7, 0, "g.example.net", dkWeb),
		dkQuery(t, c, s, 7, "g.example.net"),
	})
	if n := noResponseAnomalies(r); len(n) != 0 {
		t.Errorf("anomaly for sends of an answered transaction: %+v", n)
	}
	assertSummaryAgrees(t, r)
}

func TestDNSNoResponse_RepeatedQueryThatRemainsUnansweredIsStillReported(t *testing.T) {
	c, s := dkClient, dkGoogle
	r := runGolden(t, [][]byte{
		dkQuery(t, c, s, 9, "u.example.net"), dkQuery(t, c, s, 9, "u.example.net"), dkQuery(t, c, s, 9, "u.example.net"),
	})
	n := noResponseAnomalies(r)
	if len(n) != 1 || !strings.Contains(n[0].Reason, "queried u.example.net 3 times without an answer") {
		t.Fatalf("anomalies = %+v", n)
	}
	for i, d := range r.DNSDetails {
		if !d.IsAnomalous {
			t.Errorf("record %d not marked", i)
		}
	}
	if r.DNSResolverSummary.Totals.Unanswered != 3 {
		t.Errorf("summary = %+v", r.DNSResolverSummary.Totals)
	}
}

// Another transaction (different ID) for the same name is judged independently: an
// answered transaction must not hide an unanswered one.
func TestDNSNoResponse_SeparateTransactionsForTheSameNameAreJudgedSeparately(t *testing.T) {
	c, s := dkClient, dkGoogle
	// id 7: sent 3x, answered. id 8: same name, sent 2x, never answered.
	r := runGolden(t, [][]byte{
		dkQuery(t, c, s, 7, "same.example.net"), dkQuery(t, c, s, 7, "same.example.net"), dkQuery(t, c, s, 7, "same.example.net"),
		dkResponse(t, c, s, 7, 0, "same.example.net", dkWeb),
		dkQuery(t, c, s, 8, "same.example.net"), dkQuery(t, c, s, 8, "same.example.net"),
	})
	n := noResponseAnomalies(r)
	if len(n) != 1 || !strings.Contains(n[0].Reason, "queried same.example.net 2 times without an answer") {
		t.Fatalf("anomalies = %+v (the unanswered transaction must be reported with its own 2 sends)", n)
	}
	marked := 0
	for _, d := range r.DNSDetails {
		if d.IsAnomalous {
			marked++
		}
	}
	if marked != 2 {
		t.Errorf("marked records = %d, want only the 2 sends of the unanswered transaction", marked)
	}
	tot := r.DNSResolverSummary.Totals
	if tot.Unanswered != 2 || tot.RetriesOfAnsweredTransactions != 2 || tot.Answered != 1 {
		t.Errorf("summary = %+v", tot)
	}

	// A single unanswered send of a second transaction outstanding past the timeout is reported too.
	pk := [][]byte{dkQuery(t, c, s, 8, "same.example.net"),
		dkQuery(t, c, s, 7, "same.example.net"), dkQuery(t, c, s, 7, "same.example.net"), dkResponse(t, c, s, 7, 0, "same.example.net", dkWeb)}
	r = runGoldenInterval(t, pk, time.Second)
	n = noResponseAnomalies(r)
	if len(n) != 1 || !strings.Contains(n[0].Reason, "unanswered for") {
		t.Errorf("single unanswered transaction = %+v", n)
	}
}

// A different client's answer is not credited (existing rule), so the repeated sends stay unanswered.
func TestDNSNoResponse_OtherClientsAnswerDoesNotSuppress(t *testing.T) {
	s := dkGoogle
	r := runGolden(t, [][]byte{
		dkQuery(t, dkClient, s, 7, "o.example.net"), dkQuery(t, dkClient, s, 7, "o.example.net"),
		dkResponse(t, dkClientB, s, 7, 0, "o.example.net", dkWeb),
	})
	if n := noResponseAnomalies(r); len(n) != 1 {
		t.Errorf("anomalies = %+v", n)
	}
}

// A response with a different transaction ID is credited by name (existing behaviour)
// but is ambiguous: it does not establish that the transaction was answered, so the
// other sends keep their no_response anomaly.
func TestDNSNoResponse_NameOnlyAnswerDoesNotSuppress(t *testing.T) {
	c, s := dkClient, dkGoogle
	pk := [][]byte{
		dkQuery(t, c, s, 1, "m.example.net"), dkQuery(t, c, s, 1, "m.example.net"),
		dkResponse(t, c, s, 2, 0, "m.example.net", dkWeb), // ID 2 matches no query
	}
	r := runGoldenInterval(t, padPairs(t, pk, 3), time.Second)
	n := noResponseAnomalies(r)
	if len(n) != 1 || !strings.Contains(n[0].Reason, "m.example.net") {
		t.Fatalf("anomalies = %+v (an ambiguous answer must not suppress the unanswered send)", n)
	}
	if r.DNSResolverSummary.Totals.AmbiguousMatches != 1 || r.DNSResolverSummary.Totals.RetriesOfAnsweredTransactions != 0 {
		t.Errorf("summary = %+v", r.DNSResolverSummary.Totals)
	}
}

func TestDNSNoResponse_AnswerFromAnotherAddressDoesNotSuppress(t *testing.T) {
	c := dkClient
	pk := [][]byte{
		dkQuery(t, c, dkGoogle, 1, "x.example.net"), dkQuery(t, c, dkGoogle, 1, "x.example.net"),
		dkResponse(t, c, dkLevel3, 1, 0, "x.example.net", dkWeb), // same client/ID/name, other responder
	}
	r := runGoldenInterval(t, padPairs(t, pk, 3), time.Second)
	if n := noResponseAnomalies(r); len(n) != 1 || !strings.Contains(n[0].Reason, "x.example.net") {
		t.Fatalf("anomalies = %+v", n)
	}
}

// Failure RCODE anomalies and the response-time record are unchanged by the correction.
func TestDNSNoResponse_OtherDNSAnomaliesAndRecordsUnchanged(t *testing.T) {
	c, s := dkClient, dkGoogle
	r := runGolden(t, [][]byte{
		dkQuery(t, c, s, 7, "f.example.net"), dkQuery(t, c, s, 7, "f.example.net"),
		dkResponse(t, c, s, 7, 2 /* SERVFAIL */, "f.example.net"),
	})
	if n := noResponseAnomalies(r); len(n) != 0 {
		t.Errorf("no_response for an answered (SERVFAIL) transaction: %+v", n)
	}
	got := kindsByQuery(r)["f.example.net"]
	if len(got) != 1 || got[0] != models.DNSKindServerFailure {
		t.Errorf("kinds = %v, want the server_failure anomaly", got)
	}
	if rec := r.DNSDetails[0]; rec.ResponseCode == nil || *rec.ResponseCode != 2 || !rec.IsAnomalous {
		t.Errorf("answered record = %+v", rec)
	}
}

// The same client/ID/name sent to two different resolvers, only the first answering: the
// second resolver's silence is its own observation (the answer came from elsewhere), so
// it stays unanswered in the anomaly and in the summary.
func TestDNSNoResponse_SendToAnotherResolverStaysUnanswered(t *testing.T) {
	c := dkClient
	r := runGolden(t, [][]byte{
		dkQuery(t, c, dkGoogle, 7, "p.example.net"), dkQuery(t, c, dkInternal, 7, "p.example.net"),
		dkResponse(t, c, dkGoogle, 7, 0, "p.example.net", dkWeb),
	})
	// The capture ends right after the send, so the single-query timeout does not apply
	// and no anomaly is due yet; the summary must still count it as unanswered.
	var in *models.DNSResolverStats
	for i := range r.DNSResolverSummary.Resolvers {
		if r.DNSResolverSummary.Resolvers[i].Resolver == "10.160.4.39" {
			in = &r.DNSResolverSummary.Resolvers[i]
		}
	}
	if in == nil || in.Unanswered != 1 || in.RetriesOfAnsweredTransactions != 0 {
		t.Fatalf("other resolver = %+v", in)
	}
	if r.DNSResolverSummary.Totals.RetriesOfAnsweredTransactions != 0 {
		t.Errorf("totals = %+v", r.DNSResolverSummary.Totals)
	}
	// Outstanding long enough, the anomaly is reported and names the silent resolver.
	pk := [][]byte{
		dkQuery(t, c, dkGoogle, 7, "p.example.net"), dkQuery(t, c, dkInternal, 7, "p.example.net"),
		dkResponse(t, c, dkGoogle, 7, 0, "p.example.net", dkWeb),
	}
	r = runGoldenInterval(t, padPairs(t, pk, 3), time.Second)
	n := noResponseAnomalies(r)
	if len(n) != 1 || n[0].ServerIP != "10.160.4.39" || !strings.Contains(n[0].Reason, "unanswered for") {
		t.Errorf("anomalies = %+v", n)
	}
	assertSummaryAgrees(t, r)
}
