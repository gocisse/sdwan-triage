package detector

import (
	"fmt"
	"testing"
	"time"

	"github.com/gocisse/sdwan-triage/pkg/models"
)

func drRec(server string, q float64, resp *float64) models.DNSRecord {
	return models.DNSRecord{QueryTimestamp: q, QueryName: "n", SourceIP: "10.0.0.1", DestinationIP: server, ResponseTimestamp: resp}
}

func fp(v float64) *float64 { return &v }

func TestNearestRank(t *testing.T) {
	s := []float64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
	if nearestRank(s, 0.5) != 5 || nearestRank(s, 0.95) != 10 || nearestRank([]float64{7}, 0.95) != 7 || nearestRank(nil, 0.5) != 0 {
		t.Errorf("nearest rank = %v %v", nearestRank(s, 0.5), nearestRank(s, 0.95))
	}
}

func TestResolverSummary_ResolverListIsBoundedAndCounted(t *testing.T) {
	var recs []models.DNSRecord
	for i := 0; i < 60; i++ {
		recs = append(recs, drRec(fmt.Sprintf("10.9.0.%d", i), float64(i), nil))
	}
	sum := buildDNSResolverSummary(recs, nil, nil, time.Unix(1000, 0), 50, 100)
	if sum.ResolversWithData != 60 || sum.ResolversShown != 50 || sum.OmittedResolvers != 10 || len(sum.Resolvers) != 50 {
		t.Errorf("bounds = %d/%d/%d", sum.ResolversWithData, sum.ResolversShown, sum.OmittedResolvers)
	}
	if sum.Totals.Queries != 60 {
		t.Errorf("totals must cover omitted resolvers too: %+v", sum.Totals)
	}
	if sum.Resolvers[0].Resolver != "10.9.0.0" || sum.Resolvers[1].Resolver != "10.9.0.1" { // ties by address (string)
		t.Errorf("tie order = %s, %s", sum.Resolvers[0].Resolver, sum.Resolvers[1].Resolver)
	}
}

func TestResolverSummary_SampleBoundKeepsMinMaxCountExact(t *testing.T) {
	var recs []models.DNSRecord
	for i := 0; i < 8; i++ {
		q := float64(i * 10)
		recs = append(recs, drRec("10.9.0.1", q, fp(q+float64(i+1)/1000))) // latencies 1..8 ms
	}
	sum := buildDNSResolverSummary(recs, nil, nil, time.Unix(1000, 0), 50, 5)
	l := sum.Totals.Latency
	if l == nil || l.Samples != 8 || !l.SamplesTruncated {
		t.Fatalf("latency = %+v", l)
	}
	if l.MinMs < 0.99 || l.MinMs > 1.01 || l.MaxMs < 7.99 || l.MaxMs > 8.01 {
		t.Errorf("min/max must cover all samples: %+v", l)
	}
	if l.MedianMs > 3.01 { // median over the first 5 retained samples (1..5 ms)
		t.Errorf("median over retained samples = %v", l.MedianMs)
	}
}

func TestResolverSummary_NegativeLatencyIsAmbiguousNotASample(t *testing.T) {
	recs := []models.DNSRecord{drRec("10.9.0.1", 10, fp(9.5))}
	sum := buildDNSResolverSummary(recs, nil, nil, time.Unix(1000, 0), 50, 100)
	if sum.Totals.Latency != nil || sum.Totals.AmbiguousMatches != 1 {
		t.Errorf("totals = %+v", sum.Totals)
	}
}

func TestResolverSummary_RetryOfAmbiguousAnswerStaysUnanswered(t *testing.T) {
	recs := []models.DNSRecord{drRec("10.9.0.1", 0, fp(1)), drRec("10.9.0.1", 0.1, nil)}
	lead := map[int]int{0: 0, 1: 0}
	sum := buildDNSResolverSummary(recs, lead, map[int]bool{0: true}, time.Unix(1000, 0), 50, 100)
	if sum.Totals.RetriesOfAnsweredTransactions != 0 || sum.Totals.Unanswered != 1 {
		t.Errorf("totals = %+v", sum.Totals)
	}
	sum = buildDNSResolverSummary(recs, lead, nil, time.Unix(1000, 0), 50, 100)
	if sum.Totals.RetriesOfAnsweredTransactions != 1 || sum.Totals.Unanswered != 0 {
		t.Errorf("unambiguous lead: totals = %+v", sum.Totals)
	}
}

func TestResolverSummary_NilWithoutRecords(t *testing.T) {
	if buildDNSResolverSummary(nil, nil, nil, time.Now(), 50, 100) != nil {
		t.Error("summary for no records")
	}
}
