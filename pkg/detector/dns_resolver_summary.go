package detector

import (
	"fmt"
	"math"
	"sort"
	"time"

	"github.com/gocisse/sdwan-triage/pkg/models"
	"github.com/google/gopacket/layers"
)

// Phase 4.32 — DNS resolver response summary. Built once at Finalize from the DNS
// records the analyzer already produced plus two pieces of match metadata recorded while
// correlating (retry groups and ambiguous matches). It changes no record, anomaly,
// finding or metric; it is a separate, bounded view.
const (
	// dnsSummaryMaxResolvers bounds the JSON list; more resolvers are counted, not listed.
	dnsSummaryMaxResolvers = 50
	// dnsSummaryMaxSamples bounds the retained response-time samples per resolver (and for
	// the totals). Min/Max/Samples stay exact; Median/P95 use the first retained samples.
	dnsSummaryMaxSamples = 10000
	dnsSummaryOrder      = "resolvers with more queries first, then by address; display order only"
)

// dnsRCodeLabel names a response code for the summary (including NOERROR).
func dnsRCodeLabel(code uint16) string {
	if layers.DNSResponseCode(code) == layers.DNSResponseCodeNoErr {
		return "NOERROR"
	}
	return dnsResponseCodeName(code)
}

type dnsLatencyAcc struct {
	n        int
	min, max float64
	samples  []float64
}

func (a *dnsLatencyAcc) add(ms float64, maxSamples int) {
	if a.n == 0 || ms < a.min {
		a.min = ms
	}
	if a.n == 0 || ms > a.max {
		a.max = ms
	}
	a.n++
	if len(a.samples) < maxSamples {
		a.samples = append(a.samples, ms)
	}
}

func nearestRank(sorted []float64, p float64) float64 {
	if len(sorted) == 0 {
		return 0
	}
	i := int(math.Ceil(p*float64(len(sorted)))) - 1
	if i < 0 {
		i = 0
	}
	return sorted[i]
}

func (a *dnsLatencyAcc) result() *models.DNSLatency {
	if a.n == 0 {
		return nil
	}
	s := append([]float64(nil), a.samples...)
	sort.Float64s(s)
	return &models.DNSLatency{
		Samples: a.n, MinMs: a.min, MaxMs: a.max,
		MedianMs: nearestRank(s, 0.5), P95Ms: nearestRank(s, 0.95),
		SamplesTruncated: a.n > len(a.samples),
	}
}

type dnsStatsAcc struct {
	stats models.DNSResolverStats
	lat   dnsLatencyAcc
}

func (a *dnsStatsAcc) finish() models.DNSResolverStats {
	s := a.stats
	s.Latency = a.lat.result()
	s.Visibility = dnsVisibility(s)
	return s
}

// dnsVisibility qualifies missing responses. It states counts and what they cannot show;
// it never attributes a missing response to a server, ISP or network failure.
func dnsVisibility(s models.DNSResolverStats) string {
	switch {
	case s.Queries > 0 && s.Answered == 0:
		return "No response was observed for any of these queries. The capture may not contain the reply direction, or replies may " +
			"not have been decodable (for example truncated packets); this does not by itself show that the resolver did not respond."
	case s.Unanswered > 0:
		msg := fmt.Sprintf("%d of %d queries have no observed response", s.Unanswered, s.Queries)
		if s.UnansweredNearCaptureEnd > 0 {
			msg += fmt.Sprintf(" (%d sent within %.0f s of the end of the capture)", s.UnansweredNearCaptureEnd, dnsUnansweredTimeoutSec)
		}
		return msg + ". That can reflect replies this capture point did not see; it does not by itself show where, or whether, a response was lost."
	}
	return ""
}

// isRetryOfAnsweredTransaction reports whether record i is an unanswered later send of a
// transaction (same client, transaction ID and name) whose first query was answered by
// a response matched on client, transaction ID, name and responding address, and that was
// sent to the same address as record i. An ambiguous
// match (name only, or another address) does not establish that the transaction was
// answered, so its repeats stay unanswered. A send of the same transaction to a DIFFERENT
// address is not covered: that address's silence is its own observation, and the answer
// came from elsewhere. The summary and the unanswered-query anomaly
// share this rule so that they cannot disagree.
func isRetryOfAnsweredTransaction(records []models.DNSRecord, lead map[int]int, ambiguous map[int]bool, i int) bool {
	l, ok := lead[i]
	return ok && l != i && records[i].ResponseTimestamp == nil && records[l].ResponseTimestamp != nil && !ambiguous[l] &&
		records[i].DestinationIP == records[l].DestinationIP
}

// buildDNSResolverSummary assembles the summary. lead maps a query index to the first
// query of its retry group (same client, transaction ID and name, sent while no
// response had been observed); ambiguous marks answered queries whose response was
// matched by name only or came from another address. endOfCapture is capture time.
func buildDNSResolverSummary(records []models.DNSRecord, lead map[int]int, ambiguous map[int]bool, endOfCapture time.Time, maxResolvers, maxSamples int) *models.DNSResolverSummary {
	if len(records) == 0 {
		return nil
	}
	end := float64(endOfCapture.UnixNano()) / 1e9
	haveEnd := !endOfCapture.IsZero()
	byResolver := make(map[string]*dnsStatsAcc)
	total := &dnsStatsAcc{stats: models.DNSResolverStats{Resolver: "all"}}

	add := func(acc *dnsStatsAcc, f func(s *models.DNSResolverStats)) { f(&acc.stats) }
	for i := range records {
		r := &records[i]
		acc := byResolver[r.DestinationIP]
		if acc == nil {
			acc = &dnsStatsAcc{stats: models.DNSResolverStats{Resolver: r.DestinationIP}}
			byResolver[r.DestinationIP] = acc
		}
		l, retried := lead[i]
		for _, a := range []*dnsStatsAcc{acc, total} {
			add(a, func(s *models.DNSResolverStats) { s.Queries++ })
			if retried && l == i {
				add(a, func(s *models.DNSResolverStats) { s.RetriedTransactions++ })
			}
		}
		switch {
		case r.ResponseTimestamp != nil:
			ms := (*r.ResponseTimestamp - r.QueryTimestamp) * 1000
			amb := ambiguous[i] || ms < 0
			for _, a := range []*dnsStatsAcc{acc, total} {
				add(a, func(s *models.DNSResolverStats) {
					s.Answered++
					if amb {
						s.AmbiguousMatches++
					}
					if r.ResponseCode != nil {
						if s.ResponseCodes == nil {
							s.ResponseCodes = make(map[string]int)
						}
						s.ResponseCodes[dnsRCodeLabel(*r.ResponseCode)]++
					}
				})
				if !amb && !retried {
					a.lat.add(ms, maxSamples)
				}
			}
		case isRetryOfAnsweredTransaction(records, lead, ambiguous, i):
			// A later send of a transaction whose first query was answered.
			for _, a := range []*dnsStatsAcc{acc, total} {
				add(a, func(s *models.DNSResolverStats) { s.RetriesOfAnsweredTransactions++ })
			}
		default:
			near := haveEnd && end-r.QueryTimestamp < dnsUnansweredTimeoutSec
			for _, a := range []*dnsStatsAcc{acc, total} {
				add(a, func(s *models.DNSResolverStats) {
					s.Unanswered++
					if near {
						s.UnansweredNearCaptureEnd++
					}
				})
			}
		}
	}

	list := make([]*dnsStatsAcc, 0, len(byResolver))
	for _, a := range byResolver {
		list = append(list, a)
	}
	sort.Slice(list, func(i, j int) bool {
		if list[i].stats.Queries != list[j].stats.Queries {
			return list[i].stats.Queries > list[j].stats.Queries
		}
		return list[i].stats.Resolver < list[j].stats.Resolver
	})
	sum := &models.DNSResolverSummary{
		Basis: models.DNSResolverSummaryBasis, Totals: total.finish(),
		ResolversWithData: len(list), MaxResolvers: maxResolvers, Order: dnsSummaryOrder,
		Resolvers: []models.DNSResolverStats{},
	}
	for i, a := range list {
		if i >= maxResolvers {
			sum.OmittedResolvers++
			continue
		}
		sum.Resolvers = append(sum.Resolvers, a.finish())
	}
	sum.ResolversShown = len(sum.Resolvers)
	return sum
}
