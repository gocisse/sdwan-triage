package models

// DNS resolver response summary (Phase 4.32).
//
// A bounded, observational account of how many DNS queries in the capture have an
// OBSERVED response, how fast the unambiguous ones were answered, and which response
// codes came back, grouped by the address the queries were sent to. It exists to
// answer "is DNS slow or failing, or can this capture simply not see the replies?".
//
// It never says that a resolver, an ISP or the network failed to answer: a missing
// response is an absence of evidence at this capture point (one-direction captures,
// truncated or undecodable replies, capture duplicates and the end of the capture all
// produce it). It feeds no finding, health, risk or exit-code decision.

// DNSResolverSummaryBasis explains how to read the numbers.
const DNSResolverSummaryBasis = "Queries are grouped by the address they were sent to. A response is 'observed' only if it was " +
	"captured, decoded and matched to a query. Response time is the capture time of the response minus the query, and is reported only " +
	"for responses matched by client, transaction ID, name and responding address to a query that was sent once; retried, name-only " +
	"and different-address matches are counted separately and excluded from it. A missing response is an absence of evidence at " +
	"this capture point, not proof that the resolver or the network did not answer."

// DNSLatency summarizes response times in milliseconds of capture time.
type DNSLatency struct {
	Samples  int     `json:"samples"`
	MinMs    float64 `json:"min_ms"`
	MedianMs float64 `json:"median_ms"` // nearest-rank over the retained samples
	P95Ms    float64 `json:"p95_ms"`    // nearest-rank over the retained samples
	MaxMs    float64 `json:"max_ms"`
	// SamplesTruncated: more samples than the retention bound existed; Min/Max/Samples
	// cover all of them, Median/P95 only the first retained ones (record order).
	SamplesTruncated bool `json:"samples_truncated,omitempty"`
}

// DNSResolverStats is the account for one queried address (or, for Totals, all).
type DNSResolverStats struct {
	Resolver string `json:"resolver"` // address the queries were sent to; "all" for the totals
	Queries  int    `json:"queries"`  // DNS query records
	Answered int    `json:"answered"` // queries with an observed response
	// RetriesOfAnsweredTransactions: queries sent again with the same client, transaction
	// ID and name whose transaction did receive an observed response (to the first query).
	RetriesOfAnsweredTransactions int `json:"retries_of_answered_transactions,omitempty"`
	// Unanswered: queries with no observed response (not counting the retries above).
	Unanswered int `json:"unanswered"`
	// UnansweredNearCaptureEnd: the subset of Unanswered sent within 2 s (capture time)
	// of the last packet, which the end of the capture may simply have cut off.
	UnansweredNearCaptureEnd int `json:"unanswered_near_capture_end,omitempty"`
	// RetriedTransactions: transactions (client, transaction ID, name) sent more than once.
	RetriedTransactions int `json:"retried_transactions,omitempty"`
	// AmbiguousMatches: answered queries whose response was matched by name only or came
	// from an address other than the one queried; they are excluded from Latency.
	AmbiguousMatches int            `json:"ambiguous_matches,omitempty"`
	ResponseCodes    map[string]int `json:"response_codes,omitempty"` // over answered queries, by RCODE name
	Latency          *DNSLatency    `json:"response_time,omitempty"`
	// Visibility qualifies missing responses in plain language; empty when every query was answered.
	Visibility string `json:"visibility,omitempty"`
}

// DNSResolverSummary is the additive JSON object `dns_resolver_summary`; absent when
// the capture holds no DNS query.
type DNSResolverSummary struct {
	Basis             string             `json:"basis"`
	Totals            DNSResolverStats   `json:"totals"`
	ResolversWithData int                `json:"resolvers_with_queries"`
	ResolversShown    int                `json:"resolvers_shown"`
	OmittedResolvers  int                `json:"omitted_resolvers,omitempty"`
	MaxResolvers      int                `json:"max_resolvers"`
	Order             string             `json:"order"`
	Resolvers         []DNSResolverStats `json:"resolvers"`
}
