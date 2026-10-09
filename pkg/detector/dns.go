package detector

import (
	"fmt"
	"strings"
	"time"

	"github.com/gocisse/sdwan-triage/pkg/events"
	"github.com/gocisse/sdwan-triage/pkg/models"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// DNS unanswered-query policy (capture time).
const (
	// dnsUnansweredTimeoutSec: a single query with no response within this many
	// seconds before end of capture is reported as unanswered.
	dnsUnansweredTimeoutSec = 2.0
	// dnsUnansweredRetryMin: the same (client, name) sent this many times with no
	// response is reported regardless of elapsed time (retries are evidence).
	dnsUnansweredRetryMin = 2
)

// dnsPendingKey identifies an outstanding query by transaction ID and name.
type dnsPendingKey struct {
	id   uint16
	name string
}

// DNSAnalyzer handles DNS packet analysis
type DNSAnalyzer struct {
	// pending maps an outstanding query to the indexes of its DNSDetails
	// records (FIFO; retries share id+name). Bounded by the number of
	// unanswered queries in the capture; answered entries are removed.
	pending map[dnsPendingKey][]int

	// Match metadata for the resolver summary (Phase 4.32). It only OBSERVES how the
	// existing correlation behaved; it changes no match decision.
	//   lead: query index -> index of the first query of its retry group (same client,
	//   transaction ID and name sent again while no response had been observed).
	//   ambiguous: answered query whose response was matched by name only, or came from
	//   an address other than the one queried.
	lead      map[int]int
	ambiguous map[int]bool
}

// NewDNSAnalyzer creates a new DNS analyzer
func NewDNSAnalyzer() *DNSAnalyzer {
	return &DNSAnalyzer{pending: make(map[dnsPendingKey][]int), lead: make(map[int]int), ambiguous: make(map[int]bool)}
}

// dnsResponseCodeName maps failure RCODEs to their conventional names.
func dnsResponseCodeName(code uint16) string {
	switch layers.DNSResponseCode(code) {
	case layers.DNSResponseCodeFormErr:
		return "FORMERR"
	case layers.DNSResponseCodeServFail:
		return "SERVFAIL"
	case layers.DNSResponseCodeNXDomain:
		return "NXDOMAIN"
	case layers.DNSResponseCodeNotImp:
		return "NOTIMP"
	case layers.DNSResponseCodeRefused:
		return "REFUSED"
	default:
		return fmt.Sprintf("RCODE %d", code)
	}
}

// dnsFailureKind classifies a failure RCODE. NXDOMAIN means the name does not
// exist, which is an ordinary resolution result; every other failure RCODE is a
// server/protocol failure.
func dnsFailureKind(code uint16) string {
	if layers.DNSResponseCode(code) == layers.DNSResponseCodeNXDomain {
		return models.DNSKindNXDomain
	}
	return models.DNSKindServerFailure
}

// Analyze processes a DNS packet and updates the report
func (d *DNSAnalyzer) Analyze(packet gopacket.Packet, state *models.AnalysisState, report *models.TriageReport) {
	dnsLayer := packet.Layer(layers.LayerTypeDNS)
	if dnsLayer == nil {
		return
	}

	dns, ok := dnsLayer.(*layers.DNS)
	if !ok {
		return
	}

	// Get network layer info (supports IPv4 and IPv6)
	ipInfo := ExtractIPInfo(packet)
	if ipInfo == nil {
		return
	}
	srcIP := ipInfo.SrcIP
	dstIP := ipInfo.DstIP

	// Get MAC address from Ethernet layer
	var srcMAC string
	if ethLayer := packet.Layer(layers.LayerTypeEthernet); ethLayer != nil {
		eth := ethLayer.(*layers.Ethernet)
		srcMAC = eth.SrcMAC.String()
	}

	timestamp := float64(packet.Metadata().Timestamp.UnixNano()) / 1e9

	// Track DNS queries
	if dns.QR == false && len(dns.Questions) > 0 {
		queryName := string(dns.Questions[0].Name)
		state.DNSQueries[dns.ID] = queryName

		// Add to DNS details
		queryType := dns.Questions[0].Type.String()
		record := models.DNSRecord{
			QueryTimestamp: timestamp,
			QueryName:      queryName,
			QueryType:      queryType,
			SourceIP:       srcIP,
			DestinationIP:  dstIP,
			AnswerIPs:      []string{},
			AnswerNames:    []string{},
		}
		report.DNSDetails = append(report.DNSDetails, record)
		pk := dnsPendingKey{id: dns.ID, name: queryName}
		if prior := d.pending[pk]; len(prior) > 0 {
			// Same transaction ID and name while a query of it is still unanswered: a retry
			// (or a capture duplicate). Record the group; the match logic is unchanged.
			for _, idx := range prior {
				if report.DNSDetails[idx].SourceIP == srcIP {
					l, ok := d.lead[idx]
					if !ok {
						l = idx
						d.lead[idx] = idx
					}
					d.lead[len(report.DNSDetails)-1] = l
					break
				}
			}
		}
		d.pending[pk] = append(d.pending[pk], len(report.DNSDetails)-1)

		// Add timeline event
		event := models.TimelineEvent{
			Timestamp:     timestamp,
			EventType:     "DNS Query",
			SourceIP:      srcIP,
			DestinationIP: dstIP,
			Protocol:      "DNS",
			Detail:        fmt.Sprintf("Query: %s (%s)", queryName, queryType),
		}
		report.AddTimelineEvent(event)
	}

	// Analyze DNS responses
	if dns.QR == true {
		queryName := state.DNSQueries[dns.ID]
		if queryName == "" && len(dns.Questions) > 0 {
			queryName = string(dns.Questions[0].Name)
		}

		// Find and update the corresponding DNS query record. Prefer the O(1)
		// transaction-ID index, and only accept an indexed entry whose client is
		// the response's destination. Fall back to a name scan only when no
		// (id, name) entry matches, and even then require the same client: a
		// response must never be credited to an unrelated client's query merely
		// because the queried name is identical.
		responseCode := uint16(dns.ResponseCode)
		matchIdx := -1
		pk := dnsPendingKey{id: dns.ID, name: queryName}
		if idxs := d.pending[pk]; len(idxs) > 0 {
			for j, idx := range idxs {
				if report.DNSDetails[idx].SourceIP == dstIP {
					matchIdx = idx
					if report.DNSDetails[idx].DestinationIP != srcIP {
						d.ambiguous[idx] = true // answered from an address other than the one queried
					}
					d.pending[pk] = append(idxs[:j:j], idxs[j+1:]...)
					if len(d.pending[pk]) == 0 {
						delete(d.pending, pk)
					}
					break
				}
			}
		}
		if matchIdx < 0 {
			for i := range report.DNSDetails {
				rec := &report.DNSDetails[i]
				if rec.QueryName == queryName && rec.ResponseTimestamp == nil && rec.SourceIP == dstIP {
					matchIdx = i
					d.ambiguous[i] = true // matched by name only: the transaction ID differs
					break
				}
			}
		}
		if i := matchIdx; i >= 0 && report.DNSDetails[i].ResponseTimestamp == nil {
			// Update the record with response data
			report.DNSDetails[i].ResponseTimestamp = &timestamp
			report.DNSDetails[i].ResponseCode = &responseCode

			// Collect all answer IPs and names
			for _, answer := range dns.Answers {
				if answer.Type == layers.DNSTypeA || answer.Type == layers.DNSTypeAAAA {
					if answer.IP != nil {
						report.DNSDetails[i].AnswerIPs = append(report.DNSDetails[i].AnswerIPs, answer.IP.String())
					}
				} else if answer.Type == layers.DNSTypeCNAME {
					report.DNSDetails[i].AnswerNames = append(report.DNSDetails[i].AnswerNames, string(answer.CNAME))
				}
			}

			// Check for anomalies and mark the record. The heuristics run per
			// answer, but an anomaly is emitted at most once per response and
			// kind: a response carrying six A records is one observation, not six.
			isAnomalous := false
			reason := ""
			emitted := make(map[string]bool)
			emit := func(kind, why, answerIP string) {
				isAnomalous = true
				reason = why
				if emitted[kind] {
					return
				}
				emitted[kind] = true
				anomaly := models.DNSAnomaly{
					Timestamp: timestamp,
					Query:     queryName,
					AnswerIP:  answerIP,
					ServerIP:  srcIP,
					ServerMAC: srcMAC,
					Reason:    why,
					Kind:      kind,
				}
				report.DNSAnomalies = append(report.DNSAnomalies, anomaly)
				emitDNSAnomaly(report, packet.Metadata().Timestamp, anomaly)
			}

			for _, answer := range dns.Answers {
				if answer.Type == layers.DNSTypeA || answer.Type == layers.DNSTypeAAAA {
					answerIP := answer.IP.String()

					// Check if DNS server is non-standard (not a known DNS server)
					if !models.IsPrivateOrReservedIP(srcIP) && !isKnownDNSServer(srcIP) {
						emit(models.DNSKindNonStandardServer, "Response from non-standard DNS server", answerIP)
					}

					// Check for private IP in response to public domain query
					if models.IsPublicDomain(queryName) && models.IsPrivateOrReservedIP(answerIP) {
						emit(models.DNSKindPrivateAnswer, "Private IP returned for public domain (possible DNS hijacking)", answerIP)
					}

					// Check for suspicious TLDs
					if isSuspiciousDomain(queryName) {
						emit(models.DNSKindSuspiciousDomain, "Suspicious domain pattern detected", answerIP)
					}
				}
			}

			// Failure response codes mark the matched record as anomalous
			// (the anomaly itself is emitted below, matched or not).
			if responseCode != uint16(layers.DNSResponseCodeNoErr) {
				isAnomalous = true
				reason = fmt.Sprintf("DNS %s for %s", dnsResponseCodeName(responseCode), queryName)
			}

			// Update anomaly status on the record
			if isAnomalous {
				report.DNSDetails[i].IsAnomalous = true
				report.DNSDetails[i].Detail = reason
			}
		}

		// Failure response codes (NXDOMAIN, SERVFAIL, REFUSED, ...) are
		// anomalies in their own right: they are evidence about the response
		// and its addressee even when the originating query is not in the
		// capture (asymmetric capture points), so they are recorded whether or
		// not a pending query record was matched above.
		if responseCode != uint16(layers.DNSResponseCodeNoErr) && queryName != "" {
			anomaly := models.DNSAnomaly{
				Timestamp: timestamp,
				Query:     queryName,
				ServerIP:  srcIP,
				ServerMAC: srcMAC,
				Reason:    fmt.Sprintf("DNS %s for %s", dnsResponseCodeName(responseCode), queryName),
				Kind:      dnsFailureKind(responseCode),
			}
			report.DNSAnomalies = append(report.DNSAnomalies, anomaly)
			emitDNSAnomaly(report, packet.Metadata().Timestamp, anomaly)
		}

		// Add timeline event for response
		if len(dns.Answers) > 0 {
			var firstAnswerIP string
			for _, answer := range dns.Answers {
				if answer.Type == layers.DNSTypeA || answer.Type == layers.DNSTypeAAAA {
					firstAnswerIP = answer.IP.String()
					break
				}
			}
			event := models.TimelineEvent{
				Timestamp:     timestamp,
				EventType:     "DNS Response",
				SourceIP:      srcIP,
				DestinationIP: dstIP,
				Protocol:      "DNS",
				Detail:        fmt.Sprintf("Response: %s -> %s (code: %d)", queryName, firstAnswerIP, responseCode),
			}
			report.AddTimelineEvent(event)
		}
	}
}

// Finalize reports queries that never received a response. endOfCapture is the
// capture timestamp of the last packet; wall-clock time must never be used.
//
// A query is considered unanswered when either
//   - the same (client, name) was sent at least dnsUnansweredRetryMin times
//     without any response (client-side retries are direct evidence), or
//   - a single query has been outstanding for at least dnsUnansweredTimeoutSec
//     of capture time when the capture ends.
//
// One anomaly is emitted per (client, name) pair.
func (d *DNSAnalyzer) Finalize(endOfCapture time.Time, report *models.TriageReport) {
	// Observational per-resolver response summary (Phase 4.32). It shares
	// isRetryOfAnsweredTransaction with the unanswered-query anomalies below so the two
	// cannot disagree about which sends belong to an answered transaction.
	report.DNSResolverSummary = buildDNSResolverSummary(report.DNSDetails, d.lead, d.ambiguous, endOfCapture, dnsSummaryMaxResolvers, dnsSummaryMaxSamples)

	if endOfCapture.IsZero() || len(report.DNSDetails) == 0 {
		return
	}
	end := float64(endOfCapture.UnixNano()) / 1e9

	type group struct {
		idxs []int // indexes of unanswered records, earliest first
	}
	type groupKey struct{ client, name string }
	groups := make(map[groupKey]*group)
	var order []groupKey

	for i := range report.DNSDetails {
		rec := &report.DNSDetails[i]
		if rec.ResponseTimestamp != nil {
			continue
		}
		// A repeated send of a transaction that WAS answered (unambiguously) is not an
		// unanswered query: the client asked again and the transaction received its
		// response. Genuinely unanswered transactions, including other transactions for
		// the same name, are still reported.
		if isRetryOfAnsweredTransaction(report.DNSDetails, d.lead, d.ambiguous, i) {
			continue
		}
		k := groupKey{rec.SourceIP, rec.QueryName}
		g, ok := groups[k]
		if !ok {
			g = &group{}
			groups[k] = g
			order = append(order, k)
		}
		g.idxs = append(g.idxs, i)
	}

	for _, k := range order {
		g := groups[k]
		first := &report.DNSDetails[g.idxs[0]]
		outstanding := end - first.QueryTimestamp

		var reason string
		switch {
		case len(g.idxs) >= dnsUnansweredRetryMin:
			reason = fmt.Sprintf("No response: %s queried %s %d times without an answer", k.client, k.name, len(g.idxs))
		case outstanding >= dnsUnansweredTimeoutSec:
			reason = fmt.Sprintf("No response: query for %s unanswered for %.1fs before end of capture", k.name, outstanding)
		default:
			continue // may simply be cut off by the end of the capture
		}

		anomaly := models.DNSAnomaly{
			Timestamp: first.QueryTimestamp,
			Query:     k.name,
			ServerIP:  first.DestinationIP,
			Reason:    reason,
			Kind:      models.DNSKindNoResponse,
		}
		report.DNSAnomalies = append(report.DNSAnomalies, anomaly)
		// Finalize runs after the last packet: stamp with the first unanswered
		// query's own capture time, not the "current" (last) packet.
		emitDNSAnomaly(report, time.Unix(0, int64(first.QueryTimestamp*1e9)).UTC(), anomaly)
		for _, i := range g.idxs {
			report.DNSDetails[i].IsAnomalous = true
			report.DNSDetails[i].Detail = reason
		}
	}
}

// emitDNSAnomaly mirrors a DNSAnomaly into the typed event store.
func emitDNSAnomaly(report *models.TriageReport, ts time.Time, a models.DNSAnomaly) {
	attrs := map[string]string{"query": a.Query, "reason": a.Reason, "server_ip": a.ServerIP}
	if a.Kind != "" {
		attrs["kind"] = a.Kind
	}
	if a.AnswerIP != "" {
		attrs["answer_ip"] = a.AnswerIP
	}
	// Event timestamps are normalised to UTC at this boundary so packet-time and
	// finalize-time DNS events serialise identically (same instant either way).
	report.Emit(events.Event{
		Kind:      events.DNSAnomaly,
		Timestamp: ts.UTC(),
		Attrs:     attrs,
		Source:    "DNS",
	})
}

// isKnownDNSServer checks if an IP is a known public DNS server
func isKnownDNSServer(ip string) bool {
	knownDNS := map[string]bool{
		"8.8.8.8":        true, // Google
		"8.8.4.4":        true, // Google
		"1.1.1.1":        true, // Cloudflare
		"1.0.0.1":        true, // Cloudflare
		"9.9.9.9":        true, // Quad9
		"208.67.222.222": true, // OpenDNS
		"208.67.220.220": true, // OpenDNS
		"64.6.64.6":      true, // Verisign
		"64.6.65.6":      true, // Verisign
	}
	return knownDNS[ip]
}

// isSuspiciousDomain checks for suspicious domain patterns
func isSuspiciousDomain(domain string) bool {
	domain = strings.ToLower(domain)

	// Check for suspicious TLDs
	suspiciousTLDs := []string{".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".work", ".click"}
	for _, tld := range suspiciousTLDs {
		if strings.HasSuffix(domain, tld) {
			return true
		}
	}

	// Check for excessive subdomains (potential DGA)
	parts := strings.Split(domain, ".")
	if len(parts) > 5 {
		return true
	}

	// Check for very long domain names (potential DGA)
	if len(domain) > 50 {
		return true
	}

	return false
}
