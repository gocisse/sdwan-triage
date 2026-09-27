package detector

import (
	"fmt"
	"strings"
	"time"

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
}

// NewDNSAnalyzer creates a new DNS analyzer
func NewDNSAnalyzer() *DNSAnalyzer {
	return &DNSAnalyzer{pending: make(map[dnsPendingKey][]int)}
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
		// transaction-ID index; fall back to the legacy name scan only when the
		// response does not match any outstanding (id, name) pair.
		responseCode := uint16(dns.ResponseCode)
		matchIdx := -1
		pk := dnsPendingKey{id: dns.ID, name: queryName}
		if idxs := d.pending[pk]; len(idxs) > 0 {
			matchIdx = idxs[0]
			if len(idxs) == 1 {
				delete(d.pending, pk)
			} else {
				d.pending[pk] = idxs[1:]
			}
		} else {
			for i := range report.DNSDetails {
				if report.DNSDetails[i].QueryName == queryName && report.DNSDetails[i].ResponseTimestamp == nil {
					matchIdx = i
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

			// Check for anomalies and mark the record
			isAnomalous := false
			reason := ""

			for _, answer := range dns.Answers {
				if answer.Type == layers.DNSTypeA || answer.Type == layers.DNSTypeAAAA {
					answerIP := answer.IP.String()

					// Check if DNS server is non-standard (not a known DNS server)
					if !models.IsPrivateOrReservedIP(srcIP) && !isKnownDNSServer(srcIP) {
						isAnomalous = true
						reason = "Response from non-standard DNS server"
					}

					// Check for private IP in response to public domain query
					if models.IsPublicDomain(queryName) && models.IsPrivateOrReservedIP(answerIP) {
						isAnomalous = true
						reason = "Private IP returned for public domain (possible DNS hijacking)"
					}

					// Check for suspicious TLDs
					if isSuspiciousDomain(queryName) {
						isAnomalous = true
						reason = "Suspicious domain pattern detected"
					}

					if isAnomalous {
						anomaly := models.DNSAnomaly{
							Timestamp: timestamp,
							Query:     queryName,
							AnswerIP:  answerIP,
							ServerIP:  srcIP,
							ServerMAC: srcMAC,
							Reason:    reason,
						}
						report.DNSAnomalies = append(report.DNSAnomalies, anomaly)
					}
				}
			}

			// Failure response codes (NXDOMAIN, SERVFAIL, REFUSED, ...) are
			// anomalies in their own right, independent of the answer section.
			if responseCode != uint16(layers.DNSResponseCodeNoErr) {
				isAnomalous = true
				reason = fmt.Sprintf("DNS %s for %s", dnsResponseCodeName(responseCode), queryName)
				report.DNSAnomalies = append(report.DNSAnomalies, models.DNSAnomaly{
					Timestamp: timestamp,
					Query:     queryName,
					ServerIP:  srcIP,
					ServerMAC: srcMAC,
					Reason:    reason,
				})
			}

			// Update anomaly status on the record
			if isAnomalous {
				report.DNSDetails[i].IsAnomalous = true
				report.DNSDetails[i].Detail = reason
			}
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

		report.DNSAnomalies = append(report.DNSAnomalies, models.DNSAnomaly{
			Timestamp: first.QueryTimestamp,
			Query:     k.name,
			ServerIP:  first.DestinationIP,
			Reason:    reason,
		})
		for _, i := range g.idxs {
			report.DNSDetails[i].IsAnomalous = true
			report.DNSDetails[i].Detail = reason
		}
	}
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
