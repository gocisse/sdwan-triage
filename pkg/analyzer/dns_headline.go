package analyzer

import (
	"fmt"
	"strings"

	"github.com/gocisse/sdwan-triage/pkg/models"
)

// Phase 4.40 — the legacy headline (risk score, top issue, recommended actions, plain-English
// summary) used to count EVERY DNS anomaly as critical and to name attacks. DNS observations
// that are ordinary results or heuristics — NXDOMAIN, no observed response, a responder
// outside the built-in resolver list, a name matching the TLD/label/length heuristics — stay
// visible in dns_anomalies and dns_resolver_summary but do not, by themselves, score or become
// the top issue. This matches models.ComputeNetworkHealth, which reads only server_failure.
// An anomaly with no kind (older reports) is still counted, as before.

// dnsObservationOnly reports whether an anomaly kind is an ordinary result or a heuristic
// match that must not independently drive the risk score.
func dnsObservationOnly(kind string) bool {
	switch kind {
	case models.DNSKindNXDomain, models.DNSKindNoResponse, models.DNSKindNonStandardServer, models.DNSKindSuspiciousDomain:
		return true
	}
	return false
}

// dnsRiskCount counts the DNS anomalies that contribute to the risk score and top issue:
// server failures and private-address answers (and unclassified anomalies).
func dnsRiskCount(r *models.TriageReport) (total, serverFailures, privateAnswers int) {
	for _, a := range r.DNSAnomalies {
		if dnsObservationOnly(a.Kind) {
			continue
		}
		total++
		switch a.Kind {
		case models.DNSKindServerFailure:
			serverFailures++
		case models.DNSKindPrivateAnswer:
			privateAnswers++
		}
	}
	return total, serverFailures, privateAnswers
}

// dnsActionText is the neutral, evidence-directed DNS recommendation. It only restates counts
// the report holds and points at the sections that show them.
func dnsActionText(r *models.TriageReport) string {
	_, sf, pa := dnsRiskCount(r)
	var parts []string
	if sf > 0 {
		parts = append(parts, fmt.Sprintf("%d DNS server failure response(s)", sf))
	}
	if pa > 0 {
		parts = append(parts, fmt.Sprintf("%d private-address answer(s) for public names", pa))
	}
	if len(parts) == 0 {
		parts = append(parts, "DNS anomalies")
	}
	text := "MEDIUM: " + strings.Join(parts, " and ") + " observed (see dns_anomalies)."
	if pa > 0 {
		text += " A private answer can come from split-horizon or filtering DNS as well as manipulation; the capture does not show which."
	}
	if s := dnsSilentResolvers(r); s != "" {
		text += " " + s
	}
	if s := dnsICMPPointer(r); s != "" {
		text += " " + s
	}
	return text + " For reply counts and response times see dns_resolver_summary."
}

// dnsSilentResolvers names queried addresses with queries and no observed reply (at most 3).
func dnsSilentResolvers(r *models.TriageReport) string {
	s := r.DNSResolverSummary
	if s == nil {
		return ""
	}
	var parts []string
	for _, res := range s.Resolvers {
		if res.Queries > 0 && res.Answered == 0 {
			noun := "queries"
			if res.Queries == 1 {
				noun = "query"
			}
			parts = append(parts, fmt.Sprintf("%s (%d %s, 0 replies observed)", res.Resolver, res.Queries, noun))
			if len(parts) == 3 {
				break
			}
		}
	}
	if len(parts) == 0 {
		return ""
	}
	return "Queried addresses with no observed reply: " + strings.Join(parts, "; ") + " — the capture may not contain the return direction."
}

// dnsICMPPointer lists ICMP errors that quote DNS queries (destination port 53), at most 3 groups.
func dnsICMPPointer(r *models.TriageReport) string {
	e := r.ICMPErrorEvidence
	if e == nil {
		return ""
	}
	var parts []string
	for _, g := range e.Errors {
		if g.Quoted.Status != "complete" || g.Quoted.DstPort != 53 || g.Quoted.Protocol != "UDP" {
			continue
		}
		p := fmt.Sprintf("%s type %d code %d from %s ×%d about queries to %s", g.Family, g.Type, g.Code, g.Reporter, g.Count, g.Quoted.Dst)
		if g.FirstFrame > 0 {
			p += fmt.Sprintf(" (first frame %d)", g.FirstFrame)
		}
		parts = append(parts, p)
		if len(parts) == 3 {
			break
		}
	}
	if len(parts) == 0 {
		return ""
	}
	return "ICMP errors quoting DNS queries (see icmp_error_evidence): " + strings.Join(parts, "; ") + "."
}

const dnsTunnelingActionText = "MEDIUM: DNS tunneling heuristic matched (see dns_tunneling_findings). It rests on query length, subdomain count and entropy only; " +
	"legitimate infrastructure and cloud domains can trigger it. This is not confirmation of tunneling or of malicious activity — review the listed domains and queries before drawing conclusions."

// dnsSummaryLine is the plain-English DNS key finding, consistent with the scoring above.
func dnsSummaryLine(r *models.TriageReport) string {
	if len(r.DNSAnomalies) == 0 {
		return ""
	}
	_, sf, pa := dnsRiskCount(r)
	other := len(r.DNSAnomalies) - sf - pa
	top := r.DNSAnomalies[0].Query
	if sf+pa > 0 {
		return fmt.Sprintf("⚠️ DNS: %d server failure(s) and %d private-address answer(s) observed, plus %d other DNS observation(s) such as NXDOMAIN or no observed reply. Top affected domain: %s",
			sf, pa, other, top)
	}
	return fmt.Sprintf("ℹ️ DNS: %d observation(s) such as NXDOMAIN, no observed reply or an unlisted responder; these are not by themselves a DNS fault (see dns_resolver_summary). First affected domain: %s",
		other, top)
}

// dnsTunnelingSourceCount counts the distinct, non-empty source IPs among the DNS-tunneling
// heuristic matches. A source is never inferred from a domain or server address.
func dnsTunnelingSourceCount(r *models.TriageReport) int {
	seen := make(map[string]struct{})
	for _, f := range r.DNSTunnelingFindings {
		if f.SourceIP != "" {
			seen[f.SourceIP] = struct{}{}
		}
	}
	return len(seen)
}
