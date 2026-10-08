package output

import "github.com/gocisse/sdwan-triage/pkg/models"

// healthLevel is the headline NETWORK HEALTH state, ordered so that a higher
// value always wins.
type healthLevel int

const (
	healthGood healthLevel = iota
	healthFair
	healthWarning
	healthCritical
)

// performanceWarnThreshold is the existing combined-count threshold above which
// the performance bucket (retransmission flows, RTT flows, handshake failures)
// escalates the headline from FAIR to WARNING.
const performanceWarnThreshold = 5

// healthVerdict derives the headline health level from evidence the engine has
// already produced. GOOD means only that no significant problem was OBSERVED in
// the analyzed evidence of this capture; it is not a statement that the network
// is healthy (a capture can be short, one-sided or missing handshakes).
//
// The result is a deterministic maximum over per-evidence-class floors:
//
//   - performance bucket: retransmission flows + RTT flows + handshake failures.
//     >0 → at least FAIR, >5 → at least WARNING. Handshake failures come from
//     the handshake tracker when it has data (failed flows only; incomplete
//     flows are never failures); the legacy RST-only count is used only when the
//     tracker has no flows, so nothing is counted twice.
//   - expired TLS certificates → at least WARNING. Suspicious-port flows and
//     self-signed certificates are OBSERVATIONS, not failures: a port number is
//     not proof of an attack and a self-signed certificate is not proof of a
//     network problem, so neither affects health (both stay in the report).
//   - stability findings (BFD/IKE/HSRP/VRRP/STP): High/Critical → at least
//     WARNING, any other severity → at least FAIR. A floor, never a sum: two
//     directional findings for one BFD drop are not worse than one.
//   - Zero Window findings → at least WARNING. Small Window is informational and
//     does not contribute.
//   - Findings with High/Critical severity and a basis other than time_proximity
//     → at least WARNING.
//   - ARP conflicts → CRITICAL (existing behavior, unchanged).
//   - DNS: NOT CRITICAL. Only observed DNS server failures (kind server_failure,
//     e.g. SERVFAIL/REFUSED) count, as distinct (server, name) incidents, in the
//     performance bucket. NXDOMAIN, non-standard server, private answer,
//     suspicious domain and unanswered queries do not affect health: an
//     unanswered query is absence of evidence (capture asymmetry, filtering,
//     truncation), not an observed failure.
//
// RiskScore is intentionally not an input.
func healthVerdict(r *models.TriageReport) healthLevel {
	level := healthGood
	raise := func(l healthLevel) {
		if l > level {
			level = l
		}
	}

	performance := len(r.TCPRetransmissions) + handshakeFailures(r) + len(r.RTTAnalysis) + dnsServerFailureIncidents(r)
	if performance > 0 {
		raise(healthFair)
	}
	if performance > performanceWarnThreshold {
		raise(healthWarning)
	}

	// Only expired certificates escalate (judged against capture time by the TLS
	// detector). SuspiciousTraffic and IsSelfSigned are informational.
	for _, cert := range r.TLSCerts {
		if cert.IsExpired {
			raise(healthWarning)
			break
		}
	}

	for _, s := range r.StabilityFindings {
		if s.Severity == "High" || s.Severity == "Critical" {
			raise(healthWarning)
		} else {
			raise(healthFair)
		}
	}

	for _, w := range r.TCPWindowFindings {
		if w.Type == "Zero Window" {
			raise(healthWarning)
		}
	}

	for _, f := range r.Findings {
		if (f.Severity == models.SeverityHigh || f.Severity == models.SeverityCritical) &&
			f.Basis != models.EvidenceTimeProximity {
			raise(healthWarning)
		}
	}

	// ARP conflicts remain CRITICAL. DNS anomalies no longer do: they are
	// observations, and only observed server failures feed the performance bucket
	// above (see dnsServerFailureIncidents).
	if len(r.ARPConflicts) > 0 {
		raise(healthCritical)
	}
	return level
}

// handshakeFailures returns the number of failed TCP handshakes: the tracker's
// failed flows when the tracker has data, otherwise the legacy RST count.
func handshakeFailures(r *models.TriageReport) int {
	if len(r.TCPHandshakeFlows) > 0 {
		return countHandshakes(r.TCPHandshakeFlows).failed()
	}
	return len(r.FailedHandshakes)
}

// dnsServerFailureIncidents counts distinct DNS server-failure incidents: one
// per (server, query name) pair, so a resolver failing the same name repeatedly
// is one incident rather than one per packet. Anomalies without a kind (for
// example from older JSON) are not interpreted: the kind is never inferred from
// Reason text.
func dnsServerFailureIncidents(r *models.TriageReport) int {
	type incident struct{ server, query string }
	seen := make(map[incident]struct{})
	for _, a := range r.DNSAnomalies {
		if a.Kind == models.DNSKindServerFailure {
			seen[incident{a.ServerIP, a.Query}] = struct{}{}
		}
	}
	return len(seen)
}
