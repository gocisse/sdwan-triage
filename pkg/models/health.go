package models

// Network health: the ONE authoritative computation of the headline health level.
//
// It lives in models (which imports only events) because both the analyzer
// (which stores the result on the report in Process) and the output package
// (which renders it) must reach it, and output imports analyzer. Every output
// surface reads TriageReport.NetworkHealth; none computes its own thresholds.
//
// NO_DATA is an analysis status, not a health level: it never reaches this
// function's callers as a level (see TriageReport.AnalysisStatus).

// Network health levels (machine-readable, lowercase).
const (
	NetworkHealthGood     = "good"
	NetworkHealthFair     = "fair"
	NetworkHealthWarning  = "warning"
	NetworkHealthCritical = "critical"
)

// healthRank orders the levels so that a higher value always wins.
var healthRank = map[string]int{
	NetworkHealthGood:     0,
	NetworkHealthFair:     1,
	NetworkHealthWarning:  2,
	NetworkHealthCritical: 3,
}

// HealthPerformanceWarnThreshold is the combined-count threshold above which the
// performance bucket (retransmission flows, RTT flows, handshake failures, DNS
// server-failure incidents) escalates the headline from FAIR to WARNING.
const HealthPerformanceWarnThreshold = 5

// ComputeNetworkHealth derives the headline health level from evidence the engine
// has already produced. "good" means only that no significant problem was
// OBSERVED in the analyzed evidence of this capture; it is not a statement that
// the network is healthy (a capture can be short, one-sided or missing handshakes).
//
// The result is a deterministic maximum over per-evidence-class floors:
//
//   - performance bucket: retransmission flows + RTT flows + handshake failures +
//     DNS server-failure incidents. >0 → at least fair, >5 → at least warning.
//     Handshake failures come from the handshake tracker when it has data (failed
//     flows only; incomplete flows are never failures); the legacy RST-only count
//     is used only when the tracker has no flows, so nothing is counted twice.
//   - expired TLS certificates → at least warning. Suspicious-port flows and
//     self-signed certificates are OBSERVATIONS, not failures: a port number is
//     not proof of an attack and a self-signed certificate is not proof of a
//     network problem, so neither affects health (both stay in the report).
//   - stability findings (BFD/IKE/HSRP/VRRP/STP): High/Critical → at least
//     warning, any other severity → at least fair. A floor, never a sum.
//   - Zero Window findings → at least warning. Small Window is informational.
//   - Findings with High/Critical severity and a basis other than time_proximity
//     → at least warning.
//   - ARP conflicts → critical.
//   - DNS: never critical. Only observed DNS server failures (kind server_failure)
//     count, as distinct (server, name) incidents, in the performance bucket.
//     NXDOMAIN, non-standard server, private answer, suspicious domain and
//     unanswered queries do not affect health: an unanswered query is absence of
//     evidence, not an observed failure.
//
// RiskScore is intentionally not an input.
func ComputeNetworkHealth(r *TriageReport) string {
	level := NetworkHealthGood
	raise := func(l string) {
		if healthRank[l] > healthRank[level] {
			level = l
		}
	}

	performance := len(r.TCPRetransmissions) + HandshakeFailures(r) + len(r.RTTAnalysis) + DNSServerFailureIncidents(r)
	if performance > 0 {
		raise(NetworkHealthFair)
	}
	if performance > HealthPerformanceWarnThreshold {
		raise(NetworkHealthWarning)
	}

	// Only expired certificates escalate (judged against capture time by the TLS
	// detector). SuspiciousTraffic and IsSelfSigned are informational.
	for _, cert := range r.TLSCerts {
		if cert.IsExpired {
			raise(NetworkHealthWarning)
			break
		}
	}

	for _, s := range r.StabilityFindings {
		if s.Severity == "High" || s.Severity == "Critical" {
			raise(NetworkHealthWarning)
		} else {
			raise(NetworkHealthFair)
		}
	}

	for _, w := range r.TCPWindowFindings {
		if w.Type == "Zero Window" {
			raise(NetworkHealthWarning)
		}
	}

	for _, f := range r.Findings {
		if (f.Severity == SeverityHigh || f.Severity == SeverityCritical) &&
			f.Basis != EvidenceTimeProximity {
			raise(NetworkHealthWarning)
		}
	}

	if len(r.ARPConflicts) > 0 {
		raise(NetworkHealthCritical)
	}
	return level
}

// HandshakeFailures returns the number of failed TCP handshakes: the tracker's
// failed flows when the tracker has data (flows still pending at the end of the
// capture are incomplete, never failures), otherwise the legacy RST count.
func HandshakeFailures(r *TriageReport) int {
	if len(r.TCPHandshakeFlows) > 0 {
		n := 0
		for _, f := range r.TCPHandshakeFlows {
			if f.State == "Handshake Failed" {
				n++
			}
		}
		return n
	}
	return len(r.FailedHandshakes)
}

// DNSServerFailureIncidents counts distinct DNS server-failure incidents: one per
// (server, query name) pair, so a resolver failing the same name repeatedly is
// one incident rather than one per packet. Anomalies without a kind (for example
// from older JSON) are not interpreted: the kind is never inferred from Reason text.
func DNSServerFailureIncidents(r *TriageReport) int {
	type incident struct{ server, query string }
	seen := make(map[incident]struct{})
	for _, a := range r.DNSAnomalies {
		if a.Kind == DNSKindServerFailure {
			seen[incident{a.ServerIP, a.Query}] = struct{}{}
		}
	}
	return len(seen)
}

// PlainEnglishHealthLabel maps a network-health level to the legacy three-label
// vocabulary (and CSS classes) used by plain_english_summary.overall_health, so
// the existing consumers keep working: good→Healthy, fair/warning→Warning,
// critical→Critical.
func PlainEnglishHealthLabel(level string) (label, icon, color string) {
	switch level {
	case NetworkHealthGood:
		return "Healthy", "🟢", "health-good"
	case NetworkHealthFair, NetworkHealthWarning:
		return "Warning", "🟡", "health-warning"
	default:
		return "Critical", "🔴", "health-critical"
	}
}

// EvidenceCoverage counts, per health-relevant evidence class, the units of
// input the analysis actually saw. It answers one binary question — "did this
// class have anything to evaluate?" — and deliberately NOT "was there enough to
// be confident": there are no sufficiency thresholds, so a single SYN gives
// tcp_flows = 1.
//
// Sources (all finalized state, no hot-path counters):
//   - TCPFlows:           TCP flows tracked by the TCP analyzer (retransmission, RTT,
//     handshake and window detectors all consume TCP segments)
//   - DNSExchanges:       DNS exchanges recorded (queries, or — for a capture that has
//     only failure responses — the failure responses); successful responses whose
//     query is not in the capture leave no trace and are not counted
//   - TLSCertificates:    server certificates parsed (expiry is the health input)
//   - StabilitySessions:  observed units of the stability protocols: BFD sessions,
//     IKE SA_INIT sessions, STP bridges / TCN BPDUs, HSRP groups, VRRP sessions
//   - ARPBindings:        distinct IPs for which an ARP REPLY was seen (the ARP
//     conflict detector reads replies only; requests do not count)
type EvidenceCoverage struct {
	TCPFlows          int `json:"tcp_flows"`
	DNSExchanges      int `json:"dns_exchanges"`
	TLSCertificates   int `json:"tls_certificates"`
	StabilitySessions int `json:"stability_sessions"`
	ARPBindings       int `json:"arp_bindings"`
}

// NoHealthRelevantEvidence reports whether coverage is known and every
// health-relevant class had zero input. A nil coverage (not computed, e.g. a
// hand-built report) is NOT treated as "no evidence". It inspects nothing else:
// not the health level, RiskScore, Findings, packet counts or completeness.
func (c *EvidenceCoverage) NoHealthRelevantEvidence() bool {
	return c != nil && c.TCPFlows == 0 && c.DNSExchanges == 0 && c.TLSCertificates == 0 &&
		c.StabilitySessions == 0 && c.ARPBindings == 0
}

// NoApplicableEvidenceNote is the single wording used wherever a GOOD verdict
// must be qualified because no health-relevant evidence class had input.
const NoApplicableEvidenceNote = "No significant issues observed \u2014 there was no TCP, DNS, TLS, ARP-reply or stability-protocol traffic to evaluate."
