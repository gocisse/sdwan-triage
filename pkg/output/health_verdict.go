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
//   - security concerns (suspicious traffic, bad certificates) → at least WARNING.
//   - stability findings (BFD/IKE/HSRP/VRRP/STP): High/Critical → at least
//     WARNING, any other severity → at least FAIR. A floor, never a sum: two
//     directional findings for one BFD drop are not worse than one.
//   - Zero Window findings → at least WARNING. Small Window is informational and
//     does not contribute.
//   - Findings with High/Critical severity and a basis other than time_proximity
//     → at least WARNING.
//   - DNS anomalies or ARP conflicts → CRITICAL (existing behavior, unchanged).
//
// RiskScore is intentionally not an input.
func healthVerdict(r *models.TriageReport) healthLevel {
	level := healthGood
	raise := func(l healthLevel) {
		if l > level {
			level = l
		}
	}

	performance := len(r.TCPRetransmissions) + handshakeFailures(r) + len(r.RTTAnalysis)
	if performance > 0 {
		raise(healthFair)
	}
	if performance > performanceWarnThreshold {
		raise(healthWarning)
	}

	security := len(r.SuspiciousTraffic)
	for _, cert := range r.TLSCerts {
		if cert.IsExpired || cert.IsSelfSigned {
			security++
		}
	}
	if security > 0 {
		raise(healthWarning)
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

	if len(r.DNSAnomalies) > 0 || len(r.ARPConflicts) > 0 {
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
