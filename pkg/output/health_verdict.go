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

// performanceWarnThreshold mirrors models.HealthPerformanceWarnThreshold (kept
// for the existing tests); the single source of truth is pkg/models/health.go.
const performanceWarnThreshold = models.HealthPerformanceWarnThreshold

// healthVerdict returns the headline health level for a report. It contains NO
// algorithm: the authoritative computation is models.ComputeNetworkHealth, whose
// result Process stores in report.NetworkHealth. When the field is unset (a
// report built by hand, for example in tests) the same function is applied, so
// there is never a second set of thresholds and the value never defaults to GOOD
// for a no-data report (callers gate NO_DATA before asking for a level).
func healthVerdict(r *models.TriageReport) healthLevel {
	level, _ := networkHealthOf(r)
	switch level {
	case models.NetworkHealthCritical:
		return healthCritical
	case models.NetworkHealthWarning:
		return healthWarning
	case models.NetworkHealthFair:
		return healthFair
	default:
		return healthGood
	}
}

// networkHealthOf is the single output-side accessor for the authoritative
// health value. ok is false for a NO_DATA report: there is no health judgment
// to show.
func networkHealthOf(r *models.TriageReport) (level string, ok bool) {
	if r == nil || r.IsNoData() {
		return "", false
	}
	if r.NetworkHealth != "" {
		return r.NetworkHealth, true
	}
	return models.ComputeNetworkHealth(r), true
}

// handshakeFailures and dnsServerFailureIncidents delegate to the models
// implementations (kept as names used by existing tests).
func handshakeFailures(r *models.TriageReport) int { return models.HandshakeFailures(r) }
func dnsServerFailureIncidents(r *models.TriageReport) int {
	return models.DNSServerFailureIncidents(r)
}
