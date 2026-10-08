package output

import (
	"fmt"
	"strings"
	"testing"

	"github.com/gocisse/sdwan-triage/pkg/models"
)

// DNS anomalies are observations. Only observed server failures reach health,
// through the existing performance bucket; nothing DNS-related is CRITICAL.

func dnsAnoms(kind string, n int) []models.DNSAnomaly {
	out := make([]models.DNSAnomaly, n)
	for i := range out {
		// distinct (server, name) pairs: each is its own incident
		out[i] = models.DNSAnomaly{Kind: kind, ServerIP: "8.8.8.8", Query: fmt.Sprintf("name%d.example.net", i)}
	}
	return out
}

func TestDNSHealth_ObservationKindsDoNotAffectHealth(t *testing.T) {
	for _, kind := range []string{
		models.DNSKindNXDomain, models.DNSKindNoResponse, models.DNSKindNonStandardServer,
		models.DNSKindPrivateAnswer, models.DNSKindSuspiciousDomain,
	} {
		for _, n := range []int{1, 6, 839, 5000} {
			hvLevel(t, fmt.Sprintf("%d x %s", n, kind), &models.TriageReport{DNSAnomalies: dnsAnoms(kind, n)}, healthGood)
		}
	}
}

func TestDNSHealth_ServerFailureUsesPerformanceBucket(t *testing.T) {
	hvLevel(t, "1 server failure", &models.TriageReport{DNSAnomalies: dnsAnoms(models.DNSKindServerFailure, 1)}, healthFair)
	hvLevel(t, "5 server failures", &models.TriageReport{DNSAnomalies: dnsAnoms(models.DNSKindServerFailure, 5)}, healthFair)
	hvLevel(t, "6 server failures", &models.TriageReport{DNSAnomalies: dnsAnoms(models.DNSKindServerFailure, 6)}, healthWarning)
	// Combined with other performance evidence the same single threshold applies.
	hvLevel(t, "3 failures + 3 failed handshakes", &models.TriageReport{DNSAnomalies: dnsAnoms(models.DNSKindServerFailure, 3), TCPHandshakeFlows: hvFailed(3)}, healthWarning)
	hvLevel(t, "1 failure + 1 retransmission flow", &models.TriageReport{DNSAnomalies: dnsAnoms(models.DNSKindServerFailure, 1), TCPRetransmissions: make([]models.TCPFlow, 1)}, healthFair)
}

func TestDNSHealth_ServerFailureCountsDistinctIncidents(t *testing.T) {
	// The same resolver failing the same name 50 times is ONE incident.
	same := make([]models.DNSAnomaly, 50)
	for i := range same {
		same[i] = models.DNSAnomaly{Kind: models.DNSKindServerFailure, ServerIP: "8.8.8.8", Query: "broken.example.net"}
	}
	r := &models.TriageReport{DNSAnomalies: same}
	if got := dnsServerFailureIncidents(r); got != 1 {
		t.Errorf("incidents = %d, want 1", got)
	}
	hvLevel(t, "50 identical failures", r, healthFair)
	// Different servers for the same name, and different names for the same server, are distinct.
	mixed := []models.DNSAnomaly{
		{Kind: models.DNSKindServerFailure, ServerIP: "8.8.8.8", Query: "a.example.net"},
		{Kind: models.DNSKindServerFailure, ServerIP: "1.1.1.1", Query: "a.example.net"},
		{Kind: models.DNSKindServerFailure, ServerIP: "8.8.8.8", Query: "b.example.net"},
	}
	if got := dnsServerFailureIncidents(&models.TriageReport{DNSAnomalies: mixed}); got != 3 {
		t.Errorf("incidents = %d, want 3", got)
	}
}

func TestDNSHealth_KindIsNeverInferredFromReasonText(t *testing.T) {
	// A kind-less anomaly (e.g. from older JSON) must not be interpreted, even if
	// its text looks like a failure.
	r := &models.TriageReport{DNSAnomalies: []models.DNSAnomaly{{Reason: "DNS SERVFAIL for x.example.net", ServerIP: "8.8.8.8", Query: "x.example.net"}}}
	hvLevel(t, "kind-less SERVFAIL text", r, healthGood)
}

func TestDNSHealth_DNSAloneCanNeverBeCritical(t *testing.T) {
	all := []models.DNSAnomaly{}
	for _, k := range []string{models.DNSKindServerFailure, models.DNSKindNXDomain, models.DNSKindNoResponse, models.DNSKindNonStandardServer, models.DNSKindPrivateAnswer, models.DNSKindSuspiciousDomain} {
		all = append(all, dnsAnoms(k, 2000)...)
	}
	if got := healthVerdict(&models.TriageReport{DNSAnomalies: all}); got == healthCritical {
		t.Errorf("DNS anomalies alone must never force CRITICAL (got %d)", got)
	}
}

func TestDNSHealth_NonDNSCriticalStillCritical(t *testing.T) {
	hvLevel(t, "ARP + DNS noise", &models.TriageReport{ARPConflicts: make([]models.ARPConflict, 1), DNSAnomalies: dnsAnoms(models.DNSKindNXDomain, 10)}, healthCritical)
}

func TestDNSHealth_CompletenessDoesNotChangeDNSVerdict(t *testing.T) {
	for _, kind := range []string{models.DNSKindServerFailure, models.DNSKindNoResponse, models.DNSKindNXDomain} {
		a := &models.TriageReport{DNSAnomalies: dnsAnoms(kind, 3)}
		b := &models.TriageReport{DNSAnomalies: dnsAnoms(kind, 3), Completeness: partialUnsupported()}
		if healthVerdict(a) != healthVerdict(b) {
			t.Errorf("%s: completeness changed the DNS health level", kind)
		}
	}
}

func TestDNSHealth_BannerNeverCriticalFromDNS(t *testing.T) {
	r := &models.TriageReport{DNSAnomalies: dnsAnoms(models.DNSKindNXDomain, 1276)}
	out := captureStdout(t, func() { PrintExecutiveSummary(r) })
	if !containsAll(out, "NETWORK HEALTH: GOOD", "DNS Anomalies:        1276") {
		t.Errorf("DNS observations stay visible but do not drive the banner:\n%s", out)
	}
}

func containsAll(s string, subs ...string) bool {
	for _, x := range subs {
		if !strings.Contains(s, x) {
			return false
		}
	}
	return true
}
