package models

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestEvidenceCoverage_NoHealthRelevantEvidence(t *testing.T) {
	if !(&EvidenceCoverage{}).NoHealthRelevantEvidence() {
		t.Error("all-zero coverage means no health-relevant evidence")
	}
	for name, c := range map[string]EvidenceCoverage{
		"tcp": {TCPFlows: 1}, "dns": {DNSExchanges: 1}, "tls": {TLSCertificates: 1},
		"stability": {StabilitySessions: 1}, "arp": {ARPBindings: 1},
	} {
		c := c
		if c.NoHealthRelevantEvidence() {
			t.Errorf("%s > 0 must count as exercised", name)
		}
	}
	// Unknown coverage (never computed) is not "no evidence".
	var nilCov *EvidenceCoverage
	if nilCov.NoHealthRelevantEvidence() {
		t.Error("nil coverage must not be treated as no evidence")
	}
}

func TestEvidenceCoverage_JSONShapeIsDeterministic(t *testing.T) {
	r := &TriageReport{EvidenceCoverage: &EvidenceCoverage{TCPFlows: 17, DNSExchanges: 7}}
	first, _ := json.Marshal(r.EvidenceCoverage)
	for i := 0; i < 50; i++ {
		b, _ := json.Marshal(r.EvidenceCoverage)
		if string(b) != string(first) {
			t.Fatal("non-deterministic JSON")
		}
	}
	want := `{"tcp_flows":17,"dns_exchanges":7,"tls_certificates":0,"stability_sessions":0,"arp_bindings":0}`
	if string(first) != want {
		t.Errorf("got %s", first)
	}
	// Absent on a report that never computed it (NO_DATA / error paths).
	b, _ := json.Marshal(&TriageReport{})
	if strings.Contains(string(b), "evidence_coverage") {
		t.Error("evidence_coverage must be omitted when unset")
	}
}

// Coverage is metadata: it can never change the health level.
func TestEvidenceCoverage_DoesNotInfluenceHealth(t *testing.T) {
	mk := func() *TriageReport { return &TriageReport{TCPRetransmissions: make([]TCPFlow, 1)} }
	base := ComputeNetworkHealth(mk())
	for _, c := range []*EvidenceCoverage{nil, {}, {TCPFlows: 99}, {ARPBindings: 3}} {
		r := mk()
		r.EvidenceCoverage = c
		if got := ComputeNetworkHealth(r); got != base {
			t.Errorf("coverage %+v changed health %q → %q", c, base, got)
		}
	}
}
