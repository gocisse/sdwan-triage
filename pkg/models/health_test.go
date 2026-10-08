package models

import "testing"

// ComputeNetworkHealth is the single authoritative health computation. These are
// parity/contract tests; the detailed per-evidence matrix lives in pkg/output
// (health_verdict_test.go, dns_health_test.go, weak_observation_health_test.go),
// which exercises the same function through the output wrapper.

func TestNetworkHealth_Levels(t *testing.T) {
	failed := func(n int) []TCPHandshakeFlow {
		out := make([]TCPHandshakeFlow, n)
		for i := range out {
			out[i] = TCPHandshakeFlow{State: "Handshake Failed"}
		}
		return out
	}
	cases := []struct {
		name string
		r    *TriageReport
		want string
	}{
		{"empty analyzed report", &TriageReport{}, NetworkHealthGood},
		{"1 retransmission flow", &TriageReport{TCPRetransmissions: make([]TCPFlow, 1)}, NetworkHealthFair},
		{"5 failed handshakes", &TriageReport{TCPHandshakeFlows: failed(5)}, NetworkHealthFair},
		{"6 failed handshakes", &TriageReport{TCPHandshakeFlows: failed(6)}, NetworkHealthWarning},
		{"zero window", &TriageReport{TCPWindowFindings: []TCPWindowFinding{{Type: "Zero Window"}}}, NetworkHealthWarning},
		{"expired cert", &TriageReport{TLSCerts: []TLSCertInfo{{IsExpired: true}}}, NetworkHealthWarning},
		{"self-signed cert only", &TriageReport{TLSCerts: []TLSCertInfo{{IsSelfSigned: true}}}, NetworkHealthGood},
		{"suspicious traffic only", &TriageReport{SuspiciousTraffic: make([]SuspiciousFlow, 3)}, NetworkHealthGood},
		{"arp conflict", &TriageReport{ARPConflicts: make([]ARPConflict, 1)}, NetworkHealthCritical},
		{"dns observations only", &TriageReport{DNSAnomalies: []DNSAnomaly{{Kind: DNSKindNXDomain}, {Kind: DNSKindNoResponse}}}, NetworkHealthGood},
		{"dns server failure", &TriageReport{DNSAnomalies: []DNSAnomaly{{Kind: DNSKindServerFailure, ServerIP: "a", Query: "x"}}}, NetworkHealthFair},
	}
	for _, tc := range cases {
		if got := ComputeNetworkHealth(tc.r); got != tc.want {
			t.Errorf("%s: %q, want %q", tc.name, got, tc.want)
		}
	}
}

func TestNetworkHealth_LegacyHandshakeFallbackAndNoDoubleCount(t *testing.T) {
	r := &TriageReport{FailedHandshakes: make([]TCPFlow, 3)}
	if HandshakeFailures(r) != 3 {
		t.Error("legacy RST count is used only when the tracker has no flows")
	}
	r.TCPHandshakeFlows = []TCPHandshakeFlow{{State: "Handshake Complete"}, {State: "SYN"}}
	if HandshakeFailures(r) != 0 {
		t.Error("tracker present: incomplete flows are not failures and the legacy count is ignored")
	}
}

func TestNetworkHealth_PlainEnglishLabels(t *testing.T) {
	for level, want := range map[string]string{
		NetworkHealthGood: "Healthy", NetworkHealthFair: "Warning", NetworkHealthWarning: "Warning", NetworkHealthCritical: "Critical",
	} {
		if got, _, _ := PlainEnglishHealthLabel(level); got != want {
			t.Errorf("%s → %q, want %q", level, got, want)
		}
	}
}

func TestNetworkHealth_JSONOmittedWhenUnset(t *testing.T) {
	var r TriageReport
	if r.NetworkHealth != "" || r.IsNoData() {
		t.Fatal("zero value must carry no health and no status")
	}
}
