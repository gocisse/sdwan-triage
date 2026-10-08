package output

import (
	"strings"
	"testing"

	"github.com/gocisse/sdwan-triage/pkg/models"
)

// Observation != failure: suspicious-port flows and self-signed certificates are
// reported but never move the health verdict. Expired certificates still do.

func suspiciousFlows(n int, srcPort, dstPort uint16) []models.SuspiciousFlow {
	out := make([]models.SuspiciousFlow, n)
	for i := range out {
		out[i] = models.SuspiciousFlow{SrcIP: "62.74.228.18", SrcPort: srcPort, DstIP: "158.115.151.194", DstPort: dstPort, Protocol: "TCP",
			Reason: "Android Debug Bridge (potential unauthorized access)"}
	}
	return out
}

func TestWeakObs_SuspiciousTrafficDoesNotAffectHealth(t *testing.T) {
	hvLevel(t, "1 suspicious flow", &models.TriageReport{SuspiciousTraffic: suspiciousFlows(1, 443, 8888)}, healthGood)
	hvLevel(t, "many suspicious flows", &models.TriageReport{SuspiciousTraffic: suspiciousFlows(500, 443, 4444)}, healthGood)
	// The Velocloud-Wan shape: overlay endpoint using SOURCE port 5555.
	hvLevel(t, "source port 5555", &models.TriageReport{SuspiciousTraffic: suspiciousFlows(2, 5555, 443)}, healthGood)
}

func TestWeakObs_SelfSignedCertsDoNotAffectHealth(t *testing.T) {
	hvLevel(t, "1 self-signed", &models.TriageReport{TLSCerts: []models.TLSCertInfo{{IsSelfSigned: true}}}, healthGood)
	many := make([]models.TLSCertInfo, 50)
	for i := range many {
		many[i] = models.TLSCertInfo{IsSelfSigned: true}
	}
	hvLevel(t, "50 self-signed", &models.TriageReport{TLSCerts: many}, healthGood)
}

func TestWeakObs_ExpiredCertKeepsExistingBehaviour(t *testing.T) {
	hvLevel(t, "expired", &models.TriageReport{TLSCerts: []models.TLSCertInfo{{IsExpired: true}}}, healthWarning)
	// Self-signed AND expired: the expiry still escalates.
	hvLevel(t, "self-signed + expired", &models.TriageReport{TLSCerts: []models.TLSCertInfo{{IsSelfSigned: true, IsExpired: true}}}, healthWarning)
	// An expired cert among many harmless ones still escalates.
	certs := []models.TLSCertInfo{{IsSelfSigned: true}, {}, {IsExpired: true}, {IsSelfSigned: true}}
	hvLevel(t, "mixed with one expired", &models.TriageReport{TLSCerts: certs}, healthWarning)
}

func TestWeakObs_DoNotSuppressUnrelatedEvidence(t *testing.T) {
	weak := func(r *models.TriageReport) *models.TriageReport {
		r.SuspiciousTraffic = suspiciousFlows(3, 5555, 443)
		r.TLSCerts = append(r.TLSCerts, models.TLSCertInfo{IsSelfSigned: true})
		return r
	}
	cases := []struct {
		name string
		r    *models.TriageReport
		want healthLevel
	}{
		{"arp", &models.TriageReport{ARPConflicts: make([]models.ARPConflict, 1)}, healthCritical},
		{"6 handshake failures", &models.TriageReport{TCPHandshakeFlows: hvFailed(6)}, healthWarning},
		{"1 retransmission flow", &models.TriageReport{TCPRetransmissions: make([]models.TCPFlow, 1)}, healthFair},
		{"zero window", &models.TriageReport{TCPWindowFindings: []models.TCPWindowFinding{{Type: "Zero Window"}}}, healthWarning},
		{"high stability", &models.TriageReport{StabilityFindings: []models.StabilityFinding{{Severity: "High"}}}, healthWarning},
		{"dns server failure", &models.TriageReport{DNSAnomalies: dnsAnoms(models.DNSKindServerFailure, 1)}, healthFair},
		{"expired cert", &models.TriageReport{TLSCerts: []models.TLSCertInfo{{IsExpired: true}}}, healthWarning},
	}
	for _, tc := range cases {
		hvLevel(t, tc.name+" (+weak observations)", weak(tc.r), tc.want)
	}
}

// The observations stay visible in the report even though they do not drive health.
func TestWeakObs_StillReportedInSummary(t *testing.T) {
	r := &models.TriageReport{
		SuspiciousTraffic: suspiciousFlows(2, 5555, 443),
		TLSCerts:          []models.TLSCertInfo{{IsSelfSigned: true}},
	}
	out := captureStdout(t, func() { PrintExecutiveSummary(r) })
	for _, want := range []string{"NETWORK HEALTH: GOOD", "Suspicious Traffic:   2", "TLS Certificates:     1"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q:\n%s", want, out)
		}
	}
}
