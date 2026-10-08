package analyzer

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gocisse/sdwan-triage/internal/testpcap"
	"github.com/gocisse/sdwan-triage/pkg/models"
	"github.com/google/gopacket/layers"
)

// Evidence coverage: which health-relevant classes had input (applicability, not
// sufficiency). Metadata only; never feeds health, risk, findings or exit codes.

func arpFrame(op byte, mac, ip []byte) []byte {
	arp := []byte{0, 1, 8, 0, 6, 4, 0, op}
	arp = append(arp, mac...)
	arp = append(arp, ip...)
	arp = append(arp, make([]byte, 6)...)
	arp = append(arp, testpcap.ServerIP...)
	return testpcap.BuildEthernet(mac, []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, 0x0806, arp)
}

func covOf(t *testing.T, frames [][]byte) *models.TriageReport {
	t.Helper()
	return runGolden(t, frames)
}

func udpOnly() [][]byte {
	return [][]byte{testpcap.UDPFrame(testpcap.ClientMAC, testpcap.ServerMAC, testpcap.ClientIP, testpcap.DNSServer, 40000, 9999, []byte("x"))}
}

func TestCoverage_PopulatedForAnalyzedReports(t *testing.T) {
	r := covOf(t, testpcap.Handshake())
	if r.EvidenceCoverage == nil || r.EvidenceCoverage.TCPFlows == 0 {
		t.Fatalf("TCP handshake: %+v", r.EvidenceCoverage)
	}
	if r.EvidenceCoverage.NoHealthRelevantEvidence() {
		t.Error("a TCP capture exercised a health-relevant class")
	}
}

func TestCoverage_UDPOnlyIsAllZeroButStillAnalyzed(t *testing.T) {
	r := covOf(t, udpOnly())
	if r.IsNoData() || r.NetworkHealth != models.NetworkHealthGood {
		t.Fatalf("UDP-only is an analyzed GOOD capture, got %q/%q", r.AnalysisStatus, r.NetworkHealth)
	}
	if r.EvidenceCoverage == nil || !r.EvidenceCoverage.NoHealthRelevantEvidence() {
		t.Errorf("UDP-only coverage must be all zero: %+v", r.EvidenceCoverage)
	}
	if want := "No significant issues observed"; !strings.Contains(strings.Join(r.PlainEnglishSummary.KeyFindings, "|"), want) {
		t.Errorf("plain-English summary must carry the note: %v", r.PlainEnglishSummary.KeyFindings)
	}
	if r.PlainEnglishSummary.OverallHealth != "Healthy" {
		t.Errorf("overall_health label must be unchanged, got %q", r.PlainEnglishSummary.OverallHealth)
	}
}

func TestCoverage_OneSYNStillCountsAsTCP(t *testing.T) {
	// Applicability, NOT sufficiency: a single SYN exercises the TCP class.
	r := covOf(t, [][]byte{testpcap.Handshake()[0]})
	if r.EvidenceCoverage.TCPFlows != 1 || r.EvidenceCoverage.NoHealthRelevantEvidence() {
		t.Errorf("%+v", r.EvidenceCoverage)
	}
}

func TestCoverage_DNS(t *testing.T) {
	c, s := dkClient, dkGoogle
	ok := covOf(t, [][]byte{dkQuery(t, c, s, 1, "a.example.net"), dkResponse(t, c, s, 1, 0, "a.example.net", dkWeb)})
	if ok.EvidenceCoverage.DNSExchanges != 1 {
		t.Errorf("query+response: %+v", ok.EvidenceCoverage)
	}
	// Failure response without its query: the evidence the health algorithm reads.
	fail := covOf(t, [][]byte{dkResponse(t, c, s, 2, layers.DNSResponseCodeServFail, "b.example.net")})
	if fail.EvidenceCoverage.DNSExchanges != 1 {
		t.Errorf("failure-only: %+v", fail.EvidenceCoverage)
	}
}

func TestCoverage_ARPRequestsDoNotCountRepliesDo(t *testing.T) {
	mac := []byte{0, 1, 2, 3, 4, 5}
	ip := []byte{192, 168, 1, 50}
	req := covOf(t, [][]byte{arpFrame(1, mac, ip), arpFrame(1, []byte{0, 1, 2, 3, 4, 6}, []byte{192, 168, 1, 51})})
	if req.EvidenceCoverage.ARPBindings != 0 || !req.EvidenceCoverage.NoHealthRelevantEvidence() {
		t.Errorf("ARP requests only must give arp_bindings 0: %+v", req.EvidenceCoverage)
	}
	rep := covOf(t, [][]byte{arpFrame(2, mac, ip), arpFrame(2, []byte{0, 1, 2, 3, 4, 6}, []byte{192, 168, 1, 51})})
	if rep.EvidenceCoverage.ARPBindings != 2 || rep.EvidenceCoverage.NoHealthRelevantEvidence() {
		t.Errorf("ARP replies: %+v", rep.EvidenceCoverage)
	}
}

func TestCoverage_StabilityEvidence(t *testing.T) {
	r := covOf(t, testpcap.BFDTunnelDrop())
	if r.EvidenceCoverage.StabilitySessions < 1 {
		t.Errorf("BFD sessions must register: %+v", r.EvidenceCoverage)
	}
}

func TestCoverage_TLSCertificatesCounted(t *testing.T) {
	p := NewProcessorWithOptions(false, false)
	state := models.NewAnalysisState()
	rep := &models.TriageReport{TLSCerts: make([]models.TLSCertInfo, 3)}
	if c := p.buildEvidenceCoverage(state, rep); c.TLSCertificates != 3 || c.NoHealthRelevantEvidence() {
		t.Errorf("%+v", c)
	}
}

func TestCoverage_AbsentForNoDataAndErrors(t *testing.T) {
	r, err := processWithFilter(t, writeEmptyPCAP(t), nil)
	if err != nil || r.EvidenceCoverage != nil {
		t.Fatalf("empty capture: err=%v coverage=%+v", err, r.EvidenceCoverage)
	}
	hs := filepath.Join(t.TempDir(), "hs.pcap")
	testpcap.WriteFile(hs, testpcap.Handshake())
	r, _ = processWithFilter(t, hs, &models.Filter{SrcIP: "9.9.9.9"})
	if !r.IsNoData() || r.EvidenceCoverage != nil {
		t.Errorf("filter-matched-nothing: coverage=%+v", r.EvidenceCoverage)
	}
	uns := writeNG(t, []uint16{testpcap.LinkTypeEthernetMPkt}, []testpcap.NGPacket{{Interface: 0, Data: make([]byte, 40)}})
	r, err = processWithFilter(t, uns, nil)
	if err == nil || r.EvidenceCoverage != nil {
		t.Errorf("error path: err=%v coverage=%+v", err, r.EvidenceCoverage)
	}
	b, _ := json.Marshal(r)
	if strings.Contains(string(b), "evidence_coverage") {
		t.Error("JSON must not carry evidence_coverage on the error path")
	}
}

func TestCoverage_Deterministic(t *testing.T) {
	var first string
	for i := 0; i < 20; i++ {
		b, _ := json.Marshal(covOf(t, testpcap.RetransmissionStorm()).EvidenceCoverage)
		if i == 0 {
			first = string(b)
		} else if string(b) != first {
			t.Fatalf("run %d: %s != %s", i, b, first)
		}
	}
}

// Metadata only: identical analysis with and without it.
func TestCoverage_DoesNotChangeAnalysis(t *testing.T) {
	a := covOf(t, testpcap.RetransmissionStorm())
	savedHealth := models.ComputeNetworkHealth(a)
	a.EvidenceCoverage = &models.EvidenceCoverage{}
	if models.ComputeNetworkHealth(a) != savedHealth || a.NetworkHealth != savedHealth {
		t.Error("coverage must not influence health")
	}
	assertSameAnalysis(t, a, covOf(t, testpcap.RetransmissionStorm()))
}
