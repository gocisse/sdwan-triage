package analyzer

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gocisse/sdwan-triage/internal/testpcap"
	"github.com/gocisse/sdwan-triage/pkg/models"
)

// network_health is set once by Process for analyzed reports, never for NO_DATA
// or errors, and agrees with the pure computation and the plain-English summary.

func TestNetworkHealth_SetForAnalyzedReports(t *testing.T) {
	for _, sc := range testpcap.Scenarios() {
		r := runGolden(t, sc.Generate())
		if r.NetworkHealth == "" {
			t.Fatalf("%s: analyzed report has no network_health", sc.Name)
		}
		if want := models.ComputeNetworkHealth(r); r.NetworkHealth != want {
			t.Errorf("%s: stored %q != computed %q", sc.Name, r.NetworkHealth, want)
		}
		label, _, _ := models.PlainEnglishHealthLabel(r.NetworkHealth)
		if r.PlainEnglishSummary == nil || r.PlainEnglishSummary.OverallHealth != label {
			t.Errorf("%s: plain-English %v disagrees with %q", sc.Name, r.PlainEnglishSummary, r.NetworkHealth)
		}
	}
}

func TestNetworkHealth_ExpectedLevelsOnFixtures(t *testing.T) {
	// retransmission_storm → FAIR (Low finding), bfd_tunnel_drop → WARNING (High stability), clean handshake → one RTT-flow artefact aside, never CRITICAL.
	if got := runGolden(t, testpcap.BFDTunnelDrop()).NetworkHealth; got != models.NetworkHealthWarning {
		t.Errorf("bfd_tunnel_drop: %q", got)
	}
	if got := runGolden(t, testpcap.RetransmissionStorm()).NetworkHealth; got != models.NetworkHealthFair {
		t.Errorf("retransmission_storm: %q", got)
	}
}

func TestNetworkHealth_AbsentForNoData(t *testing.T) {
	r, err := processWithFilter(t, writeEmptyPCAP(t), nil)
	if err != nil || !r.IsNoData() || r.NetworkHealth != "" {
		t.Fatalf("err=%v status=%q health=%q", err, r.AnalysisStatus, r.NetworkHealth)
	}
	b, _ := json.Marshal(r)
	if strings.Contains(string(b), "network_health") {
		t.Error("NO_DATA JSON must not contain network_health")
	}
	if r.PlainEnglishSummary.OverallHealth != "No Data" {
		t.Errorf("plain-English: %q", r.PlainEnglishSummary.OverallHealth)
	}
	hs := filepath.Join(t.TempDir(), "hs.pcap")
	testpcap.WriteFile(hs, testpcap.Handshake())
	r, err = processWithFilter(t, hs, &models.Filter{SrcIP: "9.9.9.9"})
	if err != nil || !r.IsNoData() || r.NetworkHealth != "" {
		t.Fatalf("filter-matched-nothing: err=%v health=%q", err, r.NetworkHealth)
	}
}

func TestNetworkHealth_NeverSetOnErrors(t *testing.T) {
	uns := writeNG(t, []uint16{testpcap.LinkTypeEthernetMPkt}, []testpcap.NGPacket{{Interface: 0, Data: make([]byte, 40)}})
	r, err := processWithFilter(t, uns, nil)
	if err == nil || r.NetworkHealth != "" {
		t.Fatalf("unsupported-only: err=%v health=%q", err, r.NetworkHealth)
	}
	g := filepath.Join(t.TempDir(), "g.pcap")
	testpcap.WriteFile(g, [][]byte{{1, 2}, {3}})
	r, err = processWithFilter(t, g, nil)
	if err == nil || r.NetworkHealth != "" {
		t.Fatalf("undecodable-only: err=%v health=%q", err, r.NetworkHealth)
	}
}

func TestNetworkHealth_PartialAndTruncatedStillJudged(t *testing.T) {
	partial := writeNG(t, []uint16{testpcap.LinkTypeEthernet, testpcap.LinkTypeEthernetMPkt}, handshakeNG(unsupportedPkts(2)...))
	r, err := processWithFilter(t, partial, nil)
	if err != nil || r.NetworkHealth == "" || r.Completeness == nil {
		t.Fatalf("partial: err=%v health=%q completeness=%v", err, r.NetworkHealth, r.Completeness)
	}
	full := filepath.Join(t.TempDir(), "f.pcap")
	testpcap.WriteFile(full, testpcap.Handshake())
	b, _ := os.ReadFile(full)
	cut := filepath.Join(t.TempDir(), "c.pcap")
	os.WriteFile(cut, b[:len(b)-10], 0o644)
	r, err = processWithFilter(t, cut, nil)
	if err != nil || r.NetworkHealth == "" || r.Completeness == nil || r.Completeness.ReadErrors < 1 {
		t.Fatalf("truncated: err=%v health=%q", err, r.NetworkHealth)
	}
}

func TestNetworkHealth_OnePacketIsAnalyzed(t *testing.T) {
	one := filepath.Join(t.TempDir(), "one.pcap")
	testpcap.WriteFile(one, [][]byte{testpcap.Handshake()[0]})
	r, err := processWithFilter(t, one, nil)
	if err != nil || r.IsNoData() || r.NetworkHealth == "" {
		t.Fatalf("one packet: err=%v health=%q", err, r.NetworkHealth)
	}
}

func TestNetworkHealth_Deterministic(t *testing.T) {
	var first string
	for i := 0; i < 30; i++ {
		got := runGolden(t, testpcap.RetransmissionStorm()).NetworkHealth
		if i == 0 {
			first = got
		} else if got != first {
			t.Fatalf("run %d: %q != %q", i, got, first)
		}
	}
}

// Setting the field must not change anything else the analyzer concluded.
func TestNetworkHealth_DoesNotChangeRiskOrFindings(t *testing.T) {
	r := runGolden(t, testpcap.RetransmissionStorm())
	again := runGolden(t, testpcap.RetransmissionStorm())
	assertSameAnalysis(t, r, again)
}
