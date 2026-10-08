package output

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gocisse/sdwan-triage/pkg/models"
)

// Display only: the human line is a pure rendering of report.EvidenceCoverage.

func covReport(c *models.EvidenceCoverage) *models.TriageReport {
	return &models.TriageReport{NetworkHealth: models.NetworkHealthGood, EvidenceCoverage: c}
}

func TestEvidenceDisplay_Wording(t *testing.T) {
	cases := []struct {
		name string
		c    models.EvidenceCoverage
		want string
	}{
		{"all zero", models.EvidenceCoverage{}, "Evidence examined: 0 TCP flows, 0 DNS exchanges, 0 TLS certificates, 0 stability units, 0 ARP bindings."},
		{"all one", models.EvidenceCoverage{TCPFlows: 1, DNSExchanges: 1, TLSCertificates: 1, StabilitySessions: 1, ARPBindings: 1},
			"Evidence examined: 1 TCP flow, 1 DNS exchange, 1 TLS certificate, 1 stability unit, 1 ARP binding."},
		{"plural", models.EvidenceCoverage{TCPFlows: 2, DNSExchanges: 2, TLSCertificates: 2, StabilitySessions: 2, ARPBindings: 2},
			"Evidence examined: 2 TCP flows, 2 DNS exchanges, 2 TLS certificates, 2 stability units, 2 ARP bindings."},
		{"mixed", models.EvidenceCoverage{TCPFlows: 17, DNSExchanges: 7, TLSCertificates: 0, StabilitySessions: 1, ARPBindings: 0},
			"Evidence examined: 17 TCP flows, 7 DNS exchanges, 0 TLS certificates, 1 stability unit, 0 ARP bindings."},
	}
	for _, tc := range cases {
		c := tc.c
		lines := evidenceCoverageLines(covReport(&c))
		if len(lines) != 2 || lines[0] != tc.want || lines[1] != "Counts show how much health-relevant traffic was seen; they do not measure how much is enough." {
			t.Errorf("%s: %q", tc.name, lines)
		}
	}
}

func TestEvidenceDisplay_AbsentWhenNothingTruthfulToShow(t *testing.T) {
	// unknown / never-computed coverage
	if evidenceCoverageLines(&models.TriageReport{NetworkHealth: models.NetworkHealthGood}) != nil {
		t.Error("unknown coverage must show nothing")
	}
	if evidenceCoverageLines(nil) != nil {
		t.Error("nil report must show nothing")
	}
	// NO_DATA, even if coverage were somehow set
	nd := noDataReport(models.NoDataReasonEmptyCapture)
	nd.EvidenceCoverage = &models.EvidenceCoverage{TCPFlows: 3}
	if evidenceCoverageLines(nd) != nil {
		t.Error("NO_DATA must show nothing")
	}
	for name, out := range map[string]string{
		"terminal":         captureStdout(t, func() { PrintExecutiveSummary(nd) }),
		"simple":           captureStdout(t, func() { GenerateSimpleReport(nd, "x") }),
		"unknown terminal": captureStdout(t, func() { PrintExecutiveSummary(&models.TriageReport{}) }),
	} {
		if strings.Contains(out, "Evidence examined") {
			t.Errorf("%s must not show the evidence line:\n%s", name, out)
		}
	}
}

func TestEvidenceDisplay_Deterministic(t *testing.T) {
	r := covReport(&models.EvidenceCoverage{TCPFlows: 5, StabilitySessions: 1})
	first := strings.Join(evidenceCoverageLines(r), "\n")
	for i := 0; i < 100; i++ {
		if strings.Join(evidenceCoverageLines(r), "\n") != first {
			t.Fatal("non-deterministic wording")
		}
	}
}

// Every surface shows the same counts as the JSON-bearing report.
func TestEvidenceDisplay_AllSurfacesIdentical(t *testing.T) {
	c := &models.EvidenceCoverage{TCPFlows: 17, DNSExchanges: 7, TLSCertificates: 1, StabilitySessions: 2, ARPBindings: 0}
	r := covReport(c)
	wantLine := "Evidence examined: 17 TCP flows, 7 DNS exchanges, 1 TLS certificate, 2 stability units, 0 ARP bindings."
	counts := "17 TCP flows, 7 DNS exchanges, 1 TLS certificate, 2 stability units, 0 ARP bindings"
	reminder := "they do not measure how much is enough."

	term := captureStdout(t, func() { PrintExecutiveSummary(r) })
	if !strings.Contains(term, wantLine) || !strings.Contains(term, reminder) {
		t.Errorf("terminal:\n%s", term)
	}
	simple := captureStdout(t, func() { GenerateSimpleReport(r, "x") })
	if !strings.Contains(simple, wantLine) || !strings.Contains(simple, reminder) {
		t.Errorf("simple:\n%s", simple)
	}

	res, err := GenerateCSVReports(r, filepath.Join(t.TempDir(), "o"))
	if err != nil {
		t.Fatal(err)
	}
	var csv string
	for _, f := range res.Files {
		if strings.Contains(filepath.Base(f), "summary") {
			b, _ := os.ReadFile(f)
			csv = string(b)
		}
	}
	if !strings.Contains(csv, "Evidence Examined,\""+counts+"\"") && !strings.Contains(csv, "Evidence Examined,"+counts) {
		t.Errorf("CSV row missing or different:\n%s", csv)
	}
	if strings.Count(csv, "Evidence Examined") != 1 {
		t.Error("exactly one CSV row expected")
	}

	hp := filepath.Join(t.TempDir(), "r.html")
	if err := GenerateHTMLReport(r, hp, "x.pcap"); err != nil {
		t.Fatal(err)
	}
	if h := readFile(t, hp); !strings.Contains(h, wantLine) || !strings.Contains(h, "evidence-examined") {
		t.Error("enterprise HTML")
	}
	mp := t.TempDir()
	if err := GenerateMultiPageHTMLReport(r, mp, "x.pcap"); err != nil {
		t.Fatal(err)
	}
	for _, page := range []string{"index.html", "executive-summary.html"} {
		if p := readFile(t, filepath.Join(mp, page)); !strings.Contains(p, wantLine) {
			t.Errorf("multi-page %s", page)
		}
	}
	pp := filepath.Join(t.TempDir(), "r.pdf")
	if err := NewPDFGenerator().GeneratePDF(r, pp, "x.pcap"); err != nil {
		t.Fatal(err)
	}
	if txt := pdfText(t, pp); !strings.Contains(txt, wantLine) {
		t.Error("PDF")
	}
	for _, l := range evidenceCoverageLines(r) {
		for _, ch := range l {
			if ch > 126 {
				t.Errorf("PDF text must be ASCII, got %q", ch)
			}
		}
	}
}

// HTML: no NO_DATA / unknown-coverage block, and attaching the block adds no new
// blank lines for reports that do not show it.
func TestEvidenceDisplay_HTMLAbsentWhenUnknownOrNoData(t *testing.T) {
	for name, r := range map[string]*models.TriageReport{"unknown": {}, "no_data": noDataReport(models.NoDataReasonEmptyCapture)} {
		hp := filepath.Join(t.TempDir(), "r.html")
		if err := GenerateHTMLReport(r, hp, "x.pcap"); err != nil {
			t.Fatal(err)
		}
		if h := readFile(t, hp); strings.Contains(h, "evidence-examined") || strings.Contains(h, "Evidence examined") {
			t.Errorf("%s: unexpected evidence block", name)
		}
	}
}

// Display never changes the verdict or any other surface text.
func TestEvidenceDisplay_DoesNotChangeHealth(t *testing.T) {
	for _, c := range []*models.EvidenceCoverage{nil, {}, {TCPFlows: 9}} {
		r := &models.TriageReport{EvidenceCoverage: c}
		if healthVerdict(r) != healthGood {
			t.Errorf("coverage %+v changed the verdict", c)
		}
	}
	// A non-GOOD level keeps its banner; the evidence line is additional, not a replacement.
	r := &models.TriageReport{ARPConflicts: make([]models.ARPConflict, 1), EvidenceCoverage: &models.EvidenceCoverage{ARPBindings: 2}}
	r.NetworkHealth = models.ComputeNetworkHealth(r)
	out := captureStdout(t, func() { PrintExecutiveSummary(r) })
	if !strings.Contains(out, "NETWORK HEALTH: CRITICAL - Immediate attention required") || !strings.Contains(out, "2 ARP bindings") {
		t.Errorf("critical + evidence line:\n%s", out)
	}
}
