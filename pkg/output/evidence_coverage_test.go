package output

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gocisse/sdwan-triage/pkg/models"
)

// GOOD with no health-relevant evidence class is worded honestly everywhere;
// every other case (non-zero coverage, FAIR/WARNING/CRITICAL, unknown coverage,
// NO_DATA) is unchanged.

func goodNoEvidence() *models.TriageReport {
	return &models.TriageReport{NetworkHealth: models.NetworkHealthGood, EvidenceCoverage: &models.EvidenceCoverage{}}
}

func goodWithEvidence() *models.TriageReport {
	return &models.TriageReport{NetworkHealth: models.NetworkHealthGood, EvidenceCoverage: &models.EvidenceCoverage{TCPFlows: 17, DNSExchanges: 7}}
}

const qual = "there was no TCP, DNS, TLS, ARP-reply or stability-protocol traffic to evaluate"

func TestCoverageWording_Terminal(t *testing.T) {
	q := captureStdout(t, func() { PrintExecutiveSummary(goodNoEvidence()) })
	if !strings.Contains(q, "NETWORK HEALTH: GOOD - No significant issues observed — "+qual) || strings.Contains(q, "No significant issues detected") {
		t.Errorf("qualified GOOD:\n%s", q)
	}
	n := captureStdout(t, func() { PrintExecutiveSummary(goodWithEvidence()) })
	if !strings.Contains(n, "NETWORK HEALTH: GOOD - No significant issues detected\n") || strings.Contains(n, qual) {
		t.Errorf("GOOD with evidence must be unchanged:\n%s", n)
	}
}

func TestCoverageWording_OtherLevelsUnchanged(t *testing.T) {
	for _, tc := range levelCases()[1:] { // fair, warning, critical
		r := tc.mk()
		r.NetworkHealth = models.ComputeNetworkHealth(r)
		r.EvidenceCoverage = &models.EvidenceCoverage{} // even with zero coverage
		out := captureStdout(t, func() { PrintExecutiveSummary(r) })
		if !strings.Contains(out, tc.banner) || strings.Contains(out, qual) {
			t.Errorf("%s must be untouched by coverage:\n%s", tc.level, out)
		}
		simple := captureStdout(t, func() { GenerateSimpleReport(r, "x") })
		if !strings.Contains(simple, tc.simple) || strings.Contains(simple, qual) {
			t.Errorf("%s -simple must be untouched", tc.level)
		}
	}
}

func TestCoverageWording_UnknownCoverageAndNoDataAreUnchanged(t *testing.T) {
	r := &models.TriageReport{} // hand-built: coverage never computed
	out := captureStdout(t, func() { PrintExecutiveSummary(r) })
	if !strings.Contains(out, "No significant issues detected") || strings.Contains(out, qual) {
		t.Errorf("unknown coverage is not 'no evidence':\n%s", out)
	}
	nd := noDataReport(models.NoDataReasonEmptyCapture)
	nd.EvidenceCoverage = &models.EvidenceCoverage{} // must be ignored
	if goodWithNoApplicableEvidence(nd) {
		t.Error("NO_DATA is never a qualified GOOD")
	}
	out = captureStdout(t, func() { PrintExecutiveSummary(nd) })
	if !strings.Contains(out, "NO DATA") || strings.Contains(out, qual) {
		t.Errorf("NO_DATA unchanged:\n%s", out)
	}
}

func TestCoverageWording_Simple(t *testing.T) {
	q := captureStdout(t, func() { GenerateSimpleReport(goodNoEvidence(), "x.pcap") })
	if !strings.Contains(q, "No problems were found, but "+qual) || strings.Contains(q, "healthy and performing well") {
		t.Errorf("qualified -simple:\n%s", q)
	}
	n := captureStdout(t, func() { GenerateSimpleReport(goodWithEvidence(), "x.pcap") })
	if !strings.Contains(n, "Your network is healthy and performing well") {
		t.Errorf("-simple with evidence must be unchanged:\n%s", n)
	}
}

func TestCoverageWording_CSVHTMLPDF(t *testing.T) {
	// CSV
	csvSummary := func(r *models.TriageReport) string {
		res, err := GenerateCSVReports(r, filepath.Join(t.TempDir(), "o"))
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range res.Files {
			if strings.Contains(filepath.Base(f), "summary") {
				b, _ := os.ReadFile(f)
				return string(b)
			}
		}
		return ""
	}
	if s := csvSummary(goodNoEvidence()); !strings.Contains(s, "Network Health Status,GOOD,") || !strings.Contains(s, qual) {
		t.Errorf("CSV qualified:\n%s", s)
	}
	if s := csvSummary(goodWithEvidence()); !strings.Contains(s, "Network Health Status,GOOD,Overall network health assessment") || strings.Contains(s, qual) {
		t.Errorf("CSV unchanged:\n%s", s)
	}

	// Enterprise + multi-page HTML
	hp := filepath.Join(t.TempDir(), "r.html")
	if err := GenerateHTMLReport(goodNoEvidence(), hp, "x.pcap"); err != nil {
		t.Fatal(err)
	}
	h := readFile(t, hp)
	if !strings.Contains(h, "coverage-notice") || !strings.Contains(h, qual) || !strings.Contains(h, `kpi-value">Good`) {
		t.Error("enterprise HTML must show the note and keep the Good level")
	}
	hp2 := filepath.Join(t.TempDir(), "r2.html")
	GenerateHTMLReport(goodWithEvidence(), hp2, "x.pcap")
	if h2 := readFile(t, hp2); strings.Contains(h2, "coverage-notice") || strings.Contains(h2, qual) {
		t.Error("enterprise HTML with evidence must carry no note")
	}
	mp := t.TempDir()
	if err := GenerateMultiPageHTMLReport(goodNoEvidence(), mp, "x.pcap"); err != nil {
		t.Fatal(err)
	}
	for _, page := range []string{"index.html", "executive-summary.html"} {
		c := readFile(t, filepath.Join(mp, page))
		if !strings.Contains(c, "coverage-notice") || !strings.Contains(c, qual) {
			t.Errorf("multi-page %s missing the note", page)
		}
	}
	mp2 := t.TempDir()
	GenerateMultiPageHTMLReport(goodWithEvidence(), mp2, "x.pcap")
	if c := readFile(t, filepath.Join(mp2, "index.html")); strings.Contains(c, "coverage-notice") {
		t.Error("multi-page with evidence must carry no note")
	}

	// PDF
	pp := filepath.Join(t.TempDir(), "r.pdf")
	if err := NewPDFGenerator().GeneratePDF(goodNoEvidence(), pp, "x.pcap"); err != nil {
		t.Fatal(err)
	}
	if txt := pdfText(t, pp); !strings.Contains(txt, "Network Health: GOOD") || !strings.Contains(txt, "- "+qual) {
		t.Error("PDF must show GOOD and the ASCII-qualified note")
	}
	if !strings.Contains(noApplicableEvidenceText(true), "observed - there was no TCP") {
		t.Errorf("ascii form: %q", noApplicableEvidenceText(true))
	}
}

func TestCoverageWording_PartialAndNoEvidenceBothVisible(t *testing.T) {
	r := goodNoEvidence()
	r.Completeness = partialUnsupported()
	out := captureStdout(t, func() { PrintExecutiveSummary(r) })
	if !strings.Contains(out, qual) || !strings.Contains(out, "PARTIAL ANALYSIS") {
		t.Errorf("both limitations must be visible:\n%s", out)
	}
}

func TestCoverageWording_HealthLevelNeverChanges(t *testing.T) {
	for _, c := range []*models.EvidenceCoverage{nil, {}, {TCPFlows: 5}} {
		r := &models.TriageReport{EvidenceCoverage: c}
		if healthVerdict(r) != healthGood {
			t.Errorf("coverage %+v changed the verdict", c)
		}
	}
}
