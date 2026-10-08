package output

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gocisse/sdwan-triage/pkg/models"
)

func noDataReport(reason string) *models.TriageReport {
	return &models.TriageReport{
		AnalysisStatus:      models.AnalysisStatusNoData,
		NoDataReason:        reason,
		RiskLevel:           "Low",
		PlainEnglishSummary: &models.PlainEnglishSummary{OverallHealth: "No Data", HealthIcon: "⚪"},
	}
}

func TestNoData_BannerNeverSaysHealthLevel(t *testing.T) {
	for reason, want := range map[string][]string{
		models.NoDataReasonEmptyCapture:         {"the capture file contains no packets.", "Check the capture interface, filter and timing, then capture again."},
		models.NoDataReasonFilterMatchedNothing: {"no packet matched the selected filter.", "Check the filter and capture again."},
	} {
		out := captureStdout(t, func() { PrintExecutiveSummary(noDataReport(reason)) })
		for _, w := range append(want, "NETWORK HEALTH: NO DATA - No packets were available to analyze", "No health judgment can be made.") {
			if !strings.Contains(out, w) {
				t.Errorf("%s: missing %q:\n%s", reason, w, out)
			}
		}
		for _, bad := range []string{"GOOD", "FAIR", "WARNING", "CRITICAL", "FINDINGS SUMMARY", "No significant issues"} {
			if strings.Contains(out, bad) {
				t.Errorf("%s: NO DATA output must not contain %q:\n%s", reason, bad, out)
			}
		}
	}
}

func TestNoData_HealthVerdictIsNotInvolved(t *testing.T) {
	// healthVerdict stays a pure four-level function over evidence: an empty report is
	// still GOOD *as a verdict*; the NO_DATA gate is what keeps it from being shown.
	if got := healthVerdict(noDataReport(models.NoDataReasonEmptyCapture)); got != healthGood {
		t.Errorf("healthVerdict must be untouched by NO_DATA, got %d", got)
	}
	// ...and a normal (analyzed) report still prints its verdict.
	out := captureStdout(t, func() { PrintExecutiveSummary(&models.TriageReport{}) })
	if !strings.Contains(out, "NETWORK HEALTH: GOOD - No significant issues detected") || strings.Contains(out, "NO DATA") {
		t.Errorf("analyzed reports are unchanged:\n%s", out)
	}
}

func TestNoData_SimpleReport(t *testing.T) {
	out := captureStdout(t, func() { GenerateSimpleReport(noDataReport(models.NoDataReasonEmptyCapture), "x.pcap") })
	if !strings.Contains(out, "No packets were available to analyze. No conclusion about your network can be drawn.") {
		t.Errorf("simple wording:\n%s", out)
	}
	for _, bad := range []string{"healthy", "performing well", "serious problems", "some issues"} {
		if strings.Contains(out, bad) {
			t.Errorf("simple NO_DATA must not contain %q:\n%s", bad, out)
		}
	}
	out = captureStdout(t, func() { GenerateSimpleReport(noDataReport(models.NoDataReasonFilterMatchedNothing), "x.pcap") })
	if !strings.Contains(out, "No packet matched the filter you selected") {
		t.Errorf("filter wording:\n%s", out)
	}
}

func TestNoData_CSV(t *testing.T) {
	base := filepath.Join(t.TempDir(), "out")
	res, err := GenerateCSVReports(noDataReport(models.NoDataReasonFilterMatchedNothing), base)
	if err != nil {
		t.Fatal(err)
	}
	var sum string
	for _, f := range res.Files {
		if strings.Contains(filepath.Base(f), "summary") {
			b, _ := os.ReadFile(f)
			sum = string(b)
		}
	}
	for _, w := range []string{"Network Health Status,NO_DATA,", "Analysis Status,no_data,", "No Data Reason,filter_matched_nothing,"} {
		if !strings.Contains(sum, w) {
			t.Errorf("CSV summary missing %q:\n%s", w, sum)
		}
	}
	if strings.Contains(sum, "Network Health Status,GOOD") {
		t.Error("CSV must not report GOOD")
	}
}

func TestNoData_HTML(t *testing.T) {
	r := noDataReport(models.NoDataReasonEmptyCapture)
	path := filepath.Join(t.TempDir(), "r.html")
	if err := GenerateHTMLReport(r, path, "x.pcap"); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(path)
	h := string(b)
	for _, w := range []string{"NETWORK HEALTH: NO DATA", "the capture file contains no packets.", `kpi-value">No data`, "kpi-card no-data"} {
		if !strings.Contains(h, w) {
			t.Errorf("enterprise HTML missing %q", w)
		}
	}
	for _, bad := range []string{"Network Health: GOOD", "Network Health: CRITICAL", `kpi-value">Critical`, `kpi-value">Good`, `kpi-badge">
                            Healthy`} {
		if strings.Contains(h, bad) {
			t.Errorf("enterprise HTML must not contain %q", bad)
		}
	}

	dir := t.TempDir()
	if err := GenerateMultiPageHTMLReport(r, dir, "x.pcap"); err != nil {
		t.Fatal(err)
	}
	var all strings.Builder
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".html") {
			b, _ := os.ReadFile(filepath.Join(dir, e.Name()))
			all.Write(b)
		}
	}
	m := all.String()
	for _, w := range []string{"Network Health: NO DATA", `kpi-value">No data`} {
		if !strings.Contains(m, w) {
			t.Errorf("multi-page HTML missing %q", w)
		}
	}
	for _, bad := range []string{"Network Health: GOOD", "Network Health: CRITICAL", "Network Health: WARNING", `kpi-value">Critical`, `kpi-value">Good`} {
		if strings.Contains(m, bad) {
			t.Errorf("multi-page HTML must not contain %q", bad)
		}
	}
	// Analyzed reports carry no NO DATA block.
	path2 := filepath.Join(t.TempDir(), "n.html")
	if err := GenerateHTMLReport(&models.TriageReport{}, path2, "x.pcap"); err != nil {
		t.Fatal(err)
	}
	b2, _ := os.ReadFile(path2)
	if strings.Contains(string(b2), "no-data-notice") || strings.Contains(string(b2), "NETWORK HEALTH: NO DATA") {
		t.Error("analyzed report must not show NO DATA")
	}
}

func TestNoData_PDF(t *testing.T) {
	path := filepath.Join(t.TempDir(), "r.pdf")
	if err := NewPDFGenerator().GeneratePDF(noDataReport(models.NoDataReasonEmptyCapture), path, "x.pcap"); err != nil {
		t.Fatal(err)
	}
	if st, err := os.Stat(path); err != nil || st.Size() == 0 {
		t.Fatal("PDF not generated")
	}
	one := noDataOneLine(noDataReport(models.NoDataReasonEmptyCapture))
	if !strings.HasPrefix(one, "NO DATA:") {
		t.Errorf("one-line: %q", one)
	}
	for _, ch := range one {
		if ch > 126 {
			t.Errorf("PDF core fonts need ASCII, got %q", ch)
		}
	}
}

func TestNoData_HelpersAreEmptyForAnalyzedReports(t *testing.T) {
	r := &models.TriageReport{}
	if noDataLines(r) != nil || noDataText(r) != "" || noDataOneLine(r) != "" || noDataSimpleLines(r) != nil || NoDataNotice(r) != "" {
		t.Error("analyzed reports must produce no NO_DATA text")
	}
	var nilReport *models.TriageReport
	if nilReport.IsNoData() {
		t.Error("nil report is not NO_DATA")
	}
}
