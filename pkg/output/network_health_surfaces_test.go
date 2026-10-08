package output

import (
	"bytes"
	"compress/zlib"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/gocisse/sdwan-triage/pkg/models"
)

// Every surface renders the SAME authoritative level. Vocabulary may differ per
// surface (fair → "Warning" only in the legacy plain-English label), but no
// surface may contradict the underlying level.

type levelCase struct {
	level   string
	banner  string // terminal banner
	simple  string // -simple headline
	csv     string
	htmlVal string // enterprise + multi-page KPI value
	pdfLine string
	mk      func() *models.TriageReport
}

func levelCases() []levelCase {
	return []levelCase{
		{models.NetworkHealthGood, "NETWORK HEALTH: GOOD", "Your network is healthy and performing well", "GOOD", "Good", "Network Health: GOOD",
			func() *models.TriageReport { return &models.TriageReport{} }},
		{models.NetworkHealthFair, "NETWORK HEALTH: FAIR", "Your network has minor issues worth a look", "FAIR", "Fair", "Network Health: FAIR",
			func() *models.TriageReport {
				return &models.TriageReport{TCPRetransmissions: make([]models.TCPFlow, 1)}
			}},
		{models.NetworkHealthWarning, "NETWORK HEALTH: WARNING", "Your network has some issues that need attention", "WARNING", "Warning", "Network Health: WARNING",
			func() *models.TriageReport {
				return &models.TriageReport{StabilityFindings: []models.StabilityFinding{{Severity: "High"}}}
			}},
		{models.NetworkHealthCritical, "NETWORK HEALTH: CRITICAL", "Your network has serious problems requiring immediate action", "CRITICAL", "Critical", "Network Health: CRITICAL",
			func() *models.TriageReport { return &models.TriageReport{ARPConflicts: make([]models.ARPConflict, 1)} }},
	}
}

func readFile(t *testing.T, p string) string {
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func pdfText(t *testing.T, p string) string {
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	var all bytes.Buffer
	re := regexp.MustCompile(`(?s)stream\r?\n(.*?)\r?\nendstream`)
	for _, m := range re.FindAllSubmatch(b, -1) {
		if zr, err := zlib.NewReader(bytes.NewReader(m[1])); err == nil {
			d, _ := io.ReadAll(zr)
			all.Write(d)
		}
	}
	return all.String()
}

func TestNetworkHealth_AllSurfacesAgree(t *testing.T) {
	for _, lc := range levelCases() {
		t.Run(lc.level, func(t *testing.T) {
			r := lc.mk()
			r.NetworkHealth = models.ComputeNetworkHealth(r) // what Process stores
			if r.NetworkHealth != lc.level {
				t.Fatalf("fixture produces %q, want %q", r.NetworkHealth, lc.level)
			}

			term := captureStdout(t, func() { PrintExecutiveSummary(r) })
			if !strings.Contains(term, lc.banner) {
				t.Errorf("terminal missing %q:\n%s", lc.banner, term)
			}
			simple := captureStdout(t, func() { GenerateSimpleReport(r, "x.pcap") })
			if !strings.Contains(simple, lc.simple) {
				t.Errorf("simple missing %q:\n%s", lc.simple, simple)
			}

			res, err := GenerateCSVReports(r, filepath.Join(t.TempDir(), "o"))
			if err != nil {
				t.Fatal(err)
			}
			var sum string
			for _, f := range res.Files {
				if strings.Contains(filepath.Base(f), "summary") {
					sum = readFile(t, f)
				}
			}
			if !strings.Contains(sum, "Network Health Status,"+lc.csv+",") {
				t.Errorf("CSV missing status %s:\n%s", lc.csv, sum)
			}

			hp := filepath.Join(t.TempDir(), "r.html")
			if err := GenerateHTMLReport(r, hp, "x.pcap"); err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(readFile(t, hp), `kpi-value">`+lc.htmlVal) {
				t.Errorf("enterprise HTML KPI should read %q", lc.htmlVal)
			}
			mp := t.TempDir()
			if err := GenerateMultiPageHTMLReport(r, mp, "x.pcap"); err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(readFile(t, filepath.Join(mp, "index.html")), `kpi-value">`+lc.htmlVal) {
				t.Errorf("multi-page KPI should read %q", lc.htmlVal)
			}
			if !strings.Contains(readFile(t, filepath.Join(mp, "executive-summary.html")), "Network Health: "+strings.ToUpper(lc.level)) {
				t.Errorf("multi-page exec summary should say %s", strings.ToUpper(lc.level))
			}

			pp := filepath.Join(t.TempDir(), "r.pdf")
			if err := NewPDFGenerator().GeneratePDF(r, pp, "x.pcap"); err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(pdfText(t, pp), lc.pdfLine) {
				t.Errorf("PDF should contain %q", lc.pdfLine)
			}

			// No surface may state a different level.
			for _, other := range levelCases() {
				if other.level == lc.level {
					continue
				}
				if strings.Contains(term, other.banner) {
					t.Errorf("terminal also says %s", other.banner)
				}
				if strings.Contains(simple, other.simple) {
					t.Errorf("simple also says %q", other.simple)
				}
				if strings.Contains(sum, "Network Health Status,"+other.csv+",") {
					t.Errorf("CSV also says %s", other.csv)
				}
			}
		})
	}
}

// The specific contradictions the audit measured.
func TestNetworkHealth_FairIsNeitherGoodNorCritical(t *testing.T) {
	r := levelCases()[1].mk()
	hp := filepath.Join(t.TempDir(), "r.html")
	if err := GenerateHTMLReport(r, hp, "x.pcap"); err != nil {
		t.Fatal(err)
	}
	h := readFile(t, hp)
	if strings.Contains(h, `kpi-value">Critical`) || strings.Contains(h, `kpi-value">Good`) || !strings.Contains(h, `kpi-value">Fair`) {
		t.Error("FAIR must not fall through to Critical/Good in the enterprise HTML")
	}
	simple := captureStdout(t, func() { GenerateSimpleReport(r, "x.pcap") })
	if strings.Contains(simple, "healthy and performing well") || strings.Contains(simple, "serious problems") {
		t.Errorf("FAIR is neither healthy nor serious in -simple:\n%s", simple)
	}
}

func TestNetworkHealth_SimpleNoLongerUsesIndependentThresholds(t *testing.T) {
	// The legacy -simple algorithm called >50 legacy handshake failures "Critical" and
	// ignored most evidence. It now follows the authoritative level.
	r := &models.TriageReport{FailedHandshakes: make([]models.TCPFlow, 60)}
	level := models.ComputeNetworkHealth(r) // warning (60 > 5 in the performance bucket)
	simple := captureStdout(t, func() { GenerateSimpleReport(r, "x.pcap") })
	if level != models.NetworkHealthWarning || !strings.Contains(simple, "some issues that need attention") || strings.Contains(simple, "serious problems") {
		t.Errorf("level=%s\n%s", level, simple)
	}
}

func TestNetworkHealth_AccessorNeverDefaultsToGoodForNoData(t *testing.T) {
	if lvl, ok := networkHealthOf(noDataReport(models.NoDataReasonEmptyCapture)); ok || lvl != "" {
		t.Errorf("no-data must have no health level, got %q/%v", lvl, ok)
	}
	if lvl, ok := networkHealthOf(nil); ok || lvl != "" {
		t.Errorf("nil report must have no health level")
	}
	// An analyzed report whose field is unset uses the same authoritative computation.
	r := &models.TriageReport{ARPConflicts: make([]models.ARPConflict, 1)}
	if lvl, ok := networkHealthOf(r); !ok || lvl != models.NetworkHealthCritical {
		t.Errorf("fallback must use the authoritative computation, got %q", lvl)
	}
	// A stored value wins over recomputation (single source of truth).
	r.NetworkHealth = models.NetworkHealthFair
	if lvl, _ := networkHealthOf(r); lvl != models.NetworkHealthFair {
		t.Errorf("stored value must be used, got %q", lvl)
	}
}
