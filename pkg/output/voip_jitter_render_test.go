package output

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"text/template"

	"github.com/gocisse/sdwan-triage/pkg/models"
)

func fptr(v float64) *float64 { return &v }

func TestVoIPJitterText(t *testing.T) {
	v := &VoIPAnalysisView{}
	if got := v.AvgJitterText(); got != "n/a" {
		t.Errorf("nil avg = %q, want n/a", got)
	}
	v.AvgJitter = fptr(0)
	if got := v.AvgJitterText(); got != "0.00 ms" {
		t.Errorf("measured zero avg = %q, want 0.00 ms", got)
	}
	v.AvgJitter = fptr(0.8811509865627158)
	if got := v.AvgJitterText(); got != "0.88 ms" {
		t.Errorf("avg = %q", got)
	}
	if got := (RTPStreamView{}).JitterText(); got != "n/a" {
		t.Errorf("nil stream jitter = %q", got)
	}
	if got := (RTPStreamView{Jitter: fptr(0)}).JitterText(); got != "0.00" {
		t.Errorf("zero stream jitter = %q", got)
	}
}

func TestConvertVoIPAnalysis_NilJitterRendersNA(t *testing.T) {
	view := convertVoIPAnalysis(&models.VoIPAnalysis{
		TotalRTPStreams: 2,
		RTPStreams: []models.RTPStreamInfo{
			{SSRC: 1, PayloadType: "Dynamic (96)", PacketCount: 9},
			{SSRC: 2, PayloadType: "PCMA (G.711 A-law)", PacketCount: 9, Jitter: fptr(0.5)},
		},
	})
	tmpl := template.Must(template.New("x").Parse(
		`{{.AvgJitterText}}|{{range .RTPStreams}}{{.JitterText}};{{end}}`))
	var sb strings.Builder
	if err := tmpl.Execute(&sb, view); err != nil {
		t.Fatal(err)
	}
	if sb.String() != "n/a|n/a;0.50;" {
		t.Errorf("rendered %q", sb.String())
	}
}

func TestVoIPTemplates_UseJitterTextNotPrintf(t *testing.T) {
	// The report templates must not format the nullable pointer with printf.
	for _, f := range []string{"html_pages.go", "html_report.go", filepath.Join("assets", "templates", "enterprise-dashboard.html")} {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(b), `printf "%.2f" .VoIPAnalysis.AvgJitter}}`) || strings.Contains(string(b), `printf "%.2f" .Jitter}}`) {
			t.Errorf("%s still printf-formats nullable jitter", f)
		}
	}
}

func TestVoIPCSV_JitterNA(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "voip.csv")
	err := generateVoIPAnalysisCSV(&models.VoIPAnalysis{
		TotalRTPStreams: 2,
		RTPStreams: []models.RTPStreamInfo{
			{SSRC: 1, PayloadType: "Dynamic (96)", PacketCount: 9},
			{SSRC: 2, PayloadType: "PCMU", PacketCount: 9, Jitter: fptr(0)},
		},
	}, f)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(f)
	out := string(b)
	if !strings.Contains(out, "Average Jitter (ms),n/a") {
		t.Errorf("average should be n/a:\n%s", out)
	}
	if !strings.Contains(out, "Dynamic (96),9,") || !strings.Contains(out, ",n/a\n") {
		t.Errorf("stream jitter should be n/a:\n%s", out)
	}
	if !strings.Contains(out, ",0.00\n") {
		t.Errorf("measured zero must stay 0.00:\n%s", out)
	}
}

func voipRenderReport() *models.TriageReport {
	return &models.TriageReport{
		TotalBytes: 1000,
		VoIPAnalysis: &models.VoIPAnalysis{
			TotalRTPStreams: 2,
			RTPStreams: []models.RTPStreamInfo{
				{SSRC: 11, SrcIP: "10.0.0.1", DstIP: "10.0.0.2", PayloadType: "Dynamic (96)", PacketCount: 9},
				{SSRC: 22, SrcIP: "10.0.0.1", DstIP: "10.0.0.2", PayloadType: "PCMU", PacketCount: 9, Jitter: fptr(0)},
			},
		},
	}
}

// readAll concatenates every file under dir (or the single file).
func readAllText(t *testing.T, path string) string {
	t.Helper()
	var sb strings.Builder
	_ = filepath.Walk(path, func(p string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() {
			b, _ := os.ReadFile(p)
			sb.Write(b)
		}
		return nil
	})
	return sb.String()
}

func TestVoIPHTMLGenerators_RenderUnavailableJitterAsNA(t *testing.T) {
	dir := t.TempDir()

	legacy := filepath.Join(dir, "legacy.html")
	if err := GenerateLegacyHTMLReport(voipRenderReport(), legacy, "t.pcap"); err != nil {
		t.Fatalf("legacy report: %v", err)
	}
	out := readAllText(t, legacy)
	if !strings.Contains(out, "n/a") || !strings.Contains(out, "<td>0.00</td>") || strings.Contains(out, "%!") {
		t.Errorf("legacy report: want n/a avg + n/a stream + measured 0.00, no format errors")
	}
	if !strings.Contains(out, `<span class="stat-value">n/a</span>`) {
		t.Error("legacy report: average jitter must render as n/a")
	}

	mp := filepath.Join(dir, "mp")
	if err := GenerateMultiPageHTMLReport(voipRenderReport(), mp, "t.pcap"); err != nil {
		t.Fatalf("multi-page report: %v", err)
	}
	mpOut := readAllText(t, mp)
	if !strings.Contains(mpOut, "<strong>Avg Jitter:</strong> n/a") || strings.Contains(mpOut, "%!") {
		t.Errorf("multi-page report must render the average as n/a without format errors")
	}
}
