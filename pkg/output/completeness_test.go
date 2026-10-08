package output

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gocisse/sdwan-triage/pkg/models"
)

// partialUnsupported is the Ultimate-PCAP-shaped completeness record.
func partialUnsupported() *models.CaptureCompleteness {
	return &models.CaptureCompleteness{
		PacketsRead: 51328, PacketsDecoded: 40661, PacketsUnsupported: 10667,
		UnsupportedLinkTypes: []models.UnsupportedLinkType{{LinkType: 18, Label: "18 (pcapng link type 274, IEEE 802.3br mPackets, truncated by the decoder library)", Packets: 10667}},
	}
}

func readErrorOnly() *models.CaptureCompleteness {
	return &models.CaptureCompleteness{PacketsRead: 100, PacketsDecoded: 100, ReadErrors: 1}
}

// ─── severity is independent of completeness ─────────────────────

func TestCompleteness_DoesNotChangeHealthLevel(t *testing.T) {
	builders := map[string]func() *models.TriageReport{
		"clean":       func() *models.TriageReport { return &models.TriageReport{} },
		"1 failed hs": func() *models.TriageReport { return &models.TriageReport{TCPHandshakeFlows: hvFailed(1)} },
		"6 failed hs": func() *models.TriageReport { return &models.TriageReport{TCPHandshakeFlows: hvFailed(6)} },
		"retrans flow": func() *models.TriageReport {
			return &models.TriageReport{TCPRetransmissions: make([]models.TCPFlow, 1)}
		},
		"high stability": func() *models.TriageReport {
			return &models.TriageReport{StabilityFindings: []models.StabilityFinding{{Severity: "High"}}}
		},
		"low stability": func() *models.TriageReport {
			return &models.TriageReport{StabilityFindings: []models.StabilityFinding{{Severity: "Low"}}}
		},
		"zero window": func() *models.TriageReport {
			return &models.TriageReport{TCPWindowFindings: []models.TCPWindowFinding{{Type: "Zero Window"}}}
		},
		"small window": func() *models.TriageReport {
			return &models.TriageReport{TCPWindowFindings: []models.TCPWindowFinding{{Type: "Small Window"}}}
		},
		"high finding": func() *models.TriageReport {
			return &models.TriageReport{Findings: []models.Finding{{Severity: models.SeverityHigh, Basis: models.EvidenceSameSession}}}
		},
		"time-proximity high": func() *models.TriageReport {
			return &models.TriageReport{Findings: []models.Finding{{Severity: models.SeverityHigh, Basis: models.EvidenceTimeProximity}}}
		},
		"dns": func() *models.TriageReport { return &models.TriageReport{DNSAnomalies: make([]models.DNSAnomaly, 1)} },
		"arp": func() *models.TriageReport { return &models.TriageReport{ARPConflicts: make([]models.ARPConflict, 1)} },
		"suspicious": func() *models.TriageReport {
			return &models.TriageReport{SuspiciousTraffic: make([]models.SuspiciousFlow, 1)}
		},
	}
	for name, mk := range builders {
		want := healthVerdict(mk())
		for cname, c := range map[string]*models.CaptureCompleteness{"unsupported": partialUnsupported(), "read error": readErrorOnly()} {
			r := mk()
			r.Completeness = c
			if got := healthVerdict(r); got != want {
				t.Errorf("%s with %s completeness: level %d, want %d (completeness must not change severity)", name, cname, got, want)
			}
		}
	}
}

// ─── banner wording ──────────────────────────────────────────────

func TestCompleteness_CompleteBannerUnchanged(t *testing.T) {
	out := captureStdout(t, func() { PrintExecutiveSummary(&models.TriageReport{}) })
	if !strings.Contains(out, "NETWORK HEALTH: GOOD - No significant issues detected\n") {
		t.Errorf("complete GOOD wording changed:\n%s", out)
	}
	if strings.Contains(out, "PARTIAL ANALYSIS") || strings.Contains(out, "INCOMPLETE CAPTURE FILE") {
		t.Errorf("complete capture must carry no completeness notice:\n%s", out)
	}
}

func TestCompleteness_PartialGoodIsObservational(t *testing.T) {
	r := &models.TriageReport{Completeness: partialUnsupported()}
	out := captureStdout(t, func() { PrintExecutiveSummary(r) })
	if !strings.Contains(out, "NETWORK HEALTH: GOOD - No significant issues observed in the analyzed packets\n") {
		t.Errorf("partial GOOD must use observational wording:\n%s", out)
	}
	if strings.Contains(out, "No significant issues detected") {
		t.Errorf("partial GOOD must not use the affirmative wording:\n%s", out)
	}
	for _, want := range []string{"PARTIAL ANALYSIS: 10,667 of 51,328 packets (20.8%) were not analyzed.", "Unsupported link type 18", "10,667 packets.", "Findings cover only the analyzed packets"} {
		if !strings.Contains(out, want) {
			t.Errorf("notice missing %q:\n%s", want, out)
		}
	}
}

func TestCompleteness_SeverityLabelsUnchangedWhenPartial(t *testing.T) {
	cases := []struct {
		name string
		mk   func() *models.TriageReport
		want string
	}{
		{"FAIR", func() *models.TriageReport { return &models.TriageReport{TCPHandshakeFlows: hvFailed(1)} }, "NETWORK HEALTH: FAIR - Minor issues detected"},
		{"WARNING", func() *models.TriageReport {
			return &models.TriageReport{StabilityFindings: []models.StabilityFinding{{Severity: "High"}}}
		}, "NETWORK HEALTH: WARNING - Issues detected that need review"},
		{"CRITICAL", func() *models.TriageReport { return &models.TriageReport{ARPConflicts: make([]models.ARPConflict, 1)} }, "NETWORK HEALTH: CRITICAL - Immediate attention required"},
	}
	for _, tc := range cases {
		complete := captureStdout(t, func() { PrintExecutiveSummary(tc.mk()) })
		r := tc.mk()
		r.Completeness = partialUnsupported()
		partial := captureStdout(t, func() { PrintExecutiveSummary(r) })
		if !strings.Contains(complete, tc.want) || !strings.Contains(partial, tc.want) {
			t.Errorf("%s: severity line must be identical for complete and partial input", tc.name)
		}
		if strings.Contains(complete, "PARTIAL ANALYSIS") {
			t.Errorf("%s: complete input must not show the notice", tc.name)
		}
		if !strings.Contains(partial, "PARTIAL ANALYSIS") {
			t.Errorf("%s: partial input must show the notice:\n%s", tc.name, partial)
		}
	}
}

func TestCompleteness_ReadErrorNoticeMakesNoLossClaim(t *testing.T) {
	r := &models.TriageReport{ARPConflicts: make([]models.ARPConflict, 1), Completeness: readErrorOnly()}
	out := captureStdout(t, func() { PrintExecutiveSummary(r) })
	for _, want := range []string{"NETWORK HEALTH: CRITICAL", "INCOMPLETE CAPTURE FILE: the capture ended unexpectedly (1 read error(s)).", "Trailing packets may be missing."} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q:\n%s", want, out)
		}
	}
	for _, text := range []string{out, completenessOneLine(&models.TriageReport{Completeness: partialUnsupported()})} {
		low := strings.ToLower(text)
		if strings.Contains(low, "packet loss") || strings.Contains(low, "lost") {
			t.Errorf("notice must not claim packet loss: %s", text)
		}
	}
}

func TestCompleteness_CausesStayDistinct(t *testing.T) {
	r := &models.TriageReport{Completeness: &models.CaptureCompleteness{
		PacketsRead: 1000, PacketsDecoded: 900, PacketsUnsupported: 60, PacketsDecodeFailed: 30, PacketsSkipped: 10, ReadErrors: 2,
		UnsupportedLinkTypes: []models.UnsupportedLinkType{{LinkType: 18, Label: "18", Packets: 40}, {LinkType: 200, Label: "200", Packets: 20}},
	}}
	text := completenessText(r)
	for _, want := range []string{
		"60 of 1,000 packets (6.0%) were not analyzed.",
		"Unsupported link type 18: 40 packets.", "Unsupported link type 200: 20 packets.",
		"30 packets could not be decoded", "10 packets were skipped after an internal analyzer error",
		"2 read error(s)",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("missing %q in:\n%s", want, text)
		}
	}
	if strings.Index(text, "link type 18") > strings.Index(text, "link type 200") {
		t.Error("unsupported link types must be listed in ascending order")
	}
	// Decode failures alone, skipped alone: still partial, no unsupported claim.
	for _, c := range []*models.CaptureCompleteness{
		{PacketsRead: 10, PacketsDecoded: 9, PacketsDecodeFailed: 1},
		{PacketsRead: 10, PacketsDecoded: 10, PacketsSkipped: 1},
	} {
		got := completenessText(&models.TriageReport{Completeness: c})
		if !strings.Contains(got, "PARTIAL ANALYSIS: some packets were not fully analyzed.") || strings.Contains(got, "Unsupported link type") {
			t.Errorf("unexpected text for %+v:\n%s", c, got)
		}
	}
}

func TestCompleteness_NilAndZeroAreComplete(t *testing.T) {
	for _, r := range []*models.TriageReport{nil, {}, {Completeness: &models.CaptureCompleteness{PacketsRead: 5, PacketsDecoded: 5}}} {
		if completenessLines(r) != nil || completenessText(r) != "" || completenessOneLine(r) != "" || goodSubline(r) != goodSublineComplete {
			t.Errorf("complete/zero completeness must produce no notice: %+v", r)
		}
	}
}

func TestCompleteness_Deterministic(t *testing.T) {
	r := &models.TriageReport{Completeness: partialUnsupported()}
	first := completenessText(r)
	for i := 0; i < 50; i++ {
		if completenessText(r) != first {
			t.Fatal("completeness text is not deterministic")
		}
	}
}

func TestWithThousands(t *testing.T) {
	for in, want := range map[int]string{0: "0", 999: "999", 1000: "1,000", 10667: "10,667", 51328: "51,328", 1234567: "1,234,567"} {
		if got := withThousands(in); got != want {
			t.Errorf("withThousands(%d) = %q, want %q", in, got, want)
		}
	}
}

// ─── JSON ────────────────────────────────────────────────────────

func TestCompleteness_JSONOmittedWhenComplete(t *testing.T) {
	b, err := json.Marshal(&models.TriageReport{})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "capture_completeness") {
		t.Errorf("complete report must not carry capture_completeness: %s", b)
	}
}

func TestCompleteness_JSONPresentWhenPartial(t *testing.T) {
	b, err := json.Marshal(&models.TriageReport{Completeness: partialUnsupported()})
	if err != nil || !json.Valid(b) {
		t.Fatalf("invalid JSON: %v", err)
	}
	var back struct {
		C *models.CaptureCompleteness `json:"capture_completeness"`
	}
	if err := json.Unmarshal(b, &back); err != nil || back.C == nil {
		t.Fatalf("capture_completeness missing: %v / %s", err, b)
	}
	if back.C.PacketsRead != 51328 || back.C.PacketsUnsupported != 10667 || back.C.PacketsDecodeFailed != 0 ||
		back.C.PacketsSkipped != 0 || back.C.ReadErrors != 0 || len(back.C.UnsupportedLinkTypes) != 1 || back.C.UnsupportedLinkTypes[0].LinkType != 18 {
		t.Errorf("unexpected content: %+v", back.C)
	}
}

// ─── simple report ───────────────────────────────────────────────

func TestCompleteness_SimpleReport(t *testing.T) {
	complete := captureStdout(t, func() { GenerateSimpleReport(&models.TriageReport{}, "x.pcap") })
	if !strings.Contains(complete, "Your network is healthy and performing well") || strings.Contains(complete, "PARTIAL ANALYSIS") {
		t.Errorf("complete simple report must be unchanged:\n%s", complete)
	}
	partial := captureStdout(t, func() {
		GenerateSimpleReport(&models.TriageReport{Completeness: partialUnsupported()}, "x.pcap")
	})
	if strings.Contains(partial, "healthy and performing well") {
		t.Errorf("partial simple report must not claim the network is healthy:\n%s", partial)
	}
	for _, want := range []string{"No problems were found in the packets that could be analyzed", "PARTIAL ANALYSIS"} {
		if !strings.Contains(partial, want) {
			t.Errorf("partial simple report missing %q:\n%s", want, partial)
		}
	}
	// Severity text for a Critical simple report is unchanged by completeness.
	crit := func(c *models.CaptureCompleteness) string {
		r := &models.TriageReport{ARPConflicts: make([]models.ARPConflict, 1), Completeness: c}
		return captureStdout(t, func() { GenerateSimpleReport(r, "x.pcap") })
	}
	if !strings.Contains(crit(nil), "serious problems requiring immediate action") || !strings.Contains(crit(partialUnsupported()), "serious problems requiring immediate action") {
		t.Error("simple severity text must not depend on completeness")
	}
}

// ─── HTML / CSV / PDF ────────────────────────────────────────────

func TestCompleteness_EnterpriseHTML(t *testing.T) {
	dir := t.TempDir()
	gen := func(name string, r *models.TriageReport) string {
		path := filepath.Join(dir, name)
		if err := GenerateHTMLReport(r, path, "x.pcap"); err != nil {
			t.Fatal(err)
		}
		b, _ := os.ReadFile(path)
		return string(b)
	}
	complete := gen("complete.html", &models.TriageReport{})
	if strings.Contains(complete, "completeness-notice") || strings.Contains(complete, "PARTIAL ANALYSIS") {
		t.Error("complete enterprise HTML must carry no notice")
	}
	partial := gen("partial.html", &models.TriageReport{Completeness: partialUnsupported()})
	for _, want := range []string{"completeness-notice", "PARTIAL ANALYSIS: 10,667 of 51,328", "No issues observed"} {
		if !strings.Contains(partial, want) {
			t.Errorf("partial enterprise HTML missing %q", want)
		}
	}
}

func TestCompleteness_MultiPageHTML(t *testing.T) {
	read := func(r *models.TriageReport) string {
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
		return all.String()
	}
	if c := read(&models.TriageReport{}); strings.Contains(c, "completeness-notice") {
		t.Error("complete multipage HTML must carry no notice")
	}
	p := read(&models.TriageReport{Completeness: partialUnsupported()})
	if !strings.Contains(p, "completeness-notice") || !strings.Contains(p, "PARTIAL ANALYSIS: 10,667 of 51,328") || !strings.Contains(p, "(analyzed packets only)") {
		t.Error("partial multipage HTML must carry the notice and the qualified GOOD badge")
	}
}

func TestCompleteness_CSVSummary(t *testing.T) {
	summary := func(r *models.TriageReport) string {
		base := filepath.Join(t.TempDir(), "out")
		res, err := GenerateCSVReports(r, base)
		if err != nil {
			t.Fatal(err)
		}
		var sb strings.Builder
		for _, f := range res.Files {
			if strings.Contains(filepath.Base(f), "summary") {
				b, _ := os.ReadFile(f)
				sb.Write(b)
			}
		}
		return sb.String()
	}
	c := summary(&models.TriageReport{})
	if c == "" || strings.Contains(c, "Capture Completeness") {
		t.Errorf("complete CSV summary must exist and carry no completeness row:\n%s", c)
	}
	p := summary(&models.TriageReport{Completeness: partialUnsupported()})
	if !strings.Contains(p, "Capture Completeness,PARTIAL,") || !strings.Contains(p, "10667 of 51328 packets not analyzed") {
		t.Errorf("partial CSV summary missing completeness row:\n%s", p)
	}
}

func TestCompleteness_PDFGenerates(t *testing.T) {
	for name, r := range map[string]*models.TriageReport{"complete": {}, "partial": {Completeness: partialUnsupported()}, "read error": {Completeness: readErrorOnly()}} {
		path := filepath.Join(t.TempDir(), name+".pdf")
		if err := NewPDFGenerator().GeneratePDF(r, path, "x.pcap"); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if st, err := os.Stat(path); err != nil || st.Size() == 0 {
			t.Fatalf("%s: empty PDF", name)
		}
	}
	one := completenessOneLine(&models.TriageReport{Completeness: partialUnsupported()})
	for _, ch := range one {
		if ch > 126 {
			t.Errorf("PDF core fonts need ASCII text, got %q in %q", ch, one)
		}
	}
}
