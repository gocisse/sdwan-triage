package output

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/gocisse/sdwan-triage/pkg/models"
	"github.com/gocisse/sdwan-triage/pkg/safety"
)

// Phase 4.46: wherever the only evidence is TCP retransmissions, user-facing
// text must not state packet loss as established. This is a semantic check
// (banned confirmed-loss claims), not a check for one preferred phrase.

var confirmedLossClaim = regexp.MustCompile(`(?i)(packets? (are|were|is) (being )?lost|is losing packets|are being lost|(severe|significant|major) packet loss|indicat\w* (network )?packet loss|retransmissions? indicate|indicating packet loss|(is|are) lost or corrupted|packet loss detected|data is being lost)`)

// hedgedLoss matches loss mentioned only as an open question or possibility
// ("whether packets were lost", "or packets were lost"), which is acceptable.
var hedgedLoss = regexp.MustCompile(`(?i)(whether|if|because|or|that|may be because)\s+(the\s+)?(original\s+)?packets?\s+(were|was)\s+lost`)

func assertNoConfirmedLoss(t *testing.T, where, text string) {
	t.Helper()
	text = hedgedLoss.ReplaceAllString(text, "")
	if m := confirmedLossClaim.FindString(text); m != "" {
		t.Errorf("%s states loss from retransmissions alone (%q):\n%s", where, m, text)
	}
}

func TestRetransmissionOnly_ExplanationsAndNextSteps(t *testing.T) {
	e := GenerateTCPRetransmissionExplanation("10.0.0.1", "10.0.0.2", 12)
	assertNoConfirmedLoss(t, "explanation", e.Definition+" "+e.Impact+" "+e.Detection+" "+e.RecommendedAction)
	if !strings.Contains(strings.ToLower(e.Impact), "does not establish") {
		t.Errorf("impact must say the cause is not established: %s", e.Impact)
	}

	r := &models.TriageReport{TCPRetransmissions: flows(30)}
	assertNoConfirmedLoss(t, "next steps", strings.Join(generateNextSteps(r), "\n"))
}

func TestRetransmissionOnly_WizardIssuesAndGuides(t *testing.T) {
	r := &models.TriageReport{TCPRetransmissions: flows(600)}
	var b strings.Builder
	for _, is := range generateTopIssues(r) {
		b.WriteString(is.Title + " " + is.PlainEnglish + " " + is.BusinessImpact + " " + is.QuickFix + " " + strings.Join(is.DetailedSteps, " ") + "\n")
	}
	for _, g := range generateEnhancedProtocolGuides(r) {
		if g.Protocol != "TCP Retransmissions" {
			continue
		}
		b.WriteString(g.ImpactDetails + " " + g.TroubleshootTip + " " + strings.Join(g.CommonIssues, " ") + "\n")
		for _, f := range g.DetailedFilters {
			b.WriteString(f.Description + " " + f.UseCase + "\n")
		}
	}
	text := b.String()
	if !strings.Contains(text, "High Packet Retransmissions") {
		t.Fatalf("expected the retransmission issue to be generated:\n%s", text)
	}
	assertNoConfirmedLoss(t, "wizard", text)
	if strings.Contains(strings.ToLower(text), "cable issues") && !strings.Contains(strings.ToLower(text), "if interface errors") && !strings.Contains(strings.ToLower(text), "interface errors") {
		t.Errorf("cable/physical causes must not be asserted without interface-error evidence:\n%s", text)
	}
}

func TestRetransmissionOnly_CSVRowDescription(t *testing.T) {
	path := filepath.Join(t.TempDir(), "retrans.csv")
	if err := generateTCPRetransmissionsCSV(flows(2), path); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	assertNoConfirmedLoss(t, "csv", string(b))
	if !strings.Contains(string(b), "TCP retransmission observed") {
		t.Errorf("csv row should say retransmission observed:\n%s", b)
	}
}

func TestRetransmissionOnly_TranslationTCP002(t *testing.T) {
	tr, ok := safety.GetTranslation("TCP-002") // identifier must stay stable
	if !ok {
		t.Fatal("TCP-002 translation missing")
	}
	assertNoConfirmedLoss(t, "TCP-002", tr.TechnicalDescription+" "+tr.CustomerFacingSummary+" "+tr.BusinessImpact+" "+tr.CommonMistake)
}

func TestRetransmissionOnly_StaticTemplatesAndExports(t *testing.T) {
	for _, rel := range []string{"assets/templates/enterprise-dashboard.html", "html_export.go", "d3_data.go", "wireshark_guide.go"} {
		b, err := os.ReadFile(rel)
		if err != nil {
			t.Fatal(err)
		}
		text := string(b)
		// Only the retransmission-related passages are asserted.
		for _, line := range strings.Split(text, "\n") {
			low := strings.ToLower(line)
			if strings.Contains(low, "retransmi") || strings.Contains(low, "this connection has") {
				assertNoConfirmedLoss(t, rel, line)
			}
		}
	}
}

// The frontend components that present the retransmission-derived metric are
// scanned from Go so the check does not need Node type definitions.
func TestRetransmissionOnly_FrontendSources(t *testing.T) {
	root := filepath.Join("..", "..", "web", "frontend", "src", "components")
	for _, rel := range []string{"dashboard/ExecutiveSummary.tsx", "results/FindingsSection.tsx", "AnalysisBadges.tsx", "StreamConversation.tsx", "Glossary.tsx"} {
		b, err := os.ReadFile(filepath.Join(root, rel))
		if err != nil {
			t.Fatal(err)
		}
		for _, line := range strings.Split(string(b), "\n") {
			low := strings.ToLower(line)
			if strings.Contains(low, "retransmi") && !strings.HasPrefix(strings.TrimSpace(line), "//") {
				assertNoConfirmedLoss(t, rel, line)
			}
		}
	}
}

// Independently measured loss wording must survive: RTP/VoIP loss and the
// Wireshark filter names are not retransmission-derived.
func TestIndependentLossWordingRetained(t *testing.T) {
	b, err := os.ReadFile("filter_builder.go")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "VOIP_PACKET_LOSS") || !strings.Contains(string(b), "tcp.analysis.lost_segment") {
		t.Error("independent loss identifiers/filters were altered")
	}
}
