package analyzer

import (
	"regexp"
	"strings"
	"testing"

	"github.com/gocisse/sdwan-triage/pkg/models"
)

var loneRetransLoss = regexp.MustCompile(`(?i)(packet loss on (the )?(network|flow|tunnel)|indicates? packet loss|indicating packet loss|significant packet loss|network experiencing|is lossy|packets are being lost|experiencing packet loss)`)

// Phase 4.46: recommendations and findings derived from retransmissions alone
// must not state loss as established.
func TestRetransmissionOnly_RecommendedActions(t *testing.T) {
	p := NewProcessor()
	for _, n := range []int{11, 60} {
		acts := p.generateRecommendations(&models.TriageReport{}, map[string]int{"TCP Retransmissions": n})
		text := strings.Join(acts, "\n")
		if !strings.Contains(text, "TCP retransmissions observed") && !strings.Contains(text, "Excessive TCP retransmissions observed") {
			t.Errorf("n=%d: action must say retransmissions were observed:\n%s", n, text)
		}
		if m := loneRetransLoss.FindString(text); m != "" {
			t.Errorf("n=%d: action claims loss (%q):\n%s", n, m, text)
		}
		if !strings.Contains(strings.ToLower(text), "not determined") && !strings.Contains(strings.ToLower(text), "does not establish") {
			t.Errorf("n=%d: action must state the cause is undetermined:\n%s", n, text)
		}
	}
}

func TestRetransmissionOnly_KnowledgeBaseStaysKeyedAndHedged(t *testing.T) {
	it, ok := IssueKnowledgeBase["TCP_RETRANSMISSION_BURST"] // key must stay stable
	if !ok {
		t.Fatal("TCP_RETRANSMISSION_BURST missing")
	}
	if loneRetransLoss.MatchString(it.Description) {
		t.Errorf("description claims loss: %s", it.Description)
	}
	if !strings.Contains(strings.ToLower(it.Description), "do not by themselves establish") {
		t.Errorf("description must hedge: %s", it.Description)
	}
	// Independent VoIP loss entry untouched.
	if _, ok := IssueKnowledgeBase["VOIP_PACKET_LOSS"]; !ok {
		t.Error("VOIP_PACKET_LOSS entry removed")
	}
}
