package output

import (
	"strings"
	"testing"

	"github.com/gocisse/sdwan-triage/pkg/models"
)

// Phase 4.35 — the detailed report shows the frames, further MACs and the explanation of an ARP conflict.
func TestDetailedReport_ARPConflictShowsEvidenceAndExplanation(t *testing.T) {
	c := models.ARPConflict{IP: "192.168.42.1", MAC1: "00:07:b4:00:2a:01", MAC2: "00:07:b4:00:2a:02", MAC1Frame: 25504, MAC2Frame: 25813, OtherMACs: []string{"00:00:5e:00:01:01"}}
	c.Classify()
	out := captureStdout(t, func() { PrintDetailedReport(&models.TriageReport{ARPConflicts: []models.ARPConflict{c}}) })
	for _, must := range []string{
		"IP 192.168.42.1 claimed by: 00:07:b4:00:2a:01 and 00:07:b4:00:2a:02",
		"also answered by: 00:00:5e:00:01:01",
		"first replies: frame 25504 (00:07:b4:00:2a:01), frame 25813 (00:07:b4:00:2a:02)",
		"consistent with a redundant gateway rather than a duplicate IP address",
	} {
		if !strings.Contains(out, must) {
			t.Errorf("missing %q in:\n%s", must, out)
		}
	}
	// A legacy conflict (no evidence fields) prints exactly the original line only.
	old := captureStdout(t, func() {
		PrintDetailedReport(&models.TriageReport{ARPConflicts: []models.ARPConflict{{IP: "10.0.0.1", MAC1: "a", MAC2: "b"}}})
	})
	if !strings.Contains(old, "IP 10.0.0.1 claimed by: a and b") || strings.Contains(old, "first replies") || strings.Contains(old, "also answered") {
		t.Errorf("legacy output changed:\n%s", old)
	}
}
