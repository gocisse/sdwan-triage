package output

import (
	"bytes"
	"strings"
	"testing"

	"github.com/gocisse/sdwan-triage/pkg/models"
)

// The executive summary reports TCP connection-setup results from the handshake
// tracker (TCPHandshakeFlows), not from the narrower RST-only FailedHandshakes.

func hsFlows(state, reason string, n int) []models.TCPHandshakeFlow {
	out := make([]models.TCPHandshakeFlow, n)
	for i := range out {
		out[i] = models.TCPHandshakeFlow{State: state, FailureReason: reason, SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: uint16(1000 + i), DstPort: 443}
	}
	return out
}

const (
	reasonSynAck = "SYN-ACK timeout (no server response)"
	reasonRST    = "Connection reset (RST received)"
	reasonAck    = "ACK timeout (client did not complete handshake)"
)

func hsText(flows []models.TCPHandshakeFlow, legacy int) string {
	r := &models.TriageReport{TCPHandshakeFlows: flows}
	r.FailedHandshakes = make([]models.TCPFlow, legacy)
	var buf bytes.Buffer
	writeHandshakeSummary(&buf, r)
	return buf.String()
}

func TestHandshakeSummary_Zero(t *testing.T) {
	// No tracker flows at all, and no tracker failures among complete flows.
	for name, flows := range map[string][]models.TCPHandshakeFlow{
		"no flows":      nil,
		"only complete": hsFlows("Handshake Complete", "", 5),
	} {
		got := hsText(flows, 0)
		if got != "  • TCP Handshake Failures: 0\n" {
			t.Errorf("%s: got %q", name, got)
		}
	}
}

func TestHandshakeSummary_SynAckNotObserved(t *testing.T) {
	got := hsText(hsFlows("Handshake Failed", reasonSynAck, 14), 0)
	want := "  • TCP Handshake Failures: 14\n      14 SYN-ACK not observed in capture\n"
	if got != want {
		t.Errorf("got %q want %q", got, want)
	}
	for _, bad := range []string{"no server response", "unreachable", "did not respond", "unavailable"} {
		if strings.Contains(got, bad) {
			t.Errorf("unsupported claim %q in output", bad)
		}
	}
}

func TestHandshakeSummary_Reset(t *testing.T) {
	got := hsText(hsFlows("Handshake Failed", reasonRST, 4), 0)
	want := "  • TCP Handshake Failures: 4\n      4 reset observed\n"
	if got != want {
		t.Errorf("got %q want %q", got, want)
	}
}

func TestHandshakeSummary_FinalAckNotObserved(t *testing.T) {
	got := hsText(hsFlows("Handshake Failed", reasonAck, 3), 0)
	want := "  • TCP Handshake Failures: 3\n      3 final ACK not observed\n"
	if got != want {
		t.Errorf("got %q want %q", got, want)
	}
	// "SYN-ACK timeout" contains "ACK timeout": it must not be miscounted here.
	if strings.Contains(got, "SYN-ACK not observed") {
		t.Errorf("ACK timeout counted as SYN-ACK: %q", got)
	}
}

// cisco-example-lan's tracker breakdown: 94 / 4 / 3 failed, 85 incomplete.
func TestHandshakeSummary_MixedReasonsAndIncomplete(t *testing.T) {
	var flows []models.TCPHandshakeFlow
	flows = append(flows, hsFlows("Handshake Failed", reasonSynAck, 94)...)
	flows = append(flows, hsFlows("Handshake Failed", reasonRST, 4)...)
	flows = append(flows, hsFlows("Handshake Failed", reasonAck, 3)...)
	flows = append(flows, hsFlows("SYN", "", 84)...)
	flows = append(flows, hsFlows("SYN-ACK", "", 1)...)
	flows = append(flows, hsFlows("Handshake Complete", "", 1)...)
	got := hsText(flows, 2)
	want := "  • TCP Handshake Failures: 101\n" +
		"      94 SYN-ACK not observed in capture\n" +
		"      4 reset observed\n" +
		"      3 final ACK not observed\n" +
		"  • TCP Handshakes Incomplete at end of capture: 85\n"
	if got != want {
		t.Errorf("got:\n%s\nwant:\n%s", got, want)
	}
	// The legacy RST-only count must not appear as "Failed Handshakes: 2".
	if strings.Contains(got, "Failed Handshakes") {
		t.Errorf("old misleading label present: %q", got)
	}
}

// Incomplete flows are never failures.
func TestHandshakeSummary_IncompleteOnly(t *testing.T) {
	got := hsText(hsFlows("SYN", "", 17), 0)
	want := "  • TCP Handshake Failures: 0\n  • TCP Handshakes Incomplete at end of capture: 17\n"
	if got != want {
		t.Errorf("got %q want %q", got, want)
	}
}

func TestHandshakeSummary_FailedPlusIncomplete(t *testing.T) {
	flows := append(hsFlows("Handshake Failed", reasonSynAck, 14), hsFlows("SYN", "", 17)...)
	flows = append(flows, hsFlows("Handshake Complete", "", 31)...)
	got := hsText(flows, 0)
	want := "  • TCP Handshake Failures: 14\n      14 SYN-ACK not observed in capture\n  • TCP Handshakes Incomplete at end of capture: 17\n"
	if got != want {
		t.Errorf("got %q want %q", got, want)
	}
}

func TestHandshakeSummary_UnrecognisedReasonIsCountedNotDropped(t *testing.T) {
	got := hsText(hsFlows("Handshake Failed", "something else", 2), 0)
	if !strings.Contains(got, "TCP Handshake Failures: 2") || !strings.Contains(got, "2 other") {
		t.Errorf("got %q", got)
	}
}

// Without tracker data only the narrow RST-refusal count exists; it is labelled
// for what it is and never presented as "Failed Handshakes".
func TestHandshakeSummary_LegacyFallbackIsLabelledNarrowly(t *testing.T) {
	got := hsText(nil, 3)
	if got != "  • TCP Connections Reset During Setup: 3\n" {
		t.Errorf("got %q", got)
	}
}

// Wired into the real summary, and the line sits where the old one was.
func TestHandshakeSummary_WiredIntoFindingsSummary(t *testing.T) {
	r := &models.TriageReport{TCPHandshakeFlows: append(hsFlows("Handshake Failed", reasonSynAck, 3), hsFlows("SYN", "", 2)...)}
	out := summaryText(r)
	i := strings.Index(out, "TCP Handshake Failures: 3")
	j := strings.Index(out, "ARP Conflicts")
	if i < 0 || j < 0 || i > j {
		t.Errorf("handshake summary missing or misplaced:\n%s", out)
	}
	if strings.Contains(out, "Failed Handshakes") {
		t.Errorf("old label still present:\n%s", out)
	}
}
