package output

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/fatih/color"
	"github.com/gocisse/sdwan-triage/pkg/models"
)

// Phase 4.8: the executive summary must label units honestly. TCPRetransmissions
// is one entry per DISTINCT FLOW; tcp.retransmission events are per segment.

func flows(n int) []models.TCPFlow {
	out := make([]models.TCPFlow, n)
	for i := range out {
		out[i] = models.TCPFlow{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: uint16(1000 + i), DstPort: 443}
	}
	return out
}

func summaryText(r *models.TriageReport) string {
	var buf bytes.Buffer
	writeFindingsSummary(&buf, r)
	return buf.String()
}

func TestSummary_FlowLabelNotSegmentCount(t *testing.T) {
	out := summaryText(&models.TriageReport{TCPRetransmissions: flows(3)})
	if !strings.Contains(out, "• TCP Retransmission Flows: 3\n") {
		t.Errorf("missing flow-based label:\n%s", out)
	}
	if strings.Contains(out, "TCP Retransmissions:") {
		t.Errorf("old unit-less label still present:\n%s", out)
	}
}

func TestSummary_EventCountShownSeparately(t *testing.T) {
	r := &models.TriageReport{TCPRetransmissions: flows(1), EventCounts: map[string]int{"tcp.retransmission": 5}}
	out := summaryText(r)
	if !strings.Contains(out, "• TCP Retransmission Flows: 1\n") || !strings.Contains(out, "• TCP Retransmission Events: 5\n") {
		t.Errorf("flow count 1 and event count 5 must both appear:\n%s", out)
	}
}

// 9 events across 9 flows: equal numbers, both units present and unambiguous.
func TestSummary_NineEventsNineFlows(t *testing.T) {
	r := &models.TriageReport{TCPRetransmissions: flows(9), EventCounts: map[string]int{"tcp.retransmission": 9}}
	out := summaryText(r)
	for _, want := range []string{"TCP Retransmission Flows: 9\n", "TCP Retransmission Events: 9\n"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q:\n%s", want, out)
		}
	}
}

// Many events on one flow: flow count 1, event count 40 — the units differ.
func TestSummary_ManyEventsOneFlow(t *testing.T) {
	r := &models.TriageReport{TCPRetransmissions: flows(1), EventCounts: map[string]int{"tcp.retransmission": 40}}
	out := summaryText(r)
	if !strings.Contains(out, "Flows: 1\n") || !strings.Contains(out, "Events: 40\n") {
		t.Errorf("flow/event units not distinguishable:\n%s", out)
	}
}

func TestSummary_NoRetransmissionEventsNoEventLine(t *testing.T) {
	cases := map[string]*models.TriageReport{
		"empty report":             {},
		"other event kind only":    {EventCounts: map[string]int{"dns.anomaly": 7, "tunnel.observed": 2}},
		"zero retransmission kind": {EventCounts: map[string]int{"tcp.retransmission": 0}},
		"dropped but none counted": {EventCounts: map[string]int{"dns.anomaly": 1}, EventsDropped: 50},
	}
	for name, r := range cases {
		t.Run(name, func(t *testing.T) {
			out := summaryText(r)
			if strings.Contains(out, "Retransmission Events") || strings.Contains(out, "lower bounds") {
				t.Errorf("unexpected event line or note:\n%s", out)
			}
		})
	}
}

func TestSummary_OverflowDisclosed(t *testing.T) {
	r := &models.TriageReport{
		TCPRetransmissions: flows(2),
		EventCounts:        map[string]int{"tcp.retransmission": 700},
		EventsDropped:      1234,
	}
	out := summaryText(r)
	if !strings.Contains(out, "• TCP Retransmission Events: ≥700\n") {
		t.Errorf("lower-bound marker missing:\n%s", out)
	}
	if !strings.Contains(out, "Note: event-derived counts are lower bounds; the event index dropped 1234 events.\n") {
		t.Errorf("overflow note missing:\n%s", out)
	}
	if again := summaryText(r); again != out {
		t.Error("output not deterministic")
	}
}

func TestSummary_NoOverflowNoNote(t *testing.T) {
	r := &models.TriageReport{EventCounts: map[string]int{"tcp.retransmission": 5}}
	out := summaryText(r)
	if strings.Contains(out, "≥") || strings.Contains(out, "lower bounds") {
		t.Errorf("unexpected overflow text:\n%s", out)
	}
}

// Other summary lines are untouched.
func TestSummary_OtherLinesUnchanged(t *testing.T) {
	out := summaryText(&models.TriageReport{DNSAnomalies: make([]models.DNSAnomaly, 2)})
	for _, want := range []string{"  • DNS Anomalies:        2\n", "  • TCP Handshake Failures: 0\n", "  • ARP Conflicts:        0\n", "  • High RTT Flows:       0\n"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q", want)
		}
	}
}

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stdout
	rd, wr, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = wr
	// fatih/color binds its writer at init; redirect it too (and drop ANSI codes).
	oldColorOut, oldNoColor := color.Output, color.NoColor
	color.Output, color.NoColor = wr, true
	done := make(chan string)
	go func() { b, _ := io.ReadAll(rd); done <- string(b) }()
	fn()
	wr.Close()
	os.Stdout = old
	color.Output, color.NoColor = oldColorOut, oldNoColor
	return <-done
}

// Wiring: the real executive summary prints the new block, followed by the
// traffic summary after a blank line.
func TestSummary_WiredIntoExecutiveSummary(t *testing.T) {
	r := &models.TriageReport{TCPRetransmissions: flows(2), EventCounts: map[string]int{"tcp.retransmission": 6}}
	out := captureStdout(t, func() { PrintExecutiveSummary(r) })
	if !strings.Contains(out, "TCP Retransmission Flows: 2\n") || !strings.Contains(out, "TCP Retransmission Events: 6\n") {
		t.Errorf("summary not wired:\n%s", out)
	}
	if !strings.Contains(out, "Devices Detected:     0\n\nTRAFFIC SUMMARY:") {
		t.Errorf("blank line between summary blocks lost:\n%s", out)
	}
}

// -simple is unchanged by Phase 4.8: it never uses the new labels.
func TestSimpleReport_UnchangedByCountLabels(t *testing.T) {
	r := &models.TriageReport{TCPRetransmissions: flows(3), EventCounts: map[string]int{"tcp.retransmission": 9}, EventsDropped: 5}
	out := captureStdout(t, func() { GenerateSimpleReport(r, "x.pcap") })
	for _, bad := range []string{"Retransmission Flows", "Retransmission Events", "lower bounds"} {
		if strings.Contains(out, bad) {
			t.Errorf("-simple output gained %q", bad)
		}
	}
	if !strings.Contains(out, "3 minor connection issues") {
		t.Errorf("-simple retransmission wording changed:\n%s", out)
	}
}

// JSON keeps its legacy field names; the labels are display-only.
func TestJSON_LegacyRetransmissionFieldUnchanged(t *testing.T) {
	r := &models.TriageReport{TCPRetransmissions: flows(2), EventCounts: map[string]int{"tcp.retransmission": 6}}
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	if !strings.Contains(s, `"tcp_retransmissions":[`) || !strings.Contains(s, `"event_counts":{"tcp.retransmission":6}`) {
		t.Errorf("legacy JSON fields changed: %s", s)
	}
	if strings.Contains(s, "retransmission_flows") || strings.Contains(s, "retransmission_events") {
		t.Errorf("display labels leaked into JSON: %s", s)
	}
}
