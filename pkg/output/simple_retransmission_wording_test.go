package output

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/gocisse/sdwan-triage/pkg/models"
)

// Phase 4.45: PacketLoss.PacketsLost / LossPercentage count observed TCP
// retransmissions. -simple must describe them as retransmissions observed, never
// as confirmed loss of data or packets.

func TestSimple_RetransmissionsAreNotPresentedAsConfirmedLoss(t *testing.T) {
	for name, pct := range map[string]float64{"high": 8.0, "moderate": 3.0} {
		r := &models.TriageReport{TCPRetransmissions: flows(3), PacketLoss: &models.PacketLossMetrics{
			TotalPacketsSent: 1000, PacketsLost: uint64(pct * 10), LossPercentage: pct, RetransmissionRate: pct,
		}}
		out := captureStdout(t, func() { GenerateSimpleReport(r, "x.pcap") })
		low := strings.ToLower(out)
		for _, bad := range []string{"being lost", "packet loss detected", "data loss", "isn't reaching its destination", "minor data loss"} {
			if strings.Contains(low, bad) {
				t.Errorf("%s: -simple still claims confirmed loss (%q):\n%s", name, bad, out)
			}
		}
		if !strings.Contains(out, "TCP retransmissions observed") {
			t.Errorf("%s: -simple must say retransmissions were observed:\n%s", name, out)
		}
		if !strings.Contains(out, "of captured packets") {
			t.Errorf("%s: percentage must state its denominator:\n%s", name, out)
		}
		if !strings.Contains(low, "not determined") && !strings.Contains(low, "does not show") {
			t.Errorf("%s: cause/loss must be stated as undetermined:\n%s", name, out)
		}
	}
}

func TestSimple_RetransmissionWordingCountsAndUnrelatedLinesStable(t *testing.T) {
	r := &models.TriageReport{TCPRetransmissions: flows(3), PacketLoss: &models.PacketLossMetrics{
		TotalPacketsSent: 100, PacketsLost: 8, LossPercentage: 8, RetransmissionRate: 8,
	}}
	out := captureStdout(t, func() { GenerateSimpleReport(r, "x.pcap") })
	if !strings.Contains(out, "TCP retransmissions observed: 8 (8.0% of captured packets)") {
		t.Errorf("count/percentage line missing:\n%s", out)
	}
	if !strings.Contains(out, "3 minor connection issues") {
		t.Errorf("unrelated retransmission-flow line changed:\n%s", out)
	}
	// Recommended-action gating on the same metric is unchanged.
	if !strings.Contains(out, "Check network cables and connections for damage") {
		t.Errorf("recommended action gating changed:\n%s", out)
	}
}

func TestSimple_NoRetransmissionsNoLine(t *testing.T) {
	r := &models.TriageReport{TCPRetransmissions: flows(3), PacketLoss: &models.PacketLossMetrics{TotalPacketsSent: 100}}
	out := captureStdout(t, func() { GenerateSimpleReport(r, "x.pcap") })
	if strings.Contains(out, "TCP retransmissions observed") {
		t.Errorf("line printed with zero retransmissions:\n%s", out)
	}
}

func TestJSON_LegacyPacketLossFieldNamesRetained(t *testing.T) {
	b, err := json.Marshal(&models.TriageReport{PacketLoss: &models.PacketLossMetrics{PacketsLost: 2, LossPercentage: 1.5, RetransmissionRate: 1.5}})
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{`"packets_lost":2`, `"loss_percentage":1.5`, `"retransmission_rate":1.5`} {
		if !strings.Contains(string(b), key) {
			t.Errorf("legacy JSON field missing %s: %s", key, b)
		}
	}
}
