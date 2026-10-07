package analyzer

import (
	"math"
	"sort"
	"testing"

	"github.com/gocisse/sdwan-triage/internal/testpcap"
	"github.com/gocisse/sdwan-triage/pkg/events"
	"github.com/gocisse/sdwan-triage/pkg/models"
)

// expectedBGPStormChains is the root_cause_chains output for the
// BGPWithdrawalStorm fixture after Phase 4.3.
//
// Pre-4.3 (commit d853bba baseline) the correlator reported two chains —
// "TCP Retransmission Spike" and "RTT Spike", both High confidence — worded as
// BGP route withdrawal having caused them. The fixture's BGP session is
// 10.0.0.2 <-> 192.168.1.100:179, while the retransmitting flow is
// 192.168.1.100:50003 -> 10.0.0.50:443: a different TCP session that merely
// shares one host IP with the BGP session. That, plus timing, does not establish
// causation, so the retransmission chain is now reported as time_proximity /
// Low confidence with no causal wording, and the RTT chain is gone (RTT spikes
// on non-session flows are not correlated; these particular spikes are
// dup-ACK/handshake artefacts of the fixture).
var expectedBGPStormChains = []models.RootCauseChain{
	{
		Timestamp:      1705320000,
		UnderlayEvent:  "BGP Withdrawal",
		UnderlayDetail: "Peer 10.0.0.2: BGP Withdrawal (withdrawn_len=4)",
		OverlayEffect:  "TCP Retransmission Burst (co-occurring)",
		OverlayDetail:  "5 retransmissions on 1 flow(s) (each with >=3) began 0.8s after BGP event; no shared flow or session identity was established, so no causal relationship is claimed",
		AffectedFlows:  []string{"192.168.1.100:50003->10.0.0.50:443 (5 retrans)"},
		CorrelationGap: 0.8,
		Confidence:     "Low",
		Severity:       "Medium",
		Recommendation: "A BGP Withdrawal event and TCP retransmissions were observed within 5s of each other, but the capture does not show that the affected flows share a session or path with it. Treat this as co-occurrence only. Check device logs and the path of the affected flows before attributing the TCP retransmissions to it.",
		EvidenceBasis:  models.EvidenceTimeProximity,
	},
}

func assertChainsEquivalent(t *testing.T, got, want []models.RootCauseChain) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("chain count = %d, want %d\n%+v", len(got), len(want), got)
	}
	for i := range want {
		g, w := got[i], want[i]
		if math.Abs(g.Timestamp-w.Timestamp) > 1e-6 {
			t.Errorf("chain %d Timestamp = %v, want %v", i, g.Timestamp, w.Timestamp)
		}
		if math.Abs(g.CorrelationGap-w.CorrelationGap) > 1e-6 {
			t.Errorf("chain %d CorrelationGap = %v, want %v", i, g.CorrelationGap, w.CorrelationGap)
		}
		for name, pair := range map[string][2]string{
			"UnderlayEvent":  {g.UnderlayEvent, w.UnderlayEvent},
			"UnderlayDetail": {g.UnderlayDetail, w.UnderlayDetail},
			"OverlayEffect":  {g.OverlayEffect, w.OverlayEffect},
			"OverlayDetail":  {g.OverlayDetail, w.OverlayDetail},
			"Confidence":     {g.Confidence, w.Confidence},
			"Severity":       {g.Severity, w.Severity},
			"Recommendation": {g.Recommendation, w.Recommendation},
			"EvidenceBasis":  {g.EvidenceBasis, w.EvidenceBasis},
		} {
			if pair[0] != pair[1] {
				t.Errorf("chain %d %s =\n  %q\nwant\n  %q", i, name, pair[0], pair[1])
			}
		}
		// The baseline built AffectedFlows by iterating a Go map (random order);
		// compare as sets.
		ga, wa := append([]string(nil), g.AffectedFlows...), append([]string(nil), w.AffectedFlows...)
		sort.Strings(ga)
		sort.Strings(wa)
		if len(ga) != len(wa) {
			t.Errorf("chain %d AffectedFlows = %v, want %v", i, g.AffectedFlows, w.AffectedFlows)
			continue
		}
		for j := range ga {
			if ga[j] != wa[j] {
				t.Errorf("chain %d AffectedFlows = %v, want %v", i, g.AffectedFlows, w.AffectedFlows)
				break
			}
		}
	}
}

// The structured inputs are unchanged; only what the correlator may claim from them changed.
func TestCorrelation_BGPWithdrawalStorm_Phase43Semantics(t *testing.T) {
	r := runGolden(t, testpcap.BGPWithdrawalStorm())
	assertChainsEquivalent(t, r.RootCauseChains, expectedBGPStormChains)

	// The structured inputs the correlator consumed are themselves on the index.
	if n := len(r.Events.ByKind(events.BGPEvent)); n != 1 {
		t.Errorf("bgp.event count = %d, want 1", n)
	}
	if n := len(r.Events.ByKind(events.TCPRetransmission)); n != 5 {
		t.Errorf("tcp.retransmission count = %d, want 5", n)
	}
	if n := len(r.Events.ByKind(events.TCPRTTSpike)); n == 0 {
		t.Errorf("expected tcp.rtt_spike events")
	}
	if r.EventCounts["bgp.event"] != 1 {
		t.Errorf("event_counts = %v", r.EventCounts)
	}
}

// Existing fixtures contain no BGP/BFD+retransmission relationship → no chains,
// exactly as before the migration (d853bba produced none for them).
func TestCorrelation_OtherFixturesProduceNoChains(t *testing.T) {
	for _, s := range testpcap.Scenarios() {
		if s.Name == "bgp_withdrawal_storm" {
			continue
		}
		r := runGolden(t, s.Generate())
		if len(r.RootCauseChains) != 0 {
			t.Errorf("%s: unexpected root cause chains: %+v", s.Name, r.RootCauseChains)
		}
	}
}

// bfd_tunnel_drop has a bfd.down but no retransmissions: the new trigger must
// not manufacture a correlation.
func TestCorrelation_BFDFixtureAloneHasNoChain(t *testing.T) {
	r := runGolden(t, testpcap.BFDTunnelDrop())
	if len(r.Events.ByKind(events.BFDDown)) != 1 {
		t.Fatal("fixture should emit one bfd.down")
	}
	if len(r.RootCauseChains) != 0 {
		t.Errorf("bfd.down without overlay effects produced chains: %+v", r.RootCauseChains)
	}
}

// BFD down followed by a retransmission burst within the window is reported as
// co-occurrence only: BFD carries no flow identity, so no causal claim is made.
func TestCorrelation_BFDDownThenRetransmissionStorm(t *testing.T) {
	pk := testpcap.BFDTunnelDrop()                     // bfd.down at packet 14 (t=1.4s)
	pk = append(pk, testpcap.RetransmissionStorm()...) // starts at t=1.5s; original sends from t=1.8s
	r := runGolden(t, pk)

	// Pre-4.3 the fixture's handshake/dup-ACK RTT spikes also produced an
	// "RTT Spike" chain; RTT spikes no longer correlate on time alone.
	if len(r.RootCauseChains) != 1 {
		t.Fatalf("expected exactly 1 chain, got %d: %+v", len(r.RootCauseChains), r.RootCauseChains)
	}
	c := r.RootCauseChains[0]
	if c.UnderlayEvent != "BFD Session Down" || c.OverlayEffect != "TCP Retransmission Burst (co-occurring)" {
		t.Errorf("unexpected chain: %+v", c)
	}
	if c.EvidenceBasis != models.EvidenceTimeProximity || c.Confidence != "Low" {
		t.Errorf("basis/confidence = %s/%s, want time_proximity/Low", c.EvidenceBasis, c.Confidence)
	}
	if c.UnderlayDetail != "BFD session 192.168.1.100 → 10.0.0.1 transitioned Up → Down" {
		t.Errorf("UnderlayDetail = %q", c.UnderlayDetail)
	}
	// first original send: storm packet 3 → absolute packet 15+3=18 → t=1.8s; BFD down t=1.4s
	if math.Abs(c.CorrelationGap-0.4) > 1e-6 {
		t.Errorf("CorrelationGap = %v, want 0.4", c.CorrelationGap)
	}
	if c.OverlayDetail != "5 retransmissions on 1 flow(s) (each with >=3) began 0.4s after BFD event; no shared flow or session identity was established, so no causal relationship is claimed" {
		t.Errorf("OverlayDetail = %q", c.OverlayDetail)
	}
	// Existing findings still present alongside the new chain.
	if len(r.StabilityFindings) != 1 || !hasTCPFlow(r.TCPRetransmissions, 50002, 443) {
		t.Errorf("existing BFD/retransmission findings changed: %+v / %+v", r.StabilityFindings, r.TCPRetransmissions)
	}
}
