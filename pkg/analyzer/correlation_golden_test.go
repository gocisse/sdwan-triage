package analyzer

import (
	"math"
	"sort"
	"testing"

	"github.com/gocisse/sdwan-triage/internal/testpcap"
	"github.com/gocisse/sdwan-triage/pkg/events"
	"github.com/gocisse/sdwan-triage/pkg/models"
)

// baselineBGPChains is the exact root_cause_chains output of the pre-Phase-3.2
// correlator (commit d853bba, callback-fed) on the BGPWithdrawalStorm fixture,
// captured before the migration. The event-driven correlator must reproduce it.
var baselineBGPChains = []models.RootCauseChain{
	{
		Timestamp:      1705320000,
		UnderlayEvent:  "BGP Withdrawal",
		UnderlayDetail: "Peer 10.0.0.2: BGP Withdrawal (withdrawn_len=4)",
		OverlayEffect:  "TCP Retransmission Spike",
		OverlayDetail:  "5 retransmissions across 1 flows within 0.8s of BGP event",
		AffectedFlows:  []string{"192.168.1.100:50003->10.0.0.50:443 (5 retrans)"},
		CorrelationGap: 0.8,
		Confidence:     "High",
		Severity:       "Medium",
		Recommendation: "BGP route withdrawal caused retransmissions in 1 overlay flows. Check underlay link health and BGP peer stability. Verify SD-WAN failover policies are configured for fast convergence (<1s). Consider BFD for sub-second failure detection on underlay links.",
	},
	{
		Timestamp:      1705320000,
		UnderlayEvent:  "BGP Withdrawal",
		UnderlayDetail: "Peer 10.0.0.2: BGP Withdrawal (withdrawn_len=4)",
		OverlayEffect:  "RTT Spike",
		OverlayDetail:  "RTT peaked at 2000ms across 2 flows within 0.6s of BGP event",
		AffectedFlows:  []string{"192.168.1.100:50003->10.0.0.50:443 (600ms)", "10.0.0.50:443->192.168.1.100:50003 (2000ms)"},
		CorrelationGap: 0.6,
		Confidence:     "High",
		Severity:       "Critical",
		Recommendation: "BGP route withdrawal caused RTT spikes in 2 overlay flows. Check underlay link health and BGP peer stability. Verify SD-WAN failover policies are configured for fast convergence (<1s). Consider BFD for sub-second failure detection on underlay links.",
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

// Equivalence: EventIndex-driven correlation == pre-3.2 callback-driven output.
func TestCorrelation_BGPWithdrawalStorm_MatchesPre32Baseline(t *testing.T) {
	r := runGolden(t, testpcap.BGPWithdrawalStorm())
	assertChainsEquivalent(t, r.RootCauseChains, baselineBGPChains)

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

// BFD down followed by a retransmission burst within the window correlates
// through the same mechanism as BGP (composed from existing fixtures).
func TestCorrelation_BFDDownThenRetransmissionStorm(t *testing.T) {
	pk := testpcap.BFDTunnelDrop()                     // bfd.down at packet 14 (t=1.4s)
	pk = append(pk, testpcap.RetransmissionStorm()...) // starts at t=1.5s; original sends from t=1.8s
	r := runGolden(t, pk)

	// The existing mechanism evaluates both overlay effects per trigger; the
	// storm fixture's 200 ms handshake RTT also yields an RTT-spike chain, so
	// select the retransmission chain explicitly.
	var bfdChains []models.RootCauseChain
	for _, c := range r.RootCauseChains {
		if c.UnderlayEvent == "BFD Session Down" && c.OverlayEffect == "TCP Retransmission Spike" {
			bfdChains = append(bfdChains, c)
		}
	}
	if len(bfdChains) != 1 {
		t.Fatalf("expected 1 BFD retransmission chain, got %d: %+v", len(bfdChains), r.RootCauseChains)
	}
	c := bfdChains[0]
	for _, ch := range r.RootCauseChains {
		if ch.UnderlayEvent != "BFD Session Down" {
			t.Errorf("unexpected non-BFD chain: %+v", ch)
		}
	}
	if c.UnderlayDetail != "BFD session 192.168.1.100 → 10.0.0.1 transitioned Up → Down" {
		t.Errorf("UnderlayDetail = %q", c.UnderlayDetail)
	}
	// first original send: storm packet 3 → absolute packet 15+3=18 → t=1.8s; BFD down t=1.4s
	if math.Abs(c.CorrelationGap-0.4) > 1e-6 {
		t.Errorf("CorrelationGap = %v, want 0.4", c.CorrelationGap)
	}
	if c.OverlayDetail != "5 retransmissions across 1 flows within 0.4s of BFD event" {
		t.Errorf("OverlayDetail = %q", c.OverlayDetail)
	}
	// Existing findings still present alongside the new chain.
	if len(r.StabilityFindings) != 1 || !hasTCPFlow(r.TCPRetransmissions, 50002, 443) {
		t.Errorf("existing BFD/retransmission findings changed: %+v / %+v", r.StabilityFindings, r.TCPRetransmissions)
	}
}
