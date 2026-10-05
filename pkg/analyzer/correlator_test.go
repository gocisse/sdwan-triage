package analyzer

import (
	"reflect"
	"testing"
	"time"

	"github.com/gocisse/sdwan-triage/pkg/events"
	"github.com/gocisse/sdwan-triage/pkg/models"
)

// Test harness: feed structured events into a report's index exactly as the
// detectors do, then run the correlator. Replaces the pre-Phase-3.2
// RecordBGPEvent/RecordRetransmission/RecordRTTSpike callback API.
type corrHarness struct {
	report *models.TriageReport
	rec    *events.Recorder
}

func newCorrHarness() *corrHarness {
	ix := events.NewIndex(0)
	return &corrHarness{report: &models.TriageReport{Events: ix}, rec: events.NewRecorder(ix, "")}
}

func (h *corrHarness) bgp(ts time.Time, peer, dst, eventType, detail string) {
	h.rec.Emit(events.Event{Kind: events.BGPEvent, Timestamp: ts, Source: "BGP",
		Attrs: map[string]string{"peer_ip": peer, "dst_ip": dst, "event_type": eventType, "detail": detail}})
}

func (h *corrHarness) bfdDown(ts time.Time, src, peer string) {
	h.rec.Emit(events.Event{Kind: events.BFDDown, Timestamp: ts, Source: "Stability",
		Values: map[string]float64{"prev_state": 3, "new_state": 1},
		Attrs:  map[string]string{"src_ip": src, "peer_ip": peer, "new_state_name": "Down"}})
}

// retrans emits a tcp.retransmission whose ORIGINAL transmission was at origTS
// (the correlator keys on first-send time, as it always did).
func (h *corrHarness) retrans(origTS time.Time, flowKey string) {
	h.rec.Emit(events.Event{Kind: events.TCPRetransmission, Timestamp: origTS.Add(200 * time.Millisecond), FlowKey: flowKey, Source: "TCP",
		Values: map[string]float64{"seq": 1, "payload_len": 100, "since_original_ms": 200, "original_ts_us": float64(origTS.UnixMicro())}})
}

func (h *corrHarness) rtt(ts time.Time, flowKey string, ms float64) {
	h.rec.Emit(events.Event{Kind: events.TCPRTTSpike, Timestamp: ts, FlowKey: flowKey, Source: "TCP",
		Values: map[string]float64{"rtt_ms": ms}})
}

func (h *corrHarness) run() []models.RootCauseChain {
	NewUnderlayOverlayCorrelator().Finalize(h.report)
	return h.report.RootCauseChains
}

var corrBase = time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC)

// ─── Existing BGP behaviour (assertions unchanged from pre-3.2 tests) ────

func TestCorrelator_BGPWithdrawalRetransmissionSpike(t *testing.T) {
	h := newCorrHarness()
	h.bgp(corrBase, "10.0.0.1", "192.168.0.0/16", "Withdrawal", "Peer 10.0.0.1: BGP Withdrawal (withdrawn_len=4)")
	for i := 0; i < 8; i++ {
		h.retrans(corrBase.Add(time.Duration(i*500)*time.Millisecond), "10.1.1.1:443->10.2.2.2:50000")
	}
	chains := h.run()

	if len(chains) == 0 {
		t.Fatal("expected at least one RootCauseChain entry")
	}
	chain := chains[0]
	if chain.UnderlayEvent != "BGP Withdrawal" {
		t.Errorf("UnderlayEvent = %q, want %q", chain.UnderlayEvent, "BGP Withdrawal")
	}
	if chain.UnderlayDetail != "Peer 10.0.0.1: BGP Withdrawal (withdrawn_len=4)" {
		t.Errorf("UnderlayDetail = %q", chain.UnderlayDetail)
	}
	if chain.OverlayEffect != "TCP Retransmission Spike" {
		t.Errorf("OverlayEffect = %q, want %q", chain.OverlayEffect, "TCP Retransmission Spike")
	}
	if chain.CorrelationGap < 0 || chain.CorrelationGap > 5.0 {
		t.Errorf("CorrelationGap = %.2f, want between 0 and 5", chain.CorrelationGap)
	}
	if chain.Recommendation == "" {
		t.Error("expected non-empty Recommendation")
	}
}

func TestCorrelator_BGPNotificationRTTSpike(t *testing.T) {
	h := newCorrHarness()
	h.bgp(corrBase, "10.0.0.1", "10.0.0.2", "Notification", "BGP NOTIFICATION: Error 6/4 from 10.0.0.1")
	h.rtt(corrBase.Add(1*time.Second), "10.1.1.1:80->10.2.2.2:50000", 350.0)
	h.rtt(corrBase.Add(2*time.Second), "10.1.1.1:80->10.2.2.2:50001", 500.0)
	chains := h.run()

	if len(chains) == 0 {
		t.Fatal("expected at least one RootCauseChain entry for RTT spike")
	}
	chain := chains[0]
	if chain.OverlayEffect != "RTT Spike" {
		t.Errorf("OverlayEffect = %q, want %q", chain.OverlayEffect, "RTT Spike")
	}
	if chain.Severity != "High" && chain.Severity != "Critical" {
		t.Errorf("Severity = %q, want High or Critical for 500ms RTT", chain.Severity)
	}
}

func TestCorrelator_NoCorrelationOutsideWindow(t *testing.T) {
	h := newCorrHarness()
	h.bgp(corrBase, "10.0.0.1", "192.168.0.0/16", "Withdrawal", "test")
	for i := 0; i < 10; i++ {
		h.retrans(corrBase.Add(10*time.Second+time.Duration(i*100)*time.Millisecond), "flow1")
	}
	if chains := h.run(); len(chains) != 0 {
		t.Errorf("expected 0 RootCauseChains for events outside window, got %d", len(chains))
	}
}

func TestCorrelator_NoUnderlayEvents(t *testing.T) {
	h := newCorrHarness()
	h.retrans(corrBase, "flow1")
	h.rtt(corrBase, "flow1", 500.0)
	if chains := h.run(); len(chains) != 0 {
		t.Errorf("expected 0 RootCauseChains without BGP/BFD events, got %d", len(chains))
	}
}

func TestCorrelator_BelowRetransmitThreshold(t *testing.T) {
	h := newCorrHarness()
	h.bgp(corrBase, "10.0.0.1", "192.168.0.0/16", "Update", "test")
	h.retrans(corrBase.Add(1*time.Second), "flow1")
	h.retrans(corrBase.Add(2*time.Second), "flow1")
	for _, chain := range h.run() {
		if chain.OverlayEffect == "TCP Retransmission Spike" {
			t.Error("should not produce retransmission chain below threshold")
		}
	}
}

func TestCorrelator_NoEventIndexIsNoop(t *testing.T) {
	report := &models.TriageReport{}
	NewUnderlayOverlayCorrelator().Finalize(report)
	if len(report.RootCauseChains) != 0 {
		t.Error("report without an event index must not produce chains")
	}
}

// ─── BFD as second underlay trigger ─────────────────────────────────────

func TestCorrelator_BFDDownWithRetransmissions(t *testing.T) {
	h := newCorrHarness()
	h.bfdDown(corrBase, "10.0.0.1", "10.0.0.2")
	for i := 0; i < 3; i++ { // exactly the existing minRetransmits
		h.retrans(corrBase.Add(time.Duration(500+i*500)*time.Millisecond), "10.1.1.1:443->10.2.2.2:50000")
	}
	chains := h.run()

	if len(chains) != 1 {
		t.Fatalf("expected exactly 1 chain, got %d: %+v", len(chains), chains)
	}
	c := chains[0]
	if c.UnderlayEvent != "BFD Session Down" || c.OverlayEffect != "TCP Retransmission Spike" {
		t.Errorf("unexpected chain %q / %q", c.UnderlayEvent, c.OverlayEffect)
	}
	if c.UnderlayDetail != "BFD session 10.0.0.1 → 10.0.0.2 transitioned Up → Down" {
		t.Errorf("UnderlayDetail = %q", c.UnderlayDetail)
	}
	if c.CorrelationGap != 0.5 {
		t.Errorf("CorrelationGap = %v, want 0.5", c.CorrelationGap)
	}
	// Same confidence/severity functions as BGP: 3 events, gap 0.5s → Medium / Low.
	if c.Confidence != "Medium" || c.Severity != "Low" {
		t.Errorf("confidence/severity = %s/%s, want Medium/Low", c.Confidence, c.Severity)
	}
	if len(c.AffectedFlows) != 1 || c.AffectedFlows[0] != "10.1.1.1:443->10.2.2.2:50000 (3 retrans)" {
		t.Errorf("AffectedFlows = %v", c.AffectedFlows)
	}
	if c.Recommendation == "" || !contains(c.Recommendation, "BFD") {
		t.Errorf("Recommendation = %q", c.Recommendation)
	}
}

func TestCorrelator_BFDDownWithoutRetransmissions(t *testing.T) {
	h := newCorrHarness()
	h.bfdDown(corrBase, "10.0.0.1", "10.0.0.2")
	h.retrans(corrBase.Add(1*time.Second), "flow1")
	h.retrans(corrBase.Add(2*time.Second), "flow1") // 2 < minRetransmits
	if chains := h.run(); len(chains) != 0 {
		t.Errorf("expected no BFD correlation below threshold, got %+v", chains)
	}
}

func TestCorrelator_RetransmissionsWithoutBFD(t *testing.T) {
	h := newCorrHarness()
	for i := 0; i < 10; i++ {
		h.retrans(corrBase.Add(time.Duration(i*100)*time.Millisecond), "flow1")
	}
	if chains := h.run(); len(chains) != 0 {
		t.Errorf("retransmissions alone must not correlate, got %+v", chains)
	}
}

// Window is [underlay, underlay+5s] inclusive, judged on the retransmission's
// ORIGINAL transmission time (existing semantics).
func TestCorrelator_BFDWindowBoundaries(t *testing.T) {
	cases := []struct {
		name   string
		offset time.Duration
		want   int
	}{
		{"just inside (5s)", 5 * time.Second, 1},
		{"just outside (5s+1µs)", 5*time.Second + time.Microsecond, 0},
		{"at trigger (0s)", 0, 1},
		{"before trigger (-1µs)", -time.Microsecond, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newCorrHarness()
			h.bfdDown(corrBase, "10.0.0.1", "10.0.0.2")
			for i := 0; i < 3; i++ {
				h.retrans(corrBase.Add(tc.offset), "flow1")
			}
			if got := len(h.run()); got != tc.want {
				t.Errorf("chains = %d, want %d", got, tc.want)
			}
		})
	}
}

func TestCorrelator_Deterministic(t *testing.T) {
	build := func() []models.RootCauseChain {
		h := newCorrHarness()
		h.bgp(corrBase, "10.0.0.1", "10.0.0.2", "Withdrawal", "w")
		h.bfdDown(corrBase.Add(2*time.Second), "10.0.0.1", "10.0.0.2")
		for i := 0; i < 6; i++ {
			h.retrans(corrBase.Add(time.Duration(2500+i*300)*time.Millisecond), []string{"flowA", "flowB"}[i%2])
			h.rtt(corrBase.Add(time.Duration(2600+i*300)*time.Millisecond), []string{"flowA", "flowB"}[i%2], 250+float64(i)*100)
		}
		return h.run()
	}
	a, b := build(), build()
	if !reflect.DeepEqual(a, b) {
		t.Errorf("correlation output differs between identical runs\n%+v\n%+v", a, b)
	}
	if len(a) != 4 { // BGP×(retrans,rtt) + BFD×(retrans,rtt)
		t.Errorf("expected 4 chains (2 triggers × 2 effects), got %d", len(a))
	}
}

func contains(s, sub string) bool {
	return len(sub) == 0 || (len(s) >= len(sub) && indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
