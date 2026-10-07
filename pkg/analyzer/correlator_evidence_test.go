package analyzer

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/gocisse/sdwan-triage/internal/testpcap"
	"github.com/gocisse/sdwan-triage/pkg/events"
	"github.com/gocisse/sdwan-triage/pkg/models"
)

// Phase 4.3 regression tests: the correlator must not turn time proximity into a
// causal claim. See the UnderlayOverlayCorrelator doc comment for the rules.

const (
	unrelatedFlowA = "10.1.1.1:443->10.2.2.2:50000"
	unrelatedFlowB = "10.1.1.1:443->10.2.2.2:50001"
	unrelatedFlowC = "10.1.1.1:443->10.2.2.2:50002"
	bgpSessionFlow = "10.0.0.2:40000->10.0.0.1:179" // BGP session 10.0.0.1 <-> 10.0.0.2
)

func assertNoCausalWording(t *testing.T, c models.RootCauseChain) {
	t.Helper()
	for _, field := range []string{c.OverlayDetail, c.Recommendation, c.OverlayEffect, c.UnderlayDetail} {
		low := strings.ToLower(field)
		for _, bad := range []string{"caused", "triggered", "root cause"} {
			if strings.Contains(low, bad) {
				t.Errorf("causal wording %q in %q", bad, field)
			}
		}
	}
}

// Negative 1: one unrelated flow retransmits near a BGP withdrawal. A single
// retransmission (or two) is not a burst: no chain at all.
func TestEvidence_UnrelatedSingleRetransmissionNoChain(t *testing.T) {
	h := newCorrHarness()
	h.bgp(corrBase, "10.0.0.1", "10.0.0.2", "Withdrawal", "w")
	h.retrans(corrBase.Add(time.Second), unrelatedFlowA)
	h.retrans(corrBase.Add(2*time.Second), unrelatedFlowA)
	if chains := h.run(); len(chains) != 0 {
		t.Errorf("expected no chain, got %+v", chains)
	}
}

// Negative 1b: an unrelated flow with a genuine burst is reported only as
// co-occurrence — Low confidence, explicit basis, no causal wording.
func TestEvidence_UnrelatedBurstIsCoOccurrenceOnly(t *testing.T) {
	h := newCorrHarness()
	h.bgp(corrBase, "10.0.0.1", "10.0.0.2", "Withdrawal", "w")
	for i := 0; i < 4; i++ {
		h.retrans(corrBase.Add(time.Duration(i+1)*time.Second), unrelatedFlowA)
	}
	chains := h.run()
	if len(chains) != 1 {
		t.Fatalf("expected 1 chain, got %+v", chains)
	}
	c := chains[0]
	if c.EvidenceBasis != models.EvidenceTimeProximity || c.Confidence != "Low" {
		t.Errorf("basis/confidence = %s/%s", c.EvidenceBasis, c.Confidence)
	}
	assertNoCausalWording(t, c)
}

// Negative 2: three unrelated flows each retransmit once near a BFD down. They
// must not be pooled into one chain (pre-4.3: 3 events >= minRetransmits).
func TestEvidence_ThreeUnrelatedFlowsNotPooled(t *testing.T) {
	h := newCorrHarness()
	h.bfdDown(corrBase, "10.0.0.1", "10.0.0.2")
	h.retrans(corrBase.Add(time.Second), unrelatedFlowA)
	h.retrans(corrBase.Add(2*time.Second), unrelatedFlowB)
	h.retrans(corrBase.Add(3*time.Second), unrelatedFlowC)
	if chains := h.run(); len(chains) != 0 {
		t.Errorf("unrelated single retransmissions must not be pooled, got %+v", chains)
	}
}

// Negative 3: RTT spikes. A routine BGP UPDATE is not a trigger, and even a
// withdrawal does not correlate with RTT spikes on an unrelated (merely slow) flow.
func TestEvidence_NormalHighRTTNearRoutineBGP(t *testing.T) {
	h := newCorrHarness()
	h.bgp(corrBase, "10.0.0.1", "10.0.0.2", "Update", "routine")
	h.bgp(corrBase.Add(time.Second), "10.0.0.1", "10.0.0.2", "Withdrawal", "w")
	for i := 0; i < 5; i++ {
		h.rtt(corrBase.Add(time.Duration(i)*time.Second), unrelatedFlowA, 250)
	}
	if chains := h.run(); len(chains) != 0 {
		t.Errorf("expected no chain, got %+v", chains)
	}
}

// A routine UPDATE alone never triggers, however many retransmissions follow.
func TestEvidence_RoutineBGPUpdateIsNotATrigger(t *testing.T) {
	h := newCorrHarness()
	h.bgp(corrBase, "10.0.0.1", "10.0.0.2", "Update", "routine")
	for i := 0; i < 10; i++ {
		h.retrans(corrBase.Add(time.Duration(i*100)*time.Millisecond), unrelatedFlowA)
	}
	if chains := h.run(); len(chains) != 0 {
		t.Errorf("routine UPDATE produced chains: %+v", chains)
	}
}

// Negative 4: a storm of triggers yields one chain per effect, not one per trigger.
func TestEvidence_TriggerStormCoalesces(t *testing.T) {
	build := func() *corrHarness {
		h := newCorrHarness()
		for i := 0; i < 50; i++ {
			h.bgp(corrBase.Add(time.Duration(i)*100*time.Millisecond), "10.0.0.1", "10.0.0.2", "Withdrawal", "w")
		}
		for i := 0; i < 5; i++ {
			h.retrans(corrBase.Add(time.Duration(1000+i*100)*time.Millisecond), unrelatedFlowA)
		}
		return h
	}
	chains := build().run()
	if len(chains) != 1 {
		t.Fatalf("storm of 50 withdrawals produced %d chains, want 1: %+v", len(chains), chains)
	}
	if !strings.Contains(chains[0].UnderlayDetail, "+49 more BGP Withdrawal events") {
		t.Errorf("UnderlayDetail does not note the coalesced triggers: %q", chains[0].UnderlayDetail)
	}
	// Deterministic across repeated runs.
	for i := 0; i < 20; i++ {
		if again := build().run(); !reflect.DeepEqual(chains, again) {
			t.Fatalf("run %d differs:\n%+v\n%+v", i, chains, again)
		}
	}
}

// Triggers separated by more than the window are distinct episodes; different
// labels never merge.
func TestEvidence_EpisodeBoundaries(t *testing.T) {
	c := NewUnderlayOverlayCorrelator()
	ue := func(off time.Duration, label string) underlayEvent {
		return underlayEvent{Timestamp: corrBase.Add(off), Label: label, Protocol: "BGP"}
	}
	eps := c.buildEpisodes([]underlayEvent{
		ue(0, "BGP Withdrawal"), ue(4*time.Second, "BGP Withdrawal"), // chained: 4s <= 5s
		ue(9*time.Second, "BGP Withdrawal"),  // chained to the 4s trigger
		ue(20*time.Second, "BGP Withdrawal"), // new episode
		ue(time.Second, "BGP Notification"),  // different label
	})
	if len(eps) != 3 {
		t.Fatalf("episodes = %d, want 3", len(eps))
	}
	if eps[0].label != "BGP Withdrawal" || eps[0].count != 3 || eps[1].label != "BGP Notification" || eps[2].count != 1 {
		t.Errorf("unexpected episodes: %+v %+v %+v", eps[0], eps[1], eps[2])
	}
}

// Positive: retransmissions on the BGP session's own TCP connection share
// session identity with the BGP event, in either direction.
func TestEvidence_SameSessionIsStrongerBasis(t *testing.T) {
	for _, flow := range []string{bgpSessionFlow, "10.0.0.1:179->10.0.0.2:40000"} {
		h := newCorrHarness()
		h.bgp(corrBase, "10.0.0.1", "10.0.0.2", "Notification", "BGP NOTIFICATION")
		for i := 0; i < 5; i++ {
			h.retrans(corrBase.Add(time.Duration(i*100)*time.Millisecond), flow)
		}
		chains := h.run()
		if len(chains) != 1 {
			t.Fatalf("%s: expected 1 chain, got %+v", flow, chains)
		}
		c := chains[0]
		if c.EvidenceBasis != models.EvidenceSameSession || c.OverlayEffect != "TCP Retransmission Spike" || c.Confidence != "High" {
			t.Errorf("%s: unexpected chain %+v", flow, c)
		}
		assertNoCausalWording(t, c)
	}
}

// A session flow and an unrelated flow in the same window are reported
// separately, same_session first; the unrelated flow is never merged into the
// stronger chain.
func TestEvidence_SessionAndUnrelatedFlowsSeparated(t *testing.T) {
	h := newCorrHarness()
	h.bgp(corrBase, "10.0.0.1", "10.0.0.2", "Withdrawal", "w")
	for i := 0; i < 3; i++ {
		h.retrans(corrBase.Add(time.Duration(i*100)*time.Millisecond), bgpSessionFlow)
		h.retrans(corrBase.Add(time.Duration(i*100)*time.Millisecond), unrelatedFlowA)
	}
	chains := h.run()
	if len(chains) != 2 || chains[0].EvidenceBasis != models.EvidenceSameSession || chains[1].EvidenceBasis != models.EvidenceTimeProximity {
		t.Fatalf("unexpected chains %+v", chains)
	}
	if len(chains[0].AffectedFlows) != 1 || !strings.HasPrefix(chains[0].AffectedFlows[0], bgpSessionFlow) {
		t.Errorf("session chain flows = %v", chains[0].AffectedFlows)
	}
	if len(chains[1].AffectedFlows) != 1 || !strings.HasPrefix(chains[1].AffectedFlows[0], unrelatedFlowA) {
		t.Errorf("proximity chain flows = %v", chains[1].AffectedFlows)
	}
}

// Sharing an IP with the BGP peer, or the peer pair on a non-179 port, is NOT
// session identity.
func TestEvidence_SharedIPOrWrongPortIsNotIdentity(t *testing.T) {
	for _, flow := range []string{
		"10.0.0.2:40000->10.9.9.9:443",  // one shared IP
		"10.0.0.2:40000->10.0.0.1:443",  // same IP pair, not BGP port
		"10.0.0.2:40000->10.0.0.1:1790", // port merely contains 179
		"10.0.0.2:179->10.9.9.9:40000",  // port 179 but other peer
	} {
		h := newCorrHarness()
		h.bgp(corrBase, "10.0.0.1", "10.0.0.2", "Withdrawal", "w")
		for i := 0; i < 3; i++ {
			h.retrans(corrBase.Add(time.Duration(i*100)*time.Millisecond), flow)
		}
		chains := h.run()
		if len(chains) != 1 || chains[0].EvidenceBasis != models.EvidenceTimeProximity {
			t.Errorf("%s: expected one time_proximity chain, got %+v", flow, chains)
		}
	}
}

// BFD has no TCP session, so it can never yield a same_session chain.
func TestEvidence_BFDNeverSameSession(t *testing.T) {
	h := newCorrHarness()
	h.bfdDown(corrBase, "10.0.0.1", "10.0.0.2")
	for i := 0; i < 3; i++ {
		h.retrans(corrBase.Add(time.Duration(i*100)*time.Millisecond), bgpSessionFlow)
		h.rtt(corrBase.Add(time.Duration(i*100)*time.Millisecond), bgpSessionFlow, 800)
	}
	for _, c := range h.run() {
		if c.EvidenceBasis != models.EvidenceTimeProximity || c.OverlayEffect == "RTT Spike" {
			t.Errorf("BFD produced a stronger-than-proximity chain: %+v", c)
		}
	}
}

func TestEvidence_SplitFlowKey(t *testing.T) {
	cases := []struct {
		in               string
		sIP, sP, dIP, dP string
		ok               bool
	}{
		{"10.0.0.1:179->10.0.0.2:40000", "10.0.0.1", "179", "10.0.0.2", "40000", true},
		{"2001:db8::1:179->2001:db8::2:40000", "2001:db8::1", "179", "2001:db8::2", "40000", true},
		{"garbage", "", "", "", "", false},
		{"10.0.0.1->10.0.0.2", "", "", "", "", false},
	}
	for _, tc := range cases {
		sIP, sP, dIP, dP, ok := splitFlowKey(tc.in)
		if ok != tc.ok || (ok && (sIP != tc.sIP || sP != tc.sP || dIP != tc.dIP || dP != tc.dP)) {
			t.Errorf("splitFlowKey(%q) = %q %q %q %q %v", tc.in, sIP, sP, dIP, dP, ok)
		}
	}
}

// ─── Negative 5: retransmission-inflated RTT (Karn) ──────────────────────

// rttSpikes builds a capture with `interval`-spaced packets from the given
// frames; gaps are filled with 1-byte UDP filler.
func rttSpikes(t *testing.T, frames map[int][]byte, n int) []events.Event {
	t.Helper()
	filler := testpcap.UDPFrame(testpcap.ClientMAC, testpcap.ServerMAC, testpcap.ClientIP, testpcap.ServerIP, 40000, 40001, []byte("x"))
	var pk [][]byte
	for i := 0; i < n; i++ {
		if f, ok := frames[i]; ok {
			pk = append(pk, f)
		} else {
			pk = append(pk, filler)
		}
	}
	r := runGoldenInterval(t, pk, 100*time.Millisecond)
	return r.Events.ByKind(events.TCPRTTSpike)
}

func rttC2S(seq, ack uint32, flags uint8, payload []byte) []byte {
	return testpcap.TCPFrame(testpcap.ClientMAC, testpcap.ServerMAC, testpcap.ClientIP, testpcap.ServerIP, 50010, 443, seq, ack, flags, payload)
}
func rttS2C(seq, ack uint32, flags uint8, payload []byte) []byte {
	return testpcap.TCPFrame(testpcap.ServerMAC, testpcap.ClientMAC, testpcap.ServerIP, testpcap.ClientIP, 443, 50010, seq, ack, flags, payload)
}

// Control: a clean SYN/SYN-ACK 300ms apart is a legitimate RTT spike and stays.
func TestRTT_CleanHandshakeSpikePreserved(t *testing.T) {
	spikes := rttSpikes(t, map[int][]byte{
		0: rttC2S(1000, 0, testpcap.SYN, nil),
		3: rttS2C(2000, 1001, testpcap.SYN|testpcap.ACK, nil),
	}, 5)
	if len(spikes) != 1 || spikes[0].Values["rtt_ms"] < 299 || spikes[0].Values["rtt_ms"] > 301 {
		t.Fatalf("expected one ~300ms spike, got %+v", spikes)
	}
}

// A retransmitted SYN: the SYN-ACK answers the retransmission, but the sample
// would be measured from the FIRST SYN (1.2 s) — an RTO artefact, not an RTT.
func TestRTT_RetransmittedSYNNotSampled(t *testing.T) {
	spikes := rttSpikes(t, map[int][]byte{
		0:  rttC2S(1000, 0, testpcap.SYN, nil),
		10: rttC2S(1000, 0, testpcap.SYN, nil), // SYN retransmission
		12: rttS2C(2000, 1001, testpcap.SYN|testpcap.ACK, nil),
	}, 14)
	if len(spikes) != 0 {
		t.Errorf("retransmission-inflated RTT became a spike: %+v", spikes)
	}
}

// Same for a retransmitted 1-byte data segment (ack == seq+1 matches the lookup).
func TestRTT_RetransmittedDataSegmentNotSampled(t *testing.T) {
	spikes := rttSpikes(t, map[int][]byte{
		0:  rttC2S(1001, 2001, testpcap.PSH|testpcap.ACK, []byte("a")),
		10: rttC2S(1001, 2001, testpcap.PSH|testpcap.ACK, []byte("a")), // retransmission
		12: rttS2C(2001, 1002, testpcap.ACK, nil),
	}, 14)
	if len(spikes) != 0 {
		t.Errorf("retransmission-inflated RTT became a spike: %+v", spikes)
	}
}
