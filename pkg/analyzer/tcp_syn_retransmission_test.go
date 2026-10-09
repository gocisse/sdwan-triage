package analyzer

import (
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"testing"

	"github.com/gocisse/sdwan-triage/internal/testpcap"
	"github.com/gocisse/sdwan-triage/pkg/events"
	"github.com/gocisse/sdwan-triage/pkg/models"
)

// Phase 4.29c — tcp.syn_retransmission: OBSERVED repeated SYN / SYN-ACK packets.
// The event is additive and independent of tcp.retransmission accounting; these
// tests also pin that existing counts are untouched. Synthetic packets are
// spaced 100 ms apart (packet i at base + i*100 ms).

const synBase = 50300

func synEvents(r *models.TriageReport) []events.Event {
	return r.Events.ByKind(events.TCPSYNRetransmission)
}

func clientSYN(port uint16, isn uint32) []byte {
	return tcpC2S(port, isn, 0, testpcap.SYN, nil)
}
func serverSYNACK(port uint16, isn, ack uint32) []byte {
	return tcpS2C(port, isn, ack, testpcap.SYN|testpcap.ACK, nil)
}

func segmentCounts(evs []events.Event) (syn, synack int) {
	for _, e := range evs {
		switch e.Attrs["segment"] {
		case "SYN":
			syn++
		case "SYN-ACK":
			synack++
		}
	}
	return
}

func TestSYNRetx_InitialSYNAndSYNACK_NoEvent(t *testing.T) {
	r := runGolden(t, handshake(synBase)) // SYN, SYN-ACK, ACK
	if n := len(synEvents(r)); n != 0 {
		t.Errorf("initial handshake produced %d tcp.syn_retransmission events: %+v", n, synEvents(r))
	}
}

func TestSYNRetx_RepeatedSYN_EventsAndValues(t *testing.T) {
	const port = synBase + 1
	pk := [][]byte{
		clientSYN(port, 1000),                       // 0 initial
		clientSYN(port, 1000),                       // 1 repeat (attempt 2)
		clientSYN(port, 1000),                       // 2 repeat (attempt 3)
		serverSYNACK(port, 2000, 1001),              // 3
		tcpC2S(port, 1001, 2001, testpcap.ACK, nil), // 4
	}
	r := runGolden(t, pk)
	ev := synEvents(r)
	if len(ev) != 2 {
		t.Fatalf("events = %d, want 2: %+v", len(ev), ev)
	}
	for i, e := range ev {
		attempt := float64(i + 2)
		if e.Attrs["segment"] != "SYN" || e.Values["seq"] != 1000 || e.Values["ack"] != 0 || e.Values["attempt"] != attempt {
			t.Errorf("event %d = %+v / %+v", i, e.Values, e.Attrs)
		}
		if e.FlowKey != "192.168.1.100:50301->10.0.0.50:443" || e.Attrs["src_ip"] != "192.168.1.100" || e.Attrs["dst_ip"] != "10.0.0.50" {
			t.Errorf("event %d flow/attrs = %q %+v", i, e.FlowKey, e.Attrs)
		}
		if math.Abs(e.Values["since_previous_ms"]-100) > 0.5 || math.Abs(e.Values["since_first_ms"]-100*attempt+100) > 0.5 {
			t.Errorf("event %d timing = prev %v first %v", i, e.Values["since_previous_ms"], e.Values["since_first_ms"])
		}
		if len(e.Packets) != 1 {
			t.Errorf("event %d should reference exactly the repeated packet: %+v", i, e.Packets)
		}
	}
	if first := ev[0].Values["first_ts_us"]; first != float64(testpcap.BaseTime.UnixMicro()) {
		t.Errorf("first_ts_us = %v, want the first SYN's capture time %v", first, float64(testpcap.BaseTime.UnixMicro()))
	}
	if r.EventCounts["tcp.syn_retransmission"] != 2 {
		t.Errorf("event_counts = %v", r.EventCounts)
	}
}

func TestSYNRetx_RepeatedSYNACK_Event(t *testing.T) {
	const port = synBase + 2
	pk := [][]byte{
		clientSYN(port, 1000),
		serverSYNACK(port, 2000, 1001),
		serverSYNACK(port, 2000, 1001), // repeat (attempt 2)
		serverSYNACK(port, 2000, 1001), // repeat (attempt 3)
		tcpC2S(port, 1001, 2001, testpcap.ACK, nil),
	}
	r := runGolden(t, pk)
	ev := synEvents(r)
	if len(ev) != 2 {
		t.Fatalf("events = %d, want 2: %+v", len(ev), ev)
	}
	for i, e := range ev {
		if e.Attrs["segment"] != "SYN-ACK" || e.Values["seq"] != 2000 || e.Values["ack"] != 1001 || e.Values["attempt"] != float64(i+2) {
			t.Errorf("event %d = %+v / %+v", i, e.Values, e.Attrs)
		}
		if e.FlowKey != "10.0.0.50:443->192.168.1.100:50302" {
			t.Errorf("event %d flow = %q", i, e.FlowKey)
		}
	}
	if syn, sa := segmentCounts(ev); syn != 0 || sa != 2 {
		t.Errorf("SYN=%d SYN-ACK=%d", syn, sa)
	}
}

func TestSYNRetx_SYNAndSYNACKTrackedIndependently(t *testing.T) {
	const port = synBase + 3
	pk := [][]byte{
		clientSYN(port, 1000),
		clientSYN(port, 1000), // SYN repeat
		serverSYNACK(port, 2000, 1001),
		serverSYNACK(port, 2000, 1001), // SYN-ACK repeat
	}
	syn, sa := segmentCounts(synEvents(runGolden(t, pk)))
	if syn != 1 || sa != 1 {
		t.Errorf("SYN=%d SYN-ACK=%d, want 1/1", syn, sa)
	}
}

// ─── cleanup and tuple reuse ────────────────────────────────────────

func TestSYNRetx_CompletedHandshakeCleanup(t *testing.T) {
	const port = synBase + 4
	pk := handshake(port)                  // SYN(1000), SYN-ACK(2000/1001), ACK -> SYN state cleared by the ACK
	pk = append(pk, clientSYN(port, 1000)) // same ISN after a completed handshake
	r := runGolden(t, pk)
	if n := len(synEvents(r)); n != 0 {
		t.Errorf("SYN after a completed handshake was reported as a repeat: %+v", synEvents(r))
	}
}

func TestSYNRetx_PeerSYNACKDoesNotClearSYNState(t *testing.T) {
	// Mirrors The-Ultimate-PCAP frames 8496/8499/8500: SYN, SYN-ACK, then the same
	// SYN again before any client ACK. Still an observed repeated SYN.
	const port = synBase + 5
	pk := [][]byte{
		clientSYN(port, 1000),
		serverSYNACK(port, 2000, 1001),
		clientSYN(port, 1000),
	}
	ev := synEvents(runGolden(t, pk))
	if len(ev) != 1 || ev[0].Attrs["segment"] != "SYN" || ev[0].Values["attempt"] != 2 {
		t.Errorf("events = %+v, want one SYN repeat", ev)
	}
}

func TestSYNRetx_RSTAndFINCleanup(t *testing.T) {
	type tc struct {
		name string
		pk   func(port uint16) [][]byte
	}
	cases := []tc{
		{"RST from server ends the SYN attempt", func(p uint16) [][]byte {
			return [][]byte{clientSYN(p, 1000), tcpS2C(p, 0, 1001, testpcap.RST|testpcap.ACK, nil), clientSYN(p, 1000)}
		}},
		{"RST from client ends the SYN attempt", func(p uint16) [][]byte {
			return [][]byte{clientSYN(p, 1000), tcpC2S(p, 1001, 0, testpcap.RST, nil), clientSYN(p, 1000)}
		}},
		{"FIN ends the SYN attempt", func(p uint16) [][]byte {
			return [][]byte{clientSYN(p, 1000), tcpC2S(p, 1001, 0, testpcap.FIN|testpcap.ACK, nil), clientSYN(p, 1000)}
		}},
		{"RST ends pending SYN-ACK state", func(p uint16) [][]byte {
			return [][]byte{clientSYN(p, 1000), serverSYNACK(p, 2000, 1001), tcpC2S(p, 1001, 2001, testpcap.RST, nil), serverSYNACK(p, 2000, 1001)}
		}},
		{"FIN ends pending SYN-ACK state", func(p uint16) [][]byte {
			return [][]byte{clientSYN(p, 1000), serverSYNACK(p, 2000, 1001), tcpS2C(p, 2001, 1001, testpcap.FIN|testpcap.ACK, nil), serverSYNACK(p, 2000, 1001)}
		}},
	}
	for i, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := runGolden(t, c.pk(uint16(synBase+10+i)))
			if n := len(synEvents(r)); n != 0 {
				t.Errorf("state not cleared: %+v", synEvents(r))
			}
		})
	}
}

func TestSYNRetx_FourTupleReuseWithDifferentISN(t *testing.T) {
	const port = synBase + 20
	pk := [][]byte{
		clientSYN(port, 1000),
		clientSYN(port, 5000), // same 4-tuple, new ISN: new attempt, not a repeat
		serverSYNACK(port, 2000, 5001),
		serverSYNACK(port, 7000, 5001), // same tuple, different server ISN: not a repeat
	}
	if n := len(synEvents(runGolden(t, pk))); n != 0 {
		t.Errorf("tuple reuse with a different ISN produced %d events", n)
	}
	// ...but the NEW attempt's state is the one that matters afterwards.
	pk = append(pk, clientSYN(port, 5000), serverSYNACK(port, 7000, 5001))
	syn, sa := segmentCounts(synEvents(runGolden(t, pk)))
	if syn != 1 || sa != 1 {
		t.Errorf("after reuse: SYN=%d SYN-ACK=%d, want 1/1 (repeats of the new attempt)", syn, sa)
	}
}

// ─── things that must not be SYN retries ────────────────────────────

// A SYN-ACK is a repeat only if BOTH its sequence and acknowledgement numbers
// match the pending one; the same server ISN acknowledging a different client
// ISN is a different attempt.
func TestSYNRetx_SYNACKWithDifferentAckIsNotARepeat(t *testing.T) {
	const port = synBase + 26
	pk := [][]byte{
		serverSYNACK(port, 2000, 1001),
		serverSYNACK(port, 2000, 5001), // same seq, different ack
	}
	if n := len(synEvents(runGolden(t, pk))); n != 0 {
		t.Errorf("SYN-ACK with a different ack number was reported as a repeat (%d events)", n)
	}
}

func TestSYNRetx_OrdinaryTrafficProducesNone(t *testing.T) {
	const port = synBase + 21
	pk := handshake(port)
	pk = append(pk,
		tcpC2S(port, 1001, 2001, psh, payloadBytes(100)),
		tcpS2C(port, 2001, 1101, testpcap.ACK, nil),
		tcpS2C(port, 2001, 1101, testpcap.ACK, nil),       // duplicate ACK
		tcpC2S(port, 1100, 2001, testpcap.ACK, []byte{0}), // keep-alive-shaped
		tcpC2S(port, 1100, 2001, testpcap.ACK, []byte{0}),
	)
	r := runGolden(t, pk)
	if n := len(synEvents(r)); n != 0 {
		t.Errorf("ordinary ACK/keep-alive traffic produced SYN retry events: %+v", synEvents(r))
	}
}

func TestSYNRetx_DoesNotChangePayloadRetransmissionAccounting(t *testing.T) {
	const port = synBase + 22
	pk := [][]byte{
		clientSYN(port, 1000),
		clientSYN(port, 1000), // SYN repeat
		serverSYNACK(port, 2000, 1001),
		serverSYNACK(port, 2000, 1001), // SYN-ACK repeat
		tcpC2S(port, 1001, 2001, testpcap.ACK, nil),
		tcpC2S(port, 1001, 2001, psh, payloadBytes(100)),
		tcpC2S(port, 1001, 2001, psh, payloadBytes(100)), // genuine data retransmission
	}
	r := runGolden(t, pk)
	if syn, sa := segmentCounts(synEvents(r)); syn != 1 || sa != 1 {
		t.Errorf("SYN=%d SYN-ACK=%d, want 1/1", syn, sa)
	}
	if n := len(retxEvents(r)); n != 1 {
		t.Errorf("tcp.retransmission events = %d, want 1 (data only)", n)
	}
	if len(r.TCPRetransmissions) != 1 || !hasTCPFlow(r.TCPRetransmissions, port, 443) {
		t.Errorf("TCPRetransmissions = %+v", r.TCPRetransmissions)
	}
	if lostPackets(r) != 1 {
		t.Errorf("packets_lost = %d, want 1", lostPackets(r))
	}
	if want := 1.0 / 7.0 * 100; math.Abs(r.PacketLoss.LossPercentage-want) > 1e-9 {
		t.Errorf("loss_percentage = %v, want %v (denominator unchanged: all 7 packets)", r.PacketLoss.LossPercentage, want)
	}
	// Existing handshake lists keep one entry per SYN / SYN-ACK packet.
	if len(r.TCPHandshakes.SYNFlows) != 2 || len(r.TCPHandshakes.SYNACKFlows) != 2 {
		t.Errorf("SYNFlows=%d SYNACKFlows=%d, want 2/2", len(r.TCPHandshakes.SYNFlows), len(r.TCPHandshakes.SYNACKFlows))
	}
}

func TestSYNRetx_NoHealthRiskOrFindingsEffect(t *testing.T) {
	const port = synBase + 23
	pk := [][]byte{
		clientSYN(port, 1000), clientSYN(port, 1000), clientSYN(port, 1000),
		serverSYNACK(port, 2000, 1001), serverSYNACK(port, 2000, 1001),
		tcpC2S(port, 1001, 2001, testpcap.ACK, nil),
	}
	r := runGolden(t, pk)
	if len(synEvents(r)) != 3 {
		t.Fatalf("expected 3 repeat events, got %d", len(synEvents(r)))
	}
	if r.NetworkHealth != models.NetworkHealthGood {
		t.Errorf("network_health = %q, want good (the new evidence must not affect health)", r.NetworkHealth)
	}
	if r.RiskScore != 0 {
		t.Errorf("risk_score = %d, want 0", r.RiskScore)
	}
	if len(r.Findings) != 0 || len(r.RootCauseChains) != 0 {
		t.Errorf("findings/chains created by SYN repeat evidence: %+v %+v", r.Findings, r.RootCauseChains)
	}
	if len(r.TCPRetransmissions) != 0 || len(retxEvents(r)) != 0 || lostPackets(r) != 0 {
		t.Errorf("legacy retransmission accounting changed")
	}
}

// ─── incomplete captures and wrap-around ────────────────────────────

func TestSYNRetx_MidStreamCapture_Conservative(t *testing.T) {
	const port = synBase + 24
	// Capture starts mid-connection: no SYN seen, so nothing can be a SYN repeat.
	pk := [][]byte{
		tcpC2S(port, 5000, 9000, psh, payloadBytes(100)),
		tcpS2C(port, 9000, 5100, testpcap.ACK, nil),
		tcpC2S(port, 5100, 9000, psh, payloadBytes(100)),
	}
	if n := len(synEvents(runGolden(t, pk))); n != 0 {
		t.Errorf("mid-stream capture produced %d SYN repeat events", n)
	}
	// Capture starts after the SYN: a repeated SYN-ACK is still visible (the first
	// SYN-ACK is in the capture) even though the SYN is not.
	pk = [][]byte{serverSYNACK(port, 2000, 1001), serverSYNACK(port, 2000, 1001)}
	syn, sa := segmentCounts(synEvents(runGolden(t, pk)))
	if syn != 0 || sa != 1 {
		t.Errorf("SYN=%d SYN-ACK=%d, want 0/1", syn, sa)
	}
}

func TestSYNRetx_SequenceWraparound(t *testing.T) {
	const port = synBase + 25
	isn := uint32(0xFFFFFFFF) // client ISN; the SYN-ACK acknowledges ISN+1 = 0
	pk := [][]byte{
		clientSYN(port, isn),
		clientSYN(port, isn),
		serverSYNACK(port, 0xFFFFFFF0, 0),
		serverSYNACK(port, 0xFFFFFFF0, 0),
	}
	ev := synEvents(runGolden(t, pk))
	syn, sa := segmentCounts(ev)
	if syn != 1 || sa != 1 {
		t.Fatalf("SYN=%d SYN-ACK=%d, want 1/1: %+v", syn, sa, ev)
	}
	for _, e := range ev {
		if e.Attrs["segment"] == "SYN" && e.Values["seq"] != float64(isn) {
			t.Errorf("SYN seq = %v", e.Values["seq"])
		}
		if e.Attrs["segment"] == "SYN-ACK" && (e.Values["seq"] != float64(0xFFFFFFF0) || e.Values["ack"] != 0) {
			t.Errorf("SYN-ACK seq/ack = %v/%v", e.Values["seq"], e.Values["ack"])
		}
	}
}

// ─── determinism and the per-capture event cap ──────────────────────

func TestSYNRetx_Deterministic(t *testing.T) {
	build := func() [][]byte {
		var pk [][]byte
		for i := 0; i < 3; i++ {
			p := uint16(synBase + 30 + i)
			pk = append(pk, clientSYN(p, 1000), clientSYN(p, 1000), serverSYNACK(p, 2000, 1001), serverSYNACK(p, 2000, 1001), clientSYN(p, 1000))
		}
		return pk
	}
	snap := func() string {
		r := runGolden(t, build())
		type ev struct {
			ID     uint64
			Flow   string
			Values map[string]float64
			Attrs  map[string]string
		}
		var out []ev
		for _, e := range synEvents(r) {
			out = append(out, ev{e.ID, e.FlowKey, e.Values, e.Attrs})
		}
		b, _ := json.Marshal(map[string]any{"events": out, "counts": r.EventCounts})
		return string(b)
	}
	first := snap()
	for i := 0; i < 4; i++ {
		if got := snap(); got != first {
			t.Fatalf("run %d differs", i+2)
		}
	}
}

func TestSYNRetx_EventCapLeavesOtherEventsAndDroppedCountUntouched(t *testing.T) {
	const stormPort, dataPort = synBase + 40, synBase + 41
	dataFlow := func() [][]byte {
		pk := handshake(dataPort)
		return append(pk,
			tcpC2S(dataPort, 1001, 2001, psh, payloadBytes(100)),
			tcpC2S(dataPort, 1001, 2001, psh, payloadBytes(100)), // one data retransmission
		)
	}
	base := runGolden(t, dataFlow())

	const repeats = 10050
	storm := make([][]byte, 0, repeats+1)
	for i := 0; i <= repeats; i++ { // initial SYN + 10,050 repeats on the same ISN
		storm = append(storm, clientSYN(stormPort, 1000))
	}
	r := runGolden(t, append(storm, dataFlow()...))

	ev := synEvents(r)
	if len(ev) != 10000 {
		t.Fatalf("emitted %d SYN repeat events, want exactly the 10,000 cap", len(ev))
	}
	if got := ev[len(ev)-1].Values["attempt"]; got != 10001 {
		t.Errorf("last emitted attempt = %v, want 10001 (attempt 1 is the initial SYN)", got)
	}
	if r.EventsDropped != 0 {
		t.Errorf("EventsDropped = %d, want 0", r.EventsDropped)
	}
	// Existing events are exactly those of the run without the storm.
	if len(retxEvents(r)) != len(retxEvents(base)) || len(retxEvents(r)) != 1 {
		t.Errorf("tcp.retransmission events = %d (base %d), want 1", len(retxEvents(r)), len(retxEvents(base)))
	}
	if len(r.TCPRetransmissions) != len(base.TCPRetransmissions) || lostPackets(r) != lostPackets(base) {
		t.Errorf("legacy accounting changed: flows %d/%d lost %d/%d", len(r.TCPRetransmissions), len(base.TCPRetransmissions), lostPackets(r), lostPackets(base))
	}
	for kind, n := range base.EventCounts {
		if kind == "tcp.syn_retransmission" {
			continue
		}
		if r.EventCounts[kind] != n {
			t.Errorf("event_counts[%s] = %d, want %d", kind, r.EventCounts[kind], n)
		}
	}
}

// The additive events are emitted after every other event, so existing events
// keep their dense IDs (Finding evidence quotes event IDs and must not shift).
func TestSYNRetx_ExistingEventIDsAreNotShifted(t *testing.T) {
	const port = synBase + 50
	pk := [][]byte{
		clientSYN(port, 1000),
		clientSYN(port, 1000), // SYN repeat early in the capture
		serverSYNACK(port, 2000, 1001),
		tcpC2S(port, 1001, 2001, testpcap.ACK, nil),
		tcpC2S(port, 1001, 2001, psh, payloadBytes(100)),
		tcpC2S(port, 1001, 2001, psh, payloadBytes(100)), // data retransmission AFTER the repeat
	}
	r := runGolden(t, pk)
	var maxOther uint64
	for _, e := range r.Events.Events() {
		if e.Kind != events.TCPSYNRetransmission && e.ID > maxOther {
			maxOther = e.ID
		}
	}
	if maxOther != uint64(len(r.Events.Events())-len(synEvents(r))) {
		t.Errorf("other events' IDs are not dense 1..%d (max %d)", len(r.Events.Events())-len(synEvents(r)), maxOther)
	}
	for _, e := range synEvents(r) {
		if e.ID <= maxOther {
			t.Errorf("SYN repeat event ID %d interleaves with existing events (max existing %d)", e.ID, maxOther)
		}
	}
}

// The repeated packet is referenced by its capture ordinal (0-based position).
func TestSYNRetx_EventReferencesTheRepeatedPacket(t *testing.T) {
	const port = synBase + 51
	pk := [][]byte{clientSYN(port, 1000), clientSYN(port, 1000), clientSYN(port, 1000)}
	ev := synEvents(runGolden(t, pk))
	if len(ev) != 2 || len(ev[0].Packets) != 1 || len(ev[1].Packets) != 1 {
		t.Fatalf("events/packets = %+v", ev)
	}
	if ev[0].Packets[0].Index != 1 || ev[1].Packets[0].Index != 2 {
		t.Errorf("packet refs = %d, %d, want 1, 2", ev[0].Packets[0].Index, ev[1].Packets[0].Index)
	}
	if !ev[0].Packets[0].Timestamp.Equal(ev[0].Timestamp) {
		t.Errorf("packet ref timestamp %v != event timestamp %v", ev[0].Packets[0].Timestamp, ev[0].Timestamp)
	}
}

// Real-capture baseline (optional; SDWAN_VENDOR_PCAP_DIR as for the vendor
// harness; a capture missing from the directory is skipped, never failed).
// Values measured at Phase 4.29c. They are observations of repeated handshake
// packets, not claims of loss. tshark comparison (tcp.analysis.retransmission &&
// tcp.flags.syn==1, split on ACK): Lab 2 0/1, Lab 4 1/1, Ultimate 14/4,
// Velocloud-Lan 89/0, Velocloud-Wan 6/0, cisco-example-lan 2/0. The one extra
// Ultimate SYN is frame 8500: a SYN with the same ISN repeated 78 ms after the
// SYN-ACK (the SYN-ACK was delayed by ARP resolution; TSval differs by 100 ms),
// which tshark labels out-of-order but which is an observed repeated SYN.
// The existing retransmission metrics must be exactly the 4.29a values.
func TestSYNRetx_RealCaptureBaseline(t *testing.T) {
	dir := os.Getenv("SDWAN_VENDOR_PCAP_DIR")
	if dir == "" {
		t.Skip("SDWAN_VENDOR_PCAP_DIR not set; skipping real-capture SYN repeat baseline")
	}
	cases := []struct {
		name                 string
		syn, synack          int
		retxEvents, retxFlow int
		lost                 uint64
	}{
		{"Lab 2-DisplayFilters", 0, 1, 1, 1, 1}, // existing values measured with the pre-4.29c binary
		{"Lab 3-TCP Retrans", 0, 0, 1, 1, 1},
		{"Lab 4-NetworkCongestion", 1, 1, 1, 1, 1},
		{"user1", 0, 0, 3, 2, 3},
		{"Velocloud-Lan", 89, 0, 0, 0, 0},
		{"Velocloud-Wan", 6, 0, 0, 0, 0},
		{"cisco-example-lan", 2, 0, 9, 9, 9},
		{"The-Ultimate-PCAP", 15, 4, 80, 41, 79},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			var path string
			for _, ext := range []string{".pcap", ".pcapng"} {
				p := filepath.Join(dir, c.name+ext)
				if _, err := os.Stat(p); err == nil {
					path = p
					break
				}
			}
			if path == "" {
				t.Skipf("%s not present in %s", c.name, dir)
			}
			r := runPCAPFile(t, path, NewProcessorWithOptions(false, false))
			syn, sa := segmentCounts(synEvents(r))
			if syn != c.syn || sa != c.synack {
				t.Errorf("SYN/SYN-ACK repeat events = %d/%d, want %d/%d", syn, sa, c.syn, c.synack)
			}
			if got := len(retxEvents(r)); got != c.retxEvents {
				t.Errorf("tcp.retransmission events = %d, want %d (unchanged)", got, c.retxEvents)
			}
			if got := len(r.TCPRetransmissions); got != c.retxFlow {
				t.Errorf("retransmission flows = %d, want %d (unchanged)", got, c.retxFlow)
			}
			if got := lostPackets(r); got != c.lost {
				t.Errorf("packets_lost = %d, want %d (unchanged)", got, c.lost)
			}
			if r.EventsDropped != 0 {
				t.Errorf("EventsDropped = %d", r.EventsDropped)
			}
		})
	}
}
