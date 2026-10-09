package analyzer

import (
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gocisse/sdwan-triage/internal/testpcap"
	"github.com/gocisse/sdwan-triage/pkg/events"
	"github.com/gocisse/sdwan-triage/pkg/models"
)

// Phase 4.30d — tcp.duplicate_ack_run: OBSERVED runs of duplicate ACKs (RFC 5681
// criteria). Not proof of loss, not a confirmed fast retransmit. Packets are 100 ms
// apart; the handshake takes ordinals 0-2. Helpers come from the 4.30a/4.30c tests.

const dupPort = 54000

func dupEvents(r *models.TriageReport) []events.Event {
	return r.Events.ByKind(events.TCPDuplicateACKRun)
}

func srvAck(ack uint32, win uint16) seqSpec { return sAck(ack, win) }

func cliAck(ack uint32, win uint16) seqSpec {
	return seqSpec{seq: 1001, ack: ack, flags: testpcap.ACK, win: win}
}

func srvSack(ack uint32, win uint16, edges ...[2]uint32) seqSpec {
	return seqSpec{fromServer: true, seq: 5001, ack: ack, flags: testpcap.ACK, win: win, sack: edges}
}

// Client sends 1001..1300 (peer next 1301) -> ordinals 3,4,5.
func outstandingData() []seqSpec {
	return []seqSpec{cData(1001, 100), cData(1101, 100), cData(1201, 100)}
}

func one(t *testing.T, r *models.TriageReport) events.Event {
	t.Helper()
	ev := dupEvents(r)
	if len(ev) != 1 {
		t.Fatalf("tcp.duplicate_ack_run events = %d, want 1: %+v", len(ev), ev)
	}
	return ev[0]
}

func TestDupRun_ValidRunWithOutstandingData_ThreeDuplicates(t *testing.T) {
	specs := append(outstandingData(),
		srvAck(1101, 100), // 6: the initial ACK
		srvAck(1101, 100), // 7: duplicate 1
		srvAck(1101, 100), // 8: duplicate 2
		srvAck(1101, 100), // 9: duplicate 3
	)
	r := sc(t, dupPort, specs...)
	e := one(t, r)
	if e.Values["ack"] != 1101 || e.Values["window"] != 100 || e.Values["dup_count"] != 3 {
		t.Fatalf("values = %+v", e.Values)
	}
	if e.Attrs["ended_by"] != "capture_end" || e.Attrs["sack"] != "none" || e.Attrs["consistent_with_fast_retransmit_trigger"] != "true" {
		t.Errorf("attrs = %+v", e.Attrs)
	}
	if e.FlowKey != "10.0.0.50:443->192.168.1.100:54000" || e.Attrs["src_ip"] != "10.0.0.50" || e.Attrs["dst_ip"] != "192.168.1.100" {
		t.Errorf("flow/attrs = %q %+v", e.FlowKey, e.Attrs)
	}
	// Beginning = the initial ACK (ordinal 6), end = the last duplicate (ordinal 9).
	first := testpcap.BaseTime.Add(6 * testpcap.DefaultInterval)
	last := testpcap.BaseTime.Add(9 * testpcap.DefaultInterval)
	if !e.Timestamp.Equal(first) || len(e.Packets) != 2 || e.Packets[0].Index != 6 || e.Packets[1].Index != 9 || !e.Packets[1].Timestamp.Equal(last) {
		t.Errorf("timestamp/packets = %v %+v", e.Timestamp, e.Packets)
	}
	if math.Abs(e.Values["duration_ms"]-300) > 0.5 {
		t.Errorf("duration_ms = %v, want 300", e.Values["duration_ms"])
	}
	if r.EventCounts["tcp.duplicate_ack_run"] != 1 {
		t.Errorf("event_counts = %v", r.EventCounts)
	}
}

func TestDupRun_ThresholdAttributeOnlyAtThreeOrMore(t *testing.T) {
	for _, tc := range []struct {
		dups int
		want bool
	}{{1, false}, {2, false}, {3, true}, {5, true}} {
		specs := append(outstandingData(), srvAck(1101, 100))
		for i := 0; i < tc.dups; i++ {
			specs = append(specs, srvAck(1101, 100))
		}
		e := one(t, sc(t, dupPort, specs...))
		if e.Values["dup_count"] != float64(tc.dups) || (e.Attrs["consistent_with_fast_retransmit_trigger"] == "true") != tc.want {
			t.Errorf("dups=%d: count=%v attrs=%+v", tc.dups, e.Values["dup_count"], e.Attrs)
		}
	}
	// An initial ACK with no repeat is not a run at all.
	if n := len(dupEvents(sc(t, dupPort, append(outstandingData(), srvAck(1101, 100))...))); n != 0 {
		t.Errorf("a single ACK produced %d runs", n)
	}
}

func TestDupRun_EndedByChangedAckOrWindow(t *testing.T) {
	base := append(outstandingData(), srvAck(1101, 100), srvAck(1101, 100), srvAck(1101, 100))
	e := one(t, sc(t, dupPort, append(append([]seqSpec{}, base...), srvAck(1201, 100))...))
	if e.Attrs["ended_by"] != "ack_changed" || e.Values["dup_count"] != 2 {
		t.Errorf("changed ack: %+v %+v", e.Values, e.Attrs)
	}
	e = one(t, sc(t, dupPort, append(append([]seqSpec{}, base...), srvAck(1101, 200))...))
	if e.Attrs["ended_by"] != "window_changed" || e.Values["dup_count"] != 2 || e.Values["window"] != 100 {
		t.Errorf("changed window: %+v %+v", e.Values, e.Attrs)
	}
	// A window update does not itself count as a duplicate and starts a new base.
	if n := len(dupEvents(sc(t, dupPort, append(outstandingData(), srvAck(1101, 100), srvAck(1101, 200), srvAck(1101, 300))...))); n != 0 {
		t.Errorf("window updates produced %d runs", n)
	}
}

func TestDupRun_EndedByNonPureACKAndControlFlags(t *testing.T) {
	base := append(outstandingData(), srvAck(1101, 100), srvAck(1101, 100), srvAck(1101, 100))
	cases := map[string]seqSpec{
		"payload-carrying ACK": {fromServer: true, seq: 5001, ack: 1101, flags: testpcap.PSH | testpcap.ACK, win: 100, payload: 10},
		"FIN":                  {fromServer: true, seq: 5001, ack: 1101, flags: testpcap.FIN | testpcap.ACK, win: 100},
		"RST":                  {fromServer: true, seq: 5001, ack: 1101, flags: testpcap.RST | testpcap.ACK, win: 100},
		"SYN-ACK":              {fromServer: true, seq: 9000, ack: 1101, flags: testpcap.SYN | testpcap.ACK, win: 100},
	}
	for name, term := range cases {
		e := one(t, sc(t, dupPort, append(append([]seqSpec{}, base...), term)...))
		if e.Attrs["ended_by"] != "non_pure_ack" || e.Values["dup_count"] != 2 {
			t.Errorf("%s: %+v %+v", name, e.Values, e.Attrs)
		}
	}
	// After a payload-carrying ACK the chain restarts: the next identical pure ACK is a first observation.
	r := sc(t, dupPort, append(append([]seqSpec{}, base...), cases["payload-carrying ACK"], srvAck(1101, 100))...)
	if n := len(dupEvents(r)); n != 1 {
		t.Errorf("chain not reset by the payload-carrying ACK: %d runs", n)
	}
}

func TestDupRun_IdleAndKeepAliveACKsNeverQualify(t *testing.T) {
	// All sent data is acknowledged: nothing outstanding, so repeats are not duplicates.
	idle := sc(t, dupPort, cData(1001, 100), srvAck(1101, 2048), srvAck(1101, 2048), srvAck(1101, 2048), srvAck(1101, 2048))
	if n := len(dupEvents(idle)); n != 0 {
		t.Errorf("idle repeated ACKs produced %d runs", n)
	}
	// Keep-alive probe (1 byte at next-1) answered by a repeated ACK.
	ka := sc(t, dupPort, cData(1001, 100),
		seqSpec{seq: 1100, ack: 5001, flags: testpcap.ACK, payload: 1}, srvAck(1101, 2048),
		seqSpec{seq: 1100, ack: 5001, flags: testpcap.ACK, payload: 1}, srvAck(1101, 2048),
		seqSpec{seq: 1100, ack: 5001, flags: testpcap.ACK}, srvAck(1101, 2048))
	if n := len(dupEvents(ka)); n != 0 {
		t.Errorf("keep-alive exchange produced %d runs", n)
	}
	// user1-style: a connection with no data at all, both sides repeating pure ACKs.
	u := sc(t, dupPort, cliAck(5001, 2048), srvAck(1001, 16), cliAck(5001, 2048), srvAck(1001, 16), cliAck(5001, 2048), srvAck(1001, 16))
	if n := len(dupEvents(u)); n != 0 {
		t.Errorf("idle keep-alive-style ACK pairs produced %d runs", n)
	}
}

func TestDupRun_UnknownPeerSequenceStateNeverQualifies(t *testing.T) {
	// No handshake, no data from the peer: its sequence position is unknown.
	r := runGolden(t, frames(dupPort, srvAck(1101, 100), srvAck(1101, 100), srvAck(1101, 100), srvAck(1101, 100)))
	if n := len(dupEvents(r)); n != 0 {
		t.Errorf("duplicate ACKs without any peer sequence knowledge produced %d runs", n)
	}
	// The peer's only visible packet is a pure ACK: still no sequence position.
	r = runGolden(t, frames(dupPort, cliAck(5001, 100), srvAck(1101, 100), srvAck(1101, 100), srvAck(1101, 100)))
	if n := len(dupEvents(r)); n != 0 {
		t.Errorf("peer known only through ACKs produced %d runs", n)
	}
}

func TestDupRun_ReverseDirectionCorrectness(t *testing.T) {
	// Server data is outstanding; the CLIENT repeats its ACK.
	r := sc(t, dupPort, sData(5001, 50), sData(5051, 50),
		cliAck(5001, 100), cliAck(5001, 100), cliAck(5001, 100), cliAck(5001, 100))
	e := one(t, r)
	if e.FlowKey != "192.168.1.100:54000->10.0.0.50:443" || e.Values["ack"] != 5001 || e.Values["dup_count"] != 3 {
		t.Errorf("client dup-ACK run = %q %+v", e.FlowKey, e.Values)
	}
	// The ACK sender's OWN outstanding data does not count: the server has data
	// outstanding toward the client, but the client has sent nothing new, so the
	// server repeating its ACK (acking only the SYN) is idle.
	r = sc(t, dupPort, sData(5001, 50), sData(5051, 50), srvAck(1001, 100), srvAck(1001, 100), srvAck(1001, 100))
	if n := len(dupEvents(r)); n != 0 {
		t.Errorf("sender's own outstanding data created %d runs", n)
	}
}

func TestDupRun_SequenceWraparound(t *testing.T) {
	isn := uint32(0xFFFFFF00)
	specs := []seqSpec{
		{seq: isn, flags: testpcap.SYN},
		{fromServer: true, seq: 5000, ack: isn + 1, flags: testpcap.SYN | testpcap.ACK},
		{seq: isn + 1, ack: 5001, flags: testpcap.ACK},
		{seq: isn + 1, ack: 5001, flags: testpcap.PSH | testpcap.ACK, payload: 0x180}, // next = 0x81 after the wrap
	}
	ack := isn + 0x10 // before the wrap point
	for i := 0; i < 3; i++ {
		specs = append(specs, seqSpec{fromServer: true, seq: 5001, ack: ack, flags: testpcap.ACK, win: 100})
	}
	e := one(t, runGolden(t, frames(dupPort, specs...)))
	if e.Values["ack"] != float64(ack) || e.Values["dup_count"] != 2 {
		t.Errorf("wrap run = %+v", e.Values)
	}
	// ACK equal to the peer's next sequence (across the wrap) is NOT outstanding.
	specs = specs[:4]
	for i := 0; i < 3; i++ {
		specs = append(specs, seqSpec{fromServer: true, seq: 5001, ack: isn + 1 + 0x180, flags: testpcap.ACK, win: 100})
	}
	if n := len(dupEvents(runGolden(t, frames(dupPort, specs...)))); n != 0 {
		t.Errorf("ACK of everything across the wrap produced %d runs", n)
	}
}

func TestDupRun_SACKIsSupportingObservationOnly(t *testing.T) {
	edges := [][2]uint32{{1201, 1301}, {1401, 1501}, {1601, 1701}, {1801, 1901}} // RFC 2018 maximum of 4
	specs := append(outstandingData(), srvAck(1101, 100),
		srvSack(1101, 100, edges[:1]...), srvSack(1101, 100, edges[:2]...), srvSack(1101, 100, edges...))
	e := one(t, sc(t, dupPort, specs...))
	if e.Attrs["sack"] != "observed" || e.Values["sack_acks"] != 3 {
		t.Fatalf("sack = %+v %+v", e.Attrs, e.Values)
	}
	for i, want := range edges { // the most recent duplicate's edges
		l, r := "sack"+string(rune('0'+i))+"_left", "sack"+string(rune('0'+i))+"_right"
		if e.Values[l] != float64(want[0]) || e.Values[r] != float64(want[1]) {
			t.Errorf("edge %d = %v-%v, want %v", i, e.Values[l], e.Values[r], want)
		}
	}
	if _, ok := e.Values["sack4_left"]; ok {
		t.Error("more than 4 SACK edges recorded")
	}
	// SACK alone is not a duplicate ACK: SACK blocks on ACKs with a CHANGING ack number.
	r := sc(t, dupPort, append(outstandingData(), srvSack(1101, 100, edges[0]), srvSack(1151, 100, edges[0]), srvSack(1181, 100, edges[0]))...)
	if n := len(dupEvents(r)); n != 0 {
		t.Errorf("SACK on advancing ACKs produced %d runs", n)
	}
}

func TestDupRun_MultipleIndependentFlowsAndDirections(t *testing.T) {
	a := frames(dupPort, hs...)
	a = append(a, frames(dupPort, outstandingData()...)...)
	a = append(a, frames(dupPort, srvAck(1101, 100), srvAck(1101, 100), srvAck(1101, 100))...)
	b := frames(dupPort+1, hs...)
	b = append(b, frames(dupPort+1, sData(5001, 50), sData(5051, 50), cliAck(5001, 100), cliAck(5001, 100))...)
	r := runGolden(t, append(a, b...))
	ev := dupEvents(r)
	if len(ev) != 2 {
		t.Fatalf("events = %d, want 2: %+v", len(ev), ev)
	}
	if ev[0].FlowKey != "10.0.0.50:443->192.168.1.100:54000" || ev[1].FlowKey != "192.168.1.100:54001->10.0.0.50:443" {
		t.Errorf("flow keys / order = %q, %q", ev[0].FlowKey, ev[1].FlowKey)
	}
	if ev[0].Values["dup_count"] != 2 || ev[1].Values["dup_count"] != 1 {
		t.Errorf("dup counts = %v, %v", ev[0].Values["dup_count"], ev[1].Values["dup_count"])
	}
	if !ev[0].Timestamp.Before(ev[1].Timestamp) {
		t.Errorf("events not ordered by run start")
	}
}

func TestDupRun_DeterministicIDsOrderAndPacketRefs(t *testing.T) {
	build := func() [][]byte {
		var pk [][]byte
		for i := 0; i < 3; i++ {
			p := uint16(dupPort + 10 + i)
			pk = append(pk, frames(p, hs...)...)
			pk = append(pk, frames(p, outstandingData()...)...)
			pk = append(pk, frames(p, srvAck(1101, 100), srvAck(1101, 100), srvAck(1101, 100), srvAck(1201, 100))...)
		}
		return pk
	}
	snap := func() string {
		r := runGolden(t, build())
		type ev struct {
			ID     uint64
			Flow   string
			TS     time.Time
			Pk     []events.PacketRef
			Values map[string]float64
			Attrs  map[string]string
		}
		var out []ev
		for _, e := range dupEvents(r) {
			out = append(out, ev{e.ID, e.FlowKey, e.Timestamp, e.Packets, e.Values, e.Attrs})
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
	r := runGolden(t, build())
	var maxOther, minDup uint64 = 0, math.MaxUint64
	for _, e := range r.Events.Events() {
		if e.Kind == events.TCPDuplicateACKRun {
			if e.ID < minDup {
				minDup = e.ID
			}
		} else if e.ID > maxOther {
			maxOther = e.ID
		}
	}
	if len(dupEvents(r)) != 3 || minDup <= maxOther {
		t.Errorf("events=%d, duplicate-ACK IDs interleave with existing events (min %d, max other %d)", len(dupEvents(r)), minDup, maxOther)
	}
}

func TestDupRun_EventCapLeavesOtherEventsUntouched(t *testing.T) {
	data := func() [][]byte {
		pk := handshake(dupPort + 40)
		return append(pk, tcpC2S(dupPort+40, 1001, 2001, psh, payloadBytes(100)), tcpC2S(dupPort+40, 1001, 2001, psh, payloadBytes(100)))
	}
	base := runGolden(t, data())

	const runs = 10100
	storm := frames(dupPort, hs...)
	storm = append(storm, seqFrame(dupPort, cData(1001, 1400))) // peer next 2401: lots outstanding
	for i := 0; i < runs; i++ {
		ack := uint32(1101)
		if i%2 == 1 {
			ack = 1201
		}
		storm = append(storm, seqFrame(dupPort, srvAck(ack, 100)), seqFrame(dupPort, srvAck(ack, 100))) // initial + 1 duplicate; next pair changes the ack
	}
	r := runGolden(t, append(storm, data()...))
	if n := len(dupEvents(r)); n != 10000 {
		t.Fatalf("duplicate-ACK events = %d, want the 10,000 cap", n)
	}
	if r.EventsDropped != 0 {
		t.Errorf("EventsDropped = %d", r.EventsDropped)
	}
	if len(retxEvents(r)) != len(retxEvents(base)) || len(retxEvents(r)) != 1 || lostPackets(r) != lostPackets(base) {
		t.Errorf("legacy outputs changed")
	}
}

// Same packet count and timing, but every ACK number differs (no duplicates): any
// difference in the verdict layers or other evidence could only come from the new events.
func TestDupRun_NoEffectOnExistingOutputs(t *testing.T) {
	gapData := []seqSpec{cData(1001, 100), cData(1201, 100), cData(1301, 100)} // gap [1101,1201)
	with := sc(t, dupPort, append(append([]seqSpec{}, gapData...),
		srvAck(1101, 100), srvAck(1101, 100), srvAck(1101, 100), srvAck(1101, 100))...)
	ref := sc(t, dupPort, append(append([]seqSpec{}, gapData...),
		srvAck(1011, 100), srvAck(1021, 100), srvAck(1031, 100), srvAck(1041, 100))...)
	if len(dupEvents(with)) != 1 || len(dupEvents(ref)) != 0 {
		t.Fatalf("setup: runs %d (want 1) vs reference %d (want 0)", len(dupEvents(with)), len(dupEvents(ref)))
	}
	if with.NetworkHealth != ref.NetworkHealth || with.RiskScore != ref.RiskScore || len(with.Findings) != len(ref.Findings) ||
		len(with.RootCauseChains) != len(ref.RootCauseChains) || with.TopIssue != ref.TopIssue {
		t.Errorf("verdicts differ: health %q/%q risk %d/%d", with.NetworkHealth, ref.NetworkHealth, with.RiskScore, ref.RiskScore)
	}
	if len(retxEvents(with)) != len(retxEvents(ref)) || len(with.TCPRetransmissions) != len(ref.TCPRetransmissions) || lostPackets(with) != lostPackets(ref) {
		t.Errorf("retransmission/loss outputs differ")
	}
	gw, gr := gapEvents(with), gapEvents(ref)
	if len(gw) != 1 || len(gr) != 1 || gw[0].Attrs["resolution"] != gr[0].Attrs["resolution"] || gw[0].Values["gap_start"] != gr[0].Values["gap_start"] {
		t.Errorf("sequence-gap evidence differs: %+v vs %+v", gw, gr)
	}
	// A run can exist without any tracked gap, and a gap without any run.
	if len(gapEvents(sc(t, dupPort, append(outstandingData(), srvAck(1101, 100), srvAck(1101, 100))...))) != 0 {
		t.Error("a duplicate-ACK run created a gap event")
	}
	if len(dupEvents(sc(t, dupPort, gapData...))) != 0 {
		t.Error("a gap created a duplicate-ACK run")
	}
}

func TestDupRun_Lab3StyleGapSACKDuplicateAcksThenMissingSegment(t *testing.T) {
	sack := func(to uint32) seqSpec { return srvSack(1101, 17520, [2]uint32{1201, to}) }
	r := sc(t, dupPort,
		cData(1001, 100),    // 3
		srvAck(1101, 17520), // 4: the ACK that precedes the loss
		cData(1201, 100),    // 5: gap [1101,1201) exposed
		sack(1301),          // 6 duplicate 1
		cData(1301, 100),    // 7
		sack(1401),          // 8 duplicate 2
		cData(1401, 100),    // 9
		sack(1501),          // 10 duplicate 3
		cData(1101, 100),    // 11: the missing segment
		srvAck(1501, 17520),
	)
	e := one(t, r)
	if e.Values["dup_count"] != 3 || e.Attrs["consistent_with_fast_retransmit_trigger"] != "true" || e.Attrs["sack"] != "observed" ||
		e.Attrs["ended_by"] != "ack_changed" || e.Values["ack"] != 1101 {
		t.Fatalf("run = %+v %+v", e.Values, e.Attrs)
	}
	if e.Values["sack0_left"] != 1201 || e.Values["sack0_right"] != 1501 { // most recent duplicate
		t.Errorf("SACK edges = %v-%v", e.Values["sack0_left"], e.Values["sack0_right"])
	}
	// The gap event is independent and unchanged in meaning.
	g := gapEvents(r)
	if len(g) != 1 || g[0].Attrs["resolution"] != "filled" {
		t.Errorf("gap evidence = %+v", g)
	}
	if len(retxEvents(r)) != 0 || lostPackets(r) != 0 {
		t.Errorf("legacy retransmission/loss outputs changed")
	}
}

// ─── optional real captures ─────────────────────────────────────────────

// Measured with the Phase 4.30d build. Observations, not loss counts. tshark
// duplicate_ack for comparison: Lab 3 4 (equal), cisco-example-lan 16 (8 here),
// The-Ultimate-PCAP 77 (7 here), user1 53 (0), Velocloud-Lan 50 (0), Velocloud-Wan 35 (0):
// the surplus tshark counts are idle/keep-alive ACK repeats with no data outstanding
// (user1 frames 24/25/64/65 are 1-second ACK pairs) or lack peer sequence knowledge,
// which this model deliberately does not count.
func TestDupRun_RealCaptureBaseline(t *testing.T) {
	dir := os.Getenv("SDWAN_VENDOR_PCAP_DIR")
	if dir == "" {
		t.Skip("SDWAN_VENDOR_PCAP_DIR not set; skipping real-capture duplicate-ACK baseline")
	}
	type want struct{ runs, dups, thr, sack int }
	cases := []struct {
		name string
		w    want
	}{
		{"Lab 2-DisplayFilters", want{0, 0, 0, 0}},
		{"Lab 3-TCP Retrans", want{2, 4, 1, 2}},
		{"Lab 4-NetworkCongestion", want{0, 0, 0, 0}},
		{"Lab 5-AnotherSlowApp", want{0, 0, 0, 0}},
		{"Lab 6-TCPResets", want{0, 0, 0, 0}},
		{"Lab 7-TCPIssues", want{0, 0, 0, 0}},
		{"Pre-Lab-SlowNetwork", want{0, 0, 0, 0}},
		{"user1", want{0, 0, 0, 0}},
		{"Velocloud-Lan", want{0, 0, 0, 0}},
		{"Velocloud-Wan", want{0, 0, 0, 0}},
		{"cisco-example-lan", want{5, 8, 1, 5}},
		{"cisco-example-wan", want{0, 0, 0, 0}},
		{"The-Ultimate-PCAP", want{4, 7, 1, 3}},
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
			var got want
			for _, e := range dupEvents(r) {
				got.runs++
				got.dups += int(e.Values["dup_count"])
				if e.Attrs["consistent_with_fast_retransmit_trigger"] == "true" {
					got.thr++
				}
				if e.Attrs["sack"] == "observed" {
					got.sack++
				}
			}
			if got != c.w {
				t.Errorf("runs/duplicates/threshold-reached/with-SACK = %+v, want %+v", got, c.w)
			}
			if r.EventsDropped != 0 {
				t.Errorf("EventsDropped = %d", r.EventsDropped)
			}
		})
	}
}
