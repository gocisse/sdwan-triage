package analyzer

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gocisse/sdwan-triage/internal/testpcap"
	"github.com/gocisse/sdwan-triage/pkg/detector"
	"github.com/gocisse/sdwan-triage/pkg/events"
	"github.com/gocisse/sdwan-triage/pkg/models"
)

// Phase 4.30c — tcp.sequence_gap: OBSERVED forward sequence gaps with a resolution
// taken from what the capture itself shows. A gap is not proof of loss. Packets are
// 100 ms apart; the 3-packet handshake occupies ordinals 0-2, so the first data
// segment has ordinal 3. Helpers (seqFrame, cData, sAck, hs, sc ...) come from
// tcp_sequence_characterization_test.go.

const gapPort = 52000

func gapEvents(r *models.TriageReport) []events.Event { return r.Events.ByKind(events.TCPSequenceGap) }

func sData(seq uint32, n int) seqSpec {
	return seqSpec{fromServer: true, seq: seq, ack: 1001, flags: testpcap.PSH | testpcap.ACK, payload: n}
}
func cAck(ack uint32) seqSpec { return seqSpec{seq: 1001, ack: ack, flags: testpcap.ACK} }

func requireOne(t *testing.T, r *models.TriageReport) events.Event {
	t.Helper()
	ev := gapEvents(r)
	if len(ev) != 1 {
		t.Fatalf("tcp.sequence_gap events = %d, want 1: %+v", len(ev), ev)
	}
	return ev[0]
}

func TestGap_UnresolvedForwardGap(t *testing.T) {
	r := sc(t, gapPort, cData(1001, 100), cData(1301, 100))
	e := requireOne(t, r)
	if e.Values["gap_start"] != 1101 || e.Values["gap_end"] != 1301 || e.Values["gap_bytes"] != 200 ||
		e.Values["filled_bytes"] != 0 || e.Values["remaining_bytes"] != 200 {
		t.Errorf("values = %+v", e.Values)
	}
	if e.Attrs["resolution"] != "unresolved" || e.Attrs["baseline"] != "syn" || e.Attrs["limitation"] != "" {
		t.Errorf("attrs = %+v", e.Attrs)
	}
	if e.FlowKey != "192.168.1.100:52000->10.0.0.50:443" || e.Attrs["src_ip"] != "192.168.1.100" || e.Attrs["dst_ip"] != "10.0.0.50" {
		t.Errorf("flow/attrs = %q %+v", e.FlowKey, e.Attrs)
	}
	// Timestamp and packet reference are those of the segment that EXPOSED the gap
	// (ordinal 4, the second data segment); the ordinal is the recorder's, not a
	// Wireshark frame number.
	want := testpcap.BaseTime.Add(4 * testpcap.DefaultInterval)
	if !e.Timestamp.Equal(want) || len(e.Packets) != 1 || e.Packets[0].Index != 4 || !e.Packets[0].Timestamp.Equal(want) {
		t.Errorf("timestamp/packets = %v %+v, want ordinal 4 at %v", e.Timestamp, e.Packets, want)
	}
	if r.EventCounts["tcp.sequence_gap"] != 1 {
		t.Errorf("event_counts = %v", r.EventCounts)
	}
}

func TestGap_FilledCompletely(t *testing.T) {
	r := sc(t, gapPort, cData(1001, 100), cData(1301, 100), cData(1101, 200))
	e := requireOne(t, r)
	if e.Attrs["resolution"] != "filled" || e.Values["filled_bytes"] != 200 || e.Values["remaining_bytes"] != 0 {
		t.Fatalf("event = %+v %+v", e.Values, e.Attrs)
	}
	if math.Abs(e.Values["fill_delay_ms"]-100) > 0.5 { // fill at ordinal 5, gap seen at ordinal 4
		t.Errorf("fill_delay_ms = %v, want 100", e.Values["fill_delay_ms"])
	}
	// The gap keeps ITS OWN timestamp/packet (ordinal 4), not the filler's.
	if e.Packets[0].Index != 4 {
		t.Errorf("packet ref = %d, want 4 (the gap observation)", e.Packets[0].Index)
	}
	// No duplicate evidence for the same range.
	if len(gapEvents(r)) != 1 {
		t.Error("filling created a second event")
	}
}

func TestGap_PartialFillStaysUnresolvedThenFullFill(t *testing.T) {
	r := sc(t, gapPort, cData(1001, 100), cData(1301, 100), cData(1101, 100))
	e := requireOne(t, r)
	if e.Attrs["resolution"] != "unresolved" || e.Values["filled_bytes"] != 100 || e.Values["remaining_bytes"] != 100 || e.Values["gap_bytes"] != 200 {
		t.Fatalf("after a partial fill: %+v %+v", e.Values, e.Attrs)
	}
	// Middle fill splits the remainder; the event still describes one original gap.
	r = sc(t, gapPort, cData(1001, 100), cData(1301, 100), cData(1151, 50))
	e = requireOne(t, r)
	if e.Values["filled_bytes"] != 50 || e.Values["remaining_bytes"] != 150 || e.Attrs["resolution"] != "unresolved" {
		t.Errorf("after a middle fill: %+v %+v", e.Values, e.Attrs)
	}
	// Partial then the rest: only now is it filled.
	r = sc(t, gapPort, cData(1001, 100), cData(1301, 100), cData(1101, 100), cData(1201, 100))
	e = requireOne(t, r)
	if e.Attrs["resolution"] != "filled" || e.Values["filled_bytes"] != 200 || e.Values["remaining_bytes"] != 0 {
		t.Errorf("after both fills: %+v %+v", e.Values, e.Attrs)
	}
}

func TestGap_MultipleGapsOneSegmentFillsBoth_AndExtends(t *testing.T) {
	r := sc(t, gapPort,
		cData(1001, 100), // next 1101
		cData(1201, 100), // gap A [1101,1201)
		cData(1401, 100), // gap B [1301,1401), next 1501
		cData(1101, 450), // covers [1101,1551): both gaps and 50 new bytes (extends the highest position)
	)
	ev := gapEvents(r)
	if len(ev) != 2 {
		t.Fatalf("events = %d, want 2", len(ev))
	}
	for i, e := range ev {
		if e.Attrs["resolution"] != "filled" || e.Values["remaining_bytes"] != 0 {
			t.Errorf("gap %d = %+v %+v", i, e.Values, e.Attrs)
		}
	}
	if ev[0].Values["gap_start"] != 1101 || ev[1].Values["gap_start"] != 1301 {
		t.Errorf("creation order lost: %v, %v", ev[0].Values["gap_start"], ev[1].Values["gap_start"])
	}
	// The segment that extended the position leaves no gap behind it.
	r = sc(t, gapPort, cData(1001, 100), cData(1301, 100), cData(1101, 350))
	e := requireOne(t, r)
	if e.Attrs["resolution"] != "filled" {
		t.Errorf("fill + extend = %+v", e.Attrs)
	}
}

func TestGap_PureACKsAndKeepAlivesNeverCreateGaps(t *testing.T) {
	r := sc(t, gapPort,
		cData(1001, 100),
		seqSpec{seq: 1101, ack: 5001, flags: testpcap.ACK},             // normal ACK
		seqSpec{seq: 5000, ack: 5001, flags: testpcap.ACK},             // pure ACK with a wild sequence number
		seqSpec{seq: 1100, ack: 5001, flags: testpcap.ACK, payload: 1}, // keep-alive probe at next-1
		seqSpec{seq: 1100, ack: 5001, flags: testpcap.ACK},             // keep-alive ACK form
		sAck(1101, 0), sAck(1101, 0),
	)
	if n := len(gapEvents(r)); n != 0 {
		t.Errorf("ACK-only traffic produced %d gap events: %+v", n, gapEvents(r))
	}
}

func TestGap_SYNAndFINConsumeSequenceSpace(t *testing.T) {
	// Data right after the SYN's number is in order; skipping one more number is a 1-byte gap.
	if n := len(gapEvents(sc(t, gapPort, cData(1001, 10)))); n != 0 {
		t.Errorf("first data after the SYN produced %d gaps", n)
	}
	e := requireOne(t, sc(t, gapPort, cData(1002, 10)))
	if e.Values["gap_start"] != 1001 || e.Values["gap_bytes"] != 1 {
		t.Errorf("gap after SYN = %+v", e.Values)
	}
	// FIN consumes one number: 1001 (10 bytes) + FIN at 1011 => next 1012.
	fin := seqSpec{seq: 1011, ack: 5001, flags: testpcap.FIN | testpcap.ACK}
	if n := len(gapEvents(sc(t, gapPort, cData(1001, 10), fin, cData(1012, 5)))); n != 0 {
		t.Errorf("segment right after the FIN produced %d gaps", n)
	}
	e = requireOne(t, sc(t, gapPort, cData(1001, 10), fin, cData(1013, 5)))
	if e.Values["gap_start"] != 1012 || e.Values["gap_end"] != 1013 {
		t.Errorf("gap after FIN = %+v", e.Values)
	}
	// A repeated SYN is a repeat, never a gap.
	pk := append(frames(gapPort, hs[0], hs[0], hs[1], hs[2]), frames(gapPort, cData(1001, 10))...)
	if n := len(gapEvents(runGolden(t, pk))); n != 0 {
		t.Errorf("repeated SYN produced %d gaps", n)
	}
}

func TestGap_SequenceWraparound(t *testing.T) {
	// Client ISN just below 2^32; the gap straddles the wrap.
	isn := uint32(0xFFFFFF00)
	specs := []seqSpec{
		{seq: isn, flags: testpcap.SYN},
		{fromServer: true, seq: 5000, ack: isn + 1, flags: testpcap.SYN | testpcap.ACK},
		{seq: isn + 1, ack: 5001, flags: testpcap.ACK},
		{seq: isn + 1, ack: 5001, flags: testpcap.PSH | testpcap.ACK, payload: 0x80},         // next 0xFFFFFF81
		{seq: isn + 1 + 0x100, ack: 5001, flags: testpcap.PSH | testpcap.ACK, payload: 0x10}, // starts 0x100 beyond: past the wrap
	}
	r := runGolden(t, frames(gapPort, specs...))
	e := requireOne(t, r)
	if e.Values["gap_start"] != float64(isn+1+0x80) || e.Values["gap_end"] != float64(isn+1+0x100) || e.Values["gap_bytes"] != 0x80 {
		t.Errorf("wrap gap = %+v", e.Values)
	}
	// Fill it after the wrap.
	specs = append(specs, seqSpec{seq: isn + 1 + 0x80, ack: 5001, flags: testpcap.PSH | testpcap.ACK, payload: 0x80})
	e = requireOne(t, runGolden(t, frames(gapPort, specs...)))
	if e.Attrs["resolution"] != "filled" {
		t.Errorf("wrap gap not filled: %+v", e.Attrs)
	}
}

func TestGap_DirectionsAreIndependent(t *testing.T) {
	r := sc(t, gapPort,
		cData(1001, 100), cData(1301, 100), // client gap
		seqSpec{fromServer: true, seq: 5001, ack: 1101, flags: testpcap.PSH | testpcap.ACK, payload: 50},
		seqSpec{fromServer: true, seq: 5051, ack: 1101, flags: testpcap.PSH | testpcap.ACK, payload: 50}, // in order: none
	)
	e := requireOne(t, r)
	if e.FlowKey != "192.168.1.100:52000->10.0.0.50:443" {
		t.Errorf("gap attributed to %q", e.FlowKey)
	}
	// And a gap in the server direction only.
	r = sc(t, gapPort, cData(1001, 100), cData(1101, 100),
		sData(5001, 50), sData(5201, 50))
	e = requireOne(t, r)
	if e.FlowKey != "10.0.0.50:443->192.168.1.100:52000" || e.Values["gap_start"] != 5051 {
		t.Errorf("server gap = %q %+v", e.FlowKey, e.Values)
	}
}

// ─── resolution by peer ACK ─────────────────────────────────────────────

func TestGap_AckedBeyondIsEvidenceOfAcknowledgementOnly(t *testing.T) {
	// Peer ACK reaching the gap end although the range was never observed.
	r := sc(t, gapPort, cData(1001, 100), cData(1301, 100), sAck(1401, 0))
	e := requireOne(t, r)
	if e.Attrs["resolution"] != "acked_beyond" || e.Values["remaining_bytes"] != 200 || e.Values["acked_ts_us"] == 0 {
		t.Fatalf("acked-beyond = %+v %+v", e.Values, e.Attrs)
	}
	// An ACK that reaches exactly the gap end counts; one that stops short does not.
	if e = requireOne(t, sc(t, gapPort, cData(1001, 100), cData(1301, 100), sAck(1301, 0))); e.Attrs["resolution"] != "acked_beyond" {
		t.Errorf("ACK at the gap end = %+v", e.Attrs)
	}
	if e = requireOne(t, sc(t, gapPort, cData(1001, 100), cData(1301, 100), sAck(1201, 0), sAck(1101, 0))); e.Attrs["resolution"] != "unresolved" {
		t.Errorf("ACK short of the gap end = %+v", e.Attrs)
	}
	// A later complete fill wins over an earlier ACK (the range WAS observed).
	if e = requireOne(t, sc(t, gapPort, cData(1001, 100), cData(1301, 100), sAck(1401, 0), cData(1101, 200))); e.Attrs["resolution"] != "filled" {
		t.Errorf("fill after ACK = %+v", e.Attrs)
	}
	// An ACK in the SAME direction as the data never counts as acknowledgement.
	if e = requireOne(t, sc(t, gapPort, cData(1001, 100), cData(1301, 100), seqSpec{seq: 1401, ack: 9999, flags: testpcap.ACK})); e.Attrs["resolution"] != "unresolved" {
		t.Errorf("same-direction ACK counted: %+v", e.Attrs)
	}
}

func TestGap_Lab3StylePattern_GapDupAcksSACKThenMissingSegment(t *testing.T) {
	sackAck := func(to uint32) seqSpec {
		return seqSpec{fromServer: true, seq: 5001, ack: 1101, flags: testpcap.ACK, win: 17520, sack: [][2]uint32{{1201, to}}}
	}
	r := sc(t, gapPort,
		cData(1001, 100), // 3
		cData(1201, 100), // 4: gap [1101,1201) exposed
		sackAck(1301),    // 5
		cData(1301, 100), // 6
		sackAck(1401),    // 7
		cData(1401, 100), // 8
		sackAck(1501),    // 9
		cData(1101, 100), // 10: the missing segment finally appears
		sAck(1501, 0),
	)
	e := requireOne(t, r)
	if e.Attrs["resolution"] != "filled" || e.Values["gap_start"] != 1101 || e.Values["gap_end"] != 1201 || e.Packets[0].Index != 4 {
		t.Fatalf("event = %+v %+v %+v", e.Values, e.Attrs, e.Packets)
	}
	if math.Abs(e.Values["fill_delay_ms"]-600) > 0.5 { // ordinal 10 - ordinal 4
		t.Errorf("fill_delay_ms = %v, want 600", e.Values["fill_delay_ms"])
	}
	// The existing outputs for this pattern are unchanged (4.30a): nothing else is reported.
	if len(retxEvents(r)) != 0 || lostPackets(r) != 0 || len(r.TCPRetransmissions) != 0 {
		t.Errorf("legacy retransmission/loss outputs changed")
	}
}

// ─── lifecycle, limits, truncation, determinism ─────────────────────────

func TestGap_RSTEndsTrackingAndRebaselines(t *testing.T) {
	r := sc(t, gapPort,
		cData(1001, 100), cData(1301, 100), // gap
		seqSpec{fromServer: true, seq: 5001, ack: 1401, flags: testpcap.RST | testpcap.ACK},
		cData(9001, 100), cData(9101, 100), // new baseline after the RST: no gap invented
	)
	e := requireOne(t, r)
	if e.Attrs["limitation"] != "rst" || e.Attrs["resolution"] != "unresolved" {
		t.Errorf("gap at RST = %+v", e.Attrs)
	}
}

func TestGap_NewISNOnSameTupleClosesOldGaps(t *testing.T) {
	pk := frames(gapPort, hs...)
	pk = append(pk, frames(gapPort, cData(1001, 100), cData(1301, 100))...)        // gap
	pk = append(pk, frames(gapPort, seqSpec{seq: 777000, flags: testpcap.SYN})...) // tuple reuse, new ISN
	pk = append(pk, frames(gapPort, cData(777001, 10))...)
	e := requireOne(t, runGolden(t, pk))
	if e.Attrs["limitation"] != "restart" {
		t.Errorf("old gap at restart = %+v", e.Attrs)
	}
}

func TestGap_FlowStateEvictionIsReportedAsALimitation(t *testing.T) {
	// A bounded state holding a single flow: any packet of another direction evicts it.
	a := detector.NewTCPAnalyzer()
	state := models.NewBoundedAnalysisState(1, 10)
	ix := events.NewIndex(0)
	rec := events.NewRecorder(ix, "")
	report := &models.TriageReport{Events: ix, Emitter: rec}
	feed := func(i int, port uint16, s seqSpec) {
		b := seqFrame(port, s)
		p := pktAt(b, i)
		rec.SetCurrentPacket(uint64(i), p.Metadata().Timestamp)
		a.Analyze(p, state, report)
	}
	feed(0, 53000, hs[0])
	feed(1, 53000, cData(1001, 100))
	feed(2, 53000, cData(1301, 100)) // gap on flow A
	feed(3, 53001, cData(7001, 10))  // another flow evicts A's direction state
	feed(4, 53000, cData(1401, 100)) // A again: fresh state => baseline, not a new gap
	a.Finalize(report)
	ev := ix.ByKind(events.TCPSequenceGap)
	if len(ev) != 1 || ev[0].Attrs["limitation"] != "state_lost" || ev[0].Attrs["resolution"] != "unresolved" {
		t.Fatalf("events after eviction = %+v", ev)
	}
}

func TestGap_PerDirectionCapIsExplicitNotLoss(t *testing.T) {
	var specs []seqSpec
	seq := uint32(1001)
	specs = append(specs, cData(seq, 10))
	seq += 10
	for i := 0; i < models.MaxOpenSeqGaps+4; i++ {
		seq += 10 // 10-byte hole
		specs = append(specs, cData(seq, 10))
		seq += 10
	}
	r := sc(t, gapPort, specs...)
	ev := gapEvents(r)
	if len(ev) != models.MaxOpenSeqGaps+4 {
		t.Fatalf("events = %d, want %d (every observed gap is recorded)", len(ev), models.MaxOpenSeqGaps+4)
	}
	capped := 0
	for _, e := range ev {
		if e.Attrs["limitation"] == "tracking_cap" {
			capped++
			if e.Attrs["resolution"] != "unresolved" {
				t.Errorf("a capped gap claims %q", e.Attrs["resolution"])
			}
		}
	}
	if capped != 4 {
		t.Errorf("capped events = %d, want 4", capped)
	}
}

func TestGap_ExpiredGapIsALimitation(t *testing.T) {
	// The second segment jumps 2^30-500 bytes ahead and is 400 bytes long: the
	// position then sits more than 2^30 beyond the first gap's start (expired) but
	// less than 2^30 beyond the new gap's start (kept).
	r := sc(t, gapPort,
		cData(1001, 100),
		cData(1201, 100), // gap [1101,1201)
		cData(1301+uint32(1<<30)-500, 400),
	)
	ev := gapEvents(r)
	if len(ev) != 2 {
		t.Fatalf("events = %d, want 2", len(ev))
	}
	if ev[0].Attrs["limitation"] != "expired" || ev[0].Attrs["resolution"] != "unresolved" {
		t.Errorf("expired gap = %+v", ev[0].Attrs)
	}
	if ev[1].Attrs["limitation"] != "" {
		t.Errorf("new gap carries limitation %q", ev[1].Attrs["limitation"])
	}
}

func TestGap_MidstreamCaptureBaselineAndLimitation(t *testing.T) {
	// No SYN: the first segment only sets the baseline; a later jump is a gap marked midstream.
	pk := frames(gapPort,
		cData(9_000_001, 100), cData(9_000_101, 100), cData(9_000_401, 100))
	e := requireOne(t, runGolden(t, pk))
	if e.Attrs["baseline"] != "midstream" || e.Values["gap_start"] != 9_000_201 || e.Values["gap_end"] != 9_000_401 {
		t.Errorf("midstream gap = %+v %+v", e.Values, e.Attrs)
	}
	// A single segment can never produce a gap.
	if n := len(gapEvents(runGolden(t, frames(gapPort, cData(123456, 10))))); n != 0 {
		t.Errorf("first segment produced %d gaps", n)
	}
}

// pcap with a snap length smaller than the frames (caplen < origlen).
func truncatedPCAP(t *testing.T, frs [][]byte, snap int) string {
	t.Helper()
	var b bytes.Buffer
	h := make([]byte, 24)
	binary.LittleEndian.PutUint32(h[0:], 0xa1b2c3d4)
	binary.LittleEndian.PutUint16(h[4:], 2)
	binary.LittleEndian.PutUint16(h[6:], 4)
	binary.LittleEndian.PutUint32(h[16:], uint32(snap))
	binary.LittleEndian.PutUint32(h[20:], 1)
	b.Write(h)
	for i, f := range frs {
		ts := testpcap.BaseTime.Add(time.Duration(i) * testpcap.DefaultInterval)
		cl := len(f)
		if cl > snap {
			cl = snap
		}
		rh := make([]byte, 16)
		binary.LittleEndian.PutUint32(rh[0:], uint32(ts.Unix()))
		binary.LittleEndian.PutUint32(rh[4:], uint32(ts.Nanosecond()/1000))
		binary.LittleEndian.PutUint32(rh[8:], uint32(cl))
		binary.LittleEndian.PutUint32(rh[12:], uint32(len(f)))
		b.Write(rh)
		b.Write(f[:cl])
	}
	p := filepath.Join(t.TempDir(), "trunc.pcap")
	if err := os.WriteFile(p, b.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// Snap-length truncation shortens len(tcp.Payload) but not the real segment length.
// Using the captured length would invent a gap after every segment (seen on Lab 5).
func TestGap_TruncatedCaptureUsesDeclaredLength(t *testing.T) {
	var specs []seqSpec
	seq := uint32(1001)
	for i := 0; i < 6; i++ {
		specs = append(specs, cData(seq, 1400)) // contiguous 1400-byte segments
		seq += 1400
	}
	frs := append(frames(gapPort, hs...), frames(gapPort, specs...)...)
	path := truncatedPCAP(t, frs, 120) // only headers + a few payload bytes captured
	r := runPCAPFile(t, path, NewProcessorWithOptions(false, false))
	if n := len(gapEvents(r)); n != 0 {
		t.Errorf("truncated but contiguous segments produced %d gap events: %+v", n, gapEvents(r))
	}
	// A REAL gap in a truncated capture is still seen.
	specs = specs[:3]
	specs = append(specs, cData(seq+1400, 1400))
	frs = append(frames(gapPort, hs...), frames(gapPort, specs...)...)
	r = runPCAPFile(t, truncatedPCAP(t, frs, 120), NewProcessorWithOptions(false, false))
	if len(gapEvents(r)) != 1 {
		t.Errorf("real gap in a truncated capture: events = %d, want 1", len(gapEvents(r)))
	}
}

func TestGap_DeterministicEventsIDsAndPacketRefs(t *testing.T) {
	build := func() [][]byte {
		return append(frames(gapPort, hs...), frames(gapPort,
			cData(1001, 100), cData(1301, 100), cData(1101, 100), cData(1501, 50), cData(1401, 100), sAck(1551, 0))...)
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
		for _, e := range gapEvents(r) {
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
	// New events come after every other event: existing IDs stay dense from 1.
	r := runGolden(t, build())
	var maxOther, minGap uint64 = 0, math.MaxUint64
	for _, e := range r.Events.Events() {
		if e.Kind == events.TCPSequenceGap {
			if e.ID < minGap {
				minGap = e.ID
			}
		} else if e.ID > maxOther {
			maxOther = e.ID
		}
	}
	if minGap <= maxOther {
		t.Errorf("gap event IDs interleave with existing events (min gap %d, max other %d)", minGap, maxOther)
	}
}

func TestGap_EventCapLeavesOtherEventsUntouched(t *testing.T) {
	data := func() [][]byte {
		pk := handshake(gapPort + 1)
		return append(pk, tcpC2S(gapPort+1, 1001, 2001, psh, payloadBytes(100)), tcpC2S(gapPort+1, 1001, 2001, psh, payloadBytes(100)))
	}
	base := runGolden(t, data())

	const gaps = 10100
	storm := make([][]byte, 0, gaps+3)
	storm = append(storm, frames(gapPort, hs...)...)
	seq := uint32(1001)
	for i := 0; i < gaps; i++ {
		seq += 20 // 10 byte hole + 10 byte segment each time
		storm = append(storm, seqFrame(gapPort, cData(seq, 10)))
	}
	r := runGolden(t, append(storm, data()...))
	if n := len(gapEvents(r)); n != 10000 {
		t.Fatalf("gap events = %d, want the 10,000 cap", n)
	}
	if r.EventsDropped != 0 {
		t.Errorf("EventsDropped = %d, want 0", r.EventsDropped)
	}
	if len(retxEvents(r)) != len(retxEvents(base)) || len(retxEvents(r)) != 1 || lostPackets(r) != lostPackets(base) {
		t.Errorf("legacy outputs changed: retx %d/%d lost %d/%d", len(retxEvents(r)), len(retxEvents(base)), lostPackets(r), lostPackets(base))
	}
}

// The verdict layers must not react to gap evidence. The reference run has the same
// number of packets with the same timing but contiguous sequence numbers (so no gap),
// which makes any difference attributable to the gap events alone. (The synthetic
// 100 ms spacing itself makes the legacy RTT logic report "fair"; that is identical
// in both runs.)
func TestGap_NoHealthRiskOrFindingsEffect(t *testing.T) {
	withGaps := sc(t, gapPort, cData(1001, 100), cData(1301, 100), cData(2001, 100))
	reference := sc(t, gapPort, cData(1001, 100), cData(1101, 100), cData(1201, 100))
	if len(gapEvents(withGaps)) == 0 || len(gapEvents(reference)) != 0 {
		t.Fatalf("setup: gap events %d (want >0) vs reference %d (want 0)", len(gapEvents(withGaps)), len(gapEvents(reference)))
	}
	if withGaps.NetworkHealth != reference.NetworkHealth || withGaps.RiskScore != reference.RiskScore ||
		len(withGaps.Findings) != len(reference.Findings) || len(withGaps.RootCauseChains) != len(reference.RootCauseChains) ||
		len(withGaps.RTTAnalysis) != len(reference.RTTAnalysis) || withGaps.TopIssue != reference.TopIssue {
		t.Errorf("verdicts differ: health %q/%q risk %d/%d findings %d/%d chains %d/%d top %q/%q",
			withGaps.NetworkHealth, reference.NetworkHealth, withGaps.RiskScore, reference.RiskScore,
			len(withGaps.Findings), len(reference.Findings), len(withGaps.RootCauseChains), len(reference.RootCauseChains),
			withGaps.TopIssue, reference.TopIssue)
	}
	if len(retxEvents(withGaps)) != 0 || len(withGaps.TCPRetransmissions) != 0 || lostPackets(withGaps) != 0 {
		t.Errorf("gaps changed retransmission/loss outputs")
	}
}

// ─── optional real-capture characterization ─────────────────────────────

// Measured with the Phase 4.30c build. They are OBSERVATIONS, not loss counts.
// tshark comparison (tcp.analysis.lost_segment): Lab 3 1, Lab 4 1 (visible only as a
// pure-ACK sequence jump, which this phase deliberately ignores), The-Ultimate-PCAP
// 32 (31 payload gaps here + 2 pure-ACK jumps ignored); user1/Velocloud tshark
// "lost" flags are not payload gaps (keep-alive related) and produce none here;
// cisco-example-lan is a partial/one-sided capture with thousands of gaps, most
// acknowledged beyond by the peer (the capture missed them).
func TestGap_RealCaptureBaseline(t *testing.T) {
	dir := os.Getenv("SDWAN_VENDOR_PCAP_DIR")
	if dir == "" {
		t.Skip("SDWAN_VENDOR_PCAP_DIR not set; skipping real-capture sequence-gap baseline")
	}
	type want struct{ total, filled, acked, unresolved int }
	cases := []struct {
		name string
		w    want
	}{
		{"Lab 2-DisplayFilters", want{3, 0, 3, 0}},
		{"Lab 3-TCP Retrans", want{1, 1, 0, 0}},
		{"Lab 4-NetworkCongestion", want{0, 0, 0, 0}},
		{"Lab 5-AnotherSlowApp", want{0, 0, 0, 0}},
		{"Lab 6-TCPResets", want{0, 0, 0, 0}},
		{"Lab 7-TCPIssues", want{0, 0, 0, 0}},
		{"Pre-Lab-SlowNetwork", want{0, 0, 0, 0}},
		{"user1", want{0, 0, 0, 0}},
		{"Velocloud-Lan", want{0, 0, 0, 0}},
		{"Velocloud-Wan", want{0, 0, 0, 0}},
		{"cisco-example-lan", want{2349, 0, 1964, 385}},
		{"cisco-example-wan", want{0, 0, 0, 0}},
		{"The-Ultimate-PCAP", want{31, 13, 14, 4}},
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
			for _, e := range gapEvents(r) {
				got.total++
				switch e.Attrs["resolution"] {
				case "filled":
					got.filled++
				case "acked_beyond":
					got.acked++
				default:
					got.unresolved++
				}
			}
			if got != c.w {
				t.Errorf("gap events total/filled/acked_beyond/unresolved = %+v, want %+v", got, c.w)
			}
			if r.EventsDropped != 0 {
				t.Errorf("EventsDropped = %d", r.EventsDropped)
			}
		})
	}
}
