package models

import (
	"fmt"
	"reflect"
	"testing"
	"time"
)

// Phase 4.30b: transitions and boundaries of the shared sequence state. Nothing
// here depends on the analysis pipeline; the model is not wired into it yet.

var seqT0 = time.Unix(1_700_000_000, 0)

func at(i int) time.Time { return seqT0.Add(time.Duration(i) * 100 * time.Millisecond) }

func seg(d *TCPSeqDir, seq uint32, n int, i int) SeqObservation {
	return d.ObserveSegment(seq, SeqConsumed(n, false, false), false, false, at(i), uint64(i))
}

func gapsOf(d *TCPSeqDir) [][2]uint32 {
	var out [][2]uint32
	for _, g := range d.OpenGaps() {
		out = append(out, [2]uint32{g.Start, g.End})
	}
	return out
}

func TestSeqConsumed_CountsSYNAndFIN(t *testing.T) {
	cases := []struct {
		n        int
		syn, fin bool
		want     uint32
	}{{0, false, false, 0}, {100, false, false, 100}, {0, true, false, 1}, {0, false, true, 1}, {10, true, true, 12}, {-5, false, false, 0}}
	for _, c := range cases {
		if got := SeqConsumed(c.n, c.syn, c.fin); got != c.want {
			t.Errorf("SeqConsumed(%d,%v,%v) = %d, want %d", c.n, c.syn, c.fin, got, c.want)
		}
	}
}

func TestSeqDir_FirstObservationSetsBaseline_NoGapBeforeIt(t *testing.T) {
	var d TCPSeqDir
	if _, ok := d.HighestNext(); ok {
		t.Fatal("a fresh direction must have no baseline")
	}
	// Midstream capture: first usable segment is at an arbitrary sequence number.
	r := seg(&d, 9_000_000, 100, 0)
	if r.Class != SeqBaseline || r.GapOpened || len(d.OpenGaps()) != 0 {
		t.Fatalf("first segment = %+v, want baseline with no gap", r)
	}
	if hn, ok := d.HighestNext(); !ok || hn != 9_000_100 {
		t.Errorf("highest next = %d,%v, want 9000100,true", hn, ok)
	}
}

func TestSeqDir_PureACKBeforeBaselineDoesNotSetItAndNeverOpensAGap(t *testing.T) {
	var d TCPSeqDir
	if r := d.ObserveSegment(5000, 0, false, false, at(0), 0); r.Class != SeqNoSequenceSpace || r.Ahead != 0 {
		t.Fatalf("pure ACK before baseline = %+v", r)
	}
	if _, ok := d.HighestNext(); ok {
		t.Fatal("a pure ACK must not set the baseline")
	}
	seg(&d, 1000, 100, 1) // baseline 1100
	// Pure ACK whose sequence is beyond highest-next: reported as Ahead, no state change.
	r := d.ObserveSegment(1500, 0, false, false, at(2), 2)
	if r.Class != SeqNoSequenceSpace || r.Ahead != 400 || r.GapOpened || len(d.OpenGaps()) != 0 {
		t.Errorf("pure ACK ahead = %+v", r)
	}
	if hn, _ := d.HighestNext(); hn != 1100 {
		t.Errorf("a pure ACK moved highest next to %d", hn)
	}
	// A pure ACK at or behind highest-next is not "ahead".
	if r := d.ObserveSegment(1099, 0, false, false, at(3), 3); r.Ahead != 0 {
		t.Errorf("keep-alive-position ACK reported Ahead=%d", r.Ahead)
	}
}

func TestSeqDir_InOrderAdvancement(t *testing.T) {
	var d TCPSeqDir
	seg(&d, 1000, 100, 0)
	for i, seq := range []uint32{1100, 1200, 1300} {
		r := seg(&d, seq, 100, i+1)
		if r.Class != SeqInOrder || !r.ExtendsHighest || r.GapOpened {
			t.Fatalf("segment %d = %+v", seq, r)
		}
	}
	if hn, _ := d.HighestNext(); hn != 1400 || len(d.OpenGaps()) != 0 {
		t.Errorf("highest next %d gaps %v", hn, gapsOf(&d))
	}
}

func TestSeqDir_ForwardGapThenFillAndPartialFill(t *testing.T) {
	var d TCPSeqDir
	seg(&d, 1000, 100, 0) // next 1100
	r := seg(&d, 1500, 100, 1)
	if r.Class != SeqForwardGap || !r.GapOpened || r.Gap.Start != 1100 || r.Gap.End != 1500 || r.Gap.Bytes() != 400 || r.Gap.Packet != 1 {
		t.Fatalf("forward gap = %+v", r)
	}
	if !r.Gap.ObservedAt.Equal(at(1)) {
		t.Errorf("gap ObservedAt = %v", r.Gap.ObservedAt)
	}
	if hn, _ := d.HighestNext(); hn != 1600 {
		t.Errorf("highest next after gap = %d, want 1600", hn)
	}
	// Partial fill from the left edge: [1100,1200) covered, [1200,1500) remains.
	r = seg(&d, 1100, 100, 2)
	if r.Class != SeqFillsGap || r.FilledBytes != 100 || len(r.Filled) != 0 || !reflect.DeepEqual(gapsOf(&d), [][2]uint32{{1200, 1500}}) {
		t.Fatalf("partial fill = %+v gaps %v", r, gapsOf(&d))
	}
	// A fill in the middle splits the gap in two.
	r = seg(&d, 1300, 100, 3)
	if r.Class != SeqFillsGap || r.FilledBytes != 100 || !reflect.DeepEqual(gapsOf(&d), [][2]uint32{{1200, 1300}, {1400, 1500}}) {
		t.Fatalf("middle fill = %+v gaps %v", r, gapsOf(&d))
	}
	// Closing both remaining pieces; the closed gaps are reported with their original packet.
	if r = seg(&d, 1200, 100, 4); len(r.Filled) != 1 || r.Filled[0].Start != 1200 || r.Filled[0].End != 1300 {
		t.Fatalf("closing fill = %+v", r)
	}
	r = seg(&d, 1400, 100, 5)
	if len(r.Filled) != 1 || r.Filled[0].Start != 1400 || r.Filled[0].Packet != 1 || len(d.OpenGaps()) != 0 {
		t.Fatalf("final fill = %+v gaps %v", r, gapsOf(&d))
	}
	// highest next never moved backwards
	if hn, _ := d.HighestNext(); hn != 1600 {
		t.Errorf("highest next = %d, want 1600", hn)
	}
}

func TestSeqDir_OneSegmentCanCloseSeveralGapsAndExtend(t *testing.T) {
	var d TCPSeqDir
	seg(&d, 1000, 100, 0)      // 1100
	seg(&d, 1200, 100, 1)      // gap [1100,1200); next 1300
	seg(&d, 1400, 100, 2)      // gap [1300,1400); next 1500
	r := seg(&d, 1100, 450, 3) // covers [1100,1550): both gaps and 50 new bytes
	if r.Class != SeqFillsGap || len(r.Filled) != 2 || r.FilledBytes != 200 || !r.ExtendsHighest {
		t.Fatalf("multi-gap fill = %+v", r)
	}
	if hn, _ := d.HighestNext(); hn != 1550 || len(d.OpenGaps()) != 0 {
		t.Errorf("highest next %d gaps %v", hn, gapsOf(&d))
	}
}

func TestSeqDir_RepeatsOverlapsAndOutOfOrder(t *testing.T) {
	var d TCPSeqDir
	seg(&d, 1000, 100, 0)
	seg(&d, 1100, 100, 1) // next 1200
	if r := seg(&d, 1000, 100, 2); r.Class != SeqRepeat || r.ExtendsHighest || len(r.Filled) != 0 {
		t.Errorf("exact repeated start = %+v, want SeqRepeat", r)
	}
	if r := seg(&d, 1050, 100, 3); r.Class != SeqRepeat {
		t.Errorf("segment inside covered space = %+v, want SeqRepeat", r)
	}
	// Starts behind, extends beyond: partial overlap with 50 new bytes.
	if r := seg(&d, 1150, 100, 4); r.Class != SeqPartialOverlap || !r.ExtendsHighest {
		t.Errorf("partial overlap = %+v", r)
	}
	if hn, _ := d.HighestNext(); hn != 1250 {
		t.Errorf("highest next = %d, want 1250", hn)
	}
	// Out-of-order WITHOUT a missing range: successor arrives first, predecessor later.
	var o TCPSeqDir
	seg(&o, 1000, 100, 0)
	if r := seg(&o, 1200, 100, 1); r.Class != SeqForwardGap {
		t.Fatalf("successor first = %+v", r)
	}
	if r := seg(&o, 1100, 100, 2); r.Class != SeqFillsGap || len(r.Filled) != 1 {
		t.Fatalf("predecessor later = %+v", r)
	}
	if len(o.OpenGaps()) != 0 {
		t.Errorf("gap left open after the predecessor arrived: %v", gapsOf(&o))
	}
}

func TestSeqDir_WraparoundAcross2To32(t *testing.T) {
	const base = uint32(0xFFFFFF00)
	var d TCPSeqDir
	seg(&d, base, 0x80, 0) // next 0xFFFFFF80
	// In order across the wrap boundary.
	if r := seg(&d, base+0x80, 0x100, 1); r.Class != SeqInOrder { // ends at 0x80 after the wrap
		t.Fatalf("segment spanning the wrap = %+v", r)
	}
	if hn, _ := d.HighestNext(); hn != 0x80 {
		t.Fatalf("highest next across wrap = %#x, want 0x80", hn)
	}
	// Forward gap whose range straddles the wrap.
	r := seg(&d, 0x200, 0x10, 2)
	if r.Class != SeqForwardGap || r.Gap.Start != 0x80 || r.Gap.End != 0x200 {
		t.Fatalf("gap after the wrap = %+v", r)
	}
	// A fill and a repeat located before the wrap point still order correctly.
	if r := seg(&d, 0x80, 0x180, 3); r.Class != SeqFillsGap || len(r.Filled) != 1 {
		t.Errorf("fill after wrap = %+v", r)
	}
	if r := seg(&d, base, 0x80, 4); r.Class != SeqRepeat {
		t.Errorf("repeat of pre-wrap data = %+v, want SeqRepeat", r)
	}
	// A gap opened BEFORE the wrap and closed AFTER it.
	var e TCPSeqDir
	seg(&e, 0xFFFFFFF0, 0x8, 0)  // next 0xFFFFFFF8
	seg(&e, 0xFFFFFFFC, 0x10, 1) // gap [0xFFFFFFF8,0xFFFFFFFC); next 0xC
	if g := e.OpenGaps(); len(g) != 1 || g[0].Start != 0xFFFFFFF8 || g[0].End != 0xFFFFFFFC {
		t.Fatalf("pre-wrap gap = %v", g)
	}
	if r := seg(&e, 0xFFFFFFF8, 0x4, 2); len(r.Filled) != 1 {
		t.Errorf("fill of the pre-wrap gap = %+v", r)
	}
}

func TestSeqDir_SYNAndFINConsumeSequenceSpace(t *testing.T) {
	var d TCPSeqDir
	// SYN at ISN 1000 consumes one number: the first data byte is 1001, in order.
	if r := d.ObserveSegment(1000, SeqConsumed(0, true, false), true, false, at(0), 0); r.Class != SeqBaseline {
		t.Fatalf("SYN = %+v", r)
	}
	if hn, _ := d.HighestNext(); hn != 1001 {
		t.Fatalf("highest next after SYN = %d, want 1001", hn)
	}
	if r := seg(&d, 1001, 50, 1); r.Class != SeqInOrder {
		t.Errorf("first data after SYN = %+v", r)
	}
	// FIN with 10 bytes of payload consumes 11.
	r := d.ObserveSegment(1051, SeqConsumed(10, false, true), false, true, at(2), 2)
	if r.Class != SeqInOrder || !d.FinSeen() {
		t.Fatalf("FIN segment = %+v finSeen=%v", r, d.FinSeen())
	}
	if hn, _ := d.HighestNext(); hn != 1062 {
		t.Errorf("highest next after FIN = %d, want 1062", hn)
	}
	// Missing the SYN's number would look like a gap: data at 1002 after SYN 1000.
	var e TCPSeqDir
	e.ObserveSegment(1000, 1, true, false, at(0), 0)
	if r := seg(&e, 1002, 10, 1); r.Class != SeqForwardGap || r.Gap.Bytes() != 1 {
		t.Errorf("skipping one number after SYN = %+v", r)
	}
}

func TestSeqDir_RepeatedSYNIsARepeatNewISNRestarts(t *testing.T) {
	var d TCPSeqDir
	d.ObserveSegment(1000, 1, true, false, at(0), 0)
	seg(&d, 1001, 100, 1)
	seg(&d, 1201, 100, 2) // gap [1101,1201)
	// A repeated SYN with the same ISN: ordinary behind-the-position segment, no restart.
	r := d.ObserveSegment(1000, 1, true, false, at(3), 3)
	if r.Restarted || r.Class != SeqRepeat {
		t.Fatalf("repeated SYN = %+v", r)
	}
	if len(d.OpenGaps()) != 1 {
		t.Errorf("a repeated SYN must not clear gaps")
	}
	// Tuple reuse: a SYN with a different ISN resets the direction first.
	r = d.ObserveSegment(7000, 1, true, false, at(4), 4)
	if !r.Restarted || r.Class != SeqBaseline || len(d.OpenGaps()) != 0 {
		t.Fatalf("new ISN = %+v gaps %v", r, gapsOf(&d))
	}
	if hn, _ := d.HighestNext(); hn != 7001 {
		t.Errorf("highest next after restart = %d", hn)
	}
	// A SYN after a MIDSTREAM baseline (no SYN seen before) is also a new connection.
	var m TCPSeqDir
	seg(&m, 50000, 100, 0)
	if r := m.ObserveSegment(2000, 1, true, false, at(1), 1); !r.Restarted {
		t.Errorf("SYN after a midstream baseline did not restart: %+v", r)
	}
}

func TestSeqDir_ResetClearsEverything(t *testing.T) {
	var d TCPSeqDir
	d.ObserveSegment(1000, 1, true, false, at(0), 0)
	seg(&d, 1001, 10, 1)
	seg(&d, 1100, 10, 2) // gap
	d.Reset()
	if _, ok := d.HighestNext(); ok || len(d.OpenGaps()) != 0 || d.FinSeen() {
		t.Errorf("state after Reset: ok=%v gaps=%v", ok, gapsOf(&d))
	}
	// After the reset, the next segment is a fresh baseline (no gap inferred).
	if r := seg(&d, 9000, 10, 3); r.Class != SeqBaseline {
		t.Errorf("segment after reset = %+v", r)
	}
}

func TestSeqDir_ReverseDirectionsAreIndependent(t *testing.T) {
	var c2s, s2c TCPSeqDir
	seg(&c2s, 1000, 100, 0)
	seg(&s2c, 5000, 100, 1)
	seg(&c2s, 1500, 100, 2) // gap in c2s only
	if len(c2s.OpenGaps()) != 1 || len(s2c.OpenGaps()) != 0 {
		t.Errorf("gaps c2s=%v s2c=%v", gapsOf(&c2s), gapsOf(&s2c))
	}
	if hn, _ := s2c.HighestNext(); hn != 5100 {
		t.Errorf("server direction moved: %d", hn)
	}
}

func TestSeqDir_OpenGapCapAndExplicitOverflow(t *testing.T) {
	var d TCPSeqDir
	seg(&d, 1000, 10, 0)
	next := uint32(1010)
	for i := 0; i < MaxOpenSeqGaps+5; i++ {
		next += 10 // leave a 10-byte hole before every segment
		r := seg(&d, next, 10, i+1)
		next += 10
		if i < MaxOpenSeqGaps && !r.GapOpened {
			t.Fatalf("gap %d should be tracked: %+v", i, r)
		}
		if i >= MaxOpenSeqGaps && (r.GapOpened || !r.GapNotTracked || r.Class != SeqForwardGap) {
			t.Fatalf("gap %d past the cap = %+v, want an explicit not-tracked forward gap", i, r)
		}
	}
	if len(d.OpenGaps()) != MaxOpenSeqGaps || d.GapsNotTracked != 5 {
		t.Errorf("tracked %d (cap %d), not tracked %d (want 5)", len(d.OpenGaps()), MaxOpenSeqGaps, d.GapsNotTracked)
	}
	// highest-next still advances over untracked gaps (the position is observed, not inferred).
	if hn, _ := d.HighestNext(); hn != next {
		t.Errorf("highest next = %d, want %d", hn, next)
	}
}

func TestSeqDir_SplitAtCapCountsNotTracked(t *testing.T) {
	var d TCPSeqDir
	seg(&d, 1000, 10, 0)
	next := uint32(1010)
	for i := 0; i < MaxOpenSeqGaps; i++ { // fill the cap with 100-byte gaps
		next += 100
		seg(&d, next, 10, i+1)
		next += 10
	}
	if len(d.OpenGaps()) != MaxOpenSeqGaps {
		t.Fatalf("setup: %d gaps", len(d.OpenGaps()))
	}
	first := d.OpenGaps()[0]
	// A segment strictly inside the first gap would split it into two; at the cap the
	// extra piece is not tracked and is counted.
	r := seg(&d, first.Start+40, 10, 99)
	if r.Class != SeqFillsGap || len(d.OpenGaps()) != MaxOpenSeqGaps || d.GapsNotTracked != 1 {
		t.Errorf("split at cap: class=%v gaps=%d notTracked=%d", r.Class, len(d.OpenGaps()), d.GapsNotTracked)
	}
}

func TestSeqDir_GapsExpireAfter1GiB(t *testing.T) {
	var e TCPSeqDir
	seg(&e, 1000, 100, 0)
	seg(&e, 1500, 100, 1) // gap [1100,1500); next 1600
	// An in-order jump that leaves the gap start just under 2^30 behind: kept.
	r := e.ObserveSegment(1600, SeqGapExpiry-600, false, false, at(2), 2)
	if r.Expired != 0 || len(e.OpenGaps()) != 1 {
		t.Fatalf("gap expired too early: %+v", r)
	}
	// 200 more bytes put the gap start 2^30+100 behind: expired and counted.
	hn, _ := e.HighestNext()
	r = e.ObserveSegment(hn, 200, false, false, at(3), 3)
	if r.Expired != 1 || len(e.OpenGaps()) != 0 || e.GapsExpired != 1 {
		t.Errorf("gap should expire: %+v expired=%d", r, e.GapsExpired)
	}
	if len(r.ExpiredGaps) != 1 || r.ExpiredGaps[0].Start != 1100 || r.ExpiredGaps[0].End != 1500 || r.ExpiredGaps[0].Packet != 1 {
		t.Errorf("expired gap details = %+v", r.ExpiredGaps)
	}
}

func TestSeqDir_DeterministicTransitions(t *testing.T) {
	run := func() string {
		var d TCPSeqDir
		var out []string
		for i, c := range []struct {
			seq uint32
			n   int
		}{{1000, 100}, {1300, 100}, {1150, 50}, {1100, 50}, {1200, 100}, {1000, 100}} {
			r := seg(&d, c.seq, c.n, i)
			out = append(out, fmt.Sprintf("%d/%v/%d/%d", r.Class, r.GapOpened, r.FilledBytes, len(r.Filled)))
		}
		hn, _ := d.HighestNext()
		return fmt.Sprintf("%v|%d|%v|%d", out, hn, gapsOf(&d), d.GapsNotTracked)
	}
	first := run()
	// Pin the transitions themselves (class/gapOpened/filledBytes/closedGaps per segment):
	// baseline, forward gap, split by a middle fill, closing fill, closing fill, repeat.
	if want := "[1/false/0/0 3/true/0/0 4/false/50/0 4/false/50/1 4/false/100/1 5/false/0/0]|1400|[]|0"; first != want {
		t.Fatalf("transition sequence = %s, want %s", first, want)
	}
	for i := 0; i < 5; i++ {
		if got := run(); got != first {
			t.Fatalf("non-deterministic transitions:\n%s\n%s", first, got)
		}
	}
}

// ─── Duplicate-ACK run state ────────────────────────────────────────────

func ackObs(ack uint32, win uint16, peerNext uint32, i int) AckObservation {
	return AckObservation{Ack: ack, Window: win, PureAck: true, PeerNext: peerNext, PeerNextValid: true, At: at(i), Packet: uint64(i)}
}

func TestDupAck_RunCountsRepeatsWithUnchangedAckAndWindow(t *testing.T) {
	var r TCPDupAckRun
	if res := r.Observe(ackObs(1100, 100, 1600, 0)); res.IsDuplicate || res.Ended {
		t.Fatalf("first ACK = %+v", res)
	}
	for i := 1; i <= 3; i++ {
		res := r.Observe(ackObs(1100, 100, 1600, i))
		if !res.IsDuplicate || res.Dups != uint32(i) {
			t.Fatalf("duplicate %d = %+v", i, res)
		}
	}
	cur, ok := r.Current()
	if !ok || cur.Dups != 3 || cur.Ack != 1100 || cur.FirstPacket != 0 || cur.LastPacket != 3 || !cur.FirstAt.Equal(at(0)) || !cur.LastAt.Equal(at(3)) {
		t.Errorf("current run = %+v ok=%v", cur, ok)
	}
}

func TestDupAck_RunResetsOnChangedAckOrWindowAndReportsTheEndedRun(t *testing.T) {
	var r TCPDupAckRun
	r.Observe(ackObs(1100, 100, 1600, 0))
	r.Observe(ackObs(1100, 100, 1600, 1))
	r.Observe(ackObs(1100, 100, 1600, 2))
	res := r.Observe(ackObs(1100, 200, 1600, 3)) // window update
	if res.IsDuplicate || res.Reason != AckWindowChanged || !res.Ended || res.EndedRun.Dups != 2 || res.EndedRun.Window != 100 {
		t.Fatalf("window change = %+v", res)
	}
	r.Observe(ackObs(1100, 200, 1600, 4))
	res = r.Observe(ackObs(1200, 200, 1600, 5)) // ack advanced
	if res.IsDuplicate || res.Reason != AckAckChanged || !res.Ended || res.EndedRun.Dups != 1 {
		t.Fatalf("ack change = %+v", res)
	}
	// A run that never had a duplicate is not reported as ended.
	res = r.Observe(ackObs(1300, 200, 1600, 6))
	if res.Ended {
		t.Errorf("a run without duplicates reported as ended: %+v", res)
	}
}

func TestDupAck_NoRunWhenPeerDataNotOutstanding(t *testing.T) {
	var r TCPDupAckRun
	r.Observe(ackObs(1100, 2048, 1100, 0)) // peer next == ack: nothing outstanding
	for i := 1; i <= 3; i++ {
		res := r.Observe(ackObs(1100, 2048, 1100, i))
		if res.IsDuplicate || res.Reason != AckNoOutstandingData {
			t.Fatalf("idle repeated ACK %d = %+v", i, res)
		}
	}
	if _, ok := r.Current(); ok {
		t.Error("an idle ACK pattern produced a run")
	}
	// Peer unknown (no baseline in the other direction): also not a duplicate.
	var u TCPDupAckRun
	u.Observe(AckObservation{Ack: 5, Window: 1, PureAck: true, At: at(0)})
	if res := u.Observe(AckObservation{Ack: 5, Window: 1, PureAck: true, At: at(1)}); res.IsDuplicate {
		t.Errorf("duplicate counted without any knowledge of the peer: %+v", res)
	}
	// Data becomes outstanding while the receiver still acknowledges the same number:
	// that is now a duplicate ACK (RFC 5681: same ack, same window, data outstanding).
	res := r.Observe(ackObs(1100, 2048, 1300, 9))
	if !res.IsDuplicate || res.Dups != 1 {
		t.Fatalf("repeated ACK once data is outstanding = %+v", res)
	}
	if res = r.Observe(ackObs(1100, 2048, 1300, 10)); !res.IsDuplicate || res.Dups != 2 {
		t.Errorf("second duplicate with outstanding data = %+v", res)
	}
}

func TestDupAck_PayloadCarryingOrControlPacketsAreNotDuplicatesAndEndTheRun(t *testing.T) {
	var r TCPDupAckRun
	r.Observe(ackObs(1100, 100, 1600, 0))
	r.Observe(ackObs(1100, 100, 1600, 1))
	o := ackObs(1100, 100, 1600, 2)
	o.PureAck = false // an ACK carrying payload (or FIN/RST)
	res := r.Observe(o)
	if res.IsDuplicate || res.Reason != AckNotPure || !res.Ended || res.EndedRun.Dups != 1 {
		t.Fatalf("payload-carrying ACK = %+v", res)
	}
	if _, ok := r.Current(); ok {
		t.Error("run state survived a non-pure ACK")
	}
	// The next pure ACK with the same numbers is a first observation again.
	if res = r.Observe(ackObs(1100, 100, 1600, 3)); res.IsDuplicate {
		t.Errorf("chain not reset by the payload-carrying ACK: %+v", res)
	}
}

func TestDupAck_AckComparisonIsWrapAware(t *testing.T) {
	var r TCPDupAckRun
	const ack = uint32(0xFFFFFFF0)
	peer := uint32(0x20) // peer next is just past the wrap: data from ack to 0x20 outstanding
	r.Observe(ackObs(ack, 10, peer, 0))
	if res := r.Observe(ackObs(ack, 10, peer, 1)); !res.IsDuplicate {
		t.Errorf("duplicate across the wrap not recognised: %+v", res)
	}
	// Peer next BEHIND the ack (stale/reordered view): not outstanding.
	var s TCPDupAckRun
	s.Observe(ackObs(0x30, 10, 0x20, 0))
	if res := s.Observe(ackObs(0x30, 10, 0x20, 1)); res.IsDuplicate {
		t.Errorf("counted a duplicate with peer next behind the ack: %+v", res)
	}
}

func TestDupAck_SACKStateIsBoundedAndCopied(t *testing.T) {
	var r TCPDupAckRun
	r.Observe(ackObs(1100, 100, 5000, 0))
	many := make([][2]uint32, 10)
	for i := range many {
		many[i] = [2]uint32{uint32(2000 + i*10), uint32(2005 + i*10)}
	}
	o := ackObs(1100, 100, 5000, 1)
	o.Sack = many
	r.Observe(o)
	cur, _ := r.Current()
	if len(cur.SackEdges) != MaxSackEdges || cur.SackSeen != 1 || cur.SackEdges[0] != many[0] {
		t.Fatalf("SACK edges = %v seen=%d", cur.SackEdges, cur.SackSeen)
	}
	many[0] = [2]uint32{9, 9} // the caller's slice must not alias the stored edges
	cur2, _ := r.Current()
	if cur2.SackEdges[0] == many[0] {
		t.Error("stored SACK edges alias the caller's slice")
	}
	cur2.SackEdges[1] = [2]uint32{7, 7} // nor may a returned summary alias the state
	if again, _ := r.Current(); again.SackEdges[1] == cur2.SackEdges[1] {
		t.Error("returned summary aliases internal state")
	}
	// A later duplicate replaces (does not append to) the edges.
	o = ackObs(1100, 100, 5000, 2)
	o.Sack = [][2]uint32{{3000, 3100}}
	r.Observe(o)
	if last, _ := r.Current(); len(last.SackEdges) != 1 || last.SackSeen != 2 {
		t.Errorf("SACK edges after second duplicate = %v seen=%d", last.SackEdges, last.SackSeen)
	}
}

func TestDupAck_CounterSaturates(t *testing.T) {
	var r TCPDupAckRun
	r.Observe(ackObs(1, 1, 100, 0))
	r.cur.Dups = ^uint32(0) - 1
	r.Observe(ackObs(1, 1, 100, 1))
	if res := r.Observe(ackObs(1, 1, 100, 2)); res.Dups != ^uint32(0) {
		t.Errorf("counter = %d, want saturation at max", res.Dups)
	}
}

func TestParseSACKEdges(t *testing.T) {
	data := []byte{0, 0, 0x0b, 0xb8, 0, 0, 0x0b, 0xe4, 0xFF, 0xFF, 0xFF, 0xF0, 0, 0, 0, 0x10, 1, 2, 3} // 2 blocks + junk
	got := ParseSACKEdges(data)
	want := [][2]uint32{{3000, 3044}, {0xFFFFFFF0, 0x10}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("edges = %v, want %v", got, want)
	}
	if len(ParseSACKEdges(make([]byte, 8*9))) != MaxSackEdges {
		t.Error("more than MaxSackEdges blocks returned")
	}
	if len(ParseSACKEdges(nil)) != 0 || len(ParseSACKEdges([]byte{1, 2, 3})) != 0 {
		t.Error("malformed/empty data must yield no edges")
	}
}

func TestTCPFlowState_SequenceStateIsLazyAndPerDirection(t *testing.T) {
	s := NewTCPFlowState()
	if s.seqDir != nil || s.ackRun != nil {
		t.Fatal("sequence state must not be allocated until used")
	}
	a, b := s.SequenceState(), s.SequenceState()
	if a != b || s.DupAckState() != s.DupAckState() {
		t.Error("accessors must return the same instance")
	}
	other := NewTCPFlowState()
	if other.SequenceState() == a {
		t.Error("separate flow states must not share sequence state")
	}
}

func TestSeqDir_SYNSeenDistinguishesMidstreamBaseline(t *testing.T) {
	var a, b TCPSeqDir
	a.ObserveSegment(1000, 1, true, false, at(0), 0)
	seg(&b, 5000, 10, 0)
	if !a.SYNSeen() || b.SYNSeen() {
		t.Errorf("SYNSeen: with SYN=%v midstream=%v", a.SYNSeen(), b.SYNSeen())
	}
}

func TestAnalysisState_PeekTCPFlowDoesNotChangeEvictionOrder(t *testing.T) {
	st := NewBoundedAnalysisState(2, 10)
	st.SetTCPFlow("a", NewTCPFlowState())
	st.SetTCPFlow("b", NewTCPFlowState())
	if st.PeekTCPFlow("a") == nil {
		t.Fatal("peek of an existing flow returned nil")
	}
	st.SetTCPFlow("c", NewTCPFlowState()) // evicts the least recently USED: "a" (peek must not have refreshed it)
	if st.PeekTCPFlow("a") != nil {
		t.Error("Peek refreshed the LRU recency of flow a")
	}
	if st.PeekTCPFlow("missing") != nil {
		t.Error("peek of an unknown flow must be nil")
	}
}
