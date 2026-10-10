package analyzer

import (
	"testing"
	"time"

	"github.com/gocisse/sdwan-triage/internal/testpcap"
)

// Phase 4.50 — stream-view labels: R = retransmission (start sequence already
// seen in that direction), O = out-of-sequence arrival (first-seen segment that
// starts before the highest start sequence seen; reordering OR hole-fill, never
// proof of loss), - = neither. A forward gap and a keep-alive probe get no label.
// Uses streamFlags / cData / sAck / seqCliPort from the characterization tests.

func TestStreamClass_AdjacentSwapsAreOutOfOrderNotRetransmission(t *testing.T) {
	var specs []seqSpec
	seq := uint32(1001)
	for i := 0; i < 6; i++ {
		specs = append(specs, cData(seq+100, 100), cData(seq, 100))
		seq += 200
	}
	if got := streamFlags(t, seqCliPort, specs...); got != "-O-O-O-O-O-O" {
		t.Errorf("flags = %q, want alternating -O (no R)", got)
	}
}

func TestStreamClass_ResendBurstOfIncreasingSequenceIsAllRetransmission(t *testing.T) {
	var specs []seqSpec
	for i := 0; i < 8; i++ {
		specs = append(specs, cData(1001+uint32(i)*100, 100))
	}
	for i := 0; i < 5; i++ { // resend segments 0..4 in increasing order: previously only the first was caught
		specs = append(specs, cData(1001+uint32(i)*100, 100))
	}
	if got := streamFlags(t, seqCliPort, specs...); got != "--------RRRRR" {
		t.Errorf("flags = %q, want 8 new then RRRRR", got)
	}
}

func TestStreamClass_RepeatOfLatestSegmentIsRetransmission(t *testing.T) {
	if got := streamFlags(t, seqCliPort, cData(1001, 100), cData(1101, 100), cData(1101, 100), cData(1101, 100)); got != "--RR" {
		t.Errorf("flags = %q, want --RR", got)
	}
}

func TestStreamClass_KeepAliveProbesGetNoLabel(t *testing.T) {
	specs := []seqSpec{cData(1001, 100), cData(1101, 100)}
	for i := 0; i < 5; i++ { // 1 byte at highest_next-1 = 1200
		specs = append(specs, cData(1200, 1))
	}
	if got := streamFlags(t, seqCliPort, specs...); got != "-------" {
		t.Errorf("flags = %q, want no label for keep-alive probes", got)
	}
}

const streamWrapBase = uint32(0xFFFFFFFF - 1000)

func TestStreamClass_WraparoundInOrderIsUnlabelled(t *testing.T) {
	var specs []seqSpec
	for i := 0; i < 30; i++ { // crosses 2^32 mid-flow
		specs = append(specs, cData(streamWrapBase+uint32(i)*100, 100))
	}
	got := streamFlags(t, seqCliPort, specs...)
	for _, c := range got {
		if c != '-' {
			t.Fatalf("wrap-around in-order flagged: %q", got)
		}
	}
}

func TestStreamClass_WraparoundResendsAndReorderingKeepTheirMeaning(t *testing.T) {
	var specs []seqSpec
	for i := 0; i < 30; i++ {
		specs = append(specs, cData(streamWrapBase+uint32(i)*100, 100))
	}
	specs = append(specs, cData(streamWrapBase, 100)) // pre-wrap segment resent after the wrap
	if got := streamFlags(t, seqCliPort, specs...); got[len(got)-1] != 'R' || got[:30] != "------------------------------" {
		t.Errorf("flags = %q, want 30 unlabelled then R", got)
	}
	// reordering straddling the wrap point
	specs = specs[:0]
	specs = append(specs, cData(streamWrapBase, 100), cData(streamWrapBase+200, 100), cData(streamWrapBase+100, 100))
	if got := streamFlags(t, seqCliPort, specs...); got != "--O" {
		t.Errorf("reordering across wrap flags = %q, want --O", got)
	}
	// a segment starting just past the wrap after one just before it is a forward step, not O
	if got := streamFlags(t, seqCliPort, cData(0xFFFFFF00, 100), cData(0x00000040, 100)); got != "--" {
		t.Errorf("forward across wrap flags = %q, want --", got)
	}
}

func TestStreamClass_ForwardGapThenLateFill(t *testing.T) {
	// gap (no label), later segments, then the missing one arrives: out-of-sequence, not a retransmission.
	got := streamFlags(t, seqCliPort, cData(1001, 100), cData(1201, 100), cData(1301, 100), cData(1101, 100))
	if got != "---O" {
		t.Errorf("flags = %q, want ---O", got)
	}
}

func TestStreamClass_OverlapWithDifferentStartIsNotARetransmission(t *testing.T) {
	// Documented limitation: the shared rule keys on the START sequence, so a
	// partial overlap that starts at an unseen sequence is treated as new data.
	if got := streamFlags(t, seqCliPort, cData(1001, 200), cData(1101, 200)); got != "--" {
		t.Errorf("forward overlap flags = %q, want --", got)
	}
	if got := streamFlags(t, seqCliPort, cData(1001, 200), cData(1201, 200), cData(1101, 200)); got != "--O" {
		t.Errorf("backward overlap flags = %q, want --O", got)
	}
}

func TestStreamClass_ControlOnlyFlowHasNoSegments(t *testing.T) {
	if got := streamFlags(t, seqCliPort, sAck(1001, 0), sAck(1001, 0)); got != "" {
		t.Errorf("ACK/control-only flow produced segments: %q", got)
	}
}

func TestStreamClass_DirectionsAndFlowsAreIndependent(t *testing.T) {
	// The same sequence numbers in the two directions, and on a second flow,
	// are not retransmissions of each other.
	sr := NewStreamReassembler(false)
	var all [][]byte
	all = append(all, frames(seqCliPort, cData(1001, 100), sAck(1101, 0))...)
	all = append(all, frames(seqCliPort+1, cData(1001, 100))...)
	for i, b := range all {
		sr.ProcessPacket(pktAt(b, i))
	}
	for _, s := range sr.GetStreamsSorted() {
		for _, sg := range s.Segments {
			if sg.IsRetransmit || sg.IsOutOfOrder {
				t.Errorf("cross-flow/direction leakage: %+v", sg)
			}
		}
	}
}

func TestStreamClass_CleanupFreesSequenceState(t *testing.T) {
	sr := NewStreamReassembler(false)
	for i, b := range frames(seqCliPort, cData(1001, 100), cData(1101, 100)) {
		sr.ProcessPacket(pktAt(b, i))
	}
	if len(sr.seqState) == 0 {
		t.Fatal("expected sequence state to be tracked")
	}
	if n := sr.CleanupStaleFlows(time.Second, testpcap.BaseTime.Add(time.Hour)); n != 1 {
		t.Fatalf("evicted = %d, want 1", n)
	}
	if len(sr.seqState) != 0 {
		t.Errorf("sequence state leaked after cleanup: %d entries", len(sr.seqState))
	}
}
