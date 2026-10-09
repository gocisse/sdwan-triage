package models

import (
	"testing"
	"time"
)

// Phase 4.29b: the shared classifier must reproduce exactly the rule both live
// consumers used before the refactor (see tcp_segment_class.go). These tests pin
// the decision table; end-to-end behaviour is pinned by
// pkg/analyzer/tcp_retransmission_characterization_test.go.

func historyWith(seqs ...uint32) *SeqHistory {
	h := NewSeqHistory(DefaultSeqHistorySize)
	for _, s := range seqs {
		h.Record(s, time.Unix(1, 0))
	}
	return h
}

func TestClassifyTCPSegment_DecisionTable(t *testing.T) {
	cases := []struct {
		name         string
		hist         []uint32
		highestNext  uint32
		highestValid bool
		seq          uint32
		payloadLen   int
		want         TCPSegmentClass
	}{
		{"new data", nil, 0, false, 1001, 100, SegmentNotRetransmission},
		{"repeat of remembered start seq", []uint32{1001}, 1101, true, 1001, 100, SegmentRetransmission},
		{"repeat with different length still matches start seq", []uint32{1001}, 1101, true, 1001, 40, SegmentRetransmission},
		{"different start seq inside a remembered range is not matched", []uint32{1001}, 1101, true, 1050, 10, SegmentNotRetransmission},
		{"payload-less segment is never a retransmission", []uint32{1001}, 1101, true, 1001, 0, SegmentNotRetransmission},
		{"one byte at highest-1 is keep-alive shape", nil, 1102, true, 1101, 1, SegmentKeepAliveShape},
		{"keep-alive shape wins over a remembered seq", []uint32{1101}, 1102, true, 1101, 1, SegmentKeepAliveShape},
		{"one byte elsewhere is still a retransmission", []uint32{1001}, 1102, true, 1001, 1, SegmentRetransmission},
		{"two bytes at highest-1 are not keep-alive shape", []uint32{1101}, 1103, true, 1101, 2, SegmentRetransmission},
		{"keep-alive shape needs a valid highest", []uint32{1101}, 1102, false, 1101, 1, SegmentRetransmission},
		// A payload-less segment at highest-1 matches the keep-alive shape. A repeated
		// SYN does exactly this (Phase 4.29a finding): it is excluded, not recognised.
		{"payload-less segment at highest-1 (repeated SYN) is keep-alive shape", []uint32{1000}, 1001, true, 1000, 0, SegmentKeepAliveShape},
		// 32-bit wrap: highest next 0 means the previous byte is 0xFFFFFFFF.
		{"keep-alive shape across wrap", nil, 0, true, 0xFFFFFFFF, 1, SegmentKeepAliveShape},
		{"repeat across wrap", []uint32{0xFFFFFF00, 0x100}, 0x164, true, 0x100, 100, SegmentRetransmission},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := ClassifyTCPSegment(historyWith(c.hist...), c.highestNext, c.highestValid, c.seq, c.payloadLen)
			if got != c.want {
				t.Errorf("class = %d, want %d", got, c.want)
			}
		})
	}
}

// An evicted sequence number is forgotten: the bounded history is part of the rule.
func TestClassifyTCPSegment_EvictedSeqIsNotRemembered(t *testing.T) {
	h := NewSeqHistory(2)
	h.Record(10, time.Unix(1, 0))
	h.Record(20, time.Unix(2, 0))
	h.Record(30, time.Unix(3, 0)) // evicts 10
	if got := ClassifyTCPSegment(h, 0, false, 10, 5); got != SegmentNotRetransmission {
		t.Errorf("evicted seq classified %d, want SegmentNotRetransmission", got)
	}
	if got := ClassifyTCPSegment(h, 0, false, 20, 5); got != SegmentRetransmission {
		t.Errorf("remembered seq classified %d, want SegmentRetransmission", got)
	}
}

// The classifier is a pure decision: it must not change the history.
func TestClassifyTCPSegment_DoesNotMutateHistory(t *testing.T) {
	h := historyWith(1001)
	before := h.Len()
	_ = ClassifyTCPSegment(h, 1101, true, 2001, 100) // new data
	_ = ClassifyTCPSegment(h, 1101, true, 1001, 100) // retransmission
	if h.Len() != before || h.Seen(2001) {
		t.Errorf("classification mutated the history (len %d -> %d, Seen(2001)=%v)", before, h.Len(), h.Seen(2001))
	}
}

// TCPFlowState.IsKeepAlive and the shared shape test must agree.
func TestIsKeepAliveShape_MatchesFlowStateMethod(t *testing.T) {
	s := NewTCPFlowState()
	s.ObserveSegment(1000, 101) // HighestNextSeq = 1101
	for _, tc := range []struct {
		seq uint32
		n   int
	}{{1100, 0}, {1100, 1}, {1100, 2}, {1101, 1}, {1099, 1}} {
		if got, want := IsKeepAliveShape(s.HighestNextSeq, s.HighestNextValid, tc.seq, tc.n), s.IsKeepAlive(tc.seq, tc.n); got != want {
			t.Errorf("seq=%d len=%d: shared=%v method=%v", tc.seq, tc.n, got, want)
		}
	}
}
