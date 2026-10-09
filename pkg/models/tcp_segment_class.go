package models

// Shared TCP retransmission classification (Phase 4.29b).
//
// Two live consumers decide whether a TCP segment is a retransmission:
// pkg/detector/tcp.go (events, retransmission flows, health/findings inputs) and
// pkg/detectors/packet_loss.go (the packet_loss report section). Both used to
// carry their own copy of the same two-step rule. This file is the single
// definition of that rule. It is deliberately a pure decision: it neither
// mutates the history nor counts anything. Each consumer keeps its own
// eligibility filter, history updates, aggregation and reporting, so their
// observable behaviour is unchanged (including the documented difference that
// packet_loss.go ignores every SYN/FIN/RST packet while tcp.go does not).
//
// The rule is exactly the pre-existing one, no more:
//
//  1. a segment matching the keep-alive shape is not a retransmission;
//  2. otherwise a segment that carries payload and whose STARTING sequence
//     number is already in the bounded SeqHistory is a retransmission.
//
// It does not detect sequence overlap with a different start, gaps, duplicate
// ACKs, fast retransmits or capture duplicates, and it does not prove packet
// loss: it reports that the same starting sequence number was seen again in
// this direction within the history window.

// TCPSegmentClass is the classification of a segment against its flow history.
type TCPSegmentClass int

const (
	// SegmentNotRetransmission: no repeat of a remembered starting sequence
	// number was found (new data, an ACK, or a repeat that was already evicted
	// from the bounded history).
	SegmentNotRetransmission TCPSegmentClass = iota
	// SegmentKeepAliveShape: the segment has the keep-alive shape (at most one
	// byte of payload sitting exactly one byte below the highest next sequence
	// number sent in this direction). It is NOT verified to be a real keep-alive:
	// any payload-less segment at that position matches, which today includes a
	// repeated SYN (a retransmitted SYN is therefore silently excluded by this
	// rule rather than recognised as a SYN retransmission). Callers must not
	// treat it as a retransmission.
	SegmentKeepAliveShape
	// SegmentRetransmission: payload > 0 and the starting sequence number is in
	// the history.
	SegmentRetransmission
)

// IsKeepAliveShape reports whether a segment of payloadLen bytes at seq matches
// the TCP keep-alive shape given the highest next sequence number sent so far
// (RFC 1122 §4.2.3.6; Wireshark's tcp.analysis.keep_alive rule). highestNext is
// meaningful only when highestValid is true. The comparison is modular, so it
// is correct across 32-bit wrap-around.
func IsKeepAliveShape(highestNext uint32, highestValid bool, seq uint32, payloadLen int) bool {
	return payloadLen <= 1 && highestValid && seq == highestNext-1
}

// ClassifyTCPSegment is the single definition of the retransmission rule used by
// the live consumers. history is the direction's SeqHistory; highestNext and
// highestValid are the direction's highest next sequence number (see
// TCPFlowState.HighestNextSeq). It does not modify any state.
func ClassifyTCPSegment(history *SeqHistory, highestNext uint32, highestValid bool, seq uint32, payloadLen int) TCPSegmentClass {
	if IsKeepAliveShape(highestNext, highestValid, seq, payloadLen) {
		return SegmentKeepAliveShape
	}
	if payloadLen > 0 && history.Seen(seq) {
		return SegmentRetransmission
	}
	return SegmentNotRetransmission
}
