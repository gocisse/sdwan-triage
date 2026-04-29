package analyzer

// tcp_analysis.go — Wireshark-style per-packet TCP analysis flags.
//
// This module detects four classic TCP analysis conditions that Wireshark
// surfaces under its "Expert Info" panel:
//
//   1. Retransmission        — a prior (seq, len) was already seen in the
//                              same direction with payload > 0.
//   2. Duplicate ACK         — a pure ACK repeating the same ack_num as the
//                              previous pure ACK in the same direction
//                              (tagged with the duplicate count).
//   3. Zero Window           — advertised window is zero (receiver stalled).
//   4. Keep-Alive            — pure ACK or 1-byte packet whose seq is one
//                              less than the expected next seq, used to
//                              probe a long-idle connection.
//
// Usage:
//
//	a := NewTCPFlagAnalyzer()
//	for each packet p in time order:
//	    flags := a.Analyze(flowKey, direction, seq, ack, window, payloadLen, isSYN, isRST, isFIN)
//	    // flags.IsRetransmission / IsDuplicateAck / IsZeroWindow / IsKeepAlive
//
// The analyzer is NOT safe for concurrent use on the same instance; a caller
// processing multiple flows in parallel should hold one analyzer per flow or
// synchronise access externally. In our codebase the streaming comparator
// processes packets sequentially, so a single instance suffices.

// TCPAnalysisFlags is the per-packet result of the analyzer.
//
// All fields are false for non-TCP packets or when the condition is not met.
// `DuplicateAckCount` is the running count of how many times the *same*
// ack_num has been seen (0 for non-duplicate-ACKs; >=2 for duplicates —
// Wireshark only flags at N>=2, i.e. the 2nd observation onward).
type TCPAnalysisFlags struct {
	IsRetransmission  bool `json:"is_retransmission,omitempty"`
	IsDuplicateAck    bool `json:"is_duplicate_ack,omitempty"`
	IsZeroWindow      bool `json:"is_zero_window,omitempty"`
	IsKeepAlive       bool `json:"is_keep_alive,omitempty"`
	DuplicateAckCount int  `json:"duplicate_ack_count,omitempty"` // 0 means "not a duplicate"
}

// HasAny reports whether at least one analysis flag is set.
func (f TCPAnalysisFlags) HasAny() bool {
	return f.IsRetransmission || f.IsDuplicateAck || f.IsZeroWindow || f.IsKeepAlive
}

// tcpFlowKey identifies a TCP flow for the analyzer. We key by the
// normalised 5-tuple *plus* the direction so that forward and reverse
// half-flows have independent state (required for correct dup-ack and
// keep-alive detection).
type tcpFlowKey struct {
	Src      string
	Dst      string
	SrcPort  uint16
	DstPort  uint16
	Protocol string
}

// tcpFlowState tracks the per-direction sequence-space history needed to
// detect the four analysis conditions.
type tcpFlowState struct {
	// highestSeqSeen tracks the highest seq+len boundary ever observed in
	// this direction. A packet whose seq is < this boundary with payload > 0
	// is a retransmission (RFC 1982 wrap-aware).
	highestSeqSeen  uint32
	highestSeqValid bool

	// For keep-alive detection: next expected seq = highestSeqSeen.
	// A keep-alive has seq = highestSeqSeen - 1.

	// For duplicate-ACK detection: we track the last ack_num emitted by a
	// pure ACK (payload=0, !SYN, !FIN, !RST) and a running duplicate count.
	lastAckNum      uint32
	lastAckValid    bool
	lastAckPayload  int  // 0 = pure ACK
	duplicateAckCnt int  // Count of repeats of lastAckNum

	// Retransmission detection via a compact (seq, payload) set.
	seenSegments map[uint64]struct{}
}

// TCPFlagAnalyzer keeps state across packets for analysis-flag computation.
type TCPFlagAnalyzer struct {
	flows map[tcpFlowKey]*tcpFlowState
}

// NewTCPFlagAnalyzer returns a fresh analyzer with no state.
func NewTCPFlagAnalyzer() *TCPFlagAnalyzer {
	return &TCPFlagAnalyzer{flows: make(map[tcpFlowKey]*tcpFlowState)}
}

// Analyze classifies one TCP packet and returns its analysis flags.
//
// Parameters mirror the wire fields of a TCP segment:
//   - srcIP/dstIP/srcPort/dstPort identify the half-flow (direction-specific).
//   - seq, ack, window are the TCP header values for this packet.
//   - payloadLen is the TCP data payload size in bytes.
//   - isSYN/isRST/isFIN are the corresponding TCP flag bits.
//
// The analyzer is deterministic given the input sequence — feeding the same
// packets in the same order always produces the same flags.
func (a *TCPFlagAnalyzer) Analyze(
	srcIP, dstIP string,
	srcPort, dstPort uint16,
	seq, ack uint32,
	window uint16,
	payloadLen int,
	isSYN, isRST, isFIN bool,
) TCPAnalysisFlags {
	// Direction-keyed flow state. Note: src→dst and dst→src are separate
	// state buckets so that, e.g., dup-ACK detection in the reverse
	// direction doesn't contaminate forward-direction analysis.
	key := tcpFlowKey{
		Src:      srcIP,
		Dst:      dstIP,
		SrcPort:  srcPort,
		DstPort:  dstPort,
		Protocol: "TCP",
	}
	st, ok := a.flows[key]
	if !ok {
		st = &tcpFlowState{seenSegments: make(map[uint64]struct{})}
		a.flows[key] = st
	}

	flags := TCPAnalysisFlags{}

	// ── Zero Window ──────────────────────────────────────────────
	// Receiver advertising zero window is a flow-control signal that
	// the receive buffer is full. SYN and RST legitimately carry w=0
	// with different semantics, so we exclude them.
	if window == 0 && !isRST && !isSYN {
		flags.IsZeroWindow = true
	}

	// ── Retransmission ───────────────────────────────────────────
	// A retransmission is a segment with payload > 0 whose (seq, len)
	// was already seen in this direction. We use a compact map keyed
	// by a packed uint64 for memory efficiency.
	if payloadLen > 0 {
		segKey := uint64(seq)<<32 | uint64(uint32(payloadLen))
		if _, seen := st.seenSegments[segKey]; seen {
			flags.IsRetransmission = true
		} else {
			st.seenSegments[segKey] = struct{}{}
		}
	}

	// ── Keep-Alive ───────────────────────────────────────────────
	// RFC 1122 §4.2.3.6 keep-alive: a segment with seq = (expected_next_seq - 1),
	// payload = 0 or 1 byte of garbage, no SYN/FIN/RST. Some stacks
	// alternatively send a pure ACK whose seq is one below the expected
	// next byte.
	if st.highestSeqValid && !isSYN && !isFIN && !isRST && payloadLen <= 1 {
		expected := st.highestSeqSeen
		// In 32-bit sequence space, (expected - 1) handles wrap correctly.
		if seq == expected-1 {
			flags.IsKeepAlive = true
		}
	}

	// ── Duplicate ACK ────────────────────────────────────────────
	// Classic Wireshark definition: a pure ACK (payload=0, no SYN/FIN/RST)
	// whose ack_num matches the previous pure ACK's ack_num in the same
	// direction. We report a running count starting at 2 (matching
	// Wireshark's "Duplicate ACK #2", "#3", ...).
	isPureAck := payloadLen == 0 && !isSYN && !isFIN && !isRST
	if isPureAck {
		if st.lastAckValid && st.lastAckNum == ack && st.lastAckPayload == 0 {
			st.duplicateAckCnt++
			// Wireshark reports "duplicate ack" starting at the 2nd occurrence.
			// duplicateAckCnt==1 → current packet is the 2nd observation.
			if st.duplicateAckCnt >= 1 {
				flags.IsDuplicateAck = true
				flags.DuplicateAckCount = st.duplicateAckCnt + 1 // 2, 3, 4, ...
			}
		} else {
			st.duplicateAckCnt = 0
		}
		st.lastAckNum = ack
		st.lastAckPayload = 0
		st.lastAckValid = true
	} else if payloadLen > 0 || isSYN || isFIN {
		// Any non-pure-ACK segment resets the dup-ACK chain.
		st.duplicateAckCnt = 0
		st.lastAckValid = false
	}

	// ── Update seq boundary tracking ─────────────────────────────
	// Advance the high-water mark so the *next* packet's keep-alive /
	// retransmission logic uses accurate state. We only advance for
	// forward progress in the seq space (not for retransmissions).
	if payloadLen > 0 {
		end := seq + uint32(payloadLen)
		if !st.highestSeqValid || tcpSeqGE(end, st.highestSeqSeen) {
			st.highestSeqSeen = end
			st.highestSeqValid = true
		}
	} else if isSYN || isFIN {
		// SYN and FIN consume one seq byte per RFC 793 §3.3.
		end := seq + 1
		if !st.highestSeqValid || tcpSeqGE(end, st.highestSeqSeen) {
			st.highestSeqSeen = end
			st.highestSeqValid = true
		}
	}

	return flags
}

// Reset clears all per-flow state. Useful between PCAP analyses.
func (a *TCPFlagAnalyzer) Reset() {
	a.flows = make(map[tcpFlowKey]*tcpFlowState)
}
