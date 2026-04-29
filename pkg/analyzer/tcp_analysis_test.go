package analyzer

import "testing"

// ─── Helpers ─────────────────────────────────────────────────────

// tcpPkt describes a test TCP packet for driving the analyzer.
type tcpPkt struct {
	srcIP, dstIP     string
	srcPort, dstPort uint16
	seq, ack         uint32
	window           uint16
	payload          int
	syn, rst, fin    bool
}

// run feeds a sequence of packets through a fresh analyzer and returns the
// resulting flags slice in order.
func run(pkts []tcpPkt) []TCPAnalysisFlags {
	a := NewTCPFlagAnalyzer()
	out := make([]TCPAnalysisFlags, 0, len(pkts))
	for _, p := range pkts {
		out = append(out, a.Analyze(
			p.srcIP, p.dstIP, p.srcPort, p.dstPort,
			p.seq, p.ack, p.window, p.payload,
			p.syn, p.rst, p.fin,
		))
	}
	return out
}

// ─── Retransmission ──────────────────────────────────────────────

func TestTCPFlagAnalyzer_RetransmissionBasic(t *testing.T) {
	flags := run([]tcpPkt{
		{"10.0.0.1", "10.0.0.2", 5000, 443, 1000, 0, 65535, 100, false, false, false},
		// Exact same segment — classic retransmission.
		{"10.0.0.1", "10.0.0.2", 5000, 443, 1000, 0, 65535, 100, false, false, false},
	})
	if flags[0].IsRetransmission {
		t.Error("first occurrence should NOT be a retransmission")
	}
	if !flags[1].IsRetransmission {
		t.Error("second occurrence SHOULD be flagged as a retransmission")
	}
}

func TestTCPFlagAnalyzer_RetransmissionIgnoresPureAcks(t *testing.T) {
	flags := run([]tcpPkt{
		// Two pure ACKs with identical seq — should NEVER be flagged as retx.
		{"10.0.0.1", "10.0.0.2", 5000, 443, 1000, 500, 65535, 0, false, false, false},
		{"10.0.0.1", "10.0.0.2", 5000, 443, 1000, 600, 65535, 0, false, false, false},
	})
	for i, f := range flags {
		if f.IsRetransmission {
			t.Errorf("packet %d should not be flagged as retransmission (it's a pure ACK)", i)
		}
	}
}

func TestTCPFlagAnalyzer_RetransmissionPerDirection(t *testing.T) {
	// Same seq in opposite directions must not be a retransmission.
	flags := run([]tcpPkt{
		{"10.0.0.1", "10.0.0.2", 5000, 443, 1000, 0, 65535, 100, false, false, false},
		{"10.0.0.2", "10.0.0.1", 443, 5000, 1000, 0, 65535, 100, false, false, false},
	})
	if flags[0].IsRetransmission || flags[1].IsRetransmission {
		t.Error("opposite-direction packets should have independent retransmission tracking")
	}
}

// ─── Duplicate ACK ──────────────────────────────────────────────

func TestTCPFlagAnalyzer_DuplicateAck(t *testing.T) {
	flags := run([]tcpPkt{
		// One data packet going forward so there's something to ACK.
		{"10.0.0.1", "10.0.0.2", 5000, 443, 500, 0, 65535, 100, false, false, false},
		// Reverse-direction pure ACKs repeating the same ack_num.
		{"10.0.0.2", "10.0.0.1", 443, 5000, 1, 600, 65535, 0, false, false, false}, // #1 normal
		{"10.0.0.2", "10.0.0.1", 443, 5000, 1, 600, 65535, 0, false, false, false}, // #2 dupack
		{"10.0.0.2", "10.0.0.1", 443, 5000, 1, 600, 65535, 0, false, false, false}, // #3 dupack
	})
	if flags[1].IsDuplicateAck {
		t.Error("first ACK should not be a duplicate")
	}
	if !flags[2].IsDuplicateAck {
		t.Error("second identical ACK should be flagged as duplicate")
	}
	if flags[2].DuplicateAckCount != 2 {
		t.Errorf("first dup should be #2, got %d", flags[2].DuplicateAckCount)
	}
	if !flags[3].IsDuplicateAck || flags[3].DuplicateAckCount != 3 {
		t.Errorf("second dup should be #3, got count=%d", flags[3].DuplicateAckCount)
	}
}

func TestTCPFlagAnalyzer_DuplicateAckResetsOnNewData(t *testing.T) {
	flags := run([]tcpPkt{
		{"10.0.0.1", "10.0.0.2", 5000, 443, 500, 0, 65535, 100, false, false, false},
		// First ACK establishes the baseline.
		{"10.0.0.2", "10.0.0.1", 443, 5000, 1, 600, 65535, 0, false, false, false},
		{"10.0.0.2", "10.0.0.1", 443, 5000, 1, 600, 65535, 0, false, false, false}, // dupack #2
		// New data segment from reverse direction — resets the chain.
		{"10.0.0.2", "10.0.0.1", 443, 5000, 1, 600, 65535, 50, false, false, false},
		// Another ACK with the same ack_num — should NOT be a duplicate now.
		{"10.0.0.2", "10.0.0.1", 443, 5000, 51, 600, 65535, 0, false, false, false},
	})
	if !flags[2].IsDuplicateAck {
		t.Error("expected duplicate ACK at index 2")
	}
	if flags[4].IsDuplicateAck {
		t.Error("dup-ACK chain should have been reset after a data segment")
	}
}

// ─── Zero Window ────────────────────────────────────────────────

func TestTCPFlagAnalyzer_ZeroWindow(t *testing.T) {
	flags := run([]tcpPkt{
		// Normal ACK with non-zero window.
		{"10.0.0.2", "10.0.0.1", 443, 5000, 1, 600, 65535, 0, false, false, false},
		// Zero-window signal from the receiver.
		{"10.0.0.2", "10.0.0.1", 443, 5000, 1, 700, 0, 0, false, false, false},
		// RST with w=0 is NOT a zero-window signal.
		{"10.0.0.2", "10.0.0.1", 443, 5000, 1, 700, 0, 0, false, true, false},
		// SYN with w=0 is a legitimate initial advertisement, not flagged.
		{"10.0.0.1", "10.0.0.2", 5000, 443, 100, 0, 0, 0, true, false, false},
	})
	if flags[0].IsZeroWindow {
		t.Error("normal packet should not be zero-window")
	}
	if !flags[1].IsZeroWindow {
		t.Error("zero-window ACK should be flagged")
	}
	if flags[2].IsZeroWindow {
		t.Error("RST with w=0 should NOT be zero-window flagged")
	}
	if flags[3].IsZeroWindow {
		t.Error("SYN with w=0 should NOT be zero-window flagged")
	}
}

// ─── Keep-Alive ─────────────────────────────────────────────────

func TestTCPFlagAnalyzer_KeepAlive(t *testing.T) {
	// Build: data segment establishing highwater=1100 (seq 1000 + 100).
	// Then keep-alive probe with seq = 1099 (highwater - 1), payload = 0.
	flags := run([]tcpPkt{
		{"10.0.0.1", "10.0.0.2", 5000, 443, 1000, 0, 65535, 100, false, false, false},
		{"10.0.0.1", "10.0.0.2", 5000, 443, 1099, 0, 65535, 0, false, false, false},
	})
	if flags[0].IsKeepAlive {
		t.Error("data segment should not be keep-alive")
	}
	if !flags[1].IsKeepAlive {
		t.Error("seq = (next_expected - 1) with payload=0 should be flagged as keep-alive")
	}
}

func TestTCPFlagAnalyzer_KeepAliveOneBytePayload(t *testing.T) {
	// Some stacks send 1 byte of garbage in keep-alives.
	flags := run([]tcpPkt{
		{"10.0.0.1", "10.0.0.2", 5000, 443, 1000, 0, 65535, 100, false, false, false},
		{"10.0.0.1", "10.0.0.2", 5000, 443, 1099, 0, 65535, 1, false, false, false},
	})
	if !flags[1].IsKeepAlive {
		t.Error("1-byte probe at seq = (next - 1) should be flagged as keep-alive")
	}
}

func TestTCPFlagAnalyzer_NotKeepAliveOnFreshFlow(t *testing.T) {
	// Without any prior segment in the direction, we don't have a valid
	// "next expected seq", so we can't legitimately flag a keep-alive.
	flags := run([]tcpPkt{
		{"10.0.0.1", "10.0.0.2", 5000, 443, 99, 0, 65535, 0, false, false, false},
	})
	if flags[0].IsKeepAlive {
		t.Error("first packet in a flow cannot be a keep-alive (no state)")
	}
}

// ─── Combined behaviour ─────────────────────────────────────────

func TestTCPFlagAnalyzer_HasAny(t *testing.T) {
	var f TCPAnalysisFlags
	if f.HasAny() {
		t.Error("empty flags should return false")
	}
	f.IsZeroWindow = true
	if !f.HasAny() {
		t.Error("any flag should make HasAny() return true")
	}
}

func TestTCPFlagAnalyzer_Reset(t *testing.T) {
	a := NewTCPFlagAnalyzer()
	// Seed state with one packet.
	a.Analyze("10.0.0.1", "10.0.0.2", 5000, 443, 1000, 0, 65535, 100, false, false, false)
	if len(a.flows) != 1 {
		t.Fatalf("expected 1 flow, got %d", len(a.flows))
	}
	a.Reset()
	if len(a.flows) != 0 {
		t.Errorf("Reset() should empty the flow map, got %d flows", len(a.flows))
	}
	// After reset, a retransmission of the seeded segment should NOT be
	// flagged because the history is gone.
	f := a.Analyze("10.0.0.1", "10.0.0.2", 5000, 443, 1000, 0, 65535, 100, false, false, false)
	if f.IsRetransmission {
		t.Error("after Reset, seeded retransmission should be a fresh segment")
	}
}
