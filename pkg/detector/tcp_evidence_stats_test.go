package detector

import (
	"net"
	"testing"
	"time"

	"github.com/gocisse/sdwan-triage/pkg/events"
	"github.com/gocisse/sdwan-triage/pkg/models"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// Phase 4.31a: bound handling of the three deferred TCP evidence trackers, with small
// bounds set through the trackers' fields. Known omitted events and tracking limits
// are asserted separately.

type evTCP struct {
	fromB     bool // false: A(10.0.0.1:portA) -> B(10.0.0.2:443); true: B -> A
	seq, ack  uint32
	syn, ackF bool
	rst, fin  bool
	payload   int
	window    uint16
}

func evPkt(portA uint16, s evTCP, i int) gopacket.Packet {
	srcIP, dstIP := net.IP{10, 0, 0, 1}, net.IP{10, 0, 0, 2}
	sp, dp := layers.TCPPort(portA), layers.TCPPort(443)
	if s.fromB {
		srcIP, dstIP, sp, dp = dstIP, srcIP, dp, sp
	}
	win := s.window
	if win == 0 {
		win = 1000
	}
	eth := &layers.Ethernet{SrcMAC: net.HardwareAddr{0, 0, 0, 0, 0, 1}, DstMAC: net.HardwareAddr{0, 0, 0, 0, 0, 2}, EthernetType: layers.EthernetTypeIPv4}
	ip := &layers.IPv4{Version: 4, IHL: 5, TTL: 64, Protocol: layers.IPProtocolTCP, SrcIP: srcIP, DstIP: dstIP}
	tcp := &layers.TCP{SrcPort: sp, DstPort: dp, Seq: s.seq, Ack: s.ack, SYN: s.syn, ACK: s.ackF, RST: s.rst, FIN: s.fin, Window: win}
	tcp.SetNetworkLayerForChecksum(ip)
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true},
		eth, ip, tcp, gopacket.Payload(make([]byte, s.payload))); err != nil {
		panic(err)
	}
	p := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
	p.Metadata().Timestamp = time.Unix(1_700_000_000, 0).Add(time.Duration(i) * 100 * time.Millisecond)
	return p
}

type evHarness struct {
	a      *TCPAnalyzer
	state  *models.AnalysisState
	report *models.TriageReport
	rec    *events.Recorder
	n      int
}

func newEvHarness() *evHarness {
	ix := events.NewIndex(0)
	rec := events.NewRecorder(ix, "")
	return &evHarness{a: NewTCPAnalyzer(), state: models.NewAnalysisState(), report: &models.TriageReport{Events: ix, Emitter: rec}, rec: rec}
}

func (h *evHarness) feed(port uint16, s evTCP) {
	p := evPkt(port, s, h.n)
	h.rec.SetCurrentPacket(uint64(h.n), p.Metadata().Timestamp)
	h.a.Analyze(p, h.state, h.report)
	h.n++
}

func (h *evHarness) count(k events.Kind) int { return len(h.report.Events.ByKind(k)) }

func TestEvidenceStats_SYNRepeatEventCapIsAKnownOmission(t *testing.T) {
	h := newEvHarness()
	h.a.handshakeRepeats.maxEvents = 2
	for i := 0; i < 6; i++ { // initial SYN + 5 repeats on one key
		h.feed(40000, evTCP{syn: true, seq: 100})
	}
	h.a.Finalize(h.report)
	st := h.a.EvidenceStats()
	if h.count(events.TCPSYNRetransmission) != 2 || st.KnownSYNRepeatKindCap != 3 {
		t.Errorf("emitted %d (want 2), known omitted by cap %d (want 3)", h.count(events.TCPSYNRetransmission), st.KnownSYNRepeatKindCap)
	}
	if st.LimitHandshakeKeysUntracked != 0 {
		t.Errorf("a kind cap must not be reported as an untracked-key limit")
	}
}

func TestEvidenceStats_SYNKeyBoundIsATrackingLimitNotAnEventCount(t *testing.T) {
	h := newEvHarness()
	h.a.handshakeRepeats.maxKeys = 1
	h.feed(40000, evTCP{syn: true, seq: 100}) // tracked
	h.feed(40001, evTCP{syn: true, seq: 200}) // key bound reached: untracked
	h.feed(40001, evTCP{syn: true, seq: 200}) // a repeat that can no longer be seen
	h.feed(40000, evTCP{syn: true, seq: 100}) // still seen on the tracked key
	h.a.Finalize(h.report)
	st := h.a.EvidenceStats()
	if st.LimitHandshakeKeysUntracked != 2 || h.count(events.TCPSYNRetransmission) != 1 {
		t.Errorf("untracked=%d (want 2: both packets of the untracked key), events=%d (want 1)", st.LimitHandshakeKeysUntracked, h.count(events.TCPSYNRetransmission))
	}
	if st.KnownSYNRepeatKindCap != 0 {
		t.Errorf("untracked keys were reported as known omitted events")
	}
}

func TestEvidenceStats_GapRecordCapIsAKnownOmission(t *testing.T) {
	h := newEvHarness()
	h.a.seqGaps.maxRecords = 2
	h.feed(40000, evTCP{syn: true, seq: 1000})
	seq := uint32(1001)
	for i := 0; i < 5; i++ { // 5 forward gaps
		seq += 10
		h.feed(40000, evTCP{ackF: true, seq: seq, payload: 10, ack: 1})
		seq += 10
	}
	h.a.Finalize(h.report)
	st := h.a.EvidenceStats()
	if h.count(events.TCPSequenceGap) != 2 || st.KnownGapKindCap != 3 {
		t.Errorf("gap events %d (want 2), known omitted %d (want 3)", h.count(events.TCPSequenceGap), st.KnownGapKindCap)
	}
}

func TestEvidenceStats_DupAckBoundsSeparateKnownOmissionsFromCapacity(t *testing.T) {
	// Flow A and B each get a peer with data outstanding and a run of 1 duplicate.
	feedRun := func(h *evHarness, port uint16, ack uint32) {
		h.feed(port, evTCP{syn: true, seq: 1000})
		h.feed(port, evTCP{fromB: true, syn: true, ackF: true, seq: 5000, ack: 1001})
		h.feed(port, evTCP{ackF: true, seq: 1001, ack: 5001})
		h.feed(port, evTCP{ackF: true, seq: 1001, ack: 5001, payload: 100}) // client data outstanding
		h.feed(port, evTCP{fromB: true, ackF: true, seq: 5001, ack: ack})
		h.feed(port, evTCP{fromB: true, ackF: true, seq: 5001, ack: ack}) // duplicate
	}
	// Active-run bound: the second flow's run cannot be followed.
	h := newEvHarness()
	h.a.dupAcks.maxActive = 1
	feedRun(h, 40000, 1001)
	feedRun(h, 40001, 1001)
	h.a.Finalize(h.report)
	st := h.a.EvidenceStats()
	if h.count(events.TCPDuplicateACKRun) != 1 || st.KnownDupAckTrackerFull != 1 || st.KnownDupAckKindCap != 0 {
		t.Errorf("events=%d trackerFull=%d kindCap=%d, want 1/1/0", h.count(events.TCPDuplicateACKRun), st.KnownDupAckTrackerFull, st.KnownDupAckKindCap)
	}
	// Event cap: both runs are followed but only one is kept.
	h = newEvHarness()
	h.a.dupAcks.maxEvents = 1
	feedRun(h, 40000, 1001)
	feedRun(h, 40001, 1001)
	h.a.Finalize(h.report)
	st = h.a.EvidenceStats()
	if h.count(events.TCPDuplicateACKRun) != 1 || st.KnownDupAckKindCap != 1 || st.KnownDupAckTrackerFull != 0 {
		t.Errorf("events=%d kindCap=%d trackerFull=%d, want 1/1/0", h.count(events.TCPDuplicateACKRun), st.KnownDupAckKindCap, st.KnownDupAckTrackerFull)
	}
}

func TestEvidenceStats_PeerPositionUnknownIsCountedAsALimitOnly(t *testing.T) {
	h := newEvHarness()
	// Capture sees only one side's pure ACKs: the peer's sequence position is unknown.
	for i := 0; i < 4; i++ {
		h.feed(40000, evTCP{fromB: true, ackF: true, seq: 5001, ack: 1001})
	}
	h.a.Finalize(h.report)
	st := h.a.EvidenceStats()
	if st.LimitDupAckPeerPositionUnknown != 3 || h.count(events.TCPDuplicateACKRun) != 0 {
		t.Errorf("peerUnknown=%d (want 3 repeats), runs=%d (want 0)", st.LimitDupAckPeerPositionUnknown, h.count(events.TCPDuplicateACKRun))
	}
	// With the peer's data known and fully acknowledged, repeats are idle, not unknown.
	h = newEvHarness()
	h.feed(40000, evTCP{syn: true, seq: 1000})
	h.feed(40000, evTCP{ackF: true, seq: 1001, ack: 1, payload: 100})
	for i := 0; i < 3; i++ {
		h.feed(40000, evTCP{fromB: true, ackF: true, seq: 1, ack: 1101})
	}
	h.a.Finalize(h.report)
	if st := h.a.EvidenceStats(); st.LimitDupAckPeerPositionUnknown != 0 {
		t.Errorf("idle ACKs with a known peer were counted as peer-unknown: %d", st.LimitDupAckPeerPositionUnknown)
	}
}

func TestEvidenceStats_UnreadableLengthResetIsALimitNotAnOmission(t *testing.T) {
	h := newEvHarness()
	h.feed(40000, evTCP{syn: true, seq: 1000})
	// A truncated packet whose IP length is zero: the real segment length cannot be read.
	p := evPkt(40000, evTCP{ackF: true, seq: 1001, payload: 500}, h.n)
	b := p.Data()
	b[16], b[17] = 0, 0 // IPv4 total length
	q := gopacket.NewPacket(b, layers.LayerTypeEthernet, gopacket.Default)
	q.Metadata().Timestamp = p.Metadata().Timestamp
	q.Metadata().CaptureInfo.CaptureLength = len(b)
	q.Metadata().CaptureInfo.Length = len(b) + 400 // truncated by the capture
	h.rec.SetCurrentPacket(uint64(h.n), q.Metadata().Timestamp)
	h.a.Analyze(q, h.state, h.report)
	h.a.Finalize(h.report)
	st := h.a.EvidenceStats()
	if st.LimitSeqLengthUnreadable != 1 {
		t.Errorf("unreadable-length resets = %d, want 1", st.LimitSeqLengthUnreadable)
	}
	if st.KnownGapKindCap+st.KnownSYNRepeatKindCap+st.KnownDupAckKindCap+st.KnownDupAckTrackerFull != 0 {
		t.Errorf("a tracking reset was reported as known omitted events: %+v", st)
	}
}
