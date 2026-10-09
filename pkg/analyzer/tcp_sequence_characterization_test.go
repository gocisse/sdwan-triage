package analyzer

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gocisse/sdwan-triage/internal/testpcap"
	"github.com/gocisse/sdwan-triage/pkg/detector"
	"github.com/gocisse/sdwan-triage/pkg/models"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// Phase 4.30a — characterization of CURRENT TCP sequence-gap, out-of-order and
// duplicate-ACK behaviour, before any new evidence is implemented.
//
// These tests assert what the code does today, including surprising and
// misleading behaviour (each is marked LEGACY QUIRK). They are NOT claims that the
// behaviour is correct. Four independent analysis paths are characterized
// separately and must not be forced to agree:
//
//   1. the live TCP detector (pkg/detector/tcp.go) + packet-loss detector, observed
//      through the full Processor (events, TCPRetransmissions, PacketLoss);
//   2. pkg/detector/tcp_advanced.go ("out-of-order" = Seq < LastSeq);
//   3. pkg/analyzer/stream_reassembly.go (IsRetransmit = seq <= previous seq,
//      IsOutOfOrder = forward jump > 1000 bytes);
//   4. compare-mode pkg/analyzer/tcp_analysis.go TCPFlagAnalyzer (duplicate ACK).
//
// Scenarios that cannot be reached through an existing entry point are listed in
// plans/phase-4.30a-tcp-gap-duplicate-ack-characterization.md.
// Synthetic packets are 100 ms apart (packet i at testpcap.BaseTime + i*100 ms).

const seqCliPort = 51000

// seqSpec describes one synthetic TCP segment (client = 192.168.1.100:port,
// server = 10.0.0.50:443).
type seqSpec struct {
	fromServer bool
	seq, ack   uint32
	flags      uint8 // testpcap.SYN/ACK/FIN/RST/PSH bits
	win        uint16
	payload    int
	sack       [][2]uint32
}

func seqFrame(port uint16, s seqSpec) []byte {
	srcMAC, dstMAC := testpcap.ClientMAC, testpcap.ServerMAC
	srcIP, dstIP := testpcap.ClientIP, testpcap.ServerIP
	sp, dp := layers.TCPPort(port), layers.TCPPort(443)
	if s.fromServer {
		srcMAC, dstMAC = dstMAC, srcMAC
		srcIP, dstIP = dstIP, srcIP
		sp, dp = dp, sp
	}
	win := s.win
	if win == 0 && s.flags&testpcap.RST == 0 {
		win = 65535
	}
	eth := &layers.Ethernet{SrcMAC: srcMAC, DstMAC: dstMAC, EthernetType: layers.EthernetTypeIPv4}
	ip := &layers.IPv4{Version: 4, IHL: 5, TTL: 64, Protocol: layers.IPProtocolTCP, SrcIP: srcIP, DstIP: dstIP}
	tcp := &layers.TCP{
		SrcPort: sp, DstPort: dp, Seq: s.seq, Ack: s.ack, Window: win,
		FIN: s.flags&testpcap.FIN != 0, SYN: s.flags&testpcap.SYN != 0, RST: s.flags&testpcap.RST != 0,
		PSH: s.flags&testpcap.PSH != 0, ACK: s.flags&testpcap.ACK != 0,
	}
	if len(s.sack) > 0 {
		data := make([]byte, 0, 8*len(s.sack))
		for _, e := range s.sack {
			var b [8]byte
			binary.BigEndian.PutUint32(b[0:4], e[0])
			binary.BigEndian.PutUint32(b[4:8], e[1])
			data = append(data, b[:]...)
		}
		tcp.Options = []layers.TCPOption{{OptionType: layers.TCPOptionKindSACK, OptionLength: uint8(2 + len(data)), OptionData: data}}
	}
	tcp.SetNetworkLayerForChecksum(ip)
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true},
		eth, ip, tcp, gopacket.Payload(make([]byte, s.payload))); err != nil {
		panic(err)
	}
	return buf.Bytes()
}

func frames(port uint16, specs ...seqSpec) [][]byte {
	out := make([][]byte, len(specs))
	for i, s := range specs {
		out[i] = seqFrame(port, s)
	}
	return out
}

func pktAt(b []byte, i int) gopacket.Packet {
	p := gopacket.NewPacket(b, layers.LayerTypeEthernet, gopacket.Default)
	p.Metadata().Timestamp = testpcap.BaseTime.Add(time.Duration(i) * testpcap.DefaultInterval)
	return p
}

// Shorthands: client data / server data / pure ACK from either side.
func cData(seq uint32, n int) seqSpec {
	return seqSpec{seq: seq, ack: 5001, flags: testpcap.PSH | testpcap.ACK, payload: n}
}
func sAck(ack uint32, win uint16) seqSpec {
	return seqSpec{fromServer: true, seq: 5001, ack: ack, flags: testpcap.ACK, win: win}
}

var hs = []seqSpec{
	{seq: 1000, flags: testpcap.SYN},
	{fromServer: true, seq: 5000, ack: 1001, flags: testpcap.SYN | testpcap.ACK},
	{seq: 1001, ack: 5001, flags: testpcap.ACK},
}

func scenario(port uint16, specs ...seqSpec) *models.TriageReport {
	return runGolden(nil2t, append(frames(port, hs...), frames(port, specs...)...))
}

// nil2t is replaced per test via sc(); kept to make scenario() readable.
var nil2t *testing.T

func sc(t *testing.T, port uint16, specs ...seqSpec) *models.TriageReport {
	t.Helper()
	nil2t = t
	return scenario(port, specs...)
}

// Sequence-evidence kinds other than the ones added deliberately must stay absent.
// Phase 4.30c deliberately introduced tcp.sequence_gap and Phase 4.30d
// tcp.duplicate_ack_run (the only exemptions); every other kind in the list below is
// still expected to be absent.
func assertNoSequenceEvidenceKinds(t *testing.T, r *models.TriageReport) {
	t.Helper()
	for k := range r.EventCounts {
		if k == "tcp.sequence_gap" || k == "tcp.duplicate_ack_run" {
			continue
		}
		for _, banned := range []string{"tcp.sequence", "tcp.gap", "tcp.duplicate", "tcp.dup", "tcp.sack", "tcp.fast", "tcp.out_of_order"} {
			if strings.HasPrefix(k, banned) {
				t.Errorf("unexpected sequence-evidence event kind %q exists today", k)
			}
		}
	}
}

// streamFlags runs frames through a fresh StreamReassembler and returns, for the
// single TCP stream, one marker per payload segment: "-" normal, "R" IsRetransmit,
// "O" IsOutOfOrder.
func streamFlags(t *testing.T, port uint16, specs ...seqSpec) string {
	t.Helper()
	sr := NewStreamReassembler(false)
	for i, b := range frames(port, specs...) {
		sr.ProcessPacket(pktAt(b, i))
	}
	var sb strings.Builder
	for _, s := range sr.GetStreamsSorted() {
		for _, sg := range s.Segments {
			switch {
			case sg.IsRetransmit:
				sb.WriteString("R")
			case sg.IsOutOfOrder:
				sb.WriteString("O")
			default:
				sb.WriteString("-")
			}
		}
	}
	return sb.String()
}

// advancedOOO runs frames through a fresh TCPAdvancedAnalyzer and returns the
// finalized out-of-order flows.
func advancedOOO(frs [][]byte) []models.TCPOutOfOrderFlow {
	a := detector.NewTCPAdvancedAnalyzer()
	state := models.NewAnalysisState()
	report := &models.TriageReport{}
	for i, b := range frs {
		a.Analyze(pktAt(b, i), state, report)
	}
	a.Finalize(report)
	return report.TCPOutOfOrderFlows
}

// ─── 1. Live detector (+ packet-loss) through the full Processor ────────────

func TestSeqChar_Live_InOrderDelivery_NoEvidence(t *testing.T) {
	r := sc(t, seqCliPort,
		cData(1001, 100), sAck(1101, 0), cData(1101, 100), sAck(1201, 0), cData(1201, 100), sAck(1301, 0))
	if len(retxEvents(r)) != 0 || len(r.TCPRetransmissions) != 0 || lostPackets(r) != 0 || len(r.TCPOutOfOrderFlows) != 0 {
		t.Errorf("in-order delivery produced evidence: retx=%d flows=%d lost=%d ooo=%d", len(retxEvents(r)), len(r.TCPRetransmissions), lostPackets(r), len(r.TCPOutOfOrderFlows))
	}
	assertNoSequenceEvidenceKinds(t, r)
}

// A forward gap is not noticed by the live pipeline: segment 1101..1200 never
// appears, 1201 arrives, nothing is reported, and it is never resolved.
func TestSeqChar_Live_ForwardGapUnresolved_Silent(t *testing.T) {
	r := sc(t, seqCliPort, cData(1001, 100), cData(1201, 100), cData(1301, 100), sAck(1101, 0))
	if len(retxEvents(r)) != 0 || len(r.TCPRetransmissions) != 0 || lostPackets(r) != 0 {
		t.Errorf("a sequence gap produced retransmission/loss evidence: events=%d lost=%d", len(retxEvents(r)), lostPackets(r))
	}
	assertNoSequenceEvidenceKinds(t, r)
}

// LEGACY QUIRK: a segment that FILLS a gap has a start sequence number that was
// never seen, so it is not a retransmission for the live detector or the
// packet-loss detector. The loss upstream of the capture point is invisible.
func TestSeqChar_Live_GapThenFill_NotARetransmission(t *testing.T) {
	r := sc(t, seqCliPort, cData(1001, 100), cData(1201, 100), cData(1101, 100), sAck(1301, 0))
	if len(retxEvents(r)) != 0 || len(r.TCPRetransmissions) != 0 || lostPackets(r) != 0 {
		t.Errorf("gap fill counted: events=%d flows=%d lost=%d", len(retxEvents(r)), len(r.TCPRetransmissions), lostPackets(r))
	}
}

// Out-of-order arrival without any missing data: also silent for the live detector.
func TestSeqChar_Live_PureReordering_Silent(t *testing.T) {
	r := sc(t, seqCliPort, cData(1101, 100), cData(1001, 100), sAck(1201, 0))
	if len(retxEvents(r)) != 0 || lostPackets(r) != 0 {
		t.Errorf("pure reordering produced events=%d lost=%d", len(retxEvents(r)), lostPackets(r))
	}
}

// Partial overlap: the second segment starts at a NEW sequence number inside the
// first one's range, so no start sequence repeats: not a retransmission.
func TestSeqChar_Live_PartialOverlap_NotARetransmission(t *testing.T) {
	r := sc(t, seqCliPort, cData(1001, 200), cData(1101, 200), sAck(1301, 0))
	if len(retxEvents(r)) != 0 || lostPackets(r) != 0 {
		t.Errorf("partial overlap counted: events=%d lost=%d", len(retxEvents(r)), lostPackets(r))
	}
}

// Exact repeated sequence start: the one case the live pipeline does report
// (events, flow and packet-loss counters all see it).
func TestSeqChar_Live_ExactRepeatedStart_Reported(t *testing.T) {
	r := sc(t, seqCliPort, cData(1001, 100), cData(1001, 100))
	if len(retxEvents(r)) != 1 || len(r.TCPRetransmissions) != 1 || lostPackets(r) != 1 {
		t.Errorf("events=%d flows=%d lost=%d, want 1/1/1", len(retxEvents(r)), len(r.TCPRetransmissions), lostPackets(r))
	}
}

// The motivating pattern (modelled on Lab 3): gap, three SACK duplicate ACKs, then
// a segment at the missing sequence. Nothing is reported - not the gap, not the
// duplicate ACKs, not the SACK blocks, not the resend.
func TestSeqChar_Live_GapDupAcksSACKThenResend_ReportsNothing(t *testing.T) {
	sackAck := func(sackFrom, sackTo uint32) seqSpec {
		return seqSpec{fromServer: true, seq: 5001, ack: 1101, flags: testpcap.ACK, win: 17520, sack: [][2]uint32{{sackFrom, sackTo}}}
	}
	r := sc(t, seqCliPort,
		cData(1001, 100),    // original, in order
		cData(1201, 100),    // gap: 1101..1200 not seen
		sackAck(1201, 1301), // dup ACK 1 with SACK
		cData(1301, 100),    // more data beyond the hole
		sackAck(1201, 1401), // dup ACK 2
		cData(1401, 100),    //
		sackAck(1201, 1501), // dup ACK 3
		cData(1101, 100),    // the missing segment finally arrives (first time seen)
		sAck(1501, 0),
	)
	if len(retxEvents(r)) != 0 || len(r.TCPRetransmissions) != 0 || lostPackets(r) != 0 {
		t.Errorf("the gap/dup-ACK/resend pattern produced retransmission evidence: events=%d lost=%d", len(retxEvents(r)), lostPackets(r))
	}
	assertNoSequenceEvidenceKinds(t, r)
	for k := range r.EventCounts {
		// Phase 4.30c/4.30d: tcp.sequence_gap (the gap before the missing segment) and
		// tcp.duplicate_ack_run (the three SACK duplicate ACKs) are the deliberate
		// additions; everything else must still be absent.
		if strings.HasPrefix(k, "tcp.") && k != "tcp.rtt_spike" && k != "tcp.zero_window" && k != "tcp.sequence_gap" && k != "tcp.duplicate_ack_run" {
			t.Errorf("unexpected TCP event kind %q in the gap/dup-ACK scenario", k)
		}
	}
}

// Pure ACKs (changing ack, repeated ack, changing window, no peer data) never
// create live-pipeline evidence of any kind.
func TestSeqChar_Live_AcksAreSilent(t *testing.T) {
	r := sc(t, seqCliPort,
		cData(1001, 100),
		sAck(1101, 100), sAck(1101, 100), sAck(1101, 100), sAck(1101, 200), // repeats and a window change
		seqSpec{seq: 1101, ack: 5001, flags: testpcap.ACK}, // client ACK, nothing outstanding
		seqSpec{seq: 1101, ack: 5001, flags: testpcap.ACK},
	)
	if len(retxEvents(r)) != 0 || lostPackets(r) != 0 || len(r.TCPRetransmissions) != 0 {
		t.Errorf("ACK traffic produced retransmission evidence")
	}
	assertNoSequenceEvidenceKinds(t, r)
}

func TestSeqChar_Live_RSTAndFIN_NoSequenceEvidence(t *testing.T) {
	r := sc(t, seqCliPort,
		cData(1001, 100),
		seqSpec{fromServer: true, seq: 5001, ack: 1101, flags: testpcap.FIN | testpcap.ACK},
		seqSpec{seq: 1101, ack: 5002, flags: testpcap.RST | testpcap.ACK},
	)
	if len(retxEvents(r)) != 0 || lostPackets(r) != 0 {
		t.Errorf("FIN/RST produced retransmission evidence")
	}
	assertNoSequenceEvidenceKinds(t, r)
}

func TestSeqChar_Live_OutputIsDeterministic(t *testing.T) {
	build := func() [][]byte {
		return append(frames(seqCliPort, hs...), frames(seqCliPort,
			cData(1001, 100), cData(1201, 100), cData(1101, 100), cData(1101, 100), sAck(1301, 0))...)
	}
	snap := func() string {
		r := runGolden(t, build())
		return strings.Join([]string{
			intS(len(retxEvents(r))), intS(len(r.TCPRetransmissions)), intS(int(lostPackets(r))), intS(len(r.TCPOutOfOrderFlows)),
		}, ",")
	}
	first := snap()
	for i := 0; i < 4; i++ {
		if got := snap(); got != first {
			t.Fatalf("run %d = %s, want %s", i+2, got, first)
		}
	}
}

func intS(n int) string { return strconv.Itoa(n) }

// ─── 2. tcp_advanced.go: "out-of-order" is Seq < LastSeq on payload packets ──

// Reporting needs >=10 such packets AND >=20 payload packets AND >=2 %
// (OutOfOrderMinCount / OutOfOrderMinPercent); anything smaller is invisible.
func TestSeqChar_Advanced_SmallNumbersBelowThresholdsAreInvisible(t *testing.T) {
	specs := frames(seqCliPort, hs...)
	for i := 0; i < 25; i++ {
		specs = append(specs, seqFrame(seqCliPort, cData(1001+uint32(i)*100, 100)))
	}
	specs = append(specs, seqFrame(seqCliPort, cData(1101, 100))) // one reordered/repeated segment
	if got := advancedOOO(specs); len(got) != 0 {
		t.Errorf("a single out-of-order packet was reported: %+v", got)
	}
}

// LEGACY QUIRK: genuine reordering (each segment preceded by its successor, no
// data missing) is counted, exactly like a retransmission.
func TestSeqChar_Advanced_ReorderedSegmentsAreCounted(t *testing.T) {
	var specs [][]byte
	specs = append(specs, frames(seqCliPort, hs...)...)
	seq := uint32(1001)
	for i := 0; i < 12; i++ { // 12 pairs delivered as (second, first): 24 packets, 12 out of order
		specs = append(specs, seqFrame(seqCliPort, cData(seq+100, 100)), seqFrame(seqCliPort, cData(seq, 100)))
		seq += 200
	}
	got := advancedOOO(specs)
	if len(got) != 1 || got[0].OutOfOrderCount != 12 || got[0].TotalPackets != 24 {
		t.Fatalf("out-of-order flows = %+v, want one flow with 12 of 24 payload packets", got)
	}
	if got[0].Severity != "Critical" { // 50 % > 10 %
		t.Errorf("severity = %q, want Critical at 50%%", got[0].Severity)
	}
}

// LEGACY QUIRK: exact retransmissions are ALSO "out-of-order" here (and are also
// retransmission events elsewhere), so the two signals double-count one cause.
func TestSeqChar_Advanced_RetransmissionsAreCountedAsOutOfOrder(t *testing.T) {
	var specs [][]byte
	specs = append(specs, frames(seqCliPort, hs...)...)
	for i := 0; i < 12; i++ { // data segment i then an exact repeat of the PREVIOUS one
		specs = append(specs, seqFrame(seqCliPort, cData(1001+uint32(i)*100, 100)))
		if i > 0 {
			specs = append(specs, seqFrame(seqCliPort, cData(1001+uint32(i-1)*100, 100)))
		}
	}
	got := advancedOOO(specs)
	if len(got) != 1 || got[0].OutOfOrderCount != 11 {
		t.Fatalf("out-of-order flows = %+v, want 11 counted retransmissions", got)
	}
	r := runGolden(t, specs)
	if n := len(retxEvents(r)); n != 11 {
		t.Errorf("the same scenario yields %d tcp.retransmission events, want 11", n)
	}
	if len(r.TCPOutOfOrderFlows) != 1 {
		t.Errorf("full pipeline TCPOutOfOrderFlows = %d, want 1", len(r.TCPOutOfOrderFlows))
	}
}

// A forward gap or an unresolved gap never counts as out-of-order here.
func TestSeqChar_Advanced_ForwardGapIsNotOutOfOrder(t *testing.T) {
	var specs [][]byte
	specs = append(specs, frames(seqCliPort, hs...)...)
	for i := 0; i < 30; i++ { // every second segment missing: 30 forward jumps, nothing out of order
		specs = append(specs, seqFrame(seqCliPort, cData(1001+uint32(i)*200, 100)))
	}
	if got := advancedOOO(specs); len(got) != 0 {
		t.Errorf("forward gaps reported as out-of-order: %+v", got)
	}
}

// ─── 3. stream_reassembly.go: R = seq <= previous seq, O = jump > 1000 B ──

func TestSeqChar_Stream_InOrder(t *testing.T) {
	if got := streamFlags(t, seqCliPort, cData(1001, 100), cData(1101, 100), cData(1201, 100)); got != "---" {
		t.Errorf("flags = %q, want ---", got)
	}
}

// A gap smaller than 1000 bytes is not flagged at all; a larger forward jump is
// labelled "Out-of-order" (it is a gap) and, once flagged, is never resolved.
func TestSeqChar_Stream_ForwardGap_ThresholdIs1000Bytes(t *testing.T) {
	if got := streamFlags(t, seqCliPort, cData(1001, 100), cData(1201, 100)); got != "--" {
		t.Errorf("200-byte gap flags = %q, want -- (not flagged)", got)
	}
	if got := streamFlags(t, seqCliPort, cData(1001, 100), cData(6001, 100)); got != "-O" {
		t.Errorf("4.9 kB jump flags = %q, want -O", got)
	}
	// The rule is seq > previousSeq + len(CURRENT payload) + 1000 (note: the previous
	// packet's START, not its end): with previous seq 1001 and a 100-byte segment the
	// boundary is 2101, strictly greater than.
	if got := streamFlags(t, seqCliPort, cData(1001, 100), cData(2102, 100)); got != "-O" {
		t.Errorf("seq 2102 flags = %q, want -O", got)
	}
	if got := streamFlags(t, seqCliPort, cData(1001, 100), cData(2101, 100)); got != "--" {
		t.Errorf("seq 2101 (exactly at the boundary) flags = %q, want --", got)
	}
}

// LEGACY QUIRK: a segment that fills a gap, and a plain reordered segment, are
// both labelled "Retransmission" (seq <= previous packet's seq).
func TestSeqChar_Stream_GapFillAndReordering_LabelledRetransmission(t *testing.T) {
	if got := streamFlags(t, seqCliPort, cData(1001, 100), cData(1201, 100), cData(1101, 100)); got != "--R" {
		t.Errorf("gap then fill flags = %q, want --R", got)
	}
	if got := streamFlags(t, seqCliPort, cData(1101, 100), cData(1001, 100)); got != "-R" {
		t.Errorf("reordered pair flags = %q, want -R", got)
	}
}

func TestSeqChar_Stream_ExactRepeatAndPartialOverlap(t *testing.T) {
	if got := streamFlags(t, seqCliPort, cData(1001, 100), cData(1001, 100)); got != "-R" {
		t.Errorf("exact repeat flags = %q, want -R", got)
	}
	// Partial overlap starts at a higher sequence number: not flagged.
	if got := streamFlags(t, seqCliPort, cData(1001, 200), cData(1101, 200)); got != "--" {
		t.Errorf("partial overlap flags = %q, want --", got)
	}
}

// LEGACY QUIRK: the comparison is with the PREVIOUS packet of the direction only,
// so a repeat of an older segment after newer data is flagged only if it is lower
// than the immediately preceding packet; and no pure ACK ever reaches the stream.
func TestSeqChar_Stream_OnlyPayloadSegmentsAreRecorded(t *testing.T) {
	got := streamFlags(t, seqCliPort, cData(1001, 100), sAck(1101, 0), sAck(1101, 0), cData(1101, 100))
	if got != "--" {
		t.Errorf("flags = %q, want -- (ACK-only packets are not stream segments)", got)
	}
}

// ─── 4. Compare-mode TCPFlagAnalyzer (duplicate ACK, different rules) ───────

func ack(a *TCPFlagAnalyzer, ackNum uint32, window uint16, payload int, syn, rst, fin bool) TCPAnalysisFlags {
	return a.Analyze("10.0.0.2", "10.0.0.1", 443, 50000, 5001, ackNum, window, payload, syn, rst, fin)
}

func TestSeqChar_Compare_DuplicateACK_Counting(t *testing.T) {
	a := NewTCPFlagAnalyzer()
	f1 := ack(a, 1101, 100, 0, false, false, false)
	f2 := ack(a, 1101, 100, 0, false, false, false)
	f3 := ack(a, 1101, 100, 0, false, false, false)
	f4 := ack(a, 1101, 100, 0, false, false, false)
	if f1.IsDuplicateAck || !f2.IsDuplicateAck || f2.DuplicateAckCount != 2 || f3.DuplicateAckCount != 3 || f4.DuplicateAckCount != 4 {
		t.Errorf("dup-ACK flags = %+v %+v %+v %+v", f1, f2, f3, f4)
	}
	// A changed ack number restarts the chain.
	if f := ack(a, 1201, 100, 0, false, false, false); f.IsDuplicateAck {
		t.Errorf("changed ack number flagged as duplicate: %+v", f)
	}
}

// LEGACY QUIRK: the window is ignored. RFC 5681 requires an UNCHANGED window; here
// the same ack number with a different window is still a "duplicate".
func TestSeqChar_Compare_DuplicateACK_IgnoresWindowChange(t *testing.T) {
	a := NewTCPFlagAnalyzer()
	ack(a, 1101, 100, 0, false, false, false)
	if f := ack(a, 1101, 5000, 0, false, false, false); !f.IsDuplicateAck {
		t.Errorf("same ack with a changed window should currently be flagged: %+v", f)
	}
}

// LEGACY QUIRK: there is no "data outstanding" requirement. An idle connection that
// repeats the same pure ACK (no data from the peer was ever sent) is flagged.
func TestSeqChar_Compare_DuplicateACK_FlaggedWithNoOutstandingData(t *testing.T) {
	a := NewTCPFlagAnalyzer()
	ack(a, 1, 2048, 0, false, false, false)
	if f := ack(a, 1, 2048, 0, false, false, false); !f.IsDuplicateAck {
		t.Errorf("idle repeated ACK should currently be flagged: %+v", f)
	}
}

func TestSeqChar_Compare_DuplicateACK_PayloadAndControlFlagsBreakTheChain(t *testing.T) {
	a := NewTCPFlagAnalyzer()
	ack(a, 1101, 100, 0, false, false, false)
	if f := ack(a, 1101, 100, 50, false, false, false); f.IsDuplicateAck {
		t.Errorf("ACK carrying payload flagged as duplicate: %+v", f)
	}
	// The payload-carrying packet reset the chain, so the next pure ACK is a first observation.
	if f := ack(a, 1101, 100, 0, false, false, false); f.IsDuplicateAck {
		t.Errorf("chain should have been reset by the payload segment: %+v", f)
	}
	for _, c := range []struct {
		name          string
		syn, rst, fin bool
	}{{"SYN", true, false, false}, {"RST", false, true, false}, {"FIN", false, false, true}} {
		a := NewTCPFlagAnalyzer()
		ack(a, 1101, 100, 0, false, false, false)
		if f := ack(a, 1101, 100, 0, c.syn, c.rst, c.fin); f.IsDuplicateAck {
			t.Errorf("%s packet flagged as duplicate ACK", c.name)
		}
	}
}

// The compare-mode analyzer has no gap, overlap or out-of-order notion: it can
// only mark an exact (seq,len) repeat.
func TestSeqChar_Compare_NoGapOrOverlapNotion(t *testing.T) {
	a := NewTCPFlagAnalyzer()
	data := func(seq uint32, n int) TCPAnalysisFlags {
		return a.Analyze("10.0.0.1", "10.0.0.2", 50000, 443, seq, 5001, 100, n, false, false, false)
	}
	for _, f := range []TCPAnalysisFlags{data(1001, 100), data(1301, 100) /*gap*/, data(1101, 100) /*fill*/, data(1151, 100) /*overlap*/} {
		if f.HasAny() {
			t.Errorf("gap/fill/overlap segment produced flags: %+v", f)
		}
	}
	if f := data(1101, 100); !f.IsRetransmission {
		t.Errorf("exact (seq,len) repeat should be flagged: %+v", f)
	}
	// Same start, different length: not a retransmission here (the live detector would flag it).
	if f := data(1101, 60); f.IsRetransmission {
		t.Errorf("same start with a different length flagged: %+v", f)
	}
}

// ─── 5. Optional real-capture characterization (SDWAN_VENDOR_PCAP_DIR) ────

// Reference values measured at HEAD 38f86b6 + Phase 4.29 work. They record what
// the current analyzers say; tshark is NOT required to agree (it reports lost
// segments / duplicate ACKs the tool does not model). A missing capture is skipped.
func TestSeqChar_RealCaptures_CurrentSequenceSignals(t *testing.T) {
	dir := os.Getenv("SDWAN_VENDOR_PCAP_DIR")
	if dir == "" {
		t.Skip("SDWAN_VENDOR_PCAP_DIR not set; skipping real-capture sequence characterization")
	}
	cases := []struct {
		name                  string
		advFlows, advCount    int
		streamRetx, streamOOO int // over the top-50 reassembled streams
	}{
		{"Lab 3-TCP Retrans", 1, 10, 0, 1},
		{"Lab 4-NetworkCongestion", 0, 0, 1, 0},
		{"user1", 0, 0, 3, 17},
		{"Velocloud-Lan", 0, 0, 0, 57},
		{"Velocloud-Wan", 0, 0, 0, 38},
		{"cisco-example-lan", 0, 0, 4, 377},
		{"The-Ultimate-PCAP", 0, 0, 0, 0},
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
			cnt := 0
			for _, f := range r.TCPOutOfOrderFlows {
				cnt += f.OutOfOrderCount
			}
			if len(r.TCPOutOfOrderFlows) != c.advFlows || cnt != c.advCount {
				t.Errorf("tcp_advanced out-of-order flows/packets = %d/%d, want %d/%d", len(r.TCPOutOfOrderFlows), cnt, c.advFlows, c.advCount)
			}
			retx, ooo := 0, 0
			for _, s := range r.RawStreams {
				for _, sg := range s.Segments {
					if sg.IsRetransmit {
						retx++
					}
					if sg.IsOutOfOrder {
						ooo++
					}
				}
			}
			if retx != c.streamRetx || ooo != c.streamOOO {
				t.Errorf("stream segments IsRetransmit/IsOutOfOrder = %d/%d, want %d/%d", retx, ooo, c.streamRetx, c.streamOOO)
			}
			assertNoSequenceEvidenceKinds(t, r)
		})
	}
}
