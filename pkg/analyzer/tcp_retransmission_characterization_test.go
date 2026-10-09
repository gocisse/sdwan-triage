package analyzer

import (
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"testing"

	"github.com/gocisse/sdwan-triage/internal/testpcap"
	"github.com/gocisse/sdwan-triage/pkg/events"
	"github.com/gocisse/sdwan-triage/pkg/models"
)

// Phase 4.29a — characterization tests for TCP retransmission accounting.
//
// These tests PIN CURRENT BEHAVIOUR so that the later shared-classifier
// refactor can be measured against it. They are not claims that the behaviour
// is semantically ideal: several pinned facts are known limitations recorded in
// plans/phase-4.29-tcp-retransmission-evidence-audit.md (SYN/SYN-ACK
// retransmissions are not retransmission events, the FIN-bearing divergence
// between the two live consumers, and a loss "percentage" that is really
// retransmissions / all decoded packets). If a test here fails after a
// refactor, the change in behaviour must be an explicit, reviewed decision.
//
// Synthetic packets are spaced testpcap.DefaultInterval (100 ms) apart, packet
// i being stamped base + i*100ms; the expected timings below follow from that.

const charPort = 50200

var psh = uint8(testpcap.PSH | testpcap.ACK)

func payloadBytes(n int) []byte { return make([]byte, n) }

func retxEvents(r *models.TriageReport) []events.Event {
	return r.Events.ByKind(events.TCPRetransmission)
}

func lostPackets(r *models.TriageReport) uint64 {
	if r.PacketLoss == nil {
		return 0
	}
	return r.PacketLoss.PacketsLost
}

// ─── A. Ordinary payload retransmission ──────────────────────────────

func TestCharacterize_PayloadRetransmission_EventFlowAndLoss(t *testing.T) {
	pk := handshake(charPort)                                             // 0,1,2
	pk = append(pk, tcpC2S(charPort, 1001, 2001, psh, payloadBytes(100))) // 3: original
	pk = append(pk, tcpS2C(charPort, 2001, 1101, testpcap.ACK, nil))      // 4
	pk = append(pk, tcpC2S(charPort, 1001, 2001, psh, payloadBytes(100))) // 5: same seq/len again
	r := runGolden(t, pk)

	ev := retxEvents(r)
	if len(ev) != 1 {
		t.Fatalf("tcp.retransmission events = %d, want 1: %+v", len(ev), ev)
	}
	e := ev[0]
	if e.Values["seq"] != 1001 || e.Values["payload_len"] != 100 {
		t.Errorf("event values = %+v, want seq 1001 len 100", e.Values)
	}
	// Packet 5 is two intervals (200 ms) after packet 3.
	if got := e.Values["since_original_ms"]; math.Abs(got-200) > 0.5 {
		t.Errorf("since_original_ms = %v, want 200", got)
	}
	if e.FlowKey != "192.168.1.100:50200->10.0.0.50:443" {
		t.Errorf("flow key = %q", e.FlowKey)
	}
	if len(r.TCPRetransmissions) != 1 || !hasTCPFlow(r.TCPRetransmissions, charPort, 443) {
		t.Errorf("distinct retransmission flows = %+v, want exactly the client->server flow", r.TCPRetransmissions)
	}
	if lostPackets(r) != 1 {
		t.Errorf("packet_loss.packets_lost = %d, want 1", lostPackets(r))
	}
	// Six packets were processed; the percentage is retransmissions / ALL packets.
	if r.PacketLoss.TotalPacketsSent != 6 {
		t.Errorf("total_packets_sent = %d, want 6", r.PacketLoss.TotalPacketsSent)
	}
	if want := 1.0 / 6.0 * 100; math.Abs(r.PacketLoss.LossPercentage-want) > 1e-9 {
		t.Errorf("loss_percentage = %v, want %v", r.PacketLoss.LossPercentage, want)
	}
	if r.PacketLoss.RetransmissionRate != r.PacketLoss.LossPercentage {
		t.Errorf("retransmission_rate (%v) and loss_percentage (%v) currently carry the same value",
			r.PacketLoss.RetransmissionRate, r.PacketLoss.LossPercentage)
	}
	if r.PacketLoss.TotalPacketsReceived != 5 {
		t.Errorf("total_packets_received = %d, want 5 (sent - retransmissions)", r.PacketLoss.TotalPacketsReceived)
	}
	// A single small flow: below the per-flow reporting threshold (>10 packets).
	if len(r.PacketLoss.PerFlowLoss) != 0 {
		t.Errorf("per-flow loss reported for a 4-packet flow: %+v", r.PacketLoss.PerFlowLoss)
	}
}

// ─── F. Events vs flows vs packets_lost ──────────────────────────────

// The three counters measure different units: segment-level events, distinct
// directional flows, and the packet-loss detector's own retransmission count.
func TestCharacterize_EventsFlowsAndPacketsLostAreDifferentUnits(t *testing.T) {
	const portA, portB = 50201, 50202
	pk := handshake(portA)
	pk = append(pk, handshake(portB)...)
	pk = append(pk,
		tcpC2S(portA, 1001, 2001, psh, payloadBytes(100)), // original
		tcpC2S(portA, 1001, 2001, psh, payloadBytes(100)), // resend 1
		tcpC2S(portA, 1001, 2001, psh, payloadBytes(100)), // resend 2
		tcpC2S(portA, 1101, 2001, psh, payloadBytes(50)),  // second segment
		tcpC2S(portA, 1101, 2001, psh, payloadBytes(50)),  // resend of the second segment
		tcpC2S(portB, 1001, 2001, psh, payloadBytes(80)),
		tcpC2S(portB, 1001, 2001, psh, payloadBytes(80)), // one resend on flow B
	)
	r := runGolden(t, pk)

	if n := len(retxEvents(r)); n != 4 {
		t.Errorf("events = %d, want 4 (segment-level)", n)
	}
	if n := len(r.TCPRetransmissions); n != 2 {
		t.Errorf("distinct flows = %d, want 2", n)
	}
	if !hasTCPFlow(r.TCPRetransmissions, portA, 443) || !hasTCPFlow(r.TCPRetransmissions, portB, 443) {
		t.Errorf("flows = %+v", r.TCPRetransmissions)
	}
	if got := lostPackets(r); got != 4 {
		t.Errorf("packets_lost = %d, want 4", got)
	}
	if r.EventCounts["tcp.retransmission"] != 4 {
		t.Errorf("event_counts[tcp.retransmission] = %d, want 4", r.EventCounts["tcp.retransmission"])
	}
}

// ─── C. SYN and SYN-ACK retransmissions (current behaviour, not a goal) ──

func TestCharacterize_RetransmittedSYN_NotARetransmissionEvent(t *testing.T) {
	const port = 50203
	pk := [][]byte{
		tcpC2S(port, 1000, 0, testpcap.SYN, nil),                 // 0
		tcpC2S(port, 1000, 0, testpcap.SYN, nil),                 // 1 retransmitted SYN
		tcpC2S(port, 1000, 0, testpcap.SYN, nil),                 // 2 retransmitted SYN
		tcpS2C(port, 2000, 1001, testpcap.SYN|testpcap.ACK, nil), // 3
		tcpC2S(port, 1001, 2001, testpcap.ACK, nil),              // 4
	}
	r := runGolden(t, pk)

	if n := len(retxEvents(r)); n != 0 {
		t.Errorf("repeated SYN produced %d tcp.retransmission events, want 0 (documented limitation)", n)
	}
	if len(r.TCPRetransmissions) != 0 {
		t.Errorf("repeated SYN populated TCPRetransmissions: %+v", r.TCPRetransmissions)
	}
	if lostPackets(r) != 0 {
		t.Errorf("repeated SYN counted by the packet-loss detector: %d", lostPackets(r))
	}
	// Every SYN packet is appended to the SYN list (3 packets, one attempt).
	if n := len(r.TCPHandshakes.SYNFlows); n != 3 {
		t.Errorf("SYNFlows = %d, want 3 (one entry per SYN packet)", n)
	}
	if n := len(r.TCPHandshakes.SYNACKFlows); n != 1 {
		t.Errorf("SYNACKFlows = %d, want 1", n)
	}
	if n := len(r.TCPHandshakes.SuccessfulHandshakes); n != 1 {
		t.Errorf("SuccessfulHandshakes = %d, want 1", n)
	}
	if len(r.FailedHandshakes) != 0 {
		t.Errorf("FailedHandshakes = %+v, want none", r.FailedHandshakes)
	}
	// The handshake tracker keeps the LAST SYN (packet 2) as the SYN time: the
	// SYN->SYN-ACK delay is one interval (100 ms), not the 300 ms since the
	// first SYN. Pinned as a known limitation (audit §4 #8).
	if len(r.TCPHandshakeFlows) != 1 {
		t.Fatalf("TCPHandshakeFlows = %d, want 1", len(r.TCPHandshakeFlows))
	}
	if got := r.TCPHandshakeFlows[0].SynToSynAckMs; math.Abs(got-100) > 0.5 {
		t.Errorf("syn_to_synack_ms = %v, want 100 (measured from the last SYN)", got)
	}
}

func TestCharacterize_RetransmittedSYNACK_NotARetransmissionEvent(t *testing.T) {
	const port = 50204
	pk := [][]byte{
		tcpC2S(port, 1000, 0, testpcap.SYN, nil),                 // 0
		tcpS2C(port, 2000, 1001, testpcap.SYN|testpcap.ACK, nil), // 1
		tcpS2C(port, 2000, 1001, testpcap.SYN|testpcap.ACK, nil), // 2 retransmitted SYN-ACK
		tcpC2S(port, 1001, 2001, testpcap.ACK, nil),              // 3
	}
	r := runGolden(t, pk)

	if n := len(retxEvents(r)); n != 0 {
		t.Errorf("repeated SYN-ACK produced %d tcp.retransmission events, want 0", n)
	}
	if len(r.TCPRetransmissions) != 0 || lostPackets(r) != 0 {
		t.Errorf("repeated SYN-ACK leaked into flows/packet-loss: %+v / %d", r.TCPRetransmissions, lostPackets(r))
	}
	if n := len(r.TCPHandshakes.SYNACKFlows); n != 2 {
		t.Errorf("SYNACKFlows = %d, want 2 (one entry per SYN-ACK packet)", n)
	}
	if n := len(r.TCPHandshakes.SuccessfulHandshakes); n != 1 {
		t.Errorf("SuccessfulHandshakes = %d, want 1", n)
	}
}

// An unanswered, repeatedly retransmitted SYN is neither a retransmission event
// nor (without a RST or an elapsed timeout in capture time) a failed handshake.
func TestCharacterize_UnansweredSYNRetries_NoRetransmissionEvidence(t *testing.T) {
	const port = 50205
	pk := [][]byte{
		tcpC2S(port, 1000, 0, testpcap.SYN, nil),
		tcpC2S(port, 1000, 0, testpcap.SYN, nil),
		tcpC2S(port, 1000, 0, testpcap.SYN, nil),
	}
	r := runGolden(t, pk)
	if len(retxEvents(r)) != 0 || len(r.TCPRetransmissions) != 0 || lostPackets(r) != 0 {
		t.Errorf("SYN retries leaked into retransmission accounting")
	}
	if n := len(r.TCPHandshakes.SYNFlows); n != 3 {
		t.Errorf("SYNFlows = %d, want 3", n)
	}
	if len(r.FailedHandshakes) != 0 {
		t.Errorf("pending SYN must not be reported failed without evidence: %+v", r.FailedHandshakes)
	}
}

// ─── D. FIN-bearing retransmission: the two live consumers diverge ──────

func TestCharacterize_FINBearingRetransmission_TCPDetectorCountsPacketLossSkips(t *testing.T) {
	const port = 50206
	pk := handshake(port)
	pk = append(pk,
		tcpC2S(port, 1001, 2001, testpcap.FIN|testpcap.ACK, payloadBytes(72)), // payload + FIN
		tcpC2S(port, 1001, 2001, testpcap.FIN|testpcap.ACK, payloadBytes(72)), // repeated
	)
	r := runGolden(t, pk)

	// pkg/detector/tcp.go: payload>0 and the sequence number was seen -> counted.
	if n := len(retxEvents(r)); n != 1 {
		t.Errorf("tcp.retransmission events = %d, want 1 (TCP detector counts the repeated FIN-bearing segment)", n)
	}
	if !hasTCPFlow(r.TCPRetransmissions, port, 443) {
		t.Errorf("flow missing from TCPRetransmissions: %+v", r.TCPRetransmissions)
	}
	// pkg/detectors/packet_loss.go: every SYN/FIN/RST packet is skipped.
	if got := lostPackets(r); got != 0 {
		t.Errorf("packet_loss.packets_lost = %d, want 0 (the packet-loss detector skips FIN)", got)
	}
}

// Same shape without FIN: both consumers agree, which isolates the divergence
// to the FIN flag (observed on The-Ultimate-PCAP frame 898: 80 events vs 79).
func TestCharacterize_NonFINRetransmission_BothConsumersAgree(t *testing.T) {
	const port = 50207
	pk := handshake(port)
	pk = append(pk,
		tcpC2S(port, 1001, 2001, psh, payloadBytes(72)),
		tcpC2S(port, 1001, 2001, psh, payloadBytes(72)),
	)
	r := runGolden(t, pk)
	if n := len(retxEvents(r)); n != 1 || lostPackets(r) != 1 {
		t.Errorf("events=%d packets_lost=%d, want 1/1", n, lostPackets(r))
	}
}

// A repeated payload-less FIN is not a retransmission for either consumer.
func TestCharacterize_PayloadlessFINRepeat_NotCounted(t *testing.T) {
	const port = 50208
	pk := handshake(port)
	pk = append(pk,
		tcpC2S(port, 1001, 2001, testpcap.FIN|testpcap.ACK, nil),
		tcpC2S(port, 1001, 2001, testpcap.FIN|testpcap.ACK, nil),
	)
	r := runGolden(t, pk)
	if len(retxEvents(r)) != 0 || lostPackets(r) != 0 || len(r.TCPRetransmissions) != 0 {
		t.Errorf("payload-less FIN repeat counted: events=%d lost=%d", len(retxEvents(r)), lostPackets(r))
	}
}

// ─── E. Packet-loss denominator and per-flow thresholds ─────────────────

func udpPacket(srcPort, dstPort uint16) []byte {
	return testpcap.UDPFrame(testpcap.ClientMAC, testpcap.ServerMAC, testpcap.ClientIP, testpcap.ServerIP, srcPort, dstPort, []byte("payload-xx"))
}

func TestCharacterize_LossPercentageUsesAllPacketsAsDenominator(t *testing.T) {
	const port = 50209
	pk := handshake(port) // 3 TCP control packets
	pk = append(pk,
		tcpC2S(port, 1001, 2001, psh, payloadBytes(100)),
		tcpC2S(port, 1001, 2001, psh, payloadBytes(100)), // the only retransmission
		tcpS2C(port, 2001, 1101, testpcap.ACK, nil),      // ACK-only
		tcpS2C(port, 2001, 1101, testpcap.ACK, nil),      // ACK-only (repeated ack number)
	)
	for i := 0; i < 8; i++ { // unrelated UDP traffic
		pk = append(pk, udpPacket(41000+uint16(i), 41500))
	}
	r := runGolden(t, pk)

	if lostPackets(r) != 1 || len(retxEvents(r)) != 1 {
		t.Fatalf("events=%d packets_lost=%d, want 1/1", len(retxEvents(r)), lostPackets(r))
	}
	total := uint64(len(pk)) // 3 + 2 + 2 + 8 = 15, all decodable
	if r.PacketLoss.TotalPacketsSent != total {
		t.Errorf("total_packets_sent = %d, want %d (every decoded packet incl. UDP and ACK-only)", r.PacketLoss.TotalPacketsSent, total)
	}
	if want := 1.0 / float64(total) * 100; math.Abs(r.PacketLoss.LossPercentage-want) > 1e-9 {
		t.Errorf("loss_percentage = %v, want %v (1 / %d packets)", r.PacketLoss.LossPercentage, want, total)
	}
}

func TestCharacterize_PerFlowLossThresholds(t *testing.T) {
	// 12 data segments + handshake ACK + 1 SYN + 1 resend: the client->server
	// flow carries 15 packets (>10) with 1 retransmission = 6.67 % (>1 %).
	const portHigh = 50210
	pk := handshake(portHigh)
	for i := 0; i < 12; i++ {
		pk = append(pk, tcpC2S(portHigh, 1001+uint32(i)*10, 2001, psh, payloadBytes(10)))
	}
	pk = append(pk, tcpC2S(portHigh, 1001, 2001, psh, payloadBytes(10)))
	r := runGolden(t, pk)
	if len(r.PacketLoss.PerFlowLoss) != 1 {
		t.Fatalf("per_flow_loss = %+v, want exactly the client->server flow", r.PacketLoss.PerFlowLoss)
	}
	f := r.PacketLoss.PerFlowLoss[0]
	if f.SrcPort != portHigh || f.DstPort != 443 || f.Protocol != "TCP" || f.PacketsSent != 15 || f.PacketsLost != 1 {
		t.Errorf("per-flow entry = %+v, want %d->443 TCP sent 15 lost 1", f, portHigh)
	}
	if want := 1.0 / 15.0 * 100; math.Abs(f.LossPercentage-want) > 1e-9 {
		t.Errorf("per-flow loss_percentage = %v, want %v", f.LossPercentage, want)
	}

	// 1 retransmission on a flow with 200 data packets = 0.5 % (<=1 %): not listed.
	const portLow = 50211
	pk = handshake(portLow)
	for i := 0; i < 200; i++ {
		pk = append(pk, tcpC2S(portLow, 1001+uint32(i)*10, 2001, psh, payloadBytes(10)))
	}
	pk = append(pk, tcpC2S(portLow, 1001, 2001, psh, payloadBytes(10)))
	r = runGolden(t, pk)
	if lostPackets(r) != 1 {
		t.Fatalf("packets_lost = %d, want 1", lostPackets(r))
	}
	if len(r.PacketLoss.PerFlowLoss) != 0 {
		t.Errorf("per-flow loss below the 1%% threshold was reported: %+v", r.PacketLoss.PerFlowLoss)
	}
}

// ─── G. Bounded sequence history and sequence wrap-around ──────────────

// Both live consumers remember only models.DefaultSeqHistorySize recent
// sequence numbers. A repeat of an evicted segment is NOT detected (documented
// false negative); a repeat of one still remembered is.
func TestCharacterize_SequenceHistoryEviction(t *testing.T) {
	const port = 50212
	// The capacity itself is part of the pinned behaviour: changing it alters which
	// retransmissions are recognised, so it must be an explicit decision.
	if models.DefaultSeqHistorySize != 512 {
		t.Fatalf("DefaultSeqHistorySize = %d; this characterization pins 512", models.DefaultSeqHistorySize)
	}
	n := models.DefaultSeqHistorySize + 1 // 513 distinct segments: the first is evicted
	pk := handshake(port)
	for i := 0; i < n; i++ {
		pk = append(pk, tcpC2S(port, 1001+uint32(i)*10, 2001, psh, payloadBytes(10)))
	}
	// Order matters: a repeat of an evicted segment is recorded as a NEW entry and
	// would itself push the oldest remembered segment out, so the still-remembered
	// second segment is repeated first.
	pk = append(pk,
		tcpC2S(port, 1011, 2001, psh, payloadBytes(10)), // repeat of the second segment (still remembered)
		tcpC2S(port, 1001, 2001, psh, payloadBytes(10)), // repeat of the evicted first segment
	)
	r := runGolden(t, pk)

	ev := retxEvents(r)
	if len(ev) != 1 || ev[0].Values["seq"] != 1011 {
		t.Fatalf("events = %+v, want exactly one for seq 1011 (seq 1001 was evicted)", ev)
	}
	if got := lostPackets(r); got != 1 {
		t.Errorf("packets_lost = %d, want 1", got)
	}
}

// Sequence numbers are compared as uint32 keys, so a resend of a segment that
// straddles 2^32 and of one just after the wrap is detected.
func TestCharacterize_SequenceWraparound(t *testing.T) {
	const port = 50213
	wrapSeq := uint32(0xFFFFFF00)
	afterWrap := wrapSeq + 512 // wraps modulo 2^32 at run time (0x100)
	pk := [][]byte{
		tcpC2S(port, wrapSeq-1, 0, testpcap.SYN, nil),
		tcpS2C(port, 2000, wrapSeq, testpcap.SYN|testpcap.ACK, nil),
		tcpC2S(port, wrapSeq, 2001, testpcap.ACK, nil),
		tcpC2S(port, wrapSeq, 2001, psh, payloadBytes(512)),   // spans the wrap (ends at 0x100)
		tcpC2S(port, afterWrap, 2001, psh, payloadBytes(100)), // starts after the wrap (0x100)
		tcpC2S(port, wrapSeq, 2001, psh, payloadBytes(512)),   // resend 1
		tcpC2S(port, afterWrap, 2001, psh, payloadBytes(100)), // resend 2
	}
	r := runGolden(t, pk)

	ev := retxEvents(r)
	if len(ev) != 2 {
		t.Fatalf("events = %d, want 2 across the wrap: %+v", len(ev), ev)
	}
	if ev[0].Values["seq"] != float64(wrapSeq) || ev[1].Values["seq"] != float64(afterWrap) {
		t.Errorf("event seqs = %v, %v", ev[0].Values["seq"], ev[1].Values["seq"])
	}
	if got := lostPackets(r); got != 2 {
		t.Errorf("packets_lost = %d, want 2", got)
	}
}

// ─── Determinism ────────────────────────────────────────────────────

func TestCharacterize_RetransmissionOutputIsDeterministic(t *testing.T) {
	build := func() [][]byte {
		const portA, portB = 50214, 50215
		pk := handshake(portA)
		pk = append(pk, handshake(portB)...)
		for i := 0; i < 5; i++ {
			pk = append(pk, tcpC2S(portA, 1001, 2001, psh, payloadBytes(60)))
			pk = append(pk, tcpC2S(portB, 1001+uint32(i%2)*60, 2001, psh, payloadBytes(60)))
		}
		return pk
	}
	snapshot := func() string {
		r := runGolden(t, build())
		type ev struct {
			ID     uint64
			Flow   string
			Values map[string]float64
		}
		var evs []ev
		for _, e := range retxEvents(r) {
			evs = append(evs, ev{e.ID, e.FlowKey, e.Values})
		}
		b, err := json.Marshal(map[string]any{
			"flows": r.TCPRetransmissions, "loss": r.PacketLoss, "counts": r.EventCounts, "events": evs,
		})
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	first := snapshot()
	for i := 0; i < 4; i++ {
		if got := snapshot(); got != first {
			t.Fatalf("run %d differs:\n%s\n%s", i+2, first, got)
		}
	}
}

// ─── Real-capture baseline (optional, environment-driven) ────────────────

// Reference values measured at HEAD 38f86b6 (Phase 4.29 baseline verification).
// They are observations of CURRENT behaviour, not claims of correctness; in
// particular The-Ultimate-PCAP shows 80 events but packets_lost 79 because one
// retransmitted segment carries FIN (see the FIN characterization above), and
// the SYN/SYN-ACK retransmissions tshark reports are absent from every count.
// Runs only when SDWAN_VENDOR_PCAP_DIR is set (same variable as the vendor
// regression harness); a capture missing from that directory is skipped
// individually, never failed.
func TestCharacterize_RealCaptureRetransmissionBaseline(t *testing.T) {
	dir := os.Getenv("SDWAN_VENDOR_PCAP_DIR")
	if dir == "" {
		t.Skip("SDWAN_VENDOR_PCAP_DIR not set; skipping real-capture retransmission baseline")
	}
	cases := []struct {
		name        string
		events      int
		flows       int
		packetsLost uint64
		lossPct     float64
	}{
		{"Lab 3-TCP Retrans", 1, 1, 1, 0.495},
		{"Lab 4-NetworkCongestion", 1, 1, 1, 5.0},
		{"user1", 3, 2, 3, 0.508},
		{"Velocloud-Lan", 0, 0, 0, 0},
		{"Velocloud-Wan", 0, 0, 0, 0},
		{"cisco-example-lan", 9, 9, 9, 0.088},
		{"The-Ultimate-PCAP", 80, 41, 79, 0.194},
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
			if got := len(retxEvents(r)); got != c.events {
				t.Errorf("tcp.retransmission events = %d, want %d", got, c.events)
			}
			if got := len(r.TCPRetransmissions); got != c.flows {
				t.Errorf("distinct retransmission flows = %d, want %d", got, c.flows)
			}
			var lost uint64
			var pct float64
			if r.PacketLoss != nil {
				lost, pct = r.PacketLoss.PacketsLost, r.PacketLoss.LossPercentage
			}
			if lost != c.packetsLost {
				t.Errorf("packet_loss.packets_lost = %d, want %d", lost, c.packetsLost)
			}
			if math.Abs(pct-c.lossPct) > 0.0006 {
				t.Errorf("packet_loss.loss_percentage = %.4f, want %.3f", pct, c.lossPct)
			}
		})
	}
}
