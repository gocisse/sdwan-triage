package analyzer

import (
	"testing"
	"time"

	"github.com/gocisse/sdwan-triage/pkg/models"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// buildTCPFrame constructs a minimal IPv4+TCP raw packet suitable for
// BuildTCPGraph parsing. Uses gopacket SerializeLayers so the bytes are
// indistinguishable from a PCAP-captured frame (aside from the missing L2
// header, which BuildTCPGraph tolerates via its IPv4 fallback).
func buildTCPFrame(t *testing.T, srcIP, dstIP string, srcPort, dstPort uint16, seq, ack uint32, window uint16, flags string, payloadLen int) []byte {
	t.Helper()
	return buildTCPFrameWithOptions(t, srcIP, dstIP, srcPort, dstPort, seq, ack, window, flags, payloadLen, nil)
}

// buildTCPFrameWithOptions is the same as buildTCPFrame but lets the caller
// attach TCP options (for window-scale tests and similar).
func buildTCPFrameWithOptions(t *testing.T, srcIP, dstIP string, srcPort, dstPort uint16, seq, ack uint32, window uint16, flags string, payloadLen int, tcpOpts []layers.TCPOption) []byte {
	t.Helper()
	ip := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    parseIPv4(srcIP),
		DstIP:    parseIPv4(dstIP),
	}
	tcp := &layers.TCP{
		SrcPort: layers.TCPPort(srcPort),
		DstPort: layers.TCPPort(dstPort),
		Seq:     seq,
		Ack:     ack,
		Window:  window,
		Options: tcpOpts,
	}
	for _, f := range []byte(flags) {
		switch f {
		case 'S':
			tcp.SYN = true
		case 'A':
			tcp.ACK = true
		case 'F':
			tcp.FIN = true
		case 'R':
			tcp.RST = true
		case 'P':
			tcp.PSH = true
		}
	}
	if err := tcp.SetNetworkLayerForChecksum(ip); err != nil {
		t.Fatalf("checksum: %v", err)
	}
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	payload := make([]byte, payloadLen)
	if err := gopacket.SerializeLayers(buf, opts, ip, tcp, gopacket.Payload(payload)); err != nil {
		t.Fatalf("serialize: %v", err)
	}
	// Make a defensive copy so callers can safely mutate the slice.
	out := make([]byte, len(buf.Bytes()))
	copy(out, buf.Bytes())
	return out
}

func parseIPv4(s string) []byte {
	// Tiny hand-rolled parser (avoids net.ParseIP drift across Go versions)
	var ip [4]byte
	var part int
	var idx int
	for i := 0; i <= len(s); i++ {
		if i == len(s) || s[i] == '.' {
			if idx >= 4 {
				return nil
			}
			ip[idx] = byte(part)
			idx++
			part = 0
			continue
		}
		if s[i] < '0' || s[i] > '9' {
			return nil
		}
		part = part*10 + int(s[i]-'0')
	}
	return ip[:]
}

func mkPacket(idx int, ts time.Time, srcIP, dstIP string, srcPort, dstPort uint16, raw []byte) *models.RawPacket {
	return &models.RawPacket{
		Index:     idx,
		Timestamp: ts,
		Length:    len(raw),
		RawData:   raw,
		SrcIP:     srcIP,
		DstIP:     dstIP,
		SrcPort:   srcPort,
		DstPort:   dstPort,
		Protocol:  "TCP",
		IsTCP:     true,
	}
}

func TestBuildTCPGraph_EmptyPackets(t *testing.T) {
	g := BuildTCPGraph("stream1", nil)
	if g == nil {
		t.Fatal("expected non-nil graph for empty input")
	}
	if len(g.Points) != 0 {
		t.Errorf("expected 0 points, got %d", len(g.Points))
	}
	if g.StreamID != "stream1" {
		t.Errorf("expected stream_id=stream1, got %q", g.StreamID)
	}
}

func TestBuildTCPGraph_SkipsNonTCP(t *testing.T) {
	// A single non-TCP packet — graph should degrade gracefully.
	p := &models.RawPacket{
		Index:     0,
		Timestamp: time.Now(),
		SrcIP:     "10.0.0.1",
		DstIP:     "10.0.0.2",
		Protocol:  "UDP",
		IsTCP:     false,
	}
	g := BuildTCPGraph("s1", []*models.RawPacket{p})
	if len(g.Points) != 0 {
		t.Errorf("expected 0 points for non-TCP stream, got %d", len(g.Points))
	}
}

func TestBuildTCPGraph_RetransmissionDetection(t *testing.T) {
	t0 := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

	// Three packets: data, ack, retransmission of the same data packet.
	raw1 := buildTCPFrame(t, "10.0.0.1", "10.0.0.2", 5000, 443, 1000, 0, 65535, "PA", 100)
	raw2 := buildTCPFrame(t, "10.0.0.2", "10.0.0.1", 443, 5000, 0, 1100, 65535, "A", 0)
	raw3 := buildTCPFrame(t, "10.0.0.1", "10.0.0.2", 5000, 443, 1000, 0, 65535, "PA", 100) // retx

	packets := []*models.RawPacket{
		mkPacket(0, t0, "10.0.0.1", "10.0.0.2", 5000, 443, raw1),
		mkPacket(1, t0.Add(50*time.Millisecond), "10.0.0.2", "10.0.0.1", 443, 5000, raw2),
		mkPacket(2, t0.Add(200*time.Millisecond), "10.0.0.1", "10.0.0.2", 5000, 443, raw3),
	}

	g := BuildTCPGraph("s1", packets)
	if g.PacketCount != 3 {
		t.Fatalf("expected 3 points, got %d", g.PacketCount)
	}
	if g.RetransmissionCount != 1 {
		t.Errorf("expected 1 retransmission, got %d", g.RetransmissionCount)
	}
	if !g.Points[2].IsRetransmission {
		t.Error("third packet should be marked as retransmission")
	}
	if g.Points[0].IsRetransmission {
		t.Error("first packet should not be flagged as retransmission")
	}
	// First packet establishes t=0; third packet is 200ms later.
	if got := g.Points[2].RelativeTime; got < 0.19 || got > 0.21 {
		t.Errorf("expected relative_time ≈ 0.2s, got %f", got)
	}
	// Direction assignment: first seen tuple is forward.
	if g.Points[0].Direction != "forward" {
		t.Errorf("expected forward direction for first packet, got %q", g.Points[0].Direction)
	}
	if g.Points[1].Direction != "reverse" {
		t.Errorf("expected reverse direction for ACK, got %q", g.Points[1].Direction)
	}
	// Payload length should propagate.
	if g.Points[0].PayloadLen != 100 {
		t.Errorf("expected payload_len=100 on first packet, got %d", g.Points[0].PayloadLen)
	}
	// Pure ACK should have payload=0 and NOT be flagged as retransmission even
	// if seq repeats later.
	if g.Points[1].PayloadLen != 0 {
		t.Errorf("expected payload_len=0 on ACK, got %d", g.Points[1].PayloadLen)
	}
}

func TestBuildTCPGraph_PureACKsNeverFlaggedRetx(t *testing.T) {
	t0 := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	// Two identical pure ACKs (seq stays the same, legitimate).
	raw1 := buildTCPFrame(t, "10.0.0.1", "10.0.0.2", 5000, 443, 500, 2000, 65535, "A", 0)
	raw2 := buildTCPFrame(t, "10.0.0.1", "10.0.0.2", 5000, 443, 500, 3000, 65535, "A", 0)

	packets := []*models.RawPacket{
		mkPacket(0, t0, "10.0.0.1", "10.0.0.2", 5000, 443, raw1),
		mkPacket(1, t0.Add(10*time.Millisecond), "10.0.0.1", "10.0.0.2", 5000, 443, raw2),
	}
	g := BuildTCPGraph("s1", packets)
	if g.RetransmissionCount != 0 {
		t.Errorf("pure ACKs should not count as retransmissions, got %d", g.RetransmissionCount)
	}
}

func TestBuildTCPGraph_FlagTracking(t *testing.T) {
	t0 := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	synRaw := buildTCPFrame(t, "10.0.0.1", "10.0.0.2", 5000, 443, 0, 0, 65535, "S", 0)
	rstRaw := buildTCPFrame(t, "10.0.0.2", "10.0.0.1", 443, 5000, 1, 0, 0, "R", 0)
	packets := []*models.RawPacket{
		mkPacket(0, t0, "10.0.0.1", "10.0.0.2", 5000, 443, synRaw),
		mkPacket(1, t0.Add(100*time.Millisecond), "10.0.0.2", "10.0.0.1", 443, 5000, rstRaw),
	}
	g := BuildTCPGraph("s1", packets)
	if g.SynCount != 1 {
		t.Errorf("expected 1 SYN, got %d", g.SynCount)
	}
	if g.RstCount != 1 {
		t.Errorf("expected 1 RST, got %d", g.RstCount)
	}
	if !g.Points[0].IsSyn {
		t.Error("first point should be SYN")
	}
	if !g.Points[1].IsRst {
		t.Error("second point should be RST")
	}
}

func TestBuildTCPGraph_WindowScaling(t *testing.T) {
	t0 := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

	// Handshake: SYN announces forward scale=7, SYN-ACK announces reverse scale=6.
	synOpts := []layers.TCPOption{
		{OptionType: layers.TCPOptionKindWindowScale, OptionLength: 3, OptionData: []byte{7}},
	}
	synAckOpts := []layers.TCPOption{
		{OptionType: layers.TCPOptionKindWindowScale, OptionLength: 3, OptionData: []byte{6}},
	}

	synRaw := buildTCPFrameWithOptions(t, "10.0.0.1", "10.0.0.2", 5000, 443, 100, 0, 1024, "S", 0, synOpts)
	synAckRaw := buildTCPFrameWithOptions(t, "10.0.0.2", "10.0.0.1", 443, 5000, 200, 101, 2048, "SA", 0, synAckOpts)
	// After the handshake, forward data with raw window 500 -> scaled = 500 << 7 = 64000.
	dataRaw := buildTCPFrame(t, "10.0.0.1", "10.0.0.2", 5000, 443, 101, 201, 500, "PA", 50)
	// And a reverse ACK with raw window 300 -> scaled = 300 << 6 = 19200.
	ackRaw := buildTCPFrame(t, "10.0.0.2", "10.0.0.1", 443, 5000, 201, 151, 300, "A", 0)

	packets := []*models.RawPacket{
		mkPacket(0, t0, "10.0.0.1", "10.0.0.2", 5000, 443, synRaw),
		mkPacket(1, t0.Add(10*time.Millisecond), "10.0.0.2", "10.0.0.1", 443, 5000, synAckRaw),
		mkPacket(2, t0.Add(20*time.Millisecond), "10.0.0.1", "10.0.0.2", 5000, 443, dataRaw),
		mkPacket(3, t0.Add(30*time.Millisecond), "10.0.0.2", "10.0.0.1", 443, 5000, ackRaw),
	}

	g := BuildTCPGraph("s1", packets)
	if g.ForwardWindowScale != 7 {
		t.Errorf("expected forward scale=7, got %d", g.ForwardWindowScale)
	}
	if g.ReverseWindowScale != 6 {
		t.Errorf("expected reverse scale=6, got %d", g.ReverseWindowScale)
	}

	// SYN itself should NOT be scaled — raw window is the canonical value.
	if g.Points[0].ScaledWindow != 1024 {
		t.Errorf("SYN scaled_window should equal raw window (1024), got %d", g.Points[0].ScaledWindow)
	}
	// SYN-ACK also should not be scaled.
	if g.Points[1].ScaledWindow != 2048 {
		t.Errorf("SYN-ACK scaled_window should equal raw window (2048), got %d", g.Points[1].ScaledWindow)
	}
	// Forward data packet → scaled
	if got := g.Points[2].ScaledWindow; got != uint32(500)<<7 {
		t.Errorf("forward data expected scaled_window=%d, got %d", uint32(500)<<7, got)
	}
	// Reverse ACK → scaled
	if got := g.Points[3].ScaledWindow; got != uint32(300)<<6 {
		t.Errorf("reverse ACK expected scaled_window=%d, got %d", uint32(300)<<6, got)
	}
}

func TestBuildTCPGraph_RTTSamples(t *testing.T) {
	t0 := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

	// Forward data at t=0 with 100 bytes, seq=1000 → expects ack_num >= 1100.
	// Reverse ACK at t=50ms with ack=1100 → RTT ≈ 50 ms.
	// Another forward data at t=100ms with 200 bytes, seq=1100 → expects ack >= 1300.
	// Reverse ACK at t=175ms with ack=1300 → RTT ≈ 75 ms.
	d1 := buildTCPFrame(t, "10.0.0.1", "10.0.0.2", 5000, 443, 1000, 0, 65535, "PA", 100)
	a1 := buildTCPFrame(t, "10.0.0.2", "10.0.0.1", 443, 5000, 500, 1100, 65535, "A", 0)
	d2 := buildTCPFrame(t, "10.0.0.1", "10.0.0.2", 5000, 443, 1100, 0, 65535, "PA", 200)
	a2 := buildTCPFrame(t, "10.0.0.2", "10.0.0.1", 443, 5000, 500, 1300, 65535, "A", 0)

	packets := []*models.RawPacket{
		mkPacket(0, t0, "10.0.0.1", "10.0.0.2", 5000, 443, d1),
		mkPacket(1, t0.Add(50*time.Millisecond), "10.0.0.2", "10.0.0.1", 443, 5000, a1),
		mkPacket(2, t0.Add(100*time.Millisecond), "10.0.0.1", "10.0.0.2", 5000, 443, d2),
		mkPacket(3, t0.Add(175*time.Millisecond), "10.0.0.2", "10.0.0.1", 443, 5000, a2),
	}

	g := BuildTCPGraph("s1", packets)
	if len(g.RTTSamples) != 2 {
		t.Fatalf("expected 2 RTT samples, got %d", len(g.RTTSamples))
	}
	if got := g.RTTSamples[0].RTTMs; got < 49 || got > 51 {
		t.Errorf("expected RTT[0] ≈ 50ms, got %f", got)
	}
	if got := g.RTTSamples[1].RTTMs; got < 74 || got > 76 {
		t.Errorf("expected RTT[1] ≈ 75ms, got %f", got)
	}
	if g.MinRTTMs < 49 || g.MinRTTMs > 51 {
		t.Errorf("expected min RTT ≈ 50ms, got %f", g.MinRTTMs)
	}
	if g.MaxRTTMs < 74 || g.MaxRTTMs > 76 {
		t.Errorf("expected max RTT ≈ 75ms, got %f", g.MaxRTTMs)
	}
	if g.AvgRTTMs < 62 || g.AvgRTTMs > 63 {
		t.Errorf("expected avg RTT ≈ 62.5ms, got %f", g.AvgRTTMs)
	}
	// Directions should be tagged correctly.
	for _, r := range g.RTTSamples {
		if r.Direction != "forward" {
			t.Errorf("all RTT samples should be forward here, got %q", r.Direction)
		}
	}
}

func TestBuildTCPGraph_RTTExcludesRetransmissions(t *testing.T) {
	t0 := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

	// Original data, retransmission of the same, then ACK.
	orig := buildTCPFrame(t, "10.0.0.1", "10.0.0.2", 5000, 443, 500, 0, 65535, "PA", 50)
	retx := buildTCPFrame(t, "10.0.0.1", "10.0.0.2", 5000, 443, 500, 0, 65535, "PA", 50)
	ack := buildTCPFrame(t, "10.0.0.2", "10.0.0.1", 443, 5000, 100, 550, 65535, "A", 0)

	packets := []*models.RawPacket{
		mkPacket(0, t0, "10.0.0.1", "10.0.0.2", 5000, 443, orig),
		mkPacket(1, t0.Add(200*time.Millisecond), "10.0.0.1", "10.0.0.2", 5000, 443, retx),
		mkPacket(2, t0.Add(300*time.Millisecond), "10.0.0.2", "10.0.0.1", 443, 5000, ack),
	}
	g := BuildTCPGraph("s1", packets)
	// Only one RTT sample — the retransmission must not generate one.
	if len(g.RTTSamples) != 1 {
		t.Errorf("expected 1 RTT sample (retx excluded), got %d", len(g.RTTSamples))
	}
	if g.RetransmissionCount != 1 {
		t.Errorf("expected 1 retransmission, got %d", g.RetransmissionCount)
	}
}

func TestBuildTCPGraph_ThroughputBins(t *testing.T) {
	t0 := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

	// A 10-second flow with one forward data packet per second. The min bin
	// size is 50ms, duration/60 ≈ 167ms — so we expect ~60 bins, each
	// containing at most one packet.
	packets := []*models.RawPacket{}
	for i := 0; i < 10; i++ {
		raw := buildTCPFrame(t, "10.0.0.1", "10.0.0.2", 5000, 443, uint32(1000+i*100), 0, 65535, "PA", 100)
		packets = append(packets, mkPacket(i, t0.Add(time.Duration(i)*time.Second), "10.0.0.1", "10.0.0.2", 5000, 443, raw))
	}

	g := BuildTCPGraph("s1", packets)
	if len(g.Throughput) == 0 {
		t.Fatal("expected non-empty throughput bins")
	}
	var totalFwd int
	for _, b := range g.Throughput {
		totalFwd += b.ForwardBytes
	}
	// 10 packets × 100 bytes = 1000 bytes.
	if totalFwd != 1000 {
		t.Errorf("total forward bytes = 1000, got %d", totalFwd)
	}
	if g.PeakBytesPerSecond <= 0 {
		t.Error("peak bytes/sec should be > 0")
	}
}

func TestBuildTCPGraph_ZeroWindowFlag(t *testing.T) {
	t0 := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	// A zero-window ACK: receiver says "don't send me any more".
	zw := buildTCPFrame(t, "10.0.0.2", "10.0.0.1", 443, 5000, 100, 1000, 0, "A", 0)
	// Compare with a normal ACK.
	norm := buildTCPFrame(t, "10.0.0.2", "10.0.0.1", 443, 5000, 100, 1000, 65535, "A", 0)

	packets := []*models.RawPacket{
		mkPacket(0, t0, "10.0.0.2", "10.0.0.1", 443, 5000, zw),
		mkPacket(1, t0.Add(10*time.Millisecond), "10.0.0.2", "10.0.0.1", 443, 5000, norm),
	}
	g := BuildTCPGraph("s1", packets)
	if !g.Points[0].IsZeroWindow {
		t.Error("first packet should be flagged zero-window")
	}
	if g.Points[1].IsZeroWindow {
		t.Error("second packet should NOT be flagged zero-window")
	}
	if g.ZeroWindowOccurrences != 1 {
		t.Errorf("expected 1 zero-window occurrence, got %d", g.ZeroWindowOccurrences)
	}
}

func TestBuildTCPGraph_SortsByTimestamp(t *testing.T) {
	t0 := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	raw := buildTCPFrame(t, "10.0.0.1", "10.0.0.2", 5000, 443, 1000, 0, 65535, "A", 0)
	// Provide packets in reverse chronological order.
	packets := []*models.RawPacket{
		mkPacket(2, t0.Add(200*time.Millisecond), "10.0.0.1", "10.0.0.2", 5000, 443, raw),
		mkPacket(1, t0.Add(100*time.Millisecond), "10.0.0.1", "10.0.0.2", 5000, 443, raw),
		mkPacket(0, t0, "10.0.0.1", "10.0.0.2", 5000, 443, raw),
	}
	g := BuildTCPGraph("s1", packets)
	for i := 1; i < len(g.Points); i++ {
		if g.Points[i].RelativeTime < g.Points[i-1].RelativeTime {
			t.Errorf("points not sorted by time: idx %d (%.3fs) < idx %d (%.3fs)",
				i, g.Points[i].RelativeTime, i-1, g.Points[i-1].RelativeTime)
		}
	}
	// Duration should match the span of timestamps (200 ms).
	if g.DurationSeconds < 0.19 || g.DurationSeconds > 0.21 {
		t.Errorf("expected duration ≈ 0.2s, got %f", g.DurationSeconds)
	}
}
