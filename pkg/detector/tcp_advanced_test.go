package detector

import (
	"testing"
	"time"

	"github.com/gocisse/sdwan-triage/pkg/models"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// Small Window detection must judge the EFFECTIVE advertised window
// (raw << negotiated per-direction Window Scale) and make no claim when the
// scale is unknown. Phase 4.13 found raw 7 with scale 4096 (28,672 bytes)
// reported as a Small Window.

const (
	swClient = "10.0.0.1"
	swServer = "10.0.0.2"
	swCPort  = 40000
	swSPort  = 443
)

// swPkt builds a TCP segment. wscale < 0 means "no Window Scale option".
func swPkt(src, dst string, sport, dport uint16, syn, ack bool, window uint16, wscale int) gopacket.Packet {
	eth := &layers.Ethernet{
		SrcMAC: []byte{0, 0, 0, 0, 0, 1}, DstMAC: []byte{0, 0, 0, 0, 0, 2}, EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{Version: 4, TTL: 64, Protocol: layers.IPProtocolTCP, SrcIP: parseIP(src), DstIP: parseIP(dst)}
	tcp := &layers.TCP{SrcPort: layers.TCPPort(sport), DstPort: layers.TCPPort(dport), SYN: syn, ACK: ack, Seq: 1000, Window: window}
	if wscale >= 0 {
		tcp.Options = []layers.TCPOption{{OptionType: layers.TCPOptionKindWindowScale, OptionLength: 3, OptionData: []byte{byte(wscale)}}}
	}
	tcp.SetNetworkLayerForChecksum(ip)
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}, eth, ip, tcp); err != nil {
		panic(err)
	}
	p := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
	p.Metadata().Timestamp = time.Unix(1700000000, 0)
	return p
}

func swSYN(wscale int) gopacket.Packet {
	return swPkt(swClient, swServer, swCPort, swSPort, true, false, 100, wscale) // small raw window on purpose
}
func swSYNACK(wscale int) gopacket.Packet {
	return swPkt(swServer, swClient, swSPort, swCPort, true, true, 100, wscale)
}
func swFromServer(window uint16) gopacket.Packet {
	return swPkt(swServer, swClient, swSPort, swCPort, false, true, window, -1)
}
func swFromClient(window uint16) gopacket.Packet {
	return swPkt(swClient, swServer, swCPort, swSPort, false, true, window, -1)
}

func swRun(pkts ...gopacket.Packet) []models.TCPWindowFinding {
	a := NewTCPAdvancedAnalyzer()
	state := models.NewAnalysisState()
	report := &models.TriageReport{}
	for _, p := range pkts {
		a.Analyze(p, state, report)
	}
	return report.TCPWindowFindings
}

func swRepeat(n int, mk func() gopacket.Packet) []gopacket.Packet {
	out := make([]gopacket.Packet, n)
	for i := range out {
		out[i] = mk()
	}
	return out
}

func swSmall(f []models.TCPWindowFinding) []models.TCPWindowFinding {
	var out []models.TCPWindowFinding
	for _, x := range f {
		if x.Type == "Small Window" {
			out = append(out, x)
		}
	}
	return out
}

func swHandshake(clientOpt, serverOpt int) []gopacket.Packet {
	return []gopacket.Packet{swSYN(clientOpt), swSYNACK(serverOpt)}
}

func TestSmallWindow_UnscaledQualifiesAtFifthPacket(t *testing.T) {
	hs := swHandshake(-1, -1)
	four := swSmall(swRun(append(hs, swRepeat(4, func() gopacket.Packet { return swFromServer(512) })...)...))
	if len(four) != 0 {
		t.Fatalf("4 qualifying packets must not produce a finding, got %+v", four)
	}
	five := swSmall(swRun(append(hs, swRepeat(5, func() gopacket.Packet { return swFromServer(512) })...)...))
	if len(five) != 1 || five[0].WindowSize != 512 || five[0].Count != 5 || five[0].SrcIP != swServer {
		t.Fatalf("5 qualifying packets: want one finding of 512 bytes from the server, got %+v", five)
	}
}

// The user1.pcap regression: raw 7 with shift 12 is a 28,672-byte window.
func TestSmallWindow_ScaledLargeWindowIsNotSmall(t *testing.T) {
	pk := append(swHandshake(6, 12), swRepeat(20, func() gopacket.Packet { return swFromServer(7) })...)
	if got := swSmall(swRun(pk...)); len(got) != 0 {
		t.Fatalf("raw 7 x 2^12 = 28672 must not be a Small Window, got %+v", got)
	}
}

func TestSmallWindow_ScaledBoundary(t *testing.T) {
	// shift 7: raw 8 -> 1024 (<= threshold, qualifies); raw 9 -> 1152 (does not).
	atBoundary := append(swHandshake(7, 7), swRepeat(5, func() gopacket.Packet { return swFromServer(8) })...)
	got := swSmall(swRun(atBoundary...))
	if len(got) != 1 || got[0].WindowSize != 1024 {
		t.Fatalf("effective 1024 should qualify, got %+v", got)
	}
	above := append(swHandshake(7, 7), swRepeat(10, func() gopacket.Packet { return swFromServer(9) })...)
	if got := swSmall(swRun(above...)); len(got) != 0 {
		t.Fatalf("effective 1152 must not qualify, got %+v", got)
	}
}

// Each direction uses its own scale: client shift 6, server shift 12.
func TestSmallWindow_ScalesAreDirectional(t *testing.T) {
	hs := swHandshake(6, 12)
	// Server raw 1 x 2^12 = 4096 (not small). Using the client's shift (64) would wrongly flag it.
	if got := swSmall(swRun(append(hs, swRepeat(10, func() gopacket.Packet { return swFromServer(1) })...)...)); len(got) != 0 {
		t.Fatalf("server direction must use the server's shift 12, got %+v", got)
	}
	// Client raw 1 x 2^6 = 64 (small). Using the server's shift (4096) would wrongly hide it.
	got := swSmall(swRun(append(hs, swRepeat(5, func() gopacket.Packet { return swFromClient(1) })...)...))
	if len(got) != 1 || got[0].SrcIP != swClient || got[0].WindowSize != 64 {
		t.Fatalf("client direction must use the client's shift 6 (64 bytes), got %+v", got)
	}
}

func TestSmallWindow_UnknownScaleMakesNoClaim(t *testing.T) {
	small := func() gopacket.Packet { return swFromServer(7) }
	cases := map[string][]gopacket.Packet{
		"no handshake at all":         swRepeat(20, small),
		"SYN with option, no SYN-ACK": append([]gopacket.Packet{swSYN(12)}, swRepeat(20, small)...),
		"SYN-ACK with option, no SYN": append([]gopacket.Packet{swSYNACK(12)}, swRepeat(20, small)...),
		"data before any handshake":   append(swRepeat(10, small), swHandshake(12, 12)...),
	}
	for name, pk := range cases {
		if got := swSmall(swRun(pk...)); len(got) != 0 {
			t.Errorf("%s: scale unknown, expected no finding, got %+v", name, got)
		}
	}
}

// Scaling is off when either side omits the option; that is a KNOWN scale of 0.
func TestSmallWindow_NoScalingNegotiatedUsesRawWindow(t *testing.T) {
	small := func() gopacket.Packet { return swFromServer(500) }
	cases := map[string][]gopacket.Packet{
		"SYN without option, SYN-ACK with option":  append(swHandshake(-1, 12), swRepeat(5, small)...),
		"SYN-ACK without option, SYN with option":  append(swHandshake(12, -1), swRepeat(5, small)...),
		"SYN-ACK without option, SYN not captured": append([]gopacket.Packet{swSYNACK(-1)}, swRepeat(5, small)...),
		"SYN without option, SYN-ACK not captured": append([]gopacket.Packet{swSYN(-1)}, swRepeat(5, small)...),
	}
	for name, pk := range cases {
		got := swSmall(swRun(pk...))
		if len(got) != 1 || got[0].WindowSize != 500 {
			t.Errorf("%s: want one raw-window finding (500), got %+v", name, got)
		}
	}
}

func TestSmallWindow_ZeroWindowUnchanged(t *testing.T) {
	pk := append(swHandshake(7, 12), swRepeat(3, func() gopacket.Packet { return swFromServer(0) })...)
	all := swRun(pk...)
	if len(swSmall(all)) != 0 {
		t.Fatalf("window 0 must never be a Small Window: %+v", all)
	}
	if len(all) != 1 || all[0].Type != "Zero Window" || all[0].Count != 3 {
		t.Fatalf("expected the existing single Zero Window finding at the 3rd occurrence, got %+v", all)
	}
	// Zero window needs no scale knowledge: still reported without a handshake.
	if z := swRun(swRepeat(3, func() gopacket.Packet { return swFromServer(0) })...); len(z) != 1 || z[0].Type != "Zero Window" {
		t.Fatalf("zero window without handshake: %+v", z)
	}
}

// Handshake segments themselves (small raw windows) never count.
func TestSmallWindow_HandshakeSegmentsAreNotCounted(t *testing.T) {
	pk := append(swHandshake(-1, -1), swRepeat(4, func() gopacket.Packet { return swFromServer(500) })...)
	if got := swSmall(swRun(pk...)); len(got) != 0 {
		t.Fatalf("SYN/SYN-ACK must not count toward the 5-packet threshold, got %+v", got)
	}
}

func TestSmallWindow_LargeScaleArithmeticDoesNotWrap(t *testing.T) {
	// 65535 << 14 would wrap to a small value in 16-bit arithmetic.
	pk := append(swHandshake(14, 14), swRepeat(20, func() gopacket.Packet { return swFromServer(65535) })...)
	if got := swSmall(swRun(pk...)); len(got) != 0 {
		t.Fatalf("65535 x 2^14 is ~1 GiB, got %+v", got)
	}
	// Shifts above 14 are capped at 14 per RFC 7323.
	pk = append(swHandshake(200, 200), swRepeat(20, func() gopacket.Packet { return swFromServer(1) })...)
	if got := swSmall(swRun(pk...)); len(got) != 0 {
		t.Fatalf("shift capped at 14: 1 x 16384 > 1024, got %+v", got)
	}
}

func TestSmallWindow_RepeatedObservationsYieldOneFindingPerDirection(t *testing.T) {
	pk := append(swHandshake(-1, -1), swRepeat(30, func() gopacket.Packet { return swFromServer(300) })...)
	pk = append(pk, swRepeat(30, func() gopacket.Packet { return swFromClient(300) })...)
	got := swSmall(swRun(pk...))
	if len(got) != 2 {
		t.Fatalf("expected exactly one finding per directional flow (2), got %d: %+v", len(got), got)
	}
	for _, f := range got {
		if f.Count != 5 {
			t.Errorf("Count = %d, want 5", f.Count)
		}
	}
}

// A new SYN on the same 4-tuple replaces the previous connection's scale.
func TestSmallWindow_NewConnectionReplacesScale(t *testing.T) {
	pk := append(swHandshake(12, 12), swFromServer(7)) // scaled connection
	pk = append(pk, swHandshake(-1, -1)...)            // port reused, now unscaled
	pk = append(pk, swRepeat(5, func() gopacket.Packet { return swFromServer(300) })...)
	got := swSmall(swRun(pk...))
	if len(got) != 1 || got[0].WindowSize != 300 {
		t.Fatalf("second connection is unscaled; want one 300-byte finding, got %+v", got)
	}
}
