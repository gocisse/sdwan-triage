package analyzer

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gocisse/sdwan-triage/internal/testpcap"
	"github.com/gocisse/sdwan-triage/pkg/events"
	"github.com/gocisse/sdwan-triage/pkg/models"
)

// runGoldenInterval is runGolden with a custom inter-packet spacing.
func runGoldenInterval(t *testing.T, packets [][]byte, interval time.Duration) *models.TriageReport {
	t.Helper()
	path := filepath.Join(t.TempDir(), "scenario.pcap")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := testpcap.WritePCAP(f, packets, testpcap.BaseTime, interval); err != nil {
		t.Fatal(err)
	}
	f.Close()
	return runPCAPFile(t, path, NewProcessorWithOptions(false, false))
}

func requireOnePacketRef(t *testing.T, e events.Event, wantIdx uint64) {
	t.Helper()
	if len(e.Packets) != 1 {
		t.Fatalf("%s: packet refs = %d, want exactly 1 (bounded)", e.Kind, len(e.Packets))
	}
	if e.Packets[0].Index != wantIdx || !e.Packets[0].Timestamp.Equal(e.Timestamp) {
		t.Errorf("%s: packet ref = %+v, want index %d @ %v", e.Kind, e.Packets[0], wantIdx, e.Timestamp)
	}
}

// ─── tcp.handshake_failed ────────────────────────────────────────────

func TestDualWrite_HandshakeFailed_RST(t *testing.T) {
	const port = 50200
	pk := [][]byte{
		tcpC2S(port, 1000, 0, testpcap.SYN, nil),              // pkt 0
		tcpS2C(port, 0, 1001, testpcap.RST|testpcap.ACK, nil), // pkt 1: server refuses
	}
	r := runGolden(t, pk)

	// Existing output unchanged: one failed handshake flow with the RST reason.
	var failed int
	for _, hs := range r.TCPHandshakeFlows {
		if hs.State == "Handshake Failed" && hs.FailureReason == "Connection reset (RST received)" {
			failed++
		}
	}
	if failed != 1 {
		t.Errorf("existing TCPHandshakeFlows failed count = %d, want 1: %+v", failed, r.TCPHandshakeFlows)
	}

	ev := r.Events.ByKind(events.TCPHandshakeFailed)
	if len(ev) != 1 {
		t.Fatalf("tcp.handshake_failed events = %d, want 1 (no duplicates)", len(ev))
	}
	e := ev[0]
	if !e.Timestamp.Equal(fixtureTime(1)) {
		t.Errorf("timestamp = %v, want RST packet time %v", e.Timestamp, fixtureTime(1))
	}
	requireOnePacketRef(t, e, 1)
	if e.FlowKey != "192.168.1.100:50200->10.0.0.50:443" {
		t.Errorf("flow = %q", e.FlowKey)
	}
	if e.Attrs["reason"] != "Connection reset (RST received)" || e.Values["wait_ms"] != 100 || e.Values["syn_ts_us"] != float64(fixtureTime(0).UnixMicro()) {
		t.Errorf("attrs/values = %v %v", e.Attrs, e.Values)
	}
}

func TestDualWrite_HandshakeFailed_Timeout(t *testing.T) {
	syn := tcpC2S(50201, 1000, 0, testpcap.SYN, nil)
	pk := [][]byte{syn}
	for i := 0; i < 50; i++ { // 5 s of unrelated traffic → SYN-ACK timeout (3 s)
		pk = append(pk, testpcap.UDPFrame(testpcap.ClientMAC, testpcap.ServerMAC, testpcap.ClientIP, testpcap.ServerIP, 40000, 40001, []byte("x")))
	}
	r := runGolden(t, pk)

	ev := r.Events.ByKind(events.TCPHandshakeFailed)
	if len(ev) != 1 {
		t.Fatalf("events = %d, want 1", len(ev))
	}
	e := ev[0]
	// Anchored to the unanswered SYN's own capture time; emitted at finalize so
	// it must NOT be attributed to the last packet.
	if !e.Timestamp.Equal(fixtureTime(0)) || len(e.Packets) != 0 {
		t.Errorf("timestamp/packets = %v / %+v, want SYN time %v and no packet ref", e.Timestamp, e.Packets, fixtureTime(0))
	}
	if e.Attrs["reason"] != "SYN-ACK timeout (no server response)" || e.Values["wait_ms"] != 5000 {
		t.Errorf("attrs/values = %v %v (wait should be 5000 ms of observed silence)", e.Attrs, e.Values)
	}
}

func TestDualWrite_CompleteHandshakeEmitsNoFailure(t *testing.T) {
	r := runGolden(t, testpcap.Handshake())
	if n := len(r.Events.ByKind(events.TCPHandshakeFailed)); n != 0 {
		t.Errorf("clean handshake emitted %d failure events", n)
	}
}

// ─── tcp.zero_window ─────────────────────────────────────────────────

func TestDualWrite_ZeroWindow(t *testing.T) {
	const port = 50300
	pk := handshake(port)
	pk = append(pk, tcpC2S(port, 1001, 2001, testpcap.PSH|testpcap.ACK, make([]byte, 100)))
	for i := 0; i < 3; i++ { // server advertises window 0 three times
		pk = append(pk, testpcap.TCPFrame(testpcap.ServerMAC, testpcap.ClientMAC, testpcap.ServerIP, testpcap.ClientIP,
			443, port, 2001, 1101, testpcap.ACK, nil))
	}
	// TCPFrame hardcodes window 65535; patch the window field (bytes 14:16 of TCP header) to 0
	for i := len(pk) - 3; i < len(pk); i++ {
		off := 14 + 20 + 14 // eth + ip + tcp window offset
		pk[i][off], pk[i][off+1] = 0, 0
	}
	r := runGolden(t, pk)

	// Existing output unchanged: one "Zero Window" finding at the 3rd occurrence.
	var zw int
	for _, f := range r.TCPWindowFindings {
		if f.Type == "Zero Window" {
			zw++
			if f.Count != 3 {
				t.Errorf("existing finding Count = %d, want 3", f.Count)
			}
		}
	}
	if zw != 1 {
		t.Errorf("existing Zero Window findings = %d, want 1", zw)
	}

	ev := r.Events.ByKind(events.TCPZeroWindow)
	if len(ev) != 3 {
		t.Fatalf("tcp.zero_window events = %d, want 3 (one per segment)", len(ev))
	}
	for i, e := range ev {
		wantIdx := uint64(4 + i)
		if !e.Timestamp.Equal(fixtureTime(int(wantIdx))) {
			t.Errorf("event %d timestamp = %v, want %v", i, e.Timestamp, fixtureTime(int(wantIdx)))
		}
		requireOnePacketRef(t, e, wantIdx)
		if e.FlowKey != "10.0.0.50:443->192.168.1.100:50300" || e.Values["zero_count"] != float64(i+1) {
			t.Errorf("event %d flow/values = %q %v", i, e.FlowKey, e.Values)
		}
	}
}

// ─── tunnel.observed ─────────────────────────────────────────────────

func TestDualWrite_TunnelObserved(t *testing.T) {
	r := runGolden(t, testpcap.GRETunnel())

	// Existing output unchanged.
	if len(r.TunnelAnalysis) != 1 || r.TunnelAnalysis[0].Type != "GRE" || r.TunnelAnalysis[0].PacketCount != 3 {
		t.Fatalf("existing TunnelAnalysis = %+v", r.TunnelAnalysis)
	}

	ev := r.Events.ByKind(events.TunnelObserved)
	if len(ev) != 1 {
		t.Fatalf("tunnel.observed events = %d, want 1 per distinct tunnel", len(ev))
	}
	e := ev[0]
	if !e.Timestamp.Equal(fixtureTime(0)) {
		t.Errorf("timestamp = %v, want first tunnel packet %v", e.Timestamp, fixtureTime(0))
	}
	if len(e.Packets) != 0 {
		t.Errorf("finalize-time event must not carry the last packet's ref: %+v", e.Packets)
	}
	if e.Attrs["type"] != "GRE" || e.Attrs["src_ip"] != "10.0.0.1" || e.Attrs["dst_ip"] != "10.0.0.2" {
		t.Errorf("attrs = %v", e.Attrs)
	}
	if e.Values["packet_count"] != 3 || e.Values["last_seen_us"] != float64(fixtureTime(2).UnixMicro()) {
		t.Errorf("values = %v", e.Values)
	}
}

// ─── traffic.gap ─────────────────────────────────────────────────────

func TestDualWrite_TrafficGap(t *testing.T) {
	// Three packets 4 s apart → two silences of 4 s (> 2 s threshold).
	f := testpcap.UDPFrame(testpcap.ClientMAC, testpcap.ServerMAC, testpcap.ClientIP, testpcap.ServerIP, 40000, 40001, []byte("x"))
	r := runGoldenInterval(t, [][]byte{f, f, f}, 4*time.Second)

	if len(r.TrafficGaps) != 2 {
		t.Fatalf("existing TrafficGaps = %d, want 2: %+v", len(r.TrafficGaps), r.TrafficGaps)
	}
	ev := r.Events.ByKind(events.TrafficGap)
	if len(ev) != 2 {
		t.Fatalf("traffic.gap events = %d, want 2", len(ev))
	}
	for i, e := range ev {
		g := r.TrafficGaps[i]
		if float64(e.Timestamp.UnixNano())/1e9 != g.StartTime || e.Values["duration_sec"] != g.DurationSec {
			t.Errorf("event %d (%v, %v) disagrees with existing gap %+v", i, e.Timestamp, e.Values, g)
		}
		if e.Values["duration_sec"] != 4 {
			t.Errorf("event %d duration = %v, want 4", i, e.Values["duration_sec"])
		}
		if len(e.Packets) != 0 {
			t.Errorf("gap event must not reference a packet (it is the absence of packets): %+v", e.Packets)
		}
	}
	// 100 ms spaced fixtures have no gaps.
	if n := len(runGolden(t, testpcap.Handshake()).Events.ByKind(events.TrafficGap)); n != 0 {
		t.Errorf("handshake fixture emitted %d gap events", n)
	}
}

// ─── Cross-cutting ───────────────────────────────────────────────────

func TestDualWrite_EventCountsReflectAllKinds(t *testing.T) {
	r := runGolden(t, append(testpcap.BFDTunnelDrop(), testpcap.RetransmissionStorm()...))
	for _, k := range []string{"bfd.down", "tcp.retransmission", "tcp.rtt_spike"} {
		if r.EventCounts[k] == 0 {
			t.Errorf("event_counts missing %s: %v", k, r.EventCounts)
		}
	}
	if r.EventsDropped != 0 {
		t.Errorf("events dropped = %d", r.EventsDropped)
	}
}
