package analyzer

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gocisse/sdwan-triage/internal/testpcap"
	"github.com/gocisse/sdwan-triage/pkg/config"
	"github.com/gocisse/sdwan-triage/pkg/events"
	"github.com/gocisse/sdwan-triage/pkg/models"
)

// Phase 4.9b: a fresh Processor starts from config.DefaultThresholds(), the same
// values the CLI applies. Effective values are verified by BEHAVIOR at the
// boundary (N-1 packets: no finding, N: finding), so no detector internals are
// exposed. Before 4.9b a fresh Processor used RTT 200 ms, port-scan 25/15.

var (
	thrSrc = []byte{198, 51, 100, 7}
	thrDst = []byte{203, 0, 113, 9}
)

func thrSYN(src, dst []byte, sport, dport uint16) []byte {
	return testpcap.TCPFrame(testpcap.ClientMAC, testpcap.ServerMAC, src, dst, sport, dport, 1000, 0, testpcap.SYN, nil)
}

func thrICMPEcho(src, dst []byte) []byte {
	icmp := []byte{8, 0, 0, 0, 0, 1, 0, 1}
	ip := testpcap.BuildIPv4(src, dst, 1, icmp)
	return testpcap.BuildEthernet(testpcap.ClientMAC, testpcap.ServerMAC, 0x0800, ip)
}

// runThr analyses packets spaced `interval` apart with a processor optionally
// customised by configure (which must run before Process).
func runThr(t *testing.T, packets [][]byte, interval time.Duration, configure func(*Processor)) *models.TriageReport {
	t.Helper()
	path := filepath.Join(t.TempDir(), "thr.pcap")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := testpcap.WritePCAP(f, packets, testpcap.BaseTime, interval); err != nil {
		t.Fatal(err)
	}
	f.Close()
	p := NewProcessorWithOptions(false, false)
	if configure != nil {
		configure(p)
	}
	return runPCAPFile(t, path, p)
}

// handshakeWithRTT: SYN at packet 0, SYN-ACK at packet `gaps` → RTT = gaps*interval.
func handshakeWithRTT(gaps int) [][]byte {
	filler := testpcap.UDPFrame(testpcap.ClientMAC, testpcap.ServerMAC, thrSrc, thrDst, 40000, 40001, []byte("x"))
	pk := [][]byte{testpcap.TCPFrame(testpcap.ClientMAC, testpcap.ServerMAC, thrSrc, thrDst, 50100, 443, 1000, 0, testpcap.SYN, nil)}
	for i := 1; i < gaps; i++ {
		pk = append(pk, filler)
	}
	return append(pk, testpcap.TCPFrame(testpcap.ServerMAC, testpcap.ClientMAC, thrDst, thrSrc, 443, 50100, 2000, 1001, testpcap.SYN|testpcap.ACK, nil))
}

func spikeCount(r *models.TriageReport) int { return len(r.Events.ByKind(events.TCPRTTSpike)) }

func TestDefaultThresholds_RTTSpike100ms(t *testing.T) {
	step := 25 * time.Millisecond
	if got := spikeCount(runThr(t, handshakeWithRTT(3), step, nil)); got != 0 { // 75 ms
		t.Errorf("75 ms RTT emitted %d spikes, want 0", got)
	}
	if got := spikeCount(runThr(t, handshakeWithRTT(4), step, nil)); got != 1 { // exactly 100 ms
		t.Errorf("100 ms RTT emitted %d spikes, want 1 (default threshold is 100 ms, pre-4.9b was 200 ms)", got)
	}
	if got := spikeCount(runThr(t, handshakeWithRTT(6), step, nil)); got != 1 { // 150 ms: spike now, none at the old 200 ms
		t.Errorf("150 ms RTT emitted %d spikes, want 1", got)
	}
}

func portScanTypes(r *models.TriageReport) map[string]int {
	out := map[string]int{}
	for _, f := range r.Security.PortScanFindings {
		out[f.Type]++
	}
	return out
}

func TestDefaultThresholds_PortScanHorizontal20(t *testing.T) {
	scan := func(ports int) [][]byte {
		var pk [][]byte
		for i := 0; i < ports; i++ {
			pk = append(pk, thrSYN(thrSrc, thrDst, uint16(40000+i), uint16(1000+i)))
		}
		return pk
	}
	if got := portScanTypes(runThr(t, scan(19), time.Millisecond, nil)); got["Horizontal"] != 0 {
		t.Errorf("19 ports: %v, want no Horizontal finding", got)
	}
	if got := portScanTypes(runThr(t, scan(20), time.Millisecond, nil)); got["Horizontal"] != 1 {
		t.Errorf("20 ports: %v, want one Horizontal finding (default is 20, pre-4.9b was 25)", got)
	}
}

func TestDefaultThresholds_PortScanVertical10(t *testing.T) {
	scan := func(targets int) [][]byte {
		var pk [][]byte
		for i := 0; i < targets; i++ {
			pk = append(pk, thrSYN(thrSrc, []byte{203, 0, 113, byte(10 + i)}, uint16(40000+i), 22))
		}
		return pk
	}
	if got := portScanTypes(runThr(t, scan(9), time.Millisecond, nil)); got["Vertical"] != 0 {
		t.Errorf("9 targets: %v, want no Vertical finding", got)
	}
	if got := portScanTypes(runThr(t, scan(10), time.Millisecond, nil)); got["Vertical"] != 1 {
		t.Errorf("10 targets: %v, want one Vertical finding (default is 10, pre-4.9b was 15)", got)
	}
}

func ddosTypes(r *models.TriageReport) map[string]int {
	out := map[string]int{}
	for _, f := range r.Security.DDoSFindings {
		out[f.Type]++
	}
	return out
}

// DDoS defaults were already equal (100/200/100) and must stay so.
//
// Boundary note: models.NewFloodCounter starts the counter at 1 and the first
// packet increments it again, so a source trips a threshold of N after N-1
// packets. That off-by-one is pre-existing and deliberately NOT changed here;
// the test pins the effective boundary (N-1) so a change to either the default
// or the counter behavior is noticed.
func TestDefaultThresholds_DDoS100_200_100(t *testing.T) {
	syn := func(n int) [][]byte {
		var pk [][]byte
		for i := 0; i < n; i++ {
			pk = append(pk, thrSYN(thrSrc, thrDst, 50000, 443))
		}
		return pk
	}
	udp := func(n int) [][]byte {
		var pk [][]byte
		f := testpcap.UDPFrame(testpcap.ClientMAC, testpcap.ServerMAC, thrSrc, thrDst, 40000, 40001, []byte("x"))
		for i := 0; i < n; i++ {
			pk = append(pk, f)
		}
		return pk
	}
	icmp := func(n int) [][]byte {
		var pk [][]byte
		for i := 0; i < n; i++ {
			pk = append(pk, thrICMPEcho(thrSrc, thrDst))
		}
		return pk
	}
	cases := []struct {
		name     string
		kind     string
		pk       func(int) [][]byte
		boundary int
	}{
		{"SYN", "SYN Flood", syn, 99},    // threshold 100
		{"UDP", "UDP Flood", udp, 199},   // threshold 200
		{"ICMP", "ICMP Flood", icmp, 99}, // threshold 100
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ddosTypes(runThr(t, tc.pk(tc.boundary-1), time.Millisecond/4, nil)); got[tc.kind] != 0 {
				t.Errorf("%d packets: %v, want no %s", tc.boundary-1, got, tc.kind)
			}
			if got := ddosTypes(runThr(t, tc.pk(tc.boundary), time.Millisecond/4, nil)); got[tc.kind] != 1 {
				t.Errorf("%d packets: %v, want one %s", tc.boundary, got, tc.kind)
			}
		})
	}
}

// The CLI sequence (NewProcessor → ApplyThresholds(LoadThresholds(""))) and a
// bare fresh Processor now produce identical results on the same input.
func TestDefaultThresholds_CLIPathEqualsFreshProcessor(t *testing.T) {
	var pk [][]byte
	pk = append(pk, handshakeWithRTT(6)...) // 150 ms RTT
	for i := 0; i < 22; i++ {               // 22 ports: horizontal scan at default 20
		pk = append(pk, thrSYN(thrSrc, thrDst, uint16(41000+i), uint16(2000+i)))
	}
	fresh := runThr(t, pk, 25*time.Millisecond, nil)
	cli := runThr(t, pk, 25*time.Millisecond, func(p *Processor) {
		cfg, err := config.LoadThresholds("")
		if err != nil {
			t.Fatal(err)
		}
		p.ApplyThresholds(cfg)
	})
	if spikeCount(fresh) != spikeCount(cli) || spikeCount(fresh) == 0 {
		t.Errorf("rtt spikes fresh=%d cli=%d (want equal and >0)", spikeCount(fresh), spikeCount(cli))
	}
	f, c := portScanTypes(fresh), portScanTypes(cli)
	if f["Horizontal"] != c["Horizontal"] || f["Horizontal"] != 1 {
		t.Errorf("port scans fresh=%v cli=%v (want equal, one Horizontal)", f, c)
	}
	if len(fresh.Events.Events()) != len(cli.Events.Events()) || fresh.RiskScore != cli.RiskScore {
		t.Errorf("events %d/%d or risk %d/%d differ", len(fresh.Events.Events()), len(cli.Events.Events()), fresh.RiskScore, cli.RiskScore)
	}
}

// Explicit configuration still overrides the defaults applied by the constructor.
func TestDefaultThresholds_ExplicitOverridesStillWork(t *testing.T) {
	// Custom config: RTT 200 ms → a 150 ms handshake is not a spike.
	cfg := config.DefaultThresholds()
	cfg.Performance.HighRTTMs = 200
	cfg.PortScan.HorizontalThreshold = 30
	apply := func(p *Processor) { p.ApplyThresholds(cfg) }

	if got := spikeCount(runThr(t, handshakeWithRTT(6), 25*time.Millisecond, apply)); got != 0 {
		t.Errorf("RTT override ignored: %d spikes at 150 ms with threshold 200", got)
	}
	var scan [][]byte
	for i := 0; i < 25; i++ {
		scan = append(scan, thrSYN(thrSrc, thrDst, uint16(40000+i), uint16(1000+i)))
	}
	if got := portScanTypes(runThr(t, scan, time.Millisecond, apply)); got["Horizontal"] != 0 {
		t.Errorf("port-scan override ignored: %v with threshold 30 and 25 ports", got)
	}

	// YAML file and preset paths go through the same ApplyThresholds.
	yamlPath := filepath.Join(t.TempDir(), "t.yaml")
	if err := os.WriteFile(yamlPath, []byte("performance:\n  high_rtt_ms: 200\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	fromYAML, err := config.LoadThresholds(yamlPath)
	if err != nil {
		t.Fatal(err)
	}
	if got := spikeCount(runThr(t, handshakeWithRTT(6), 25*time.Millisecond, func(p *Processor) { p.ApplyThresholds(fromYAML) })); got != 0 {
		t.Errorf("YAML high_rtt_ms=200 ignored: %d spikes", got)
	}
	perf, err := config.LoadThresholds("performance") // HighRTTMs 50
	if err != nil {
		t.Fatal(err)
	}
	if got := spikeCount(runThr(t, handshakeWithRTT(3), 25*time.Millisecond, func(p *Processor) { p.ApplyThresholds(perf) })); got != 1 {
		t.Errorf("performance preset (50 ms): %d spikes at 75 ms, want 1", got)
	}
}
