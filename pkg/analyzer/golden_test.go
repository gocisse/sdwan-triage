package analyzer

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gocisse/sdwan-triage/internal/testpcap"
	"github.com/gocisse/sdwan-triage/pkg/models"
)

// runGolden writes a deterministic scenario to a temp pcap, runs it through the
// standard Processor (same path as the CLI and web server) and returns the report.
func runGolden(t *testing.T, packets [][]byte) *models.TriageReport {
	t.Helper()
	path := filepath.Join(t.TempDir(), "scenario.pcap")
	if err := testpcap.WriteFile(path, packets); err != nil {
		t.Fatalf("write pcap: %v", err)
	}
	return runPCAPFile(t, path, NewProcessorWithOptions(false, false))
}

func runPCAPFile(t *testing.T, path string, p *Processor) *models.TriageReport {
	t.Helper()
	handle, err := OpenCapture(path)
	if err != nil {
		t.Fatalf("open capture: %v", err)
	}
	defer handle.Close()

	report := &models.TriageReport{ApplicationBreakdown: make(map[string]models.AppCategory)}
	state := models.NewAnalysisState()
	if err := p.Process(handle.Reader, state, report, nil); err != nil {
		t.Fatalf("process: %v", err)
	}
	return report
}

func hasTCPFlow(flows []models.TCPFlow, srcPort, dstPort uint16) bool {
	for _, f := range flows {
		if f.SrcPort == srcPort && f.DstPort == dstPort {
			return true
		}
	}
	return false
}

func TestGolden_Handshake(t *testing.T) {
	r := runGolden(t, testpcap.Handshake())

	if got := len(r.TCPHandshakes.SuccessfulHandshakes); got != 1 {
		t.Errorf("successful handshakes = %d, want 1", got)
	}
	if got := len(r.TCPHandshakes.FailedHandshakeAttempts); got != 0 {
		t.Errorf("failed handshake attempts = %d, want 0", got)
	}
	// The first data segment reuses the sequence number of the pure ACK that
	// completed the handshake. That is normal TCP, not a retransmission.
	if len(r.TCPRetransmissions) != 0 {
		t.Errorf("clean handshake must not report retransmissions, got %+v", r.TCPRetransmissions)
	}
	if r.PacketLoss != nil && r.PacketLoss.PacketsLost != 0 {
		t.Errorf("clean handshake must not report packet loss, got %d", r.PacketLoss.PacketsLost)
	}
	for _, hs := range r.TCPHandshakeFlows {
		if hs.State == "Handshake Failed" {
			t.Errorf("handshake flow wrongly marked failed: %+v", hs)
		}
	}
}

func TestGolden_MTUIssue(t *testing.T) {
	r := runGolden(t, testpcap.MTUIssue())

	// The 1460-byte server segment is sent three times → retransmission on 80→50001.
	if !hasTCPFlow(r.TCPRetransmissions, 80, 50001) {
		t.Errorf("expected retransmission flow 80->50001, got %+v", r.TCPRetransmissions)
	}
	// The client→server direction never retransmits.
	if hasTCPFlow(r.TCPRetransmissions, 50001, 80) {
		t.Errorf("unexpected retransmission flow 50001->80")
	}
	if r.PacketLoss == nil || r.PacketLoss.PacketsLost != 2 {
		t.Errorf("expected exactly 2 retransmitted data segments, got %+v", r.PacketLoss)
	}
}

func TestGolden_DNSFailure(t *testing.T) {
	r := runGolden(t, testpcap.DNSFailure())

	if len(r.DNSDetails) != 4 {
		t.Fatalf("expected 4 DNS query records, got %d", len(r.DNSDetails))
	}
	for i, d := range r.DNSDetails {
		if d.ResponseTimestamp != nil {
			t.Errorf("record %d unexpectedly has a response", i)
		}
	}
	var found bool
	for _, a := range r.DNSAnomalies {
		if a.Query == "example.com" && strings.Contains(strings.ToLower(a.Reason), "no response") {
			found = true
			if a.ServerIP != "8.8.8.8" {
				t.Errorf("anomaly server ip = %q, want 8.8.8.8", a.ServerIP)
			}
		}
	}
	if !found {
		t.Errorf("expected an unanswered-DNS anomaly for example.com, got %+v", r.DNSAnomalies)
	}
	// One (client, name) pair retried 4× must yield exactly one anomaly, not four.
	if len(r.DNSAnomalies) != 1 {
		t.Errorf("expected exactly 1 DNS anomaly, got %d", len(r.DNSAnomalies))
	}
}

func TestGolden_BFDTunnelDrop(t *testing.T) {
	r := runGolden(t, testpcap.BFDTunnelDrop())

	var down, flapping int
	for _, f := range r.StabilityFindings {
		switch f.Type {
		case "BFD Session Down":
			down++
			if f.Protocol != "BFD" || f.SourceIP != "192.168.1.100" || f.PeerIP != "10.0.0.1" {
				t.Errorf("unexpected BFD Down finding fields: %+v", f)
			}
			if f.StateChanges != 1 {
				t.Errorf("BFD Down state changes = %d, want 1", f.StateChanges)
			}
		case "BFD Flapping":
			flapping++
		}
	}
	if down != 1 {
		t.Errorf("expected exactly 1 'BFD Session Down' finding, got %d (%+v)", down, r.StabilityFindings)
	}
	if flapping != 0 {
		t.Errorf("a single Up→Down transition must not be reported as flapping")
	}
}

func TestGolden_RetransmissionStorm(t *testing.T) {
	r := runGolden(t, testpcap.RetransmissionStorm())

	if !hasTCPFlow(r.TCPRetransmissions, 50002, 443) {
		t.Errorf("expected retransmission flow 50002->443, got %+v", r.TCPRetransmissions)
	}
	// Duplicate ACKs from the server are pure ACKs and must not count as retransmissions.
	if hasTCPFlow(r.TCPRetransmissions, 443, 50002) {
		t.Errorf("duplicate ACKs wrongly counted as retransmissions on 443->50002")
	}
	if r.PacketLoss == nil || r.PacketLoss.PacketsLost != 5 {
		t.Errorf("expected 5 retransmitted data segments, got %+v", r.PacketLoss)
	}
	if got := len(r.TCPHandshakes.SuccessfulHandshakes); got != 1 {
		t.Errorf("successful handshakes = %d, want 1", got)
	}
}

// Handshake still pending at end-of-capture must not be reported as failed
// unless the capture itself shows the timeout elapsing.
func TestGolden_PendingSYNAtEndOfCaptureIsNotFailed(t *testing.T) {
	syn := testpcap.TCPFrame(testpcap.ClientMAC, testpcap.ServerMAC, testpcap.ClientIP, testpcap.ServerIP,
		50010, 443, 1000, 0, testpcap.SYN, nil)
	r := runGolden(t, [][]byte{syn})

	for _, hs := range r.TCPHandshakeFlows {
		if hs.State == "Handshake Failed" {
			t.Errorf("SYN 0ms before end of capture marked failed: %+v", hs)
		}
	}
}

// A SYN followed by ≥3s of unrelated traffic and no SYN-ACK IS a failed handshake.
func TestGolden_SYNTimeoutMeasuredInCaptureTime(t *testing.T) {
	syn := testpcap.TCPFrame(testpcap.ClientMAC, testpcap.ServerMAC, testpcap.ClientIP, testpcap.ServerIP,
		50011, 443, 1000, 0, testpcap.SYN, nil)
	// 50 packets at 100ms = 5s of other traffic after the SYN
	var packets [][]byte
	packets = append(packets, syn)
	for i := 0; i < 50; i++ {
		packets = append(packets, testpcap.UDPFrame(testpcap.ClientMAC, testpcap.ServerMAC,
			testpcap.ClientIP, testpcap.ServerIP, 40000, 40001, []byte("x")))
	}
	r := runGolden(t, packets)

	var failed bool
	for _, hs := range r.TCPHandshakeFlows {
		if hs.SrcPort == 50011 && hs.State == "Handshake Failed" {
			failed = true
		}
	}
	if !failed {
		t.Errorf("SYN unanswered for 5s of capture time should be a failed handshake: %+v", r.TCPHandshakeFlows)
	}
}

func TestGolden_ReportEncodesToValidJSON(t *testing.T) {
	for _, s := range testpcap.Scenarios() {
		t.Run(s.Name, func(t *testing.T) {
			r := runGolden(t, s.Generate())
			data, err := json.Marshal(r)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			if !json.Valid(data) {
				t.Fatalf("report JSON is not valid")
			}
		})
	}
}

// Process must never write to stdout: the CLI streams the JSON report there.
func TestProcess_DoesNotWriteToStdout(t *testing.T) {
	path := filepath.Join(t.TempDir(), "s.pcap")
	if err := testpcap.WriteFile(path, testpcap.RetransmissionStorm()); err != nil {
		t.Fatal(err)
	}

	origStdout := os.Stdout
	rp, wp, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = wp
	defer func() { os.Stdout = origStdout }()

	done := make(chan []byte)
	go func() {
		var buf bytes.Buffer
		io.Copy(&buf, rp)
		done <- buf.Bytes()
	}()

	runPCAPFile(t, path, NewProcessorWithOptions(true, false))
	wp.Close()
	out := <-done
	os.Stdout = origStdout

	if len(out) != 0 {
		t.Errorf("Process wrote %d bytes to stdout: %q", len(out), string(out))
	}
}

func TestGolden_FixturesAreDeterministic(t *testing.T) {
	for _, s := range testpcap.Scenarios() {
		var a, b bytes.Buffer
		if err := testpcap.WritePCAP(&a, s.Generate(), testpcap.BaseTime, testpcap.DefaultInterval); err != nil {
			t.Fatal(err)
		}
		time.Sleep(2 * time.Millisecond)
		if err := testpcap.WritePCAP(&b, s.Generate(), testpcap.BaseTime, testpcap.DefaultInterval); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(a.Bytes(), b.Bytes()) {
			t.Errorf("%s: fixture bytes differ between generations", s.Name)
		}
	}
}
