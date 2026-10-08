package main

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/gocisse/sdwan-triage/internal/testpcap"
)

// buildCLI compiles the CLI once per test into a temp dir.
func buildCLI(t *testing.T) string {
	t.Helper()
	if testing.Short() {
		t.Skip("skipping CLI build in -short mode")
	}
	bin := filepath.Join(t.TempDir(), "sdwan-triage-test")
	cmd := exec.Command("go", "build", "-o", bin, ".")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build failed: %v\n%s", err, out)
	}
	return bin
}

func writeNGFile(t *testing.T, linkTypes []uint16, pkts []testpcap.NGPacket) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "fixture.pcapng")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := testpcap.WritePCAPNG(f, linkTypes, pkts, testpcap.BaseTime, testpcap.DefaultInterval); err != nil {
		t.Fatal(err)
	}
	return path
}

func runCLI(t *testing.T, bin string, args ...string) (stdout, stderr string, exit int) {
	t.Helper()
	cmd := exec.Command(bin, args...)
	var so, se bytes.Buffer
	cmd.Stdout, cmd.Stderr = &so, &se
	err := cmd.Run()
	if ee, ok := err.(*exec.ExitError); ok {
		exit = ee.ExitCode()
	} else if err != nil {
		t.Fatalf("run: %v", err)
	}
	return so.String(), se.String(), exit
}

func TestCLI_ZeroDecodeExitsNonZeroWithoutHealthBanner(t *testing.T) {
	bin := buildCLI(t)
	path := writeNGFile(t, []uint16{testpcap.LinkTypeEthernetMPkt},
		[]testpcap.NGPacket{{Interface: 0, Data: make([]byte, 40)}, {Interface: 0, Data: make([]byte, 40)}})
	stdout, stderr, exit := runCLI(t, bin, path)
	if exit == 0 {
		t.Fatalf("exit = 0, want non-zero\nstdout:\n%s\nstderr:\n%s", stdout, stderr)
	}
	if bytes.Contains([]byte(stdout+stderr), []byte("NETWORK HEALTH")) {
		t.Fatalf("undecoded capture must not produce a health verdict:\n%s\n%s", stdout, stderr)
	}
	if !bytes.Contains([]byte(stderr), []byte("none could be decoded")) {
		t.Fatalf("stderr should explain the failure:\n%s", stderr)
	}
}

func TestCLI_PartialDecodePrintsNotice(t *testing.T) {
	bin := buildCLI(t)
	pkts := testpcap.EthernetNG(testpcap.Handshake())
	pkts = append(pkts, testpcap.NGPacket{Interface: 1, Data: make([]byte, 40)})
	path := writeNGFile(t, []uint16{testpcap.LinkTypeEthernet, testpcap.LinkTypeEthernetMPkt}, pkts)
	stdout, stderr, exit := runCLI(t, bin, path)
	if exit != 0 {
		t.Fatalf("exit = %d\n%s\n%s", exit, stdout, stderr)
	}
	if !bytes.Contains([]byte(stderr), []byte("PARTIAL ANALYSIS")) || !bytes.Contains([]byte(stderr), []byte("NOT analyzed")) {
		t.Fatalf("partial-decode notice missing from stderr:\n%s", stderr)
	}
}

func TestCLI_PartialDecodeKeepsJSONStdoutClean(t *testing.T) {
	bin := buildCLI(t)
	pkts := testpcap.EthernetNG(testpcap.Handshake())
	pkts = append(pkts, testpcap.NGPacket{Interface: 1, Data: make([]byte, 40)})
	path := writeNGFile(t, []uint16{testpcap.LinkTypeEthernet, testpcap.LinkTypeEthernetMPkt}, pkts)
	stdout, _, exit := runCLI(t, bin, "-json", path)
	if exit != 0 || len(stdout) == 0 || stdout[0] != '{' {
		t.Fatalf("exit=%d, stdout must be pure JSON, got: %.80q", exit, stdout)
	}
}

func TestCLI_NormalPcapngMatchesPcapVerdict(t *testing.T) {
	bin := buildCLI(t)
	frames := testpcap.RetransmissionStorm()
	ng := writeNGFile(t, []uint16{testpcap.LinkTypeEthernet}, testpcap.EthernetNG(frames))
	pc := filepath.Join(t.TempDir(), "s.pcap")
	if err := testpcap.WriteFile(pc, frames); err != nil {
		t.Fatal(err)
	}
	so1, _, e1 := runCLI(t, bin, ng)
	so2, _, e2 := runCLI(t, bin, pc)
	if e1 != 0 || e2 != 0 {
		t.Fatalf("exit codes %d %d", e1, e2)
	}
	banner := func(s string) string {
		for _, l := range bytes.Split([]byte(s), []byte("\n")) {
			if bytes.Contains(l, []byte("NETWORK HEALTH")) {
				return string(l)
			}
		}
		return ""
	}
	if banner(so1) == "" || banner(so1) != banner(so2) {
		t.Fatalf("pcapng banner %q != pcap banner %q", banner(so1), banner(so2))
	}
}

func partialFixture(t *testing.T) string {
	t.Helper()
	pkts := testpcap.EthernetNG(testpcap.Handshake())
	pkts = append(pkts, testpcap.NGPacket{Interface: 1, Data: make([]byte, 40)})
	return writeNGFile(t, []uint16{testpcap.LinkTypeEthernet, testpcap.LinkTypeEthernetMPkt}, pkts)
}

func TestCLI_PartialAnalysisQualifiesVerdictOnStdout(t *testing.T) {
	bin := buildCLI(t)
	stdout, _, exit := runCLI(t, bin, partialFixture(t))
	if exit != 0 {
		t.Fatalf("exit = %d", exit)
	}
	for _, want := range []string{"NETWORK HEALTH: ", "PARTIAL ANALYSIS: 1 of 6 packets", "Unsupported link type 18", "Findings cover only the analyzed packets"} {
		if !bytes.Contains([]byte(stdout), []byte(want)) {
			t.Errorf("stdout missing %q:\n%s", want, stdout)
		}
	}
	if bytes.Contains([]byte(stdout), []byte("No significant issues detected")) {
		t.Errorf("partial GOOD must not use the affirmative wording:\n%s", stdout)
	}
}

func TestCLI_CompleteCaptureHasNoCompletenessOutput(t *testing.T) {
	bin := buildCLI(t)
	path := writeNGFile(t, []uint16{testpcap.LinkTypeEthernet}, testpcap.EthernetNG(testpcap.Handshake()))
	stdout, stderr, exit := runCLI(t, bin, path)
	if exit != 0 || bytes.Contains([]byte(stdout+stderr), []byte("PARTIAL ANALYSIS")) || bytes.Contains([]byte(stdout), []byte("INCOMPLETE CAPTURE FILE")) {
		t.Fatalf("complete capture must carry no completeness notice (exit %d)\n%s\n%s", exit, stdout, stderr)
	}
	js, _, _ := runCLI(t, bin, "-json", path)
	if !json.Valid([]byte(js)) || bytes.Contains([]byte(js), []byte("capture_completeness")) {
		t.Fatalf("complete JSON must be valid and omit capture_completeness")
	}
}

func TestCLI_JSONCarriesCompletenessWhenPartial(t *testing.T) {
	bin := buildCLI(t)
	js, _, exit := runCLI(t, bin, "-json", partialFixture(t))
	if exit != 0 || !json.Valid([]byte(js)) {
		t.Fatalf("exit=%d valid=%v", exit, json.Valid([]byte(js)))
	}
	var rep struct {
		C struct {
			PacketsRead        int `json:"packets_read"`
			PacketsDecoded     int `json:"packets_decoded"`
			PacketsUnsupported int `json:"packets_unsupported"`
			ReadErrors         int `json:"read_errors"`
		} `json:"capture_completeness"`
	}
	if err := json.Unmarshal([]byte(js), &rep); err != nil {
		t.Fatal(err)
	}
	if rep.C.PacketsRead != 6 || rep.C.PacketsDecoded != 5 || rep.C.PacketsUnsupported != 1 || rep.C.ReadErrors != 0 {
		t.Fatalf("unexpected completeness: %+v", rep.C)
	}
	if bytes.Contains([]byte(js), []byte("PARTIAL ANALYSIS")) {
		t.Error("human-readable text must never appear in JSON stdout")
	}
}

func TestCLI_TruncatedCaptureIsQualified(t *testing.T) {
	bin := buildCLI(t)
	full := filepath.Join(t.TempDir(), "full.pcap")
	if err := testpcap.WriteFile(full, testpcap.Handshake()); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(full)
	cut := filepath.Join(t.TempDir(), "cut.pcap")
	if err := os.WriteFile(cut, b[:len(b)-10], 0o644); err != nil {
		t.Fatal(err)
	}
	stdout, _, exit := runCLI(t, bin, cut)
	if exit != 0 {
		t.Fatalf("exit = %d", exit)
	}
	for _, want := range []string{"NETWORK HEALTH: ", "INCOMPLETE CAPTURE FILE: the capture ended unexpectedly", "Trailing packets may be missing."} {
		if !bytes.Contains([]byte(stdout), []byte(want)) {
			t.Errorf("stdout missing %q:\n%s", want, stdout)
		}
	}
}

// Suspicious-port flows stay reported but do not drive the health verdict
// (observation != failure).
func TestCLI_SuspiciousPortIsReportedButNotHealth(t *testing.T) {
	bin := buildCLI(t)
	// Client uses SOURCE port 5555 (the Velocloud-Wan shape) for a full handshake + data exchange.
	c2s := func(seq, ack uint32, flags uint8, payload []byte) []byte {
		return testpcap.TCPFrame(testpcap.ClientMAC, testpcap.ServerMAC, testpcap.ClientIP, testpcap.ServerIP, 5555, 443, seq, ack, flags, payload)
	}
	s2c := func(seq, ack uint32, flags uint8, payload []byte) []byte {
		return testpcap.TCPFrame(testpcap.ServerMAC, testpcap.ClientMAC, testpcap.ServerIP, testpcap.ClientIP, 443, 5555, seq, ack, flags, payload)
	}
	frames := [][]byte{c2s(1000, 0, testpcap.SYN, nil), s2c(2000, 1001, testpcap.SYN|testpcap.ACK, nil), c2s(1001, 2001, testpcap.ACK, nil)}
	path := filepath.Join(t.TempDir(), "p5555.pcap")
	if err := testpcap.WriteFile(path, frames); err != nil {
		t.Fatal(err)
	}
	js, _, exit := runCLI(t, bin, "-json", path)
	var rep struct {
		Susp []struct {
			SrcPort int    `json:"src_port"`
			Reason  string `json:"reason"`
		} `json:"suspicious_traffic"`
	}
	if exit != 0 || json.Unmarshal([]byte(js), &rep) != nil || len(rep.Susp) == 0 || rep.Susp[0].SrcPort != 5555 {
		t.Fatalf("suspicious-port detection must stay intact (exit %d): %s", exit, js)
	}
	out, _, _ := runCLI(t, bin, path)
	if !bytes.Contains([]byte(out), []byte("Suspicious Traffic:   ")) {
		t.Errorf("observation must stay in the summary:\n%s", out)
	}
	for _, bad := range []string{"NETWORK HEALTH: WARNING", "NETWORK HEALTH: CRITICAL"} {
		if bytes.Contains([]byte(out), []byte(bad)) {
			t.Errorf("a port number alone must not produce %q:\n%s", bad, out)
		}
	}
}
