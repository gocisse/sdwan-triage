package main

import (
	"bytes"
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
