package main

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gocisse/sdwan-triage/internal/testpcap"
)

// Binary-level tests of the NO_DATA contract:
//   exit 0 = analyzed with evidence, 1 = error / could not analyze, 2 = no evidence to judge.

func runIn(t *testing.T, dir, bin string, args ...string) (stdout, stderr string, exit int) {
	t.Helper()
	cmd := exec.Command(bin, args...)
	cmd.Dir = dir
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

func emptyPCAP(t *testing.T) string {
	p := filepath.Join(t.TempDir(), "empty.pcap")
	if err := testpcap.WriteFile(p, nil); err != nil {
		t.Fatal(err)
	}
	return p
}

func emptyPCAPNG(t *testing.T) string {
	return writeNGFile(t, []uint16{testpcap.LinkTypeEthernet}, nil)
}

func handshakePCAP(t *testing.T, frames [][]byte) string {
	p := filepath.Join(t.TempDir(), "hs.pcap")
	if err := testpcap.WriteFile(p, frames); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestNoDataCLI_ZeroPacketCapturesExit2(t *testing.T) {
	bin := buildCLI(t)
	for name, path := range map[string]string{"pcap": emptyPCAP(t), "pcapng": emptyPCAPNG(t)} {
		stdout, stderr, exit := runIn(t, t.TempDir(), bin, path)
		if exit != 2 {
			t.Errorf("%s: exit = %d, want 2\n%s\n%s", name, exit, stdout, stderr)
		}
		if !strings.Contains(stdout, "NETWORK HEALTH: NO DATA") || strings.Contains(stdout, "GOOD") {
			t.Errorf("%s: banner must be NO DATA and never GOOD:\n%s", name, stdout)
		}
		if !strings.Contains(stderr, "NO DATA:") {
			t.Errorf("%s: stderr notice missing:\n%s", name, stderr)
		}
	}
}

func TestNoDataCLI_JSONIsValidAndExit2(t *testing.T) {
	bin := buildCLI(t)
	stdout, _, exit := runIn(t, t.TempDir(), bin, "-json", emptyPCAP(t))
	if exit != 2 || !json.Valid([]byte(stdout)) {
		t.Fatalf("exit=%d valid=%v", exit, json.Valid([]byte(stdout)))
	}
	var d struct {
		Status string `json:"analysis_status"`
		Reason string `json:"no_data_reason"`
		Plain  struct {
			Overall string `json:"overall_health"`
		} `json:"plain_english_summary"`
		Risk string `json:"risk_level"`
	}
	if err := json.Unmarshal([]byte(stdout), &d); err != nil {
		t.Fatal(err)
	}
	if d.Status != "no_data" || d.Reason != "empty_capture" || d.Plain.Overall != "No Data" || d.Risk != "Low" {
		t.Errorf("unexpected JSON: %+v", d)
	}
	if strings.Contains(stdout, "NO DATA:") {
		t.Error("human text must not appear in JSON stdout")
	}
}

func TestNoDataCLI_SimpleExit2NeverHealthy(t *testing.T) {
	bin := buildCLI(t)
	stdout, _, exit := runIn(t, t.TempDir(), bin, "-simple", emptyPCAP(t))
	if exit != 2 {
		t.Errorf("exit = %d", exit)
	}
	if strings.Contains(stdout, "healthy") || !strings.Contains(stdout, "No conclusion about your network can be drawn") {
		t.Errorf("simple output:\n%s", stdout)
	}
}

func TestNoDataCLI_ExportsAreStillGenerated(t *testing.T) {
	bin := buildCLI(t)
	dir := t.TempDir()
	_, stderr, exit := runIn(t, dir, bin, "-csv", "c", "-html", "r.html", "-pdf", "r.pdf", emptyPCAP(t))
	if exit != 2 {
		t.Fatalf("exit = %d\n%s", exit, stderr)
	}
	var csvSummary, html, pdf string
	filepath.Walk(dir, func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		switch {
		case strings.HasSuffix(p, "c_summary.csv"):
			b, _ := os.ReadFile(p)
			csvSummary = string(b)
		case strings.HasSuffix(p, "r.html"):
			b, _ := os.ReadFile(p)
			html = string(b)
		case strings.HasSuffix(p, "r.pdf"):
			pdf = p
		}
		return nil
	})
	if !strings.Contains(csvSummary, "Network Health Status,NO_DATA,") {
		t.Errorf("CSV not generated or wrong:\n%s", csvSummary)
	}
	if !strings.Contains(html, "NETWORK HEALTH: NO DATA") || strings.Contains(html, "Network Health: GOOD") {
		t.Error("HTML not generated or misleading")
	}
	if st, err := os.Stat(pdf); pdf == "" || err != nil || st.Size() == 0 {
		t.Error("PDF not generated")
	}
}

func TestNoDataCLI_UnsupportedOnlyStillExit1(t *testing.T) {
	bin := buildCLI(t)
	p := writeNGFile(t, []uint16{testpcap.LinkTypeEthernetMPkt}, []testpcap.NGPacket{{Interface: 0, Data: make([]byte, 40)}})
	stdout, stderr, exit := runIn(t, t.TempDir(), bin, p)
	if exit != 1 || strings.Contains(stdout, "NETWORK HEALTH") || !strings.Contains(stderr, "none could be decoded") {
		t.Errorf("exit=%d\n%s\n%s", exit, stdout, stderr)
	}
}

func TestNoDataCLI_AnalyzedCapturesExit0(t *testing.T) {
	bin := buildCLI(t)
	normal := handshakePCAP(t, testpcap.Handshake())
	one := handshakePCAP(t, [][]byte{testpcap.Handshake()[0]}) // a single analyzable packet is NOT no-data
	for name, p := range map[string]string{"normal": normal, "one packet": one} {
		stdout, _, exit := runIn(t, t.TempDir(), bin, p)
		if exit != 0 || !strings.Contains(stdout, "NETWORK HEALTH: ") || strings.Contains(stdout, "NO DATA") {
			t.Errorf("%s: exit=%d\n%s", name, exit, stdout)
		}
		js, _, _ := runIn(t, t.TempDir(), bin, "-json", p)
		if strings.Contains(js, "analysis_status") || strings.Contains(js, "no_data_reason") {
			t.Errorf("%s: analyzed JSON must omit the NO_DATA fields", name)
		}
	}
}

func TestNoDataCLI_FilterMatchesNothing(t *testing.T) {
	bin := buildCLI(t)
	p := handshakePCAP(t, testpcap.Handshake())
	stdout, stderr, exit := runIn(t, t.TempDir(), bin, "-src-ip", "9.9.9.9", p)
	if exit != 2 || !strings.Contains(stdout, "NETWORK HEALTH: NO DATA") || !strings.Contains(stdout, "no packet matched the selected filter.") {
		t.Fatalf("exit=%d\n%s\n%s", exit, stdout, stderr)
	}
	if strings.Contains(stdout+stderr, "could be decoded") {
		t.Error("filtered packets must never be described as undecodable")
	}
	js, _, jexit := runIn(t, t.TempDir(), bin, "-json", "-src-ip", "9.9.9.9", p)
	if jexit != 2 || !strings.Contains(js, `"no_data_reason": "filter_matched_nothing"`) {
		t.Errorf("json exit=%d\n%.200s", jexit, js)
	}
	// A filter that does match is a normal analysis.
	_, _, mexit := runIn(t, t.TempDir(), bin, "-src-ip", "192.168.1.100", p)
	if mexit != 0 {
		t.Errorf("matching filter exit = %d, want 0", mexit)
	}
}
