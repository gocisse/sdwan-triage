package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/gocisse/sdwan-triage/internal/testpcap"
)

// arpReply builds an Ethernet+ARP reply claiming ip is at mac.
func arpReply(mac, ip []byte) []byte {
	arp := []byte{0, 1, 8, 0, 6, 4, 0, 2}
	arp = append(arp, mac...)
	arp = append(arp, ip...)
	arp = append(arp, testpcap.ServerMAC...)
	arp = append(arp, testpcap.ServerIP...)
	return testpcap.BuildEthernet(mac, []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, 0x0806, arp)
}

func healthFixtures(t *testing.T) map[string]string {
	t.Helper()
	w := func(name string, frames [][]byte) string {
		p := filepath.Join(t.TempDir(), name+".pcap")
		if err := testpcap.WriteFile(p, frames); err != nil {
			t.Fatal(err)
		}
		return p
	}
	ip := []byte{192, 168, 1, 50}
	return map[string]string{
		"good":     w("good", [][]byte{testpcap.UDPFrame(testpcap.ClientMAC, testpcap.ServerMAC, testpcap.ClientIP, testpcap.DNSServer, 40000, 9999, []byte("x"))}),
		"fair":     w("fair", testpcap.RetransmissionStorm()),
		"warning":  w("warning", testpcap.BFDTunnelDrop()),
		"critical": w("critical", [][]byte{arpReply([]byte{0, 1, 2, 3, 4, 5}, ip), arpReply([]byte{0, 9, 9, 9, 9, 9}, ip)}),
	}
}

// Script-style consumer (the documented algorithm): exit code first, then JSON.
func TestNetworkHealthCLI_JSONConsumerAlgorithm(t *testing.T) {
	bin := buildCLI(t)
	for want, path := range healthFixtures(t) {
		js, _, exit := runIn(t, t.TempDir(), bin, "-json", path)
		if exit != 0 || !json.Valid([]byte(js)) {
			t.Fatalf("%s: exit=%d valid=%v", want, exit, json.Valid([]byte(js)))
		}
		var d struct {
			Health string `json:"network_health"`
			Status string `json:"analysis_status"`
			Plain  struct {
				Overall string `json:"overall_health"`
			} `json:"plain_english_summary"`
		}
		if err := json.Unmarshal([]byte(js), &d); err != nil {
			t.Fatal(err)
		}
		if d.Health != want || d.Status != "" {
			t.Errorf("%s: network_health=%q analysis_status=%q", want, d.Health, d.Status)
		}
		legacy := map[string]string{"good": "Healthy", "fair": "Warning", "warning": "Warning", "critical": "Critical"}[want]
		if d.Plain.Overall != legacy {
			t.Errorf("%s: plain-English %q, want %q", want, d.Plain.Overall, legacy)
		}
	}
}

// Every CLI surface agrees with the JSON value; CRITICAL still exits 0.
func TestNetworkHealthCLI_SurfacesAgreeAndExit0(t *testing.T) {
	bin := buildCLI(t)
	banner := map[string]string{"good": "GOOD", "fair": "FAIR", "warning": "WARNING", "critical": "CRITICAL"}
	simple := map[string]string{
		// The "good" fixture is one UDP packet: no health-relevant evidence class had input,
		// so the (unchanged) GOOD level is worded with the 4.25 qualification.
		"good": "No problems were found, but there was no TCP, DNS, TLS, ARP-reply or stability-protocol traffic to evaluate", "fair": "minor issues worth a look",
		"warning": "some issues that need attention", "critical": "serious problems requiring immediate action"}
	for level, path := range healthFixtures(t) {
		term, _, exit := runIn(t, t.TempDir(), bin, path)
		if exit != 0 {
			t.Errorf("%s: exit %d (health must not influence the exit code)", level, exit)
		}
		m := regexp.MustCompile(`NETWORK HEALTH: (\w+)`).FindStringSubmatch(term)
		if m == nil || m[1] != banner[level] {
			t.Errorf("%s: terminal banner %v", level, m)
		}
		sp, _, _ := runIn(t, t.TempDir(), bin, "-simple", path)
		if !strings.Contains(sp, simple[level]) {
			t.Errorf("%s: -simple missing %q", level, simple[level])
		}
		dir := t.TempDir()
		runIn(t, dir, bin, "-csv", "c", "-html", "r.html", "-multi-page-html", "mp", path)
		var csv, html, mpi string
		filepath.Walk(dir, func(p string, i os.FileInfo, err error) error {
			if err != nil || i.IsDir() {
				return nil
			}
			b, _ := os.ReadFile(p)
			switch {
			case strings.HasSuffix(p, "c_summary.csv"):
				csv = string(b)
			case strings.HasSuffix(p, "r.html"):
				html = string(b)
			case strings.HasSuffix(p, "mp/index.html"):
				mpi = string(b)
			}
			return nil
		})
		if !strings.Contains(csv, "Network Health Status,"+banner[level]+",") {
			t.Errorf("%s: CSV disagrees:\n%.300s", level, csv)
		}
		val := map[string]string{"good": "Good", "fair": "Fair", "warning": "Warning", "critical": "Critical"}[level]
		if !strings.Contains(html, `kpi-value">`+val) || !strings.Contains(mpi, `kpi-value">`+val) {
			t.Errorf("%s: HTML KPI should read %s", level, val)
		}
	}
}

func TestNetworkHealthCLI_NoDataAndErrorsCarryNoHealth(t *testing.T) {
	bin := buildCLI(t)
	js, _, exit := runIn(t, t.TempDir(), bin, "-json", emptyPCAP(t))
	if exit != 2 || strings.Contains(js, "network_health") || !strings.Contains(js, `"analysis_status": "no_data"`) {
		t.Errorf("no_data: exit=%d", exit)
	}
	p := writeNGFile(t, []uint16{testpcap.LinkTypeEthernetMPkt}, []testpcap.NGPacket{{Interface: 0, Data: make([]byte, 40)}})
	js, _, exit = runIn(t, t.TempDir(), bin, "-json", p)
	if exit != 1 || strings.TrimSpace(js) != "" {
		t.Errorf("error: exit=%d stdout=%q (must be empty)", exit, js)
	}
}

func TestNetworkHealthCLI_PartialAndTruncatedStayJudged(t *testing.T) {
	bin := buildCLI(t)
	js, _, exit := runIn(t, t.TempDir(), bin, "-json", partialFixture(t))
	if exit != 0 || !strings.Contains(js, `"network_health"`) || !strings.Contains(js, `"capture_completeness"`) {
		t.Errorf("partial: exit=%d", exit)
	}
}

func TestNetworkHealthCLI_DeterministicAcrossRuns(t *testing.T) {
	bin := buildCLI(t)
	path := healthFixtures(t)["fair"]
	var first string
	for i := 0; i < 8; i++ {
		js, _, _ := runIn(t, t.TempDir(), bin, "-json", path)
		var d struct {
			Health string `json:"network_health"`
		}
		json.Unmarshal([]byte(js), &d)
		if i == 0 {
			first = d.Health
		} else if d.Health != first {
			t.Fatalf("run %d: %q != %q", i, d.Health, first)
		}
	}
}

// Evidence applicability (4.25): the level and exit code are unchanged; only the
// wording is qualified, and only when no health-relevant class had input.
func TestCoverageCLI_QualifiedGoodForUDPOnly(t *testing.T) {
	bin := buildCLI(t)
	udp := healthFixtures(t)["good"] // one UDP packet
	stdout, _, exit := runIn(t, t.TempDir(), bin, udp)
	if exit != 0 || !strings.Contains(stdout, "NETWORK HEALTH: GOOD - No significant issues observed — there was no TCP, DNS, TLS, ARP-reply or stability-protocol traffic to evaluate") {
		t.Fatalf("exit=%d\n%s", exit, stdout)
	}
	js, _, _ := runIn(t, t.TempDir(), bin, "-json", udp)
	var d struct {
		Health string `json:"network_health"`
		Cov    *struct {
			TCP, DNS, TLS, Stab, ARP int
		} `json:"-"`
		Raw map[string]int `json:"evidence_coverage"`
	}
	if err := json.Unmarshal([]byte(js), &d); err != nil {
		t.Fatal(err)
	}
	if d.Health != "good" || len(d.Raw) != 5 {
		t.Errorf("health=%q coverage=%v", d.Health, d.Raw)
	}
	for k, v := range d.Raw {
		if v != 0 {
			t.Errorf("%s = %d, want 0", k, v)
		}
	}
}

func TestCoverageCLI_NotQualifiedWithRelevantEvidence(t *testing.T) {
	bin := buildCLI(t)
	fx := healthFixtures(t)
	p := handshakePCAP(t, testpcap.Handshake())
	stdout, _, exit := runIn(t, t.TempDir(), bin, p)
	if exit != 0 || strings.Contains(stdout, "no TCP, DNS, TLS") {
		t.Errorf("TCP capture must not be qualified (exit %d)", exit)
	}
	// FAIR / WARNING / CRITICAL fixtures keep their wording.
	for _, level := range []string{"fair", "warning", "critical"} {
		out, _, _ := runIn(t, t.TempDir(), bin, fx[level])
		if strings.Contains(out, "no TCP, DNS, TLS") {
			t.Errorf("%s must not be qualified", level)
		}
	}
	// ARP requests only → qualified; ARP replies → not qualified.
	mac, ip := []byte{0, 1, 2, 3, 4, 5}, []byte{192, 168, 1, 50}
	req := handshakePCAP(t, [][]byte{arpFrameCLI(1, mac, ip)})
	if out, _, _ := runIn(t, t.TempDir(), bin, req); !strings.Contains(out, "no TCP, DNS, TLS") {
		t.Errorf("ARP requests only must be qualified:\n%s", out)
	}
	rep := handshakePCAP(t, [][]byte{arpFrameCLI(2, mac, ip)})
	if out, _, _ := runIn(t, t.TempDir(), bin, rep); strings.Contains(out, "no TCP, DNS, TLS") {
		t.Errorf("ARP replies must not be qualified:\n%s", out)
	}
}

func arpFrameCLI(op byte, mac, ip []byte) []byte {
	arp := []byte{0, 1, 8, 0, 6, 4, 0, op}
	arp = append(arp, mac...)
	arp = append(arp, ip...)
	arp = append(arp, make([]byte, 6)...)
	arp = append(arp, testpcap.ServerIP...)
	return testpcap.BuildEthernet(mac, []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, 0x0806, arp)
}

func TestCoverageCLI_NoDataHasNoCoverageOrHealth(t *testing.T) {
	bin := buildCLI(t)
	js, _, exit := runIn(t, t.TempDir(), bin, "-json", emptyPCAP(t))
	if exit != 2 || strings.Contains(js, "evidence_coverage") || strings.Contains(js, "network_health") {
		t.Errorf("exit=%d", exit)
	}
}

// 4.26: the human evidence line matches the JSON evidence_coverage exactly.
func TestEvidenceDisplayCLI_MatchesJSON(t *testing.T) {
	bin := buildCLI(t)
	noun := func(n int, s, p string) string {
		if n == 1 {
			return "1 " + s
		}
		return strconv.Itoa(n) + " " + p
	}
	for level, path := range healthFixtures(t) {
		js, _, _ := runIn(t, t.TempDir(), bin, "-json", path)
		var d struct {
			Cov struct {
				TCP, DNS, TLS, Stab, ARP int
			} `json:"-"`
			Raw map[string]int `json:"evidence_coverage"`
		}
		if err := json.Unmarshal([]byte(js), &d); err != nil {
			t.Fatal(err)
		}
		want := "Evidence examined: " + strings.Join([]string{
			noun(d.Raw["tcp_flows"], "TCP flow", "TCP flows"),
			noun(d.Raw["dns_exchanges"], "DNS exchange", "DNS exchanges"),
			noun(d.Raw["tls_certificates"], "TLS certificate", "TLS certificates"),
			noun(d.Raw["stability_sessions"], "stability unit", "stability units"),
			noun(d.Raw["arp_bindings"], "ARP binding", "ARP bindings"),
		}, ", ") + "."
		term, _, _ := runIn(t, t.TempDir(), bin, path)
		sp, _, _ := runIn(t, t.TempDir(), bin, "-simple", path)
		for name, out := range map[string]string{"terminal": term, "simple": sp} {
			if !strings.Contains(out, want) || !strings.Contains(out, "they do not measure how much is enough.") {
				t.Errorf("%s/%s: want %q in\n%s", level, name, want, out)
			}
		}
	}
}
