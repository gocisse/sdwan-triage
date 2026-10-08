package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
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
		"good": "healthy and performing well", "fair": "minor issues worth a look",
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
