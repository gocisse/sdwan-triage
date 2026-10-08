package analyzer

import (
	"encoding/json"
	"fmt"
	"net"
	"sort"
	"testing"

	"github.com/gocisse/sdwan-triage/internal/testpcap"
	"github.com/gocisse/sdwan-triage/pkg/models"
)

// Same evidence must produce the same answer: Go map iteration order must never
// decide a user-visible or machine-visible result.

const detRuns = 40

func TestDeterminism_TopIssueTieBreak(t *testing.T) {
	order := []string{"ARP Conflicts", "DNS Anomalies", "TLS Security Issues", "TCP Retransmissions", "Failed Handshakes", "High RTT Flows"}
	issues := map[string]int{"Failed Handshakes": 3, "TCP Retransmissions": 3, "DNS Anomalies": 3, "High RTT Flows": 3, "ARP Conflicts": 0}
	for i := 0; i < 500; i++ { // each range over the map starts at a random position
		name, count := pickTopIssue(issues, order)
		if name != "DNS Anomalies" || count != 3 {
			t.Fatalf("run %d: got %q/%d, want the earliest-priority tied issue \"DNS Anomalies\"/3", i, name, count)
		}
	}
	// A strictly higher count always wins regardless of priority.
	issues["High RTT Flows"] = 4
	for i := 0; i < 100; i++ {
		if name, count := pickTopIssue(issues, order); name != "High RTT Flows" || count != 4 {
			t.Fatalf("got %q/%d", name, count)
		}
	}
	// Unlisted names rank after listed ones, then lexically.
	for i := 0; i < 100; i++ {
		name, _ := pickTopIssue(map[string]int{"zzz": 2, "aaa": 2, "Failed Handshakes": 2}, order)
		if name != "Failed Handshakes" {
			t.Fatalf("listed issue must beat unlisted on ties, got %q", name)
		}
		name, _ = pickTopIssue(map[string]int{"zzz": 2, "aaa": 2}, order)
		if name != "aaa" {
			t.Fatalf("unlisted ties resolve lexically, got %q", name)
		}
	}
	if name, count := pickTopIssue(map[string]int{}, order); name != "" || count != 0 {
		t.Errorf("no issues → empty, got %q/%d", name, count)
	}
}

func TestDeterminism_TopIssueThroughRiskScore(t *testing.T) {
	mk := func() *models.TriageReport {
		return &models.TriageReport{
			DNSAnomalies:       make([]models.DNSAnomaly, 3),
			TCPRetransmissions: make([]models.TCPFlow, 3),
			FailedHandshakes:   make([]models.TCPFlow, 3),
			RTTAnalysis:        make([]models.RTTFlow, 3),
		}
	}
	p := NewProcessorWithOptions(false, false)
	for i := 0; i < 300; i++ {
		r := mk()
		p.calculateRiskScore(r)
		if r.TopIssue != "DNS Anomalies" || r.TopIssueCount != 3 {
			t.Fatalf("run %d: TopIssue = %q/%d, want DNS Anomalies/3", i, r.TopIssue, r.TopIssueCount)
		}
	}
}

// Several independent BFD sessions go down. Their findings come from a map of
// sessions; the order must be the sorted session-key order every time.
func TestDeterminism_StabilityFindingOrder(t *testing.T) {
	const bfdUp, bfdDown = 0xC0, 0x40
	var frames [][]byte
	peers := []net.IP{}
	for i := 6; i >= 1; i-- { // deliberately not inserted in sorted order
		peers = append(peers, net.IPv4(10, 0, 0, byte(i)))
	}
	for _, peer := range peers {
		p4 := peer.To4()
		for i := 0; i < 5; i++ {
			frames = append(frames, testpcap.UDPFrame(testpcap.ClientMAC, testpcap.ServerMAC, testpcap.ClientIP, p4, 49152, 3784, testpcap.BFDControl(bfdUp)))
			frames = append(frames, testpcap.UDPFrame(testpcap.ServerMAC, testpcap.ClientMAC, p4, testpcap.ClientIP, 3784, 49152, testpcap.BFDControl(bfdUp)))
		}
		for i := 0; i < 4; i++ {
			frames = append(frames, testpcap.UDPFrame(testpcap.ClientMAC, testpcap.ServerMAC, testpcap.ClientIP, p4, 49152, 3784, testpcap.BFDControl(bfdUp)))
		}
		frames = append(frames, testpcap.UDPFrame(testpcap.ClientMAC, testpcap.ServerMAC, testpcap.ClientIP, p4, 49152, 3784, testpcap.BFDControl(bfdDown)))
	}
	var first []string
	for run := 0; run < detRuns; run++ {
		r := runGolden(t, frames)
		var got []string
		for _, f := range r.StabilityFindings {
			got = append(got, f.SourceIP+"->"+f.PeerIP)
		}
		if len(got) != 6 {
			t.Fatalf("expected 6 BFD findings, got %v", got)
		}
		if !sort.StringsAreSorted(got) {
			t.Fatalf("run %d: findings not in sorted session order: %v", run, got)
		}
		if run == 0 {
			first = got
		} else if fmt.Sprint(got) != fmt.Sprint(first) {
			t.Fatalf("run %d differs: %v vs %v", run, got, first)
		}
	}
}

// Many SYN-only flows time out at the end of the capture. The failed-handshake
// flows (and their events) are appended while iterating a map; the order must
// be fixed.
func TestDeterminism_HandshakeTimeoutOrder(t *testing.T) {
	var frames [][]byte
	for i := 0; i < 12; i++ {
		frames = append(frames, testpcap.TCPFrame(testpcap.ClientMAC, testpcap.ServerMAC, testpcap.ClientIP, testpcap.ServerIP,
			uint16(50001+i), 443, 1000, 0, testpcap.SYN, nil))
	}
	// Advance capture time well past the handshake timeout with unrelated traffic.
	for i := 0; i < 60; i++ {
		frames = append(frames, testpcap.UDPFrame(testpcap.ClientMAC, testpcap.ServerMAC, testpcap.ClientIP, testpcap.DNSServer, 40000, 9999, []byte("x")))
	}
	var first string
	for run := 0; run < detRuns; run++ {
		r := runGolden(t, frames)
		var keys []string
		for _, f := range r.TCPHandshakeFlows {
			if f.State == "Handshake Failed" {
				keys = append(keys, fmt.Sprintf("%s:%d->%s:%d", f.SrcIP, f.SrcPort, f.DstIP, f.DstPort))
			}
		}
		if len(keys) != 12 {
			t.Fatalf("expected 12 failed handshakes, got %d", len(keys))
		}
		if !sort.StringsAreSorted(keys) {
			t.Fatalf("run %d: failed handshakes not in sorted flow order: %v", run, keys)
		}
		ev := fmt.Sprint(len(r.Events.Events()))
		got := fmt.Sprint(keys) + ev
		if run == 0 {
			first = got
		} else if got != first {
			t.Fatalf("run %d differs", run)
		}
	}
}

// Whole-report equality on the synthetic fixtures (all timestamps are fixed).
func TestDeterminism_FixturesProduceIdenticalReports(t *testing.T) {
	for _, sc := range testpcap.Scenarios() {
		t.Run(sc.Name, func(t *testing.T) {
			var first []byte
			for run := 0; run < 15; run++ {
				r := runGolden(t, sc.Generate())
				b, err := json.Marshal(r)
				if err != nil {
					t.Fatal(err)
				}
				if run == 0 {
					first = b
				} else if string(b) != string(first) {
					t.Fatalf("run %d produced a different report for %s", run, sc.Name)
				}
			}
		})
	}
}
