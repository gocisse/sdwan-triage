package analyzer

import (
	"strings"
	"testing"
	"time"

	"github.com/gocisse/sdwan-triage/internal/testpcap"
	"github.com/gocisse/sdwan-triage/pkg/models"
)

// Phase 4.51 — end-to-end checks of the live vendor stream detectors.
//
// Packets are built with internal/testpcap, written to a temp pcap and run through
// the real Processor (OpenCapture → detector registry → StreamReassembler →
// finalizeReport → Aruba/Viptela/VeloCloud detectors), then the resulting
// report.VendorDPIIssues are asserted. Nothing constructs StreamData or detector
// output directly, and no corpus path or environment variable is used.
//
// Stream classification is limited to the first 10 KB stored per direction, so
// the scenarios use 100-byte segments (≈100 per direction at most).

const vendorCliPort = 52000

// vSeg is the i-th 100-byte client→server data segment to server port sp.
func vSeg(sp uint16, i int) []byte {
	return testpcap.TCPFrame(testpcap.ClientMAC, testpcap.ServerMAC, testpcap.ClientIP, testpcap.ServerIP,
		vendorCliPort, sp, 1001+uint32(100*i), 2001, uint8(testpcap.PSH|testpcap.ACK), make([]byte, 100))
}

func vHandshake(sp uint16) [][]byte {
	return [][]byte{
		testpcap.TCPFrame(testpcap.ClientMAC, testpcap.ServerMAC, testpcap.ClientIP, testpcap.ServerIP, vendorCliPort, sp, 1000, 0, testpcap.SYN, nil),
		testpcap.TCPFrame(testpcap.ServerMAC, testpcap.ClientMAC, testpcap.ServerIP, testpcap.ClientIP, sp, vendorCliPort, 2000, 1001, testpcap.SYN|testpcap.ACK, nil),
		testpcap.TCPFrame(testpcap.ClientMAC, testpcap.ServerMAC, testpcap.ClientIP, testpcap.ServerIP, vendorCliPort, sp, 1001, 2001, testpcap.ACK, nil),
	}
}

// vFlow builds n in-order segments, then swaps the first `swaps` adjacent pairs
// (genuine reordering, no repeated data), then appends `resends` exact repeats of
// the earliest segments (retransmissions).
func vFlow(sp uint16, n, swaps, resends int) [][]byte {
	pk := vHandshake(sp)
	order := make([]int, n)
	for i := range order {
		order[i] = i
	}
	for k := 0; k < swaps; k++ {
		order[2*k], order[2*k+1] = order[2*k+1], order[2*k]
	}
	for _, i := range order {
		pk = append(pk, vSeg(sp, i))
	}
	for i := 0; i < resends; i++ {
		pk = append(pk, vSeg(sp, i))
	}
	return pk
}

func vendorIDs(r *models.TriageReport) map[string]int {
	m := map[string]int{}
	for _, v := range r.VendorDPIIssues {
		m[v.IssueID]++
	}
	return m
}

func runVendor(t *testing.T, pk [][]byte, interval time.Duration) *models.TriageReport {
	t.Helper()
	return runGoldenInterval(t, pk, interval)
}

// ── Aruba EdgeConnect (tunnel bonding out-of-order, path conditioning) ──────

func TestVendorE2E_ArubaBondingOutOfOrder(t *testing.T) {
	sp := ArubaEdgeConnectPort
	// Positive: 40 segments, 10 genuine adjacent swaps → 10 out-of-order of 40 (25% > 5%; > 15% = Critical).
	r := runVendor(t, vFlow(sp, 40, 10, 0), 100*time.Millisecond)
	ids := vendorIDs(r)
	if ids["ARUBA-BOND-001"] != 1 {
		t.Fatalf("reordering on the bonded tunnel must raise ARUBA-BOND-001, got %v", ids)
	}
	for _, v := range r.VendorDPIIssues {
		if v.IssueID == "ARUBA-BOND-001" {
			if v.Severity != string(SeverityCritical) {
				t.Errorf("severity = %q, want Critical at 25%%", v.Severity)
			}
			if want := "25% out-of-order packet rate (10/40 segments)"; !strings.Contains(v.Description, want) {
				t.Errorf("evidence = %q, want it to contain %q", v.Description, want)
			}
		}
	}
	if ids["ARUBA-PATH-001"] != 0 {
		t.Errorf("reordering must not look like retransmissions (PATH-001): %v", ids)
	}

	// Negative control 1: in-order traffic.
	if ids := vendorIDs(runVendor(t, vFlow(sp, 40, 0, 0), 100*time.Millisecond)); ids["ARUBA-BOND-001"] != 0 || ids["ARUBA-PATH-001"] != 0 {
		t.Errorf("in-order: %v", ids)
	}
	// Negative control 2: retransmissions only — not out-of-order, but they are the
	// PATH-001 (retransmit rate) evidence: 6 of 46 segments = 13%.
	ids = vendorIDs(runVendor(t, vFlow(sp, 40, 0, 6), 100*time.Millisecond))
	if ids["ARUBA-BOND-001"] != 0 {
		t.Errorf("retransmissions must not raise the bonding out-of-order finding: %v", ids)
	}
	if ids["ARUBA-PATH-001"] != 1 {
		t.Errorf("retransmission rate above 5%% should raise ARUBA-PATH-001: %v", ids)
	}
	// Negative control 3: below the segment minimum (ArubaMinSegmentsForAnalysis = 5).
	if ids := vendorIDs(runVendor(t, vFlow(sp, 4, 2, 0), 100*time.Millisecond)); ids["ARUBA-BOND-001"] != 0 {
		t.Errorf("4 segments are below the analysis minimum: %v", ids)
	}
}

// ── VeloCloud LAG-002 (out-of-order without proportional retransmits) ───────

func TestVendorE2E_VeloCloudLAGHashImbalance(t *testing.T) {
	sp := VeloCloudHTTPSPort
	// Positive: 30 segments, 6 swaps → 6 out-of-order (20% > 5%), 0 retransmissions.
	r := runVendor(t, vFlow(sp, 30, 6, 0), 100*time.Millisecond)
	ids := vendorIDs(r)
	if ids["VELOCLOUD-LAG-002"] != 1 {
		t.Fatalf("reordering without retransmissions must raise VELOCLOUD-LAG-002, got %v", ids)
	}
	for _, v := range r.VendorDPIIssues {
		if v.IssueID == "VELOCLOUD-LAG-002" && !strings.Contains(v.Description, "20% out-of-order packet rate (6/30 segments) with low retransmit count (0)") {
			t.Errorf("evidence = %q", v.Description)
		}
	}
	// Negative 1: in-order.
	if ids := vendorIDs(runVendor(t, vFlow(sp, 30, 0, 0), 100*time.Millisecond)); ids["VELOCLOUD-LAG-002"] != 0 {
		t.Errorf("in-order: %v", ids)
	}
	// Negative 2: retransmissions only (the old classifier labelled resends/reordering
	// interchangeably): no reordering evidence, so no LAG finding.
	if ids := vendorIDs(runVendor(t, vFlow(sp, 30, 0, 8), 100*time.Millisecond)); ids["VELOCLOUD-LAG-002"] != 0 {
		t.Errorf("retransmissions alone: %v", ids)
	}
	// Negative 3: reordering accompanied by at least as many retransmissions (6 swaps, 8 resends):
	// the detector's own rule treats that as loss, not reordering.
	if ids := vendorIDs(runVendor(t, vFlow(sp, 30, 6, 8), 100*time.Millisecond)); ids["VELOCLOUD-LAG-002"] != 0 {
		t.Errorf("reordering with proportional retransmits: %v", ids)
	}
	// Negative 4: below the 10-segment minimum.
	if ids := vendorIDs(runVendor(t, vFlow(sp, 8, 3, 0), 100*time.Millisecond)); ids["VELOCLOUD-LAG-002"] != 0 {
		t.Errorf("8 segments are below the analysis minimum: %v", ids)
	}
}

// ── Cisco Viptela AAR (retransmission ratio over a >10 s stream) ────────────

func TestVendorE2E_ViptelaAARRetransmissionRatio(t *testing.T) {
	sp := ViptelaOMPPort
	slow := 250 * time.Millisecond // 70 packets → > 10 s between the first and last data segment

	// Positive: 60 segments + 6 resends = 6/66 (9.1%) retransmissions over > 10 s → High.
	r := runVendor(t, vFlow(sp, 60, 0, 6), slow)
	ids := vendorIDs(r)
	if ids["VIPTELA-AAR-001"] != 1 {
		t.Fatalf("retransmission ratio above 5%% over >10 s must raise VIPTELA-AAR-001, got %v", ids)
	}
	for _, v := range r.VendorDPIIssues {
		if v.IssueID == "VIPTELA-AAR-001" {
			if v.Severity != string(SeverityHigh) {
				t.Errorf("severity = %q, want High at 9.1%%", v.Severity)
			}
			if !strings.Contains(v.Description, "9.1% of segments") || !strings.Contains(v.Description, "retransmissions alone do not confirm packet loss") {
				t.Errorf("evidence = %q", v.Description)
			}
		}
	}
	// Negative 1: in-order.
	if ids := vendorIDs(runVendor(t, vFlow(sp, 60, 0, 0), slow)); ids["VIPTELA-AAR-001"] != 0 {
		t.Errorf("in-order: %v", ids)
	}
	// Negative 2 (the point of Phase 4.50): genuine reordering is NOT retransmissions.
	// The old classifier labelled every reordered segment a retransmission and
	// would have raised AAR-001 here (12 of 60).
	if ids := vendorIDs(runVendor(t, vFlow(sp, 60, 12, 0), slow)); ids["VIPTELA-AAR-001"] != 0 {
		t.Errorf("reordering raised the retransmission-ratio finding: %v", ids)
	}
	// Negative 3: same retransmissions but the stream lasts under 10 s.
	if ids := vendorIDs(runVendor(t, vFlow(sp, 60, 0, 6), 100*time.Millisecond)); ids["VIPTELA-AAR-001"] != 0 {
		t.Errorf("stream shorter than 10 s: %v", ids)
	}
	// Negative 4: ratio at or below the threshold (2 of 62 = 3.2%).
	if ids := vendorIDs(runVendor(t, vFlow(sp, 60, 0, 2), slow)); ids["VIPTELA-AAR-001"] != 0 {
		t.Errorf("3.2%% is below the 5%% threshold: %v", ids)
	}
}
