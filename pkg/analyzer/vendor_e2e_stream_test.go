package analyzer

import (
	"testing"
	"time"

	"github.com/gocisse/sdwan-triage/internal/testpcap"
	"github.com/gocisse/sdwan-triage/pkg/models"
)

// Phase 4.51/4.53 — end-to-end checks of the live vendor stream detectors.
//
// Phase 4.53: ARUBA-PATH-001, ARUBA-BOND-001, VELOCLOUD-LAG-002 and VIPTELA-AAR-001
// were retired (Phase 4.52: their evidence is TCP sequence classification, which
// cannot be evaluated for the UDP tunnel traffic they target, and it did not
// establish the vendor-specific causes). These tests now prove, through the real
// pipeline, that the retired IDs are never emitted for the very scenarios that
// used to raise them, and that unrelated findings of the same detectors still are.
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

// vSegSized is a client→server data segment of n bytes at stream offset off.
func vSegSized(sp uint16, off uint32, n int) []byte {
	return testpcap.TCPFrame(testpcap.ClientMAC, testpcap.ServerMAC, testpcap.ClientIP, testpcap.ServerIP,
		vendorCliPort, sp, 1001+off, 2001, uint8(testpcap.PSH|testpcap.ACK), make([]byte, n))
}

// vSizedFlow builds a flow whose first `big` segments carry bigLen bytes and whose
// next `small` segments carry smallLen bytes (a throughput drop mid-stream).
func vSizedFlow(sp uint16, big, bigLen, small, smallLen int) [][]byte {
	pk := vHandshake(sp)
	off := uint32(0)
	for i := 0; i < big; i++ {
		pk = append(pk, vSegSized(sp, off, bigLen))
		off += uint32(bigLen)
	}
	for i := 0; i < small; i++ {
		pk = append(pk, vSegSized(sp, off, smallLen))
		off += uint32(smallLen)
	}
	return pk
}

var retiredVendorIDs = []string{"ARUBA-PATH-001", "ARUBA-BOND-001", "VELOCLOUD-LAG-002", "VIPTELA-AAR-001"}

func assertNoRetired(t *testing.T, name string, r *models.TriageReport) {
	t.Helper()
	ids := vendorIDs(r)
	for _, id := range retiredVendorIDs {
		if ids[id] != 0 {
			t.Errorf("%s: retired finding %s was emitted (issues: %v)", name, id, ids)
		}
	}
	for _, v := range r.VendorDPIIssues {
		if v.Severity == "Critical" && (v.IssueID == "ARUBA-BOND-001" || v.IssueID == "VELOCLOUD-LAG-002") {
			t.Errorf("%s: retired Critical finding reached the report", name)
		}
	}
}

// The scenarios below are exactly the ones that used to raise each retired finding
// (Phase 4.51 positives) plus their former negative controls.
func TestVendorE2E_RetiredFindingsAreNeverEmitted(t *testing.T) {
	slow := 250 * time.Millisecond
	fast := 100 * time.Millisecond
	cases := []struct {
		name     string
		pk       [][]byte
		interval time.Duration
	}{
		// Aruba EdgeConnect port 4980
		{"aruba reordering 10/40 (was BOND-001 Critical)", vFlow(ArubaEdgeConnectPort, 40, 10, 0), fast},
		{"aruba retransmissions 6/46 (was PATH-001)", vFlow(ArubaEdgeConnectPort, 40, 0, 6), fast},
		{"aruba in-order", vFlow(ArubaEdgeConnectPort, 40, 0, 0), fast},
		{"aruba alt port 4981 reordering", vFlow(ArubaEdgeConnectAltPort, 40, 10, 0), fast},
		// VeloCloud management TCP port 8443 and 8080
		{"velocloud reordering 6/30 (was LAG-002)", vFlow(VeloCloudHTTPSPort, 30, 6, 0), fast},
		{"velocloud 8080 reordering", vFlow(VeloCloudHTTPPort, 30, 6, 0), fast},
		{"velocloud reordering + resends", vFlow(VeloCloudHTTPSPort, 30, 6, 8), fast},
		{"velocloud resends only", vFlow(VeloCloudHTTPSPort, 30, 0, 8), fast},
		// Viptela ports: control/data 12346 and NETCONF 830
		{"viptela retransmissions 6/66 over >10 s (was AAR-001 High)", vFlow(ViptelaOMPPort, 60, 0, 6), slow},
		{"viptela heavy retransmissions over >10 s (was AAR-001 Critical)", vFlow(ViptelaOMPPort, 60, 0, 12), slow},
		{"viptela reordering over >10 s", vFlow(ViptelaOMPPort, 60, 12, 0), slow},
		{"viptela NETCONF 830 retransmissions", vFlow(ViptelaNetconfPort, 60, 0, 6), slow},
	}
	for _, c := range cases {
		assertNoRetired(t, c.name, runVendor(t, c.pk, c.interval))
	}
}

// Unrelated findings of the same detectors must keep working through the real
// pipeline. (Plumbing controls only: they show the detectors still run; this
// phase takes no position on the validity of those other findings.)
func TestVendorE2E_UnrelatedFindingsStillEmitted(t *testing.T) {
	// ARUBA-BOND-002: second-half throughput < 20% of the first half on port 4980.
	r := runVendor(t, vSizedFlow(ArubaEdgeConnectPort, 10, 100, 10, 10), 100*time.Millisecond)
	if vendorIDs(r)["ARUBA-BOND-002"] != 1 {
		t.Errorf("ARUBA-BOND-002 should still be emitted, got %v", vendorIDs(r))
	}
	assertNoRetired(t, "aruba throughput drop", r)

	// VELOCLOUD-LAG-001: second-half throughput < 45% of the first half on port 8443.
	r = runVendor(t, vSizedFlow(VeloCloudHTTPSPort, 15, 100, 15, 30), 100*time.Millisecond)
	if vendorIDs(r)["VELOCLOUD-LAG-001"] != 1 {
		t.Errorf("VELOCLOUD-LAG-001 should still be emitted, got %v", vendorIDs(r))
	}
	assertNoRetired(t, "velocloud throughput drop", r)

	// VIPTELA-AAR-002 (inter-packet interval heuristic): 250 ms spacing over >5 s on port 12346.
	r = runVendor(t, vFlow(ViptelaOMPPort, 60, 0, 0), 250*time.Millisecond)
	if vendorIDs(r)["VIPTELA-AAR-002"] != 1 {
		t.Errorf("VIPTELA-AAR-002 should still be emitted, got %v", vendorIDs(r))
	}
	assertNoRetired(t, "viptela interval", r)
}

// Consumers: the web integration counts Critical vendor issues and records one
// customer-intelligence entry per VendorDPIIssue (pkg/web/handlers/analyzer.go).
// Both iterate report.VendorDPIIssues, so a retired ID that is absent from that
// slice cannot increment either counter. This asserts the property on the report
// the production pipeline produces for the former Critical scenarios.
func TestVendorE2E_RetiredCriticalScenariosAddNoVendorIssues(t *testing.T) {
	for name, r := range map[string]*models.TriageReport{
		"aruba":     runVendor(t, vFlow(ArubaEdgeConnectPort, 40, 10, 0), 100*time.Millisecond),
		"viptela":   runVendor(t, vFlow(ViptelaOMPPort, 60, 0, 12), 250*time.Millisecond),
		"velocloud": runVendor(t, vFlow(VeloCloudHTTPSPort, 30, 6, 0), 100*time.Millisecond),
	} {
		for _, v := range r.VendorDPIIssues {
			if v.Severity == "Critical" {
				t.Errorf("%s: unexpected Critical vendor issue %s", name, v.IssueID)
			}
		}
	}
}
