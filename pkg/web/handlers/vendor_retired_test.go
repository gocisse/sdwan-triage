package handlers

import (
	"path/filepath"
	"testing"

	"github.com/gocisse/sdwan-triage/internal/testpcap"
	"github.com/gocisse/sdwan-triage/pkg/analyzer"
	"github.com/gocisse/sdwan-triage/pkg/models"
)

// Phase 4.53: ARUBA-BOND-001 (Critical for >15% out-of-order) was retired. The
// web integration counts Critical vendor issues through countCriticalFindings, so
// the former trigger scenario, run through the real analyzer pipeline, must add
// nothing to that count.
func TestRetiredVendorFinding_DoesNotReachCriticalCount(t *testing.T) {
	const sp, cp = uint16(4980), uint16(52000)
	frame := func(seq uint32) []byte {
		return testpcap.TCPFrame(testpcap.ClientMAC, testpcap.ServerMAC, testpcap.ClientIP, testpcap.ServerIP,
			cp, sp, 1001+seq, 2001, uint8(testpcap.PSH|testpcap.ACK), make([]byte, 100))
	}
	pk := [][]byte{
		testpcap.TCPFrame(testpcap.ClientMAC, testpcap.ServerMAC, testpcap.ClientIP, testpcap.ServerIP, cp, sp, 1000, 0, testpcap.SYN, nil),
		testpcap.TCPFrame(testpcap.ServerMAC, testpcap.ClientMAC, testpcap.ServerIP, testpcap.ClientIP, sp, cp, 2000, 1001, testpcap.SYN|testpcap.ACK, nil),
		testpcap.TCPFrame(testpcap.ClientMAC, testpcap.ServerMAC, testpcap.ClientIP, testpcap.ServerIP, cp, sp, 1001, 2001, testpcap.ACK, nil),
	}
	for i := 0; i < 40; i += 2 { // 20 adjacent swaps: 50% out-of-order, previously Critical
		pk = append(pk, frame(uint32(100*(i+1))), frame(uint32(100*i)))
	}
	path := filepath.Join(t.TempDir(), "aruba.pcap")
	if err := testpcap.WriteFile(path, pk); err != nil {
		t.Fatal(err)
	}
	handle, err := analyzer.OpenCapture(path)
	if err != nil {
		t.Fatal(err)
	}
	defer handle.Close()
	report := &models.TriageReport{ApplicationBreakdown: make(map[string]models.AppCategory)}
	if err := analyzer.NewProcessorWithOptions(false, false).Process(handle.Reader, models.NewAnalysisState(), report, nil); err != nil {
		t.Fatal(err)
	}
	for _, v := range report.VendorDPIIssues {
		if v.IssueID == "ARUBA-BOND-001" || v.IssueID == "ARUBA-PATH-001" {
			t.Errorf("retired finding emitted: %+v", v)
		}
	}
	if n := countCriticalFindings(report); n != 0 {
		t.Errorf("countCriticalFindings = %d, want 0 (retired Critical finding must not be counted)", n)
	}
}
