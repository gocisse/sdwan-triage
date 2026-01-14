package detector

import (
	"testing"

	"github.com/gocisse/sdwan-triage/pkg/models"
)

func TestDetectBGPHijack_ShortASPath(t *testing.T) {
	analyzer := NewBGPAnalyzer()
	report := &models.TriageReport{}
	ipInfo := &PacketIPInfo{SrcIP: "192.168.1.1", DstIP: "10.0.0.1"}

	// Heuristic 1: Short AS path (length 1)
	asPath := []uint32{65001}
	analyzer.detectBGPHijack(asPath, ipInfo, 1234567890.0, report)

	// Should have at least 1 indicator for short AS path
	if len(report.BGPHijackIndicators) < 1 {
		t.Errorf("Expected at least 1 BGP indicator for short AS path, got %d", len(report.BGPHijackIndicators))
	}

	// Check that "Suspicious Short AS Path" is one of the indicators
	found := false
	for _, indicator := range report.BGPHijackIndicators {
		if indicator.Reason == "Suspicious Short AS Path" {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected 'Suspicious Short AS Path' indicator")
	}
}

func TestDetectBGPHijack_ASPathPrepending(t *testing.T) {
	analyzer := NewBGPAnalyzer()
	report := &models.TriageReport{}
	ipInfo := &PacketIPInfo{SrcIP: "192.168.1.1", DstIP: "10.0.0.1"}

	// Heuristic 2: AS path prepending (same AS appears > 3 times)
	asPath := []uint32{65001, 65001, 65001, 65001, 65002, 65003}
	analyzer.detectBGPHijack(asPath, ipInfo, 1234567890.0, report)

	found := false
	for _, indicator := range report.BGPHijackIndicators {
		if indicator.Reason == "AS Path Prepending Detected" {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected 'AS Path Prepending Detected' indicator")
	}
}

func TestDetectBGPHijack_PrivateAS(t *testing.T) {
	analyzer := NewBGPAnalyzer()
	report := &models.TriageReport{}
	ipInfo := &PacketIPInfo{SrcIP: "192.168.1.1", DstIP: "10.0.0.1"}

	// Heuristic 3: Private AS in public path
	asPath := []uint32{65001, 64512, 65003} // 64512 is private AS
	analyzer.detectBGPHijack(asPath, ipInfo, 1234567890.0, report)

	found := false
	for _, indicator := range report.BGPHijackIndicators {
		if indicator.Reason == "Private AS in Public Path" {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected 'Private AS in Public Path' indicator")
	}
}

func TestDetectBGPHijack_ReservedAS(t *testing.T) {
	analyzer := NewBGPAnalyzer()
	report := &models.TriageReport{}
	ipInfo := &PacketIPInfo{SrcIP: "192.168.1.1", DstIP: "10.0.0.1"}

	// Heuristic 4: Reserved AS number (AS 0)
	asPath := []uint32{0, 65001, 65002}
	analyzer.detectBGPHijack(asPath, ipInfo, 1234567890.0, report)

	found := false
	for _, indicator := range report.BGPHijackIndicators {
		if indicator.Reason == "Reserved AS Number" {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected 'Reserved AS Number' indicator")
	}
}

func TestDetectBGPHijack_ASPathLoop(t *testing.T) {
	analyzer := NewBGPAnalyzer()
	report := &models.TriageReport{}
	ipInfo := &PacketIPInfo{SrcIP: "192.168.1.1", DstIP: "10.0.0.1"}

	// Heuristic 5: AS path loop (same AS appears non-consecutively)
	asPath := []uint32{65001, 65002, 65001} // 65001 appears at positions 1 and 3
	analyzer.detectBGPHijack(asPath, ipInfo, 1234567890.0, report)

	found := false
	for _, indicator := range report.BGPHijackIndicators {
		if indicator.Reason == "AS Path Loop Detected" {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected 'AS Path Loop Detected' indicator")
	}
}

func TestDetectBGPHijack_LongASPath(t *testing.T) {
	analyzer := NewBGPAnalyzer()
	report := &models.TriageReport{}
	ipInfo := &PacketIPInfo{SrcIP: "192.168.1.1", DstIP: "10.0.0.1"}

	// Heuristic 6: Unusually long AS path (> 15)
	asPath := make([]uint32, 20)
	for i := range asPath {
		asPath[i] = uint32(65000 + i)
	}
	analyzer.detectBGPHijack(asPath, ipInfo, 1234567890.0, report)

	found := false
	for _, indicator := range report.BGPHijackIndicators {
		if indicator.Reason == "Unusually Long AS Path" {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected 'Unusually Long AS Path' indicator")
	}
}

func TestDetectBGPHijack_EmptyPath(t *testing.T) {
	analyzer := NewBGPAnalyzer()
	report := &models.TriageReport{}
	ipInfo := &PacketIPInfo{SrcIP: "192.168.1.1", DstIP: "10.0.0.1"}

	// Empty AS path should not generate any indicators
	asPath := []uint32{}
	analyzer.detectBGPHijack(asPath, ipInfo, 1234567890.0, report)

	if len(report.BGPHijackIndicators) != 0 {
		t.Errorf("Expected 0 BGP indicators for empty AS path, got %d", len(report.BGPHijackIndicators))
	}
}

func TestDetectBGPHijack_NormalPath(t *testing.T) {
	analyzer := NewBGPAnalyzer()
	report := &models.TriageReport{}
	ipInfo := &PacketIPInfo{SrcIP: "192.168.1.1", DstIP: "10.0.0.1"}

	// Normal AS path with public AS numbers (not in private range 64512-65534)
	// No loops, reasonable length - should not generate any indicators
	asPath := []uint32{15169, 3356, 7018, 1299, 2914} // Real public ASNs (Google, Level3, AT&T, Telia, NTT)
	analyzer.detectBGPHijack(asPath, ipInfo, 1234567890.0, report)

	// Log what indicators were generated for debugging
	for _, ind := range report.BGPHijackIndicators {
		t.Logf("Unexpected indicator: %s", ind.Reason)
	}

	if len(report.BGPHijackIndicators) != 0 {
		t.Errorf("Expected 0 BGP indicators for normal AS path, got %d", len(report.BGPHijackIndicators))
	}
}

func TestBGPAnalyzer_NewBGPAnalyzer(t *testing.T) {
	analyzer := NewBGPAnalyzer()
	if analyzer == nil {
		t.Error("NewBGPAnalyzer returned nil")
	}
	if analyzer.bgpSessions == nil {
		t.Error("bgpSessions map not initialized")
	}
}

func TestParseBGPMessage_ValidMarker(t *testing.T) {
	analyzer := NewBGPAnalyzer()

	// Valid BGP message with correct marker (16 bytes of 0xFF)
	payload := make([]byte, 29)
	for i := 0; i < 16; i++ {
		payload[i] = 0xFF
	}
	// Length = 29 (big-endian)
	payload[16] = 0x00
	payload[17] = 0x1D
	// Type = KEEPALIVE (4)
	payload[18] = 0x04

	msg := analyzer.parseBGPMessage(payload)
	if msg == nil {
		t.Error("Expected valid BGP message, got nil")
	}
	if msg != nil && msg.Type != BGPKeepAlive {
		t.Errorf("Expected message type %d, got %d", BGPKeepAlive, msg.Type)
	}
}

func TestParseBGPMessage_InvalidMarker(t *testing.T) {
	analyzer := NewBGPAnalyzer()

	// Invalid BGP message with incorrect marker
	payload := make([]byte, 29)
	for i := 0; i < 16; i++ {
		payload[i] = 0x00 // Should be 0xFF
	}
	payload[16] = 0x00
	payload[17] = 0x1D
	payload[18] = 0x04

	msg := analyzer.parseBGPMessage(payload)
	if msg != nil {
		t.Error("Expected nil for invalid marker, got message")
	}
}

func TestParseBGPMessage_TooShort(t *testing.T) {
	analyzer := NewBGPAnalyzer()

	// Too short payload
	payload := make([]byte, 10)
	msg := analyzer.parseBGPMessage(payload)
	if msg != nil {
		t.Error("Expected nil for short payload, got message")
	}
}
