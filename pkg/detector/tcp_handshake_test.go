package detector

import (
	"testing"
	"time"

	"github.com/gocisse/sdwan-triage/pkg/models"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func TestTCPHandshakeTracker_NewTracker(t *testing.T) {
	tracker := NewTCPHandshakeTracker()
	if tracker == nil {
		t.Fatal("NewTCPHandshakeTracker returned nil")
	}
	if tracker.flows == nil {
		t.Error("flows map not initialized")
	}
}

func TestTCPHandshakeTracker_SYNTracking(t *testing.T) {
	tracker := NewTCPHandshakeTracker()
	state := models.NewAnalysisState()
	report := &models.TriageReport{}

	// Create a SYN packet
	packet := createTCPPacket("192.168.1.100", "192.168.1.200", 12345, 80, true, false, false)
	tracker.TrackHandshake(packet, state, report)

	// Check that flow was tracked
	flowKey := "192.168.1.100:12345->192.168.1.200:80"
	if _, exists := tracker.flows[flowKey]; !exists {
		t.Error("SYN flow not tracked")
	}

	flow := tracker.flows[flowKey]
	if flow.State != StateSynSent {
		t.Errorf("Expected state StateSynSent, got %v", flow.State)
	}
}

func TestTCPHandshakeTracker_CompleteHandshake(t *testing.T) {
	tracker := NewTCPHandshakeTracker()
	state := models.NewAnalysisState()
	report := &models.TriageReport{}

	// Step 1: SYN
	synPacket := createTCPPacket("192.168.1.100", "192.168.1.200", 12345, 80, true, false, false)
	tracker.TrackHandshake(synPacket, state, report)

	// Step 2: SYN-ACK (reverse direction)
	time.Sleep(10 * time.Millisecond)
	synAckPacket := createTCPPacket("192.168.1.200", "192.168.1.100", 80, 12345, true, true, false)
	tracker.TrackHandshake(synAckPacket, state, report)

	// Check state is SYN-ACK received
	flowKey := "192.168.1.100:12345->192.168.1.200:80"
	flow := tracker.flows[flowKey]
	if flow.State != StateSynAckReceived {
		t.Errorf("Expected state StateSynAckReceived, got %v", flow.State)
	}

	// Step 3: ACK
	time.Sleep(10 * time.Millisecond)
	ackPacket := createTCPPacket("192.168.1.100", "192.168.1.200", 12345, 80, false, true, false)
	tracker.TrackHandshake(ackPacket, state, report)

	// Check state is Established
	if flow.State != StateEstablished {
		t.Errorf("Expected state StateEstablished, got %v", flow.State)
	}

	// Check that handshake was added to report
	if len(report.TCPHandshakeFlows) != 1 {
		t.Errorf("Expected 1 handshake in report, got %d", len(report.TCPHandshakeFlows))
	}

	handshake := report.TCPHandshakeFlows[0]
	if handshake.State != "Handshake Complete" {
		t.Errorf("Expected 'Handshake Complete', got %s", handshake.State)
	}
	if handshake.SrcIP != "192.168.1.100" {
		t.Errorf("Expected SrcIP 192.168.1.100, got %s", handshake.SrcIP)
	}
	if handshake.DstIP != "192.168.1.200" {
		t.Errorf("Expected DstIP 192.168.1.200, got %s", handshake.DstIP)
	}
}

func TestTCPHandshakeTracker_Timeout(t *testing.T) {
	tracker := NewTCPHandshakeTracker()
	state := models.NewAnalysisState()
	report := &models.TriageReport{}

	// Create a SYN packet
	synPacket := createTCPPacket("192.168.1.100", "192.168.1.200", 12345, 80, true, false, false)
	tracker.TrackHandshake(synPacket, state, report)

	// Check for timeout after 1 second
	time.Sleep(10 * time.Millisecond)
	currentTime := time.Now().Add(2 * time.Second)
	tracker.CheckTimeouts(currentTime, 1*time.Second, report)

	// Check that flow was marked as failed
	if len(report.TCPHandshakeFlows) != 1 {
		t.Errorf("Expected 1 handshake in report, got %d", len(report.TCPHandshakeFlows))
	}

	handshake := report.TCPHandshakeFlows[0]
	if handshake.State != "Handshake Failed" {
		t.Errorf("Expected 'Handshake Failed', got %s", handshake.State)
	}
	if handshake.FailureReason == "" {
		t.Error("Expected failure reason to be set")
	}
}

func TestGetHandshakeStatistics(t *testing.T) {
	flows := []models.TCPHandshakeFlow{
		{State: "Handshake Complete", TotalHandshakeMs: 10.0},
		{State: "Handshake Complete", TotalHandshakeMs: 20.0},
		{State: "Handshake Failed", FailureReason: "timeout"},
		{State: "SYN"},
	}

	stats := GetHandshakeStatistics(flows)

	if stats.Total != 4 {
		t.Errorf("Expected total 4, got %d", stats.Total)
	}
	if stats.Successful != 2 {
		t.Errorf("Expected successful 2, got %d", stats.Successful)
	}
	if stats.Failed != 1 {
		t.Errorf("Expected failed 1, got %d", stats.Failed)
	}
	if stats.Incomplete != 1 {
		t.Errorf("Expected incomplete 1, got %d", stats.Incomplete)
	}
	if stats.SuccessRate != 50.0 {
		t.Errorf("Expected success rate 50%%, got %.1f%%", stats.SuccessRate)
	}
	if stats.AverageHandshakeTime != 15.0 {
		t.Errorf("Expected average time 15.0ms, got %.1fms", stats.AverageHandshakeTime)
	}
}

func TestGetFailurePattern(t *testing.T) {
	tests := []struct {
		name     string
		flows    []models.TCPHandshakeFlow
		expected string
	}{
		{
			name: "All successful",
			flows: []models.TCPHandshakeFlow{
				{State: "Handshake Complete"},
				{State: "Handshake Complete"},
			},
			expected: "✅ Pattern: All handshakes successful",
		},
		{
			name: "High SYN-ACK timeout rate",
			flows: []models.TCPHandshakeFlow{
				{State: "Handshake Failed", FailureReason: "SYN-ACK timeout (no server response)"},
				{State: "Handshake Failed", FailureReason: "SYN-ACK timeout (no server response)"},
				{State: "Handshake Complete"},
			},
			expected: "⚠️  Pattern: High SYN-ACK timeout rate",
		},
		{
			name: "High failure rate",
			flows: []models.TCPHandshakeFlow{
				{State: "Handshake Failed"},
				{State: "Handshake Failed"},
				{State: "Handshake Failed"},
				{State: "Handshake Complete"},
			},
			expected: "🔴 Pattern: High failure rate",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pattern := GetFailurePattern(tt.flows)
			if !containsSubstring(pattern, tt.expected) {
				t.Errorf("Expected pattern to contain %q, got %q", tt.expected, pattern)
			}
		})
	}
}

func TestGetTroubleshootingSuggestion(t *testing.T) {
	tests := []struct {
		reason     string
		shouldHave string
	}{
		{
			reason:     "SYN-ACK timeout (no server response)",
			shouldHave: "Check if server is reachable",
		},
		{
			reason:     "ACK timeout (client did not complete handshake)",
			shouldHave: "Check client-side network connectivity",
		},
		{
			reason:     "Unknown reason",
			shouldHave: "Check network connectivity",
		},
	}

	for _, tt := range tests {
		t.Run(tt.reason, func(t *testing.T) {
			suggestion := GetTroubleshootingSuggestion(tt.reason)
			if !containsSubstring(suggestion, tt.shouldHave) {
				t.Errorf("Expected suggestion to contain %q, got %q", tt.shouldHave, suggestion)
			}
		})
	}
}

// Helper functions

func createTCPPacket(srcIP, dstIP string, srcPort, dstPort uint16, syn, ack, rst bool) gopacket.Packet {
	// Create Ethernet layer
	eth := &layers.Ethernet{
		SrcMAC:       []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
		DstMAC:       []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x02},
		EthernetType: layers.EthernetTypeIPv4,
	}

	// Create IP layer
	ip := &layers.IPv4{
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    parseIP(srcIP),
		DstIP:    parseIP(dstIP),
	}

	// Create TCP layer
	tcp := &layers.TCP{
		SrcPort: layers.TCPPort(srcPort),
		DstPort: layers.TCPPort(dstPort),
		SYN:     syn,
		ACK:     ack,
		RST:     rst,
		Seq:     1000,
		Window:  65535,
	}
	tcp.SetNetworkLayerForChecksum(ip)

	// Serialize layers
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}

	err := gopacket.SerializeLayers(buf, opts, eth, ip, tcp)
	if err != nil {
		panic(err)
	}

	// Create packet
	packet := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
	return packet
}

func parseIP(ipStr string) []byte {
	// Simple IPv4 parser for test purposes
	var parts [4]byte
	var partIdx, val int

	for i := 0; i < len(ipStr); i++ {
		if ipStr[i] == '.' {
			parts[partIdx] = byte(val)
			partIdx++
			val = 0
		} else {
			val = val*10 + int(ipStr[i]-'0')
		}
	}
	parts[partIdx] = byte(val)

	return parts[:]
}

func containsSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// Benchmark tests

func BenchmarkTrackHandshake(b *testing.B) {
	tracker := NewTCPHandshakeTracker()
	state := models.NewAnalysisState()
	report := &models.TriageReport{}
	packet := createTCPPacket("192.168.1.100", "192.168.1.200", 12345, 80, true, false, false)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tracker.TrackHandshake(packet, state, report)
	}
}

func BenchmarkGetHandshakeStatistics(b *testing.B) {
	flows := make([]models.TCPHandshakeFlow, 1000)
	for i := 0; i < 1000; i++ {
		flows[i] = models.TCPHandshakeFlow{
			State:            "Handshake Complete",
			TotalHandshakeMs: float64(i % 100),
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = GetHandshakeStatistics(flows)
	}
}
