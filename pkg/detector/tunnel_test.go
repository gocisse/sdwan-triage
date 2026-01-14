package detector

import (
	"testing"
	"time"
)

func TestIsOpenVPNPacket_ValidControlPacket(t *testing.T) {
	analyzer := NewTunnelAnalyzer()

	// OpenVPN Control Hard Reset Client V2 (opcode 7, key_id 0)
	// Opcode is in high 5 bits: 7 << 3 = 0x38
	// Need valid session ID (not all zeros) and proper length
	payload := make([]byte, 50)
	payload[0] = 0x38 // opcode 7, key_id 0
	// Set non-zero session ID (bytes 1-8)
	payload[1] = 0x12
	payload[2] = 0x34
	payload[3] = 0x56
	payload[4] = 0x78
	payload[5] = 0x9a
	payload[6] = 0xbc
	payload[7] = 0xde
	payload[8] = 0xf0

	if !analyzer.isOpenVPNPacket(payload) {
		t.Error("Expected valid OpenVPN control packet to be detected")
	}
}

func TestIsOpenVPNPacket_ValidDataPacket(t *testing.T) {
	analyzer := NewTunnelAnalyzer()

	// OpenVPN Data V2 (opcode 9, key_id 0)
	// Opcode is in high 5 bits: 9 << 3 = 0x48
	// Data packets need minimum 28 bytes
	payload := make([]byte, 100)
	payload[0] = 0x48 // opcode 9, key_id 0

	if !analyzer.isOpenVPNPacket(payload) {
		t.Error("Expected valid OpenVPN data packet to be detected")
	}
}

func TestIsOpenVPNPacket_InvalidPacket(t *testing.T) {
	analyzer := NewTunnelAnalyzer()

	// Random data that doesn't match OpenVPN structure
	payload := []byte{0x00, 0x01, 0x02, 0x03}

	if analyzer.isOpenVPNPacket(payload) {
		t.Error("Expected invalid packet to not be detected as OpenVPN")
	}
}

func TestIsOpenVPNPacket_TooShort(t *testing.T) {
	analyzer := NewTunnelAnalyzer()

	// Too short payload
	payload := []byte{0x38}

	if analyzer.isOpenVPNPacket(payload) {
		t.Error("Expected short packet to not be detected as OpenVPN")
	}
}

func TestIsOpenVPNPacket_AllZeroSessionID(t *testing.T) {
	analyzer := NewTunnelAnalyzer()

	// OpenVPN packet with all-zero session ID should be rejected
	payload := make([]byte, 50)
	payload[0] = 0x38 // opcode 7, key_id 0
	// Session ID bytes 1-8 are all zeros (default)

	if analyzer.isOpenVPNPacket(payload) {
		t.Error("Expected packet with all-zero session ID to be rejected")
	}
}

func TestIsOpenVPNPacketStrict_ValidHandshake(t *testing.T) {
	analyzer := NewTunnelAnalyzer()

	// Valid OpenVPN handshake init packet (opcode 7)
	// Must be at least 42 bytes with valid session ID
	payload := make([]byte, 50)
	payload[0] = 0x38 // opcode 7, key_id 0
	// Set non-zero session ID
	payload[1] = 0x12
	payload[2] = 0x34
	payload[3] = 0x56
	payload[4] = 0x78
	payload[5] = 0x9a
	payload[6] = 0xbc
	payload[7] = 0xde
	payload[8] = 0xf0
	// Packet ID array length = 0 for initial handshake
	payload[9] = 0x00

	if !analyzer.isOpenVPNPacketStrict(payload, 8080, 8080) {
		t.Error("Expected valid OpenVPN handshake to be detected by strict check")
	}
}

func TestIsOpenVPNPacketStrict_RejectsDataPackets(t *testing.T) {
	analyzer := NewTunnelAnalyzer()

	// Data packets should be rejected by strict check on non-standard ports
	payload := make([]byte, 100)
	payload[0] = 0x48 // opcode 9 (data v2), key_id 0

	if analyzer.isOpenVPNPacketStrict(payload, 8080, 8080) {
		t.Error("Expected data packet to be rejected by strict check on non-standard port")
	}
}

func TestIsOpenVPNPacketStrict_RejectsTooShort(t *testing.T) {
	analyzer := NewTunnelAnalyzer()

	// Packet too short for strict validation
	payload := make([]byte, 30)
	payload[0] = 0x38

	if analyzer.isOpenVPNPacketStrict(payload, 8080, 8080) {
		t.Error("Expected short packet to be rejected by strict check")
	}
}

func TestIsExcludedFromVPNDetection_GoogleDNS(t *testing.T) {
	analyzer := NewTunnelAnalyzer()

	// Traffic to Google DNS should be excluded
	ipInfo := &PacketIPInfo{SrcIP: "192.168.1.1", DstIP: "8.8.8.8"}
	if !analyzer.isExcludedFromVPNDetection(ipInfo, 12345, 53) {
		t.Error("Expected Google DNS traffic to be excluded from VPN detection")
	}

	// Traffic from Google DNS should be excluded
	ipInfo2 := &PacketIPInfo{SrcIP: "8.8.4.4", DstIP: "192.168.1.1"}
	if !analyzer.isExcludedFromVPNDetection(ipInfo2, 53, 12345) {
		t.Error("Expected traffic from Google DNS to be excluded from VPN detection")
	}
}

func TestIsExcludedFromVPNDetection_CloudflareDNS(t *testing.T) {
	analyzer := NewTunnelAnalyzer()

	// Traffic to Cloudflare DNS should be excluded
	ipInfo := &PacketIPInfo{SrcIP: "192.168.1.1", DstIP: "1.1.1.1"}
	if !analyzer.isExcludedFromVPNDetection(ipInfo, 12345, 53) {
		t.Error("Expected Cloudflare DNS traffic to be excluded from VPN detection")
	}
}

func TestIsExcludedFromVPNDetection_DNSPort(t *testing.T) {
	analyzer := NewTunnelAnalyzer()

	// Traffic on DNS port should be excluded (unless VPN port)
	ipInfo := &PacketIPInfo{SrcIP: "192.168.1.1", DstIP: "10.0.0.1"}
	if !analyzer.isExcludedFromVPNDetection(ipInfo, 12345, 53) {
		t.Error("Expected DNS port traffic to be excluded from VPN detection")
	}
}

func TestIsExcludedFromVPNDetection_VPNPort(t *testing.T) {
	analyzer := NewTunnelAnalyzer()

	// Traffic on VPN port should NOT be excluded
	ipInfo := &PacketIPInfo{SrcIP: "192.168.1.1", DstIP: "10.0.0.1"}
	if analyzer.isExcludedFromVPNDetection(ipInfo, 12345, 1194) {
		t.Error("Expected OpenVPN port traffic to NOT be excluded from VPN detection")
	}
}

func TestIsExcludedFromVPNDetection_NormalTraffic(t *testing.T) {
	analyzer := NewTunnelAnalyzer()

	// Normal traffic on non-excluded ports should NOT be excluded
	ipInfo := &PacketIPInfo{SrcIP: "192.168.1.1", DstIP: "10.0.0.1"}
	if analyzer.isExcludedFromVPNDetection(ipInfo, 12345, 8080) {
		t.Error("Expected normal traffic to NOT be excluded from VPN detection")
	}
}

func TestIsWireGuardPacket_HandshakeInitiation(t *testing.T) {
	analyzer := NewTunnelAnalyzer()

	// WireGuard Handshake Initiation (type 1, 148 bytes)
	payload := make([]byte, 148)
	payload[0] = 0x01 // Type 1 (little-endian)
	payload[1] = 0x00
	payload[2] = 0x00
	payload[3] = 0x00

	if !analyzer.isWireGuardPacket(payload) {
		t.Error("Expected valid WireGuard handshake initiation to be detected")
	}
}

func TestIsWireGuardPacket_HandshakeResponse(t *testing.T) {
	analyzer := NewTunnelAnalyzer()

	// WireGuard Handshake Response (type 2, 92 bytes)
	payload := make([]byte, 92)
	payload[0] = 0x02 // Type 2 (little-endian)
	payload[1] = 0x00
	payload[2] = 0x00
	payload[3] = 0x00

	if !analyzer.isWireGuardPacket(payload) {
		t.Error("Expected valid WireGuard handshake response to be detected")
	}
}

func TestIsWireGuardPacket_TransportData(t *testing.T) {
	analyzer := NewTunnelAnalyzer()

	// WireGuard Transport Data (type 4, min 32 bytes)
	payload := make([]byte, 64)
	payload[0] = 0x04 // Type 4 (little-endian)
	payload[1] = 0x00
	payload[2] = 0x00
	payload[3] = 0x00

	if !analyzer.isWireGuardPacket(payload) {
		t.Error("Expected valid WireGuard transport data to be detected")
	}
}

func TestIsWireGuardPacket_WrongSize(t *testing.T) {
	analyzer := NewTunnelAnalyzer()

	// WireGuard Handshake Initiation with wrong size (should be 148)
	payload := make([]byte, 100)
	payload[0] = 0x01
	payload[1] = 0x00
	payload[2] = 0x00
	payload[3] = 0x00

	if analyzer.isWireGuardPacket(payload) {
		t.Error("Expected WireGuard packet with wrong size to not be detected")
	}
}

func TestIsWireGuardPacket_InvalidType(t *testing.T) {
	analyzer := NewTunnelAnalyzer()

	// Invalid WireGuard type (5 is not valid)
	payload := make([]byte, 100)
	payload[0] = 0x05
	payload[1] = 0x00
	payload[2] = 0x00
	payload[3] = 0x00

	if analyzer.isWireGuardPacket(payload) {
		t.Error("Expected invalid WireGuard type to not be detected")
	}
}

func TestAnalyzeOpenVPN_DPIDetection(t *testing.T) {
	analyzer := NewTunnelAnalyzer()
	ipInfo := &PacketIPInfo{SrcIP: "192.168.1.1", DstIP: "10.0.0.1"}
	timestamp := time.Now()

	// OpenVPN Control Hard Reset Client V2 (opcode 7)
	payload := make([]byte, 50)
	payload[0] = 0x38 // opcode 7, key_id 0

	analyzer.analyzeOpenVPN(payload, ipInfo, 1194, 1194, timestamp)

	tunnels := analyzer.GetTunnels()
	if len(tunnels) != 1 {
		t.Fatalf("Expected 1 tunnel, got %d", len(tunnels))
	}

	for _, tunnel := range tunnels {
		if tunnel.Type != "OpenVPN" {
			t.Errorf("Expected tunnel type 'OpenVPN', got '%s'", tunnel.Type)
		}
		if tunnel.DetectionMethod != "DPI" {
			t.Errorf("Expected detection method 'DPI', got '%s'", tunnel.DetectionMethod)
		}
		if tunnel.Confidence != VPNConfidenceHigh {
			t.Errorf("Expected confidence 'High', got '%s'", tunnel.Confidence)
		}
		if tunnel.SessionState != "Handshake-Init" {
			t.Errorf("Expected session state 'Handshake-Init', got '%s'", tunnel.SessionState)
		}
		if tunnel.ProtocolVersion != "v2" {
			t.Errorf("Expected protocol version 'v2', got '%s'", tunnel.ProtocolVersion)
		}
	}
}

func TestAnalyzeWireGuard_DPIDetection(t *testing.T) {
	analyzer := NewTunnelAnalyzer()
	ipInfo := &PacketIPInfo{SrcIP: "192.168.1.1", DstIP: "10.0.0.1"}
	timestamp := time.Now()

	// WireGuard Handshake Initiation (type 1, 148 bytes)
	payload := make([]byte, 148)
	payload[0] = 0x01
	payload[1] = 0x00
	payload[2] = 0x00
	payload[3] = 0x00
	// Sender index at bytes 4-7
	payload[4] = 0x12
	payload[5] = 0x34
	payload[6] = 0x56
	payload[7] = 0x78

	analyzer.analyzeWireGuard(payload, ipInfo, 51820, 51820, timestamp)

	tunnels := analyzer.GetTunnels()
	if len(tunnels) != 1 {
		t.Fatalf("Expected 1 tunnel, got %d", len(tunnels))
	}

	for _, tunnel := range tunnels {
		if tunnel.Type != "WireGuard" {
			t.Errorf("Expected tunnel type 'WireGuard', got '%s'", tunnel.Type)
		}
		if tunnel.DetectionMethod != "DPI" {
			t.Errorf("Expected detection method 'DPI', got '%s'", tunnel.DetectionMethod)
		}
		if tunnel.Confidence != VPNConfidenceHigh {
			t.Errorf("Expected confidence 'High', got '%s'", tunnel.Confidence)
		}
		if tunnel.SessionState != "Handshake-Init" {
			t.Errorf("Expected session state 'Handshake-Init', got '%s'", tunnel.SessionState)
		}
	}
}

func TestAnalyzeOpenVPN_PortBasedFallback(t *testing.T) {
	analyzer := NewTunnelAnalyzer()
	ipInfo := &PacketIPInfo{SrcIP: "192.168.1.1", DstIP: "10.0.0.1"}
	timestamp := time.Now()

	// Invalid OpenVPN packet on standard port - should fall back to port-based
	payload := []byte{0x00} // Too short for DPI

	analyzer.analyzeOpenVPN(payload, ipInfo, 1194, 1194, timestamp)

	tunnels := analyzer.GetTunnels()
	if len(tunnels) != 1 {
		t.Fatalf("Expected 1 tunnel, got %d", len(tunnels))
	}

	for _, tunnel := range tunnels {
		if tunnel.DetectionMethod != "Port-based" {
			t.Errorf("Expected detection method 'Port-based', got '%s'", tunnel.DetectionMethod)
		}
		if tunnel.Confidence != VPNConfidenceLow {
			t.Errorf("Expected confidence 'Low', got '%s'", tunnel.Confidence)
		}
	}
}

func TestGetVPNTunnels(t *testing.T) {
	analyzer := NewTunnelAnalyzer()
	ipInfo := &PacketIPInfo{SrcIP: "192.168.1.1", DstIP: "10.0.0.1"}
	timestamp := time.Now()

	// Add OpenVPN tunnel
	ovpnPayload := make([]byte, 50)
	ovpnPayload[0] = 0x38
	analyzer.analyzeOpenVPN(ovpnPayload, ipInfo, 1194, 1194, timestamp)

	// Add WireGuard tunnel
	wgPayload := make([]byte, 148)
	wgPayload[0] = 0x01
	ipInfo2 := &PacketIPInfo{SrcIP: "192.168.1.2", DstIP: "10.0.0.2"}
	analyzer.analyzeWireGuard(wgPayload, ipInfo2, 51820, 51820, timestamp)

	vpnTunnels := analyzer.GetVPNTunnels()
	if len(vpnTunnels) != 2 {
		t.Errorf("Expected 2 VPN tunnels, got %d", len(vpnTunnels))
	}
}

func TestGetTunnelsByConfidence(t *testing.T) {
	analyzer := NewTunnelAnalyzer()
	ipInfo := &PacketIPInfo{SrcIP: "192.168.1.1", DstIP: "10.0.0.1"}
	timestamp := time.Now()

	// Add high confidence tunnel (DPI detected)
	ovpnPayload := make([]byte, 50)
	ovpnPayload[0] = 0x38
	analyzer.analyzeOpenVPN(ovpnPayload, ipInfo, 1194, 1194, timestamp)

	// Add low confidence tunnel (port-based)
	lowPayload := []byte{0x00}
	ipInfo2 := &PacketIPInfo{SrcIP: "192.168.1.2", DstIP: "10.0.0.2"}
	analyzer.analyzeOpenVPN(lowPayload, ipInfo2, 1194, 1194, timestamp)

	byConfidence := analyzer.GetTunnelsByConfidence()

	if len(byConfidence[VPNConfidenceHigh]) != 1 {
		t.Errorf("Expected 1 high confidence tunnel, got %d", len(byConfidence[VPNConfidenceHigh]))
	}
	if len(byConfidence[VPNConfidenceLow]) != 1 {
		t.Errorf("Expected 1 low confidence tunnel, got %d", len(byConfidence[VPNConfidenceLow]))
	}
}

func TestValidateSDWANTunnels(t *testing.T) {
	analyzer := NewTunnelAnalyzer()
	ipInfo := &PacketIPInfo{SrcIP: "192.168.1.1", DstIP: "10.0.0.1"}
	timestamp := time.Now()

	// Add OpenVPN tunnel on non-standard port
	ovpnPayload := make([]byte, 50)
	ovpnPayload[0] = 0x38
	analyzer.analyzeOpenVPN(ovpnPayload, ipInfo, 8443, 8443, timestamp) // Non-standard port

	// Authorized endpoints
	authorized := map[string]bool{
		"192.168.1.1": true,
	}

	unauthorized := analyzer.ValidateSDWANTunnels(authorized)

	// Should flag the tunnel as suspicious (VPN on non-standard port)
	if len(unauthorized) != 1 {
		t.Errorf("Expected 1 unauthorized tunnel, got %d", len(unauthorized))
	}

	if len(unauthorized) > 0 && unauthorized[0].RiskLevel != "Medium" {
		t.Errorf("Expected risk level 'Medium', got '%s'", unauthorized[0].RiskLevel)
	}
}

func TestTunnelAnalyzer_NewTunnelAnalyzer(t *testing.T) {
	analyzer := NewTunnelAnalyzer()
	if analyzer == nil {
		t.Error("NewTunnelAnalyzer returned nil")
	}
	if analyzer.tunnels == nil {
		t.Error("tunnels map not initialized")
	}
}

func TestGetTunnelStats(t *testing.T) {
	analyzer := NewTunnelAnalyzer()
	ipInfo := &PacketIPInfo{SrcIP: "192.168.1.1", DstIP: "10.0.0.1"}
	timestamp := time.Now()

	// Add OpenVPN tunnel
	ovpnPayload := make([]byte, 50)
	ovpnPayload[0] = 0x38
	analyzer.analyzeOpenVPN(ovpnPayload, ipInfo, 1194, 1194, timestamp)

	// Add WireGuard tunnel
	wgPayload := make([]byte, 148)
	wgPayload[0] = 0x01
	ipInfo2 := &PacketIPInfo{SrcIP: "192.168.1.2", DstIP: "10.0.0.2"}
	analyzer.analyzeWireGuard(wgPayload, ipInfo2, 51820, 51820, timestamp)

	stats := analyzer.GetTunnelStats()

	if stats["OpenVPN"] != 1 {
		t.Errorf("Expected 1 OpenVPN tunnel in stats, got %d", stats["OpenVPN"])
	}
	if stats["WireGuard"] != 1 {
		t.Errorf("Expected 1 WireGuard tunnel in stats, got %d", stats["WireGuard"])
	}
}
