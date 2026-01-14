package detector

import (
	"fmt"
	"time"

	"github.com/gocisse/sdwan-triage/pkg/models"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// Tunnel protocol constants
const (
	VXLANPort     = 4789
	GREProtocol   = 47
	ESPProtocol   = 50
	AHProtocol    = 51
	GTPUPort      = 2152
	GTPCPort      = 2123
	L2TPPort      = 1701
	OpenVPNPort   = 1194
	WireGuardPort = 51820
)

// OpenVPN opcodes for DPI
const (
	OpenVPNControlHardResetClientV1 = 1
	OpenVPNControlHardResetServerV1 = 2
	OpenVPNControlSoftResetV1       = 3
	OpenVPNControlV1                = 4
	OpenVPNAckV1                    = 5
	OpenVPNDataV1                   = 6
	OpenVPNControlHardResetClientV2 = 7
	OpenVPNControlHardResetServerV2 = 8
	OpenVPNDataV2                   = 9
)

// WireGuard message types for DPI
const (
	WireGuardHandshakeInitiation = 1
	WireGuardHandshakeResponse   = 2
	WireGuardHandshakeCookie     = 3
	WireGuardTransportData       = 4
)

// VPN detection confidence levels
const (
	VPNConfidenceHigh   = "High"
	VPNConfidenceMedium = "Medium"
	VPNConfidenceLow    = "Low"
)

// VPNSessionInfo tracks VPN session details from DPI
type VPNSessionInfo struct {
	Protocol        string // "OpenVPN" or "WireGuard"
	Version         string // Protocol version detected
	SessionState    string // "Handshake", "Established", "Data"
	DetectionMethod string // "DPI", "Port-based"
	Confidence      string // "High", "Medium", "Low"
	HandshakeCount  int
	DataPackets     int
	IsEncrypted     bool
	CipherSuite     string // If detectable
}

// TunnelAnalyzer handles encapsulation protocol detection
type TunnelAnalyzer struct {
	tunnels map[string]*TunnelInfo
}

// TunnelInfo represents detected tunnel information
type TunnelInfo struct {
	Type        string
	SrcIP       string
	DstIP       string
	SrcPort     uint16
	DstPort     uint16
	VNI         uint32 // VXLAN Network Identifier
	GREKey      uint32
	FirstSeen   time.Time
	LastSeen    time.Time
	PacketCount uint64
	ByteCount   uint64
	InnerProto  string
	// DPI-enhanced fields
	DetectionMethod string // "DPI", "Port-based", "Signature"
	Confidence      string // "High", "Medium", "Low"
	ProtocolVersion string // Protocol version if detected
	SessionState    string // "Handshake", "Established", "Data"
	IsAuthorized    bool   // For SD-WAN security validation
	SDWANPath       string // Associated SD-WAN path if detected
}

// NewTunnelAnalyzer creates a new tunnel analyzer
func NewTunnelAnalyzer() *TunnelAnalyzer {
	return &TunnelAnalyzer{
		tunnels: make(map[string]*TunnelInfo),
	}
}

// Analyze processes packets for tunnel/encapsulation protocols
func (t *TunnelAnalyzer) Analyze(packet gopacket.Packet, state *models.AnalysisState, report *models.TriageReport) {
	ipInfo := ExtractIPInfo(packet)
	if ipInfo == nil {
		return
	}

	timestamp := packet.Metadata().Timestamp

	// Check for GRE
	if greLayer := packet.Layer(layers.LayerTypeGRE); greLayer != nil {
		t.analyzeGRE(packet, greLayer.(*layers.GRE), ipInfo, timestamp)
		return
	}

	// Check for IPsec (ESP/AH)
	if espLayer := packet.Layer(layers.LayerTypeIPSecESP); espLayer != nil {
		t.analyzeIPSec(ipInfo, "ESP", timestamp, uint64(len(packet.Data())))
		return
	}
	if ahLayer := packet.Layer(layers.LayerTypeIPSecAH); ahLayer != nil {
		t.analyzeIPSec(ipInfo, "AH", timestamp, uint64(len(packet.Data())))
		return
	}

	// Check UDP-based tunnels
	if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp := udpLayer.(*layers.UDP)
		srcPort := uint16(udp.SrcPort)
		dstPort := uint16(udp.DstPort)
		payload := udp.Payload

		// VXLAN
		if dstPort == VXLANPort || srcPort == VXLANPort {
			t.analyzeVXLAN(payload, ipInfo, srcPort, dstPort, timestamp)
			return
		}

		// GTP-U (GPRS Tunneling Protocol)
		if dstPort == GTPUPort || srcPort == GTPUPort {
			t.analyzeGTP(payload, ipInfo, srcPort, dstPort, "GTP-U", timestamp)
			return
		}

		// GTP-C
		if dstPort == GTPCPort || srcPort == GTPCPort {
			t.analyzeGTP(payload, ipInfo, srcPort, dstPort, "GTP-C", timestamp)
			return
		}

		// L2TP
		if dstPort == L2TPPort || srcPort == L2TPPort {
			t.analyzeL2TP(payload, ipInfo, srcPort, dstPort, timestamp)
			return
		}

		// OpenVPN - Try DPI first, fall back to port-based
		if dstPort == OpenVPNPort || srcPort == OpenVPNPort {
			t.analyzeOpenVPN(payload, ipInfo, srcPort, dstPort, timestamp)
			return
		}
		// Also check for OpenVPN on non-standard ports via DPI
		if t.isOpenVPNPacket(payload) {
			t.analyzeOpenVPN(payload, ipInfo, srcPort, dstPort, timestamp)
			return
		}

		// WireGuard - Try DPI first, fall back to port-based
		if dstPort == WireGuardPort || srcPort == WireGuardPort {
			t.analyzeWireGuard(payload, ipInfo, srcPort, dstPort, timestamp)
			return
		}
		// Also check for WireGuard on non-standard ports via DPI
		if t.isWireGuardPacket(payload) {
			t.analyzeWireGuard(payload, ipInfo, srcPort, dstPort, timestamp)
			return
		}
	}

	// Check for MPLS
	if mplsLayer := packet.Layer(layers.LayerTypeMPLS); mplsLayer != nil {
		t.analyzeMPLS(mplsLayer.(*layers.MPLS), ipInfo, timestamp, uint64(len(packet.Data())))
	}
}

func (t *TunnelAnalyzer) analyzeVXLAN(payload []byte, ipInfo *PacketIPInfo, srcPort, dstPort uint16, timestamp time.Time) {
	if len(payload) < 8 {
		return
	}

	// VXLAN header: 8 bytes
	// Flags (1) + Reserved (3) + VNI (3) + Reserved (1)
	flags := payload[0]
	if flags&0x08 == 0 { // I flag must be set
		return
	}

	vni := uint32(payload[4])<<16 | uint32(payload[5])<<8 | uint32(payload[6])

	key := fmt.Sprintf("vxlan-%s-%s-%d", ipInfo.SrcIP, ipInfo.DstIP, vni)
	if tunnel, exists := t.tunnels[key]; exists {
		tunnel.LastSeen = timestamp
		tunnel.PacketCount++
		tunnel.ByteCount += uint64(len(payload))
	} else {
		t.tunnels[key] = &TunnelInfo{
			Type:        "VXLAN",
			SrcIP:       ipInfo.SrcIP,
			DstIP:       ipInfo.DstIP,
			SrcPort:     srcPort,
			DstPort:     dstPort,
			VNI:         vni,
			FirstSeen:   timestamp,
			LastSeen:    timestamp,
			PacketCount: 1,
			ByteCount:   uint64(len(payload)),
			InnerProto:  "Ethernet",
		}
	}
}

func (t *TunnelAnalyzer) analyzeGRE(packet gopacket.Packet, gre *layers.GRE, ipInfo *PacketIPInfo, timestamp time.Time) {
	tunnelType := "GRE"
	var greKey uint32

	if gre.KeyPresent {
		greKey = gre.Key
	}

	// Check for NVGRE (uses GRE key as VSID)
	if gre.Protocol == layers.EthernetTypeTransparentEthernetBridging {
		tunnelType = "NVGRE"
	}

	// Check for ERSPAN
	if gre.Protocol == 0x88BE || gre.Protocol == 0x22EB {
		tunnelType = "ERSPAN"
	}

	key := fmt.Sprintf("gre-%s-%s-%d", ipInfo.SrcIP, ipInfo.DstIP, greKey)
	if tunnel, exists := t.tunnels[key]; exists {
		tunnel.LastSeen = timestamp
		tunnel.PacketCount++
		tunnel.ByteCount += uint64(len(packet.Data()))
	} else {
		t.tunnels[key] = &TunnelInfo{
			Type:        tunnelType,
			SrcIP:       ipInfo.SrcIP,
			DstIP:       ipInfo.DstIP,
			GREKey:      greKey,
			FirstSeen:   timestamp,
			LastSeen:    timestamp,
			PacketCount: 1,
			ByteCount:   uint64(len(packet.Data())),
			InnerProto:  gre.Protocol.String(),
		}
	}
}

func (t *TunnelAnalyzer) analyzeIPSec(ipInfo *PacketIPInfo, protocol string, timestamp time.Time, byteCount uint64) {
	key := fmt.Sprintf("ipsec-%s-%s-%s", protocol, ipInfo.SrcIP, ipInfo.DstIP)
	if tunnel, exists := t.tunnels[key]; exists {
		tunnel.LastSeen = timestamp
		tunnel.PacketCount++
		tunnel.ByteCount += byteCount
	} else {
		t.tunnels[key] = &TunnelInfo{
			Type:        "IPsec " + protocol,
			SrcIP:       ipInfo.SrcIP,
			DstIP:       ipInfo.DstIP,
			FirstSeen:   timestamp,
			LastSeen:    timestamp,
			PacketCount: 1,
			ByteCount:   byteCount,
			InnerProto:  "Encrypted",
		}
	}
}

func (t *TunnelAnalyzer) analyzeGTP(payload []byte, ipInfo *PacketIPInfo, srcPort, dstPort uint16, gtpType string, timestamp time.Time) {
	if len(payload) < 8 {
		return
	}

	// GTP header: minimum 8 bytes
	// Version/PT/E/S/PN (1) + Message Type (1) + Length (2) + TEID (4)
	teid := uint32(payload[4])<<24 | uint32(payload[5])<<16 | uint32(payload[6])<<8 | uint32(payload[7])

	key := fmt.Sprintf("gtp-%s-%s-%d", ipInfo.SrcIP, ipInfo.DstIP, teid)
	if tunnel, exists := t.tunnels[key]; exists {
		tunnel.LastSeen = timestamp
		tunnel.PacketCount++
		tunnel.ByteCount += uint64(len(payload))
	} else {
		t.tunnels[key] = &TunnelInfo{
			Type:        gtpType,
			SrcIP:       ipInfo.SrcIP,
			DstIP:       ipInfo.DstIP,
			SrcPort:     srcPort,
			DstPort:     dstPort,
			VNI:         teid, // Using VNI field for TEID
			FirstSeen:   timestamp,
			LastSeen:    timestamp,
			PacketCount: 1,
			ByteCount:   uint64(len(payload)),
			InnerProto:  "IP",
		}
	}
}

func (t *TunnelAnalyzer) analyzeL2TP(payload []byte, ipInfo *PacketIPInfo, srcPort, dstPort uint16, timestamp time.Time) {
	if len(payload) < 6 {
		return
	}

	t.recordTunnel("L2TP", ipInfo, srcPort, dstPort, 0, timestamp, uint64(len(payload)))
}

func (t *TunnelAnalyzer) analyzeMPLS(mpls *layers.MPLS, ipInfo *PacketIPInfo, timestamp time.Time, byteCount uint64) {
	label := mpls.Label

	key := fmt.Sprintf("mpls-%s-%s-%d", ipInfo.SrcIP, ipInfo.DstIP, label)
	if tunnel, exists := t.tunnels[key]; exists {
		tunnel.LastSeen = timestamp
		tunnel.PacketCount++
		tunnel.ByteCount += byteCount
	} else {
		t.tunnels[key] = &TunnelInfo{
			Type:        "MPLS",
			SrcIP:       ipInfo.SrcIP,
			DstIP:       ipInfo.DstIP,
			VNI:         label, // Using VNI field for MPLS label
			FirstSeen:   timestamp,
			LastSeen:    timestamp,
			PacketCount: 1,
			ByteCount:   byteCount,
			InnerProto:  "IP/Ethernet",
		}
	}
}

func (t *TunnelAnalyzer) recordTunnel(tunnelType string, ipInfo *PacketIPInfo, srcPort, dstPort uint16, identifier uint32, timestamp time.Time, byteCount uint64) {
	key := fmt.Sprintf("%s-%s-%s", tunnelType, ipInfo.SrcIP, ipInfo.DstIP)
	if tunnel, exists := t.tunnels[key]; exists {
		tunnel.LastSeen = timestamp
		tunnel.PacketCount++
		tunnel.ByteCount += byteCount
	} else {
		t.tunnels[key] = &TunnelInfo{
			Type:        tunnelType,
			SrcIP:       ipInfo.SrcIP,
			DstIP:       ipInfo.DstIP,
			SrcPort:     srcPort,
			DstPort:     dstPort,
			VNI:         identifier,
			FirstSeen:   timestamp,
			LastSeen:    timestamp,
			PacketCount: 1,
			ByteCount:   byteCount,
		}
	}
}

// GetTunnels returns all detected tunnels
func (t *TunnelAnalyzer) GetTunnels() map[string]*TunnelInfo {
	return t.tunnels
}

// GetTunnelStats returns tunnel statistics by type
func (t *TunnelAnalyzer) GetTunnelStats() map[string]int {
	stats := make(map[string]int)
	for _, tunnel := range t.tunnels {
		stats[tunnel.Type]++
	}
	return stats
}

// ============================================================================
// OpenVPN Deep Packet Inspection
// ============================================================================

// isOpenVPNPacket performs DPI to detect OpenVPN traffic on non-standard ports
func (t *TunnelAnalyzer) isOpenVPNPacket(payload []byte) bool {
	if len(payload) < 2 {
		return false
	}

	// OpenVPN packet structure:
	// - First byte contains opcode (high 5 bits) and key_id (low 3 bits)
	// - For P_CONTROL_HARD_RESET_CLIENT_V2 (opcode 7), packet starts with 0x38
	// - For P_CONTROL_HARD_RESET_SERVER_V2 (opcode 8), packet starts with 0x40
	// - For P_DATA_V1 (opcode 6), packet starts with 0x30
	// - For P_DATA_V2 (opcode 9), packet starts with 0x48

	opcode := (payload[0] >> 3) & 0x1F

	// Valid OpenVPN opcodes are 1-9
	if opcode >= 1 && opcode <= 9 {
		// Additional validation based on packet structure
		switch opcode {
		case OpenVPNControlHardResetClientV2, OpenVPNControlHardResetServerV2:
			// Control packets have session ID (8 bytes) after opcode
			if len(payload) >= 9 {
				return true
			}
		case OpenVPNDataV1, OpenVPNDataV2:
			// Data packets - check for reasonable encrypted payload size
			if len(payload) >= 20 {
				return true
			}
		case OpenVPNControlV1, OpenVPNAckV1:
			// Control/ACK packets
			if len(payload) >= 9 {
				return true
			}
		}
	}

	return false
}

// analyzeOpenVPN performs deep packet inspection on OpenVPN traffic
func (t *TunnelAnalyzer) analyzeOpenVPN(payload []byte, ipInfo *PacketIPInfo, srcPort, dstPort uint16, timestamp time.Time) {
	if len(payload) < 2 {
		// Fall back to port-based detection
		t.recordTunnelWithDPI("OpenVPN", ipInfo, srcPort, dstPort, 0, timestamp, uint64(len(payload)),
			"Port-based", VPNConfidenceLow, "", "Unknown")
		return
	}

	opcode := (payload[0] >> 3) & 0x1F
	keyID := payload[0] & 0x07

	var sessionState string
	var protocolVersion string
	var confidence string
	var detectionMethod string

	switch opcode {
	case OpenVPNControlHardResetClientV1:
		sessionState = "Handshake-Init"
		protocolVersion = "v1"
		confidence = VPNConfidenceHigh
		detectionMethod = "DPI"
	case OpenVPNControlHardResetServerV1:
		sessionState = "Handshake-Response"
		protocolVersion = "v1"
		confidence = VPNConfidenceHigh
		detectionMethod = "DPI"
	case OpenVPNControlHardResetClientV2:
		sessionState = "Handshake-Init"
		protocolVersion = "v2"
		confidence = VPNConfidenceHigh
		detectionMethod = "DPI"
	case OpenVPNControlHardResetServerV2:
		sessionState = "Handshake-Response"
		protocolVersion = "v2"
		confidence = VPNConfidenceHigh
		detectionMethod = "DPI"
	case OpenVPNControlV1:
		sessionState = "Control"
		protocolVersion = "v1"
		confidence = VPNConfidenceHigh
		detectionMethod = "DPI"
	case OpenVPNAckV1:
		sessionState = "Established"
		protocolVersion = "v1"
		confidence = VPNConfidenceHigh
		detectionMethod = "DPI"
	case OpenVPNDataV1:
		sessionState = "Data"
		protocolVersion = "v1"
		confidence = VPNConfidenceHigh
		detectionMethod = "DPI"
	case OpenVPNDataV2:
		sessionState = "Data"
		protocolVersion = "v2"
		confidence = VPNConfidenceHigh
		detectionMethod = "DPI"
	case OpenVPNControlSoftResetV1:
		sessionState = "Soft-Reset"
		protocolVersion = "v1"
		confidence = VPNConfidenceHigh
		detectionMethod = "DPI"
	default:
		// Unknown opcode - use port-based detection
		if srcPort == OpenVPNPort || dstPort == OpenVPNPort {
			sessionState = "Unknown"
			protocolVersion = "Unknown"
			confidence = VPNConfidenceMedium
			detectionMethod = "Port-based"
		} else {
			return // Not OpenVPN
		}
	}

	// Extract session ID if present (8 bytes after opcode for control packets)
	var sessionID uint64
	if len(payload) >= 9 && opcode != OpenVPNDataV1 && opcode != OpenVPNDataV2 {
		for i := 1; i < 9; i++ {
			sessionID = (sessionID << 8) | uint64(payload[i])
		}
	}

	key := fmt.Sprintf("openvpn-%s-%s-%d", ipInfo.SrcIP, ipInfo.DstIP, keyID)
	if tunnel, exists := t.tunnels[key]; exists {
		tunnel.LastSeen = timestamp
		tunnel.PacketCount++
		tunnel.ByteCount += uint64(len(payload))
		// Update session state if progressing
		if sessionState == "Data" || sessionState == "Established" {
			tunnel.SessionState = sessionState
		}
	} else {
		t.tunnels[key] = &TunnelInfo{
			Type:            "OpenVPN",
			SrcIP:           ipInfo.SrcIP,
			DstIP:           ipInfo.DstIP,
			SrcPort:         srcPort,
			DstPort:         dstPort,
			VNI:             uint32(keyID),
			FirstSeen:       timestamp,
			LastSeen:        timestamp,
			PacketCount:     1,
			ByteCount:       uint64(len(payload)),
			InnerProto:      "Encrypted",
			DetectionMethod: detectionMethod,
			Confidence:      confidence,
			ProtocolVersion: protocolVersion,
			SessionState:    sessionState,
		}
	}
}

// ============================================================================
// WireGuard Deep Packet Inspection
// ============================================================================

// isWireGuardPacket performs DPI to detect WireGuard traffic on non-standard ports
func (t *TunnelAnalyzer) isWireGuardPacket(payload []byte) bool {
	if len(payload) < 4 {
		return false
	}

	// WireGuard packet structure:
	// - First 4 bytes: message type (little-endian uint32)
	// - Type 1: Handshake Initiation (148 bytes)
	// - Type 2: Handshake Response (92 bytes)
	// - Type 3: Cookie Reply (64 bytes)
	// - Type 4: Transport Data (variable, min 32 bytes)

	msgType := uint32(payload[0]) | uint32(payload[1])<<8 | uint32(payload[2])<<16 | uint32(payload[3])<<24

	switch msgType {
	case WireGuardHandshakeInitiation:
		// Handshake initiation is exactly 148 bytes
		return len(payload) == 148
	case WireGuardHandshakeResponse:
		// Handshake response is exactly 92 bytes
		return len(payload) == 92
	case WireGuardHandshakeCookie:
		// Cookie reply is exactly 64 bytes
		return len(payload) == 64
	case WireGuardTransportData:
		// Transport data is at least 32 bytes (16 header + 16 auth tag minimum)
		return len(payload) >= 32
	}

	return false
}

// analyzeWireGuard performs deep packet inspection on WireGuard traffic
func (t *TunnelAnalyzer) analyzeWireGuard(payload []byte, ipInfo *PacketIPInfo, srcPort, dstPort uint16, timestamp time.Time) {
	if len(payload) < 4 {
		// Fall back to port-based detection
		t.recordTunnelWithDPI("WireGuard", ipInfo, srcPort, dstPort, 0, timestamp, uint64(len(payload)),
			"Port-based", VPNConfidenceLow, "", "Unknown")
		return
	}

	// WireGuard uses little-endian for message type
	msgType := uint32(payload[0]) | uint32(payload[1])<<8 | uint32(payload[2])<<16 | uint32(payload[3])<<24

	var sessionState string
	var confidence string
	var detectionMethod string
	var senderIndex uint32

	switch msgType {
	case WireGuardHandshakeInitiation:
		if len(payload) != 148 {
			// Wrong size for handshake initiation
			if srcPort == WireGuardPort || dstPort == WireGuardPort {
				confidence = VPNConfidenceMedium
				detectionMethod = "Port-based"
				sessionState = "Unknown"
			} else {
				return
			}
		} else {
			sessionState = "Handshake-Init"
			confidence = VPNConfidenceHigh
			detectionMethod = "DPI"
			// Extract sender index (bytes 4-7, little-endian)
			senderIndex = uint32(payload[4]) | uint32(payload[5])<<8 | uint32(payload[6])<<16 | uint32(payload[7])<<24
		}
	case WireGuardHandshakeResponse:
		if len(payload) != 92 {
			if srcPort == WireGuardPort || dstPort == WireGuardPort {
				confidence = VPNConfidenceMedium
				detectionMethod = "Port-based"
				sessionState = "Unknown"
			} else {
				return
			}
		} else {
			sessionState = "Handshake-Response"
			confidence = VPNConfidenceHigh
			detectionMethod = "DPI"
			senderIndex = uint32(payload[4]) | uint32(payload[5])<<8 | uint32(payload[6])<<16 | uint32(payload[7])<<24
		}
	case WireGuardHandshakeCookie:
		if len(payload) != 64 {
			if srcPort == WireGuardPort || dstPort == WireGuardPort {
				confidence = VPNConfidenceMedium
				detectionMethod = "Port-based"
				sessionState = "Unknown"
			} else {
				return
			}
		} else {
			sessionState = "Cookie-Reply"
			confidence = VPNConfidenceHigh
			detectionMethod = "DPI"
		}
	case WireGuardTransportData:
		if len(payload) < 32 {
			if srcPort == WireGuardPort || dstPort == WireGuardPort {
				confidence = VPNConfidenceMedium
				detectionMethod = "Port-based"
				sessionState = "Unknown"
			} else {
				return
			}
		} else {
			sessionState = "Data"
			confidence = VPNConfidenceHigh
			detectionMethod = "DPI"
			// Extract receiver index (bytes 4-7, little-endian)
			senderIndex = uint32(payload[4]) | uint32(payload[5])<<8 | uint32(payload[6])<<16 | uint32(payload[7])<<24
		}
	default:
		// Unknown message type - check if on standard port
		if srcPort == WireGuardPort || dstPort == WireGuardPort {
			sessionState = "Unknown"
			confidence = VPNConfidenceMedium
			detectionMethod = "Port-based"
		} else {
			return // Not WireGuard
		}
	}

	key := fmt.Sprintf("wireguard-%s-%s", ipInfo.SrcIP, ipInfo.DstIP)
	if tunnel, exists := t.tunnels[key]; exists {
		tunnel.LastSeen = timestamp
		tunnel.PacketCount++
		tunnel.ByteCount += uint64(len(payload))
		// Update session state if progressing
		if sessionState == "Data" {
			tunnel.SessionState = sessionState
		}
	} else {
		t.tunnels[key] = &TunnelInfo{
			Type:            "WireGuard",
			SrcIP:           ipInfo.SrcIP,
			DstIP:           ipInfo.DstIP,
			SrcPort:         srcPort,
			DstPort:         dstPort,
			VNI:             senderIndex,
			FirstSeen:       timestamp,
			LastSeen:        timestamp,
			PacketCount:     1,
			ByteCount:       uint64(len(payload)),
			InnerProto:      "Encrypted",
			DetectionMethod: detectionMethod,
			Confidence:      confidence,
			ProtocolVersion: "1.0",
			SessionState:    sessionState,
		}
	}
}

// recordTunnelWithDPI records a tunnel with DPI-enhanced metadata
func (t *TunnelAnalyzer) recordTunnelWithDPI(tunnelType string, ipInfo *PacketIPInfo, srcPort, dstPort uint16, identifier uint32, timestamp time.Time, byteCount uint64, detectionMethod, confidence, version, state string) {
	key := fmt.Sprintf("%s-%s-%s", tunnelType, ipInfo.SrcIP, ipInfo.DstIP)
	if tunnel, exists := t.tunnels[key]; exists {
		tunnel.LastSeen = timestamp
		tunnel.PacketCount++
		tunnel.ByteCount += byteCount
	} else {
		t.tunnels[key] = &TunnelInfo{
			Type:            tunnelType,
			SrcIP:           ipInfo.SrcIP,
			DstIP:           ipInfo.DstIP,
			SrcPort:         srcPort,
			DstPort:         dstPort,
			VNI:             identifier,
			FirstSeen:       timestamp,
			LastSeen:        timestamp,
			PacketCount:     1,
			ByteCount:       byteCount,
			DetectionMethod: detectionMethod,
			Confidence:      confidence,
			ProtocolVersion: version,
			SessionState:    state,
		}
	}
}

// ============================================================================
// SD-WAN Security Validation
// ============================================================================

// ValidateSDWANTunnels checks for unauthorized tunnels bypassing SD-WAN policies
func (t *TunnelAnalyzer) ValidateSDWANTunnels(authorizedEndpoints map[string]bool) []UnauthorizedTunnel {
	var unauthorized []UnauthorizedTunnel

	for _, tunnel := range t.tunnels {
		// Check if tunnel endpoints are in authorized list
		srcAuthorized := authorizedEndpoints[tunnel.SrcIP]
		dstAuthorized := authorizedEndpoints[tunnel.DstIP]

		if !srcAuthorized && !dstAuthorized {
			unauthorized = append(unauthorized, UnauthorizedTunnel{
				TunnelInfo:     tunnel,
				Reason:         "Unknown tunnel endpoints",
				RiskLevel:      "High",
				Recommendation: "Investigate tunnel origin and destination",
			})
		} else if tunnel.Type == "OpenVPN" || tunnel.Type == "WireGuard" {
			// VPN tunnels on non-standard ports are suspicious
			if tunnel.SrcPort != OpenVPNPort && tunnel.DstPort != OpenVPNPort &&
				tunnel.SrcPort != WireGuardPort && tunnel.DstPort != WireGuardPort {
				unauthorized = append(unauthorized, UnauthorizedTunnel{
					TunnelInfo:     tunnel,
					Reason:         "VPN on non-standard port (potential policy bypass)",
					RiskLevel:      "Medium",
					Recommendation: "Verify if this VPN tunnel is authorized",
				})
			}
		}

		tunnel.IsAuthorized = srcAuthorized || dstAuthorized
	}

	return unauthorized
}

// UnauthorizedTunnel represents a potentially unauthorized tunnel
type UnauthorizedTunnel struct {
	TunnelInfo     *TunnelInfo
	Reason         string
	RiskLevel      string
	Recommendation string
}

// GetTunnelsByConfidence returns tunnels grouped by detection confidence
func (t *TunnelAnalyzer) GetTunnelsByConfidence() map[string][]*TunnelInfo {
	result := map[string][]*TunnelInfo{
		VPNConfidenceHigh:   {},
		VPNConfidenceMedium: {},
		VPNConfidenceLow:    {},
	}

	for _, tunnel := range t.tunnels {
		if tunnel.Confidence != "" {
			result[tunnel.Confidence] = append(result[tunnel.Confidence], tunnel)
		}
	}

	return result
}

// GetVPNTunnels returns only VPN tunnels (OpenVPN and WireGuard)
func (t *TunnelAnalyzer) GetVPNTunnels() []*TunnelInfo {
	var vpnTunnels []*TunnelInfo

	for _, tunnel := range t.tunnels {
		if tunnel.Type == "OpenVPN" || tunnel.Type == "WireGuard" {
			vpnTunnels = append(vpnTunnels, tunnel)
		}
	}

	return vpnTunnels
}
