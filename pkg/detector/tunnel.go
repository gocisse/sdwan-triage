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

// SD-WAN Vendor-Specific Ports (highest priority detection)
const (
	// Cisco SD-WAN (Viptela / IOS-XE SD-WAN)
	CiscoSDWANDataPort    = 12346 // UDP data plane tunnels
	CiscoSDWANControlPort = 23456 // TCP/UDP control plane (vSmart, vManage)
	CiscoSDWANNATPort     = 12366 // UDP NAT-traversal / fallback

	// VMware Velocloud
	VelocloudVCMPPort = 2426 // UDP VCMP tunnels (primary identifier)

	// Fortinet Secure SD-WAN
	FortinetSDWANPort = 541 // TCP/UDP control and data

	// Aruba EdgeConnect / Silver Peak / Palo Alto Prisma / Zscaler (IPsec-based)
	IPsecIKEPort  = 500  // IKE key exchange
	IPsecNATTPort = 4500 // IPsec NAT-Traversal

	// Juniper Session Smart (Mist / 128T) - uses dynamic ports, identified by behavior
)

// SD-WAN Vendor identifiers
const (
	SDWANVendorCisco     = "Cisco SD-WAN"
	SDWANVendorVelocloud = "VMware Velocloud"
	SDWANVendorFortinet  = "Fortinet SD-WAN"
	SDWANVendorAruba     = "Aruba EdgeConnect"
	SDWANVendorPaloAlto  = "Palo Alto Prisma"
	SDWANVendorZscaler   = "Zscaler"
	SDWANVendorGeneric   = "Generic IPsec SD-WAN"
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

// Common ports to exclude from VPN detection (false positive prevention)
const (
	DNSPort    = 53
	DNSOverTLS = 853
	HTTPSPort  = 443
	HTTPPort   = 80
	NTPPort    = 123
	SNMPPort   = 161
	SyslogPort = 514
)

// Known DNS server IPs to whitelist (prevent false positives)
var knownDNSServers = map[string]bool{
	// Google DNS
	"8.8.8.8":              true,
	"8.8.4.4":              true,
	"2001:4860:4860::8888": true,
	"2001:4860:4860::8844": true,
	// Cloudflare DNS
	"1.1.1.1":              true,
	"1.0.0.1":              true,
	"2606:4700:4700::1111": true,
	"2606:4700:4700::1001": true,
	// Quad9 DNS
	"9.9.9.9":         true,
	"149.112.112.112": true,
	// OpenDNS
	"208.67.222.222": true,
	"208.67.220.220": true,
}

// Ports that should never be classified as VPN (unless on VPN-specific port)
var excludedPorts = map[uint16]bool{
	DNSPort:    true,
	DNSOverTLS: true,
	HTTPPort:   true,
	NTPPort:    true,
	SNMPPort:   true,
	SyslogPort: true,
}

// VPNSessionTracker tracks VPN session state for multi-packet validation
type VPNSessionTracker struct {
	HandshakePackets int
	DataPackets      int
	ControlPackets   int
	FirstSeen        time.Time
	LastSeen         time.Time
	ValidSequence    bool // True if we've seen a valid handshake sequence
}

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
	tunnels     map[string]*TunnelInfo
	vpnSessions map[string]*VPNSessionTracker // Track VPN sessions for multi-packet validation
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
		tunnels:     make(map[string]*TunnelInfo),
		vpnSessions: make(map[string]*VPNSessionTracker),
	}
}

// isExcludedFromVPNDetection checks if traffic should be excluded from VPN detection
func (t *TunnelAnalyzer) isExcludedFromVPNDetection(ipInfo *PacketIPInfo, srcPort, dstPort uint16) bool {
	// Check if either endpoint is a known DNS server
	if knownDNSServers[ipInfo.SrcIP] || knownDNSServers[ipInfo.DstIP] {
		return true
	}

	// Check if using excluded ports (DNS, NTP, etc.) - unless on VPN-specific port
	if srcPort != OpenVPNPort && dstPort != OpenVPNPort &&
		srcPort != WireGuardPort && dstPort != WireGuardPort {
		if excludedPorts[srcPort] || excludedPorts[dstPort] {
			return true
		}
	}

	// Exclude HTTPS traffic unless on VPN-specific port
	if (srcPort == HTTPSPort || dstPort == HTTPSPort) &&
		srcPort != OpenVPNPort && dstPort != OpenVPNPort {
		return true
	}

	return false
}

// Analyze processes packets for tunnel/encapsulation protocols
// Detection priority: SD-WAN vendor ports > Protocol signatures > Generic VPN patterns
func (t *TunnelAnalyzer) Analyze(packet gopacket.Packet, state *models.AnalysisState, report *models.TriageReport) {
	ipInfo := ExtractIPInfo(packet)
	if ipInfo == nil {
		return
	}

	timestamp := packet.Metadata().Timestamp

	// Check for GRE (protocol 47)
	if greLayer := packet.Layer(layers.LayerTypeGRE); greLayer != nil {
		t.analyzeGRE(packet, greLayer.(*layers.GRE), ipInfo, timestamp)
		return
	}

	// Check for IPsec ESP (protocol 50) - could be SD-WAN or standalone IPsec
	if espLayer := packet.Layer(layers.LayerTypeIPSecESP); espLayer != nil {
		t.analyzeIPSecWithContext(ipInfo, "ESP", timestamp, uint64(len(packet.Data())), state)
		return
	}
	// Check for IPsec AH (protocol 51)
	if ahLayer := packet.Layer(layers.LayerTypeIPSecAH); ahLayer != nil {
		t.analyzeIPSec(ipInfo, "AH", timestamp, uint64(len(packet.Data())))
		return
	}

	// Check UDP-based tunnels with SD-WAN vendor priority
	if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp := udpLayer.(*layers.UDP)
		srcPort := uint16(udp.SrcPort)
		dstPort := uint16(udp.DstPort)
		payload := udp.Payload

		// ============================================================
		// PRIORITY 1: SD-WAN Vendor-Specific Ports (Highest Confidence)
		// ============================================================

		// Cisco SD-WAN (Viptela) - UDP 12346 is the signature
		if dstPort == CiscoSDWANDataPort || srcPort == CiscoSDWANDataPort {
			t.analyzeSDWANTunnel(SDWANVendorCisco, "Data Plane", ipInfo, srcPort, dstPort, timestamp, uint64(len(payload)))
			return
		}
		if dstPort == CiscoSDWANControlPort || srcPort == CiscoSDWANControlPort {
			t.analyzeSDWANTunnel(SDWANVendorCisco, "Control Plane", ipInfo, srcPort, dstPort, timestamp, uint64(len(payload)))
			return
		}
		if dstPort == CiscoSDWANNATPort || srcPort == CiscoSDWANNATPort {
			t.analyzeSDWANTunnel(SDWANVendorCisco, "NAT Traversal", ipInfo, srcPort, dstPort, timestamp, uint64(len(payload)))
			return
		}

		// VMware Velocloud - UDP 2426 is the signature
		if dstPort == VelocloudVCMPPort || srcPort == VelocloudVCMPPort {
			t.analyzeSDWANTunnel(SDWANVendorVelocloud, "VCMP Tunnel", ipInfo, srcPort, dstPort, timestamp, uint64(len(payload)))
			return
		}

		// Fortinet SD-WAN - UDP 541 is the signature
		if dstPort == FortinetSDWANPort || srcPort == FortinetSDWANPort {
			t.analyzeSDWANTunnel(SDWANVendorFortinet, "Data/Control", ipInfo, srcPort, dstPort, timestamp, uint64(len(payload)))
			return
		}

		// IPsec NAT-T (UDP 4500) - Aruba/Palo Alto/Zscaler SD-WAN
		if dstPort == IPsecNATTPort || srcPort == IPsecNATTPort {
			t.analyzeIPsecNATT(payload, ipInfo, srcPort, dstPort, timestamp, state)
			return
		}

		// IKE (UDP 500) - IPsec key exchange
		if dstPort == IPsecIKEPort || srcPort == IPsecIKEPort {
			t.analyzeIKE(payload, ipInfo, srcPort, dstPort, timestamp)
			return
		}

		// ============================================================
		// PRIORITY 2: Standard Tunnel Protocols
		// ============================================================

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

		// ============================================================
		// PRIORITY 3: VPN Detection (with strict exclusions)
		// ============================================================

		// Skip VPN detection for excluded services (DNS, NTP, etc.)
		if t.isExcludedFromVPNDetection(ipInfo, srcPort, dstPort) {
			return
		}

		// OpenVPN - Only on standard port 1194
		if dstPort == OpenVPNPort || srcPort == OpenVPNPort {
			if t.isOpenVPNPacket(payload) {
				t.analyzeOpenVPN(payload, ipInfo, srcPort, dstPort, timestamp)
				return
			}
		}

		// WireGuard - Only on standard port 51820
		if dstPort == WireGuardPort || srcPort == WireGuardPort {
			if t.isWireGuardPacket(payload) {
				t.analyzeWireGuard(payload, ipInfo, srcPort, dstPort, timestamp)
				return
			}
		}

		// NOTE: Removed non-standard port DPI detection to prevent false positives
		// OpenVPN/WireGuard on non-standard ports requires explicit configuration
	}

	// Check TCP for SD-WAN control plane
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp := tcpLayer.(*layers.TCP)
		srcPort := uint16(tcp.SrcPort)
		dstPort := uint16(tcp.DstPort)

		// Cisco SD-WAN control plane (TCP 23456)
		if dstPort == CiscoSDWANControlPort || srcPort == CiscoSDWANControlPort {
			t.analyzeSDWANTunnel(SDWANVendorCisco, "Control Plane (TCP)", ipInfo, srcPort, dstPort, timestamp, uint64(len(tcp.Payload)))
			return
		}

		// Fortinet SD-WAN control (TCP 541)
		if dstPort == FortinetSDWANPort || srcPort == FortinetSDWANPort {
			t.analyzeSDWANTunnel(SDWANVendorFortinet, "Control Plane (TCP)", ipInfo, srcPort, dstPort, timestamp, uint64(len(tcp.Payload)))
			return
		}
	}

	// Check for MPLS
	if mplsLayer := packet.Layer(layers.LayerTypeMPLS); mplsLayer != nil {
		t.analyzeMPLS(mplsLayer.(*layers.MPLS), ipInfo, timestamp, uint64(len(packet.Data())))
	}
}

// analyzeSDWANTunnel records SD-WAN vendor-specific tunnel traffic
func (t *TunnelAnalyzer) analyzeSDWANTunnel(vendor, tunnelFunction string, ipInfo *PacketIPInfo, srcPort, dstPort uint16, timestamp time.Time, byteCount uint64) {
	tunnelType := fmt.Sprintf("%s %s", vendor, tunnelFunction)
	key := fmt.Sprintf("sdwan-%s-%s-%s-%d-%d", vendor, ipInfo.SrcIP, ipInfo.DstIP, srcPort, dstPort)

	if tunnel, exists := t.tunnels[key]; exists {
		tunnel.LastSeen = timestamp
		tunnel.PacketCount++
		tunnel.ByteCount += byteCount
	} else {
		// Generate Wireshark filter for this tunnel
		wiresharkFilter := t.generateSDWANWiresharkFilter(vendor, srcPort, dstPort)

		t.tunnels[key] = &TunnelInfo{
			Type:            tunnelType,
			SrcIP:           ipInfo.SrcIP,
			DstIP:           ipInfo.DstIP,
			SrcPort:         srcPort,
			DstPort:         dstPort,
			FirstSeen:       timestamp,
			LastSeen:        timestamp,
			PacketCount:     1,
			ByteCount:       byteCount,
			InnerProto:      "Encrypted",
			DetectionMethod: "Port-based",
			Confidence:      VPNConfidenceHigh,
			SDWANPath:       wiresharkFilter,
		}
	}
}

// generateSDWANWiresharkFilter generates a Wireshark filter for the SD-WAN tunnel
func (t *TunnelAnalyzer) generateSDWANWiresharkFilter(vendor string, srcPort, dstPort uint16) string {
	switch vendor {
	case SDWANVendorCisco:
		return fmt.Sprintf("udp.port == %d || udp.port == %d || tcp.port == %d", CiscoSDWANDataPort, CiscoSDWANControlPort, CiscoSDWANControlPort)
	case SDWANVendorVelocloud:
		return fmt.Sprintf("udp.port == %d", VelocloudVCMPPort)
	case SDWANVendorFortinet:
		return fmt.Sprintf("udp.port == %d || tcp.port == %d", FortinetSDWANPort, FortinetSDWANPort)
	case SDWANVendorAruba, SDWANVendorPaloAlto, SDWANVendorZscaler, SDWANVendorGeneric:
		return "udp.port == 4500 || udp.port == 500 || esp"
	default:
		return fmt.Sprintf("udp.port == %d", dstPort)
	}
}

// analyzeIPsecNATT analyzes IPsec NAT-Traversal traffic (UDP 4500)
// This is commonly used by Aruba, Palo Alto, and Zscaler SD-WAN
func (t *TunnelAnalyzer) analyzeIPsecNATT(payload []byte, ipInfo *PacketIPInfo, srcPort, dstPort uint16, timestamp time.Time, state *models.AnalysisState) {
	// IPsec NAT-T packets start with 4 zero bytes (Non-ESP marker) or ESP header
	tunnelType := "IPsec NAT-T"

	// Check if this IP has been seen with ESP traffic (indicates SD-WAN)
	espKey := fmt.Sprintf("ipsec-ESP-%s-%s", ipInfo.SrcIP, ipInfo.DstIP)
	espKeyReverse := fmt.Sprintf("ipsec-ESP-%s-%s", ipInfo.DstIP, ipInfo.SrcIP)
	if _, hasESP := t.tunnels[espKey]; hasESP {
		tunnelType = "IPsec SD-WAN NAT-T"
	} else if _, hasESP := t.tunnels[espKeyReverse]; hasESP {
		tunnelType = "IPsec SD-WAN NAT-T"
	}

	key := fmt.Sprintf("ipsec-natt-%s-%s", ipInfo.SrcIP, ipInfo.DstIP)
	if tunnel, exists := t.tunnels[key]; exists {
		tunnel.LastSeen = timestamp
		tunnel.PacketCount++
		tunnel.ByteCount += uint64(len(payload))
	} else {
		t.tunnels[key] = &TunnelInfo{
			Type:            tunnelType,
			SrcIP:           ipInfo.SrcIP,
			DstIP:           ipInfo.DstIP,
			SrcPort:         srcPort,
			DstPort:         dstPort,
			FirstSeen:       timestamp,
			LastSeen:        timestamp,
			PacketCount:     1,
			ByteCount:       uint64(len(payload)),
			InnerProto:      "Encrypted",
			DetectionMethod: "Port-based",
			Confidence:      VPNConfidenceHigh,
			SDWANPath:       fmt.Sprintf("udp.port == 4500 && ip.addr == %s", ipInfo.DstIP),
		}
		// Track for correlation with ESP
		t.trackIPsecSession(ipInfo.SrcIP, ipInfo.DstIP, "NAT-T")
	}
}

// analyzeIKE analyzes IKE (Internet Key Exchange) traffic for IPsec
func (t *TunnelAnalyzer) analyzeIKE(payload []byte, ipInfo *PacketIPInfo, srcPort, dstPort uint16, timestamp time.Time) {
	key := fmt.Sprintf("ike-%s-%s", ipInfo.SrcIP, ipInfo.DstIP)
	if tunnel, exists := t.tunnels[key]; exists {
		tunnel.LastSeen = timestamp
		tunnel.PacketCount++
		tunnel.ByteCount += uint64(len(payload))
	} else {
		t.tunnels[key] = &TunnelInfo{
			Type:            "IKE (IPsec Key Exchange)",
			SrcIP:           ipInfo.SrcIP,
			DstIP:           ipInfo.DstIP,
			SrcPort:         srcPort,
			DstPort:         dstPort,
			FirstSeen:       timestamp,
			LastSeen:        timestamp,
			PacketCount:     1,
			ByteCount:       uint64(len(payload)),
			InnerProto:      "IKE",
			DetectionMethod: "Port-based",
			Confidence:      VPNConfidenceHigh,
			SDWANPath:       fmt.Sprintf("udp.port == 500 && ip.addr == %s", ipInfo.DstIP),
		}
		// Track for correlation with ESP/NAT-T
		t.trackIPsecSession(ipInfo.SrcIP, ipInfo.DstIP, "IKE")
	}
}

// analyzeIPSecWithContext analyzes ESP traffic with SD-WAN context
func (t *TunnelAnalyzer) analyzeIPSecWithContext(ipInfo *PacketIPInfo, protocol string, timestamp time.Time, byteCount uint64, state *models.AnalysisState) {
	// Check if we have IKE or NAT-T traffic for this IP pair (indicates SD-WAN)
	ikeKey := fmt.Sprintf("ike-%s-%s", ipInfo.SrcIP, ipInfo.DstIP)
	ikeKeyReverse := fmt.Sprintf("ike-%s-%s", ipInfo.DstIP, ipInfo.SrcIP)
	nattKey := fmt.Sprintf("ipsec-natt-%s-%s", ipInfo.SrcIP, ipInfo.DstIP)
	nattKeyReverse := fmt.Sprintf("ipsec-natt-%s-%s", ipInfo.DstIP, ipInfo.SrcIP)

	tunnelType := "IPsec " + protocol
	if _, hasIKE := t.tunnels[ikeKey]; hasIKE {
		tunnelType = "IPsec SD-WAN " + protocol
	} else if _, hasIKE := t.tunnels[ikeKeyReverse]; hasIKE {
		tunnelType = "IPsec SD-WAN " + protocol
	} else if _, hasNATT := t.tunnels[nattKey]; hasNATT {
		tunnelType = "IPsec SD-WAN " + protocol
	} else if _, hasNATT := t.tunnels[nattKeyReverse]; hasNATT {
		tunnelType = "IPsec SD-WAN " + protocol
	}

	key := fmt.Sprintf("ipsec-%s-%s-%s", protocol, ipInfo.SrcIP, ipInfo.DstIP)
	if tunnel, exists := t.tunnels[key]; exists {
		tunnel.LastSeen = timestamp
		tunnel.PacketCount++
		tunnel.ByteCount += byteCount
		// Update type if we now have context
		if tunnelType != tunnel.Type && tunnelType != "IPsec "+protocol {
			tunnel.Type = tunnelType
		}
	} else {
		t.tunnels[key] = &TunnelInfo{
			Type:            tunnelType,
			SrcIP:           ipInfo.SrcIP,
			DstIP:           ipInfo.DstIP,
			FirstSeen:       timestamp,
			LastSeen:        timestamp,
			PacketCount:     1,
			ByteCount:       byteCount,
			InnerProto:      "Encrypted",
			DetectionMethod: "Protocol",
			Confidence:      VPNConfidenceHigh,
			SDWANPath:       fmt.Sprintf("esp && ip.addr == %s", ipInfo.DstIP),
		}
	}
}

// trackIPsecSession tracks IPsec session components for correlation
func (t *TunnelAnalyzer) trackIPsecSession(srcIP, dstIP, component string) {
	sessionKey := fmt.Sprintf("ipsec-session-%s-%s", srcIP, dstIP)
	if session, exists := t.vpnSessions[sessionKey]; exists {
		switch component {
		case "IKE":
			session.ControlPackets++
		case "NAT-T":
			session.DataPackets++
		case "ESP":
			session.DataPackets++
		}
		session.LastSeen = time.Now()
	} else {
		t.vpnSessions[sessionKey] = &VPNSessionTracker{
			FirstSeen: time.Now(),
			LastSeen:  time.Now(),
		}
		switch component {
		case "IKE":
			t.vpnSessions[sessionKey].ControlPackets = 1
		case "NAT-T", "ESP":
			t.vpnSessions[sessionKey].DataPackets = 1
		}
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
// OpenVPN Deep Packet Inspection (Strict Validation)
// ============================================================================

// isOpenVPNPacketStrict performs strict DPI validation for OpenVPN on non-standard ports
// This requires multiple validation checks to prevent false positives
func (t *TunnelAnalyzer) isOpenVPNPacketStrict(payload []byte, srcPort, dstPort uint16) bool {
	// Minimum OpenVPN packet size is much larger than simple checks
	// Control packets: 1 (opcode) + 8 (session_id) + 1 (packet_id_array_len) + 4 (packet_id) = 14 bytes minimum
	// Data packets: 1 (opcode) + 4 (peer_id for v2) + encrypted payload
	if len(payload) < 14 {
		return false
	}

	opcode := (payload[0] >> 3) & 0x1F
	keyID := payload[0] & 0x07

	// Key ID should typically be 0-7, but most commonly 0
	if keyID > 7 {
		return false
	}

	// Only accept handshake packets for non-standard port detection
	// This prevents false positives from random data packets
	switch opcode {
	case OpenVPNControlHardResetClientV2:
		// P_CONTROL_HARD_RESET_CLIENT_V2 (opcode 7)
		// Expected packet structure: opcode(1) + session_id(8) + packet_id_array_len(1) + packet_id(4) + ...
		// Minimum size ~42 bytes for a valid handshake init
		if len(payload) < 42 {
			return false
		}
		// Session ID should not be all zeros or all ones (unlikely for real traffic)
		sessionID := payload[1:9]
		allZeros := true
		allOnes := true
		for _, b := range sessionID {
			if b != 0x00 {
				allZeros = false
			}
			if b != 0xFF {
				allOnes = false
			}
		}
		if allZeros || allOnes {
			return false
		}
		// Packet ID array length should be 0 for initial handshake
		if payload[9] != 0 {
			return false
		}
		return true

	case OpenVPNControlHardResetServerV2:
		// P_CONTROL_HARD_RESET_SERVER_V2 (opcode 8)
		// Similar validation to client
		if len(payload) < 42 {
			return false
		}
		sessionID := payload[1:9]
		allZeros := true
		for _, b := range sessionID {
			if b != 0x00 {
				allZeros = false
				break
			}
		}
		if allZeros {
			return false
		}
		return true

	default:
		// For non-standard ports, only accept handshake packets
		// Data packets on non-standard ports are too prone to false positives
		return false
	}
}

// isOpenVPNPacket performs basic DPI check (used for standard port detection)
func (t *TunnelAnalyzer) isOpenVPNPacket(payload []byte) bool {
	if len(payload) < 10 {
		return false
	}

	opcode := (payload[0] >> 3) & 0x1F
	keyID := payload[0] & 0x07

	if keyID > 7 {
		return false
	}

	// Valid OpenVPN opcodes are 1-9
	if opcode >= 1 && opcode <= 9 {
		switch opcode {
		case OpenVPNControlHardResetClientV2, OpenVPNControlHardResetServerV2:
			// Control packets need session ID validation
			if len(payload) >= 14 {
				// Check session ID is not all zeros
				sessionID := payload[1:9]
				for _, b := range sessionID {
					if b != 0x00 {
						return true
					}
				}
			}
		case OpenVPNControlHardResetClientV1, OpenVPNControlHardResetServerV1:
			if len(payload) >= 14 {
				return true
			}
		case OpenVPNControlV1, OpenVPNAckV1, OpenVPNControlSoftResetV1:
			if len(payload) >= 14 {
				return true
			}
		case OpenVPNDataV1, OpenVPNDataV2:
			// Data packets need minimum encrypted payload
			if len(payload) >= 28 {
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
// WireGuard Deep Packet Inspection (Strict Validation)
// ============================================================================

// isWireGuardPacketStrict performs strict DPI validation for WireGuard on non-standard ports
// Only accepts handshake packets to prevent false positives
func (t *TunnelAnalyzer) isWireGuardPacketStrict(payload []byte, srcPort, dstPort uint16) bool {
	if len(payload) < 32 {
		return false
	}

	// WireGuard message type is first 4 bytes (little-endian)
	msgType := uint32(payload[0]) | uint32(payload[1])<<8 | uint32(payload[2])<<16 | uint32(payload[3])<<24

	// For non-standard ports, only accept handshake packets with exact sizes
	// This prevents false positives from random data
	switch msgType {
	case WireGuardHandshakeInitiation:
		// Handshake initiation MUST be exactly 148 bytes
		if len(payload) != 148 {
			return false
		}
		// Additional validation: sender index should not be 0
		senderIndex := uint32(payload[4]) | uint32(payload[5])<<8 | uint32(payload[6])<<16 | uint32(payload[7])<<24
		if senderIndex == 0 {
			return false
		}
		// Check that reserved bytes (bytes 116-147) contain the MAC values
		// MACs should not be all zeros in a valid handshake
		mac1AllZeros := true
		for i := 116; i < 132; i++ {
			if payload[i] != 0 {
				mac1AllZeros = false
				break
			}
		}
		if mac1AllZeros {
			return false
		}
		return true

	case WireGuardHandshakeResponse:
		// Handshake response MUST be exactly 92 bytes
		if len(payload) != 92 {
			return false
		}
		// Validate sender index is not 0
		senderIndex := uint32(payload[4]) | uint32(payload[5])<<8 | uint32(payload[6])<<16 | uint32(payload[7])<<24
		if senderIndex == 0 {
			return false
		}
		return true

	default:
		// For non-standard ports, don't accept transport data or cookie packets
		// They're too prone to false positives
		return false
	}
}

// isWireGuardPacket performs basic DPI check (used for standard port detection)
func (t *TunnelAnalyzer) isWireGuardPacket(payload []byte) bool {
	if len(payload) < 32 {
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
		// Additional check: counter should be reasonable (not all zeros or all ones)
		if len(payload) >= 32 {
			counter := uint64(payload[8]) | uint64(payload[9])<<8 | uint64(payload[10])<<16 |
				uint64(payload[11])<<24 | uint64(payload[12])<<32 | uint64(payload[13])<<40 |
				uint64(payload[14])<<48 | uint64(payload[15])<<56
			// Counter of 0 is valid for first packet, but very high values are suspicious
			if counter > 0xFFFFFFFF {
				return false
			}
			return true
		}
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
