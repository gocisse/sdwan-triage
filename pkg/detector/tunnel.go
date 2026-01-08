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

		// OpenVPN
		if dstPort == OpenVPNPort || srcPort == OpenVPNPort {
			t.recordTunnel("OpenVPN", ipInfo, srcPort, dstPort, 0, timestamp, uint64(len(payload)))
			return
		}

		// WireGuard
		if dstPort == WireGuardPort || srcPort == WireGuardPort {
			t.recordTunnel("WireGuard", ipInfo, srcPort, dstPort, 0, timestamp, uint64(len(payload)))
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
