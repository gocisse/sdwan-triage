package detector

import (
	"strings"
	"time"

	"github.com/gocisse/sdwan-triage/pkg/models"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// SD-WAN vendor signatures
var sdwanVendorSignatures = map[string]SDWANVendorInfo{
	// Cisco SD-WAN (Viptela)
	"viptela": {
		Name:        "Cisco SD-WAN (Viptela)",
		Ports:       []uint16{12346, 12366, 12386, 12406, 12426},
		SNIPatterns: []string{"vmanage", "vbond", "vsmart", "vedge"},
		UserAgents:  []string{"vManage"},
	},
	// VMware SD-WAN (VeloCloud)
	"velocloud": {
		Name:        "VMware SD-WAN (VeloCloud)",
		Ports:       []uint16{2426, 443},
		SNIPatterns: []string{"velocloud", "vmware-sdwan"},
		UserAgents:  []string{"VeloCloud"},
	},
	// Fortinet SD-WAN
	"fortinet": {
		Name:        "Fortinet SD-WAN",
		Ports:       []uint16{541, 703, 8008, 8010},
		SNIPatterns: []string{"fortigate", "fortimanager", "fortios"},
		UserAgents:  []string{"FortiGate", "FortiOS"},
	},
	// Palo Alto Prisma SD-WAN
	"prisma": {
		Name:        "Palo Alto Prisma SD-WAN",
		Ports:       []uint16{4443, 4500},
		SNIPatterns: []string{"prismasdwan", "cloudgenix", "paloaltonetworks"},
		UserAgents:  []string{"Prisma", "CloudGenix"},
	},
	// Silver Peak (Aruba)
	"silverpeak": {
		Name:        "Silver Peak (Aruba) SD-WAN",
		Ports:       []uint16{4163, 4164},
		SNIPatterns: []string{"silverpeak", "aruba-edgeconnect"},
		UserAgents:  []string{"Silver Peak", "EdgeConnect"},
	},
	// Citrix SD-WAN
	"citrix": {
		Name:        "Citrix SD-WAN",
		Ports:       []uint16{4980, 4981},
		SNIPatterns: []string{"citrix", "netscaler"},
		UserAgents:  []string{"Citrix SD-WAN", "NetScaler"},
	},
	// Versa Networks
	"versa": {
		Name:        "Versa Networks SD-WAN",
		Ports:       []uint16{4566, 4567},
		SNIPatterns: []string{"versa-networks", "versa-director"},
		UserAgents:  []string{"Versa"},
	},
}

// SDWANVendorInfo contains vendor identification patterns
type SDWANVendorInfo struct {
	Name        string
	Ports       []uint16
	SNIPatterns []string
	UserAgents  []string
}

// SDWANVendorAnalyzer handles SD-WAN vendor detection
type SDWANVendorAnalyzer struct {
	detectedVendors map[string]*SDWANDetection
}

// SDWANDetection represents a detected SD-WAN vendor
type SDWANDetection struct {
	Vendor      string
	Confidence  string
	DetectedBy  string
	FirstSeen   time.Time
	LastSeen    time.Time
	PacketCount int
	FlowKeys    []string
}

// NewSDWANVendorAnalyzer creates a new SD-WAN vendor analyzer
func NewSDWANVendorAnalyzer() *SDWANVendorAnalyzer {
	return &SDWANVendorAnalyzer{
		detectedVendors: make(map[string]*SDWANDetection),
	}
}

// Analyze processes packets for SD-WAN vendor signatures
func (s *SDWANVendorAnalyzer) Analyze(packet gopacket.Packet, state *models.AnalysisState, report *models.TriageReport) {
	timestamp := packet.Metadata().Timestamp

	// Check TCP ports
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp := tcpLayer.(*layers.TCP)
		srcPort := uint16(tcp.SrcPort)
		dstPort := uint16(tcp.DstPort)

		s.checkPort(srcPort, timestamp, state)
		s.checkPort(dstPort, timestamp, state)

		// Check for HTTP User-Agent in payload
		if len(tcp.Payload) > 0 {
			s.checkHTTPPayload(tcp.Payload, timestamp)
		}
	}

	// Check UDP ports
	if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp := udpLayer.(*layers.UDP)
		srcPort := uint16(udp.SrcPort)
		dstPort := uint16(udp.DstPort)

		s.checkPort(srcPort, timestamp, state)
		s.checkPort(dstPort, timestamp, state)
	}

	// Check TLS SNI from cache
	s.checkSNI(state, timestamp)
}

func (s *SDWANVendorAnalyzer) checkPort(port uint16, timestamp time.Time, state *models.AnalysisState) {
	for vendorKey, info := range sdwanVendorSignatures {
		for _, vendorPort := range info.Ports {
			if port == vendorPort {
				s.recordDetection(vendorKey, info.Name, "Port Match", timestamp)
				return
			}
		}
	}
}

func (s *SDWANVendorAnalyzer) checkSNI(state *models.AnalysisState, timestamp time.Time) {
	for _, sni := range state.TLSSNICache {
		sniLower := strings.ToLower(sni)
		for vendorKey, info := range sdwanVendorSignatures {
			for _, pattern := range info.SNIPatterns {
				if strings.Contains(sniLower, pattern) {
					s.recordDetection(vendorKey, info.Name, "TLS SNI", timestamp)
					return
				}
			}
		}
	}
}

func (s *SDWANVendorAnalyzer) checkHTTPPayload(payload []byte, timestamp time.Time) {
	payloadStr := string(payload)

	// Check for User-Agent header
	if strings.Contains(payloadStr, "User-Agent:") {
		for vendorKey, info := range sdwanVendorSignatures {
			for _, ua := range info.UserAgents {
				if strings.Contains(payloadStr, ua) {
					s.recordDetection(vendorKey, info.Name, "HTTP User-Agent", timestamp)
					return
				}
			}
		}
	}
}

func (s *SDWANVendorAnalyzer) recordDetection(vendorKey, vendorName, detectedBy string, timestamp time.Time) {
	if detection, exists := s.detectedVendors[vendorKey]; exists {
		detection.LastSeen = timestamp
		detection.PacketCount++
		// Upgrade confidence if detected by multiple methods
		if detection.DetectedBy != detectedBy {
			detection.Confidence = "High"
			detection.DetectedBy = detection.DetectedBy + ", " + detectedBy
		}
	} else {
		s.detectedVendors[vendorKey] = &SDWANDetection{
			Vendor:      vendorName,
			Confidence:  "Medium",
			DetectedBy:  detectedBy,
			FirstSeen:   timestamp,
			LastSeen:    timestamp,
			PacketCount: 1,
		}
	}
}

// GetDetectedVendors returns all detected SD-WAN vendors
func (s *SDWANVendorAnalyzer) GetDetectedVendors() map[string]*SDWANDetection {
	return s.detectedVendors
}

// GetPrimaryVendor returns the most likely SD-WAN vendor
func (s *SDWANVendorAnalyzer) GetPrimaryVendor() *SDWANDetection {
	var primary *SDWANDetection
	maxPackets := 0

	for _, detection := range s.detectedVendors {
		if detection.PacketCount > maxPackets {
			maxPackets = detection.PacketCount
			primary = detection
		}
	}

	return primary
}
