package detector

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/gocisse/sdwan-triage/pkg/models"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// ─── Evidence strength categories ──────────────────────────────────────
// Strong evidence: definitively identifies SD-WAN overlay traffic.
// Weak evidence: could be generic infrastructure (e.g., any HTTPS on port 443).
// A vendor is only reported if it has at least one strong evidence hit.
const (
	evidenceStrong = "strong"
	evidenceWeak   = "weak"
)

// SD-WAN vendor signatures.
//
// Port classification:
//   - DedicatedPorts: ports unique to this vendor's SD-WAN overlay / control plane.
//     A match here is STRONG evidence (e.g., UDP 12346 = Viptela, UDP 2426 = VCMP).
//   - SharedPorts: ports that may carry SD-WAN traffic but are also used by generic
//     services (HTTPS 443, IPsec NAT-T 4500, etc.). A match here is WEAK evidence
//     and will be suppressed unless corroborated by SNI, User-Agent, or payload sig.
var sdwanVendorSignatures = map[string]SDWANVendorInfo{
	// Cisco SD-WAN (Viptela)
	"viptela": {
		Name:           "Cisco SD-WAN (Viptela)",
		DedicatedPorts: []uint16{12346, 12366, 12386, 12406, 12426},
		SharedPorts:    []uint16{},
		SNIPatterns:    []string{"vmanage", "vbond", "vsmart", "vedge"},
		UserAgents:     []string{"vManage"},
		PayloadSignatures: []PayloadSignature{
			// Viptela DTLS overlay: content type 0x16 + DTLS 1.2 version 0xFEFD
			{Description: "Viptela DTLS Overlay", Offset: 0, Magic: []byte{0x16, 0xFE, 0xFD}},
			// Viptela OMP (Overlay Management Protocol) header magic
			{Description: "Viptela OMP Header", Offset: 0, Magic: []byte{0x00, 0x01, 0x00, 0x01}},
			// Viptela BFD keepalive on control port
			{Description: "Viptela BFD Keepalive", Offset: 0, Magic: []byte{0x20, 0xC0}},
		},
	},
	// VMware SD-WAN (VeloCloud)
	// NOTE: Port 443 is intentionally NOT listed. Generic HTTPS to any server
	// on 443 was causing massive false positives on LAN captures. VeloCloud
	// overlay traffic uses UDP 2426 (VCMP). Management traffic to VCO on 443
	// is only detected via SNI matching ("velocloud", "vmware-sdwan").
	"velocloud": {
		Name:           "VMware SD-WAN (VeloCloud)",
		DedicatedPorts: []uint16{2426},
		SharedPorts:    []uint16{},
		SNIPatterns:    []string{"velocloud", "vmware-sdwan"},
		UserAgents:     []string{"VeloCloud"},
		PayloadSignatures: []PayloadSignature{
			// VeloCloud VCMP (VeloCloud Management Protocol) header
			{Description: "VeloCloud VCMP Header", Offset: 0, Magic: []byte{0x56, 0x43, 0x4D, 0x50}}, // "VCMP"
			// VeloCloud proprietary encapsulation marker
			{Description: "VeloCloud Encap Marker", Offset: 0, Magic: []byte{0xAC, 0xED, 0x00, 0x05}},
		},
	},
	// Fortinet SD-WAN
	// NOTE: Port 541 (UUCP-rlogin / FortiGate HA heartbeat) and 703 (FGFM
	// management) are firewall infrastructure ports, NOT SD-WAN overlay.
	// They appear as ephemeral source ports on non-Fortinet devices and cause
	// false positives. Only 8008/8010 (FortiOS SD-WAN health probes) are dedicated.
	"fortinet": {
		Name:           "Fortinet SD-WAN",
		DedicatedPorts: []uint16{8008, 8010},
		SharedPorts:    []uint16{541, 703},
		SNIPatterns:    []string{"fortigate", "fortimanager", "fortios"},
		UserAgents:     []string{"FortiGate", "FortiOS"},
		PayloadSignatures: []PayloadSignature{
			// FortiOS FGCP (FortiGate Cluster Protocol) heartbeat
			{Description: "FortiGate FGCP Heartbeat", Offset: 0, Magic: []byte{0x46, 0x47, 0x43, 0x50}}, // "FGCP"
			// FortiLink protocol header
			{Description: "FortiLink Header", Offset: 0, Magic: []byte{0x46, 0x4C, 0x4E, 0x4B}}, // "FLNK"
			// FortiOS SD-WAN health-check probe (proprietary UDP)
			{Description: "FortiOS Health Probe", Offset: 0, Magic: []byte{0x00, 0x09, 0x0F, 0x09}},
		},
	},
	// Palo Alto Prisma SD-WAN
	"prisma": {
		Name:           "Palo Alto Prisma SD-WAN",
		DedicatedPorts: []uint16{4443},
		SharedPorts:    []uint16{4500},
		SNIPatterns:    []string{"prismasdwan", "cloudgenix", "paloaltonetworks"},
		UserAgents:     []string{"Prisma", "CloudGenix"},
		// NOTE: Removed the generic 0x00000000 signature — four zero bytes appear
		// in many non-SD-WAN protocols (IPsec keepalive, NTP, padding, etc.).
		PayloadSignatures: []PayloadSignature{},
	},
	// Silver Peak (Aruba)
	"silverpeak": {
		Name:           "Silver Peak (Aruba) SD-WAN",
		DedicatedPorts: []uint16{4163, 4164},
		SharedPorts:    []uint16{},
		SNIPatterns:    []string{"silverpeak", "aruba-edgeconnect"},
		UserAgents:     []string{"Silver Peak", "EdgeConnect"},
		PayloadSignatures: []PayloadSignature{
			// Silver Peak tunnel encapsulation header
			{Description: "Silver Peak Tunnel", Offset: 0, Magic: []byte{0x53, 0x50, 0x45, 0x43}}, // "SPEC"
		},
	},
	// Citrix SD-WAN
	"citrix": {
		Name:           "Citrix SD-WAN",
		DedicatedPorts: []uint16{4980, 4981},
		SharedPorts:    []uint16{},
		SNIPatterns:    []string{"citrix", "netscaler"},
		UserAgents:     []string{"Citrix SD-WAN", "NetScaler"},
	},
	// Versa Networks
	"versa": {
		Name:           "Versa Networks SD-WAN",
		DedicatedPorts: []uint16{4566, 4567},
		SharedPorts:    []uint16{},
		SNIPatterns:    []string{"versa-networks", "versa-director"},
		UserAgents:     []string{"Versa"},
		PayloadSignatures: []PayloadSignature{
			// Versa FlexVNF encapsulation
			{Description: "Versa FlexVNF Encap", Offset: 0, Magic: []byte{0x56, 0x52, 0x53, 0x41}}, // "VRSA"
		},
	},
}

// PayloadSignature describes a byte-level signature in packet payloads.
type PayloadSignature struct {
	Description string // Human-readable description of what this signature matches
	Offset      int    // Byte offset to check (-1 = scan anywhere in payload)
	Magic       []byte // Byte sequence to match
}

// SDWANVendorInfo contains vendor identification patterns.
type SDWANVendorInfo struct {
	Name              string
	DedicatedPorts    []uint16           // Ports unique to this vendor's SD-WAN — strong evidence
	SharedPorts       []uint16           // Multi-purpose ports (443, 4500) — weak, needs corroboration
	SNIPatterns       []string           // TLS/DTLS SNI substrings — strong evidence
	UserAgents        []string           // HTTP User-Agent substrings — strong evidence
	PayloadSignatures []PayloadSignature // Proprietary header / magic byte signatures — strong evidence
}

// SDWANVendorAnalyzer handles SD-WAN vendor detection.
type SDWANVendorAnalyzer struct {
	detectedVendors map[string]*SDWANDetection
}

// SDWANDetection represents a detected SD-WAN vendor.
type SDWANDetection struct {
	Vendor      string
	Confidence  string
	DetectedBy  string
	FirstSeen   time.Time
	LastSeen    time.Time
	PacketCount int
	FlowKeys    []string
	// hasStrongEvidence is true if at least one detection came from a
	// dedicated port, payload signature, SNI, or User-Agent match.
	hasStrongEvidence bool
}

// NewSDWANVendorAnalyzer creates a new SD-WAN vendor analyzer.
func NewSDWANVendorAnalyzer() *SDWANVendorAnalyzer {
	return &SDWANVendorAnalyzer{
		detectedVendors: make(map[string]*SDWANDetection),
	}
}

// Analyze processes a single packet for SD-WAN vendor signatures.
func (s *SDWANVendorAnalyzer) Analyze(packet gopacket.Packet, state *models.AnalysisState, report *models.TriageReport) {
	timestamp := packet.Metadata().Timestamp

	// Check TCP
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp := tcpLayer.(*layers.TCP)
		srcPort := uint16(tcp.SrcPort)
		dstPort := uint16(tcp.DstPort)

		s.checkPort(srcPort, timestamp)
		s.checkPort(dstPort, timestamp)

		// Check for HTTP User-Agent in payload
		if len(tcp.Payload) > 0 {
			s.checkHTTPPayload(tcp.Payload, timestamp)
		}
	}

	// Check UDP — ports + deep payload inspection
	if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp := udpLayer.(*layers.UDP)
		srcPort := uint16(udp.SrcPort)
		dstPort := uint16(udp.DstPort)

		s.checkPort(srcPort, timestamp)
		s.checkPort(dstPort, timestamp)

		// Deep payload inspection for UDP flows on non-standard ports
		if len(udp.Payload) >= 4 && !isStandardPort(srcPort) && !isStandardPort(dstPort) {
			if vendor, sig := AnalyzePayload(udp.Payload); vendor != "" {
				detail := fmt.Sprintf("Payload Signature (%s)", sig)
				s.recordDetection(vendor, sdwanVendorSignatures[vendor].Name, detail, timestamp, evidenceStrong)
			}
		}
	}

	// Check TLS SNI from cache
	s.checkSNI(state, timestamp)
}

// checkPort tests a single port against all vendor signatures.
// Dedicated ports produce strong evidence; shared ports produce weak evidence.
func (s *SDWANVendorAnalyzer) checkPort(port uint16, timestamp time.Time) {
	for vendorKey, info := range sdwanVendorSignatures {
		for _, vp := range info.DedicatedPorts {
			if port == vp {
				s.recordDetection(vendorKey, info.Name, fmt.Sprintf("Dedicated Port %d", port), timestamp, evidenceStrong)
				return
			}
		}
		for _, vp := range info.SharedPorts {
			if port == vp {
				s.recordDetection(vendorKey, info.Name, fmt.Sprintf("Shared Port %d", port), timestamp, evidenceWeak)
				return
			}
		}
	}
}

func (s *SDWANVendorAnalyzer) checkSNI(state *models.AnalysisState, timestamp time.Time) {
	// Iterate over SNI cache using bounded cache accessor
	state.ForEachSNI(func(sni string) bool {
		sniLower := strings.ToLower(sni)
		for vendorKey, info := range sdwanVendorSignatures {
			for _, pattern := range info.SNIPatterns {
				if strings.Contains(sniLower, pattern) {
					s.recordDetection(vendorKey, info.Name, "TLS SNI", timestamp, evidenceStrong)
					return false // stop iteration
				}
			}
		}
		return true // continue iteration
	})
}

func (s *SDWANVendorAnalyzer) checkHTTPPayload(payload []byte, timestamp time.Time) {
	payloadStr := string(payload)

	// Check for User-Agent header
	if strings.Contains(payloadStr, "User-Agent:") {
		for vendorKey, info := range sdwanVendorSignatures {
			for _, ua := range info.UserAgents {
				if strings.Contains(payloadStr, ua) {
					s.recordDetection(vendorKey, info.Name, "HTTP User-Agent", timestamp, evidenceStrong)
					return
				}
			}
		}
	}
}

func (s *SDWANVendorAnalyzer) recordDetection(vendorKey, vendorName, detectedBy string, timestamp time.Time, strength string) {
	if detection, exists := s.detectedVendors[vendorKey]; exists {
		detection.LastSeen = timestamp
		detection.PacketCount++
		if strength == evidenceStrong {
			detection.hasStrongEvidence = true
		}
		// Upgrade confidence if detected by multiple methods
		if !strings.Contains(detection.DetectedBy, detectedBy) {
			detection.Confidence = "High"
			detection.DetectedBy = detection.DetectedBy + ", " + detectedBy
		}
	} else {
		s.detectedVendors[vendorKey] = &SDWANDetection{
			Vendor:            vendorName,
			Confidence:        "Medium",
			DetectedBy:        detectedBy,
			FirstSeen:         timestamp,
			LastSeen:          timestamp,
			PacketCount:       1,
			hasStrongEvidence: strength == evidenceStrong,
		}
	}
}

// Finalize prunes vendors that were detected only by weak evidence
// (e.g., shared port 443 with no corroborating SNI/payload/User-Agent).
// This MUST be called after all packets have been processed.
func (s *SDWANVendorAnalyzer) Finalize() {
	for key, det := range s.detectedVendors {
		if !det.hasStrongEvidence {
			delete(s.detectedVendors, key)
		}
	}
}

// GetDetectedVendors returns all detected SD-WAN vendors.
// Call Finalize() first to remove false positives.
func (s *SDWANVendorAnalyzer) GetDetectedVendors() map[string]*SDWANDetection {
	return s.detectedVendors
}

// isStandardPort returns true for well-known ports that are unlikely to carry SD-WAN overlay traffic.
func isStandardPort(port uint16) bool {
	switch port {
	case 53, 80, 443, 8080, 8443, 22, 23, 25, 110, 143, 993, 995, 3389:
		return true
	}
	return false
}

// AnalyzePayload inspects raw payload bytes for known SD-WAN proprietary headers.
// Returns the vendor key and matched signature description, or empty strings if no match.
// This function is exported so it can be called from the main processing loop for
// UDP flows on non-standard ports.
func AnalyzePayload(payload []byte) (vendorKey string, signatureDesc string) {
	if len(payload) < 2 {
		return "", ""
	}

	for vKey, info := range sdwanVendorSignatures {
		for _, sig := range info.PayloadSignatures {
			if matchPayloadSignature(payload, sig) {
				return vKey, sig.Description
			}
		}
	}

	// Heuristic: check for embedded TLS ClientHello with SD-WAN SNI inside UDP payload.
	// This catches DTLS-wrapped overlay tunnels where the SNI reveals the vendor.
	if sni := extractSNIFromDTLS(payload); sni != "" {
		sniLower := strings.ToLower(sni)
		for vKey, info := range sdwanVendorSignatures {
			for _, pattern := range info.SNIPatterns {
				if strings.Contains(sniLower, pattern) {
					return vKey, fmt.Sprintf("DTLS SNI: %s", sni)
				}
			}
		}
	}

	return "", ""
}

// matchPayloadSignature checks if payload matches a specific signature.
func matchPayloadSignature(payload []byte, sig PayloadSignature) bool {
	if sig.Offset >= 0 {
		// Fixed offset match
		if sig.Offset+len(sig.Magic) > len(payload) {
			return false
		}
		return bytes.Equal(payload[sig.Offset:sig.Offset+len(sig.Magic)], sig.Magic)
	}
	// Scan anywhere in payload
	return bytes.Contains(payload, sig.Magic)
}

// extractSNIFromDTLS attempts to extract the SNI from a DTLS ClientHello embedded in UDP payload.
// DTLS record: ContentType(1) + Version(2) + Epoch(2) + SeqNum(6) + Length(2) + Fragment
// Inside the fragment, the ClientHello contains extensions with SNI (type 0x0000).
func extractSNIFromDTLS(payload []byte) string {
	// Minimum DTLS record header: 13 bytes
	if len(payload) < 25 {
		return ""
	}

	// Check for DTLS Handshake content type (0x16) and DTLS version (0xFEFF=1.0 or 0xFEFD=1.2)
	if payload[0] != 0x16 {
		return ""
	}
	if !(payload[1] == 0xFE && (payload[2] == 0xFF || payload[2] == 0xFD)) {
		return ""
	}

	// Search for SNI extension pattern: type 0x00 0x00 followed by list length, name type 0x00 (host_name)
	// This is a best-effort heuristic scan rather than full DTLS parsing.
	for i := 13; i < len(payload)-5; i++ {
		// Look for SNI extension type (0x0000)
		if payload[i] == 0x00 && payload[i+1] == 0x00 {
			// Next 2 bytes = extension data length
			if i+4 >= len(payload) {
				continue
			}
			extLen := int(payload[i+2])<<8 | int(payload[i+3])
			if extLen <= 0 || i+4+extLen > len(payload) {
				continue
			}

			// Inside SNI extension: list length (2) + name type (1) + name length (2) + name
			extData := payload[i+4 : i+4+extLen]
			if len(extData) < 5 {
				continue
			}

			nameType := extData[2]
			if nameType != 0x00 { // host_name
				continue
			}

			nameLen := int(extData[3])<<8 | int(extData[4])
			if nameLen <= 0 || 5+nameLen > len(extData) {
				continue
			}

			name := string(extData[5 : 5+nameLen])
			// Validate it looks like a hostname
			if isValidHostname(name) {
				return name
			}
		}
	}

	return ""
}

// isValidHostname performs a basic check that a string looks like a DNS hostname.
func isValidHostname(s string) bool {
	if len(s) == 0 || len(s) > 253 {
		return false
	}
	for _, c := range s {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '.' || c == '-') {
			return false
		}
	}
	return strings.Contains(s, ".")
}

// PayloadHexDump returns a short hex dump of the first N bytes for debugging.
func PayloadHexDump(payload []byte, maxBytes int) string {
	if len(payload) > maxBytes {
		payload = payload[:maxBytes]
	}
	return hex.EncodeToString(payload)
}

// GetPrimaryVendor returns the most likely SD-WAN vendor.
// Call Finalize() first to remove false positives.
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
