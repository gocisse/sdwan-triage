package detector

import (
	"encoding/binary"
	"fmt"
	"time"

	"github.com/gocisse/sdwan-triage/pkg/models"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// LAN Protocol Constants
const (
	// VRRP (Virtual Router Redundancy Protocol)
	VRRPProtocol = 112 // IP Protocol number for VRRP

	// CDP (Cisco Discovery Protocol) - Layer 2
	CDPMulticastMAC = "01:00:0c:cc:cc:cc"
	CDPEtherType    = 0x2000

	// LLDP (Link Layer Discovery Protocol) - Layer 2
	LLDPMulticastMAC = "01:80:c2:00:00:0e"
	LLDPEtherType    = 0x88cc

	// HSRP (Hot Standby Router Protocol)
	HSRPUDPPort = 1985

	// STP (Spanning Tree Protocol)
	STPMulticastMAC = "01:80:c2:00:00:00"
)

// VRRP Packet Types
const (
	VRRPTypeAdvertisement = 1
)

// VRRP States
const (
	VRRPStateInitialize = 0
	VRRPStateBackup     = 1
	VRRPStateMaster     = 2
)

// LANProtocolAnalyzer handles LAN protocol detection
type LANProtocolAnalyzer struct {
	vrrpSessions map[string]*VRRPSession
	cdpDevices   map[string]*CDPDevice
	lldpDevices  map[string]*LLDPDevice
	hsrpGroups   map[string]*HSRPGroup
	stpBridges   map[string]*STPBridge
}

// VRRPSession tracks VRRP session information
type VRRPSession struct {
	VirtualRouterID uint8
	Priority        uint8
	State           string
	MasterIP        string
	VirtualIPs      []string
	AuthType        uint8
	AdvertInterval  uint8
	FirstSeen       time.Time
	LastSeen        time.Time
	PacketCount     uint64
	Transitions     []VRRPTransition
}

// VRRPTransition tracks VRRP state changes
type VRRPTransition struct {
	Timestamp   time.Time
	FromState   string
	ToState     string
	Priority    uint8
	RouterIP    string
	Description string
}

// CDPDevice represents a Cisco Discovery Protocol device
type CDPDevice struct {
	DeviceID     string
	IPAddress    string
	Platform     string
	Capabilities string
	SoftwareVer  string
	PortID       string
	FirstSeen    time.Time
	LastSeen     time.Time
	PacketCount  uint64
}

// LLDPDevice represents an LLDP device
type LLDPDevice struct {
	ChassisID    string
	PortID       string
	SystemName   string
	SystemDesc   string
	Capabilities string
	ManagementIP string
	FirstSeen    time.Time
	LastSeen     time.Time
	PacketCount  uint64
}

// HSRPGroup represents an HSRP group
type HSRPGroup struct {
	GroupNumber  uint8
	State        string
	Priority     uint8
	VirtualIP    string
	ActiveRouter string
	StandbyRouter string
	FirstSeen    time.Time
	LastSeen     time.Time
	PacketCount  uint64
}

// STPBridge represents a Spanning Tree Protocol bridge
type STPBridge struct {
	BridgeID     string
	RootBridgeID string
	RootCost     uint32
	PortID       uint16
	FirstSeen    time.Time
	LastSeen     time.Time
	PacketCount  uint64
}

// NewLANProtocolAnalyzer creates a new LAN protocol analyzer
func NewLANProtocolAnalyzer() *LANProtocolAnalyzer {
	return &LANProtocolAnalyzer{
		vrrpSessions: make(map[string]*VRRPSession),
		cdpDevices:   make(map[string]*CDPDevice),
		lldpDevices:  make(map[string]*LLDPDevice),
		hsrpGroups:   make(map[string]*HSRPGroup),
		stpBridges:   make(map[string]*STPBridge),
	}
}

// Analyze processes packets for LAN protocols
func (l *LANProtocolAnalyzer) Analyze(packet gopacket.Packet, state *models.AnalysisState, report *models.TriageReport) {
	timestamp := packet.Metadata().Timestamp

	// Check for VRRP (IP Protocol 112)
	if ipInfo := ExtractIPInfo(packet); ipInfo != nil {
		if ipInfo.Protocol == VRRPProtocol {
			l.analyzeVRRP(packet, ipInfo, timestamp, report)
			return
		}
	}

	// Check for CDP (Ethernet Type 0x2000 or SNAP with Cisco OUI)
	if ethLayer := packet.Layer(layers.LayerTypeEthernet); ethLayer != nil {
		eth := ethLayer.(*layers.Ethernet)
		
		// CDP detection
		if eth.EthernetType == CDPEtherType || eth.DstMAC.String() == CDPMulticastMAC {
			l.analyzeCDP(packet, eth, timestamp, report)
			return
		}

		// LLDP detection
		if eth.EthernetType == LLDPEtherType || eth.DstMAC.String() == LLDPMulticastMAC {
			l.analyzeLLDP(packet, eth, timestamp, report)
			return
		}

		// STP detection
		if eth.DstMAC.String() == STPMulticastMAC {
			l.analyzeSTP(packet, eth, timestamp, report)
			return
		}
	}

	// Check for HSRP (UDP port 1985)
	if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp := udpLayer.(*layers.UDP)
		if uint16(udp.DstPort) == HSRPUDPPort || uint16(udp.SrcPort) == HSRPUDPPort {
			l.analyzeHSRP(packet, udp, timestamp, report)
			return
		}
	}
}

// analyzeVRRP processes VRRP packets
func (l *LANProtocolAnalyzer) analyzeVRRP(packet gopacket.Packet, ipInfo *PacketIPInfo, timestamp time.Time, report *models.TriageReport) {
	// Get the payload after IP header
	var payload []byte
	if appLayer := packet.ApplicationLayer(); appLayer != nil {
		payload = appLayer.Payload()
	} else if transportLayer := packet.TransportLayer(); transportLayer != nil {
		payload = transportLayer.LayerPayload()
	} else {
		// Try to get raw payload from IP layer
		for _, layer := range packet.Layers() {
			if layer.LayerType() == layers.LayerTypeIPv4 || layer.LayerType() == layers.LayerTypeIPv6 {
				payload = layer.LayerPayload()
				break
			}
		}
	}

	if len(payload) < 8 {
		return // Invalid VRRP packet
	}

	// Parse VRRP header
	version := (payload[0] >> 4) & 0x0F
	packetType := payload[0] & 0x0F
	virtualRouterID := payload[1]
	priority := payload[2]
	countIPAddrs := payload[3]
	authType := payload[4]
	advertInterval := payload[5]

	if packetType != VRRPTypeAdvertisement {
		return // Only process advertisements
	}

	// Determine state based on priority
	state := "Unknown"
	if priority == 0 {
		state = "Master Shutdown"
	} else if priority == 255 {
		state = "Master (Owner)"
	} else {
		// We can't determine exact state from packet alone, but we can infer
		state = "Active"
	}

	// Extract virtual IP addresses
	virtualIPs := []string{}
	offset := 8
	for i := 0; i < int(countIPAddrs) && offset+4 <= len(payload); i++ {
		ip := fmt.Sprintf("%d.%d.%d.%d", payload[offset], payload[offset+1], payload[offset+2], payload[offset+3])
		virtualIPs = append(virtualIPs, ip)
		offset += 4
	}

	// Track VRRP session
	sessionKey := fmt.Sprintf("%s-vrid-%d", ipInfo.SrcIP, virtualRouterID)
	
	if session, exists := l.vrrpSessions[sessionKey]; exists {
		// Check for state transition
		if session.Priority != priority {
			transition := VRRPTransition{
				Timestamp:   timestamp,
				FromState:   session.State,
				ToState:     state,
				Priority:    priority,
				RouterIP:    ipInfo.SrcIP,
				Description: fmt.Sprintf("Priority changed from %d to %d", session.Priority, priority),
			}
			session.Transitions = append(session.Transitions, transition)

			// Add timeline event for VRRP flapping
			event := models.TimelineEvent{
				Timestamp: float64(timestamp.UnixNano()) / 1e9,
				EventType: "VRRP State Change",
				SourceIP:  ipInfo.SrcIP,
				Protocol:  "VRRP",
				Detail:    fmt.Sprintf("VRID %d: Priority changed from %d to %d (Virtual IPs: %v)", virtualRouterID, session.Priority, priority, virtualIPs),
			}
			report.Timeline = append(report.Timeline, event)
		}

		session.Priority = priority
		session.State = state
		session.MasterIP = ipInfo.SrcIP
		session.VirtualIPs = virtualIPs
		session.LastSeen = timestamp
		session.PacketCount++
	} else {
		// New VRRP session
		l.vrrpSessions[sessionKey] = &VRRPSession{
			VirtualRouterID: virtualRouterID,
			Priority:        priority,
			State:           state,
			MasterIP:        ipInfo.SrcIP,
			VirtualIPs:      virtualIPs,
			AuthType:        authType,
			AdvertInterval:  advertInterval,
			FirstSeen:       timestamp,
			LastSeen:        timestamp,
			PacketCount:     1,
			Transitions:     []VRRPTransition{},
		}

		// Add timeline event for new VRRP session
		event := models.TimelineEvent{
			Timestamp: float64(timestamp.UnixNano()) / 1e9,
			EventType: "VRRP Session Detected",
			SourceIP:  ipInfo.SrcIP,
			Protocol:  "VRRP",
			Detail:    fmt.Sprintf("VRID %d detected (v%d): Priority %d, Virtual IPs: %v, Interval: %ds", virtualRouterID, version, priority, virtualIPs, advertInterval),
		}
		report.Timeline = append(report.Timeline, event)
	}
}

// analyzeCDP processes CDP packets
func (l *LANProtocolAnalyzer) analyzeCDP(packet gopacket.Packet, eth *layers.Ethernet, timestamp time.Time, report *models.TriageReport) {
	// CDP packets use SNAP encapsulation
	payload := eth.Payload
	
	// Check for LLC/SNAP header
	if len(payload) < 8 {
		return
	}

	// LLC header: DSAP=0xAA, SSAP=0xAA, Control=0x03
	if payload[0] != 0xAA || payload[1] != 0xAA || payload[2] != 0x03 {
		return
	}

	// SNAP header: OUI=0x00000C (Cisco), Protocol=0x2000 (CDP)
	if payload[3] != 0x00 || payload[4] != 0x00 || payload[5] != 0x0C {
		return
	}

	cdpPayload := payload[8:] // Skip LLC/SNAP headers
	if len(cdpPayload) < 4 {
		return
	}

	// Parse CDP header
	version := cdpPayload[0]
	ttl := cdpPayload[1]
	// checksum := binary.BigEndian.Uint16(cdpPayload[2:4])

	// Parse CDP TLVs
	device := &CDPDevice{
		FirstSeen:   timestamp,
		LastSeen:    timestamp,
		PacketCount: 1,
	}

	offset := 4
	for offset+4 <= len(cdpPayload) {
		tlvType := binary.BigEndian.Uint16(cdpPayload[offset : offset+2])
		tlvLength := binary.BigEndian.Uint16(cdpPayload[offset+2 : offset+4])
		
		if tlvLength < 4 || offset+int(tlvLength) > len(cdpPayload) {
			break
		}

		tlvData := cdpPayload[offset+4 : offset+int(tlvLength)]

		switch tlvType {
		case 0x0001: // Device ID
			device.DeviceID = string(tlvData)
		case 0x0002: // Addresses
			// Parse IP addresses (simplified)
			if len(tlvData) > 4 {
				device.IPAddress = parseFirstIPFromCDP(tlvData)
			}
		case 0x0003: // Port ID
			device.PortID = string(tlvData)
		case 0x0004: // Capabilities
			if len(tlvData) >= 4 {
				caps := binary.BigEndian.Uint32(tlvData)
				device.Capabilities = parseCDPCapabilities(caps)
			}
		case 0x0005: // Software Version
			device.SoftwareVer = string(tlvData)
		case 0x0006: // Platform
			device.Platform = string(tlvData)
		}

		offset += int(tlvLength)
	}

	// Store device information
	deviceKey := fmt.Sprintf("cdp-%s", eth.SrcMAC.String())
	if existing, exists := l.cdpDevices[deviceKey]; exists {
		existing.LastSeen = timestamp
		existing.PacketCount++
	} else {
		l.cdpDevices[deviceKey] = device

		// Add timeline event
		event := models.TimelineEvent{
			Timestamp: float64(timestamp.UnixNano()) / 1e9,
			EventType: "CDP Device Discovered",
			SourceIP:  device.IPAddress,
			Protocol:  "CDP",
			Detail:    fmt.Sprintf("Device: %s, Platform: %s, Port: %s, Capabilities: %s (v%d, TTL: %ds)", device.DeviceID, device.Platform, device.PortID, device.Capabilities, version, ttl),
		}
		report.Timeline = append(report.Timeline, event)
	}
}

// analyzeLLDP processes LLDP packets
func (l *LANProtocolAnalyzer) analyzeLLDP(packet gopacket.Packet, eth *layers.Ethernet, timestamp time.Time, report *models.TriageReport) {
	payload := eth.Payload
	if len(payload) < 2 {
		return
	}

	device := &LLDPDevice{
		FirstSeen:   timestamp,
		LastSeen:    timestamp,
		PacketCount: 1,
	}

	offset := 0
	for offset+2 <= len(payload) {
		tlvHeader := binary.BigEndian.Uint16(payload[offset : offset+2])
		tlvType := (tlvHeader >> 9) & 0x7F
		tlvLength := int(tlvHeader & 0x1FF)

		if offset+2+tlvLength > len(payload) {
			break
		}

		tlvData := payload[offset+2 : offset+2+tlvLength]

		switch tlvType {
		case 0: // End of LLDPDU
			break
		case 1: // Chassis ID
			if len(tlvData) > 1 {
				device.ChassisID = parseLLDPString(tlvData[1:])
			}
		case 2: // Port ID
			if len(tlvData) > 1 {
				device.PortID = parseLLDPString(tlvData[1:])
			}
		case 5: // System Name
			device.SystemName = string(tlvData)
		case 6: // System Description
			device.SystemDesc = string(tlvData)
		case 7: // System Capabilities
			if len(tlvData) >= 4 {
				caps := binary.BigEndian.Uint16(tlvData[0:2])
				device.Capabilities = parseLLDPCapabilities(caps)
			}
		case 8: // Management Address
			if len(tlvData) > 5 {
				device.ManagementIP = parseManagementAddress(tlvData)
			}
		}

		offset += 2 + tlvLength

		if tlvType == 0 {
			break
		}
	}

	// Store device information
	deviceKey := fmt.Sprintf("lldp-%s", eth.SrcMAC.String())
	if existing, exists := l.lldpDevices[deviceKey]; exists {
		existing.LastSeen = timestamp
		existing.PacketCount++
	} else {
		l.lldpDevices[deviceKey] = device

		// Add timeline event
		event := models.TimelineEvent{
			Timestamp: float64(timestamp.UnixNano()) / 1e9,
			EventType: "LLDP Device Discovered",
			SourceIP:  device.ManagementIP,
			Protocol:  "LLDP",
			Detail:    fmt.Sprintf("System: %s, Chassis: %s, Port: %s, Capabilities: %s", device.SystemName, device.ChassisID, device.PortID, device.Capabilities),
		}
		report.Timeline = append(report.Timeline, event)
	}
}

// analyzeHSRP processes HSRP packets
func (l *LANProtocolAnalyzer) analyzeHSRP(packet gopacket.Packet, udp *layers.UDP, timestamp time.Time, report *models.TriageReport) {
	payload := udp.Payload
	if len(payload) < 20 {
		return
	}

	// Parse HSRP header
	version := payload[0]
	opCode := payload[1]
	state := payload[2]
	priority := payload[4]
	groupNumber := payload[5]
	
	var virtualIP string
	if len(payload) >= 16 {
		virtualIP = fmt.Sprintf("%d.%d.%d.%d", payload[12], payload[13], payload[14], payload[15])
	}

	ipInfo := ExtractIPInfo(packet)
	if ipInfo == nil {
		return
	}

	stateStr := parseHSRPState(state)
	groupKey := fmt.Sprintf("hsrp-group-%d", groupNumber)

	if group, exists := l.hsrpGroups[groupKey]; exists {
		group.LastSeen = timestamp
		group.PacketCount++
		
		// Track state changes
		if group.State != stateStr || group.Priority != priority {
			event := models.TimelineEvent{
				Timestamp: float64(timestamp.UnixNano()) / 1e9,
				EventType: "HSRP State Change",
				SourceIP:  ipInfo.SrcIP,
				Protocol:  "HSRP",
				Detail:    fmt.Sprintf("Group %d: State=%s, Priority=%d, Virtual IP=%s (v%d, Op=%d)", groupNumber, stateStr, priority, virtualIP, version, opCode),
			}
			report.Timeline = append(report.Timeline, event)
		}
		
		group.State = stateStr
		group.Priority = priority
		if stateStr == "Active" {
			group.ActiveRouter = ipInfo.SrcIP
		} else if stateStr == "Standby" {
			group.StandbyRouter = ipInfo.SrcIP
		}
	} else {
		l.hsrpGroups[groupKey] = &HSRPGroup{
			GroupNumber:  groupNumber,
			State:        stateStr,
			Priority:     priority,
			VirtualIP:    virtualIP,
			ActiveRouter: ipInfo.SrcIP,
			FirstSeen:    timestamp,
			LastSeen:     timestamp,
			PacketCount:  1,
		}

		event := models.TimelineEvent{
			Timestamp: float64(timestamp.UnixNano()) / 1e9,
			EventType: "HSRP Group Detected",
			SourceIP:  ipInfo.SrcIP,
			Protocol:  "HSRP",
			Detail:    fmt.Sprintf("Group %d: State=%s, Priority=%d, Virtual IP=%s", groupNumber, stateStr, priority, virtualIP),
		}
		report.Timeline = append(report.Timeline, event)
	}
}

// analyzeSTP processes STP/RSTP packets
func (l *LANProtocolAnalyzer) analyzeSTP(packet gopacket.Packet, eth *layers.Ethernet, timestamp time.Time, report *models.TriageReport) {
	payload := eth.Payload
	
	// Check for LLC header
	if len(payload) < 35 {
		return
	}

	// LLC header for STP: DSAP=0x42, SSAP=0x42
	if payload[0] != 0x42 || payload[1] != 0x42 {
		return
	}

	stpPayload := payload[3:] // Skip LLC header
	if len(stpPayload) < 35 {
		return
	}

	// Parse STP BPDU
	protocolID := binary.BigEndian.Uint16(stpPayload[0:2])
	if protocolID != 0 {
		return // Not STP
	}

	// Extract bridge IDs and costs
	rootBridgeID := fmt.Sprintf("%02x%02x.%02x%02x.%02x%02x.%02x%02x",
		stpPayload[5], stpPayload[6], stpPayload[7], stpPayload[8],
		stpPayload[9], stpPayload[10], stpPayload[11], stpPayload[12])
	
	rootCost := binary.BigEndian.Uint32(stpPayload[13:17])
	
	bridgeID := fmt.Sprintf("%02x%02x.%02x%02x.%02x%02x.%02x%02x",
		stpPayload[17], stpPayload[18], stpPayload[19], stpPayload[20],
		stpPayload[21], stpPayload[22], stpPayload[23], stpPayload[24])
	
	portID := binary.BigEndian.Uint16(stpPayload[25:27])

	bridgeKey := fmt.Sprintf("stp-%s", bridgeID)
	
	if bridge, exists := l.stpBridges[bridgeKey]; exists {
		bridge.LastSeen = timestamp
		bridge.PacketCount++
		
		// Detect topology changes
		if bridge.RootBridgeID != rootBridgeID {
			event := models.TimelineEvent{
				Timestamp: float64(timestamp.UnixNano()) / 1e9,
				EventType: "STP Topology Change",
				Protocol:  "STP",
				Detail:    fmt.Sprintf("Root bridge changed from %s to %s (Bridge: %s)", bridge.RootBridgeID, rootBridgeID, bridgeID),
			}
			report.Timeline = append(report.Timeline, event)
		}
		
		bridge.RootBridgeID = rootBridgeID
		bridge.RootCost = rootCost
	} else {
		l.stpBridges[bridgeKey] = &STPBridge{
			BridgeID:     bridgeID,
			RootBridgeID: rootBridgeID,
			RootCost:     rootCost,
			PortID:       portID,
			FirstSeen:    timestamp,
			LastSeen:     timestamp,
			PacketCount:  1,
		}

		event := models.TimelineEvent{
			Timestamp: float64(timestamp.UnixNano()) / 1e9,
			EventType: "STP Bridge Detected",
			Protocol:  "STP",
			Detail:    fmt.Sprintf("Bridge: %s, Root: %s, Cost: %d, Port: %d", bridgeID, rootBridgeID, rootCost, portID),
		}
		report.Timeline = append(report.Timeline, event)
	}
}

// GetFindings returns all LAN protocol findings
func (l *LANProtocolAnalyzer) GetFindings() *models.LANProtocolFindings {
	findings := &models.LANProtocolFindings{
		VRRPSessions: make([]models.VRRPFinding, 0),
		CDPDevices:   make([]models.CDPFinding, 0),
		LLDPDevices:  make([]models.LLDPFinding, 0),
		HSRPGroups:   make([]models.HSRPFinding, 0),
		STPBridges:   make([]models.STPFinding, 0),
	}

	// Convert VRRP sessions
	for _, session := range l.vrrpSessions {
		finding := models.VRRPFinding{
			VirtualRouterID: session.VirtualRouterID,
			Priority:        session.Priority,
			State:           session.State,
			MasterIP:        session.MasterIP,
			VirtualIPs:      session.VirtualIPs,
			AuthType:        session.AuthType,
			AdvertInterval:  session.AdvertInterval,
			FirstSeen:       session.FirstSeen.Format(time.RFC3339),
			LastSeen:        session.LastSeen.Format(time.RFC3339),
			PacketCount:     session.PacketCount,
			TransitionCount: len(session.Transitions),
		}
		
		// Check for flapping
		if len(session.Transitions) > 3 {
			finding.IsFlapping = true
			finding.FlappingReason = fmt.Sprintf("Detected %d state transitions", len(session.Transitions))
		}
		
		findings.VRRPSessions = append(findings.VRRPSessions, finding)
	}

	// Convert CDP devices
	for _, device := range l.cdpDevices {
		findings.CDPDevices = append(findings.CDPDevices, models.CDPFinding{
			DeviceID:     device.DeviceID,
			IPAddress:    device.IPAddress,
			Platform:     device.Platform,
			Capabilities: device.Capabilities,
			SoftwareVer:  device.SoftwareVer,
			PortID:       device.PortID,
			FirstSeen:    device.FirstSeen.Format(time.RFC3339),
			LastSeen:     device.LastSeen.Format(time.RFC3339),
			PacketCount:  device.PacketCount,
		})
	}

	// Convert LLDP devices
	for _, device := range l.lldpDevices {
		findings.LLDPDevices = append(findings.LLDPDevices, models.LLDPFinding{
			ChassisID:    device.ChassisID,
			PortID:       device.PortID,
			SystemName:   device.SystemName,
			SystemDesc:   device.SystemDesc,
			Capabilities: device.Capabilities,
			ManagementIP: device.ManagementIP,
			FirstSeen:    device.FirstSeen.Format(time.RFC3339),
			LastSeen:     device.LastSeen.Format(time.RFC3339),
			PacketCount:  device.PacketCount,
		})
	}

	// Convert HSRP groups
	for _, group := range l.hsrpGroups {
		findings.HSRPGroups = append(findings.HSRPGroups, models.HSRPFinding{
			GroupNumber:   group.GroupNumber,
			State:         group.State,
			Priority:      group.Priority,
			VirtualIP:     group.VirtualIP,
			ActiveRouter:  group.ActiveRouter,
			StandbyRouter: group.StandbyRouter,
			FirstSeen:     group.FirstSeen.Format(time.RFC3339),
			LastSeen:      group.LastSeen.Format(time.RFC3339),
			PacketCount:   group.PacketCount,
		})
	}

	// Convert STP bridges
	for _, bridge := range l.stpBridges {
		findings.STPBridges = append(findings.STPBridges, models.STPFinding{
			BridgeID:     bridge.BridgeID,
			RootBridgeID: bridge.RootBridgeID,
			RootCost:     bridge.RootCost,
			PortID:       bridge.PortID,
			FirstSeen:    bridge.FirstSeen.Format(time.RFC3339),
			LastSeen:     bridge.LastSeen.Format(time.RFC3339),
			PacketCount:  bridge.PacketCount,
		})
	}

	return findings
}

// Helper functions

func parseFirstIPFromCDP(data []byte) string {
	if len(data) < 9 {
		return ""
	}
	// Skip count and first address header
	offset := 4
	if offset+5 > len(data) {
		return ""
	}
	// Protocol type (1=NLPID, value 0xCC=IP)
	if data[offset] == 1 && data[offset+1] == 1 && data[offset+2] == 0xCC {
		addrLen := binary.BigEndian.Uint16(data[offset+3 : offset+5])
		if offset+5+int(addrLen) <= len(data) && addrLen == 4 {
			return fmt.Sprintf("%d.%d.%d.%d", data[offset+5], data[offset+6], data[offset+7], data[offset+8])
		}
	}
	return ""
}

func parseCDPCapabilities(caps uint32) string {
	capabilities := []string{}
	if caps&0x01 != 0 {
		capabilities = append(capabilities, "Router")
	}
	if caps&0x02 != 0 {
		capabilities = append(capabilities, "TransparentBridge")
	}
	if caps&0x04 != 0 {
		capabilities = append(capabilities, "SourceRouteBridge")
	}
	if caps&0x08 != 0 {
		capabilities = append(capabilities, "Switch")
	}
	if caps&0x10 != 0 {
		capabilities = append(capabilities, "Host")
	}
	if caps&0x20 != 0 {
		capabilities = append(capabilities, "IGMPCapable")
	}
	if caps&0x40 != 0 {
		capabilities = append(capabilities, "Repeater")
	}
	if len(capabilities) == 0 {
		return "Unknown"
	}
	return fmt.Sprintf("%v", capabilities)
}

func parseLLDPCapabilities(caps uint16) string {
	capabilities := []string{}
	if caps&0x0001 != 0 {
		capabilities = append(capabilities, "Other")
	}
	if caps&0x0002 != 0 {
		capabilities = append(capabilities, "Repeater")
	}
	if caps&0x0004 != 0 {
		capabilities = append(capabilities, "Bridge")
	}
	if caps&0x0008 != 0 {
		capabilities = append(capabilities, "WLAN-AP")
	}
	if caps&0x0010 != 0 {
		capabilities = append(capabilities, "Router")
	}
	if caps&0x0020 != 0 {
		capabilities = append(capabilities, "Telephone")
	}
	if caps&0x0040 != 0 {
		capabilities = append(capabilities, "DOCSIS")
	}
	if caps&0x0080 != 0 {
		capabilities = append(capabilities, "Station")
	}
	if len(capabilities) == 0 {
		return "Unknown"
	}
	return fmt.Sprintf("%v", capabilities)
}

func parseLLDPString(data []byte) string {
	return string(data)
}

func parseManagementAddress(data []byte) string {
	if len(data) < 6 {
		return ""
	}
	addrLen := int(data[0])
	if addrLen < 2 || 1+addrLen > len(data) {
		return ""
	}
	addrType := data[1]
	addr := data[2 : 1+addrLen]
	
	// IPv4
	if addrType == 1 && len(addr) == 4 {
		return fmt.Sprintf("%d.%d.%d.%d", addr[0], addr[1], addr[2], addr[3])
	}
	// IPv6
	if addrType == 2 && len(addr) == 16 {
		return fmt.Sprintf("%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
			addr[0], addr[1], addr[2], addr[3], addr[4], addr[5], addr[6], addr[7],
			addr[8], addr[9], addr[10], addr[11], addr[12], addr[13], addr[14], addr[15])
	}
	return ""
}

func parseHSRPState(state uint8) string {
	switch state {
	case 0:
		return "Initial"
	case 1:
		return "Learn"
	case 2:
		return "Listen"
	case 4:
		return "Speak"
	case 8:
		return "Standby"
	case 16:
		return "Active"
	default:
		return fmt.Sprintf("Unknown(%d)", state)
	}
}
