package detector

import (
	"fmt"
	"time"

	"github.com/gocisse/sdwan-triage/pkg/models"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// ── Thresholds ──────────────────────────────────────────────────────────────

const (
	// BFD: >3 state transitions in 60s = flapping
	bfdFlappingThreshold = 3
	bfdWindowSeconds     = 60.0

	// IKE: >3 IKE_SA_INIT from same peer in 60s = tunnel rebuild storm
	ikeRebuildThreshold = 3
	ikeWindowSeconds    = 60.0

	// STP: >5 TCN BPDUs = topology change storm
	stpTCNThreshold = 5

	// BFD ports
	bfdControlPort = 3784
	bfdEchoPort    = 4784

	// IKE ports
	ikePort    = 500
	ikeNATPort = 4500
)

// ── BFD constants ───────────────────────────────────────────────────────────

// BFD state values (RFC 5880 §4.1)
const (
	bfdStateAdminDown = 0
	bfdStateDown      = 1
	bfdStateInit      = 2
	bfdStateUp        = 3
)

func bfdStateName(s uint8) string {
	switch s {
	case bfdStateAdminDown:
		return "AdminDown"
	case bfdStateDown:
		return "Down"
	case bfdStateInit:
		return "Init"
	case bfdStateUp:
		return "Up"
	default:
		return fmt.Sprintf("Unknown(%d)", s)
	}
}

// ── Internal tracking structs ───────────────────────────────────────────────

// bfdSession tracks BFD state transitions per peer pair.
type bfdSession struct {
	srcIP       string
	peerIP      string
	lastState   uint8
	transitions []time.Time // timestamps of Up→Down or Down→Up transitions
	firstSeen   time.Time
	lastSeen    time.Time
	packetCount int
}

// ikeSession tracks IKE_SA_INIT requests per peer pair.
type ikeSession struct {
	initiatorIP string
	responderIP string
	initTimes   []time.Time // timestamps of IKE_SA_INIT packets
	firstSeen   time.Time
	lastSeen    time.Time
}

// stpTCNTracker tracks STP Topology Change Notification BPDUs.
type stpTCNTracker struct {
	tcnTimes  []time.Time
	firstSeen time.Time
	lastSeen  time.Time
}

// ── StabilityMonitor ────────────────────────────────────────────────────────

// StabilityMonitor detects WAN/LAN interface flapping from packet captures.
//   - BFD session flapping (UDP 3784/4784)
//   - IPsec IKE tunnel rebuilds (UDP 500/4500, IKE_SA_INIT)
//   - STP TCN storms (BPDU with TC/TCN flags)
//
// HSRP/VRRP flapping is handled by the enhanced LANProtocolAnalyzer.
type StabilityMonitor struct {
	bfdSessions map[string]*bfdSession // key: "srcIP->peerIP"
	ikeSessions map[string]*ikeSession // key: "initiatorIP->responderIP"
	stpTCN      *stpTCNTracker
}

// NewStabilityMonitor creates a new stability monitor.
func NewStabilityMonitor() *StabilityMonitor {
	return &StabilityMonitor{
		bfdSessions: make(map[string]*bfdSession),
		ikeSessions: make(map[string]*ikeSession),
		stpTCN:      &stpTCNTracker{},
	}
}

// Analyze processes a packet looking for BFD, IKE, and STP TCN indicators.
func (sm *StabilityMonitor) Analyze(packet gopacket.Packet, state *models.AnalysisState, report *models.TriageReport) {
	timestamp := packet.Metadata().Timestamp

	// Check UDP layer for BFD and IKE
	udpLayer := packet.Layer(layers.LayerTypeUDP)
	if udpLayer != nil {
		udp := udpLayer.(*layers.UDP)
		dstPort := uint16(udp.DstPort)
		srcPort := uint16(udp.SrcPort)

		// BFD Control (UDP 3784) or Echo (UDP 4784)
		if dstPort == bfdControlPort || dstPort == bfdEchoPort ||
			srcPort == bfdControlPort || srcPort == bfdEchoPort {
			sm.analyzeBFD(packet, udp, timestamp, report)
			return
		}

		// IKE (UDP 500) or IKE NAT-T (UDP 4500)
		if dstPort == ikePort || dstPort == ikeNATPort {
			sm.analyzeIKE(packet, udp, timestamp, report)
			return
		}
	}

	// STP TCN detection via Ethernet destination MAC 01:80:C2:00:00:00
	if ethLayer := packet.Layer(layers.LayerTypeEthernet); ethLayer != nil {
		eth := ethLayer.(*layers.Ethernet)
		if eth.DstMAC.String() == STPMulticastMAC {
			sm.analyzeSTPTCN(eth, timestamp, report)
		}
	}
}

// ── BFD Analysis ────────────────────────────────────────────────────────────

func (sm *StabilityMonitor) analyzeBFD(packet gopacket.Packet, udp *layers.UDP, ts time.Time, report *models.TriageReport) {
	payload := udp.Payload
	// BFD control packet minimum: 24 bytes (RFC 5880 §4.1)
	if len(payload) < 24 {
		return
	}

	// Byte 0: Version (3 bits) | Diag (5 bits)
	version := (payload[0] >> 5) & 0x07
	if version != 1 {
		return // Only BFD v1
	}

	// Byte 1: Sta (2 bits) | ... flags
	currentState := (payload[1] >> 6) & 0x03

	ipInfo := ExtractIPInfo(packet)
	if ipInfo == nil {
		return
	}

	sessionKey := fmt.Sprintf("%s->%s", ipInfo.SrcIP, ipInfo.DstIP)

	session, exists := sm.bfdSessions[sessionKey]
	if !exists {
		sm.bfdSessions[sessionKey] = &bfdSession{
			srcIP:       ipInfo.SrcIP,
			peerIP:      ipInfo.DstIP,
			lastState:   currentState,
			transitions: nil,
			firstSeen:   ts,
			lastSeen:    ts,
			packetCount: 1,
		}

		event := models.TimelineEvent{
			Timestamp:     float64(ts.UnixNano()) / 1e9,
			EventType:     "BFD Session Detected",
			SourceIP:      ipInfo.SrcIP,
			DestinationIP: ipInfo.DstIP,
			Protocol:      "BFD",
			Detail:        fmt.Sprintf("BFD session %s → %s, state: %s", ipInfo.SrcIP, ipInfo.DstIP, bfdStateName(currentState)),
		}
		report.Timeline = append(report.Timeline, event)
		return
	}

	session.lastSeen = ts
	session.packetCount++

	// Detect state transition
	if currentState != session.lastState {
		session.transitions = append(session.transitions, ts)

		event := models.TimelineEvent{
			Timestamp:     float64(ts.UnixNano()) / 1e9,
			EventType:     "BFD State Change",
			SourceIP:      ipInfo.SrcIP,
			DestinationIP: ipInfo.DstIP,
			Protocol:      "BFD",
			Detail:        fmt.Sprintf("BFD %s → %s: %s → %s", ipInfo.SrcIP, ipInfo.DstIP, bfdStateName(session.lastState), bfdStateName(currentState)),
		}
		report.Timeline = append(report.Timeline, event)

		session.lastState = currentState
	}
}

// ── IKE Analysis ────────────────────────────────────────────────────────────

func (sm *StabilityMonitor) analyzeIKE(packet gopacket.Packet, udp *layers.UDP, ts time.Time, report *models.TriageReport) {
	payload := udp.Payload

	// For NAT-T (port 4500), skip the 4-byte non-ESP marker
	offset := 0
	if uint16(udp.DstPort) == ikeNATPort {
		if len(payload) < 4 {
			return
		}
		// Non-ESP marker is 4 zero bytes; if not zero, it's ESP, not IKE
		if payload[0] != 0 || payload[1] != 0 || payload[2] != 0 || payload[3] != 0 {
			return
		}
		offset = 4
	}

	ikePayload := payload[offset:]

	// IKEv2 header is 28 bytes minimum (RFC 7296 §3.1)
	if len(ikePayload) < 28 {
		return
	}

	// Byte 17: Major version (high nibble) | Minor version (low nibble)
	majorVersion := (ikePayload[17] >> 4) & 0x0F

	// Byte 18: Exchange Type
	exchangeType := ikePayload[18]

	// Byte 19: Flags — bit 3 (0x08) = Initiator flag
	flags := ikePayload[19]
	isInitiator := (flags & 0x08) != 0

	// We care about IKE_SA_INIT (exchange type 34) from the initiator.
	// IKEv1 Main Mode (exchange type 2) is also relevant.
	isIKESAInit := false
	if majorVersion == 2 && exchangeType == 34 && isInitiator {
		isIKESAInit = true
	} else if majorVersion == 1 && exchangeType == 2 {
		// IKEv1 Main Mode — check that the message ID is 0 (first exchange)
		msgID := uint32(ikePayload[20])<<24 | uint32(ikePayload[21])<<16 | uint32(ikePayload[22])<<8 | uint32(ikePayload[23])
		if msgID == 0 {
			isIKESAInit = true
		}
	}

	if !isIKESAInit {
		return
	}

	ipInfo := ExtractIPInfo(packet)
	if ipInfo == nil {
		return
	}

	sessionKey := fmt.Sprintf("%s->%s", ipInfo.SrcIP, ipInfo.DstIP)

	session, exists := sm.ikeSessions[sessionKey]
	if !exists {
		sm.ikeSessions[sessionKey] = &ikeSession{
			initiatorIP: ipInfo.SrcIP,
			responderIP: ipInfo.DstIP,
			initTimes:   []time.Time{ts},
			firstSeen:   ts,
			lastSeen:    ts,
		}

		event := models.TimelineEvent{
			Timestamp:     float64(ts.UnixNano()) / 1e9,
			EventType:     "IKE SA Init",
			SourceIP:      ipInfo.SrcIP,
			DestinationIP: ipInfo.DstIP,
			Protocol:      "IKE",
			Detail:        fmt.Sprintf("IKEv%d SA_INIT from %s → %s", majorVersion, ipInfo.SrcIP, ipInfo.DstIP),
		}
		report.Timeline = append(report.Timeline, event)
		return
	}

	session.lastSeen = ts
	session.initTimes = append(session.initTimes, ts)

	event := models.TimelineEvent{
		Timestamp:     float64(ts.UnixNano()) / 1e9,
		EventType:     "IKE SA Init",
		SourceIP:      ipInfo.SrcIP,
		DestinationIP: ipInfo.DstIP,
		Protocol:      "IKE",
		Detail:        fmt.Sprintf("IKEv%d SA_INIT #%d from %s → %s", majorVersion, len(session.initTimes), ipInfo.SrcIP, ipInfo.DstIP),
	}
	report.Timeline = append(report.Timeline, event)
}

// ── STP TCN Analysis ────────────────────────────────────────────────────────

func (sm *StabilityMonitor) analyzeSTPTCN(eth *layers.Ethernet, ts time.Time, report *models.TriageReport) {
	payload := eth.Payload

	// LLC header for STP: DSAP=0x42, SSAP=0x42
	if len(payload) < 3 || payload[0] != 0x42 || payload[1] != 0x42 {
		return
	}

	stpPayload := payload[3:]

	// Detect TCN BPDU: a TCN BPDU is exactly 4 bytes in the LLC payload,
	// with Protocol ID = 0x0000, Version = 0x00, Type = 0x80 (TCN).
	if len(stpPayload) >= 4 {
		protocolID := uint16(stpPayload[0])<<8 | uint16(stpPayload[1])
		bpduType := stpPayload[3]

		if protocolID == 0x0000 && bpduType == 0x80 {
			// This is a TCN BPDU
			sm.stpTCN.tcnTimes = append(sm.stpTCN.tcnTimes, ts)
			if sm.stpTCN.firstSeen.IsZero() {
				sm.stpTCN.firstSeen = ts
			}
			sm.stpTCN.lastSeen = ts

			event := models.TimelineEvent{
				Timestamp: float64(ts.UnixNano()) / 1e9,
				EventType: "STP TCN BPDU",
				Protocol:  "STP",
				Detail:    fmt.Sprintf("STP Topology Change Notification BPDU #%d", len(sm.stpTCN.tcnTimes)),
			}
			report.Timeline = append(report.Timeline, event)
			return
		}
	}

	// Also check Config BPDU with TC flag set (bit 0 of flags byte)
	// Config BPDU: type 0x00, minimum 35 bytes in STP payload
	if len(stpPayload) >= 35 {
		protocolID := uint16(stpPayload[0])<<8 | uint16(stpPayload[1])
		bpduType := stpPayload[3]
		flags := stpPayload[4]

		if protocolID == 0x0000 && bpduType == 0x00 && (flags&0x01) != 0 {
			// TC flag is set in config BPDU
			sm.stpTCN.tcnTimes = append(sm.stpTCN.tcnTimes, ts)
			if sm.stpTCN.firstSeen.IsZero() {
				sm.stpTCN.firstSeen = ts
			}
			sm.stpTCN.lastSeen = ts

			event := models.TimelineEvent{
				Timestamp: float64(ts.UnixNano()) / 1e9,
				EventType: "STP TC Flag",
				Protocol:  "STP",
				Detail:    fmt.Sprintf("STP Config BPDU with Topology Change flag set (#%d)", len(sm.stpTCN.tcnTimes)),
			}
			report.Timeline = append(report.Timeline, event)
		}
	}
}

// ── Finalize ────────────────────────────────────────────────────────────────

// Finalize evaluates all tracked sessions against thresholds and appends
// StabilityFinding entries to the report.
func (sm *StabilityMonitor) Finalize(report *models.TriageReport) {
	sm.finalizeBFD(report)
	sm.finalizeIKE(report)
	sm.finalizeSTPTCN(report)
}

func (sm *StabilityMonitor) finalizeBFD(report *models.TriageReport) {
	for _, session := range sm.bfdSessions {
		if len(session.transitions) == 0 {
			continue
		}

		// Count transitions that fall within any sliding 60-second window
		maxInWindow := countInSlidingWindow(session.transitions, bfdWindowSeconds)

		if maxInWindow > bfdFlappingThreshold {
			window := session.lastSeen.Sub(session.firstSeen).Seconds()
			if window < 1 {
				window = 1
			}

			finding := models.StabilityFinding{
				Type:          "BFD Flapping",
				Severity:      "Critical",
				Identifier:    fmt.Sprintf("%s ↔ %s", session.srcIP, session.peerIP),
				Description:   fmt.Sprintf("BFD session between %s and %s flapping: %d state transitions detected (%d within a %.0fs window)", session.srcIP, session.peerIP, len(session.transitions), maxInWindow, bfdWindowSeconds),
				StateChanges:  len(session.transitions),
				WindowSeconds: window,
				FirstSeen:     session.firstSeen.Format(time.RFC3339),
				LastSeen:      session.lastSeen.Format(time.RFC3339),
				SourceIP:      session.srcIP,
				PeerIP:        session.peerIP,
				Protocol:      "BFD",
				RootCauseHint: "WAN link instability, ISP flapping, or misconfigured BFD timers (reduce Tx/Rx interval multiplier). Check 'show bfd neighbors detail' on both endpoints.",
			}
			report.StabilityFindings = append(report.StabilityFindings, finding)
		}
	}
}

func (sm *StabilityMonitor) finalizeIKE(report *models.TriageReport) {
	for _, session := range sm.ikeSessions {
		if len(session.initTimes) <= 1 {
			continue
		}

		// Count IKE_SA_INIT requests within a sliding window
		maxInWindow := countInSlidingWindow(session.initTimes, ikeWindowSeconds)

		if maxInWindow > ikeRebuildThreshold {
			window := session.lastSeen.Sub(session.firstSeen).Seconds()
			if window < 1 {
				window = 1
			}

			finding := models.StabilityFinding{
				Type:          "IKE Tunnel Rebuild",
				Severity:      "High",
				Identifier:    fmt.Sprintf("%s → %s", session.initiatorIP, session.responderIP),
				Description:   fmt.Sprintf("IPsec tunnel between %s and %s is repeatedly rebuilding: %d IKE_SA_INIT requests (%d within a %.0fs window)", session.initiatorIP, session.responderIP, len(session.initTimes), maxInWindow, ikeWindowSeconds),
				StateChanges:  len(session.initTimes),
				WindowSeconds: window,
				FirstSeen:     session.firstSeen.Format(time.RFC3339),
				LastSeen:      session.lastSeen.Format(time.RFC3339),
				SourceIP:      session.initiatorIP,
				PeerIP:        session.responderIP,
				Protocol:      "IKE",
				RootCauseHint: "Underlying WAN link flapping causes IPsec tunnel teardown/rebuild. Check ISP link stability, DPD timers, and IKE lifetime settings. Run 'show crypto ikev2 sa detail'.",
			}
			report.StabilityFindings = append(report.StabilityFindings, finding)
		}
	}
}

func (sm *StabilityMonitor) finalizeSTPTCN(report *models.TriageReport) {
	if len(sm.stpTCN.tcnTimes) <= stpTCNThreshold {
		return
	}

	window := sm.stpTCN.lastSeen.Sub(sm.stpTCN.firstSeen).Seconds()
	if window < 1 {
		window = 1
	}

	finding := models.StabilityFinding{
		Type:          "STP TCN Storm",
		Severity:      "High",
		Identifier:    "Layer 2 Domain",
		Description:   fmt.Sprintf("STP Topology Change storm detected: %d TCN events in %.0f seconds (threshold: %d). Likely caused by a switch port flapping.", len(sm.stpTCN.tcnTimes), window, stpTCNThreshold),
		StateChanges:  len(sm.stpTCN.tcnTimes),
		WindowSeconds: window,
		FirstSeen:     sm.stpTCN.firstSeen.Format(time.RFC3339),
		LastSeen:      sm.stpTCN.lastSeen.Format(time.RFC3339),
		Protocol:      "STP",
		RootCauseHint: "A switch port is flapping (cable fault, SFP issue, or duplex mismatch), causing STP to recalculate. Identify the port with 'show spanning-tree detail' and 'show log | include %LINK'.",
	}
	report.StabilityFindings = append(report.StabilityFindings, finding)
}

// ── Helpers ─────────────────────────────────────────────────────────────────

// countInSlidingWindow returns the maximum number of events that fall within
// any sliding window of the given duration.
func countInSlidingWindow(times []time.Time, windowSec float64) int {
	if len(times) == 0 {
		return 0
	}

	maxCount := 0
	windowDur := time.Duration(windowSec * float64(time.Second))

	for i := 0; i < len(times); i++ {
		count := 0
		windowEnd := times[i].Add(windowDur)
		for j := i; j < len(times); j++ {
			if times[j].Before(windowEnd) || times[j].Equal(windowEnd) {
				count++
			} else {
				break
			}
		}
		if count > maxCount {
			maxCount = count
		}
	}

	return maxCount
}
