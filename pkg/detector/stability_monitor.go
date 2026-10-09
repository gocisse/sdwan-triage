package detector

import (
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/gocisse/sdwan-triage/pkg/events"
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

	// maxTrackedTransitions bounds per-session timestamp histories (BFD
	// transitions, IKE SA_INIT bursts, STP TCNs). The flapping thresholds are
	// all < 10 events per window, so 1024 retained events is far more than the
	// detectors need while keeping a pathological flap storm at ~24 KB.
	maxTrackedTransitions = 1024
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

// bfdDownInfo is what the packet showing an Up → non-Up transition said about it.
type bfdDownInfo struct {
	diag     uint8
	newState uint8
	frame    uint64
}

// bfdDiagName names an RFC 5880 §4.1 diagnostic code.
func bfdDiagName(d uint8) string {
	switch d {
	case 0:
		return "No Diagnostic"
	case 1:
		return "Control Detection Time Expired"
	case 2:
		return "Echo Function Failed"
	case 3:
		return "Neighbor Signaled Session Down"
	case 4:
		return "Forwarding Plane Reset"
	case 5:
		return "Path Down"
	case 6:
		return "Concatenated Path Down"
	case 7:
		return "Administratively Down"
	case 8:
		return "Reverse Concatenated Path Down"
	}
	return fmt.Sprintf("Unknown diagnostic %d", d)
}

// bfdDownHint states what the sender's own diagnostic code says and what it does not. The
// code is the sender's report about its own session; this capture does not show the cause.
func bfdDownHint(d bfdDownInfo) string {
	const tail = " Check 'show bfd neighbors detail' on both endpoints."
	switch {
	case d.newState == bfdStateAdminDown || d.diag == 7:
		return "The sender reported Administratively Down: a deliberate local shutdown or configuration change, not a detected path failure." + tail
	case d.diag == 1:
		return "The sender reported that its control detection time expired, i.e. it had stopped receiving the peer's BFD control packets. " +
			"Whether the cause is the underlay path, the peer or filtering is not established by this capture; check whether the peer's packets are present in it." + tail
	case d.diag == 2:
		return "The sender reported that the BFD echo function failed (echo packets it sent were not returned); the cause is not established by this capture." + tail
	case d.diag == 3:
		return "The sender went down after the neighbor signalled Down; look at the neighbor's own state and diagnostic code for the reason." + tail
	case d.diag >= 4 && d.diag <= 6, d.diag == 8:
		return "The sender reported \"" + bfdDiagName(d.diag) + "\" (a path or forwarding-plane condition it detected or was told about); this capture does not establish where." + tail
	case d.diag == 0:
		return "The sender went down without a diagnostic code, so the capture shows the state change but not its cause (underlay, peer or configuration)." + tail
	}
	return "The sender reported \"" + bfdDiagName(d.diag) + "\"; this capture shows the state change, not its cause." + tail
}

// bfdSession tracks BFD state transitions per peer pair.
type bfdSession struct {
	srcIP       string
	peerIP      string
	lastState   uint8
	transitions []time.Time // timestamps of Up→Down or Down→Up transitions (bounded)
	downEvents  []time.Time // timestamps of Up→Down transitions only (bounded)
	// downInfo is parallel to downEvents (Phase 4.38): the diagnostic code, new state and
	// capture frame carried by the packet that showed each Up → non-Up transition.
	downInfo    []bfdDownInfo
	firstSeen   time.Time
	lastSeen    time.Time
	packetCount int
}

// ikeSession tracks IKE_SA_INIT requests per peer pair.
type ikeSession struct {
	initiatorIP string
	responderIP string
	// initTimes holds one timestamp per DISTINCT IKE SA initiation (Phase 4.37): the first
	// packet of each initiator SPI / IKEv1 initiator cookie. Repeats of the same initiation
	// are retransmissions and are counted in retransmits, not in initTimes.
	initTimes      []time.Time
	spis           map[string]bool // initiator SPIs seen (bounded by maxTrackedTransitions)
	retransmits    int
	untrackedSPIs  int
	firstInitFrame uint64
	firstSeen      time.Time
	lastSeen       time.Time
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
		report.AddTimelineEvent(event)
		return
	}

	session.lastSeen = ts
	session.packetCount++

	// Detect state transition
	if currentState != session.lastState {
		if len(session.transitions) < maxTrackedTransitions {
			session.transitions = append(session.transitions, ts)
		}
		if session.lastState == bfdStateUp && currentState != bfdStateUp {
			frame, _ := currentFrame(report, ts)
			diag := payload[0] & 0x1f
			if len(session.downEvents) < maxTrackedTransitions {
				session.downEvents = append(session.downEvents, ts)
				session.downInfo = append(session.downInfo, bfdDownInfo{diag: diag, newState: currentState, frame: frame})
			}
			report.Emit(events.Event{
				Kind:      events.BFDDown,
				Timestamp: ts,
				Values: map[string]float64{
					"prev_state": float64(session.lastState),
					"new_state":  float64(currentState),
				},
				Attrs: map[string]string{"src_ip": ipInfo.SrcIP, "peer_ip": ipInfo.DstIP, "new_state_name": bfdStateName(currentState),
					"diag": fmt.Sprintf("%d", diag), "diag_name": bfdDiagName(diag)},
				Source: "Stability",
			})
		}

		event := models.TimelineEvent{
			Timestamp:     float64(ts.UnixNano()) / 1e9,
			EventType:     "BFD State Change",
			SourceIP:      ipInfo.SrcIP,
			DestinationIP: ipInfo.DstIP,
			Protocol:      "BFD",
			Detail:        fmt.Sprintf("BFD %s → %s: %s → %s", ipInfo.SrcIP, ipInfo.DstIP, bfdStateName(session.lastState), bfdStateName(currentState)),
		}
		report.AddTimelineEvent(event)

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

	// Byte 19: Flags — bit 3 (0x08) = Initiator flag, bit 5 (0x20) = Response flag (IKEv2)
	flags := ikePayload[19]
	isInitiator := (flags & 0x08) != 0
	isResponse := (flags & 0x20) != 0

	// A NEW IKE SA initiation (Phase 4.37) is the first message of an exchange, identified by
	// the initiator SPI: an IKEv2 IKE_SA_INIT request (exchange 34, initiator flag, not a
	// response, responder SPI zero) or the first IKEv1 Main Mode message (exchange 2,
	// message ID 0, responder cookie zero). Responses and the later Main Mode messages that
	// the same side sends are not initiations; repeats of the same initiator SPI are
	// retransmissions.
	responderSPIZero := true
	for _, b := range ikePayload[8:16] {
		if b != 0 {
			responderSPIZero = false
		}
	}
	isIKESAInit := false
	if majorVersion == 2 && exchangeType == 34 && isInitiator && !isResponse && responderSPIZero {
		isIKESAInit = true
	} else if majorVersion == 1 && exchangeType == 2 {
		// IKEv1 Main Mode — the initiator's first message has message ID 0 and no responder cookie yet
		msgID := uint32(ikePayload[20])<<24 | uint32(ikePayload[21])<<16 | uint32(ikePayload[22])<<8 | uint32(ikePayload[23])
		if msgID == 0 && responderSPIZero {
			isIKESAInit = true
		}
	}

	if !isIKESAInit {
		return
	}
	spiKey := fmt.Sprintf("v%d/%x", majorVersion, ikePayload[0:8])

	ipInfo := ExtractIPInfo(packet)
	if ipInfo == nil {
		return
	}

	sessionKey := fmt.Sprintf("%s->%s", ipInfo.SrcIP, ipInfo.DstIP)

	session, exists := sm.ikeSessions[sessionKey]
	frame, _ := currentFrame(report, ts)
	if !exists {
		sm.ikeSessions[sessionKey] = &ikeSession{
			initiatorIP:    ipInfo.SrcIP,
			responderIP:    ipInfo.DstIP,
			initTimes:      []time.Time{ts},
			spis:           map[string]bool{spiKey: true},
			firstInitFrame: frame,
			firstSeen:      ts,
			lastSeen:       ts,
		}

		event := models.TimelineEvent{
			Timestamp:     float64(ts.UnixNano()) / 1e9,
			EventType:     "IKE SA Init",
			SourceIP:      ipInfo.SrcIP,
			DestinationIP: ipInfo.DstIP,
			Protocol:      "IKE",
			Detail:        fmt.Sprintf("IKEv%d SA_INIT from %s → %s", majorVersion, ipInfo.SrcIP, ipInfo.DstIP),
		}
		report.AddTimelineEvent(event)
		return
	}

	session.lastSeen = ts
	if session.spis[spiKey] {
		// The same initiator SPI again: a retransmission of an initiation, not a new SA.
		session.retransmits++
		return
	}
	if len(session.spis) >= maxTrackedTransitions {
		session.untrackedSPIs++
		return
	}
	session.spis[spiKey] = true
	if len(session.initTimes) < maxTrackedTransitions {
		session.initTimes = append(session.initTimes, ts)
	}

	event := models.TimelineEvent{
		Timestamp:     float64(ts.UnixNano()) / 1e9,
		EventType:     "IKE SA Init",
		SourceIP:      ipInfo.SrcIP,
		DestinationIP: ipInfo.DstIP,
		Protocol:      "IKE",
		Detail:        fmt.Sprintf("IKEv%d SA_INIT #%d from %s → %s", majorVersion, len(session.initTimes), ipInfo.SrcIP, ipInfo.DstIP),
	}
	report.AddTimelineEvent(event)
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
			if len(sm.stpTCN.tcnTimes) < maxTrackedTransitions {
				sm.stpTCN.tcnTimes = append(sm.stpTCN.tcnTimes, ts)
			}
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
			report.AddTimelineEvent(event)
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
			if len(sm.stpTCN.tcnTimes) < maxTrackedTransitions {
				sm.stpTCN.tcnTimes = append(sm.stpTCN.tcnTimes, ts)
			}
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
			report.AddTimelineEvent(event)
		}
	}
}

// ObservedUnits returns how many stability-protocol units this monitor saw:
// BFD sessions, IKE SA_INIT sessions and STP TCN BPDUs. Read-only; it exposes
// existing state and changes no detection behavior.
func (sm *StabilityMonitor) ObservedUnits() int {
	return len(sm.bfdSessions) + len(sm.ikeSessions) + len(sm.stpTCN.tcnTimes)
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
	// Sorted keys: finding order must not depend on Go map iteration order.
	for _, key := range slices.Sorted(maps.Keys(sm.bfdSessions)) {
		session := sm.bfdSessions[key]
		if len(session.transitions) == 0 {
			continue
		}

		// Count transitions that fall within any sliding 60-second window
		maxInWindow := countInSlidingWindow(session.transitions, bfdWindowSeconds)

		if maxInWindow <= bfdFlappingThreshold && len(session.downEvents) > 0 {
			// Not flapping, but the session did go down: a single Up→Down is
			// first-class SD-WAN evidence (tunnel/path loss) and must be visible.
			first := session.downEvents[0]
			last := session.downEvents[len(session.downEvents)-1]
			finding := models.StabilityFinding{
				Type:          "BFD Session Down",
				Severity:      "High",
				Identifier:    fmt.Sprintf("%s ↔ %s", session.srcIP, session.peerIP),
				Description:   fmt.Sprintf("BFD session between %s and %s transitioned Up → Down at %s (%d down event(s), %d state transitions in capture)%s", session.srcIP, session.peerIP, first.Format(time.RFC3339), len(session.downEvents), len(session.transitions), bfdDownDetail(session)),
				StateChanges:  len(session.downEvents),
				WindowSeconds: last.Sub(first).Seconds(),
				FirstSeen:     first.Format(time.RFC3339),
				LastSeen:      session.lastSeen.Format(time.RFC3339),
				SourceIP:      session.srcIP,
				PeerIP:        session.peerIP,
				Protocol:      "BFD",
				RootCauseHint: bfdFirstDownHint(session),
			}
			report.StabilityFindings = append(report.StabilityFindings, finding)
			continue
		}

		if maxInWindow > bfdFlappingThreshold {
			window := session.lastSeen.Sub(session.firstSeen).Seconds()
			if window < 1 {
				window = 1
			}

			finding := models.StabilityFinding{
				Type:          "BFD Flapping",
				Severity:      "Critical",
				Identifier:    fmt.Sprintf("%s ↔ %s", session.srcIP, session.peerIP),
				Description:   fmt.Sprintf("BFD session between %s and %s flapping: %d state transitions detected (%d within a %.0fs window)%s", session.srcIP, session.peerIP, len(session.transitions), maxInWindow, bfdWindowSeconds, bfdDownSummary(session)),
				StateChanges:  len(session.transitions),
				WindowSeconds: window,
				FirstSeen:     session.firstSeen.Format(time.RFC3339),
				LastSeen:      session.lastSeen.Format(time.RFC3339),
				SourceIP:      session.srcIP,
				PeerIP:        session.peerIP,
				Protocol:      "BFD",
				RootCauseHint: "Possible causes include underlay instability, BFD timer settings or peer restarts; this capture shows the state changes (and the sender's diagnostic codes, if any), not which cause applies. Check 'show bfd neighbors detail' on both endpoints.",
			}
			report.StabilityFindings = append(report.StabilityFindings, finding)
		}
	}
}

// bfdFirstDownHint returns the hint for the first Up → non-Up transition of a session.
func bfdFirstDownHint(s *bfdSession) string {
	if len(s.downInfo) == 0 {
		return "The capture shows the state change, not its cause. Check 'show bfd neighbors detail' on both endpoints."
	}
	return bfdDownHint(s.downInfo[0])
}

// bfdDownDetail describes the packet that showed the first Down transition.
func bfdDownDetail(s *bfdSession) string {
	if len(s.downInfo) == 0 {
		return ""
	}
	d := s.downInfo[0]
	text := fmt.Sprintf("; the first Down packet from %s carried diagnostic code %d (%s)", s.srcIP, d.diag, bfdDiagName(d.diag))
	if d.frame != 0 {
		text += fmt.Sprintf(" at frame %d", d.frame)
	}
	return text
}

// bfdDownSummary counts the diagnostic codes carried by a session's Down transitions.
func bfdDownSummary(s *bfdSession) string {
	if len(s.downInfo) == 0 {
		return ""
	}
	counts := map[uint8]int{}
	for _, d := range s.downInfo {
		counts[d.diag]++
	}
	codes := make([]int, 0, len(counts))
	for c := range counts {
		codes = append(codes, int(c))
	}
	slices.Sort(codes)
	parts := make([]string, 0, len(codes))
	for _, c := range codes {
		parts = append(parts, fmt.Sprintf("%s ×%d", bfdDiagName(uint8(c)), counts[uint8(c)]))
	}
	text := fmt.Sprintf("; %d Up → Down transition(s) from %s, diagnostic codes: %s", len(s.downInfo), s.srcIP, strings.Join(parts, ", "))
	if f := s.downInfo[0].frame; f != 0 {
		text += fmt.Sprintf("; first at frame %d", f)
	}
	return text
}

func (sm *StabilityMonitor) finalizeIKE(report *models.TriageReport) {
	for _, key := range slices.Sorted(maps.Keys(sm.ikeSessions)) {
		session := sm.ikeSessions[key]
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
				Type:       "IKE Tunnel Rebuild",
				Severity:   "High",
				Identifier: fmt.Sprintf("%s → %s", session.initiatorIP, session.responderIP),
				Description: fmt.Sprintf("IPsec peers %s and %s show repeated IKE initiations: %d distinct IKE SAs initiated by %s (%d within a %.0fs window)%s; first initiation%s. Retransmissions of an initiation are not counted.",
					session.initiatorIP, session.responderIP, len(session.initTimes), session.initiatorIP, maxInWindow, ikeWindowSeconds, ikeRetransText(session), ikeFrameText(session)),
				StateChanges:  len(session.initTimes),
				WindowSeconds: window,
				FirstSeen:     session.firstSeen.Format(time.RFC3339),
				LastSeen:      session.lastSeen.Format(time.RFC3339),
				SourceIP:      session.initiatorIP,
				PeerIP:        session.responderIP,
				Protocol:      "IKE",
				RootCauseHint: "Repeated new IKE SAs can follow tunnel teardown or rekeying (for example underlay instability, DPD or lifetime settings, or peer restarts); this capture shows the initiations, not which cause applies. Check 'show crypto ikev2 sa detail' on both endpoints.",
			}
			report.StabilityFindings = append(report.StabilityFindings, finding)
		}
	}
}

func ikeRetransText(s *ikeSession) string {
	if s.retransmits == 0 && s.untrackedSPIs == 0 {
		return ""
	}
	t := fmt.Sprintf("; %d retransmission(s) of an initiation seen", s.retransmits)
	if s.untrackedSPIs > 0 {
		t += fmt.Sprintf(", %d further initiation(s) not tracked (bound reached)", s.untrackedSPIs)
	}
	return t
}

func ikeFrameText(s *ikeSession) string {
	if s.firstInitFrame == 0 {
		return ""
	}
	return fmt.Sprintf(" at frame %d", s.firstInitFrame)
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
