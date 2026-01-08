package detector

import (
	"fmt"
	"time"

	"github.com/gocisse/sdwan-triage/pkg/models"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// TCPAnalyzer handles TCP packet analysis
type TCPAnalyzer struct{}

// NewTCPAnalyzer creates a new TCP analyzer
func NewTCPAnalyzer() *TCPAnalyzer {
	return &TCPAnalyzer{}
}

// Analyze processes a TCP packet and updates the report
func (t *TCPAnalyzer) Analyze(packet gopacket.Packet, state *models.AnalysisState, report *models.TriageReport) {
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		return
	}

	tcp, ok := tcpLayer.(*layers.TCP)
	if !ok {
		return
	}

	// Get IP layer info (supports IPv4 and IPv6)
	ipInfo := ExtractIPInfo(packet)
	if ipInfo == nil {
		return
	}
	srcIP := ipInfo.SrcIP
	dstIP := ipInfo.DstIP
	ttl := ipInfo.TTL

	srcPort := uint16(tcp.SrcPort)
	dstPort := uint16(tcp.DstPort)
	flowKey := fmt.Sprintf("%s:%d->%s:%d", srcIP, srcPort, dstIP, dstPort)
	reverseFlowKey := fmt.Sprintf("%s:%d->%s:%d", dstIP, dstPort, srcIP, srcPort)
	timestamp := packet.Metadata().Timestamp

	// Initialize flow state if needed
	if state.TCPFlows[flowKey] == nil {
		state.TCPFlows[flowKey] = &models.TCPFlowState{
			SeqSeen:   make(map[uint32]bool),
			SentTimes: make(map[uint32]time.Time),
		}
	}
	flowState := state.TCPFlows[flowKey]

	// Track handshakes
	t.analyzeHandshake(tcp, srcIP, dstIP, srcPort, dstPort, flowKey, reverseFlowKey, timestamp, state, report)

	// Detect retransmissions
	t.detectRetransmissions(tcp, srcIP, dstIP, srcPort, dstPort, flowKey, flowState, report)

	// Calculate RTT from ACKs
	t.calculateRTT(tcp, reverseFlowKey, timestamp, state, report)

	// Device fingerprinting from SYN packets
	if tcp.SYN && !tcp.ACK {
		t.fingerprintDevice(tcp, srcIP, ttl, state, report)
	}

	// Update flow state
	flowState.LastSeq = tcp.Seq
	flowState.LastAck = tcp.Ack
	flowState.SeqSeen[tcp.Seq] = true
	flowState.SentTimes[tcp.Seq] = timestamp

	// Track bytes
	payloadLen := uint64(len(tcp.Payload))
	flowState.TotalBytes += payloadLen
	report.TotalBytes += payloadLen
}

// analyzeHandshake tracks TCP handshake states
func (t *TCPAnalyzer) analyzeHandshake(tcp *layers.TCP, srcIP, dstIP string, srcPort, dstPort uint16, flowKey, reverseFlowKey string, timestamp time.Time, state *models.AnalysisState, report *models.TriageReport) {
	ts := float64(timestamp.UnixNano()) / 1e9

	// SYN packet (connection initiation)
	if tcp.SYN && !tcp.ACK {
		state.SynSent[flowKey] = nil // We don't need to store the packet, just track the key

		// Add to handshake analysis
		handshake := models.TCPHandshakeFlow{
			SrcIP:     srcIP,
			SrcPort:   srcPort,
			DstIP:     dstIP,
			DstPort:   dstPort,
			Timestamp: ts,
			Count:     1,
		}
		report.TCPHandshakes.SYNFlows = append(report.TCPHandshakes.SYNFlows, handshake)

		// Add timeline event
		event := models.TimelineEvent{
			Timestamp:     ts,
			EventType:     "TCP SYN",
			SourceIP:      srcIP,
			DestinationIP: dstIP,
			Protocol:      "TCP",
			Detail:        fmt.Sprintf("Connection attempt to port %d", dstPort),
		}
		srcPortPtr := srcPort
		dstPortPtr := dstPort
		event.SourcePort = &srcPortPtr
		event.DestinationPort = &dstPortPtr
		report.Timeline = append(report.Timeline, event)
	}

	// SYN-ACK packet (connection response)
	if tcp.SYN && tcp.ACK {
		if _, exists := state.SynSent[reverseFlowKey]; exists {
			state.SynAckReceived[reverseFlowKey] = true

			handshake := models.TCPHandshakeFlow{
				SrcIP:     srcIP,
				SrcPort:   srcPort,
				DstIP:     dstIP,
				DstPort:   dstPort,
				Timestamp: ts,
				Count:     1,
			}
			report.TCPHandshakes.SYNACKFlows = append(report.TCPHandshakes.SYNACKFlows, handshake)
		}
	}

	// ACK packet completing handshake
	if tcp.ACK && !tcp.SYN && !tcp.FIN && !tcp.RST {
		if state.SynAckReceived[flowKey] {
			handshake := models.TCPHandshakeFlow{
				SrcIP:     srcIP,
				SrcPort:   srcPort,
				DstIP:     dstIP,
				DstPort:   dstPort,
				Timestamp: ts,
				Count:     1,
			}
			report.TCPHandshakes.SuccessfulHandshakes = append(report.TCPHandshakes.SuccessfulHandshakes, handshake)
			delete(state.SynAckReceived, flowKey)
			delete(state.SynSent, flowKey)
		}
	}

	// RST packet (connection reset - potential failed handshake)
	if tcp.RST {
		if _, exists := state.SynSent[reverseFlowKey]; exists {
			handshake := models.TCPHandshakeFlow{
				SrcIP:     dstIP,
				SrcPort:   dstPort,
				DstIP:     srcIP,
				DstPort:   srcPort,
				Timestamp: ts,
				Count:     1,
			}
			report.TCPHandshakes.FailedHandshakeAttempts = append(report.TCPHandshakes.FailedHandshakeAttempts, handshake)

			// Also add to failed handshakes list
			flow := models.TCPFlow{
				SrcIP:   dstIP,
				SrcPort: dstPort,
				DstIP:   srcIP,
				DstPort: srcPort,
			}
			report.FailedHandshakes = append(report.FailedHandshakes, flow)
			delete(state.SynSent, reverseFlowKey)
		}
	}
}

// detectRetransmissions identifies TCP retransmissions
func (t *TCPAnalyzer) detectRetransmissions(tcp *layers.TCP, srcIP, dstIP string, srcPort, dstPort uint16, flowKey string, flowState *models.TCPFlowState, report *models.TriageReport) {
	// Check if we've seen this sequence number before (retransmission)
	if flowState.SeqSeen[tcp.Seq] && len(tcp.Payload) > 0 {
		flow := models.TCPFlow{
			SrcIP:   srcIP,
			SrcPort: srcPort,
			DstIP:   dstIP,
			DstPort: dstPort,
		}

		// Check if this flow is already in retransmissions
		found := false
		for _, existing := range report.TCPRetransmissions {
			if existing.SrcIP == srcIP && existing.DstIP == dstIP &&
				existing.SrcPort == srcPort && existing.DstPort == dstPort {
				found = true
				break
			}
		}

		if !found {
			report.TCPRetransmissions = append(report.TCPRetransmissions, flow)
		}
	}
}

// calculateRTT calculates round-trip time from ACK packets
func (t *TCPAnalyzer) calculateRTT(tcp *layers.TCP, reverseFlowKey string, timestamp time.Time, state *models.AnalysisState, report *models.TriageReport) {
	if !tcp.ACK {
		return
	}

	// Look for the original packet this ACK is responding to
	if reverseState, exists := state.TCPFlows[reverseFlowKey]; exists {
		if sentTime, ok := reverseState.SentTimes[tcp.Ack-1]; ok {
			rtt := timestamp.Sub(sentTime).Seconds() * 1000 // Convert to milliseconds
			if rtt > 0 && rtt < 10000 {                     // Sanity check: RTT should be < 10 seconds
				reverseState.RTTSamples = append(reverseState.RTTSamples, rtt)
			}
		}
	}
}

// fingerprintDevice extracts TCP fingerprint for OS detection
func (t *TCPAnalyzer) fingerprintDevice(tcp *layers.TCP, srcIP string, ttl uint8, state *models.AnalysisState, report *models.TriageReport) {
	fp := &models.TCPFingerprint{
		WindowSize: tcp.Window,
		TTL:        ttl,
	}

	// Parse TCP options
	for _, opt := range tcp.Options {
		switch opt.OptionType {
		case layers.TCPOptionKindMSS:
			if len(opt.OptionData) >= 2 {
				fp.MSS = uint16(opt.OptionData[0])<<8 | uint16(opt.OptionData[1])
			}
		case layers.TCPOptionKindTimestamps:
			fp.HasTS = true
		case layers.TCPOptionKindSACKPermitted:
			fp.HasSACK = true
		case layers.TCPOptionKindWindowScale:
			fp.HasWS = true
		}
	}

	// Store fingerprint
	state.DeviceFingerprints[srcIP] = fp

	// Guess OS from fingerprint
	deviceType, osGuess, confidence := guessOSFromFingerprint(fp)

	// Check if we already have this device
	found := false
	for _, existing := range report.DeviceFingerprinting {
		if existing.SrcIP == srcIP {
			found = true
			break
		}
	}

	if !found {
		fingerprint := models.DeviceFingerprint{
			SrcIP:      srcIP,
			DeviceType: deviceType,
			OSGuess:    osGuess,
			Confidence: confidence,
			Details:    fmt.Sprintf("Window: %d, TTL: %d, MSS: %d", fp.WindowSize, fp.TTL, fp.MSS),
		}
		report.DeviceFingerprinting = append(report.DeviceFingerprinting, fingerprint)
	}
}

// guessOSFromFingerprint attempts to identify OS from TCP fingerprint
func guessOSFromFingerprint(fp *models.TCPFingerprint) (string, string, string) {
	// Windows signatures
	if fp.WindowSize == 8192 && fp.TTL >= 128 && fp.TTL <= 130 {
		return "Windows", "Windows 7/8/10", "High"
	}
	if fp.WindowSize == 65535 && fp.TTL >= 128 && fp.TTL <= 130 {
		return "Windows", "Windows 10/11", "High"
	}

	// Linux signatures
	if fp.TTL >= 64 && fp.TTL <= 66 {
		if fp.WindowSize == 5840 || fp.WindowSize == 14600 || fp.WindowSize == 29200 {
			return "Linux", "Linux 2.6/3.x/4.x", "High"
		}
		if fp.HasTS && fp.HasSACK && fp.HasWS {
			return "Linux", "Linux (modern)", "Medium"
		}
	}

	// macOS/iOS signatures
	if fp.TTL >= 64 && fp.TTL <= 66 && fp.WindowSize == 65535 {
		return "Apple", "macOS/iOS", "Medium"
	}

	// Android signatures
	if fp.TTL >= 64 && fp.TTL <= 66 && fp.WindowSize >= 14000 && fp.WindowSize <= 15000 {
		return "Mobile", "Android", "Medium"
	}

	// Network device signatures
	if fp.TTL == 255 {
		return "Network Device", "Router/Switch", "Medium"
	}

	// Default
	if fp.TTL >= 128 {
		return "Unknown", "Windows-like", "Low"
	}
	return "Unknown", "Unix-like", "Low"
}
