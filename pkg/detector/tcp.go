package detector

import (
	"fmt"
	"time"

	"github.com/gocisse/sdwan-triage/pkg/events"
	"github.com/gocisse/sdwan-triage/pkg/models"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// TCPAnalyzer handles TCP packet analysis.
// Correlation inputs (retransmissions, RTT spikes) are published as typed
// events on the report's event index rather than via private callbacks.
type TCPAnalyzer struct {
	rttSpikeThreshMs float64 // RTT threshold to emit a tcp.rtt_spike event
}

// NewTCPAnalyzer creates a new TCP analyzer
func NewTCPAnalyzer() *TCPAnalyzer {
	return &TCPAnalyzer{
		rttSpikeThreshMs: 200.0, // 200ms default threshold
	}
}

// SetHighRTTThreshold sets the RTT spike threshold in milliseconds
func (t *TCPAnalyzer) SetHighRTTThreshold(thresholdMs float64) {
	t.rttSpikeThreshMs = thresholdMs
}

// SetRetransmitThreshold is a placeholder for retransmit threshold configuration
// (TCPAnalyzer currently detects all retransmissions; threshold is applied during reporting)
func (t *TCPAnalyzer) SetRetransmitThreshold(threshold int) {
	// Stored for future use in filtering retransmission reports
	_ = threshold
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

	// Initialize flow state if needed (using bounded cache)
	flowState := state.GetTCPFlow(flowKey)
	if flowState == nil {
		flowState = models.NewTCPFlowState()
		state.SetTCPFlow(flowKey, flowState)
	}

	// Track handshakes
	t.analyzeHandshake(tcp, srcIP, dstIP, srcPort, dstPort, flowKey, reverseFlowKey, timestamp, state, report)

	// Detect retransmissions
	t.detectRetransmissions(tcp, srcIP, dstIP, srcPort, dstPort, flowKey, timestamp, flowState, report)

	// Calculate RTT from ACKs
	t.calculateRTT(tcp, reverseFlowKey, timestamp, state, report)

	// Device fingerprinting from SYN packets
	if tcp.SYN && !tcp.ACK {
		t.fingerprintDevice(tcp, srcIP, ttl, state, report)
	}

	// Update flow state
	flowState.LastSeq = tcp.Seq
	flowState.LastAck = tcp.Ack

	// Only segments that consume sequence space (data, SYN, FIN) are remembered.
	// A pure ACK shares its sequence number with the next data segment; recording
	// it made every connection's first data segment look like a retransmission.
	if len(tcp.Payload) > 0 || tcp.SYN || tcp.FIN {
		flowState.Seq.Record(tcp.Seq, timestamp)
		consumed := uint32(len(tcp.Payload))
		if tcp.SYN {
			consumed++
		}
		if tcp.FIN {
			consumed++
		}
		flowState.ObserveSegment(tcp.Seq, consumed)
	}

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
		state.MarkSynSent(flowKey, timestamp) // Store timestamp only, not the full packet

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
		report.AddTimelineEvent(event)
	}

	// SYN-ACK packet (connection response)
	if tcp.SYN && tcp.ACK {
		if _, exists := state.GetSynSent(reverseFlowKey); exists {
			state.MarkSynAckReceived(reverseFlowKey)

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
		if state.HasSynAckReceived(flowKey) {
			handshake := models.TCPHandshakeFlow{
				SrcIP:     srcIP,
				SrcPort:   srcPort,
				DstIP:     dstIP,
				DstPort:   dstPort,
				Timestamp: ts,
				Count:     1,
			}
			report.TCPHandshakes.SuccessfulHandshakes = append(report.TCPHandshakes.SuccessfulHandshakes, handshake)
			state.DeleteSynAckReceived(flowKey)
			state.DeleteSynSent(flowKey)
		}
	}

	// RST packet (connection reset - potential failed handshake)
	if tcp.RST {
		if _, exists := state.GetSynSent(reverseFlowKey); exists {
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
			state.DeleteSynSent(reverseFlowKey)
		}
	}
}

// detectRetransmissions identifies TCP retransmissions
func (t *TCPAnalyzer) detectRetransmissions(tcp *layers.TCP, srcIP, dstIP string, srcPort, dstPort uint16, flowKey string, timestamp time.Time, flowState *models.TCPFlowState, report *models.TriageReport) {
	// A TCP keep-alive probe (<=1 byte at highest_next_seq-1) legitimately
	// repeats its sequence number every interval; it is not a retransmission.
	// Only this exact pattern is excluded — a 1-byte segment elsewhere in the
	// stream is still eligible for retransmission detection.
	if flowState.IsKeepAlive(tcp.Seq, len(tcp.Payload)) {
		return
	}

	// Check if we've seen this sequence number before (retransmission)
	if len(tcp.Payload) > 0 && flowState.Seq.Seen(tcp.Seq) {
		flow := models.TCPFlow{
			SrcIP:   srcIP,
			SrcPort: srcPort,
			DstIP:   dstIP,
			DstPort: dstPort,
		}

		// Original send time (capture time only): the first transmission if
		// still remembered, else this packet's time.
		origTS, ok := flowState.Seq.Lookup(tcp.Seq)
		if !ok || origTS.IsZero() {
			origTS = timestamp
		}

		// Typed observation: one event per retransmitted segment, stamped with
		// the retransmission's own capture time (the packet being analysed).
		// original_ts_us lets consumers recover the first-send instant exactly.
		report.Emit(events.Event{
			Kind:      events.TCPRetransmission,
			Timestamp: timestamp,
			FlowKey:   flowKey,
			Values: map[string]float64{
				"seq":               float64(tcp.Seq),
				"payload_len":       float64(len(tcp.Payload)),
				"since_original_ms": timestamp.Sub(origTS).Seconds() * 1000,
				"original_ts_us":    float64(origTS.UnixMicro()),
			},
			Attrs:  map[string]string{"src_ip": srcIP, "dst_ip": dstIP},
			Source: "TCP",
		})

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

	// Look for the original packet this ACK is responding to (using bounded cache)
	reverseState := state.GetTCPFlow(reverseFlowKey)
	if reverseState != nil {
		if sentTime, ok := reverseState.Seq.Lookup(tcp.Ack - 1); ok {
			rtt := timestamp.Sub(sentTime).Seconds() * 1000 // Convert to milliseconds
			if rtt > 0 && rtt < 10000 {                     // Sanity check: RTT should be < 10 seconds
				reverseState.AddRTTSample(rtt)

				// Publish RTT spikes for correlation
				if rtt >= t.rttSpikeThreshMs {
					report.Emit(events.Event{
						Kind:      events.TCPRTTSpike,
						Timestamp: timestamp,
						FlowKey:   reverseFlowKey,
						Values:    map[string]float64{"rtt_ms": rtt},
						Source:    "TCP",
					})
				}
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

	// Store fingerprint (using bounded cache)
	state.SetDeviceFingerprint(srcIP, fp)

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
