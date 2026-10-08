package detector

import (
	"fmt"
	"maps"
	"slices"

	"github.com/gocisse/sdwan-triage/pkg/events"
	"github.com/gocisse/sdwan-triage/pkg/models"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// TCP Advanced analysis thresholds
// maxAdvancedTrackedFlows caps the per-flow window/out-of-order tracker maps.
// Trackers are ~64 bytes, so 100k flows ≈ 6 MB per map; matches
// models.DefaultMaxFlows used by AnalysisState.
const maxAdvancedTrackedFlows = 100000

const (
	ZeroWindowThreshold  = 3    // Number of zero-window events to report
	SmallWindowThreshold = 5    // Number of small-window events to report
	SmallWindowSize      = 1024 // Window size considered "small"
	OutOfOrderMinCount   = 10   // Minimum OOO packets to report
	OutOfOrderMinPercent = 2.0  // Minimum OOO percentage to report
)

// TCPAdvancedAnalyzer detects TCP window issues and out-of-order packets
type TCPAdvancedAnalyzer struct {
	windowIssues map[string]*tcpWindowTracker
	oooFlows     map[string]*tcpOOOTracker
	// conns holds the Window Scale evidence seen in each connection's handshake,
	// keyed by the client->server (SYN) direction.
	conns map[string]*tcpScaleState
}

// maxWindowScaleShift is the largest shift RFC 7323 allows (a larger value is
// treated as 14).
const maxWindowScaleShift = 14

// tcpScaleState is the Window Scale evidence observed in one connection's
// handshake. The option is per direction: the SYN sender's shift applies to the
// windows it advertises, the SYN-ACK sender's shift to the windows the server
// advertises. Scaling is in effect only if BOTH sides sent the option.
type tcpScaleState struct {
	synSeen, synHasOpt       bool
	synAckSeen, synAckHasOpt bool
	synShift, synAckShift    uint8
}

// resolve reports whether the scale of each direction is known and, if so,
// the shift to apply to client->server (clientShift) and server->client
// (serverShift) windows. Unknown means the capture does not contain enough of
// the handshake to establish it; callers must not assume shift 0 in that case.
func (c *tcpScaleState) resolve() (known bool, clientShift, serverShift uint8) {
	switch {
	case c.synSeen && !c.synHasOpt, c.synAckSeen && !c.synAckHasOpt:
		// Either side omitting the option disables scaling in both directions.
		return true, 0, 0
	case c.synSeen && c.synAckSeen && c.synHasOpt && c.synAckHasOpt:
		return true, c.synShift, c.synAckShift
	}
	return false, 0, 0
}

// windowScaleOption returns the Window Scale shift carried by a TCP segment.
func windowScaleOption(tcp *layers.TCP) (shift uint8, ok bool) {
	for _, opt := range tcp.Options {
		if opt.OptionType == layers.TCPOptionKindWindowScale && len(opt.OptionData) >= 1 {
			s := opt.OptionData[0]
			if s > maxWindowScaleShift {
				s = maxWindowScaleShift
			}
			return s, true
		}
	}
	return 0, false
}

type tcpWindowTracker struct {
	SrcIP      string
	DstIP      string
	SrcPort    uint16
	DstPort    uint16
	ZeroCount  int
	SmallCount int
	LastWindow uint16
}

type tcpOOOTracker struct {
	SrcIP        string
	DstIP        string
	SrcPort      uint16
	DstPort      uint16
	LastSeq      uint32
	TotalPackets int
	OOOCount     int
	Initialized  bool
}

// NewTCPAdvancedAnalyzer creates a new TCP advanced analyzer
func NewTCPAdvancedAnalyzer() *TCPAdvancedAnalyzer {
	return &TCPAdvancedAnalyzer{
		windowIssues: make(map[string]*tcpWindowTracker),
		oooFlows:     make(map[string]*tcpOOOTracker),
		conns:        make(map[string]*tcpScaleState),
	}
}

// Analyze processes TCP packets for window issues and out-of-order detection
func (t *TCPAdvancedAnalyzer) Analyze(packet gopacket.Packet, state *models.AnalysisState, report *models.TriageReport) {
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		return
	}

	tcp, ok := tcpLayer.(*layers.TCP)
	if !ok {
		return
	}

	ipInfo := ExtractIPInfo(packet)
	if ipInfo == nil {
		return
	}

	srcPort := uint16(tcp.SrcPort)
	dstPort := uint16(tcp.DstPort)
	flowKey := fmt.Sprintf("%s:%d->%s:%d", ipInfo.SrcIP, srcPort, ipInfo.DstIP, dstPort)
	ts := float64(packet.Metadata().Timestamp.UnixNano()) / 1e9

	// Learn Window Scale from the handshake (must run before analyzeWindow skips SYNs).
	t.learnWindowScale(tcp, ipInfo, srcPort, dstPort)

	// --- Window Size Analysis ---
	t.analyzeWindow(tcp, ipInfo, srcPort, dstPort, flowKey, ts, report)

	// --- Out-of-Order Detection ---
	if len(tcp.Payload) > 0 {
		t.analyzeOutOfOrder(tcp, ipInfo, srcPort, dstPort, flowKey, report)
	}
}

// learnWindowScale records the Window Scale option of a SYN (client direction)
// or SYN-ACK (server direction). A new SYN starts a fresh connection record.
func (t *TCPAdvancedAnalyzer) learnWindowScale(tcp *layers.TCP, ipInfo *PacketIPInfo, srcPort, dstPort uint16) {
	if !tcp.SYN {
		return
	}
	shift, has := windowScaleOption(tcp)
	if !tcp.ACK {
		key := fmt.Sprintf("%s:%d->%s:%d", ipInfo.SrcIP, srcPort, ipInfo.DstIP, dstPort)
		if _, exists := t.conns[key]; !exists && len(t.conns) >= maxAdvancedTrackedFlows {
			return
		}
		t.conns[key] = &tcpScaleState{synSeen: true, synHasOpt: has, synShift: shift}
		return
	}
	// SYN-ACK: the connection is keyed by the client->server direction.
	key := fmt.Sprintf("%s:%d->%s:%d", ipInfo.DstIP, dstPort, ipInfo.SrcIP, srcPort)
	c, exists := t.conns[key]
	if !exists {
		if len(t.conns) >= maxAdvancedTrackedFlows {
			return
		}
		c = &tcpScaleState{}
		t.conns[key] = c
	}
	c.synAckSeen, c.synAckHasOpt, c.synAckShift = true, has, shift
}

// effectiveWindow returns the advertised window in bytes for a packet sent from
// ipInfo.Src to ipInfo.Dst, or ok=false when the Window Scale for that
// direction is unknown (handshake not captured).
func (t *TCPAdvancedAnalyzer) effectiveWindow(tcp *layers.TCP, ipInfo *PacketIPInfo, srcPort, dstPort uint16) (window uint64, ok bool) {
	fwd := fmt.Sprintf("%s:%d->%s:%d", ipInfo.SrcIP, srcPort, ipInfo.DstIP, dstPort)
	if c, exists := t.conns[fwd]; exists { // packet travels client->server
		known, clientShift, _ := c.resolve()
		if !known {
			return 0, false
		}
		return uint64(tcp.Window) << clientShift, true
	}
	rev := fmt.Sprintf("%s:%d->%s:%d", ipInfo.DstIP, dstPort, ipInfo.SrcIP, srcPort)
	if c, exists := t.conns[rev]; exists { // packet travels server->client
		known, _, serverShift := c.resolve()
		if !known {
			return 0, false
		}
		return uint64(tcp.Window) << serverShift, true
	}
	return 0, false
}

func (t *TCPAdvancedAnalyzer) analyzeWindow(tcp *layers.TCP, ipInfo *PacketIPInfo, srcPort, dstPort uint16, flowKey string, ts float64, report *models.TriageReport) {
	// Skip SYN/FIN/RST packets for window analysis
	if tcp.SYN || tcp.FIN || tcp.RST {
		return
	}

	tracker, exists := t.windowIssues[flowKey]
	if !exists {
		if len(t.windowIssues) >= maxAdvancedTrackedFlows {
			return
		}
		tracker = &tcpWindowTracker{
			SrcIP:   ipInfo.SrcIP,
			DstIP:   ipInfo.DstIP,
			SrcPort: srcPort,
			DstPort: dstPort,
		}
		t.windowIssues[flowKey] = tracker
	}

	tracker.LastWindow = tcp.Window

	// Zero Window detection
	if tcp.Window == 0 {
		tracker.ZeroCount++
		// Typed observation per zero-window segment (dual-write; the existing
		// threshold-based TCPWindowFinding below is unchanged).
		report.Emit(events.Event{
			Kind:    events.TCPZeroWindow,
			FlowKey: flowKey,
			Values:  map[string]float64{"zero_count": float64(tracker.ZeroCount)},
			Attrs:   map[string]string{"src_ip": ipInfo.SrcIP, "dst_ip": ipInfo.DstIP},
			Source:  "TCP-Advanced",
		})
		if tracker.ZeroCount == ZeroWindowThreshold {
			report.TCPWindowFindings = append(report.TCPWindowFindings, models.TCPWindowFinding{
				Timestamp:   ts,
				SrcIP:       ipInfo.SrcIP,
				DstIP:       ipInfo.DstIP,
				SrcPort:     srcPort,
				DstPort:     dstPort,
				Type:        "Zero Window",
				WindowSize:  0,
				Severity:    "Critical",
				Description: fmt.Sprintf("TCP Zero Window from %s:%d — receiver buffer is full, sender must stop transmitting. This causes application stalls.", ipInfo.SrcIP, srcPort),
				Count:       tracker.ZeroCount,
			})
		}
	}

	// Small Window detection. The raw header field is meaningless without the
	// negotiated Window Scale, so judge the EFFECTIVE window; if the scale for
	// this direction is unknown, make no claim (never assume scale 0).
	if tcp.Window > 0 {
		if eff, ok := t.effectiveWindow(tcp, ipInfo, srcPort, dstPort); ok && eff <= SmallWindowSize {
			tracker.SmallCount++
			if tracker.SmallCount == SmallWindowThreshold {
				report.TCPWindowFindings = append(report.TCPWindowFindings, models.TCPWindowFinding{
					Timestamp:   ts,
					SrcIP:       ipInfo.SrcIP,
					DstIP:       ipInfo.DstIP,
					SrcPort:     srcPort,
					DstPort:     dstPort,
					Type:        "Small Window",
					WindowSize:  uint16(eff), // eff <= SmallWindowSize
					Severity:    "Warning",
					Description: fmt.Sprintf("TCP Small Window: %s:%d advertised an effective receive window of %d bytes (raw %d with negotiated scale) in %d segments. This shows the receiver offered little buffer space; it does not by itself show why.", ipInfo.SrcIP, srcPort, eff, tcp.Window, tracker.SmallCount),
					Count:       tracker.SmallCount,
				})
			}
		}
	}
}

func (t *TCPAdvancedAnalyzer) analyzeOutOfOrder(tcp *layers.TCP, ipInfo *PacketIPInfo, srcPort, dstPort uint16, flowKey string, report *models.TriageReport) {
	tracker, exists := t.oooFlows[flowKey]
	if !exists {
		if len(t.oooFlows) >= maxAdvancedTrackedFlows {
			return
		}
		tracker = &tcpOOOTracker{
			SrcIP:   ipInfo.SrcIP,
			DstIP:   ipInfo.DstIP,
			SrcPort: srcPort,
			DstPort: dstPort,
		}
		t.oooFlows[flowKey] = tracker
	}

	tracker.TotalPackets++

	if !tracker.Initialized {
		tracker.LastSeq = tcp.Seq
		tracker.Initialized = true
		return
	}

	// Detect out-of-order: sequence number is less than expected
	// (accounting for wraparound)
	expectedSeq := tracker.LastSeq + uint32(len(tcp.Payload))
	if tcp.Seq < tracker.LastSeq && (tracker.LastSeq-tcp.Seq) < 0x80000000 {
		tracker.OOOCount++
	}

	// Update last seen sequence
	if tcp.Seq > tracker.LastSeq || (tcp.Seq < tracker.LastSeq && (tracker.LastSeq-tcp.Seq) > 0x80000000) {
		tracker.LastSeq = tcp.Seq
	}
	_ = expectedSeq
}

// Finalize generates findings from accumulated out-of-order data
func (t *TCPAdvancedAnalyzer) Finalize(report *models.TriageReport) {
	for _, flowKey := range slices.Sorted(maps.Keys(t.oooFlows)) {
		tracker := t.oooFlows[flowKey]
		if tracker.OOOCount < OutOfOrderMinCount || tracker.TotalPackets < 20 {
			continue
		}

		pct := float64(tracker.OOOCount) / float64(tracker.TotalPackets) * 100
		if pct < OutOfOrderMinPercent {
			continue
		}

		severity := "Warning"
		if pct > 10.0 {
			severity = "Critical"
		}

		report.TCPOutOfOrderFlows = append(report.TCPOutOfOrderFlows, models.TCPOutOfOrderFlow{
			SrcIP:           tracker.SrcIP,
			DstIP:           tracker.DstIP,
			SrcPort:         tracker.SrcPort,
			DstPort:         tracker.DstPort,
			OutOfOrderCount: tracker.OOOCount,
			TotalPackets:    tracker.TotalPackets,
			Percentage:      pct,
			Severity:        severity,
		})
	}
}
