package analyzer

// tcp_graph.go — Per-packet TCP data extraction for Stevens-style time-sequence graphing.
//
// This module turns a slice of captured TCP packets into a compact series of
// data points suitable for visualising as a TCP Time-Sequence graph. It
// captures: relative time, sequence number, acknowledgement number, window
// size, TCP flags, payload length, direction, and retransmission status.
//
// Used by:
//   - pkg/web/handlers/packet_inspection.go (GetStreamGraph endpoint)
//   - Frontend TCPSequenceGraph.tsx component (consumes the JSON output)
//
// Design goals:
//   - Zero new dependencies (reuses gopacket which is already imported)
//   - Bounded memory: O(N) with compact struct layout
//   - Deterministic: stable sort by timestamp, stable direction assignment
//   - Resilient: skips non-TCP/malformed packets without failing the whole graph

import (
	"sort"
	"time"

	"github.com/gocisse/sdwan-triage/pkg/models"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// TCPGraphPoint is a single data point on the TCP Time-Sequence graph.
//
// Semantic: for outbound data (client -> server), the segment is drawn from
// (RelativeTime, SeqNum) to (RelativeTime, SeqNum + PayloadLen). For pure
// ACKs / empty packets, PayloadLen is 0 and the point appears as a tick.
//
// Retransmissions are flagged when the same (direction, seq_num) has been
// observed previously within the stream.
type TCPGraphPoint struct {
	PacketIndex      int     `json:"packet_index"`      // Original index within the stream
	RelativeTime     float64 `json:"relative_time"`     // Seconds since the first packet in the stream
	AbsoluteTime     string  `json:"absolute_time"`     // RFC3339-style for tooltip display
	Direction        string  `json:"direction"`         // "forward" (client->server) or "reverse" (server->client)
	SeqNum           uint32  `json:"seq_num"`           // Absolute TCP sequence number
	AckNum           uint32  `json:"ack_num"`           // Absolute TCP acknowledgement number
	WindowSize       uint16  `json:"window_size"`       // Advertised TCP receive window (raw, unscaled)
	ScaledWindow     uint32  `json:"scaled_window"`     // Effective window after applying the per-direction Window Scale option
	PayloadLen       int     `json:"payload_len"`       // TCP payload bytes (segment height on the graph)
	Flags            string  `json:"flags"`             // e.g. "SYN,ACK" or "PSH,ACK"
	IsRetransmission bool    `json:"is_retransmission"` // true if (direction, seq_num, payload_len) was seen previously
	IsSyn            bool    `json:"is_syn"`
	IsFin            bool    `json:"is_fin"`
	IsRst            bool    `json:"is_rst"`
	IsZeroWindow     bool    `json:"is_zero_window"` // Advertised window is zero (receiver stalled)
}

// TCPGraphRTT is a single round-trip time sample, derived by matching a data
// segment to the earliest ACK that covers its final byte.
type TCPGraphRTT struct {
	PacketIndex  int     `json:"packet_index"`  // Index of the data segment whose RTT is being reported
	AckIndex     int     `json:"ack_index"`     // Index of the matching ACK segment
	RelativeTime float64 `json:"relative_time"` // Time of the data segment, seconds since stream start
	RTTMs        float64 `json:"rtt_ms"`        // Round-trip time in milliseconds (ack_time - data_time)
	Direction    string  `json:"direction"`     // Direction of the data segment ("forward" or "reverse")
	SeqNum       uint32  `json:"seq_num"`       // Seq of the data segment (for tooltip)
	PayloadLen   int     `json:"payload_len"`   // Payload length (for tooltip)
}

// TCPGraphThroughputBin is a single throughput measurement bucket.
type TCPGraphThroughputBin struct {
	StartTime      float64 `json:"start_time"`      // Bin start, seconds since stream start
	EndTime        float64 `json:"end_time"`        // Bin end, seconds since stream start
	ForwardBytes   int     `json:"forward_bytes"`   // Forward payload bytes in this bin
	ReverseBytes   int     `json:"reverse_bytes"`   // Reverse payload bytes in this bin
	ForwardPackets int     `json:"forward_packets"` // Forward packet count
	ReversePackets int     `json:"reverse_packets"` // Reverse packet count
}

// TCPGraphData is the API response payload for the graph endpoint.
type TCPGraphData struct {
	StreamID        string                  `json:"stream_id"`
	SrcIP           string                  `json:"src_ip"`
	DstIP           string                  `json:"dst_ip"`
	SrcPort         uint16                  `json:"src_port"`
	DstPort         uint16                  `json:"dst_port"`
	Protocol        string                  `json:"protocol"`
	PacketCount     int                     `json:"packet_count"`
	DurationSeconds float64                 `json:"duration_seconds"`
	FirstTimestamp  string                  `json:"first_timestamp"`
	LastTimestamp   string                  `json:"last_timestamp"`
	Points          []TCPGraphPoint         `json:"points"`
	RTTSamples      []TCPGraphRTT           `json:"rtt_samples"`
	Throughput      []TCPGraphThroughputBin `json:"throughput"`

	// Window Scale factors discovered from the handshake (TCP Option Kind 3).
	// A value of 0 means "not negotiated" or "scale factor of 0" — both imply
	// the raw WindowSize is the effective window.
	ForwardWindowScale uint8 `json:"forward_window_scale"`
	ReverseWindowScale uint8 `json:"reverse_window_scale"`

	// Quick-glance stats surfaced next to the graph
	ForwardPackets        int     `json:"forward_packets"`
	ReversePackets        int     `json:"reverse_packets"`
	RetransmissionCount   int     `json:"retransmission_count"`
	SynCount              int     `json:"syn_count"`
	FinCount              int     `json:"fin_count"`
	RstCount              int     `json:"rst_count"`
	MaxPayload            int     `json:"max_payload"`
	TotalPayloadBytes     int     `json:"total_payload_bytes"`
	DistinctForwardSeqs   int     `json:"distinct_forward_seqs"`
	DistinctReverseSeqs   int     `json:"distinct_reverse_seqs"`
	MinWindow             int     `json:"min_window"` // smallest non-zero advertised window (flags zero-window if 0 present)
	ZeroWindowOccurrences int     `json:"zero_window_occurrences"`
	MinRTTMs              float64 `json:"min_rtt_ms"`
	MaxRTTMs              float64 `json:"max_rtt_ms"`
	AvgRTTMs              float64 `json:"avg_rtt_ms"`
	PeakBytesPerSecond    float64 `json:"peak_bytes_per_second"`
}

// BuildTCPGraph extracts TCP graph points from a slice of raw packets belonging
// to a single stream (bidirectional 5-tuple). Packets are sorted by timestamp,
// and the very first packet defines t=0 for the stream.
//
// Non-TCP packets are silently skipped — TCP Time-Sequence graphs are only
// meaningful for TCP streams.
func BuildTCPGraph(streamID string, packets []*models.RawPacket) *TCPGraphData {
	if len(packets) == 0 {
		return &TCPGraphData{StreamID: streamID, Points: []TCPGraphPoint{}}
	}

	// Stable sort by timestamp — required for retransmission detection to be
	// deterministic (we compare against already-seen sequence numbers).
	sorted := make([]*models.RawPacket, len(packets))
	copy(sorted, packets)
	sort.SliceStable(sorted, func(i, j int) bool {
		return sorted[i].Timestamp.Before(sorted[j].Timestamp)
	})

	// Establish canonical "forward" direction from the first TCP packet in the
	// stream. This ensures the graph always plots the initiator's seq numbers
	// in the forward series regardless of 5-tuple ordering.
	var forwardSrcIP, forwardDstIP string
	var forwardSrcPort, forwardDstPort uint16
	var firstTCPFound bool
	for _, p := range sorted {
		if p.IsTCP {
			forwardSrcIP = p.SrcIP
			forwardDstIP = p.DstIP
			forwardSrcPort = p.SrcPort
			forwardDstPort = p.DstPort
			firstTCPFound = true
			break
		}
	}
	if !firstTCPFound {
		// No TCP packets at all — return an empty but well-formed response.
		return &TCPGraphData{
			StreamID:    streamID,
			PacketCount: len(sorted),
			Points:      []TCPGraphPoint{},
		}
	}

	// Reference time: first packet's timestamp.
	t0 := sorted[0].Timestamp

	// Track (direction, seq, payloadLen) tuples for retransmission detection.
	// Two packets in the same direction with the same seq and the same payload
	// length are almost certainly retransmissions. Pure ACKs (payload=0) can
	// legitimately repeat the same seq, so we only flag when payload > 0.
	type seqKey struct {
		direction string
		seq       uint32
		payload   int
	}
	seen := make(map[seqKey]int, len(sorted))

	points := make([]TCPGraphPoint, 0, len(sorted))
	data := &TCPGraphData{
		StreamID:       streamID,
		SrcIP:          forwardSrcIP,
		DstIP:          forwardDstIP,
		SrcPort:        forwardSrcPort,
		DstPort:        forwardDstPort,
		Protocol:       "TCP",
		FirstTimestamp: sorted[0].Timestamp.Format(time.RFC3339Nano),
		LastTimestamp:  sorted[len(sorted)-1].Timestamp.Format(time.RFC3339Nano),
	}
	distinctFwd := make(map[uint32]struct{}, len(sorted))
	distinctRev := make(map[uint32]struct{}, len(sorted))
	minWindow := -1 // -1 means "uninitialised"

	// Window Scale factors: discovered from the SYN (forward) and SYN-ACK
	// (reverse). Until the handshake is observed, scale=0 which means the
	// raw WindowSize is the effective window.
	var fwdScale, revScale uint8
	var fwdScaleSeen, revScaleSeen bool

	// First pass: parse packets, capture handshake window-scale options.
	type parsedPkt struct {
		raw       *models.RawPacket
		tcp       *layers.TCP
		direction string
		relTime   float64
	}
	parsed := make([]parsedPkt, 0, len(sorted))

	for _, p := range sorted {
		if !p.IsTCP || len(p.RawData) == 0 {
			continue
		}

		tcp := parseTCPFromRaw(p.RawData)
		if tcp == nil {
			continue
		}

		direction := "reverse"
		if p.SrcIP == forwardSrcIP && p.SrcPort == forwardSrcPort &&
			p.DstIP == forwardDstIP && p.DstPort == forwardDstPort {
			direction = "forward"
		}

		relTime := p.Timestamp.Sub(t0).Seconds()
		if relTime < 0 {
			relTime = 0
		}

		// Capture Window Scale from TCP options on the handshake packets.
		// The Window Scale option (Kind=3, Len=3) advertises the shift count
		// that the sender will apply to its window values on every segment
		// *after* the handshake. Per RFC 7323, it must appear on the SYN.
		if tcp.SYN {
			if scale, ok := extractWindowScale(tcp); ok {
				if direction == "forward" && !fwdScaleSeen {
					fwdScale = scale
					fwdScaleSeen = true
				} else if direction == "reverse" && !revScaleSeen {
					revScale = scale
					revScaleSeen = true
				}
			}
		}

		parsed = append(parsed, parsedPkt{
			raw:       p,
			tcp:       tcp,
			direction: direction,
			relTime:   relTime,
		})
	}

	data.ForwardWindowScale = fwdScale
	data.ReverseWindowScale = revScale

	// Second pass: build points and aggregate stats.
	for _, pp := range parsed {
		p := pp.raw
		tcp := pp.tcp
		direction := pp.direction
		relTime := pp.relTime

		payload := len(tcp.Payload)
		key := seqKey{direction: direction, seq: tcp.Seq, payload: payload}
		isRetx := false
		if payload > 0 {
			if _, ok := seen[key]; ok {
				isRetx = true
			} else {
				seen[key] = p.Index
			}
		}

		// Apply the per-direction window scale. The scale is only valid
		// *after* the handshake — so we do not scale the SYN itself
		// (which advertises its own raw window with the scale embedded
		// in the option).
		scaledWindow := uint32(tcp.Window)
		if !tcp.SYN {
			if direction == "forward" && fwdScaleSeen {
				scaledWindow = uint32(tcp.Window) << fwdScale
			} else if direction == "reverse" && revScaleSeen {
				scaledWindow = uint32(tcp.Window) << revScale
			}
		}

		flags := formatTCPFlagList(tcp)

		pt := TCPGraphPoint{
			PacketIndex:      p.Index,
			RelativeTime:     relTime,
			AbsoluteTime:     p.Timestamp.Format(time.RFC3339Nano),
			Direction:        direction,
			SeqNum:           tcp.Seq,
			AckNum:           tcp.Ack,
			WindowSize:       tcp.Window,
			ScaledWindow:     scaledWindow,
			PayloadLen:       payload,
			Flags:            flags,
			IsRetransmission: isRetx,
			IsSyn:            tcp.SYN,
			IsFin:            tcp.FIN,
			IsRst:            tcp.RST,
			IsZeroWindow:     tcp.Window == 0 && !tcp.RST && !tcp.SYN,
		}
		points = append(points, pt)

		// Roll up stats.
		if direction == "forward" {
			data.ForwardPackets++
			distinctFwd[tcp.Seq] = struct{}{}
		} else {
			data.ReversePackets++
			distinctRev[tcp.Seq] = struct{}{}
		}
		if isRetx {
			data.RetransmissionCount++
		}
		if tcp.SYN {
			data.SynCount++
		}
		if tcp.FIN {
			data.FinCount++
		}
		if tcp.RST {
			data.RstCount++
		}
		if payload > data.MaxPayload {
			data.MaxPayload = payload
		}
		data.TotalPayloadBytes += payload
		if tcp.Window == 0 {
			data.ZeroWindowOccurrences++
		} else if minWindow < 0 || int(tcp.Window) < minWindow {
			minWindow = int(tcp.Window)
		}
	}

	data.Points = points
	data.PacketCount = len(points)
	data.DistinctForwardSeqs = len(distinctFwd)
	data.DistinctReverseSeqs = len(distinctRev)
	if minWindow < 0 {
		data.MinWindow = 0
	} else {
		data.MinWindow = minWindow
	}
	if len(points) > 0 {
		data.DurationSeconds = points[len(points)-1].RelativeTime
	}

	// Derive RTT samples and throughput bins from the finalised points.
	data.RTTSamples = deriveRTTSamples(points)
	data.Throughput = deriveThroughputBins(points, data.DurationSeconds)

	// RTT aggregate stats.
	if len(data.RTTSamples) > 0 {
		minR := data.RTTSamples[0].RTTMs
		maxR := data.RTTSamples[0].RTTMs
		var sum float64
		for _, r := range data.RTTSamples {
			if r.RTTMs < minR {
				minR = r.RTTMs
			}
			if r.RTTMs > maxR {
				maxR = r.RTTMs
			}
			sum += r.RTTMs
		}
		data.MinRTTMs = minR
		data.MaxRTTMs = maxR
		data.AvgRTTMs = sum / float64(len(data.RTTSamples))
	}

	// Peak throughput (bytes/sec of the hottest bin).
	for _, b := range data.Throughput {
		if b.EndTime <= b.StartTime {
			continue
		}
		bps := float64(b.ForwardBytes+b.ReverseBytes) / (b.EndTime - b.StartTime)
		if bps > data.PeakBytesPerSecond {
			data.PeakBytesPerSecond = bps
		}
	}

	return data
}

// deriveRTTSamples matches each data segment to the earliest ACK that covers
// its final byte (Stevens-style RTT estimation). It operates on the already-
// sorted point slice and runs in O(N) with two cursors — one walking the
// forward direction, one the reverse.
//
// A data segment (direction=D, seq=S, len=L, time=t1) is "acked" by the
// earliest reverse-direction ACK with ack_num >= S+L and time > t1. The RTT
// is (ack_time - data_time).
//
// Retransmissions are excluded because their RTT would be ambiguous.
func deriveRTTSamples(points []TCPGraphPoint) []TCPGraphRTT {
	if len(points) < 2 {
		return []TCPGraphRTT{}
	}

	// Separate points into direction-specific slices while preserving order.
	var fwdIdx, revIdx []int
	for i, p := range points {
		if p.Direction == "forward" {
			fwdIdx = append(fwdIdx, i)
		} else {
			revIdx = append(revIdx, i)
		}
	}

	out := make([]TCPGraphRTT, 0, len(points)/4)

	// Forward data segments acked by reverse ACKs.
	out = matchDataToAcks(points, fwdIdx, revIdx, "forward", out)
	// Reverse data segments acked by forward ACKs.
	out = matchDataToAcks(points, revIdx, fwdIdx, "reverse", out)

	// Sort RTT samples by the data segment's time so the plot looks natural.
	sort.Slice(out, func(i, j int) bool {
		return out[i].RelativeTime < out[j].RelativeTime
	})
	return out
}

// matchDataToAcks walks the data-side indices and the ack-side indices in
// lockstep, emitting an RTT sample for each non-retransmit data segment that
// finds a covering ACK.
func matchDataToAcks(points []TCPGraphPoint, dataIdx, ackIdx []int, direction string, out []TCPGraphRTT) []TCPGraphRTT {
	if len(dataIdx) == 0 || len(ackIdx) == 0 {
		return out
	}

	j := 0 // pointer into ackIdx
	for _, di := range dataIdx {
		d := points[di]
		if d.PayloadLen == 0 || d.IsRetransmission || d.IsRst {
			continue
		}
		needAck := d.SeqNum + uint32(d.PayloadLen)

		// Advance j to the earliest ACK that:
		//   (a) arrives strictly after the data segment, AND
		//   (b) acks up to or past needAck.
		// We reuse the cursor across data segments because both lists are
		// already time-ordered; a later data segment can only need the
		// same or a later ACK.
		for j < len(ackIdx) {
			a := points[ackIdx[j]]
			if a.RelativeTime <= d.RelativeTime {
				j++
				continue
			}
			// tcpSeqGE handles 32-bit seq-space wrap.
			if tcpSeqGE(a.AckNum, needAck) {
				rtt := (a.RelativeTime - d.RelativeTime) * 1000.0
				// Sanity clamp: RTTs longer than 30s are almost certainly
				// spurious (connection idle + new data+ACK, or sequence
				// wrap interaction).
				if rtt >= 0 && rtt < 30000 {
					out = append(out, TCPGraphRTT{
						PacketIndex:  d.PacketIndex,
						AckIndex:     a.PacketIndex,
						RelativeTime: d.RelativeTime,
						RTTMs:        rtt,
						Direction:    direction,
						SeqNum:       d.SeqNum,
						PayloadLen:   d.PayloadLen,
					})
				}
				break
			}
			j++
		}
		if j >= len(ackIdx) {
			break
		}
	}
	return out
}

// tcpSeqGE reports whether seq a is >= seq b in TCP's 32-bit sequence space,
// with proper handling of wrap-around (RFC 1982 arithmetic).
func tcpSeqGE(a, b uint32) bool {
	return int32(a-b) >= 0
}

// deriveThroughputBins buckets payload bytes into time windows sized to
// produce ~60 bins over the stream's duration (min 50ms, max 5s per bin).
// Each bin carries both forward and reverse byte/packet counts so the UI can
// render them as a stacked bar chart.
func deriveThroughputBins(points []TCPGraphPoint, durationSec float64) []TCPGraphThroughputBin {
	if len(points) == 0 {
		return []TCPGraphThroughputBin{}
	}
	if durationSec <= 0 {
		// Single-timestamp stream — return one bin with everything.
		bin := TCPGraphThroughputBin{StartTime: 0, EndTime: 0.001}
		for _, p := range points {
			if p.Direction == "forward" {
				bin.ForwardBytes += p.PayloadLen
				bin.ForwardPackets++
			} else {
				bin.ReverseBytes += p.PayloadLen
				bin.ReversePackets++
			}
		}
		return []TCPGraphThroughputBin{bin}
	}

	// Target ~60 bins, clamped to [50ms, 5s].
	const targetBins = 60.0
	const minBinSec = 0.05
	const maxBinSec = 5.0
	binSec := durationSec / targetBins
	if binSec < minBinSec {
		binSec = minBinSec
	}
	if binSec > maxBinSec {
		binSec = maxBinSec
	}

	nBins := int(durationSec/binSec) + 1
	bins := make([]TCPGraphThroughputBin, nBins)
	for i := range bins {
		bins[i].StartTime = float64(i) * binSec
		bins[i].EndTime = float64(i+1) * binSec
	}

	for _, p := range points {
		if p.PayloadLen <= 0 {
			continue
		}
		idx := int(p.RelativeTime / binSec)
		if idx < 0 {
			idx = 0
		}
		if idx >= nBins {
			idx = nBins - 1
		}
		if p.Direction == "forward" {
			bins[idx].ForwardBytes += p.PayloadLen
			bins[idx].ForwardPackets++
		} else {
			bins[idx].ReverseBytes += p.PayloadLen
			bins[idx].ReversePackets++
		}
	}

	// Trim trailing empty bins to avoid a long dead tail on the chart.
	last := len(bins) - 1
	for last > 0 && bins[last].ForwardBytes == 0 && bins[last].ReverseBytes == 0 {
		last--
	}
	return bins[:last+1]
}

// extractWindowScale parses the TCP options array looking for the Window
// Scale option (Kind=3, Len=3) and returns the shift count (0-14 per
// RFC 7323). Returns (scale, false) if the option is absent or malformed.
func extractWindowScale(tcp *layers.TCP) (uint8, bool) {
	for _, opt := range tcp.Options {
		if opt.OptionType == layers.TCPOptionKindWindowScale {
			if len(opt.OptionData) >= 1 {
				s := opt.OptionData[0]
				if s > 14 { // RFC 7323 §2.2 caps the shift at 14
					s = 14
				}
				return s, true
			}
		}
	}
	return 0, false
}

// parseTCPFromRaw decodes a TCP layer out of a raw captured frame. Returns
// nil if the frame does not contain a parseable TCP header.
func parseTCPFromRaw(raw []byte) *layers.TCP {
	if len(raw) == 0 {
		return nil
	}
	// Decode lazily — we only need the TCP layer. Try Ethernet first (the
	// common case on PCAPs captured on a LAN interface). If it fails, fall
	// back to Raw IP which covers interface captures without a link layer.
	pkt := gopacket.NewPacket(raw, layers.LayerTypeEthernet, gopacket.DecodeOptions{
		Lazy:                     true,
		NoCopy:                   true,
		SkipDecodeRecovery:       true,
		DecodeStreamsAsDatagrams: false,
	})
	if tcpLayer := pkt.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		if tcp, ok := tcpLayer.(*layers.TCP); ok {
			return tcp
		}
	}
	// Fallback: raw IPv4 (some SD-WAN captures strip the L2 header).
	pkt = gopacket.NewPacket(raw, layers.LayerTypeIPv4, gopacket.DecodeOptions{
		Lazy:                     true,
		NoCopy:                   true,
		SkipDecodeRecovery:       true,
		DecodeStreamsAsDatagrams: false,
	})
	if tcpLayer := pkt.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		if tcp, ok := tcpLayer.(*layers.TCP); ok {
			return tcp
		}
	}
	return nil
}

// formatTCPFlagList returns a compact, human-friendly flag list such as
// "SYN,ACK" or "PSH,ACK". Order is fixed for display stability.
func formatTCPFlagList(tcp *layers.TCP) string {
	var out []byte
	appendFlag := func(name string, set bool) {
		if !set {
			return
		}
		if len(out) > 0 {
			out = append(out, ',')
		}
		out = append(out, name...)
	}
	appendFlag("SYN", tcp.SYN)
	appendFlag("ACK", tcp.ACK)
	appendFlag("FIN", tcp.FIN)
	appendFlag("RST", tcp.RST)
	appendFlag("PSH", tcp.PSH)
	appendFlag("URG", tcp.URG)
	appendFlag("ECE", tcp.ECE)
	appendFlag("CWR", tcp.CWR)
	return string(out)
}
