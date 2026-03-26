package analyzer

import (
	"fmt"
	"hash/fnv"
	"math"
	"os"
	"sort"
	"strings"
	"time"
)

// Maximum discrepancies kept in report to prevent unbounded memory growth.
const maxDiscrepancies = 10000

// ─── Forensic Types ─────────────────────────────────────────────

// ForensicSummary contains actionable forensic insights from the comparison.
type ForensicSummary struct {
	TotalFlowsMatched    int `json:"total_flows_matched"`
	FlowsDroppedLANtoWAN int `json:"flows_dropped_lan_to_wan"`
	FlowsDroppedWANtoLAN int `json:"flows_dropped_wan_to_lan"`

	AvgOneWayLatencyMs float64 `json:"avg_one_way_latency_ms"`
	MinOneWayLatencyMs float64 `json:"min_one_way_latency_ms"`
	MaxOneWayLatencyMs float64 `json:"max_one_way_latency_ms"`
	P95OneWayLatencyMs float64 `json:"p95_one_way_latency_ms"`
	LatencySampleCount int     `json:"latency_sample_count"`

	TotalRetransmissionsDropped int `json:"total_retransmissions_dropped"`

	FailedHandshakes           []FailedHandshake        `json:"failed_handshakes,omitempty"`
	TopRetransmissionOffenders []RetransmissionOffender  `json:"top_retransmission_offenders,omitempty"`
	LatencySpikes              []LatencySpike            `json:"latency_spikes,omitempty"`
}

// FailedHandshake describes a TCP flow where the handshake didn't complete across both captures.
type FailedHandshake struct {
	SrcIP   string `json:"src_ip"`
	DstIP   string `json:"dst_ip"`
	SrcPort uint16 `json:"src_port"`
	DstPort uint16 `json:"dst_port"`
	Reason  string `json:"reason"`
	Detail  string `json:"detail"`
}

// RetransmissionOffender is a flow with high packet drops.
type RetransmissionOffender struct {
	SrcIP           string `json:"src_ip"`
	DstIP           string `json:"dst_ip"`
	SrcPort         uint16 `json:"src_port"`
	DstPort         uint16 `json:"dst_port"`
	Protocol        string `json:"protocol"`
	Retransmissions int    `json:"retransmissions"`
	PacketsDropped  int    `json:"packets_dropped"`
}

// LatencySpike is a flow whose one-way delay exceeds the average significantly.
type LatencySpike struct {
	SrcIP      string  `json:"src_ip"`
	DstIP      string  `json:"dst_ip"`
	SrcPort    uint16  `json:"src_port"`
	DstPort    uint16  `json:"dst_port"`
	LatencyMs  float64 `json:"latency_ms"`
	AvgMs      float64 `json:"avg_ms"`
	Multiplier float64 `json:"multiplier"`
}

// ─── Lightweight Streaming Types ────────────────────────────────

// flowID is a lightweight flow identifier.
type flowID struct {
	SrcIP, DstIP     string
	SrcPort, DstPort uint16
	Protocol         string
}

// fingerprint is a compact per-packet identity (~48 bytes vs ~200+ for packetMeta).
type fingerprint struct {
	timestamp time.Time
	ttl       uint8
	dscp      uint8
	payload   int
	tcpFlags  string // only stored for SYN/SYN-ACK
	matched   bool
}

// flowState tracks per-flow forensic data during streaming comparison.
type flowState struct {
	SrcIP, DstIP     string
	SrcPort, DstPort uint16
	Protocol         string

	PacketsA, PacketsB         int
	Matched, MissingB, MissingA int
	Modified                   int
	HasNAT                     bool

	TunnelType   string
	Encapsulated bool

	// TCP Handshake tracking
	SynSeenA, SynSeenB           bool
	SynTimestampA, SynTimestampB time.Time
	SynAckSeenA, SynAckSeenB     bool

	// Latency samples (SYN delta between A and B)
	LatencySamples []float64
}

// ─── Streaming Compare ──────────────────────────────────────────

// CompareStreaming is the new streaming two-pass comparison engine.
// Pass 1: Stream file A (LAN), build fingerprint index + flow state.
// Pass 2: Stream file B (WAN), match against index, detect forensics.
// Memory: O(fingerprints + flows) instead of O(all_packets × 2).
func (c *Comparator) CompareStreaming(fileA, fileB string) (*ComparisonReport, error) {
	start := time.Now()

	report := &ComparisonReport{
		FileA:           fileA,
		FileB:           fileB,
		Discrepancies:   make([]Discrepancy, 0, 1024),
		TunnelBreakdown: make(map[string]int),
	}

	flows := make(map[flowID]*flowState, 4096)
	fpIndex := make(map[uint64][]*fingerprint, 65536)
	natIndex := make(map[uint64][]*fingerprint, 8192)

	// ── Pass 1: Stream LAN (file A) ─────────────────────────────
	if c.verbose {
		fmt.Fprintf(os.Stderr, "[COMPARE] Pass 1: streaming LAN file: %s\n", fileA)
	}

	totalA, err := c.streamFile(fileA, func(meta *packetMeta) {
		fid := flowID{meta.Key.SrcIP, meta.Key.DstIP, meta.Key.SrcPort, meta.Key.DstPort, meta.Key.Protocol}
		fs := getOrCreateFlow(flows, fid, meta)
		fs.PacketsA++

		if meta.Key.Protocol == "TCP" {
			trackHandshakeA(fs, meta)
		}

		fp := &fingerprint{
			timestamp: meta.Timestamp,
			ttl:       meta.TTL,
			dscp:      meta.DSCP,
			payload:   meta.Payload,
		}
		if isSynOrSynAck(meta.TCPFlags) {
			fp.tcpFlags = meta.TCPFlags
		}

		h := computeHash(meta)
		fpIndex[h] = append(fpIndex[h], fp)

		if meta.Key.Protocol == "TCP" || meta.Key.Protocol == "UDP" {
			nh := computeNATHash(meta)
			natIndex[nh] = append(natIndex[nh], fp)
		}
	})
	if err != nil {
		return nil, fmt.Errorf("failed to stream file A (%s): %w", fileA, err)
	}
	report.TotalPacketsA = totalA

	if c.verbose {
		fmt.Fprintf(os.Stderr, "[COMPARE] Pass 1 done: %d packets, %d flows\n", totalA, len(flows))
	}

	// ── Pass 2: Stream WAN (file B) ─────────────────────────────
	if c.verbose {
		fmt.Fprintf(os.Stderr, "[COMPARE] Pass 2: streaming WAN file: %s\n", fileB)
	}

	tunnelTypesSet := make(map[string]bool)

	totalB, err := c.streamFile(fileB, func(meta *packetMeta) {
		fid := flowID{meta.Key.SrcIP, meta.Key.DstIP, meta.Key.SrcPort, meta.Key.DstPort, meta.Key.Protocol}
		fs := getOrCreateFlow(flows, fid, meta)
		fs.PacketsB++

		// Tunnel stats
		if meta.TunnelType != TunnelNone {
			report.TunnelBreakdown[meta.TunnelType]++
			tunnelTypesSet[meta.TunnelType] = true
			report.EncapsulatedCount++
			if meta.Encrypted {
				report.EncryptedCount++
			}
			if !fs.Encapsulated {
				fs.Encapsulated = true
				fs.TunnelType = meta.TunnelType
			}
		}

		if meta.Key.Protocol == "TCP" {
			trackHandshakeB(fs, meta)
		}

		// Try exact match
		h := computeHash(meta)
		if candidates, ok := fpIndex[h]; ok {
			for i, fp := range candidates {
				if fp.matched {
					continue
				}
				fp.matched = true
				fpIndex[h] = append(candidates[:i], candidates[i+1:]...)

				changes := detectModFromFP(fp, meta)
				if len(changes) > 0 {
					report.ModifiedCount++
					fs.Modified++
					for _, ch := range changes {
						if ch.Field == "TTL" {
							report.TTLChanges++
						} else if ch.Field == "DSCP" {
							report.DSCPChanges++
						}
					}
					addDisc(report, Discrepancy{
						State: StateModified, SrcIP: meta.Key.SrcIP, DstIP: meta.Key.DstIP,
						SrcPort: meta.Key.SrcPort, DstPort: meta.Key.DstPort, Protocol: meta.Key.Protocol,
						PacketIndex: meta.Index, Timestamp: meta.Timestamp.Format("15:04:05.000000"),
						Length: meta.Length, Detail: formatModificationDetail(changes),
						TCPFlags: meta.TCPFlags, FieldChanges: changes,
					})
				} else {
					report.MatchedCount++
					fs.Matched++
					// Collect latency from SYN packets
					if isSynOnly(meta.TCPFlags) && isSynOnly(fp.tcpFlags) {
						delta := meta.Timestamp.Sub(fp.timestamp).Seconds() * 1000.0
						if delta >= 0 && delta < 30000 {
							fs.LatencySamples = append(fs.LatencySamples, delta)
						}
					}
				}
				return
			}
		}

		// NAT relaxed match
		if meta.Key.Protocol == "TCP" || meta.Key.Protocol == "UDP" {
			nh := computeNATHash(meta)
			if candidates, ok := natIndex[nh]; ok {
				for i, fp := range candidates {
					if fp.matched || abs(fp.payload-meta.Payload) > 4 {
						continue
					}
					fp.matched = true
					natIndex[nh] = append(candidates[:i], candidates[i+1:]...)
					report.ModifiedCount++
					report.NATDetected = true
					fs.Modified++
					fs.HasNAT = true
					addDisc(report, Discrepancy{
						State: StateModified, SrcIP: meta.Key.SrcIP, DstIP: meta.Key.DstIP,
						SrcPort: meta.Key.SrcPort, DstPort: meta.Key.DstPort, Protocol: meta.Key.Protocol,
						PacketIndex: meta.Index, Timestamp: meta.Timestamp.Format("15:04:05.000000"),
						Length: meta.Length, Detail: "NAT translation detected", TCPFlags: meta.TCPFlags,
					})
					return
				}
			}
		}

		if meta.Encrypted {
			return
		}

		// MISSING_A
		report.MissingACount++
		fs.MissingA++
		detail := "Packet in WAN but not LAN (asymmetric routing or injected)"
		if meta.TunnelType != TunnelNone {
			detail = fmt.Sprintf("[%s tunnel] %s", meta.TunnelType, detail)
		}
		addDisc(report, Discrepancy{
			State: StateMissingA, SrcIP: meta.Key.SrcIP, DstIP: meta.Key.DstIP,
			SrcPort: meta.Key.SrcPort, DstPort: meta.Key.DstPort, Protocol: meta.Key.Protocol,
			PacketIndex: meta.Index, Timestamp: meta.Timestamp.Format("15:04:05.000000"),
			Length: meta.Length, Detail: detail, TCPFlags: meta.TCPFlags,
			TunnelType: meta.TunnelType, Encrypted: meta.Encrypted,
		})
	})
	if err != nil {
		return nil, fmt.Errorf("failed to stream file B (%s): %w", fileB, err)
	}
	report.TotalPacketsB = totalB

	// Count unmatched fingerprints from A → MISSING_B
	for _, fps := range fpIndex {
		for _, fp := range fps {
			if !fp.matched {
				report.MissingBCount++
			}
		}
	}

	for t := range tunnelTypesSet {
		report.TunnelTypes = append(report.TunnelTypes, t)
	}
	report.TunnelDetected = report.EncapsulatedCount > 0

	// ── Finalize ────────────────────────────────────────────────
	c.finalizeStreaming(report, flows)
	report.AnalysisDuration = time.Since(start)

	if c.verbose {
		fmt.Fprintf(os.Stderr, "[COMPARE] Done in %v: matched=%d missingB=%d missingA=%d modified=%d score=%.1f%%\n",
			report.AnalysisDuration, report.MatchedCount, report.MissingBCount,
			report.MissingACount, report.ModifiedCount, report.PathIntegrityScore)
	}
	return report, nil
}

// ─── Finalization ───────────────────────────────────────────────

func (c *Comparator) finalizeStreaming(report *ComparisonReport, flows map[flowID]*flowState) {
	forensics := &ForensicSummary{}
	var allLatency []float64

	for _, fs := range flows {
		droppedA := fs.PacketsA - fs.Matched - fs.Modified
		if droppedA < 0 {
			droppedA = 0
		}
		fs.MissingB = droppedA

		total := fs.PacketsA
		if fs.PacketsB > total {
			total = fs.PacketsB
		}
		rate := 0.0
		if total > 0 {
			rate = float64(fs.Matched) / float64(total)
		}

		report.FlowSummaries = append(report.FlowSummaries, FlowComparisonSummary{
			SrcIP: fs.SrcIP, DstIP: fs.DstIP, SrcPort: fs.SrcPort, DstPort: fs.DstPort,
			Protocol: fs.Protocol, PacketsA: fs.PacketsA, PacketsB: fs.PacketsB,
			Matched: fs.Matched, MissingB: fs.MissingB, MissingA: fs.MissingA,
			Modified: fs.Modified, MatchRate: rate, HasNAT: fs.HasNAT,
			TunnelType: fs.TunnelType, Encapsulated: fs.Encapsulated,
		})

		// Failed handshakes
		if fs.Protocol == "TCP" {
			if fs.SynSeenA && !fs.SynSeenB {
				forensics.FlowsDroppedLANtoWAN++
				forensics.FailedHandshakes = append(forensics.FailedHandshakes, FailedHandshake{
					SrcIP: fs.SrcIP, DstIP: fs.DstIP, SrcPort: fs.SrcPort, DstPort: fs.DstPort,
					Reason: "SYN dropped by policy",
					Detail: fmt.Sprintf("TCP SYN %s:%d→%s:%d on LAN never appeared on WAN (policy/ACL drop)",
						fs.SrcIP, fs.SrcPort, fs.DstIP, fs.DstPort),
				})
			}
			if fs.SynAckSeenB && !fs.SynAckSeenA {
				forensics.FlowsDroppedWANtoLAN++
				forensics.FailedHandshakes = append(forensics.FailedHandshakes, FailedHandshake{
					SrcIP: fs.DstIP, DstIP: fs.SrcIP, SrcPort: fs.DstPort, DstPort: fs.SrcPort,
					Reason: "SYN-ACK lost on return path",
					Detail: fmt.Sprintf("TCP SYN-ACK %s:%d→%s:%d on WAN never reached LAN (asymmetric routing)",
						fs.DstIP, fs.DstPort, fs.SrcIP, fs.SrcPort),
				})
			}
		}

		// Retransmission offenders
		if fs.MissingB > 3 && fs.Protocol == "TCP" {
			forensics.TotalRetransmissionsDropped += fs.MissingB
			forensics.TopRetransmissionOffenders = append(forensics.TopRetransmissionOffenders, RetransmissionOffender{
				SrcIP: fs.SrcIP, DstIP: fs.DstIP, SrcPort: fs.SrcPort, DstPort: fs.DstPort,
				Protocol: fs.Protocol, Retransmissions: fs.MissingB, PacketsDropped: fs.MissingB,
			})
		}

		allLatency = append(allLatency, fs.LatencySamples...)
		if fs.Matched > 0 {
			forensics.TotalFlowsMatched++
		}
	}

	// Sort flows worst-first
	sort.Slice(report.FlowSummaries, func(i, j int) bool {
		return report.FlowSummaries[i].MatchRate < report.FlowSummaries[j].MatchRate
	})

	// Latency statistics
	if len(allLatency) > 0 {
		sort.Float64s(allLatency)
		forensics.LatencySampleCount = len(allLatency)
		var sum float64
		for _, v := range allLatency {
			sum += v
		}
		forensics.AvgOneWayLatencyMs = sum / float64(len(allLatency))
		forensics.MinOneWayLatencyMs = allLatency[0]
		forensics.MaxOneWayLatencyMs = allLatency[len(allLatency)-1]
		p95 := int(math.Ceil(float64(len(allLatency))*0.95)) - 1
		if p95 < 0 {
			p95 = 0
		}
		if p95 >= len(allLatency) {
			p95 = len(allLatency) - 1
		}
		forensics.P95OneWayLatencyMs = allLatency[p95]

		// Latency spikes
		if forensics.AvgOneWayLatencyMs > 0 {
			for _, fs := range flows {
				for _, s := range fs.LatencySamples {
					mult := s / forensics.AvgOneWayLatencyMs
					if mult > 2.0 && s > 5.0 {
						forensics.LatencySpikes = append(forensics.LatencySpikes, LatencySpike{
							SrcIP: fs.SrcIP, DstIP: fs.DstIP, SrcPort: fs.SrcPort, DstPort: fs.DstPort,
							LatencyMs: s, AvgMs: forensics.AvgOneWayLatencyMs, Multiplier: mult,
						})
					}
				}
			}
		}
	}

	// Top 10 retransmission offenders
	sort.Slice(forensics.TopRetransmissionOffenders, func(i, j int) bool {
		return forensics.TopRetransmissionOffenders[i].Retransmissions > forensics.TopRetransmissionOffenders[j].Retransmissions
	})
	if len(forensics.TopRetransmissionOffenders) > 10 {
		forensics.TopRetransmissionOffenders = forensics.TopRetransmissionOffenders[:10]
	}

	// Top 10 latency spikes
	sort.Slice(forensics.LatencySpikes, func(i, j int) bool {
		return forensics.LatencySpikes[i].LatencyMs > forensics.LatencySpikes[j].LatencyMs
	})
	if len(forensics.LatencySpikes) > 10 {
		forensics.LatencySpikes = forensics.LatencySpikes[:10]
	}

	// Limit failed handshakes
	if len(forensics.FailedHandshakes) > 50 {
		forensics.FailedHandshakes = forensics.FailedHandshakes[:50]
	}

	report.Forensics = forensics

	// Path Integrity Score
	totalPkts := report.TotalPacketsA
	if report.TotalPacketsB > totalPkts {
		totalPkts = report.TotalPacketsB
	}
	if totalPkts > 0 {
		report.PathIntegrityScore = float64(report.MatchedCount) / float64(totalPkts) * 100.0
	}
	switch {
	case report.PathIntegrityScore >= 95:
		report.IntegrityRating = "Healthy"
	case report.PathIntegrityScore >= 80:
		report.IntegrityRating = "Degraded"
	case report.PathIntegrityScore >= 50:
		report.IntegrityRating = "Warning"
	default:
		report.IntegrityRating = "Critical"
	}
}

// ─── Streaming Helpers ──────────────────────────────────────────

func getOrCreateFlow(flows map[flowID]*flowState, fid flowID, meta *packetMeta) *flowState {
	if fs, ok := flows[fid]; ok {
		return fs
	}
	fs := &flowState{
		SrcIP: fid.SrcIP, DstIP: fid.DstIP, SrcPort: fid.SrcPort, DstPort: fid.DstPort,
		Protocol: fid.Protocol,
	}
	if meta.TunnelType != TunnelNone {
		fs.Encapsulated = true
		fs.TunnelType = meta.TunnelType
	}
	flows[fid] = fs
	return fs
}

func trackHandshakeA(fs *flowState, meta *packetMeta) {
	if isSynOnly(meta.TCPFlags) && !fs.SynSeenA {
		fs.SynSeenA = true
		fs.SynTimestampA = meta.Timestamp
	}
	if isSynAck(meta.TCPFlags) && !fs.SynAckSeenA {
		fs.SynAckSeenA = true
	}
}

func trackHandshakeB(fs *flowState, meta *packetMeta) {
	if isSynOnly(meta.TCPFlags) && !fs.SynSeenB {
		fs.SynSeenB = true
		fs.SynTimestampB = meta.Timestamp
	}
	if isSynAck(meta.TCPFlags) && !fs.SynAckSeenB {
		fs.SynAckSeenB = true
	}
}

func isSynOnly(flags string) bool {
	return flags == "SYN" || flags == "SYN,ECE" || flags == "SYN,CWR,ECE"
}

func isSynAck(flags string) bool {
	return strings.Contains(flags, "SYN") && strings.Contains(flags, "ACK") && !strings.Contains(flags, "FIN")
}

func isSynOrSynAck(flags string) bool {
	return isSynOnly(flags) || isSynAck(flags)
}

func computeHash(m *packetMeta) uint64 {
	h := fnv.New64a()
	fmt.Fprintf(h, "%s|%s|%d|%d|%s|%d|%d",
		m.Key.SrcIP, m.Key.DstIP, m.Key.SrcPort, m.Key.DstPort,
		m.Key.Protocol, m.Key.SeqNum, m.Key.IPId)
	return h.Sum64()
}

func computeNATHash(m *packetMeta) uint64 {
	h := fnv.New64a()
	fmt.Fprintf(h, "NAT|%s|%d|%d|%d", m.Key.Protocol, m.Key.SeqNum, m.Key.DstPort, m.Payload)
	return h.Sum64()
}

func detectModFromFP(fp *fingerprint, b *packetMeta) []FieldChange {
	var changes []FieldChange
	if fp.ttl != b.TTL {
		changes = append(changes, FieldChange{Field: "TTL", ValueA: fmt.Sprintf("%d", fp.ttl), ValueB: fmt.Sprintf("%d", b.TTL)})
	}
	if fp.dscp != b.DSCP {
		changes = append(changes, FieldChange{Field: "DSCP", ValueA: fmt.Sprintf("%d", fp.dscp), ValueB: fmt.Sprintf("%d", b.DSCP)})
	}
	return changes
}

func addDisc(report *ComparisonReport, d Discrepancy) {
	if len(report.Discrepancies) < maxDiscrepancies {
		report.Discrepancies = append(report.Discrepancies, d)
	}
}
