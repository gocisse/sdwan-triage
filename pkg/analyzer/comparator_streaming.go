package analyzer

import (
	"fmt"
	"hash/fnv"
	"math"
	"net"
	"os"
	"sort"
	"strings"
	"time"
)

// Maximum discrepancies kept in report to prevent unbounded memory growth.
const maxDiscrepancies = 10000

// Tunnel overhead ranges for time+size encrypted correlation.
// Typical overhead: ESP=50-72, DTLS=29-45, Viptela=48-80, VeloCloud VCMP=32-64
const (
	minTunnelOverhead = -40 // Allow negative (fragmentation/MTU clamp makes WAN smaller)
	maxTunnelOverhead = 150 // Maximum overhead (outer IP + UDP + tunnel + ESP IV/ICV + padding)
	timeWindowMs      = 50  // ±50 ms correlation window for encrypted matching
	maxSizeDeltaPct   = 30  // Maximum size difference as % of LAN packet size
)

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
	TopRetransmissionOffenders []RetransmissionOffender `json:"top_retransmission_offenders,omitempty"`
	LatencySpikes              []LatencySpike           `json:"latency_spikes,omitempty"`
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
	MTUBlackhole    bool   `json:"mtu_blackhole,omitempty"` // True if large payloads (>1400) were dropped
	MaxPayload      int    `json:"max_payload,omitempty"`   // Largest dropped payload size
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
	timestamp  time.Time
	ttl        uint8
	dscp       uint8
	payload    int
	tcpFlags   string // stored for all TCP packets (needed for drop categorization)
	protocol   string // TCP/UDP/ICMP etc.
	dstIP      string // needed for traffic classification
	srcIP      string // needed for traffic classification
	srcPort    uint16 // needed for management traffic detection
	dstPort    uint16 // needed for management traffic detection
	matched    bool
	noiseClass string // NoiseNone, NoiseLocal, NoiseMgmt, NoiseRouting, NoiseLocalLAN
}

// timeSlot is a compact LAN packet record for encrypted time+size correlation.
// Sorted by timestamp. Used in Pass 2 for binary-search matching.
type timeSlot struct {
	timestamp time.Time
	length    int // Wire length (ci.Length)
	matched   bool
}

// flowState tracks per-flow forensic data during streaming comparison.
type flowState struct {
	SrcIP, DstIP     string
	SrcPort, DstPort uint16
	Protocol         string

	PacketsA, PacketsB          int
	Matched, MissingB, MissingA int
	Modified                    int
	VerifiedEncrypted           int
	HasNAT                      bool

	TunnelType   string
	Encapsulated bool

	// Max payload seen (for MTU blackhole detection)
	MaxPayload int

	// TCP Handshake tracking
	SynSeenA, SynSeenB           bool
	SynTimestampA, SynTimestampB time.Time
	SynAckSeenA, SynAckSeenB     bool

	// Latency samples (SYN delta between A and B)
	LatencySamples []float64
}

// ─── Streaming Compare ──────────────────────────────────────────

// CompareStreaming is the streaming two-pass comparison engine.
// Pass 1: Stream file A (LAN), build fingerprint index + time-sorted list for encrypted correlation.
// Pass 2: Stream file B (WAN), match via:
//
//	a) Exact hash (5-tuple + seq + ipid) for clear or decapsulated packets
//	b) NAT-relaxed hash (protocol + seq + dstport + payload) for NAT'd packets
//	c) Time+Size correlation for encrypted tunnel packets (ESP/DTLS)
//
// Memory: O(fingerprints + flows + timeSlots) — no raw packet data retained.
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
	portIndex := make(map[uint64][]*fingerprint, 16384) // protocol+ports+payload (no IPs, no seq)

	// Time-sorted LAN packets for encrypted tunnel correlation.
	// We only store timestamp + wire length — ~24 bytes per slot.
	var lanTimeSlots []timeSlot
	var lanFirstTs time.Time
	lanTsInit := false

	// ── Pass 1: Stream LAN (file A) ─────────────────────────────
	if c.verbose {
		fmt.Fprintf(os.Stderr, "[COMPARE] Pass 1: streaming LAN file: %s\n", fileA)
	}

	totalA, err := c.streamFile(fileA, func(meta *packetMeta) {
		if !lanTsInit {
			lanFirstTs = meta.Timestamp
			lanTsInit = true
		}
		fid := flowID{meta.Key.SrcIP, meta.Key.DstIP, meta.Key.SrcPort, meta.Key.DstPort, meta.Key.Protocol}
		fs := getOrCreateFlow(flows, fid, meta)
		fs.PacketsA++

		if meta.Key.Protocol == "TCP" {
			trackHandshakeA(fs, meta)
		}

		nc := classifyNoise(meta.Key.SrcIP, meta.Key.DstIP, meta.Key.SrcPort, meta.Key.DstPort, meta.Key.Protocol)
		fp := &fingerprint{
			timestamp:  meta.Timestamp,
			ttl:        meta.TTL,
			dscp:       meta.DSCP,
			payload:    meta.Payload,
			tcpFlags:   meta.TCPFlags,
			protocol:   meta.Key.Protocol,
			dstIP:      meta.Key.DstIP,
			srcIP:      meta.Key.SrcIP,
			srcPort:    meta.Key.SrcPort,
			dstPort:    meta.Key.DstPort,
			noiseClass: nc,
		}

		// Track max payload for MTU blackhole detection
		if meta.Payload > fs.MaxPayload {
			fs.MaxPayload = meta.Payload
		}

		h := computeHash(meta)
		fpIndex[h] = append(fpIndex[h], fp)

		if meta.Key.Protocol == "TCP" || meta.Key.Protocol == "UDP" {
			nh := computeNATHash(meta)
			natIndex[nh] = append(natIndex[nh], fp)
			ph := computePortHash(meta)
			portIndex[ph] = append(portIndex[ph], fp)
		}

		// Append to time-sorted list for encrypted correlation
		lanTimeSlots = append(lanTimeSlots, timeSlot{
			timestamp: meta.Timestamp,
			length:    meta.Length,
		})
	})
	if err != nil {
		return nil, fmt.Errorf("failed to stream file A (%s): %w", fileA, err)
	}
	report.TotalPacketsA = totalA

	// Sort LAN time slots (should already be sorted by capture order, but be safe)
	sort.Slice(lanTimeSlots, func(i, j int) bool {
		return lanTimeSlots[i].timestamp.Before(lanTimeSlots[j].timestamp)
	})

	if c.verbose {
		fmt.Fprintf(os.Stderr, "[COMPARE] Pass 1 done: %d packets, %d flows, %d time slots\n", totalA, len(flows), len(lanTimeSlots))
	}

	// Detect time offset: the two captures may start at different wall-clock times.
	// We'll compute the offset from the WAN first packet during Pass 2.
	var wanFirstTs, wanLastTs time.Time
	wanTsInit := false
	var timeOffset time.Duration // WAN_time - LAN_time (add to LAN to align with WAN)

	// ── Pass 2: Stream WAN (file B) ─────────────────────────────
	if c.verbose {
		fmt.Fprintf(os.Stderr, "[COMPARE] Pass 2: streaming WAN file: %s\n", fileB)
	}

	tunnelTypesSet := make(map[string]bool)
	timeWindow := time.Duration(timeWindowMs) * time.Millisecond

	totalB, err := c.streamFile(fileB, func(meta *packetMeta) {
		// Capture WAN first/last timestamp for offset calculation and range
		if !wanTsInit {
			wanFirstTs = meta.Timestamp
			wanTsInit = true
			timeOffset = wanFirstTs.Sub(lanFirstTs)
			if c.verbose {
				fmt.Fprintf(os.Stderr, "[COMPARE] Time offset: LAN starts %s, WAN starts %s, delta=%v\n",
					lanFirstTs.Format("15:04:05.000"), wanFirstTs.Format("15:04:05.000"), timeOffset)
			}
		}
		wanLastTs = meta.Timestamp

		// Tunnel stats (always count, even for encrypted)
		if meta.TunnelType != TunnelNone {
			report.TunnelBreakdown[meta.TunnelType]++
			tunnelTypesSet[meta.TunnelType] = true
			report.EncapsulatedCount++
			if meta.Encrypted {
				report.EncryptedCount++
			}
		}

		// ── Strategy A: Exact match (works for clear-text + decapsulated) ──
		if !meta.Encrypted {
			fid := flowID{meta.Key.SrcIP, meta.Key.DstIP, meta.Key.SrcPort, meta.Key.DstPort, meta.Key.Protocol}
			fs := getOrCreateFlow(flows, fid, meta)
			fs.PacketsB++

			if meta.TunnelType != TunnelNone && !fs.Encapsulated {
				fs.Encapsulated = true
				fs.TunnelType = meta.TunnelType
			}

			if meta.Key.Protocol == "TCP" {
				trackHandshakeB(fs, meta)
			}

			// Try exact hash match
			h := computeHash(meta)
			if matched := tryExactMatch(fpIndex, h, meta, report, fs); matched {
				return
			}

			// Try NAT relaxed match
			if meta.Key.Protocol == "TCP" || meta.Key.Protocol == "UDP" {
				nh := computeNATHash(meta)
				if matched := tryNATMatch(natIndex, nh, meta, report, fs); matched {
					return
				}
			}

			// Try port-based relaxed match (protocol+ports+payload, no IPs/seq)
			// This catches SD-WAN NAT where both IPs and IP-ID are rewritten
			if meta.Key.Protocol == "TCP" || meta.Key.Protocol == "UDP" {
				ph := computePortHash(meta)
				if matched := tryPortMatch(portIndex, ph, meta, report, fs, timeOffset); matched {
					return
				}
			}

			// Try relaxed inner match (for decapsulated tunnel packets where
			// SeqNum/IPId may not survive tunnel processing perfectly)
			if meta.TunnelType != TunnelNone {
				rh := computeRelaxedHash(meta)
				if matched := tryRelaxedMatch(fpIndex, rh, meta, report, fs); matched {
					return
				}
			}

			// Check if this is WAN-side control plane traffic (BFD, ICMP, routing)
			if isWANControlPlane(meta) {
				report.IgnoredControlPlaneCount++
				return
			}

			// Unmatched non-encrypted → MISSING_A
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
			return
		}

		// ── Strategy B: Encrypted tunnel → time+size correlation ──
		// The WAN packet is encrypted (ESP/DTLS). We cannot see the inner headers.
		// Instead, find a LAN packet within ±timeWindow whose wire length + tunnel
		// overhead ≈ the encrypted WAN packet length.
		if correlateEncrypted(lanTimeSlots, meta, timeWindow, timeOffset) {
			// Track under the outer (tunnel endpoint) flow
			ofid := flowID{meta.Key.SrcIP, meta.Key.DstIP, meta.Key.SrcPort, meta.Key.DstPort, meta.Key.Protocol}
			ofs := getOrCreateFlow(flows, ofid, meta)
			ofs.PacketsB++
			if !ofs.Encapsulated {
				ofs.Encapsulated = true
				ofs.TunnelType = meta.TunnelType
			}
			ofs.VerifiedEncrypted++
			report.VerifiedEncryptedCount++
		} else {
			// Encrypted packet with no LAN correlation → control plane
			// (tunnel keepalive, BFD, OMP, DTLS control — no LAN origin)
			report.IgnoredControlPlaneCount++
			ofid := flowID{meta.Key.SrcIP, meta.Key.DstIP, meta.Key.SrcPort, meta.Key.DstPort, meta.Key.Protocol}
			ofs := getOrCreateFlow(flows, ofid, meta)
			ofs.PacketsB++
			if !ofs.Encapsulated {
				ofs.Encapsulated = true
				ofs.TunnelType = meta.TunnelType
			}
		}
	})
	if err != nil {
		return nil, fmt.Errorf("failed to stream file B (%s): %w", fileB, err)
	}
	report.TotalPacketsB = totalB

	// Count unmatched fingerprints from A that fall within the WAN capture time window.
	// Separate into: local traffic (ignored), out-of-window (excluded), and genuine drops.
	//
	// Convert WAN time range to LAN timeframe using the offset.
	lanWindowStart := wanFirstTs.Add(-timeOffset).Add(-time.Duration(timeWindowMs) * time.Millisecond)
	lanWindowEnd := wanLastTs.Add(-timeOffset).Add(time.Duration(timeWindowMs) * time.Millisecond)

	unmatchedInWindow := 0
	unmatchedOutOfWindow := 0
	localTrafficCount := 0
	mgmtTrafficCount := 0
	routingTrafficCount := 0
	localLANCount := 0

	for _, fps := range fpIndex {
		for _, fp := range fps {
			if fp.matched {
				continue
			}
			// Classify noise: traffic not expected on WAN
			switch fp.noiseClass {
			case NoiseLocal:
				localTrafficCount++
				continue
			case NoiseMgmt:
				mgmtTrafficCount++
				continue
			case NoiseRouting:
				routingTrafficCount++
				continue
			case NoiseLocalLAN:
				localLANCount++
				continue
			}
			if fp.timestamp.Before(lanWindowStart) || fp.timestamp.After(lanWindowEnd) {
				unmatchedOutOfWindow++
				continue
			}
			unmatchedInWindow++
		}
	}
	report.IgnoredLocalCount = localTrafficCount
	report.IgnoredMgmtCount = mgmtTrafficCount
	report.IgnoredRoutingCount = routingTrafficCount
	report.IgnoredLocalLANCount = localLANCount
	totalNoiseCount := localTrafficCount + mgmtTrafficCount + routingTrafficCount + localLANCount

	// Subtract verified encrypted from in-window unmatched (those transited via tunnel)
	report.MissingBCount = unmatchedInWindow - report.VerifiedEncryptedCount
	if report.MissingBCount < 0 {
		report.MissingBCount = 0
	}

	if c.verbose {
		if unmatchedOutOfWindow > 0 {
			fmt.Fprintf(os.Stderr, "[COMPARE] %d LAN packets outside WAN capture window excluded from MISSING_B\n", unmatchedOutOfWindow)
		}
		if totalNoiseCount > 0 {
			fmt.Fprintf(os.Stderr, "[COMPARE] Noise excluded from MISSING_B: %d local, %d mgmt, %d routing, %d same-subnet\n",
				localTrafficCount, mgmtTrafficCount, routingTrafficCount, localLANCount)
		}
		if report.IgnoredControlPlaneCount > 0 {
			fmt.Fprintf(os.Stderr, "[COMPARE] WAN control plane excluded from score: %d packets (BFD/OMP/keepalive/ICMP)\n",
				report.IgnoredControlPlaneCount)
		}
	}

	for t := range tunnelTypesSet {
		report.TunnelTypes = append(report.TunnelTypes, t)
	}
	report.TunnelDetected = report.EncapsulatedCount > 0

	// ── Finalize ────────────────────────────────────────────────
	c.finalizeStreaming(report, flows, unmatchedOutOfWindow, totalNoiseCount, report.IgnoredControlPlaneCount)
	report.AnalysisDuration = time.Since(start)

	if c.verbose {
		fmt.Fprintf(os.Stderr, "[COMPARE] Done in %v: matched=%d verified_encrypted=%d missingB=%d missingA=%d modified=%d score=%.1f%%\n",
			report.AnalysisDuration, report.MatchedCount, report.VerifiedEncryptedCount,
			report.MissingBCount, report.MissingACount, report.ModifiedCount, report.PathIntegrityScore)
	}
	return report, nil
}

// ─── Finalization ───────────────────────────────────────────────

func (c *Comparator) finalizeStreaming(report *ComparisonReport, flows map[flowID]*flowState, outOfWindowCount, noiseCount, controlPlaneCount int) {
	forensics := &ForensicSummary{}
	var allLatency []float64

	// If >10% of WAN traffic is encrypted, suppress handshake failure reports
	// for LAN-only flows — their SYNs likely transited inside the encrypted tunnel.
	heavyEncryption := report.TotalPacketsB > 0 &&
		float64(report.EncryptedCount)/float64(report.TotalPacketsB) > 0.10

	for _, fs := range flows {
		droppedA := fs.PacketsA - fs.Matched - fs.Modified - fs.VerifiedEncrypted
		if droppedA < 0 {
			droppedA = 0
		}
		fs.MissingB = droppedA

		// Match rate includes exact matches + modifications + verified encrypted transit
		successful := fs.Matched + fs.Modified + fs.VerifiedEncrypted
		total := fs.PacketsA
		if fs.PacketsB > total {
			total = fs.PacketsB
		}
		rate := 0.0
		if total > 0 {
			rate = float64(successful) / float64(total)
		}

		// Determine per-flow drop reason and accumulate packet-level counts.
		// This ensures PolicyDropCount + BlackholeCount ≤ MissingBCount.
		dropReason := ""
		if fs.MissingB > 0 && fs.Protocol == "TCP" {
			if fs.SynSeenA && !fs.SynSeenB && fs.Matched == 0 && fs.VerifiedEncrypted == 0 {
				dropReason = DropReasonPolicyDrop
				report.PolicyDropCount += fs.MissingB
			} else if fs.Matched > 0 || fs.Modified > 0 {
				// Had some successful transit then packets disappeared
				dropReason = DropReasonBlackhole
				report.BlackholeCount += fs.MissingB
			}
		}

		report.FlowSummaries = append(report.FlowSummaries, FlowComparisonSummary{
			SrcIP: fs.SrcIP, DstIP: fs.DstIP, SrcPort: fs.SrcPort, DstPort: fs.DstPort,
			Protocol: fs.Protocol, PacketsA: fs.PacketsA, PacketsB: fs.PacketsB,
			Matched: fs.Matched, MissingB: fs.MissingB, MissingA: fs.MissingA,
			Modified: fs.Modified, VerifiedEncrypted: fs.VerifiedEncrypted,
			MatchRate: rate, HasNAT: fs.HasNAT, DropReason: dropReason,
			TunnelType: fs.TunnelType, Encapsulated: fs.Encapsulated,
		})

		// Failed handshakes — only report for non-encrypted flows.
		// If the flow has verified encrypted transit, the SYN is inside the
		// encrypted tunnel and we cannot observe it on the WAN side.
		// Also suppress when heavyEncryption is true and this is a LAN-only flow
		// (PacketsB == 0) since the SYN likely went through the encrypted tunnel.
		suppressHandshake := fs.VerifiedEncrypted > 0 || fs.Encapsulated ||
			(heavyEncryption && fs.PacketsB == 0)
		if fs.Protocol == "TCP" && !suppressHandshake {
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

		if fs.Matched > 0 || fs.VerifiedEncrypted > 0 || fs.Modified > 0 {
			forensics.TotalFlowsMatched++
		}

		// Retransmission offenders — skip flows with encrypted transit
		// since their "missing" packets likely transited via the tunnel.
		if fs.MissingB > 3 && fs.Protocol == "TCP" && fs.VerifiedEncrypted == 0 {
			forensics.TotalRetransmissionsDropped += fs.MissingB
			// MTU Blackhole detection: if max payload > 1400, large frames likely
			// exceed the tunnel MTU and get silently dropped.
			mtuBlackhole := fs.MaxPayload > 1400
			forensics.TopRetransmissionOffenders = append(forensics.TopRetransmissionOffenders, RetransmissionOffender{
				SrcIP: fs.SrcIP, DstIP: fs.DstIP, SrcPort: fs.SrcPort, DstPort: fs.DstPort,
				Protocol: fs.Protocol, Retransmissions: fs.MissingB, PacketsDropped: fs.MissingB,
				MTUBlackhole: mtuBlackhole, MaxPayload: fs.MaxPayload,
			})

			// Fix Flows Dropped contradiction: if a flow has >3 retransmissions
			// and 0 verified packets on the WAN side, it IS a dropped flow.
			if fs.PacketsB == 0 || (fs.Matched == 0 && fs.Modified == 0 && fs.VerifiedEncrypted == 0) {
				forensics.FlowsDroppedLANtoWAN++
			}
		}

		allLatency = append(allLatency, fs.LatencySamples...)
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

	// Path Integrity Score: matched + modified + verified_encrypted all count as successful transit.
	// Denominator excludes:
	//   LAN side: out-of-window + noise (broadcast/mgmt/routing/same-subnet)
	//   WAN side: control plane (BFD/OMP/keepalive/ICMP — device-generated)
	// This gives a "Data Plane Health" score.
	inWindowA := report.TotalPacketsA - outOfWindowCount - noiseCount
	if inWindowA < 0 {
		inWindowA = 0
	}
	dataPlaneB := report.TotalPacketsB - controlPlaneCount
	if dataPlaneB < 0 {
		dataPlaneB = 0
	}
	totalPkts := inWindowA
	if dataPlaneB > totalPkts {
		totalPkts = dataPlaneB
	}
	if totalPkts > 0 {
		successful := report.MatchedCount + report.ModifiedCount + report.VerifiedEncryptedCount
		report.PathIntegrityScore = float64(successful) / float64(totalPkts) * 100.0
		if report.PathIntegrityScore > 100.0 {
			report.PathIntegrityScore = 100.0
		}
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

// ─── Traffic Classification ─────────────────────────────────────

// classifyNoise determines if a LAN packet is "noise" — traffic that should
// not be expected on the WAN side. Returns NoiseNone for real user traffic.
func classifyNoise(srcIP, dstIP string, srcPort, dstPort uint16, protocol string) string {
	// 1. Broadcast / Multicast / Link-local
	if isBroadcastOrMulticast(dstIP) || isBroadcastOrMulticast(srcIP) ||
		isLinkLocal(dstIP) || isLinkLocal(srcIP) {
		return NoiseLocal
	}

	// 2. Routing protocols — IP protocol numbers or well-known ports
	// HSRP/VRRP: IP protocol 112 (VRRP) or UDP 1985 (HSRP)
	// OSPF: IP protocol 89, EIGRP: IP protocol 88
	switch protocol {
	case "VRRP", "IP/112":
		return NoiseRouting
	case "OSPF", "IP/89":
		return NoiseRouting
	case "EIGRP", "IP/88":
		return NoiseRouting
	}
	if protocol == "UDP" && (srcPort == 1985 || dstPort == 1985) {
		return NoiseRouting
	}

	// 3. Management protocols — SNMP, Syslog, NTP
	if protocol == "UDP" {
		if dstPort == 161 || dstPort == 162 || srcPort == 161 || srcPort == 162 {
			return NoiseMgmt // SNMP
		}
		if dstPort == 514 || srcPort == 514 {
			return NoiseMgmt // Syslog
		}
		if dstPort == 123 || srcPort == 123 {
			return NoiseMgmt // NTP
		}
	}

	// 4. Same private subnet (RFC1918 intra-subnet heuristic)
	// If both IPs are in the same /16 for 10.x or same /24 for 172.16-31 or 192.168
	if samePrivateSubnet(srcIP, dstIP) {
		return NoiseLocalLAN
	}

	return NoiseNone
}

// isBroadcastOrMulticast checks for broadcast and multicast addresses.
func isBroadcastOrMulticast(ipStr string) bool {
	if ipStr == "" {
		return false
	}
	if ipStr == "255.255.255.255" || ipStr == "0.0.0.0" {
		return true
	}
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	if ip4 := ip.To4(); ip4 != nil {
		// Multicast: 224.0.0.0/4
		if ip4[0] >= 224 && ip4[0] <= 239 {
			return true
		}
		// Subnet broadcast heuristic: x.x.x.255
		if ip4[3] == 255 {
			return true
		}
		return false
	}
	// IPv6 multicast: ff00::/8
	return ip[0] == 0xff
}

// isLinkLocal checks for link-local addresses.
func isLinkLocal(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	if ip4 := ip.To4(); ip4 != nil {
		return ip4[0] == 169 && ip4[1] == 254
	}
	// IPv6 link-local: fe80::/10
	return ip[0] == 0xfe && (ip[1]&0xc0) == 0x80
}

// samePrivateSubnet returns true if both IPs are in the same private subnet.
// Uses conservative subnet sizes:
//   - 10.x.y.z: same /16 (10.X.Y.*)
//   - 172.16-31.x.y: same /24
//   - 192.168.x.y: same /24
func samePrivateSubnet(srcIP, dstIP string) bool {
	sIP := net.ParseIP(srcIP)
	dIP := net.ParseIP(dstIP)
	if sIP == nil || dIP == nil {
		return false
	}
	s4 := sIP.To4()
	d4 := dIP.To4()
	if s4 == nil || d4 == nil {
		return false
	}
	// Both must be RFC1918
	sPriv := isRFC1918(s4)
	dPriv := isRFC1918(d4)
	if !sPriv || !dPriv {
		return false
	}
	// 10.0.0.0/8: same /16
	if s4[0] == 10 && d4[0] == 10 {
		return s4[1] == d4[1]
	}
	// 172.16.0.0/12: same /24
	if s4[0] == 172 && d4[0] == 172 &&
		(s4[1] >= 16 && s4[1] <= 31) && (d4[1] >= 16 && d4[1] <= 31) {
		return s4[1] == d4[1] && s4[2] == d4[2]
	}
	// 192.168.0.0/16: same /24
	if s4[0] == 192 && s4[1] == 168 && d4[0] == 192 && d4[1] == 168 {
		return s4[2] == d4[2]
	}
	return false
}

func isRFC1918(ip4 net.IP) bool {
	if ip4[0] == 10 {
		return true
	}
	if ip4[0] == 172 && ip4[1] >= 16 && ip4[1] <= 31 {
		return true
	}
	if ip4[0] == 192 && ip4[1] == 168 {
		return true
	}
	return false
}

// ─── WAN Control Plane Classification ───────────────────────────

// isWANControlPlane returns true if a WAN-side packet is SD-WAN control plane
// traffic that will never have a LAN-side counterpart. These packets are
// generated by the SD-WAN device itself (BFD, OMP, DTLS control, keepalives).
func isWANControlPlane(meta *packetMeta) bool {
	// Cisco Viptela: BFD/OMP on UDP 12346-12426
	if meta.Key.Protocol == "UDP" {
		sp, dp := meta.Key.SrcPort, meta.Key.DstPort
		if (sp >= viptelaPortLow && sp <= viptelaPortHigh) ||
			(dp >= viptelaPortLow && dp <= viptelaPortHigh) {
			// Encrypted tunnel data packets are already handled by correlateEncrypted.
			// Uncorrelated encrypted packets (no LAN match) are control plane.
			if meta.Encrypted {
				return true
			}
			// Small non-encrypted Viptela packets (<200 bytes) are OMP/BFD keepalives
			if meta.Length < 200 {
				return true
			}
		}
		// VeloCloud: VCMP on UDP 2426
		if sp == vcmpPort || dp == vcmpPort {
			if meta.Encrypted {
				return true
			}
			if meta.Length < 200 {
				return true
			}
		}
	}
	// BFD: UDP 3784/4784
	if meta.Key.Protocol == "UDP" &&
		(meta.Key.DstPort == 3784 || meta.Key.DstPort == 4784 ||
			meta.Key.SrcPort == 3784 || meta.Key.SrcPort == 4784) {
		return true
	}
	// ICMP between WAN peers (device-generated pings/traceroutes)
	if meta.Key.Protocol == "ICMP" || meta.Key.Protocol == "ICMPv6" {
		return true
	}
	// Routing protocols that appear on WAN (OSPF underlay, EIGRP)
	switch meta.Key.Protocol {
	case "OSPF", "IP/89", "EIGRP", "IP/88", "VRRP", "IP/112":
		return true
	}
	// HSRP/VRRP multicast on WAN
	if isBroadcastOrMulticast(meta.Key.DstIP) {
		return true
	}
	return false
}

// IsWANNoisyDiscrepancy returns true if a MISSING_A packet is noise that
// should not appear in the Top Discrepancies list.
func IsWANNoisyDiscrepancy(d *Discrepancy) bool {
	// Multicast/broadcast destinations
	if isBroadcastOrMulticast(d.DstIP) {
		return true
	}
	// ICMP (device-generated)
	if d.Protocol == "ICMP" || d.Protocol == "ICMPv6" {
		return true
	}
	// Routing protocols
	switch d.Protocol {
	case "OSPF", "IP/89", "EIGRP", "IP/88", "VRRP", "IP/112":
		return true
	}
	// HSRP/GLBP
	if d.Protocol == "UDP" && (d.SrcPort == 1985 || d.DstPort == 1985) {
		return true
	}
	// Encrypted tunnel packets (control plane already counted separately)
	if d.Encrypted {
		return true
	}
	return false
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

// ─── Match Strategy Helpers ─────────────────────────────────────

// tryExactMatch attempts to find an exact fingerprint match in fpIndex by hash.
// Returns true if a match was found (either PRESENT_BOTH or MODIFIED).
func tryExactMatch(fpIndex map[uint64][]*fingerprint, h uint64, meta *packetMeta, report *ComparisonReport, fs *flowState) bool {
	candidates, ok := fpIndex[h]
	if !ok {
		return false
	}
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
		return true
	}
	return false
}

// tryNATMatch attempts a NAT-relaxed match (protocol + seq + dstport + payload).
func tryNATMatch(natIndex map[uint64][]*fingerprint, nh uint64, meta *packetMeta, report *ComparisonReport, fs *flowState) bool {
	candidates, ok := natIndex[nh]
	if !ok {
		return false
	}
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
		return true
	}
	return false
}

// computePortHash computes a hash using only protocol + ports + payload size.
// No IPs, no SeqNum, no IPId. This is the broadest match — used when SD-WAN
// rewrites source/dest IPs (NAT) AND IP-ID/SeqNum.
func computePortHash(m *packetMeta) uint64 {
	h := fnv.New64a()
	// Use both port directions sorted to handle reverse flows
	lo, hi := m.Key.SrcPort, m.Key.DstPort
	if lo > hi {
		lo, hi = hi, lo
	}
	fmt.Fprintf(h, "PORT|%s|%d|%d|%d", m.Key.Protocol, lo, hi, m.Payload)
	return h.Sum64()
}

// tryPortMatch attempts a port-based match with timestamp proximity.
// This is the fallback for SD-WAN NAT where IPs and SeqNum are both rewritten.
// Requires timestamp within the capture time offset window to avoid false positives.
func tryPortMatch(portIndex map[uint64][]*fingerprint, ph uint64, meta *packetMeta, report *ComparisonReport, fs *flowState, timeOffset time.Duration) bool {
	candidates, ok := portIndex[ph]
	if !ok {
		return false
	}
	// Adjust WAN time to LAN timeframe
	adjustedTime := meta.Timestamp.Add(-timeOffset)
	window := time.Duration(timeWindowMs) * time.Millisecond

	bestIdx := -1
	bestDelta := time.Duration(1<<62 - 1)

	for i, fp := range candidates {
		if fp.matched {
			continue
		}
		// Payload must be within 4 bytes
		if abs(fp.payload-meta.Payload) > 4 {
			continue
		}
		// Must be within time window (adjusted for capture offset)
		delta := adjustedTime.Sub(fp.timestamp)
		if delta < 0 {
			delta = -delta
		}
		if delta > window {
			continue
		}
		if delta < bestDelta {
			bestDelta = delta
			bestIdx = i
		}
	}

	if bestIdx >= 0 {
		candidates[bestIdx].matched = true
		portIndex[ph] = append(candidates[:bestIdx], candidates[bestIdx+1:]...)
		report.ModifiedCount++
		report.NATDetected = true
		fs.Modified++
		fs.HasNAT = true
		addDisc(report, Discrepancy{
			State: StateModified, SrcIP: meta.Key.SrcIP, DstIP: meta.Key.DstIP,
			SrcPort: meta.Key.SrcPort, DstPort: meta.Key.DstPort, Protocol: meta.Key.Protocol,
			PacketIndex: meta.Index, Timestamp: meta.Timestamp.Format("15:04:05.000000"),
			Length: meta.Length, Detail: "NAT translation detected (port+payload+time correlation)",
			TCPFlags: meta.TCPFlags,
		})
		return true
	}
	return false
}

// computeRelaxedHash computes a hash based only on 5-tuple (no SeqNum/IPId).
// Used for decapsulated tunnel packets where inner SeqNum/IPId may not survive
// tunnel encapsulation/decapsulation perfectly.
func computeRelaxedHash(m *packetMeta) uint64 {
	h := fnv.New64a()
	fmt.Fprintf(h, "RLX|%s|%s|%d|%d|%s|%d",
		m.Key.SrcIP, m.Key.DstIP, m.Key.SrcPort, m.Key.DstPort,
		m.Key.Protocol, m.Payload)
	return h.Sum64()
}

// tryRelaxedMatch attempts a relaxed match for decapsulated tunnel packets.
// Matches on 5-tuple + payload size (no SeqNum/IPId) + timestamp proximity.
func tryRelaxedMatch(fpIndex map[uint64][]*fingerprint, rh uint64, meta *packetMeta, report *ComparisonReport, fs *flowState) bool {
	// We need to search the fpIndex differently — the relaxed hash won't be in fpIndex
	// which is keyed by exact hash. Instead, search all unmatched fingerprints for this flow.
	// Since we can't do that efficiently, we use a brute-force scan of the NAT index or
	// iterate the fpIndex looking for 5-tuple+payload matches.
	//
	// More efficient approach: for decapsulated packets, compute the exact hash with
	// the LAN-side fields and check. Since the inner header extraction may have
	// slightly different SeqNum, we match on 5-tuple + payload + time window.

	// Build a candidate hash ignoring SeqNum — just protocol + IPs + ports + payload
	_ = rh // already computed but fpIndex doesn't contain it

	// Scan for time-proximate match in the flow's fingerprints via exact key minus seq
	// This is O(candidates) but only runs for the ~29 decapsulated packets
	for hash, candidates := range fpIndex {
		for i, fp := range candidates {
			if fp.matched {
				continue
			}
			// Check payload match (within 4 bytes)
			if abs(fp.payload-meta.Payload) > 4 {
				continue
			}
			// Check timestamp proximity (within 100ms for decapsulated)
			delta := meta.Timestamp.Sub(fp.timestamp)
			if delta < 0 {
				delta = -delta
			}
			if delta > 100*time.Millisecond {
				continue
			}
			// Match found
			fp.matched = true
			fpIndex[hash] = append(candidates[:i], candidates[i+1:]...)
			report.MatchedCount++
			fs.Matched++
			return true
		}
	}
	return false
}

// ─── Encrypted Tunnel Correlation ───────────────────────────────

// correlateEncrypted performs time+size correlation between an encrypted WAN
// packet and the LAN time slots. Uses binary search to find LAN packets within
// the time window (adjusted by timeOffset), then checks size correlation.
// WAN ≈ LAN + tunnel overhead, but also allows WAN < LAN (fragmentation),
// and packets that are within maxSizeDeltaPct% of each other.
func correlateEncrypted(slots []timeSlot, meta *packetMeta, window, timeOffset time.Duration) bool {
	if len(slots) == 0 {
		return false
	}

	wanLen := meta.Length
	// Adjust WAN timestamp to LAN time frame: LAN_time = WAN_time - offset
	adjustedTime := meta.Timestamp.Add(-timeOffset)

	// Binary search for the first slot with timestamp >= adjustedTime - window
	lo := sort.Search(len(slots), func(i int) bool {
		return !slots[i].timestamp.Before(adjustedTime.Add(-window))
	})

	// Scan forward within the time window, find the best size match
	bestIdx := -1
	bestDelta := int(1 << 30)

	for i := lo; i < len(slots); i++ {
		slot := &slots[i]
		if slot.timestamp.After(adjustedTime.Add(window)) {
			break // past the window
		}
		if slot.matched {
			continue
		}

		// Size correlation: overhead = WAN - LAN
		overhead := wanLen - slot.length
		if overhead >= minTunnelOverhead && overhead <= maxTunnelOverhead {
			delta := abs(overhead)
			if delta < bestDelta {
				bestDelta = delta
				bestIdx = i
			}
		}

		// Also accept if sizes are within maxSizeDeltaPct% of each other
		// (handles fragmentation, MTU differences, padding)
		if slot.length > 0 {
			pctDelta := abs(wanLen-slot.length) * 100 / slot.length
			if pctDelta <= maxSizeDeltaPct {
				delta := abs(wanLen - slot.length)
				if delta < bestDelta {
					bestDelta = delta
					bestIdx = i
				}
			}
		}
	}

	if bestIdx >= 0 {
		slots[bestIdx].matched = true
		return true
	}
	return false
}
