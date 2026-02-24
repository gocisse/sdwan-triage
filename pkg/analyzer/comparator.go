package analyzer

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

// ─── Packet Comparison States ───────────────────────────────────
const (
	StatePresentBoth = "PRESENT_BOTH" // Packet found in both captures
	StateMissingB    = "MISSING_B"    // In file A (LAN), not in B (WAN) — dropped by device
	StateMissingA    = "MISSING_A"    // In file B (WAN), not in A (LAN) — asymmetric routing / spoofed
	StateModified    = "MODIFIED"     // Present in both but fields changed (TTL, DSCP, NAT)
)

// ─── Tunnel Encapsulation Types ─────────────────────────────────
const (
	TunnelNone    = ""          // No encapsulation (clear-text)
	TunnelESP     = "ESP/IPsec" // Encrypted — inner flow hidden
	TunnelGRE     = "GRE"       // Clear tunnel — inner extractable
	TunnelVXLAN   = "VXLAN"     // UDP 4789 — inner extractable
	TunnelVCMP    = "VeloCloud" // UDP 2426 — partially extractable
	TunnelViptela = "Viptela"   // UDP 12346–12426 — partially extractable
)

// SD-WAN tunnel port ranges
const (
	vxlanPort       = 4789
	vcmpPort        = 2426
	viptelaPortLow  = 12346
	viptelaPortHigh = 12426
)

// ─── Core Structs ───────────────────────────────────────────────

// Comparator performs packet-level comparison between two PCAP files.
type Comparator struct {
	verbose bool
}

// NewComparator creates a new PCAP comparator.
func NewComparator(verbose bool) *Comparator {
	return &Comparator{verbose: verbose}
}

// packetKey is the matching key for correlating packets across captures.
// TCP:  5-tuple + TCP sequence number
// UDP:  5-tuple + IP Identification + IP checksum
// Other: 5-tuple + IP Identification
type packetKey struct {
	SrcIP    string
	DstIP    string
	SrcPort  uint16
	DstPort  uint16
	Protocol string
	SeqNum   uint32 // TCP Seq or IP.Id for UDP/other
	IPId     uint16
}

func (k packetKey) String() string {
	return fmt.Sprintf("%s:%d->%s:%d/%s seq=%d ipid=%d",
		k.SrcIP, k.SrcPort, k.DstIP, k.DstPort, k.Protocol, k.SeqNum, k.IPId)
}

// packetMeta holds extracted metadata for a single packet.
type packetMeta struct {
	Key       packetKey
	Index     int
	Timestamp time.Time
	Length    int
	TTL       uint8
	DSCP      uint8
	Checksum  uint16
	TCPFlags  string
	Payload   int // payload size

	// Tunnel/encapsulation metadata
	TunnelType string     // TunnelNone, TunnelESP, TunnelGRE, etc.
	OuterKey   *packetKey // Outer 5-tuple (nil if not encapsulated)
	Encrypted  bool       // True if inner payload is encrypted (ESP without keys)
}

// ─── Comparison Report ──────────────────────────────────────────

// ComparisonReport is the final output of a two-file PCAP comparison.
type ComparisonReport struct {
	FileA string `json:"file_a"` // LAN-side filename
	FileB string `json:"file_b"` // WAN-side filename

	// Aggregate stats
	TotalPacketsA int `json:"total_packets_a"`
	TotalPacketsB int `json:"total_packets_b"`
	MatchedCount  int `json:"matched_count"`
	MissingBCount int `json:"missing_b_count"` // In A not B (dropped)
	MissingACount int `json:"missing_a_count"` // In B not A (asymmetric)
	ModifiedCount int `json:"modified_count"`

	// Path Integrity Score (0–100)
	PathIntegrityScore float64 `json:"path_integrity_score"`
	IntegrityRating    string  `json:"integrity_rating"` // "Healthy", "Degraded", "Critical"

	// Detailed discrepancies
	Discrepancies []Discrepancy `json:"discrepancies"`

	// Per-flow summary
	FlowSummaries []FlowComparisonSummary `json:"flow_summaries"`

	// Modification breakdown
	NATDetected bool `json:"nat_detected"`
	TTLChanges  int  `json:"ttl_changes"`
	DSCPChanges int  `json:"dscp_changes"`

	// Tunnel/Encapsulation stats
	TunnelDetected    bool           `json:"tunnel_detected"`
	TunnelTypes       []string       `json:"tunnel_types,omitempty"`     // Unique tunnel types found
	EncapsulatedCount int            `json:"encapsulated_count"`         // Packets that were decapsulated
	EncryptedCount    int            `json:"encrypted_count"`            // ESP packets where inner is hidden
	TunnelBreakdown   map[string]int `json:"tunnel_breakdown,omitempty"` // TunnelType → count

	// Timing
	AnalysisDuration time.Duration `json:"analysis_duration_ms"`
}

// Discrepancy represents a single packet-level difference between the two captures.
type Discrepancy struct {
	State       string `json:"state"` // MISSING_B, MISSING_A, MODIFIED
	SrcIP       string `json:"src_ip"`
	DstIP       string `json:"dst_ip"`
	SrcPort     uint16 `json:"src_port"`
	DstPort     uint16 `json:"dst_port"`
	Protocol    string `json:"protocol"`
	PacketIndex int    `json:"packet_index"` // Index in the source file
	Timestamp   string `json:"timestamp"`
	Length      int    `json:"length"`
	Detail      string `json:"detail"` // Human-readable explanation
	TCPFlags    string `json:"tcp_flags,omitempty"`

	// Tunnel metadata
	TunnelType string `json:"tunnel_type,omitempty"` // e.g. "GRE", "ESP/IPsec"
	Encrypted  bool   `json:"encrypted,omitempty"`   // True if ESP-encrypted

	// For MODIFIED state
	FieldChanges []FieldChange `json:"field_changes,omitempty"`
}

// FieldChange describes a single field modification between the two captures.
type FieldChange struct {
	Field  string `json:"field"`   // "TTL", "DSCP", "SrcIP" (NAT), "DstIP" (NAT)
	ValueA string `json:"value_a"` // Value in file A
	ValueB string `json:"value_b"` // Value in file B
}

// FlowComparisonSummary aggregates comparison results per 5-tuple flow.
type FlowComparisonSummary struct {
	SrcIP        string  `json:"src_ip"`
	DstIP        string  `json:"dst_ip"`
	SrcPort      uint16  `json:"src_port"`
	DstPort      uint16  `json:"dst_port"`
	Protocol     string  `json:"protocol"`
	PacketsA     int     `json:"packets_a"`
	PacketsB     int     `json:"packets_b"`
	Matched      int     `json:"matched"`
	MissingB     int     `json:"missing_b"`
	MissingA     int     `json:"missing_a"`
	Modified     int     `json:"modified"`
	MatchRate    float64 `json:"match_rate"` // 0.0–1.0
	HasNAT       bool    `json:"has_nat"`
	TunnelType   string  `json:"tunnel_type,omitempty"`
	Encapsulated bool    `json:"encapsulated"`
}

// ─── Main Compare Method ────────────────────────────────────────

// Compare performs a full packet-level comparison between two PCAP files.
// fileA is typically the LAN-side capture, fileB is the WAN-side capture.
func (c *Comparator) Compare(fileA, fileB string) (*ComparisonReport, error) {
	start := time.Now()

	if c.verbose {
		fmt.Fprintf(os.Stderr, "[COMPARE] Loading file A: %s\n", fileA)
	}
	packetsA, err := c.loadPackets(fileA)
	if err != nil {
		return nil, fmt.Errorf("failed to load file A (%s): %w", fileA, err)
	}

	if c.verbose {
		fmt.Fprintf(os.Stderr, "[COMPARE] Loading file B: %s\n", fileB)
		fmt.Fprintf(os.Stderr, "[COMPARE] File A: %d packets, File B: loading...\n", len(packetsA))
	}
	packetsB, err := c.loadPackets(fileB)
	if err != nil {
		return nil, fmt.Errorf("failed to load file B (%s): %w", fileB, err)
	}

	if c.verbose {
		fmt.Fprintf(os.Stderr, "[COMPARE] File B: %d packets\n", len(packetsB))
		fmt.Fprintf(os.Stderr, "[COMPARE] Building indices...\n")
	}

	// Build lookup index for file B: key → []packetMeta (multiple packets may share a key)
	indexB := make(map[string][]*packetMeta, len(packetsB))
	for i := range packetsB {
		k := packetsB[i].Key.String()
		indexB[k] = append(indexB[k], &packetsB[i])
	}

	// Track which B packets were matched
	matchedB := make(map[string]bool) // key string → matched

	// Collect tunnel stats from WAN-side packets
	tunnelBreakdown := make(map[string]int)
	tunnelTypesSet := make(map[string]bool)
	encapsulatedCount := 0
	encryptedCount := 0
	for i := range packetsB {
		if packetsB[i].TunnelType != TunnelNone {
			tunnelBreakdown[packetsB[i].TunnelType]++
			tunnelTypesSet[packetsB[i].TunnelType] = true
			encapsulatedCount++
			if packetsB[i].Encrypted {
				encryptedCount++
			}
		}
	}
	var tunnelTypes []string
	for t := range tunnelTypesSet {
		tunnelTypes = append(tunnelTypes, t)
	}

	if c.verbose && encapsulatedCount > 0 {
		fmt.Fprintf(os.Stderr, "[COMPARE] Tunnel decapsulation: %d encapsulated packets (%d encrypted)\n", encapsulatedCount, encryptedCount)
		for t, cnt := range tunnelBreakdown {
			fmt.Fprintf(os.Stderr, "[COMPARE]   %s: %d packets\n", t, cnt)
		}
	}

	report := &ComparisonReport{
		FileA:             fileA,
		FileB:             fileB,
		TotalPacketsA:     len(packetsA),
		TotalPacketsB:     len(packetsB),
		Discrepancies:     make([]Discrepancy, 0),
		TunnelDetected:    encapsulatedCount > 0,
		TunnelTypes:       tunnelTypes,
		EncapsulatedCount: encapsulatedCount,
		EncryptedCount:    encryptedCount,
		TunnelBreakdown:   tunnelBreakdown,
	}

	// Flow-level aggregation
	type flowKey struct {
		SrcIP, DstIP     string
		SrcPort, DstPort uint16
		Protocol         string
	}
	flowStats := make(map[flowKey]*FlowComparisonSummary)
	getFlow := func(m *packetMeta) *FlowComparisonSummary {
		fk := flowKey{m.Key.SrcIP, m.Key.DstIP, m.Key.SrcPort, m.Key.DstPort, m.Key.Protocol}
		if fs, ok := flowStats[fk]; ok {
			// Upgrade tunnel info if this packet is encapsulated
			if m.TunnelType != TunnelNone && !fs.Encapsulated {
				fs.Encapsulated = true
				fs.TunnelType = m.TunnelType
			}
			return fs
		}
		fs := &FlowComparisonSummary{
			SrcIP: m.Key.SrcIP, DstIP: m.Key.DstIP,
			SrcPort: m.Key.SrcPort, DstPort: m.Key.DstPort,
			Protocol:     m.Key.Protocol,
			Encapsulated: m.TunnelType != TunnelNone,
			TunnelType:   m.TunnelType,
		}
		flowStats[fk] = fs
		return fs
	}

	// ── Phase 1: Match packets from A against B ─────────────────
	for i := range packetsA {
		pa := &packetsA[i]
		fs := getFlow(pa)
		fs.PacketsA++

		k := pa.Key.String()
		candidates, found := indexB[k]

		if !found || len(candidates) == 0 {
			// Try relaxed match for NAT detection:
			// Same protocol + seq but different IP (NAT rewrites source)
			natMatch := c.findNATMatch(pa, indexB, matchedB)
			if natMatch != nil {
				// MODIFIED — NAT detected
				changes := c.detectModifications(pa, natMatch)
				report.ModifiedCount++
				report.NATDetected = true
				fs.Modified++
				fs.HasNAT = true
				matchedB[natMatch.Key.String()] = true

				report.Discrepancies = append(report.Discrepancies, Discrepancy{
					State:        StateModified,
					SrcIP:        pa.Key.SrcIP,
					DstIP:        pa.Key.DstIP,
					SrcPort:      pa.Key.SrcPort,
					DstPort:      pa.Key.DstPort,
					Protocol:     pa.Key.Protocol,
					PacketIndex:  pa.Index,
					Timestamp:    pa.Timestamp.Format("15:04:05.000000"),
					Length:       pa.Length,
					Detail:       "NAT translation detected",
					TCPFlags:     pa.TCPFlags,
					FieldChanges: changes,
				})
				continue
			}

			// MISSING_B — packet in A not in B (dropped)
			report.MissingBCount++
			fs.MissingB++
			report.Discrepancies = append(report.Discrepancies, Discrepancy{
				State:       StateMissingB,
				SrcIP:       pa.Key.SrcIP,
				DstIP:       pa.Key.DstIP,
				SrcPort:     pa.Key.SrcPort,
				DstPort:     pa.Key.DstPort,
				Protocol:    pa.Key.Protocol,
				PacketIndex: pa.Index,
				Timestamp:   pa.Timestamp.Format("15:04:05.000000"),
				Length:      pa.Length,
				Detail:      "Packet present in LAN capture but missing from WAN capture (dropped by device)",
				TCPFlags:    pa.TCPFlags,
			})
			continue
		}

		// Found exact key match — consume the first unmatched candidate
		var pb *packetMeta
		for ci, cand := range candidates {
			ck := cand.Key.String()
			if !matchedB[ck+fmt.Sprintf("@%d", cand.Index)] {
				pb = cand
				matchedB[ck+fmt.Sprintf("@%d", cand.Index)] = true
				// Remove from candidates to avoid double-match
				indexB[k] = append(candidates[:ci], candidates[ci+1:]...)
				break
			}
		}
		if pb == nil {
			// All candidates already matched — treat as missing
			report.MissingBCount++
			fs.MissingB++
			report.Discrepancies = append(report.Discrepancies, Discrepancy{
				State:       StateMissingB,
				SrcIP:       pa.Key.SrcIP,
				DstIP:       pa.Key.DstIP,
				SrcPort:     pa.Key.SrcPort,
				DstPort:     pa.Key.DstPort,
				Protocol:    pa.Key.Protocol,
				PacketIndex: pa.Index,
				Timestamp:   pa.Timestamp.Format("15:04:05.000000"),
				Length:      pa.Length,
				Detail:      "Packet present in LAN capture but no unmatched counterpart in WAN capture",
				TCPFlags:    pa.TCPFlags,
			})
			continue
		}

		// Check for modifications (TTL, DSCP changes)
		changes := c.detectModifications(pa, pb)
		if len(changes) > 0 {
			report.ModifiedCount++
			fs.Modified++
			for _, ch := range changes {
				switch ch.Field {
				case "TTL":
					report.TTLChanges++
				case "DSCP":
					report.DSCPChanges++
				}
			}
			report.Discrepancies = append(report.Discrepancies, Discrepancy{
				State:        StateModified,
				SrcIP:        pa.Key.SrcIP,
				DstIP:        pa.Key.DstIP,
				SrcPort:      pa.Key.SrcPort,
				DstPort:      pa.Key.DstPort,
				Protocol:     pa.Key.Protocol,
				PacketIndex:  pa.Index,
				Timestamp:    pa.Timestamp.Format("15:04:05.000000"),
				Length:       pa.Length,
				Detail:       formatModificationDetail(changes),
				TCPFlags:     pa.TCPFlags,
				FieldChanges: changes,
			})
		} else {
			// PRESENT_BOTH — no discrepancy to report
			report.MatchedCount++
			fs.Matched++
		}
	}

	// ── Phase 2: Find unmatched packets in B (MISSING_A) ────────
	// Build a set of matched B packet indices for efficient lookup
	matchedBIdx := make(map[int]bool, len(matchedB))
	for i := range packetsB {
		k := packetsB[i].Key.String() + fmt.Sprintf("@%d", packetsB[i].Index)
		if matchedB[k] {
			matchedBIdx[packetsB[i].Index] = true
		}
	}
	for i := range packetsB {
		pb := &packetsB[i]
		if matchedBIdx[pb.Index] {
			continue
		}

		fs := getFlow(pb)
		fs.PacketsB++

		// If this packet is encrypted and we couldn't decapsulate, don't count as MISSING_A —
		// it's expected that encrypted tunnel packets have no LAN-side match on outer headers.
		if pb.Encrypted {
			continue
		}

		report.MissingACount++
		fs.MissingA++

		detail := "Packet present in WAN capture but missing from LAN capture (asymmetric routing or injected)"
		if pb.TunnelType != TunnelNone {
			detail = fmt.Sprintf("[%s tunnel] %s", pb.TunnelType, detail)
		}

		report.Discrepancies = append(report.Discrepancies, Discrepancy{
			State:       StateMissingA,
			SrcIP:       pb.Key.SrcIP,
			DstIP:       pb.Key.DstIP,
			SrcPort:     pb.Key.SrcPort,
			DstPort:     pb.Key.DstPort,
			Protocol:    pb.Key.Protocol,
			PacketIndex: pb.Index,
			Timestamp:   pb.Timestamp.Format("15:04:05.000000"),
			Length:      pb.Length,
			Detail:      detail,
			TCPFlags:    pb.TCPFlags,
			TunnelType:  pb.TunnelType,
			Encrypted:   pb.Encrypted,
		})
	}

	// ── Phase 3: Compute flow summaries and scores ──────────────
	for _, fs := range flowStats {
		total := fs.PacketsA
		if fs.PacketsB > total {
			total = fs.PacketsB
		}
		if total > 0 {
			fs.MatchRate = float64(fs.Matched) / float64(total)
		}
		report.FlowSummaries = append(report.FlowSummaries, *fs)
	}
	// Sort flows by match rate ascending (worst first)
	sort.Slice(report.FlowSummaries, func(i, j int) bool {
		return report.FlowSummaries[i].MatchRate < report.FlowSummaries[j].MatchRate
	})

	// Calculate Path Integrity Score
	totalPackets := report.TotalPacketsA
	if report.TotalPacketsB > totalPackets {
		totalPackets = report.TotalPacketsB
	}
	if totalPackets > 0 {
		report.PathIntegrityScore = float64(report.MatchedCount) / float64(totalPackets) * 100.0
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

	report.AnalysisDuration = time.Since(start)

	// Limit discrepancies to 10000 for API/UI sanity
	if len(report.Discrepancies) > 10000 {
		report.Discrepancies = report.Discrepancies[:10000]
	}

	if c.verbose {
		fmt.Fprintf(os.Stderr, "[COMPARE] Done in %v: matched=%d missingB=%d missingA=%d modified=%d score=%.1f%%\n",
			report.AnalysisDuration, report.MatchedCount, report.MissingBCount, report.MissingACount, report.ModifiedCount, report.PathIntegrityScore)
	}

	return report, nil
}

// ─── Packet Loading (Tunnel-Aware) ──────────────────────────────

func (c *Comparator) loadPackets(filePath string) ([]packetMeta, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	reader, err := pcapgo.NewReader(f)
	if err != nil {
		return nil, fmt.Errorf("invalid PCAP: %w", err)
	}

	var packets []packetMeta
	index := 0

	for {
		data, ci, err := reader.ReadPacketData()
		if err != nil {
			break // EOF
		}

		pkt := gopacket.NewPacket(data, reader.LinkType(), gopacket.Lazy)
		if pkt == nil {
			index++
			continue
		}

		meta := packetMeta{
			Index:     index,
			Timestamp: ci.Timestamp,
			Length:    ci.Length,
		}

		// Extract outer network layer
		var srcIP, dstIP string
		var outerIPv4 *layers.IPv4
		if ip4 := pkt.Layer(layers.LayerTypeIPv4); ip4 != nil {
			outerIPv4 = ip4.(*layers.IPv4)
			srcIP = outerIPv4.SrcIP.String()
			dstIP = outerIPv4.DstIP.String()
			meta.TTL = outerIPv4.TTL
			meta.DSCP = uint8(outerIPv4.TOS >> 2)
			meta.Key.IPId = outerIPv4.Id
			meta.Key.Protocol = outerIPv4.Protocol.String()
		} else if ip6 := pkt.Layer(layers.LayerTypeIPv6); ip6 != nil {
			ip := ip6.(*layers.IPv6)
			srcIP = ip.SrcIP.String()
			dstIP = ip.DstIP.String()
			meta.TTL = ip.HopLimit
			meta.DSCP = uint8(ip.TrafficClass >> 2)
			meta.Key.Protocol = ip.NextHeader.String()
		} else {
			index++
			continue // Skip non-IP packets (ARP, etc.)
		}

		meta.Key.SrcIP = srcIP
		meta.Key.DstIP = dstIP

		// ── Tunnel Detection & Decapsulation ─────────────────────
		// Check for encapsulated packets and extract inner headers.
		// Order of checks: ESP, GRE, then UDP-based tunnels (VXLAN, VCMP, Viptela)
		tunnelDetected := false

		// 1. ESP (IPsec) — IP Protocol 50
		if espLayer := pkt.Layer(layers.LayerTypeIPSecESP); espLayer != nil {
			outerKey := meta.Key // save outer
			meta.OuterKey = &outerKey
			meta.TunnelType = TunnelESP
			meta.Encrypted = true
			tunnelDetected = true
			// ESP is encrypted — we can't see the inner headers.
			// Keep the outer key but mark it encrypted so the UI can report it.
			// We still extract the ESP SPI for correlation potential.
			esp := espLayer.(*layers.IPSecESP)
			meta.Key.SeqNum = esp.Seq
		}

		// 2. GRE — IP Protocol 47
		if !tunnelDetected {
			if greLayer := pkt.Layer(layers.LayerTypeGRE); greLayer != nil {
				gre := greLayer.(*layers.GRE)
				// GRE payload should contain an inner IP packet
				if len(gre.Payload) >= 20 {
					if inner := c.decapsulateIP(gre.Payload); inner != nil {
						outerKey := meta.Key
						meta.OuterKey = &outerKey
						meta.TunnelType = TunnelGRE
						c.applyInnerMeta(&meta, inner)
						tunnelDetected = true
					}
				}
			}
		}

		// 3. UDP-based tunnels: VXLAN (4789), VeloCloud VCMP (2426), Viptela (12346–12426)
		if !tunnelDetected {
			if udpLayer := pkt.Layer(layers.LayerTypeUDP); udpLayer != nil {
				u := udpLayer.(*layers.UDP)
				dstP := uint16(u.DstPort)
				srcP := uint16(u.SrcPort)

				switch {
				case dstP == vxlanPort || srcP == vxlanPort:
					// VXLAN: 8-byte VXLAN header then inner Ethernet frame
					if payload := u.Payload; len(payload) > 8+14 {
						// Skip 8-byte VXLAN header + 14-byte Ethernet header
						innerIPData := payload[8+14:]
						if inner := c.decapsulateIP(innerIPData); inner != nil {
							outerKey := meta.Key
							meta.OuterKey = &outerKey
							meta.TunnelType = TunnelVXLAN
							c.applyInnerMeta(&meta, inner)
							tunnelDetected = true
						}
					}

				case dstP == vcmpPort || srcP == vcmpPort:
					// VeloCloud VCMP: proprietary header then inner IP
					// VCMP has a variable-length header; try common offsets
					if inner := c.tryDecapsulateWithOffsets(u.Payload, []int{16, 20, 24, 32}); inner != nil {
						outerKey := meta.Key
						meta.OuterKey = &outerKey
						meta.TunnelType = TunnelVCMP
						c.applyInnerMeta(&meta, inner)
						tunnelDetected = true
					} else {
						// Can't extract inner — mark as encrypted/opaque
						outerKey := meta.Key
						meta.OuterKey = &outerKey
						meta.TunnelType = TunnelVCMP
						meta.Encrypted = true
						tunnelDetected = true
					}

				case (dstP >= viptelaPortLow && dstP <= viptelaPortHigh) ||
					(srcP >= viptelaPortLow && srcP <= viptelaPortHigh):
					// Cisco Viptela: proprietary DTLS/OMP header then inner IP
					if inner := c.tryDecapsulateWithOffsets(u.Payload, []int{8, 12, 16, 20, 24, 28, 32, 36, 40, 48}); inner != nil {
						outerKey := meta.Key
						meta.OuterKey = &outerKey
						meta.TunnelType = TunnelViptela
						c.applyInnerMeta(&meta, inner)
						tunnelDetected = true
					} else {
						// Encrypted overlay — can't extract inner
						outerKey := meta.Key
						meta.OuterKey = &outerKey
						meta.TunnelType = TunnelViptela
						meta.Encrypted = true
						tunnelDetected = true
					}
				}
			}
		}

		// ── Standard (non-tunnel) transport extraction ───────────
		if !tunnelDetected {
			if tcp := pkt.Layer(layers.LayerTypeTCP); tcp != nil {
				t := tcp.(*layers.TCP)
				meta.Key.SrcPort = uint16(t.SrcPort)
				meta.Key.DstPort = uint16(t.DstPort)
				meta.Key.Protocol = "TCP"
				meta.Key.SeqNum = t.Seq
				meta.Checksum = t.Checksum
				meta.Payload = len(t.Payload)
				meta.TCPFlags = formatTCPFlags(t)
			} else if udp := pkt.Layer(layers.LayerTypeUDP); udp != nil {
				u := udp.(*layers.UDP)
				meta.Key.SrcPort = uint16(u.SrcPort)
				meta.Key.DstPort = uint16(u.DstPort)
				meta.Key.Protocol = "UDP"
				meta.Key.SeqNum = uint32(meta.Key.IPId)
				meta.Checksum = u.Checksum
				meta.Payload = len(u.Payload)
			} else if pkt.Layer(layers.LayerTypeICMPv4) != nil {
				meta.Key.Protocol = "ICMP"
				meta.Key.SeqNum = uint32(meta.Key.IPId)
			}
		}

		packets = append(packets, meta)
		index++
	}

	return packets, nil
}

// ─── Tunnel Decapsulation Helpers ───────────────────────────────

// decapsulateIP parses raw bytes as an IPv4 packet and extracts inner metadata.
// Returns nil if the data is not a valid IPv4 packet.
type innerPacketInfo struct {
	SrcIP    string
	DstIP    string
	SrcPort  uint16
	DstPort  uint16
	Protocol string
	TTL      uint8
	DSCP     uint8
	IPId     uint16
	SeqNum   uint32
	Checksum uint16
	Payload  int
	TCPFlags string
}

func (c *Comparator) decapsulateIP(data []byte) *innerPacketInfo {
	if len(data) < 20 {
		return nil
	}

	// Verify this looks like an IPv4 header (version nibble = 4)
	version := data[0] >> 4
	if version != 4 {
		return nil
	}

	ihl := int(data[0]&0x0f) * 4
	if ihl < 20 || ihl > len(data) {
		return nil
	}

	totalLen := int(binary.BigEndian.Uint16(data[2:4]))
	if totalLen < ihl || totalLen > len(data)+100 { // allow some padding tolerance
		return nil
	}

	info := &innerPacketInfo{
		SrcIP: net.IP(data[12:16]).String(),
		DstIP: net.IP(data[16:20]).String(),
		TTL:   data[8],
		DSCP:  data[1] >> 2,
		IPId:  binary.BigEndian.Uint16(data[4:6]),
	}

	// Validate that the IPs look sane (non-zero, non-broadcast)
	if info.SrcIP == "0.0.0.0" || info.DstIP == "0.0.0.0" {
		return nil
	}

	protocol := data[9]
	transportData := data[ihl:]

	switch protocol {
	case 6: // TCP
		if len(transportData) < 20 {
			return nil
		}
		info.Protocol = "TCP"
		info.SrcPort = binary.BigEndian.Uint16(transportData[0:2])
		info.DstPort = binary.BigEndian.Uint16(transportData[2:4])
		info.SeqNum = binary.BigEndian.Uint32(transportData[4:8])
		info.Checksum = binary.BigEndian.Uint16(transportData[16:18])
		tcpDataOff := int(transportData[12]>>4) * 4
		if tcpDataOff >= 20 && tcpDataOff <= len(transportData) {
			info.Payload = len(transportData) - tcpDataOff
		}
		// Parse TCP flags (byte 13)
		flags := transportData[13]
		var flagNames []string
		if flags&0x02 != 0 {
			flagNames = append(flagNames, "SYN")
		}
		if flags&0x10 != 0 {
			flagNames = append(flagNames, "ACK")
		}
		if flags&0x01 != 0 {
			flagNames = append(flagNames, "FIN")
		}
		if flags&0x04 != 0 {
			flagNames = append(flagNames, "RST")
		}
		if flags&0x08 != 0 {
			flagNames = append(flagNames, "PSH")
		}
		if flags&0x20 != 0 {
			flagNames = append(flagNames, "URG")
		}
		info.TCPFlags = strings.Join(flagNames, ",")

	case 17: // UDP
		if len(transportData) < 8 {
			return nil
		}
		info.Protocol = "UDP"
		info.SrcPort = binary.BigEndian.Uint16(transportData[0:2])
		info.DstPort = binary.BigEndian.Uint16(transportData[2:4])
		info.Checksum = binary.BigEndian.Uint16(transportData[6:8])
		info.Payload = len(transportData) - 8
		info.SeqNum = uint32(info.IPId) // Use IP ID for UDP matching

	case 1: // ICMP
		info.Protocol = "ICMP"
		info.SeqNum = uint32(info.IPId)

	default:
		info.Protocol = fmt.Sprintf("IP/%d", protocol)
		info.SeqNum = uint32(info.IPId)
	}

	return info
}

// tryDecapsulateWithOffsets tries to find an inner IP packet at various byte
// offsets within a payload. Used for proprietary SD-WAN headers (VCMP, Viptela)
// where the header length is not fixed/documented.
func (c *Comparator) tryDecapsulateWithOffsets(payload []byte, offsets []int) *innerPacketInfo {
	for _, off := range offsets {
		if off >= len(payload) {
			continue
		}
		if inner := c.decapsulateIP(payload[off:]); inner != nil {
			return inner
		}
	}
	return nil
}

// applyInnerMeta replaces the packet's key with the decapsulated inner flow info.
func (c *Comparator) applyInnerMeta(meta *packetMeta, inner *innerPacketInfo) {
	meta.Key.SrcIP = inner.SrcIP
	meta.Key.DstIP = inner.DstIP
	meta.Key.SrcPort = inner.SrcPort
	meta.Key.DstPort = inner.DstPort
	meta.Key.Protocol = inner.Protocol
	meta.Key.SeqNum = inner.SeqNum
	meta.Key.IPId = inner.IPId
	meta.TTL = inner.TTL
	meta.DSCP = inner.DSCP
	meta.Checksum = inner.Checksum
	meta.Payload = inner.Payload
	meta.TCPFlags = inner.TCPFlags
}

// ─── Modification Detection ─────────────────────────────────────

func (c *Comparator) detectModifications(a, b *packetMeta) []FieldChange {
	var changes []FieldChange

	if a.TTL != b.TTL {
		changes = append(changes, FieldChange{
			Field:  "TTL",
			ValueA: fmt.Sprintf("%d", a.TTL),
			ValueB: fmt.Sprintf("%d", b.TTL),
		})
	}

	if a.DSCP != b.DSCP {
		changes = append(changes, FieldChange{
			Field:  "DSCP",
			ValueA: fmt.Sprintf("%d", a.DSCP),
			ValueB: fmt.Sprintf("%d", b.DSCP),
		})
	}

	if a.Key.SrcIP != b.Key.SrcIP {
		changes = append(changes, FieldChange{
			Field:  "SrcIP",
			ValueA: a.Key.SrcIP,
			ValueB: b.Key.SrcIP,
		})
	}

	if a.Key.DstIP != b.Key.DstIP {
		changes = append(changes, FieldChange{
			Field:  "DstIP",
			ValueA: a.Key.DstIP,
			ValueB: b.Key.DstIP,
		})
	}

	if a.Key.SrcPort != b.Key.SrcPort {
		changes = append(changes, FieldChange{
			Field:  "SrcPort",
			ValueA: fmt.Sprintf("%d", a.Key.SrcPort),
			ValueB: fmt.Sprintf("%d", b.Key.SrcPort),
		})
	}

	if a.Key.DstPort != b.Key.DstPort {
		changes = append(changes, FieldChange{
			Field:  "DstPort",
			ValueA: fmt.Sprintf("%d", a.Key.DstPort),
			ValueB: fmt.Sprintf("%d", b.Key.DstPort),
		})
	}

	return changes
}

// findNATMatch attempts to find a matching packet in B when exact 5-tuple fails,
// by relaxing the source/dest IP constraint (NAT rewrites addresses).
// We match on: protocol + TCP seq (or IP ID for UDP) + ports.
func (c *Comparator) findNATMatch(a *packetMeta, indexB map[string][]*packetMeta, matchedB map[string]bool) *packetMeta {
	// Only attempt NAT match for TCP/UDP with meaningful seq numbers
	if a.Key.Protocol != "TCP" && a.Key.Protocol != "UDP" {
		return nil
	}

	// Search all B packets for a match on protocol + seq + payload size
	for _, candidates := range indexB {
		for _, b := range candidates {
			bk := b.Key.String() + fmt.Sprintf("@%d", b.Index)
			if matchedB[bk] {
				continue
			}
			if b.Key.Protocol != a.Key.Protocol {
				continue
			}
			if b.Key.SeqNum != a.Key.SeqNum {
				continue
			}
			// For TCP, require same ports (NAT usually preserves ports or at least dest port)
			if a.Key.Protocol == "TCP" {
				if b.Key.DstPort != a.Key.DstPort {
					continue
				}
			}
			// Must have similar payload size (within 4 bytes for possible header differences)
			if abs(a.Payload-b.Payload) > 4 {
				continue
			}
			// Good enough match — likely NAT
			return b
		}
	}
	return nil
}

// ─── Helpers ────────────────────────────────────────────────────

func formatTCPFlags(tcp *layers.TCP) string {
	var flags []string
	if tcp.SYN {
		flags = append(flags, "SYN")
	}
	if tcp.ACK {
		flags = append(flags, "ACK")
	}
	if tcp.FIN {
		flags = append(flags, "FIN")
	}
	if tcp.RST {
		flags = append(flags, "RST")
	}
	if tcp.PSH {
		flags = append(flags, "PSH")
	}
	if tcp.URG {
		flags = append(flags, "URG")
	}
	return strings.Join(flags, ",")
}

func formatModificationDetail(changes []FieldChange) string {
	parts := make([]string, 0, len(changes))
	for _, ch := range changes {
		switch ch.Field {
		case "TTL":
			parts = append(parts, fmt.Sprintf("TTL changed: %s→%s (device hop)", ch.ValueA, ch.ValueB))
		case "DSCP":
			parts = append(parts, fmt.Sprintf("DSCP/QoS remarked: %s→%s", ch.ValueA, ch.ValueB))
		case "SrcIP":
			parts = append(parts, fmt.Sprintf("Source NAT: %s→%s", ch.ValueA, ch.ValueB))
		case "DstIP":
			parts = append(parts, fmt.Sprintf("Destination NAT: %s→%s", ch.ValueA, ch.ValueB))
		case "SrcPort":
			parts = append(parts, fmt.Sprintf("Source port translated: %s→%s", ch.ValueA, ch.ValueB))
		case "DstPort":
			parts = append(parts, fmt.Sprintf("Destination port translated: %s→%s", ch.ValueA, ch.ValueB))
		default:
			parts = append(parts, fmt.Sprintf("%s: %s→%s", ch.Field, ch.ValueA, ch.ValueB))
		}
	}
	return strings.Join(parts, "; ")
}

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}
