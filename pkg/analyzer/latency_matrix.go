package analyzer

import (
	"fmt"
	"math"
	"net"
	"sort"
	"strings"

	"github.com/gocisse/sdwan-triage/pkg/models"
)

// ─── Latency Matrix Types ───────────────────────────────────────

// LatencyMatrix is the top-level result returned by BuildLatencyMatrix.
type LatencyMatrix struct {
	Subnets []string             `json:"subnets"`           // Ordered list of /24 (or /64) subnets
	Cells   map[string]*CellStat `json:"cells"`             // Key: "srcSubnet->dstSubnet"
	Flows   int                  `json:"total_flows"`       // Total flow count contributing data
	MaxRTT  float64              `json:"max_rtt_ms"`        // Global max RTT (for colour normalisation)
	MaxLoss float64              `json:"max_loss_pct"`      // Global max loss %
}

// CellStat holds aggregated latency/loss stats for a subnet pair.
type CellStat struct {
	SrcSubnet  string  `json:"src_subnet"`
	DstSubnet  string  `json:"dst_subnet"`
	AvgRTT     float64 `json:"avg_rtt_ms"`
	MinRTT     float64 `json:"min_rtt_ms"`
	MaxRTT     float64 `json:"max_rtt_ms"`
	LossPct    float64 `json:"loss_pct"`
	FlowCount  int     `json:"flow_count"`
	TotalBytes uint64  `json:"total_bytes,omitempty"`
}

// ─── Builder ────────────────────────────────────────────────────

// BuildLatencyMatrix aggregates RTT and packet-loss data from the
// TriageReport into a subnet-to-subnet latency matrix.
//
// It consumes:
//   - report.RTTAnalysis   (per-flow RTT stats — only flows > 100 ms)
//   - state (ForEachTCPFlow) for ALL flows with RTT samples
//   - report.PacketLoss.PerFlowLoss (per-flow loss stats)
//   - report.TCPRetransmissions      (retransmit flows, used as loss proxy)
//
// Subnets are /24 for IPv4, /64 for IPv6.
func BuildLatencyMatrix(report *models.TriageReport, state *models.AnalysisState) *LatencyMatrix {
	type accumulator struct {
		sumRTT   float64
		minRTT   float64
		maxRTT   float64
		samples  int
		lossPct  float64 // weighted accumulator
		lossFlows int
	}

	cells := make(map[string]*accumulator)

	// Helper: add an RTT observation to the matrix
	addRTT := func(srcIP, dstIP string, avgRTT, minRTT, maxRTT float64, sampleSize int) {
		srcSub := subnetOf(srcIP)
		dstSub := subnetOf(dstIP)
		if srcSub == "" || dstSub == "" || srcSub == dstSub {
			return
		}
		key := srcSub + "->" + dstSub
		a, ok := cells[key]
		if !ok {
			a = &accumulator{minRTT: math.MaxFloat64}
			cells[key] = a
		}
		// Weighted contribution by sample size
		a.sumRTT += avgRTT * float64(sampleSize)
		a.samples += sampleSize
		if minRTT < a.minRTT {
			a.minRTT = minRTT
		}
		if maxRTT > a.maxRTT {
			a.maxRTT = maxRTT
		}
	}

	// ── 1. Collect RTT from AnalysisState (ALL flows, not just >100ms) ──
	if state != nil {
		state.ForEachTCPFlow(func(flowKey string, fs *models.TCPFlowState) bool {
			if len(fs.RTTSamples) == 0 {
				return true
			}
			srcIP, dstIP := parseFlowKey(flowKey)
			if srcIP == "" {
				return true
			}
			var minR, maxR, sumR float64
			minR = fs.RTTSamples[0]
			for _, r := range fs.RTTSamples {
				sumR += r
				if r < minR {
					minR = r
				}
				if r > maxR {
					maxR = r
				}
			}
			avg := sumR / float64(len(fs.RTTSamples))
			addRTT(srcIP, dstIP, avg, minR, maxR, len(fs.RTTSamples))
			return true
		})
	}

	// ── 2. Fold in report.RTTAnalysis (enriches if state was evicted) ──
	for _, f := range report.RTTAnalysis {
		addRTT(f.SrcIP, f.DstIP, f.AvgRTT, f.MinRTT, f.MaxRTT, f.SampleSize)
	}

	// ── 3. Merge per-flow packet loss ───────────────────────────────
	if report.PacketLoss != nil {
		for _, pl := range report.PacketLoss.PerFlowLoss {
			srcSub := subnetOf(pl.SrcIP)
			dstSub := subnetOf(pl.DstIP)
			if srcSub == "" || dstSub == "" || srcSub == dstSub {
				continue
			}
			key := srcSub + "->" + dstSub
			a, ok := cells[key]
			if !ok {
				a = &accumulator{minRTT: math.MaxFloat64}
				cells[key] = a
			}
			a.lossPct += pl.LossPercentage
			a.lossFlows++
		}
	}

	// ── 4. Count retransmission flows per subnet pair as loss proxy ──
	retransmitCount := make(map[string]int)
	for _, r := range report.TCPRetransmissions {
		srcSub := subnetOf(r.SrcIP)
		dstSub := subnetOf(r.DstIP)
		if srcSub == "" || dstSub == "" || srcSub == dstSub {
			continue
		}
		retransmitCount[srcSub+"->"+dstSub]++
	}

	// ── 5. Build final CellStat map + collect subnets ───────────────
	subnetSet := make(map[string]bool)
	result := &LatencyMatrix{
		Cells: make(map[string]*CellStat),
	}

	for key, a := range cells {
		parts := strings.SplitN(key, "->", 2)
		src, dst := parts[0], parts[1]
		subnetSet[src] = true
		subnetSet[dst] = true

		cs := &CellStat{
			SrcSubnet: src,
			DstSubnet: dst,
			FlowCount: max(a.samples, 1), // at least 1 if we have loss data
		}

		if a.samples > 0 {
			cs.AvgRTT = a.sumRTT / float64(a.samples)
			cs.MinRTT = a.minRTT
			cs.MaxRTT = a.maxRTT
		}
		if a.lossFlows > 0 {
			cs.LossPct = a.lossPct / float64(a.lossFlows)
		}

		// Enrich with retransmit count as secondary loss signal
		if rc, ok := retransmitCount[key]; ok && cs.LossPct == 0 && rc > 0 {
			// Rough heuristic: each retransmit flow adds ~2% perceived loss
			cs.LossPct = math.Min(float64(rc)*2.0, 100.0)
		}

		if cs.MaxRTT > result.MaxRTT {
			result.MaxRTT = cs.MaxRTT
		}
		if cs.LossPct > result.MaxLoss {
			result.MaxLoss = cs.LossPct
		}
		result.Flows += cs.FlowCount

		result.Cells[key] = cs
	}

	// ── 6. Sort subnets deterministically ───────────────────────────
	subnets := make([]string, 0, len(subnetSet))
	for s := range subnetSet {
		subnets = append(subnets, s)
	}
	sort.Strings(subnets)
	result.Subnets = subnets

	return result
}

// ─── Helpers ────────────────────────────────────────────────────

// subnetOf returns the /24 (IPv4) or /64 (IPv6) subnet string for an IP,
// e.g. "192.168.1.0/24" or "2001:db8::/64". Returns "" on parse failure.
func subnetOf(ipStr string) string {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return ""
	}
	if ip4 := ip.To4(); ip4 != nil {
		// /24 mask
		masked := net.IPv4(ip4[0], ip4[1], ip4[2], 0)
		return masked.String() + "/24"
	}
	// IPv6: /64
	ipNet := &net.IPNet{
		IP:   ip.Mask(net.CIDRMask(64, 128)),
		Mask: net.CIDRMask(64, 128),
	}
	return ipNet.String()
}

// parseFlowKey splits "srcIP:srcPort->dstIP:dstPort" and returns the two IPs.
func parseFlowKey(key string) (srcIP, dstIP string) {
	parts := strings.SplitN(key, "->", 2)
	if len(parts) != 2 {
		return "", ""
	}
	srcParts := strings.Split(parts[0], ":")
	dstParts := strings.Split(parts[1], ":")
	if len(srcParts) < 2 || len(dstParts) < 2 {
		return "", ""
	}
	// Handle IPv6 addresses with colons — port is always the last segment
	srcIP = strings.Join(srcParts[:len(srcParts)-1], ":")
	dstIP = strings.Join(dstParts[:len(dstParts)-1], ":")
	return srcIP, dstIP
}

// max returns the larger of two ints.
func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// BuildLatencyMatrixFromReport is a convenience wrapper when AnalysisState
// is not available (e.g. the matrix is computed from saved JSON results).
// It uses only report.RTTAnalysis and report.PacketLoss.
func BuildLatencyMatrixFromReport(report *models.TriageReport) *LatencyMatrix {
	return BuildLatencyMatrix(report, nil)
}

// ─── Threshold helpers (used by frontend too) ───────────────────

// LatencyLevel returns a severity label for a given average RTT.
func LatencyLevel(avgRTT float64) string {
	switch {
	case avgRTT < 50:
		return "healthy"
	case avgRTT < 150:
		return "degraded"
	default:
		return "critical"
	}
}

// FormatSubnetPair returns a human-readable label for a cell key.
func FormatSubnetPair(key string) (src, dst string) {
	parts := strings.SplitN(key, "->", 2)
	if len(parts) == 2 {
		return parts[0], parts[1]
	}
	return key, ""
}

// CellKey builds a canonical cell key from two subnets.
func CellKey(src, dst string) string {
	return fmt.Sprintf("%s->%s", src, dst)
}
