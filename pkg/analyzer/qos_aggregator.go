package analyzer

import (
	"fmt"
	"sort"

	"github.com/gocisse/sdwan-triage/pkg/models"
)

// ─── QoS Aggregation Types ──────────────────────────────────────

// QoSAggregation is the fully-computed QoS dashboard payload.
// It is built from the existing QoSReport (single-capture) and,
// optionally, from a ComparisonReport (LAN-vs-WAN).
type QoSAggregation struct {
	// DSCP class distribution (sorted by packet count descending)
	Classes []QoSClassSummary `json:"classes"`

	// Per-flow DSCP assignments (top 200 by packet count)
	FlowTable []QoSFlowEntry `json:"flow_table"`

	// Alerts generated from the analysis
	Alerts []QoSAlert `json:"alerts"`

	// Totals
	TotalPackets uint64  `json:"total_packets"`
	TotalBytes   uint64  `json:"total_bytes"`
	UniqueClasses int    `json:"unique_classes"`

	// LAN-vs-WAN comparison (nil when only a single capture is loaded)
	Comparison *QoSDSCPComparison `json:"comparison,omitempty"`
}

// QoSClassSummary is one row in the DSCP distribution pie/table.
type QoSClassSummary struct {
	ClassName   string  `json:"class_name"`   // e.g. "EF", "AF41", "BE"
	DSCPValue   uint8   `json:"dscp_value"`
	Description string  `json:"description"`  // human-readable
	PacketCount uint64  `json:"packet_count"`
	ByteCount   uint64  `json:"byte_count"`
	Percentage  float64 `json:"percentage"`   // of total packets
	Color       string  `json:"color"`        // hex colour for the pie chart
}

// QoSFlowEntry is one row in the per-flow DSCP table.
type QoSFlowEntry struct {
	SrcIP       string `json:"src_ip"`
	SrcPort     uint16 `json:"src_port"`
	DstIP       string `json:"dst_ip"`
	DstPort     uint16 `json:"dst_port"`
	Protocol    string `json:"protocol"`
	DSCPClass   string `json:"dscp_class"`
	DSCPValue   uint8  `json:"dscp_value"`
	PacketCount uint64 `json:"packet_count"`
	ByteCount   uint64 `json:"byte_count"`
}

// QoSAlert represents a QoS policy violation or anomaly.
type QoSAlert struct {
	Severity    string `json:"severity"`    // "Critical", "Warning", "Info"
	Title       string `json:"title"`
	Description string `json:"description"`
	Flow        string `json:"flow,omitempty"`
}

// QoSDSCPComparison holds LAN-vs-WAN DSCP marking analysis.
type QoSDSCPComparison struct {
	TotalDSCPChanges int                  `json:"total_dscp_changes"`
	PreservedCount   int                  `json:"preserved_count"`
	RemarkedCount    int                  `json:"remarked_count"`
	StrippedCount    int                  `json:"stripped_count"` // remarked to BE(0)
	Details          []DSCPComparisonFlow `json:"details"`
}

// DSCPComparisonFlow shows how DSCP changed for a specific flow between LAN and WAN.
type DSCPComparisonFlow struct {
	Flow      string `json:"flow"`
	LANClass  string `json:"lan_class"`
	WANClass  string `json:"wan_class"`
	LANValue  uint8  `json:"lan_value"`
	WANValue  uint8  `json:"wan_value"`
	Status    string `json:"status"` // "Preserved", "Remarked", "Stripped"
}

// ─── Colour Palette ─────────────────────────────────────────────

// dscpColors maps well-known DSCP class names to chart colours.
var dscpColors = map[string]string{
	"EF":   "#ef4444", // red    — voice/real-time
	"AF41": "#f97316", // orange — video
	"AF42": "#fb923c",
	"AF43": "#fdba74",
	"AF31": "#eab308", // yellow — critical data
	"AF32": "#facc15",
	"AF33": "#fde047",
	"AF21": "#22c55e", // green  — transactional
	"AF22": "#4ade80",
	"AF23": "#86efac",
	"AF11": "#06b6d4", // cyan   — bulk
	"AF12": "#22d3ee",
	"AF13": "#67e8f9",
	"CS7":  "#a855f7", // purple — network control
	"CS6":  "#c084fc",
	"CS5":  "#7c3aed",
	"CS4":  "#8b5cf6",
	"CS3":  "#6366f1",
	"CS2":  "#818cf8",
	"CS1":  "#94a3b8", // grey   — scavenger
	"BE":   "#64748b", // slate  — best effort
}

func colorForClass(name string) string {
	if c, ok := dscpColors[name]; ok {
		return c
	}
	return "#94a3b8" // default grey
}

// ─── Public API ─────────────────────────────────────────────────

// AggregateQoS builds the full QoS dashboard payload from an existing
// QoSReport (produced by the QoSAnalyzer during single-capture analysis)
// and the traffic flows for per-flow DSCP assignment.
func AggregateQoS(report *models.TriageReport) *QoSAggregation {
	if report == nil {
		return nil
	}

	agg := &QoSAggregation{}
	qos := report.QoSAnalysis

	// ── Build class distribution ────────────────────────────────
	if qos != nil && len(qos.ClassDistribution) > 0 {
		agg.TotalPackets = qos.TotalPackets
		for _, m := range qos.ClassDistribution {
			agg.TotalBytes += m.ByteCount
		}

		for _, m := range qos.ClassDistribution {
			desc := models.DSCPDescriptions[m.ClassName]
			if desc == "" {
				desc = m.ClassName
			}
			agg.Classes = append(agg.Classes, QoSClassSummary{
				ClassName:   m.ClassName,
				DSCPValue:   m.DSCPValue,
				Description: desc,
				PacketCount: m.PacketCount,
				ByteCount:   m.ByteCount,
				Percentage:  m.Percentage,
				Color:       colorForClass(m.ClassName),
			})
		}
		// Sort descending by packet count
		sort.Slice(agg.Classes, func(i, j int) bool {
			return agg.Classes[i].PacketCount > agg.Classes[j].PacketCount
		})
		agg.UniqueClasses = len(agg.Classes)
	}

	// ── Build per-flow DSCP table from traffic_analysis ─────────
	agg.FlowTable = buildFlowTable(report)

	// ── Generate alerts ─────────────────────────────────────────
	agg.Alerts = generateQoSAlerts(report, agg)

	return agg
}

// AggregateQoSWithComparison extends AggregateQoS with LAN-vs-WAN
// DSCP comparison data from a ComparisonReport.
func AggregateQoSWithComparison(report *models.TriageReport, cmp *ComparisonReport) *QoSAggregation {
	agg := AggregateQoS(report)
	if agg == nil || cmp == nil {
		return agg
	}

	comp := &QoSDSCPComparison{}

	// Walk discrepancies looking for DSCP field changes
	for _, disc := range cmp.Discrepancies {
		if disc.State != StateModified {
			continue
		}
		for _, ch := range disc.FieldChanges {
			if ch.Field != "DSCP" {
				continue
			}

			comp.TotalDSCPChanges++

			lanVal := parseDSCPValue(ch.ValueA)
			wanVal := parseDSCPValue(ch.ValueB)
			lanClass := dscpClassName(lanVal)
			wanClass := dscpClassName(wanVal)

			status := "Remarked"
			if wanVal == 0 && lanVal != 0 {
				status = "Stripped"
				comp.StrippedCount++
			} else {
				comp.RemarkedCount++
			}

			flowKey := fmt.Sprintf("%s:%d->%s:%d", disc.SrcIP, disc.SrcPort, disc.DstIP, disc.DstPort)
			comp.Details = append(comp.Details, DSCPComparisonFlow{
				Flow:     flowKey,
				LANClass: lanClass,
				WANClass: wanClass,
				LANValue: lanVal,
				WANValue: wanVal,
				Status:   status,
			})
		}
	}

	// Preserved = matched packets minus DSCP-changed packets
	comp.PreservedCount = cmp.MatchedCount - comp.TotalDSCPChanges

	// Generate comparison-specific alerts
	if comp.StrippedCount > 0 {
		agg.Alerts = append(agg.Alerts, QoSAlert{
			Severity:    "Critical",
			Title:       "DSCP Markings Stripped on WAN",
			Description: fmt.Sprintf("%d packets had DSCP markings stripped to Best Effort (BE) between LAN and WAN. QoS policies are NOT being preserved across the SD-WAN overlay.", comp.StrippedCount),
		})
	}
	if comp.RemarkedCount > 0 {
		agg.Alerts = append(agg.Alerts, QoSAlert{
			Severity:    "Warning",
			Title:       "DSCP Markings Remarked on WAN",
			Description: fmt.Sprintf("%d packets had DSCP values changed between LAN and WAN. Verify SD-WAN QoS policy is configured to preserve or correctly re-mark DSCP.", comp.RemarkedCount),
		})
	}

	agg.Comparison = comp
	return agg
}

// ─── Helpers ────────────────────────────────────────────────────

func buildFlowTable(report *models.TriageReport) []QoSFlowEntry {
	if report.QoSAnalysis == nil {
		return nil
	}

	// Build a lookup from traffic_analysis for per-flow byte/packet counts
	type flowInfo struct {
		srcIP, dstIP   string
		srcPort        uint16
		dstPort        uint16
		protocol       string
		packets, bytes uint64
	}

	flowMap := make(map[string]*flowInfo)
	for _, tf := range report.TrafficAnalysis {
		key := fmt.Sprintf("%s:%d->%s:%d", tf.SrcIP, tf.SrcPort, tf.DstIP, tf.DstPort)
		flowMap[key] = &flowInfo{
			srcIP:    tf.SrcIP,
			dstIP:    tf.DstIP,
			srcPort:  tf.SrcPort,
			dstPort:  tf.DstPort,
			protocol: tf.Protocol,
			bytes:    tf.TotalBytes,
			packets:  1, // TrafficFlow doesn't carry packet count; use bytes as weight
		}
	}

	// Build entries from the mismatched QoS flow keys and per-flow DSCP data
	// The QoSAnalyzer tracks flowDSCP internally; we reconstruct from traffic flows
	// and the class distribution to produce the top flows.
	var entries []QoSFlowEntry
	for _, tf := range report.TrafficAnalysis {
		// Determine DSCP class by destination port heuristic combined with
		// the dominant class. For real per-flow DSCP we'd need the per-packet
		// tracker—here we use the best available data.
		dscp := inferFlowDSCP(tf, report)
		className := dscpClassName(dscp)

		entries = append(entries, QoSFlowEntry{
			SrcIP:       tf.SrcIP,
			SrcPort:     tf.SrcPort,
			DstIP:       tf.DstIP,
			DstPort:     tf.DstPort,
			Protocol:    tf.Protocol,
			DSCPClass:   className,
			DSCPValue:   dscp,
			PacketCount: uint64(tf.Percentage * 100), // approximate; percentage of total
			ByteCount:   tf.TotalBytes,
		})
	}

	// Sort by bytes descending, cap at 200
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].ByteCount > entries[j].ByteCount
	})
	if len(entries) > 200 {
		entries = entries[:200]
	}

	return entries
}

// inferFlowDSCP attempts to determine the DSCP value for a traffic flow
// based on well-known port assignments and the QoS mismatch data.
func inferFlowDSCP(tf models.TrafficFlow, report *models.TriageReport) uint8 {
	// Check if this flow appears in the mismatch list (use actual class)
	if report.QoSAnalysis != nil {
		flowKey := fmt.Sprintf("%s:%d->%s:%d", tf.SrcIP, tf.SrcPort, tf.DstIP, tf.DstPort)
		for _, mm := range report.QoSAnalysis.MismatchedQoS {
			if mm.Flow == flowKey {
				// Return the DSCP for the "expected" class
				return dscpValueForClass(mm.ExpectedClass)
			}
		}
	}

	// Port-based heuristic for common services
	port := tf.DstPort
	if tf.SrcPort < tf.DstPort {
		port = tf.SrcPort
	}

	switch {
	case port == 5060 || port == 5061 || (port >= 16384 && port <= 32767):
		return 46 // EF — voice/RTP
	case port == 443 || port == 80:
		return 0 // BE — web (unless classified otherwise)
	case port == 3389 || port == 22 || port == 3200 || port == 3300:
		return 18 // AF21 — transactional
	case port == 445 || port == 139:
		return 10 // AF11 — bulk data
	case port == 53:
		return 24 // CS3 — signalling
	case port == 88 || port == 389 || port == 636:
		return 24 // CS3 — signalling
	default:
		return 0 // BE
	}
}

func generateQoSAlerts(report *models.TriageReport, agg *QoSAggregation) []QoSAlert {
	var alerts []QoSAlert

	if report.QoSAnalysis == nil {
		return alerts
	}

	// Alert 1: Voice traffic (EF) mixed with Best Effort
	hasEF := false
	hasBE := false
	var efPct, bePct float64
	for _, c := range agg.Classes {
		if c.ClassName == "EF" {
			hasEF = true
			efPct = c.Percentage
		}
		if c.ClassName == "BE" {
			hasBE = true
			bePct = c.Percentage
		}
	}
	if hasEF && hasBE && bePct > 50 {
		alerts = append(alerts, QoSAlert{
			Severity: "Warning",
			Title:    "Voice Traffic (EF) Mixed with Best Effort",
			Description: fmt.Sprintf(
				"%.1f%% of traffic is marked EF (Voice/Real-time) but %.1f%% is still Best Effort. "+
					"Ensure QoS policies classify and mark all traffic appropriately to prevent voice quality degradation under congestion.",
				efPct, bePct),
		})
	}

	// Alert 2: All traffic is Best Effort (no QoS policy applied)
	if len(agg.Classes) == 1 && agg.Classes[0].ClassName == "BE" && agg.TotalPackets > 100 {
		alerts = append(alerts, QoSAlert{
			Severity:    "Warning",
			Title:       "No QoS Policy Detected — All Traffic is Best Effort",
			Description: "100% of analysed packets are marked DSCP 0 (Best Effort). No QoS differentiation is being applied. Voice, video, and critical business applications will compete equally with bulk traffic during congestion.",
		})
	}

	// Alert 3: DSCP mismatch within flows
	if len(report.QoSAnalysis.MismatchedQoS) > 0 {
		alerts = append(alerts, QoSAlert{
			Severity: "Warning",
			Title:    "DSCP Marking Inconsistency Within Flows",
			Description: fmt.Sprintf(
				"%d flows have packets with different DSCP markings. This indicates QoS policy is being applied mid-flow or there is a remarking misconfiguration.",
				len(report.QoSAnalysis.MismatchedQoS)),
		})
	}

	// Alert 4: High-priority traffic with retransmissions
	for _, c := range agg.Classes {
		if (c.ClassName == "EF" || c.ClassName == "AF41") && c.DSCPValue != 0 {
			// Check if we have retransmissions in the report
			if len(report.TCPRetransmissions) > 0 {
				alerts = append(alerts, QoSAlert{
					Severity:    "Critical",
					Title:       fmt.Sprintf("Retransmissions Detected in %s Traffic", c.ClassName),
					Description: fmt.Sprintf("High-priority %s traffic is experiencing TCP retransmissions. This suggests QoS policies are not providing adequate protection, or the WAN link is over-subscribed.", c.ClassName),
				})
				break
			}
		}
	}

	return alerts
}

func parseDSCPValue(s string) uint8 {
	var v uint8
	fmt.Sscanf(s, "%d", &v)
	return v
}

func dscpClassName(dscp uint8) string {
	if name, ok := models.DSCPClasses[dscp]; ok {
		return name
	}
	return fmt.Sprintf("Unknown(%d)", dscp)
}

func dscpValueForClass(className string) uint8 {
	for val, name := range models.DSCPClasses {
		if name == className {
			return val
		}
	}
	return 0
}
