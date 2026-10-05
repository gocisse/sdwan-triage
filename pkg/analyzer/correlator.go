package analyzer

import (
	"fmt"
	"sort"
	"time"

	"github.com/gocisse/sdwan-triage/pkg/events"
	"github.com/gocisse/sdwan-triage/pkg/models"
)

// UnderlayOverlayCorrelator links underlay events (BGP route changes/session
// resets, BFD session loss) with overlay effects (TCP retransmission spikes,
// RTT increases) to build root-cause chains.
//
// Architecture (Phase 3.2):
//   - Detectors publish typed observations to report.Events (events.Index).
//   - Finalize() reads bgp.event / bfd.down as underlay triggers and
//     tcp.retransmission / tcp.rtt_spike as overlay effects from that index,
//     then scans for overlay events that fall within a configurable window
//     after each underlay event, producing RootCauseChain entries.
//
// The correlator holds no detector-fed state of its own; the event index is
// the shared evidence bus.
type UnderlayOverlayCorrelator struct {
	// Configuration
	correlationWindow time.Duration // Max gap between underlay and overlay events
	minRetransmits    int           // Minimum retransmissions in window to trigger correlation
	rttSpikeThreshMs  float64       // RTT threshold (ms) to consider a spike
}

// underlayEvent is a BGP or BFD trigger derived from the event index.
type underlayEvent struct {
	Timestamp time.Time
	Protocol  string // "BGP" or "BFD"
	EventType string // BGP: "Update", "Withdrawal", "Notification"; BFD: "Down"
	Label     string // UnderlayEvent text, e.g. "BGP Withdrawal", "BFD Session Down"
	Detail    string
}

// overlayEvent is a TCP overlay effect derived from the event index.
type overlayEvent struct {
	Timestamp time.Time
	FlowKey   string
	Value     float64 // Retransmission count (1) or RTT in ms
}

// NewUnderlayOverlayCorrelator creates a correlator with default settings.
func NewUnderlayOverlayCorrelator() *UnderlayOverlayCorrelator {
	return &UnderlayOverlayCorrelator{
		correlationWindow: 5 * time.Second,
		minRetransmits:    3,
		rttSpikeThreshMs:  200.0, // 200ms is a significant RTT spike
	}
}

// Finalize correlates underlay and overlay events read from report.Events and
// appends RootCauseChain entries to the report.
func (c *UnderlayOverlayCorrelator) Finalize(report *models.TriageReport) {
	if report.Events == nil {
		return
	}
	underlay := c.loadUnderlayEvents(report.Events)
	if len(underlay) == 0 {
		return
	}
	retransmissions := c.loadRetransmissions(report.Events)
	rttSpikes := c.loadRTTSpikes(report.Events)

	// Sort events by timestamp for efficient window scanning
	sort.SliceStable(underlay, func(i, j int) bool { return underlay[i].Timestamp.Before(underlay[j].Timestamp) })
	sort.SliceStable(retransmissions, func(i, j int) bool { return retransmissions[i].Timestamp.Before(retransmissions[j].Timestamp) })
	sort.SliceStable(rttSpikes, func(i, j int) bool { return rttSpikes[i].Timestamp.Before(rttSpikes[j].Timestamp) })

	// For each underlay event, look for overlay effects within the correlation window
	for _, ue := range underlay {
		windowStart := ue.Timestamp
		windowEnd := ue.Timestamp.Add(c.correlationWindow)

		// --- Correlate with retransmission spikes ---
		retransInWindow := c.findOverlayEventsInWindow(retransmissions, windowStart, windowEnd)
		if len(retransInWindow) >= c.minRetransmits {
			// Group by flow to find the most affected flows
			flowCounts := make(map[string]int)
			var flowOrder []string
			var earliestOverlay time.Time

			for _, evt := range retransInWindow {
				if _, seen := flowCounts[evt.FlowKey]; !seen {
					flowOrder = append(flowOrder, evt.FlowKey)
				}
				flowCounts[evt.FlowKey]++
				if earliestOverlay.IsZero() || evt.Timestamp.Before(earliestOverlay) {
					earliestOverlay = evt.Timestamp
				}
			}

			var affectedFlows []string
			for _, flow := range flowOrder {
				if count := flowCounts[flow]; count >= 2 {
					affectedFlows = append(affectedFlows, fmt.Sprintf("%s (%d retrans)", flow, count))
				}
			}

			gap := earliestOverlay.Sub(ue.Timestamp).Seconds()
			confidence := c.calculateConfidence(len(retransInWindow), gap)
			severity := c.calculateSeverity(len(retransInWindow), len(flowCounts))

			chain := models.RootCauseChain{
				Timestamp:      float64(ue.Timestamp.UnixNano()) / 1e9,
				UnderlayEvent:  ue.Label,
				UnderlayDetail: ue.Detail,
				OverlayEffect:  "TCP Retransmission Spike",
				OverlayDetail: fmt.Sprintf("%d retransmissions across %d flows within %.1fs of %s event",
					len(retransInWindow), len(flowCounts), gap, ue.Protocol),
				AffectedFlows:  affectedFlows,
				CorrelationGap: gap,
				Confidence:     confidence,
				Severity:       severity,
				Recommendation: c.generateRecommendation(ue, "retransmissions", len(flowCounts)),
			}
			report.RootCauseChains = append(report.RootCauseChains, chain)
		}

		// --- Correlate with RTT spikes ---
		rttInWindow := c.findOverlayEventsInWindow(rttSpikes, windowStart, windowEnd)
		if len(rttInWindow) > 0 {
			flowRTTs := make(map[string]float64)
			var flowOrder []string
			var earliestOverlay time.Time
			var maxRTT float64

			for _, evt := range rttInWindow {
				if _, seen := flowRTTs[evt.FlowKey]; !seen {
					flowOrder = append(flowOrder, evt.FlowKey)
				}
				if evt.Value > flowRTTs[evt.FlowKey] {
					flowRTTs[evt.FlowKey] = evt.Value
				}
				if evt.Value > maxRTT {
					maxRTT = evt.Value
				}
				if earliestOverlay.IsZero() || evt.Timestamp.Before(earliestOverlay) {
					earliestOverlay = evt.Timestamp
				}
			}

			var affectedFlows []string
			for _, flow := range flowOrder {
				affectedFlows = append(affectedFlows, fmt.Sprintf("%s (%.0fms)", flow, flowRTTs[flow]))
			}

			gap := earliestOverlay.Sub(ue.Timestamp).Seconds()
			confidence := c.calculateConfidence(len(rttInWindow), gap)
			severity := "Medium"
			if maxRTT >= 500 {
				severity = "High"
			}
			if maxRTT >= 1000 {
				severity = "Critical"
			}

			chain := models.RootCauseChain{
				Timestamp:      float64(ue.Timestamp.UnixNano()) / 1e9,
				UnderlayEvent:  ue.Label,
				UnderlayDetail: ue.Detail,
				OverlayEffect:  "RTT Spike",
				OverlayDetail: fmt.Sprintf("RTT peaked at %.0fms across %d flows within %.1fs of %s event",
					maxRTT, len(flowRTTs), gap, ue.Protocol),
				AffectedFlows:  affectedFlows,
				CorrelationGap: gap,
				Confidence:     confidence,
				Severity:       severity,
				Recommendation: c.generateRecommendation(ue, "RTT spikes", len(flowRTTs)),
			}
			report.RootCauseChains = append(report.RootCauseChains, chain)
		}
	}
}

// ─── Event index adapters ────────────────────────────────────────────

// loadUnderlayEvents reads bgp.event and bfd.down observations as triggers.
func (c *UnderlayOverlayCorrelator) loadUnderlayEvents(ix *events.Index) []underlayEvent {
	var out []underlayEvent
	for _, e := range ix.ByKind(events.BGPEvent) {
		et := e.Attrs["event_type"]
		out = append(out, underlayEvent{
			Timestamp: e.Timestamp,
			Protocol:  "BGP",
			EventType: et,
			Label:     fmt.Sprintf("BGP %s", et),
			Detail:    e.Attrs["detail"],
		})
	}
	for _, e := range ix.ByKind(events.BFDDown) {
		out = append(out, underlayEvent{
			Timestamp: e.Timestamp,
			Protocol:  "BFD",
			EventType: "Down",
			Label:     "BFD Session Down",
			Detail: fmt.Sprintf("BFD session %s → %s transitioned %s → %s",
				e.Attrs["src_ip"], e.Attrs["peer_ip"], bfdStateLabel(e.Values["prev_state"]), e.Attrs["new_state_name"]),
		})
	}
	return out
}

// loadRetransmissions reads tcp.retransmission events. The overlay timestamp
// is the FIRST transmission of the segment (original_ts_us), matching the
// semantics the correlator always used; it falls back to the event time.
func (c *UnderlayOverlayCorrelator) loadRetransmissions(ix *events.Index) []overlayEvent {
	evs := ix.ByKind(events.TCPRetransmission)
	out := make([]overlayEvent, 0, len(evs))
	for _, e := range evs {
		ts := e.Timestamp
		if us, ok := e.Values["original_ts_us"]; ok && us > 0 {
			ts = time.UnixMicro(int64(us)).UTC()
		}
		out = append(out, overlayEvent{Timestamp: ts, FlowKey: e.FlowKey, Value: 1})
	}
	return out
}

// loadRTTSpikes reads tcp.rtt_spike events. The spike threshold is applied by
// the TCP analyzer at emission time (configurable via thresholds config); the
// correlator consumes every published spike, exactly as the pre-3.2 callback
// path did. c.rttSpikeThreshMs is retained as configuration but, as before,
// does not filter inputs.
func (c *UnderlayOverlayCorrelator) loadRTTSpikes(ix *events.Index) []overlayEvent {
	evs := ix.ByKind(events.TCPRTTSpike)
	out := make([]overlayEvent, 0, len(evs))
	for _, e := range evs {
		out = append(out, overlayEvent{Timestamp: e.Timestamp, FlowKey: e.FlowKey, Value: e.Values["rtt_ms"]})
	}
	return out
}

func bfdStateLabel(v float64) string {
	switch int(v) {
	case 0:
		return "AdminDown"
	case 1:
		return "Down"
	case 2:
		return "Init"
	case 3:
		return "Up"
	}
	return fmt.Sprintf("Unknown(%d)", int(v))
}

// ─── Correlation mechanics (unchanged) ───────────────────────────────

// findOverlayEventsInWindow returns overlay events whose timestamps fall within [start, end].
// Assumes events are sorted by timestamp.
func (c *UnderlayOverlayCorrelator) findOverlayEventsInWindow(evs []overlayEvent, start, end time.Time) []overlayEvent {
	var result []overlayEvent

	// Binary search for the first event >= start
	startIdx := sort.Search(len(evs), func(i int) bool {
		return !evs[i].Timestamp.Before(start)
	})

	for i := startIdx; i < len(evs); i++ {
		if evs[i].Timestamp.After(end) {
			break
		}
		result = append(result, evs[i])
	}

	return result
}

// calculateConfidence determines correlation confidence based on event count and timing gap.
func (c *UnderlayOverlayCorrelator) calculateConfidence(eventCount int, gapSeconds float64) string {
	// Tighter gap + more events = higher confidence
	if gapSeconds <= 1.0 && eventCount >= 5 {
		return "High"
	}
	if gapSeconds <= 3.0 && eventCount >= 3 {
		return "Medium"
	}
	return "Low"
}

// calculateSeverity determines severity based on retransmission count and affected flow count.
func (c *UnderlayOverlayCorrelator) calculateSeverity(retransCount, flowCount int) string {
	if retransCount >= 20 || flowCount >= 10 {
		return "Critical"
	}
	if retransCount >= 10 || flowCount >= 5 {
		return "High"
	}
	if retransCount >= 5 || flowCount >= 3 {
		return "Medium"
	}
	return "Low"
}

// generateRecommendation produces actionable advice based on the correlation.
func (c *UnderlayOverlayCorrelator) generateRecommendation(ue underlayEvent, overlayEffect string, flowCount int) string {
	if ue.Protocol == "BFD" {
		return fmt.Sprintf(
			"BFD session loss coincided with %s in %d overlay flows. "+
				"Check the underlay path and WAN circuit for the affected BFD peer, review BFD timers and detect multiplier, "+
				"and confirm SD-WAN path failover completed. Run 'show bfd neighbors detail' on both endpoints.",
			overlayEffect, flowCount)
	}
	switch ue.EventType {
	case "Withdrawal":
		return fmt.Sprintf(
			"BGP route withdrawal caused %s in %d overlay flows. "+
				"Check underlay link health and BGP peer stability. "+
				"Verify SD-WAN failover policies are configured for fast convergence (<1s). "+
				"Consider BFD for sub-second failure detection on underlay links.",
			overlayEffect, flowCount)
	case "Notification":
		return fmt.Sprintf(
			"BGP session reset triggered %s in %d overlay flows. "+
				"Investigate BGP NOTIFICATION error codes for root cause. "+
				"Check for MTU mismatches, authentication failures, or hold-timer expiry. "+
				"Review SD-WAN transport redundancy configuration.",
			overlayEffect, flowCount)
	default:
		return fmt.Sprintf(
			"BGP route change correlated with %s in %d overlay flows. "+
				"Monitor underlay routing stability. "+
				"Ensure SD-WAN path selection can adapt to underlay changes within SLA thresholds.",
			overlayEffect, flowCount)
	}
}
