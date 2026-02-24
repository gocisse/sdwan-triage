package analyzer

import (
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/gocisse/sdwan-triage/pkg/models"
)

// UnderlayOverlayCorrelator links underlay events (BGP route changes, link failures)
// with overlay effects (TCP retransmission spikes, RTT increases) to build root-cause chains.
//
// Architecture:
//   - BGP updates/withdrawals are recorded as underlay events with timestamps.
//   - TCP retransmissions and RTT spikes are recorded as overlay events.
//   - Finalize() scans for overlay events that fall within a configurable window
//     after an underlay event, producing RootCauseChain entries.
type UnderlayOverlayCorrelator struct {
	mu sync.Mutex

	// Underlay events (BGP route changes, session resets)
	bgpEvents []bgpEvent

	// Overlay events (retransmissions, RTT spikes)
	retransmissions []overlayEvent
	rttSpikes       []overlayEvent

	// Configuration
	correlationWindow time.Duration // Max gap between underlay and overlay events
	minRetransmits    int           // Minimum retransmissions in window to trigger correlation
	rttSpikeThreshMs  float64       // RTT threshold (ms) to consider a spike
}

// bgpEvent represents a BGP underlay event (update or withdrawal).
type bgpEvent struct {
	Timestamp time.Time
	PeerIP    string
	Prefix    string // Affected IP prefix (if parseable)
	EventType string // "Update", "Withdrawal", "Notification"
	Detail    string
}

// overlayEvent represents a TCP overlay event (retransmission or RTT spike).
type overlayEvent struct {
	Timestamp time.Time
	FlowKey   string
	SrcIP     string
	DstIP     string
	Value     float64 // Retransmission count or RTT in ms
	EventType string  // "Retransmission", "RTT Spike"
}

// NewUnderlayOverlayCorrelator creates a correlator with default settings.
func NewUnderlayOverlayCorrelator() *UnderlayOverlayCorrelator {
	return &UnderlayOverlayCorrelator{
		correlationWindow: 5 * time.Second,
		minRetransmits:    3,
		rttSpikeThreshMs:  200.0, // 200ms is a significant RTT spike
	}
}

// RecordBGPEvent records a BGP underlay event for later correlation.
func (c *UnderlayOverlayCorrelator) RecordBGPEvent(timestamp time.Time, peerIP, prefix, eventType, detail string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.bgpEvents = append(c.bgpEvents, bgpEvent{
		Timestamp: timestamp,
		PeerIP:    peerIP,
		Prefix:    prefix,
		EventType: eventType,
		Detail:    detail,
	})
}

// RecordRetransmission records a TCP retransmission overlay event.
func (c *UnderlayOverlayCorrelator) RecordRetransmission(timestamp time.Time, flowKey, srcIP, dstIP string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.retransmissions = append(c.retransmissions, overlayEvent{
		Timestamp: timestamp,
		FlowKey:   flowKey,
		SrcIP:     srcIP,
		DstIP:     dstIP,
		Value:     1,
		EventType: "Retransmission",
	})
}

// RecordRTTSpike records an RTT spike overlay event.
func (c *UnderlayOverlayCorrelator) RecordRTTSpike(timestamp time.Time, flowKey, srcIP, dstIP string, rttMs float64) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.rttSpikes = append(c.rttSpikes, overlayEvent{
		Timestamp: timestamp,
		FlowKey:   flowKey,
		SrcIP:     srcIP,
		DstIP:     dstIP,
		Value:     rttMs,
		EventType: "RTT Spike",
	})
}

// Finalize correlates all collected underlay and overlay events and appends
// RootCauseChain entries to the report.
func (c *UnderlayOverlayCorrelator) Finalize(report *models.TriageReport) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if len(c.bgpEvents) == 0 {
		return
	}

	// Sort events by timestamp for efficient window scanning
	sort.Slice(c.bgpEvents, func(i, j int) bool {
		return c.bgpEvents[i].Timestamp.Before(c.bgpEvents[j].Timestamp)
	})
	sort.Slice(c.retransmissions, func(i, j int) bool {
		return c.retransmissions[i].Timestamp.Before(c.retransmissions[j].Timestamp)
	})
	sort.Slice(c.rttSpikes, func(i, j int) bool {
		return c.rttSpikes[i].Timestamp.Before(c.rttSpikes[j].Timestamp)
	})

	// For each BGP event, look for overlay effects within the correlation window
	for _, bgp := range c.bgpEvents {
		windowStart := bgp.Timestamp
		windowEnd := bgp.Timestamp.Add(c.correlationWindow)

		// --- Correlate with retransmission spikes ---
		retransInWindow := c.findOverlayEventsInWindow(c.retransmissions, windowStart, windowEnd)
		if len(retransInWindow) >= c.minRetransmits {
			// Group by flow to find the most affected flows
			flowCounts := make(map[string]int)
			var affectedFlows []string
			var earliestOverlay time.Time

			for _, evt := range retransInWindow {
				flowCounts[evt.FlowKey]++
				if earliestOverlay.IsZero() || evt.Timestamp.Before(earliestOverlay) {
					earliestOverlay = evt.Timestamp
				}
			}

			for flow, count := range flowCounts {
				if count >= 2 {
					affectedFlows = append(affectedFlows, fmt.Sprintf("%s (%d retrans)", flow, count))
				}
			}

			gap := earliestOverlay.Sub(bgp.Timestamp).Seconds()
			confidence := c.calculateConfidence(len(retransInWindow), gap)
			severity := c.calculateSeverity(len(retransInWindow), len(flowCounts))

			chain := models.RootCauseChain{
				Timestamp:      float64(bgp.Timestamp.UnixNano()) / 1e9,
				UnderlayEvent:  fmt.Sprintf("BGP %s", bgp.EventType),
				UnderlayDetail: bgp.Detail,
				OverlayEffect:  "TCP Retransmission Spike",
				OverlayDetail: fmt.Sprintf("%d retransmissions across %d flows within %.1fs of BGP event",
					len(retransInWindow), len(flowCounts), gap),
				AffectedFlows:  affectedFlows,
				CorrelationGap: gap,
				Confidence:     confidence,
				Severity:       severity,
				Recommendation: c.generateRecommendation(bgp.EventType, "retransmissions", len(flowCounts)),
			}
			report.RootCauseChains = append(report.RootCauseChains, chain)
		}

		// --- Correlate with RTT spikes ---
		rttInWindow := c.findOverlayEventsInWindow(c.rttSpikes, windowStart, windowEnd)
		if len(rttInWindow) > 0 {
			flowRTTs := make(map[string]float64)
			var affectedFlows []string
			var earliestOverlay time.Time
			var maxRTT float64

			for _, evt := range rttInWindow {
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

			for flow, rtt := range flowRTTs {
				affectedFlows = append(affectedFlows, fmt.Sprintf("%s (%.0fms)", flow, rtt))
			}

			gap := earliestOverlay.Sub(bgp.Timestamp).Seconds()
			confidence := c.calculateConfidence(len(rttInWindow), gap)
			severity := "Medium"
			if maxRTT >= 500 {
				severity = "High"
			}
			if maxRTT >= 1000 {
				severity = "Critical"
			}

			chain := models.RootCauseChain{
				Timestamp:      float64(bgp.Timestamp.UnixNano()) / 1e9,
				UnderlayEvent:  fmt.Sprintf("BGP %s", bgp.EventType),
				UnderlayDetail: bgp.Detail,
				OverlayEffect:  "RTT Spike",
				OverlayDetail: fmt.Sprintf("RTT peaked at %.0fms across %d flows within %.1fs of BGP event",
					maxRTT, len(flowRTTs), gap),
				AffectedFlows:  affectedFlows,
				CorrelationGap: gap,
				Confidence:     confidence,
				Severity:       severity,
				Recommendation: c.generateRecommendation(bgp.EventType, "RTT spikes", len(flowRTTs)),
			}
			report.RootCauseChains = append(report.RootCauseChains, chain)
		}
	}
}

// findOverlayEventsInWindow returns overlay events whose timestamps fall within [start, end].
// Assumes events are sorted by timestamp.
func (c *UnderlayOverlayCorrelator) findOverlayEventsInWindow(events []overlayEvent, start, end time.Time) []overlayEvent {
	var result []overlayEvent

	// Binary search for the first event >= start
	startIdx := sort.Search(len(events), func(i int) bool {
		return !events[i].Timestamp.Before(start)
	})

	for i := startIdx; i < len(events); i++ {
		if events[i].Timestamp.After(end) {
			break
		}
		result = append(result, events[i])
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
func (c *UnderlayOverlayCorrelator) generateRecommendation(bgpEventType, overlayEffect string, flowCount int) string {
	switch bgpEventType {
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

// Stats returns summary statistics about collected events.
func (c *UnderlayOverlayCorrelator) Stats() (bgpCount, retransCount, rttSpikeCount int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.bgpEvents), len(c.retransmissions), len(c.rttSpikes)
}
