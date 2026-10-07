package analyzer

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/gocisse/sdwan-triage/pkg/events"
	"github.com/gocisse/sdwan-triage/pkg/models"
)

// UnderlayOverlayCorrelator relates underlay events (BGP withdrawals/session
// resets, BFD session loss) to overlay observations (TCP retransmission bursts,
// RTT spikes) and records the relationship as RootCauseChain entries.
//
// Architecture (Phase 3.2): detectors publish typed observations to
// report.Events (events.Index); Finalize reads them from there. The correlator
// holds no detector-fed state of its own.
//
// Evidence semantics (Phase 4.3). Every chain states its EvidenceBasis:
//
//   - same_session: the overlay events are on the very TCP session that carried
//     the underlay event (BGP peer IP pair, TCP port 179). This is the only
//     identity the current Event model can establish. It still does not prove
//     that the BGP event caused the retransmissions, so no chain says "caused".
//   - time_proximity: the events merely fall within the correlation window.
//     BGP/BFD events carry no flow, interface, tunnel or path identity, so a
//     shared IP address or a timestamp does not establish that an overlay flow
//     traverses the failed underlay element. These chains are reported as
//     co-occurrence with Low confidence, and are restricted to flows that show a
//     retransmission burst on their own (>= minRetransmits on the same flow);
//     scattered single retransmissions across unrelated flows are not grouped.
//
// Further conservative rules:
//   - A plain BGP UPDATE (announcement) is routine routing activity and is not a
//     trigger; only withdrawals, NOTIFICATIONs and BFD Up→non-Up transitions are.
//   - RTT spikes support only same_session chains. A single spike with no
//     baseline says nothing about a change, and a flow that is simply
//     high-latency would otherwise be blamed on any nearby routing event.
//   - Triggers of the same kind that follow each other within the correlation
//     window form one episode and yield one chain per effect/basis, instead of
//     one near-identical chain per trigger.
type UnderlayOverlayCorrelator struct {
	// Configuration
	correlationWindow time.Duration // Max gap between underlay and overlay events
	minRetransmits    int           // Minimum retransmissions on one flow in window to correlate
	rttSpikeThreshMs  float64       // RTT threshold (ms) to consider a spike
}

// bgpPort is the TCP port of the BGP session an underlay bgp.event was seen on.
const bgpPort = "179"

// underlayEvent is a BGP or BFD trigger derived from the event index.
type underlayEvent struct {
	Timestamp time.Time
	Protocol  string // "BGP" or "BFD"
	EventType string // BGP: "Withdrawal", "Notification"; BFD: "Down"
	Label     string // UnderlayEvent text, e.g. "BGP Withdrawal", "BFD Session Down"
	Detail    string
	// SessionA/SessionB are the two IPs of the BGP TCP session the event was
	// observed on. Empty for BFD (UDP, no TCP session).
	SessionA, SessionB string
	// Ev is the source Event, kept so chains can cite their exact evidence.
	Ev events.Event
}

// episode is a run of same-label triggers, each within the correlation window
// of the previous one.
type episode struct {
	first, last time.Time
	label       string
	protocol    string
	eventType   string
	detail      string // detail of the first trigger
	count       int
	sessions    [][2]string    // distinct BGP session IP pairs (normalised order)
	triggers    []events.Event // every trigger in the episode (exact evidence)
}

// overlayEvent is a TCP overlay effect derived from the event index.
type overlayEvent struct {
	Timestamp time.Time
	FlowKey   string
	Value     float64      // Retransmission count (1) or RTT in ms
	Ev        events.Event // source Event, kept so chains can cite their exact evidence
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

	sort.SliceStable(retransmissions, func(i, j int) bool { return retransmissions[i].Timestamp.Before(retransmissions[j].Timestamp) })
	sort.SliceStable(rttSpikes, func(i, j int) bool { return rttSpikes[i].Timestamp.Before(rttSpikes[j].Timestamp) })

	for _, ep := range c.buildEpisodes(underlay) {
		windowStart := ep.first
		windowEnd := ep.last.Add(c.correlationWindow)

		c.correlateRetransmissions(report, ep, c.findOverlayEventsInWindow(retransmissions, windowStart, windowEnd))
		c.correlateRTT(report, ep, c.findOverlayEventsInWindow(rttSpikes, windowStart, windowEnd))
	}
}

// buildEpisodes coalesces triggers into episodes, deterministically: triggers
// are ordered by (timestamp, label, detail); only triggers with the same label
// join an episode; a trigger joins the open episode of its label when it is no
// more than correlationWindow after that episode's last trigger. Episodes are
// returned ordered by (first timestamp, label).
func (c *UnderlayOverlayCorrelator) buildEpisodes(underlay []underlayEvent) []*episode {
	sorted := append([]underlayEvent(nil), underlay...)
	sort.SliceStable(sorted, func(i, j int) bool {
		a, b := sorted[i], sorted[j]
		if !a.Timestamp.Equal(b.Timestamp) {
			return a.Timestamp.Before(b.Timestamp)
		}
		if a.Label != b.Label {
			return a.Label < b.Label
		}
		return a.Detail < b.Detail
	})

	var all []*episode
	open := make(map[string]*episode)
	for _, ue := range sorted {
		ep := open[ue.Label]
		if ep == nil || ue.Timestamp.Sub(ep.last) > c.correlationWindow {
			ep = &episode{first: ue.Timestamp, label: ue.Label, protocol: ue.Protocol, eventType: ue.EventType, detail: ue.Detail}
			open[ue.Label] = ep
			all = append(all, ep)
		}
		ep.last = ue.Timestamp
		ep.count++
		ep.triggers = append(ep.triggers, ue.Ev)
		if ue.SessionA != "" {
			pair := [2]string{ue.SessionA, ue.SessionB}
			known := false
			for _, p := range ep.sessions {
				if p == pair {
					known = true
					break
				}
			}
			if !known {
				ep.sessions = append(ep.sessions, pair)
			}
		}
	}
	sort.SliceStable(all, func(i, j int) bool {
		if !all[i].first.Equal(all[j].first) {
			return all[i].first.Before(all[j].first)
		}
		return all[i].label < all[j].label
	})
	return all
}

// matchesSession reports whether flowKey is the TCP session (port 179, same IP
// pair in either direction) on which one of the episode's BGP events was seen.
func (ep *episode) matchesSession(flowKey string) bool {
	srcIP, srcPort, dstIP, dstPort, ok := splitFlowKey(flowKey)
	if !ok || (srcPort != bgpPort && dstPort != bgpPort) {
		return false
	}
	pair := normalisePair(srcIP, dstIP)
	for _, p := range ep.sessions {
		if p == pair {
			return true
		}
	}
	return false
}

// splitFlowKey parses the detector flow-key convention "srcIP:port->dstIP:port".
// The port is taken after the LAST colon of each side so IPv6 addresses work.
func splitFlowKey(k string) (srcIP, srcPort, dstIP, dstPort string, ok bool) {
	i := strings.Index(k, "->")
	if i < 0 {
		return
	}
	split := func(s string) (string, string, bool) {
		j := strings.LastIndex(s, ":")
		if j <= 0 || j == len(s)-1 {
			return "", "", false
		}
		return s[:j], s[j+1:], true
	}
	var ok1, ok2 bool
	srcIP, srcPort, ok1 = split(k[:i])
	dstIP, dstPort, ok2 = split(k[i+2:])
	return srcIP, srcPort, dstIP, dstPort, ok1 && ok2
}

func normalisePair(a, b string) [2]string {
	if b < a {
		a, b = b, a
	}
	return [2]string{a, b}
}

// flowGroup is the set of qualifying retransmissions of one flow.
type flowGroup struct {
	flow     string
	count    int
	earliest time.Time
	events   []events.Event // the exact retransmission events counted for this flow
}

// correlateRetransmissions emits at most one same_session chain and one
// time_proximity chain for the episode. Only flows with at least minRetransmits
// retransmissions in the window qualify.
func (c *UnderlayOverlayCorrelator) correlateRetransmissions(report *models.TriageReport, ep *episode, evs []overlayEvent) {
	var order []string
	groups := make(map[string]*flowGroup)
	for _, e := range evs {
		g := groups[e.FlowKey]
		if g == nil {
			g = &flowGroup{flow: e.FlowKey, earliest: e.Timestamp}
			groups[e.FlowKey] = g
			order = append(order, e.FlowKey)
		}
		g.count++
		g.events = append(g.events, e.Ev)
		if e.Timestamp.Before(g.earliest) {
			g.earliest = e.Timestamp
		}
	}

	var session, proximity []*flowGroup
	for _, k := range order {
		g := groups[k]
		if g.count < c.minRetransmits {
			continue
		}
		if ep.matchesSession(k) {
			session = append(session, g)
		} else {
			proximity = append(proximity, g)
		}
	}
	if len(session) > 0 {
		c.appendRetransChain(report, ep, session, models.EvidenceSameSession)
	}
	if len(proximity) > 0 {
		c.appendRetransChain(report, ep, proximity, models.EvidenceTimeProximity)
	}
}

func (c *UnderlayOverlayCorrelator) appendRetransChain(report *models.TriageReport, ep *episode, groups []*flowGroup, basis string) {
	total := 0
	earliest := groups[0].earliest
	affected := make([]string, 0, len(groups))
	// Evidence: every trigger of the episode plus exactly the retransmission
	// events counted for the flows reported in this chain.
	evidence := append([]events.Event(nil), ep.triggers...)
	for _, g := range groups {
		evidence = append(evidence, g.events...)
		total += g.count
		if g.earliest.Before(earliest) {
			earliest = g.earliest
		}
		affected = append(affected, fmt.Sprintf("%s (%d retrans)", g.flow, g.count))
	}
	gap := earliest.Sub(ep.first).Seconds()

	chain := models.RootCauseChain{
		Timestamp:      float64(ep.first.UnixNano()) / 1e9,
		UnderlayEvent:  ep.label,
		UnderlayDetail: ep.underlayDetail(),
		AffectedFlows:  affected,
		CorrelationGap: gap,
		Severity:       c.calculateSeverity(total, len(groups)),
		EvidenceBasis:  basis,
	}
	chain.Evidence, chain.EvidenceCount = boundedEvidence(evidence)
	if basis == models.EvidenceSameSession {
		chain.OverlayEffect = "TCP Retransmission Spike"
		chain.OverlayDetail = fmt.Sprintf("%d retransmissions on the BGP session's own TCP connection within %.1fs of %s event",
			total, gap, ep.protocol)
		chain.Confidence = c.calculateConfidence(total, gap)
	} else {
		chain.OverlayEffect = "TCP Retransmission Burst (co-occurring)"
		chain.OverlayDetail = fmt.Sprintf("%d retransmissions on %d flow(s) (each with >=%d) began %.1fs after %s event; "+
			"no shared flow or session identity was established, so no causal relationship is claimed",
			total, len(groups), c.minRetransmits, gap, ep.protocol)
		chain.Confidence = "Low"
	}
	chain.Recommendation = c.generateRecommendation(ep, "TCP retransmissions", basis)
	report.RootCauseChains = append(report.RootCauseChains, chain)
}

// correlateRTT emits a chain only for RTT spikes on the BGP session's own TCP
// connection (same_session). RTT spikes on other flows are not correlated: with
// no baseline, a spike is indistinguishable from a flow that is simply slow.
func (c *UnderlayOverlayCorrelator) correlateRTT(report *models.TriageReport, ep *episode, evs []overlayEvent) {
	var order []string
	peak := make(map[string]float64)
	var earliest time.Time
	var maxRTT float64
	spikes := 0
	evidence := append([]events.Event(nil), ep.triggers...)
	for _, e := range evs {
		if !ep.matchesSession(e.FlowKey) {
			continue
		}
		spikes++
		evidence = append(evidence, e.Ev)
		if _, seen := peak[e.FlowKey]; !seen {
			order = append(order, e.FlowKey)
		}
		if e.Value > peak[e.FlowKey] {
			peak[e.FlowKey] = e.Value
		}
		if e.Value > maxRTT {
			maxRTT = e.Value
		}
		if earliest.IsZero() || e.Timestamp.Before(earliest) {
			earliest = e.Timestamp
		}
	}
	if len(order) == 0 {
		return
	}
	affected := make([]string, 0, len(order))
	for _, f := range order {
		affected = append(affected, fmt.Sprintf("%s (%.0fms)", f, peak[f]))
	}
	gap := earliest.Sub(ep.first).Seconds()
	severity := "Medium"
	if maxRTT >= 500 {
		severity = "High"
	}
	if maxRTT >= 1000 {
		severity = "Critical"
	}
	refs, refCount := boundedEvidence(evidence)
	report.RootCauseChains = append(report.RootCauseChains, models.RootCauseChain{
		Timestamp:      float64(ep.first.UnixNano()) / 1e9,
		UnderlayEvent:  ep.label,
		UnderlayDetail: ep.underlayDetail(),
		Evidence:       refs,
		EvidenceCount:  refCount,
		OverlayEffect:  "RTT Spike",
		OverlayDetail: fmt.Sprintf("RTT peaked at %.0fms on the BGP session's own TCP connection within %.1fs of %s event",
			maxRTT, gap, ep.protocol),
		AffectedFlows:  affected,
		CorrelationGap: gap,
		Confidence:     c.calculateConfidence(spikes, gap),
		Severity:       severity,
		EvidenceBasis:  models.EvidenceSameSession,
		Recommendation: c.generateRecommendation(ep, "RTT spikes", models.EvidenceSameSession),
	})
}

// underlayDetail is the first trigger's detail, noting any coalesced triggers.
func (ep *episode) underlayDetail() string {
	if ep.count <= 1 {
		return ep.detail
	}
	return fmt.Sprintf("%s (+%d more %s events within %.1fs, coalesced into one episode)",
		ep.detail, ep.count-1, ep.label, ep.last.Sub(ep.first).Seconds())
}

// ─── Event index adapters ────────────────────────────────────────────

// loadUnderlayEvents reads bgp.event and bfd.down observations as triggers.
func (c *UnderlayOverlayCorrelator) loadUnderlayEvents(ix *events.Index) []underlayEvent {
	var out []underlayEvent
	for _, e := range ix.ByKind(events.BGPEvent) {
		et := e.Attrs["event_type"]
		// A plain UPDATE is an announcement/attribute change: routine routing
		// activity that the event cannot distinguish from a failure. Only
		// withdrawals and NOTIFICATIONs (session resets) are triggers.
		if et != "Withdrawal" && et != "Notification" {
			continue
		}
		pair := normalisePair(e.Attrs["peer_ip"], e.Attrs["dst_ip"])
		out = append(out, underlayEvent{
			Timestamp: e.Timestamp,
			Protocol:  "BGP",
			EventType: et,
			Label:     fmt.Sprintf("BGP %s", et),
			Detail:    e.Attrs["detail"],
			SessionA:  pair[0],
			SessionB:  pair[1],
			Ev:        e,
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
			Ev: e,
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
		out = append(out, overlayEvent{Timestamp: ts, FlowKey: e.FlowKey, Value: 1, Ev: e})
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
		out = append(out, overlayEvent{Timestamp: e.Timestamp, FlowKey: e.FlowKey, Value: e.Values["rtt_ms"], Ev: e})
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

// generateRecommendation produces advice that matches the evidence basis. It
// never asserts causation: same_session says the events share a session;
// time_proximity says only that they co-occurred and what to verify next.
func (c *UnderlayOverlayCorrelator) generateRecommendation(ep *episode, overlayEffect, basis string) string {
	if basis == models.EvidenceTimeProximity {
		return fmt.Sprintf(
			"A %s event and %s were observed within %.0fs of each other, but the capture does not show that the affected flows share a session or path with it. "+
				"Treat this as co-occurrence only. Check device logs and the path of the affected flows before attributing the %s to it.",
			ep.label, overlayEffect, c.correlationWindow.Seconds(), overlayEffect)
	}
	switch ep.eventType {
	case "Withdrawal":
		return fmt.Sprintf(
			"%s occurred on the BGP session's own TCP connection around a BGP route withdrawal. "+
				"Check underlay link health and BGP peer stability, and consider BFD for sub-second failure detection on underlay links.",
			overlayEffect)
	default: // Notification
		return fmt.Sprintf(
			"%s occurred on the BGP session's own TCP connection around a BGP NOTIFICATION (session reset). "+
				"Investigate the NOTIFICATION error codes; check for MTU mismatches, authentication failures or hold-timer expiry.",
			overlayEffect)
	}
}
