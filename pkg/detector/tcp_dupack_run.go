package detector

import (
	"sort"
	"time"

	"github.com/gocisse/sdwan-triage/pkg/events"
	"github.com/gocisse/sdwan-triage/pkg/models"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// Phase 4.30d — tcp.duplicate_ack_run evidence.
//
// The criteria live in models.TCPDupAckRun (Phase 4.30b, RFC 5681): a PURE ACK (no
// payload, no SYN/FIN/RST) repeating the previous pure ACK's acknowledgment number
// AND advertised window while the PEER has data outstanding. The peer's progress
// comes from the opposite direction's models.TCPSeqDir (Phase 4.30c feeds it); when
// the peer's sequence position is unknown (capture started late, one-sided capture,
// state reset or evicted) nothing qualifies. Idle keep-alive-style ACK repeats never
// qualify. Criteria were NOT loosened to match tshark, whose "duplicate ACK" count
// includes such idle patterns.
//
// One event is emitted per run that had at least one duplicate, when the run ends or
// at finalize. The event records OBSERVED repeated ACKs. It does not say a segment
// was lost, that a fast retransmit happened or why: the optional attribute
// consistent_with_fast_retransmit_trigger only says the duplicate count reached
// RFC 5681's threshold of three. SACK blocks are reported as observed support, never
// interpreted. Window values are compared raw (the scale factor is constant within
// a direction); a window update therefore ends a run, exactly as in RFC 5681.
//
// Events are deferred to Finalize (after tcp.syn_retransmission and
// tcp.sequence_gap) so existing event IDs and Finding evidence are unchanged; at
// most maxDupAckRunEvents are emitted per capture and at most maxActiveDupRuns runs
// are followed at once. Runs beyond either bound are counted, not emitted.
const (
	maxDupAckRunEvents = 10000
	maxActiveDupRuns   = 100000
	// dupAckThreshold is RFC 5681's duplicate-ACK count that triggers fast
	// retransmit in a sender; used only to label the run, never to assert an action.
	dupAckThreshold = 3
)

type activeDupRun struct {
	run          *models.TCPDupAckRun
	srcIP, dstIP string
	refs         bool
}

type dupAckRecord struct {
	flowKey, srcIP, dstIP string
	sum                   models.DupAckRunSummary
	endedBy               string
	refs                  bool
}

type dupAckRunTracker struct {
	active  map[string]*activeDupRun // runs with >=1 duplicate, by ACK-sender flow key
	records []dupAckRecord

	// Completeness accounting (Phase 4.31a). kindCapDropped: runs that had ended (or
	// were open at the end) but were not kept because maxDupAckRunEvents was reached;
	// capacityDropped: runs with at least one duplicate that could not be followed
	// because maxActiveDupRuns was reached (each is a known omitted event, though
	// further duplicates of that run are unknown); peerUnknown: pure ACKs that
	// repeated the previous pure ACK (same ack and window) while the peer's sequence
	// position was unknown, so duplicate status could not be decided (tracking limit).
	kindCapDropped  int
	capacityDropped int
	peerUnknown     int

	// Bounds (defaults: the constants above); fields so tests can use small values.
	maxEvents, maxActive int
}

func newDupAckRunTracker() *dupAckRunTracker {
	return &dupAckRunTracker{active: make(map[string]*activeDupRun), maxEvents: maxDupAckRunEvents, maxActive: maxActiveDupRuns}
}

func endedByName(r models.AckReason) string {
	switch r {
	case models.AckNotPure:
		return "non_pure_ack"
	case models.AckAckChanged:
		return "ack_changed"
	case models.AckWindowChanged:
		return "window_changed"
	case models.AckNoOutstandingData:
		return "no_outstanding_data"
	case models.AckPeerPositionUnknown:
		return "peer_position_unknown"
	}
	return "unknown"
}

// observe is called for every TCP packet. flowKey is the packet's own direction (the
// ACK sender); reverseKey is the peer (data sender) whose sequence progress decides
// whether data is outstanding.
func (d *dupAckRunTracker) observe(packet gopacket.Packet, tcp *layers.TCP, flowState *models.TCPFlowState, state *models.AnalysisState, flowKey, reverseKey, srcIP, dstIP string, ts time.Time, report *models.TriageReport) {
	pure := false
	if tcp.ACK && !tcp.SYN && !tcp.FIN && !tcp.RST {
		// A truncated capture can hide payload; use the declared length, and treat an
		// unknown length as "not pure" (conservative).
		if n, ok := segmentPayloadLen(packet, tcp); ok && n == 0 {
			pure = true
		}
	}

	var peerNext uint32
	peerValid := false
	if rev := state.PeekTCPFlow(reverseKey); rev != nil {
		peerNext, peerValid = rev.SequenceState().HighestNext()
	}
	ordinal, havePacket := currentPacket(report, ts)

	obs := models.AckObservation{
		Ack: tcp.Ack, Window: tcp.Window, PureAck: pure,
		PeerNext: peerNext, PeerNextValid: peerValid, At: ts, Packet: ordinal,
	}
	if pure {
		for _, o := range tcp.Options {
			if o.OptionType == layers.TCPOptionKindSACK {
				obs.Sack = models.ParseSACKEdges(o.OptionData)
				break
			}
		}
	}

	run := flowState.DupAckState()
	res := run.Observe(obs)
	if pure && res.Reason == models.AckPeerPositionUnknown {
		d.peerUnknown++
	}
	if res.Ended {
		d.finish(flowKey, srcIP, dstIP, res.EndedRun, endedByName(res.Reason), havePacket)
		if a, ok := d.active[flowKey]; ok && a.run == run {
			delete(d.active, flowKey)
		}
	}
	if res.IsDuplicate && res.Dups == 1 {
		if old, ok := d.active[flowKey]; ok && old.run != run {
			// The flow's state was evicted and recreated while a run was open.
			if cur, has := old.run.Current(); has {
				d.finish(flowKey, old.srcIP, old.dstIP, cur, "state_lost", old.refs)
			}
			delete(d.active, flowKey)
		}
		if _, ok := d.active[flowKey]; !ok {
			if len(d.active) >= d.maxActive {
				d.capacityDropped++
			} else {
				d.active[flowKey] = &activeDupRun{run: run, srcIP: srcIP, dstIP: dstIP, refs: havePacket}
			}
		}
	}
}

func (d *dupAckRunTracker) finish(flowKey, srcIP, dstIP string, sum models.DupAckRunSummary, endedBy string, refs bool) {
	if len(d.records) >= d.maxEvents {
		d.kindCapDropped++
		return
	}
	d.records = append(d.records, dupAckRecord{flowKey: flowKey, srcIP: srcIP, dstIP: dstIP, sum: sum, endedBy: endedBy, refs: refs})
}

// flush emits the runs (ended ones and those still open at the end of the capture)
// in a deterministic order: run start time, then flow key, then acknowledgment number.
func (d *dupAckRunTracker) flush(report *models.TriageReport) {
	keys := make([]string, 0, len(d.active))
	for k := range d.active {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		a := d.active[k]
		if cur, ok := a.run.Current(); ok {
			d.finish(k, a.srcIP, a.dstIP, cur, "capture_end", a.refs)
		}
	}
	sort.SliceStable(d.records, func(i, j int) bool {
		a, b := d.records[i], d.records[j]
		if !a.sum.FirstAt.Equal(b.sum.FirstAt) {
			return a.sum.FirstAt.Before(b.sum.FirstAt)
		}
		if a.flowKey != b.flowKey {
			return a.flowKey < b.flowKey
		}
		return a.sum.Ack < b.sum.Ack
	})
	for _, r := range d.records {
		s := r.sum
		vals := map[string]float64{
			"ack":         float64(s.Ack),
			"window":      float64(s.Window),
			"dup_count":   float64(s.Dups),
			"duration_ms": s.LastAt.Sub(s.FirstAt).Seconds() * 1000,
			"first_ts_us": float64(s.FirstAt.UnixMicro()),
			"last_ts_us":  float64(s.LastAt.UnixMicro()),
			"sack_acks":   float64(s.SackSeen),
		}
		attrs := map[string]string{"ended_by": r.endedBy, "sack": "none", "src_ip": r.srcIP, "dst_ip": r.dstIP}
		if s.SackSeen > 0 {
			attrs["sack"] = "observed"
			// Edges of the most recent duplicate that carried SACK (bounded to MaxSackEdges).
			for i, e := range s.SackEdges {
				vals["sack"+string(rune('0'+i))+"_left"] = float64(e[0])
				vals["sack"+string(rune('0'+i))+"_right"] = float64(e[1])
			}
		}
		if s.Dups >= dupAckThreshold {
			attrs["consistent_with_fast_retransmit_trigger"] = "true"
		}
		e := events.Event{
			Kind:      events.TCPDuplicateACKRun,
			Timestamp: s.FirstAt,
			FlowKey:   r.flowKey,
			Values:    vals,
			Attrs:     attrs,
			Source:    "TCP",
		}
		if r.refs {
			e.Packets = []events.PacketRef{
				{Index: s.FirstPacket, Timestamp: s.FirstAt},
				{Index: s.LastPacket, Timestamp: s.LastAt},
			}
		}
		report.Emit(e)
	}
	d.records, d.active = nil, make(map[string]*activeDupRun)
}
