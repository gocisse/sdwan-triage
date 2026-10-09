package detector

import (
	"time"

	"github.com/gocisse/sdwan-triage/pkg/events"
	"github.com/gocisse/sdwan-triage/pkg/models"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// Phase 4.30c — tcp.sequence_gap evidence.
//
// The sequence arithmetic lives in models.TCPSeqDir (Phase 4.30b); this file only
// feeds it from the live TCP path and keeps one RECORD per observed gap so that the
// evidence survives the model's own bookkeeping (filled, expired, reset, evicted).
//
// What a gap is: the capture saw a sequence-consuming segment (payload, SYN or FIN)
// begin beyond the highest sequence position seen so far in that direction. It is
// NOT proof of loss, of a transmission that was never received, or of where
// anything was lost: it can equally be capture loss, asymmetric visibility, a
// capture that began mid-connection, or reordering. Pure ACKs (including
// keep-alives) never open a gap.
//
// Resolution (decided at finalize, from what the capture itself shows):
//   - "filled":        later observed segments covered the whole range;
//   - "acked_beyond":  the peer's ACK advanced to or past the end of the gap while
//     the range was not (fully) observed - evidence the receiver acknowledged data
//     the capture did not show, NOT proof of loss;
//   - "unresolved":    neither of the above by the end of the capture.
//
// A partial fill keeps the remaining range unresolved and reports filled_bytes /
// remaining_bytes. The optional "limitation" attribute names why tracking was cut
// short (rst, restart, state_lost = flow state evicted, expired, tracking_cap =
// the per-direction 16-gap cap); a limited record is never described as loss.
//
// Events are deferred to Finalize (like tcp.syn_retransmission) so existing events
// keep their IDs. At most maxSequenceGapEvents are emitted per capture.
const maxSequenceGapEvents = 10000

type gapRecord struct {
	flowKey, srcIP, dstIP string
	start, end            uint32
	observedAt            time.Time
	packet                uint64
	havePacket            bool
	baseline              string // "syn" or "midstream"

	total       uint32 // end-start
	remaining   uint32
	pieces      int
	untracked   bool // not stored in the model (cap): fills cannot be followed
	closed      bool // no further updates (filled, reset, restarted, evicted, expired)
	filled      bool
	filledAt    time.Time
	ackedBeyond bool
	ackedAt     time.Time
	limitation  string
}

type sequenceGapTracker struct {
	records []*gapRecord            // creation order (deterministic)
	open    map[string][]*gapRecord // by directional flow key, records still updatable
	dropped int                     // gaps observed but not recorded because the event cap was reached (known omitted events)

	// Tracking-limit counters (Phase 4.31a): conditions that interrupted or limited
	// evidence collection where the number of missed events is NOT known.
	lengthResets int // segments whose length was unreadable (truncated capture): the direction was re-baselined
	notFollowed  int // recorded gaps whose fills cannot be followed (per-direction cap)
	expired      int // recorded gaps dropped by the 2^30-byte expiry
	stateLost    int // flows whose sequence state was found evicted/recreated while gaps were open

	maxRecords int // bound on records/events (default maxSequenceGapEvents); a field for tests
}

func newSequenceGapTracker() *sequenceGapTracker {
	return &sequenceGapTracker{open: make(map[string][]*gapRecord), maxRecords: maxSequenceGapEvents}
}

// segmentPayloadLen returns the TCP payload length the sender actually used. When
// the capture was truncated (snap length), len(tcp.Payload) under-counts it, and
// feeding that to the sequence model would invent a gap at every following
// segment (observed on Lab 5: "Packet size limited during capture"). The length is
// therefore taken from the IP header when it is available; if the packet is
// truncated and the IP header cannot give it (IPv6 extension headers, IPv4
// fragments, zero IP length from offload), ok is false and the caller must not
// feed the segment.
func segmentPayloadLen(packet gopacket.Packet, tcp *layers.TCP) (n int, ok bool) {
	ci := packet.Metadata().CaptureInfo
	truncated := ci.CaptureLength < ci.Length
	thl := int(tcp.DataOffset) * 4
	// The IP header that carries THIS TCP segment is the last IP layer before the
	// TCP layer (tunnelled traffic has outer headers first).
	var ip4 *layers.IPv4
	var ip6 *layers.IPv6
	for _, l := range packet.Layers() {
		switch v := l.(type) {
		case *layers.IPv4:
			ip4, ip6 = v, nil
		case *layers.IPv6:
			ip4, ip6 = nil, v
		case *layers.TCP:
			if v == tcp {
				goto found
			}
		}
	}
found:
	if ip4 != nil {
		// gopacket rewrites a zero total length (TSO/offload) to the captured length,
		// which would under-count in a truncated capture, so read the header field.
		rawLen := int(ip4.Length)
		if len(ip4.Contents) >= 4 {
			rawLen = int(ip4.Contents[2])<<8 | int(ip4.Contents[3])
		}
		if rawLen > 0 && ip4.Flags&layers.IPv4MoreFragments == 0 && ip4.FragOffset == 0 {
			if d := rawLen - int(ip4.IHL)*4 - thl; d >= 0 {
				return d, true
			}
		}
	} else if ip6 != nil {
		if ip6.NextHeader == layers.IPProtocolTCP && ip6.Length > 0 {
			if d := int(ip6.Length) - thl; d >= 0 {
				return d, true
			}
		}
	}
	if !truncated {
		return len(tcp.Payload), true
	}
	return 0, false
}

// currentPacket returns the recorder ordinal of the packet being analysed when the
// emitter exposes it.
func currentPacket(report *models.TriageReport, ts time.Time) (uint64, bool) {
	if cp, ok := report.Emitter.(interface {
		CurrentPacket() (uint64, time.Time, bool)
	}); ok {
		if idx, pts, have := cp.CurrentPacket(); have && pts.Equal(ts) {
			return idx, true
		}
	}
	return 0, false
}

// observe is called for every TCP packet. flowState is the packet's own direction;
// state gives read-only (no LRU touch) access to the reverse direction for RST.
func (g *sequenceGapTracker) observe(packet gopacket.Packet, tcp *layers.TCP, flowState *models.TCPFlowState, state *models.AnalysisState, flowKey, reverseKey, srcIP, dstIP string, ts time.Time, report *models.TriageReport) {
	if tcp.RST {
		g.closeFlow(flowKey, "rst")
		g.closeFlow(reverseKey, "rst")
		flowState.SequenceState().Reset()
		if rev := state.PeekTCPFlow(reverseKey); rev != nil {
			rev.SequenceState().Reset()
		}
		return
	}

	// ACK evidence for the OPPOSITE direction's open gaps.
	if tcp.ACK && len(g.open) > 0 {
		for _, rec := range g.open[reverseKey] {
			if !rec.ackedBeyond && int32(tcp.Ack-rec.end) >= 0 {
				rec.ackedBeyond, rec.ackedAt = true, ts
			}
		}
	}

	payloadLen, lenOK := segmentPayloadLen(packet, tcp)
	if !lenOK {
		// Truncated capture and no reliable length: the sequence position after this
		// segment is unknown. Forget the direction (re-baseline on the next segment)
		// rather than invent a gap; any open gaps are left unresolved.
		g.lengthResets++
		g.closeFlow(flowKey, "length_unknown")
		flowState.SequenceState().Reset()
		return
	}
	consumed := models.SeqConsumed(payloadLen, tcp.SYN, tcp.FIN)
	if consumed == 0 {
		return // pure ACKs never create or change gap evidence
	}

	dir := flowState.SequenceState()
	prevNext, hadBaseline := dir.HighestNext()
	ordinal, havePacket := currentPacket(report, ts)
	res := dir.ObserveSegment(tcp.Seq, consumed, tcp.SYN, tcp.FIN, ts, ordinal)

	if res.Restarted {
		g.closeFlow(flowKey, "restart") // tuple reuse: earlier gaps belong to the old connection
	}
	if res.Class == models.SeqBaseline && len(g.open[flowKey]) > 0 {
		g.stateLost++
		g.closeFlow(flowKey, "state_lost") // fresh state for a flow that had open gaps: evicted
	}

	baseline := "midstream"
	if dir.SYNSeen() {
		baseline = "syn"
	}
	switch {
	case res.GapOpened:
		g.add(&gapRecord{flowKey: flowKey, srcIP: srcIP, dstIP: dstIP, start: res.Gap.Start, end: res.Gap.End,
			observedAt: ts, packet: ordinal, havePacket: havePacket, baseline: baseline,
			total: res.Gap.Bytes(), remaining: res.Gap.Bytes(), pieces: 1})
	case res.GapNotTracked && hadBaseline:
		g.add(&gapRecord{flowKey: flowKey, srcIP: srcIP, dstIP: dstIP, start: prevNext, end: tcp.Seq,
			observedAt: ts, packet: ordinal, havePacket: havePacket, baseline: baseline,
			total: tcp.Seq - prevNext, remaining: tcp.Seq - prevNext, pieces: 1,
			untracked: true, limitation: "tracking_cap"})
	}
	if res.FilledBytes > 0 || res.Expired > 0 {
		g.reconcile(flowKey, dir, res, ts)
	}
}

func (g *sequenceGapTracker) add(rec *gapRecord) {
	if len(g.records) >= g.maxRecords {
		g.dropped++
		return
	}
	g.records = append(g.records, rec)
	g.open[rec.flowKey] = append(g.open[rec.flowKey], rec)
	if rec.untracked {
		g.notFollowed++
	}
}

// closeFlow ends updating of every open record of the flow, naming why.
func (g *sequenceGapTracker) closeFlow(flowKey, why string) {
	for _, rec := range g.open[flowKey] {
		rec.closed = true
		if rec.limitation == "" {
			rec.limitation = why
		}
	}
	delete(g.open, flowKey)
}

// contains reports whether piece lies inside the record's original range.
func (r *gapRecord) contains(p models.SeqGap) bool {
	return p.ObservedAt.Equal(r.observedAt) && p.Packet == r.packet &&
		p.Start-r.start < r.total && p.End-r.start <= r.total
}

// reconcile updates the records of this flow from the model after fills/expiry.
func (g *sequenceGapTracker) reconcile(flowKey string, dir *models.TCPSeqDir, res models.SeqObservation, ts time.Time) {
	recs := g.open[flowKey]
	if len(recs) == 0 {
		return
	}
	pieces := dir.OpenGaps()
	keep := recs[:0]
	for _, rec := range recs {
		if rec.untracked {
			keep = append(keep, rec)
			continue
		}
		var rem uint32
		n := 0
		for _, p := range pieces {
			if rec.contains(p) {
				rem += p.Bytes()
				n++
			}
		}
		var expired uint32
		for _, e := range res.ExpiredGaps {
			if rec.contains(e) {
				expired += e.Bytes()
			}
		}
		rec.remaining, rec.pieces = rem, n
		switch {
		case expired > 0:
			rec.remaining += expired // the expired range is still unobserved
			rec.limitation, rec.closed = "expired", true
			g.expired++
		case rem == 0:
			rec.filled, rec.filledAt, rec.closed = true, ts, true
		}
		if !rec.closed {
			keep = append(keep, rec)
		}
	}
	if len(keep) == 0 {
		delete(g.open, flowKey)
	} else {
		g.open[flowKey] = keep
	}
}

func (r *gapRecord) resolution() string {
	switch {
	case r.filled:
		return "filled"
	case r.ackedBeyond:
		return "acked_beyond"
	default:
		return "unresolved"
	}
}

// flush emits one event per record, in creation order, and clears the tracker.
func (g *sequenceGapTracker) flush(report *models.TriageReport) {
	for _, r := range g.records {
		filledBytes := r.total - r.remaining
		vals := map[string]float64{
			"gap_start":       float64(r.start),
			"gap_end":         float64(r.end),
			"gap_bytes":       float64(r.total),
			"filled_bytes":    float64(filledBytes),
			"remaining_bytes": float64(r.remaining),
		}
		attrs := map[string]string{
			"resolution": r.resolution(),
			"baseline":   r.baseline,
			"src_ip":     r.srcIP,
			"dst_ip":     r.dstIP,
		}
		if r.limitation != "" {
			attrs["limitation"] = r.limitation
		}
		if r.filled {
			vals["filled_ts_us"] = float64(r.filledAt.UnixMicro())
			vals["fill_delay_ms"] = r.filledAt.Sub(r.observedAt).Seconds() * 1000
		}
		if r.ackedBeyond {
			vals["acked_ts_us"] = float64(r.ackedAt.UnixMicro())
		}
		e := events.Event{
			Kind:      events.TCPSequenceGap,
			Timestamp: r.observedAt,
			FlowKey:   r.flowKey,
			Values:    vals,
			Attrs:     attrs,
			Source:    "TCP",
		}
		if r.havePacket {
			e.Packets = []events.PacketRef{{Index: r.packet, Timestamp: r.observedAt}}
		}
		report.Emit(e)
	}
	g.records, g.open = nil, make(map[string][]*gapRecord)
}
