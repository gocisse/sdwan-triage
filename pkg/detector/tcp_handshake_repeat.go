package detector

import (
	"time"

	"github.com/gocisse/sdwan-triage/pkg/events"
	"github.com/gocisse/sdwan-triage/pkg/models"
	"github.com/google/gopacket/layers"
)

// Phase 4.29c — repeated SYN / SYN-ACK evidence.
//
// This tracker records OBSERVED repeated handshake packets as
// events.TCPSYNRetransmission. It deliberately shares nothing with the data
// retransmission rule (models.ClassifyTCPSegment), the handshake tracker, or any
// report slice: it keeps its own bounded state and only calls report.Emit, so
// tcp.retransmission events, TCPRetransmissions, packet-loss metrics, SYN lists,
// health, risk and findings are unaffected.
//
// Definitions (sequence values are compared for EQUALITY only, so 32-bit
// wrap-around cannot change a decision):
//
//   - SYN repeat: a SYN (ACK clear) whose initial sequence number equals that of an
//     earlier SYN still pending on the same directional flow. A different ISN on
//     the same 4-tuple is a new attempt (tuple reuse): the state is replaced and
//     nothing is emitted.
//   - SYN-ACK repeat: a SYN-ACK whose (seq, ack) pair equals that of an earlier
//     SYN-ACK still pending on the same directional flow.
//
// Pending state is cleared by RST or FIN on either direction of the 4-tuple, and
// (SYN state only) by any other ACK-bearing packet from the SYN sender, i.e. the
// handshake progressed. It is intentionally NOT cleared by the peer's SYN-ACK: a
// SYN repeated after a SYN-ACK was seen (for example because the SYN-ACK was
// delayed) is still an observed repeat.
//
// Limits: a repeat whose first copy precedes the capture is invisible; identical
// packets duplicated by a mirror/tap cannot be told apart by sequence alone
// (since_previous_ms is recorded so a reader can judge); a repeat is evidence of
// repeated packets, not of loss or of where it occurred.
const (
	// maxHandshakeRepeatKeys bounds each pending-state map (same convention as
	// maxPendingHandshakes). When full, new keys are not tracked.
	maxHandshakeRepeatKeys = 100000
	// maxSYNRetransmissionEvents bounds emitted events per capture so the shared
	// event index (100k) cannot be exhausted by a SYN storm. Repeats beyond the cap
	// still advance state but are not emitted.
	maxSYNRetransmissionEvents = 10000
)

type synRepeatState struct {
	isn         uint32
	attempts    int
	first, prev time.Time
}

type synAckRepeatState struct {
	seq, ack    uint32
	attempts    int
	first, prev time.Time
}

type handshakeRepeatTracker struct {
	syn     map[string]*synRepeatState    // key: directional flow of the SYN sender
	synAck  map[string]*synAckRepeatState // key: directional flow of the SYN-ACK sender
	emitted int

	// pending holds the events until Flush: they are emitted AFTER every other
	// event so that existing events keep their dense IDs (Finding evidence
	// references event IDs, which must not shift because of this additive kind).
	pending []events.Event

	// Completeness accounting (Phase 4.31a). capDropped: repeats that WERE detected
	// but not emitted because maxSYNRetransmissionEvents was reached (a known
	// omitted-event count). untracked: first-seen SYN/SYN-ACK keys that could not be
	// tracked because the key bound was reached; how many repeats they would have
	// produced is unknown (a tracking limit, not an event count).
	capDropped int
	untracked  int

	// Bounds (defaults: the constants above); fields so tests can use small values.
	maxKeys, maxEvents int
}

func newHandshakeRepeatTracker() *handshakeRepeatTracker {
	return &handshakeRepeatTracker{
		syn:       make(map[string]*synRepeatState),
		synAck:    make(map[string]*synAckRepeatState),
		maxKeys:   maxHandshakeRepeatKeys,
		maxEvents: maxSYNRetransmissionEvents,
	}
}

// observe updates the pending state for one TCP packet and emits an event when the
// packet is a repeat. flowKey/reverseFlowKey use the TCPAnalyzer convention
// "srcIP:port->dstIP:port".
func (h *handshakeRepeatTracker) observe(tcp *layers.TCP, flowKey, reverseFlowKey, srcIP, dstIP string, ts time.Time, report *models.TriageReport) {
	if tcp.RST || tcp.FIN {
		// The connection (or attempt) ended: a later SYN on this tuple is a new one.
		delete(h.syn, flowKey)
		delete(h.syn, reverseFlowKey)
		delete(h.synAck, flowKey)
		delete(h.synAck, reverseFlowKey)
		return
	}

	switch {
	case tcp.SYN && !tcp.ACK:
		if st, ok := h.syn[flowKey]; ok && st.isn == tcp.Seq {
			st.attempts++
			h.emit(report, ts, flowKey, srcIP, dstIP, "SYN", tcp.Seq, 0, st.attempts, st.first, st.prev)
			st.prev = ts
		} else if ok || len(h.syn) < h.maxKeys {
			// New attempt (or tuple reuse with a different ISN): replace the state.
			h.syn[flowKey] = &synRepeatState{isn: tcp.Seq, attempts: 1, first: ts, prev: ts}
		} else {
			h.untracked++
		}
		// A new SYN invalidates a pending SYN-ACK that answered a different attempt.
		if sa, ok := h.synAck[reverseFlowKey]; ok && sa.ack != tcp.Seq+1 {
			delete(h.synAck, reverseFlowKey)
		}
	case tcp.SYN && tcp.ACK:
		if st, ok := h.synAck[flowKey]; ok && st.seq == tcp.Seq && st.ack == tcp.Ack {
			st.attempts++
			h.emit(report, ts, flowKey, srcIP, dstIP, "SYN-ACK", tcp.Seq, tcp.Ack, st.attempts, st.first, st.prev)
			st.prev = ts
		} else if ok || len(h.synAck) < h.maxKeys {
			h.synAck[flowKey] = &synAckRepeatState{seq: tcp.Seq, ack: tcp.Ack, attempts: 1, first: ts, prev: ts}
		} else {
			h.untracked++
		}
	case tcp.ACK:
		// The SYN sender sent an ACK-bearing non-SYN packet: its handshake progressed.
		if len(h.syn) > 0 {
			delete(h.syn, flowKey)
		}
	}
}

func (h *handshakeRepeatTracker) emit(report *models.TriageReport, ts time.Time, flowKey, srcIP, dstIP, segment string, seq, ack uint32, attempt int, first, prev time.Time) {
	if h.emitted >= h.maxEvents {
		h.capDropped++
		return
	}
	h.emitted++
	e := events.Event{
		Kind:      events.TCPSYNRetransmission,
		Timestamp: ts,
		FlowKey:   flowKey,
		Values: map[string]float64{
			"seq":               float64(seq),
			"ack":               float64(ack),
			"attempt":           float64(attempt),
			"since_first_ms":    ts.Sub(first).Seconds() * 1000,
			"since_previous_ms": ts.Sub(prev).Seconds() * 1000,
			"first_ts_us":       float64(first.UnixMicro()),
		},
		Attrs:  map[string]string{"segment": segment, "src_ip": srcIP, "dst_ip": dstIP},
		Source: "TCP",
	}
	// Capture the packet reference now; the event itself is emitted at Flush.
	if cp, ok := report.Emitter.(interface {
		CurrentPacket() (uint64, time.Time, bool)
	}); ok {
		if idx, pts, have := cp.CurrentPacket(); have && pts.Equal(ts) {
			e.Packets = []events.PacketRef{{Index: idx, Timestamp: pts}}
		}
	}
	h.pending = append(h.pending, e)
}

// flush emits the collected events (capture-ordered) and clears them. It must be
// called after every other event emitter has run.
func (h *handshakeRepeatTracker) flush(report *models.TriageReport) {
	for _, e := range h.pending {
		report.Emit(e)
	}
	h.pending = nil
}
