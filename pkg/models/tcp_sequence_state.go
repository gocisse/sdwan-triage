package models

import (
	"math"
	"time"
)

// Phase 4.30b — shared, bounded TCP sequence state (FOUNDATION ONLY).
//
// Nothing in the analysis pipeline calls this code yet: it emits no events and
// changes no output. It exists so that later phases can add sequence-gap,
// gap-fill and duplicate-ACK evidence on ONE well-tested state model instead of
// another private copy of the arithmetic.
//
// What it records are OBSERVED sequence positions. Whether an open gap means
// "lost", "reordered" or "not captured" is NOT decided here: a gap is only the
// range [Start, End) that a later segment started beyond, and a fill is only a
// later segment that covered part of it. Interpretation belongs to the evidence
// layer, which also has the peer's ACK/SACK state.
//
// Sequence arithmetic. TCP sequence numbers are 32-bit modular values. All
// comparisons use int32(a-b), which orders correctly while the two values are
// less than 2^31 apart; every value held here is kept within that window of the
// direction's highest-next position (see SeqGapExpiry), so the ordering is
// unambiguous across the 2^32 wrap. A distance of exactly 2^31 is treated as
// "behind" (never "ahead"). Sequence space consumed by a segment is
// payload + 1 for SYN + 1 for FIN (SeqConsumed).
//
// Boundedness: at most MaxOpenSeqGaps gaps per direction, MaxSackEdges SACK
// edges per duplicate-ACK run, and counters that saturate. When a limit is hit
// the observation is NOT dropped silently: it is reported in the result and
// counted (GapsNotTracked / GapsExpired), and must never be read as loss.
const (
	// MaxOpenSeqGaps bounds the unresolved gaps tracked per direction.
	MaxOpenSeqGaps = 16
	// SeqGapExpiry: when the highest-next position advances 2^30 bytes (1 GiB)
	// past a gap's start, the gap is expired (no longer tracked). It keeps every
	// stored value within 2^31 of the highest-next position so modular ordering
	// stays unambiguous.
	SeqGapExpiry = uint32(1) << 30
	// MaxSackEdges is the RFC 2018 maximum number of SACK blocks in one segment.
	MaxSackEdges = 4
)

// SeqConsumed returns the sequence space a segment consumes: payload bytes plus
// one for SYN and one for FIN.
func SeqConsumed(payloadLen int, syn, fin bool) uint32 {
	n := uint32(0)
	if payloadLen > 0 {
		n = uint32(payloadLen)
	}
	if syn {
		n++
	}
	if fin {
		n++
	}
	return n
}

func seqLT(a, b uint32) bool { return int32(a-b) < 0 }
func seqLE(a, b uint32) bool { return int32(a-b) <= 0 }

// SeqClass describes how an observed segment relates to the direction's state.
type SeqClass int

const (
	// SeqNoSequenceSpace: the packet consumes no sequence space (a pure ACK). Only
	// its sequence position is noted (SeqObservation.Ahead); state is unchanged and
	// no gap is ever opened by it.
	SeqNoSequenceSpace SeqClass = iota
	// SeqBaseline: the first sequence-consuming segment seen in this direction (or
	// the first after a restart). It sets the baseline; no gap is inferred before it.
	SeqBaseline
	// SeqInOrder: starts exactly at the highest next sequence number.
	SeqInOrder
	// SeqForwardGap: starts beyond the highest next number; the skipped range was
	// opened as a gap (unless the per-direction cap was reached).
	SeqForwardGap
	// SeqFillsGap: starts behind the highest next number and covers part or all of
	// at least one open gap.
	SeqFillsGap
	// SeqRepeat: lies entirely within already-covered space and fills no open gap
	// (a repeat/duplicate of data already seen, or a re-cover of a closed range).
	SeqRepeat
	// SeqPartialOverlap: starts behind the highest next number, fills no open gap,
	// and extends beyond it (some bytes new, some already seen).
	SeqPartialOverlap
)

// SeqGap is an observed hole: [Start, End) was skipped when the segment at End
// was seen. ObservedAt/Packet are the capture time and ordinal (caller-supplied,
// 0 when unknown) of the segment that exposed it.
type SeqGap struct {
	Start, End uint32
	ObservedAt time.Time
	Packet     uint64
}

// Bytes returns the size of the gap.
func (g SeqGap) Bytes() uint32 { return g.End - g.Start }

// SeqObservation is the result of TCPSeqDir.ObserveSegment.
type SeqObservation struct {
	Class SeqClass
	// Ahead is, for SeqNoSequenceSpace, how far beyond the highest-next position
	// the packet's sequence number is (0 when not ahead or no baseline yet).
	Ahead uint32
	// GapOpened/Gap: a gap was opened and tracked by this segment.
	GapOpened bool
	Gap       SeqGap
	// GapNotTracked: a gap exists but the per-direction cap was reached, so it is
	// NOT tracked (counted in TCPSeqDir.GapsNotTracked). Not evidence of loss.
	GapNotTracked bool
	// Filled lists the gaps this segment closed completely (copies, with their
	// original observation time/packet). FilledBytes counts all covered gap bytes,
	// including partial fills.
	Filled      []SeqGap
	FilledBytes uint32
	// ExtendsHighest: the segment advanced the highest-next position.
	ExtendsHighest bool
	// Restarted: a SYN with a different initial sequence number (or a SYN after a
	// midstream baseline) reset this direction before the observation (tuple reuse).
	Restarted bool
	// Expired: gaps dropped because the position advanced past SeqGapExpiry, and
	// ExpiredGaps their ranges (copies, with original time/packet). Expiry is a
	// tracking limit, not evidence about the data.
	Expired     int
	ExpiredGaps []SeqGap
}

// TCPSeqDir is the sequence state of ONE direction of a TCP connection. It is
// not safe for concurrent use (the analysis pipeline is single-threaded).
type TCPSeqDir struct {
	baseline    bool
	highestNext uint32
	synSeen     bool
	isn         uint32
	finSeen     bool
	gaps        []SeqGap

	// GapsNotTracked counts gaps that could not be tracked because
	// MaxOpenSeqGaps was reached (saturating). GapsExpired counts gaps dropped by
	// SeqGapExpiry (saturating). Neither is evidence of loss.
	GapsNotTracked uint32
	GapsExpired    uint32
}

// HighestNext returns the highest sequence number expected next in this
// direction and whether a baseline exists.
func (d *TCPSeqDir) HighestNext() (uint32, bool) { return d.highestNext, d.baseline }

// SYNSeen reports whether a SYN has been observed in this direction (false for a
// connection first seen midstream).
func (d *TCPSeqDir) SYNSeen() bool { return d.synSeen }

// FinSeen reports whether a FIN has been observed in this direction.
func (d *TCPSeqDir) FinSeen() bool { return d.finSeen }

// OpenGaps returns a copy of the unresolved gaps in ascending sequence order.
func (d *TCPSeqDir) OpenGaps() []SeqGap {
	out := make([]SeqGap, len(d.gaps))
	copy(out, d.gaps)
	return out
}

// Reset clears all state (RST, or a restarted connection). The caller should
// snapshot OpenGaps first if it wants to report gaps that were still open.
func (d *TCPSeqDir) Reset() {
	d.baseline, d.highestNext = false, 0
	d.synSeen, d.isn, d.finSeen = false, 0, false
	d.gaps = nil
}

func satInc(v *uint32, n int) {
	if n <= 0 {
		return
	}
	if uint64(*v)+uint64(n) > math.MaxUint32 {
		*v = math.MaxUint32
		return
	}
	*v += uint32(n)
}

// ObserveSegment records one packet of this direction. consumed is the sequence
// space it uses (SeqConsumed); syn/fin mark the flags. at and packet identify the
// observation for later evidence (packet may be 0 when unknown).
//
// A SYN whose initial sequence number differs from the one already seen, or a
// SYN arriving after a midstream baseline, starts a new connection: the state is
// reset first (Restarted). A repeated SYN with the same number is an ordinary
// repeat. A pure ACK (consumed == 0) never changes state or opens a gap.
func (d *TCPSeqDir) ObserveSegment(seq, consumed uint32, syn, fin bool, at time.Time, packet uint64) SeqObservation {
	var res SeqObservation
	if syn {
		if d.baseline && !(d.synSeen && d.isn == seq) {
			d.Reset()
			res.Restarted = true
		}
		d.synSeen, d.isn = true, seq
	}
	if fin {
		d.finSeen = true
	}

	if consumed == 0 {
		res.Class = SeqNoSequenceSpace
		if d.baseline {
			if dist := seq - d.highestNext; dist != 0 && dist < 1<<31 {
				res.Ahead = dist
			}
		}
		return res
	}

	end := seq + consumed
	if !d.baseline {
		d.baseline, d.highestNext = true, end
		res.Class = SeqBaseline
		return res
	}

	dist := seq - d.highestNext
	switch {
	case dist == 0:
		res.Class = SeqInOrder
		d.highestNext = end
		res.ExtendsHighest = true
	case dist < 1<<31:
		res.Class = SeqForwardGap
		g := SeqGap{Start: d.highestNext, End: seq, ObservedAt: at, Packet: packet}
		if len(d.gaps) >= MaxOpenSeqGaps {
			res.GapNotTracked = true
			satInc(&d.GapsNotTracked, 1)
		} else {
			d.gaps = append(d.gaps, g)
			res.GapOpened, res.Gap = true, g
		}
		d.highestNext = end
		res.ExtendsHighest = true
	default: // behind the highest next number (a distance of exactly 2^31 lands here)
		filled := d.cover(seq, end, &res)
		switch {
		case filled:
			res.Class = SeqFillsGap
		case seqLE(end, d.highestNext):
			res.Class = SeqRepeat
		default:
			res.Class = SeqPartialOverlap
		}
		if seqLT(d.highestNext, end) {
			d.highestNext = end
			res.ExtendsHighest = true
		}
	}

	if res.ExtendsHighest {
		d.expire(&res)
	}
	return res
}

// cover removes [seq, end) from the open gaps, splitting or shrinking them, and
// reports whether any gap bytes were covered.
func (d *TCPSeqDir) cover(seq, end uint32, res *SeqObservation) bool {
	if len(d.gaps) == 0 {
		return false
	}
	kept := make([]SeqGap, 0, len(d.gaps)+1)
	any := false
	for i, g := range d.gaps {
		if seqLE(g.End, seq) || seqLE(end, g.Start) { // no intersection
			kept = append(kept, g)
			continue
		}
		any = true
		lo, hi := g.Start, g.End
		if seqLT(lo, seq) {
			lo = seq
		}
		if seqLT(end, hi) {
			hi = end
		}
		res.FilledBytes += hi - lo
		hasLeft, hasRight := seqLT(g.Start, seq), seqLT(end, g.End)
		if !hasLeft && !hasRight {
			res.Filled = append(res.Filled, g)
			continue
		}
		// A remainder replaces the gap one-for-one; only a SPLIT (two remainders)
		// needs an extra slot. The untouched gaps after this one keep their slots,
		// so the total never exceeds MaxOpenSeqGaps; a piece that does not fit is
		// counted in GapsNotTracked rather than dropped silently.
		remaining := len(d.gaps) - i - 1
		if hasLeft {
			p := g
			p.End = seq
			kept = append(kept, p)
		}
		if hasRight {
			p := g
			p.Start = end
			if !hasLeft || len(kept)+remaining < MaxOpenSeqGaps {
				kept = append(kept, p)
			} else {
				satInc(&d.GapsNotTracked, 1)
			}
		}
	}
	d.gaps = kept
	return any
}

// expire drops gaps whose start is SeqGapExpiry or more behind the highest-next
// position.
func (d *TCPSeqDir) expire(res *SeqObservation) {
	if len(d.gaps) == 0 {
		return
	}
	kept := d.gaps[:0]
	for _, g := range d.gaps {
		if d.highestNext-g.Start >= SeqGapExpiry {
			res.Expired++
			res.ExpiredGaps = append(res.ExpiredGaps, g)
			satInc(&d.GapsExpired, 1)
			continue
		}
		kept = append(kept, g)
	}
	d.gaps = kept
}

// ─── Duplicate-ACK run state ──────────────────────────────────────────────

// ParseSACKEdges decodes the data of a TCP SACK option (pairs of 32-bit left and
// right edges) into at most MaxSackEdges blocks. Malformed trailing bytes are
// ignored. It performs no interpretation; wiring it to decoded packets is a later
// phase.
func ParseSACKEdges(optionData []byte) [][2]uint32 {
	n := len(optionData) / 8
	if n > MaxSackEdges {
		n = MaxSackEdges
	}
	out := make([][2]uint32, 0, n)
	for i := 0; i < n; i++ {
		b := optionData[i*8 : i*8+8]
		out = append(out, [2]uint32{
			uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3]),
			uint32(b[4])<<24 | uint32(b[5])<<16 | uint32(b[6])<<8 | uint32(b[7]),
		})
	}
	return out
}

// AckObservation is one ACK-bearing packet of the ACK sender's direction.
type AckObservation struct {
	// Ack and Window are the raw header values (the window scale factor is
	// constant within a direction, so raw equality is window equality).
	Ack    uint32
	Window uint16
	// PureAck: ACK flag set, no payload, no SYN/FIN/RST. Anything else is not a
	// duplicate-ACK candidate and ends the current run.
	PureAck bool
	// PeerNext/PeerNextValid: the highest next sequence number the PEER (data
	// sender) has used, i.e. the other direction's TCPSeqDir.HighestNext().
	PeerNext      uint32
	PeerNextValid bool
	At            time.Time
	Packet        uint64
	// Sack: decoded SACK edges, if any (see ParseSACKEdges); at most MaxSackEdges
	// are kept.
	Sack [][2]uint32
}

// DupAckRunSummary describes a run of duplicate ACKs.
type DupAckRunSummary struct {
	Ack         uint32
	Window      uint16
	Dups        uint32 // duplicates after the first ACK of the run
	FirstAt     time.Time
	LastAt      time.Time
	FirstPacket uint64
	LastPacket  uint64
	// SackEdges are the edges of the most recent duplicate that carried SACK (at
	// most MaxSackEdges); SackSeen counts duplicates that carried SACK (saturating).
	SackEdges [][2]uint32
	SackSeen  uint32
}

// AckReason says why an observation did not extend a run.
type AckReason int

const (
	AckNone AckReason = iota
	// AckNotPure: the packet carried payload or SYN/FIN/RST (or lacked ACK).
	AckNotPure
	// AckAckChanged: the acknowledgment number differs from the run's.
	AckAckChanged
	// AckWindowChanged: same acknowledgment number, different advertised window.
	AckWindowChanged
	// AckNoOutstandingData: same ack and window, but the peer had no unacknowledged
	// data (idle keep-alive style ACKs); it is not a duplicate ACK.
	AckNoOutstandingData
	// AckPeerPositionUnknown: same ack and window, but the peer's sequence position
	// is unknown (capture began late, one-sided capture, state reset or evicted), so
	// it cannot be told whether data was outstanding. Not counted as a duplicate;
	// reported separately so the blind spot is visible.
	AckPeerPositionUnknown
)

// AckResult is the result of TCPDupAckRun.Observe.
type AckResult struct {
	// IsDuplicate: this packet was counted as a duplicate ACK; Dups is the run's
	// count so far.
	IsDuplicate bool
	Dups        uint32
	Reason      AckReason
	// Ended/EndedRun: a run with at least one duplicate was ended by this packet.
	Ended    bool
	EndedRun DupAckRunSummary
}

// TCPDupAckRun tracks the current duplicate-ACK run of ONE direction (the ACK
// sender). It follows RFC 5681's duplicate-ACK conditions: a pure ACK repeating
// the previous pure ACK's acknowledgment number AND advertised window while the
// peer has unacknowledged data outstanding. State is O(1): one run, at most
// MaxSackEdges edges.
type TCPDupAckRun struct {
	has bool
	cur DupAckRunSummary
}

// Current returns the run in progress if it has at least one duplicate (for
// flushing at the end of the capture).
func (r *TCPDupAckRun) Current() (DupAckRunSummary, bool) {
	if !r.has || r.cur.Dups == 0 {
		return DupAckRunSummary{}, false
	}
	return r.cur.clone(), true
}

// Reset clears the run state (flow eviction/RST).
func (r *TCPDupAckRun) Reset() { r.has, r.cur = false, DupAckRunSummary{} }

func (s DupAckRunSummary) clone() DupAckRunSummary {
	s.SackEdges = append([][2]uint32(nil), s.SackEdges...)
	return s
}

// Observe processes one ACK-bearing packet.
func (r *TCPDupAckRun) Observe(o AckObservation) AckResult {
	var res AckResult
	end := func(reason AckReason) {
		res.Reason = reason
		if r.has && r.cur.Dups > 0 {
			res.Ended, res.EndedRun = true, r.cur.clone()
		}
	}
	start := func() {
		r.has = true
		r.cur = DupAckRunSummary{Ack: o.Ack, Window: o.Window, FirstAt: o.At, LastAt: o.At, FirstPacket: o.Packet, LastPacket: o.Packet}
	}

	if !o.PureAck {
		end(AckNotPure)
		r.Reset()
		return res
	}
	if !r.has {
		start()
		return res
	}
	if o.Ack != r.cur.Ack {
		end(AckAckChanged)
		start()
		return res
	}
	if o.Window != r.cur.Window {
		end(AckWindowChanged)
		start()
		return res
	}
	// Same acknowledgment number and window: a duplicate only if the peer has data
	// outstanding (its next sequence number is beyond this ack).
	if !o.PeerNextValid {
		end(AckPeerPositionUnknown)
		start()
		return res
	}
	if !seqLT(o.Ack, o.PeerNext) {
		end(AckNoOutstandingData)
		start()
		return res
	}
	satInc(&r.cur.Dups, 1)
	r.cur.LastAt, r.cur.LastPacket = o.At, o.Packet
	if len(o.Sack) > 0 {
		n := len(o.Sack)
		if n > MaxSackEdges {
			n = MaxSackEdges
		}
		r.cur.SackEdges = append(r.cur.SackEdges[:0], o.Sack[:n]...)
		satInc(&r.cur.SackSeen, 1)
	}
	res.IsDuplicate, res.Dups = true, r.cur.Dups
	return res
}
