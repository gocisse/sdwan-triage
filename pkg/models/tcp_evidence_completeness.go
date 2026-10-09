package models

import (
	"fmt"
	"sort"
	"strings"
)

// TCP evidence completeness (Phase 4.31a).
//
// A missing evidence event must never silently look like evidence that nothing
// happened. This object discloses the conditions, known to the engine, that caused
// TCP evidence to be omitted or collection to be limited. It keeps two different
// things apart:
//
//   - KnownOmittedEvents: events that WERE generated (the retransmission, repeated
//     SYN, sequence gap or duplicate-ACK run was actually observed) but could not be
//     stored or emitted. These are counts of real, lost events (at least; a bound that
//     stops tracking cannot say how many followed).
//   - TrackingLimits: conditions that interrupted, reset or prevented evidence
//     collection where the number of events that might have been missed is UNKNOWN.
//     They are counts of occurrences of the limiting condition, never event counts.
//
// What this does NOT cover (so zero/absent never proves completeness): captures that
// start mid-connection or see one direction only, packets never captured, retransmissions
// of sequence numbers already evicted from the 512-entry per-flow history, capture
// duplicates, segments whose length could be read but whose neighbours were lost, and
// any limit that the engine cannot observe about itself.

// EvidenceOmission counts events of one kind that were generated but not kept.
type EvidenceOmission struct {
	// IndexFull: rejected because the bounded event index (events_dropped) was full.
	IndexFull int `json:"index_full,omitempty"`
	// KindCap: not emitted because the per-capture cap for this kind (10,000) was reached.
	KindCap int `json:"kind_cap,omitempty"`
	// TrackerCapacity: observed but not followed because an active-state bound was reached.
	TrackerCapacity int `json:"tracker_capacity,omitempty"`
}

func (o EvidenceOmission) total() int { return o.IndexFull + o.KindCap + o.TrackerCapacity }

// TCPTrackingLimits counts occurrences of limiting conditions (number of missed events unknown).
type TCPTrackingLimits struct {
	// SequenceLengthUnreadableResets: segments in a truncated capture whose real length
	// could not be read; the direction was re-baselined, so gaps around it were not tracked.
	SequenceLengthUnreadableResets int `json:"sequence_length_unreadable_resets,omitempty"`
	// SequenceGapsNotFollowed: gap events recorded but whose later fills could not be
	// followed (the per-direction open-gap cap); their resolution is therefore limited.
	SequenceGapsNotFollowed int `json:"sequence_gaps_not_followed,omitempty"`
	// SequenceGapsExpired: gaps that stopped being tracked after the position advanced 2^30 bytes.
	SequenceGapsExpired int `json:"sequence_gaps_expired,omitempty"`
	// SequenceStateLostFlows: flows whose sequence state was evicted and recreated while gaps were open.
	SequenceStateLostFlows int `json:"sequence_state_lost_flows,omitempty"`
	// HandshakeRepeatKeysUntracked: SYN/SYN-ACK keys not tracked (key bound); repeats on them are unseen.
	HandshakeRepeatKeysUntracked int `json:"handshake_repeat_keys_untracked,omitempty"`
	// DuplicateACKRepeatsPeerPositionUnknown: pure ACKs repeating the previous ACK (same
	// ack and window) while the peer's sequence position was unknown; they may or may not
	// be duplicate ACKs.
	DuplicateACKRepeatsPeerPositionUnknown int `json:"duplicate_ack_repeats_peer_position_unknown,omitempty"`
}

func (l TCPTrackingLimits) total() int {
	return l.SequenceLengthUnreadableResets + l.SequenceGapsNotFollowed + l.SequenceGapsExpired +
		l.SequenceStateLostFlows + l.HandshakeRepeatKeysUntracked + l.DuplicateACKRepeatsPeerPositionUnknown
}

// TCPEvidenceCompleteness is the additive JSON object `tcp_evidence_completeness`.
type TCPEvidenceCompleteness struct {
	// KnownOmittedEvents is keyed by event kind ("tcp.retransmission", "tcp.syn_retransmission",
	// "tcp.sequence_gap", "tcp.duplicate_ack_run"); only kinds with an omission appear.
	KnownOmittedEvents map[string]EvidenceOmission `json:"known_omitted_events,omitempty"`
	// TrackingLimits is present only when at least one limit occurred.
	TrackingLimits *TCPTrackingLimits `json:"tracking_limits,omitempty"`
	// Semantics states how to read the object.
	Semantics string `json:"semantics"`
}

// TCPEvidenceCompletenessSemantics is the fixed explanation carried in the JSON.
const TCPEvidenceCompletenessSemantics = "known_omitted_events: events that were generated but not stored or emitted. " +
	"tracking_limits: occurrences of conditions that limited evidence collection; the number of missed events is unknown. " +
	"Absence of this object, or zero counts, does not prove the capture or the evidence is complete."

// KnownOmittedTotal returns the total number of known omitted events.
func (c *TCPEvidenceCompleteness) KnownOmittedTotal() int {
	if c == nil {
		return 0
	}
	n := 0
	for _, o := range c.KnownOmittedEvents {
		n += o.total()
	}
	return n
}

// TrackingLimitsTotal returns the total number of limiting-condition occurrences.
func (c *TCPEvidenceCompleteness) TrackingLimitsTotal() int {
	if c == nil || c.TrackingLimits == nil {
		return 0
	}
	return c.TrackingLimits.total()
}

// Affected reports whether any omission or limit was recorded.
func (c *TCPEvidenceCompleteness) Affected() bool {
	return c.KnownOmittedTotal() > 0 || c.TrackingLimitsTotal() > 0
}

// Details explains every non-zero counter in plain language, in a fixed order (known
// omissions by kind and reason, then tracking limits alphabetically). The JSON fields
// of the object itself are unchanged. An unknown missed-event count is never shown as zero.
func (c *TCPEvidenceCompleteness) Details() []CompletenessDetail {
	if c == nil {
		return nil
	}
	var out []CompletenessDetail
	kinds := make([]string, 0, len(c.KnownOmittedEvents))
	for k := range c.KnownOmittedEvents {
		kinds = append(kinds, k)
	}
	sort.Strings(kinds)
	for _, k := range kinds {
		o := c.KnownOmittedEvents[k]
		for _, r := range []struct {
			reason string
			n      int
			why    string
		}{
			{"index_full", o.IndexFull, "the bounded event index was full"},
			{"kind_cap", o.KindCap, "the per-capture limit for this kind of evidence was reached"},
			{"tracker_capacity", o.TrackerCapacity, "an active-tracking bound was reached"},
		} {
			if r.n > 0 {
				out = append(out, CompletenessDetail{
					Name: k + "/" + r.reason, Category: "omitted_events", Count: r.n,
					Meaning: fmt.Sprintf("%d %s event(s) were detected but not kept because %s.", r.n, strings.TrimPrefix(k, "tcp."), r.why),
				})
			}
		}
	}
	if l := c.TrackingLimits; l != nil {
		const unknown = " The number of events possibly missed is unknown."
		for _, x := range []struct {
			name string
			n    int
			text string
		}{
			{"duplicate_ack_repeats_peer_position_unknown", l.DuplicateACKRepeatsPeerPositionUnknown,
				"%d repeated ACK(s) could not be classified as duplicate ACKs because the peer's sequence position was not available."},
			{"handshake_repeat_keys_untracked", l.HandshakeRepeatKeysUntracked,
				"%d SYN/SYN-ACK packet(s) were not tracked because the handshake-tracking bound was reached, so repeats of them were not seen."},
			{"sequence_gaps_expired", l.SequenceGapsExpired,
				"%d recorded sequence gap(s) stopped being tracked after the sequence position advanced more than 2^30 bytes."},
			{"sequence_gaps_not_followed", l.SequenceGapsNotFollowed,
				"%d recorded sequence gap(s) could not be followed to a later fill because too many gaps were open on the direction; their resolution is limited."},
			{"sequence_length_unreadable_resets", l.SequenceLengthUnreadableResets,
				"%d segment(s) had an unreadable length (truncated capture), so sequence tracking for that direction restarted and gaps around them were not tracked."},
			{"sequence_state_lost_flows", l.SequenceStateLostFlows,
				"%d flow(s) lost their sequence state while gaps were open, so the resolution of those gaps is unknown."},
		} {
			if x.n > 0 {
				out = append(out, CompletenessDetail{Name: x.name, Category: "tracking_limit", Count: x.n, Meaning: fmt.Sprintf(x.text, x.n) + unknown})
			}
		}
	}
	return out
}
