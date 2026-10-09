package detector

// TCPEvidenceStats is the completeness accounting of the three deferred TCP evidence
// trackers (Phase 4.31a). The Known* fields count events that WERE generated (a
// repeat, a gap or a duplicate-ACK run was actually observed) but were not kept
// or emitted because of a bound. The Limit* fields count conditions that
// interrupted or prevented evidence collection where the number of missed events is
// NOT known; they must never be read as event counts or as loss.
type TCPEvidenceStats struct {
	// Known omitted events (kind cap = the per-capture event cap of that kind).
	KnownSYNRepeatKindCap  int
	KnownGapKindCap        int
	KnownDupAckKindCap     int
	KnownDupAckTrackerFull int // runs with >=1 duplicate that could not be followed (active-run bound)

	// Tracking limits (unknown number of missed events).
	LimitHandshakeKeysUntracked    int // SYN/SYN-ACK keys not tracked (key bound): later repeats on them are unseen
	LimitSeqLengthUnreadable       int // segments of unreadable length that forced a direction re-baseline
	LimitSeqGapsNotFollowed        int // recorded gaps whose fills cannot be followed (per-direction cap)
	LimitSeqGapsExpired            int // recorded gaps dropped by the 2^30-byte expiry
	LimitSeqStateLostFlows         int // flows whose sequence state was found evicted while gaps were open
	LimitDupAckPeerPositionUnknown int // repeated pure ACKs whose duplicate status could not be decided
}

// EvidenceStats returns the accounting. Call it AFTER Finalize (the deferred events
// are counted against their caps when they are flushed).
func (t *TCPAnalyzer) EvidenceStats() TCPEvidenceStats {
	return TCPEvidenceStats{
		KnownSYNRepeatKindCap:          t.handshakeRepeats.capDropped,
		KnownGapKindCap:                t.seqGaps.dropped,
		KnownDupAckKindCap:             t.dupAcks.kindCapDropped,
		KnownDupAckTrackerFull:         t.dupAcks.capacityDropped,
		LimitHandshakeKeysUntracked:    t.handshakeRepeats.untracked,
		LimitSeqLengthUnreadable:       t.seqGaps.lengthResets,
		LimitSeqGapsNotFollowed:        t.seqGaps.notFollowed,
		LimitSeqGapsExpired:            t.seqGaps.expired,
		LimitSeqStateLostFlows:         t.seqGaps.stateLost,
		LimitDupAckPeerPositionUnknown: t.dupAcks.peerUnknown,
	}
}
