package analyzer

import (
	"github.com/gocisse/sdwan-triage/pkg/detector"
	"github.com/gocisse/sdwan-triage/pkg/events"
	"github.com/gocisse/sdwan-triage/pkg/models"
)

// buildTCPEvidenceCompleteness assembles the additive `tcp_evidence_completeness`
// object (Phase 4.31a). It must be called after TCPAnalyzer.Finalize, because the
// deferred evidence is emitted (and may be rejected by a full event index) there.
// It returns nil when no omission and no tracking limit occurred, so unaffected
// captures carry no new field and no warning.
func buildTCPEvidenceCompleteness(ix *events.Index, st detector.TCPEvidenceStats) *models.TCPEvidenceCompleteness {
	var dropped map[events.Kind]int
	if ix != nil {
		dropped = ix.DroppedByKind()
	}
	out := &models.TCPEvidenceCompleteness{Semantics: models.TCPEvidenceCompletenessSemantics}
	add := func(kind events.Kind, o models.EvidenceOmission) {
		o.IndexFull = dropped[kind]
		if o.IndexFull+o.KindCap+o.TrackerCapacity == 0 {
			return
		}
		if out.KnownOmittedEvents == nil {
			out.KnownOmittedEvents = make(map[string]models.EvidenceOmission)
		}
		out.KnownOmittedEvents[string(kind)] = o
	}
	add(events.TCPRetransmission, models.EvidenceOmission{})
	add(events.TCPSYNRetransmission, models.EvidenceOmission{KindCap: st.KnownSYNRepeatKindCap})
	add(events.TCPSequenceGap, models.EvidenceOmission{KindCap: st.KnownGapKindCap})
	add(events.TCPDuplicateACKRun, models.EvidenceOmission{KindCap: st.KnownDupAckKindCap, TrackerCapacity: st.KnownDupAckTrackerFull})

	lim := models.TCPTrackingLimits{
		SequenceLengthUnreadableResets:         st.LimitSeqLengthUnreadable,
		SequenceGapsNotFollowed:                st.LimitSeqGapsNotFollowed,
		SequenceGapsExpired:                    st.LimitSeqGapsExpired,
		SequenceStateLostFlows:                 st.LimitSeqStateLostFlows,
		HandshakeRepeatKeysUntracked:           st.LimitHandshakeKeysUntracked,
		DuplicateACKRepeatsPeerPositionUnknown: st.LimitDupAckPeerPositionUnknown,
	}
	if lim != (models.TCPTrackingLimits{}) {
		out.TrackingLimits = &lim
	}
	if !out.Affected() {
		return nil
	}
	return out
}
