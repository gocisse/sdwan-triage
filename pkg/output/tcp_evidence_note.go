package output

import (
	"fmt"
	"sort"
	"strings"

	"github.com/gocisse/sdwan-triage/pkg/models"
)

// tcpEvidenceCompletenessNote returns one short, neutral line when TCP evidence
// collection was limited (Phase 4.31a), or "" when nothing was limited. The line
// never says anything about the network; it only says the evidence set may be
// incomplete. "" must not be read as "complete".
func tcpEvidenceCompletenessNote(r *models.TriageReport) string {
	c := r.TCPEvidenceCompleteness
	if !c.Affected() {
		return ""
	}
	var parts []string
	if n := c.KnownOmittedTotal(); n > 0 {
		kinds := make([]string, 0, len(c.KnownOmittedEvents))
		for k := range c.KnownOmittedEvents {
			kinds = append(kinds, k)
		}
		sort.Strings(kinds)
		var detail []string
		for _, k := range kinds {
			o := c.KnownOmittedEvents[k]
			detail = append(detail, fmt.Sprintf("%s %d", strings.TrimPrefix(k, "tcp."), o.IndexFull+o.KindCap+o.TrackerCapacity))
		}
		parts = append(parts, fmt.Sprintf("%d events omitted (%s)", n, strings.Join(detail, ", ")))
	}
	if n := c.TrackingLimitsTotal(); n > 0 {
		l := c.TrackingLimits
		var detail []string
		for _, x := range []struct {
			name string
			n    int
		}{
			{"duplicate_ack_repeats_peer_position_unknown", l.DuplicateACKRepeatsPeerPositionUnknown},
			{"handshake_repeat_keys_untracked", l.HandshakeRepeatKeysUntracked},
			{"sequence_gaps_expired", l.SequenceGapsExpired},
			{"sequence_gaps_not_followed", l.SequenceGapsNotFollowed},
			{"sequence_length_unreadable_resets", l.SequenceLengthUnreadableResets},
			{"sequence_state_lost_flows", l.SequenceStateLostFlows},
		} {
			if x.n > 0 {
				detail = append(detail, fmt.Sprintf("%s %d", x.name, x.n))
			}
		}
		parts = append(parts, "tracking limits ("+strings.Join(detail, ", ")+")")
	}
	return "TCP evidence may be incomplete: " + strings.Join(parts, "; ") + " - see tcp_evidence_completeness (JSON)"
}
