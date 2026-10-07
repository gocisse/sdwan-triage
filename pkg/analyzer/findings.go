package analyzer

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/gocisse/sdwan-triage/pkg/events"
	"github.com/gocisse/sdwan-triage/pkg/models"
)

// Finding construction (Phase 4.5).
//
// BuildFindings ASSEMBLES conclusions from evidence that already exists: the
// typed Event index and the correlator's RootCauseChains. It is deliberately not
// a detector — it adds no packet inspection, state, windows or rates.

const (
	// maxEvidenceRefs bounds Finding.Evidence; EvidenceCount keeps the true total.
	maxEvidenceRefs = 20

	// minRetransmissionEvents is the aggregation rule for retransmission
	// Findings: a flow needs at least this many tcp.retransmission events in the
	// whole capture. It is intentionally independent of the correlator's
	// per-window constant; there is no windowing, rate or cause inference.
	minRetransmissionEvents = 3
)

// Finding kinds.
const (
	findingKindRetransmissions = "tcp.retransmissions"
	findingKindSameSession     = "underlay_overlay.same_session"
	findingKindCoOccurrence    = "underlay_overlay.co_occurrence"
)

// BuildFindings returns the report's Findings in deterministic order
// (FirstSeen, Kind, ID) with duplicate IDs removed.
func BuildFindings(report *models.TriageReport) []models.Finding {
	var out []models.Finding
	out = append(out, retransmissionFindings(report)...)
	for _, chain := range report.RootCauseChains {
		out = append(out, chainFinding(chain))
	}

	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if !a.FirstSeen.Equal(b.FirstSeen) {
			return a.FirstSeen.Before(b.FirstSeen)
		}
		if a.Kind != b.Kind {
			return a.Kind < b.Kind
		}
		return a.ID < b.ID
	})

	seen := make(map[string]bool, len(out))
	deduped := out[:0]
	for _, f := range out {
		if seen[f.ID] {
			continue
		}
		seen[f.ID] = true
		deduped = append(deduped, f)
	}
	if len(deduped) == 0 {
		return nil
	}
	return deduped
}

func findingID(kind string, keyParts ...string) string {
	sum := sha256.Sum256([]byte(kind + "\x00" + strings.Join(keyParts, "\x00")))
	return kind + ":" + hex.EncodeToString(sum[:])[:12]
}

func evidenceRef(e events.Event) models.EvidenceRef {
	ref := models.EvidenceRef{Kind: string(e.Kind), Timestamp: e.Timestamp.UTC(), FlowKey: e.FlowKey, EventID: e.ID}
	if len(e.Packets) > 0 {
		idx := e.Packets[0].Index
		ref.PacketIndex = &idx
	}
	return ref
}

// boundedEvidence returns the first maxEvidenceRefs refs in chronological order
// (ties broken by kind, flow, event ID) and the true total.
func boundedEvidence(evs []events.Event) ([]models.EvidenceRef, int) {
	// Drop repeats of the same event (by non-zero ID) so evidence is unique.
	sorted := make([]events.Event, 0, len(evs))
	seenIDs := make(map[uint64]bool, len(evs))
	for _, e := range evs {
		if e.ID != 0 {
			if seenIDs[e.ID] {
				continue
			}
			seenIDs[e.ID] = true
		}
		sorted = append(sorted, e)
	}
	sort.SliceStable(sorted, func(i, j int) bool {
		a, b := sorted[i], sorted[j]
		if !a.Timestamp.Equal(b.Timestamp) {
			return a.Timestamp.Before(b.Timestamp)
		}
		if a.Kind != b.Kind {
			return a.Kind < b.Kind
		}
		if a.FlowKey != b.FlowKey {
			return a.FlowKey < b.FlowKey
		}
		return a.ID < b.ID
	})
	n := len(sorted)
	if n > maxEvidenceRefs {
		sorted = sorted[:maxEvidenceRefs]
	}
	refs := make([]models.EvidenceRef, len(sorted))
	for i, e := range sorted {
		refs[i] = evidenceRef(e)
	}
	return refs, n
}

// ─── Source 2: tcp.retransmission events ─────────────────────────────

// retransmissionFindings applies the aggregation rule documented on
// minRetransmissionEvents: one Finding per flow with enough retransmission
// events. Counts come from Events (packets), not from len(TCPRetransmissions),
// which holds distinct flows.
func retransmissionFindings(report *models.TriageReport) []models.Finding {
	if report.Events == nil {
		return nil
	}
	byFlow := make(map[string][]events.Event)
	var order []string
	for _, e := range report.Events.ByKind(events.TCPRetransmission) {
		if _, ok := byFlow[e.FlowKey]; !ok {
			order = append(order, e.FlowKey)
		}
		byFlow[e.FlowKey] = append(byFlow[e.FlowKey], e)
	}

	var out []models.Finding
	for _, flow := range order {
		evs := byFlow[flow]
		if len(evs) < minRetransmissionEvents {
			continue
		}
		first, last := evs[0].Timestamp, evs[0].Timestamp
		for _, e := range evs {
			if e.Timestamp.Before(first) {
				first = e.Timestamp
			}
			if e.Timestamp.After(last) {
				last = e.Timestamp
			}
		}
		refs, total := boundedEvidence(evs)
		out = append(out, models.Finding{
			ID:         findingID(findingKindRetransmissions, flow),
			Kind:       findingKindRetransmissions,
			Title:      fmt.Sprintf("TCP retransmissions on %s", flow),
			Summary:    fmt.Sprintf("%d retransmitted segments observed on %s between %s and %s. The cause (loss, congestion, path change) is not determined.", total, flow, first.UTC().Format(findingTimeFmt), last.UTC().Format(findingTimeFmt)),
			Severity:   retransmissionSeverity(total),
			Confidence: retransmissionConfidence(total),
			Basis:      models.FindingBasisObserved,
			FirstSeen:  first.UTC(),
			LastSeen:   last.UTC(),
			Evidence:   refs, EvidenceCount: total,
		})
	}
	return out
}

const findingTimeFmt = "2006-01-02T15:04:05.000Z"

// retransmissionSeverity: impact if true. Provisional, per-source.
func retransmissionSeverity(n int) models.Severity {
	switch {
	case n >= 100:
		return models.SeverityHigh
	case n >= 10:
		return models.SeverityMedium
	default:
		return models.SeverityLow
	}
}

// retransmissionConfidence: strength of evidence. Repeated observations on one
// flow are stronger evidence that this is not a one-off artefact.
func retransmissionConfidence(n int) models.Confidence {
	if n >= 10 {
		return models.ConfidenceHigh
	}
	return models.ConfidenceMedium
}

// ─── Source 1: RootCauseChain ────────────────────────────────────────

// chainFinding produces exactly one Finding for a RootCauseChain. The chain
// itself is not modified.
func chainFinding(chain models.RootCauseChain) models.Finding {
	kind := findingKindCoOccurrence
	basis := models.EvidenceTimeProximity
	if chain.EvidenceBasis == models.EvidenceSameSession {
		kind = findingKindSameSession
		basis = models.EvidenceSameSession
	}

	// The chain's overlay label already says "(co-occurring)" for proximity chains;
	// the Finding's own wording carries that, so drop the suffix to avoid repeating it.
	overlay := strings.TrimSuffix(chain.OverlayEffect, " (co-occurring)")
	var summary string
	if basis == models.EvidenceSameSession {
		summary = fmt.Sprintf("%s observed on the BGP session's own TCP connection around %s.", overlay, chain.UnderlayEvent)
	} else {
		summary = fmt.Sprintf("%s and %s co-occurred within %.1fs; no shared session or flow identity was established, so no causal relationship is claimed.",
			chain.UnderlayEvent, overlay, chain.CorrelationGap)
	}

	// Evidence is exactly what the correlator recorded on the chain; nothing is
	// re-resolved or inferred. A chain without recorded evidence yields an empty
	// (non-nil) list and a zero count.
	ts := chainTime(chain)
	refs := append([]models.EvidenceRef{}, chain.Evidence...)
	total := chain.EvidenceCount
	if total < len(refs) {
		total = len(refs)
	}
	first, last := ts, ts
	for _, r := range refs {
		if r.Timestamp.After(last) {
			last = r.Timestamp
		}
	}

	return models.Finding{
		ID:         findingID(kind, chain.UnderlayEvent, chain.OverlayEffect, fmt.Sprintf("%.6f", chain.Timestamp), basis),
		Kind:       kind,
		Title:      fmt.Sprintf("%s / %s", chain.UnderlayEvent, overlay),
		Summary:    summary,
		Severity:   chainSeverity(chain, basis),
		Confidence: chainConfidence(chain, basis),
		Basis:      basis,
		FirstSeen:  first.UTC(),
		LastSeen:   last.UTC(),
		Evidence:   refs, EvidenceCount: total,
	}
}

func chainTime(chain models.RootCauseChain) time.Time {
	return time.Unix(0, int64(chain.Timestamp*1e9)).UTC()
}

// chainSeverity maps the chain's severity label explicitly. Co-occurrence is
// capped at Medium: an unproven relationship must not read as Critical.
func chainSeverity(chain models.RootCauseChain, basis string) models.Severity {
	var sev models.Severity
	switch chain.Severity {
	case "Critical":
		sev = models.SeverityCritical
	case "High":
		sev = models.SeverityHigh
	case "Medium":
		sev = models.SeverityMedium
	case "Low":
		sev = models.SeverityLow
	default:
		sev = models.SeverityInfo
	}
	if basis != models.EvidenceSameSession && (sev == models.SeverityCritical || sev == models.SeverityHigh) {
		sev = models.SeverityMedium
	}
	return sev
}

// chainConfidence: co-occurrence is always Low; same-session maps the chain's
// own confidence label (unknown → Low).
func chainConfidence(chain models.RootCauseChain, basis string) models.Confidence {
	if basis != models.EvidenceSameSession {
		return models.ConfidenceLow
	}
	switch chain.Confidence {
	case "High":
		return models.ConfidenceHigh
	case "Medium":
		return models.ConfidenceMedium
	default:
		return models.ConfidenceLow
	}
}
