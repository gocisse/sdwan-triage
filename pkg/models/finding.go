package models

import "time"

// Severity is the impact of a Finding's conclusion IF that conclusion is true.
// It says nothing about how well the conclusion is supported (see Confidence).
type Severity string

const (
	SeverityInfo     Severity = "Info"
	SeverityLow      Severity = "Low"
	SeverityMedium   Severity = "Medium"
	SeverityHigh     Severity = "High"
	SeverityCritical Severity = "Critical"
)

// Confidence is the strength of the evidence supporting a Finding's conclusion.
type Confidence string

const (
	ConfidenceLow    Confidence = "Low"
	ConfidenceMedium Confidence = "Medium"
	ConfidenceHigh   Confidence = "High"
)

// FindingBasisObserved marks a Finding that states only what was observed in the
// capture (no relationship between separate events is asserted). Correlated
// Findings use EvidenceSameSession / EvidenceTimeProximity instead.
const FindingBasisObserved = "observed"

// EvidenceRef points at one observation supporting a Finding. It is understandable
// on its own (kind, capture time, packet ordinal, flow) because EventID depends on
// emission order and is informational only.
type EvidenceRef struct {
	Kind        string    `json:"kind"`
	Timestamp   time.Time `json:"timestamp"`              // capture time, UTC
	PacketIndex *uint64   `json:"packet_index,omitempty"` // 0-based ordinal in the capture, when known
	FlowKey     string    `json:"flow_key,omitempty"`     // "srcIP:port->dstIP:port"
	EventID     uint64    `json:"event_id,omitempty"`     // informational; never an identity
}

// Finding is a conclusion assembled from existing evidence. It is not a
// detector output and carries no recommendation text.
type Finding struct {
	ID            string        `json:"id"` // deterministic; never derived from event IDs
	Kind          string        `json:"kind"`
	Title         string        `json:"title"`
	Summary       string        `json:"summary"`
	Severity      Severity      `json:"severity"`
	Confidence    Confidence    `json:"confidence"`
	Basis         string        `json:"basis"` // FindingBasisObserved | EvidenceSameSession | EvidenceTimeProximity
	FirstSeen     time.Time     `json:"first_seen"`
	LastSeen      time.Time     `json:"last_seen"`
	Evidence      []EvidenceRef `json:"evidence"`       // bounded sample, chronological
	EvidenceCount int           `json:"evidence_count"` // true total, may exceed len(Evidence)
}
