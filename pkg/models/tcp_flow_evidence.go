package models

// Per-flow TCP evidence summary (Phase 4.31b).
//
// A bounded, deterministic, OBSERVATIONAL view of the TCP evidence the engine already
// computed (tcp.retransmission, tcp.syn_retransmission, tcp.sequence_gap,
// tcp.duplicate_ack_run), grouped by TCP connection. It adds no detection and feeds
// no verdict: health, risk, findings and the loss metrics never read it.
//
// It never says where, or whether, a packet was lost in the network: a single Edge
// capture cannot establish that. Every record carries a neutral description; gaps keep
// their resolution (filled / acked_beyond / unresolved); duplicate-ACK runs carry the
// duplicate count, never a "fast retransmit" claim; completeness limits are referenced
// (tcp_evidence_completeness) and any display truncation is reported explicitly.

// TCPFlowEvidenceFrameBasis documents how frame numbers are derived.
const TCPFlowEvidenceFrameBasis = "frame = capture frame number = position of the packet in the capture file counted from 1 " +
	"(the engine's packet ordinal plus one). It matched tshark frame numbers on every capture tested, including a capture with " +
	"unsupported-link-type packets; it has not been verified for every pcapng interface layout or for filtered captures."

// TCPFlowEvidenceSequenceBasis documents the sequence-number representation.
const TCPFlowEvidenceSequenceBasis = "absolute 32-bit TCP sequence and acknowledgment numbers as carried in the packets " +
	"(Wireshark shows relative numbers by default; use tcp.seq_raw / tcp.ack_raw to compare)"

// TCPFlowEvidenceOrder documents the (display-only) flow ordering.
const TCPFlowEvidenceOrder = "flows with a repeated SYN and no observed SYN-ACK first; within each group, flows with more distinct evidence kinds first, " +
	"then more records, then earlier first evidence, then endpoints. Within a flow, sequence-gap records are listed unresolved, then acked_beyond, then filled " +
	"(chronological within each). The order is for display only and is not a severity ranking"

// TCPFlowEvidenceCompletenessNote references the completeness object.
const TCPFlowEvidenceCompletenessNote = "This summary lists only evidence that was detected and kept. See tcp_evidence_completeness for evidence " +
	"that was omitted or whose collection was limited; an absent object or zero counts does not prove the capture or the evidence is complete."

// TCPFlowEvidenceLimits are the JSON display bounds.
type TCPFlowEvidenceLimits struct {
	MaxFlows          int `json:"max_flows"`
	MaxRecordsPerKind int `json:"max_records_per_kind_per_flow"`
	MaxFramesPerEntry int `json:"max_frames_per_entry"`
}

// RepeatedSegmentEvidence summarizes tcp.retransmission events of one flow.
type RepeatedSegmentEvidence struct {
	Count           int      `json:"count"`
	Frames          []uint64 `json:"frames,omitempty"`
	FramesTruncated bool     `json:"frames_truncated,omitempty"`
	Description     string   `json:"description"`
}

// RepeatedHandshakeEvidence is one tcp.syn_retransmission event.
type RepeatedHandshakeEvidence struct {
	Segment      string  `json:"segment"` // "SYN" | "SYN-ACK"
	Direction    string  `json:"direction"`
	Attempt      int     `json:"attempt"` // 1 = the initial packet, so the first repeat is 2
	Frame        uint64  `json:"frame,omitempty"`
	Time         string  `json:"time"`
	SinceFirstMs float64 `json:"since_first_ms"`
	// SincePreviousMs is the capture-time interval since the previous packet of the same
	// kind and sequence numbers (the event's since_previous_ms). A very short interval can
	// also result from a capture duplicate; a repeat can follow an observed SYN-ACK.
	SincePreviousMs float64 `json:"since_previous_ms"`
	SYNACKObserved  *bool   `json:"synack_observed,omitempty"` // SYN repeats only: was any SYN-ACK observed for this address/port pair in the capture (tuple-level; not matched to this attempt)
	Description     string  `json:"description"`
}

// SequenceGapEvidence is one tcp.sequence_gap event.
type SequenceGapEvidence struct {
	Direction      string   `json:"direction"` // direction that carried the data
	GapStart       uint64   `json:"gap_start"`
	GapEnd         uint64   `json:"gap_end"`
	GapBytes       uint64   `json:"gap_bytes"`
	Resolution     string   `json:"resolution"` // filled | acked_beyond | unresolved
	FilledBytes    uint64   `json:"filled_bytes"`
	RemainingBytes uint64   `json:"remaining_bytes"`
	FillDelayMs    *float64 `json:"fill_delay_ms,omitempty"`
	Frame          uint64   `json:"frame,omitempty"` // the frame that exposed the gap
	Time           string   `json:"time"`
	Baseline       string   `json:"baseline"` // syn | midstream
	Limitation     string   `json:"limitation,omitempty"`
	Description    string   `json:"description"`
}

// DuplicateACKRunEvidence is one tcp.duplicate_ack_run event.
type DuplicateACKRunEvidence struct {
	Direction   string      `json:"direction"` // the ACK sender
	Ack         uint64      `json:"ack"`
	Window      uint64      `json:"window"`
	Duplicates  int         `json:"duplicates"` // after the initial ACK
	DurationMs  float64     `json:"duration_ms"`
	FirstFrame  uint64      `json:"first_frame,omitempty"`
	LastFrame   uint64      `json:"last_frame,omitempty"`
	Time        string      `json:"time"`
	SACK        string      `json:"sack"` // observed | none
	SACKEdges   [][2]uint64 `json:"sack_edges,omitempty"`
	EndedBy     string      `json:"ended_by"`
	Description string      `json:"description"`
}

// GapResolutionCounts counts sequence-gap records by resolution. Total is the number of
// recorded gap events counted, which is the denominator for the others; it does not
// include gaps the engine could not record (see tcp_evidence_completeness).
type GapResolutionCounts struct {
	Total       int `json:"total"`
	Unresolved  int `json:"unresolved"`
	AckedBeyond int `json:"acked_beyond"`
	Filled      int `json:"filled"`
}

// SequenceGapSummary is the capture-wide gap-resolution tally with a cautious reading.
type SequenceGapSummary struct {
	GapResolutionCounts
	Note string `json:"note,omitempty"`
}

// CompletenessDetail explains one tcp_evidence_completeness counter in plain language.
// Category is "omitted_events" (events generated but not kept) or "tracking_limit"
// (occurrences of a limiting condition; the number of missed events is unknown).
type CompletenessDetail struct {
	Name     string `json:"name"`
	Category string `json:"category"`
	Count    int    `json:"count"`
	Meaning  string `json:"meaning"`
}

// TCPFlowEvidenceOmitted counts records of one flow not shown because of the bounds.
type TCPFlowEvidenceOmitted struct {
	RepeatedHandshake int `json:"repeated_handshake,omitempty"`
	SequenceGaps      int `json:"sequence_gaps,omitempty"`
	DuplicateACKRuns  int `json:"duplicate_ack_runs,omitempty"`
}

// TCPFlowEvidence is the evidence of one TCP connection (both directions).
type TCPFlowEvidence struct {
	Endpoints         string                      `json:"endpoints"` // "a:port <-> b:port", sorted
	EvidenceKinds     []string                    `json:"evidence_kinds"`
	RepeatedSegments  *RepeatedSegmentEvidence    `json:"repeated_segments,omitempty"`
	RepeatedHandshake []RepeatedHandshakeEvidence `json:"repeated_handshake,omitempty"`
	SequenceGaps      []SequenceGapEvidence       `json:"sequence_gaps,omitempty"`
	DuplicateACKRuns  []DuplicateACKRunEvidence   `json:"duplicate_ack_runs,omitempty"`
	// RepeatedSYNWithoutSYNACK: the flow has a repeated SYN and no SYN-ACK was observed for
	// the connection in this capture (the reason it is listed first). Not a severity.
	RepeatedSYNWithoutSYNACK bool `json:"repeated_syn_without_synack,omitempty"`
	// GapResolutions tallies ALL recorded gap events of the flow, including any not listed.
	GapResolutions *GapResolutionCounts    `json:"gap_resolutions,omitempty"`
	Omitted        *TCPFlowEvidenceOmitted `json:"omitted,omitempty"`
}

// TCPFlowEvidenceSummary is the additive JSON object `tcp_flow_evidence`; absent when
// no TCP evidence was detected.
type TCPFlowEvidenceSummary struct {
	FrameNumberBasis     string                `json:"frame_number_basis"`
	SequenceNumberBasis  string                `json:"sequence_number_basis"`
	Order                string                `json:"order"`
	Limits               TCPFlowEvidenceLimits `json:"limits"`
	FlowsWithEvidence    int                   `json:"flows_with_evidence"`
	FlowsShown           int                   `json:"flows_shown"`
	Truncated            bool                  `json:"truncated"`
	OmittedFlows         int                   `json:"omitted_flows,omitempty"`
	OmittedRecords       int                   `json:"omitted_records,omitempty"` // events not shown: those of omitted flows plus gap/handshake/dup records beyond the per-flow bound
	CompletenessAffected bool                  `json:"completeness_affected"`
	CompletenessNote     string                `json:"completeness_note"`
	// CompletenessDetails explains each non-zero tcp_evidence_completeness counter (the
	// machine-readable object is unchanged); empty when nothing was limited.
	CompletenessDetails []CompletenessDetail `json:"completeness_details,omitempty"`
	// SequenceGaps tallies every recorded gap event of the capture (not only shown flows).
	SequenceGaps *SequenceGapSummary `json:"sequence_gaps,omitempty"`
	Flows        []TCPFlowEvidence   `json:"flows"`
}
