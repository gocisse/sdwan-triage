// Package events defines the typed, capture-timestamped observation model that
// detectors emit into, and the in-memory index that later correlation stages
// query. An Event records WHAT was observed and WHEN (in capture time); it
// deliberately carries no severity, confidence or recommendation — those belong
// to the Finding/Diagnosis layer that will consume the index.
package events

import "time"

// Kind identifies the type of observation. Kinds are dotted, lower-case and
// namespaced by protocol/subsystem ("tcp.retransmission"). The vocabulary is
// intentionally small and only covers signals an existing detector produces.
type Kind string

const (
	// TCPRetransmission: a data segment re-sent with a sequence number already
	// seen on the same flow. Values: seq, payload_len, since_original_ms,
	// original_ts_us (unix microseconds of the first transmission, exact in
	// float64). Attrs: src_ip, dst_ip.
	TCPRetransmission Kind = "tcp.retransmission"

	// BFDDown: a BFD session observed transitioning from Up to a non-Up state.
	// Values: prev_state, new_state (RFC 5880 numeric). Attrs: src_ip, peer_ip,
	// new_state_name, diag (RFC 5880 §4.1 diagnostic code carried by the packet that showed
	// the transition) and diag_name. The code is the sender's report about its own session.
	BFDDown Kind = "bfd.down"

	// TCPRTTSpike: a measured round-trip time at or above the TCP analyzer's
	// spike threshold. Values: rtt_ms. FlowKey is the direction that sent the
	// acknowledged segment.
	TCPRTTSpike Kind = "tcp.rtt_spike"

	// BGPEvent: a BGP UPDATE (with or without withdrawn routes) or NOTIFICATION
	// observed on a peering session. Attrs: peer_ip (sender), dst_ip,
	// event_type ("Update" | "Withdrawal" | "Notification"), detail.
	// A finer BGP taxonomy is deliberately deferred.
	BGPEvent Kind = "bgp.event"

	// TCPHandshakeFailed: a connection attempt that did not complete — reset
	// by RST or SYN/SYN-ACK unanswered within the handshake timeout (judged in
	// capture time). Timestamp: RST packet time, or the unanswered SYN's time.
	// Values: syn_ts_us, wait_ms. Attrs: reason, state.
	TCPHandshakeFailed Kind = "tcp.handshake_failed"

	// TCPZeroWindow: a segment advertising a receive window of 0 (receiver
	// buffer full). One event per such segment. Values: zero_count (running
	// per-flow count). Attrs: src_ip, dst_ip.
	TCPZeroWindow Kind = "tcp.zero_window"

	// TCPSYNRetransmission: a repeated TCP SYN or SYN-ACK observed in the capture
	// (same initial sequence number, and for SYN-ACK the same acknowledgement
	// number, as an earlier still-pending handshake packet on the same direction
	// of the same 4-tuple). It records OBSERVED REPEATED HANDSHAKE PACKETS only:
	// it is not proof of packet loss and does not say where a packet was lost or
	// whether the sender or a capture duplicate produced the repeat (use
	// since_previous_ms to judge). A repeat whose first copy precedes the capture
	// cannot be seen. One event per repeated packet, capped at 10,000 events per
	// capture so that it cannot exhaust the shared event index; repeats beyond
	// the cap still advance state but are not emitted. Independent of
	// tcp.retransmission (never counted there). FlowKey: direction of the repeated
	// packet. Values: seq, ack (0 for SYN), attempt (1 = initial, so the first
	// repeat is 2), since_first_ms, since_previous_ms, first_ts_us. Attrs:
	// segment ("SYN" | "SYN-ACK"), src_ip, dst_ip.
	TCPSYNRetransmission Kind = "tcp.syn_retransmission"

	// TCPSequenceGap: a sequence-consuming TCP segment (payload, SYN or FIN) began
	// beyond the highest sequence position seen so far in that direction, leaving
	// the range [gap_start, gap_end) unobserved at that moment. It is an OBSERVED
	// SEQUENCE GAP, not proof of packet loss: it can equally be capture loss,
	// asymmetric visibility, a capture that began mid-connection, or reordering.
	// Pure ACKs (keep-alives included) never create one. One event per gap,
	// emitted after all other events (existing IDs unchanged), capped at 10,000 per
	// capture. Timestamp/Packets: the segment that exposed the gap. FlowKey: the
	// direction that carried the data. Values: gap_start, gap_end, gap_bytes,
	// filled_bytes, remaining_bytes, and fill_delay_ms/filled_ts_us (resolution
	// filled) or acked_ts_us (acked_beyond). Attrs: resolution ("filled" - later
	// segments covered the whole range; "acked_beyond" - the peer's ACK reached the
	// gap end while the range was not fully observed, evidence of acknowledgement
	// not of loss; "unresolved"), baseline ("syn" | "midstream"), limitation
	// (optional: rst | restart | state_lost | expired | tracking_cap - why tracking
	// stopped early), src_ip, dst_ip.
	TCPSequenceGap Kind = "tcp.sequence_gap"

	// TCPDuplicateACKRun: a run of duplicate ACKs - pure ACKs (no payload, no
	// SYN/FIN/RST) repeating the previous ACK's acknowledgment number AND advertised
	// window while the peer had data outstanding (RFC 5681 criteria; idle keep-alive
	// ACK repeats never qualify, and nothing qualifies when the peer's sequence
	// position is unknown). It records OBSERVED repeated ACKs only: not packet loss,
	// not a confirmed fast retransmit, not a fault location. One event per run with
	// at least one duplicate, emitted after all other events (existing IDs unchanged)
	// when the run ends or at the end of the capture; capped at 10,000 per capture.
	// FlowKey: the ACK sender's direction. Timestamp: the run's first ACK; Packets:
	// [first ACK, last duplicate] recorder ordinals. Values: ack, window, dup_count
	// (duplicates after the initial ACK), duration_ms, first_ts_us, last_ts_us,
	// sack_acks (duplicates that carried SACK) and, when SACK was observed, sack0_left,
	// sack0_right ... sack3_right (edges of the most recent such duplicate; supporting
	// observation only). Attrs: ended_by (non_pure_ack | ack_changed | window_changed |
	// no_outstanding_data | peer_position_unknown | capture_end | state_lost), sack ("observed" | "none"),
	// consistent_with_fast_retransmit_trigger ("true" only when dup_count >= 3, the
	// RFC 5681 threshold; it does not say a retransmission happened), src_ip, dst_ip.
	TCPDuplicateACKRun Kind = "tcp.duplicate_ack_run"

	// TunnelObserved: an encapsulation/VPN/SD-WAN tunnel was seen on the wire.
	// One event per distinct tunnel, stamped with its first packet. Values:
	// packet_count, byte_count, last_seen_us, vni. Attrs: type, src_ip, dst_ip,
	// inner_proto, detection_method.
	TunnelObserved Kind = "tunnel.observed"

	// TrafficGap: no packets at all for longer than the gap threshold.
	// Timestamp is the start of the silence. Values: duration_sec, end_ts_us.
	TrafficGap Kind = "traffic.gap"

	// DNSAnomaly: a DNS observation the DNS detector classified as anomalous
	// (failure RCODE, unanswered query, suspicious answer). Attrs: query,
	// reason, kind (models.DNSKind*), server_ip, and answer_ip when applicable.
	DNSAnomaly Kind = "dns.anomaly"
)

// PacketRef points at a packet in the source capture by ordinal (0-based
// position in the file). Drill-down re-reads the capture; no payload is copied.
type PacketRef struct {
	Index     uint64    `json:"index"`
	Timestamp time.Time `json:"timestamp"`
}

// Event is a single deterministic observation derived from the capture.
type Event struct {
	// ID is assigned by the Emitter in emission order (1-based, dense).
	ID uint64 `json:"id"`

	Kind Kind `json:"kind"`

	// Timestamp is CAPTURE time: the timestamp of the packet that produced the
	// observation, or of the earliest packet it summarises. Never wall clock.
	Timestamp time.Time `json:"timestamp"`

	// Capture labels the source capture ("" for single-capture analysis; used
	// to distinguish sides in future multi-capture work).
	Capture string `json:"capture,omitempty"`

	// FlowKey uses the existing detector convention "srcIP:port->dstIP:port"
	// (empty for capture-wide or host-level observations).
	FlowKey string `json:"flow_key,omitempty"`

	// Packets references the packet(s) that evidence the observation.
	Packets []PacketRef `json:"packets,omitempty"`

	// Values holds numeric measurements (seq numbers, counts, durations in ms).
	Values map[string]float64 `json:"values,omitempty"`

	// Attrs holds small string attributes (IPs, names, reasons). Not payloads.
	Attrs map[string]string `json:"attrs,omitempty"`

	// Source is the emitting detector's name.
	Source string `json:"source"`
}

// Emitter is what detectors write to. Implementations assign IDs, fill in the
// current packet reference when the detector did not, and store the event.
type Emitter interface {
	Emit(Event)
}
