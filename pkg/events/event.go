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
	// seen on the same flow. Values: seq, payload_len. Attrs: src_ip, dst_ip.
	TCPRetransmission Kind = "tcp.retransmission"

	// BFDDown: a BFD session observed transitioning from Up to a non-Up state.
	// Values: prev_state, new_state (RFC 5880 numeric). Attrs: src_ip, peer_ip.
	BFDDown Kind = "bfd.down"

	// DNSAnomaly: a DNS observation the DNS detector classified as anomalous
	// (failure RCODE, unanswered query, suspicious answer). Attrs: query,
	// reason, server_ip, and answer_ip when applicable.
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
