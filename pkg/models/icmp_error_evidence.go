package models

// ICMP error evidence (Phase 4.33).
//
// An ICMP (v4) or ICMPv6 ERROR message quotes the start of the packet that triggered it.
// This type groups the error messages seen in the capture by what was reported (type and
// code), who reported it, and — when the quote is usable — the original flow it refers to,
// with exact codes, frame numbers, counts and the next-hop MTU where the message carries one.
//
// It states what was OBSERVED: a device sent this message about that packet. It does not
// say why, where the problem lies, that an application failed, or that a provider, tunnel
// or endpoint is at fault: a single Edge capture cannot show that. A missing or truncated
// quote means the flow could not be identified from the message, never that no flow was
// affected. It feeds no finding, health, risk or exit-code decision.

// ICMPErrorEvidenceBasis explains how to read the evidence.
const ICMPErrorEvidenceBasis = "Each group is a set of ICMP/ICMPv6 error messages with the same type, code, reporting address and quoted flow. " +
	"The quoted flow is read from the part of the original packet the message carries; when that part is missing or truncated the flow " +
	"is unknown (not absent). Frame numbers are capture frame numbers. An error message shows that a device generated it about a packet; " +
	"it does not by itself show why, where in the network, or that an application failed."

// ICMPQuotedFlow is the original packet quoted inside an ICMP error.
type ICMPQuotedFlow struct {
	// Status: "complete" (addresses, protocol and, for TCP/UDP, ports), "no_ports" (addresses and
	// protocol only: transport header cut off or not TCP/UDP), or "unusable" (absent, truncated
	// before the IP header ended, or not the expected IP version).
	Status   string `json:"status"`
	Protocol string `json:"protocol,omitempty"` // TCP, UDP, ICMP, ICMPv6 or "protocol N"
	Src      string `json:"src,omitempty"`
	// SrcPort is the quoted source port. In a group it is the first one seen; the group
	// does not split on it (see ICMPErrorGroup.DistinctSrcPorts).
	SrcPort uint16 `json:"src_port,omitempty"`
	Dst     string `json:"dst,omitempty"`
	DstPort uint16 `json:"dst_port,omitempty"`
}

// ICMPErrorGroup is one group of identical error messages.
type ICMPErrorGroup struct {
	Family     string         `json:"family"` // ICMP | ICMPv6
	Type       uint8          `json:"icmp_type"`
	Code       uint8          `json:"icmp_code"`
	TypeName   string         `json:"type_name"`
	Meaning    string         `json:"meaning"` // neutral description of the type/code
	Reporter   string         `json:"reporter"`
	Recipient  string         `json:"recipient"`
	Quoted     ICMPQuotedFlow `json:"quoted_flow"`
	Count      int            `json:"count"`
	FirstTime  string         `json:"first_time"`
	LastTime   string         `json:"last_time"`
	FirstFrame uint64         `json:"first_frame,omitempty"`
	Frames     []uint64       `json:"frames,omitempty"` // first frames, bounded
	// NextHopMTU is the MTU carried by Fragmentation Needed (ICMP) or Packet Too Big (ICMPv6);
	// MinMTU/MaxMTU differ only when the group carried different values. 0 = none/not stated.
	MinMTU uint32 `json:"mtu_min,omitempty"`
	MaxMTU uint32 `json:"mtu_max,omitempty"`
	// DistinctSrcPorts counts the different quoted source ports in the group (capped; see
	// SrcPortsCapped). Messages about the same service from many client ports form one group.
	DistinctSrcPorts int  `json:"distinct_src_ports,omitempty"`
	SrcPortsCapped   bool `json:"src_ports_capped,omitempty"`
	// QuotedSourceDiffers: the quoted packet's source is not the address the message was sent to
	// (for example address translation or a tunnel between the original sender and this capture point).
	QuotedSourceDiffers bool `json:"quoted_source_differs_from_recipient,omitempty"`
}

// ICMPErrorEvidence is the additive JSON object `icmp_error_evidence`; absent when no
// ICMP error message was observed.
type ICMPErrorEvidence struct {
	Basis           string `json:"basis"`
	TotalMessages   int    `json:"total_messages"`
	GroupsTotal     int    `json:"groups_total"`
	GroupsShown     int    `json:"groups_shown"`
	MaxGroups       int    `json:"max_groups"`
	OmittedGroups   int    `json:"omitted_groups,omitempty"` // groups (and their messages) not listed
	OmittedMessages int    `json:"omitted_messages,omitempty"`
	// MessagesWithUnusableQuote counts messages whose original flow could not be identified.
	MessagesWithUnusableQuote int              `json:"messages_with_unusable_quote"`
	Order                     string           `json:"order"`
	Errors                    []ICMPErrorGroup `json:"errors"`
}
