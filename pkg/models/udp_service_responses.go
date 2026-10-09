package models

// UDP request/response visibility for well-known request/response services (Phase 4.36).
//
// Generic UDP has no handshake, so a request that is never answered leaves no trace in the
// existing output. For a small set of services whose server always replies to a client
// request from its own service port (SNMP, NTP, RADIUS, Kerberos, LDAP/CLDAP), this lists
// per client -> server pair how many conversations, requests and replies were OBSERVED, and
// how many conversations had no reply at all.
//
// "No reply observed" is an absence of evidence at this capture point: the capture may not
// contain the return direction, the reply may have been filtered, lost or never generated,
// or the capture may have ended first. It does not show that the server failed, that packets
// were lost, or where. ICMP errors about the same traffic are reported separately
// (icmp_error_evidence). It feeds no finding, health, risk or exit-code decision.

// UDPServiceResponsesBasis explains how to read the numbers.
const UDPServiceResponsesBasis = "Per client address, server address and service, the UDP conversations (client address:port to server address:port) seen " +
	"in this capture, the requests (client to server) and the replies (server service port to client) observed. A conversation with no reply " +
	"observed is an absence of evidence at this capture point (the return direction may not be captured, or the reply was filtered, lost or " +
	"never sent, or the capture ended first); it does not show that the server failed or that packets were lost. Replies are not matched to " +
	"individual requests, so fewer replies than requests is reported as counts only."

// UDPServiceGroup is the account for one client -> server pair and service.
type UDPServiceGroup struct {
	Service    string `json:"service"` // SNMP, NTP, RADIUS, RADIUS accounting, Kerberos, LDAP
	Client     string `json:"client"`
	Server     string `json:"server"`
	ServerPort uint16 `json:"server_port"`
	// Conversations are distinct client port + server tuples.
	Conversations int `json:"conversations"`
	Requests      int `json:"requests"`
	Replies       int `json:"replies"`
	// ConversationsWithoutReply: conversations in which no reply at all was observed.
	ConversationsWithoutReply int `json:"conversations_without_reply"`
	// WithoutReplyNearCaptureEnd: the subset whose last request was within 2 s of the last
	// packet, which the end of the capture may simply have cut off.
	WithoutReplyNearCaptureEnd int    `json:"without_reply_near_capture_end,omitempty"`
	FirstRequestFrame          uint64 `json:"first_request_frame,omitempty"`
	// FirstUnansweredFrame is the first request of the first conversation without a reply.
	FirstUnansweredFrame uint64 `json:"first_unanswered_frame,omitempty"`
	FirstRequestTime     string `json:"first_request_time"`
	LastRequestTime      string `json:"last_request_time"`
	// Visibility qualifies missing replies; empty when every conversation had a reply.
	Visibility string `json:"visibility,omitempty"`
}

// UDPServiceTotals counts per service over every tracked conversation (not only listed groups).
type UDPServiceTotals struct {
	Service                   string `json:"service"`
	Conversations             int    `json:"conversations"`
	ConversationsWithoutReply int    `json:"conversations_without_reply"`
}

// UDPServiceResponses is the additive JSON object `udp_service_responses`; absent when no
// request to a covered service was observed.
type UDPServiceResponses struct {
	Basis                string             `json:"basis"`
	Services             []UDPServiceTotals `json:"services"`
	ConversationsTracked int                `json:"conversations_tracked"`
	// DatagramsUntracked counts covered datagrams of conversations beyond the tracking bound
	// (their requests and replies are unknown).
	DatagramsUntracked int               `json:"datagrams_untracked,omitempty"`
	GroupsTotal        int               `json:"groups_total"`
	GroupsShown        int               `json:"groups_shown"`
	OmittedGroups      int               `json:"omitted_groups,omitempty"`
	MaxGroups          int               `json:"max_groups"`
	Order              string            `json:"order"`
	Groups             []UDPServiceGroup `json:"groups"`
}
