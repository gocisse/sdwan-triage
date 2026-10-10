package models

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/gocisse/sdwan-triage/pkg/events"
)

// TriageReport contains all detected network anomalies and analysis results
// The Mu field protects concurrent slice/map appends from parallel detectors.
type TriageReport struct {
	Mu                          sync.Mutex                   `json:"-"` // Protects concurrent writes from parallel detectors
	DNSAnomalies                []DNSAnomaly                 `json:"dns_anomalies"`
	TCPRetransmissions          []TCPFlow                    `json:"tcp_retransmissions"`
	FailedHandshakes            []TCPFlow                    `json:"failed_handshakes"`
	TCPHandshakes               TCPHandshakeAnalysis         `json:"tcp_handshakes"`
	TCPHandshakeFlows           []TCPHandshakeFlow           `json:"tcp_handshake_flows,omitempty"`
	TCPHandshakeCorrelatedFlows []TCPHandshakeCorrelatedFlow `json:"tcp_handshake_correlated_flows,omitempty"`
	ARPConflicts                []ARPConflict                `json:"arp_conflicts"`
	HTTPErrors                  []HTTPError                  `json:"http_errors"`
	TLSCerts                    []TLSCertInfo                `json:"tls_certs"`
	TLSFlows                    []TCPFlow                    `json:"tls_flows"`
	HTTP2Flows                  []TCPFlow                    `json:"http2_flows"`
	QUICFlows                   []UDPFlow                    `json:"quic_flows"`
	TrafficAnalysis             []TrafficFlow                `json:"traffic_analysis"`
	ApplicationBreakdown        map[string]AppCategory       `json:"application_breakdown"`
	SuspiciousTraffic           []SuspiciousFlow             `json:"suspicious_traffic"`
	RTTAnalysis                 []RTTFlow                    `json:"rtt_analysis"`
	RTTHistogram                map[string]int               `json:"rtt_histogram"`
	DeviceFingerprinting        []DeviceFingerprint          `json:"device_fingerprinting"`
	BandwidthReport             BandwidthReport              `json:"bandwidth_report"`
	Timeline                    []TimelineEvent              `json:"timeline"`
	DNSDetails                  []DNSRecord                  `json:"dns_details"`
	BGPHijackIndicators         []BGPIndicator               `json:"bgp_hijack_indicators,omitempty"`
	QoSAnalysis                 *QoSReport                   `json:"qos_analysis,omitempty"`
	AppIdentification           []IdentifiedApp              `json:"app_identification,omitempty"`
	TotalBytes                  uint64                       `json:"total_bytes"`

	// Risk Assessment
	RiskScore int    `json:"risk_score"`
	RiskLevel string `json:"risk_level"` // "Low", "Medium", "High", "Critical"

	// Top Issues for Executive Summary
	TopIssue           string   `json:"top_issue,omitempty"`
	TopIssueCount      int      `json:"top_issue_count,omitempty"`
	RecommendedActions []string `json:"recommended_actions,omitempty"`

	// Security Analysis
	Security SecurityAnalysis `json:"security"`

	// Network Analysis
	ICMPAnalysis   []ICMPFinding   `json:"icmp_analysis,omitempty"`
	VoIPAnalysis   *VoIPAnalysis   `json:"voip_analysis,omitempty"`
	TunnelAnalysis []TunnelFinding `json:"tunnel_analysis,omitempty"`
	SDWANVendors   []SDWANVendor   `json:"sdwan_vendors,omitempty"`

	// Packet Loss Metrics
	PacketLoss *PacketLossMetrics `json:"packet_loss,omitempty"`

	// Protocol Detection
	SMBFlows      []SMBFlow      `json:"smb_flows,omitempty"`
	LDAPFlows     []LDAPFlow     `json:"ldap_flows,omitempty"`
	KerberosFlows []KerberosFlow `json:"kerberos_flows,omitempty"`

	// LAN Protocol Detection
	LANProtocols *LANProtocolFindings `json:"lan_protocols,omitempty"`

	// Baseline Comparison
	BaselineComparison *BaselineComparison `json:"baseline_comparison,omitempty"`

	// Vendor-Specific DPI Issues
	VendorDPIIssues []VendorDPIIssue `json:"vendor_dpi_issues,omitempty"`

	// Stream Reassembly (Follow TCP/UDP Stream)
	Streams    []StreamViewData `json:"streams,omitempty"`
	RawStreams []*StreamData    `json:"-"` // Raw stream data for actionable analysis

	// Bandwidth Time Series
	BandwidthTimeSeries *BandwidthTimeSeries `json:"bandwidth_timeseries,omitempty"`

	// Plain English Summary
	PlainEnglishSummary *PlainEnglishSummary `json:"plain_english_summary,omitempty"`

	// Traffic Gaps
	TrafficGaps []TrafficGapInfo `json:"traffic_gaps,omitempty"`

	// DHCP Analysis
	DHCPFindings []DHCPFinding `json:"dhcp_findings,omitempty"`

	// NTP Analysis
	NTPFindings []NTPFinding `json:"ntp_findings,omitempty"`

	// DNS Tunneling Detection
	DNSTunnelingFindings []DNSTunnelingFinding `json:"dns_tunneling_findings,omitempty"`

	// C2 Beaconing Detection
	C2BeaconingFindings []C2BeaconingFinding `json:"c2_beaconing_findings,omitempty"`

	// TCP Advanced Analysis (window issues, out-of-order)
	TCPWindowFindings  []TCPWindowFinding  `json:"tcp_window_findings,omitempty"`
	TCPOutOfOrderFlows []TCPOutOfOrderFlow `json:"tcp_out_of_order_flows,omitempty"`

	// Underlay/Overlay Correlation
	RootCauseChains []RootCauseChain `json:"root_cause_chains,omitempty"`

	// Findings are conclusions assembled from Events and correlation results
	// (additive; the legacy slices above are unchanged).
	Findings []Finding `json:"findings,omitempty"`

	// Interface Stability / Flapping Detection
	StabilityFindings []StabilityFinding `json:"stability_findings,omitempty"`

	// Threat Intelligence Matches (from STIX 2.1 feeds)
	ThreatIntelMatches []ThreatIntelMatch `json:"threat_intel_matches,omitempty"`

	// PCAP Export Info
	SourcePCAPPath string `json:"source_pcap_path,omitempty"`

	// ── Typed observation events (Phase 3 seam) ─────────────────────────
	// Events is the chronologically indexed store of typed observations that
	// detectors emit in ADDITION to their existing report fields. It is not
	// serialised into the report JSON (events reference packets; the drill-down
	// API re-reads the capture). EventCounts/EventsDropped are the only
	// JSON-visible trace, so the schema change is small and intentional.
	Events        *events.Index  `json:"-"`
	Emitter       events.Emitter `json:"-"`
	EventCounts   map[string]int `json:"event_counts,omitempty"`
	EventsDropped int            `json:"events_dropped,omitempty"`

	// TCPEvidenceCompleteness is present ONLY when TCP evidence collection was
	// affected by a bound or reset (Phase 4.31a). Its absence does not mean the
	// capture is complete: it only means none of the conditions counted there
	// occurred (see the type documentation for what is not covered).
	TCPEvidenceCompleteness *TCPEvidenceCompleteness `json:"tcp_evidence_completeness,omitempty"`

	// TCPFlowEvidence is a bounded, observational per-flow view of the TCP evidence
	// events (Phase 4.31b); absent when no TCP evidence was detected.
	TCPFlowEvidence *TCPFlowEvidenceSummary `json:"tcp_flow_evidence,omitempty"`

	// DNSResolverSummary accounts for observed DNS responses per queried address
	// (Phase 4.32); absent when the capture holds no DNS query. Observational only.
	DNSResolverSummary *DNSResolverSummary `json:"dns_resolver_summary,omitempty"`

	// ICMPErrorEvidence groups ICMP/ICMPv6 error messages by type, code, reporter and
	// quoted original flow (Phase 4.33); absent when none was observed. Observational only.
	ICMPErrorEvidence *ICMPErrorEvidence `json:"icmp_error_evidence,omitempty"`

	// TLSHandshakeEvidence lists connections with TLS alerts or a ClientHello without an
	// observed ServerHello (Phase 4.34); absent when there are none. Observational only.
	TLSHandshakeEvidence *TLSHandshakeEvidence `json:"tls_handshake_evidence,omitempty"`

	// UDPServiceResponses accounts for requests and observed replies of a few well-known
	// UDP request/response services (Phase 4.36); absent when none was observed.
	UDPServiceResponses *UDPServiceResponses `json:"udp_service_responses,omitempty"`

	// Completeness records provable limitations of the INPUT analysis (packets
	// not analyzed, truncated capture file). It is nil for a complete analysis,
	// so complete captures serialise without the key. It is evidence-scope
	// metadata only: it never feeds RiskScore, Findings, Events or health severity.
	Completeness *CaptureCompleteness `json:"capture_completeness,omitempty"`

	// EvidenceCoverage says which health-relevant evidence classes had input in
	// this capture (applicability, NOT sufficiency). Set once at the end of
	// Process for analyzed reports; absent for NO_DATA and on errors. An all-zero
	// value is meaningful: packets were analyzed, but none of them exercised a
	// class that can move NetworkHealth. It never influences NetworkHealth.
	EvidenceCoverage *EvidenceCoverage `json:"evidence_coverage,omitempty"`

	// NetworkHealth is the ONE authoritative machine-readable health conclusion:
	// "good" | "fair" | "warning" | "critical" (NetworkHealth* constants). It is
	// set once at the end of Process for analyzed reports and is absent when the
	// analysis had no data (AnalysisStatus = no_data) and on errors (no report is
	// emitted). Every output surface renders this value; none computes its own.
	// It is NOT derived from RiskLevel (risk is not health).
	NetworkHealth string `json:"network_health,omitempty"`

	// AnalysisStatus is an analysis status ORTHOGONAL to health: it is set only
	// when there was no evidence to judge (AnalysisStatusNoData) and is absent
	// for every analysis that examined at least one packet. NoDataReason says why.
	// When set, no health level (GOOD/FAIR/WARNING/CRITICAL) may be presented.
	AnalysisStatus string `json:"analysis_status,omitempty"`
	NoDataReason   string `json:"no_data_reason,omitempty"`

	// TimelineTruncated is the number of timeline events that were NOT retained
	// because MaxTimelineEvents was reached. Retained events are a uniform,
	// deterministic sample across the whole capture (see AddTimelineEvent).
	TimelineTruncated int `json:"timeline_truncated,omitempty"`

	timelineSeen int    // total events offered to AddTimelineEvent
	timelineRNG  uint64 // deterministic xorshift state for reservoir sampling
}

// Emit forwards a typed observation to the report's Emitter. It is a no-op when
// no emitter is configured (e.g. detector unit tests using a bare report), so
// detectors can always call it unconditionally.
func (r *TriageReport) Emit(e events.Event) {
	if r.Emitter != nil {
		r.Emitter.Emit(e)
	}
}

// MaxTimelineEvents bounds report.Timeline. The timeline feeds the UI's
// packet-rate histogram/time scrubber, so when the bound is hit events are
// reservoir-sampled uniformly over the capture rather than truncated at the
// start, preserving the temporal distribution. 20k events ≈ 3 MB of JSON.
const MaxTimelineEvents = 20000

// AddTimelineEvent appends a timeline event, keeping the slice bounded by
// MaxTimelineEvents using deterministic reservoir sampling (Algorithm R with a
// fixed-seed xorshift generator, so identical captures yield identical output).
func (r *TriageReport) AddTimelineEvent(e TimelineEvent) {
	r.timelineSeen++
	if len(r.Timeline) < MaxTimelineEvents {
		r.Timeline = append(r.Timeline, e)
		return
	}
	r.TimelineTruncated++
	// Replace a random retained element with probability MaxTimelineEvents/seen.
	if r.timelineRNG == 0 {
		r.timelineRNG = 0x9E3779B97F4A7C15
	}
	x := r.timelineRNG
	x ^= x << 13
	x ^= x >> 7
	x ^= x << 17
	r.timelineRNG = x
	if j := int(x % uint64(r.timelineSeen)); j < MaxTimelineEvents {
		r.Timeline[j] = e
	}
}

// StabilityFinding represents a detected interface flapping or instability event.
// Covers BFD session flapping, IPsec IKE tunnel rebuilds, HSRP/VRRP gateway
// flapping, and STP Topology Change Notification (TCN) storms.
type StabilityFinding struct {
	Type          string  `json:"type"`           // "BFD Flapping", "IKE Tunnel Rebuild", "HSRP Flapping", "VRRP Flapping", "STP TCN Storm"
	Severity      string  `json:"severity"`       // "Critical", "High", "Warning"
	Identifier    string  `json:"identifier"`     // IP pair, group ID, or bridge ID
	Description   string  `json:"description"`    // Human-readable summary
	StateChanges  int     `json:"state_changes"`  // Number of transitions / events
	WindowSeconds float64 `json:"window_seconds"` // Observation window in seconds
	FirstSeen     string  `json:"first_seen"`     // RFC3339
	LastSeen      string  `json:"last_seen"`      // RFC3339
	SourceIP      string  `json:"source_ip,omitempty"`
	PeerIP        string  `json:"peer_ip,omitempty"`
	Protocol      string  `json:"protocol"`        // "BFD", "IKE", "HSRP", "VRRP", "STP"
	RootCauseHint string  `json:"root_cause_hint"` // Suggested root cause
}

// ThreatIntelMatch represents a match from STIX 2.1 threat intelligence feeds
type ThreatIntelMatch struct {
	Timestamp   float64 `json:"timestamp"`
	Type        string  `json:"type"`        // "IP", "Domain", "Hash"
	Value       string  `json:"value"`       // The matched indicator value
	ThreatType  string  `json:"threat_type"` // "C2 Server", "Malware", "Phishing", "Botnet", "Scanner", "Ransomware"
	Confidence  string  `json:"confidence"`  // "High", "Medium", "Low"
	Source      string  `json:"source"`      // Feed name, e.g. "AlienVault OTX"
	FirstSeen   string  `json:"first_seen"`  // When the indicator was first reported
	Description string  `json:"description"`
	SourceIP    string  `json:"source_ip,omitempty"`
	DestIP      string  `json:"dest_ip,omitempty"`
}

// TrafficGapInfo represents a gap in network traffic
type TrafficGapInfo struct {
	StartTime   float64 `json:"start_time"`
	EndTime     float64 `json:"end_time"`
	DurationSec float64 `json:"duration_sec"`
	Description string  `json:"description"`
}

// TimelineEvent represents a network event in the timeline
type TimelineEvent struct {
	Timestamp       float64 `json:"timestamp"`
	EventType       string  `json:"event_type"`
	SourceIP        string  `json:"source_ip"`
	DestinationIP   string  `json:"destination_ip"`
	SourcePort      *uint16 `json:"source_port,omitempty"`
	DestinationPort *uint16 `json:"destination_port,omitempty"`
	Protocol        string  `json:"protocol"`
	Detail          string  `json:"detail"`
}

// DNSRecord stores detailed DNS query/response information
type DNSRecord struct {
	QueryTimestamp    float64  `json:"query_timestamp"`
	QueryName         string   `json:"query_name"`
	QueryType         string   `json:"query_type"`
	SourceIP          string   `json:"source_ip"`
	DestinationIP     string   `json:"destination_ip"`
	ResponseTimestamp *float64 `json:"response_timestamp,omitempty"`
	ResponseCode      *uint16  `json:"response_code,omitempty"`
	AnswerIPs         []string `json:"answer_ips"`
	AnswerNames       []string `json:"answer_names"`
	IsAnomalous       bool     `json:"is_anomalous"`
	Detail            string   `json:"detail"`
}

// TCPHandshakeFlow represents a TCP handshake flow
type TCPHandshakeFlow struct {
	SrcIP            string    `json:"src_ip"`
	SrcPort          uint16    `json:"src_port"`
	DstIP            string    `json:"dst_ip"`
	DstPort          uint16    `json:"dst_port"`
	Timestamp        float64   `json:"timestamp"`
	Count            int       `json:"count"`
	State            string    `json:"state"` // "SYN", "SYN-ACK", "Handshake Complete", "Handshake Failed"
	SynTime          time.Time `json:"syn_time"`
	SynAckTime       time.Time `json:"syn_ack_time"`
	AckTime          time.Time `json:"ack_time"`
	FailureReason    string    `json:"failure_reason,omitempty"`
	IsIPv6           bool      `json:"is_ipv6"`
	SynToSynAckMs    float64   `json:"syn_to_synack_ms,omitempty"`   // Time from SYN to SYN-ACK in milliseconds
	SynAckToAckMs    float64   `json:"synack_to_ack_ms,omitempty"`   // Time from SYN-ACK to ACK in milliseconds
	TotalHandshakeMs float64   `json:"total_handshake_ms,omitempty"` // Total handshake time in milliseconds
}

// TCPHandshakeAnalysis contains TCP handshake analysis results
type TCPHandshakeAnalysis struct {
	SYNFlows                []TCPHandshakeFlow `json:"syn_flows"`
	SYNACKFlows             []TCPHandshakeFlow `json:"synack_flows"`
	SuccessfulHandshakes    []TCPHandshakeFlow `json:"successful_handshakes"`
	FailedHandshakeAttempts []TCPHandshakeFlow `json:"failed_handshake_attempts"`
}

// TCPHandshakeEvent represents a single event in a TCP handshake sequence
type TCPHandshakeEvent struct {
	Type      string  `json:"type"`      // "SYN", "SYN-ACK", "Handshake Complete"
	Timestamp float64 `json:"timestamp"` // Unix timestamp
}

// TCPHandshakeCorrelatedFlow represents a TCP handshake flow with all its events grouped together
type TCPHandshakeCorrelatedFlow struct {
	FlowID  string              `json:"flow_id"` // e.g., "SrcIP:SrcPort->DstIP:DstPort"
	SrcIP   string              `json:"src_ip"`
	SrcPort uint16              `json:"src_port"`
	DstIP   string              `json:"dst_ip"`
	DstPort uint16              `json:"dst_port"`
	Events  []TCPHandshakeEvent `json:"events"` // Ordered list of events for this flow
	Status  string              `json:"status"` // "Complete", "Failed", "Pending"
}

// TrafficFlowSummary represents a summarized traffic flow for bandwidth analysis
type TrafficFlowSummary struct {
	SrcIP            string        `json:"src_ip"`
	SrcPort          uint16        `json:"src_port"`
	DstIP            string        `json:"dst_ip"`
	DstPort          uint16        `json:"dst_port"`
	Protocol         string        `json:"protocol"`
	TotalBytes       uint64        `json:"total_bytes"`
	TotalPackets     uint64        `json:"total_packets"`
	Duration         time.Duration `json:"duration"`
	AvgBitsPerSecond float64       `json:"avg_bits_per_second"`
	FirstSeen        time.Time     `json:"first_seen"`
	LastSeen         time.Time     `json:"last_seen"`
}

// TimeBucket represents a time-based traffic bucket
type TimeBucket struct {
	Timestamp    time.Time `json:"timestamp"`
	TotalBytes   uint64    `json:"total_bytes"`
	TotalPackets uint64    `json:"total_packets"`
}

// BandwidthReport contains bandwidth analysis results
type BandwidthReport struct {
	TopConversationsByBytes   []TrafficFlowSummary `json:"top_conversations_by_bytes"`
	TopConversationsByPackets []TrafficFlowSummary `json:"top_conversations_by_packets"`
	TimeSeriesData            []TimeBucket         `json:"time_series_data"`
}

// RootCauseChain evidence bases.
const (
	// EvidenceSameSession: the overlay events occurred on the same TCP session
	// that carried the underlay event (BGP peer pair on port 179).
	EvidenceSameSession = "same_session"
	// EvidenceTimeProximity: the events are close in capture time and nothing
	// more is established. This is co-occurrence, not causation.
	EvidenceTimeProximity = "time_proximity"
)

// RootCauseChain represents a correlated underlay/overlay event chain.
// For example, a BGP route withdrawal (underlay) observed together with TCP retransmission
// bursts (overlay). EvidenceBasis states whether the link is shared session identity or
// time proximity only; neither is proof of causation.
type RootCauseChain struct {
	Timestamp      float64  `json:"timestamp"`
	UnderlayEvent  string   `json:"underlay_event"`           // e.g., "BGP Route Withdrawal"
	UnderlayDetail string   `json:"underlay_detail"`          // e.g., "Peer 10.0.0.1 withdrew 192.168.0.0/16"
	OverlayEffect  string   `json:"overlay_effect"`           // e.g., "TCP Retransmission Spike"
	OverlayDetail  string   `json:"overlay_detail"`           // e.g., "14 retransmissions in 5s window"
	AffectedFlows  []string `json:"affected_flows,omitempty"` // Flow keys impacted
	CorrelationGap float64  `json:"correlation_gap_sec"`      // Seconds between underlay event and overlay effect
	Confidence     string   `json:"confidence"`               // "High", "Medium", "Low"
	Severity       string   `json:"severity"`                 // "Critical", "High", "Medium", "Low"
	Recommendation string   `json:"recommendation"`
	EvidenceBasis  string   `json:"evidence_basis"` // EvidenceSameSession | EvidenceTimeProximity (co-occurrence only)
	// Evidence is the exact set of Events the correlator used (triggers of the
	// episode plus the overlay events it counted), bounded to a chronological
	// sample; EvidenceCount is the true total. Ref timestamps are observation
	// times, while window membership was decided on original send time.
	Evidence      []EvidenceRef `json:"evidence,omitempty"`
	EvidenceCount int           `json:"evidence_count,omitempty"`
}

// BGPIndicator represents a BGP hijack indicator
type BGPIndicator struct {
	IPAddress      string `json:"ip_address"`
	IPPrefix       string `json:"ip_prefix"`
	ExpectedASN    int    `json:"expected_asn"`
	ExpectedASName string `json:"expected_as_name"`
	ObservedASN    int    `json:"observed_asn,omitempty"`
	ObservedASName string `json:"observed_as_name,omitempty"`
	Confidence     string `json:"confidence"`
	Reason         string `json:"reason"`
	RelatedDomain  string `json:"related_domain,omitempty"`
	IsAnomaly      bool   `json:"is_anomaly"`
}

// QoSReport contains QoS/DSCP analysis results
type QoSReport struct {
	ClassDistribution map[string]*QoSClassMetrics `json:"class_distribution"`
	TotalPackets      uint64                      `json:"total_packets"`
	MismatchedQoS     []QoSMismatch               `json:"mismatched_qos,omitempty"`
}

// QoSClassMetrics represents metrics for a QoS class
type QoSClassMetrics struct {
	ClassName       string  `json:"class_name"`
	DSCPValue       uint8   `json:"dscp_value"`
	PacketCount     uint64  `json:"packet_count"`
	ByteCount       uint64  `json:"byte_count"`
	Percentage      float64 `json:"percentage"`
	AvgRTT          float64 `json:"avg_rtt_ms,omitempty"`
	RetransmitCount uint64  `json:"retransmit_count"`
	RetransmitRate  float64 `json:"retransmit_rate_percent"`
}

// QoSMismatch represents a QoS marking mismatch
type QoSMismatch struct {
	Flow          string `json:"flow"`
	ExpectedClass string `json:"expected_class"`
	ActualClass   string `json:"actual_class"`
	Reason        string `json:"reason"`
}

// IdentifiedApp represents an identified application
type IdentifiedApp struct {
	Name             string   `json:"name"`
	Category         string   `json:"category"`
	Protocol         string   `json:"protocol"`
	Port             uint16   `json:"port,omitempty"`
	SNI              string   `json:"sni,omitempty"`
	ALPN             string   `json:"alpn,omitempty"`
	PacketCount      uint64   `json:"packet_count"`
	ByteCount        uint64   `json:"byte_count"`
	Confidence       string   `json:"confidence"`
	IdentifiedBy     string   `json:"identified_by"`
	SampleFlows      []string `json:"sample_flows,omitempty"`
	IsSuspicious     bool     `json:"is_suspicious"`
	SuspiciousReason string   `json:"suspicious_reason,omitempty"`
}

// DNS anomaly kinds. The kind is assigned where the anomaly is produced and is
// never inferred from Reason text. Only DNSKindServerFailure influences the
// health verdict; every kind remains an observation in the report.
const (
	DNSKindServerFailure     = "server_failure"      // response with a failure RCODE other than NXDOMAIN (SERVFAIL, REFUSED, FORMERR, NOTIMP, ...)
	DNSKindNXDomain          = "nxdomain"            // response with RCODE NXDOMAIN (the name does not exist: a normal resolution result)
	DNSKindNoResponse        = "no_response"         // query without a matching response in the capture (absence of evidence)
	DNSKindNonStandardServer = "non_standard_server" // answer from a public responder outside the hard-coded resolver list
	DNSKindPrivateAnswer     = "private_answer"      // private/reserved address returned for a public-TLD name
	DNSKindSuspiciousDomain  = "suspicious_domain"   // name matched the TLD / label-count / length heuristics
)

type DNSAnomaly struct {
	Timestamp float64 `json:"timestamp"`
	Query     string  `json:"query"`
	AnswerIP  string  `json:"answer_ip"`
	ServerIP  string  `json:"server_ip"`
	ServerMAC string  `json:"server_mac"`
	Reason    string  `json:"reason"`
	Kind      string  `json:"kind,omitempty"` // one of the DNSKind* constants
}

type TCPFlow struct {
	SrcIP   string `json:"src_ip"`
	SrcPort uint16 `json:"src_port"`
	DstIP   string `json:"dst_ip"`
	DstPort uint16 `json:"dst_port"`
}

type UDPFlow struct {
	SrcIP      string `json:"src_ip"`
	SrcPort    uint16 `json:"src_port"`
	DstIP      string `json:"dst_ip"`
	DstPort    uint16 `json:"dst_port"`
	ServerName string `json:"server_name,omitempty"`
}

type ARPConflict struct {
	IP   string `json:"ip"`
	MAC1 string `json:"mac1"`
	MAC2 string `json:"mac2"`

	// Phase 4.35 (additive). MAC1Frame / MAC2Frame are the capture frames of the first ARP
	// reply from each MAC; OtherMACs lists further MACs that answered for the IP (bounded).
	// Classification is ARPConflictVirtualGateway when EVERY MAC that answered is in a
	// documented virtual redundant-gateway range, otherwise ARPConflictUnexplained (also the
	// meaning of an empty value). Explanation states what the capture does and does not show.
	MAC1Frame      uint64   `json:"mac1_frame,omitempty"`
	MAC2Frame      uint64   `json:"mac2_frame,omitempty"`
	OtherMACs      []string `json:"other_macs,omitempty"`
	Classification string   `json:"classification,omitempty"`
	Explanation    string   `json:"explanation,omitempty"`
}

type HTTPError struct {
	Timestamp float64 `json:"timestamp"`
	Method    string  `json:"method"`
	Host      string  `json:"host"`
	Path      string  `json:"path"`
	Code      int     `json:"status_code"`
}

type TLSCertInfo struct {
	Timestamp    float64  `json:"timestamp"`
	ServerIP     string   `json:"server_ip"`
	ServerPort   uint16   `json:"server_port"`
	ServerName   string   `json:"server_name"`
	Issuer       string   `json:"issuer"`
	Subject      string   `json:"subject"`
	NotBefore    string   `json:"not_before"`
	NotAfter     string   `json:"not_after"`
	Fingerprint  string   `json:"fingerprint"`
	IsExpired    bool     `json:"is_expired"`
	IsSelfSigned bool     `json:"is_self_signed"`
	DNSNames     []string `json:"dns_names,omitempty"`
	JA3Hash      string   `json:"ja3_hash,omitempty"`
	JA3SHash     string   `json:"ja3s_hash,omitempty"`
}

type TrafficFlow struct {
	SrcIP      string  `json:"src_ip"`
	SrcPort    uint16  `json:"src_port"`
	DstIP      string  `json:"dst_ip"`
	DstPort    uint16  `json:"dst_port"`
	Protocol   string  `json:"protocol"`
	TotalBytes uint64  `json:"total_bytes"`
	Percentage float64 `json:"percentage"`
}

type AppCategory struct {
	Name        string `json:"name"`
	Port        uint16 `json:"port"`
	Protocol    string `json:"protocol"`
	PacketCount uint64 `json:"packet_count"`
	ByteCount   uint64 `json:"byte_count"`
}

type SuspiciousFlow struct {
	SrcIP       string `json:"src_ip"`
	SrcPort     uint16 `json:"src_port"`
	DstIP       string `json:"dst_ip"`
	DstPort     uint16 `json:"dst_port"`
	Protocol    string `json:"protocol"`
	Reason      string `json:"reason"`
	Description string `json:"description"`
}

type RTTFlow struct {
	SrcIP      string  `json:"src_ip"`
	SrcPort    uint16  `json:"src_port"`
	DstIP      string  `json:"dst_ip"`
	DstPort    uint16  `json:"dst_port"`
	MinRTT     float64 `json:"min_rtt_ms"`
	MaxRTT     float64 `json:"max_rtt_ms"`
	AvgRTT     float64 `json:"avg_rtt_ms"`
	SampleSize int     `json:"sample_size"`
}

type DeviceFingerprint struct {
	SrcIP      string `json:"src_ip"`
	DeviceType string `json:"device_type"`
	OSGuess    string `json:"os_guess"`
	Confidence string `json:"confidence"`
	Details    string `json:"details"`
}

// SecurityAnalysis contains all security-related findings
type SecurityAnalysis struct {
	DDoSFindings        []DDoSFinding        `json:"ddos_findings,omitempty"`
	PortScanFindings    []PortScanFinding    `json:"port_scan_findings,omitempty"`
	IOCFindings         []IOCFinding         `json:"ioc_findings,omitempty"`
	TLSSecurityFindings []TLSSecurityFinding `json:"tls_security_findings,omitempty"`
}

// DDoSFinding is a retained compatibility type. DDoS detection was removed from the
// analysis engine; nothing populates SecurityAnalysis.DDoSFindings any more. It is kept
// only so frozen consumers (pkg/web) still compile; remove it with the web cleanup.
type DDoSFinding struct {
	Timestamp   float64 `json:"timestamp"`
	SourceIP    string  `json:"source_ip"`
	TargetIP    string  `json:"target_ip,omitempty"`
	Type        string  `json:"type"` // "SYN Flood", "UDP Flood", "ICMP Flood"
	PacketCount int     `json:"packet_count"`
	Threshold   int     `json:"threshold"`
	Duration    float64 `json:"duration_seconds"`
	Severity    string  `json:"severity"` // "Low", "Medium", "High", "Critical"
}

// PortScanFinding represents a detected port scanning activity
type PortScanFinding struct {
	Timestamp    float64  `json:"timestamp"`
	SourceIP     string   `json:"source_ip"`
	TargetIP     string   `json:"target_ip,omitempty"`
	Type         string   `json:"type"` // "Horizontal", "Vertical", "Block"
	PortsScanned int      `json:"ports_scanned"`
	SamplePorts  []uint16 `json:"sample_ports,omitempty"`
	Severity     string   `json:"severity"`
}

// IOCFinding represents a matched Indicator of Compromise
type IOCFinding struct {
	Timestamp    float64 `json:"timestamp"`
	MatchedValue string  `json:"matched_value"`
	Type         string  `json:"type"`     // "IP", "Domain", "Hash"
	IOCType      string  `json:"ioc_type"` // "C2 Server", "Malware", "Phishing"
	SourceIP     string  `json:"source_ip,omitempty"`
	DestIP       string  `json:"dest_ip,omitempty"`
	Confidence   string  `json:"confidence"`
	Description  string  `json:"description"`
}

// TLSSecurityFinding represents a TLS security weakness
type TLSSecurityFinding struct {
	Timestamp    float64 `json:"timestamp"`
	ServerIP     string  `json:"server_ip"`
	ServerPort   uint16  `json:"server_port"`
	ServerName   string  `json:"server_name,omitempty"`
	TLSVersion   string  `json:"tls_version"`
	CipherSuite  string  `json:"cipher_suite,omitempty"`
	WeaknessType string  `json:"weakness_type"` // "Weak TLS Version", "Weak Cipher", "No PFS"
	Severity     string  `json:"severity"`
	Description  string  `json:"description"`
}

// ICMPFinding represents ICMP traffic analysis results
type ICMPFinding struct {
	Timestamp   float64 `json:"timestamp"`
	SourceIP    string  `json:"source_ip"`
	DestIP      string  `json:"dest_ip"`
	Type        uint8   `json:"icmp_type"`
	Code        uint8   `json:"icmp_code"`
	TypeName    string  `json:"type_name"`
	Count       int     `json:"count"`
	IsAnomaly   bool    `json:"is_anomaly"`
	Description string  `json:"description,omitempty"`
}

// VoIPAnalysis contains VoIP/SIP/RTP analysis results
type VoIPAnalysis struct {
	SIPCalls         []SIPCallInfo   `json:"sip_calls,omitempty"`
	RTPStreams       []RTPStreamInfo `json:"rtp_streams,omitempty"`
	TotalCalls       int             `json:"total_calls"`
	EstablishedCalls int             `json:"established_calls"`
	FailedCalls      int             `json:"failed_calls"`
	TotalRTPStreams  int             `json:"total_rtp_streams"`
	AvgJitter        *float64        `json:"avg_jitter_ms"` // ms; nil (null) when unavailable, 0 is a measured zero
	PacketLossRate   float64         `json:"packet_loss_rate"`
}

// SIPCallInfo represents a SIP call
type SIPCallInfo struct {
	CallID    string  `json:"call_id"`
	FromURI   string  `json:"from_uri"`
	ToURI     string  `json:"to_uri"`
	State     string  `json:"state"`
	StartTime float64 `json:"start_time"`
	EndTime   float64 `json:"end_time,omitempty"`
	SrcIP     string  `json:"src_ip"`
	DstIP     string  `json:"dst_ip"`
}

// RTPStreamInfo represents an RTP media stream
type RTPStreamInfo struct {
	SSRC        uint32   `json:"ssrc"`
	SrcIP       string   `json:"src_ip"`
	DstIP       string   `json:"dst_ip"`
	PayloadType string   `json:"payload_type"`
	PacketCount uint64   `json:"packet_count"`
	ByteCount   uint64   `json:"byte_count"`
	LostPackets uint64   `json:"lost_packets"`
	Jitter      *float64 `json:"jitter_ms"` // ms; nil (null) without a known RTP clock rate, 0 is a measured zero
}

// TunnelFinding represents a detected tunnel/encapsulation
type TunnelFinding struct {
	Type        string  `json:"type"`
	SrcIP       string  `json:"src_ip"`
	DstIP       string  `json:"dst_ip"`
	SrcPort     uint16  `json:"src_port,omitempty"`
	DstPort     uint16  `json:"dst_port,omitempty"`
	Identifier  uint32  `json:"identifier,omitempty"` // VNI, GRE Key, MPLS Label, etc.
	InnerProto  string  `json:"inner_protocol,omitempty"`
	PacketCount uint64  `json:"packet_count"`
	ByteCount   uint64  `json:"byte_count"`
	FirstSeen   float64 `json:"first_seen"`
	LastSeen    float64 `json:"last_seen"`
	// DPI-enhanced fields for VPN tunnels
	DetectionMethod string `json:"detection_method,omitempty"` // "DPI", "Port-based", "Signature"
	Confidence      string `json:"confidence,omitempty"`       // "High", "Medium", "Low"
	ProtocolVersion string `json:"protocol_version,omitempty"` // Protocol version if detected
	SessionState    string `json:"session_state,omitempty"`    // "Handshake", "Established", "Data"
	IsAuthorized    bool   `json:"is_authorized,omitempty"`    // For SD-WAN security validation
	// SD-WAN specific fields
	SDWANPath string `json:"sdwan_path,omitempty"` // Wireshark filter for this tunnel
}

// PacketLossMetrics contains the TCP retransmission statistics gathered by
// pkg/detectors/packet_loss.go.
//
// LEGACY NAMES: PacketsLost, LossPercentage (and TotalPacketsReceived, which is
// TotalPacketsSent - PacketsLost) are kept for JSON/API compatibility, but they
// are derived from OBSERVED TCP RETRANSMISSIONS, not from confirmed loss. A
// retransmission shows a segment was sent again; it does not establish that the
// original was lost, where, or why (it may be a delayed ACK or a spurious
// retransmission). LossPercentage equals RetransmissionRate: retransmitted data
// segments as a percentage of ALL captured packets. User-facing text must say
// "retransmissions observed", not "packets lost".
type PacketLossMetrics struct {
	TotalPacketsSent     uint64           `json:"total_packets_sent"`
	TotalPacketsReceived uint64           `json:"total_packets_received"`
	PacketsLost          uint64           `json:"packets_lost"`
	LossPercentage       float64          `json:"loss_percentage"`
	RetransmissionRate   float64          `json:"retransmission_rate"`
	OutOfOrderPackets    uint64           `json:"out_of_order_packets"`
	DuplicatePackets     uint64           `json:"duplicate_packets"`
	PerFlowLoss          []FlowPacketLoss `json:"per_flow_loss,omitempty"`
}

// FlowPacketLoss holds per-flow TCP retransmission counts under the same legacy
// names as PacketLossMetrics: PacketsLost is the flow's observed retransmission
// count, not confirmed loss.
type FlowPacketLoss struct {
	SrcIP          string  `json:"src_ip"`
	DstIP          string  `json:"dst_ip"`
	SrcPort        uint16  `json:"src_port"`
	DstPort        uint16  `json:"dst_port"`
	Protocol       string  `json:"protocol"`
	PacketsSent    uint64  `json:"packets_sent"`
	PacketsLost    uint64  `json:"packets_lost"`
	LossPercentage float64 `json:"loss_percentage"`
}

// SMBFlow represents SMB/CIFS protocol traffic
type SMBFlow struct {
	SrcIP       string  `json:"src_ip"`
	DstIP       string  `json:"dst_ip"`
	SrcPort     uint16  `json:"src_port"`
	DstPort     uint16  `json:"dst_port"`
	Version     string  `json:"version"` // SMB1, SMB2, SMB3
	Command     string  `json:"command,omitempty"`
	ShareName   string  `json:"share_name,omitempty"`
	FileName    string  `json:"file_name,omitempty"`
	PacketCount uint64  `json:"packet_count"`
	ByteCount   uint64  `json:"byte_count"`
	FirstSeen   float64 `json:"first_seen"`
	LastSeen    float64 `json:"last_seen"`
	IsEncrypted bool    `json:"is_encrypted"`
	Status      string  `json:"status,omitempty"`
}

// LDAPFlow represents LDAP protocol traffic
type LDAPFlow struct {
	SrcIP       string  `json:"src_ip"`
	DstIP       string  `json:"dst_ip"`
	SrcPort     uint16  `json:"src_port"`
	DstPort     uint16  `json:"dst_port"`
	Operation   string  `json:"operation"` // bind, search, modify, etc.
	BaseDN      string  `json:"base_dn,omitempty"`
	Filter      string  `json:"filter,omitempty"`
	PacketCount uint64  `json:"packet_count"`
	ByteCount   uint64  `json:"byte_count"`
	FirstSeen   float64 `json:"first_seen"`
	LastSeen    float64 `json:"last_seen"`
	IsSecure    bool    `json:"is_secure"` // LDAPS
	ResultCode  int     `json:"result_code,omitempty"`
}

// KerberosFlow represents Kerberos authentication traffic
type KerberosFlow struct {
	SrcIP       string  `json:"src_ip"`
	DstIP       string  `json:"dst_ip"`
	SrcPort     uint16  `json:"src_port"`
	DstPort     uint16  `json:"dst_port"`
	MessageType string  `json:"message_type"` // AS-REQ, AS-REP, TGS-REQ, TGS-REP, AP-REQ, AP-REP
	Realm       string  `json:"realm,omitempty"`
	Principal   string  `json:"principal,omitempty"`
	Service     string  `json:"service,omitempty"`
	PacketCount uint64  `json:"packet_count"`
	ByteCount   uint64  `json:"byte_count"`
	FirstSeen   float64 `json:"first_seen"`
	LastSeen    float64 `json:"last_seen"`
	ErrorCode   int     `json:"error_code,omitempty"`
	EncType     string  `json:"enc_type,omitempty"` // Encryption type
}

// BaselineComparison contains baseline comparison metrics
type BaselineComparison struct {
	HasBaseline          bool                `json:"has_baseline"`
	BaselineFile         string              `json:"baseline_file,omitempty"`
	IsNormal             bool                `json:"is_normal"`
	Deviations           []BaselineDeviation `json:"deviations,omitempty"`
	TrafficVolumeChange  float64             `json:"traffic_volume_change"` // Percentage change
	ProtocolDistribution map[string]float64  `json:"protocol_distribution,omitempty"`
	BaselineMetrics      *BaselineMetrics    `json:"baseline_metrics,omitempty"`
	CurrentMetrics       *BaselineMetrics    `json:"current_metrics,omitempty"`
	Recommendation       string              `json:"recommendation,omitempty"`
}

// BaselineDeviation represents a deviation from baseline
type BaselineDeviation struct {
	Metric      string  `json:"metric"`
	Baseline    float64 `json:"baseline"`
	Current     float64 `json:"current"`
	Change      float64 `json:"change"`   // Percentage change
	Severity    string  `json:"severity"` // "Low", "Medium", "High", "Critical"
	Description string  `json:"description"`
}

// BaselineMetrics contains key metrics for baseline comparison
type BaselineMetrics struct {
	TotalPackets       uint64            `json:"total_packets"`
	TotalBytes         uint64            `json:"total_bytes"`
	AvgPacketSize      float64           `json:"avg_packet_size"`
	PacketRate         float64           `json:"packet_rate"` // packets per second
	RetransmissionRate float64           `json:"retransmission_rate"`
	DNSQueries         uint64            `json:"dns_queries"`
	HTTPRequests       uint64            `json:"http_requests"`
	TLSConnections     uint64            `json:"tls_connections"`
	UniqueIPs          int               `json:"unique_ips"`
	TopProtocols       map[string]uint64 `json:"top_protocols"`
}

// SDWANVendor represents a detected SD-WAN vendor
type SDWANVendor struct {
	Name        string  `json:"name"`
	Confidence  string  `json:"confidence"`
	DetectedBy  string  `json:"detected_by"`
	PacketCount int     `json:"packet_count"`
	FirstSeen   float64 `json:"first_seen"`
	LastSeen    float64 `json:"last_seen"`
}

// LANProtocolFindings contains all LAN protocol detection results
type LANProtocolFindings struct {
	VRRPSessions []VRRPFinding `json:"vrrp_sessions,omitempty"`
	CDPDevices   []CDPFinding  `json:"cdp_devices,omitempty"`
	LLDPDevices  []LLDPFinding `json:"lldp_devices,omitempty"`
	HSRPGroups   []HSRPFinding `json:"hsrp_groups,omitempty"`
	STPBridges   []STPFinding  `json:"stp_bridges,omitempty"`
}

// VRRPFinding represents a detected VRRP session
type VRRPFinding struct {
	VirtualRouterID uint8    `json:"virtual_router_id"`
	Priority        uint8    `json:"priority"`
	State           string   `json:"state"`
	MasterIP        string   `json:"master_ip"`
	VirtualIPs      []string `json:"virtual_ips"`
	AuthType        uint8    `json:"auth_type"`
	AdvertInterval  uint8    `json:"advert_interval"`
	FirstSeen       string   `json:"first_seen"`
	LastSeen        string   `json:"last_seen"`
	PacketCount     uint64   `json:"packet_count"`
	TransitionCount int      `json:"transition_count"`
	IsFlapping      bool     `json:"is_flapping"`
	FlappingReason  string   `json:"flapping_reason,omitempty"`
}

// CDPFinding represents a Cisco Discovery Protocol device
type CDPFinding struct {
	DeviceID     string `json:"device_id"`
	IPAddress    string `json:"ip_address"`
	Platform     string `json:"platform"`
	Capabilities string `json:"capabilities"`
	SoftwareVer  string `json:"software_version"`
	PortID       string `json:"port_id"`
	FirstSeen    string `json:"first_seen"`
	LastSeen     string `json:"last_seen"`
	PacketCount  uint64 `json:"packet_count"`
}

// LLDPFinding represents an LLDP device
type LLDPFinding struct {
	ChassisID    string `json:"chassis_id"`
	PortID       string `json:"port_id"`
	SystemName   string `json:"system_name"`
	SystemDesc   string `json:"system_desc"`
	Capabilities string `json:"capabilities"`
	ManagementIP string `json:"management_ip"`
	FirstSeen    string `json:"first_seen"`
	LastSeen     string `json:"last_seen"`
	PacketCount  uint64 `json:"packet_count"`
}

// HSRPFinding represents an HSRP group
type HSRPFinding struct {
	GroupNumber   uint16 `json:"group_number"`
	State         string `json:"state"`
	Priority      uint8  `json:"priority"`
	VirtualIP     string `json:"virtual_ip"`
	ActiveRouter  string `json:"active_router"`
	StandbyRouter string `json:"standby_router"`
	FirstSeen     string `json:"first_seen"`
	LastSeen      string `json:"last_seen"`
	PacketCount   uint64 `json:"packet_count"`
}

// STPFinding represents a Spanning Tree Protocol bridge
type STPFinding struct {
	BridgeID     string `json:"bridge_id"`
	RootBridgeID string `json:"root_bridge_id"`
	RootCost     uint32 `json:"root_cost"`
	PortID       uint16 `json:"port_id"`
	FirstSeen    string `json:"first_seen"`
	LastSeen     string `json:"last_seen"`
	PacketCount  uint64 `json:"packet_count"`
}

// DHCPFinding represents a DHCP-related finding
type DHCPFinding struct {
	Timestamp    float64  `json:"timestamp"`
	Type         string   `json:"type"` // "Rogue Server", "Starvation", "NAK Storm", "Lease Exhaustion"
	ServerIP     string   `json:"server_ip,omitempty"`
	ClientMAC    string   `json:"client_mac,omitempty"`
	OfferedIP    string   `json:"offered_ip,omitempty"`
	Severity     string   `json:"severity"`
	Description  string   `json:"description"`
	PacketCount  int      `json:"packet_count"`
	ServerMAC    string   `json:"server_mac,omitempty"`
	KnownServers []string `json:"known_servers,omitempty"`
}

// NTPFinding represents an NTP-related finding
type NTPFinding struct {
	Timestamp    float64 `json:"timestamp"`
	Type         string  `json:"type"` // "Amplification", "Stratum Change", "Time Drift", "Monlist Response"
	SourceIP     string  `json:"source_ip"`
	DestIP       string  `json:"dest_ip,omitempty"`
	Stratum      uint8   `json:"stratum,omitempty"`
	Severity     string  `json:"severity"`
	Description  string  `json:"description"`
	PacketCount  int     `json:"packet_count"`
	ResponseSize int     `json:"response_size,omitempty"`
}

// DNSTunnelingFinding represents suspected DNS tunneling activity
type DNSTunnelingFinding struct {
	Timestamp        float64  `json:"timestamp"`
	SourceIP         string   `json:"source_ip"`
	ServerIP         string   `json:"server_ip"`
	Domain           string   `json:"domain"`
	Severity         string   `json:"severity"`
	Description      string   `json:"description"`
	AvgQueryLength   float64  `json:"avg_query_length"`
	QueryCount       int      `json:"query_count"`
	UniqueSubdomains int      `json:"unique_subdomains"`
	EntropyScore     float64  `json:"entropy_score"`
	SampleQueries    []string `json:"sample_queries,omitempty"`
}

// C2BeaconingFinding represents suspected C2 beaconing activity
type C2BeaconingFinding struct {
	Timestamp       float64 `json:"timestamp"`
	SourceIP        string  `json:"source_ip"`
	DestIP          string  `json:"dest_ip"`
	DestPort        uint16  `json:"dest_port"`
	Protocol        string  `json:"protocol"`
	Severity        string  `json:"severity"`
	Description     string  `json:"description"`
	BeaconInterval  float64 `json:"beacon_interval_sec"`
	IntervalJitter  float64 `json:"interval_jitter_pct"`
	ConnectionCount int     `json:"connection_count"`
	AvgPayloadSize  int     `json:"avg_payload_size"`
	PayloadVariance float64 `json:"payload_variance"`
	Confidence      string  `json:"confidence"`
}

// TCPWindowFinding represents a TCP window size issue
type TCPWindowFinding struct {
	Timestamp   float64 `json:"timestamp"`
	SrcIP       string  `json:"src_ip"`
	DstIP       string  `json:"dst_ip"`
	SrcPort     uint16  `json:"src_port"`
	DstPort     uint16  `json:"dst_port"`
	Type        string  `json:"type"` // "Zero Window", "Small Window", "Window Full"
	WindowSize  uint16  `json:"window_size"`
	Severity    string  `json:"severity"`
	Description string  `json:"description"`
	Count       int     `json:"count"`
}

// TCPOutOfOrderFlow represents a flow with significant out-of-order packets
type TCPOutOfOrderFlow struct {
	SrcIP           string  `json:"src_ip"`
	DstIP           string  `json:"dst_ip"`
	SrcPort         uint16  `json:"src_port"`
	DstPort         uint16  `json:"dst_port"`
	OutOfOrderCount int     `json:"out_of_order_count"`
	TotalPackets    int     `json:"total_packets"`
	Percentage      float64 `json:"percentage"`
	Severity        string  `json:"severity"`
}

// VendorDPIIssue represents a vendor-specific issue detected via deep packet inspection
type VendorDPIIssue struct {
	Vendor          string  `json:"vendor"`
	IssueID         string  `json:"issue_id"`
	Title           string  `json:"title"`
	Description     string  `json:"description"`
	BusinessImpact  string  `json:"business_impact"`
	Severity        string  `json:"severity"`
	Confidence      float64 `json:"confidence"`
	Category        string  `json:"category"`
	RootCause       string  `json:"root_cause"`
	WiresharkFilter string  `json:"wireshark_filter,omitempty"`
}

// UnsupportedLinkType counts packets skipped because their link type is not
// decoded by the analyzer.
type UnsupportedLinkType struct {
	LinkType int    `json:"link_type"` // as seen by the decoder (pcapng types >= 256 are truncated, e.g. 274 -> 18)
	Label    string `json:"label"`
	Packets  int    `json:"packets"`
}

// CaptureCompleteness describes what the analyzer could and could not examine.
// The causes are deliberately kept separate:
//   - PacketsUnsupported: read, but the link type is not supported (not analyzed)
//   - PacketsDecodeFailed: supported link type, but no link/network layer could be decoded
//   - PacketsSkipped: dropped from analysis by the analyzer's own skip/recovery path
//   - ReadErrors: the reader returned a non-EOF error (e.g. a truncated capture file)
//
// These are facts about the analysis input. They are not statements about packet
// loss in the network, and no percentage threshold is applied anywhere.
type CaptureCompleteness struct {
	PacketsRead          int                   `json:"packets_read"`
	PacketsDecoded       int                   `json:"packets_decoded"`
	PacketsUnsupported   int                   `json:"packets_unsupported"`
	PacketsDecodeFailed  int                   `json:"packets_decode_failed"`
	PacketsSkipped       int                   `json:"packets_skipped"`
	ReadErrors           int                   `json:"read_errors"`
	UnsupportedLinkTypes []UnsupportedLinkType `json:"unsupported_link_types,omitempty"` // sorted by link type
}

// IsPartial reports whether any provable analysis limitation exists.
func (c *CaptureCompleteness) IsPartial() bool {
	return c != nil && (c.PacketsUnsupported > 0 || c.PacketsDecodeFailed > 0 ||
		c.PacketsSkipped > 0 || c.ReadErrors > 0)
}

// Analysis status values (orthogonal to the health levels).
const (
	AnalysisStatusNoData = "no_data"

	NoDataReasonEmptyCapture         = "empty_capture"          // the capture file contains no packets
	NoDataReasonFilterMatchedNothing = "filter_matched_nothing" // packets exist, the user's filter excluded all of them
)

// IsNoData reports whether the analysis had no evidence to judge. A NO_DATA
// report must never be presented as GOOD (or any other health level).
func (r *TriageReport) IsNoData() bool {
	return r != nil && r.AnalysisStatus == AnalysisStatusNoData
}

// ARP conflict classifications.
const (
	// ARPConflictVirtualGateway: all MACs that answered for the IP are virtual redundant-
	// gateway MACs (VRRP/CARP, HSRP, GLBP). Such protocols answer ARP with these addresses
	// by design (GLBP load-balances with several; failover moves the IP between them).
	ARPConflictVirtualGateway = "virtual_gateway_macs"
	// ARPConflictUnexplained: the capture does not explain the differing MACs.
	ARPConflictUnexplained = "unexplained"
)

// VirtualGatewayMACKind names the redundancy protocol whose documented virtual-MAC range
// contains mac ("VRRP/CARP", "HSRP", "HSRPv2", "GLBP"), or "" when it is in none of them.
// mac is "aa:bb:cc:dd:ee:ff" (any case). A match shows the address is in the range, not
// that a genuine redundancy group owns it.
func VirtualGatewayMACKind(mac string) string {
	var b [6]byte
	if n, err := fmt.Sscanf(strings.ToLower(mac), "%02x:%02x:%02x:%02x:%02x:%02x", &b[0], &b[1], &b[2], &b[3], &b[4], &b[5]); n != 6 || err != nil {
		return ""
	}
	switch {
	case b[0] == 0x00 && b[1] == 0x00 && b[2] == 0x5e && b[3] == 0x00 && b[4] == 0x01:
		return "VRRP/CARP"
	case b[0] == 0x00 && b[1] == 0x00 && b[2] == 0x0c && b[3] == 0x07 && b[4] == 0xac:
		return "HSRP"
	case b[0] == 0x00 && b[1] == 0x00 && b[2] == 0x0c && b[3] == 0x9f && b[4]&0xf0 == 0xf0:
		return "HSRPv2"
	case b[0] == 0x00 && b[1] == 0x07 && b[2] == 0xb4 && b[3] == 0x00:
		return "GLBP"
	}
	return ""
}

// Classify sets Classification and Explanation from the MACs recorded so far.
func (c *ARPConflict) Classify() {
	macs := append([]string{c.MAC1, c.MAC2}, c.OtherMACs...)
	kinds := map[string]bool{}
	all := true
	for _, m := range macs {
		k := VirtualGatewayMACKind(m)
		if k == "" {
			all = false
			break
		}
		kinds[k] = true
	}
	if !all {
		c.Classification = ARPConflictUnexplained
		c.Explanation = "Replies for this IP address came from different MAC addresses. The capture shows the replies, not why: a duplicate IP address, " +
			"a device or network-card replacement, proxy ARP, a redundancy protocol, address translation or spoofing would all look like this."
		return
	}
	var names []string
	for _, k := range []string{"GLBP", "HSRP", "HSRPv2", "VRRP/CARP"} {
		if kinds[k] {
			names = append(names, k)
		}
	}
	c.Classification = ARPConflictVirtualGateway
	c.Explanation = "Every MAC address that answered for this IP is in a documented virtual redundant-gateway range (" + strings.Join(names, ", ") +
		"). Those protocols answer ARP with such addresses by design (GLBP load-balances with several; a failover moves the IP between them), so this is " +
		"consistent with a redundant gateway rather than a duplicate IP address. The capture cannot verify that the addresses belong to a genuine group."
}

// UnexplainedARPConflicts counts conflicts not classified as virtual-gateway MACs.
// Reports and tests that predate the classification (empty value) count as unexplained,
// which keeps their behaviour unchanged.
func (r *TriageReport) UnexplainedARPConflicts() int {
	n := 0
	for _, c := range r.ARPConflicts {
		if c.Classification != ARPConflictVirtualGateway {
			n++
		}
	}
	return n
}
