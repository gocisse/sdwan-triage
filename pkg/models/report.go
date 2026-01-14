package models

import "time"

// TriageReport contains all detected network anomalies and analysis results
type TriageReport struct {
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
	ICMPAnalysis    []ICMPFinding   `json:"icmp_analysis,omitempty"`
	VoIPAnalysis    *VoIPAnalysis   `json:"voip_analysis,omitempty"`
	TunnelAnalysis  []TunnelFinding `json:"tunnel_analysis,omitempty"`
	SDWANVendors    []SDWANVendor   `json:"sdwan_vendors,omitempty"`
	LocationSummary map[string]int  `json:"location_summary,omitempty"`
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

type DNSAnomaly struct {
	Timestamp float64 `json:"timestamp"`
	Query     string  `json:"query"`
	AnswerIP  string  `json:"answer_ip"`
	ServerIP  string  `json:"server_ip"`
	ServerMAC string  `json:"server_mac"`
	Reason    string  `json:"reason"`
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

// DDoSFinding represents a detected DDoS attack pattern
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
	AvgJitter        float64         `json:"avg_jitter_ms"`
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
	SSRC        uint32  `json:"ssrc"`
	SrcIP       string  `json:"src_ip"`
	DstIP       string  `json:"dst_ip"`
	PayloadType string  `json:"payload_type"`
	PacketCount uint64  `json:"packet_count"`
	ByteCount   uint64  `json:"byte_count"`
	LostPackets uint64  `json:"lost_packets"`
	Jitter      float64 `json:"jitter_ms"`
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

// SDWANVendor represents a detected SD-WAN vendor
type SDWANVendor struct {
	Name        string  `json:"name"`
	Confidence  string  `json:"confidence"`
	DetectedBy  string  `json:"detected_by"`
	PacketCount int     `json:"packet_count"`
	FirstSeen   float64 `json:"first_seen"`
	LastSeen    float64 `json:"last_seen"`
}
