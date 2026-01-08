package models

import "time"

// TriageReport contains all detected network anomalies and analysis results
type TriageReport struct {
	DNSAnomalies         []DNSAnomaly           `json:"dns_anomalies"`
	TCPRetransmissions   []TCPFlow              `json:"tcp_retransmissions"`
	FailedHandshakes     []TCPFlow              `json:"failed_handshakes"`
	TCPHandshakes        TCPHandshakeAnalysis   `json:"tcp_handshakes"`
	ARPConflicts         []ARPConflict          `json:"arp_conflicts"`
	HTTPErrors           []HTTPError            `json:"http_errors"`
	TLSCerts             []TLSCertInfo          `json:"tls_certs"`
	HTTP2Flows           []TCPFlow              `json:"http2_flows"`
	QUICFlows            []UDPFlow              `json:"quic_flows"`
	TrafficAnalysis      []TrafficFlow          `json:"traffic_analysis"`
	ApplicationBreakdown map[string]AppCategory `json:"application_breakdown"`
	SuspiciousTraffic    []SuspiciousFlow       `json:"suspicious_traffic"`
	RTTAnalysis          []RTTFlow              `json:"rtt_analysis"`
	DeviceFingerprinting []DeviceFingerprint    `json:"device_fingerprinting"`
	BandwidthReport      BandwidthReport        `json:"bandwidth_report"`
	Timeline             []TimelineEvent        `json:"timeline"`
	DNSDetails           []DNSRecord            `json:"dns_details"`
	BGPHijackIndicators  []BGPIndicator         `json:"bgp_hijack_indicators,omitempty"`
	QoSAnalysis          *QoSReport             `json:"qos_analysis,omitempty"`
	AppIdentification    []IdentifiedApp        `json:"app_identification,omitempty"`
	TotalBytes           uint64                 `json:"total_bytes"`
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
	SrcIP     string  `json:"src_ip"`
	SrcPort   uint16  `json:"src_port"`
	DstIP     string  `json:"dst_ip"`
	DstPort   uint16  `json:"dst_port"`
	Timestamp float64 `json:"timestamp"`
	Count     int     `json:"count"`
}

// TCPHandshakeAnalysis contains TCP handshake analysis results
type TCPHandshakeAnalysis struct {
	SYNFlows                []TCPHandshakeFlow `json:"syn_flows"`
	SYNACKFlows             []TCPHandshakeFlow `json:"synack_flows"`
	SuccessfulHandshakes    []TCPHandshakeFlow `json:"successful_handshakes"`
	FailedHandshakeAttempts []TCPHandshakeFlow `json:"failed_handshake_attempts"`
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
