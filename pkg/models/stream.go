package models

import (
	"time"
)

// StreamData represents reassembled stream data for a TCP/UDP conversation
type StreamData struct {
	FlowID      string          `json:"flow_id"`
	SrcIP       string          `json:"src_ip"`
	SrcPort     uint16          `json:"src_port"`
	DstIP       string          `json:"dst_ip"`
	DstPort     uint16          `json:"dst_port"`
	Protocol    string          `json:"protocol"`              // "TCP" or "UDP"
	Application string          `json:"application,omitempty"` // "HTTP", "TLS", "SIP", "DNS", etc.
	ServerName  string          `json:"server_name,omitempty"` // TLS SNI or HTTP Host
	Segments    []StreamSegment `json:"segments"`
	TotalBytes  uint64          `json:"total_bytes"`
	PacketCount uint64          `json:"packet_count"`
	FirstSeen   time.Time       `json:"first_seen"`
	LastSeen    time.Time       `json:"last_seen"`
	Duration    float64         `json:"duration_seconds"`
	IsComplete  bool            `json:"is_complete"`
	TruncatedAt int             `json:"truncated_at,omitempty"` // Byte offset where truncation occurred
}

// StreamSegment represents a single segment/direction in the stream
type StreamSegment struct {
	Direction     string    `json:"direction"` // "client_to_server" or "server_to_client"
	Timestamp     time.Time `json:"timestamp"`
	SeqNum        uint32    `json:"seq_num,omitempty"` // For TCP
	Data          []byte    `json:"-"`                 // Raw bytes (not serialized to JSON)
	DataHex       string    `json:"data_hex,omitempty"`
	DataASCII     string    `json:"data_ascii,omitempty"`
	DataDecoded   string    `json:"data_decoded,omitempty"`  // Protocol-decoded content
	PlainEnglish  string    `json:"plain_english,omitempty"` // Human-readable summary
	Length        int       `json:"length"`
	IsRetransmit  bool      `json:"is_retransmit,omitempty"`
	IsOutOfOrder  bool      `json:"is_out_of_order,omitempty"`
	HasReset      bool      `json:"has_reset,omitempty"`
	GapFromPrev   float64   `json:"gap_from_prev,omitempty"` // Seconds since previous segment
	AnomalyReason string    `json:"anomaly_reason,omitempty"`
}

// StreamReassemblyState tracks state for stream reassembly
type StreamReassemblyState struct {
	Streams         map[string]*StreamData
	MaxBytesPerFlow int // Limit per direction (default 10KB)
	MaxFlowsToTrack int // Limit total flows tracked
}

// NewStreamReassemblyState creates a new stream reassembly state
func NewStreamReassemblyState() *StreamReassemblyState {
	return &StreamReassemblyState{
		Streams:         make(map[string]*StreamData),
		MaxBytesPerFlow: 10 * 1024, // 10KB per direction
		MaxFlowsToTrack: 1000,      // Track up to 1000 flows
	}
}

// StreamExportRequest represents a request to export a specific stream as PCAP
type StreamExportRequest struct {
	FlowID      string `json:"flow_id"`
	SrcIP       string `json:"src_ip"`
	SrcPort     uint16 `json:"src_port"`
	DstIP       string `json:"dst_ip"`
	DstPort     uint16 `json:"dst_port"`
	Protocol    string `json:"protocol"`
	Description string `json:"description,omitempty"`
}

// BandwidthTimeSeries represents time-series bandwidth data
type BandwidthTimeSeries struct {
	Buckets         []BandwidthBucket `json:"buckets"`
	IntervalMs      int64             `json:"interval_ms"`
	StartTime       time.Time         `json:"start_time"`
	EndTime         time.Time         `json:"end_time"`
	PeakBytesPerSec uint64            `json:"peak_bytes_per_sec"`
	AvgBytesPerSec  uint64            `json:"avg_bytes_per_sec"`
	TotalBytes      uint64            `json:"total_bytes"`
	TotalPackets    uint64            `json:"total_packets"`
}

// BandwidthBucket represents a single time bucket for bandwidth analysis
type BandwidthBucket struct {
	Timestamp     time.Time         `json:"timestamp"`
	TimestampUnix float64           `json:"timestamp_unix"`
	BytesIn       uint64            `json:"bytes_in"`
	BytesOut      uint64            `json:"bytes_out"`
	PacketsIn     uint64            `json:"packets_in"`
	PacketsOut    uint64            `json:"packets_out"`
	ActiveFlows   int               `json:"active_flows"`
	TopProtocol   string            `json:"top_protocol,omitempty"`
	TopTalkerSrc  string            `json:"top_talker_src,omitempty"`
	TopTalkerDst  string            `json:"top_talker_dst,omitempty"`
	ProtocolBytes map[string]uint64 `json:"protocol_bytes,omitempty"`
}

// PlainEnglishSummary contains human-readable summaries for the report
type PlainEnglishSummary struct {
	OverallHealth     string   `json:"overall_health"`     // "Healthy", "Warning", "Critical"
	HealthIcon        string   `json:"health_icon"`        // Emoji icon
	HealthColor       string   `json:"health_color"`       // CSS color class
	KeyFindings       []string `json:"key_findings"`       // Top 5 findings in plain English
	QuickActions      []string `json:"quick_actions"`      // Recommended next steps
	TrafficGaps       []string `json:"traffic_gaps"`       // Notable gaps in traffic
	PerformanceIssues []string `json:"performance_issues"` // Performance-related summaries
	SecurityAlerts    []string `json:"security_alerts"`    // Security-related summaries
}

// StreamViewData represents stream data formatted for HTML display
type StreamViewData struct {
	FlowID          string              `json:"flow_id"`
	Label           string              `json:"label"` // e.g., "192.168.1.10:54321 → 203.0.113.5:443 (TLS)"
	SrcIP           string              `json:"src_ip"`
	SrcPort         uint16              `json:"src_port"`
	DstIP           string              `json:"dst_ip"`
	DstPort         uint16              `json:"dst_port"`
	Protocol        string              `json:"protocol"`
	Application     string              `json:"application"`
	Duration        string              `json:"duration"`
	TotalBytes      string              `json:"total_bytes"`
	PacketCount     uint64              `json:"packet_count"`
	Segments        []StreamSegmentView `json:"segments"`
	ExportFilename  string              `json:"export_filename"`
	WiresharkFilter string              `json:"wireshark_filter"`
}

// StreamSegmentView represents a stream segment formatted for HTML display
type StreamSegmentView struct {
	Direction      string `json:"direction"`       // "→" or "←"
	DirectionCSS   string `json:"direction_css"`   // "client-to-server" or "server-to-client"
	DirectionLabel string `json:"direction_label"` // "Client → Server" or "Server → Client"
	Timestamp      string `json:"timestamp"`
	TimestampRel   string `json:"timestamp_rel"` // Relative to stream start
	PlainEnglish   string `json:"plain_english"` // Human-readable summary (e.g., "TLS 1.2 ApplicationData")
	DataSummary    string `json:"data_summary"`  // Clean summary like "[Binary data: 164 bytes]"
	DataPreview    string `json:"data_preview"`  // First 100 chars (for text)
	DataFull       string `json:"data_full"`     // Full ASCII representation
	DataHex        string `json:"data_hex"`      // Hex dump
	DataDecoded    string `json:"data_decoded"`  // Protocol-decoded (if available)
	Length         int    `json:"length"`
	LengthDisplay  string `json:"length_display"`  // Human-readable size
	IsAnomaly      bool   `json:"is_anomaly"`      // Has retransmit, gap, reset, etc.
	AnomalyIcon    string `json:"anomaly_icon"`    // Icon for anomaly type
	AnomalyReason  string `json:"anomaly_reason"`  // Why it's flagged
	ShowHexToggle  bool   `json:"show_hex_toggle"` // Whether to show hex dump toggle
}
