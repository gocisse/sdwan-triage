package models

import (
	"time"

	"github.com/google/gopacket"
)

// TCPFlowState tracks state for TCP flow analysis
type TCPFlowState struct {
	LastSeq    uint32
	LastAck    uint32
	SeqSeen    map[uint32]bool
	RTTSamples []float64
	SentTimes  map[uint32]time.Time
	TotalBytes uint64
}

// UDPFlowState tracks state for UDP flow analysis
type UDPFlowState struct {
	TotalBytes uint64
}

// HTTPRequest stores parsed HTTP request details
type HTTPRequest struct {
	Method    string
	Host      string
	Path      string
	Timestamp time.Time
}

// TCPFingerprint stores TCP/IP stack characteristics for OS detection
type TCPFingerprint struct {
	WindowSize uint16
	TTL        uint8
	MSS        uint16
	HasTS      bool
	HasSACK    bool
	HasWS      bool
	DFFlag     bool
}

// AnalysisState holds all state needed for packet analysis
type AnalysisState struct {
	SynSent            map[string]gopacket.Packet
	SynAckReceived     map[string]bool
	ARPIPToMAC         map[string]string
	DNSQueries         map[uint16]string
	TCPFlows           map[string]*TCPFlowState
	UDPFlows           map[string]*UDPFlowState
	HTTPRequests       map[string]*HTTPRequest
	TLSSNICache        map[string]string
	TLSFlowsSeen       map[string]bool
	HTTP2FlowsSeen     map[string]bool
	DeviceFingerprints map[string]*TCPFingerprint
	AppStats           map[string]*AppCategory

	// Security state tracking
	SecurityState *SecurityState
}

// SecurityState holds state for security analysis
type SecurityState struct {
	// DDoS detection
	SYNCountPerIP     map[string]*FloodCounter
	UDPCountPerIP     map[string]*FloodCounter
	ICMPCountPerIP    map[string]*FloodCounter
	LastResetTime     time.Time
	ResetIntervalSecs float64

	// Port scan detection
	ScannedPortsPerIP    map[string]map[string]map[uint16]bool // srcIP -> dstIP -> ports
	ScanAttemptsPerIP    map[string]int
	ConnectionsPerIPPair map[string]int

	// ICMP tracking
	ICMPStats map[string]*ICMPStats
}

// FloodCounter tracks packet counts for flood detection
type FloodCounter struct {
	Count     int
	FirstSeen time.Time
	LastSeen  time.Time
	TargetIPs map[string]int
}

// ICMPStats tracks ICMP statistics per source IP
type ICMPStats struct {
	TypeCounts map[uint8]int
	TotalCount int
	FirstSeen  time.Time
	LastSeen   time.Time
}

// NewAnalysisState creates a new initialized analysis state
func NewAnalysisState() *AnalysisState {
	return &AnalysisState{
		SynSent:            make(map[string]gopacket.Packet),
		SynAckReceived:     make(map[string]bool),
		ARPIPToMAC:         make(map[string]string),
		DNSQueries:         make(map[uint16]string),
		TCPFlows:           make(map[string]*TCPFlowState),
		UDPFlows:           make(map[string]*UDPFlowState),
		HTTPRequests:       make(map[string]*HTTPRequest),
		TLSSNICache:        make(map[string]string),
		TLSFlowsSeen:       make(map[string]bool),
		HTTP2FlowsSeen:     make(map[string]bool),
		DeviceFingerprints: make(map[string]*TCPFingerprint),
		AppStats:           make(map[string]*AppCategory),
		SecurityState:      NewSecurityState(),
	}
}

// NewSecurityState creates a new initialized security state
func NewSecurityState() *SecurityState {
	return &SecurityState{
		SYNCountPerIP:        make(map[string]*FloodCounter),
		UDPCountPerIP:        make(map[string]*FloodCounter),
		ICMPCountPerIP:       make(map[string]*FloodCounter),
		LastResetTime:        time.Now(),
		ResetIntervalSecs:    10.0,
		ScannedPortsPerIP:    make(map[string]map[string]map[uint16]bool),
		ScanAttemptsPerIP:    make(map[string]int),
		ConnectionsPerIPPair: make(map[string]int),
		ICMPStats:            make(map[string]*ICMPStats),
	}
}

// NewFloodCounter creates a new flood counter
func NewFloodCounter(t time.Time) *FloodCounter {
	return &FloodCounter{
		Count:     1,
		FirstSeen: t,
		LastSeen:  t,
		TargetIPs: make(map[string]int),
	}
}

// Filter holds packet filtering criteria
type Filter struct {
	SrcIP    string
	DstIP    string
	Service  string
	Protocol string
}

// IsEmpty returns true if no filters are set or filter is nil
func (f *Filter) IsEmpty() bool {
	if f == nil {
		return true
	}
	return f.SrcIP == "" && f.DstIP == "" && f.Service == "" && f.Protocol == ""
}
