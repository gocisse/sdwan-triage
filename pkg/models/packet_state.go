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
	DeviceFingerprints map[string]*TCPFingerprint
	AppStats           map[string]*AppCategory
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
		DeviceFingerprints: make(map[string]*TCPFingerprint),
		AppStats:           make(map[string]*AppCategory),
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
