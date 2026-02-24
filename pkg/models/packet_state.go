package models

import (
	"sync"
	"time"

	lru "github.com/hashicorp/golang-lru/v2"
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

// Cache configuration defaults
const (
	DefaultMaxFlows      = 100000 // 100k concurrent flows
	DefaultMaxSYNEntries = 50000  // 50k pending SYN states
	DefaultMaxSNICache   = 10000  // 10k TLS SNI entries
	DefaultMaxDevices    = 5000   // 5k device fingerprints
)

// AnalysisState holds all state needed for packet analysis
// Uses bounded LRU caches to prevent OOM on large PCAP files
type AnalysisState struct {
	mu sync.RWMutex // Protects concurrent access to maps

	// Bounded LRU caches (evict oldest when full)
	tcpFlowsCache  *lru.Cache[string, *TCPFlowState]
	udpFlowsCache  *lru.Cache[string, *UDPFlowState]
	tlsSNICache    *lru.Cache[string, string]
	deviceFPCache  *lru.Cache[string, *TCPFingerprint]
	synSentCache   *lru.Cache[string, time.Time] // Changed: store timestamp only, not packet
	synAckReceived map[string]bool               // Keep as map (cleared on handshake complete)

	// Unbounded maps (relatively small or short-lived)
	ARPIPToMAC     map[string]string
	DNSQueries     map[uint16]string
	HTTPRequests   map[string]*HTTPRequest
	TLSFlowsSeen   map[string]bool
	HTTP2FlowsSeen map[string]bool
	AppStats       map[string]*AppCategory

	// Configuration
	maxFlows      int
	maxSYNEntries int

	// Security state tracking
	SecurityState *SecurityState
}

// SecurityState holds state for security analysis
// All map access is protected by mu for concurrent detector execution.
type SecurityState struct {
	mu sync.RWMutex

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

// Lock acquires the write lock on SecurityState.
func (s *SecurityState) Lock() { s.mu.Lock() }

// Unlock releases the write lock on SecurityState.
func (s *SecurityState) Unlock() { s.mu.Unlock() }

// RLock acquires the read lock on SecurityState.
func (s *SecurityState) RLock() { s.mu.RLock() }

// RUnlock releases the read lock on SecurityState.
func (s *SecurityState) RUnlock() { s.mu.RUnlock() }

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

// NewAnalysisState creates a new initialized analysis state with default bounds
func NewAnalysisState() *AnalysisState {
	return NewBoundedAnalysisState(DefaultMaxFlows, DefaultMaxSYNEntries)
}

// NewBoundedAnalysisState creates a new analysis state with specified cache limits
// This is the recommended constructor for production use with large PCAP files
func NewBoundedAnalysisState(maxFlows, maxSYN int) *AnalysisState {
	// Create LRU caches (thread-safe)
	tcpCache, _ := lru.New[string, *TCPFlowState](maxFlows)
	udpCache, _ := lru.New[string, *UDPFlowState](maxFlows)
	sniCache, _ := lru.New[string, string](DefaultMaxSNICache)
	deviceCache, _ := lru.New[string, *TCPFingerprint](DefaultMaxDevices)
	synCache, _ := lru.New[string, time.Time](maxSYN)

	return &AnalysisState{
		tcpFlowsCache:  tcpCache,
		udpFlowsCache:  udpCache,
		tlsSNICache:    sniCache,
		deviceFPCache:  deviceCache,
		synSentCache:   synCache,
		synAckReceived: make(map[string]bool),
		ARPIPToMAC:     make(map[string]string),
		DNSQueries:     make(map[uint16]string),
		HTTPRequests:   make(map[string]*HTTPRequest),
		TLSFlowsSeen:   make(map[string]bool),
		HTTP2FlowsSeen: make(map[string]bool),
		AppStats:       make(map[string]*AppCategory),
		maxFlows:       maxFlows,
		maxSYNEntries:  maxSYN,
		SecurityState:  NewSecurityState(),
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

// TCPFlows accessors with thread-safety

// GetTCPFlow retrieves a TCP flow state, returns nil if not found
func (s *AnalysisState) GetTCPFlow(flowKey string) *TCPFlowState {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if val, ok := s.tcpFlowsCache.Get(flowKey); ok {
		return val
	}
	return nil
}

// SetTCPFlow stores a TCP flow state
func (s *AnalysisState) SetTCPFlow(flowKey string, state *TCPFlowState) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tcpFlowsCache.Add(flowKey, state)
}

// GetUDPFlow retrieves a UDP flow state, returns nil if not found
func (s *AnalysisState) GetUDPFlow(flowKey string) *UDPFlowState {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if val, ok := s.udpFlowsCache.Get(flowKey); ok {
		return val
	}
	return nil
}

// SetUDPFlow stores a UDP flow state
func (s *AnalysisState) SetUDPFlow(flowKey string, state *UDPFlowState) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.udpFlowsCache.Add(flowKey, state)
}

// GetTLSSNI retrieves a TLS SNI from cache
func (s *AnalysisState) GetTLSSNI(flowKey string) (string, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.tlsSNICache.Get(flowKey)
}

// SetTLSSNI stores a TLS SNI in cache
func (s *AnalysisState) SetTLSSNI(flowKey, sni string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tlsSNICache.Add(flowKey, sni)
}

// GetDeviceFingerprint retrieves a device fingerprint
func (s *AnalysisState) GetDeviceFingerprint(srcIP string) *TCPFingerprint {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if val, ok := s.deviceFPCache.Get(srcIP); ok {
		return val
	}
	return nil
}

// SetDeviceFingerprint stores a device fingerprint
func (s *AnalysisState) SetDeviceFingerprint(srcIP string, fp *TCPFingerprint) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.deviceFPCache.Add(srcIP, fp)
}

// SynSent accessors - now stores timestamp instead of packet

// MarkSynSent records a SYN was sent at the given timestamp
func (s *AnalysisState) MarkSynSent(flowKey string, timestamp time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.synSentCache.Add(flowKey, timestamp)
}

// GetSynSent checks if a SYN was sent, returns the timestamp and whether it exists
func (s *AnalysisState) GetSynSent(flowKey string) (time.Time, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.synSentCache.Get(flowKey)
}

// DeleteSynSent removes a SYN entry (after handshake complete or failed)
func (s *AnalysisState) DeleteSynSent(flowKey string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.synSentCache.Remove(flowKey)
}

// SynAckReceived accessors

// MarkSynAckReceived marks that a SYN-ACK was received
func (s *AnalysisState) MarkSynAckReceived(flowKey string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.synAckReceived[flowKey] = true
}

// HasSynAckReceived checks if a SYN-ACK was received
func (s *AnalysisState) HasSynAckReceived(flowKey string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.synAckReceived[flowKey]
}

// DeleteSynAckReceived removes a SYN-ACK entry
func (s *AnalysisState) DeleteSynAckReceived(flowKey string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.synAckReceived, flowKey)
}

// CacheStats returns statistics about cache usage
func (s *AnalysisState) CacheStats() map[string]interface{} {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return map[string]interface{}{
		"tcp_flows_size":      s.tcpFlowsCache.Len(),
		"tcp_flows_max":       s.maxFlows,
		"udp_flows_size":      s.udpFlowsCache.Len(),
		"syn_sent_size":       s.synSentCache.Len(),
		"syn_sent_max":        s.maxSYNEntries,
		"tls_sni_size":        s.tlsSNICache.Len(),
		"device_fingerprints": s.deviceFPCache.Len(),
	}
}

// ForEachTCPFlow iterates over all TCP flows in the cache
// The callback receives the flow key and state; return false to stop iteration
func (s *AnalysisState) ForEachTCPFlow(callback func(flowKey string, state *TCPFlowState) bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Get all keys from the cache
	for _, key := range s.tcpFlowsCache.Keys() {
		if val, ok := s.tcpFlowsCache.Peek(key); ok {
			if !callback(key, val) {
				return
			}
		}
	}
}

// ForEachUDPFlow iterates over all UDP flows in the cache
// The callback receives the flow key and state; return false to stop iteration
func (s *AnalysisState) ForEachUDPFlow(callback func(flowKey string, state *UDPFlowState) bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, key := range s.udpFlowsCache.Keys() {
		if val, ok := s.udpFlowsCache.Peek(key); ok {
			if !callback(key, val) {
				return
			}
		}
	}
}

// TCPFlowCount returns the number of TCP flows currently tracked
func (s *AnalysisState) TCPFlowCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.tcpFlowsCache.Len()
}

// UDPFlowCount returns the number of UDP flows currently tracked
func (s *AnalysisState) UDPFlowCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.udpFlowsCache.Len()
}

// ForEachSNI iterates over all SNI entries in the cache
// The callback receives the SNI string; return false to stop iteration
func (s *AnalysisState) ForEachSNI(callback func(sni string) bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, key := range s.tlsSNICache.Keys() {
		if val, ok := s.tlsSNICache.Peek(key); ok {
			if !callback(val) {
				return
			}
		}
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
