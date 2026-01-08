package models

import (
	"testing"
	"time"
)

func TestNewAnalysisState(t *testing.T) {
	state := NewAnalysisState()

	if state == nil {
		t.Fatal("NewAnalysisState() returned nil")
	}

	if state.TCPFlows == nil {
		t.Error("TCPFlows map is nil")
	}

	if state.UDPFlows == nil {
		t.Error("UDPFlows map is nil")
	}

	if state.DNSQueries == nil {
		t.Error("DNSQueries map is nil")
	}

	if state.HTTPRequests == nil {
		t.Error("HTTPRequests map is nil")
	}

	if state.SynSent == nil {
		t.Error("SynSent map is nil")
	}

	if state.SynAckReceived == nil {
		t.Error("SynAckReceived map is nil")
	}

	if state.ARPIPToMAC == nil {
		t.Error("ARPIPToMAC map is nil")
	}

	if state.TLSSNICache == nil {
		t.Error("TLSSNICache map is nil")
	}

	if state.DeviceFingerprints == nil {
		t.Error("DeviceFingerprints map is nil")
	}

	if state.AppStats == nil {
		t.Error("AppStats map is nil")
	}
}

func TestFilter_IsEmpty(t *testing.T) {
	tests := []struct {
		name   string
		filter *Filter
		want   bool
	}{
		{
			name:   "nil filter",
			filter: nil,
			want:   true,
		},
		{
			name:   "empty filter",
			filter: &Filter{},
			want:   true,
		},
		{
			name: "filter with SrcIP",
			filter: &Filter{
				SrcIP: "192.168.1.1",
			},
			want: false,
		},
		{
			name: "filter with DstIP",
			filter: &Filter{
				DstIP: "8.8.8.8",
			},
			want: false,
		},
		{
			name: "filter with Service",
			filter: &Filter{
				Service: "https",
			},
			want: false,
		},
		{
			name: "filter with Protocol",
			filter: &Filter{
				Protocol: "tcp",
			},
			want: false,
		},
		{
			name: "filter with all fields",
			filter: &Filter{
				SrcIP:    "192.168.1.1",
				DstIP:    "8.8.8.8",
				Service:  "https",
				Protocol: "tcp",
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.filter.IsEmpty()
			if got != tt.want {
				t.Errorf("Filter.IsEmpty() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestTCPFlowState_Initialization(t *testing.T) {
	flowState := &TCPFlowState{
		SeqSeen:   make(map[uint32]bool),
		SentTimes: make(map[uint32]time.Time),
	}

	if flowState.SeqSeen == nil {
		t.Error("SeqSeen map is nil")
	}

	if flowState.SentTimes == nil {
		t.Error("SentTimes map is nil")
	}

	// Test adding to maps
	flowState.SeqSeen[12345] = true
	if !flowState.SeqSeen[12345] {
		t.Error("Failed to add to SeqSeen map")
	}

	flowState.TotalBytes = 1000
	if flowState.TotalBytes != 1000 {
		t.Errorf("TotalBytes = %d, want %d", flowState.TotalBytes, 1000)
	}

	flowState.RTTSamples = append(flowState.RTTSamples, 10.5, 15.2, 12.8)
	if len(flowState.RTTSamples) != 3 {
		t.Errorf("RTTSamples length = %d, want %d", len(flowState.RTTSamples), 3)
	}
}

func TestUDPFlowState_Initialization(t *testing.T) {
	flowState := &UDPFlowState{
		TotalBytes: 500,
	}

	if flowState.TotalBytes != 500 {
		t.Errorf("TotalBytes = %d, want %d", flowState.TotalBytes, 500)
	}
}

func TestHTTPRequest_Fields(t *testing.T) {
	ts := time.Now()
	req := &HTTPRequest{
		Method:    "GET",
		Host:      "example.com",
		Path:      "/api/v1/users",
		Timestamp: ts,
	}

	if req.Method != "GET" {
		t.Errorf("Method = %q, want %q", req.Method, "GET")
	}

	if req.Host != "example.com" {
		t.Errorf("Host = %q, want %q", req.Host, "example.com")
	}

	if req.Path != "/api/v1/users" {
		t.Errorf("Path = %q, want %q", req.Path, "/api/v1/users")
	}

	if req.Timestamp != ts {
		t.Errorf("Timestamp mismatch")
	}
}

func TestTCPFingerprint_Fields(t *testing.T) {
	fp := &TCPFingerprint{
		WindowSize: 65535,
		TTL:        64,
		MSS:        1460,
		HasTS:      true,
		HasSACK:    true,
		HasWS:      true,
		DFFlag:     true,
	}

	if fp.WindowSize != 65535 {
		t.Errorf("WindowSize = %d, want %d", fp.WindowSize, 65535)
	}

	if fp.TTL != 64 {
		t.Errorf("TTL = %d, want %d", fp.TTL, 64)
	}

	if fp.MSS != 1460 {
		t.Errorf("MSS = %d, want %d", fp.MSS, 1460)
	}

	if !fp.HasTS {
		t.Error("HasTS = false, want true")
	}

	if !fp.HasSACK {
		t.Error("HasSACK = false, want true")
	}

	if !fp.HasWS {
		t.Error("HasWS = false, want true")
	}

	if !fp.DFFlag {
		t.Error("DFFlag = false, want true")
	}
}
