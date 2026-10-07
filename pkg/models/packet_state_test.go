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

	// Test bounded caches are initialized via accessor methods
	if state.TCPFlowCount() != 0 {
		t.Error("TCPFlows cache should be empty initially")
	}

	if state.UDPFlowCount() != 0 {
		t.Error("UDPFlows cache should be empty initially")
	}

	if state.DNSQueries == nil {
		t.Error("DNSQueries map is nil")
	}

	if state.HTTPRequests == nil {
		t.Error("HTTPRequests map is nil")
	}

	// Test SynSent cache via accessor
	if _, ok := state.GetSynSent("test"); ok {
		t.Error("SynSent cache should be empty initially")
	}

	if state.synAckReceived == nil {
		t.Error("SynAckReceived map is nil")
	}

	if state.ARPIPToMAC == nil {
		t.Error("ARPIPToMAC map is nil")
	}

	// Test SNI cache via accessor
	if _, ok := state.GetTLSSNI("test"); ok {
		t.Error("TLSSNICache should be empty initially")
	}

	// Test device fingerprint cache via accessor
	if fp := state.GetDeviceFingerprint("test"); fp != nil {
		t.Error("DeviceFingerprints cache should be empty initially")
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
	flowState := NewTCPFlowState()

	if flowState.Seq == nil {
		t.Fatal("Seq history is nil")
	}

	ts := time.Unix(1700000000, 0)
	flowState.Seq.Record(12345, ts)
	if !flowState.Seq.Seen(12345) {
		t.Error("Failed to record sequence number")
	}
	if got, ok := flowState.Seq.Lookup(12345); !ok || !got.Equal(ts) {
		t.Errorf("Lookup(12345) = %v,%v want %v,true", got, ok, ts)
	}

	flowState.TotalBytes = 1000
	if flowState.TotalBytes != 1000 {
		t.Errorf("TotalBytes = %d, want %d", flowState.TotalBytes, 1000)
	}

	for _, s := range []float64{10.5, 15.2, 12.8} {
		flowState.AddRTTSample(s)
	}
	if len(flowState.RTTSamples) != 3 {
		t.Errorf("RTTSamples length = %d, want %d", len(flowState.RTTSamples), 3)
	}
	count, min, max, avg := flowState.RTTStats()
	if count != 3 || min != 10.5 || max != 15.2 || avg < 12.8 || avg > 12.9 {
		t.Errorf("RTTStats() = %d,%v,%v,%v", count, min, max, avg)
	}
}

func TestSeqHistory_BoundedFIFO(t *testing.T) {
	h := NewSeqHistory(4)
	base := time.Unix(1700000000, 0)
	for i := uint32(0); i < 6; i++ {
		h.Record(i*1000, base.Add(time.Duration(i)*time.Millisecond))
	}
	if h.Len() != 4 {
		t.Fatalf("Len() = %d, want 4", h.Len())
	}
	// Oldest two evicted, newest four retained
	for _, seq := range []uint32{0, 1000} {
		if h.Seen(seq) {
			t.Errorf("seq %d should have been evicted", seq)
		}
	}
	for _, seq := range []uint32{2000, 3000, 4000, 5000} {
		if !h.Seen(seq) {
			t.Errorf("seq %d should be retained", seq)
		}
	}
	// Re-recording keeps the original timestamp (RTT measured from first send)
	orig, _ := h.Lookup(5000)
	h.Record(5000, base.Add(time.Hour))
	if got, _ := h.Lookup(5000); !got.Equal(orig) {
		t.Errorf("re-record changed timestamp: %v -> %v", orig, got)
	}
	if h.Len() != 4 {
		t.Errorf("re-record grew history to %d", h.Len())
	}
}

func TestTCPFlowState_RTTSamplesBounded(t *testing.T) {
	fs := NewTCPFlowState()
	for i := 0; i < MaxRTTSamplesPerFlow+500; i++ {
		fs.AddRTTSample(float64(i))
	}
	if len(fs.RTTSamples) != MaxRTTSamplesPerFlow {
		t.Errorf("RTTSamples len = %d, want %d", len(fs.RTTSamples), MaxRTTSamplesPerFlow)
	}
	count, min, max, _ := fs.RTTStats()
	if count != MaxRTTSamplesPerFlow+500 || min != 0 || max != float64(MaxRTTSamplesPerFlow+499) {
		t.Errorf("aggregate stats lost samples: count=%d min=%v max=%v", count, min, max)
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

func TestSeqHistory_MarkRetransmitted(t *testing.T) {
	h := NewSeqHistory(2)
	ts := time.Unix(100, 0)
	h.MarkRetransmitted(1) // not remembered: no-op
	if h.WasRetransmitted(1) {
		t.Fatal("unremembered seq must not be flagged")
	}
	h.Record(1, ts)
	h.MarkRetransmitted(1)
	if !h.WasRetransmitted(1) {
		t.Fatal("seq 1 should be flagged")
	}
	// Eviction drops the flag together with the entry (bounded memory), and a
	// later reuse of the sequence number starts unflagged.
	h.Record(2, ts)
	h.Record(3, ts) // evicts 1
	if h.WasRetransmitted(1) {
		t.Fatal("flag must be dropped when the entry is evicted")
	}
	h.Record(1, ts)
	if h.WasRetransmitted(1) {
		t.Fatal("re-recorded seq must start unflagged")
	}
}
