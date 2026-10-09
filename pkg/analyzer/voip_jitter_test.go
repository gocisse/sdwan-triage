package analyzer

import (
	"encoding/json"
	"math"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/gocisse/sdwan-triage/pkg/models"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// Phase 4.27b: avg_jitter_ms / jitter_ms are milliseconds at the payload's RTP
// clock rate, or JSON null when the clock rate is unknown.

func rtpDatagram(pt uint8, seq uint16, ts, ssrc uint32) []byte {
	b := make([]byte, 22)
	b[0] = 0x80
	b[1] = pt
	b[2], b[3] = byte(seq>>8), byte(seq)
	b[4], b[5], b[6], b[7] = byte(ts>>24), byte(ts>>16), byte(ts>>8), byte(ts)
	b[8], b[9], b[10], b[11] = byte(ssrc>>24), byte(ssrc>>16), byte(ssrc>>8), byte(ssrc)
	return b
}

func feedRTP(t *testing.T, p *Processor, srcPort uint16, ssrc uint32, pt uint8, tsStep uint32, intervals []time.Duration) {
	t.Helper()
	at := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	state := models.NewAnalysisState()
	report := &models.TriageReport{}
	for i := 0; i <= len(intervals); i++ {
		buf := gopacket.NewSerializeBuffer()
		ip := &layers.IPv4{Version: 4, IHL: 5, TTL: 64, Protocol: layers.IPProtocolUDP,
			SrcIP: net.IP{10, 0, 0, 1}, DstIP: net.IP{10, 0, 0, 2}}
		udp := &layers.UDP{SrcPort: layers.UDPPort(srcPort), DstPort: 40002}
		udp.SetNetworkLayerForChecksum(ip)
		eth := &layers.Ethernet{SrcMAC: net.HardwareAddr{0, 1, 2, 3, 4, 5}, DstMAC: net.HardwareAddr{6, 7, 8, 9, 10, 11}, EthernetType: layers.EthernetTypeIPv4}
		if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true},
			eth, ip, udp, gopacket.Payload(rtpDatagram(pt, uint16(i+1), 1000+tsStep*uint32(i), ssrc))); err != nil {
			t.Fatal(err)
		}
		pkt := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
		pkt.Metadata().Timestamp = at
		pkt.Metadata().CaptureInfo.CaptureLength = len(buf.Bytes())
		pkt.Metadata().CaptureInfo.Length = len(buf.Bytes())
		p.rtpAnalyzer.Analyze(pkt, state, report)
		if i < len(intervals) {
			at = at.Add(intervals[i])
		}
	}
}

func alternating(n int, a, b time.Duration) []time.Duration {
	out := make([]time.Duration, n)
	for i := range out {
		if i%2 == 0 {
			out[i] = a
		} else {
			out[i] = b
		}
	}
	return out
}

func finalizeVoIP(p *Processor) *models.TriageReport {
	r := &models.TriageReport{}
	p.finalizeVoIPAnalysis(r)
	return r
}

func TestFinalizeVoIP_JitterMillisecondsAndNull(t *testing.T) {
	p := NewProcessor()
	// PCMA (PT 8, 8 kHz): nine 16-tick updates => 0.8811509865627158 ms.
	feedRTP(t, p, 40000, 100, 8, 160, alternating(9, 22*time.Millisecond, 18*time.Millisecond))
	// Dynamic PT 96: unknown clock => null.
	feedRTP(t, p, 40001, 200, 96, 160, alternating(9, 22*time.Millisecond, 18*time.Millisecond))
	// Perfectly regular PCMU: measured zero (not null).
	feedRTP(t, p, 40003, 300, 0, 160, alternating(9, 20*time.Millisecond, 20*time.Millisecond))

	v := finalizeVoIP(p).VoIPAnalysis
	if v == nil || v.TotalRTPStreams != 3 {
		t.Fatalf("expected 3 RTP streams, got %+v", v)
	}
	bySSRC := map[uint32]*float64{}
	for _, s := range v.RTPStreams {
		bySSRC[s.SSRC] = s.Jitter
	}
	if j := bySSRC[100]; j == nil || math.Abs(*j-0.8811509865627158) > 1e-9 {
		t.Errorf("PCMA jitter = %v, want 0.8811509865627158", j)
	}
	if bySSRC[200] != nil {
		t.Errorf("dynamic PT jitter = %v, want nil", *bySSRC[200])
	}
	if j := bySSRC[300]; j == nil || *j != 0 {
		t.Errorf("regular stream jitter must be a measured 0, got %v", j)
	}
	// Average only over available streams: (0.8811509865627158 + 0)/2.
	if v.AvgJitter == nil || math.Abs(*v.AvgJitter-0.4405754932813579) > 1e-9 {
		t.Errorf("avg jitter = %v, want 0.4405754932813579", v.AvgJitter)
	}
	if v.TotalRTPStreams != 3 {
		t.Error("RTP stream count must not depend on jitter availability")
	}

	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	_ = json.Unmarshal(raw, &m)
	streams := m["rtp_streams"].([]any)
	nulls, zeros := 0, 0
	for _, s := range streams {
		jv, present := s.(map[string]any)["jitter_ms"]
		if !present {
			t.Fatal("jitter_ms key must always be present")
		}
		if jv == nil {
			nulls++
		} else if jv.(float64) == 0 {
			zeros++
		}
	}
	if nulls != 1 || zeros != 1 {
		t.Errorf("want 1 null and 1 numeric zero stream, got nulls=%d zeros=%d (%s)", nulls, zeros, raw)
	}
}

func TestFinalizeVoIP_AllUnavailableIsNull(t *testing.T) {
	p := NewProcessor()
	feedRTP(t, p, 40000, 1, 111, 160, alternating(9, 22*time.Millisecond, 18*time.Millisecond))
	v := finalizeVoIP(p).VoIPAnalysis
	if v == nil || v.TotalRTPStreams != 1 {
		t.Fatalf("expected 1 stream, got %+v", v)
	}
	if v.AvgJitter != nil {
		t.Errorf("avg jitter = %v, want nil", *v.AvgJitter)
	}
	raw, _ := json.Marshal(v)
	if !strings.Contains(string(raw), `"avg_jitter_ms":null`) || !strings.Contains(string(raw), `"jitter_ms":null`) {
		t.Errorf("unavailable jitter must serialize as null: %s", raw)
	}
}

func TestFinalizeVoIP_JitterDeterministic(t *testing.T) {
	var first string
	for i := 0; i < 5; i++ {
		p := NewProcessor()
		feedRTP(t, p, 40000, 100, 8, 160, alternating(9, 22*time.Millisecond, 18*time.Millisecond))
		feedRTP(t, p, 40001, 200, 34, 3000, alternating(9, 34*time.Millisecond, 32*time.Millisecond))
		raw, _ := json.Marshal(finalizeVoIP(p).VoIPAnalysis)
		if i == 0 {
			first = string(raw)
		} else if string(raw) != first {
			t.Fatal("VoIP JSON not deterministic")
		}
	}
}
