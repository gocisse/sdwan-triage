package detector

import (
	"testing"
	"time"

	"github.com/gocisse/sdwan-triage/pkg/events"
	"github.com/gocisse/sdwan-triage/pkg/models"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// Phase 4.44: one transmission yields at most one RTT sample. Before the fix,
// every later ACK carrying the same acknowledgment number (repeated pure ACKs
// with ack = ISN+1) was timed against the original SYN-ACK send time, producing
// growing, bogus RTT samples and false tcp.rtt_spike events.

var rttT0 = time.Unix(1700000000, 0)

type rttSeg struct {
	fromServer bool
	syn, ack   bool
	seq, ackN  uint32
	payload    int
	at         time.Duration
	cport      uint16
}

func rttPkt(s rttSeg) gopacket.Packet {
	cport := s.cport
	if cport == 0 {
		cport = 40000
	}
	src, dst, sp, dp := swClient, swServer, uint16(cport), uint16(swSPort)
	if s.fromServer {
		src, dst, sp, dp = swServer, swClient, uint16(swSPort), uint16(cport)
	}
	eth := &layers.Ethernet{SrcMAC: []byte{0, 0, 0, 0, 0, 1}, DstMAC: []byte{0, 0, 0, 0, 0, 2}, EthernetType: layers.EthernetTypeIPv4}
	ip := &layers.IPv4{Version: 4, TTL: 64, Protocol: layers.IPProtocolTCP, SrcIP: parseIP(src), DstIP: parseIP(dst)}
	tcp := &layers.TCP{SrcPort: layers.TCPPort(sp), DstPort: layers.TCPPort(dp), SYN: s.syn, ACK: s.ack, Seq: s.seq, Ack: s.ackN, Window: 65000}
	tcp.SetNetworkLayerForChecksum(ip)
	buf := gopacket.NewSerializeBuffer()
	layersToSend := []gopacket.SerializableLayer{eth, ip, tcp}
	if s.payload > 0 {
		layersToSend = append(layersToSend, gopacket.Payload(make([]byte, s.payload)))
	}
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}, layersToSend...); err != nil {
		panic(err)
	}
	p := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
	p.Metadata().Timestamp = rttT0.Add(s.at)
	return p
}

func rttRun(segs ...rttSeg) (*models.AnalysisState, *models.TriageReport) {
	a := NewTCPAnalyzer()
	state := models.NewAnalysisState()
	ix := events.NewIndex(0)
	rec := events.NewRecorder(ix, "")
	report := &models.TriageReport{Events: ix, Emitter: rec}
	for i, s := range segs {
		p := rttPkt(s)
		rec.SetCurrentPacket(uint64(i), p.Metadata().Timestamp)
		a.Analyze(p, state, report)
	}
	return state, report
}

func ms(n int) time.Duration { return time.Duration(n) * time.Millisecond }

func rttFlow(state *models.AnalysisState, server bool, cport int) *models.TCPFlowState {
	key := "10.0.0.1:40000->10.0.0.2:443"
	if server {
		key = "10.0.0.2:443->10.0.0.1:40000"
	}
	_ = cport
	return state.GetTCPFlow(key)
}

func TestRTT_RepeatedISNPlus1AcksDoNotReuseSynAckTimestamp(t *testing.T) {
	// SYN-ACK (server ISN 5000) at 0 ms; client ACK at 20 ms is the genuine
	// sample (20 ms). Three further pure ACKs with ack=5001 arrive 1-3 s later.
	state, report := rttRun(
		rttSeg{syn: true, seq: 100, at: -ms(20)},
		rttSeg{fromServer: true, syn: true, ack: true, seq: 5000, ackN: 101, at: 0},
		rttSeg{ack: true, seq: 101, ackN: 5001, at: ms(20)},
		rttSeg{ack: true, seq: 101, ackN: 5001, at: ms(1000)},
		rttSeg{ack: true, seq: 101, ackN: 5001, at: ms(2000)},
		rttSeg{ack: true, seq: 101, ackN: 5001, at: ms(3000)},
	)
	fs := rttFlow(state, true, 0)
	if fs == nil {
		t.Fatal("server flow state missing")
	}
	if fs.RTTCount != 1 {
		t.Fatalf("RTTCount = %d, want 1 (repeated ACKs must not re-sample)", fs.RTTCount)
	}
	if fs.RTTMax < 19 || fs.RTTMax > 21 {
		t.Fatalf("RTTMax = %.1f ms, want ~20 (inflated by repeated ACKs?)", fs.RTTMax)
	}
	if n := len(report.Events.ByKind(events.TCPRTTSpike)); n != 0 {
		t.Fatalf("rtt spike events = %d, want 0", n)
	}
}

func TestRTT_ValidHandshakeSampleStillRecorded(t *testing.T) {
	state, _ := rttRun(
		rttSeg{syn: true, seq: 100, at: 0},
		rttSeg{fromServer: true, syn: true, ack: true, seq: 5000, ackN: 101, at: ms(30)},
		rttSeg{ack: true, seq: 101, ackN: 5001, at: ms(40)},
	)
	if c := rttFlow(state, false, 0); c == nil || c.RTTCount != 1 || c.RTTMax < 29 || c.RTTMax > 31 {
		t.Fatalf("client-side SYN sample wrong: %+v", c)
	}
	if s := rttFlow(state, true, 0); s == nil || s.RTTCount != 1 || s.RTTMax < 9 || s.RTTMax > 11 {
		t.Fatalf("server-side SYN-ACK sample wrong: %+v", s)
	}
}

func TestRTT_SpikeStillEmittedOnceForGenuineSlowSample(t *testing.T) {
	_, report := rttRun(
		rttSeg{fromServer: true, syn: true, ack: true, seq: 5000, ackN: 101, at: 0},
		rttSeg{ack: true, seq: 101, ackN: 5001, at: ms(300)},
		rttSeg{ack: true, seq: 101, ackN: 5001, at: ms(900)},
	)
	if n := len(report.Events.ByKind(events.TCPRTTSpike)); n != 1 {
		t.Fatalf("rtt spike events = %d, want exactly 1 (threshold unchanged)", n)
	}
}

func TestRTT_RetransmittedSegmentStillExcludedByKarn(t *testing.T) {
	state, _ := rttRun(
		rttSeg{fromServer: true, syn: true, ack: true, seq: 5000, ackN: 101, at: 0},
		rttSeg{fromServer: true, syn: true, ack: true, seq: 5000, ackN: 101, at: ms(1000)}, // SYN-ACK retransmission
		rttSeg{ack: true, seq: 101, ackN: 5001, at: ms(1010)},
	)
	if s := rttFlow(state, true, 0); s == nil || s.RTTCount != 0 {
		t.Fatalf("ambiguous (retransmitted) sample must not be taken: %+v", s)
	}
}

func TestRTT_IndependentDataSamplesRemainPossible(t *testing.T) {
	// Client sends 1-byte segments seq 101 and 102; each ACK (102, 103) is a
	// distinct transmission and yields its own sample; a duplicate ACK of the
	// first does not.
	state, _ := rttRun(
		rttSeg{ack: true, seq: 101, ackN: 5001, payload: 1, at: 0},
		rttSeg{fromServer: true, ack: true, seq: 5001, ackN: 102, at: ms(10)},
		rttSeg{ack: true, seq: 102, ackN: 5001, payload: 1, at: ms(100)},
		rttSeg{fromServer: true, ack: true, seq: 5001, ackN: 103, at: ms(125)},
		rttSeg{fromServer: true, ack: true, seq: 5001, ackN: 102, at: ms(500)}, // duplicate ACK
	)
	c := rttFlow(state, false, 0)
	if c == nil || c.RTTCount != 2 {
		t.Fatalf("want 2 independent samples, got %+v", c)
	}
	if c.RTTMin < 9 || c.RTTMin > 11 || c.RTTMax < 24 || c.RTTMax > 26 {
		t.Fatalf("samples wrong: min %.1f max %.1f", c.RTTMin, c.RTTMax)
	}
}

func TestRTT_UnrelatedFlowsDoNotShareSampleState(t *testing.T) {
	// Same ack number on two connections (different client ports): each flow
	// is sampled once, independently.
	a := NewTCPAnalyzer()
	state := models.NewAnalysisState()
	report := &models.TriageReport{}
	for _, s := range []rttSeg{
		{fromServer: true, syn: true, ack: true, seq: 5000, ackN: 101, at: 0, cport: 40000},
		{fromServer: true, syn: true, ack: true, seq: 5000, ackN: 101, at: 0, cport: 40001},
		{ack: true, seq: 101, ackN: 5001, at: ms(15), cport: 40000},
		{ack: true, seq: 101, ackN: 5001, at: ms(25), cport: 40001},
		{ack: true, seq: 101, ackN: 5001, at: ms(2000), cport: 40000},
	} {
		a.Analyze(rttPkt(s), state, report)
	}
	f0 := state.GetTCPFlow("10.0.0.2:443->10.0.0.1:40000")
	f1 := state.GetTCPFlow("10.0.0.2:443->10.0.0.1:40001")
	if f0 == nil || f1 == nil || f0.RTTCount != 1 || f1.RTTCount != 1 {
		t.Fatalf("each flow must be sampled exactly once: %+v %+v", f0, f1)
	}
	if f0.RTTMax > 16 || f1.RTTMax < 24 || f1.RTTMax > 26 {
		t.Fatalf("samples crossed between flows: %.1f %.1f", f0.RTTMax, f1.RTTMax)
	}
}
