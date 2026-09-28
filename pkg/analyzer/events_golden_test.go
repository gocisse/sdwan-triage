package analyzer

import (
	"reflect"
	"testing"
	"time"

	"github.com/gocisse/sdwan-triage/internal/testpcap"
	"github.com/gocisse/sdwan-triage/pkg/events"
)

func fixtureTime(i int) time.Time {
	return testpcap.BaseTime.Add(time.Duration(i) * testpcap.DefaultInterval)
}

func TestEvents_RetransmissionStorm(t *testing.T) {
	r := runGolden(t, testpcap.RetransmissionStorm())
	if r.Events == nil {
		t.Fatal("report.Events not attached")
	}

	retrans := r.Events.ByKind(events.TCPRetransmission)
	if len(retrans) != 5 {
		t.Fatalf("expected 5 tcp.retransmission events (one per retransmitted segment), got %d", len(retrans))
	}
	// Packet layout per burst: data, 3 dup-ACKs, retransmission, ACK → 6 packets.
	// First burst starts at packet 3 (after the 3-packet handshake), so the
	// retransmissions are packets 7, 13, 19, 25, 31.
	for i, e := range retrans {
		wantIdx := uint64(7 + 6*i)
		if e.FlowKey != "192.168.1.100:50002->10.0.0.50:443" {
			t.Errorf("event %d flow = %q", i, e.FlowKey)
		}
		if e.Source != "TCP" || e.Capture != "" {
			t.Errorf("event %d source/capture = %q/%q", i, e.Source, e.Capture)
		}
		if !e.Timestamp.Equal(fixtureTime(int(wantIdx))) {
			t.Errorf("event %d timestamp = %v, want packet %d time %v", i, e.Timestamp, wantIdx, fixtureTime(int(wantIdx)))
		}
		if len(e.Packets) != 1 || e.Packets[0].Index != wantIdx {
			t.Errorf("event %d packet ref = %+v, want index %d", i, e.Packets, wantIdx)
		}
		if e.Values["seq"] != float64(1001+1000*i) || e.Values["payload_len"] != 1000 {
			t.Errorf("event %d values = %v", i, e.Values)
		}
		// Original segment was 4 packets (400 ms) earlier.
		if e.Values["since_original_ms"] != 400 {
			t.Errorf("event %d since_original_ms = %v, want 400", i, e.Values["since_original_ms"])
		}
	}
	// IDs are dense and in emission order.
	for i, e := range retrans {
		if e.ID != uint64(i+1) {
			t.Errorf("event %d ID = %d", i, e.ID)
		}
	}
	if r.EventCounts["tcp.retransmission"] != 5 || r.EventsDropped != 0 {
		t.Errorf("EventCounts = %v dropped=%d", r.EventCounts, r.EventsDropped)
	}
}

func TestEvents_BFDTunnelDrop(t *testing.T) {
	r := runGolden(t, testpcap.BFDTunnelDrop())

	down := r.Events.ByKind(events.BFDDown)
	if len(down) != 1 {
		t.Fatalf("expected exactly 1 bfd.down event, got %d", len(down))
	}
	e := down[0]
	// Down packet is the 15th packet (index 14): 10 keepalives + 4 one-way + Down.
	if !e.Timestamp.Equal(fixtureTime(14)) || len(e.Packets) != 1 || e.Packets[0].Index != 14 {
		t.Errorf("bfd.down timestamp/packet = %v / %+v, want packet 14", e.Timestamp, e.Packets)
	}
	if e.Attrs["src_ip"] != "192.168.1.100" || e.Attrs["peer_ip"] != "10.0.0.1" || e.Attrs["new_state_name"] != "Down" {
		t.Errorf("bfd.down attrs = %v", e.Attrs)
	}
	if e.Values["prev_state"] != 3 || e.Values["new_state"] != 1 {
		t.Errorf("bfd.down values = %v", e.Values)
	}
	// The existing StabilityFinding is still produced alongside the event.
	var found bool
	for _, f := range r.StabilityFindings {
		found = found || f.Type == "BFD Session Down"
	}
	if !found {
		t.Error("existing 'BFD Session Down' finding missing — events must be additive")
	}
}

func TestEvents_DNSFailure(t *testing.T) {
	r := runGolden(t, testpcap.DNSFailure())

	anomalies := r.Events.ByKind(events.DNSAnomaly)
	if len(anomalies) != 1 {
		t.Fatalf("expected 1 dns.anomaly event, got %d", len(anomalies))
	}
	e := anomalies[0]
	// Unanswered-query anomaly is stamped with the FIRST query's capture time
	// (packet 0), even though it is emitted at finalize after the last packet.
	if !e.Timestamp.Equal(fixtureTime(0)) {
		t.Errorf("dns.anomaly timestamp = %v, want first query time %v", e.Timestamp, fixtureTime(0))
	}
	if len(e.Packets) != 0 {
		t.Errorf("finalize-time event must not be attributed to the last packet: %+v", e.Packets)
	}
	if e.Attrs["query"] != "example.com" || e.Attrs["server_ip"] != "8.8.8.8" || e.Attrs["reason"] == "" {
		t.Errorf("dns.anomaly attrs = %v", e.Attrs)
	}
	if len(r.DNSAnomalies) != 1 {
		t.Errorf("existing DNSAnomalies changed: %d", len(r.DNSAnomalies))
	}
}

func TestEvents_CleanScenariosEmitNothing(t *testing.T) {
	for _, name := range []string{"handshake"} {
		for _, s := range testpcap.Scenarios() {
			if s.Name != name {
				continue
			}
			r := runGolden(t, s.Generate())
			if r.Events.Len() != 0 {
				t.Errorf("%s: expected no events, got %+v", name, r.Events.Events())
			}
			if r.EventCounts != nil {
				t.Errorf("%s: event_counts should be omitted when empty, got %v", name, r.EventCounts)
			}
		}
	}
}

func TestEvents_DeterministicAcrossRuns(t *testing.T) {
	for _, s := range testpcap.Scenarios() {
		a := runGolden(t, s.Generate()).Events.Events()
		b := runGolden(t, s.Generate()).Events.Events()
		if !reflect.DeepEqual(a, b) {
			t.Errorf("%s: events differ between identical runs\n%+v\n%+v", s.Name, a, b)
		}
	}
}
