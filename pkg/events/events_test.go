package events

import (
	"reflect"
	"testing"
	"time"
)

var base = time.Date(2024, 1, 15, 12, 0, 0, 0, time.UTC)

func at(ms int) time.Time { return base.Add(time.Duration(ms) * time.Millisecond) }

func TestRecorder_StampsFromCurrentPacket(t *testing.T) {
	ix := NewIndex(0)
	r := NewRecorder(ix, "A")
	r.SetCurrentPacket(41, at(500))

	r.Emit(Event{Kind: TCPRetransmission, FlowKey: "1.1.1.1:1->2.2.2.2:2", Source: "TCP"})

	ev := ix.Events()
	if len(ev) != 1 {
		t.Fatalf("len = %d", len(ev))
	}
	e := ev[0]
	if e.ID != 1 || e.Kind != TCPRetransmission || e.Source != "TCP" || e.Capture != "A" || e.FlowKey != "1.1.1.1:1->2.2.2.2:2" {
		t.Errorf("fields not preserved: %+v", e)
	}
	if !e.Timestamp.Equal(at(500)) {
		t.Errorf("timestamp = %v, want current packet time %v", e.Timestamp, at(500))
	}
	if len(e.Packets) != 1 || e.Packets[0].Index != 41 || !e.Packets[0].Timestamp.Equal(at(500)) {
		t.Errorf("packet ref = %+v, want index 41 @ %v", e.Packets, at(500))
	}
}

func TestRecorder_ExplicitTimestampKeptAndNoPacketRefWhenNotCurrent(t *testing.T) {
	ix := NewIndex(0)
	r := NewRecorder(ix, "")
	r.SetCurrentPacket(99, at(9000))

	// Finalize-style emit: timestamp in the past relative to the current packet.
	r.Emit(Event{Kind: DNSAnomaly, Timestamp: at(100), Source: "DNS"})
	e := ix.Events()[0]
	if !e.Timestamp.Equal(at(100)) {
		t.Errorf("explicit timestamp overwritten: %v", e.Timestamp)
	}
	if len(e.Packets) != 0 {
		t.Errorf("must not attribute a past event to the current packet: %+v", e.Packets)
	}
}

func TestRecorder_RejectsEventWithoutAnyCaptureTime(t *testing.T) {
	ix := NewIndex(0)
	r := NewRecorder(ix, "")
	r.Emit(Event{Kind: BFDDown})
	if ix.Len() != 0 || r.Rejected() != 1 {
		t.Errorf("event without capture time must be rejected, len=%d rejected=%d", ix.Len(), r.Rejected())
	}
	// IDs stay dense: next accepted event is ID 1.
	r.SetCurrentPacket(0, at(0))
	r.Emit(Event{Kind: BFDDown})
	if got := ix.Events()[0].ID; got != 1 {
		t.Errorf("ID = %d, want 1", got)
	}
}

func TestIndex_QueriesAndBoundaries(t *testing.T) {
	ix := NewIndex(0)
	r := NewRecorder(ix, "")
	// Emit out of chronological order to exercise lazy sorting.
	for _, tc := range []struct {
		ms   int
		kind Kind
	}{
		{300, TCPRetransmission}, {100, DNSAnomaly}, {200, BFDDown}, {300, DNSAnomaly}, {400, TCPRetransmission}, {200, TCPRetransmission},
	} {
		r.Emit(Event{Kind: tc.kind, Timestamp: at(tc.ms)})
	}

	all := ix.Events()
	if len(all) != 6 {
		t.Fatalf("len = %d", len(all))
	}
	for i := 1; i < len(all); i++ {
		a, b := all[i-1], all[i]
		if b.Timestamp.Before(a.Timestamp) || (b.Timestamp.Equal(a.Timestamp) && b.ID < a.ID) {
			t.Errorf("not sorted by (ts,id) at %d: %v/%d then %v/%d", i, a.Timestamp, a.ID, b.Timestamp, b.ID)
		}
	}

	// Inclusive boundaries: [200, 300] → the two @200, the two @300.
	if got := ix.ByTime(at(200), at(300)); len(got) != 4 {
		t.Errorf("ByTime(200,300) = %d events, want 4", len(got))
	}
	if got := ix.ByTime(at(201), at(299)); len(got) != 0 {
		t.Errorf("ByTime(201,299) = %d events, want 0", len(got))
	}
	if got := ix.ByTime(at(400), at(400)); len(got) != 1 || got[0].Kind != TCPRetransmission {
		t.Errorf("ByTime(400,400) = %+v", got)
	}
	if got := ix.ByTime(at(500), at(600)); len(got) != 0 {
		t.Errorf("ByTime past end = %d", len(got))
	}
	if got := ix.ByTime(at(300), at(100)); len(got) != 0 {
		t.Errorf("inverted range must be empty, got %d", len(got))
	}

	if got := ix.ByKind(TCPRetransmission); len(got) != 3 || !got[0].Timestamp.Equal(at(200)) || !got[2].Timestamp.Equal(at(400)) {
		t.Errorf("ByKind(retrans) = %+v", got)
	}
	if got := ix.ByKind(Kind("nope")); got != nil {
		t.Errorf("unknown kind should be nil, got %v", got)
	}

	if got := ix.ByKindAndTime(TCPRetransmission, at(200), at(300)); len(got) != 2 {
		t.Errorf("ByKindAndTime(retrans,200,300) = %d, want 2", len(got))
	}
	if got := ix.ByKindAndTime(DNSAnomaly, at(300), at(300)); len(got) != 1 {
		t.Errorf("ByKindAndTime(dns,300,300) = %d, want 1", len(got))
	}

	counts := ix.Counts()
	if counts[TCPRetransmission] != 3 || counts[DNSAnomaly] != 2 || counts[BFDDown] != 1 {
		t.Errorf("Counts = %v", counts)
	}
}

func TestIndex_QueriesAfterInterleavedAdds(t *testing.T) {
	ix := NewIndex(0)
	r := NewRecorder(ix, "")
	r.Emit(Event{Kind: BFDDown, Timestamp: at(100)})
	_ = ix.ByKind(BFDDown)                          // forces a sort
	r.Emit(Event{Kind: BFDDown, Timestamp: at(50)}) // earlier than everything stored
	r.Emit(Event{Kind: BFDDown, Timestamp: at(150)})
	got := ix.ByKind(BFDDown)
	if len(got) != 3 || !got[0].Timestamp.Equal(at(50)) || !got[2].Timestamp.Equal(at(150)) {
		t.Errorf("per-kind index stale after interleaved add: %+v", got)
	}
}

func TestIndex_Bounded(t *testing.T) {
	ix := NewIndex(3)
	r := NewRecorder(ix, "")
	for i := 0; i < 5; i++ {
		r.Emit(Event{Kind: BFDDown, Timestamp: at(i)})
	}
	if ix.Len() != 3 || ix.Dropped() != 2 || ix.Cap() != 3 {
		t.Errorf("len=%d dropped=%d cap=%d", ix.Len(), ix.Dropped(), ix.Cap())
	}
	// Earliest observations are retained.
	if ev := ix.Events(); !ev[0].Timestamp.Equal(at(0)) || !ev[2].Timestamp.Equal(at(2)) {
		t.Errorf("wrong events retained: %+v", ev)
	}
}

func TestIndex_Deterministic(t *testing.T) {
	build := func() []Event {
		ix := NewIndex(0)
		r := NewRecorder(ix, "")
		for i := 0; i < 50; i++ {
			r.SetCurrentPacket(uint64(i), at((i*37)%200))
			r.Emit(Event{Kind: TCPRetransmission, Values: map[string]float64{"seq": float64(i)}})
		}
		return ix.Events()
	}
	if !reflect.DeepEqual(build(), build()) {
		t.Error("identical emissions produced different indexes")
	}
}

// Phase 4.31a: rejected events are attributed to their kind, and the per-kind
// counts always add up to Dropped().
func TestIndex_DroppedByKindAttributesRejectedEvents(t *testing.T) {
	ix := NewIndex(3)
	base := time.Unix(1_700_000_000, 0)
	kinds := []Kind{TCPRetransmission, TCPSequenceGap, TCPSequenceGap, TCPDuplicateACKRun, TCPSYNRetransmission, TCPSequenceGap, TCPRetransmission}
	var accepted int
	for i, k := range kinds {
		if ix.Add(Event{ID: uint64(i + 1), Kind: k, Timestamp: base.Add(time.Duration(i) * time.Second)}) {
			accepted++
		}
	}
	if accepted != 3 || ix.Len() != 3 || ix.Dropped() != 4 {
		t.Fatalf("accepted=%d len=%d dropped=%d, want 3/3/4", accepted, ix.Len(), ix.Dropped())
	}
	got := ix.DroppedByKind()
	want := map[Kind]int{TCPDuplicateACKRun: 1, TCPSYNRetransmission: 1, TCPSequenceGap: 1, TCPRetransmission: 1}
	if len(got) != len(want) {
		t.Fatalf("DroppedByKind = %v, want %v", got, want)
	}
	sum := 0
	for k, n := range want {
		if got[k] != n {
			t.Errorf("dropped[%s] = %d, want %d", k, got[k], n)
		}
		sum += got[k]
	}
	if sum != ix.Dropped() {
		t.Errorf("per-kind sum %d != Dropped() %d", sum, ix.Dropped())
	}
	// The returned map is a copy.
	got[TCPRetransmission] = 99
	if ix.DroppedByKind()[TCPRetransmission] != 1 {
		t.Error("DroppedByKind aliases internal state")
	}
	// Nothing dropped => empty map.
	if n := len(NewIndex(10).DroppedByKind()); n != 0 {
		t.Errorf("empty index reports %d dropped kinds", n)
	}
}
