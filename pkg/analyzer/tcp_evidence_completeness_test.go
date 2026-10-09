package analyzer

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gocisse/sdwan-triage/internal/testpcap"
	"github.com/gocisse/sdwan-triage/pkg/events"
	"github.com/gocisse/sdwan-triage/pkg/models"
)

// Phase 4.31a — completeness accounting for TCP evidence. A missing evidence event
// must never silently look like evidence that nothing happened. Known omitted
// events (generated, then not kept) are asserted separately from tracking limits
// (collection interrupted, number of missed events unknown).

const compPort = 56000

var fourKinds = []events.Kind{events.TCPRetransmission, events.TCPSYNRetransmission, events.TCPSequenceGap, events.TCPDuplicateACKRun}

// mixedEvidence yields at least one event of each of the four kinds.
func mixedEvidence() [][]byte {
	pk := frames(compPort, hs[0], hs[0], hs[1], hs[2]) // repeated SYN
	pk = append(pk, frames(compPort,
		cData(1001, 100), cData(1001, 100), // exact repeat => tcp.retransmission
		cData(1201, 100),                                                           // gap [1101,1201)
		srvAck(1101, 100), srvAck(1101, 100), srvAck(1101, 100), srvAck(1101, 100), // initial + 3 duplicates
		cData(1101, 100), // fill
	)...)
	return pk
}

func runWithMax(t *testing.T, pk [][]byte, max int) *models.TriageReport {
	t.Helper()
	path := filepath.Join(t.TempDir(), "s.pcap")
	if err := testpcap.WriteFile(path, pk); err != nil {
		t.Fatal(err)
	}
	p := NewProcessorWithOptions(false, false)
	p.MaxEvents = max
	return runPCAPFile(t, path, p)
}

func generated(r *models.TriageReport, k events.Kind) int {
	return r.EventCounts[string(k)]
}

// Event-index exhaustion is attributed to the real kind, for every capacity.
func TestTCPEvidenceCompleteness_IndexOverflowAttributedPerKind(t *testing.T) {
	ref := runWithMax(t, mixedEvidence(), 0)
	for _, k := range fourKinds {
		if generated(ref, k) == 0 {
			t.Fatalf("setup: reference run has no %s event: %v", k, ref.EventCounts)
		}
	}
	if ref.TCPEvidenceCompleteness != nil {
		t.Fatalf("setup: the unconstrained run should report no limitation, got %+v", ref.TCPEvidenceCompleteness)
	}
	total := ref.Events.Len()
	for max := 1; max <= total; max++ {
		r := runWithMax(t, mixedEvidence(), max)
		byKind := r.Events.DroppedByKind()
		sum := 0
		for _, n := range byKind {
			sum += n
		}
		if sum != r.EventsDropped || r.EventsDropped != total-max {
			t.Fatalf("max=%d: per-kind sum %d, EventsDropped %d, want %d", max, sum, r.EventsDropped, total-max)
		}
		c := r.TCPEvidenceCompleteness
		for _, k := range fourKinds {
			stored := generated(r, k)
			lost := 0
			if c != nil {
				lost = c.KnownOmittedEvents[string(k)].IndexFull
			}
			if stored+lost != generated(ref, k) {
				t.Fatalf("max=%d kind %s: stored %d + index_full %d != generated %d", max, k, stored, lost, generated(ref, k))
			}
			if lost != byKind[k] {
				t.Fatalf("max=%d kind %s: index_full %d != rejected by the index %d", max, k, lost, byKind[k])
			}
		}
		// Anything rejected from the four kinds makes the capture "affected"; nothing
		// rejected from them (only other kinds dropped) must not claim an omission.
		fourDropped := byKind[events.TCPRetransmission] + byKind[events.TCPSYNRetransmission] + byKind[events.TCPSequenceGap] + byKind[events.TCPDuplicateACKRun]
		if (fourDropped > 0) != (c != nil) {
			t.Fatalf("max=%d: completeness present=%v but %d TCP-evidence events were rejected", max, c != nil, fourDropped)
		}
	}
}

// The new evidence is emitted last, so a full index loses it first: the very case
// that used to look like "no gaps, no duplicate ACKs".
func TestTCPEvidenceCompleteness_FullIndexLosesDeferredEvidenceButIsDisclosed(t *testing.T) {
	ref := runWithMax(t, mixedEvidence(), 0)
	deferred := generated(ref, events.TCPSYNRetransmission) + generated(ref, events.TCPSequenceGap) + generated(ref, events.TCPDuplicateACKRun)
	r := runWithMax(t, mixedEvidence(), ref.Events.Len()-deferred) // exactly the deferred events no longer fit
	for _, k := range []events.Kind{events.TCPSYNRetransmission, events.TCPSequenceGap, events.TCPDuplicateACKRun} {
		if generated(r, k) != 0 {
			t.Errorf("%s still present", k)
		}
	}
	if generated(r, events.TCPRetransmission) != generated(ref, events.TCPRetransmission) {
		t.Errorf("inline retransmission events were lost")
	}
	c := r.TCPEvidenceCompleteness
	if c == nil || c.KnownOmittedTotal() != deferred || c.TrackingLimitsTotal() != 0 {
		t.Fatalf("completeness = %+v, want %d known omitted events and no tracking limits", c, deferred)
	}
	for _, k := range []events.Kind{events.TCPSYNRetransmission, events.TCPSequenceGap, events.TCPDuplicateACKRun} {
		if c.KnownOmittedEvents[string(k)].IndexFull != generated(ref, k) {
			t.Errorf("%s index_full = %d, want %d", k, c.KnownOmittedEvents[string(k)].IndexFull, generated(ref, k))
		}
	}
}

// ─── per-kind caps at the real 10,000 bound ─────────────────────────────

func TestTCPEvidenceCompleteness_SYNRepeatKindCap(t *testing.T) {
	storm := make([][]byte, 0, 10052)
	for i := 0; i <= 10050; i++ { // initial SYN + 10,050 repeats
		storm = append(storm, seqFrame(compPort, hs[0]))
	}
	r := runWithMax(t, storm, 0)
	c := r.TCPEvidenceCompleteness
	if generated(r, events.TCPSYNRetransmission) != 10000 || c == nil ||
		c.KnownOmittedEvents["tcp.syn_retransmission"] != (models.EvidenceOmission{KindCap: 50}) || r.EventsDropped != 0 {
		t.Fatalf("events=%d completeness=%+v dropped=%d, want 10000 events and kind_cap 50", generated(r, events.TCPSYNRetransmission), c, r.EventsDropped)
	}
}

func TestTCPEvidenceCompleteness_GapKindCapAndGapsNotFollowed(t *testing.T) {
	pk := frames(compPort, hs...)
	seq := uint32(1001)
	for i := 0; i < 10100; i++ {
		seq += 20 // a 10-byte hole before every 10-byte segment
		pk = append(pk, seqFrame(compPort, cData(seq, 10)))
	}
	r := runWithMax(t, pk, 0)
	c := r.TCPEvidenceCompleteness
	if generated(r, events.TCPSequenceGap) != 10000 || c == nil {
		t.Fatalf("events=%d completeness=%v", generated(r, events.TCPSequenceGap), c)
	}
	if c.KnownOmittedEvents["tcp.sequence_gap"] != (models.EvidenceOmission{KindCap: 100}) {
		t.Errorf("known omitted = %+v, want kind_cap 100", c.KnownOmittedEvents["tcp.sequence_gap"])
	}
	// 16 gaps are followed per direction; the other recorded gaps cannot be followed.
	if c.TrackingLimits == nil || c.TrackingLimits.SequenceGapsNotFollowed != 10000-models.MaxOpenSeqGaps {
		t.Errorf("tracking limits = %+v, want sequence_gaps_not_followed %d", c.TrackingLimits, 10000-models.MaxOpenSeqGaps)
	}
}

func TestTCPEvidenceCompleteness_DuplicateACKRunKindCap(t *testing.T) {
	pk := frames(compPort, hs...)
	pk = append(pk, seqFrame(compPort, cData(1001, 1400))) // peer next 2401
	for i := 0; i < 10100; i++ {
		ack := uint32(1101)
		if i%2 == 1 {
			ack = 1201
		}
		pk = append(pk, seqFrame(compPort, srvAck(ack, 100)), seqFrame(compPort, srvAck(ack, 100)))
	}
	r := runWithMax(t, pk, 0)
	c := r.TCPEvidenceCompleteness
	if generated(r, events.TCPDuplicateACKRun) != 10000 || c == nil ||
		c.KnownOmittedEvents["tcp.duplicate_ack_run"] != (models.EvidenceOmission{KindCap: 100}) {
		t.Fatalf("events=%d completeness=%+v, want 10000 events and kind_cap 100", generated(r, events.TCPDuplicateACKRun), c)
	}
	if c.TrackingLimitsTotal() != 0 {
		t.Errorf("a kind cap must not create tracking limits: %+v", c.TrackingLimits)
	}
}

// ─── tracking limits are not event counts ──────────────────────────────

func TestTCPEvidenceCompleteness_PerDirectionGapCapIsATrackingLimit(t *testing.T) {
	specs := []seqSpec{cData(1001, 10)}
	seq := uint32(1011)
	for i := 0; i < models.MaxOpenSeqGaps+4; i++ {
		seq += 10
		specs = append(specs, cData(seq, 10))
		seq += 10
	}
	r := sc(t, compPort, specs...)
	c := r.TCPEvidenceCompleteness
	if c == nil || len(c.KnownOmittedEvents) != 0 || c.TrackingLimits == nil || c.TrackingLimits.SequenceGapsNotFollowed != 4 {
		t.Fatalf("completeness = %+v, want only sequence_gaps_not_followed = 4", c)
	}
	if generated(r, events.TCPSequenceGap) != models.MaxOpenSeqGaps+4 {
		t.Errorf("every observed gap should still be an event")
	}
}

func TestTCPEvidenceCompleteness_PeerPositionUnknownRepeatsAreALimit(t *testing.T) {
	r := runWithMax(t, frames(compPort, srvAck(1101, 100), srvAck(1101, 100), srvAck(1101, 100), srvAck(1101, 100)), 0)
	c := r.TCPEvidenceCompleteness
	if c == nil || c.TrackingLimits == nil || c.TrackingLimits.DuplicateACKRepeatsPeerPositionUnknown != 3 || len(c.KnownOmittedEvents) != 0 {
		t.Fatalf("completeness = %+v, want 3 peer-position-unknown repeats and no omitted events", c)
	}
	if generated(r, events.TCPDuplicateACKRun) != 0 {
		t.Error("unknown peer position produced a duplicate-ACK run")
	}
	// Idle repeats with a known, fully acknowledged peer are not a limitation.
	idle := sc(t, compPort, cData(1001, 100), srvAck(1101, 100), srvAck(1101, 100), srvAck(1101, 100))
	if idle.TCPEvidenceCompleteness != nil {
		t.Errorf("idle ACKs with a known peer produced %+v", idle.TCPEvidenceCompleteness)
	}
}

// Unreadable segment lengths (truncated capture, zero IP length) re-baseline the
// direction: evidence collection was interrupted, but nothing was "omitted".
func TestTCPEvidenceCompleteness_UnreadableLengthResetsAreLimitsNotOmissions(t *testing.T) {
	var specs []seqSpec
	seq := uint32(1001)
	for i := 0; i < 6; i++ {
		specs = append(specs, cData(seq, 1400))
		seq += 1400
	}
	frs := append(frames(compPort, hs...), frames(compPort, specs...)...)
	for i := 3; i < len(frs); i++ { // zero the IPv4 total length of the data segments
		frs[i][16], frs[i][17] = 0, 0
	}
	r := runPCAPFile(t, truncatedPCAP(t, frs, 120), NewProcessorWithOptions(false, false))
	c := r.TCPEvidenceCompleteness
	if c == nil || c.TrackingLimits == nil || c.TrackingLimits.SequenceLengthUnreadableResets != 6 {
		t.Fatalf("completeness = %+v, want 6 unreadable-length resets", c)
	}
	if len(c.KnownOmittedEvents) != 0 || c.KnownOmittedTotal() != 0 {
		t.Errorf("a tracking reset was reported as omitted events: %+v", c.KnownOmittedEvents)
	}
	if generated(r, events.TCPSequenceGap) != 0 {
		t.Error("unreadable lengths produced gap events")
	}
	// Control: the same capture with readable lengths is unaffected.
	frs2 := append(frames(compPort, hs...), frames(compPort, specs...)...)
	if clean := runPCAPFile(t, truncatedPCAP(t, frs2, 120), NewProcessorWithOptions(false, false)); clean.TCPEvidenceCompleteness != nil {
		t.Errorf("readable lengths produced %+v", clean.TCPEvidenceCompleteness)
	}
}

// ─── affected vs clean, determinism, JSON ───────────────────────────────

func TestTCPEvidenceCompleteness_CleanCaptureHasNoObjectAndNoKey(t *testing.T) {
	r := runWithMax(t, mixedEvidence(), 0)
	if r.TCPEvidenceCompleteness != nil {
		t.Fatalf("clean capture reports %+v", r.TCPEvidenceCompleteness)
	}
	b, _ := json.Marshal(r)
	// The KEY must be absent (other summaries may mention the name in their prose).
	if strings.Contains(string(b), `"tcp_evidence_completeness":`) {
		t.Error("clean capture serializes the tcp_evidence_completeness key")
	}
}

func TestTCPEvidenceCompleteness_AffectedCaptureSerializesDeterministically(t *testing.T) {
	snap := func() string {
		r := runWithMax(t, mixedEvidence(), 3)
		if r.TCPEvidenceCompleteness == nil {
			t.Fatal("affected capture reports no completeness")
		}
		b, _ := json.Marshal(r.TCPEvidenceCompleteness)
		return string(b)
	}
	first := snap()
	for i := 0; i < 4; i++ {
		if got := snap(); got != first {
			t.Fatalf("run %d differs:\n%s\n%s", i+2, first, got)
		}
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(first), &m); err != nil {
		t.Fatal(err)
	}
	if _, ok := m["known_omitted_events"]; !ok {
		t.Errorf("known_omitted_events missing: %s", first)
	}
	if sem, _ := m["semantics"].(string); !strings.Contains(sem, "does not prove") {
		t.Errorf("semantics text missing/incorrect: %q", sem)
	}
}

// The additive object changes nothing else: verdict layers, retransmission and loss
// outputs are identical whether or not evidence was constrained.
func TestTCPEvidenceCompleteness_NoEffectOnExistingOutputs(t *testing.T) {
	a := runWithMax(t, mixedEvidence(), 0)
	b := runWithMax(t, mixedEvidence(), 2) // heavily constrained index
	if a.NetworkHealth != b.NetworkHealth || a.RiskScore != b.RiskScore || len(a.Findings) != len(b.Findings) ||
		len(a.RootCauseChains) != len(b.RootCauseChains) || len(a.TCPRetransmissions) != len(b.TCPRetransmissions) ||
		lostPackets(a) != lostPackets(b) {
		t.Errorf("legacy outputs differ: health %q/%q risk %d/%d findings %d/%d", a.NetworkHealth, b.NetworkHealth, a.RiskScore, b.RiskScore, len(a.Findings), len(b.Findings))
	}
}

// ─── optional real captures ────────────────────────────────────────────

// Measured with the Phase 4.31a build. The affected captures are those where the
// engine could not decide duplicate-ACK status because the peer's sequence position
// was unknown (tshark counts these repeats as duplicate ACKs: user1 53, Velocloud-Lan
// 50, Velocloud-Wan 35) and cisco-example-lan, whose 991 recorded gaps could not be
// followed past the per-direction cap. All other corpus captures report nothing.
func TestTCPEvidenceCompleteness_RealCaptureBaseline(t *testing.T) {
	dir := os.Getenv("SDWAN_VENDOR_PCAP_DIR")
	if dir == "" {
		t.Skip("SDWAN_VENDOR_PCAP_DIR not set; skipping real-capture completeness baseline")
	}
	type want struct{ omitted, notFollowed, peerUnknown int }
	cases := []struct {
		name     string
		affected bool
		w        want
	}{
		{"Lab 2-DisplayFilters", false, want{}},
		{"Lab 3-TCP Retrans", false, want{}},
		{"Lab 4-NetworkCongestion", false, want{}},
		{"Lab 5-AnotherSlowApp", false, want{}},
		{"Lab 6-TCPResets", false, want{}},
		{"Lab 7-TCPIssues", false, want{}},
		{"Pre-Lab-SlowNetwork", false, want{}},
		{"The-Ultimate-PCAP", false, want{}},
		{"user1", true, want{0, 0, 50}},
		{"Velocloud-Lan", true, want{0, 0, 38}},
		{"Velocloud-Wan", true, want{0, 0, 22}},
		{"cisco-example-lan", true, want{0, 991, 5}},
		{"cisco-example-wan", false, want{}},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			var path string
			for _, ext := range []string{".pcap", ".pcapng"} {
				p := filepath.Join(dir, c.name+ext)
				if _, err := os.Stat(p); err == nil {
					path = p
					break
				}
			}
			if path == "" {
				t.Skipf("%s not present in %s", c.name, dir)
			}
			r := runPCAPFile(t, path, NewProcessorWithOptions(false, false))
			cmp := r.TCPEvidenceCompleteness
			if (cmp != nil) != c.affected {
				t.Fatalf("completeness present=%v, want %v: %+v", cmp != nil, c.affected, cmp)
			}
			if cmp == nil {
				return
			}
			got := want{omitted: cmp.KnownOmittedTotal()}
			if cmp.TrackingLimits != nil {
				got.notFollowed = cmp.TrackingLimits.SequenceGapsNotFollowed
				got.peerUnknown = cmp.TrackingLimits.DuplicateACKRepeatsPeerPositionUnknown
			}
			if got != c.w {
				t.Errorf("omitted/notFollowed/peerUnknown = %+v, want %+v", got, c.w)
			}
		})
	}
}
