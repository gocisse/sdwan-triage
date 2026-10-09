package analyzer

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gocisse/sdwan-triage/internal/testpcap"
	"github.com/gocisse/sdwan-triage/pkg/models"
)

// Phase 4.31b — bounded per-flow TCP evidence summary. It only re-groups existing
// evidence events; it must stay observational (never "lost", "dropped by", "provider",
// "fast retransmit confirmed") and carry frame numbers (ordinal + 1), completeness and
// truncation caveats. Packets are 100 ms apart; the handshake takes ordinals 0-2.

const fePort = 57000

var bannedClaims = []string{"packet loss", "was lost", "were lost", "dropped by", "provider", "fast retransmit", "fault", "confirmed", "no loss"}

func assertObservational(t *testing.T, text string) {
	t.Helper()
	l := strings.ToLower(text)
	for _, b := range bannedClaims {
		if strings.Contains(l, b) {
			t.Errorf("text makes an unsupported claim (%q): %s", b, text)
		}
	}
}

func summaryOf(t *testing.T, r *models.TriageReport) *models.TCPFlowEvidenceSummary {
	t.Helper()
	if r.TCPFlowEvidence == nil {
		t.Fatal("no tcp_flow_evidence summary")
	}
	return r.TCPFlowEvidence
}

func TestFlowEvidence_AbsentWithoutTCPEvidence(t *testing.T) {
	r := runGolden(t, handshake(fePort))
	if r.TCPFlowEvidence != nil {
		t.Errorf("summary present without evidence: %+v", r.TCPFlowEvidence)
	}
	b, _ := json.Marshal(r)
	if strings.Contains(string(b), "tcp_flow_evidence") {
		t.Error("key serialized without evidence")
	}
}

// Lab-3 pattern on one flow: gap, SACK duplicate ACKs, fill, plus a repeated segment.
func TestFlowEvidence_Lab3PatternGroupsDirectionsIntoOneFlow(t *testing.T) {
	sack := func(to uint32) seqSpec { return srvSack(1101, 17520, [2]uint32{1201, to}) }
	r := sc(t, fePort,
		cData(1001, 100),    // 3
		srvAck(1101, 17520), // 4  initial ACK (run start)
		cData(1201, 100),    // 5  gap [1101,1201) exposed
		sack(1301),          // 6  dup 1
		cData(1301, 100),    // 7
		sack(1401),          // 8  dup 2
		cData(1401, 100),    // 9
		sack(1501),          // 10 dup 3
		cData(1101, 100),    // 11 fill
		srvAck(1501, 17520), // 12 ends the run
		cData(1001, 100),    // 13 repeated segment
	)
	s := summaryOf(t, r)
	if s.FlowsWithEvidence != 1 || s.FlowsShown != 1 || s.Truncated || s.CompletenessAffected {
		t.Fatalf("summary header = %+v", s)
	}
	f := s.Flows[0]
	if f.Endpoints != "10.0.0.50:443 <-> 192.168.1.100:57000" {
		t.Errorf("endpoints = %q", f.Endpoints)
	}
	if strings.Join(f.EvidenceKinds, ",") != "duplicate_ack_run,retransmission,sequence_gap" {
		t.Errorf("kinds = %v", f.EvidenceKinds)
	}
	// Directions stay clear: the gap is in the data direction, the run in the ACK sender's.
	if len(f.SequenceGaps) != 1 || f.SequenceGaps[0].Direction != "192.168.1.100:57000->10.0.0.50:443" {
		t.Fatalf("gaps = %+v", f.SequenceGaps)
	}
	g := f.SequenceGaps[0]
	if g.Frame != 6 || g.Resolution != "filled" || g.GapStart != 1101 || g.GapEnd != 1201 || g.GapBytes != 100 || g.FillDelayMs == nil || math.Abs(*g.FillDelayMs-600) > 0.5 {
		t.Errorf("gap = %+v", g)
	}
	if len(f.DuplicateACKRuns) != 1 || f.DuplicateACKRuns[0].Direction != "10.0.0.50:443->192.168.1.100:57000" {
		t.Fatalf("runs = %+v", f.DuplicateACKRuns)
	}
	d := f.DuplicateACKRuns[0]
	if d.Ack != 1101 || d.Window != 17520 || d.Duplicates != 3 || d.FirstFrame != 5 || d.LastFrame != 11 || d.SACK != "observed" ||
		len(d.SACKEdges) != 1 || d.SACKEdges[0] != [2]uint64{1201, 1501} || d.EndedBy != "ack_changed" {
		t.Errorf("run = %+v", d)
	}
	if f.RepeatedSegments == nil || f.RepeatedSegments.Count != 1 || len(f.RepeatedSegments.Frames) != 1 || f.RepeatedSegments.Frames[0] != 14 {
		t.Errorf("repeated segments = %+v", f.RepeatedSegments)
	}
	for _, text := range []string{g.Description, d.Description, f.RepeatedSegments.Description, s.CompletenessNote, s.FrameNumberBasis, s.Order} {
		assertObservational(t, text)
	}
	if !strings.Contains(g.Description, "not observed before later data") || !strings.Contains(d.Description, "while data was outstanding") {
		t.Errorf("descriptions: %q / %q", g.Description, d.Description)
	}
}

func TestFlowEvidence_SingleEvidenceTypeFlows(t *testing.T) {
	cases := map[string]func() *models.TriageReport{
		"retransmission": func() *models.TriageReport { return sc(t, fePort, cData(1001, 100), cData(1001, 100)) },
		"sequence_gap":   func() *models.TriageReport { return sc(t, fePort, cData(1001, 100), cData(1301, 100)) },
		"duplicate_ack_run": func() *models.TriageReport {
			return sc(t, fePort, append(outstandingData(), srvAck(1101, 100), srvAck(1101, 100))...)
		},
		"repeated_handshake": func() *models.TriageReport {
			return runGolden(t, frames(fePort, hs[0], hs[0]))
		},
	}
	for kind, run := range cases {
		s := summaryOf(t, run())
		if s.FlowsWithEvidence != 1 || len(s.Flows[0].EvidenceKinds) != 1 || s.Flows[0].EvidenceKinds[0] != kind {
			t.Errorf("%s: flows=%d kinds=%v", kind, s.FlowsWithEvidence, s.Flows[0].EvidenceKinds)
		}
	}
}

func TestFlowEvidence_GapResolutionsDoNotOverstate(t *testing.T) {
	cases := []struct {
		name    string
		specs   []seqSpec
		res     string
		must    []string
		mustNot []string
	}{
		{"unresolved", []seqSpec{cData(1001, 100), cData(1301, 100)}, "unresolved",
			[]string{"not observed before later data", "neither observed later nor acknowledged beyond"}, []string{"subsequently filled"}},
		{"acked_beyond", []seqSpec{cData(1001, 100), cData(1301, 100), sAck(1401, 0)}, "acked_beyond",
			[]string{"acknowledgment later reached beyond the range", "not fully observed"}, []string{"subsequently filled", "neither observed"}},
		{"partially filled and unresolved", []seqSpec{cData(1001, 100), cData(1301, 100), cData(1101, 100)}, "unresolved",
			[]string{"100 of 200 bytes were subsequently observed", "100 bytes remained unobserved"}, []string{"subsequently filled after"}},
		{"filled", []seqSpec{cData(1001, 100), cData(1301, 100), cData(1101, 200)}, "filled",
			[]string{"subsequently filled after approximately 100 ms"}, []string{"neither observed"}},
	}
	for _, c := range cases {
		g := summaryOf(t, sc(t, fePort, c.specs...)).Flows[0].SequenceGaps[0]
		if g.Resolution != c.res {
			t.Errorf("%s: resolution = %q", c.name, g.Resolution)
		}
		for _, m := range c.must {
			if !strings.Contains(g.Description, m) {
				t.Errorf("%s: description %q lacks %q", c.name, g.Description, m)
			}
		}
		for _, m := range c.mustNot {
			if strings.Contains(g.Description, m) {
				t.Errorf("%s: description %q contains %q", c.name, g.Description, m)
			}
		}
		assertObservational(t, g.Description)
	}
	// Midstream and limitation qualifiers appear in the text.
	g := summaryOf(t, runGolden(t, frames(fePort, cData(9_000_001, 100), cData(9_000_301, 100)))).Flows[0].SequenceGaps[0]
	if g.Baseline != "midstream" || !strings.Contains(g.Description, "first seen mid-connection") {
		t.Errorf("midstream gap = %+v", g)
	}
}

func TestFlowEvidence_RepeatedSYNWithAndWithoutSYNACK(t *testing.T) {
	without := summaryOf(t, runGolden(t, frames(fePort, hs[0], hs[0], hs[0]))).Flows[0]
	if len(without.RepeatedHandshake) != 2 {
		t.Fatalf("records = %+v", without.RepeatedHandshake)
	}
	for i, h := range without.RepeatedHandshake {
		if h.Segment != "SYN" || h.Attempt != i+2 || h.SYNACKObserved == nil || *h.SYNACKObserved || h.Frame != uint64(i+2) ||
			!strings.Contains(h.Description, "No SYN-ACK was observed for this address/port pair in this capture") {
			t.Errorf("record %d = %+v", i, h)
		}
		assertObservational(t, h.Description)
	}
	with := summaryOf(t, runGolden(t, frames(fePort, hs[0], hs[0], hs[1], hs[2]))).Flows[0]
	h := with.RepeatedHandshake[0]
	if h.SYNACKObserved == nil || !*h.SYNACKObserved || !strings.Contains(h.Description, "A SYN-ACK was observed for this address/port pair in this capture (not matched to this attempt; it may precede or follow this repeat)") {
		t.Errorf("record with SYN-ACK observed = %+v", h)
	}
	// A repeated SYN-ACK is described as such and carries no synack_observed flag.
	sa := summaryOf(t, runGolden(t, frames(fePort, hs[0], hs[1], hs[1]))).Flows[0].RepeatedHandshake[0]
	if sa.Segment != "SYN-ACK" || sa.SYNACKObserved != nil || !strings.HasPrefix(sa.Description, "Repeated SYN-ACK observed") {
		t.Errorf("SYN-ACK record = %+v", sa)
	}
}

// ─── ordering, bounds, determinism ──────────────────────────────────────

func manyFlows(n int) [][]byte {
	var pk [][]byte
	for i := 0; i < n; i++ {
		pk = append(pk, frames(uint16(fePort+100+i), hs[0], hs[0])...) // one repeated SYN per flow
	}
	return pk
}

func TestFlowEvidence_FlowBoundAndTruncationAreExplicit(t *testing.T) {
	s := summaryOf(t, runGolden(t, manyFlows(25)))
	if s.FlowsWithEvidence != 25 || s.FlowsShown != 20 || len(s.Flows) != 20 || !s.Truncated || s.OmittedFlows != 5 || s.OmittedRecords != 5 {
		t.Errorf("header = flows %d shown %d omittedFlows %d omittedRecords %d truncated %v", s.FlowsWithEvidence, s.FlowsShown, s.OmittedFlows, s.OmittedRecords, s.Truncated)
	}
	if s.Limits.MaxFlows != 20 || s.Limits.MaxRecordsPerKind != 10 || s.Limits.MaxFramesPerEntry != 10 {
		t.Errorf("limits = %+v", s.Limits)
	}
	// A summary within the bounds is not marked truncated.
	if s2 := summaryOf(t, runGolden(t, manyFlows(3))); s2.Truncated || s2.OmittedFlows != 0 {
		t.Errorf("small summary flagged truncated: %+v", s2)
	}
}

func TestFlowEvidence_PerFlowRecordAndFrameBounds(t *testing.T) {
	var specs []seqSpec
	seq := uint32(1001)
	specs = append(specs, cData(seq, 10))
	seq += 10
	for i := 0; i < 12; i++ { // 12 gaps in one direction
		seq += 10
		specs = append(specs, cData(seq, 10))
		seq += 10
	}
	f := summaryOf(t, sc(t, fePort, specs...)).Flows[0]
	if len(f.SequenceGaps) != 10 || f.Omitted == nil || f.Omitted.SequenceGaps != 2 {
		t.Errorf("gap records shown %d, omitted %+v, want 10 / 2", len(f.SequenceGaps), f.Omitted)
	}
	s := summaryOf(t, sc(t, fePort, specs...))
	if !s.Truncated || s.OmittedRecords != 2 {
		t.Errorf("record truncation not reported: truncated=%v omittedRecords=%d", s.Truncated, s.OmittedRecords)
	}
	// 13 repeated segments: all counted, only 10 frames listed, and the cut is marked.
	rep := []seqSpec{cData(1001, 100)}
	for i := 0; i < 12; i++ {
		rep = append(rep, cData(1001, 100))
	}
	rs := summaryOf(t, sc(t, fePort, rep...)).Flows[0].RepeatedSegments
	if rs.Count != 12 || len(rs.Frames) != 10 || !rs.FramesTruncated {
		t.Errorf("repeated segments = count %d frames %d truncated %v", rs.Count, len(rs.Frames), rs.FramesTruncated)
	}
	for i := 1; i < len(rs.Frames); i++ {
		if rs.Frames[i] <= rs.Frames[i-1] {
			t.Errorf("frames not ascending: %v", rs.Frames)
		}
	}
}

func TestFlowEvidence_OrderRichestFirstThenTimeThenEndpoints(t *testing.T) {
	var pk [][]byte
	// Flow A (earliest): one repeated SYN. Flow B: gap + repeated SYN (two kinds). Flow C: one repeated SYN.
	// Every flow completes its handshake (SYN-ACK observed), so the Phase 4.31d
	// "repeated SYN without SYN-ACK first" tier does not apply and the volume rules are what is tested.
	pk = append(pk, frames(fePort+1, hs[0], hs[0], hs[1], hs[2])...)
	pk = append(pk, frames(fePort+2, hs[0], hs[0], hs[1], hs[2], cData(1001, 100), cData(1301, 100))...)
	pk = append(pk, frames(fePort+3, hs[0], hs[0], hs[1], hs[2])...)
	s := summaryOf(t, runGolden(t, pk))
	var order []string
	for _, f := range s.Flows {
		order = append(order, f.Endpoints)
	}
	want := []string{"10.0.0.50:443 <-> 192.168.1.100:57002", "10.0.0.50:443 <-> 192.168.1.100:57001", "10.0.0.50:443 <-> 192.168.1.100:57003"}
	if strings.Join(order, "|") != strings.Join(want, "|") {
		t.Errorf("order = %v, want %v", order, want)
	}
}

func TestFlowEvidence_DeterministicJSON(t *testing.T) {
	build := func() [][]byte {
		pk := manyFlows(6)
		return append(pk, append(frames(fePort, hs...), frames(fePort, cData(1001, 100), cData(1301, 100), cData(1001, 100), srvAck(1101, 100), srvAck(1101, 100))...)...)
	}
	snap := func() string {
		b, err := json.Marshal(summaryOf(t, runGolden(t, build())))
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	first := snap()
	for i := 0; i < 4; i++ {
		if got := snap(); got != first {
			t.Fatalf("run %d differs", i+2)
		}
	}
}

// ─── completeness ───────────────────────────────────────────────────────

func TestFlowEvidence_CompletenessCaveatIsCarried(t *testing.T) {
	clean := summaryOf(t, runWithMax(t, mixedEvidence(), 0))
	if clean.CompletenessAffected {
		t.Error("clean capture flagged as affected")
	}
	// Even a clean summary states that zero limits do not prove completeness.
	if !strings.Contains(clean.CompletenessNote, "does not prove") || !strings.Contains(clean.CompletenessNote, "tcp_evidence_completeness") {
		t.Errorf("note = %q", clean.CompletenessNote)
	}
	// Constrain the index so that deferred evidence is lost: the summary says so.
	r := runWithMax(t, mixedEvidence(), 3)
	if r.TCPEvidenceCompleteness == nil {
		t.Fatal("setup: expected completeness to be affected")
	}
	if s := r.TCPFlowEvidence; s != nil && !s.CompletenessAffected {
		t.Error("summary of an affected capture does not carry the caveat")
	}
	// Peer-position-unknown limit with otherwise-present evidence.
	r = runGolden(t, append(frames(fePort, hs[0], hs[0]), frames(fePort+1, srvAck(1101, 100), srvAck(1101, 100), srvAck(1101, 100))...))
	if s := summaryOf(t, r); !s.CompletenessAffected {
		t.Error("tracking limit not reflected in the summary")
	}
}

// ─── frame references ──────────────────────────────────────────────────

// The frame number is the packet's 1-based position in the capture file, also when
// packets of an unsupported link type are interleaved and never analysed.
func TestFlowEvidence_FrameNumbersCountUnsupportedPackets(t *testing.T) {
	unsupported := func() testpcap.NGPacket { return testpcap.NGPacket{Interface: 1, Data: make([]byte, 40)} }
	eth := func(s seqSpec) testpcap.NGPacket { return testpcap.NGPacket{Interface: 0, Data: seqFrame(fePort, s)} }
	pkts := []testpcap.NGPacket{
		unsupported(), unsupported(), // frames 1-2
		eth(hs[0]), eth(hs[1]), eth(hs[2]), // frames 3-5
		unsupported(),         // frame 6
		eth(cData(1001, 100)), // frame 7
		eth(cData(1301, 100)), // frame 8: exposes the gap
		unsupported(),         // frame 9
		eth(cData(1301, 100)), // frame 10: repeated segment
		eth(hs[0]),            // frame 11: a SYN repeat after the handshake would not count; the earlier SYN is pending? (see below)
	}
	path := writeNG(t, []uint16{testpcap.LinkTypeEthernet, testpcap.LinkTypeEthernetMPkt}, pkts)
	r, sum, err := processFile(t, path)
	if err != nil || sum.PacketsUnsupported != 4 {
		t.Fatalf("setup: err=%v summary=%+v", err, sum)
	}
	f := summaryOf(t, r).Flows[0]
	if len(f.SequenceGaps) != 1 || f.SequenceGaps[0].Frame != 8 {
		t.Errorf("gap frame = %+v, want 8", f.SequenceGaps)
	}
	if f.RepeatedSegments == nil || len(f.RepeatedSegments.Frames) != 1 || f.RepeatedSegments.Frames[0] != 10 {
		t.Errorf("repeated segment frames = %+v, want [10]", f.RepeatedSegments)
	}
	// Control: the same packets without unsupported ones shift the frame numbers accordingly.
	plain := summaryOf(t, runGolden(t, [][]byte{seqFrame(fePort, hs[0]), seqFrame(fePort, hs[1]), seqFrame(fePort, hs[2]),
		seqFrame(fePort, cData(1001, 100)), seqFrame(fePort, cData(1301, 100)), seqFrame(fePort, cData(1301, 100))})).Flows[0]
	if plain.SequenceGaps[0].Frame != 5 || plain.RepeatedSegments.Frames[0] != 6 {
		t.Errorf("plain frames = gap %d repeated %v, want 5 / 6", plain.SequenceGaps[0].Frame, plain.RepeatedSegments.Frames)
	}
}

// The conversion is applied exactly once: the summary frame is the event ordinal + 1.
func TestFlowEvidence_FrameIsOrdinalPlusOneExactlyOnce(t *testing.T) {
	r := sc(t, fePort, cData(1001, 100), cData(1301, 100))
	var ordinal uint64
	for _, e := range gapEvents(r) {
		ordinal = e.Packets[0].Index
	}
	if got := summaryOf(t, r).Flows[0].SequenceGaps[0].Frame; got != ordinal+1 || got != captureFrameNumber(ordinal) {
		t.Errorf("frame = %d, event ordinal = %d", got, ordinal)
	}
}

// ─── optional real captures ─────────────────────────────────────────────

// Frame numbers pinned from the tool and cross-checked against tshark in Phase 4.30e/4.31b
// (tcp.analysis.lost_segment / retransmission && syn frames; unique connection counts for
// Velocloud-Lan 31, Velocloud-Wan 2, user1 1 were also confirmed with tshark). Observations only.
func TestFlowEvidence_RealCaptureFrames(t *testing.T) {
	dir := os.Getenv("SDWAN_VENDOR_PCAP_DIR")
	if dir == "" {
		t.Skip("SDWAN_VENDOR_PCAP_DIR not set; skipping real-capture frame checks")
	}
	type check struct {
		name       string
		flows      int
		gapFrames  []uint64 // frames of sequence_gap records found in the shown flows (subset check)
		synFrames  []uint64 // first frames of repeated handshake records (subset check)
		runFrames  [][2]uint64
		completion bool
	}
	cases := []check{
		{name: "Lab 3-TCP Retrans", flows: 1, gapFrames: []uint64{54}, runFrames: [][2]uint64{{53, 59}, {61, 63}}},
		{name: "Lab 4-NetworkCongestion", flows: 1, synFrames: []uint64{2, 6}},
		{name: "Velocloud-Wan", flows: 2, completion: true},
		{name: "Velocloud-Lan", flows: 31, synFrames: []uint64{3214}, completion: true},
		{name: "cisco-example-lan", flows: 320, completion: true},
		{name: "The-Ultimate-PCAP", flows: 63},
		{name: "user1", flows: 1, completion: true},
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
			s := summaryOf(t, r)
			if s.FlowsWithEvidence != c.flows {
				t.Errorf("flows with evidence = %d, want %d", s.FlowsWithEvidence, c.flows)
			}
			if s.CompletenessAffected != c.completion {
				t.Errorf("completeness affected = %v, want %v", s.CompletenessAffected, c.completion)
			}
			gaps := map[uint64]bool{}
			syns := map[uint64]bool{}
			runs := map[[2]uint64]bool{}
			for _, f := range s.Flows {
				for _, g := range f.SequenceGaps {
					gaps[g.Frame] = true
				}
				for _, h := range f.RepeatedHandshake {
					syns[h.Frame] = true
				}
				for _, d := range f.DuplicateACKRuns {
					runs[[2]uint64{d.FirstFrame, d.LastFrame}] = true
				}
			}
			for _, fr := range c.gapFrames {
				if !gaps[fr] {
					t.Errorf("gap frame %d not found (have %v)", fr, gaps)
				}
			}
			for _, fr := range c.synFrames {
				if !syns[fr] {
					t.Errorf("repeated-handshake frame %d not found", fr)
				}
			}
			for _, fr := range c.runFrames {
				if !runs[fr] {
					t.Errorf("duplicate-ACK run frames %v not found (have %v)", fr, runs)
				}
			}
		})
	}
}

var _ = fmt.Sprintf
