package analyzer

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/gocisse/sdwan-triage/internal/testpcap"
	"github.com/gocisse/sdwan-triage/pkg/models"
	"github.com/google/gopacket/layers"
)

func handshakeNG(extra ...testpcap.NGPacket) []testpcap.NGPacket {
	pkts := testpcap.EthernetNG(testpcap.Handshake())
	return append(pkts, extra...)
}

func unsupportedPkts(n int) []testpcap.NGPacket {
	out := make([]testpcap.NGPacket, n)
	for i := range out {
		out[i] = testpcap.NGPacket{Interface: 1, Data: make([]byte, 40)}
	}
	return out
}

func TestCompleteness_NilForCompleteCaptures(t *testing.T) {
	ng := writeNG(t, []uint16{testpcap.LinkTypeEthernet}, handshakeNG())
	r, _, err := processFile(t, ng)
	if err != nil {
		t.Fatal(err)
	}
	if r.Completeness != nil {
		t.Fatalf("complete pcapng must have nil completeness, got %+v", r.Completeness)
	}
	pc := filepath.Join(t.TempDir(), "c.pcap")
	if err := testpcap.WriteFile(pc, testpcap.Handshake()); err != nil {
		t.Fatal(err)
	}
	r, _, err = processFile(t, pc)
	if err != nil || r.Completeness != nil {
		t.Fatalf("complete pcap: err=%v completeness=%+v", err, r.Completeness)
	}
	b, _ := json.Marshal(r)
	if strings.Contains(string(b), "capture_completeness") {
		t.Error("JSON of a complete capture must not contain capture_completeness")
	}
}

func TestCompleteness_Unsupported(t *testing.T) {
	path := writeNG(t, []uint16{testpcap.LinkTypeEthernet, testpcap.LinkTypeEthernetMPkt}, handshakeNG(unsupportedPkts(4)...))
	r, _, err := processFile(t, path)
	if err != nil {
		t.Fatal(err)
	}
	c := r.Completeness
	if c == nil || c.PacketsRead != 9 || c.PacketsDecoded != 5 || c.PacketsUnsupported != 4 || c.PacketsDecodeFailed != 0 || c.PacketsSkipped != 0 || c.ReadErrors != 0 {
		t.Fatalf("unexpected completeness %+v", c)
	}
	if len(c.UnsupportedLinkTypes) != 1 || c.UnsupportedLinkTypes[0].LinkType != 18 || c.UnsupportedLinkTypes[0].Packets != 4 || !strings.Contains(c.UnsupportedLinkTypes[0].Label, "274") {
		t.Fatalf("unexpected unsupported link types %+v", c.UnsupportedLinkTypes)
	}
	if !c.IsPartial() {
		t.Error("IsPartial must be true")
	}
}

func TestCompleteness_DecodeFailure(t *testing.T) {
	// Valid handshake plus frames too short to hold an Ethernet header.
	frames := append(testpcap.Handshake(), []byte{1, 2}, []byte{3, 4, 5})
	path := filepath.Join(t.TempDir(), "df.pcap")
	if err := testpcap.WriteFile(path, frames); err != nil {
		t.Fatal(err)
	}
	r, _, err := processFile(t, path)
	if err != nil {
		t.Fatal(err)
	}
	c := r.Completeness
	if c == nil || c.PacketsDecodeFailed != 2 || c.PacketsUnsupported != 0 || c.PacketsSkipped != 0 || c.ReadErrors != 0 || c.PacketsDecoded != 5 {
		t.Fatalf("unexpected completeness %+v", c)
	}
}

func TestCompleteness_ReadError_TruncatedCapture(t *testing.T) {
	frames := testpcap.Handshake()
	full := filepath.Join(t.TempDir(), "full.pcap")
	if err := testpcap.WriteFile(full, frames); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(full)
	if err != nil {
		t.Fatal(err)
	}
	cut := filepath.Join(t.TempDir(), "cut.pcap")
	if err := os.WriteFile(cut, b[:len(b)-10], 0o644); err != nil { // last record cut mid-payload
		t.Fatal(err)
	}
	r, _, err := processFile(t, cut)
	if err != nil {
		t.Fatalf("a truncated capture must still analyze what it has: %v", err)
	}
	if r.Completeness == nil || r.Completeness.ReadErrors < 1 || r.Completeness.PacketsUnsupported != 0 {
		t.Fatalf("truncated capture must record a read error: %+v", r.Completeness)
	}

	// Same analysis result as the capture without its final packet (only completeness differs).
	shorter := filepath.Join(t.TempDir(), "short.pcap")
	if err := testpcap.WriteFile(shorter, frames[:len(frames)-1]); err != nil {
		t.Fatal(err)
	}
	s, _, err := processFile(t, shorter)
	if err != nil {
		t.Fatal(err)
	}
	if s.Completeness != nil {
		t.Fatalf("clean short capture must be complete: %+v", s.Completeness)
	}
	assertSameAnalysis(t, s, r)
}

// Skipped packets and multiple causes: set the private counters directly (a
// recovered detector panic cannot be provoked from valid traffic).
func TestCompleteness_SkippedAndMultipleCauses(t *testing.T) {
	p := NewProcessorWithOptions(false, false)
	p.decode = decodeStats{read: 100, decoded: 80, failed: 5}
	p.decode.addUnsupported(200)
	p.decode.addUnsupported(18)
	p.decode.addUnsupported(18)
	p.skippedPackets = 3
	p.errorCount = 2
	c := p.buildCompleteness()
	want := &models.CaptureCompleteness{
		PacketsRead: 100, PacketsDecoded: 80, PacketsUnsupported: 3, PacketsDecodeFailed: 5, PacketsSkipped: 3, ReadErrors: 2,
		UnsupportedLinkTypes: []models.UnsupportedLinkType{
			{LinkType: 18, Label: LinkTypeLabel(layers.LinkType(18)), Packets: 2},
			{LinkType: 200, Label: LinkTypeLabel(layers.LinkType(200)), Packets: 1},
		},
	}
	if !reflect.DeepEqual(c, want) {
		t.Fatalf("got  %+v\nwant %+v", c, want)
	}
	// Each cause alone makes the capture partial and stays separate.
	for name, set := range map[string]func(*Processor){
		"skipped only": func(q *Processor) { q.skippedPackets = 1 },
		"read error":   func(q *Processor) { q.errorCount = 1 },
		"failed only":  func(q *Processor) { q.decode.failed = 1 },
		"unsupported":  func(q *Processor) { q.decode.addUnsupported(18) },
	} {
		q := NewProcessorWithOptions(false, false)
		q.decode = decodeStats{read: 10, decoded: 9}
		set(q)
		got := q.buildCompleteness()
		if got == nil || !got.IsPartial() {
			t.Errorf("%s: expected partial completeness, got %+v", name, got)
		}
	}
	// Nothing wrong → nil.
	q := NewProcessorWithOptions(false, false)
	q.decode = decodeStats{read: 10, decoded: 10}
	if q.buildCompleteness() != nil {
		t.Error("complete analysis must yield nil")
	}
}

func TestCompleteness_Deterministic(t *testing.T) {
	path := writeNG(t, []uint16{testpcap.LinkTypeEthernet, testpcap.LinkTypeEthernetMPkt, 200}, handshakeNG(
		testpcap.NGPacket{Interface: 2, Data: make([]byte, 30)},
		testpcap.NGPacket{Interface: 1, Data: make([]byte, 30)},
		testpcap.NGPacket{Interface: 1, Data: make([]byte, 30)},
	))
	var first string
	for i := 0; i < 20; i++ {
		r, _, err := processFile(t, path)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := json.Marshal(r.Completeness)
		if i == 0 {
			first = string(b)
			if !strings.Contains(first, `"link_type":18`) || strings.Index(first, `"link_type":18`) > strings.Index(first, `"link_type":200`) {
				t.Fatalf("unsupported link types must be sorted: %s", first)
			}
			continue
		}
		if string(b) != first {
			t.Fatalf("run %d differs:\n%s\n%s", i, b, first)
		}
	}
}

// Zero-decode protection is untouched: no report, no completeness, typed error.
func TestCompleteness_ZeroDecodeStillAnError(t *testing.T) {
	path := writeNG(t, []uint16{testpcap.LinkTypeEthernetMPkt}, []testpcap.NGPacket{{Interface: 0, Data: make([]byte, 40)}})
	r, _, err := processFile(t, path)
	if err == nil || !strings.Contains(err.Error(), "none could be decoded") {
		t.Fatalf("err = %v, want ErrNoDecodablePackets", err)
	}
	if r.Completeness != nil {
		t.Error("completeness must not be attached when Process fails")
	}
}

// Completeness is evidence-scope metadata: analysis of the supported packets
// must be identical with and without unsupported packets in the file.
func TestCompleteness_DoesNotAffectAnalysis(t *testing.T) {
	for name, gen := range map[string]func() [][]byte{
		"handshake": testpcap.Handshake, "retransmission_storm": testpcap.RetransmissionStorm, "mtu_issue": testpcap.MTUIssue, "dns_failure": testpcap.DNSFailure,
	} {
		t.Run(name, func(t *testing.T) {
			frames := gen()
			clean := writeNG(t, []uint16{testpcap.LinkTypeEthernet}, testpcap.EthernetNG(frames))
			mixed := append(testpcap.EthernetNG(frames), unsupportedPkts(7)...)
			partial := writeNG(t, []uint16{testpcap.LinkTypeEthernet, testpcap.LinkTypeEthernetMPkt}, mixed)
			a, _, err := processFile(t, clean)
			if err != nil {
				t.Fatal(err)
			}
			b, _, err := processFile(t, partial)
			if err != nil {
				t.Fatal(err)
			}
			if a.Completeness != nil || b.Completeness == nil {
				t.Fatalf("completeness: complete=%+v partial=%+v", a.Completeness, b.Completeness)
			}
			assertSameAnalysis(t, a, b)
		})
	}
}

// assertSameAnalysis compares everything the analyzer concluded.
func assertSameAnalysis(t *testing.T, a, b *models.TriageReport) {
	t.Helper()
	if a.RiskScore != b.RiskScore || a.RiskLevel != b.RiskLevel || a.TopIssue != b.TopIssue || a.TopIssueCount != b.TopIssueCount {
		t.Errorf("risk differs: %d/%s/%q vs %d/%s/%q", a.RiskScore, a.RiskLevel, a.TopIssue, b.RiskScore, b.RiskLevel, b.TopIssue)
	}
	if !reflect.DeepEqual(a.RecommendedActions, b.RecommendedActions) {
		t.Errorf("recommendations differ")
	}
	if !reflect.DeepEqual(a.Findings, b.Findings) {
		t.Errorf("findings differ:\n%+v\n%+v", a.Findings, b.Findings)
	}
	if a.Events.Len() != b.Events.Len() || !reflect.DeepEqual(a.EventCounts, b.EventCounts) || a.EventsDropped != b.EventsDropped {
		t.Errorf("events differ: %d/%v vs %d/%v", a.Events.Len(), a.EventCounts, b.Events.Len(), b.EventCounts)
	}
	if !reflect.DeepEqual(a.TCPRetransmissions, b.TCPRetransmissions) ||
		len(a.DNSAnomalies) != len(b.DNSAnomalies) ||
		len(a.TCPHandshakes.SuccessfulHandshakes) != len(b.TCPHandshakes.SuccessfulHandshakes) ||
		len(a.TCPHandshakeFlows) != len(b.TCPHandshakeFlows) ||
		len(a.StabilityFindings) != len(b.StabilityFindings) ||
		a.TotalBytes != b.TotalBytes {
		t.Errorf("detector results differ")
	}
}
