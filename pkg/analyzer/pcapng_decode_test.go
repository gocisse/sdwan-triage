package analyzer

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/gocisse/sdwan-triage/internal/testpcap"
	"github.com/gocisse/sdwan-triage/pkg/models"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

// ─── fixtures ────────────────────────────────────────────────────

func writeNG(t *testing.T, linkTypes []uint16, pkts []testpcap.NGPacket) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "fixture.pcapng")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := testpcap.WritePCAPNG(f, linkTypes, pkts, testpcap.BaseTime, testpcap.DefaultInterval); err != nil {
		t.Fatal(err)
	}
	return path
}

func ethNG(frames [][]byte) []testpcap.NGPacket { return testpcap.EthernetNG(frames) }

// rawHandshake is a SYN / SYN-ACK / ACK as raw IPv4 packets (no link header).
func rawHandshake() [][]byte {
	cIP, sIP := []byte{172, 16, 0, 10}, []byte{172, 16, 0, 20}
	seg := func(src, dst []byte, sp, dp uint16, seq, ack uint32, fl uint8) []byte {
		return testpcap.BuildIPv4(src, dst, 6, testpcap.BuildTCP(sp, dp, seq, ack, fl, 65535, nil))
	}
	return [][]byte{
		seg(cIP, sIP, 60000, 8080, 100, 0, testpcap.SYN),
		seg(sIP, cIP, 8080, 60000, 900, 101, testpcap.SYN|testpcap.ACK),
		seg(cIP, sIP, 60000, 8080, 101, 901, testpcap.ACK),
	}
}

// processFile runs the standard Processor and returns report, summary and error.
func processFile(t *testing.T, path string) (*models.TriageReport, DecodeSummary, error) {
	t.Helper()
	handle, err := OpenCapture(path)
	if err != nil {
		t.Fatalf("open capture: %v", err)
	}
	defer handle.Close()
	p := NewProcessorWithOptions(false, false)
	report := &models.TriageReport{ApplicationBreakdown: make(map[string]models.AppCategory)}
	err = p.Process(handle.Reader, models.NewAnalysisState(), report, nil)
	return report, p.DecodeSummary(), err
}

// ─── reader helpers ──────────────────────────────────────────────

type fakeReader struct{ lt layers.LinkType }

func (f fakeReader) ReadPacketData() ([]byte, gopacket.CaptureInfo, error) {
	return nil, gopacket.CaptureInfo{}, nil
}
func (f fakeReader) LinkType() layers.LinkType { return f.lt }

func TestPacketLinkType_ClassicFallsBackToReader(t *testing.T) {
	lt, per := PacketLinkType(fakeReader{layers.LinkTypeEthernet}, gopacket.CaptureInfo{})
	if lt != layers.LinkTypeEthernet || per {
		t.Fatalf("got (%v, %v), want (Ethernet, false)", lt, per)
	}
}

func TestPacketLinkType_PcapngUsesAncillaryData(t *testing.T) {
	ci := gopacket.CaptureInfo{AncillaryData: []interface{}{layers.LinkTypeRaw}}
	// Reader-wide value is the Null zero value for mixed-link pcapng and must be ignored.
	lt, per := PacketLinkType(fakeReader{layers.LinkTypeNull}, ci)
	if lt != layers.LinkTypeRaw || !per {
		t.Fatalf("got (%v, %v), want (Raw, true)", lt, per)
	}
}

func TestPacketLinkType_UnexpectedAncillaryTypeFallsBack(t *testing.T) {
	ci := gopacket.CaptureInfo{AncillaryData: []interface{}{"not a link type"}}
	lt, per := PacketLinkType(fakeReader{layers.LinkTypeEthernet}, ci)
	if lt != layers.LinkTypeEthernet || per {
		t.Fatalf("got (%v, %v)", lt, per)
	}
}

func TestIsSupportedLinkType(t *testing.T) {
	for _, lt := range []layers.LinkType{layers.LinkTypeEthernet, layers.LinkTypeRaw, layers.LinkTypeIPv4, layers.LinkTypeIPv6, layers.LinkTypeLinuxSLL} {
		if !IsSupportedLinkType(lt) {
			t.Errorf("%d should be supported", lt)
		}
	}
	// 274 (IEEE 802.3br mPackets) is truncated to 18 by gopacket's uint8 LinkType.
	if got := layers.LinkType(uint16(274) & 0xff); got != 18 {
		t.Fatalf("truncation assumption broken: %d", got)
	}
	for _, lt := range []layers.LinkType{18, layers.LinkTypeNull, layers.LinkTypePPP, 200} {
		if IsSupportedLinkType(lt) {
			t.Errorf("%d must not be supported", lt)
		}
	}
	if !strings.Contains(LinkTypeLabel(18), "274") {
		t.Errorf("link type 18 label should mention 274: %s", LinkTypeLabel(18))
	}
}

// ─── pcapng decoding ─────────────────────────────────────────────

func TestPCAPNG_EthernetDecodesTCP(t *testing.T) {
	path := writeNG(t, []uint16{testpcap.LinkTypeEthernet}, ethNG(testpcap.Handshake()))
	r, sum, err := processFile(t, path)
	if err != nil {
		t.Fatal(err)
	}
	// The old defect: link type Null → nothing decoded → empty report.
	if got := len(r.TCPHandshakes.SuccessfulHandshakes); got != 1 {
		t.Fatalf("successful handshakes = %d, want 1", got)
	}
	if sum.PacketsRead != 5 || sum.PacketsDecoded != 5 || sum.PacketsUnsupported != 0 || sum.DecodeFailed != 0 {
		t.Fatalf("unexpected summary %+v", sum)
	}
}

func TestPCAPNG_EquivalentToClassicPCAP(t *testing.T) {
	for name, gen := range map[string]func() [][]byte{
		"handshake":            testpcap.Handshake,
		"retransmission_storm": testpcap.RetransmissionStorm,
		"mtu_issue":            testpcap.MTUIssue,
	} {
		t.Run(name, func(t *testing.T) {
			frames := gen()
			pcapPath := filepath.Join(t.TempDir(), "s.pcap")
			if err := testpcap.WriteFile(pcapPath, frames); err != nil {
				t.Fatal(err)
			}
			ngPath := writeNG(t, []uint16{testpcap.LinkTypeEthernet}, ethNG(frames))

			a, sa, err := processFile(t, pcapPath)
			if err != nil {
				t.Fatal(err)
			}
			b, sb, err := processFile(t, ngPath)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(sa, sb) {
				t.Errorf("summary differs: pcap %+v vs pcapng %+v", sa, sb)
			}
			if !reflect.DeepEqual(a.TCPRetransmissions, b.TCPRetransmissions) {
				t.Errorf("retransmissions differ:\n%+v\n%+v", a.TCPRetransmissions, b.TCPRetransmissions)
			}
			if !reflect.DeepEqual(a.PacketLoss, b.PacketLoss) {
				t.Errorf("packet loss differs: %+v vs %+v", a.PacketLoss, b.PacketLoss)
			}
			if len(a.TCPHandshakes.SuccessfulHandshakes) != len(b.TCPHandshakes.SuccessfulHandshakes) ||
				len(a.TCPHandshakes.FailedHandshakeAttempts) != len(b.TCPHandshakes.FailedHandshakeAttempts) {
				t.Errorf("handshake results differ")
			}
			if a.Events.Len() != b.Events.Len() {
				t.Errorf("event count differs: %d vs %d", a.Events.Len(), b.Events.Len())
			}
		})
	}
}

func TestPCAPNG_RetransmissionScenarioDetected(t *testing.T) {
	path := writeNG(t, []uint16{testpcap.LinkTypeEthernet}, ethNG(testpcap.RetransmissionStorm()))
	r, _, err := processFile(t, path)
	if err != nil {
		t.Fatal(err)
	}
	if !hasTCPFlow(r.TCPRetransmissions, 50002, 443) {
		t.Fatalf("expected retransmission flow 50002->443, got %+v", r.TCPRetransmissions)
	}
}

func TestPCAPNG_MixedEthernetAndRawDecodeIndividually(t *testing.T) {
	var pkts []testpcap.NGPacket
	for _, f := range testpcap.Handshake() {
		pkts = append(pkts, testpcap.NGPacket{Interface: 0, Data: f})
	}
	for _, f := range rawHandshake() {
		pkts = append(pkts, testpcap.NGPacket{Interface: 1, Data: f})
	}
	path := writeNG(t, []uint16{testpcap.LinkTypeEthernet, testpcap.LinkTypeRaw}, pkts)
	r, sum, err := processFile(t, path)
	if err != nil {
		t.Fatal(err)
	}
	if sum.PacketsRead != 8 || sum.PacketsDecoded != 8 || sum.PacketsUnsupported != 0 {
		t.Fatalf("unexpected summary %+v", sum)
	}
	if got := len(r.TCPHandshakes.SuccessfulHandshakes); got != 2 {
		t.Fatalf("successful handshakes = %d, want 2 (one Ethernet, one Raw IP)", got)
	}
}

func TestPCAPNG_UnsupportedLinkTypeSkippedAndCounted(t *testing.T) {
	var pkts []testpcap.NGPacket
	for _, f := range testpcap.Handshake() {
		pkts = append(pkts, testpcap.NGPacket{Interface: 0, Data: f})
	}
	for i := 0; i < 4; i++ {
		pkts = append(pkts, testpcap.NGPacket{Interface: 1, Data: make([]byte, 40)})
	}
	path := writeNG(t, []uint16{testpcap.LinkTypeEthernet, testpcap.LinkTypeEthernetMPkt}, pkts)
	r, sum, err := processFile(t, path)
	if err != nil {
		t.Fatalf("partial decode must not be an error: %v", err)
	}
	if sum.PacketsRead != 9 || sum.PacketsDecoded != 5 || sum.PacketsUnsupported != 4 {
		t.Fatalf("unexpected summary %+v", sum)
	}
	if sum.UnsupportedByType[18] != 4 {
		t.Fatalf("expected 4 packets of (truncated) link type 18, got %+v", sum.UnsupportedByType)
	}
	if got := len(r.TCPHandshakes.SuccessfulHandshakes); got != 1 {
		t.Fatalf("supported packets must still be analysed: handshakes = %d", got)
	}
	notice := sum.PartialDecodeNotice()
	for _, want := range []string{"4 of 9", "NOT analyzed", "18"} {
		if !strings.Contains(notice, want) {
			t.Errorf("notice %q missing %q", notice, want)
		}
	}
}

func TestPCAPNG_OnlyUnsupportedIsAnError(t *testing.T) {
	pkts := []testpcap.NGPacket{{Interface: 0, Data: make([]byte, 40)}, {Interface: 0, Data: make([]byte, 40)}}
	path := writeNG(t, []uint16{testpcap.LinkTypeEthernetMPkt}, pkts)
	_, sum, err := processFile(t, path)
	if !errors.Is(err, ErrNoDecodablePackets) {
		t.Fatalf("err = %v, want ErrNoDecodablePackets", err)
	}
	if !strings.Contains(err.Error(), "2 packets read, 0 could be decoded") {
		t.Errorf("error should explain the situation: %v", err)
	}
	if sum.PacketsRead != 2 || sum.PacketsDecoded != 0 {
		t.Fatalf("unexpected summary %+v", sum)
	}
}

func TestPCAPNG_EmptyCaptureIsNotAnError(t *testing.T) {
	path := writeNG(t, []uint16{testpcap.LinkTypeEthernet}, nil)
	_, sum, err := processFile(t, path)
	if err != nil {
		t.Fatalf("empty pcapng must stay non-error: %v", err)
	}
	if sum.PacketsRead != 0 {
		t.Fatalf("unexpected summary %+v", sum)
	}
}

func TestPCAP_EmptyCaptureIsNotAnError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "empty.pcap")
	if err := testpcap.WriteFile(path, nil); err != nil {
		t.Fatal(err)
	}
	if _, _, err := processFile(t, path); err != nil {
		t.Fatalf("empty pcap must stay non-error: %v", err)
	}
}

func TestPCAP_UndecodablePacketsAreAnError(t *testing.T) {
	// Non-empty classic pcap whose frames are shorter than an Ethernet header.
	path := filepath.Join(t.TempDir(), "garbage.pcap")
	if err := testpcap.WriteFile(path, [][]byte{{1, 2}, {3, 4}}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := processFile(t, path); !errors.Is(err, ErrNoDecodablePackets) {
		t.Fatalf("err = %v, want ErrNoDecodablePackets", err)
	}
}

func TestPCAPNG_AccountingIsDeterministic(t *testing.T) {
	var pkts []testpcap.NGPacket
	for _, f := range testpcap.Handshake() {
		pkts = append(pkts, testpcap.NGPacket{Interface: 0, Data: f})
	}
	pkts = append(pkts, testpcap.NGPacket{Interface: 1, Data: make([]byte, 30)})
	path := writeNG(t, []uint16{testpcap.LinkTypeEthernet, testpcap.LinkTypeEthernetMPkt}, pkts)
	_, first, err := processFile(t, path)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 20; i++ {
		_, again, err := processFile(t, path)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(first, again) {
			t.Fatalf("run %d differs: %+v vs %+v", i, first, again)
		}
	}
}

func TestPartialDecodeNotice_OrderedAndEmpty(t *testing.T) {
	var d decodeStats
	d.read = 10
	d.decoded = 4
	d.addUnsupported(200)
	d.addUnsupported(18)
	d.addUnsupported(200)
	_ = d
	s := DecodeSummary{PacketsRead: 10, PacketsDecoded: 4, PacketsUnsupported: 3, UnsupportedByType: d.unsupported, UnsupportedDescribe: d.describeUnsupported()}
	i18 := strings.Index(s.UnsupportedDescribe, "18")
	i200 := strings.Index(s.UnsupportedDescribe, "200")
	if i18 < 0 || i200 < 0 || i18 > i200 {
		t.Fatalf("link types must be listed in ascending order: %q", s.UnsupportedDescribe)
	}
	if (DecodeSummary{}).PartialDecodeNotice() != "" {
		t.Fatal("no unsupported packets → no notice")
	}
}

// ─── comparator / export guards ──────────────────────────────────

func TestComparator_StreamFilePcapngDecodes(t *testing.T) {
	path := writeNG(t, []uint16{testpcap.LinkTypeEthernet}, ethNG(testpcap.Handshake()))
	var ipPackets int
	n, err := NewComparator(false).streamFile(path, func(m *packetMeta) {
		if m.Key.SrcIP != "" {
			ipPackets++
		}
	})
	if err != nil || n != 5 || ipPackets != 5 {
		t.Fatalf("n=%d ipPackets=%d err=%v, want 5/5/nil", n, ipPackets, err)
	}
}

func TestComparator_StreamFileOnlyUnsupportedIsAnError(t *testing.T) {
	path := writeNG(t, []uint16{testpcap.LinkTypeEthernetMPkt}, []testpcap.NGPacket{{Interface: 0, Data: make([]byte, 40)}})
	_, err := NewComparator(false).streamFile(path, func(*packetMeta) {})
	if !errors.Is(err, ErrNoDecodablePackets) {
		t.Fatalf("err = %v, want ErrNoDecodablePackets", err)
	}
}

func TestExport_PcapngSingleLinkTypeWritesValidPcap(t *testing.T) {
	src := writeNG(t, []uint16{testpcap.LinkTypeEthernet}, ethNG(testpcap.Handshake()))
	out := t.TempDir()
	res, err := NewPCAPExporter(src, out, false).ExportStream(ExportFilter{SrcIP: "192.168.1.100", DstIP: "10.0.0.50"})
	if err != nil || res.PacketCount != 5 {
		t.Fatalf("res=%+v err=%v", res, err)
	}
	f, err := os.Open(res.OutputPath)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	r, err := pcapgo.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	if r.LinkType() != layers.LinkTypeEthernet {
		t.Fatalf("exported link type = %v, want Ethernet", r.LinkType())
	}
}

func TestExport_PcapngMixedLinkTypesIsExplicitError(t *testing.T) {
	pkts := []testpcap.NGPacket{
		{Interface: 0, Data: testpcap.Handshake()[0]},
		{Interface: 1, Data: rawHandshake()[0]},
	}
	src := writeNG(t, []uint16{testpcap.LinkTypeEthernet, testpcap.LinkTypeRaw}, pkts)
	if _, err := NewPCAPExporter(src, t.TempDir(), false).ExportStream(ExportFilter{}); err == nil {
		t.Fatal("mixed link types must not be silently written to a single pcap")
	}
}

func TestAdvancedStreaming_RejectsPcapng(t *testing.T) {
	src := writeNG(t, []uint16{testpcap.LinkTypeEthernet}, ethNG(testpcap.Handshake()))
	sp := NewAdvancedStreamingProcessor(AdvancedStreamingConfig{})
	if _, err := sp.ProcessFile(t.Context(), src); err == nil {
		t.Fatal("advanced streaming must refuse pcapng instead of mis-decoding it")
	}
}
