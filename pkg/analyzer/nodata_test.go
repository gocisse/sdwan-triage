package analyzer

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gocisse/sdwan-triage/internal/testpcap"
	"github.com/gocisse/sdwan-triage/pkg/models"
	"github.com/google/gopacket/layers"
)

// NO_DATA = nothing to analyze (empty capture / filter excluded everything).
// It is distinct from "the tool could not analyze packets that exist" (error).

func TestNoData_Classify(t *testing.T) {
	unsup := map[layers.LinkType]int{18: 2}
	cases := []struct {
		name   string
		d      decodeStats
		want   analysisOutcome
		reason string
	}{
		{"empty capture", decodeStats{}, outcomeNoData, models.NoDataReasonEmptyCapture},
		{"one decoded packet", decodeStats{read: 1, decoded: 1}, outcomeAnalyzed, ""},
		{"decoded + unsupported (partial)", decodeStats{read: 5, decoded: 3, unsupported: unsup}, outcomeAnalyzed, ""},
		{"decoded + failed (partial)", decodeStats{read: 5, decoded: 3, failed: 2}, outcomeAnalyzed, ""},
		{"decoded + filtered", decodeStats{read: 5, decoded: 1, filtered: 4}, outcomeAnalyzed, ""},
		{"unsupported only", decodeStats{read: 2, unsupported: unsup}, outcomeError, ""},
		{"undecodable only", decodeStats{read: 2, failed: 2}, outcomeError, ""},
		{"filter excluded everything", decodeStats{read: 202, filtered: 202}, outcomeNoData, models.NoDataReasonFilterMatchedNothing},
		{"filter excluded + unsupported present", decodeStats{read: 10, filtered: 6, unsupported: unsup}, outcomeError, ""},
		{"filter excluded + undecodable present", decodeStats{read: 10, filtered: 6, failed: 4}, outcomeError, ""},
	}
	for _, tc := range cases {
		got, reason := tc.d.classify()
		if got != tc.want || reason != tc.reason {
			t.Errorf("%s: got (%d,%q), want (%d,%q)", tc.name, got, reason, tc.want, tc.reason)
		}
	}
}

func writeEmptyPCAP(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "empty-but-valid.pcap")
	if err := testpcap.WriteFile(path, nil); err != nil {
		t.Fatal(err)
	}
	return path
}

func processWithFilter(t *testing.T, path string, f *models.Filter) (*models.TriageReport, error) {
	t.Helper()
	handle, err := OpenCapture(path)
	if err != nil {
		return nil, err
	}
	defer handle.Close()
	p := NewProcessorWithOptions(false, false)
	report := &models.TriageReport{ApplicationBreakdown: make(map[string]models.AppCategory)}
	err = p.Process(handle.Reader, models.NewAnalysisState(), report, f)
	return report, err
}

func assertNoData(t *testing.T, r *models.TriageReport, reason string) {
	t.Helper()
	if !r.IsNoData() || r.AnalysisStatus != models.AnalysisStatusNoData || r.NoDataReason != reason {
		t.Fatalf("status = %q/%q, want no_data/%s", r.AnalysisStatus, r.NoDataReason, reason)
	}
	ps := r.PlainEnglishSummary
	if ps == nil || ps.OverallHealth != "No Data" || len(ps.QuickActions) == 0 {
		t.Errorf("plain-English summary must say No Data: %+v", ps)
	}
	if r.RiskScore != 0 || r.RiskLevel != "Low" {
		t.Errorf("risk is left as computed (0/Low), got %d/%s", r.RiskScore, r.RiskLevel)
	}
}

func TestNoData_ZeroPacketPCAP(t *testing.T) {
	r, err := processWithFilter(t, writeEmptyPCAP(t), nil)
	if err != nil {
		t.Fatalf("empty capture is a result, not an error: %v", err)
	}
	assertNoData(t, r, models.NoDataReasonEmptyCapture)
}

func TestNoData_ZeroPacketPCAPNG(t *testing.T) {
	r, err := processWithFilter(t, writeNG(t, []uint16{testpcap.LinkTypeEthernet}, nil), nil)
	if err != nil {
		t.Fatal(err)
	}
	assertNoData(t, r, models.NoDataReasonEmptyCapture)
}

func TestNoData_InvalidAndEmptyFilesStayErrors(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad.pcap")
	os.WriteFile(bad, []byte("notapcap"), 0o644)
	empty := filepath.Join(dir, "zero-bytes.pcap")
	os.WriteFile(empty, nil, 0o644)
	for _, p := range []string{bad, empty} {
		if _, err := processWithFilter(t, p, nil); err == nil {
			t.Errorf("%s must still be an error", filepath.Base(p))
		}
	}
}

func TestNoData_UnsupportedOnlyAndUndecodableOnlyStayErrors(t *testing.T) {
	uns := writeNG(t, []uint16{testpcap.LinkTypeEthernetMPkt}, []testpcap.NGPacket{{Interface: 0, Data: make([]byte, 40)}})
	r, err := processWithFilter(t, uns, nil)
	if !errors.Is(err, ErrNoDecodablePackets) || r.IsNoData() {
		t.Fatalf("unsupported-only: err=%v status=%q", err, r.AnalysisStatus)
	}
	garbage := filepath.Join(t.TempDir(), "g.pcap")
	if err := testpcap.WriteFile(garbage, [][]byte{{1, 2}, {3}}); err != nil {
		t.Fatal(err)
	}
	r, err = processWithFilter(t, garbage, nil)
	if !errors.Is(err, ErrNoDecodablePackets) || r.IsNoData() {
		t.Fatalf("undecodable-only: err=%v status=%q", err, r.AnalysisStatus)
	}
}

func TestNoData_FilterMatchedNothing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hs.pcap")
	if err := testpcap.WriteFile(path, testpcap.Handshake()); err != nil {
		t.Fatal(err)
	}
	r, err := processWithFilter(t, path, &models.Filter{SrcIP: "9.9.9.9"})
	if err != nil {
		t.Fatalf("a filter that matches nothing is NO_DATA, not an error: %v", err)
	}
	assertNoData(t, r, models.NoDataReasonFilterMatchedNothing)
	// The packets were decodable: nothing may claim otherwise.
	if strings.Contains(strings.ToLower(r.PlainEnglishSummary.OverallHealth), "decode") {
		t.Error("filtered packets are not undecodable")
	}
}

func TestNoData_FilterExcludingAllPlusUnsupportedIsAnErrorNotNoData(t *testing.T) {
	pkts := append(testpcap.EthernetNG(testpcap.Handshake()), unsupportedPkts(2)...)
	path := writeNG(t, []uint16{testpcap.LinkTypeEthernet, testpcap.LinkTypeEthernetMPkt}, pkts)
	r, err := processWithFilter(t, path, &models.Filter{SrcIP: "9.9.9.9"})
	if !errors.Is(err, ErrNoDecodablePackets) || r.IsNoData() {
		t.Fatalf("err=%v status=%q", err, r.AnalysisStatus)
	}
	// And the error must describe the filtered packets honestly.
	if !strings.Contains(err.Error(), "excluded by the filter") {
		t.Errorf("message should mention the filter: %v", err)
	}
}

func TestNoData_FilterMessageNeverBlamesDecoding(t *testing.T) {
	d := decodeStats{read: 202, filtered: 202}
	if outcome, _ := d.classify(); outcome != outcomeNoData {
		t.Fatal("expected NO_DATA")
	}
	d = decodeStats{read: 10, filtered: 6, failed: 4}
	msg := d.noDecodableError().Error()
	if !strings.Contains(msg, "4 decode failures") || !strings.Contains(msg, "6 packets were excluded by the filter") {
		t.Errorf("unexpected message: %s", msg)
	}
}

func TestNoData_AnalyzedCapturesAreNotNoData(t *testing.T) {
	// One analyzable packet, no TCP, no DNS, no findings: still a normal analysis.
	one := filepath.Join(t.TempDir(), "one.pcap")
	if err := testpcap.WriteFile(one, [][]byte{testpcap.Handshake()[0]}); err != nil {
		t.Fatal(err)
	}
	r, err := processWithFilter(t, one, nil)
	if err != nil || r.IsNoData() || r.AnalysisStatus != "" || r.NoDataReason != "" {
		t.Fatalf("one packet: err=%v status=%q/%q", err, r.AnalysisStatus, r.NoDataReason)
	}
	// A filter that matches some packets is a normal analysis of those.
	hs := filepath.Join(t.TempDir(), "hs.pcap")
	testpcap.WriteFile(hs, testpcap.Handshake())
	r, err = processWithFilter(t, hs, &models.Filter{SrcIP: "192.168.1.100"})
	if err != nil || r.IsNoData() {
		t.Fatalf("matching filter: err=%v status=%q", err, r.AnalysisStatus)
	}
	// Partial decode keeps the Phase 4.19 behavior.
	partial := writeNG(t, []uint16{testpcap.LinkTypeEthernet, testpcap.LinkTypeEthernetMPkt}, handshakeNG(unsupportedPkts(2)...))
	r, err = processWithFilter(t, partial, nil)
	if err != nil || r.IsNoData() || r.Completeness == nil || r.Completeness.PacketsUnsupported != 2 {
		t.Fatalf("partial: err=%v status=%q completeness=%+v", err, r.AnalysisStatus, r.Completeness)
	}
	// Truncated capture with packets keeps its read-error qualifier.
	full := filepath.Join(t.TempDir(), "f.pcap")
	testpcap.WriteFile(full, testpcap.Handshake())
	b, _ := os.ReadFile(full)
	cut := filepath.Join(t.TempDir(), "c.pcap")
	os.WriteFile(cut, b[:len(b)-10], 0o644)
	r, err = processWithFilter(t, cut, nil)
	if err != nil || r.IsNoData() || r.Completeness == nil || r.Completeness.ReadErrors < 1 {
		t.Fatalf("truncated: err=%v status=%q", err, r.AnalysisStatus)
	}
}

func TestNoData_JSONFieldsAbsentForNormalAnalysis(t *testing.T) {
	hs := filepath.Join(t.TempDir(), "hs.pcap")
	testpcap.WriteFile(hs, testpcap.Handshake())
	r, _ := processWithFilter(t, hs, nil)
	b, _ := json.Marshal(r)
	if strings.Contains(string(b), "analysis_status") || strings.Contains(string(b), "no_data_reason") {
		t.Error("normal analyses must not carry analysis_status / no_data_reason")
	}
	e, _ := processWithFilter(t, writeEmptyPCAP(t), nil)
	b, _ = json.Marshal(e)
	if !json.Valid(b) || !strings.Contains(string(b), `"analysis_status":"no_data"`) || !strings.Contains(string(b), `"no_data_reason":"empty_capture"`) {
		t.Errorf("NO_DATA JSON: %s", b[:200])
	}
}

func TestNoData_RepeatedProcessingIsIdentical(t *testing.T) {
	path := writeEmptyPCAP(t)
	var first string
	for i := 0; i < 20; i++ {
		r, err := processWithFilter(t, path, nil)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := json.Marshal(r)
		if i == 0 {
			first = string(b)
		} else if string(b) != first {
			t.Fatalf("run %d differs", i)
		}
	}
}
