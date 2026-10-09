package detector

import (
	"testing"
	"time"

	"github.com/gocisse/sdwan-triage/pkg/models"
)

func TestICMPErrors_TrackedGroupBoundCountsTheRest(t *testing.T) {
	a := NewICMPAnalyzer()
	a.errors.maxTracked = 3
	report := &models.TriageReport{}
	quote := func(dstLast byte) []byte {
		q := make([]byte, 28)
		q[0] = 0x45
		q[9] = 17
		copy(q[12:16], []byte{10, 0, 0, 1})
		copy(q[16:20], []byte{10, 0, 1, dstLast})
		q[22], q[23] = 0, 53
		return q
	}
	ts := time.Unix(1000, 0)
	for i := 0; i < 5; i++ {
		a.observeErrorMessage(false, 3, 1, "10.0.0.254", "10.0.0.1", quote(byte(i)), 0, ts, report)
	}
	a.observeErrorMessage(false, 3, 1, "10.0.0.254", "10.0.0.1", quote(0), 0, ts, report) // existing group still counts
	a.Finalize(report)
	e := report.ICMPErrorEvidence
	if e == nil || e.TotalMessages != 6 || e.GroupsTotal != 5 || e.GroupsShown != 3 || e.OmittedGroups != 2 || e.OmittedMessages != 2 {
		t.Fatalf("evidence = %+v", e)
	}
	var first int
	for _, g := range e.Errors {
		first += g.Count
	}
	if first != 4 { // 3 tracked groups: 2 + 1 + 1
		t.Errorf("listed messages = %d", first)
	}
}

func TestICMPErrors_SourcePortSetIsBounded(t *testing.T) {
	a := NewICMPAnalyzer()
	report := &models.TriageReport{}
	for i := 0; i < icmpErrMaxSrcPorts+50; i++ {
		q := make([]byte, 28)
		q[0] = 0x45
		q[9] = 17
		copy(q[12:16], []byte{10, 0, 0, 1})
		copy(q[16:20], []byte{10, 0, 1, 1})
		q[20], q[21] = byte(i>>8), byte(i)
		q[22], q[23] = 0, 53
		a.observeErrorMessage(false, 3, 1, "10.0.0.254", "10.0.0.1", q, 0, time.Unix(1000, 0), report)
	}
	a.Finalize(report)
	g := report.ICMPErrorEvidence.Errors[0]
	if g.Count != icmpErrMaxSrcPorts+50 || g.DistinctSrcPorts != icmpErrMaxSrcPorts || !g.SrcPortsCapped {
		t.Errorf("group = %+v", g)
	}
}

func TestParseQuotedPackets(t *testing.T) {
	v4 := make([]byte, 28)
	v4[0], v4[9] = 0x45, 6
	copy(v4[12:16], []byte{192, 0, 2, 1})
	copy(v4[16:20], []byte{198, 51, 100, 2})
	v4[20], v4[21], v4[22], v4[23] = 0x13, 0x88, 0x01, 0xbb // 5000 -> 443
	if q := parseQuotedIPv4(v4); q.Status != "complete" || q.Protocol != "TCP" || q.SrcPort != 5000 || q.DstPort != 443 || q.Src != "192.0.2.1" || q.Dst != "198.51.100.2" {
		t.Errorf("v4 = %+v", q)
	}
	if parseQuotedIPv4(v4[:19]).Status != "unusable" || parseQuotedIPv4(nil).Status != "unusable" {
		t.Error("short v4 quote not unusable")
	}
	opt := append([]byte(nil), v4...)
	opt[0] = 0x46                                               // IHL 6: header is 24 bytes, so ports sit at 24..28
	opt[24], opt[25], opt[26], opt[27] = 0x00, 0x35, 0x30, 0x39 // IHL 6: transport header starts at byte 24
	if q := parseQuotedIPv4(opt); q.Status != "complete" || q.SrcPort != 53 || q.DstPort != 12345 {
		t.Errorf("ihl6 = %+v (ports must be read after the options)", q)
	}
	if parseQuotedIPv4(append([]byte{0x4f}, v4[1:]...)).Status != "unusable" { // IHL 15 > length
		t.Error("IHL beyond the quote accepted")
	}
	v6 := make([]byte, 48)
	v6[0], v6[6] = 0x60, 17
	v6[40], v6[41], v6[42], v6[43] = 0, 53, 0xc3, 0x50
	if q := parseQuotedIPv6(v6); q.Status != "complete" || q.Protocol != "UDP" || q.SrcPort != 53 || q.DstPort != 50000 {
		t.Errorf("v6 = %+v", q)
	}
	if parseQuotedIPv6(v6[:39]).Status != "unusable" || parseQuotedIPv6(append([]byte{0x40}, v6[1:]...)).Status != "unusable" {
		t.Error("bad v6 quote accepted")
	}
	if q := parseQuotedIPv6(v6[:42]); q.Status != "no_ports" {
		t.Errorf("v6 without full ports = %+v", q)
	}
}
