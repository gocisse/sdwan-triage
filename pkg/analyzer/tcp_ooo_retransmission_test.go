package analyzer

import (
	"strings"
	"testing"

	"github.com/gocisse/sdwan-triage/internal/testpcap"
	"github.com/gocisse/sdwan-triage/pkg/events"
	"github.com/gocisse/sdwan-triage/pkg/models"
)

// Phase 4.49 — the advanced out-of-order tracker must not count retransmissions
// (or keep-alive probes) as out-of-order data, while genuine reordering is still
// reported. Retransmission events and packets_lost must be unaffected.

const oooPort = 50400

var oooPSH = uint8(testpcap.PSH | testpcap.ACK)

// oooSeg is the i-th 100-byte client->server data segment starting at base.
func oooSeg(port uint16, base uint32, i int) []byte {
	return tcpC2S(port, base+uint32(100*i), 2001, oooPSH, make([]byte, 100))
}

const oooISN = uint32(1001)

func oooFlowsFor(r *models.TriageReport) []models.TCPOutOfOrderFlow { return r.TCPOutOfOrderFlows }

func oooRetx(r *models.TriageReport) int { return len(r.Events.ByKind(events.TCPRetransmission)) }

func oooHasAction(r *models.TriageReport) bool {
	for _, a := range r.RecommendedActions {
		if strings.Contains(a, "out-of-order packets detected") {
			return true
		}
	}
	return false
}

func oooInOrder(port uint16, n int) [][]byte {
	pk := handshake(port)
	for i := 0; i < n; i++ {
		pk = append(pk, oooSeg(port, oooISN, i))
	}
	return pk
}

func TestOOO_InOrderTrafficIsNotOutOfOrder(t *testing.T) {
	r := runGolden(t, oooInOrder(oooPort, 30))
	if len(oooFlowsFor(r)) != 0 || oooRetx(r) != 0 || r.RiskScore != 0 {
		t.Errorf("in-order: ooo=%v retx=%d risk=%d", oooFlowsFor(r), oooRetx(r), r.RiskScore)
	}
}

// The defect: resending OLD segments (no reordering at all) used to be reported
// as a Critical out-of-order flow and add +3 risk.
func TestOOO_RetransmissionsOfOldSegmentsAreNotOutOfOrder(t *testing.T) {
	pk := oooInOrder(oooPort+1, 25)
	for i := 0; i < 12; i++ {
		pk = append(pk, oooSeg(oooPort+1, oooISN, i))
	}
	r := runGolden(t, pk)
	if f := oooFlowsFor(r); len(f) != 0 {
		t.Fatalf("retransmissions reported as out-of-order: %+v", f)
	}
	// Invariant: the retransmission accounting is untouched.
	if oooRetx(r) != 12 || lostPackets(r) != 12 || len(r.TCPRetransmissions) != 1 {
		t.Errorf("retransmission accounting changed: events=%d packets_lost=%d flows=%d", oooRetx(r), lostPackets(r), len(r.TCPRetransmissions))
	}
	// Risk is the retransmission contribution only (5), without the +3 for an out-of-order flow.
	if r.RiskScore != 5 {
		t.Errorf("risk = %d, want 5 (retransmissions only)", r.RiskScore)
	}
	if oooHasAction(r) {
		t.Errorf("out-of-order action recommended for retransmissions alone: %v", r.RecommendedActions)
	}
}

func TestOOO_GenuineAdjacentReorderingIsStillReported(t *testing.T) {
	pk := handshake(oooPort + 2)
	for i := 0; i < 30; i += 2 {
		pk = append(pk, oooSeg(oooPort+2, oooISN, i+1), oooSeg(oooPort+2, oooISN, i))
	}
	r := runGolden(t, pk)
	f := oooFlowsFor(r)
	if len(f) != 1 || f[0].OutOfOrderCount != 15 || f[0].TotalPackets != 30 || f[0].Severity != "Critical" {
		t.Fatalf("genuine reordering must still be reported as 15/30 Critical, got %+v", f)
	}
	if oooRetx(r) != 0 || lostPackets(r) != 0 {
		t.Errorf("reordering must not become a retransmission: events=%d lost=%d", oooRetx(r), lostPackets(r))
	}
	if r.RiskScore != 3 || !oooHasAction(r) {
		t.Errorf("risk=%d action=%v, want risk 3 and the out-of-order action", r.RiskScore, oooHasAction(r))
	}
}

func oooWrapBase() uint32 { return uint32(0xFFFFFFFF - 1500) }

func oooWrapFlow(port uint16, n int) [][]byte {
	base := oooWrapBase()
	pk := [][]byte{
		tcpC2S(port, base-1, 0, testpcap.SYN, nil),
		tcpS2C(port, 2000, base, testpcap.SYN|testpcap.ACK, nil),
		tcpC2S(port, base, 2001, testpcap.ACK, nil),
	}
	for i := 0; i < n; i++ {
		pk = append(pk, oooSeg(port, base, i)) // sequence wraps through 2^32 during these 30 segments
	}
	return pk
}

func TestOOO_WraparoundInOrderIsNotOutOfOrder(t *testing.T) {
	r := runGolden(t, oooWrapFlow(oooPort+3, 30))
	if len(oooFlowsFor(r)) != 0 || oooRetx(r) != 0 {
		t.Errorf("wrap-around in-order: ooo=%+v retx=%d", oooFlowsFor(r), oooRetx(r))
	}
}

func TestOOO_WraparoundThenRetransmissionsAreNotOutOfOrder(t *testing.T) {
	base := oooWrapBase()
	pk := oooWrapFlow(oooPort+4, 30)
	for i := 0; i < 12; i++ {
		pk = append(pk, oooSeg(oooPort+4, base, i)) // pre-wrap segments resent after the wrap
	}
	r := runGolden(t, pk)
	if len(oooFlowsFor(r)) != 0 {
		t.Errorf("post-wrap retransmissions reported as out-of-order: %+v", oooFlowsFor(r))
	}
	if oooRetx(r) != 12 || lostPackets(r) != 12 {
		t.Errorf("retransmission accounting changed: events=%d lost=%d", oooRetx(r), lostPackets(r))
	}
}

// Reordering that straddles the wrap point must still be seen (modular compare).
func TestOOO_ReorderingAcrossWraparoundIsReported(t *testing.T) {
	base := oooWrapBase()
	port := uint16(oooPort + 5)
	pk := [][]byte{
		tcpC2S(port, base-1, 0, testpcap.SYN, nil),
		tcpS2C(port, 2000, base, testpcap.SYN|testpcap.ACK, nil),
		tcpC2S(port, base, 2001, testpcap.ACK, nil),
	}
	for i := 0; i < 30; i += 2 {
		pk = append(pk, oooSeg(port, base, i+1), oooSeg(port, base, i))
	}
	r := runGolden(t, pk)
	f := oooFlowsFor(r)
	if len(f) != 1 || f[0].OutOfOrderCount != 15 || f[0].TotalPackets != 30 {
		t.Errorf("reordering across wrap-around: %+v, want 15/30", f)
	}
}

func TestOOO_RepeatedRetransmissionsOfLatestSegment(t *testing.T) {
	pk := oooInOrder(oooPort+6, 25)
	for i := 0; i < 12; i++ {
		pk = append(pk, oooSeg(oooPort+6, oooISN, 24))
	}
	r := runGolden(t, pk)
	if len(oooFlowsFor(r)) != 0 || oooRetx(r) != 12 || lostPackets(r) != 12 {
		t.Errorf("latest-segment resends: ooo=%+v events=%d lost=%d", oooFlowsFor(r), oooRetx(r), lostPackets(r))
	}
}

func TestOOO_KeepAliveProbesAreNeitherRetransmissionNorOutOfOrder(t *testing.T) {
	pk := oooInOrder(oooPort+7, 25)
	next := oooISN + 2500
	for i := 0; i < 12; i++ {
		pk = append(pk, tcpC2S(oooPort+7, next-1, 2001, oooPSH, []byte{0}))
	}
	r := runGolden(t, pk)
	if len(oooFlowsFor(r)) != 0 || oooRetx(r) != 0 || lostPackets(r) != 0 {
		t.Errorf("keep-alives: ooo=%+v events=%d lost=%d", oooFlowsFor(r), oooRetx(r), lostPackets(r))
	}
}

// Mixed: only the genuinely reordered first-seen segments count; the resends
// are excluded from both the count and the denominator.
func TestOOO_MixedReorderingAndRetransmissionsCountOnlyReordering(t *testing.T) {
	port := uint16(oooPort + 8)
	pk := handshake(port)
	for i := 0; i < 20; i += 2 {
		pk = append(pk, oooSeg(port, oooISN, i+1), oooSeg(port, oooISN, i))
	}
	for i := 0; i < 12; i++ {
		pk = append(pk, oooSeg(port, oooISN, i))
	}
	r := runGolden(t, pk)
	f := oooFlowsFor(r)
	if len(f) != 1 || f[0].OutOfOrderCount != 10 || f[0].TotalPackets != 20 {
		t.Errorf("mixed: %+v, want 10/20 (previously 22/32)", f)
	}
	if oooRetx(r) != 12 || lostPackets(r) != 12 {
		t.Errorf("retransmission accounting changed: events=%d lost=%d", oooRetx(r), lostPackets(r))
	}
}

func TestOOO_ShortFlowStaysBelowThresholds(t *testing.T) {
	pk := oooInOrder(oooPort+9, 8)
	for i := 0; i < 3; i++ {
		pk = append(pk, oooSeg(oooPort+9, oooISN, i))
	}
	r := runGolden(t, pk)
	if len(oooFlowsFor(r)) != 0 || oooRetx(r) != 3 || lostPackets(r) != 3 {
		t.Errorf("short flow: ooo=%+v events=%d lost=%d", oooFlowsFor(r), oooRetx(r), lostPackets(r))
	}
}

// A hole filled late is out-of-sequence data, not a retransmission: it is
// counted by the tracker (and is ambiguous between reordering and a resend of
// an original this capture never saw), but below thresholds it stays unreported.
func TestOOO_HoleFillIsNotARetransmission(t *testing.T) {
	port := uint16(oooPort + 10)
	pk := handshake(port)
	for i := 0; i < 30; i++ {
		if i == 10 {
			continue
		}
		pk = append(pk, oooSeg(port, oooISN, i))
	}
	pk = append(pk, oooSeg(port, oooISN, 10))
	r := runGolden(t, pk)
	if oooRetx(r) != 0 || lostPackets(r) != 0 {
		t.Errorf("hole-fill became a retransmission: events=%d lost=%d", oooRetx(r), lostPackets(r))
	}
	if len(r.Events.ByKind(events.TCPSequenceGap)) != 1 {
		t.Errorf("sequence-gap evidence changed")
	}
}
