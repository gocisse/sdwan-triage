package analyzer

import (
	"encoding/binary"
	"strings"
	"testing"

	"github.com/gocisse/sdwan-triage/internal/testpcap"
	"github.com/gocisse/sdwan-triage/pkg/models"
)

// Phase 4.37 — "IKE Tunnel Rebuild" counts DISTINCT IKE SA initiations (initiator SPI /
// IKEv1 initiator cookie), not every packet: retransmissions of one initiation, responses
// and the later IKEv1 Main Mode messages are not rebuilds. Packets are 100 ms apart.

func ikePacket(srcIsInitiator bool, version, exch, flags byte, ispi, rspi uint64, msgID uint32, natT bool) []byte {
	h := make([]byte, 28)
	binary.BigEndian.PutUint64(h[0:8], ispi)
	binary.BigEndian.PutUint64(h[8:16], rspi)
	h[16] = 33 // next payload (SA)
	h[17] = version
	h[18] = exch
	h[19] = flags
	binary.BigEndian.PutUint32(h[20:24], msgID)
	binary.BigEndian.PutUint32(h[24:28], 28)
	port := uint16(500)
	if natT {
		h = append([]byte{0, 0, 0, 0}, h...)
		port = 4500
	}
	return testpcap.UDPFrame(testpcap.ClientMAC, testpcap.ServerMAC, testpcap.ClientIP, testpcap.ServerIP, port, port, h)
}

func ikeSAInitV2(spi uint64) []byte { return ikePacket(true, 0x20, 34, 0x08, spi, 0, 0, false) }

func ikeRebuildFindings(r *models.TriageReport) []models.StabilityFinding {
	var out []models.StabilityFinding
	for _, f := range r.StabilityFindings {
		if f.Type == "IKE Tunnel Rebuild" {
			out = append(out, f)
		}
	}
	return out
}

func ikeInitEvents(r *models.TriageReport) int {
	n := 0
	for _, e := range r.Timeline {
		if e.EventType == "IKE SA Init" {
			n++
		}
	}
	return n
}

func TestIKERebuild_DistinctSAInitiationsStillTriggerTheFinding(t *testing.T) {
	var pk [][]byte
	for i := 0; i < 5; i++ {
		pk = append(pk, ikeSAInitV2(uint64(0x1000+i)))
	}
	r := runGolden(t, pk)
	f := ikeRebuildFindings(r)
	if len(f) != 1 || f[0].StateChanges != 5 || f[0].Severity != "High" || f[0].Protocol != "IKE" {
		t.Fatalf("findings = %+v", f)
	}
	for _, must := range []string{"5 distinct IKE SAs initiated by 192.168.1.100", "(5 within a 60s window)", "first initiation at frame 1", "Retransmissions of an initiation are not counted"} {
		if !strings.Contains(f[0].Description, must) {
			t.Errorf("description lacks %q: %s", must, f[0].Description)
		}
	}
	// The hint no longer asserts a cause.
	if strings.Contains(f[0].RootCauseHint, "WAN link flapping causes") || !strings.Contains(f[0].RootCauseHint, "not which cause applies") {
		t.Errorf("hint = %s", f[0].RootCauseHint)
	}
	if ikeInitEvents(r) != 5 {
		t.Errorf("timeline events = %d", ikeInitEvents(r))
	}
}

// The corpus case (The-Ultimate-PCAP): the same initiation repeated is a retransmission, not a rebuild.
func TestIKERebuild_RetransmissionsOfOneInitiationAreNotRebuilds(t *testing.T) {
	var pk [][]byte
	for i := 0; i < 8; i++ {
		pk = append(pk, ikeSAInitV2(0xe5bc6755))
	}
	r := runGolden(t, pk)
	if f := ikeRebuildFindings(r); len(f) != 0 {
		t.Fatalf("retransmissions produced a rebuild finding: %+v", f)
	}
	if ikeInitEvents(r) != 1 {
		t.Errorf("timeline events = %d, want 1 (the initiation; retransmissions are not new SAs)", ikeInitEvents(r))
	}
}

func TestIKERebuild_RetransmissionsAreReportedSeparatelyNotCounted(t *testing.T) {
	var pk [][]byte
	for i := 0; i < 4; i++ { // 4 distinct SAs, each sent twice
		pk = append(pk, ikeSAInitV2(uint64(0x2000+i)), ikeSAInitV2(uint64(0x2000+i)))
	}
	f := ikeRebuildFindings(runGolden(t, pk))
	if len(f) != 1 || f[0].StateChanges != 4 || !strings.Contains(f[0].Description, "4 retransmission(s) of an initiation seen") {
		t.Fatalf("findings = %+v", f)
	}
	// 3 distinct SAs (below the threshold) with many retransmissions: no finding.
	pk = nil
	for i := 0; i < 3; i++ {
		for k := 0; k < 4; k++ {
			pk = append(pk, ikeSAInitV2(uint64(0x3000+i)))
		}
	}
	if f := ikeRebuildFindings(runGolden(t, pk)); len(f) != 0 {
		t.Errorf("3 distinct SAs: %+v", f)
	}
}

func TestIKERebuild_ResponsesAndLaterMainModeMessagesAreNotInitiations(t *testing.T) {
	var pk [][]byte
	for i := 0; i < 5; i++ {
		spi := uint64(0x4000 + i)
		// IKEv2 response (response flag, responder SPI set) and IKEv1 Main Mode messages 3/5 (message ID 0,
		// responder cookie set) sent by the same address: none of them starts an SA.
		pk = append(pk, ikePacket(true, 0x20, 34, 0x20, spi, 0x99, 0, false), ikePacket(true, 0x10, 2, 0, spi, 0x77, 0, false))
	}
	if r := runGolden(t, pk); len(ikeRebuildFindings(r)) != 0 || ikeInitEvents(r) != 0 {
		t.Errorf("responses counted: findings %+v events %d", ikeRebuildFindings(r), ikeInitEvents(r))
	}
}

func TestIKERebuild_IKEv1MainModeCountsOnlyTheFirstMessageOfEachExchange(t *testing.T) {
	var pk [][]byte
	for i := 0; i < 3; i++ { // 3 exchanges × 3 initiator messages with message ID 0 → still 3 initiations
		spi := uint64(0x5000 + i)
		pk = append(pk, ikePacket(true, 0x10, 2, 0, spi, 0, 0, false), ikePacket(true, 0x10, 2, 0, spi, 0x55, 0, false), ikePacket(true, 0x10, 2, 0, spi, 0x55, 0, false))
	}
	if f := ikeRebuildFindings(runGolden(t, pk)); len(f) != 0 {
		t.Errorf("3 main-mode exchanges produced a finding: %+v", f)
	}
	pk = nil
	for i := 0; i < 5; i++ {
		pk = append(pk, ikePacket(true, 0x10, 2, 0, uint64(0x6000+i), 0, 0, false))
	}
	f := ikeRebuildFindings(runGolden(t, pk))
	if len(f) != 1 || f[0].StateChanges != 5 {
		t.Errorf("5 distinct main-mode initiations: %+v", f)
	}
}

func TestIKERebuild_NATTInitiationsAreCountedByTheirSPIToo(t *testing.T) {
	var pk [][]byte
	for i := 0; i < 5; i++ {
		pk = append(pk, ikePacket(true, 0x20, 34, 0x08, uint64(0x7000+i), 0, 0, true), ikePacket(true, 0x20, 34, 0x08, uint64(0x7000+i), 0, 0, true))
	}
	f := ikeRebuildFindings(runGolden(t, pk))
	if len(f) != 1 || f[0].StateChanges != 5 || !strings.Contains(f[0].Description, "5 retransmission(s)") {
		t.Errorf("findings = %+v", f)
	}
}

func TestIKERebuild_TrackedSPIBoundIsReported(t *testing.T) {
	var pk [][]byte
	for i := 0; i < 1030; i++ { // more distinct SPIs than the per-session bound of 1,024
		pk = append(pk, ikeSAInitV2(uint64(0x10000+i)))
	}
	f := ikeRebuildFindings(runGolden(t, pk))
	if len(f) != 1 || f[0].StateChanges != 1024 || !strings.Contains(f[0].Description, "6 further initiation(s) not tracked (bound reached)") {
		t.Fatalf("findings = %+v", f)
	}
}

// An IKEv2 exchange-34 packet that carries a responder SPI cannot be a first IKE_SA_INIT request.
func TestIKERebuild_ARequestFlagWithAResponderSPIIsNotAnInitiation(t *testing.T) {
	var pk [][]byte
	for i := 0; i < 5; i++ {
		pk = append(pk, ikePacket(true, 0x20, 34, 0x08, uint64(0x8000+i), 0x42, 0, false))
	}
	if r := runGolden(t, pk); len(ikeRebuildFindings(r)) != 0 || ikeInitEvents(r) != 0 {
		t.Errorf("findings %+v events %d", ikeRebuildFindings(r), ikeInitEvents(r))
	}
}
