package analyzer

import (
	"strings"
	"testing"

	"github.com/gocisse/sdwan-triage/internal/testpcap"
	"github.com/gocisse/sdwan-triage/pkg/events"
	"github.com/gocisse/sdwan-triage/pkg/models"
)

// Phase 4.38 — BFD findings report the RFC 5880 diagnostic code carried by the packet that
// showed each Up → non-Up transition, and the hint no longer asserts a cause the capture
// cannot show. Packets are 100 ms apart.

const (
	bfdSAdmin = 0
	bfdSDown  = 1
	bfdSInit  = 2
	bfdSUp    = 3
)

func bfdPacket(state, diag byte) []byte {
	p := testpcap.BFDControl(state << 6)
	p[0] = 0x20 | (diag & 0x1f) // version 1, diagnostic code
	return testpcap.UDPFrame(testpcap.ClientMAC, testpcap.ServerMAC, testpcap.ClientIP, testpcap.BFDPeer, 49152, 3784, p)
}

func bfdFindings(r *models.TriageReport, typ string) []models.StabilityFinding {
	var out []models.StabilityFinding
	for _, f := range r.StabilityFindings {
		if f.Type == typ {
			out = append(out, f)
		}
	}
	return out
}

// upThenDown: 3 Up packets, then Down with the given state and diagnostic code (frame 4).
func upThenDown(newState, diag byte) [][]byte {
	return [][]byte{bfdPacket(bfdSUp, 0), bfdPacket(bfdSUp, 0), bfdPacket(bfdSUp, 0), bfdPacket(newState, diag), bfdPacket(newState, diag)}
}

func TestBFDDiag_ControlDetectionTimeExpiredIsReportedWithoutAssertingACause(t *testing.T) {
	r := runGolden(t, upThenDown(bfdSDown, 1))
	f := bfdFindings(r, "BFD Session Down")
	if len(f) != 1 || f[0].Severity != "High" || f[0].StateChanges != 1 {
		t.Fatalf("findings = %+v", f)
	}
	for _, must := range []string{"the first Down packet from 192.168.1.100 carried diagnostic code 1 (Control Detection Time Expired) at frame 4"} {
		if !strings.Contains(f[0].Description, must) {
			t.Errorf("description lacks %q: %s", must, f[0].Description)
		}
	}
	h := f[0].RootCauseHint
	for _, must := range []string{"stopped receiving the peer's BFD control packets", "not established by this capture"} {
		if !strings.Contains(h, must) {
			t.Errorf("hint lacks %q: %s", must, h)
		}
	}
	for _, banned := range []string{"Peer stopped responding", "WAN circuit failure", "peer reload", "underlay path loss"} {
		if strings.Contains(h, banned) {
			t.Errorf("hint asserts %q: %s", banned, h)
		}
	}
}

func TestBFDDiag_AdministrativeAndOtherCodes(t *testing.T) {
	cases := []struct {
		name         string
		state, diag  byte
		must, mustNo string
	}{
		{"admin down state", bfdSAdmin, 7, "deliberate local shutdown", "stopped receiving"},
		{"admin down code on Down", bfdSDown, 7, "deliberate local shutdown", "stopped receiving"},
		{"no diagnostic", bfdSDown, 0, "without a diagnostic code", "stopped receiving"},
		{"neighbor signalled", bfdSDown, 3, "after the neighbor signalled Down", "stopped receiving"},
		{"echo failed", bfdSDown, 2, "echo function failed", "deliberate"},
		{"path down", bfdSDown, 5, "\"Path Down\"", "deliberate"},
		{"unknown code", bfdSDown, 20, "Unknown diagnostic 20", "deliberate"},
	}
	for _, c := range cases {
		f := bfdFindings(runGolden(t, upThenDown(c.state, c.diag)), "BFD Session Down")
		if len(f) != 1 {
			t.Fatalf("%s: findings = %+v", c.name, f)
		}
		if !strings.Contains(f[0].RootCauseHint, c.must) || strings.Contains(f[0].RootCauseHint, c.mustNo) {
			t.Errorf("%s: hint = %s", c.name, f[0].RootCauseHint)
		}
		if !strings.Contains(f[0].Description, "carried diagnostic code") {
			t.Errorf("%s: description = %s", c.name, f[0].Description)
		}
	}
}

func TestBFDDiag_FlappingListsTheCodesAndHasANonCausalHint(t *testing.T) {
	var pk [][]byte
	for i := 0; i < 3; i++ { // Up, Down(code 1), Up, Down(code 3), ...
		pk = append(pk, bfdPacket(bfdSUp, 0), bfdPacket(bfdSDown, 1), bfdPacket(bfdSUp, 0), bfdPacket(bfdSDown, 3))
	}
	f := bfdFindings(runGolden(t, pk), "BFD Flapping")
	if len(f) != 1 || f[0].Severity != "Critical" {
		t.Fatalf("findings = %+v", f)
	}
	for _, must := range []string{"6 Up → Down transition(s) from 192.168.1.100", "Control Detection Time Expired ×3", "Neighbor Signaled Session Down ×3", "first at frame 2"} {
		if !strings.Contains(f[0].Description, must) {
			t.Errorf("description lacks %q: %s", must, f[0].Description)
		}
	}
	if !strings.Contains(f[0].RootCauseHint, "Possible causes include") || strings.Contains(f[0].RootCauseHint, "ISP flapping") {
		t.Errorf("hint = %s", f[0].RootCauseHint)
	}
}

func TestBFDDiag_HealthyStartupAndEventAttributes(t *testing.T) {
	r := runGolden(t, [][]byte{bfdPacket(bfdSDown, 0), bfdPacket(bfdSInit, 0), bfdPacket(bfdSUp, 0), bfdPacket(bfdSUp, 0)})
	if len(r.StabilityFindings) != 0 || len(r.Events.ByKind(events.BFDDown)) != 0 {
		t.Errorf("a normal Down → Init → Up start produced %+v", r.StabilityFindings)
	}
	r = runGolden(t, upThenDown(bfdSDown, 1))
	ev := r.Events.ByKind(events.BFDDown)
	if len(ev) != 1 || ev[0].Attrs["diag"] != "1" || ev[0].Attrs["diag_name"] != "Control Detection Time Expired" ||
		ev[0].Values["prev_state"] != float64(bfdSUp) || ev[0].Values["new_state"] != float64(bfdSDown) || ev[0].Attrs["new_state_name"] != "Down" {
		t.Errorf("event = %+v", ev)
	}
}

// The existing tunnel-drop scenario keeps its single High finding (code 0 in that fixture).
func TestBFDDiag_ExistingTunnelDropScenarioIsUnchangedExceptWording(t *testing.T) {
	r := runGolden(t, testpcap.BFDTunnelDrop())
	f := bfdFindings(r, "BFD Session Down")
	if len(f) != 1 || f[0].Severity != "High" || f[0].StateChanges != 1 || len(bfdFindings(r, "BFD Flapping")) != 0 {
		t.Fatalf("findings = %+v", r.StabilityFindings)
	}
	if !strings.Contains(f[0].RootCauseHint, "without a diagnostic code") {
		t.Errorf("hint = %s", f[0].RootCauseHint)
	}
}

func TestBFDDiag_DownInfoIsBounded(t *testing.T) {
	var pk [][]byte
	for i := 0; i < 1100; i++ {
		pk = append(pk, bfdPacket(bfdSUp, 0), bfdPacket(bfdSDown, 1))
	}
	f := bfdFindings(runGolden(t, pk), "BFD Flapping")
	if len(f) != 1 || !strings.Contains(f[0].Description, "1024 Up → Down transition(s)") {
		t.Fatalf("findings = %+v", f)
	}
}
