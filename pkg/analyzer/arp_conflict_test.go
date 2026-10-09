package analyzer

import (
	"encoding/json"
	"net"
	"strings"
	"testing"

	"github.com/gocisse/sdwan-triage/internal/testpcap"
	"github.com/gocisse/sdwan-triage/pkg/models"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// Phase 4.35 — ARP conflicts: frames and every answering MAC are recorded, and a conflict
// whose MACs are all documented virtual redundant-gateway MACs (GLBP/VRRP/HSRP) is listed
// but no longer drives critical health, the risk score, the top issue or the
// "investigate ARP spoofing" action. Anything else behaves exactly as before.

func arpTestFrame(op uint16, srcMAC string, srcIP string, dstIP string) []byte {
	hw, _ := net.ParseMAC(srcMAC)
	eth := &layers.Ethernet{SrcMAC: hw, DstMAC: testpcap.ClientMAC, EthernetType: layers.EthernetTypeARP}
	if op == 1 {
		eth.DstMAC = net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	}
	arp := &layers.ARP{
		AddrType: layers.LinkTypeEthernet, Protocol: layers.EthernetTypeIPv4, HwAddressSize: 6, ProtAddressSize: 4, Operation: op,
		SourceHwAddress: hw, SourceProtAddress: net.ParseIP(srcIP).To4(), DstHwAddress: testpcap.ClientMAC, DstProtAddress: net.ParseIP(dstIP).To4(),
	}
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{}, eth, arp); err != nil {
		panic(err)
	}
	return buf.Bytes()
}

func arpTestReply(mac, ip string) []byte { return arpTestFrame(2, mac, ip, "192.168.42.11") }

const (
	arpPhys1 = "b8:27:eb:c9:16:37"
	arpPhys2 = "b8:27:eb:00:00:02"
	arpGLBP1 = "00:07:b4:00:2a:01"
	arpGLBP2 = "00:07:b4:00:2a:02"
	arpVRRP  = "00:00:5e:00:01:01"
)

func TestARPConflict_PhysicalMACsStayAnUnexplainedCriticalConflict(t *testing.T) {
	r := runGolden(t, [][]byte{arpTestReply(arpPhys1, "192.168.42.1"), arpTestReply(arpPhys1, "192.168.42.1"), arpTestReply(arpPhys2, "192.168.42.1")})
	if len(r.ARPConflicts) != 1 {
		t.Fatalf("conflicts = %+v", r.ARPConflicts)
	}
	c := r.ARPConflicts[0]
	if c.IP != "192.168.42.1" || c.MAC1 != arpPhys1 || c.MAC2 != arpPhys2 || c.MAC1Frame != 1 || c.MAC2Frame != 3 || c.Classification != models.ARPConflictUnexplained {
		t.Errorf("conflict = %+v", c)
	}
	if !strings.Contains(c.Explanation, "duplicate IP address") || !strings.Contains(c.Explanation, "spoofing would all look like this") {
		t.Errorf("explanation = %s", c.Explanation)
	}
	if models.ComputeNetworkHealth(r) != models.NetworkHealthCritical || r.RiskScore < 10 || r.TopIssue != "ARP Conflicts" {
		t.Errorf("health %s risk %d top %q", models.ComputeNetworkHealth(r), r.RiskScore, r.TopIssue)
	}
	found := false
	for _, a := range r.RecommendedActions {
		found = found || strings.Contains(a, "ARP spoofing")
	}
	if !found {
		t.Errorf("existing action lost: %v", r.RecommendedActions)
	}
}

// The corpus pattern (The-Ultimate-PCAP, frames 25504/25813/28236): GLBP forwarders and a
// VRRP virtual MAC answering for the same gateway IP.
func TestARPConflict_VirtualGatewayMACsAreListedButNotCritical(t *testing.T) {
	base := runGolden(t, [][]byte{arpTestReply(arpPhys1, "192.168.42.11")})
	r := runGolden(t, [][]byte{
		arpTestReply(arpGLBP1, "192.168.42.1"), arpTestReply(arpGLBP2, "192.168.42.1"), arpTestReply(arpGLBP1, "192.168.42.1"), arpTestReply(arpVRRP, "192.168.42.1"),
		arpTestReply(arpPhys1, "192.168.42.11"),
	})
	if len(r.ARPConflicts) != 1 {
		t.Fatalf("conflicts = %+v", r.ARPConflicts)
	}
	c := r.ARPConflicts[0]
	if c.Classification != models.ARPConflictVirtualGateway || len(c.OtherMACs) != 1 || c.OtherMACs[0] != arpVRRP || c.MAC1Frame != 1 || c.MAC2Frame != 2 {
		t.Errorf("conflict = %+v", c)
	}
	if !strings.Contains(c.Explanation, "GLBP") || !strings.Contains(c.Explanation, "VRRP/CARP") || !strings.Contains(c.Explanation, "cannot verify") {
		t.Errorf("explanation = %s", c.Explanation)
	}
	if h := models.ComputeNetworkHealth(r); h == models.NetworkHealthCritical {
		t.Errorf("health = %s", h)
	}
	if r.RiskScore != base.RiskScore || r.TopIssue != base.TopIssue || len(r.RecommendedActions) != len(base.RecommendedActions) {
		t.Errorf("risk %d/%d top %q/%q actions %v/%v", r.RiskScore, base.RiskScore, r.TopIssue, base.TopIssue, r.RecommendedActions, base.RecommendedActions)
	}
	for _, a := range r.RecommendedActions {
		if strings.Contains(a, "ARP spoofing") {
			t.Errorf("spoofing action for a virtual-gateway conflict: %s", a)
		}
	}
	// Still visible in the report (count unchanged) and in the JSON with its evidence.
	b, _ := json.Marshal(r.ARPConflicts)
	for _, must := range []string{`"classification":"virtual_gateway_macs"`, `"mac1_frame":1`, `"other_macs":["00:00:5e:00:01:01"]`, `"explanation"`} {
		if !strings.Contains(string(b), must) {
			t.Errorf("JSON lacks %s: %s", must, b)
		}
	}
}

// A later non-virtual MAC reclassifies the conflict; so does a virtual MAC paired with a physical one.
func TestARPConflict_AnyNonVirtualMACMakesItUnexplained(t *testing.T) {
	r := runGolden(t, [][]byte{arpTestReply(arpGLBP1, "192.168.42.1"), arpTestReply(arpGLBP2, "192.168.42.1"), arpTestReply(arpPhys1, "192.168.42.1")})
	if c := r.ARPConflicts[0]; c.Classification != models.ARPConflictUnexplained || len(c.OtherMACs) != 1 {
		t.Errorf("conflict = %+v", c)
	}
	if models.ComputeNetworkHealth(r) != models.NetworkHealthCritical {
		t.Error("health not critical")
	}
	r = runGolden(t, [][]byte{arpTestReply(arpVRRP, "192.168.42.1"), arpTestReply(arpPhys1, "192.168.42.1")})
	if r.ARPConflicts[0].Classification != models.ARPConflictUnexplained || models.ComputeNetworkHealth(r) != models.NetworkHealthCritical {
		t.Errorf("virtual + physical = %+v", r.ARPConflicts[0])
	}
}

func TestARPConflict_MixedIPsKeepTheUnexplainedOneCritical(t *testing.T) {
	r := runGolden(t, [][]byte{
		arpTestReply(arpGLBP1, "192.168.42.1"), arpTestReply(arpGLBP2, "192.168.42.1"),
		arpTestReply(arpPhys1, "192.168.42.50"), arpTestReply(arpPhys2, "192.168.42.50"),
	})
	if len(r.ARPConflicts) != 2 || r.UnexplainedARPConflicts() != 1 || models.ComputeNetworkHealth(r) != models.NetworkHealthCritical {
		t.Errorf("conflicts = %+v", r.ARPConflicts)
	}
	if r.RiskScore < 10 || r.RiskScore >= 20 {
		t.Errorf("risk score %d should count only the unexplained conflict", r.RiskScore)
	}
}

func TestARPConflict_OtherMACListIsBounded(t *testing.T) {
	var pk [][]byte
	for i := 0; i < 14; i++ {
		pk = append(pk, arpTestReply("02:00:00:00:00:"+string("0123456789abcdef"[i])+"0", "192.168.42.9"))
	}
	c := runGolden(t, pk).ARPConflicts[0]
	if len(c.OtherMACs) != 8 {
		t.Errorf("other MACs = %d, want the bound of 8", len(c.OtherMACs))
	}
}

// Unchanged behaviour: one MAC per IP is no conflict; requests are not read (documented limitation).
func TestARPConflict_UnchangedForSingleBindingsAndRequests(t *testing.T) {
	r := runGolden(t, [][]byte{arpTestReply(arpPhys1, "192.168.42.1"), arpTestReply(arpPhys1, "192.168.42.1"), arpTestReply(arpPhys2, "192.168.42.2")})
	if len(r.ARPConflicts) != 0 {
		t.Errorf("conflicts = %+v", r.ARPConflicts)
	}
	r = runGolden(t, [][]byte{arpTestFrame(1, arpPhys1, "192.168.42.1", "192.168.42.9"), arpTestFrame(1, arpPhys2, "192.168.42.1", "192.168.42.9")})
	if len(r.ARPConflicts) != 0 {
		t.Errorf("ARP requests created a conflict: %+v", r.ARPConflicts)
	}
}
