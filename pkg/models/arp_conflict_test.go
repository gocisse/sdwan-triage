package models

import "testing"

// Phase 4.35 — virtual redundant-gateway MACs and ARP conflict classification.
func TestVirtualGatewayMACKind(t *testing.T) {
	cases := map[string]string{
		"00:00:5e:00:01:01": "VRRP/CARP", "00:00:5E:00:01:FF": "VRRP/CARP",
		"00:00:0c:07:ac:2a": "HSRP", "00:00:0c:9f:f0:01": "HSRPv2", "00:00:0c:9f:ff:ff": "HSRPv2",
		"00:07:b4:00:2a:01": "GLBP", "00:07:B4:00:2A:02": "GLBP",
		// near misses and non-matches
		"00:00:5e:00:02:01": "", "00:00:5e:00:00:01": "", "00:00:0c:07:ad:01": "", "00:00:0c:9f:e0:01": "",
		"00:07:b4:01:2a:01": "", "00:07:b5:00:2a:01": "", "b8:27:eb:c9:16:37": "", "": "", "not-a-mac": "", "00:00:5e:00:01": "",
	}
	for mac, want := range cases {
		if got := VirtualGatewayMACKind(mac); got != want {
			t.Errorf("VirtualGatewayMACKind(%q) = %q, want %q", mac, got, want)
		}
	}
}

func TestARPConflictClassify(t *testing.T) {
	c := ARPConflict{IP: "192.168.42.1", MAC1: "00:07:b4:00:2a:01", MAC2: "00:07:b4:00:2a:02", OtherMACs: []string{"00:00:5e:00:01:01"}}
	c.Classify()
	if c.Classification != ARPConflictVirtualGateway {
		t.Fatalf("classification = %q", c.Classification)
	}
	for _, must := range []string{"GLBP", "VRRP/CARP", "consistent with a redundant gateway", "cannot verify"} {
		if !contains(c.Explanation, must) {
			t.Errorf("explanation lacks %q: %s", must, c.Explanation)
		}
	}
	// One non-virtual MAC anywhere makes the conflict unexplained.
	c.OtherMACs = append(c.OtherMACs, "b8:27:eb:c9:16:37")
	c.Classify()
	if c.Classification != ARPConflictUnexplained || contains(c.Explanation, "redundant gateway") {
		t.Errorf("mixed conflict = %q / %s", c.Classification, c.Explanation)
	}
	u := ARPConflict{MAC1: "aa:aa:aa:00:00:01", MAC2: "00:00:5e:00:01:01"}
	u.Classify()
	if u.Classification != ARPConflictUnexplained {
		t.Errorf("physical + virtual = %q", u.Classification)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

func TestUnexplainedARPConflictsAndHealth(t *testing.T) {
	legacy := &TriageReport{ARPConflicts: make([]ARPConflict, 1)} // no classification: unchanged behaviour
	if legacy.UnexplainedARPConflicts() != 1 || ComputeNetworkHealth(legacy) != NetworkHealthCritical {
		t.Error("an unclassified conflict must stay critical")
	}
	virtual := &TriageReport{ARPConflicts: []ARPConflict{{Classification: ARPConflictVirtualGateway}}}
	if virtual.UnexplainedARPConflicts() != 0 || ComputeNetworkHealth(virtual) != NetworkHealthGood {
		t.Errorf("virtual-gateway conflict: unexplained=%d health=%s", virtual.UnexplainedARPConflicts(), ComputeNetworkHealth(virtual))
	}
	mixed := &TriageReport{ARPConflicts: []ARPConflict{{Classification: ARPConflictVirtualGateway}, {Classification: ARPConflictUnexplained}}}
	if mixed.UnexplainedARPConflicts() != 1 || ComputeNetworkHealth(mixed) != NetworkHealthCritical {
		t.Error("an unexplained conflict next to a virtual-gateway one must stay critical")
	}
}
