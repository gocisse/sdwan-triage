package output

import (
	"bytes"
	"strings"
	"testing"

	"github.com/gocisse/sdwan-triage/pkg/models"
)

func icmpText(r *models.TriageReport) string {
	var b bytes.Buffer
	WriteICMPErrorEvidence(&b, r)
	return b.String()
}

func TestICMPErrorCLI_NothingWithoutEvidence(t *testing.T) {
	if icmpText(&models.TriageReport{}) != "" || icmpText(&models.TriageReport{ICMPErrorEvidence: &models.ICMPErrorEvidence{}}) != "" {
		t.Error("output without evidence")
	}
}

func TestICMPErrorCLI_ShowsTypeCodeFlowFramesAndMTU(t *testing.T) {
	e := &models.ICMPErrorEvidence{TotalMessages: 12, GroupsTotal: 3, GroupsShown: 3, MaxGroups: 50, MessagesWithUnusableQuote: 2, Errors: []models.ICMPErrorGroup{
		{Family: "ICMP", Type: 3, Code: 1, Reporter: "172.26.88.17", Recipient: "10.160.4.40", Count: 604, Meaning: "Destination Unreachable: Host Unreachable",
			Quoted:     models.ICMPQuotedFlow{Status: "complete", Protocol: "UDP", Src: "10.160.4.40", SrcPort: 5, Dst: "172.24.88.11", DstPort: 53},
			FirstFrame: 13, Frames: []uint64{13, 14, 15, 16, 17}, DistinctSrcPorts: 256, SrcPortsCapped: true},
		{Family: "ICMPv6", Type: 2, Reporter: "fe80::1", Recipient: "2001:db8::10", Count: 2, Meaning: "Packet Too Big", MinMTU: 1280, MaxMTU: 1400,
			Quoted:     models.ICMPQuotedFlow{Status: "complete", Protocol: "TCP", Src: "2001:db8::10", SrcPort: 51000, Dst: "2001:db8:1::53", DstPort: 443},
			FirstFrame: 7, Frames: []uint64{7, 9}, DistinctSrcPorts: 1},
		{Family: "ICMP", Type: 11, Reporter: "10.0.0.1", Recipient: "10.0.0.2", Count: 1, Meaning: "Time Exceeded: TTL reached zero in transit", QuotedSourceDiffers: true,
			Quoted: models.ICMPQuotedFlow{Status: "no_ports", Protocol: "ICMP", Src: "10.0.0.2", Dst: "8.8.8.8"}, FirstFrame: 20, Frames: []uint64{20}},
	}}
	out := icmpText(&models.TriageReport{ICMPErrorEvidence: e})
	for _, must := range []string{
		"ICMP ERRORS (messages observed in this capture; they show what a device sent, not why or where the problem is):",
		"ICMP type 3 code 1 from 172.26.88.17 to 10.160.4.40, 604 message(s): Destination Unreachable: Host Unreachable about UDP from 10.160.4.40 to 172.24.88.11:53; 256+ different source ports (first frame 13)",
		"ICMPv6 type 2 code 0 from fe80::1 to 2001:db8::10, 2 message(s): Packet Too Big about TCP from 2001:db8::10 to 2001:db8:1::53:443; source port 51000; reported next-hop MTU 1280-1400 (frames 7..9)",
		"about an ICMP packet 10.0.0.2 -> 8.8.8.8 (ports not available in the quoted part) (frame 20)",
		"The quoted packet's source is not the address this message was sent to",
		"2 of 12 message(s) did not quote a usable original packet, so the affected flow is unknown for them.",
		"does not by itself show that an application failed",
	} {
		if !strings.Contains(out, must) {
			t.Errorf("missing %q in:\n%s", must, out)
		}
	}
	for _, banned := range []string{"caused", "because", "outage", "provider", "faulty"} {
		if strings.Contains(strings.ToLower(out), banned) {
			t.Errorf("contains %q", banned)
		}
	}
	if strings.Contains(out, "Display limited") {
		t.Error("display notice without truncation")
	}
}

func TestICMPErrorCLI_BoundAndUnusableQuoteText(t *testing.T) {
	e := &models.ICMPErrorEvidence{TotalMessages: 12, GroupsTotal: 12, GroupsShown: 12, MaxGroups: 50}
	for i := 0; i < 12; i++ {
		e.Errors = append(e.Errors, models.ICMPErrorGroup{Family: "ICMP", Type: 3, Code: uint8(i), Reporter: "r", Recipient: "c", Count: 1, Meaning: "m", Quoted: models.ICMPQuotedFlow{Status: "unusable"}})
	}
	out := icmpText(&models.TriageReport{ICMPErrorEvidence: e})
	if got := strings.Count(out, "  ICMP type 3 code"); got != cliICMPErrorMaxGroups {
		t.Errorf("groups shown = %d, want %d", got, cliICMPErrorMaxGroups)
	}
	for _, must := range []string{"Display limited: showing 8 of 12 groups (most messages first); the JSON list (icmp_error_evidence) is bounded at 50.", "could not be identified (quote absent or truncated)"} {
		if !strings.Contains(out, must) {
			t.Errorf("missing %q", must)
		}
	}
	if icmpText(&models.TriageReport{ICMPErrorEvidence: e}) != out {
		t.Error("output not deterministic")
	}
}
