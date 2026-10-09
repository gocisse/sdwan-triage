package detector

import (
	"net"
	"testing"
	"time"

	"github.com/gocisse/sdwan-triage/pkg/models"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func udpTestPacket(t *testing.T, src, dst net.IP, sport, dport uint16, payload []byte) gopacket.Packet {
	t.Helper()
	eth := &layers.Ethernet{SrcMAC: net.HardwareAddr{0, 1, 2, 3, 4, 5}, DstMAC: net.HardwareAddr{0, 1, 2, 3, 4, 6}, EthernetType: layers.EthernetTypeIPv4}
	ip := &layers.IPv4{Version: 4, IHL: 5, TTL: 64, Protocol: layers.IPProtocolUDP, SrcIP: src, DstIP: dst}
	udp := &layers.UDP{SrcPort: layers.UDPPort(sport), DstPort: layers.UDPPort(dport)}
	_ = udp.SetNetworkLayerForChecksum(ip)
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, eth, ip, udp, gopacket.Payload(payload)); err != nil {
		t.Fatal(err)
	}
	p := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
	p.Metadata().Timestamp = time.Unix(1000, 0)
	return p
}

func TestUDPServices_TrackingBoundCountsUntrackedDatagrams(t *testing.T) {
	u := NewUDPServiceAnalyzer()
	u.maxConvs = 2
	report := &models.TriageReport{}
	state := models.NewAnalysisState()
	for i := 0; i < 5; i++ { // five client ports, bound of two conversations
		u.Analyze(udpTestPacket(t, net.IPv4(10, 0, 0, 1), net.IPv4(10, 0, 0, 2), uint16(40000+i), 161, []byte("q")), state, report)
	}
	// A second datagram of a tracked conversation is still counted.
	u.Analyze(udpTestPacket(t, net.IPv4(10, 0, 0, 1), net.IPv4(10, 0, 0, 2), 40000, 161, []byte("q")), state, report)
	u.Finalize(time.Unix(1010, 0), report)
	r := report.UDPServiceResponses
	if r == nil || r.ConversationsTracked != 2 || r.DatagramsUntracked != 3 || r.GroupsTotal != 1 || r.Groups[0].Conversations != 2 || r.Groups[0].Requests != 3 {
		t.Fatalf("summary = %+v", r)
	}
}

// Both ports in the service set (a peer protocol, e.g. SNMP agent to manager on 161) is not a request or reply.
func TestUDPServices_ServicePortOnBothSidesIsIgnored(t *testing.T) {
	u := NewUDPServiceAnalyzer()
	report := &models.TriageReport{}
	u.Analyze(udpTestPacket(t, net.IPv4(10, 0, 0, 1), net.IPv4(10, 0, 0, 2), 161, 161, []byte("x")), models.NewAnalysisState(), report)
	u.Finalize(time.Unix(1010, 0), report)
	if report.UDPServiceResponses != nil || len(u.convs) != 0 {
		t.Errorf("peer datagram tracked: %+v", u.convs)
	}
}

func TestUDPServices_VisibilityText(t *testing.T) {
	if udpSvcVisibility(0, 3) != "" {
		t.Error("note for fully answered conversations")
	}
	if v := udpSvcVisibility(3, 3); v == "" || !contains(v, "any of these conversations") {
		t.Errorf("all unanswered = %q", v)
	}
	if v := udpSvcVisibility(1, 3); !contains(v, "1 of 3 conversations") {
		t.Errorf("some unanswered = %q", v)
	}
}

func TestUDPServices_RepliesWithoutRequestsDoNotFormGroups(t *testing.T) {
	u := NewUDPServiceAnalyzer()
	u.convs["x"] = &udpSvcConv{svc: "SNMP", client: "c", server: "s", serverPort: 161, reps: 3}
	u.order = []string{"x"}
	report := &models.TriageReport{}
	u.Finalize(time.Unix(1000, 0), report)
	if report.UDPServiceResponses != nil {
		t.Errorf("summary from replies only: %+v", report.UDPServiceResponses)
	}
}
