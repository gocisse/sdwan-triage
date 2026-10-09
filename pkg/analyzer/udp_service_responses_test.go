package analyzer

import (
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/gocisse/sdwan-triage/internal/testpcap"
	"github.com/gocisse/sdwan-triage/pkg/models"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// Phase 4.36 — UDP request/response visibility for SNMP, NTP, RADIUS, Kerberos and LDAP.
// A missing reply is "no reply observed" with a visibility qualifier, never a failed server
// or packet loss. Packets are 100 ms apart unless runGoldenInterval is used.

var (
	usClient = []byte{10, 250, 29, 156}
	usServer = []byte{172, 26, 88, 17}
)

func usReq(client, server []byte, cport, sport uint16, payload []byte) []byte {
	return testpcap.UDPFrame(testpcap.ClientMAC, testpcap.ServerMAC, client, server, cport, sport, payload)
}

func usRep(client, server []byte, cport, sport uint16, payload []byte) []byte {
	return testpcap.UDPFrame(testpcap.ServerMAC, testpcap.ClientMAC, server, client, sport, cport, payload)
}

func usSummary(t *testing.T, r *models.TriageReport) *models.UDPServiceResponses {
	t.Helper()
	if r.UDPServiceResponses == nil {
		t.Fatal("no udp_service_responses")
	}
	return r.UDPServiceResponses
}

var usBanned = []string{"server failed", "is down", "packet loss", "was lost", "were lost", "outage", "provider", "blocked", "dropped by"}

func usNoClaims(t *testing.T, text string) {
	t.Helper()
	// The text may NEGATE a claim ("does not ... show that the server failed"); it must not assert one.
	l := strings.ToLower(text)
	for _, neg := range []string{"it does not show that the server failed or that packets were lost", "this does not by itself show that the server failed",
		"it does not by itself show that packets were lost or where"} {
		l = strings.ReplaceAll(l, neg, "")
	}
	for _, b := range usBanned {
		if strings.Contains(l, b) {
			t.Errorf("text makes an unsupported claim (%q): %s", b, text)
		}
	}
}

func TestUDPServices_AbsentWithoutCoveredServices(t *testing.T) {
	r := runGolden(t, [][]byte{usReq(usClient, usServer, 40000, 9999, []byte("x")), usRep(usClient, usServer, 40000, 9999, []byte("y"))})
	if r.UDPServiceResponses != nil {
		t.Errorf("summary for an uncovered port: %+v", r.UDPServiceResponses)
	}
	b, _ := json.Marshal(r)
	if strings.Contains(string(b), "udp_service_responses") {
		t.Error("key serialized without covered services")
	}
}

func TestUDPServices_AnsweredConversationHasNoVisibilityNote(t *testing.T) {
	r := runGolden(t, [][]byte{
		usReq(usClient, usServer, 52938, 161, []byte("q1")), usRep(usClient, usServer, 52938, 161, []byte("a1")),
		usReq(usClient, usServer, 52938, 161, []byte("q2")), usRep(usClient, usServer, 52938, 161, []byte("a2")),
	})
	g := usSummary(t, r).Groups[0]
	if g.Service != "SNMP" || g.Client != "10.250.29.156" || g.Server != "172.26.88.17" || g.ServerPort != 161 || g.Conversations != 1 || g.Requests != 2 || g.Replies != 2 ||
		g.ConversationsWithoutReply != 0 || g.Visibility != "" || g.FirstRequestFrame != 1 {
		t.Errorf("group = %+v", g)
	}
}

// Requests only (a one-direction capture, or a silent server): reported as "no reply observed".
func TestUDPServices_NoReplyIsQualifiedNotBlamed(t *testing.T) {
	r := runGoldenInterval(t, [][]byte{
		usReq(usClient, usServer, 52938, 161, []byte("q1")), usReq(usClient, usServer, 52938, 161, []byte("q2")),
		usReq(usClient, usServer, 52939, 161, []byte("q3")), usReq(usClient, usServer, 52939, 161, []byte("q4")),
		usReq(usClient, usServer, 52940, 161, []byte("q5")), usReq(usClient, usServer, 52940, 161, []byte("q6")),
	}, time.Second)
	u := usSummary(t, r)
	g := u.Groups[0]
	if g.Conversations != 3 || g.Requests != 6 || g.Replies != 0 || g.ConversationsWithoutReply != 3 || g.FirstUnansweredFrame != 1 || g.WithoutReplyNearCaptureEnd != 1 { // only the conversation whose last request is at the end (< 2 s)
		t.Fatalf("group = %+v", g)
	}
	for _, must := range []string{"No reply was observed in any of these conversations", "may not contain the return direction", "does not by itself show that the server failed"} {
		if !strings.Contains(g.Visibility, must) {
			t.Errorf("visibility lacks %q: %s", must, g.Visibility)
		}
	}
	usNoClaims(t, g.Visibility)
	usNoClaims(t, models.UDPServiceResponsesBasis)
	if len(u.Services) != 1 || u.Services[0].Service != "SNMP" || u.Services[0].ConversationsWithoutReply != 3 {
		t.Errorf("services = %+v", u.Services)
	}
}

func TestUDPServices_MixedConversationsAndPartialReplies(t *testing.T) {
	r := runGolden(t, [][]byte{
		usReq(usClient, usServer, 40001, 161, []byte("a")), usRep(usClient, usServer, 40001, 161, []byte("a")), // answered
		usReq(usClient, usServer, 40002, 161, []byte("b")),                                                                                                         // no reply
		usReq(usClient, usServer, 40003, 161, []byte("c")), usReq(usClient, usServer, 40003, 161, []byte("c")), usRep(usClient, usServer, 40003, 161, []byte("c")), // 2 requests, 1 reply
	})
	g := usSummary(t, r).Groups[0]
	if g.Conversations != 3 || g.Requests == 0 || g.Replies != 2 || g.ConversationsWithoutReply != 1 || g.FirstUnansweredFrame != 3 {
		t.Fatalf("group = %+v", g)
	}
	if !strings.Contains(g.Visibility, "No reply was observed in 1 of 3 conversations") {
		t.Errorf("visibility = %s", g.Visibility)
	}
	// Fewer replies than requests within a conversation is not reported as unanswered (counts only).
	if g.Requests != 4 {
		t.Errorf("requests = %d", g.Requests)
	}
}

func TestUDPServices_RepliesWithoutRequestsAndPeerPortsAreIgnored(t *testing.T) {
	ntp := func(mode byte) []byte { p := make([]byte, 48); p[0] = 0x18 | mode; return p }
	r := runGolden(t, [][]byte{
		usRep(usClient, usServer, 40001, 161, []byte("orphan")), // reply, never a request
		usReq(usClient, usServer, 123, 123, ntp(1)),             // NTP symmetric (both ports 123)
		usReq(usClient, usServer, 40005, 123, ntp(4)),           // mode 4 sent to the server: not a client request
		usReq(usClient, usServer, 40006, 123, ntp(5)),           // broadcast mode
		usRep(usClient, usServer, 40007, 123, ntp(3)),           // mode 3 from the server port: not a server reply
	})
	if r.UDPServiceResponses != nil {
		t.Errorf("unexpected summary: %+v", r.UDPServiceResponses)
	}
	r = runGolden(t, [][]byte{usReq(usClient, usServer, 40006, 123, ntp(3)), usRep(usClient, usServer, 40006, 123, ntp(4))})
	if g := usSummary(t, r).Groups[0]; g.Service != "NTP" || g.Requests != 1 || g.Replies != 1 {
		t.Errorf("NTP group = %+v", g)
	}
}

func TestUDPServices_ServiceNames(t *testing.T) {
	cases := map[uint16]string{161: "SNMP", 123: "NTP", 1812: "RADIUS", 1645: "RADIUS", 1813: "RADIUS accounting", 1646: "RADIUS accounting", 88: "Kerberos", 389: "LDAP"}
	for port, want := range cases {
		payload := []byte("x")
		if port == 123 {
			payload = make([]byte, 48)
			payload[0] = 0x1b
		}
		r := runGolden(t, [][]byte{usReq(usClient, usServer, 40001, port, payload)})
		if g := usSummary(t, r).Groups[0]; g.Service != want || g.ServerPort != port {
			t.Errorf("port %d: %+v", port, g)
		}
	}
}

// A large reply is IP-fragmented; the decoder gives no UDP layer, so the first fragment (which
// holds the UDP header) must be read, otherwise a answered request would look unanswered.
func TestUDPServices_FragmentedReplyIsCountedOnce(t *testing.T) {
	udpHdr := []byte{0, 161, 0xcd, 0xc8, 0x07, 0x89, 0, 0} // 161 -> 52680, length 1929
	first := append(append([]byte(nil), udpHdr...), make([]byte, 1000)...)
	frag := func(offset uint16, more bool, body []byte) []byte {
		eth := &layers.Ethernet{SrcMAC: testpcap.ServerMAC, DstMAC: testpcap.ClientMAC, EthernetType: layers.EthernetTypeIPv4}
		ip := &layers.IPv4{Version: 4, IHL: 5, TTL: 64, Protocol: layers.IPProtocolUDP, SrcIP: net.IP(usServer), DstIP: net.IP(usClient), Id: 77, FragOffset: offset}
		if more {
			ip.Flags = layers.IPv4MoreFragments
		}
		buf := gopacket.NewSerializeBuffer()
		if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, eth, ip, gopacket.Payload(body)); err != nil {
			panic(err)
		}
		return buf.Bytes()
	}
	r := runGolden(t, [][]byte{
		usReq(usClient, usServer, 52680, 161, []byte("bulk")),
		frag(0, true, first), frag(125, false, make([]byte, 929)),
	})
	g := usSummary(t, r).Groups[0]
	if g.Replies != 1 || g.ConversationsWithoutReply != 0 || g.Visibility != "" {
		t.Errorf("fragmented reply not counted once: %+v", g)
	}
}

func TestUDPServices_GroupListIsBoundedAndUnansweredFirst(t *testing.T) {
	var pk [][]byte
	// 55 servers whose requests were answered, then one that was not.
	for i := 0; i < 55; i++ {
		srv := []byte{172, 30, byte(i / 250), byte(i%250 + 1)}
		pk = append(pk, usReq(usClient, srv, 40000, 161, []byte("q")), usRep(usClient, srv, 40000, 161, []byte("a")))
	}
	pk = append(pk, usReq(usClient, []byte{172, 31, 0, 1}, 40000, 161, []byte("q")))
	u := usSummary(t, runGolden(t, pk))
	if u.GroupsTotal != 56 || u.GroupsShown != 50 || u.OmittedGroups != 6 {
		t.Fatalf("bounds = %d/%d/%d", u.GroupsTotal, u.GroupsShown, u.OmittedGroups)
	}
	if u.Groups[0].Server != "172.31.0.1" || u.Groups[0].ConversationsWithoutReply != 1 {
		t.Errorf("first group = %+v", u.Groups[0])
	}
	if u.Services[0].Conversations != 56 || u.Services[0].ConversationsWithoutReply != 1 {
		t.Errorf("totals must cover omitted groups: %+v", u.Services)
	}
}

func TestUDPServices_DeterministicAndDoesNotChangeOtherOutput(t *testing.T) {
	mk := func() [][]byte {
		var pk [][]byte
		for i := 0; i < 6; i++ {
			pk = append(pk, usReq(usClient, usServer, uint16(40000+i), []uint16{161, 1812, 389}[i%3], []byte(fmt.Sprint(i))))
		}
		return pk
	}
	var first string
	for i := 0; i < 4; i++ {
		b, _ := json.Marshal(runGolden(t, mk()).UDPServiceResponses)
		if i == 0 {
			first = string(b)
		} else if string(b) != first {
			t.Fatal("not deterministic")
		}
	}
	r := runGolden(t, mk())
	if len(r.DNSAnomalies) != 0 || r.ICMPErrorEvidence != nil || len(r.TCPRetransmissions) != 0 {
		t.Errorf("unrelated output changed")
	}
}
