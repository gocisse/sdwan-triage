package analyzer

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"testing"

	"github.com/gocisse/sdwan-triage/internal/testpcap"
	"github.com/gocisse/sdwan-triage/pkg/models"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// Phase 4.33 — ICMP error evidence: type/code kept exactly, the quoted original flow read
// when usable, frame numbers, next-hop MTU, grouping, ICMPv4 and ICMPv6, and neutral wording.

var (
	icReporter  = net.IPv4(172, 26, 88, 17)
	icClient    = net.IPv4(10, 160, 4, 40)
	icServer    = net.IPv4(172, 24, 88, 11)
	icClient6   = net.ParseIP("2001:db8::10")
	icServer6   = net.ParseIP("2001:db8:1::53")
	icReporter6 = net.ParseIP("2001:db8:ffff::1")
)

// quoteV4 builds the IPv4 header + first bytes of a UDP/TCP header an ICMPv4 error quotes.
func quoteV4(src, dst net.IP, proto layers.IPProtocol, sport, dport uint16, transportBytes int) []byte {
	ip := &layers.IPv4{Version: 4, IHL: 5, TTL: 64, Protocol: proto, SrcIP: src.To4(), DstIP: dst.To4(), Length: 60}
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: false}, ip, gopacket.Payload(make([]byte, 0))); err != nil {
		panic(err)
	}
	b := append([]byte(nil), buf.Bytes()...)
	tp := make([]byte, 8)
	binary.BigEndian.PutUint16(tp[0:2], sport)
	binary.BigEndian.PutUint16(tp[2:4], dport)
	if transportBytes > 8 {
		transportBytes = 8
	}
	return append(b, tp[:transportBytes]...)
}

func quoteV6(src, dst net.IP, nh layers.IPProtocol, sport, dport uint16, transportBytes int) []byte {
	b := make([]byte, 40)
	b[0] = 0x60
	b[6] = byte(nh)
	b[7] = 64
	copy(b[8:24], src.To16())
	copy(b[24:40], dst.To16())
	tp := make([]byte, 8)
	binary.BigEndian.PutUint16(tp[0:2], sport)
	binary.BigEndian.PutUint16(tp[2:4], dport)
	return append(b, tp[:transportBytes]...)
}

func errV4(reporter, recipient net.IP, typ, code uint8, mtu uint16, quote []byte) []byte {
	eth := &layers.Ethernet{SrcMAC: testpcap.ServerMAC, DstMAC: testpcap.ClientMAC, EthernetType: layers.EthernetTypeIPv4}
	ip := &layers.IPv4{Version: 4, IHL: 5, TTL: 64, Protocol: layers.IPProtocolICMPv4, SrcIP: reporter.To4(), DstIP: recipient.To4()}
	ic := &layers.ICMPv4{TypeCode: layers.CreateICMPv4TypeCode(typ, code), Seq: mtu}
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, eth, ip, ic, gopacket.Payload(quote)); err != nil {
		panic(err)
	}
	return buf.Bytes()
}

func errV6(reporter, recipient net.IP, typ, code uint8, mtu uint32, quote []byte) []byte {
	eth := &layers.Ethernet{SrcMAC: testpcap.ServerMAC, DstMAC: testpcap.ClientMAC, EthernetType: layers.EthernetTypeIPv6}
	ip := &layers.IPv6{Version: 6, HopLimit: 64, NextHeader: layers.IPProtocolICMPv6, SrcIP: reporter, DstIP: recipient}
	ic := &layers.ICMPv6{TypeCode: layers.CreateICMPv6TypeCode(typ, code)}
	_ = ic.SetNetworkLayerForChecksum(ip)
	body := make([]byte, 4)
	binary.BigEndian.PutUint32(body, mtu)
	body = append(body, quote...)
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, eth, ip, ic, gopacket.Payload(body)); err != nil {
		panic(err)
	}
	return buf.Bytes()
}

func icEvidence(t *testing.T, r *models.TriageReport) *models.ICMPErrorEvidence {
	t.Helper()
	if r.ICMPErrorEvidence == nil {
		t.Fatal("no icmp_error_evidence")
	}
	return r.ICMPErrorEvidence
}

var icBanned = []string{"caused", "because", "outage", "provider", "isp ", "faulty", "is down", "blocked by", "attack", "mitm", "failed to"}

func icNoClaims(t *testing.T, text string) {
	t.Helper()
	l := strings.ToLower(text)
	for _, b := range icBanned {
		if strings.Contains(l, b) {
			t.Errorf("text makes an unsupported claim (%q): %s", b, text)
		}
	}
}

func TestICMPErrors_AbsentWithoutErrors(t *testing.T) {
	r := runGolden(t, handshake(fePort))
	if r.ICMPErrorEvidence != nil {
		t.Errorf("evidence without ICMP errors: %+v", r.ICMPErrorEvidence)
	}
	b, _ := json.Marshal(r)
	if strings.Contains(string(b), "icmp_error_evidence") {
		t.Error("key serialized without errors")
	}
}

func TestICMPErrors_HostUnreachableQuotesTheDNSFlow(t *testing.T) {
	q := quoteV4(icClient, icServer, layers.IPProtocolUDP, 58995, 53, 8)
	pk := append(handshake(fePort), errV4(icReporter, icClient, 3, 1, 0, q)) // 4th packet → frame 4
	e := icEvidence(t, runGolden(t, pk))
	if e.TotalMessages != 1 || e.GroupsShown != 1 || e.MessagesWithUnusableQuote != 0 {
		t.Fatalf("evidence = %+v", e)
	}
	g := e.Errors[0]
	if g.Family != "ICMP" || g.Type != 3 || g.Code != 1 || g.Reporter != "172.26.88.17" || g.Recipient != "10.160.4.40" || g.Count != 1 {
		t.Errorf("group = %+v", g)
	}
	want := models.ICMPQuotedFlow{Status: "complete", Protocol: "UDP", Src: "10.160.4.40", SrcPort: 58995, Dst: "172.24.88.11", DstPort: 53}
	if g.Quoted != want {
		t.Errorf("quoted = %+v, want %+v", g.Quoted, want)
	}
	if g.FirstFrame != 4 || len(g.Frames) != 1 || g.Frames[0] != 4 {
		t.Errorf("frames = %d %v, want capture frame 4 (ordinal + 1)", g.FirstFrame, g.Frames)
	}
	if !strings.Contains(g.Meaning, "Host Unreachable") || g.QuotedSourceDiffers {
		t.Errorf("group = %+v", g)
	}
	icNoClaims(t, g.Meaning)
	icNoClaims(t, models.ICMPErrorEvidenceBasis)
}

// Messages about the same service from many client ports are one group; codes stay separate
// (the pre-existing icmp_analysis keeps only the first code per source and type).
func TestICMPErrors_GroupsByServiceAndKeepsCodesSeparate(t *testing.T) {
	var pk [][]byte
	for i := 0; i < 8; i++ {
		pk = append(pk, errV4(icReporter, icClient, 3, 1, 0, quoteV4(icClient, icServer, layers.IPProtocolUDP, uint16(40000+i), 53, 8)))
	}
	pk = append(pk, errV4(icReporter, icClient, 3, 3, 0, quoteV4(icClient, icServer, layers.IPProtocolUDP, 40100, 53, 8)))
	r := runGolden(t, pk)
	e := icEvidence(t, r)
	if e.GroupsTotal != 2 || e.TotalMessages != 9 {
		t.Fatalf("evidence = %+v", e)
	}
	var host, port *models.ICMPErrorGroup
	for i := range e.Errors {
		switch e.Errors[i].Code {
		case 1:
			host = &e.Errors[i]
		case 3:
			port = &e.Errors[i]
		}
	}
	if host == nil || port == nil || host.Count != 8 || host.DistinctSrcPorts != 8 || len(host.Frames) != icmpErrFramesBound || host.FirstFrame != 1 || port.Count != 1 {
		t.Fatalf("groups = %+v %+v", host, port)
	}
	// The existing aggregation is unchanged: one finding per (source, type), first code.
	if len(r.ICMPAnalysis) != 1 || r.ICMPAnalysis[0].Count != 9 || r.ICMPAnalysis[0].Code != 1 {
		t.Errorf("existing icmp_analysis changed: %+v", r.ICMPAnalysis)
	}
}

const icmpErrFramesBound = 5

func TestICMPErrors_NextHopMTU(t *testing.T) {
	q := quoteV4(icClient, icServer, layers.IPProtocolTCP, 50000, 443, 8)
	r := runGolden(t, [][]byte{
		errV4(icReporter, icClient, 3, 4, 1400, q), errV4(icReporter, icClient, 3, 4, 1360, q), errV4(icReporter, icClient, 3, 4, 1400, q),
	})
	g := icEvidence(t, r).Errors[0]
	if g.Code != 4 || g.Count != 3 || g.MinMTU != 1360 || g.MaxMTU != 1400 || !strings.Contains(g.Meaning, "Fragmentation Needed") {
		t.Errorf("group = %+v", g)
	}
	// A message that does not carry an MTU (other codes) reports none.
	r = runGolden(t, [][]byte{errV4(icReporter, icClient, 3, 3, 777, q)})
	if g := icEvidence(t, r).Errors[0]; g.MinMTU != 0 || g.MaxMTU != 0 {
		t.Errorf("MTU reported for a non-fragmentation code: %+v", g)
	}
}

func TestICMPErrors_ICMPv6PacketTooBigAndTimeExceeded(t *testing.T) {
	q := quoteV6(icClient6, icServer6, layers.IPProtocolTCP, 51000, 443, 8)
	r := runGolden(t, [][]byte{
		errV6(icReporter6, icClient6, 2, 0, 1280, q),
		errV6(icReporter6, icClient6, 3, 0, 0, q),
		errV6(icReporter6, icClient6, 1, 4, 0, quoteV6(icClient6, icServer6, layers.IPProtocolUDP, 5353, 53, 8)),
	})
	e := icEvidence(t, r)
	if e.TotalMessages != 3 || e.GroupsTotal != 3 {
		t.Fatalf("evidence = %+v", e)
	}
	by := map[uint8]models.ICMPErrorGroup{}
	for _, g := range e.Errors {
		if g.Family != "ICMPv6" {
			t.Errorf("family = %s", g.Family)
		}
		by[g.Type] = g
	}
	ptb := by[2]
	if ptb.MinMTU != 1280 || ptb.MaxMTU != 1280 || ptb.Quoted.Protocol != "TCP" || ptb.Quoted.Src != "2001:db8::10" || ptb.Quoted.DstPort != 443 || ptb.Quoted.Status != "complete" {
		t.Errorf("packet too big = %+v", ptb)
	}
	if !strings.Contains(by[3].Meaning, "hop limit") || by[3].MinMTU != 0 {
		t.Errorf("time exceeded = %+v", by[3])
	}
	if !strings.Contains(by[1].Meaning, "port unreachable") || by[1].Quoted.Protocol != "UDP" {
		t.Errorf("destination unreachable = %+v", by[1])
	}
}

// Missing or truncated quotes are incomplete evidence: the flow is unknown, never "not affected".
func TestICMPErrors_IncompleteQuotesAreReportedHonestly(t *testing.T) {
	full := quoteV4(icClient, icServer, layers.IPProtocolUDP, 40000, 53, 8)
	r := runGolden(t, [][]byte{
		errV4(icReporter, icClient, 3, 1, 0, nil),                                                                 // no quote at all
		errV4(icReporter, icClient, 3, 1, 0, full[:12]),                                                           // cut inside the IP header
		errV4(icReporter, icClient, 3, 3, 0, full[:20]),                                                           // IP header only
		errV4(icReporter, icClient, 3, 2, 0, full[:22]),                                                           // 2 transport bytes: no ports
		append(errV4(icReporter, icClient, 3, 0, 0, nil), []byte{}...),                                            // empty again
		errV4(icReporter, icClient, 3, 9, 0, append([]byte{0x65}, full[1:]...)),                                   // wrong IP version
		errV6(icReporter6, icClient6, 1, 3, 0, quoteV6(icClient6, icServer6, layers.IPProtocolUDP, 1, 2, 8)[:30]), // v6 cut
	})
	e := icEvidence(t, r)
	if e.TotalMessages != 7 {
		t.Fatalf("total = %d", e.TotalMessages)
	}
	status := map[string]int{}
	for _, g := range e.Errors {
		status[g.Quoted.Status] += g.Count
		if g.Quoted.Status != "complete" && (g.Quoted.SrcPort != 0 || g.Quoted.DstPort != 0) {
			t.Errorf("ports invented for status %s: %+v", g.Quoted.Status, g)
		}
	}
	if status["unusable"] != 5 || status["no_ports"] != 2 || status["complete"] != 0 || e.MessagesWithUnusableQuote != 5 {
		t.Errorf("statuses = %v, unusable = %d", status, e.MessagesWithUnusableQuote)
	}
	for _, g := range e.Errors {
		if g.Quoted.Status == "unusable" && (g.Quoted.Src != "" || g.Quoted.Protocol != "") {
			t.Errorf("flow invented from an unusable quote: %+v", g.Quoted)
		}
	}
}

func TestICMPErrors_NonFirstFragmentAndExtensionHeaderHaveNoPorts(t *testing.T) {
	frag := quoteV4(icClient, icServer, layers.IPProtocolUDP, 40000, 53, 8)
	binary.BigEndian.PutUint16(frag[6:8], 0x00b9) // fragment offset != 0
	ext := quoteV6(icClient6, icServer6, layers.IPProtocol(44), 0, 0, 8)
	r := runGolden(t, [][]byte{errV4(icReporter, icClient, 3, 1, 0, frag), errV6(icReporter6, icClient6, 1, 0, 0, ext)})
	for _, g := range icEvidence(t, r).Errors {
		if g.Quoted.Status != "no_ports" {
			t.Errorf("status = %s for %+v", g.Quoted.Status, g.Quoted)
		}
	}
}

func TestICMPErrors_QuotedSourceDifferingFromRecipientIsFlagged(t *testing.T) {
	q := quoteV4(net.IPv4(62, 74, 228, 18), net.IPv4(10, 164, 112, 18), layers.IPProtocolUDP, 5057, 33364, 8)
	g := icEvidence(t, runGolden(t, [][]byte{errV4(icReporter, net.IPv4(4, 2, 2, 1), 3, 3, 0, q)})).Errors[0]
	if !g.QuotedSourceDiffers {
		t.Errorf("group = %+v", g)
	}
	// Matching recipient: not flagged.
	g = icEvidence(t, runGolden(t, [][]byte{errV4(icReporter, icClient, 3, 3, 0, quoteV4(icClient, icServer, layers.IPProtocolUDP, 1, 53, 8))})).Errors[0]
	if g.QuotedSourceDiffers {
		t.Errorf("flagged although the quote matches the recipient: %+v", g)
	}
}

func TestICMPErrors_OnlyErrorMessagesAreIncluded(t *testing.T) {
	echo := func() []byte {
		eth := &layers.Ethernet{SrcMAC: testpcap.ClientMAC, DstMAC: testpcap.ServerMAC, EthernetType: layers.EthernetTypeIPv4}
		ip := &layers.IPv4{Version: 4, IHL: 5, TTL: 64, Protocol: layers.IPProtocolICMPv4, SrcIP: icClient.To4(), DstIP: icServer.To4()}
		ic := &layers.ICMPv4{TypeCode: layers.CreateICMPv4TypeCode(8, 0), Id: 1, Seq: 1}
		buf := gopacket.NewSerializeBuffer()
		_ = gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, eth, ip, ic, gopacket.Payload([]byte("ping")))
		return buf.Bytes()
	}()
	redirect := errV4(icReporter, icClient, 5, 1, 0, quoteV4(icClient, icServer, layers.IPProtocolUDP, 1, 53, 8))
	r := runGolden(t, [][]byte{echo, redirect})
	if r.ICMPErrorEvidence != nil {
		t.Errorf("echo/redirect produced error evidence: %+v", r.ICMPErrorEvidence)
	}
	if len(r.ICMPAnalysis) == 0 {
		t.Error("existing ICMP analysis lost")
	}
}

func TestICMPErrors_ListIsBoundedAndCounted(t *testing.T) {
	var pk [][]byte
	for i := 0; i < 60; i++ {
		dst := net.IPv4(172, 24, byte(i/250), byte(i%250+1))
		pk = append(pk, errV4(icReporter, icClient, 3, 1, 0, quoteV4(icClient, dst, layers.IPProtocolUDP, 40000, 53, 8)))
	}
	e := icEvidence(t, runGolden(t, pk))
	if e.GroupsTotal != 60 || e.GroupsShown != 50 || e.OmittedGroups != 10 || e.OmittedMessages != 10 || e.TotalMessages != 60 || len(e.Errors) != 50 {
		t.Errorf("bounds = total %d shown %d omitted %d/%d messages %d", e.GroupsTotal, e.GroupsShown, e.OmittedGroups, e.OmittedMessages, e.TotalMessages)
	}
}

func TestICMPErrors_DeterministicJSON(t *testing.T) {
	mk := func() string {
		var pk [][]byte
		for i := 0; i < 5; i++ {
			pk = append(pk, errV4(icReporter, icClient, 3, uint8(i%3), 0, quoteV4(icClient, icServer, layers.IPProtocolUDP, uint16(1000+i), uint16(50+i%2), 8)))
		}
		pk = append(pk, errV6(icReporter6, icClient6, 2, 0, 1280, quoteV6(icClient6, icServer6, layers.IPProtocolTCP, 1, 443, 8)))
		b, _ := json.Marshal(runGolden(t, pk).ICMPErrorEvidence)
		return string(b)
	}
	first := mk()
	for i := 0; i < 3; i++ {
		if got := mk(); got != first {
			t.Fatalf("run %d differs", i)
		}
	}
}

func TestICMPErrors_DoesNotChangeOtherOutput(t *testing.T) {
	q := quoteV4(icClient, icServer, layers.IPProtocolUDP, 40000, 53, 8)
	base := handshake(fePort)
	r0 := runGolden(t, base)
	r1 := runGolden(t, append(append([][]byte(nil), base...), errV4(icReporter, icClient, 3, 1, 0, q)))
	j := func(r *models.TriageReport) string {
		return fmt.Sprint(len(r.TCPHandshakes.SuccessfulHandshakes), len(r.TCPRetransmissions), len(r.DNSAnomalies), r.RiskScore, len(r.Events.ByKind("tcp.retransmission")))
	}
	if j(r0) != j(r1) {
		t.Errorf("unrelated output changed: %s vs %s", j(r0), j(r1))
	}
}
