package detector

import (
	"fmt"
	"sort"
	"time"

	"github.com/gocisse/sdwan-triage/pkg/models"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// Phase 4.36 — UDP request/response visibility for a few well-known services (see
// models.UDPServiceResponses). Direction is decided by ports only: a datagram to the
// service port from another port is a request; a datagram from the service port to
// another port is a reply. Datagrams with the service port on both sides (peer
// protocols such as NTP symmetric mode) are ignored, as are NTP datagrams that are not
// client (3) or server (4) mode. Replies are not matched to individual requests.
const (
	udpSvcMaxConversations = 20000
	udpSvcMaxGroups        = 50
	udpSvcNearEndSec       = 2.0
	udpSvcOrder            = "groups with conversations that had no reply first, then more requests, then earlier first request, then addresses; display order only"
	udpSvcTimeFmt          = "2006-01-02T15:04:05.000Z"
)

var udpServices = map[uint16]string{
	161: "SNMP", 123: "NTP", 1812: "RADIUS", 1645: "RADIUS", 1813: "RADIUS accounting", 1646: "RADIUS accounting",
	88: "Kerberos", 389: "LDAP",
}

type udpSvcConv struct {
	svc, client, server string
	serverPort          uint16
	reqs, reps          int
	firstFrame          uint64
	firstReq, lastReq   time.Time
}

// UDPServiceAnalyzer tracks conversations of the covered services.
type UDPServiceAnalyzer struct {
	convs      map[string]*udpSvcConv
	order      []string
	untracked  int
	lastPacket time.Time
	maxConvs   int
}

// NewUDPServiceAnalyzer creates the analyzer.
func NewUDPServiceAnalyzer() *UDPServiceAnalyzer {
	return &UDPServiceAnalyzer{convs: make(map[string]*udpSvcConv), maxConvs: udpSvcMaxConversations}
}

// Analyze reads one packet.
func (u *UDPServiceAnalyzer) Analyze(packet gopacket.Packet, state *models.AnalysisState, report *models.TriageReport) {
	sp, dp, payload, ok := udpPorts(packet)
	if !ok {
		return
	}
	ts := packet.Metadata().Timestamp
	if ts.After(u.lastPacket) {
		u.lastPacket = ts
	}
	_, srcSvc := udpServices[sp]
	svcName, dstSvc := udpServices[dp]
	if srcSvc == dstSvc { // neither, or the service port on both sides
		return
	}
	request := dstSvc
	if !request {
		svcName = udpServices[sp]
	}
	if svcName == "NTP" && len(payload) > 0 {
		mode := payload[0] & 7
		if (request && mode != 3) || (!request && mode != 4) {
			return
		}
	}
	ip := ExtractIPInfo(packet)
	if ip == nil {
		return
	}
	var client, server string
	var serverPort, clientPort uint16
	if request {
		client, server, serverPort, clientPort = ip.SrcIP, ip.DstIP, dp, sp
	} else {
		client, server, serverPort, clientPort = ip.DstIP, ip.SrcIP, sp, dp
	}
	key := fmt.Sprintf("%s|%s|%s|%d|%d", svcName, client, server, serverPort, clientPort)
	c := u.convs[key]
	if c == nil {
		if len(u.convs) >= u.maxConvs {
			u.untracked++
			return
		}
		c = &udpSvcConv{svc: svcName, client: client, server: server, serverPort: serverPort}
		u.convs[key] = c
		u.order = append(u.order, key)
	}
	if !request {
		c.reps++
		return
	}
	c.reqs++
	if c.reqs == 1 {
		c.firstReq = ts
		if f, ok := currentFrame(report, ts); ok {
			c.firstFrame = f
		}
	}
	c.lastReq = ts
}

// udpPorts returns the UDP ports and payload of a datagram. A datagram that was IP-fragmented
// (large SNMP replies, for example) has no UDP layer in the decoder: its UDP header sits at
// the start of the FIRST fragment, which is read here. Later fragments carry no ports and
// cannot be attributed, so only the first fragment of a datagram is counted.
func udpPorts(packet gopacket.Packet) (sp, dp uint16, payload []byte, ok bool) {
	if l := packet.Layer(layers.LayerTypeUDP); l != nil {
		if udp, isUDP := l.(*layers.UDP); isUDP {
			return uint16(udp.SrcPort), uint16(udp.DstPort), udp.Payload, true
		}
		return 0, 0, nil, false
	}
	var raw []byte
	if l := packet.Layer(layers.LayerTypeIPv4); l != nil {
		ip, isIP := l.(*layers.IPv4)
		if !isIP || ip.Protocol != layers.IPProtocolUDP || ip.FragOffset != 0 || ip.Flags&layers.IPv4MoreFragments == 0 {
			return 0, 0, nil, false
		}
		raw = ip.Payload
	} else if l := packet.Layer(layers.LayerTypeIPv6Fragment); l != nil {
		fr, isFr := l.(*layers.IPv6Fragment)
		if !isFr || fr.NextHeader != layers.IPProtocolUDP || fr.FragmentOffset != 0 || !fr.MoreFragments {
			return 0, 0, nil, false
		}
		raw = fr.Payload
	} else {
		return 0, 0, nil, false
	}
	if len(raw) < 8 {
		return 0, 0, nil, false
	}
	return uint16(raw[0])<<8 | uint16(raw[1]), uint16(raw[2])<<8 | uint16(raw[3]), raw[8:], true
}

func udpSvcVisibility(withoutReply, convs int) string {
	if withoutReply == 0 {
		return ""
	}
	if withoutReply == convs {
		return "No reply was observed in any of these conversations. The capture may not contain the return direction, or the replies may have been filtered, lost or never sent; " +
			"this does not by itself show that the server failed."
	}
	return fmt.Sprintf("No reply was observed in %d of %d conversations. That can reflect replies this capture point did not see; it does not by itself show that packets were lost or where.", withoutReply, convs)
}

// Finalize publishes the summary (nil when no covered request was observed).
func (u *UDPServiceAnalyzer) Finalize(endOfCapture time.Time, report *models.TriageReport) {
	if len(u.convs) == 0 {
		return
	}
	end := endOfCapture
	if end.IsZero() {
		end = u.lastPacket
	}
	type gkey struct {
		svc, client, server string
		port                uint16
	}
	type gacc struct {
		g          models.UDPServiceGroup
		first      time.Time
		firstFrame uint64
	}
	groups := map[gkey]*gacc{}
	totals := map[string]*models.UDPServiceTotals{}
	for _, key := range u.order {
		c := u.convs[key]
		if c.reqs == 0 { // replies without an observed request: not a request/response account
			continue
		}
		k := gkey{c.svc, c.client, c.server, c.serverPort}
		a := groups[k]
		if a == nil {
			a = &gacc{g: models.UDPServiceGroup{Service: c.svc, Client: c.client, Server: c.server, ServerPort: c.serverPort}, first: c.firstReq, firstFrame: c.firstFrame}
			groups[k] = a
		}
		t := totals[c.svc]
		if t == nil {
			t = &models.UDPServiceTotals{Service: c.svc}
			totals[c.svc] = t
		}
		t.Conversations++
		g := &a.g
		g.Conversations++
		g.Requests += c.reqs
		g.Replies += c.reps
		if c.firstReq.Before(a.first) || a.first.IsZero() {
			a.first, a.firstFrame = c.firstReq, c.firstFrame
		}
		if g.LastRequestTime == "" || c.lastReq.UTC().Format(udpSvcTimeFmt) > g.LastRequestTime {
			g.LastRequestTime = c.lastReq.UTC().Format(udpSvcTimeFmt)
		}
		if c.reps == 0 {
			g.ConversationsWithoutReply++
			t.ConversationsWithoutReply++
			if g.FirstUnansweredFrame == 0 {
				g.FirstUnansweredFrame = c.firstFrame
			}
			if !end.IsZero() && end.Sub(c.lastReq).Seconds() < udpSvcNearEndSec {
				g.WithoutReplyNearCaptureEnd++
			}
		}
	}
	if len(groups) == 0 {
		return
	}
	list := make([]*gacc, 0, len(groups))
	for _, a := range groups {
		a.g.FirstRequestFrame = a.firstFrame
		a.g.FirstRequestTime = a.first.UTC().Format(udpSvcTimeFmt)
		a.g.Visibility = udpSvcVisibility(a.g.ConversationsWithoutReply, a.g.Conversations)
		list = append(list, a)
	}
	sort.Slice(list, func(i, j int) bool {
		x, y := list[i], list[j]
		if (x.g.ConversationsWithoutReply > 0) != (y.g.ConversationsWithoutReply > 0) {
			return x.g.ConversationsWithoutReply > 0
		}
		if x.g.Requests != y.g.Requests {
			return x.g.Requests > y.g.Requests
		}
		if !x.first.Equal(y.first) {
			return x.first.Before(y.first)
		}
		kx := x.g.Service + "|" + x.g.Client + "|" + x.g.Server
		ky := y.g.Service + "|" + y.g.Client + "|" + y.g.Server
		return kx < ky
	})
	out := &models.UDPServiceResponses{
		Basis: models.UDPServiceResponsesBasis, ConversationsTracked: len(u.convs), DatagramsUntracked: u.untracked,
		GroupsTotal: len(list), MaxGroups: udpSvcMaxGroups, Order: udpSvcOrder, Groups: []models.UDPServiceGroup{}, Services: []models.UDPServiceTotals{},
	}
	names := make([]string, 0, len(totals))
	for n := range totals {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		out.Services = append(out.Services, *totals[n])
	}
	for i, a := range list {
		if i >= udpSvcMaxGroups {
			out.OmittedGroups++
			continue
		}
		out.Groups = append(out.Groups, a.g)
	}
	out.GroupsShown = len(out.Groups)
	report.UDPServiceResponses = out
}
