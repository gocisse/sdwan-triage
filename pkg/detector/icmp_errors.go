package detector

import (
	"encoding/binary"
	"fmt"
	"net"
	"sort"
	"time"

	"github.com/gocisse/sdwan-triage/pkg/models"
)

// Phase 4.33 — ICMP error evidence. The existing ICMPAnalyzer aggregates findings by
// (source, type) and keeps one code and no flow; this view keeps every message's exact
// type/code, reads the quoted original packet (when usable) to name the affected flow,
// records frame numbers and the next-hop MTU, and groups identical messages. It changes
// no existing finding, event or metric.
//
// Quote rules: ICMPv4 errors quote the original IP header plus at least 8 bytes of its
// payload; ICMPv6 errors quote as much of the original packet as fits. A quote that is
// absent, shorter than the IP header, or of the wrong IP version is "unusable"; a quote
// without the transport header is "no_ports". IPv6 extension headers are not walked: a
// quoted IPv6 packet whose next header is not TCP/UDP is reported with its protocol
// number and without ports.
const (
	// icmpErrMaxTrackedGroups bounds accumulator memory; messages of further groups are
	// counted as omitted, not tracked.
	icmpErrMaxTrackedGroups = 5000
	// icmpErrMaxGroups bounds the listed (JSON) groups.
	icmpErrMaxGroups = 50
	// icmpErrMaxFrames bounds the frames kept per group.
	icmpErrMaxFrames = 5

	icmpErrOrder = "groups with more messages first, then earlier first message, then type, code, reporter and quoted flow; display order only"
	icmpTimeFmt  = "2006-01-02T15:04:05.000Z"
)

type icmpErrKey struct {
	family       string
	typ, code    uint8
	reporter     string
	status       string
	proto        string
	src, dst     string
	dstP         uint16
	srcDiffers   bool
	recipientKey string
}

// icmpErrMaxSrcPorts bounds the distinct quoted source ports remembered per group.
const icmpErrMaxSrcPorts = 256

type icmpErrAcc struct {
	g          models.ICMPErrorGroup
	first, end time.Time
	srcPorts   map[uint16]struct{}
}

type icmpErrorTracker struct {
	groups          map[icmpErrKey]*icmpErrAcc
	total           int
	unusable        int
	untrackedGroups int
	untrackedMsgs   int
	maxTracked      int
}

func newICMPErrorTracker() *icmpErrorTracker {
	return &icmpErrorTracker{groups: make(map[icmpErrKey]*icmpErrAcc), maxTracked: icmpErrMaxTrackedGroups}
}

func icmpProtoName(p uint8) string {
	switch p {
	case 1:
		return "ICMP"
	case 6:
		return "TCP"
	case 17:
		return "UDP"
	case 58:
		return "ICMPv6"
	}
	return fmt.Sprintf("protocol %d", p)
}

// parseQuotedIPv4 reads the original packet quoted in an ICMPv4 error.
func parseQuotedIPv4(b []byte) models.ICMPQuotedFlow {
	if len(b) < 20 || b[0]>>4 != 4 {
		return models.ICMPQuotedFlow{Status: "unusable"}
	}
	ihl := int(b[0]&0x0f) * 4
	if ihl < 20 || len(b) < ihl {
		return models.ICMPQuotedFlow{Status: "unusable"}
	}
	q := models.ICMPQuotedFlow{
		Status: "no_ports", Protocol: icmpProtoName(b[9]),
		Src: net.IP(b[12:16]).String(), Dst: net.IP(b[16:20]).String(),
	}
	firstFragment := (binary.BigEndian.Uint16(b[6:8]) & 0x1fff) == 0
	if (b[9] == 6 || b[9] == 17) && firstFragment && len(b) >= ihl+4 {
		q.SrcPort = binary.BigEndian.Uint16(b[ihl : ihl+2])
		q.DstPort = binary.BigEndian.Uint16(b[ihl+2 : ihl+4])
		q.Status = "complete"
	}
	return q
}

// parseQuotedIPv6 reads the original packet quoted in an ICMPv6 error (no extension-header walk).
func parseQuotedIPv6(b []byte) models.ICMPQuotedFlow {
	if len(b) < 40 || b[0]>>4 != 6 {
		return models.ICMPQuotedFlow{Status: "unusable"}
	}
	q := models.ICMPQuotedFlow{
		Status: "no_ports", Protocol: icmpProtoName(b[6]),
		Src: net.IP(b[8:24]).String(), Dst: net.IP(b[24:40]).String(),
	}
	if (b[6] == 6 || b[6] == 17) && len(b) >= 44 {
		q.SrcPort = binary.BigEndian.Uint16(b[40:42])
		q.DstPort = binary.BigEndian.Uint16(b[42:44])
		q.Status = "complete"
	}
	return q
}

func sameAddr(a, b string) bool {
	x, y := net.ParseIP(a), net.ParseIP(b)
	if x == nil || y == nil {
		return a == b
	}
	return x.Equal(y)
}

// icmpErrorMeaning is a neutral description of an error type/code (no cause is stated).
func (i *ICMPAnalyzer) icmpErrorMeaning(v6 bool, typ, code uint8, mtu uint32) string {
	if !v6 {
		switch typ {
		case 3:
			return "Destination Unreachable: " + i.getUnreachableDescription(code)
		case 11:
			if code == 1 {
				return "Time Exceeded: fragment reassembly time exceeded"
			}
			return "Time Exceeded: TTL reached zero in transit"
		case 12:
			return "Parameter Problem"
		}
		return icmpv4TypeNames[typ]
	}
	switch typ {
	case 1:
		reasons := map[uint8]string{0: "no route to destination", 1: "communication administratively prohibited", 2: "beyond scope of source address",
			3: "address unreachable", 4: "port unreachable", 5: "source address failed ingress/egress policy", 6: "reject route to destination"}
		if r, ok := reasons[code]; ok {
			return "Destination Unreachable: " + r
		}
		return fmt.Sprintf("Destination Unreachable (code %d)", code)
	case 2:
		return "Packet Too Big"
	case 3:
		if code == 1 {
			return "Time Exceeded: fragment reassembly time exceeded"
		}
		return "Time Exceeded: hop limit reached zero in transit"
	case 4:
		return "Parameter Problem"
	}
	return icmpv6TypeNames[typ]
}

// observeErrorMessage records one ICMP error message. quote is the byte slice that holds
// the quoted original packet (may be empty); mtu is 0 when the message carries none.
func (i *ICMPAnalyzer) observeErrorMessage(v6 bool, typ, code uint8, reporter, recipient string, quote []byte, mtu uint32, ts time.Time, report *models.TriageReport) {
	t := i.errors
	t.total++
	var q models.ICMPQuotedFlow
	if v6 {
		q = parseQuotedIPv6(quote)
	} else {
		q = parseQuotedIPv4(quote)
	}
	if q.Status == "unusable" {
		t.unusable++
	}
	family := "ICMP"
	if v6 {
		family = "ICMPv6"
	}
	differs := q.Status != "unusable" && !sameAddr(q.Src, recipient)
	key := icmpErrKey{family: family, typ: typ, code: code, reporter: reporter, status: q.Status, proto: q.Protocol,
		src: q.Src, dst: q.Dst, dstP: q.DstPort, srcDiffers: differs, recipientKey: recipient}
	a := t.groups[key]
	if a == nil {
		if len(t.groups) >= t.maxTracked {
			t.untrackedGroups++
			t.untrackedMsgs++
			return
		}
		name := icmpv4TypeNames[typ]
		if v6 {
			name = icmpv6TypeNames[typ]
		}
		a = &icmpErrAcc{g: models.ICMPErrorGroup{
			Family: family, Type: typ, Code: code, TypeName: name, Meaning: i.icmpErrorMeaning(v6, typ, code, mtu),
			Reporter: reporter, Recipient: recipient, Quoted: q, QuotedSourceDiffers: differs,
		}, first: ts, srcPorts: make(map[uint16]struct{})}
		t.groups[key] = a
	}
	a.g.Count++
	if q.Status == "complete" {
		if _, seen := a.srcPorts[q.SrcPort]; !seen {
			if len(a.srcPorts) < icmpErrMaxSrcPorts {
				a.srcPorts[q.SrcPort] = struct{}{}
			} else {
				a.g.SrcPortsCapped = true
			}
		}
		a.g.DistinctSrcPorts = len(a.srcPorts)
	}
	a.end = ts
	if frame, ok := currentFrame(report, ts); ok {
		if a.g.FirstFrame == 0 {
			a.g.FirstFrame = frame
		}
		if len(a.g.Frames) < icmpErrMaxFrames {
			a.g.Frames = append(a.g.Frames, frame)
		}
	}
	if mtu > 0 {
		if a.g.MinMTU == 0 || mtu < a.g.MinMTU {
			a.g.MinMTU = mtu
		}
		if mtu > a.g.MaxMTU {
			a.g.MaxMTU = mtu
		}
	}
}

// currentFrame returns the 1-based capture frame number of the packet being analysed
// (the recorder's 0-based ordinal plus one), when the emitter provides it.
func currentFrame(report *models.TriageReport, ts time.Time) (uint64, bool) {
	cp, ok := report.Emitter.(interface {
		CurrentPacket() (uint64, time.Time, bool)
	})
	if !ok {
		return 0, false
	}
	idx, pts, have := cp.CurrentPacket()
	if !have || !pts.Equal(ts) {
		return 0, false
	}
	return idx + 1, true
}

// Finalize publishes the ICMP error evidence (nil when no error message was observed).
func (i *ICMPAnalyzer) Finalize(report *models.TriageReport) {
	t := i.errors
	if t == nil || t.total == 0 {
		return
	}
	list := make([]*icmpErrAcc, 0, len(t.groups))
	for _, a := range t.groups {
		a.g.FirstTime = a.first.UTC().Format(icmpTimeFmt)
		a.g.LastTime = a.end.UTC().Format(icmpTimeFmt)
		list = append(list, a)
	}
	sort.Slice(list, func(x, y int) bool {
		a, b := list[x], list[y]
		if a.g.Count != b.g.Count {
			return a.g.Count > b.g.Count
		}
		if !a.first.Equal(b.first) {
			return a.first.Before(b.first)
		}
		ka := fmt.Sprintf("%s|%03d|%03d|%s|%s|%s|%s|%d", a.g.Family, a.g.Type, a.g.Code, a.g.Reporter, a.g.Quoted.Src, a.g.Quoted.Protocol, a.g.Quoted.Dst, a.g.Quoted.DstPort)
		kb := fmt.Sprintf("%s|%03d|%03d|%s|%s|%s|%s|%d", b.g.Family, b.g.Type, b.g.Code, b.g.Reporter, b.g.Quoted.Src, b.g.Quoted.Protocol, b.g.Quoted.Dst, b.g.Quoted.DstPort)
		return ka < kb
	})
	ev := &models.ICMPErrorEvidence{
		Basis: models.ICMPErrorEvidenceBasis, TotalMessages: t.total, GroupsTotal: len(list) + t.untrackedGroups,
		MaxGroups: icmpErrMaxGroups, MessagesWithUnusableQuote: t.unusable, Order: icmpErrOrder,
		OmittedMessages: t.untrackedMsgs, Errors: []models.ICMPErrorGroup{},
	}
	ev.OmittedGroups = t.untrackedGroups
	for idx, a := range list {
		if idx >= icmpErrMaxGroups {
			ev.OmittedGroups++
			ev.OmittedMessages += a.g.Count
			continue
		}
		ev.Errors = append(ev.Errors, a.g)
	}
	ev.GroupsShown = len(ev.Errors)
	report.ICMPErrorEvidence = ev
}
