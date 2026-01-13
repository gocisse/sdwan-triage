package detector

import (
	"encoding/binary"
	"fmt"
	"net"

	"github.com/gocisse/sdwan-triage/pkg/models"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// ICMPv6Analyzer handles ICMPv6 protocol analysis including neighbor discovery
type ICMPv6Analyzer struct {
	neighborCache map[string]*NeighborEntry
	routerCache   map[string]*RouterEntry
}

// NeighborEntry represents a neighbor discovery cache entry
type NeighborEntry struct {
	IPAddress  net.IP
	MACAddress net.HardwareAddr
	IsRouter   bool
	LastSeen   float64
}

// RouterEntry represents a router advertisement cache entry
type RouterEntry struct {
	IPAddress  net.IP
	MACAddress net.HardwareAddr
	Lifetime   uint16
	Prefixes   []net.IPNet
	MTU        uint32
	LastSeen   float64
}

// NewICMPv6Analyzer creates a new ICMPv6 analyzer
func NewICMPv6Analyzer() *ICMPv6Analyzer {
	return &ICMPv6Analyzer{
		neighborCache: make(map[string]*NeighborEntry),
		routerCache:   make(map[string]*RouterEntry),
	}
}

// Analyze processes ICMPv6 packets
func (i *ICMPv6Analyzer) Analyze(packet gopacket.Packet, state *models.AnalysisState, report *models.TriageReport) {
	icmpv6Layer := packet.Layer(layers.LayerTypeICMPv6)
	if icmpv6Layer == nil {
		return
	}

	icmpv6, ok := icmpv6Layer.(*layers.ICMPv6)
	if !ok {
		return
	}

	// Get IPv6 info
	ipv6Info := ParseIPv6Packet(packet)
	if ipv6Info == nil {
		return
	}

	timestamp := float64(packet.Metadata().Timestamp.UnixNano()) / 1e9

	// Process based on ICMPv6 type
	switch icmpv6.TypeCode.Type() {
	case layers.ICMPv6TypeRouterSolicitation:
		i.handleRouterSolicitation(packet, ipv6Info, timestamp, report)
	case layers.ICMPv6TypeRouterAdvertisement:
		i.handleRouterAdvertisement(packet, ipv6Info, icmpv6, timestamp, report)
	case layers.ICMPv6TypeNeighborSolicitation:
		i.handleNeighborSolicitation(packet, ipv6Info, icmpv6, timestamp, report)
	case layers.ICMPv6TypeNeighborAdvertisement:
		i.handleNeighborAdvertisement(packet, ipv6Info, icmpv6, timestamp, report)
	case layers.ICMPv6TypeRedirect:
		i.handleRedirect(packet, ipv6Info, timestamp, report)
	case layers.ICMPv6TypeEchoRequest, layers.ICMPv6TypeEchoReply:
		i.handleEcho(packet, ipv6Info, icmpv6, timestamp, report)
	case layers.ICMPv6TypeDestinationUnreachable:
		i.handleDestinationUnreachable(packet, ipv6Info, icmpv6, timestamp, report)
	case layers.ICMPv6TypePacketTooBig:
		i.handlePacketTooBig(packet, ipv6Info, icmpv6, timestamp, report)
	case layers.ICMPv6TypeTimeExceeded:
		i.handleTimeExceeded(packet, ipv6Info, icmpv6, timestamp, report)
	}
}

// handleRouterSolicitation processes Router Solicitation messages
func (i *ICMPv6Analyzer) handleRouterSolicitation(packet gopacket.Packet, ipv6Info *IPv6PacketInfo, timestamp float64, report *models.TriageReport) {
	// Router solicitation is sent by hosts to discover routers
	event := models.TimelineEvent{
		Timestamp:     timestamp,
		EventType:     "ICMPv6_Router_Solicitation",
		SourceIP:      NormalizeIPv6Address(ipv6Info.SrcIP),
		DestinationIP: NormalizeIPv6Address(ipv6Info.DstIP),
		Protocol:      "ICMPv6",
		Detail:        "Host requesting router advertisement",
	}
	report.Timeline = append(report.Timeline, event)
}

// handleRouterAdvertisement processes Router Advertisement messages
func (i *ICMPv6Analyzer) handleRouterAdvertisement(packet gopacket.Packet, ipv6Info *IPv6PacketInfo, icmpv6 *layers.ICMPv6, timestamp float64, report *models.TriageReport) {
	// Extract router information
	if len(icmpv6.Payload) < 12 {
		return
	}

	hopLimit := icmpv6.Payload[0]
	flags := icmpv6.Payload[1]
	lifetime := binary.BigEndian.Uint16(icmpv6.Payload[2:4])
	reachableTime := binary.BigEndian.Uint32(icmpv6.Payload[4:8])
	retransTimer := binary.BigEndian.Uint32(icmpv6.Payload[8:12])

	managedFlag := (flags & 0x80) != 0
	otherFlag := (flags & 0x40) != 0

	// Get MAC address from Ethernet layer
	var macAddr net.HardwareAddr
	if ethLayer := packet.Layer(layers.LayerTypeEthernet); ethLayer != nil {
		if eth, ok := ethLayer.(*layers.Ethernet); ok {
			macAddr = eth.SrcMAC
		}
	}

	// Cache router entry
	routerKey := NormalizeIPv6Address(ipv6Info.SrcIP)
	i.routerCache[routerKey] = &RouterEntry{
		IPAddress:  ipv6Info.SrcIP,
		MACAddress: macAddr,
		Lifetime:   lifetime,
		LastSeen:   timestamp,
	}

	detail := fmt.Sprintf("Router advertisement: Lifetime=%ds, HopLimit=%d, Managed=%v, Other=%v, Reachable=%dms, Retrans=%dms",
		lifetime, hopLimit, managedFlag, otherFlag, reachableTime, retransTimer)

	event := models.TimelineEvent{
		Timestamp:     timestamp,
		EventType:     "ICMPv6_Router_Advertisement",
		SourceIP:      routerKey,
		DestinationIP: NormalizeIPv6Address(ipv6Info.DstIP),
		Protocol:      "ICMPv6",
		Detail:        detail,
	}
	report.Timeline = append(report.Timeline, event)
}

// handleNeighborSolicitation processes Neighbor Solicitation messages
func (i *ICMPv6Analyzer) handleNeighborSolicitation(packet gopacket.Packet, ipv6Info *IPv6PacketInfo, icmpv6 *layers.ICMPv6, timestamp float64, report *models.TriageReport) {
	if len(icmpv6.Payload) < 20 {
		return
	}

	// Target address is at offset 4-19
	targetAddr := net.IP(icmpv6.Payload[4:20])

	event := models.TimelineEvent{
		Timestamp:     timestamp,
		EventType:     "ICMPv6_Neighbor_Solicitation",
		SourceIP:      NormalizeIPv6Address(ipv6Info.SrcIP),
		DestinationIP: NormalizeIPv6Address(ipv6Info.DstIP),
		Protocol:      "ICMPv6",
		Detail:        fmt.Sprintf("Resolving neighbor: %s", NormalizeIPv6Address(targetAddr)),
	}
	report.Timeline = append(report.Timeline, event)
}

// handleNeighborAdvertisement processes Neighbor Advertisement messages
func (i *ICMPv6Analyzer) handleNeighborAdvertisement(packet gopacket.Packet, ipv6Info *IPv6PacketInfo, icmpv6 *layers.ICMPv6, timestamp float64, report *models.TriageReport) {
	if len(icmpv6.Payload) < 20 {
		return
	}

	flags := binary.BigEndian.Uint32(icmpv6.Payload[0:4])
	routerFlag := (flags & 0x80000000) != 0
	solicitedFlag := (flags & 0x40000000) != 0
	overrideFlag := (flags & 0x20000000) != 0

	targetAddr := net.IP(icmpv6.Payload[4:20])

	// Get MAC address from options
	var macAddr net.HardwareAddr
	if len(icmpv6.Payload) > 20 {
		// Parse options
		options := icmpv6.Payload[20:]
		if len(options) >= 8 && options[0] == 2 { // Target Link-Layer Address option
			macAddr = net.HardwareAddr(options[2:8])
		}
	}

	// Cache neighbor entry
	neighborKey := NormalizeIPv6Address(targetAddr)
	i.neighborCache[neighborKey] = &NeighborEntry{
		IPAddress:  targetAddr,
		MACAddress: macAddr,
		IsRouter:   routerFlag,
		LastSeen:   timestamp,
	}

	detail := fmt.Sprintf("Neighbor advertisement: %s -> %s, Router=%v, Solicited=%v, Override=%v",
		NormalizeIPv6Address(targetAddr), macAddr, routerFlag, solicitedFlag, overrideFlag)

	event := models.TimelineEvent{
		Timestamp:     timestamp,
		EventType:     "ICMPv6_Neighbor_Advertisement",
		SourceIP:      NormalizeIPv6Address(ipv6Info.SrcIP),
		DestinationIP: NormalizeIPv6Address(ipv6Info.DstIP),
		Protocol:      "ICMPv6",
		Detail:        detail,
	}
	report.Timeline = append(report.Timeline, event)
}

// handleRedirect processes ICMPv6 Redirect messages
func (i *ICMPv6Analyzer) handleRedirect(packet gopacket.Packet, ipv6Info *IPv6PacketInfo, timestamp float64, report *models.TriageReport) {
	event := models.TimelineEvent{
		Timestamp:     timestamp,
		EventType:     "ICMPv6_Redirect",
		SourceIP:      NormalizeIPv6Address(ipv6Info.SrcIP),
		DestinationIP: NormalizeIPv6Address(ipv6Info.DstIP),
		Protocol:      "ICMPv6",
		Detail:        "Router redirect message",
	}
	report.Timeline = append(report.Timeline, event)
}

// handleEcho processes ICMPv6 Echo Request/Reply messages
func (i *ICMPv6Analyzer) handleEcho(packet gopacket.Packet, ipv6Info *IPv6PacketInfo, icmpv6 *layers.ICMPv6, timestamp float64, report *models.TriageReport) {
	eventType := "ICMPv6_Echo_Request"
	if icmpv6.TypeCode.Type() == layers.ICMPv6TypeEchoReply {
		eventType = "ICMPv6_Echo_Reply"
	}

	var seq uint16
	if len(icmpv6.Payload) >= 4 {
		seq = binary.BigEndian.Uint16(icmpv6.Payload[2:4])
	}

	event := models.TimelineEvent{
		Timestamp:     timestamp,
		EventType:     eventType,
		SourceIP:      NormalizeIPv6Address(ipv6Info.SrcIP),
		DestinationIP: NormalizeIPv6Address(ipv6Info.DstIP),
		Protocol:      "ICMPv6",
		Detail:        fmt.Sprintf("Sequence: %d", seq),
	}
	report.Timeline = append(report.Timeline, event)
}

// handleDestinationUnreachable processes ICMPv6 Destination Unreachable messages
func (i *ICMPv6Analyzer) handleDestinationUnreachable(packet gopacket.Packet, ipv6Info *IPv6PacketInfo, icmpv6 *layers.ICMPv6, timestamp float64, report *models.TriageReport) {
	code := icmpv6.TypeCode.Code()
	var reason string
	switch code {
	case 0:
		reason = "No route to destination"
	case 1:
		reason = "Communication administratively prohibited"
	case 2:
		reason = "Beyond scope of source address"
	case 3:
		reason = "Address unreachable"
	case 4:
		reason = "Port unreachable"
	case 5:
		reason = "Source address failed ingress/egress policy"
	case 6:
		reason = "Reject route to destination"
	default:
		reason = fmt.Sprintf("Code %d", code)
	}

	event := models.TimelineEvent{
		Timestamp:     timestamp,
		EventType:     "ICMPv6_Destination_Unreachable",
		SourceIP:      NormalizeIPv6Address(ipv6Info.SrcIP),
		DestinationIP: NormalizeIPv6Address(ipv6Info.DstIP),
		Protocol:      "ICMPv6",
		Detail:        reason,
	}
	report.Timeline = append(report.Timeline, event)
}

// handlePacketTooBig processes ICMPv6 Packet Too Big messages
func (i *ICMPv6Analyzer) handlePacketTooBig(packet gopacket.Packet, ipv6Info *IPv6PacketInfo, icmpv6 *layers.ICMPv6, timestamp float64, report *models.TriageReport) {
	var mtu uint32
	if len(icmpv6.Payload) >= 4 {
		mtu = binary.BigEndian.Uint32(icmpv6.Payload[0:4])
	}

	event := models.TimelineEvent{
		Timestamp:     timestamp,
		EventType:     "ICMPv6_Packet_Too_Big",
		SourceIP:      NormalizeIPv6Address(ipv6Info.SrcIP),
		DestinationIP: NormalizeIPv6Address(ipv6Info.DstIP),
		Protocol:      "ICMPv6",
		Detail:        fmt.Sprintf("MTU: %d bytes", mtu),
	}
	report.Timeline = append(report.Timeline, event)
}

// handleTimeExceeded processes ICMPv6 Time Exceeded messages
func (i *ICMPv6Analyzer) handleTimeExceeded(packet gopacket.Packet, ipv6Info *IPv6PacketInfo, icmpv6 *layers.ICMPv6, timestamp float64, report *models.TriageReport) {
	code := icmpv6.TypeCode.Code()
	var reason string
	switch code {
	case 0:
		reason = "Hop limit exceeded in transit"
	case 1:
		reason = "Fragment reassembly time exceeded"
	default:
		reason = fmt.Sprintf("Code %d", code)
	}

	event := models.TimelineEvent{
		Timestamp:     timestamp,
		EventType:     "ICMPv6_Time_Exceeded",
		SourceIP:      NormalizeIPv6Address(ipv6Info.SrcIP),
		DestinationIP: NormalizeIPv6Address(ipv6Info.DstIP),
		Protocol:      "ICMPv6",
		Detail:        reason,
	}
	report.Timeline = append(report.Timeline, event)
}

// GetNeighborCache returns the neighbor discovery cache
func (i *ICMPv6Analyzer) GetNeighborCache() map[string]*NeighborEntry {
	return i.neighborCache
}

// GetRouterCache returns the router advertisement cache
func (i *ICMPv6Analyzer) GetRouterCache() map[string]*RouterEntry {
	return i.routerCache
}
