package models

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// PacketStore holds raw packet data for hex inspection and stream reassembly
type PacketStore struct {
	mu           sync.RWMutex
	packets      []*RawPacket
	maxPackets   int   // Maximum packets to store (0 = unlimited)
	maxBytes     int64 // Maximum total bytes to store (0 = unlimited)
	currentBytes int64
}

// RawPacket represents a single raw packet with all layers
type RawPacket struct {
	Index     int       `json:"index"` // Packet index in the PCAP (0-based)
	Timestamp time.Time `json:"timestamp"`
	Length    int       `json:"length"`  // Wire length
	CapLen    int       `json:"cap_len"` // Captured length
	RawData   []byte    `json:"-"`       // Raw bytes (not serialized to JSON)
	RawHex    string    `json:"raw_hex"` // Hex dump for API

	// Parsed layers for tree view
	LinkLayer        *LayerInfo `json:"link_layer,omitempty"`
	NetworkLayer     *LayerInfo `json:"network_layer,omitempty"`
	TransportLayer   *LayerInfo `json:"transport_layer,omitempty"`
	ApplicationLayer *LayerInfo `json:"application_layer,omitempty"`

	// 5-tuple for stream identification
	StreamID string `json:"stream_id"` // Normalized 5-tuple hash
	SrcIP    string `json:"src_ip"`
	DstIP    string `json:"dst_ip"`
	SrcPort  uint16 `json:"src_port,omitempty"`
	DstPort  uint16 `json:"dst_port,omitempty"`
	Protocol string `json:"protocol"` // TCP, UDP, ICMP, etc.

	// Flags for quick filtering
	IsTCP      bool `json:"is_tcp"`
	IsUDP      bool `json:"is_udp"`
	IsICMP     bool `json:"is_icmp"`
	IsTLS      bool `json:"is_tls"`
	IsHTTP     bool `json:"is_http"`
	IsDNS      bool `json:"is_dns"`
	HasPayload bool `json:"has_payload"`
}

// LayerInfo represents a decoded protocol layer for the tree view
type LayerInfo struct {
	Name       string            `json:"name"`                  // e.g., "Ethernet", "IPv4", "TCP"
	Protocol   string            `json:"protocol"`              // Protocol number/name
	Src        string            `json:"src,omitempty"`         // Source address/port
	Dst        string            `json:"dst,omitempty"`         // Destination address/port
	Length     int               `json:"length"`                // Layer length in bytes
	Flags      map[string]string `json:"flags,omitempty"`       // TCP flags, IP flags, etc.
	Fields     map[string]string `json:"fields,omitempty"`      // Key fields for display
	Summary    string            `json:"summary"`               // One-line summary
	RawHex     string            `json:"raw_hex,omitempty"`     // Hex dump of this layer
	PayloadHex string            `json:"payload_hex,omitempty"` // Hex dump of payload
}

// NewPacketStore creates a new packet store
func NewPacketStore(maxPackets int, maxBytes int64) *PacketStore {
	return &PacketStore{
		packets:    make([]*RawPacket, 0),
		maxPackets: maxPackets,
		maxBytes:   maxBytes,
	}
}

// AddPacket adds a packet to the store
func (ps *PacketStore) AddPacket(packet gopacket.Packet, index int) error {
	ps.mu.Lock()
	defer ps.mu.Unlock()

	// Get raw data — make a copy since gopacket may reuse buffers
	origData := packet.Data()
	data := make([]byte, len(origData))
	copy(data, origData)

	// Evict oldest packets if over count limit
	for ps.maxPackets > 0 && len(ps.packets) >= ps.maxPackets && len(ps.packets) > 0 {
		ps.currentBytes -= int64(len(ps.packets[0].RawData))
		ps.packets[0].RawData = nil // help GC
		ps.packets = ps.packets[1:]
	}

	// Evict oldest packets if over byte limit
	for ps.maxBytes > 0 && len(ps.packets) > 0 && ps.currentBytes+int64(len(data)) > ps.maxBytes {
		ps.currentBytes -= int64(len(ps.packets[0].RawData))
		ps.packets[0].RawData = nil // help GC
		ps.packets = ps.packets[1:]
	}

	rawPacket := &RawPacket{
		Index:     index,
		Timestamp: packet.Metadata().Timestamp,
		Length:    packet.Metadata().Length,
		CapLen:    packet.Metadata().CaptureLength,
		RawData:   data,
		RawHex:    formatHexDump(data),
	}

	// Parse layers
	ps.parseLayers(packet, rawPacket)

	// Add to store
	ps.packets = append(ps.packets, rawPacket)
	ps.currentBytes += int64(len(data))

	return nil
}

// parseLayers extracts layer information from a packet
func (ps *PacketStore) parseLayers(packet gopacket.Packet, rp *RawPacket) {
	// Link layer (Ethernet)
	if ethLayer := packet.Layer(layers.LayerTypeEthernet); ethLayer != nil {
		eth := ethLayer.(*layers.Ethernet)
		rp.LinkLayer = &LayerInfo{
			Name:     "Ethernet",
			Src:      eth.SrcMAC.String(),
			Dst:      eth.DstMAC.String(),
			Length:   14,
			Protocol: eth.EthernetType.String(),
			Summary:  fmt.Sprintf("%s → %s (%s)", eth.SrcMAC, eth.DstMAC, eth.EthernetType),
			Fields: map[string]string{
				"Source MAC":      eth.SrcMAC.String(),
				"Destination MAC": eth.DstMAC.String(),
				"EtherType":       eth.EthernetType.String(),
			},
		}
	}

	// Network layer (IPv4/IPv6)
	if ip4Layer := packet.Layer(layers.LayerTypeIPv4); ip4Layer != nil {
		ip4 := ip4Layer.(*layers.IPv4)
		rp.NetworkLayer = &LayerInfo{
			Name:     "IPv4",
			Protocol: "IPv4",
			Src:      ip4.SrcIP.String(),
			Dst:      ip4.DstIP.String(),
			Length:   int(ip4.IHL) * 4,
			Summary:  fmt.Sprintf("%s → %s (TTL=%d, ID=%d)", ip4.SrcIP, ip4.DstIP, ip4.TTL, ip4.Id),
			Fields: map[string]string{
				"Source":      ip4.SrcIP.String(),
				"Destination": ip4.DstIP.String(),
				"TTL":         fmt.Sprintf("%d", ip4.TTL),
				"ID":          fmt.Sprintf("%d", ip4.Id),
				"Flags":       ip4.Flags.String(),
				"Protocol":    ip4.Protocol.String(),
			},
			Flags: map[string]string{
				"DF": fmt.Sprintf("%v", ip4.Flags&layers.IPv4DontFragment != 0),
				"MF": fmt.Sprintf("%v", ip4.Flags&layers.IPv4MoreFragments != 0),
			},
		}
		rp.SrcIP = ip4.SrcIP.String()
		rp.DstIP = ip4.DstIP.String()
		rp.Protocol = ip4.Protocol.String()
	} else if ip6Layer := packet.Layer(layers.LayerTypeIPv6); ip6Layer != nil {
		ip6 := ip6Layer.(*layers.IPv6)
		rp.NetworkLayer = &LayerInfo{
			Name:     "IPv6",
			Protocol: "IPv6",
			Src:      ip6.SrcIP.String(),
			Dst:      ip6.DstIP.String(),
			Length:   40,
			Summary:  fmt.Sprintf("%s → %s (HopLimit=%d)", ip6.SrcIP, ip6.DstIP, ip6.HopLimit),
			Fields: map[string]string{
				"Source":      ip6.SrcIP.String(),
				"Destination": ip6.DstIP.String(),
				"Hop Limit":   fmt.Sprintf("%d", ip6.HopLimit),
				"Next Header": ip6.NextHeader.String(),
			},
		}
		rp.SrcIP = ip6.SrcIP.String()
		rp.DstIP = ip6.DstIP.String()
		rp.Protocol = ip6.NextHeader.String()
	}

	// Transport layer (TCP/UDP/ICMP)
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp := tcpLayer.(*layers.TCP)
		flags := make(map[string]string)
		if tcp.SYN {
			flags["SYN"] = "✓"
		}
		if tcp.ACK {
			flags["ACK"] = "✓"
		}
		if tcp.FIN {
			flags["FIN"] = "✓"
		}
		if tcp.RST {
			flags["RST"] = "✓"
		}
		if tcp.PSH {
			flags["PSH"] = "✓"
		}
		if tcp.URG {
			flags["URG"] = "✓"
		}

		rp.TransportLayer = &LayerInfo{
			Name:     "TCP",
			Protocol: "TCP",
			Src:      fmt.Sprintf("%d", tcp.SrcPort),
			Dst:      fmt.Sprintf("%d", tcp.DstPort),
			Length:   int(tcp.DataOffset) * 4,
			Summary:  fmt.Sprintf("Port %d → %d [Seq=%d Ack=%d Win=%d]", tcp.SrcPort, tcp.DstPort, tcp.Seq, tcp.Ack, tcp.Window),
			Flags:    flags,
			Fields: map[string]string{
				"Source Port": fmt.Sprintf("%d", tcp.SrcPort),
				"Dest Port":   fmt.Sprintf("%d", tcp.DstPort),
				"Seq":         fmt.Sprintf("%d", tcp.Seq),
				"Ack":         fmt.Sprintf("%d", tcp.Ack),
				"Window":      fmt.Sprintf("%d", tcp.Window),
				"Data Offset": fmt.Sprintf("%d bytes", int(tcp.DataOffset)*4),
			},
		}
		if len(tcp.Payload) > 0 {
			n := len(tcp.Payload)
			if n > 128 {
				n = 128
			}
			rp.TransportLayer.PayloadHex = formatHexDump(tcp.Payload[:n])
		}
		rp.SrcPort = uint16(tcp.SrcPort)
		rp.DstPort = uint16(tcp.DstPort)
		rp.Protocol = "TCP"
		rp.IsTCP = true
	} else if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp := udpLayer.(*layers.UDP)
		rp.TransportLayer = &LayerInfo{
			Name:     "UDP",
			Protocol: "UDP",
			Src:      fmt.Sprintf("%d", udp.SrcPort),
			Dst:      fmt.Sprintf("%d", udp.DstPort),
			Length:   8,
			Summary:  fmt.Sprintf("Port %d → %d (Len=%d)", udp.SrcPort, udp.DstPort, udp.Length),
			Fields: map[string]string{
				"Source Port": fmt.Sprintf("%d", udp.SrcPort),
				"Dest Port":   fmt.Sprintf("%d", udp.DstPort),
				"Length":      fmt.Sprintf("%d", udp.Length),
			},
		}
		if len(udp.Payload) > 0 {
			n := len(udp.Payload)
			if n > 128 {
				n = 128
			}
			rp.TransportLayer.PayloadHex = formatHexDump(udp.Payload[:n])
		}
		rp.SrcPort = uint16(udp.SrcPort)
		rp.DstPort = uint16(udp.DstPort)
		rp.Protocol = "UDP"
		rp.IsUDP = true
	} else if icmpLayer := packet.Layer(layers.LayerTypeICMPv4); icmpLayer != nil {
		icmp := icmpLayer.(*layers.ICMPv4)
		rp.TransportLayer = &LayerInfo{
			Name:     "ICMP",
			Protocol: "ICMP",
			Summary:  fmt.Sprintf("Type=%d Code=%d", icmp.TypeCode.Type(), icmp.TypeCode.Code()),
			Fields: map[string]string{
				"Type": fmt.Sprintf("%d (%s)", icmp.TypeCode.Type(), icmpTypeToString(icmp.TypeCode.Type())),
				"Code": fmt.Sprintf("%d", icmp.TypeCode.Code()),
				"Id":   fmt.Sprintf("%d", icmp.Id),
				"Seq":  fmt.Sprintf("%d", icmp.Seq),
			},
		}
		rp.Protocol = "ICMP"
		rp.IsICMP = true
	}

	// Application layer detection
	appLayer := packet.ApplicationLayer()
	if appLayer != nil && len(appLayer.Payload()) > 0 {
		payload := appLayer.Payload()
		rp.HasPayload = true
		rp.ApplicationLayer = &LayerInfo{
			Name:    "Payload",
			Length:  len(payload),
			Summary: fmt.Sprintf("%d bytes", len(payload)),
		}

		// Detect application protocol
		if len(payload) >= 5 {
			// HTTP detection
			if string(payload[:4]) == "HTTP" || string(payload[:4]) == "GET " ||
				string(payload[:5]) == "POST " || string(payload[:4]) == "PUT " {
				rp.IsHTTP = true
				rp.ApplicationLayer.Name = "HTTP"
				lines := strings.SplitN(string(payload), "\r\n", 2)
				if len(lines) > 0 {
					rp.ApplicationLayer.Summary = strings.TrimSpace(lines[0])
				}
			}
			// TLS detection
			if payload[0] == 0x16 && payload[1] == 0x03 {
				rp.IsTLS = true
				rp.ApplicationLayer.Name = "TLS"
				rp.ApplicationLayer.Summary = decodeTLSHandshake(payload)
			}
		}
		// DNS detection
		if (rp.SrcPort == 53 || rp.DstPort == 53) && len(payload) >= 12 {
			rp.IsDNS = true
			rp.ApplicationLayer.Name = "DNS"
		}

		// Add payload hex (truncated)
		maxPayload := 256
		if len(payload) < maxPayload {
			maxPayload = len(payload)
		}
		rp.ApplicationLayer.RawHex = formatHexDump(payload[:maxPayload])
	}

	// Generate stream ID for TCP/UDP
	if rp.IsTCP || rp.IsUDP {
		rp.StreamID = normalizeStreamID(rp.SrcIP, rp.SrcPort, rp.DstIP, rp.DstPort, rp.Protocol)
	}
}

// GetPacket returns a packet by its PCAP index (not slice position)
func (ps *PacketStore) GetPacket(index int) (*RawPacket, error) {
	ps.mu.RLock()
	defer ps.mu.RUnlock()

	// Search by PCAP index since eviction may have shifted slice positions
	for _, p := range ps.packets {
		if p.Index == index {
			return p, nil
		}
	}
	return nil, fmt.Errorf("packet index %d not found in store", index)
}

// GetPacketsByStream returns all packets belonging to a stream
func (ps *PacketStore) GetPacketsByStream(streamID string) []*RawPacket {
	ps.mu.RLock()
	defer ps.mu.RUnlock()

	var packets []*RawPacket
	for _, p := range ps.packets {
		if p.StreamID == streamID {
			packets = append(packets, p)
		}
	}
	return packets
}

// GetPacketCount returns the total number of stored packets
func (ps *PacketStore) GetPacketCount() int {
	ps.mu.RLock()
	defer ps.mu.RUnlock()
	return len(ps.packets)
}

// GetAllPackets returns a snapshot of all stored packets (safe for iteration)
func (ps *PacketStore) GetAllPackets() []*RawPacket {
	ps.mu.RLock()
	defer ps.mu.RUnlock()
	result := make([]*RawPacket, len(ps.packets))
	copy(result, ps.packets)
	return result
}

// Clear removes all packets from the store
func (ps *PacketStore) Clear() {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	ps.packets = ps.packets[:0]
	ps.currentBytes = 0
}

// GetStreamIDs returns all unique stream IDs
func (ps *PacketStore) GetStreamIDs() []string {
	ps.mu.RLock()
	defer ps.mu.RUnlock()

	streamSet := make(map[string]bool)
	for _, p := range ps.packets {
		if p.StreamID != "" {
			streamSet[p.StreamID] = true
		}
	}

	ids := make([]string, 0, len(streamSet))
	for id := range streamSet {
		ids = append(ids, id)
	}
	return ids
}

// normalizeStreamID creates a canonical stream ID (lower tuple first)
func normalizeStreamID(srcIP string, srcPort uint16, dstIP string, dstPort uint16, protocol string) string {
	src := fmt.Sprintf("%s:%d", srcIP, srcPort)
	dst := fmt.Sprintf("%s:%d", dstIP, dstPort)
	if src < dst {
		return fmt.Sprintf("%s->%s/%s", src, dst, protocol)
	}
	return fmt.Sprintf("%s->%s/%s", dst, src, protocol)
}

// formatHexDump creates a Wireshark-style hex dump
func formatHexDump(data []byte) string {
	var sb strings.Builder
	for i := 0; i < len(data); i += 16 {
		// Offset
		sb.WriteString(fmt.Sprintf("%04x  ", i))

		// Hex bytes
		for j := 0; j < 16; j++ {
			if i+j < len(data) {
				sb.WriteString(fmt.Sprintf("%02x ", data[i+j]))
			} else {
				sb.WriteString("   ")
			}
			if j == 7 {
				sb.WriteString(" ")
			}
		}

		// ASCII
		sb.WriteString(" |")
		for j := 0; j < 16 && i+j < len(data); j++ {
			b := data[i+j]
			if b >= 32 && b < 127 {
				sb.WriteByte(b)
			} else {
				sb.WriteByte('.')
			}
		}
		sb.WriteString("|\n")
	}
	return sb.String()
}

// decodeTLSHandshake returns a human-readable TLS description
func decodeTLSHandshake(data []byte) string {
	if len(data) < 6 {
		return "TLS (incomplete)"
	}

	contentType := data[0]
	version := uint16(data[1])<<8 | uint16(data[2])

	versionStr := "TLS"
	switch version {
	case 0x0301:
		versionStr = "TLS 1.0"
	case 0x0302:
		versionStr = "TLS 1.1"
	case 0x0303:
		versionStr = "TLS 1.2"
	case 0x0304:
		versionStr = "TLS 1.3"
	}

	switch contentType {
	case 0x14:
		return fmt.Sprintf("%s ChangeCipherSpec", versionStr)
	case 0x15:
		return fmt.Sprintf("%s Alert", versionStr)
	case 0x16:
		if len(data) > 5 {
			hsType := data[5]
			switch hsType {
			case 0x01:
				return fmt.Sprintf("%s ClientHello", versionStr)
			case 0x02:
				return fmt.Sprintf("%s ServerHello", versionStr)
			case 0x0b:
				return fmt.Sprintf("%s Certificate", versionStr)
			case 0x14:
				return fmt.Sprintf("%s Finished", versionStr)
			}
		}
		return fmt.Sprintf("%s Handshake", versionStr)
	case 0x17:
		return fmt.Sprintf("%s ApplicationData", versionStr)
	}

	return fmt.Sprintf("%s Record", versionStr)
}

// icmpTypeToString converts ICMP type number to name
func icmpTypeToString(t uint8) string {
	types := map[uint8]string{
		0:  "Echo Reply",
		3:  "Destination Unreachable",
		4:  "Source Quench",
		5:  "Redirect",
		8:  "Echo Request",
		9:  "Router Advertisement",
		10: "Router Solicitation",
		11: "Time Exceeded",
		12: "Parameter Problem",
		13: "Timestamp Request",
		14: "Timestamp Reply",
	}
	if name, ok := types[t]; ok {
		return name
	}
	return "Unknown"
}
