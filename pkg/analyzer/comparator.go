package analyzer

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// ─── Packet Comparison States ───────────────────────────────────
const (
	StatePresentBoth       = "PRESENT_BOTH"       // Packet found in both captures
	StateMissingB          = "MISSING_B"          // In file A (LAN), not in B (WAN) — dropped by device
	StateMissingA          = "MISSING_A"          // In file B (WAN), not in A (LAN) — asymmetric routing / spoofed
	StateModified          = "MODIFIED"           // Present in both but fields changed (TTL, DSCP, NAT)
	StateVerifiedEncrypted = "VERIFIED_ENCRYPTED" // LAN clear-text correlated to encrypted WAN tunnel via time+size
	StateIgnoredLocal      = "IGNORED_LOCAL"      // Broadcast/multicast/link-local — not expected on WAN
)

// Noise classification for LAN packets not expected on WAN.
const (
	NoiseNone     = ""          // Real user traffic — candidate for WAN transit
	NoiseLocal    = "local"     // Broadcast/multicast/link-local
	NoiseMgmt     = "mgmt"      // SNMP (161/162), Syslog (514), NTP (123)
	NoiseRouting  = "routing"   // HSRP/VRRP (proto 112, UDP 1985), OSPF (proto 89), EIGRP (proto 88)
	NoiseLocalLAN = "local_lan" // Same private subnet (RFC1918 intra-subnet)
)

// Drop reason categories for MISSING_B packets.
const (
	DropReasonPolicyDrop = "policy_drop" // TCP SYN with no response — likely ACL/policy block
	DropReasonBlackhole  = "blackhole"   // Ongoing data transfer that suddenly disappears
	DropReasonUnknown    = "unknown"     // Cannot determine reason
)

// ─── Tunnel Encapsulation Types ─────────────────────────────────
const (
	TunnelNone    = ""          // No encapsulation (clear-text)
	TunnelESP     = "ESP/IPsec" // Encrypted — inner flow hidden
	TunnelGRE     = "GRE"       // Clear tunnel — inner extractable
	TunnelVXLAN   = "VXLAN"     // UDP 4789 — inner extractable
	TunnelVCMP    = "VeloCloud" // UDP 2426 — partially extractable
	TunnelViptela = "Viptela"   // UDP 12346–12426 — partially extractable
)

// SD-WAN tunnel port ranges
const (
	vxlanPort       = 4789
	vcmpPort        = 2426
	viptelaPortLow  = 12346
	viptelaPortHigh = 12426
)

// isTLSPort returns true if the port is commonly used for TLS traffic.
func isTLSPort(port uint16) bool {
	switch port {
	case 443, 8443, 993, 995, 465, 636, 989, 990, 5061, 853:
		// HTTPS, HTTPS-alt, IMAPS, POP3S, SMTPS, LDAPS, FTPS-data, FTPS-ctrl, SIPS, DNS-over-TLS
		return true
	default:
		return false
	}
}

// ─── Core Structs ───────────────────────────────────────────────

// Comparator performs packet-level comparison between two PCAP files.
type Comparator struct {
	verbose    bool
	KeyLogPath string // Optional path to NSS SSL Key Log file for TLS decryption (C4)

	// TLS decryption state (C4) — initialized when KeyLogPath is set
	tlsDecryptor  *TLSDecryptor
	tlsStats      *TLSDecryptionStats
	clientRandoms map[string][32]byte // flowKey → client random for session tracking
}

// NewComparator creates a new PCAP comparator.
func NewComparator(verbose bool) *Comparator {
	return &Comparator{verbose: verbose}
}

// packetKey is the matching key for correlating packets across captures.
// TCP:  5-tuple + TCP sequence number
// UDP:  5-tuple + IP Identification + IP checksum
// Other: 5-tuple + IP Identification
type packetKey struct {
	SrcIP    string
	DstIP    string
	SrcPort  uint16
	DstPort  uint16
	Protocol string
	SeqNum   uint32 // TCP Seq or IP.Id for UDP/other
	IPId     uint16
}

func (k packetKey) String() string {
	return fmt.Sprintf("%s:%d->%s:%d/%s seq=%d ipid=%d",
		k.SrcIP, k.SrcPort, k.DstIP, k.DstPort, k.Protocol, k.SeqNum, k.IPId)
}

// packetMeta holds extracted metadata for a single packet.
type packetMeta struct {
	Key       packetKey
	Index     int
	Timestamp time.Time
	Length    int
	TTL       uint8
	DSCP      uint8
	Checksum  uint16
	TCPFlags  string
	Payload   int    // payload size
	AckNum    uint32 // TCP ack number (0 for non-TCP)
	Window    uint16 // TCP advertised receive window (0 for non-TCP)

	// Wireshark-style analysis flags (populated by the comparator's Pass 2
	// analyzer before match helpers are invoked). Zero for non-TCP or when
	// analysis has not been computed.
	Analysis TCPAnalysisFlags

	// Tunnel/encapsulation metadata
	TunnelType string     // TunnelNone, TunnelESP, TunnelGRE, etc.
	OuterKey   *packetKey // Outer 5-tuple (nil if not encapsulated)
	Encrypted  bool       // True if inner payload is encrypted (ESP without keys)

	// Raw TCP payload for TLS decryption (C4). Only populated when key log is provided.
	// Limited to first 8KB to avoid memory bloat.
	RawPayload []byte
}

// ─── Comparison Report ──────────────────────────────────────────

// ComparisonReport is the final output of a two-file PCAP comparison.
type ComparisonReport struct {
	FileA string `json:"file_a"` // LAN-side filename
	FileB string `json:"file_b"` // WAN-side filename

	// Aggregate stats
	TotalPacketsA            int `json:"total_packets_a"`
	TotalPacketsB            int `json:"total_packets_b"`
	MatchedCount             int `json:"matched_count"`
	MissingBCount            int `json:"missing_b_count"` // In A not B (dropped)
	MissingACount            int `json:"missing_a_count"` // In B not A (asymmetric)
	ModifiedCount            int `json:"modified_count"`
	VerifiedEncryptedCount   int `json:"verified_encrypted_count"`    // LAN↔encrypted WAN correlated by time+size
	IgnoredLocalCount        int `json:"ignored_local_count"`         // Broadcast/multicast/link-local excluded
	IgnoredMgmtCount         int `json:"ignored_mgmt_count"`          // SNMP/Syslog/NTP excluded
	IgnoredRoutingCount      int `json:"ignored_routing_count"`       // HSRP/VRRP/OSPF/EIGRP excluded
	IgnoredLocalLANCount     int `json:"ignored_local_lan_count"`     // Same-subnet RFC1918 excluded
	IgnoredControlPlaneCount int `json:"ignored_control_plane_count"` // WAN-side BFD/OMP/keepalive excluded from score
	PolicyDropCount          int `json:"policy_drop_count"`           // TCP SYN with no response
	BlackholeCount           int `json:"blackhole_count"`             // Ongoing data that disappears

	// Path Integrity Score (0–100)
	PathIntegrityScore float64 `json:"path_integrity_score"`
	IntegrityRating    string  `json:"integrity_rating"` // "Healthy", "Degraded", "Critical"

	// Detailed discrepancies
	Discrepancies []Discrepancy `json:"discrepancies"`

	// Per-flow summary
	FlowSummaries []FlowComparisonSummary `json:"flow_summaries"`

	// Modification breakdown
	NATDetected bool `json:"nat_detected"`
	TTLChanges  int  `json:"ttl_changes"`
	DSCPChanges int  `json:"dscp_changes"`

	// Tunnel/Encapsulation stats
	TunnelDetected    bool           `json:"tunnel_detected"`
	TunnelTypes       []string       `json:"tunnel_types,omitempty"`     // Unique tunnel types found
	EncapsulatedCount int            `json:"encapsulated_count"`         // Packets that were decapsulated
	EncryptedCount    int            `json:"encrypted_count"`            // ESP packets where inner is hidden
	TunnelBreakdown   map[string]int `json:"tunnel_breakdown,omitempty"` // TunnelType → count

	// Forensic Comparison Summary (streaming engine)
	Forensics *ForensicSummary `json:"forensics,omitempty"`

	// TLS Decryption stats (C4)
	TLSDecryption *TLSDecryptionStats `json:"tls_decryption,omitempty"`

	// Timing
	AnalysisDuration time.Duration `json:"analysis_duration_ms"`
}

// TLSDecryptionStats reports how many TLS sessions/records were decrypted.
type TLSDecryptionStats struct {
	KeysLoaded       int `json:"keys_loaded"`       // Number of sessions in key log
	RecordsDecrypted int `json:"records_decrypted"` // Application data records successfully decrypted
	RecordsFailed    int `json:"records_failed"`    // Records where decryption was attempted but failed
	SessionsMatched  int `json:"sessions_matched"`  // Sessions where client random was found in key log
}

// Discrepancy represents a single packet-level difference between the two captures.
type Discrepancy struct {
	State       string `json:"state"` // MISSING_B, MISSING_A, MODIFIED
	SrcIP       string `json:"src_ip"`
	DstIP       string `json:"dst_ip"`
	SrcPort     uint16 `json:"src_port"`
	DstPort     uint16 `json:"dst_port"`
	Protocol    string `json:"protocol"`
	PacketIndex int    `json:"packet_index"` // Index in the source file
	Timestamp   string `json:"timestamp"`
	Length      int    `json:"length"`
	Detail      string `json:"detail"` // Human-readable explanation
	TCPFlags    string `json:"tcp_flags,omitempty"`

	// TCP Time-Sequence graph fields (populated for TCP only; zero for UDP/ICMP)
	SeqNum     uint32 `json:"seq_num,omitempty"`     // TCP sequence number
	AckNum     uint32 `json:"ack_num,omitempty"`     // TCP acknowledgement number
	WindowSize uint16 `json:"window_size,omitempty"` // Advertised receive window (unscaled)
	PayloadLen int    `json:"payload_len,omitempty"` // TCP payload bytes (segment height on graph)

	// Wireshark-style per-packet TCP analysis flags. All false for non-TCP.
	IsRetransmission  bool `json:"is_retransmission,omitempty"`
	IsDuplicateAck    bool `json:"is_duplicate_ack,omitempty"`
	IsZeroWindow      bool `json:"is_zero_window,omitempty"`
	IsKeepAlive       bool `json:"is_keep_alive,omitempty"`
	DuplicateAckCount int  `json:"duplicate_ack_count,omitempty"` // "Dup ACK #N"

	// Tunnel metadata
	TunnelType string `json:"tunnel_type,omitempty"` // e.g. "GRE", "ESP/IPsec"
	Encrypted  bool   `json:"encrypted,omitempty"`   // True if ESP-encrypted

	// TLS decryption (C4) — populated when key log is provided
	DecryptedProtocol string `json:"decrypted_protocol,omitempty"` // "HTTP", "HTTP/2", "gRPC", etc.
	DecryptedSummary  string `json:"decrypted_summary,omitempty"`  // Human-readable one-liner
	DecryptedData     string `json:"decrypted_data,omitempty"`     // First 4KB of cleartext (base64 or UTF-8)
	TLSVersion        string `json:"tls_version,omitempty"`        // "TLS 1.2", "TLS 1.3"

	// For MODIFIED state
	FieldChanges []FieldChange `json:"field_changes,omitempty"`
}

// FieldChange describes a single field modification between the two captures.
type FieldChange struct {
	Field  string `json:"field"`   // "TTL", "DSCP", "SrcIP" (NAT), "DstIP" (NAT)
	ValueA string `json:"value_a"` // Value in file A
	ValueB string `json:"value_b"` // Value in file B
}

// FlowComparisonSummary aggregates comparison results per 5-tuple flow.
type FlowComparisonSummary struct {
	SrcIP             string  `json:"src_ip"`
	DstIP             string  `json:"dst_ip"`
	SrcPort           uint16  `json:"src_port"`
	DstPort           uint16  `json:"dst_port"`
	Protocol          string  `json:"protocol"`
	PacketsA          int     `json:"packets_a"`
	PacketsB          int     `json:"packets_b"`
	Matched           int     `json:"matched"`
	MissingB          int     `json:"missing_b"`
	MissingA          int     `json:"missing_a"`
	Modified          int     `json:"modified"`
	VerifiedEncrypted int     `json:"verified_encrypted"` // Correlated via time+size
	MatchRate         float64 `json:"match_rate"`         // 0.0–1.0
	HasNAT            bool    `json:"has_nat"`
	DropReason        string  `json:"drop_reason,omitempty"` // policy_drop, blackhole, or empty
	TunnelType        string  `json:"tunnel_type,omitempty"`
	Encapsulated      bool    `json:"encapsulated"`
}

// ─── Main Compare Method ────────────────────────────────────────

// Compare performs a streaming two-pass packet-level comparison between
// two PCAP files. fileA is the LAN-side capture, fileB is the WAN-side.
//
// The streaming engine uses O(flows + fingerprints) memory instead of
// O(all_packets × 2), enabling 100 MB+ captures without crashing.
func (c *Comparator) Compare(fileA, fileB string) (*ComparisonReport, error) {
	return c.CompareStreaming(fileA, fileB)
}

// ─── Streaming Packet Reader ────────────────────────────────────

// streamFile opens a PCAP file and streams each packet through the callback.
// Returns total packet count. No packet data is retained after the callback.
func (c *Comparator) streamFile(filePath string, onPacket func(*packetMeta)) (int, error) {
	handle, err := OpenCapture(filePath)
	if err != nil {
		return 0, fmt.Errorf("invalid capture file: %w", err)
	}
	defer handle.Close()

	reader := handle.Reader
	index := 0

	for {
		data, ci, err := reader.ReadPacketData()
		if err != nil {
			break // EOF
		}

		pkt := gopacket.NewPacket(data, reader.LinkType(), gopacket.Lazy)
		if pkt == nil {
			index++
			continue
		}

		meta := packetMeta{
			Index:     index,
			Timestamp: ci.Timestamp,
			Length:    ci.Length,
		}

		// Extract outer network layer
		var srcIP, dstIP string
		if ip4 := pkt.Layer(layers.LayerTypeIPv4); ip4 != nil {
			outerIPv4 := ip4.(*layers.IPv4)
			srcIP = outerIPv4.SrcIP.String()
			dstIP = outerIPv4.DstIP.String()
			meta.TTL = outerIPv4.TTL
			meta.DSCP = uint8(outerIPv4.TOS >> 2)
			meta.Key.IPId = outerIPv4.Id
			meta.Key.Protocol = outerIPv4.Protocol.String()
		} else if ip6 := pkt.Layer(layers.LayerTypeIPv6); ip6 != nil {
			ip := ip6.(*layers.IPv6)
			srcIP = ip.SrcIP.String()
			dstIP = ip.DstIP.String()
			meta.TTL = ip.HopLimit
			meta.DSCP = uint8(ip.TrafficClass >> 2)
			meta.Key.Protocol = ip.NextHeader.String()
		} else {
			index++
			continue // Skip non-IP packets (ARP, etc.)
		}

		meta.Key.SrcIP = srcIP
		meta.Key.DstIP = dstIP

		// ── Tunnel Detection & Decapsulation ─────────────────────
		tunnelDetected := false

		// 1. ESP (IPsec) — IP Protocol 50
		if espLayer := pkt.Layer(layers.LayerTypeIPSecESP); espLayer != nil {
			outerKey := meta.Key
			meta.OuterKey = &outerKey
			meta.TunnelType = TunnelESP
			meta.Encrypted = true
			tunnelDetected = true
			esp := espLayer.(*layers.IPSecESP)
			meta.Key.SeqNum = esp.Seq
		}

		// 2. GRE — IP Protocol 47
		if !tunnelDetected {
			if greLayer := pkt.Layer(layers.LayerTypeGRE); greLayer != nil {
				gre := greLayer.(*layers.GRE)
				if len(gre.Payload) >= 20 {
					if inner := c.decapsulateIP(gre.Payload); inner != nil {
						outerKey := meta.Key
						meta.OuterKey = &outerKey
						meta.TunnelType = TunnelGRE
						c.applyInnerMeta(&meta, inner)
						tunnelDetected = true
					}
				}
			}
		}

		// 3. UDP-based tunnels: VXLAN (4789), VeloCloud VCMP (2426), Viptela (12346–12426)
		if !tunnelDetected {
			if udpLayer := pkt.Layer(layers.LayerTypeUDP); udpLayer != nil {
				u := udpLayer.(*layers.UDP)
				dstP := uint16(u.DstPort)
				srcP := uint16(u.SrcPort)

				switch {
				case dstP == vxlanPort || srcP == vxlanPort:
					if payload := u.Payload; len(payload) > 8+14 {
						innerIPData := payload[8+14:]
						if inner := c.decapsulateIP(innerIPData); inner != nil {
							outerKey := meta.Key
							meta.OuterKey = &outerKey
							meta.TunnelType = TunnelVXLAN
							c.applyInnerMeta(&meta, inner)
							tunnelDetected = true
						}
					}

				case dstP == vcmpPort || srcP == vcmpPort:
					if inner := c.tryDecapsulateWithOffsets(u.Payload, []int{16, 20, 24, 32}); inner != nil {
						outerKey := meta.Key
						meta.OuterKey = &outerKey
						meta.TunnelType = TunnelVCMP
						c.applyInnerMeta(&meta, inner)
						tunnelDetected = true
					} else {
						outerKey := meta.Key
						meta.OuterKey = &outerKey
						meta.TunnelType = TunnelVCMP
						meta.Encrypted = true
						tunnelDetected = true
					}

				case (dstP >= viptelaPortLow && dstP <= viptelaPortHigh) ||
					(srcP >= viptelaPortLow && srcP <= viptelaPortHigh):
					if inner := c.tryDecapsulateWithOffsets(u.Payload, []int{8, 12, 16, 20, 24, 28, 32, 36, 40, 48}); inner != nil {
						outerKey := meta.Key
						meta.OuterKey = &outerKey
						meta.TunnelType = TunnelViptela
						c.applyInnerMeta(&meta, inner)
						tunnelDetected = true
					} else {
						outerKey := meta.Key
						meta.OuterKey = &outerKey
						meta.TunnelType = TunnelViptela
						meta.Encrypted = true
						tunnelDetected = true
					}
				}
			}
		}

		// ── Standard (non-tunnel) transport extraction ───────────
		if !tunnelDetected {
			if tcp := pkt.Layer(layers.LayerTypeTCP); tcp != nil {
				t := tcp.(*layers.TCP)
				meta.Key.SrcPort = uint16(t.SrcPort)
				meta.Key.DstPort = uint16(t.DstPort)
				meta.Key.Protocol = "TCP"
				meta.Key.SeqNum = t.Seq
				meta.AckNum = t.Ack
				meta.Window = t.Window
				meta.Checksum = t.Checksum
				meta.Payload = len(t.Payload)
				meta.TCPFlags = formatTCPFlags(t)

				// TLS decryption (C4): capture raw payload for TLS ports
				if c.tlsDecryptor != nil && len(t.Payload) > 0 {
					dstP, srcP := uint16(t.DstPort), uint16(t.SrcPort)
					if isTLSPort(dstP) || isTLSPort(srcP) {
						// Limit to 8KB to avoid memory bloat
						if len(t.Payload) <= 8192 {
							meta.RawPayload = make([]byte, len(t.Payload))
							copy(meta.RawPayload, t.Payload)
						} else {
							meta.RawPayload = make([]byte, 8192)
							copy(meta.RawPayload, t.Payload[:8192])
						}
					}
				}
			} else if udp := pkt.Layer(layers.LayerTypeUDP); udp != nil {
				u := udp.(*layers.UDP)
				meta.Key.SrcPort = uint16(u.SrcPort)
				meta.Key.DstPort = uint16(u.DstPort)
				meta.Key.Protocol = "UDP"
				meta.Key.SeqNum = uint32(meta.Key.IPId)
				meta.Checksum = u.Checksum
				meta.Payload = len(u.Payload)
			} else if pkt.Layer(layers.LayerTypeICMPv4) != nil {
				meta.Key.Protocol = "ICMP"
				meta.Key.SeqNum = uint32(meta.Key.IPId)
			}
		}

		onPacket(&meta)
		index++
	}

	return index, nil
}

// ─── Tunnel Decapsulation Helpers ───────────────────────────────

// decapsulateIP parses raw bytes as an IPv4 packet and extracts inner metadata.
// Returns nil if the data is not a valid IPv4 packet.
type innerPacketInfo struct {
	SrcIP    string
	DstIP    string
	SrcPort  uint16
	DstPort  uint16
	Protocol string
	TTL      uint8
	DSCP     uint8
	IPId     uint16
	SeqNum   uint32
	AckNum   uint32 // TCP ack number (0 for non-TCP)
	Window   uint16 // TCP advertised receive window (0 for non-TCP)
	Checksum uint16
	Payload  int
	TCPFlags string
}

func (c *Comparator) decapsulateIP(data []byte) *innerPacketInfo {
	if len(data) < 20 {
		return nil
	}

	// Verify this looks like an IPv4 header (version nibble = 4)
	version := data[0] >> 4
	if version != 4 {
		return nil
	}

	ihl := int(data[0]&0x0f) * 4
	if ihl < 20 || ihl > len(data) {
		return nil
	}

	totalLen := int(binary.BigEndian.Uint16(data[2:4]))
	if totalLen < ihl || totalLen > len(data)+100 { // allow some padding tolerance
		return nil
	}

	info := &innerPacketInfo{
		SrcIP: net.IP(data[12:16]).String(),
		DstIP: net.IP(data[16:20]).String(),
		TTL:   data[8],
		DSCP:  data[1] >> 2,
		IPId:  binary.BigEndian.Uint16(data[4:6]),
	}

	// Validate that the IPs look sane (non-zero, non-broadcast)
	if info.SrcIP == "0.0.0.0" || info.DstIP == "0.0.0.0" {
		return nil
	}

	protocol := data[9]
	transportData := data[ihl:]

	switch protocol {
	case 6: // TCP
		if len(transportData) < 20 {
			return nil
		}
		info.Protocol = "TCP"
		info.SrcPort = binary.BigEndian.Uint16(transportData[0:2])
		info.DstPort = binary.BigEndian.Uint16(transportData[2:4])
		info.SeqNum = binary.BigEndian.Uint32(transportData[4:8])
		info.AckNum = binary.BigEndian.Uint32(transportData[8:12])
		info.Window = binary.BigEndian.Uint16(transportData[14:16])
		info.Checksum = binary.BigEndian.Uint16(transportData[16:18])
		tcpDataOff := int(transportData[12]>>4) * 4
		if tcpDataOff >= 20 && tcpDataOff <= len(transportData) {
			info.Payload = len(transportData) - tcpDataOff
		}
		// Parse TCP flags (byte 13)
		flags := transportData[13]
		var flagNames []string
		if flags&0x02 != 0 {
			flagNames = append(flagNames, "SYN")
		}
		if flags&0x10 != 0 {
			flagNames = append(flagNames, "ACK")
		}
		if flags&0x01 != 0 {
			flagNames = append(flagNames, "FIN")
		}
		if flags&0x04 != 0 {
			flagNames = append(flagNames, "RST")
		}
		if flags&0x08 != 0 {
			flagNames = append(flagNames, "PSH")
		}
		if flags&0x20 != 0 {
			flagNames = append(flagNames, "URG")
		}
		info.TCPFlags = strings.Join(flagNames, ",")

	case 17: // UDP
		if len(transportData) < 8 {
			return nil
		}
		info.Protocol = "UDP"
		info.SrcPort = binary.BigEndian.Uint16(transportData[0:2])
		info.DstPort = binary.BigEndian.Uint16(transportData[2:4])
		info.Checksum = binary.BigEndian.Uint16(transportData[6:8])
		info.Payload = len(transportData) - 8
		info.SeqNum = uint32(info.IPId) // Use IP ID for UDP matching

	case 1: // ICMP
		info.Protocol = "ICMP"
		info.SeqNum = uint32(info.IPId)

	default:
		info.Protocol = fmt.Sprintf("IP/%d", protocol)
		info.SeqNum = uint32(info.IPId)
	}

	return info
}

// tryDecapsulateWithOffsets tries to find an inner IP packet at various byte
// offsets within a payload. Used for proprietary SD-WAN headers (VCMP, Viptela)
// where the header length is not fixed/documented.
func (c *Comparator) tryDecapsulateWithOffsets(payload []byte, offsets []int) *innerPacketInfo {
	for _, off := range offsets {
		if off >= len(payload) {
			continue
		}
		if inner := c.decapsulateIP(payload[off:]); inner != nil {
			return inner
		}
	}
	return nil
}

// applyInnerMeta replaces the packet's key with the decapsulated inner flow info.
func (c *Comparator) applyInnerMeta(meta *packetMeta, inner *innerPacketInfo) {
	meta.Key.SrcIP = inner.SrcIP
	meta.Key.DstIP = inner.DstIP
	meta.Key.SrcPort = inner.SrcPort
	meta.Key.DstPort = inner.DstPort
	meta.Key.Protocol = inner.Protocol
	meta.Key.SeqNum = inner.SeqNum
	meta.Key.IPId = inner.IPId
	meta.TTL = inner.TTL
	meta.DSCP = inner.DSCP
	meta.Checksum = inner.Checksum
	meta.Payload = inner.Payload
	meta.TCPFlags = inner.TCPFlags
	meta.AckNum = inner.AckNum
	meta.Window = inner.Window
}

// ─── Helpers ────────────────────────────────────────────────────

func formatTCPFlags(tcp *layers.TCP) string {
	var flags []string
	if tcp.SYN {
		flags = append(flags, "SYN")
	}
	if tcp.ACK {
		flags = append(flags, "ACK")
	}
	if tcp.FIN {
		flags = append(flags, "FIN")
	}
	if tcp.RST {
		flags = append(flags, "RST")
	}
	if tcp.PSH {
		flags = append(flags, "PSH")
	}
	if tcp.URG {
		flags = append(flags, "URG")
	}
	return strings.Join(flags, ",")
}

func formatModificationDetail(changes []FieldChange) string {
	parts := make([]string, 0, len(changes))
	for _, ch := range changes {
		switch ch.Field {
		case "TTL":
			parts = append(parts, fmt.Sprintf("TTL changed: %s→%s (device hop)", ch.ValueA, ch.ValueB))
		case "DSCP":
			parts = append(parts, fmt.Sprintf("DSCP/QoS remarked: %s→%s", ch.ValueA, ch.ValueB))
		case "SrcIP":
			parts = append(parts, fmt.Sprintf("Source NAT: %s→%s", ch.ValueA, ch.ValueB))
		case "DstIP":
			parts = append(parts, fmt.Sprintf("Destination NAT: %s→%s", ch.ValueA, ch.ValueB))
		case "SrcPort":
			parts = append(parts, fmt.Sprintf("Source port translated: %s→%s", ch.ValueA, ch.ValueB))
		case "DstPort":
			parts = append(parts, fmt.Sprintf("Destination port translated: %s→%s", ch.ValueA, ch.ValueB))
		default:
			parts = append(parts, fmt.Sprintf("%s: %s→%s", ch.Field, ch.ValueA, ch.ValueB))
		}
	}
	return strings.Join(parts, "; ")
}

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

// ─── TLS Decryption Integration (C4) ────────────────────────────

// tryDecryptTLS attempts to decrypt TLS application data in the raw payload
// and populates the discrepancy's decrypted fields if successful.
// Returns true if decryption was attempted (regardless of success).
func (c *Comparator) tryDecryptTLS(d *Discrepancy, rawPayload []byte, srcIP string, srcPort, dstPort uint16) bool {
	if c.tlsDecryptor == nil || len(rawPayload) < 5 {
		return false
	}

	// Only attempt on TLS ApplicationData records
	if rawPayload[0] != TLSContentTypeApplicationData {
		return false
	}

	// Find the client random for this flow (try both directions)
	flowKey1 := fmt.Sprintf("%s:%d->%s:%d", srcIP, srcPort, d.DstIP, dstPort)
	flowKey2 := fmt.Sprintf("%s:%d->%s:%d", d.DstIP, dstPort, srcIP, srcPort)

	var clientRandom [32]byte
	var found bool
	if cr, ok := c.clientRandoms[flowKey1]; ok {
		clientRandom = cr
		found = true
	} else if cr, ok := c.clientRandoms[flowKey2]; ok {
		clientRandom = cr
		found = true
	}

	if !found {
		return false
	}

	c.tlsStats.SessionsMatched++

	// Determine direction: fromServer if srcPort is a TLS port
	fromServer := isTLSPort(srcPort)

	result := c.tlsDecryptor.TryDecryptRecord(rawPayload, clientRandom, fromServer)
	if result == nil {
		c.tlsStats.RecordsFailed++
		return true
	}

	c.tlsStats.RecordsDecrypted++

	// Populate discrepancy fields
	d.DecryptedProtocol = result.Protocol
	d.DecryptedSummary = result.Summary
	d.TLSVersion = result.TLSVersion

	// Store first 4KB of decrypted data as UTF-8 if printable, else note binary
	if len(result.Data) > 0 {
		maxLen := 4096
		if len(result.Data) < maxLen {
			maxLen = len(result.Data)
		}
		// Check if data is mostly printable
		printable := 0
		for _, b := range result.Data[:maxLen] {
			if b >= 0x20 && b < 0x7f || b == '\r' || b == '\n' || b == '\t' {
				printable++
			}
		}
		if float64(printable)/float64(maxLen) > 0.7 {
			d.DecryptedData = string(result.Data[:maxLen])
		} else {
			d.DecryptedData = fmt.Sprintf("[binary: %d bytes]", len(result.Data))
		}
	}

	return true
}
