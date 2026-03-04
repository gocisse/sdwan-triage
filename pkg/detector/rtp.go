package detector

import (
	"fmt"
	"time"

	"github.com/gocisse/sdwan-triage/pkg/models"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// RTP header constants
const (
	RTPVersion     = 2
	RTPHeaderSize  = 12
	RTCPHeaderSize = 8

	// Minimum packets required before a stream is considered real RTP.
	// Single-packet "streams" are almost always false positives.
	minRTPStreamPackets = 5
)

// wellKnownServicePorts contains UDP ports that must never be classified as
// RTP unless explicit SIP/SDP signaling is observed (which we do not track
// in this heuristic detector). Query-response protocols on these ports
// frequently produce payloads whose first bytes accidentally satisfy the
// loose "version == 2" RTP check.
var wellKnownServicePorts = map[uint16]bool{
	53:   true, // DNS
	67:   true, // DHCP server
	68:   true, // DHCP client
	123:  true, // NTP
	161:  true, // SNMP
	162:  true, // SNMP Trap
	443:  true, // QUIC / HTTPS-over-UDP
	500:  true, // IKE (IPsec)
	514:  true, // Syslog
	520:  true, // RIP
	1194: true, // OpenVPN
	1985: true, // HSRP
	3784: true, // BFD
	4500: true, // IPsec NAT-T
	4789: true, // VXLAN
	4790: true, // VXLAN-GPE
	6081: true, // Geneve
	8472: true, // Linux VXLAN
}

// knownPublicDNSResolvers contains IPs that are definitively not VoIP
// endpoints. Streams involving these IPs are suppressed.
var knownPublicDNSResolvers = map[string]bool{
	"8.8.8.8":         true, // Google
	"8.8.4.4":         true, // Google
	"1.1.1.1":         true, // Cloudflare
	"1.0.0.1":         true, // Cloudflare
	"9.9.9.9":         true, // Quad9
	"149.112.112.112": true, // Quad9
	"208.67.222.222":  true, // OpenDNS
	"208.67.220.220":  true, // OpenDNS
	"4.2.2.1":         true, // Level3
	"4.2.2.2":         true, // Level3
}

// Common RTP payload types
var rtpPayloadTypes = map[uint8]string{
	0:   "PCMU (G.711 μ-law)",
	3:   "GSM",
	4:   "G723",
	8:   "PCMA (G.711 A-law)",
	9:   "G722",
	18:  "G729",
	26:  "JPEG",
	31:  "H261",
	32:  "MPV",
	33:  "MP2T",
	34:  "H263",
	96:  "Dynamic (96)",
	97:  "Dynamic (97)",
	98:  "Dynamic (98)",
	99:  "Dynamic (99)",
	100: "Dynamic (100)",
	101: "Dynamic (101)",
	102: "Dynamic (102)",
	103: "Dynamic (103)",
	104: "Dynamic (104)",
	105: "Dynamic (105)",
	106: "Dynamic (106)",
	107: "Dynamic (107)",
	108: "Dynamic (108)",
	109: "Dynamic (109)",
	110: "Dynamic (110)",
	111: "Dynamic (111)",
	112: "Dynamic (112)",
	113: "Dynamic (113)",
	114: "Dynamic (114)",
	115: "Dynamic (115)",
	116: "Dynamic (116)",
	117: "Dynamic (117)",
	118: "Dynamic (118)",
	119: "Dynamic (119)",
	120: "Dynamic (120)",
	121: "Dynamic (121)",
	122: "Dynamic (122)",
	123: "Dynamic (123)",
	124: "Dynamic (124)",
	125: "Dynamic (125)",
	126: "Dynamic (126)",
	127: "Dynamic (127)",
}

// RTPAnalyzer handles RTP/RTCP traffic analysis
type RTPAnalyzer struct {
	streams map[string]*RTPStream
}

// RTPStream represents an RTP media stream
type RTPStream struct {
	SSRC          uint32
	SrcIP         string
	DstIP         string
	SrcPort       uint16
	DstPort       uint16
	PayloadType   uint8
	PayloadName   string
	FirstSeen     time.Time
	LastSeen      time.Time
	PacketCount   uint64
	ByteCount     uint64
	LastSeq       uint16
	LostPackets   uint64
	OutOfOrder    uint64
	Jitter        float64
	LastTimestamp uint32
	LastArrival   time.Time
}

// NewRTPAnalyzer creates a new RTP analyzer
func NewRTPAnalyzer() *RTPAnalyzer {
	return &RTPAnalyzer{
		streams: make(map[string]*RTPStream),
	}
}

// Analyze processes packets for RTP/RTCP traffic
func (r *RTPAnalyzer) Analyze(packet gopacket.Packet, state *models.AnalysisState, report *models.TriageReport) {
	udpLayer := packet.Layer(layers.LayerTypeUDP)
	if udpLayer == nil {
		return
	}

	udp := udpLayer.(*layers.UDP)
	srcPort := uint16(udp.SrcPort)
	dstPort := uint16(udp.DstPort)

	// ── Gate 1: Exclude well-known service ports ────────────────
	if wellKnownServicePorts[srcPort] || wellKnownServicePorts[dstPort] {
		return
	}

	payload := udp.Payload
	if len(payload) < RTPHeaderSize {
		return
	}

	// ── Gate 2: Strict RTP header validation ─────────────────────
	if !r.isRTPPacket(payload) {
		return
	}

	ipInfo := ExtractIPInfo(packet)
	if ipInfo == nil {
		return
	}

	// ── Gate 3: Exclude known public DNS resolvers ───────────────
	if knownPublicDNSResolvers[ipInfo.SrcIP] || knownPublicDNSResolvers[ipInfo.DstIP] {
		return
	}

	timestamp := packet.Metadata().Timestamp
	r.parseRTPPacket(payload, ipInfo.SrcIP, ipInfo.DstIP, srcPort, dstPort, timestamp)
}

func (r *RTPAnalyzer) isRTPPacket(payload []byte) bool {
	if len(payload) < RTPHeaderSize {
		return false
	}

	// ── Check 1: RTP version must be 2 ──────────────────────────
	version := (payload[0] >> 6) & 0x03
	if version != RTPVersion {
		return false
	}

	// ── Check 2: CSRC count sanity — CC field (4 bits) ──────────
	// Each CSRC adds 4 bytes; the total header must fit in the payload.
	cc := payload[0] & 0x0F
	requiredLen := RTPHeaderSize + int(cc)*4
	if len(payload) < requiredLen {
		return false
	}

	// ── Check 3: Payload type must be in a valid range ──────────
	pt := payload[1] & 0x7F
	if !isValidRTPPayloadType(pt) {
		return false
	}

	// ── Check 4: Payload must carry actual media data ───────────
	// A real RTP audio frame has data beyond the header. DNS answers
	// that accidentally match version=2 often have only ~12 bytes
	// of "payload" once you subtract the UDP header.
	minMediaBytes := 10 // even the smallest G.729 frame is 10 bytes
	if len(payload) < requiredLen+minMediaBytes {
		return false
	}

	// ── Check 5: Sequence number should not be zero ─────────────
	// Zero seq + zero timestamp + zero SSRC is highly unlikely for
	// real media but common in protocol control messages.
	seqNum := uint16(payload[2])<<8 | uint16(payload[3])
	rtpTS := uint32(payload[4])<<24 | uint32(payload[5])<<16 | uint32(payload[6])<<8 | uint32(payload[7])
	ssrc := uint32(payload[8])<<24 | uint32(payload[9])<<16 | uint32(payload[10])<<8 | uint32(payload[11])
	if seqNum == 0 && rtpTS == 0 && ssrc == 0 {
		return false
	}

	return true
}

// isValidRTPPayloadType returns true only for payload types defined in
// RFC 3551 (static audio/video 0-34) or the dynamic range (96-127).
// PTs 35-71 are unassigned, 72-76 overlap with RTCP packet types,
// and 77-95 are unassigned — all rejected.
func isValidRTPPayloadType(pt uint8) bool {
	if pt <= 34 {
		return true // static audio/video types
	}
	if pt >= 96 && pt <= 127 {
		return true // dynamic types
	}
	return false
}

func (r *RTPAnalyzer) parseRTPPacket(payload []byte, srcIP, dstIP string, srcPort, dstPort uint16, timestamp time.Time) {
	// RTP Header structure:
	// 0                   1                   2                   3
	// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |V=2|P|X|  CC   |M|     PT      |       sequence number         |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |                           timestamp                           |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |           synchronization source (SSRC) identifier            |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

	payloadType := payload[1] & 0x7F
	seqNum := uint16(payload[2])<<8 | uint16(payload[3])
	rtpTimestamp := uint32(payload[4])<<24 | uint32(payload[5])<<16 | uint32(payload[6])<<8 | uint32(payload[7])
	ssrc := uint32(payload[8])<<24 | uint32(payload[9])<<16 | uint32(payload[10])<<8 | uint32(payload[11])

	// Create stream key
	streamKey := r.getStreamKey(srcIP, dstIP, srcPort, dstPort, ssrc)

	stream, exists := r.streams[streamKey]
	if !exists {
		payloadName := rtpPayloadTypes[payloadType]
		if payloadName == "" {
			payloadName = "Unknown"
		}

		stream = &RTPStream{
			SSRC:          ssrc,
			SrcIP:         srcIP,
			DstIP:         dstIP,
			SrcPort:       srcPort,
			DstPort:       dstPort,
			PayloadType:   payloadType,
			PayloadName:   payloadName,
			FirstSeen:     timestamp,
			LastSeen:      timestamp,
			PacketCount:   0,
			LastSeq:       seqNum,
			LastTimestamp: rtpTimestamp,
			LastArrival:   timestamp,
		}
		r.streams[streamKey] = stream
	}

	// Update stream statistics
	stream.PacketCount++
	stream.ByteCount += uint64(len(payload))
	stream.LastSeen = timestamp

	// Calculate packet loss
	if exists {
		expectedSeq := stream.LastSeq + 1
		if seqNum != expectedSeq {
			if seqNum > expectedSeq {
				// Packets lost
				stream.LostPackets += uint64(seqNum - expectedSeq)
			} else if seqNum < stream.LastSeq-1000 {
				// Sequence number wrapped or out of order
				stream.OutOfOrder++
			}
		}

		// Calculate jitter (simplified RFC 3550 algorithm)
		if stream.PacketCount > 1 {
			arrivalDiff := timestamp.Sub(stream.LastArrival).Seconds() * 8000 // Assuming 8kHz sample rate
			timestampDiff := float64(rtpTimestamp - stream.LastTimestamp)
			d := arrivalDiff - timestampDiff
			if d < 0 {
				d = -d
			}
			stream.Jitter = stream.Jitter + (d-stream.Jitter)/16
		}
	}

	stream.LastSeq = seqNum
	stream.LastTimestamp = rtpTimestamp
	stream.LastArrival = timestamp
}

func (r *RTPAnalyzer) getStreamKey(srcIP, dstIP string, srcPort, dstPort uint16, ssrc uint32) string {
	return fmt.Sprintf("%s:%d->%s:%d/%d", srcIP, srcPort, dstIP, dstPort, ssrc)
}

// GetStreams returns RTP streams that meet the minimum packet threshold.
// Streams with fewer than minRTPStreamPackets are suppressed as likely
// false positives (single DNS response, stray NTP packet, etc.).
func (r *RTPAnalyzer) GetStreams() map[string]*RTPStream {
	filtered := make(map[string]*RTPStream, len(r.streams))
	for k, s := range r.streams {
		if s.PacketCount >= minRTPStreamPackets {
			filtered[k] = s
		}
	}
	return filtered
}

// GetStreamStats returns aggregate RTP statistics (only for streams
// that meet the minimum packet threshold).
func (r *RTPAnalyzer) GetStreamStats() (totalStreams int, totalPackets, totalBytes, totalLost uint64, avgJitter float64) {
	var jitterSum float64
	for _, stream := range r.streams {
		if stream.PacketCount < minRTPStreamPackets {
			continue
		}
		totalStreams++
		totalPackets += stream.PacketCount
		totalBytes += stream.ByteCount
		totalLost += stream.LostPackets
		jitterSum += stream.Jitter
	}
	if totalStreams > 0 {
		avgJitter = jitterSum / float64(totalStreams)
	}
	return
}
