package detector

import (
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
)

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
	payload := udp.Payload

	if len(payload) < RTPHeaderSize {
		return
	}

	// Check RTP header
	if !r.isRTPPacket(payload) {
		return
	}

	ipInfo := ExtractIPInfo(packet)
	if ipInfo == nil {
		return
	}

	timestamp := packet.Metadata().Timestamp
	r.parseRTPPacket(payload, ipInfo.SrcIP, ipInfo.DstIP, uint16(udp.SrcPort), uint16(udp.DstPort), timestamp)
}

func (r *RTPAnalyzer) isRTPPacket(payload []byte) bool {
	if len(payload) < RTPHeaderSize {
		return false
	}

	// Check RTP version (should be 2)
	version := (payload[0] >> 6) & 0x03
	if version != RTPVersion {
		return false
	}

	// Check payload type (should be valid)
	payloadType := payload[1] & 0x7F
	if payloadType > 127 {
		return false
	}

	// Additional heuristics to distinguish from other UDP traffic
	// RTP typically uses even port numbers, RTCP uses odd
	// Payload types 72-76 are reserved for RTCP

	return true
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
	return srcIP + ":" + string(rune(srcPort)) + "->" + dstIP + ":" + string(rune(dstPort)) + "/" + string(rune(ssrc))
}

// GetStreams returns all tracked RTP streams
func (r *RTPAnalyzer) GetStreams() map[string]*RTPStream {
	return r.streams
}

// GetStreamStats returns aggregate RTP statistics
func (r *RTPAnalyzer) GetStreamStats() (totalStreams int, totalPackets, totalBytes, totalLost uint64, avgJitter float64) {
	var jitterSum float64
	for _, stream := range r.streams {
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
