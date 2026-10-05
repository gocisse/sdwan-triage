// Package testpcap builds small, fully deterministic synthetic PCAP scenarios.
//
// The scenarios double as the learning-platform sample captures shipped with
// the web UI (see tools/generate_samples) and as golden regression fixtures for
// the analysis engine (see pkg/analyzer/golden_test.go). Because they are used
// as regression fixtures, generation must never depend on wall-clock time: all
// packets are stamped relative to BaseTime.
package testpcap

import (
	"encoding/binary"
	"io"
	"os"
	"time"
)

// BaseTime is the capture timestamp of the first packet in every scenario.
// It is fixed so that generated fixtures are byte-for-byte reproducible.
var BaseTime = time.Date(2024, time.January, 15, 12, 0, 0, 0, time.UTC)

// DefaultInterval is the spacing between consecutive packets.
const DefaultInterval = 100 * time.Millisecond

// PCAP file format constants
const (
	pcapMagic      = 0xa1b2c3d4
	pcapVersionMaj = 2
	pcapVersionMin = 4
	pcapSnapLen    = 65535
	pcapLinkType   = 1 // Ethernet
)

// TCP flags
const (
	FIN = 0x01
	SYN = 0x02
	RST = 0x04
	PSH = 0x08
	ACK = 0x10
)

// Well-known endpoints shared by all scenarios.
var (
	ClientMAC = []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}
	ServerMAC = []byte{0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee}
	ClientIP  = []byte{192, 168, 1, 100}
	ServerIP  = []byte{10, 0, 0, 50}
	DNSServer = []byte{8, 8, 8, 8}
	BFDPeer   = []byte{10, 0, 0, 1}
)

// Scenario is a named synthetic capture.
type Scenario struct {
	Name     string
	FileName string
	Generate func() [][]byte
}

// Scenarios returns every built-in scenario in a stable order.
func Scenarios() []Scenario {
	return []Scenario{
		{"handshake", "handshake.pcap", Handshake},
		{"mtu_issue", "mtu_issue.pcap", MTUIssue},
		{"dns_failure", "dns_failure.pcap", DNSFailure},
		{"bfd_tunnel_drop", "bfd_tunnel_drop.pcap", BFDTunnelDrop},
		{"retransmission_storm", "retransmission_storm.pcap", RetransmissionStorm},
		{"bgp_withdrawal_storm", "bgp_withdrawal_storm.pcap", BGPWithdrawalStorm},
	}
}

// WritePCAP writes packets as a classic little-endian pcap stream. Packet i is
// stamped base + i*interval.
func WritePCAP(w io.Writer, packets [][]byte, base time.Time, interval time.Duration) error {
	header := make([]byte, 24)
	binary.LittleEndian.PutUint32(header[0:4], pcapMagic)
	binary.LittleEndian.PutUint16(header[4:6], pcapVersionMaj)
	binary.LittleEndian.PutUint16(header[6:8], pcapVersionMin)
	binary.LittleEndian.PutUint32(header[8:12], 0)  // thiszone
	binary.LittleEndian.PutUint32(header[12:16], 0) // sigfigs
	binary.LittleEndian.PutUint32(header[16:20], pcapSnapLen)
	binary.LittleEndian.PutUint32(header[20:24], pcapLinkType)
	if _, err := w.Write(header); err != nil {
		return err
	}

	pktHeader := make([]byte, 16)
	for i, pkt := range packets {
		ts := base.Add(time.Duration(i) * interval)
		binary.LittleEndian.PutUint32(pktHeader[0:4], uint32(ts.Unix()))
		binary.LittleEndian.PutUint32(pktHeader[4:8], uint32(ts.Nanosecond()/1000))
		binary.LittleEndian.PutUint32(pktHeader[8:12], uint32(len(pkt)))
		binary.LittleEndian.PutUint32(pktHeader[12:16], uint32(len(pkt)))
		if _, err := w.Write(pktHeader); err != nil {
			return err
		}
		if _, err := w.Write(pkt); err != nil {
			return err
		}
	}
	return nil
}

// WriteFile writes packets to path using BaseTime and DefaultInterval.
func WriteFile(path string, packets [][]byte) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return WritePCAP(f, packets, BaseTime, DefaultInterval)
}

// ─── Packet Builders ──────────────────────────────────────────────

// BuildEthernet wraps payload in an Ethernet II frame.
func BuildEthernet(srcMAC, dstMAC []byte, etherType uint16, payload []byte) []byte {
	pkt := make([]byte, 14+len(payload))
	copy(pkt[0:6], dstMAC)
	copy(pkt[6:12], srcMAC)
	binary.BigEndian.PutUint16(pkt[12:14], etherType)
	copy(pkt[14:], payload)
	return pkt
}

// BuildIPv4 wraps payload in a minimal IPv4 header (checksum left zero).
func BuildIPv4(srcIP, dstIP []byte, protocol uint8, payload []byte) []byte {
	totalLen := 20 + len(payload)
	pkt := make([]byte, totalLen)
	pkt[0] = 0x45 // Version 4, IHL 5
	pkt[1] = 0    // DSCP/ECN
	binary.BigEndian.PutUint16(pkt[2:4], uint16(totalLen))
	binary.BigEndian.PutUint16(pkt[4:6], 0x1234) // ID
	pkt[6] = 0x40                                // Don't Fragment
	pkt[7] = 0
	pkt[8] = 64 // TTL
	pkt[9] = protocol
	// Checksum at 10:12 (leave as 0 for simplicity)
	copy(pkt[12:16], srcIP)
	copy(pkt[16:20], dstIP)
	copy(pkt[20:], payload)
	return pkt
}

// BuildTCP builds a TCP segment with a 20-byte header (checksum left zero).
func BuildTCP(srcPort, dstPort uint16, seq, ack uint32, flags uint8, window uint16, payload []byte) []byte {
	headerLen := 20
	pkt := make([]byte, headerLen+len(payload))
	binary.BigEndian.PutUint16(pkt[0:2], srcPort)
	binary.BigEndian.PutUint16(pkt[2:4], dstPort)
	binary.BigEndian.PutUint32(pkt[4:8], seq)
	binary.BigEndian.PutUint32(pkt[8:12], ack)
	pkt[12] = byte(headerLen/4) << 4 // Data offset
	pkt[13] = flags
	binary.BigEndian.PutUint16(pkt[14:16], window)
	// Checksum at 16:18, Urgent at 18:20 (leave as 0)
	copy(pkt[20:], payload)
	return pkt
}

// BuildUDP builds a UDP datagram (checksum left zero).
func BuildUDP(srcPort, dstPort uint16, payload []byte) []byte {
	pkt := make([]byte, 8+len(payload))
	binary.BigEndian.PutUint16(pkt[0:2], srcPort)
	binary.BigEndian.PutUint16(pkt[2:4], dstPort)
	binary.BigEndian.PutUint16(pkt[4:6], uint16(8+len(payload)))
	// Checksum at 6:8 (leave as 0)
	copy(pkt[8:], payload)
	return pkt
}

// TCPFrame is a convenience wrapper: Ethernet+IPv4+TCP in one call.
func TCPFrame(srcMAC, dstMAC, srcIP, dstIP []byte, srcPort, dstPort uint16, seq, ack uint32, flags uint8, payload []byte) []byte {
	tcp := BuildTCP(srcPort, dstPort, seq, ack, flags, 65535, payload)
	ip := BuildIPv4(srcIP, dstIP, 6, tcp)
	return BuildEthernet(srcMAC, dstMAC, 0x0800, ip)
}

// UDPFrame is a convenience wrapper: Ethernet+IPv4+UDP in one call.
func UDPFrame(srcMAC, dstMAC, srcIP, dstIP []byte, srcPort, dstPort uint16, payload []byte) []byte {
	udp := BuildUDP(srcPort, dstPort, payload)
	ip := BuildIPv4(srcIP, dstIP, 17, udp)
	return BuildEthernet(srcMAC, dstMAC, 0x0800, ip)
}

// ─── Sample Generators ────────────────────────────────────────────

// Handshake is a clean SYN / SYN-ACK / ACK followed by one request and its ACK.
// It must produce NO retransmission, loss, or failure findings.
func Handshake() [][]byte {
	var packets [][]byte
	c2s := func(seq, ack uint32, flags uint8, payload []byte) []byte {
		return TCPFrame(ClientMAC, ServerMAC, ClientIP, ServerIP, 50000, 443, seq, ack, flags, payload)
	}
	s2c := func(seq, ack uint32, flags uint8, payload []byte) []byte {
		return TCPFrame(ServerMAC, ClientMAC, ServerIP, ClientIP, 443, 50000, seq, ack, flags, payload)
	}

	packets = append(packets, c2s(1000, 0, SYN, nil))
	packets = append(packets, s2c(2000, 1001, SYN|ACK, nil))
	packets = append(packets, c2s(1001, 2001, ACK, nil))

	data := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
	packets = append(packets, c2s(1001, 2001, PSH|ACK, data))
	packets = append(packets, s2c(2001, 1001+uint32(len(data)), ACK, nil))
	return packets
}

// MTUIssue models a PMTUD black hole: a small server segment succeeds, a
// 1460-byte segment is (re)transmitted three times and never acknowledged.
func MTUIssue() [][]byte {
	var packets [][]byte
	c2s := func(seq, ack uint32, flags uint8, payload []byte) []byte {
		return TCPFrame(ClientMAC, ServerMAC, ClientIP, ServerIP, 50001, 80, seq, ack, flags, payload)
	}
	s2c := func(seq, ack uint32, flags uint8, payload []byte) []byte {
		return TCPFrame(ServerMAC, ClientMAC, ServerIP, ClientIP, 80, 50001, seq, ack, flags, payload)
	}

	packets = append(packets, c2s(1000, 0, SYN, nil))
	packets = append(packets, s2c(2000, 1001, SYN|ACK, nil))
	packets = append(packets, c2s(1001, 2001, ACK, nil))

	// Small packet succeeds
	smallData := make([]byte, 100)
	packets = append(packets, s2c(2001, 1001, PSH|ACK, smallData))
	packets = append(packets, c2s(1001, 2101, ACK, nil))

	// Large packet (1460 bytes) is dropped and retransmitted twice
	largeData := make([]byte, 1460)
	large := s2c(2101, 1001, PSH|ACK, largeData)
	packets = append(packets, large, large, large)
	return packets
}

// DNSFailure is one A query for example.com sent four times to 8.8.8.8 with
// no response at all.
func DNSFailure() [][]byte {
	dnsQuery := []byte{
		0x12, 0x34, // Transaction ID
		0x01, 0x00, // Flags: Standard query
		0x00, 0x01, // Questions: 1
		0x00, 0x00, // Answers: 0
		0x00, 0x00, // Authority: 0
		0x00, 0x00, // Additional: 0
		// Query: example.com
		0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
		0x03, 'c', 'o', 'm',
		0x00,       // Root
		0x00, 0x01, // Type A
		0x00, 0x01, // Class IN
	}
	q := UDPFrame(ClientMAC, ServerMAC, ClientIP, DNSServer, 53000, 53, dnsQuery)
	return [][]byte{q, q, q, q}
}

// BFDControl returns a minimal RFC 5880 BFD v1 control packet with the given
// state byte (state occupies the top two bits: Up=0xC0, Down=0x40, Init=0x80).
func BFDControl(stateByte byte) []byte {
	return []byte{
		0x20,                   // Version 1, Diag 0
		stateByte,              // State | flags
		0x03,                   // Detect Mult = 3
		0x18,                   // Length = 24
		0x00, 0x00, 0x00, 0x01, // My Discriminator
		0x00, 0x00, 0x00, 0x02, // Your Discriminator
		0x00, 0x04, 0x93, 0xe0, // Desired Min TX Interval (300ms)
		0x00, 0x04, 0x93, 0xe0, // Required Min RX Interval
		0x00, 0x00, 0x00, 0x00, // Required Min Echo RX Interval
	}
}

// BFDTunnelDrop is a healthy bidirectional BFD session that goes one-way and
// then transitions Up→Down once. It must produce a single "BFD Session Down"
// stability finding (not a flapping finding).
func BFDTunnelDrop() [][]byte {
	var packets [][]byte
	const bfdUp, bfdDown = 0xC0, 0x40

	for i := 0; i < 5; i++ {
		packets = append(packets, UDPFrame(ClientMAC, ServerMAC, ClientIP, BFDPeer, 49152, 3784, BFDControl(bfdUp)))
		packets = append(packets, UDPFrame(ServerMAC, ClientMAC, BFDPeer, ClientIP, 3784, 49152, BFDControl(bfdUp)))
	}
	// Peer stops responding; our side keeps sending
	for i := 0; i < 4; i++ {
		packets = append(packets, UDPFrame(ClientMAC, ServerMAC, ClientIP, BFDPeer, 49152, 3784, BFDControl(bfdUp)))
	}
	// Session goes Down
	packets = append(packets, UDPFrame(ClientMAC, ServerMAC, ClientIP, BFDPeer, 49152, 3784, BFDControl(bfdDown)))
	return packets
}

// BGPPeer is the neighbour used by the BGP scenario.
var BGPPeer = []byte{10, 0, 0, 2}

// BGPUpdateWithdrawal returns a BGP UPDATE (type 2) withdrawing one /24.
// Withdrawn Routes Length = 4 (prefix length byte + 3 prefix bytes),
// Total Path Attribute Length = 0. Message length = 19 + 2 + 4 + 2 = 27.
func BGPUpdateWithdrawal(prefix [3]byte) []byte {
	msg := make([]byte, 0, 27)
	for i := 0; i < 16; i++ {
		msg = append(msg, 0xFF) // marker
	}
	msg = append(msg, 0x00, 27) // length
	msg = append(msg, 0x02)     // type: UPDATE
	msg = append(msg, 0x00, 0x04)
	msg = append(msg, 24, prefix[0], prefix[1], prefix[2]) // withdrawn /24
	msg = append(msg, 0x00, 0x00)                          // path attribute length
	return msg
}

// BGPWithdrawalStorm is the underlay/overlay correlation scenario:
//
//	pkt 0      BGP UPDATE withdrawal from 10.0.0.2 -> 192.168.1.100 (underlay event, t=0)
//	pkt 1-2    filler
//	pkt 3,6    SYN / SYN-ACK 300 ms apart (RTT spike >= 200 ms) + ACK at pkt 7
//	pkt 8..    five 1000-byte segments each retransmitted once (five retransmissions
//	           within the 5 s correlation window after the BGP event)
func BGPWithdrawalStorm() [][]byte {
	var packets [][]byte
	packets = append(packets, TCPFrame(ServerMAC, ClientMAC, BGPPeer, ClientIP, 179, 40179, 5000, 6000, PSH|ACK,
		BGPUpdateWithdrawal([3]byte{192, 168, 50})))
	filler := UDPFrame(ClientMAC, ServerMAC, ClientIP, ServerIP, 40000, 40001, []byte("x"))
	packets = append(packets, filler, filler)

	c2s := func(seq, ack uint32, flags uint8, payload []byte) []byte {
		return TCPFrame(ClientMAC, ServerMAC, ClientIP, ServerIP, 50003, 443, seq, ack, flags, payload)
	}
	s2c := func(seq, ack uint32, flags uint8, payload []byte) []byte {
		return TCPFrame(ServerMAC, ClientMAC, ServerIP, ClientIP, 443, 50003, seq, ack, flags, payload)
	}
	packets = append(packets, c2s(1000, 0, SYN, nil)) // pkt 3
	packets = append(packets, filler, filler)         // 200 ms of nothing
	packets = append(packets, s2c(2000, 1001, SYN|ACK, nil))
	packets = append(packets, c2s(1001, 2001, ACK, nil))

	data := make([]byte, 1000)
	seq := uint32(1001)
	for i := 0; i < 5; i++ {
		packets = append(packets, c2s(seq, 2001, PSH|ACK, data))
		packets = append(packets, s2c(2001, seq, ACK, nil))
		packets = append(packets, c2s(seq, 2001, PSH|ACK, data)) // retransmission
		seq += uint32(len(data))
		packets = append(packets, s2c(2001, seq, ACK, nil))
	}
	return packets
}

// RetransmissionStorm is a handshake followed by five 1000-byte segments that
// are each retransmitted once after three duplicate ACKs.
func RetransmissionStorm() [][]byte {
	var packets [][]byte
	c2s := func(seq, ack uint32, flags uint8, payload []byte) []byte {
		return TCPFrame(ClientMAC, ServerMAC, ClientIP, ServerIP, 50002, 443, seq, ack, flags, payload)
	}
	s2c := func(seq, ack uint32, flags uint8, payload []byte) []byte {
		return TCPFrame(ServerMAC, ClientMAC, ServerIP, ClientIP, 443, 50002, seq, ack, flags, payload)
	}

	packets = append(packets, c2s(1000, 0, SYN, nil))
	packets = append(packets, s2c(2000, 1001, SYN|ACK, nil))
	packets = append(packets, c2s(1001, 2001, ACK, nil))

	data := make([]byte, 1000)
	seq := uint32(1001)
	for i := 0; i < 5; i++ {
		packets = append(packets, c2s(seq, 2001, PSH|ACK, data))
		for j := 0; j < 3; j++ { // duplicate ACKs
			packets = append(packets, s2c(2001, seq, ACK, nil))
		}
		packets = append(packets, c2s(seq, 2001, PSH|ACK, data)) // retransmission
		seq += uint32(len(data))
		packets = append(packets, s2c(2001, seq, ACK, nil))
	}
	return packets
}
