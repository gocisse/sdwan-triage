// generate_samples generates small sample PCAP files for the learning platform.
// Run with: go run tools/generate_samples/main.go
package main

import (
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// PCAP file format constants
const (
	pcapMagic     = 0xa1b2c3d4
	pcapVersionMaj = 2
	pcapVersionMin = 4
	pcapSnapLen   = 65535
	pcapLinkType  = 1 // Ethernet
)

func main() {
	outputDir := "web/frontend/public/samples"
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		fmt.Printf("Error creating output directory: %v\n", err)
		os.Exit(1)
	}

	samples := []struct {
		name     string
		generate func() [][]byte
	}{
		{"handshake.pcap", generateHandshake},
		{"mtu_issue.pcap", generateMTUIssue},
		{"dns_failure.pcap", generateDNSFailure},
		{"bfd_tunnel_drop.pcap", generateBFDTunnelDrop},
		{"retransmission_storm.pcap", generateRetransmissionStorm},
	}

	for _, s := range samples {
		path := filepath.Join(outputDir, s.name)
		packets := s.generate()
		if err := writePCAP(path, packets); err != nil {
			fmt.Printf("Error writing %s: %v\n", s.name, err)
			continue
		}
		fmt.Printf("Generated %s (%d packets)\n", s.name, len(packets))
	}

	fmt.Println("\nAll sample PCAPs generated successfully!")
}

func writePCAP(path string, packets [][]byte) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	// Write PCAP global header
	header := make([]byte, 24)
	binary.LittleEndian.PutUint32(header[0:4], pcapMagic)
	binary.LittleEndian.PutUint16(header[4:6], pcapVersionMaj)
	binary.LittleEndian.PutUint16(header[6:8], pcapVersionMin)
	binary.LittleEndian.PutUint32(header[8:12], 0)  // thiszone
	binary.LittleEndian.PutUint32(header[12:16], 0) // sigfigs
	binary.LittleEndian.PutUint32(header[16:20], pcapSnapLen)
	binary.LittleEndian.PutUint32(header[20:24], pcapLinkType)
	if _, err := f.Write(header); err != nil {
		return err
	}

	// Write each packet
	baseTime := time.Now()
	for i, pkt := range packets {
		ts := baseTime.Add(time.Duration(i*100) * time.Millisecond)
		pktHeader := make([]byte, 16)
		binary.LittleEndian.PutUint32(pktHeader[0:4], uint32(ts.Unix()))
		binary.LittleEndian.PutUint32(pktHeader[4:8], uint32(ts.Nanosecond()/1000))
		binary.LittleEndian.PutUint32(pktHeader[8:12], uint32(len(pkt)))
		binary.LittleEndian.PutUint32(pktHeader[12:16], uint32(len(pkt)))
		if _, err := f.Write(pktHeader); err != nil {
			return err
		}
		if _, err := f.Write(pkt); err != nil {
			return err
		}
	}

	return nil
}

// ─── Packet Builders ──────────────────────────────────────────────

func buildEthernet(srcMAC, dstMAC []byte, etherType uint16, payload []byte) []byte {
	pkt := make([]byte, 14+len(payload))
	copy(pkt[0:6], dstMAC)
	copy(pkt[6:12], srcMAC)
	binary.BigEndian.PutUint16(pkt[12:14], etherType)
	copy(pkt[14:], payload)
	return pkt
}

func buildIPv4(srcIP, dstIP []byte, protocol uint8, payload []byte) []byte {
	totalLen := 20 + len(payload)
	pkt := make([]byte, totalLen)
	pkt[0] = 0x45 // Version 4, IHL 5
	pkt[1] = 0    // DSCP/ECN
	binary.BigEndian.PutUint16(pkt[2:4], uint16(totalLen))
	binary.BigEndian.PutUint16(pkt[4:6], 0x1234) // ID
	pkt[6] = 0x40 // Don't Fragment
	pkt[7] = 0
	pkt[8] = 64 // TTL
	pkt[9] = protocol
	// Checksum at 10:12 (leave as 0 for simplicity)
	copy(pkt[12:16], srcIP)
	copy(pkt[16:20], dstIP)
	copy(pkt[20:], payload)
	return pkt
}

func buildTCP(srcPort, dstPort uint16, seq, ack uint32, flags uint8, window uint16, payload []byte) []byte {
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

func buildUDP(srcPort, dstPort uint16, payload []byte) []byte {
	pkt := make([]byte, 8+len(payload))
	binary.BigEndian.PutUint16(pkt[0:2], srcPort)
	binary.BigEndian.PutUint16(pkt[2:4], dstPort)
	binary.BigEndian.PutUint16(pkt[4:6], uint16(8+len(payload)))
	// Checksum at 6:8 (leave as 0)
	copy(pkt[8:], payload)
	return pkt
}

// TCP flags
const (
	FIN = 0x01
	SYN = 0x02
	RST = 0x04
	PSH = 0x08
	ACK = 0x10
)

var (
	clientMAC = []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}
	serverMAC = []byte{0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee}
	clientIP  = []byte{192, 168, 1, 100}
	serverIP  = []byte{10, 0, 0, 50}
)

// ─── Sample Generators ────────────────────────────────────────────

func generateHandshake() [][]byte {
	var packets [][]byte

	// SYN
	tcp := buildTCP(50000, 443, 1000, 0, SYN, 65535, nil)
	ip := buildIPv4(clientIP, serverIP, 6, tcp)
	packets = append(packets, buildEthernet(clientMAC, serverMAC, 0x0800, ip))

	// SYN-ACK
	tcp = buildTCP(443, 50000, 2000, 1001, SYN|ACK, 65535, nil)
	ip = buildIPv4(serverIP, clientIP, 6, tcp)
	packets = append(packets, buildEthernet(serverMAC, clientMAC, 0x0800, ip))

	// ACK
	tcp = buildTCP(50000, 443, 1001, 2001, ACK, 65535, nil)
	ip = buildIPv4(clientIP, serverIP, 6, tcp)
	packets = append(packets, buildEthernet(clientMAC, serverMAC, 0x0800, ip))

	// Data packet
	data := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
	tcp = buildTCP(50000, 443, 1001, 2001, PSH|ACK, 65535, data)
	ip = buildIPv4(clientIP, serverIP, 6, tcp)
	packets = append(packets, buildEthernet(clientMAC, serverMAC, 0x0800, ip))

	// ACK from server
	tcp = buildTCP(443, 50000, 2001, 1001+uint32(len(data)), ACK, 65535, nil)
	ip = buildIPv4(serverIP, clientIP, 6, tcp)
	packets = append(packets, buildEthernet(serverMAC, clientMAC, 0x0800, ip))

	return packets
}

func generateMTUIssue() [][]byte {
	var packets [][]byte

	// Handshake
	tcp := buildTCP(50001, 80, 1000, 0, SYN, 65535, nil)
	ip := buildIPv4(clientIP, serverIP, 6, tcp)
	packets = append(packets, buildEthernet(clientMAC, serverMAC, 0x0800, ip))

	tcp = buildTCP(80, 50001, 2000, 1001, SYN|ACK, 65535, nil)
	ip = buildIPv4(serverIP, clientIP, 6, tcp)
	packets = append(packets, buildEthernet(serverMAC, clientMAC, 0x0800, ip))

	tcp = buildTCP(50001, 80, 1001, 2001, ACK, 65535, nil)
	ip = buildIPv4(clientIP, serverIP, 6, tcp)
	packets = append(packets, buildEthernet(clientMAC, serverMAC, 0x0800, ip))

	// Small packet succeeds
	smallData := make([]byte, 100)
	tcp = buildTCP(80, 50001, 2001, 1001, PSH|ACK, 65535, smallData)
	ip = buildIPv4(serverIP, clientIP, 6, tcp)
	packets = append(packets, buildEthernet(serverMAC, clientMAC, 0x0800, ip))

	tcp = buildTCP(50001, 80, 1001, 2101, ACK, 65535, nil)
	ip = buildIPv4(clientIP, serverIP, 6, tcp)
	packets = append(packets, buildEthernet(clientMAC, serverMAC, 0x0800, ip))

	// Large packet (1460 bytes) - this would be dropped
	largeData := make([]byte, 1460)
	tcp = buildTCP(80, 50001, 2101, 1001, PSH|ACK, 65535, largeData)
	ip = buildIPv4(serverIP, clientIP, 6, tcp)
	packets = append(packets, buildEthernet(serverMAC, clientMAC, 0x0800, ip))

	// Retransmission of large packet (simulating drop)
	packets = append(packets, buildEthernet(serverMAC, clientMAC, 0x0800, ip))
	packets = append(packets, buildEthernet(serverMAC, clientMAC, 0x0800, ip))

	return packets
}

func generateDNSFailure() [][]byte {
	var packets [][]byte

	// DNS query for example.com
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

	dnsServer := []byte{8, 8, 8, 8}

	// First query
	udp := buildUDP(53000, 53, dnsQuery)
	ip := buildIPv4(clientIP, dnsServer, 17, udp)
	packets = append(packets, buildEthernet(clientMAC, serverMAC, 0x0800, ip))

	// Retry 1 (no response)
	packets = append(packets, buildEthernet(clientMAC, serverMAC, 0x0800, ip))

	// Retry 2
	packets = append(packets, buildEthernet(clientMAC, serverMAC, 0x0800, ip))

	// Retry 3
	packets = append(packets, buildEthernet(clientMAC, serverMAC, 0x0800, ip))

	return packets
}

func generateBFDTunnelDrop() [][]byte {
	var packets [][]byte

	bfdPeer := []byte{10, 0, 0, 1}

	// BFD packet structure (simplified)
	bfdPacket := func(state byte) []byte {
		return []byte{
			0x20,  // Version 1, Diag 0
			state, // State (3=Up, 1=Down)
			0x03,  // Detect Mult = 3
			0x18,  // Length = 24
			// My Discriminator
			0x00, 0x00, 0x00, 0x01,
			// Your Discriminator
			0x00, 0x00, 0x00, 0x02,
			// Desired Min TX Interval (300ms = 300000 µs)
			0x00, 0x04, 0x93, 0xe0,
			// Required Min RX Interval
			0x00, 0x04, 0x93, 0xe0,
			// Required Min Echo RX Interval
			0x00, 0x00, 0x00, 0x00,
		}
	}

	// Normal BFD keepalives (state = Up = 0xC0)
	for i := 0; i < 5; i++ {
		udp := buildUDP(49152, 3784, bfdPacket(0xC0))
		ip := buildIPv4(clientIP, bfdPeer, 17, udp)
		packets = append(packets, buildEthernet(clientMAC, serverMAC, 0x0800, ip))

		udp = buildUDP(3784, 49152, bfdPacket(0xC0))
		ip = buildIPv4(bfdPeer, clientIP, 17, udp)
		packets = append(packets, buildEthernet(serverMAC, clientMAC, 0x0800, ip))
	}

	// Peer stops responding (simulating link failure)
	// Our side keeps sending
	for i := 0; i < 4; i++ {
		udp := buildUDP(49152, 3784, bfdPacket(0xC0))
		ip := buildIPv4(clientIP, bfdPeer, 17, udp)
		packets = append(packets, buildEthernet(clientMAC, serverMAC, 0x0800, ip))
	}

	// Session goes Down
	udp := buildUDP(49152, 3784, bfdPacket(0x40)) // State = Down
	ip := buildIPv4(clientIP, bfdPeer, 17, udp)
	packets = append(packets, buildEthernet(clientMAC, serverMAC, 0x0800, ip))

	return packets
}

func generateRetransmissionStorm() [][]byte {
	var packets [][]byte

	// Handshake
	tcp := buildTCP(50002, 443, 1000, 0, SYN, 65535, nil)
	ip := buildIPv4(clientIP, serverIP, 6, tcp)
	packets = append(packets, buildEthernet(clientMAC, serverMAC, 0x0800, ip))

	tcp = buildTCP(443, 50002, 2000, 1001, SYN|ACK, 65535, nil)
	ip = buildIPv4(serverIP, clientIP, 6, tcp)
	packets = append(packets, buildEthernet(serverMAC, clientMAC, 0x0800, ip))

	tcp = buildTCP(50002, 443, 1001, 2001, ACK, 65535, nil)
	ip = buildIPv4(clientIP, serverIP, 6, tcp)
	packets = append(packets, buildEthernet(clientMAC, serverMAC, 0x0800, ip))

	// Data transfer with losses
	data := make([]byte, 1000)
	seq := uint32(1001)

	for i := 0; i < 5; i++ {
		// Send data
		tcp = buildTCP(50002, 443, seq, 2001, PSH|ACK, 65535, data)
		ip = buildIPv4(clientIP, serverIP, 6, tcp)
		packets = append(packets, buildEthernet(clientMAC, serverMAC, 0x0800, ip))

		// Duplicate ACKs (indicating packet loss)
		for j := 0; j < 3; j++ {
			tcp = buildTCP(443, 50002, 2001, seq, ACK, 65535, nil)
			ip = buildIPv4(serverIP, clientIP, 6, tcp)
			packets = append(packets, buildEthernet(serverMAC, clientMAC, 0x0800, ip))
		}

		// Retransmission
		tcp = buildTCP(50002, 443, seq, 2001, PSH|ACK, 65535, data)
		ip = buildIPv4(clientIP, serverIP, 6, tcp)
		packets = append(packets, buildEthernet(clientMAC, serverMAC, 0x0800, ip))

		// ACK
		seq += uint32(len(data))
		tcp = buildTCP(443, 50002, 2001, seq, ACK, 65535, nil)
		ip = buildIPv4(serverIP, clientIP, 6, tcp)
		packets = append(packets, buildEthernet(serverMAC, clientMAC, 0x0800, ip))
	}

	return packets
}
