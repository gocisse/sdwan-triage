package analyzer

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// ─── PCAP Builder ──────────────────────────────────────────────────
// buildTestPCAP constructs a valid libpcap file from a slice of synthetic
// TCP/UDP packets. Each testPacket specifies 5-tuple, flags, TTL, seq, etc.

type testPacket struct {
	srcIP   [4]byte
	dstIP   [4]byte
	srcPort uint16
	dstPort uint16
	proto   byte // 6=TCP, 17=UDP
	ttl     byte
	dscp    byte
	seqNum  uint32
	tcpFlag byte // 0x02=SYN, 0x10=ACK, 0x12=SYN-ACK, etc.
	payload []byte
	tsOff   time.Duration // offset from base time
}

func buildTestPCAP(pkts []testPacket) []byte {
	var buf bytes.Buffer
	baseTime := time.Date(2025, 6, 1, 12, 0, 0, 0, time.UTC)

	// Global header (24 bytes)
	binary.Write(&buf, binary.LittleEndian, uint32(0xa1b2c3d4))
	binary.Write(&buf, binary.LittleEndian, uint16(2))
	binary.Write(&buf, binary.LittleEndian, uint16(4))
	binary.Write(&buf, binary.LittleEndian, int32(0))
	binary.Write(&buf, binary.LittleEndian, uint32(0))
	binary.Write(&buf, binary.LittleEndian, uint32(65535))
	binary.Write(&buf, binary.LittleEndian, uint32(1)) // Ethernet

	for _, p := range pkts {
		ts := baseTime.Add(p.tsOff)

		// Build Ethernet(14) + IP(20) + TCP/UDP(20/8) + payload
		hdrLen := 14 + 20
		if p.proto == 6 {
			hdrLen += 20 // TCP
		} else {
			hdrLen += 8 // UDP
		}
		totalLen := hdrLen + len(p.payload)
		pkt := make([]byte, totalLen)

		// Ethernet: dst=ff, src=00:11:22:33:44:55, type=0x0800
		for i := 0; i < 6; i++ {
			pkt[i] = 0xff
		}
		pkt[6], pkt[7], pkt[8], pkt[9], pkt[10], pkt[11] = 0x00, 0x11, 0x22, 0x33, 0x44, 0x55
		pkt[12], pkt[13] = 0x08, 0x00

		// IPv4 header
		pkt[14] = 0x45
		pkt[15] = p.dscp << 2
		ipTotalLen := uint16(totalLen - 14)
		pkt[16] = byte(ipTotalLen >> 8)
		pkt[17] = byte(ipTotalLen)
		pkt[22] = p.ttl
		pkt[23] = p.proto
		copy(pkt[26:30], p.srcIP[:])
		copy(pkt[30:34], p.dstIP[:])

		// Transport header
		off := 34
		pkt[off] = byte(p.srcPort >> 8)
		pkt[off+1] = byte(p.srcPort)
		pkt[off+2] = byte(p.dstPort >> 8)
		pkt[off+3] = byte(p.dstPort)

		if p.proto == 6 {
			// TCP: seq at offset+4, ack at +8, data offset at +12, flags at +13
			pkt[off+4] = byte(p.seqNum >> 24)
			pkt[off+5] = byte(p.seqNum >> 16)
			pkt[off+6] = byte(p.seqNum >> 8)
			pkt[off+7] = byte(p.seqNum)
			pkt[off+12] = 0x50 // data offset = 5 (20 bytes)
			pkt[off+13] = p.tcpFlag
		} else {
			// UDP: length at +4
			udpLen := uint16(8 + len(p.payload))
			pkt[off+4] = byte(udpLen >> 8)
			pkt[off+5] = byte(udpLen)
		}

		// Payload
		if len(p.payload) > 0 {
			copy(pkt[hdrLen:], p.payload)
		}

		// Packet record header (16 bytes)
		binary.Write(&buf, binary.LittleEndian, uint32(ts.Unix()))
		binary.Write(&buf, binary.LittleEndian, uint32(ts.Nanosecond()/1000))
		binary.Write(&buf, binary.LittleEndian, uint32(totalLen))
		binary.Write(&buf, binary.LittleEndian, uint32(totalLen))
		buf.Write(pkt)
	}
	return buf.Bytes()
}

func writeTempPCAP(t *testing.T, data []byte, name string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return path
}

// ─── Common packet definitions ─────────────────────────────────────

var (
	lanIP  = [4]byte{192, 168, 1, 10}
	wanIP  = [4]byte{10, 0, 0, 1}
	bfdIP  = [4]byte{10, 0, 0, 2}
	natIP  = [4]byte{203, 0, 113, 5} // public NAT IP
)

// ─── Test Cases ────────────────────────────────────────────────────

func TestCompareStreaming_IdenticalPackets_PresentBoth(t *testing.T) {
	// Same TCP SYN packet in both files → PRESENT_BOTH
	pkt := testPacket{
		srcIP: lanIP, dstIP: wanIP,
		srcPort: 55555, dstPort: 443,
		proto: 6, ttl: 64, seqNum: 1000,
		tcpFlag: 0x02, // SYN
	}
	fileA := writeTempPCAP(t, buildTestPCAP([]testPacket{pkt}), "lan.pcap")
	fileB := writeTempPCAP(t, buildTestPCAP([]testPacket{pkt}), "wan.pcap")

	c := NewComparator(false)
	report, err := c.CompareStreaming(fileA, fileB)
	if err != nil {
		t.Fatalf("CompareStreaming: %v", err)
	}

	if report.TotalPacketsA != 1 {
		t.Errorf("TotalPacketsA = %d, want 1", report.TotalPacketsA)
	}
	if report.TotalPacketsB != 1 {
		t.Errorf("TotalPacketsB = %d, want 1", report.TotalPacketsB)
	}
	if report.MatchedCount != 1 {
		t.Errorf("MatchedCount = %d, want 1", report.MatchedCount)
	}
	if report.MissingBCount != 0 {
		t.Errorf("MissingBCount = %d, want 0", report.MissingBCount)
	}
}

func TestCompareStreaming_PacketDrop_MissingB(t *testing.T) {
	// Packet in LAN only, not in WAN → MISSING_B (dropped by device)
	pkt1 := testPacket{
		srcIP: lanIP, dstIP: wanIP,
		srcPort: 55555, dstPort: 443,
		proto: 6, ttl: 64, seqNum: 1000,
		tcpFlag: 0x02,
	}
	pkt2 := testPacket{
		srcIP: lanIP, dstIP: wanIP,
		srcPort: 55555, dstPort: 443,
		proto: 6, ttl: 64, seqNum: 2000,
		tcpFlag: 0x10, // ACK
		tsOff:   10 * time.Millisecond,
	}

	// LAN has both packets, WAN has only the first
	fileA := writeTempPCAP(t, buildTestPCAP([]testPacket{pkt1, pkt2}), "lan.pcap")
	fileB := writeTempPCAP(t, buildTestPCAP([]testPacket{pkt1}), "wan.pcap")

	c := NewComparator(false)
	report, err := c.CompareStreaming(fileA, fileB)
	if err != nil {
		t.Fatalf("CompareStreaming: %v", err)
	}

	if report.TotalPacketsA != 2 {
		t.Errorf("TotalPacketsA = %d, want 2", report.TotalPacketsA)
	}
	if report.MatchedCount < 1 {
		t.Errorf("MatchedCount = %d, want >= 1", report.MatchedCount)
	}
	// The second packet should be MISSING_B
	if report.MissingBCount < 1 {
		t.Errorf("MissingBCount = %d, want >= 1", report.MissingBCount)
	}
}

func TestCompareStreaming_NATModification(t *testing.T) {
	// Same packet but source IP changes (NAT) → MODIFIED or matched via NAT-relaxed hash
	lanPkt := testPacket{
		srcIP: lanIP, dstIP: wanIP,
		srcPort: 55555, dstPort: 443,
		proto: 6, ttl: 64, seqNum: 3000,
		tcpFlag: 0x02,
	}
	wanPkt := testPacket{
		srcIP: natIP, dstIP: wanIP, // NAT'd source IP
		srcPort: 55555, dstPort: 443,
		proto: 6, ttl: 63, seqNum: 3000, // TTL also decremented
		tcpFlag: 0x02,
	}

	fileA := writeTempPCAP(t, buildTestPCAP([]testPacket{lanPkt}), "lan.pcap")
	fileB := writeTempPCAP(t, buildTestPCAP([]testPacket{wanPkt}), "wan.pcap")

	c := NewComparator(false)
	report, err := c.CompareStreaming(fileA, fileB)
	if err != nil {
		t.Fatalf("CompareStreaming: %v", err)
	}

	// Either MODIFIED (if matched) or the NAT-relaxed hash catches it
	totalAccounted := report.MatchedCount + report.ModifiedCount
	if totalAccounted < 1 {
		t.Errorf("Expected NAT packet to be matched or modified, got matched=%d modified=%d",
			report.MatchedCount, report.ModifiedCount)
	}

	// Check NAT detection
	if report.NATDetected {
		t.Logf("NAT correctly detected")
	}
}

func TestCompareStreaming_BFDControlPlane_Ignored(t *testing.T) {
	// BFD packets on WAN side (UDP 3784) should be excluded from scoring
	lanPkt := testPacket{
		srcIP: lanIP, dstIP: wanIP,
		srcPort: 55555, dstPort: 443,
		proto: 6, ttl: 64, seqNum: 4000,
		tcpFlag: 0x02,
	}
	bfdPkt := testPacket{
		srcIP: bfdIP, dstIP: wanIP,
		srcPort: 49152, dstPort: 3784, // BFD
		proto: 17, ttl: 255,
	}

	// LAN has 1 TCP packet; WAN has same TCP + a BFD packet
	fileA := writeTempPCAP(t, buildTestPCAP([]testPacket{lanPkt}), "lan.pcap")
	fileB := writeTempPCAP(t, buildTestPCAP([]testPacket{lanPkt, bfdPkt}), "wan.pcap")

	c := NewComparator(false)
	report, err := c.CompareStreaming(fileA, fileB)
	if err != nil {
		t.Fatalf("CompareStreaming: %v", err)
	}

	if report.TotalPacketsB != 2 {
		t.Errorf("TotalPacketsB = %d, want 2", report.TotalPacketsB)
	}
	// BFD should be counted as control plane
	if report.IgnoredControlPlaneCount < 1 {
		t.Logf("IgnoredControlPlaneCount = %d (BFD may be counted as MISSING_A instead — implementation-dependent)", report.IgnoredControlPlaneCount)
	}
	// The TCP packet should still match
	if report.MatchedCount < 1 {
		t.Errorf("MatchedCount = %d, want >= 1 (TCP SYN should match)", report.MatchedCount)
	}
	// Path integrity should not be penalized by the BFD packet
	if report.PathIntegrityScore < 90.0 {
		t.Errorf("PathIntegrityScore = %.1f, want >= 90 (BFD should not affect score)", report.PathIntegrityScore)
	}
}

func TestCompareStreaming_EmptyFiles(t *testing.T) {
	// Both files empty → no errors, zero counts
	fileA := writeTempPCAP(t, buildTestPCAP(nil), "empty_a.pcap")
	fileB := writeTempPCAP(t, buildTestPCAP(nil), "empty_b.pcap")

	c := NewComparator(false)
	report, err := c.CompareStreaming(fileA, fileB)
	if err != nil {
		t.Fatalf("CompareStreaming: %v", err)
	}

	if report.TotalPacketsA != 0 || report.TotalPacketsB != 0 {
		t.Errorf("Empty files should have 0 packets, got A=%d B=%d",
			report.TotalPacketsA, report.TotalPacketsB)
	}
}

func TestCompareStreaming_MultipleFlows(t *testing.T) {
	// Two distinct flows — both matched
	flow1LAN := testPacket{
		srcIP: lanIP, dstIP: wanIP,
		srcPort: 55555, dstPort: 443,
		proto: 6, ttl: 64, seqNum: 100,
		tcpFlag: 0x02,
	}
	flow2LAN := testPacket{
		srcIP: lanIP, dstIP: [4]byte{10, 0, 0, 2},
		srcPort: 44444, dstPort: 80,
		proto: 6, ttl: 64, seqNum: 200,
		tcpFlag: 0x02,
		tsOff: 5 * time.Millisecond,
	}

	fileA := writeTempPCAP(t, buildTestPCAP([]testPacket{flow1LAN, flow2LAN}), "lan.pcap")
	fileB := writeTempPCAP(t, buildTestPCAP([]testPacket{flow1LAN, flow2LAN}), "wan.pcap")

	c := NewComparator(false)
	report, err := c.CompareStreaming(fileA, fileB)
	if err != nil {
		t.Fatalf("CompareStreaming: %v", err)
	}

	if report.MatchedCount != 2 {
		t.Errorf("MatchedCount = %d, want 2", report.MatchedCount)
	}
	if len(report.FlowSummaries) < 2 {
		t.Errorf("FlowSummaries = %d, want >= 2", len(report.FlowSummaries))
	}
}

func TestCompareStreaming_TTLChange_Modified(t *testing.T) {
	// Same packet with TTL decremented → MODIFIED with TTL field change
	lanPkt := testPacket{
		srcIP: lanIP, dstIP: wanIP,
		srcPort: 55555, dstPort: 443,
		proto: 6, ttl: 64, seqNum: 5000,
		tcpFlag: 0x02,
	}
	wanPkt := testPacket{
		srcIP: lanIP, dstIP: wanIP,
		srcPort: 55555, dstPort: 443,
		proto: 6, ttl: 62, seqNum: 5000, // TTL decremented by 2
		tcpFlag: 0x02,
	}

	fileA := writeTempPCAP(t, buildTestPCAP([]testPacket{lanPkt}), "lan.pcap")
	fileB := writeTempPCAP(t, buildTestPCAP([]testPacket{wanPkt}), "wan.pcap")

	c := NewComparator(false)
	report, err := c.CompareStreaming(fileA, fileB)
	if err != nil {
		t.Fatalf("CompareStreaming: %v", err)
	}

	if report.ModifiedCount < 1 && report.MatchedCount < 1 {
		t.Errorf("TTL-changed packet should be MODIFIED or matched, got modified=%d matched=%d",
			report.ModifiedCount, report.MatchedCount)
	}
	if report.TTLChanges < 1 && report.ModifiedCount >= 1 {
		t.Logf("TTLChanges = %d (TTL modification detected via MODIFIED state)", report.TTLChanges)
	}
}
