package analyzer

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/gocisse/sdwan-triage/internal/testpcap"
	"github.com/gocisse/sdwan-triage/pkg/events"
)

// ─── TCP keep-alive vs retransmission ────────────────────────────────

func tcpC2S(port uint16, seq, ack uint32, flags uint8, payload []byte) []byte {
	return testpcap.TCPFrame(testpcap.ClientMAC, testpcap.ServerMAC, testpcap.ClientIP, testpcap.ServerIP, port, 443, seq, ack, flags, payload)
}
func tcpS2C(port uint16, seq, ack uint32, flags uint8, payload []byte) []byte {
	return testpcap.TCPFrame(testpcap.ServerMAC, testpcap.ClientMAC, testpcap.ServerIP, testpcap.ClientIP, 443, port, seq, ack, flags, payload)
}

func handshake(port uint16) [][]byte {
	return [][]byte{
		tcpC2S(port, 1000, 0, testpcap.SYN, nil),
		tcpS2C(port, 2000, 1001, testpcap.SYN|testpcap.ACK, nil),
		tcpC2S(port, 1001, 2001, testpcap.ACK, nil),
	}
}

// Keep-alive probes (1 byte at highest_next_seq-1, repeated) are not retransmissions.
func TestKeepAlive_NotReportedAsRetransmission(t *testing.T) {
	const port = 50100
	data := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n") // 38 bytes → next seq 1039
	pk := handshake(port)
	pk = append(pk, tcpC2S(port, 1001, 2001, testpcap.PSH|testpcap.ACK, data))
	pk = append(pk, tcpS2C(port, 2001, 1039, testpcap.ACK, nil))
	for i := 0; i < 3; i++ { // periodic keep-alives: seq = 1039-1, len 1
		pk = append(pk, tcpC2S(port, 1038, 2001, testpcap.ACK, []byte{0}))
		pk = append(pk, tcpS2C(port, 2001, 1039, testpcap.ACK, nil))
	}
	r := runGolden(t, pk)

	if n := len(r.Events.ByKind(events.TCPRetransmission)); n != 0 {
		t.Errorf("keep-alives emitted %d tcp.retransmission events: %+v", n, r.Events.ByKind(events.TCPRetransmission))
	}
	if len(r.TCPRetransmissions) != 0 {
		t.Errorf("keep-alives populated TCPRetransmissions: %+v", r.TCPRetransmissions)
	}
	if r.PacketLoss != nil && r.PacketLoss.PacketsLost != 0 {
		t.Errorf("keep-alives counted as packet loss: %d", r.PacketLoss.PacketsLost)
	}
}

// A genuine 1-byte segment that is NOT at highest_next_seq-1 is still eligible.
func TestOneByteSegment_StillDetectedAsRetransmissionWhenNotKeepAlivePattern(t *testing.T) {
	const port = 50101
	pk := handshake(port)
	pk = append(pk, tcpC2S(port, 1001, 2001, testpcap.PSH|testpcap.ACK, []byte{'x'}))       // 1 byte @1001 → next 1002
	pk = append(pk, tcpC2S(port, 1002, 2001, testpcap.PSH|testpcap.ACK, make([]byte, 100))) // 100 bytes → next 1102
	pk = append(pk, tcpC2S(port, 1001, 2001, testpcap.PSH|testpcap.ACK, []byte{'x'}))       // retransmit the 1-byte segment (1001 != 1101)
	r := runGolden(t, pk)

	ev := r.Events.ByKind(events.TCPRetransmission)
	if len(ev) != 1 || ev[0].Values["seq"] != 1001 || ev[0].Values["payload_len"] != 1 {
		t.Fatalf("expected exactly one 1-byte retransmission event @1001, got %+v", ev)
	}
	if !hasTCPFlow(r.TCPRetransmissions, port, 443) {
		t.Errorf("legacy TCPRetransmissions missing the flow")
	}
	if r.PacketLoss == nil || r.PacketLoss.PacketsLost != 1 {
		t.Errorf("packet loss should count the genuine 1-byte retransmission, got %+v", r.PacketLoss)
	}
}

// Existing multi-byte retransmission behaviour is unchanged (storm fixture).
func TestKeepAliveRule_DoesNotAffectDataRetransmissions(t *testing.T) {
	r := runGolden(t, testpcap.RetransmissionStorm())
	if n := len(r.Events.ByKind(events.TCPRetransmission)); n != 5 {
		t.Errorf("storm retransmission events = %d, want 5", n)
	}
}

// ─── DNS response attribution ────────────────────────────────────────

var clientB = []byte{192, 168, 1, 101}

func dnsQuery(id uint16) []byte {
	q := []byte{
		byte(id >> 8), byte(id), 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00, 0x00, 0x01, 0x00, 0x01,
	}
	return q
}

func dnsResponse(id uint16, rcode byte, answerIP []byte) []byte {
	r := dnsQuery(id)
	r[2], r[3] = 0x81, 0x80|rcode // QR=1, RD, RA, rcode
	if answerIP != nil {
		r[7] = 1 // ANCOUNT
		r = append(r, 0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3C, 0x00, 0x04)
		r = append(r, answerIP...)
	}
	return r
}

func TestDNS_ResponseNotCreditedToOtherClientWithSameName(t *testing.T) {
	// Same transaction ID from both clients (exercises the (id,name) index path)
	// and a second pair with mismatched IDs (exercises the name fallback path).
	pk := [][]byte{
		testpcap.UDPFrame(testpcap.ClientMAC, testpcap.ServerMAC, testpcap.ClientIP, testpcap.DNSServer, 40001, 53, dnsQuery(0x1234)), // A
		testpcap.UDPFrame(testpcap.ClientMAC, testpcap.ServerMAC, clientB, testpcap.DNSServer, 40002, 53, dnsQuery(0x1234)),           // B
		testpcap.UDPFrame(testpcap.ServerMAC, testpcap.ClientMAC, testpcap.DNSServer, clientB, 53, 40002, dnsResponse(0x1234, 0, []byte{93, 184, 216, 34})),
		testpcap.UDPFrame(testpcap.ClientMAC, testpcap.ServerMAC, testpcap.ClientIP, testpcap.DNSServer, 40003, 53, dnsQuery(0x5555)),                       // A again
		testpcap.UDPFrame(testpcap.ClientMAC, testpcap.ServerMAC, clientB, testpcap.DNSServer, 40004, 53, dnsQuery(0x6666)),                                 // B again
		testpcap.UDPFrame(testpcap.ServerMAC, testpcap.ClientMAC, testpcap.DNSServer, clientB, 53, 40004, dnsResponse(0x9999, 0, []byte{93, 184, 216, 34})), // to B, id mismatch → fallback
	}
	r := runGolden(t, pk)

	if len(r.DNSDetails) != 4 {
		t.Fatalf("expected 4 query records, got %d", len(r.DNSDetails))
	}
	for i, rec := range r.DNSDetails {
		answered := rec.ResponseTimestamp != nil
		switch rec.SourceIP {
		case "192.168.1.100":
			if answered {
				t.Errorf("record %d: client A query wrongly marked answered by client B's response", i)
			}
		case "192.168.1.101":
			if !answered {
				t.Errorf("record %d: client B query should be answered (same client)", i)
			}
		}
	}
}

func TestDNS_SameClientRetriesStillMatchInOrder(t *testing.T) {
	pk := [][]byte{
		testpcap.UDPFrame(testpcap.ClientMAC, testpcap.ServerMAC, testpcap.ClientIP, testpcap.DNSServer, 40001, 53, dnsQuery(0x1234)),
		testpcap.UDPFrame(testpcap.ClientMAC, testpcap.ServerMAC, testpcap.ClientIP, testpcap.DNSServer, 40001, 53, dnsQuery(0x1234)), // retry
		testpcap.UDPFrame(testpcap.ServerMAC, testpcap.ClientMAC, testpcap.DNSServer, testpcap.ClientIP, 53, 40001, dnsResponse(0x1234, 0, []byte{93, 184, 216, 34})),
	}
	r := runGolden(t, pk)
	if r.DNSDetails[0].ResponseTimestamp == nil || r.DNSDetails[1].ResponseTimestamp != nil {
		t.Errorf("response should satisfy the earliest pending retry only: %+v", r.DNSDetails)
	}
	if len(r.DNSAnomalies) != 0 {
		t.Errorf("no anomaly expected for an answered query, got %+v", r.DNSAnomalies)
	}
}

// A failure RCODE is evidence even when its query is absent from the capture
// (asymmetric capture point); strict client matching must not discard it.
func TestDNS_FailureRcodeRecordedWithoutMatchingQuery(t *testing.T) {
	pk := [][]byte{
		testpcap.UDPFrame(testpcap.ServerMAC, testpcap.ClientMAC, testpcap.DNSServer, clientB, 53, 40009, dnsResponse(0x4242, 3, nil)), // NXDOMAIN, no query seen
	}
	r := runGolden(t, pk)
	if len(r.DNSDetails) != 0 {
		t.Fatalf("no query record expected, got %d", len(r.DNSDetails))
	}
	if len(r.DNSAnomalies) != 1 || !strings.Contains(r.DNSAnomalies[0].Reason, "NXDOMAIN") || r.DNSAnomalies[0].Query != "example.com" {
		t.Errorf("expected one NXDOMAIN anomaly for the unmatched response, got %+v", r.DNSAnomalies)
	}
	if n := len(r.Events.ByKind(events.DNSAnomaly)); n != 1 {
		t.Errorf("expected 1 dns.anomaly event, got %d", n)
	}
}

// ─── UTC normalisation ───────────────────────────────────────────────

func TestDNSEvents_TimestampsAreUTC(t *testing.T) {
	// Packet-time anomaly (NXDOMAIN response) + finalize-time anomaly (unanswered retries).
	pk := [][]byte{
		testpcap.UDPFrame(testpcap.ClientMAC, testpcap.ServerMAC, testpcap.ClientIP, testpcap.DNSServer, 40001, 53, dnsQuery(0x1234)),
		testpcap.UDPFrame(testpcap.ServerMAC, testpcap.ClientMAC, testpcap.DNSServer, testpcap.ClientIP, 53, 40001, dnsResponse(0x1234, 3, nil)), // NXDOMAIN
	}
	pk = append(pk, testpcap.DNSFailure()...) // 4 unanswered retries of a different id
	r := runGolden(t, pk)

	ev := r.Events.ByKind(events.DNSAnomaly)
	if len(ev) != 2 {
		t.Fatalf("expected 2 dns.anomaly events (1 NXDOMAIN, 1 unanswered), got %d: %+v", len(ev), ev)
	}
	for _, e := range ev {
		if e.Timestamp.Location() != time.UTC {
			t.Errorf("event %d (%s) timestamp location = %v, want UTC", e.ID, e.Attrs["reason"], e.Timestamp.Location())
		}
		b, _ := json.Marshal(e.Timestamp)
		if !strings.HasSuffix(string(b), `Z"`) {
			t.Errorf("event %d serialises as %s, want trailing Z", e.ID, b)
		}
	}
	// Instants are the packet times: NXDOMAIN response = packet 1, unanswered = its first query (packet 2).
	if !ev[0].Timestamp.Equal(fixtureTime(1)) || !ev[1].Timestamp.Equal(fixtureTime(2)) {
		t.Errorf("instants changed by UTC normalisation: %v / %v", ev[0].Timestamp, ev[1].Timestamp)
	}
}
