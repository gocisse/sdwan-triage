package handlers

import (
	"testing"
	"time"

	"github.com/gocisse/sdwan-triage/pkg/models"
)

// mkPkt builds a minimal *models.RawPacket with the fields the search
// matchers look at. Avoids going through the full gopacket parse pipeline.
func mkPkt(idx int, src, dst string, sport, dport uint16, proto string, payload []byte) *models.RawPacket {
	return &models.RawPacket{
		Index:     idx,
		Timestamp: time.Unix(0, 0),
		Length:    len(payload),
		SrcIP:     src,
		DstIP:     dst,
		SrcPort:   sport,
		DstPort:   dport,
		Protocol:  proto,
		RawData:   payload,
	}
}

// ─── Address mode ───────────────────────────────────────────────

func TestAddressMatcher_IPOnly(t *testing.T) {
	m, err := buildPacketMatcher("10.0.0.5", "address", false)
	if err != nil {
		t.Fatal(err)
	}
	hit := m.match(mkPkt(1, "10.0.0.5", "10.0.0.9", 5000, 443, "TCP", nil))
	if hit == nil {
		t.Fatal("IP in src should match")
	}
	hit2 := m.match(mkPkt(2, "10.0.0.9", "10.0.0.5", 443, 5000, "TCP", nil))
	if hit2 == nil {
		t.Fatal("IP in dst should match")
	}
	miss := m.match(mkPkt(3, "10.0.0.1", "10.0.0.2", 443, 5000, "TCP", nil))
	if miss != nil {
		t.Fatal("unrelated packet should not match")
	}
}

func TestAddressMatcher_IPPort(t *testing.T) {
	m, err := buildPacketMatcher("10.0.0.5:443", "address", false)
	if err != nil {
		t.Fatal(err)
	}
	// Both IP and port on same side → hit
	if m.match(mkPkt(1, "10.0.0.5", "10.0.0.9", 443, 5000, "TCP", nil)) == nil {
		t.Error("ip+port on src should match")
	}
	// IP on one side, port on other → should NOT match (same-side constraint)
	if m.match(mkPkt(2, "10.0.0.5", "10.0.0.9", 5000, 443, "TCP", nil)) != nil {
		t.Error("ip+port split across sides should not match")
	}
}

func TestAddressMatcher_PortOnly(t *testing.T) {
	m, err := buildPacketMatcher("port:8080", "address", false)
	if err != nil {
		t.Fatal(err)
	}
	if m.match(mkPkt(1, "1.1.1.1", "2.2.2.2", 8080, 5000, "TCP", nil)) == nil {
		t.Error("src port 8080 should match")
	}
	if m.match(mkPkt(2, "1.1.1.1", "2.2.2.2", 5000, 8080, "TCP", nil)) == nil {
		t.Error("dst port 8080 should match")
	}
	if m.match(mkPkt(3, "1.1.1.1", "2.2.2.2", 1234, 5678, "TCP", nil)) != nil {
		t.Error("packet without port 8080 should not match")
	}
}

func TestAddressMatcher_CommaList(t *testing.T) {
	m, err := buildPacketMatcher("10.0.0.5,10.0.0.6", "address", false)
	if err != nil {
		t.Fatal(err)
	}
	if m.match(mkPkt(1, "10.0.0.5", "8.8.8.8", 0, 0, "ICMP", nil)) == nil {
		t.Error("first list entry should match")
	}
	if m.match(mkPkt(2, "8.8.8.8", "10.0.0.6", 0, 0, "ICMP", nil)) == nil {
		t.Error("second list entry should match")
	}
	if m.match(mkPkt(3, "8.8.8.8", "8.8.4.4", 0, 0, "ICMP", nil)) != nil {
		t.Error("packet not in list should not match")
	}
}

func TestAddressMatcher_InvalidPort(t *testing.T) {
	if _, err := buildPacketMatcher("port:abc", "address", false); err == nil {
		t.Error("non-numeric port should produce error")
	}
	if _, err := buildPacketMatcher("port:70000", "address", false); err == nil {
		t.Error("port > 65535 should produce error")
	}
}

// ─── String mode ────────────────────────────────────────────────

func TestStringMatcher_CaseInsensitive(t *testing.T) {
	m, _ := buildPacketMatcher("HTTP", "string", false)
	payload := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
	hit := m.match(mkPkt(1, "a", "b", 0, 0, "TCP", payload))
	if hit == nil {
		t.Fatal("case-insensitive match on 'HTTP' should hit")
	}
	if hit.MatchOffset != 6 {
		t.Errorf("expected match at offset 6, got %d", hit.MatchOffset)
	}
	if hit.MatchLength != 4 {
		t.Errorf("expected match length 4, got %d", hit.MatchLength)
	}

	// Lower-case query should also hit an upper-case payload region.
	m2, _ := buildPacketMatcher("http", "string", false)
	if m2.match(mkPkt(2, "a", "b", 0, 0, "TCP", payload)) == nil {
		t.Error("'http' should fold-match 'HTTP'")
	}
}

func TestStringMatcher_CaseSensitive(t *testing.T) {
	m, _ := buildPacketMatcher("http", "string", true)
	payload := []byte("GET / HTTP/1.1\r\n")
	if m.match(mkPkt(1, "a", "b", 0, 0, "TCP", payload)) != nil {
		t.Error("case-sensitive 'http' should NOT match 'HTTP'")
	}
}

func TestStringMatcher_Miss(t *testing.T) {
	m, _ := buildPacketMatcher("FTP", "string", false)
	if m.match(mkPkt(1, "a", "b", 0, 0, "TCP", []byte("GET / HTTP/1.1"))) != nil {
		t.Error("missing substring should not match")
	}
}

func TestStringMatcher_Preview(t *testing.T) {
	m, _ := buildPacketMatcher("secret", "string", false)
	payload := []byte("prefix SECRET data here")
	hit := m.match(mkPkt(1, "a", "b", 0, 0, "TCP", payload))
	if hit == nil {
		t.Fatal("expected hit")
	}
	if hit.Preview == "" {
		t.Error("preview should be populated")
	}
}

// ─── Hex mode ───────────────────────────────────────────────────

func TestHexMatcher_SimpleHit(t *testing.T) {
	m, err := buildPacketMatcher("160301", "hex", false)
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte{0x00, 0x16, 0x03, 0x01, 0xff, 0xff}
	hit := m.match(mkPkt(1, "a", "b", 0, 0, "TCP", payload))
	if hit == nil {
		t.Fatal("expected TLS ClientHello signature hit")
	}
	if hit.MatchOffset != 1 {
		t.Errorf("expected offset 1, got %d", hit.MatchOffset)
	}
}

func TestHexMatcher_SpacesAndColons(t *testing.T) {
	// All three of these should be equivalent and match a "de:ad:be:ef"
	// byte sequence.
	for _, q := range []string{"deadbeef", "de ad be ef", "de:ad:be:ef"} {
		m, err := buildPacketMatcher(q, "hex", false)
		if err != nil {
			t.Fatalf("buildPacketMatcher(%q) failed: %v", q, err)
		}
		if m.match(mkPkt(1, "a", "b", 0, 0, "TCP", []byte{0x00, 0xde, 0xad, 0xbe, 0xef})) == nil {
			t.Errorf("query %q should match 0xDEADBEEF", q)
		}
	}
}

func TestHexMatcher_InvalidQuery(t *testing.T) {
	if _, err := buildPacketMatcher("ZZ", "hex", false); err == nil {
		t.Error("invalid hex digits should error")
	}
	if _, err := buildPacketMatcher("123", "hex", false); err == nil {
		t.Error("odd number of hex digits should error")
	}
	if _, err := buildPacketMatcher("", "hex", false); err == nil {
		t.Error("empty hex query should error")
	}
}

// ─── Mode routing ───────────────────────────────────────────────

func TestBuildPacketMatcher_UnknownMode(t *testing.T) {
	if _, err := buildPacketMatcher("x", "regex", false); err == nil {
		t.Error("unknown mode should error")
	}
}
