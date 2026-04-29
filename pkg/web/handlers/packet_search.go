package handlers

// packet_search.go — full-text packet search endpoint.
//
// Exposes GET /api/packets/search/:jobID with three search modes:
//
//	mode=address  — match packets by source or destination IP / port.
//	              Accepts "ip", "ip:port", "ip1,ip2", or "port:N".
//	mode=string   — case-insensitive substring match on packet payload
//	              interpreted as ASCII. Non-printable bytes become '.'.
//	mode=hex      — raw byte-sequence match. Query is a hex string like
//	              "4d5a" or "16 03 01 ...".
//
// Returns a capped list of matches (default 200, max 1000) so a pathological
// query can't blow up memory. Each match carries the packet index, the
// 5-tuple, and a short preview showing the match in context.

import (
	"encoding/hex"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/gocisse/sdwan-triage/pkg/models"
)

// SearchMatch describes one matching packet plus a short preview of where
// the match occurred. Preview is empty for address mode (the packet
// metadata is the match).
type SearchMatch struct {
	Index       int    `json:"index"`
	Timestamp   string `json:"timestamp"`
	Length      int    `json:"length"`
	SrcIP       string `json:"src_ip"`
	DstIP       string `json:"dst_ip"`
	SrcPort     uint16 `json:"src_port,omitempty"`
	DstPort     uint16 `json:"dst_port,omitempty"`
	Protocol    string `json:"protocol"`
	Summary     string `json:"summary"`
	MatchOffset int    `json:"match_offset,omitempty"` // byte offset into raw packet (string/hex mode)
	MatchLength int    `json:"match_length,omitempty"` // length of the matched region
	Preview     string `json:"preview,omitempty"`      // short ASCII excerpt around the match
}

// SearchResponse is returned by the search endpoint.
type SearchResponse struct {
	Query     string        `json:"query"`
	Mode      string        `json:"mode"`
	Total     int           `json:"total"`     // matches returned in this response
	Truncated bool          `json:"truncated"` // true when the result cap was hit
	Scanned   int           `json:"scanned"`   // packets actually inspected
	Matches   []SearchMatch `json:"matches"`
}

// SearchPackets handles GET /api/packets/search/:jobID
//
// Query parameters:
//   - q        : search query (required)
//   - mode     : "address" | "string" | "hex" (default "string")
//   - limit    : result cap, 1..1000, default 200
//   - case     : "1" to make string mode case-sensitive (default is insensitive)
func (h *PacketInspectionHandlers) SearchPackets(c *gin.Context) {
	jobID := c.Param("jobID")

	query := strings.TrimSpace(c.Query("q"))
	if query == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Missing required query parameter 'q'"})
		return
	}

	mode := c.Query("mode")
	if mode == "" {
		mode = "string"
	}
	switch mode {
	case "address", "string", "hex":
		// ok
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid mode; must be one of: address, string, hex"})
		return
	}

	limit := 200
	if l := c.Query("limit"); l != "" {
		if n, err := strconv.Atoi(l); err == nil && n > 0 {
			if n > 1000 {
				n = 1000
			}
			limit = n
		}
	}

	caseSensitive := c.Query("case") == "1"

	if h.ensurePacketsLoaded(c, jobID) == nil {
		return
	}

	// Build the matcher once for the whole scan — avoids re-parsing the query
	// for every packet and lets us bail out early on invalid inputs.
	matcher, err := buildPacketMatcher(query, mode, caseSensitive)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	packets := h.packetStore.GetAllPackets()
	matches := make([]SearchMatch, 0, 64)
	truncated := false

	for _, p := range packets {
		hit := matcher.match(p)
		if hit == nil {
			continue
		}
		matches = append(matches, *hit)
		if len(matches) >= limit {
			truncated = true
			break
		}
	}

	c.JSON(http.StatusOK, SearchResponse{
		Query:     query,
		Mode:      mode,
		Total:     len(matches),
		Truncated: truncated,
		Scanned:   len(packets),
		Matches:   matches,
	})
}

// ─── Matcher implementation ─────────────────────────────────────

// packetMatcher is the strategy interface for a search mode. Returning nil
// from match() means the packet did not match. Returning a non-nil
// SearchMatch means the caller should collect it as a hit.
type packetMatcher interface {
	match(p *models.RawPacket) *SearchMatch
}

func buildPacketMatcher(query, mode string, caseSensitive bool) (packetMatcher, error) {
	switch mode {
	case "address":
		return newAddressMatcher(query)
	case "string":
		return newStringMatcher(query, caseSensitive), nil
	case "hex":
		return newHexMatcher(query)
	}
	return nil, fmt.Errorf("unknown search mode: %s", mode)
}

// ── Address mode ────────────────────────────────────────────────
//
// Accepts flexible address-style queries:
//   - single IP             → "10.0.0.5"
//   - IP with port          → "10.0.0.5:443"
//   - port only             → "port:443" or just ":443"
//   - comma-separated list  → "10.0.0.5,10.0.0.6"
//
// A packet matches if *either* its src or dst satisfies the query. A single
// query string may specify multiple candidates via comma separation, and
// each candidate is evaluated independently (logical OR).

type addressClause struct {
	ip   string // "" means any
	port uint16 // 0 means any
}

type addressMatcher struct {
	clauses []addressClause
}

func newAddressMatcher(query string) (packetMatcher, error) {
	m := &addressMatcher{}
	for _, raw := range strings.Split(query, ",") {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		c, err := parseAddressClause(raw)
		if err != nil {
			return nil, err
		}
		m.clauses = append(m.clauses, c)
	}
	if len(m.clauses) == 0 {
		return nil, fmt.Errorf("address query is empty")
	}
	return m, nil
}

func parseAddressClause(s string) (addressClause, error) {
	// "port:443"
	if strings.HasPrefix(strings.ToLower(s), "port:") {
		portStr := s[5:]
		port, err := strconv.Atoi(strings.TrimSpace(portStr))
		if err != nil || port <= 0 || port > 65535 {
			return addressClause{}, fmt.Errorf("invalid port in %q", s)
		}
		return addressClause{port: uint16(port)}, nil
	}

	// ":443" → port-only
	if strings.HasPrefix(s, ":") {
		port, err := strconv.Atoi(strings.TrimSpace(s[1:]))
		if err != nil || port <= 0 || port > 65535 {
			return addressClause{}, fmt.Errorf("invalid port in %q", s)
		}
		return addressClause{port: uint16(port)}, nil
	}

	// "ip:port"  — split on last colon so IPv6 addresses without brackets
	// still produce meaningful IP-only matches (a bare IPv6 like
	// "fe80::1" without a port will have its last colon interpreted as a
	// port separator unless users bracket it; that's acceptable UX for
	// now — we can upgrade to RFC 3986 bracket syntax later.)
	if i := strings.LastIndex(s, ":"); i > 0 && i < len(s)-1 {
		ip := s[:i]
		portStr := s[i+1:]
		// Only treat as ip:port when the right side is a valid port number.
		if port, err := strconv.Atoi(portStr); err == nil && port > 0 && port <= 65535 {
			return addressClause{ip: ip, port: uint16(port)}, nil
		}
	}

	// Bare IP or hostname (no port).
	return addressClause{ip: s}, nil
}

func (m *addressMatcher) match(p *models.RawPacket) *SearchMatch {
	for _, c := range m.clauses {
		if addressClauseHits(c, p) {
			return buildBaseMatch(p)
		}
	}
	return nil
}

func addressClauseHits(c addressClause, p *models.RawPacket) bool {
	// Port-only clause: match either side.
	if c.ip == "" {
		return c.port != 0 && (p.SrcPort == c.port || p.DstPort == c.port)
	}
	// IP clause.
	ipMatches := p.SrcIP == c.ip || p.DstIP == c.ip
	if !ipMatches {
		return false
	}
	// IP+port must match on the same side to reduce false positives.
	if c.port == 0 {
		return true
	}
	return (p.SrcIP == c.ip && p.SrcPort == c.port) ||
		(p.DstIP == c.ip && p.DstPort == c.port)
}

// ── String mode ─────────────────────────────────────────────────
//
// Scans the raw packet bytes for an ASCII substring. To preserve Wireshark
// "Find Packet → String" ergonomics we default to case-insensitive, with a
// caller-controllable override.

type stringMatcher struct {
	needle        []byte
	caseSensitive bool
}

func newStringMatcher(query string, caseSensitive bool) packetMatcher {
	needle := []byte(query)
	if !caseSensitive {
		needle = bytes_ToLower(needle)
	}
	return &stringMatcher{needle: needle, caseSensitive: caseSensitive}
}

func (m *stringMatcher) match(p *models.RawPacket) *SearchMatch {
	data := p.RawData
	if len(data) == 0 || len(m.needle) == 0 {
		return nil
	}
	idx := -1
	if m.caseSensitive {
		idx = indexBytes(data, m.needle)
	} else {
		idx = indexBytesFold(data, m.needle)
	}
	if idx < 0 {
		return nil
	}
	match := buildBaseMatch(p)
	match.MatchOffset = idx
	match.MatchLength = len(m.needle)
	match.Preview = extractPreview(data, idx, len(m.needle))
	return match
}

// ── Hex mode ────────────────────────────────────────────────────
//
// Accepts loose hex input — spaces and ":" separators are stripped so users
// can paste Wireshark display-filter-style patterns like "16 03 01" or
// "de:ad:be:ef" directly. Pattern must decode to at least one byte.

type hexMatcher struct {
	needle []byte
}

func newHexMatcher(query string) (packetMatcher, error) {
	clean := strings.Map(func(r rune) rune {
		switch r {
		case ' ', ':', '-', '\t', '\n':
			return -1
		}
		return r
	}, query)
	if clean == "" {
		return nil, fmt.Errorf("hex query is empty")
	}
	if len(clean)%2 != 0 {
		return nil, fmt.Errorf("hex query must have an even number of hex digits")
	}
	needle, err := hex.DecodeString(clean)
	if err != nil {
		return nil, fmt.Errorf("invalid hex query: %w", err)
	}
	return &hexMatcher{needle: needle}, nil
}

func (m *hexMatcher) match(p *models.RawPacket) *SearchMatch {
	data := p.RawData
	if len(data) == 0 || len(m.needle) == 0 {
		return nil
	}
	idx := indexBytes(data, m.needle)
	if idx < 0 {
		return nil
	}
	match := buildBaseMatch(p)
	match.MatchOffset = idx
	match.MatchLength = len(m.needle)
	match.Preview = extractPreview(data, idx, len(m.needle))
	return match
}

// ─── Helpers ────────────────────────────────────────────────────

// buildBaseMatch populates the packet-level fields of a SearchMatch.
// Callers then fill MatchOffset / Preview for content-based matchers.
func buildBaseMatch(p *models.RawPacket) *SearchMatch {
	return &SearchMatch{
		Index:     p.Index,
		Timestamp: p.Timestamp.Format("15:04:05.000000"),
		Length:    p.Length,
		SrcIP:     p.SrcIP,
		DstIP:     p.DstIP,
		SrcPort:   p.SrcPort,
		DstPort:   p.DstPort,
		Protocol:  p.Protocol,
		Summary:   packetSummaryOneLine(p),
	}
}

// packetSummaryOneLine produces a compact human-readable description of a
// packet — the same format used by ListPackets so search results and
// list rows look alike.
func packetSummaryOneLine(p *models.RawPacket) string {
	if p.IsTCP {
		s := fmt.Sprintf("%s:%d → %s:%d TCP", p.SrcIP, p.SrcPort, p.DstIP, p.DstPort)
		if p.IsHTTP {
			s += " (HTTP)"
		} else if p.IsTLS {
			s += " (TLS)"
		}
		return s
	}
	if p.IsUDP {
		s := fmt.Sprintf("%s:%d → %s:%d UDP", p.SrcIP, p.SrcPort, p.DstIP, p.DstPort)
		if p.IsDNS {
			s += " (DNS)"
		}
		return s
	}
	if p.IsICMP {
		return fmt.Sprintf("%s → %s ICMP", p.SrcIP, p.DstIP)
	}
	return fmt.Sprintf("%s → %s %s", p.SrcIP, p.DstIP, p.Protocol)
}

// extractPreview returns a short ASCII snippet around a byte-range match,
// converting non-printable bytes to '.' (Wireshark-style). The preview is
// bounded so we never return huge payloads in the search response.
func extractPreview(data []byte, offset, length int) string {
	const context = 24 // bytes of context on each side
	start := offset - context
	if start < 0 {
		start = 0
	}
	end := offset + length + context
	if end > len(data) {
		end = len(data)
	}
	out := make([]byte, end-start)
	for i := start; i < end; i++ {
		b := data[i]
		if b >= 0x20 && b < 0x7f {
			out[i-start] = b
		} else {
			out[i-start] = '.'
		}
	}
	return string(out)
}

// indexBytes is a plain forward scan. For the packet sizes we handle (≤ a
// few kB typically, never more than a jumbo frame), the naive O(n·m)
// approach is faster than setting up a Boyer-Moore table per query.
func indexBytes(haystack, needle []byte) int {
	if len(needle) == 0 || len(haystack) < len(needle) {
		return -1
	}
	for i := 0; i <= len(haystack)-len(needle); i++ {
		match := true
		for j := 0; j < len(needle); j++ {
			if haystack[i+j] != needle[j] {
				match = false
				break
			}
		}
		if match {
			return i
		}
	}
	return -1
}

// indexBytesFold is like indexBytes but ASCII-case-insensitive. The needle
// is assumed to already be lowercase (see newStringMatcher).
func indexBytesFold(haystack, needle []byte) int {
	if len(needle) == 0 || len(haystack) < len(needle) {
		return -1
	}
	for i := 0; i <= len(haystack)-len(needle); i++ {
		match := true
		for j := 0; j < len(needle); j++ {
			a := haystack[i+j]
			if a >= 'A' && a <= 'Z' {
				a += 'a' - 'A'
			}
			if a != needle[j] {
				match = false
				break
			}
		}
		if match {
			return i
		}
	}
	return -1
}

// bytes_ToLower is a tiny allocation-saving ASCII lowercaser. We avoid the
// standard `bytes.ToLower` so we don't pay for UTF-8 folding on every
// query (the needle is ASCII by construction here — non-ASCII search
// queries on binary packets produce no hits anyway).
func bytes_ToLower(in []byte) []byte {
	out := make([]byte, len(in))
	for i, b := range in {
		if b >= 'A' && b <= 'Z' {
			b += 'a' - 'A'
		}
		out[i] = b
	}
	return out
}
