package detector

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gocisse/sdwan-triage/pkg/models"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// ThreatIntelEntry represents a single threat intelligence indicator
type ThreatIntelEntry struct {
	Type        string `json:"type"`        // "IP", "Domain", "Hash"
	Value       string `json:"value"`       // The indicator value
	ThreatType  string `json:"threat_type"` // "C2 Server", "Malware", "Phishing", "Botnet", "Scanner", "Ransomware"
	Confidence  string `json:"confidence"`  // "High", "Medium", "Low"
	Source      string `json:"source"`      // Feed name, e.g. "AlienVault OTX", "Abuse.ch"
	FirstSeen   string `json:"first_seen"`  // RFC3339
	Description string `json:"description"`
}

// ThreatIntelMatcher holds all threat intel indicators indexed for O(1) lookup
type ThreatIntelMatcher struct {
	ipIndex     map[string]ThreatIntelEntry // IP → entry
	domainIndex map[string]ThreatIntelEntry // domain (lowercase) → entry
	hashIndex   map[string]ThreatIntelEntry // hash (lowercase) → entry
	enabled     bool
	feedCount   int
	totalIOCs   int
}

// NewThreatIntelMatcher creates an empty matcher
func NewThreatIntelMatcher() *ThreatIntelMatcher {
	return &ThreatIntelMatcher{
		ipIndex:     make(map[string]ThreatIntelEntry),
		domainIndex: make(map[string]ThreatIntelEntry),
		hashIndex:   make(map[string]ThreatIntelEntry),
		enabled:     false,
	}
}

// IsEnabled returns whether any feeds have been loaded
func (m *ThreatIntelMatcher) IsEnabled() bool {
	return m.enabled
}

// Stats returns load statistics
func (m *ThreatIntelMatcher) Stats() (feeds int, indicators int) {
	return m.feedCount, m.totalIOCs
}

// ─── STIX 2.1 Parsing ──────────────────────────────────────────────────────

// STIX 2.1 Bundle structure (subset relevant to indicators)
type stixBundle struct {
	Type    string       `json:"type"`
	ID      string       `json:"id"`
	Objects []stixObject `json:"objects"`
}

type stixObject struct {
	Type        string   `json:"type"`
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Pattern     string   `json:"pattern"`
	PatternType string   `json:"pattern_type"`
	Created     string   `json:"created"`
	Modified    string   `json:"modified"`
	ValidFrom   string   `json:"valid_from"`
	Labels      []string `json:"labels"`
	Confidence  int      `json:"confidence"`
	// External references for source attribution
	ExternalReferences []stixExternalRef `json:"external_references"`
}

type stixExternalRef struct {
	SourceName string `json:"source_name"`
	URL        string `json:"url"`
}

// LoadSTIXBundle loads a STIX 2.1 JSON bundle file and extracts indicators
func (m *ThreatIntelMatcher) LoadSTIXBundle(filePath string) error {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("reading STIX bundle %s: %w", filePath, err)
	}

	var bundle stixBundle
	if err := json.Unmarshal(data, &bundle); err != nil {
		return fmt.Errorf("parsing STIX bundle %s: %w", filePath, err)
	}

	if bundle.Type != "bundle" {
		return fmt.Errorf("%s: not a STIX bundle (type=%s)", filePath, bundle.Type)
	}

	sourceName := filepath.Base(filePath)
	added := 0

	for _, obj := range bundle.Objects {
		if obj.Type != "indicator" {
			continue
		}

		// Extract source from external references
		source := sourceName
		for _, ref := range obj.ExternalReferences {
			if ref.SourceName != "" {
				source = ref.SourceName
				break
			}
		}

		// Determine threat type from labels
		threatType := inferThreatType(obj.Labels, obj.Name, obj.Description)

		// Determine confidence
		confidence := inferConfidence(obj.Confidence, obj.Labels)

		// Determine first_seen from valid_from or created
		firstSeen := obj.ValidFrom
		if firstSeen == "" {
			firstSeen = obj.Created
		}

		// Parse STIX pattern to extract indicator values
		indicators := parseSTIXPattern(obj.Pattern)
		for _, ind := range indicators {
			entry := ThreatIntelEntry{
				Type:        ind.indicatorType,
				Value:       ind.value,
				ThreatType:  threatType,
				Confidence:  confidence,
				Source:      source,
				FirstSeen:   firstSeen,
				Description: obj.Description,
			}
			if entry.Description == "" {
				entry.Description = obj.Name
			}

			switch ind.indicatorType {
			case "IP":
				m.ipIndex[ind.value] = entry
			case "Domain":
				m.domainIndex[strings.ToLower(ind.value)] = entry
			case "Hash":
				m.hashIndex[strings.ToLower(ind.value)] = entry
			}
			added++
		}
	}

	if added > 0 {
		m.enabled = true
		m.feedCount++
		m.totalIOCs += added
	}

	return nil
}

// LoadFeedsDirectory loads all .json files in a directory as STIX bundles
func (m *ThreatIntelMatcher) LoadFeedsDirectory(dirPath string) (int, error) {
	entries, err := os.ReadDir(dirPath)
	if err != nil {
		return 0, fmt.Errorf("reading feeds directory %s: %w", dirPath, err)
	}

	loaded := 0
	var lastErr error
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := strings.ToLower(entry.Name())
		if !strings.HasSuffix(name, ".json") {
			continue
		}
		path := filepath.Join(dirPath, entry.Name())
		if err := m.LoadSTIXBundle(path); err != nil {
			lastErr = err
			continue
		}
		loaded++
	}

	if loaded == 0 && lastErr != nil {
		return 0, lastErr
	}
	return loaded, nil
}

// ─── Matching ───────────────────────────────────────────────────────────────

// MatchIP checks if an IP address matches any threat intel indicator
func (m *ThreatIntelMatcher) MatchIP(ip string) *ThreatIntelEntry {
	if !m.enabled || ip == "" {
		return nil
	}
	if entry, ok := m.ipIndex[ip]; ok {
		return &entry
	}
	return nil
}

// MatchDomain checks if a domain matches any threat intel indicator
func (m *ThreatIntelMatcher) MatchDomain(domain string) *ThreatIntelEntry {
	if !m.enabled || domain == "" {
		return nil
	}
	lower := strings.ToLower(domain)
	if entry, ok := m.domainIndex[lower]; ok {
		return &entry
	}
	// Check parent domains (e.g., sub.evil.com → evil.com)
	parts := strings.Split(lower, ".")
	for i := 1; i < len(parts)-1; i++ {
		parent := strings.Join(parts[i:], ".")
		if entry, ok := m.domainIndex[parent]; ok {
			return &entry
		}
	}
	return nil
}

// MatchHash checks if a hash matches any threat intel indicator
func (m *ThreatIntelMatcher) MatchHash(hash string) *ThreatIntelEntry {
	if !m.enabled || hash == "" {
		return nil
	}
	if entry, ok := m.hashIndex[strings.ToLower(hash)]; ok {
		return &entry
	}
	return nil
}

// Match checks an IP and domain against all indicators (convenience method)
func (m *ThreatIntelMatcher) Match(ip, domain string) []ThreatIntelEntry {
	if !m.enabled {
		return nil
	}
	var matches []ThreatIntelEntry
	if entry := m.MatchIP(ip); entry != nil {
		matches = append(matches, *entry)
	}
	if entry := m.MatchDomain(domain); entry != nil {
		matches = append(matches, *entry)
	}
	return matches
}

// ─── Packet Analysis Integration ────────────────────────────────────────────

// AnalyzePacket checks a packet's IPs and DNS queries against threat intel
func (m *ThreatIntelMatcher) AnalyzePacket(packet gopacket.Packet, _ *models.AnalysisState, report *models.TriageReport) {
	if !m.enabled {
		return
	}

	ipInfo := ExtractIPInfo(packet)
	if ipInfo == nil {
		return
	}

	timestamp := packet.Metadata().Timestamp

	// Check source IP
	if entry := m.MatchIP(ipInfo.SrcIP); entry != nil {
		m.reportMatch(ipInfo.SrcIP, "", *entry, timestamp, report)
	}

	// Check destination IP
	if entry := m.MatchIP(ipInfo.DstIP); entry != nil {
		m.reportMatch("", ipInfo.DstIP, *entry, timestamp, report)
	}

	// Check DNS queries for domain indicators
	if dnsLayer := packet.Layer(layers.LayerTypeDNS); dnsLayer != nil {
		if dns, ok := dnsLayer.(*layers.DNS); ok {
			for _, q := range dns.Questions {
				domain := strings.ToLower(string(q.Name))
				if entry := m.MatchDomain(domain); entry != nil {
					m.reportMatch(ipInfo.SrcIP, ipInfo.DstIP, *entry, timestamp, report)
				}
			}
		}
	}
}

func (m *ThreatIntelMatcher) reportMatch(srcIP, dstIP string, entry ThreatIntelEntry, timestamp time.Time, report *models.TriageReport) {
	// No report lock here: detectors run sequentially on one goroutine
	// (DetectorRegistry.AnalyzePacket). Re-taking report.Mu deadlocked.

	// Dedup by value
	for _, existing := range report.ThreatIntelMatches {
		if existing.Value == entry.Value {
			return
		}
	}

	report.ThreatIntelMatches = append(report.ThreatIntelMatches, models.ThreatIntelMatch{
		Timestamp:   float64(timestamp.UnixNano()) / 1e9,
		Type:        entry.Type,
		Value:       entry.Value,
		ThreatType:  entry.ThreatType,
		Confidence:  entry.Confidence,
		Source:      entry.Source,
		FirstSeen:   entry.FirstSeen,
		Description: entry.Description,
		SourceIP:    srcIP,
		DestIP:      dstIP,
	})
}

// ─── STIX Pattern Parsing ───────────────────────────────────────────────────

type parsedIndicator struct {
	indicatorType string // "IP", "Domain", "Hash"
	value         string
}

// parseSTIXPattern extracts IOC values from a STIX 2.1 pattern expression
// Examples:
//
//	[ipv4-addr:value = '198.51.100.1']
//	[domain-name:value = 'evil.com']
//	[file:hashes.'SHA-256' = 'abc123...']
//	[ipv4-addr:value = '1.2.3.4'] OR [ipv4-addr:value = '5.6.7.8']
func parseSTIXPattern(pattern string) []parsedIndicator {
	var results []parsedIndicator
	if pattern == "" {
		return results
	}

	// Split on OR / AND for compound patterns
	segments := splitSTIXPattern(pattern)

	for _, seg := range segments {
		seg = strings.TrimSpace(seg)
		// Remove brackets
		seg = strings.Trim(seg, "[]")
		seg = strings.TrimSpace(seg)

		if strings.HasPrefix(seg, "ipv4-addr:value") || strings.HasPrefix(seg, "ipv6-addr:value") {
			if val := extractSTIXValue(seg); val != "" {
				results = append(results, parsedIndicator{indicatorType: "IP", value: val})
			}
		} else if strings.HasPrefix(seg, "domain-name:value") {
			if val := extractSTIXValue(seg); val != "" {
				results = append(results, parsedIndicator{indicatorType: "Domain", value: val})
			}
		} else if strings.Contains(seg, "hashes.") {
			if val := extractSTIXValue(seg); val != "" {
				results = append(results, parsedIndicator{indicatorType: "Hash", value: val})
			}
		} else if strings.HasPrefix(seg, "network-traffic:dst_ref") {
			// network-traffic:dst_ref.type = 'ipv4-addr' AND network-traffic:dst_ref.value = '...'
			if val := extractSTIXValue(seg); val != "" {
				results = append(results, parsedIndicator{indicatorType: "IP", value: val})
			}
		} else if strings.HasPrefix(seg, "url:value") {
			// Extract domain from URL patterns
			if val := extractSTIXValue(seg); val != "" {
				// Try to extract domain from URL
				domain := extractDomainFromURL(val)
				if domain != "" {
					results = append(results, parsedIndicator{indicatorType: "Domain", value: domain})
				}
			}
		}
	}

	return results
}

func splitSTIXPattern(pattern string) []string {
	// Simple split on ] OR [ and ] AND [ boundaries
	var segments []string
	// Replace common compound separators
	normalized := strings.ReplaceAll(pattern, "] OR [", "]\x00[")
	normalized = strings.ReplaceAll(normalized, "] AND [", "]\x00[")
	parts := strings.Split(normalized, "\x00")
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			segments = append(segments, p)
		}
	}
	if len(segments) == 0 && pattern != "" {
		segments = append(segments, pattern)
	}
	return segments
}

func extractSTIXValue(expr string) string {
	// Find the value between single quotes after = or '='
	eqIdx := strings.Index(expr, "=")
	if eqIdx < 0 {
		return ""
	}
	rest := expr[eqIdx+1:]
	rest = strings.TrimSpace(rest)
	// Remove leading '
	if len(rest) > 0 && rest[0] == '\'' {
		rest = rest[1:]
	}
	// Find closing '
	endIdx := strings.Index(rest, "'")
	if endIdx < 0 {
		return strings.TrimSpace(rest)
	}
	return rest[:endIdx]
}

func extractDomainFromURL(url string) string {
	// Strip scheme
	u := url
	if idx := strings.Index(u, "://"); idx >= 0 {
		u = u[idx+3:]
	}
	// Strip path
	if idx := strings.IndexAny(u, "/?#"); idx >= 0 {
		u = u[:idx]
	}
	// Strip port
	if idx := strings.LastIndex(u, ":"); idx >= 0 {
		u = u[:idx]
	}
	return u
}

// ─── Inference Helpers ──────────────────────────────────────────────────────

func inferThreatType(labels []string, name, description string) string {
	combined := strings.ToLower(strings.Join(labels, " ") + " " + name + " " + description)
	switch {
	case strings.Contains(combined, "c2") || strings.Contains(combined, "command-and-control") || strings.Contains(combined, "command and control"):
		return "C2 Server"
	case strings.Contains(combined, "ransomware"):
		return "Ransomware"
	case strings.Contains(combined, "botnet"):
		return "Botnet"
	case strings.Contains(combined, "phishing"):
		return "Phishing"
	case strings.Contains(combined, "malware") || strings.Contains(combined, "trojan") || strings.Contains(combined, "rat"):
		return "Malware"
	case strings.Contains(combined, "scan") || strings.Contains(combined, "reconnaissance"):
		return "Scanner"
	case strings.Contains(combined, "exploit"):
		return "Exploit"
	case strings.Contains(combined, "spam"):
		return "Spam"
	default:
		if len(labels) > 0 {
			return labels[0]
		}
		return "Malicious"
	}
}

func inferConfidence(stixConfidence int, labels []string) string {
	if stixConfidence > 0 {
		switch {
		case stixConfidence >= 75:
			return "High"
		case stixConfidence >= 40:
			return "Medium"
		default:
			return "Low"
		}
	}
	// Try labels
	for _, l := range labels {
		lower := strings.ToLower(l)
		if strings.Contains(lower, "high") {
			return "High"
		}
		if strings.Contains(lower, "medium") {
			return "Medium"
		}
		if strings.Contains(lower, "low") {
			return "Low"
		}
	}
	return "Medium"
}
