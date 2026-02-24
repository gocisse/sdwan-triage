package detector

import (
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/gocisse/sdwan-triage/pkg/models"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// DNS Tunneling detection thresholds
const (
	DNSTunnelMinQueryLength     = 50  // Minimum avg query length to flag
	DNSTunnelMinQueryCount      = 20  // Minimum queries to same base domain
	DNSTunnelMinSubdomains      = 10  // Minimum unique subdomains
	DNSTunnelEntropyThreshold   = 3.5 // Shannon entropy threshold for subdomain labels
	DNSTunnelDetectionWindowSec = 120.0
)

// DNSTunnelingAnalyzer detects DNS tunneling activity
type DNSTunnelingAnalyzer struct {
	domainStats map[string]*dnsDomainStats // base domain -> stats
	lastReset   time.Time
}

type dnsDomainStats struct {
	BaseDomain       string
	SourceIP         string
	ServerIP         string
	QueryCount       int
	TotalQueryLength int
	Subdomains       map[string]bool
	SampleQueries    []string
	FirstSeen        time.Time
	LastSeen         time.Time
}

// NewDNSTunnelingAnalyzer creates a new DNS tunneling analyzer
func NewDNSTunnelingAnalyzer() *DNSTunnelingAnalyzer {
	return &DNSTunnelingAnalyzer{
		domainStats: make(map[string]*dnsDomainStats),
	}
}

// Analyze processes DNS packets for tunneling indicators
func (d *DNSTunnelingAnalyzer) Analyze(packet gopacket.Packet, state *models.AnalysisState, report *models.TriageReport) {
	dnsLayer := packet.Layer(layers.LayerTypeDNS)
	if dnsLayer == nil {
		return
	}

	dns, ok := dnsLayer.(*layers.DNS)
	if !ok {
		return
	}

	// Only analyze queries (not responses)
	if dns.QR || len(dns.Questions) == 0 {
		return
	}

	ipInfo := ExtractIPInfo(packet)
	if ipInfo == nil {
		return
	}

	timestamp := packet.Metadata().Timestamp
	d.maybeReset(timestamp)

	queryName := string(dns.Questions[0].Name)
	if len(queryName) < 10 {
		return // Too short to be tunneling
	}

	// Extract base domain (last 2 labels)
	baseDomain := extractBaseDomain(queryName)
	if baseDomain == "" {
		return
	}

	// Extract subdomain part
	subdomain := ""
	if len(queryName) > len(baseDomain)+1 {
		subdomain = queryName[:len(queryName)-len(baseDomain)-1]
	}

	// Track stats per base domain per source IP
	key := fmt.Sprintf("%s|%s", ipInfo.SrcIP, baseDomain)
	stats, exists := d.domainStats[key]
	if !exists {
		stats = &dnsDomainStats{
			BaseDomain: baseDomain,
			SourceIP:   ipInfo.SrcIP,
			ServerIP:   ipInfo.DstIP,
			Subdomains: make(map[string]bool),
			FirstSeen:  timestamp,
		}
		d.domainStats[key] = stats
	}

	stats.QueryCount++
	stats.TotalQueryLength += len(queryName)
	stats.LastSeen = timestamp

	if subdomain != "" {
		stats.Subdomains[subdomain] = true
	}

	if len(stats.SampleQueries) < 5 {
		stats.SampleQueries = append(stats.SampleQueries, queryName)
	}

	// Check for tunneling indicators
	d.checkTunneling(key, stats, timestamp, report)
}

func (d *DNSTunnelingAnalyzer) checkTunneling(key string, stats *dnsDomainStats, timestamp time.Time, report *models.TriageReport) {
	if stats.QueryCount < DNSTunnelMinQueryCount {
		return
	}

	avgLength := float64(stats.TotalQueryLength) / float64(stats.QueryCount)
	uniqueSubdomains := len(stats.Subdomains)

	if avgLength < float64(DNSTunnelMinQueryLength) && uniqueSubdomains < DNSTunnelMinSubdomains {
		return
	}

	// Calculate entropy of subdomain labels
	entropy := calculateSubdomainEntropy(stats.Subdomains)

	// Must meet at least 2 of 3 criteria
	criteria := 0
	if avgLength >= float64(DNSTunnelMinQueryLength) {
		criteria++
	}
	if uniqueSubdomains >= DNSTunnelMinSubdomains {
		criteria++
	}
	if entropy >= DNSTunnelEntropyThreshold {
		criteria++
	}

	if criteria < 2 {
		return
	}

	// Only report once per key
	for _, f := range report.DNSTunnelingFindings {
		if f.SourceIP == stats.SourceIP && f.Domain == stats.BaseDomain {
			return
		}
	}

	ts := float64(timestamp.UnixNano()) / 1e9
	severity := "Warning"
	if criteria == 3 {
		severity = "Critical"
	}

	report.DNSTunnelingFindings = append(report.DNSTunnelingFindings, models.DNSTunnelingFinding{
		Timestamp:        ts,
		SourceIP:         stats.SourceIP,
		ServerIP:         stats.ServerIP,
		Domain:           stats.BaseDomain,
		Severity:         severity,
		Description:      fmt.Sprintf("Suspected DNS tunneling to %s from %s: %d queries, avg length %.0f chars, %d unique subdomains, entropy %.2f", stats.BaseDomain, stats.SourceIP, stats.QueryCount, avgLength, uniqueSubdomains, entropy),
		AvgQueryLength:   avgLength,
		QueryCount:       stats.QueryCount,
		UniqueSubdomains: uniqueSubdomains,
		EntropyScore:     entropy,
		SampleQueries:    stats.SampleQueries,
	})
}

func extractBaseDomain(fqdn string) string {
	fqdn = strings.TrimSuffix(fqdn, ".")
	parts := strings.Split(fqdn, ".")
	if len(parts) < 2 {
		return ""
	}
	// Return last 2 labels (e.g., "example.com")
	return strings.Join(parts[len(parts)-2:], ".")
}

func calculateSubdomainEntropy(subdomains map[string]bool) float64 {
	if len(subdomains) == 0 {
		return 0
	}

	// Concatenate all subdomain characters
	var allChars string
	for sub := range subdomains {
		allChars += sub
	}

	if len(allChars) == 0 {
		return 0
	}

	// Calculate Shannon entropy
	freq := make(map[rune]int)
	for _, c := range allChars {
		freq[c]++
	}

	total := float64(len(allChars))
	entropy := 0.0
	for _, count := range freq {
		p := float64(count) / total
		if p > 0 {
			entropy -= p * math.Log2(p)
		}
	}

	return entropy
}

func (d *DNSTunnelingAnalyzer) maybeReset(timestamp time.Time) {
	if d.lastReset.IsZero() {
		d.lastReset = timestamp
		return
	}
	if timestamp.Sub(d.lastReset).Seconds() >= DNSTunnelDetectionWindowSec {
		d.domainStats = make(map[string]*dnsDomainStats)
		d.lastReset = timestamp
	}
}
