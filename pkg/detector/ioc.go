package detector

import (
	"encoding/json"
	"os"
	"strings"
	"time"

	"github.com/gocisse/sdwan-triage/pkg/models"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// IOCAnalyzer handles Indicator of Compromise checking
type IOCAnalyzer struct {
	maliciousIPs     map[string]IOCEntry
	maliciousDomains map[string]IOCEntry
	enabled          bool
}

// IOCEntry represents a single IOC entry
type IOCEntry struct {
	Value       string `json:"value"`
	Type        string `json:"type"`       // "C2 Server", "Malware", "Phishing", "Botnet"
	Confidence  string `json:"confidence"` // "High", "Medium", "Low"
	Description string `json:"description"`
}

// IOCDatabase represents the IOC database file format
type IOCDatabase struct {
	IPs     []IOCEntry `json:"ips"`
	Domains []IOCEntry `json:"domains"`
}

// NewIOCAnalyzer creates a new IOC analyzer
func NewIOCAnalyzer() *IOCAnalyzer {
	analyzer := &IOCAnalyzer{
		maliciousIPs:     make(map[string]IOCEntry),
		maliciousDomains: make(map[string]IOCEntry),
		enabled:          true,
	}

	// Load default IOCs (common known bad indicators)
	analyzer.loadDefaultIOCs()

	return analyzer
}

// LoadIOCFile loads IOCs from a JSON file
func (i *IOCAnalyzer) LoadIOCFile(filename string) error {
	data, err := os.ReadFile(filename)
	if err != nil {
		return err
	}

	var db IOCDatabase
	if err := json.Unmarshal(data, &db); err != nil {
		return err
	}

	for _, entry := range db.IPs {
		i.maliciousIPs[entry.Value] = entry
	}
	for _, entry := range db.Domains {
		i.maliciousDomains[strings.ToLower(entry.Value)] = entry
	}

	return nil
}

func (i *IOCAnalyzer) loadDefaultIOCs() {
	// Sample known malicious indicators (for demonstration)
	// In production, these would be loaded from threat intelligence feeds
	defaultMaliciousIPs := []IOCEntry{
		{Value: "185.220.101.1", Type: "Tor Exit Node", Confidence: "High", Description: "Known Tor exit node"},
		{Value: "45.33.32.156", Type: "Scanner", Confidence: "Medium", Description: "Known scanner IP (scanme.nmap.org)"},
	}

	defaultMaliciousDomains := []IOCEntry{
		{Value: "malware.testcategory.com", Type: "Malware", Confidence: "High", Description: "Test malware domain"},
		{Value: "phishing.testcategory.com", Type: "Phishing", Confidence: "High", Description: "Test phishing domain"},
	}

	for _, entry := range defaultMaliciousIPs {
		i.maliciousIPs[entry.Value] = entry
	}
	for _, entry := range defaultMaliciousDomains {
		i.maliciousDomains[strings.ToLower(entry.Value)] = entry
	}
}

// AnalyzeIP checks if an IP matches any IOC
func (i *IOCAnalyzer) AnalyzeIP(packet gopacket.Packet, state *models.AnalysisState, report *models.TriageReport) {
	if !i.enabled {
		return
	}

	ipInfo := ExtractIPInfo(packet)
	if ipInfo == nil {
		return
	}

	timestamp := packet.Metadata().Timestamp

	// Check source IP
	if entry, found := i.maliciousIPs[ipInfo.SrcIP]; found {
		i.reportIOC(ipInfo.SrcIP, "", entry, "IP", timestamp, report)
	}

	// Check destination IP
	if entry, found := i.maliciousIPs[ipInfo.DstIP]; found {
		i.reportIOC("", ipInfo.DstIP, entry, "IP", timestamp, report)
	}
}

// AnalyzeDNS checks DNS queries against domain IOCs
func (i *IOCAnalyzer) AnalyzeDNS(packet gopacket.Packet, state *models.AnalysisState, report *models.TriageReport) {
	if !i.enabled {
		return
	}

	dnsLayer := packet.Layer(layers.LayerTypeDNS)
	if dnsLayer == nil {
		return
	}

	dns, ok := dnsLayer.(*layers.DNS)
	if !ok {
		return
	}

	ipInfo := ExtractIPInfo(packet)
	timestamp := packet.Metadata().Timestamp

	srcIP := ""
	dstIP := ""
	if ipInfo != nil {
		srcIP = ipInfo.SrcIP
		dstIP = ipInfo.DstIP
	}

	// Check queries
	for _, q := range dns.Questions {
		domain := strings.ToLower(string(q.Name))
		if entry, found := i.maliciousDomains[domain]; found {
			i.reportDomainIOC(domain, srcIP, dstIP, entry, timestamp, report)
		}

		// Also check parent domains
		parts := strings.Split(domain, ".")
		for j := 1; j < len(parts)-1; j++ {
			parentDomain := strings.Join(parts[j:], ".")
			if entry, found := i.maliciousDomains[parentDomain]; found {
				i.reportDomainIOC(domain, srcIP, dstIP, entry, timestamp, report)
				break
			}
		}
	}
}

func (i *IOCAnalyzer) reportIOC(srcIP, dstIP string, entry IOCEntry, matchType string, timestamp time.Time, report *models.TriageReport) {
	matchedValue := srcIP
	if matchedValue == "" {
		matchedValue = dstIP
	}

	// Check if already reported
	for _, finding := range report.Security.IOCFindings {
		if finding.MatchedValue == matchedValue && finding.Type == matchType {
			return
		}
	}

	finding := models.IOCFinding{
		Timestamp:    float64(timestamp.UnixNano()) / 1e9,
		MatchedValue: matchedValue,
		Type:         matchType,
		IOCType:      entry.Type,
		SourceIP:     srcIP,
		DestIP:       dstIP,
		Confidence:   entry.Confidence,
		Description:  entry.Description,
	}

	report.Security.IOCFindings = append(report.Security.IOCFindings, finding)
}

func (i *IOCAnalyzer) reportDomainIOC(domain, srcIP, dstIP string, entry IOCEntry, timestamp time.Time, report *models.TriageReport) {
	// Check if already reported
	for _, finding := range report.Security.IOCFindings {
		if finding.MatchedValue == domain && finding.Type == "Domain" {
			return
		}
	}

	finding := models.IOCFinding{
		Timestamp:    float64(timestamp.UnixNano()) / 1e9,
		MatchedValue: domain,
		Type:         "Domain",
		IOCType:      entry.Type,
		SourceIP:     srcIP,
		DestIP:       dstIP,
		Confidence:   entry.Confidence,
		Description:  entry.Description,
	}

	report.Security.IOCFindings = append(report.Security.IOCFindings, finding)
}

// AddIP adds an IP to the IOC list
func (i *IOCAnalyzer) AddIP(ip, iocType, confidence, description string) {
	i.maliciousIPs[ip] = IOCEntry{
		Value:       ip,
		Type:        iocType,
		Confidence:  confidence,
		Description: description,
	}
}

// AddDomain adds a domain to the IOC list
func (i *IOCAnalyzer) AddDomain(domain, iocType, confidence, description string) {
	i.maliciousDomains[strings.ToLower(domain)] = IOCEntry{
		Value:       domain,
		Type:        iocType,
		Confidence:  confidence,
		Description: description,
	}
}
