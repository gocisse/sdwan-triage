package detector

import (
	"fmt"
	"strings"

	"github.com/gocisse/sdwan-triage/pkg/models"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// DNSAnalyzer handles DNS packet analysis
type DNSAnalyzer struct{}

// NewDNSAnalyzer creates a new DNS analyzer
func NewDNSAnalyzer() *DNSAnalyzer {
	return &DNSAnalyzer{}
}

// Analyze processes a DNS packet and updates the report
func (d *DNSAnalyzer) Analyze(packet gopacket.Packet, state *models.AnalysisState, report *models.TriageReport) {
	dnsLayer := packet.Layer(layers.LayerTypeDNS)
	if dnsLayer == nil {
		return
	}

	dns, ok := dnsLayer.(*layers.DNS)
	if !ok {
		return
	}

	// Get network layer info (supports IPv4 and IPv6)
	ipInfo := ExtractIPInfo(packet)
	if ipInfo == nil {
		return
	}
	srcIP := ipInfo.SrcIP
	dstIP := ipInfo.DstIP

	// Get MAC address from Ethernet layer
	var srcMAC string
	if ethLayer := packet.Layer(layers.LayerTypeEthernet); ethLayer != nil {
		eth := ethLayer.(*layers.Ethernet)
		srcMAC = eth.SrcMAC.String()
	}

	timestamp := float64(packet.Metadata().Timestamp.UnixNano()) / 1e9

	// Track DNS queries
	if dns.QR == false && len(dns.Questions) > 0 {
		queryName := string(dns.Questions[0].Name)
		state.DNSQueries[dns.ID] = queryName

		// Add to DNS details
		queryType := dns.Questions[0].Type.String()
		record := models.DNSRecord{
			QueryTimestamp: timestamp,
			QueryName:      queryName,
			QueryType:      queryType,
			SourceIP:       srcIP,
			DestinationIP:  dstIP,
			AnswerIPs:      []string{},
			AnswerNames:    []string{},
		}
		report.DNSDetails = append(report.DNSDetails, record)

		// Add timeline event
		event := models.TimelineEvent{
			Timestamp:     timestamp,
			EventType:     "DNS Query",
			SourceIP:      srcIP,
			DestinationIP: dstIP,
			Protocol:      "DNS",
			Detail:        fmt.Sprintf("Query: %s (%s)", queryName, queryType),
		}
		report.Timeline = append(report.Timeline, event)
	}

	// Analyze DNS responses
	if dns.QR == true {
		queryName := state.DNSQueries[dns.ID]
		if queryName == "" && len(dns.Questions) > 0 {
			queryName = string(dns.Questions[0].Name)
		}

		// Find and update the corresponding DNS query record
		responseCode := uint16(dns.ResponseCode)
		for i := range report.DNSDetails {
			if report.DNSDetails[i].QueryName == queryName && report.DNSDetails[i].ResponseTimestamp == nil {
				// Update the record with response data
				report.DNSDetails[i].ResponseTimestamp = &timestamp
				report.DNSDetails[i].ResponseCode = &responseCode

				// Collect all answer IPs and names
				for _, answer := range dns.Answers {
					if answer.Type == layers.DNSTypeA || answer.Type == layers.DNSTypeAAAA {
						if answer.IP != nil {
							report.DNSDetails[i].AnswerIPs = append(report.DNSDetails[i].AnswerIPs, answer.IP.String())
						}
					} else if answer.Type == layers.DNSTypeCNAME {
						report.DNSDetails[i].AnswerNames = append(report.DNSDetails[i].AnswerNames, string(answer.CNAME))
					}
				}

				// Check for anomalies and mark the record
				isAnomalous := false
				reason := ""

				for _, answer := range dns.Answers {
					if answer.Type == layers.DNSTypeA || answer.Type == layers.DNSTypeAAAA {
						answerIP := answer.IP.String()

						// Check if DNS server is non-standard (not a known DNS server)
						if !models.IsPrivateOrReservedIP(srcIP) && !isKnownDNSServer(srcIP) {
							isAnomalous = true
							reason = "Response from non-standard DNS server"
						}

						// Check for private IP in response to public domain query
						if models.IsPublicDomain(queryName) && models.IsPrivateOrReservedIP(answerIP) {
							isAnomalous = true
							reason = "Private IP returned for public domain (possible DNS hijacking)"
						}

						// Check for suspicious TLDs
						if isSuspiciousDomain(queryName) {
							isAnomalous = true
							reason = "Suspicious domain pattern detected"
						}

						if isAnomalous {
							anomaly := models.DNSAnomaly{
								Timestamp: timestamp,
								Query:     queryName,
								AnswerIP:  answerIP,
								ServerIP:  srcIP,
								ServerMAC: srcMAC,
								Reason:    reason,
							}
							report.DNSAnomalies = append(report.DNSAnomalies, anomaly)
						}
					}
				}

				// Update anomaly status on the record
				if isAnomalous {
					report.DNSDetails[i].IsAnomalous = true
					report.DNSDetails[i].Detail = reason
				}

				break // Found and updated the matching query
			}
		}

		// Add timeline event for response
		if len(dns.Answers) > 0 {
			var firstAnswerIP string
			for _, answer := range dns.Answers {
				if answer.Type == layers.DNSTypeA || answer.Type == layers.DNSTypeAAAA {
					firstAnswerIP = answer.IP.String()
					break
				}
			}
			event := models.TimelineEvent{
				Timestamp:     timestamp,
				EventType:     "DNS Response",
				SourceIP:      srcIP,
				DestinationIP: dstIP,
				Protocol:      "DNS",
				Detail:        fmt.Sprintf("Response: %s -> %s (code: %d)", queryName, firstAnswerIP, responseCode),
			}
			report.Timeline = append(report.Timeline, event)
		}
	}
}

// isKnownDNSServer checks if an IP is a known public DNS server
func isKnownDNSServer(ip string) bool {
	knownDNS := map[string]bool{
		"8.8.8.8":        true, // Google
		"8.8.4.4":        true, // Google
		"1.1.1.1":        true, // Cloudflare
		"1.0.0.1":        true, // Cloudflare
		"9.9.9.9":        true, // Quad9
		"208.67.222.222": true, // OpenDNS
		"208.67.220.220": true, // OpenDNS
		"64.6.64.6":      true, // Verisign
		"64.6.65.6":      true, // Verisign
	}
	return knownDNS[ip]
}

// isSuspiciousDomain checks for suspicious domain patterns
func isSuspiciousDomain(domain string) bool {
	domain = strings.ToLower(domain)

	// Check for suspicious TLDs
	suspiciousTLDs := []string{".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".work", ".click"}
	for _, tld := range suspiciousTLDs {
		if strings.HasSuffix(domain, tld) {
			return true
		}
	}

	// Check for excessive subdomains (potential DGA)
	parts := strings.Split(domain, ".")
	if len(parts) > 5 {
		return true
	}

	// Check for very long domain names (potential DGA)
	if len(domain) > 50 {
		return true
	}

	return false
}
