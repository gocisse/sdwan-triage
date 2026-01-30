package analyzer

import (
	"strings"

	"github.com/gocisse/sdwan-triage/pkg/models"
)

// SecurityDetector detects security-related issues and threats
type SecurityDetector struct {
	classifier   *AdvancedClassifier
	healthScorer *HealthScorer
}

// NewSecurityDetector creates a new security detector
func NewSecurityDetector() *SecurityDetector {
	return &SecurityDetector{
		classifier:   NewAdvancedClassifier(),
		healthScorer: NewHealthScorer(),
	}
}

// DetectSecurityIssues analyzes streams for security-related problems
func (sd *SecurityDetector) DetectSecurityIssues(stream *models.StreamData) []DetectedIssue {
	issues := []DetectedIssue{}

	// SSL/TLS inspection breaking applications
	if tlsIssues := sd.detectTLSInspectionIssues(stream); len(tlsIssues) > 0 {
		issues = append(issues, tlsIssues...)
	}

	// Geo-blocking affecting legitimate traffic
	if geoIssues := sd.detectGeoBlockingIssues(stream); len(geoIssues) > 0 {
		issues = append(issues, geoIssues...)
	}

	// Certificate pinning failures
	if certIssues := sd.detectCertPinningIssues(stream); len(certIssues) > 0 {
		issues = append(issues, certIssues...)
	}

	// Unexpected traffic steering
	if steeringIssues := sd.detectTrafficSteeringIssues(stream); len(steeringIssues) > 0 {
		issues = append(issues, steeringIssues...)
	}

	// Firewall policy blocks
	if fwIssues := sd.detectFirewallBlockIssues(stream); len(fwIssues) > 0 {
		issues = append(issues, fwIssues...)
	}

	return issues
}

// detectTLSInspectionIssues detects SSL/TLS inspection breaking applications
func (sd *SecurityDetector) detectTLSInspectionIssues(stream *models.StreamData) []DetectedIssue {
	issues := []DetectedIssue{}

	// Check for TLS traffic with certificate issues
	if stream.DstPort != 443 && stream.SrcPort != 443 {
		return issues
	}

	// Look for signs of TLS inspection: connection resets after handshake
	hasReset := false
	resetAfterData := false
	dataSegments := 0

	for _, segment := range stream.Segments {
		if len(segment.Data) > 0 {
			dataSegments++
		}
		if segment.HasReset && dataSegments > 0 {
			hasReset = true
			resetAfterData = true
		}
	}

	// TLS inspection often causes resets after initial data exchange
	if hasReset && resetAfterData && stream.Duration < 5 {
		classification := sd.classifier.ClassifyStream(stream)

		// More likely if it's a known service that shouldn't be inspected
		if classification.Category == CategoryM365Teams ||
			classification.Category == CategoryM365Exchange ||
			strings.Contains(stream.ServerName, "microsoft") ||
			strings.Contains(stream.ServerName, "apple") ||
			strings.Contains(stream.ServerName, "google") {

			issue := DetectedIssue{
				ID:              "SEC-TLS-001",
				Title:           "TLS Inspection Breaking Application",
				TechnicalDesc:   "SSL/TLS inspection proxy causing connection failures for trusted service",
				BusinessImpact:  "Application unavailable, user complaints, productivity loss",
				Severity:        SeverityHigh,
				Confidence:      0.75,
				Category:        CategoryTLSIssues,
				RootCause:       "TLS inspection proxy intercepting traffic that should be bypassed",
				AffectedService: string(classification.Category),

				BaseFilter:      buildStreamFilter(stream),
				ExpandedFilter:  buildExpandedFilter(stream),
				OptimizedFilter: buildOptimizedFilter(stream),

				InvestigationSteps: []InvestigationStep{
					{
						Order:          1,
						Purpose:        "Check certificate issuer",
						DisplayFilter:  buildStreamFilter(stream) + " && ssl.handshake.certificate",
						ExpectedNormal: "Certificate issued by legitimate CA (DigiCert, Let's Encrypt, etc.)",
						AbnormalSign:   "Certificate issued by internal/proxy CA",
						CustomColumns:  []string{"ssl.handshake.certificate", "x509.issuer"},
					},
					{
						Order:          2,
						Purpose:        "Examine connection termination",
						DisplayFilter:  buildStreamFilter(stream) + " && tcp.flags.reset == 1",
						ExpectedNormal: "Clean connection closure",
						AbnormalSign:   "RST immediately after certificate exchange",
					},
				},

				ImmediateActions: []RemediationAction{
					{
						Description:    "Verify TLS inspection bypass list",
						Commands:       []string{"Check firewall/proxy bypass list for this domain", "Review SSL inspection policy"},
						Verification:   "Domain in bypass list",
						EstimatedTime:  "5 minutes",
						RequiresChange: false,
						SuccessRate:    0.85,
					},
				},

				ShortTermFixes: []RemediationAction{
					{
						Description:    "Add domain to TLS inspection bypass list",
						Commands:       []string{"Add *.microsoft.com, *.office365.com to bypass list", "Apply policy change"},
						Verification:   "Application connects successfully",
						EstimatedTime:  "15 minutes",
						RequiresChange: true,
						SuccessRate:    0.90,
						RollbackSteps:  []string{"Remove domain from bypass list"},
					},
				},

				LongTermSolutions: []RemediationAction{
					{
						Description:    "Implement category-based TLS inspection bypass",
						Verification:   "All trusted SaaS applications bypass inspection",
						EstimatedTime:  "1 week",
						RequiresChange: true,
						SuccessRate:    0.95,
					},
				},

				KnowledgeBaseRef: "KB-SEC-TLS-001",
			}
			issues = append(issues, issue)
		}
	}

	return issues
}

// detectGeoBlockingIssues detects geo-blocking affecting legitimate traffic
func (sd *SecurityDetector) detectGeoBlockingIssues(stream *models.StreamData) []DetectedIssue {
	issues := []DetectedIssue{}

	// Look for immediate connection refusal patterns
	if stream.PacketCount <= 3 && stream.Duration < 1 {
		hasReset := false
		for _, segment := range stream.Segments {
			if segment.HasReset {
				hasReset = true
				break
			}
		}

		if hasReset {
			classification := sd.classifier.ClassifyStream(stream)

			// Check if it's a legitimate business service
			if classification.Category != CategoryUnknown && classification.Confidence > 0.7 {
				issue := DetectedIssue{
					ID:              "SEC-GEO-001",
					Title:           "Possible Geo-Blocking of Legitimate Traffic",
					TechnicalDesc:   "Connection immediately refused, possibly due to geo-IP policy",
					BusinessImpact:  "Service unavailable from this location, remote users affected",
					Severity:        SeverityMedium,
					Confidence:      0.60,
					Category:        CategoryInfraIssues,
					RootCause:       "Geo-IP blocking policy or regional service restriction",
					AffectedService: string(classification.Category),

					BaseFilter:      buildStreamFilter(stream),
					ExpandedFilter:  buildExpandedFilter(stream),
					OptimizedFilter: buildOptimizedFilter(stream),

					ImmediateActions: []RemediationAction{
						{
							Description:    "Verify service availability from different location",
							Commands:       []string{"Test connection from different network/VPN", "Check service status page"},
							Verification:   "Service accessible from other locations",
							EstimatedTime:  "5 minutes",
							RequiresChange: false,
							SuccessRate:    0.80,
						},
					},

					ShortTermFixes: []RemediationAction{
						{
							Description:    "Review and update geo-IP policy",
							Commands:       []string{"Check firewall geo-IP rules", "Add exception for this service"},
							Verification:   "Connection succeeds",
							EstimatedTime:  "15 minutes",
							RequiresChange: true,
							SuccessRate:    0.85,
						},
					},

					KnowledgeBaseRef: "KB-SEC-GEO-001",
				}
				issues = append(issues, issue)
			}
		}
	}

	return issues
}

// detectCertPinningIssues detects certificate pinning failures
func (sd *SecurityDetector) detectCertPinningIssues(stream *models.StreamData) []DetectedIssue {
	issues := []DetectedIssue{}

	// Certificate pinning failures typically show as TLS handshake completion followed by immediate app-level disconnect
	if stream.DstPort != 443 && stream.SrcPort != 443 {
		return issues
	}

	// Look for pattern: successful TLS handshake but very short session
	if stream.Duration > 0.5 && stream.Duration < 3 && stream.PacketCount > 10 {
		hasReset := false
		for _, segment := range stream.Segments {
			if segment.HasReset {
				hasReset = true
				break
			}
		}

		if hasReset {
			classification := sd.classifier.ClassifyStream(stream)

			// Mobile apps commonly use certificate pinning
			if strings.Contains(stream.ServerName, "api.") ||
				strings.Contains(stream.ServerName, "mobile.") ||
				strings.Contains(stream.ServerName, "app.") {

				issue := DetectedIssue{
					ID:              "SEC-CERT-001",
					Title:           "Certificate Pinning Failure",
					TechnicalDesc:   "Application rejecting connection due to certificate mismatch (pinning)",
					BusinessImpact:  "Mobile app or API client cannot connect, user authentication fails",
					Severity:        SeverityHigh,
					Confidence:      0.70,
					Category:        CategoryTLSIssues,
					RootCause:       "TLS inspection replacing certificate, breaking app's pinned certificate validation",
					AffectedService: string(classification.Category),

					BaseFilter:      buildStreamFilter(stream),
					ExpandedFilter:  buildExpandedFilter(stream),
					OptimizedFilter: buildOptimizedFilter(stream),

					InvestigationSteps: []InvestigationStep{
						{
							Order:          1,
							Purpose:        "Verify TLS handshake completes",
							DisplayFilter:  buildStreamFilter(stream) + " && ssl.handshake.type == 20",
							ExpectedNormal: "ChangeCipherSpec message present",
							AbnormalSign:   "Handshake completes but connection immediately reset",
						},
					},

					ImmediateActions: []RemediationAction{
						{
							Description:    "Check if domain is subject to TLS inspection",
							Commands:       []string{"Review SSL inspection policy for this domain"},
							Verification:   "Determine if inspection is active",
							EstimatedTime:  "3 minutes",
							RequiresChange: false,
							SuccessRate:    0.85,
						},
					},

					ShortTermFixes: []RemediationAction{
						{
							Description:    "Bypass TLS inspection for pinned certificate domains",
							Commands:       []string{"Add domain to SSL inspection bypass list"},
							Verification:   "Application connects successfully",
							EstimatedTime:  "10 minutes",
							RequiresChange: true,
							SuccessRate:    0.90,
						},
					},

					KnowledgeBaseRef: "KB-SEC-CERT-001",
				}
				issues = append(issues, issue)
			}
		}
	}

	return issues
}

// detectTrafficSteeringIssues detects unexpected traffic steering
func (sd *SecurityDetector) detectTrafficSteeringIssues(stream *models.StreamData) []DetectedIssue {
	// Traffic steering issues require policy analysis
	return nil
}

// detectFirewallBlockIssues detects firewall policy blocks
func (sd *SecurityDetector) detectFirewallBlockIssues(stream *models.StreamData) []DetectedIssue {
	issues := []DetectedIssue{}

	// Look for ICMP unreachable or immediate TCP RST patterns
	hasReset := false
	for _, segment := range stream.Segments {
		if segment.HasReset {
			hasReset = true
			break
		}
	}

	// Immediate reset with no data exchange suggests firewall block
	if hasReset && stream.TotalBytes == 0 && stream.PacketCount <= 4 {
		classification := sd.classifier.ClassifyStream(stream)

		issue := DetectedIssue{
			ID:              "SEC-FW-001",
			Title:           "Firewall Policy Block Detected",
			TechnicalDesc:   "Connection immediately refused, likely by firewall policy",
			BusinessImpact:  "Service unreachable, application failure, user complaints",
			Severity:        SeverityHigh,
			Confidence:      0.80,
			Category:        CategoryInfraIssues,
			RootCause:       "Firewall rule blocking this traffic flow",
			AffectedService: string(classification.Category),

			BaseFilter:      buildStreamFilter(stream),
			ExpandedFilter:  buildExpandedFilter(stream) + " || (icmp.type == 3)",
			OptimizedFilter: buildOptimizedFilter(stream),

			InvestigationSteps: []InvestigationStep{
				{
					Order:          1,
					Purpose:        "Check for ICMP unreachable messages",
					DisplayFilter:  "icmp.type == 3 && ip.dst == " + stream.SrcIP,
					ExpectedNormal: "No ICMP unreachable messages",
					AbnormalSign:   "ICMP administratively prohibited or port unreachable",
					CustomColumns:  []string{"icmp.type", "icmp.code"},
				},
				{
					Order:          2,
					Purpose:        "Examine TCP RST source",
					DisplayFilter:  buildStreamFilter(stream) + " && tcp.flags.reset == 1",
					ExpectedNormal: "RST from destination after data exchange",
					AbnormalSign:   "RST immediately after SYN or from intermediate device",
				},
			},

			ImmediateActions: []RemediationAction{
				{
					Description:    "Identify blocking firewall",
					Commands:       []string{"traceroute to destination", "Check firewall logs for deny entries"},
					Verification:   "Blocking device identified",
					EstimatedTime:  "5 minutes",
					RequiresChange: false,
					SuccessRate:    0.85,
				},
			},

			ShortTermFixes: []RemediationAction{
				{
					Description:    "Add firewall rule to permit traffic",
					Commands:       []string{"Create permit rule for source/destination/port", "Apply and test"},
					Verification:   "Connection succeeds",
					EstimatedTime:  "15 minutes",
					RequiresChange: true,
					SuccessRate:    0.90,
					RollbackSteps:  []string{"Remove permit rule if security concern"},
				},
			},

			KnowledgeBaseRef: "KB-SEC-FW-001",
		}
		issues = append(issues, issue)
	}

	return issues
}

// ThreatDetector detects potential security threats
type ThreatDetector struct {
	classifier *AdvancedClassifier
}

// NewThreatDetector creates a new threat detector
func NewThreatDetector() *ThreatDetector {
	return &ThreatDetector{
		classifier: NewAdvancedClassifier(),
	}
}

// DetectThreats analyzes streams for potential security threats
func (td *ThreatDetector) DetectThreats(stream *models.StreamData) []DetectedIssue {
	issues := []DetectedIssue{}

	// DDoS pattern detection
	if ddosIssues := td.detectDDoSPatterns(stream); len(ddosIssues) > 0 {
		issues = append(issues, ddosIssues...)
	}

	// C2 beaconing detection
	if c2Issues := td.detectC2Beaconing(stream); len(c2Issues) > 0 {
		issues = append(issues, c2Issues...)
	}

	// Data exfiltration patterns
	if exfilIssues := td.detectDataExfiltration(stream); len(exfilIssues) > 0 {
		issues = append(issues, exfilIssues...)
	}

	// DNS tunneling detection
	if dnsIssues := td.detectDNSTunneling(stream); len(dnsIssues) > 0 {
		issues = append(issues, dnsIssues...)
	}

	return issues
}

// detectDDoSPatterns detects potential DDoS attack patterns
func (td *ThreatDetector) detectDDoSPatterns(stream *models.StreamData) []DetectedIssue {
	issues := []DetectedIssue{}

	// High packet rate with small packets suggests DDoS
	if stream.PacketCount > 1000 && stream.Duration > 0 {
		pps := float64(stream.PacketCount) / stream.Duration
		avgPacketSize := float64(stream.TotalBytes) / float64(stream.PacketCount)

		// Very high PPS with small packets
		if pps > 1000 && avgPacketSize < 100 {
			issue := DetectedIssue{
				ID:              "THREAT-DDOS-001",
				Title:           "Potential DDoS Attack Pattern",
				TechnicalDesc:   "High packet rate with small packet sizes indicating possible volumetric attack",
				BusinessImpact:  "Service degradation, bandwidth exhaustion, legitimate traffic affected",
				Severity:        SeverityCritical,
				Confidence:      0.70,
				Category:        CategoryInfraIssues,
				RootCause:       "Volumetric DDoS attack or misconfigured application",
				AffectedService: "Network Infrastructure",

				BaseFilter:      buildStreamFilter(stream),
				ExpandedFilter:  buildExpandedFilter(stream),
				OptimizedFilter: buildOptimizedFilter(stream),

				ImmediateActions: []RemediationAction{
					{
						Description:    "Verify if traffic is legitimate",
						Commands:       []string{"Check source IP reputation", "Verify application behavior"},
						Verification:   "Determine if attack or legitimate traffic",
						EstimatedTime:  "5 minutes",
						RequiresChange: false,
						SuccessRate:    0.80,
					},
					{
						Description:    "Enable rate limiting if attack confirmed",
						Commands:       []string{"Apply rate limit to source IP/subnet", "Monitor impact"},
						Verification:   "Attack traffic reduced",
						EstimatedTime:  "5 minutes",
						RequiresChange: true,
						SuccessRate:    0.85,
					},
				},

				ShortTermFixes: []RemediationAction{
					{
						Description:     "Block attacking source at edge",
						Commands:        []string{"Add ACL to block source IP/subnet", "Engage DDoS mitigation service"},
						Verification:    "Attack traffic blocked",
						EstimatedTime:   "15 minutes",
						RequiresChange:  true,
						SuccessRate:     0.90,
						EscalationPoint: "Engage ISP or DDoS mitigation provider for large attacks",
					},
				},

				KnowledgeBaseRef: "KB-THREAT-DDOS-001",
			}
			issues = append(issues, issue)
		}
	}

	return issues
}

// detectC2Beaconing detects potential command and control beaconing
func (td *ThreatDetector) detectC2Beaconing(stream *models.StreamData) []DetectedIssue {
	issues := []DetectedIssue{}

	// C2 beaconing typically shows regular intervals between connections
	if len(stream.Segments) < 10 {
		return issues
	}

	// Calculate inter-packet timing regularity
	intervals := make([]float64, 0)
	for i := 1; i < len(stream.Segments); i++ {
		if stream.Segments[i].GapFromPrev > 0 {
			intervals = append(intervals, stream.Segments[i].GapFromPrev)
		}
	}

	if len(intervals) < 5 {
		return issues
	}

	// Check for regular intervals (low variance)
	var sum, sumSq float64
	for _, interval := range intervals {
		sum += interval
		sumSq += interval * interval
	}
	mean := sum / float64(len(intervals))
	variance := (sumSq / float64(len(intervals))) - (mean * mean)

	// Low variance in timing suggests beaconing
	if variance < 1.0 && mean > 10 && mean < 300 { // 10-300 second intervals with low variance
		issue := DetectedIssue{
			ID:              "THREAT-C2-001",
			Title:           "Potential C2 Beaconing Detected",
			TechnicalDesc:   "Regular interval communication pattern consistent with command and control beaconing",
			BusinessImpact:  "Possible malware infection, data breach risk, compliance violation",
			Severity:        SeverityCritical,
			Confidence:      0.65,
			Category:        CategoryInfraIssues,
			RootCause:       "Malware beaconing to command and control server",
			AffectedService: "Endpoint Security",

			BaseFilter:      buildStreamFilter(stream),
			ExpandedFilter:  buildExpandedFilter(stream),
			OptimizedFilter: buildOptimizedFilter(stream),

			ImmediateActions: []RemediationAction{
				{
					Description:    "Investigate source endpoint",
					Commands:       []string{"Identify endpoint at " + stream.SrcIP, "Run endpoint security scan"},
					Verification:   "Endpoint identified and scanned",
					EstimatedTime:  "10 minutes",
					RequiresChange: false,
					SuccessRate:    0.80,
				},
				{
					Description:    "Check destination IP reputation",
					Commands:       []string{"Query threat intelligence for " + stream.DstIP, "Check domain reputation"},
					Verification:   "Destination reputation determined",
					EstimatedTime:  "5 minutes",
					RequiresChange: false,
					SuccessRate:    0.85,
				},
			},

			ShortTermFixes: []RemediationAction{
				{
					Description:     "Isolate potentially infected endpoint",
					Commands:        []string{"Quarantine endpoint from network", "Block destination IP at firewall"},
					Verification:    "Endpoint isolated, C2 traffic blocked",
					EstimatedTime:   "15 minutes",
					RequiresChange:  true,
					SuccessRate:     0.90,
					EscalationPoint: "Engage incident response team for confirmed infections",
				},
			},

			KnowledgeBaseRef: "KB-THREAT-C2-001",
		}
		issues = append(issues, issue)
	}

	return issues
}

// detectDataExfiltration detects potential data exfiltration patterns
func (td *ThreatDetector) detectDataExfiltration(stream *models.StreamData) []DetectedIssue {
	issues := []DetectedIssue{}

	// Large outbound data transfer to unusual destination
	if stream.TotalBytes > 100*1024*1024 { // > 100MB
		classification := td.classifier.ClassifyStream(stream)

		// If not a known service, flag as potential exfiltration
		if classification.Category == CategoryUnknown || classification.Confidence < 0.5 {
			issue := DetectedIssue{
				ID:              "THREAT-EXFIL-001",
				Title:           "Potential Data Exfiltration",
				TechnicalDesc:   "Large data transfer to unclassified destination",
				BusinessImpact:  "Possible data breach, intellectual property theft, compliance violation",
				Severity:        SeverityHigh,
				Confidence:      0.60,
				Category:        CategoryInfraIssues,
				RootCause:       "Unauthorized data transfer or misconfigured backup",
				AffectedService: "Data Loss Prevention",

				BaseFilter:      buildStreamFilter(stream),
				ExpandedFilter:  buildExpandedFilter(stream),
				OptimizedFilter: buildOptimizedFilter(stream),

				ImmediateActions: []RemediationAction{
					{
						Description:    "Identify data transfer purpose",
						Commands:       []string{"Check with user at " + stream.SrcIP, "Review application logs"},
						Verification:   "Transfer purpose identified",
						EstimatedTime:  "10 minutes",
						RequiresChange: false,
						SuccessRate:    0.75,
					},
				},

				ShortTermFixes: []RemediationAction{
					{
						Description:     "Block suspicious transfer if unauthorized",
						Commands:        []string{"Block destination IP", "Terminate active session"},
						Verification:    "Transfer stopped",
						EstimatedTime:   "5 minutes",
						RequiresChange:  true,
						SuccessRate:     0.90,
						EscalationPoint: "Engage security team for investigation",
					},
				},

				KnowledgeBaseRef: "KB-THREAT-EXFIL-001",
			}
			issues = append(issues, issue)
		}
	}

	return issues
}

// detectDNSTunneling detects potential DNS tunneling attempts
func (td *ThreatDetector) detectDNSTunneling(stream *models.StreamData) []DetectedIssue {
	issues := []DetectedIssue{}

	// DNS tunneling uses port 53 with unusual patterns
	if stream.DstPort != 53 && stream.SrcPort != 53 {
		return issues
	}

	// High data volume over DNS is suspicious
	if stream.TotalBytes > 10*1024 { // > 10KB over DNS
		avgPacketSize := float64(stream.TotalBytes) / float64(stream.PacketCount)

		// Large DNS packets suggest tunneling
		if avgPacketSize > 200 {
			issue := DetectedIssue{
				ID:              "THREAT-DNS-001",
				Title:           "Potential DNS Tunneling",
				TechnicalDesc:   "Unusually large DNS traffic volume suggesting data tunneling",
				BusinessImpact:  "Data exfiltration via DNS, security control bypass",
				Severity:        SeverityHigh,
				Confidence:      0.70,
				Category:        CategoryDNSIssues,
				RootCause:       "DNS tunneling tool or malware using DNS for covert communication",
				AffectedService: "DNS Security",

				BaseFilter:      buildStreamFilter(stream),
				ExpandedFilter:  buildExpandedFilter(stream),
				OptimizedFilter: buildOptimizedFilter(stream),

				InvestigationSteps: []InvestigationStep{
					{
						Order:          1,
						Purpose:        "Examine DNS query patterns",
						DisplayFilter:  buildStreamFilter(stream) + " && dns",
						ExpectedNormal: "Standard DNS queries with short names",
						AbnormalSign:   "Long encoded subdomains, TXT record queries",
						CustomColumns:  []string{"dns.qry.name", "dns.qry.type", "dns.resp.len"},
					},
				},

				ImmediateActions: []RemediationAction{
					{
						Description:    "Analyze DNS query content",
						Commands:       []string{"Extract DNS queries from PCAP", "Check for encoded data in subdomains"},
						Verification:   "Tunneling confirmed or ruled out",
						EstimatedTime:  "10 minutes",
						RequiresChange: false,
						SuccessRate:    0.80,
					},
				},

				ShortTermFixes: []RemediationAction{
					{
						Description:    "Block suspicious DNS destination",
						Commands:       []string{"Add DNS server to blocklist", "Force DNS through internal resolvers"},
						Verification:   "Tunneling traffic blocked",
						EstimatedTime:  "15 minutes",
						RequiresChange: true,
						SuccessRate:    0.85,
					},
				},

				KnowledgeBaseRef: "KB-THREAT-DNS-001",
			}
			issues = append(issues, issue)
		}
	}

	return issues
}
