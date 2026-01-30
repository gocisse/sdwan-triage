package output

import (
	"fmt"
	"html/template"
	"sort"
	"strings"

	"github.com/gocisse/sdwan-triage/pkg/models"
)

// TroubleshootingWizard provides interactive guidance for network issues
type TroubleshootingWizard struct {
	TopIssues           []PrioritizedIssue
	TroubleshootingFlow []TroubleshootingStep
	QuickWins           []QuickWin
	ProtocolGuides      []ProtocolGuide
}

// PrioritizedIssue represents a top issue to address
type PrioritizedIssue struct {
	Rank            int
	Severity        string // "critical", "high", "medium", "low"
	Category        string // "security", "performance", "connectivity", "configuration"
	Title           string
	PlainEnglish    string // Non-technical explanation
	BusinessImpact  string
	AffectedCount   int
	WiresharkFilter string
	QuickFix        string
	DetailedSteps   []string
	RelatedIPs      []string
	Icon            string
	Color           string
}

// TroubleshootingStep represents a step in the troubleshooting flow
type TroubleshootingStep struct {
	StepNumber  int
	Title       string
	Description string
	Actions     []string
	Tools       []string
	NextStep    string
	IsComplete  bool
}

// QuickWin represents an immediately actionable fix
type QuickWin struct {
	Title       string
	Description string
	Command     string
	TimeToFix   string
	Impact      string
}

// ProtocolGuide provides troubleshooting guidance for specific protocols
type ProtocolGuide struct {
	Protocol        string
	Icon            string
	Color           string
	CommonIssues    []string
	TroubleshootTip string
	WiresharkFilter string
	LearnMoreURL    string
	// Enhanced fields
	PacketCount     int
	FlowCount       int
	FirstSeen       string
	LastSeen        string
	Duration        string
	ImpactLevel     string // "critical", "high", "medium", "low", "none"
	ImpactDetails   string
	AffectedHosts   []string
	DetailedFilters []DetailedFilter
}

// DetailedFilter provides specific Wireshark filters for different scenarios
type DetailedFilter struct {
	Name        string
	Description string
	Filter      string
	UseCase     string
}

// GenerateTroubleshootingWizard creates the wizard data from the report
func GenerateTroubleshootingWizard(report *models.TriageReport) *TroubleshootingWizard {
	wizard := &TroubleshootingWizard{
		TopIssues:      generateTopIssues(report),
		QuickWins:      generateQuickWins(report),
		ProtocolGuides: generateEnhancedProtocolGuides(report),
	}

	wizard.TroubleshootingFlow = generateTroubleshootingFlow(wizard.TopIssues)

	return wizard
}

// generateTopIssues creates prioritized list of issues
func generateTopIssues(report *models.TriageReport) []PrioritizedIssue {
	var issues []PrioritizedIssue

	// Security Issues (Critical Priority)
	if len(report.Security.DDoSFindings) > 0 {
		var ips []string
		for _, attack := range report.Security.DDoSFindings {
			ips = append(ips, attack.SourceIP)
		}
		issues = append(issues, PrioritizedIssue{
			Severity:        "critical",
			Category:        "security",
			Title:           "DDoS Attack Detected",
			PlainEnglish:    "Someone is flooding your network with fake traffic to make your services unavailable.",
			BusinessImpact:  "Users cannot access applications. Services may crash. Revenue loss possible.",
			AffectedCount:   len(report.Security.DDoSFindings),
			WiresharkFilter: generateDDoSFilter(report.Security.DDoSFindings),
			QuickFix:        "Block attacking IP addresses at the firewall immediately.",
			DetailedSteps: []string{
				"1. Identify the source IP addresses from the table below",
				"2. Add firewall rules to block these IPs: iptables -A INPUT -s [IP] -j DROP",
				"3. Enable rate limiting on affected ports",
				"4. Contact your ISP if attack persists (they can filter upstream)",
				"5. Consider enabling DDoS protection service",
			},
			RelatedIPs: ips,
			Icon:       "fa-bomb",
			Color:      "#dc2626",
		})
	}

	if len(report.Security.PortScanFindings) > 0 {
		var ips []string
		for _, scan := range report.Security.PortScanFindings {
			ips = append(ips, scan.SourceIP)
		}
		issues = append(issues, PrioritizedIssue{
			Severity:        "high",
			Category:        "security",
			Title:           "Port Scanning Activity",
			PlainEnglish:    "Someone is probing your network to find open services they can attack.",
			BusinessImpact:  "Attacker is mapping your network. An attack may follow within hours or days.",
			AffectedCount:   len(report.Security.PortScanFindings),
			WiresharkFilter: "tcp.flags.syn == 1 && tcp.flags.ack == 0",
			QuickFix:        "Monitor scanner IP for follow-up attacks. Consider blocking if external.",
			DetailedSteps: []string{
				"1. Check if scanner IP is internal (compromised host) or external (attacker)",
				"2. Run 'whois [IP]' to identify the source organization",
				"3. Review which ports were scanned - these are likely targets",
				"4. Verify those services are patched and secured",
				"5. Set up alerts for connections from scanner IP to discovered ports",
			},
			RelatedIPs: ips,
			Icon:       "fa-search",
			Color:      "#ea580c",
		})
	}

	if len(report.Security.IOCFindings) > 0 {
		issues = append(issues, PrioritizedIssue{
			Severity:        "critical",
			Category:        "security",
			Title:           "Malware Indicators Found",
			PlainEnglish:    "Traffic matches known malware or command-and-control server patterns.",
			BusinessImpact:  "Possible active malware infection. Data may be exfiltrated. Immediate action required.",
			AffectedCount:   len(report.Security.IOCFindings),
			WiresharkFilter: "ip.addr == [IOC_IP]",
			QuickFix:        "Isolate affected hosts immediately. Do not power off (preserve evidence).",
			DetailedSteps: []string{
				"1. Identify which internal hosts communicated with IOC addresses",
				"2. Isolate those hosts from the network (unplug or disable port)",
				"3. Do NOT power off - preserve memory for forensics",
				"4. Notify security team and management",
				"5. Begin incident response procedure",
			},
			Icon:  "fa-virus",
			Color: "#dc2626",
		})
	}

	// Performance Issues (High Priority)
	if len(report.FailedHandshakes) > 0 {
		var ips []string
		for _, h := range report.FailedHandshakes {
			ips = append(ips, h.DstIP)
		}
		issues = append(issues, PrioritizedIssue{
			Severity:        "high",
			Category:        "connectivity",
			Title:           "Failed TCP Connections",
			PlainEnglish:    "Devices are trying to connect to services that aren't responding.",
			BusinessImpact:  "Applications timeout. Users see 'connection refused' or 'cannot connect' errors.",
			AffectedCount:   len(report.FailedHandshakes),
			WiresharkFilter: "tcp.flags.syn == 1 && tcp.flags.ack == 0 && !tcp.analysis.retransmission",
			QuickFix:        "Check if destination services are running. Verify firewall rules.",
			DetailedSteps: []string{
				"1. Look at the destination IPs - are those servers running?",
				"2. Check if a firewall is blocking the connection",
				"3. Verify the service is listening: netstat -tlnp | grep [PORT]",
				"4. Check for network path issues: traceroute [DEST_IP]",
				"5. Review recent changes - was something deployed or updated?",
			},
			RelatedIPs: uniqueStrings(ips),
			Icon:       "fa-handshake-slash",
			Color:      "#dc2626",
		})
	}

	if len(report.TCPRetransmissions) > 10 {
		issues = append(issues, PrioritizedIssue{
			Severity:        "medium",
			Category:        "performance",
			Title:           "High Packet Retransmissions",
			PlainEnglish:    "Packets are being lost and need to be resent, slowing everything down.",
			BusinessImpact:  "Applications feel slow. File transfers take longer. Video calls may stutter.",
			AffectedCount:   len(report.TCPRetransmissions),
			WiresharkFilter: "tcp.analysis.retransmission",
			QuickFix:        "Check for network congestion, cable issues, or overloaded switches.",
			DetailedSteps: []string{
				"1. Identify which flows have the most retransmissions",
				"2. Check the network path between source and destination",
				"3. Look for interface errors: show interface [name] (on switches)",
				"4. Check for duplex mismatches or cable problems",
				"5. Review QoS policies - is traffic being dropped?",
			},
			Icon:  "fa-redo",
			Color: "#f59e0b",
		})
	}

	// DNS Issues
	if len(report.DNSAnomalies) > 0 {
		issues = append(issues, PrioritizedIssue{
			Severity:        "medium",
			Category:        "connectivity",
			Title:           "DNS Resolution Problems",
			PlainEnglish:    "Domain name lookups are failing or returning suspicious results.",
			BusinessImpact:  "Websites won't load. Applications can't find servers. Possible security issue.",
			AffectedCount:   len(report.DNSAnomalies),
			WiresharkFilter: "dns.flags.rcode != 0",
			QuickFix:        "Check DNS server health. Verify DNS configuration on clients.",
			DetailedSteps: []string{
				"1. Identify which queries are failing (NXDOMAIN, SERVFAIL)",
				"2. Test DNS resolution manually: nslookup [domain] [dns-server]",
				"3. Check if DNS server is overloaded or unreachable",
				"4. Look for unusual query patterns (possible DNS tunneling)",
				"5. Verify DNS server configuration and upstream forwarders",
			},
			Icon:  "fa-globe",
			Color: "#f59e0b",
		})
	}

	// ARP Conflicts
	if len(report.ARPConflicts) > 0 {
		issues = append(issues, PrioritizedIssue{
			Severity:        "high",
			Category:        "configuration",
			Title:           "IP Address Conflicts",
			PlainEnglish:    "Two devices are using the same IP address, causing network confusion.",
			BusinessImpact:  "Intermittent connectivity. Random disconnections. Unpredictable behavior.",
			AffectedCount:   len(report.ARPConflicts),
			WiresharkFilter: "arp",
			QuickFix:        "Find and reconfigure the device with the duplicate IP.",
			DetailedSteps: []string{
				"1. Identify the conflicting IP address from the report",
				"2. Note both MAC addresses claiming that IP",
				"3. Use MAC address lookup to identify device vendors",
				"4. Locate devices physically or via switch port mapping",
				"5. Reconfigure one device with a unique IP or use DHCP",
			},
			Icon:  "fa-exclamation-triangle",
			Color: "#dc2626",
		})
	}

	// TLS Issues
	if len(report.Security.TLSSecurityFindings) > 0 {
		issues = append(issues, PrioritizedIssue{
			Severity:        "medium",
			Category:        "security",
			Title:           "Weak Encryption Detected",
			PlainEnglish:    "Some connections use outdated encryption that could be cracked by attackers.",
			BusinessImpact:  "Sensitive data could be intercepted. Compliance violations possible.",
			AffectedCount:   len(report.Security.TLSSecurityFindings),
			WiresharkFilter: "ssl.handshake.type == 1",
			QuickFix:        "Update server TLS configuration to disable weak ciphers.",
			DetailedSteps: []string{
				"1. Identify which servers are using weak TLS",
				"2. Check the TLS version and cipher suite in use",
				"3. Update server configuration to require TLS 1.2+",
				"4. Disable weak ciphers (RC4, DES, MD5, SHA1)",
				"5. Test with: openssl s_client -connect [server]:443",
			},
			Icon:  "fa-lock-open",
			Color: "#7c3aed",
		})
	}

	// Sort by severity
	severityOrder := map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3}
	sort.Slice(issues, func(i, j int) bool {
		return severityOrder[issues[i].Severity] < severityOrder[issues[j].Severity]
	})

	// Assign ranks and limit to top 5
	for i := range issues {
		issues[i].Rank = i + 1
	}

	if len(issues) > 5 {
		issues = issues[:5]
	}

	return issues
}

// generateQuickWins creates list of immediately actionable fixes
func generateQuickWins(report *models.TriageReport) []QuickWin {
	var wins []QuickWin

	if len(report.Security.DDoSFindings) > 0 {
		for _, attack := range report.Security.DDoSFindings {
			wins = append(wins, QuickWin{
				Title:       fmt.Sprintf("Block DDoS Source: %s", attack.SourceIP),
				Description: "Add firewall rule to block attacking IP",
				Command:     fmt.Sprintf("iptables -A INPUT -s %s -j DROP", attack.SourceIP),
				TimeToFix:   "1 minute",
				Impact:      "Stops attack traffic immediately",
			})
		}
	}

	if len(report.ARPConflicts) > 0 {
		wins = append(wins, QuickWin{
			Title:       "Resolve IP Conflicts",
			Description: "Clear ARP cache and identify conflicting devices",
			Command:     "arp -d -a  # Clear ARP cache (run on affected hosts)",
			TimeToFix:   "5 minutes",
			Impact:      "Restores stable connectivity",
		})
	}

	return wins
}

// generateProtocolGuides creates protocol-specific troubleshooting guides
func generateProtocolGuides() []ProtocolGuide {
	return []ProtocolGuide{
		{
			Protocol:        "DNS",
			Icon:            "fa-globe",
			Color:           "#3b82f6",
			CommonIssues:    []string{"NXDOMAIN errors", "Slow resolution", "DNS tunneling", "Cache poisoning"},
			TroubleshootTip: "Check DNS server health, verify upstream forwarders, look for unusual query patterns",
			WiresharkFilter: "dns",
			LearnMoreURL:    "https://wiki.wireshark.org/DNS",
		},
		{
			Protocol:        "TCP/HTTP",
			Icon:            "fa-exchange-alt",
			Color:           "#10b981",
			CommonIssues:    []string{"Connection timeouts", "Retransmissions", "RST packets", "Slow response"},
			TroubleshootTip: "Follow the TCP stream, check for retransmissions, analyze RTT patterns",
			WiresharkFilter: "tcp",
			LearnMoreURL:    "https://wiki.wireshark.org/TCP_Analysis",
		},
		{
			Protocol:        "TLS/SSL",
			Icon:            "fa-lock",
			Color:           "#8b5cf6",
			CommonIssues:    []string{"Certificate errors", "Weak ciphers", "Handshake failures", "Version mismatches"},
			TroubleshootTip: "Check certificate validity, verify TLS version, analyze cipher negotiation",
			WiresharkFilter: "tls",
			LearnMoreURL:    "https://wiki.wireshark.org/TLS",
		},
		{
			Protocol:        "SMB/CIFS",
			Icon:            "fa-folder-open",
			Color:           "#f59e0b",
			CommonIssues:    []string{"Access denied", "Slow file transfers", "Connection drops", "Authentication failures"},
			TroubleshootTip: "Check SMB version negotiation, verify credentials, analyze read/write patterns",
			WiresharkFilter: "smb || smb2",
			LearnMoreURL:    "https://wiki.wireshark.org/SMB",
		},
		{
			Protocol:        "VoIP/SIP",
			Icon:            "fa-phone",
			Color:           "#06b6d4",
			CommonIssues:    []string{"Call quality issues", "One-way audio", "Registration failures", "Codec problems"},
			TroubleshootTip: "Check RTP stream quality, verify SIP registration, analyze jitter and packet loss",
			WiresharkFilter: "sip || rtp",
			LearnMoreURL:    "https://wiki.wireshark.org/SIP",
		},
		{
			Protocol:        "SD-WAN Tunnels",
			Icon:            "fa-network-wired",
			Color:           "#ec4899",
			CommonIssues:    []string{"Tunnel flapping", "Path selection issues", "Encryption problems", "MTU issues"},
			TroubleshootTip: "Identify vendor (Cisco/Velocloud/Fortinet), check tunnel health, verify underlay connectivity",
			WiresharkFilter: "udp.port == 12346 || udp.port == 2426 || esp",
			LearnMoreURL:    "https://www.cisco.com/c/en/us/solutions/enterprise-networks/sd-wan/index.html",
		},
	}
}

// generateEnhancedProtocolGuides creates enhanced protocol-specific troubleshooting guides with actual data
func generateEnhancedProtocolGuides(report *models.TriageReport) []ProtocolGuide {
	guides := []ProtocolGuide{}

	// DNS Protocol Guide
	if len(report.DNSAnomalies) > 0 || len(report.DNSDetails) > 0 {
		dnsHosts := make(map[string]bool)
		for _, anomaly := range report.DNSAnomalies {
			dnsHosts[anomaly.ServerIP] = true
		}

		var firstSeen, lastSeen float64
		if len(report.DNSAnomalies) > 0 {
			firstSeen = report.DNSAnomalies[0].Timestamp
			lastSeen = report.DNSAnomalies[len(report.DNSAnomalies)-1].Timestamp
		}

		impactLevel := "low"
		impactDetails := "Normal DNS activity detected"
		if len(report.DNSAnomalies) > 50 {
			impactLevel = "critical"
			impactDetails = fmt.Sprintf("High volume of DNS anomalies (%d) detected - potential DNS attack or misconfiguration", len(report.DNSAnomalies))
		} else if len(report.DNSAnomalies) > 10 {
			impactLevel = "high"
			impactDetails = fmt.Sprintf("%d DNS anomalies detected - investigate for resolution failures", len(report.DNSAnomalies))
		} else if len(report.DNSAnomalies) > 0 {
			impactLevel = "medium"
			impactDetails = fmt.Sprintf("%d DNS anomalies detected - minor issues present", len(report.DNSAnomalies))
		}

		guides = append(guides, ProtocolGuide{
			Protocol:        "DNS",
			Icon:            "fa-globe",
			Color:           "#3b82f6",
			CommonIssues:    []string{"NXDOMAIN errors", "Slow resolution", "DNS tunneling", "Cache poisoning"},
			TroubleshootTip: "Check DNS server health, verify upstream forwarders, look for unusual query patterns",
			WiresharkFilter: "dns",
			LearnMoreURL:    "https://wiki.wireshark.org/DNS",
			PacketCount:     len(report.DNSDetails),
			FlowCount:       len(report.DNSAnomalies),
			FirstSeen:       formatTimestamp(firstSeen),
			LastSeen:        formatTimestamp(lastSeen),
			Duration:        formatDurationSeconds(lastSeen - firstSeen),
			ImpactLevel:     impactLevel,
			ImpactDetails:   impactDetails,
			AffectedHosts:   mapKeysToSlice(dnsHosts),
			DetailedFilters: []DetailedFilter{
				{
					Name:        "DNS Failures Only",
					Description: "Show only failed DNS queries (NXDOMAIN, SERVFAIL)",
					Filter:      "dns.flags.rcode != 0",
					UseCase:     "Troubleshooting resolution failures",
				},
				{
					Name:        "DNS Queries to Specific Server",
					Description: "Filter DNS traffic to/from specific DNS server",
					Filter:      "dns && ip.addr == <SERVER_IP>",
					UseCase:     "Isolating traffic to problematic DNS server",
				},
				{
					Name:        "Slow DNS Responses",
					Description: "Find DNS queries with response time > 1 second",
					Filter:      "dns.time > 1",
					UseCase:     "Identifying performance issues",
				},
				{
					Name:        "DNS Tunneling Detection",
					Description: "Unusually large DNS queries or responses",
					Filter:      "dns && frame.len > 512",
					UseCase:     "Security investigation for data exfiltration",
				},
			},
		})
	}

	// TCP Retransmissions Guide
	if len(report.TCPRetransmissions) > 0 {
		tcpHosts := make(map[string]bool)
		for _, flow := range report.TCPRetransmissions {
			tcpHosts[flow.SrcIP] = true
			tcpHosts[flow.DstIP] = true
		}

		impactLevel := "low"
		impactDetails := "Minor TCP retransmissions detected"
		if len(report.TCPRetransmissions) > 500 {
			impactLevel = "critical"
			impactDetails = fmt.Sprintf("Severe network issues: %d TCP retransmissions - major packet loss or congestion", len(report.TCPRetransmissions))
		} else if len(report.TCPRetransmissions) > 100 {
			impactLevel = "high"
			impactDetails = fmt.Sprintf("%d TCP retransmissions - significant performance degradation expected", len(report.TCPRetransmissions))
		} else if len(report.TCPRetransmissions) > 20 {
			impactLevel = "medium"
			impactDetails = fmt.Sprintf("%d TCP retransmissions - moderate network issues", len(report.TCPRetransmissions))
		}

		guides = append(guides, ProtocolGuide{
			Protocol:        "TCP Retransmissions",
			Icon:            "fa-exchange-alt",
			Color:           "#ef4444",
			CommonIssues:    []string{"Packet loss", "Network congestion", "Routing issues", "Firewall problems"},
			TroubleshootTip: "Analyze retransmission patterns, check for packet loss, verify network path MTU",
			WiresharkFilter: "tcp.analysis.retransmission",
			LearnMoreURL:    "https://wiki.wireshark.org/TCP_Analyze_Sequence_Numbers",
			PacketCount:     len(report.TCPRetransmissions),
			FlowCount:       len(report.TCPRetransmissions),
			ImpactLevel:     impactLevel,
			ImpactDetails:   impactDetails,
			AffectedHosts:   mapKeysToSlice(tcpHosts),
			DetailedFilters: []DetailedFilter{
				{
					Name:        "All TCP Issues",
					Description: "Show all TCP analysis flags (retransmissions, out-of-order, etc.)",
					Filter:      "tcp.analysis.flags",
					UseCase:     "Comprehensive TCP troubleshooting",
				},
				{
					Name:        "Retransmissions for Specific Flow",
					Description: "Show retransmissions for a specific IP pair",
					Filter:      "tcp.analysis.retransmission && ip.addr == <IP1> && ip.addr == <IP2>",
					UseCase:     "Isolating specific connection issues",
				},
				{
					Name:        "Fast Retransmissions",
					Description: "Fast retransmissions indicate packet loss",
					Filter:      "tcp.analysis.fast_retransmission",
					UseCase:     "Identifying packet loss events",
				},
				{
					Name:        "Spurious Retransmissions",
					Description: "Unnecessary retransmissions",
					Filter:      "tcp.analysis.spurious_retransmission",
					UseCase:     "Finding network inefficiencies",
				},
			},
		})
	}

	// TLS/SSL Guide
	if len(report.TLSCerts) > 0 || len(report.TLSFlows) > 0 {
		tlsHosts := make(map[string]bool)
		for _, flow := range report.TLSFlows {
			tlsHosts[flow.SrcIP] = true
			tlsHosts[flow.DstIP] = true
		}

		impactLevel := "low"
		impactDetails := "TLS traffic detected - normal encrypted communications"
		if len(report.Security.TLSSecurityFindings) > 0 {
			impactLevel = "high"
			impactDetails = fmt.Sprintf("%d TLS security issues found - weak ciphers or certificate problems", len(report.Security.TLSSecurityFindings))
		}

		guides = append(guides, ProtocolGuide{
			Protocol:        "TLS/SSL",
			Icon:            "fa-lock",
			Color:           "#8b5cf6",
			CommonIssues:    []string{"Certificate errors", "Weak ciphers", "Handshake failures", "Version mismatches"},
			TroubleshootTip: "Check certificate validity, verify TLS version, analyze cipher negotiation",
			WiresharkFilter: "tls",
			LearnMoreURL:    "https://wiki.wireshark.org/TLS",
			PacketCount:     len(report.TLSFlows),
			FlowCount:       len(report.TLSCerts),
			ImpactLevel:     impactLevel,
			ImpactDetails:   impactDetails,
			AffectedHosts:   mapKeysToSlice(tlsHosts),
			DetailedFilters: []DetailedFilter{
				{
					Name:        "TLS Handshakes Only",
					Description: "Show only TLS handshake packets",
					Filter:      "tls.handshake",
					UseCase:     "Analyzing connection establishment",
				},
				{
					Name:        "TLS Alerts",
					Description: "Show TLS alert messages (errors)",
					Filter:      "tls.alert_message",
					UseCase:     "Troubleshooting TLS failures",
				},
				{
					Name:        "Weak Cipher Suites",
					Description: "Identify connections using weak encryption",
					Filter:      "tls.handshake.ciphersuite in {0x0004 0x0005 0x000a}",
					UseCase:     "Security audit",
				},
				{
					Name:        "TLS Version Check",
					Description: "Filter by TLS version",
					Filter:      "tls.record.version == 0x0303",
					UseCase:     "Verify TLS 1.2 usage",
				},
			},
		})
	}

	// SMB/CIFS Guide
	if len(report.SMBFlows) > 0 {
		smbHosts := make(map[string]bool)
		var firstSeen, lastSeen float64
		for i, flow := range report.SMBFlows {
			smbHosts[flow.SrcIP] = true
			smbHosts[flow.DstIP] = true
			if i == 0 {
				firstSeen = flow.FirstSeen
				lastSeen = flow.LastSeen
			} else {
				if flow.FirstSeen < firstSeen {
					firstSeen = flow.FirstSeen
				}
				if flow.LastSeen > lastSeen {
					lastSeen = flow.LastSeen
				}
			}
		}

		totalPackets := 0
		for _, flow := range report.SMBFlows {
			totalPackets += int(flow.PacketCount)
		}

		guides = append(guides, ProtocolGuide{
			Protocol:        "SMB/CIFS",
			Icon:            "fa-folder-open",
			Color:           "#f59e0b",
			CommonIssues:    []string{"Access denied", "Slow file transfers", "Connection drops", "Authentication failures"},
			TroubleshootTip: "Check SMB version negotiation, verify credentials, analyze read/write patterns",
			WiresharkFilter: "smb || smb2",
			LearnMoreURL:    "https://wiki.wireshark.org/SMB",
			PacketCount:     totalPackets,
			FlowCount:       len(report.SMBFlows),
			FirstSeen:       formatTimestamp(firstSeen),
			LastSeen:        formatTimestamp(lastSeen),
			Duration:        formatDurationSeconds(lastSeen - firstSeen),
			ImpactLevel:     "low",
			ImpactDetails:   fmt.Sprintf("%d SMB file sharing sessions detected", len(report.SMBFlows)),
			AffectedHosts:   mapKeysToSlice(smbHosts),
			DetailedFilters: []DetailedFilter{
				{
					Name:        "SMB Errors Only",
					Description: "Show SMB error responses",
					Filter:      "smb.nt_status != 0x00000000 || smb2.nt_status != 0x00000000",
					UseCase:     "Troubleshooting access issues",
				},
				{
					Name:        "SMB Version Negotiation",
					Description: "Show SMB version negotiation packets",
					Filter:      "smb.cmd == 0x72 || smb2.cmd == 0",
					UseCase:     "Verify SMB version compatibility",
				},
				{
					Name:        "SMB File Operations",
					Description: "Show file open/read/write operations",
					Filter:      "smb2.cmd in {5 8 9}",
					UseCase:     "Analyzing file access patterns",
				},
				{
					Name:        "SMB Authentication",
					Description: "Show SMB session setup and authentication",
					Filter:      "smb.cmd == 0x73 || smb2.cmd == 1",
					UseCase:     "Troubleshooting login issues",
				},
			},
		})
	}

	// LDAP Guide
	if len(report.LDAPFlows) > 0 {
		ldapHosts := make(map[string]bool)
		var firstSeen, lastSeen float64
		totalPackets := 0

		for i, flow := range report.LDAPFlows {
			ldapHosts[flow.SrcIP] = true
			ldapHosts[flow.DstIP] = true
			totalPackets += int(flow.PacketCount)
			if i == 0 {
				firstSeen = flow.FirstSeen
				lastSeen = flow.LastSeen
			} else {
				if flow.FirstSeen < firstSeen {
					firstSeen = flow.FirstSeen
				}
				if flow.LastSeen > lastSeen {
					lastSeen = flow.LastSeen
				}
			}
		}

		guides = append(guides, ProtocolGuide{
			Protocol:        "LDAP",
			Icon:            "fa-address-book",
			Color:           "#06b6d4",
			CommonIssues:    []string{"Bind failures", "Slow queries", "Connection timeouts", "Referral loops"},
			TroubleshootTip: "Check LDAP bind operations, verify search filters, analyze query performance",
			WiresharkFilter: "ldap",
			LearnMoreURL:    "https://wiki.wireshark.org/LDAP",
			PacketCount:     totalPackets,
			FlowCount:       len(report.LDAPFlows),
			FirstSeen:       formatTimestamp(firstSeen),
			LastSeen:        formatTimestamp(lastSeen),
			Duration:        formatDurationSeconds(lastSeen - firstSeen),
			ImpactLevel:     "low",
			ImpactDetails:   fmt.Sprintf("%d LDAP directory queries detected", len(report.LDAPFlows)),
			AffectedHosts:   mapKeysToSlice(ldapHosts),
			DetailedFilters: []DetailedFilter{
				{
					Name:        "LDAP Bind Operations",
					Description: "Show authentication attempts",
					Filter:      "ldap.protocolOp == 0",
					UseCase:     "Troubleshooting authentication",
				},
				{
					Name:        "LDAP Search Operations",
					Description: "Show directory search queries",
					Filter:      "ldap.protocolOp == 3",
					UseCase:     "Analyzing query patterns",
				},
				{
					Name:        "LDAP Errors",
					Description: "Show LDAP error responses",
					Filter:      "ldap.resultCode != 0",
					UseCase:     "Identifying failed operations",
				},
				{
					Name:        "LDAPS (Secure LDAP)",
					Description: "Show encrypted LDAP traffic",
					Filter:      "tcp.port == 636",
					UseCase:     "Verify secure connections",
				},
			},
		})
	}

	// Kerberos Guide
	if len(report.KerberosFlows) > 0 {
		kerbHosts := make(map[string]bool)
		var firstSeen, lastSeen float64
		totalPackets := 0

		for i, flow := range report.KerberosFlows {
			kerbHosts[flow.SrcIP] = true
			kerbHosts[flow.DstIP] = true
			totalPackets += int(flow.PacketCount)
			if i == 0 {
				firstSeen = flow.FirstSeen
				lastSeen = flow.LastSeen
			} else {
				if flow.FirstSeen < firstSeen {
					firstSeen = flow.FirstSeen
				}
				if flow.LastSeen > lastSeen {
					lastSeen = flow.LastSeen
				}
			}
		}

		guides = append(guides, ProtocolGuide{
			Protocol:        "Kerberos",
			Icon:            "fa-key",
			Color:           "#10b981",
			CommonIssues:    []string{"Clock skew errors", "Pre-authentication failures", "Ticket expiration", "Encryption type mismatches"},
			TroubleshootTip: "Verify time synchronization, check encryption types, analyze ticket requests",
			WiresharkFilter: "kerberos",
			LearnMoreURL:    "https://wiki.wireshark.org/Kerberos",
			PacketCount:     totalPackets,
			FlowCount:       len(report.KerberosFlows),
			FirstSeen:       formatTimestamp(firstSeen),
			LastSeen:        formatTimestamp(lastSeen),
			Duration:        formatDurationSeconds(lastSeen - firstSeen),
			ImpactLevel:     "low",
			ImpactDetails:   fmt.Sprintf("%d Kerberos authentication sessions detected", len(report.KerberosFlows)),
			AffectedHosts:   mapKeysToSlice(kerbHosts),
			DetailedFilters: []DetailedFilter{
				{
					Name:        "Kerberos Errors",
					Description: "Show Kerberos error messages",
					Filter:      "kerberos.msg_type == 30",
					UseCase:     "Troubleshooting authentication failures",
				},
				{
					Name:        "AS-REQ (Initial Auth)",
					Description: "Show initial authentication requests",
					Filter:      "kerberos.msg_type == 10",
					UseCase:     "Analyzing login attempts",
				},
				{
					Name:        "TGS-REQ (Service Tickets)",
					Description: "Show service ticket requests",
					Filter:      "kerberos.msg_type == 12",
					UseCase:     "Tracking service access",
				},
				{
					Name:        "Pre-auth Failures",
					Description: "Show pre-authentication failures",
					Filter:      "kerberos.error_code == 25",
					UseCase:     "Identifying clock skew issues",
				},
			},
		})
	}

	// VoIP/SIP Guide
	if report.VoIPAnalysis != nil && len(report.VoIPAnalysis.SIPCalls) > 0 {
		sipHosts := make(map[string]bool)
		for _, call := range report.VoIPAnalysis.SIPCalls {
			sipHosts[call.SrcIP] = true
			sipHosts[call.DstIP] = true
		}

		guides = append(guides, ProtocolGuide{
			Protocol:        "VoIP/SIP",
			Icon:            "fa-phone",
			Color:           "#06b6d4",
			CommonIssues:    []string{"Call quality issues", "One-way audio", "Registration failures", "Codec problems"},
			TroubleshootTip: "Check RTP stream quality, verify SIP registration, analyze jitter and packet loss",
			WiresharkFilter: "sip || rtp",
			LearnMoreURL:    "https://wiki.wireshark.org/SIP",
			FlowCount:       len(report.VoIPAnalysis.SIPCalls),
			ImpactLevel:     "medium",
			ImpactDetails:   fmt.Sprintf("%d SIP calls detected", len(report.VoIPAnalysis.SIPCalls)),
			AffectedHosts:   mapKeysToSlice(sipHosts),
			DetailedFilters: []DetailedFilter{
				{
					Name:        "SIP Errors",
					Description: "Show SIP error responses (4xx, 5xx, 6xx)",
					Filter:      "sip.Status-Code >= 400",
					UseCase:     "Troubleshooting call failures",
				},
				{
					Name:        "RTP Packet Loss",
					Description: "Show RTP streams with packet loss",
					Filter:      "rtp.seq_nr_gaps",
					UseCase:     "Analyzing audio quality issues",
				},
				{
					Name:        "SIP INVITE Messages",
					Description: "Show call setup attempts",
					Filter:      "sip.Method == INVITE",
					UseCase:     "Tracking call attempts",
				},
				{
					Name:        "RTP Jitter Analysis",
					Description: "Analyze RTP jitter for quality",
					Filter:      "rtp",
					UseCase:     "Use Statistics > RTP > Stream Analysis",
				},
			},
		})
	}

	// SD-WAN Tunnels Guide
	if len(report.TunnelAnalysis) > 0 {
		tunnelHosts := make(map[string]bool)
		for _, tunnel := range report.TunnelAnalysis {
			tunnelHosts[tunnel.SrcIP] = true
			tunnelHosts[tunnel.DstIP] = true
		}

		guides = append(guides, ProtocolGuide{
			Protocol:        "SD-WAN Tunnels",
			Icon:            "fa-network-wired",
			Color:           "#ec4899",
			CommonIssues:    []string{"Tunnel flapping", "Path selection issues", "Encryption problems", "MTU issues"},
			TroubleshootTip: "Identify vendor (Cisco/Velocloud/Fortinet), check tunnel health, verify underlay connectivity",
			WiresharkFilter: "udp.port == 12346 || udp.port == 2426 || esp",
			LearnMoreURL:    "https://www.cisco.com/c/en/us/solutions/enterprise-networks/sd-wan/index.html",
			FlowCount:       len(report.TunnelAnalysis),
			ImpactLevel:     "medium",
			ImpactDetails:   fmt.Sprintf("%d SD-WAN tunnels detected", len(report.TunnelAnalysis)),
			AffectedHosts:   mapKeysToSlice(tunnelHosts),
			DetailedFilters: []DetailedFilter{
				{
					Name:        "VXLAN Tunnels",
					Description: "Show VXLAN encapsulated traffic",
					Filter:      "vxlan",
					UseCase:     "Analyzing overlay network",
				},
				{
					Name:        "GRE Tunnels",
					Description: "Show GRE encapsulated traffic",
					Filter:      "gre",
					UseCase:     "Troubleshooting GRE tunnels",
				},
				{
					Name:        "IPsec ESP",
					Description: "Show encrypted IPsec traffic",
					Filter:      "esp",
					UseCase:     "Verifying encryption",
				},
				{
					Name:        "Cisco SD-WAN",
					Description: "Cisco SD-WAN control plane",
					Filter:      "udp.port == 12346 || udp.port == 12366",
					UseCase:     "Cisco Viptela troubleshooting",
				},
			},
		})
	}

	return guides
}

// Helper functions for enhanced protocol guides
func formatTimestamp(ts float64) string {
	if ts == 0 {
		return "N/A"
	}
	return fmt.Sprintf("%.3f", ts)
}

func formatDurationSeconds(duration float64) string {
	if duration <= 0 {
		return "N/A"
	}
	if duration < 60 {
		return fmt.Sprintf("%.1fs", duration)
	} else if duration < 3600 {
		return fmt.Sprintf("%.1fm", duration/60)
	}
	return fmt.Sprintf("%.1fh", duration/3600)
}

func mapKeysToSlice(m map[string]bool) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

// generateTroubleshootingFlow creates step-by-step troubleshooting guidance
func generateTroubleshootingFlow(issues []PrioritizedIssue) []TroubleshootingStep {
	steps := []TroubleshootingStep{
		{
			StepNumber:  1,
			Title:       "Identify the Problem",
			Description: "Review the Top Issues section to understand what's happening on your network.",
			Actions: []string{
				"Look at the severity indicators (🔴 Critical, 🟡 Warning, 🟢 Info)",
				"Read the 'Plain English' explanation for each issue",
				"Note which IPs and services are affected",
			},
			Tools:    []string{"This report", "Network diagram"},
			NextStep: "Once you understand the issues, proceed to Step 2",
		},
		{
			StepNumber:  2,
			Title:       "Gather More Information",
			Description: "Use Wireshark to examine the actual packets and confirm the issue.",
			Actions: []string{
				"Open the original PCAP file in Wireshark",
				"Apply the Wireshark filter provided for each issue",
				"Look at the packet details to understand the traffic pattern",
			},
			Tools:    []string{"Wireshark", "Original PCAP file"},
			NextStep: "After confirming the issue, proceed to Step 3",
		},
		{
			StepNumber:  3,
			Title:       "Determine Root Cause",
			Description: "Investigate why the issue is occurring.",
			Actions: []string{
				"Check if affected devices/services are running",
				"Verify network connectivity (ping, traceroute)",
				"Review recent changes (deployments, config changes)",
				"Check for resource exhaustion (CPU, memory, bandwidth)",
			},
			Tools:    []string{"ping", "traceroute", "netstat", "top/htop"},
			NextStep: "Once you know the cause, proceed to Step 4",
		},
		{
			StepNumber:  4,
			Title:       "Implement Fix",
			Description: "Apply the recommended fix or escalate if needed.",
			Actions: []string{
				"Follow the 'Quick Fix' suggestion if applicable",
				"For complex issues, follow the detailed steps provided",
				"Document what you changed",
				"If unsure, escalate to senior engineer",
			},
			Tools:    []string{"SSH/Console access", "Change management system"},
			NextStep: "After implementing, proceed to Step 5",
		},
		{
			StepNumber:  5,
			Title:       "Verify Resolution",
			Description: "Confirm the issue is resolved and document the fix.",
			Actions: []string{
				"Capture new traffic to verify issue is gone",
				"Run this tool again on new capture",
				"Confirm with users that problem is resolved",
				"Document the issue and resolution for future reference",
			},
			Tools:    []string{"tcpdump/Wireshark", "This tool", "Ticketing system"},
			NextStep: "Issue resolved! Update documentation.",
		},
	}

	return steps
}

// Helper functions
func generateDDoSFilter(attacks []models.DDoSFinding) string {
	var filters []string
	for _, attack := range attacks {
		filters = append(filters, fmt.Sprintf("ip.src == %s", attack.SourceIP))
	}
	return strings.Join(filters, " || ")
}

func uniqueStrings(input []string) []string {
	seen := make(map[string]bool)
	var result []string
	for _, s := range input {
		if !seen[s] {
			seen[s] = true
			result = append(result, s)
		}
	}
	return result
}

// ToHTML generates the HTML for the troubleshooting wizard
func (w *TroubleshootingWizard) GenerateTopIssuesHTML() template.HTML {
	if len(w.TopIssues) == 0 {
		return template.HTML(`
			<div style="background: linear-gradient(135deg, #10b981 0%, #059669 100%); border-radius: 12px; padding: 32px; text-align: center; color: white;">
				<i class="fas fa-check-circle" style="font-size: 48px; margin-bottom: 16px;"></i>
				<h3 style="margin: 0 0 8px 0; font-size: 1.5rem;">No Critical Issues Found</h3>
				<p style="margin: 0; opacity: 0.9;">Your network appears healthy. Continue monitoring for changes.</p>
			</div>
		`)
	}

	var html strings.Builder

	html.WriteString(`<div class="top-issues-container">`)

	for _, issue := range w.TopIssues {
		severityClass := issue.Severity
		severityIcon := "fa-info-circle"
		switch issue.Severity {
		case "critical":
			severityIcon = "fa-exclamation-circle"
		case "high":
			severityIcon = "fa-exclamation-triangle"
		case "medium":
			severityIcon = "fa-exclamation"
		}

		html.WriteString(fmt.Sprintf(`
			<div class="priority-issue-card %s" data-issue-id="%d">
				<div class="issue-header">
					<div class="issue-rank">#%d</div>
					<div class="issue-severity %s">
						<i class="fas %s"></i>
						%s
					</div>
				</div>
				<div class="issue-content">
					<h4 class="issue-title">
						<i class="fas %s" style="color: %s;"></i>
						%s
					</h4>
					<p class="issue-plain-english">%s</p>
					<div class="issue-impact">
						<strong>Business Impact:</strong> %s
					</div>
					<div class="issue-affected">
						<span class="affected-badge">%d affected</span>
					</div>
				</div>
				<div class="issue-actions">
					<details class="issue-details">
						<summary class="quick-fix-toggle">
							<i class="fas fa-bolt"></i> Quick Fix
						</summary>
						<div class="quick-fix-content">
							<p>%s</p>
						</div>
					</details>
					<details class="issue-details">
						<summary class="steps-toggle">
							<i class="fas fa-list-ol"></i> Step-by-Step Guide
						</summary>
						<div class="steps-content">
							<ol>`,
			severityClass, issue.Rank, issue.Rank,
			severityClass, severityIcon, strings.ToUpper(issue.Severity),
			issue.Icon, issue.Color, issue.Title,
			issue.PlainEnglish, issue.BusinessImpact, issue.AffectedCount,
			issue.QuickFix))

		for _, step := range issue.DetailedSteps {
			html.WriteString(fmt.Sprintf(`<li>%s</li>`, step))
		}

		html.WriteString(`</ol>
						</div>
					</details>`)

		if issue.WiresharkFilter != "" {
			html.WriteString(fmt.Sprintf(`
					<div class="wireshark-filter-box">
						<label>Wireshark Filter:</label>
						<code class="filter-code">%s</code>
						<button class="copy-btn" onclick="copyToClipboard('%s')">
							<i class="fas fa-copy"></i>
						</button>
					</div>`,
				issue.WiresharkFilter,
				strings.ReplaceAll(issue.WiresharkFilter, "'", "\\'")))
		}

		html.WriteString(`
				</div>
			</div>`)
	}

	html.WriteString(`</div>`)

	return template.HTML(html.String())
}

// GenerateTroubleshootingFlowHTML generates the step-by-step wizard HTML
func (w *TroubleshootingWizard) GenerateTroubleshootingFlowHTML() template.HTML {
	var html strings.Builder

	html.WriteString(`
		<div class="troubleshooting-wizard">
			<div class="wizard-header">
				<h3><i class="fas fa-magic"></i> Interactive Troubleshooting Wizard</h3>
				<p>Follow these steps to investigate and resolve network issues</p>
			</div>
			<div class="wizard-steps">`)

	for _, step := range w.TroubleshootingFlow {
		html.WriteString(fmt.Sprintf(`
				<div class="wizard-step" data-step="%d">
					<div class="step-number">%d</div>
					<div class="step-content">
						<h4 class="step-title">%s</h4>
						<p class="step-description">%s</p>
						<details class="step-details">
							<summary>View Actions & Tools</summary>
							<div class="step-actions">
								<h5>Actions:</h5>
								<ul>`,
			step.StepNumber, step.StepNumber, step.Title, step.Description))

		for _, action := range step.Actions {
			html.WriteString(fmt.Sprintf(`<li>%s</li>`, action))
		}

		html.WriteString(`</ul>
								<h5>Tools Needed:</h5>
								<div class="tools-list">`)

		for _, tool := range step.Tools {
			html.WriteString(fmt.Sprintf(`<span class="tool-badge">%s</span>`, tool))
		}

		html.WriteString(fmt.Sprintf(`</div>
							</div>
						</details>
						<div class="step-next">
							<i class="fas fa-arrow-right"></i> %s
						</div>
					</div>
				</div>`,
			step.NextStep))
	}

	html.WriteString(`
			</div>
		</div>`)

	return template.HTML(html.String())
}

// GenerateProtocolGuidesHTML generates enhanced protocol-specific troubleshooting guides
func (w *TroubleshootingWizard) GenerateProtocolGuidesHTML() template.HTML {
	var html strings.Builder

	html.WriteString(`
		<div class="protocol-guides">
			<h3><i class="fas fa-book"></i> Enhanced Protocol Troubleshooting Guides</h3>
			<p>Detailed protocol analysis with packet counts, timestamps, and advanced Wireshark filters</p>
			<div class="protocol-grid">`)

	for _, guide := range w.ProtocolGuides {
		// Determine impact badge color
		impactBadgeClass := "impact-low"
		switch guide.ImpactLevel {
		case "critical":
			impactBadgeClass = "impact-critical"
		case "high":
			impactBadgeClass = "impact-high"
		case "medium":
			impactBadgeClass = "impact-medium"
		}

		html.WriteString(fmt.Sprintf(`
				<div class="protocol-card-enhanced" style="border-left: 4px solid %s;">
					<div class="protocol-header">
						<div class="protocol-title">
							<i class="fas %s" style="color: %s;"></i>
							<h4>%s</h4>
						</div>
						<span class="impact-badge %s">%s</span>
					</div>
					
					<div class="protocol-stats">
						<div class="stat-item">
							<i class="fas fa-layer-group"></i>
							<span class="stat-label">Flows:</span>
							<span class="stat-value">%d</span>
						</div>
						<div class="stat-item">
							<i class="fas fa-cube"></i>
							<span class="stat-label">Packets:</span>
							<span class="stat-value">%d</span>
						</div>
						<div class="stat-item">
							<i class="fas fa-clock"></i>
							<span class="stat-label">Duration:</span>
							<span class="stat-value">%s</span>
						</div>
					</div>
					
					<div class="protocol-impact">
						<strong>Impact:</strong> %s
					</div>`,
			guide.Color, guide.Icon, guide.Color, guide.Protocol,
			impactBadgeClass, guide.ImpactLevel,
			guide.FlowCount, guide.PacketCount, guide.Duration,
			guide.ImpactDetails))

		// Add timestamp info if available
		if guide.FirstSeen != "N/A" && guide.LastSeen != "N/A" {
			html.WriteString(fmt.Sprintf(`
					<div class="protocol-timeline">
						<small><i class="fas fa-calendar-alt"></i> First seen: %s | Last seen: %s</small>
					</div>`,
				guide.FirstSeen, guide.LastSeen))
		}

		// Add affected hosts if available
		if len(guide.AffectedHosts) > 0 {
			hostsDisplay := strings.Join(guide.AffectedHosts[:min(5, len(guide.AffectedHosts))], ", ")
			if len(guide.AffectedHosts) > 5 {
				hostsDisplay += fmt.Sprintf(" (+%d more)", len(guide.AffectedHosts)-5)
			}
			html.WriteString(fmt.Sprintf(`
					<div class="affected-hosts">
						<strong>Affected Hosts:</strong> <code>%s</code>
					</div>`, hostsDisplay))
		}

		html.WriteString(`
					<details class="protocol-details" open>
						<summary><i class="fas fa-exclamation-triangle"></i> Common Issues</summary>
						<ul class="issues-list">`)

		for _, issue := range guide.CommonIssues {
			html.WriteString(fmt.Sprintf(`<li>%s</li>`, issue))
		}

		html.WriteString(fmt.Sprintf(`</ul>
						<div class="troubleshoot-tip">
							<i class="fas fa-lightbulb"></i> <strong>Troubleshooting Tip:</strong> %s
						</div>
					</details>
					
					<details class="protocol-filters">
						<summary><i class="fas fa-filter"></i> Wireshark Filters (%d filters available)</summary>
						
						<div class="filter-section">
							<div class="filter-item basic-filter">
								<div class="filter-header">
									<strong>Basic Filter</strong>
									<span class="filter-badge">General</span>
								</div>
								<div class="filter-code-box">
									<code class="wireshark-filter">%s</code>
									<button class="copy-filter-btn" onclick="copyToClipboard('%s')" title="Copy to clipboard">
										<i class="fas fa-copy"></i>
									</button>
								</div>
							</div>`,
			guide.TroubleshootTip,
			len(guide.DetailedFilters)+1,
			guide.WiresharkFilter, escapeForJS(guide.WiresharkFilter)))

		// Add detailed filters
		for _, filter := range guide.DetailedFilters {
			html.WriteString(fmt.Sprintf(`
							<div class="filter-item">
								<div class="filter-header">
									<strong>%s</strong>
									<span class="filter-badge">%s</span>
								</div>
								<p class="filter-description">%s</p>
								<div class="filter-code-box">
									<code class="wireshark-filter">%s</code>
									<button class="copy-filter-btn" onclick="copyToClipboard('%s')" title="Copy to clipboard">
										<i class="fas fa-copy"></i>
									</button>
								</div>
								<div class="filter-usecase">
									<i class="fas fa-info-circle"></i> <em>Use case: %s</em>
								</div>
							</div>`,
				filter.Name, filter.UseCase,
				filter.Description,
				filter.Filter, escapeForJS(filter.Filter),
				filter.UseCase))
		}

		html.WriteString(`
						</div>
					</details>
					
					<div class="protocol-footer">
						<a href="` + guide.LearnMoreURL + `" target="_blank" class="learn-more-link">
							<i class="fas fa-external-link-alt"></i> Learn More
						</a>
					</div>
				</div>`)
	}

	html.WriteString(`
			</div>
		</div>`)

	return template.HTML(html.String())
}

// Helper function for min
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// Helper function to escape strings for JavaScript
func escapeForJS(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `'`, `\'`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	s = strings.ReplaceAll(s, "\n", `\n`)
	s = strings.ReplaceAll(s, "\r", `\r`)
	return s
}
