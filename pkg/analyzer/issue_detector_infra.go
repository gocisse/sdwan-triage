package analyzer

import (
	"fmt"

	"github.com/gocisse/sdwan-triage/pkg/models"
)

// DNS Issue Detection
func detectDNSIssues(stream *models.StreamData, classification ServiceClassification, health HealthScore) []DetectedIssue {
	if classification.Category != CategoryDNS {
		return nil
	}

	issues := []DetectedIssue{}

	// DNS timeout
	if health.Status == HealthStatusCritical || stream.Duration > 2.0 {
		issue := DetectedIssue{
			ID:              "DNS-001",
			Title:           "DNS Resolution Timeout",
			TechnicalDesc:   "DNS query not receiving response within acceptable timeframe",
			BusinessImpact:  "Application failures, web browsing delays, service unavailability",
			Severity:        SeverityCritical,
			Confidence:      0.95,
			Category:        CategoryDNSIssues,
			RootCause:       "DNS server unreachable, overloaded, or misconfigured",
			AffectedService: "DNS Resolution",

			BaseFilter:      buildStreamFilter(stream),
			ExpandedFilter:  buildExpandedFilter(stream),
			OptimizedFilter: buildOptimizedFilter(stream),

			InvestigationSteps: []InvestigationStep{
				{
					Order:          1,
					Purpose:        "Verify DNS query sent",
					DisplayFilter:  buildStreamFilter(stream) + " && dns.flags.response == 0",
					ExpectedNormal: "DNS query packet present",
					AbnormalSign:   "No query packet found",
				},
				{
					Order:          2,
					Purpose:        "Check for DNS response",
					DisplayFilter:  buildStreamFilter(stream) + " && dns.flags.response == 1",
					ExpectedNormal: "DNS response within 100ms",
					AbnormalSign:   "No response or SERVFAIL/NXDOMAIN",
					CustomColumns:  []string{"dns.qry.name", "dns.resp.name", "dns.flags.rcode"},
				},
			},

			ImmediateActions: []RemediationAction{
				{
					Description:    "Test DNS server reachability",
					Commands:       []string{"nslookup google.com " + stream.DstIP, "ping " + stream.DstIP},
					Verification:   "DNS server responds to queries",
					EstimatedTime:  "1 minute",
					RequiresChange: false,
					SuccessRate:    0.90,
				},
				{
					Description:    "Switch to alternate DNS server temporarily",
					Commands:       []string{"Use 8.8.8.8 or 1.1.1.1", "Test resolution"},
					Verification:   "DNS queries resolve successfully",
					EstimatedTime:  "2 minutes",
					RequiresChange: false,
					SuccessRate:    0.85,
				},
			},

			ShortTermFixes: []RemediationAction{
				{
					Description:    "Restart DNS service on server",
					Commands:       []string{"Restart-Service DNS", "Clear-DnsServerCache"},
					Verification:   "DNS service running, queries resolving",
					EstimatedTime:  "5 minutes",
					RequiresChange: true,
					SuccessRate:    0.80,
					RollbackSteps:  []string{"Service restarts automatically"},
				},
			},

			LongTermSolutions: []RemediationAction{
				{
					Description:    "Implement redundant DNS infrastructure with monitoring",
					Verification:   "DNS queries resolve reliably with failover",
					EstimatedTime:  "1 week",
					RequiresChange: true,
					SuccessRate:    0.95,
				},
			},

			KnowledgeBaseRef: "KB-DNS-001",
		}
		issues = append(issues, issue)
	}

	// DNS retry storm
	if stream.PacketCount > 10 {
		issue := DetectedIssue{
			ID:              "DNS-002",
			Title:           "DNS Query Retry Storm",
			TechnicalDesc:   "Excessive DNS query retries indicating server unresponsiveness",
			BusinessImpact:  "Network congestion, application timeouts, poor user experience",
			Severity:        SeverityHigh,
			Confidence:      0.85,
			Category:        CategoryDNSIssues,
			RootCause:       "DNS server overload, network packet loss, or firewall blocking",
			AffectedService: "DNS Resolution",

			BaseFilter:      buildStreamFilter(stream),
			ExpandedFilter:  buildExpandedFilter(stream),
			OptimizedFilter: buildOptimizedFilter(stream),

			ImmediateActions: []RemediationAction{
				{
					Description:    "Check DNS server load",
					Commands:       []string{"Check DNS server CPU and memory usage"},
					Verification:   "DNS server not overloaded",
					EstimatedTime:  "2 minutes",
					RequiresChange: false,
					SuccessRate:    0.75,
				},
			},

			ShortTermFixes: []RemediationAction{
				{
					Description:    "Increase DNS cache size",
					Commands:       []string{"Set-DnsServerCache -MaxCacheTTL 86400"},
					Verification:   "Reduced query load on DNS server",
					EstimatedTime:  "10 minutes",
					RequiresChange: true,
					SuccessRate:    0.80,
				},
			},

			KnowledgeBaseRef: "KB-DNS-002",
		}
		issues = append(issues, issue)
	}

	return issues
}

// NTP Issue Detection
func detectNTPIssues(stream *models.StreamData, classification ServiceClassification, health HealthScore) []DetectedIssue {
	if classification.Category != CategoryNTP {
		return nil
	}

	issues := []DetectedIssue{}

	// NTP sync timeout
	if stream.Duration > 2.0 {
		issue := DetectedIssue{
			ID:              "NTP-001",
			Title:           "NTP Time Synchronization Timeout",
			TechnicalDesc:   "NTP sync taking excessive time or failing",
			BusinessImpact:  "Time drift, authentication failures, log correlation issues",
			Severity:        SeverityHigh,
			Confidence:      0.85,
			Category:        CategoryNTPIssues,
			RootCause:       "NTP server unreachable or network latency",
			AffectedService: "NTP Time Sync",

			BaseFilter:      buildStreamFilter(stream),
			ExpandedFilter:  buildExpandedFilter(stream),
			OptimizedFilter: buildOptimizedFilter(stream),

			ImmediateActions: []RemediationAction{
				{
					Description:    "Test NTP server reachability",
					Commands:       []string{"w32tm /stripchart /computer:" + stream.DstIP, "Test-NetConnection -ComputerName " + stream.DstIP + " -Port 123"},
					Verification:   "NTP server responds",
					EstimatedTime:  "2 minutes",
					RequiresChange: false,
					SuccessRate:    0.85,
				},
			},

			ShortTermFixes: []RemediationAction{
				{
					Description:    "Switch to alternate NTP server",
					Commands:       []string{"w32tm /config /manualpeerlist:time.windows.com /syncfromflags:manual /update", "w32tm /resync"},
					Verification:   "Time synchronized successfully",
					EstimatedTime:  "5 minutes",
					RequiresChange: true,
					SuccessRate:    0.90,
					RollbackSteps:  []string{"Restore previous NTP configuration"},
				},
			},

			KnowledgeBaseRef: "KB-NTP-001",
		}
		issues = append(issues, issue)
	}

	return issues
}

// SD-WAN Control Plane Issue Detection
func detectSDWANControlPlaneIssues(stream *models.StreamData, classification ServiceClassification, health HealthScore) []DetectedIssue {
	if classification.Category != CategoryCiscoViptela &&
		classification.Category != CategoryVeloCloud &&
		classification.Category != CategoryAruba &&
		classification.Category != CategoryPaloAlto &&
		classification.Category != CategorySilverPeak &&
		classification.Category != CategoryFortinet {
		return nil
	}

	issues := []DetectedIssue{}

	// Control plane connection failure
	if health.Status == HealthStatusCritical {
		vendorName := classification.VendorIdentified
		if vendorName == "" {
			vendorName = "SD-WAN"
		}

		issue := DetectedIssue{
			ID:              "SDWAN-CTRL-001",
			Title:           fmt.Sprintf("%s Controller Unreachable", vendorName),
			TechnicalDesc:   "SD-WAN control plane connection timeout or failure",
			BusinessImpact:  "Site loses policy updates, cannot establish new tunnels, management visibility lost",
			Severity:        SeverityCritical,
			Confidence:      0.90,
			Category:        CategorySDWANControl,
			RootCause:       "Network connectivity issue, controller outage, or certificate problem",
			AffectedService: vendorName + " Control Plane",

			BaseFilter:      buildStreamFilter(stream),
			ExpandedFilter:  buildExpandedFilter(stream),
			OptimizedFilter: buildOptimizedFilter(stream),

			InvestigationSteps: []InvestigationStep{
				{
					Order:          1,
					Purpose:        "Verify control plane packets sent",
					DisplayFilter:  buildStreamFilter(stream),
					ExpectedNormal: "Regular control plane keepalives",
					AbnormalSign:   "No response packets or TCP resets",
				},
				{
					Order:          2,
					Purpose:        "Check for certificate issues",
					DisplayFilter:  buildStreamFilter(stream) + " && ssl",
					ExpectedNormal: "Successful TLS handshake",
					AbnormalSign:   "Certificate validation failure or handshake timeout",
				},
			},

			ImmediateActions: []RemediationAction{
				{
					Description:    "Verify controller reachability",
					Commands:       []string{"ping <controller-ip>", "Test-NetConnection -ComputerName <controller-ip> -Port 443"},
					Verification:   "Controller responds to ping and HTTPS",
					EstimatedTime:  "2 minutes",
					RequiresChange: false,
					SuccessRate:    0.85,
				},
				{
					Description:    "Check local WAN interface status",
					Commands:       []string{"Show interface status", "Check WAN link state"},
					Verification:   "WAN interface up and operational",
					EstimatedTime:  "1 minute",
					RequiresChange: false,
					SuccessRate:    0.80,
				},
			},

			ShortTermFixes: []RemediationAction{
				{
					Description:    "Restart SD-WAN control plane service",
					Commands:       []string{"Restart control plane daemon", "Monitor reconnection"},
					Verification:   "Control plane connection re-established",
					EstimatedTime:  "5 minutes",
					RequiresChange: true,
					SuccessRate:    0.75,
					RollbackSteps:  []string{"Service restarts automatically"},
				},
			},

			LongTermSolutions: []RemediationAction{
				{
					Description:     "Implement redundant controller connectivity",
					Verification:    "Automatic failover to backup controller",
					EstimatedTime:   "1 week",
					RequiresChange:  true,
					SuccessRate:     0.95,
					EscalationPoint: "Engage SD-WAN vendor support if persistent",
				},
			},

			KnowledgeBaseRef: "KB-SDWAN-CTRL-001",
		}
		issues = append(issues, issue)
	}

	return issues
}

// SD-WAN Data Plane Issue Detection
func detectSDWANDataPlaneIssues(stream *models.StreamData, classification ServiceClassification, health HealthScore) []DetectedIssue {
	// Placeholder for data plane detection
	return nil
}

// Database Connectivity Issue Detection
func detectDatabaseIssues(stream *models.StreamData, classification ServiceClassification, health HealthScore) []DetectedIssue {
	if classification.Category != CategorySAP && classification.Category != CategoryOracle {
		return nil
	}

	issues := []DetectedIssue{}

	// Database connection timeout
	if health.Status == HealthStatusCritical || stream.Duration > 10 {
		dbType := "Database"
		if classification.Category == CategorySAP {
			dbType = "SAP"
		} else if classification.Category == CategoryOracle {
			dbType = "Oracle"
		}

		issue := DetectedIssue{
			ID:              "DB-001",
			Title:           fmt.Sprintf("%s Connection Timeout", dbType),
			TechnicalDesc:   "Database connection taking excessive time or failing",
			BusinessImpact:  "Application unavailable, business process disruption, user complaints",
			Severity:        SeverityCritical,
			Confidence:      0.85,
			Category:        CategoryDatabaseIssues,
			RootCause:       "Database server overload, network latency, or listener issue",
			AffectedService: dbType + " Database",

			BaseFilter:      buildStreamFilter(stream),
			ExpandedFilter:  buildExpandedFilter(stream),
			OptimizedFilter: buildOptimizedFilter(stream),

			ImmediateActions: []RemediationAction{
				{
					Description:    "Verify database listener status",
					Commands:       []string{"lsnrctl status", "Check database availability"},
					Verification:   "Listener running and accepting connections",
					EstimatedTime:  "2 minutes",
					RequiresChange: false,
					SuccessRate:    0.80,
				},
			},

			ShortTermFixes: []RemediationAction{
				{
					Description:     "Restart database listener",
					Commands:        []string{"lsnrctl stop", "lsnrctl start"},
					Verification:    "Listener accepting connections",
					EstimatedTime:   "5 minutes",
					RequiresChange:  true,
					SuccessRate:     0.75,
					RollbackSteps:   []string{"Listener restarts automatically"},
					EscalationPoint: "Engage DBA if issue persists",
				},
			},

			LongTermSolutions: []RemediationAction{
				{
					Description:    "Optimize database performance and connection pooling",
					Verification:   "Consistent low connection latency",
					EstimatedTime:  "2 weeks",
					RequiresChange: true,
					SuccessRate:    0.90,
				},
			},

			KnowledgeBaseRef: "KB-DB-001",
		}
		issues = append(issues, issue)
	}

	return issues
}
