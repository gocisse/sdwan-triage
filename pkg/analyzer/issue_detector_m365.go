package analyzer

import (
	"fmt"

	"github.com/gocisse/sdwan-triage/pkg/models"
)

// Microsoft 365 Exchange Issue Detection
func detectM365ExchangeIssues(stream *models.StreamData, classification ServiceClassification, health HealthScore) []DetectedIssue {
	if classification.Category != CategoryM365Exchange {
		return nil
	}

	issues := []DetectedIssue{}

	// Autodiscover loop detection
	if stream.Duration > 30 && stream.PacketCount > 50 {
		issue := DetectedIssue{
			ID:              "M365-EXO-001",
			Title:           "Exchange Autodiscover Loop Detected",
			TechnicalDesc:   "Client repeatedly attempting Autodiscover with no successful response",
			BusinessImpact:  "Users cannot configure Outlook profiles, email access delayed",
			Severity:        SeverityCritical,
			Confidence:      0.85,
			Category:        CategoryM365Issues,
			RootCause:       "Autodiscover DNS records misconfigured or CAS array health issue",
			AffectedService: "Exchange Online",

			BaseFilter:      buildStreamFilter(stream),
			ExpandedFilter:  buildExpandedFilter(stream),
			OptimizedFilter: buildOptimizedFilter(stream),

			InvestigationSteps: []InvestigationStep{
				{
					Order:          1,
					Purpose:        "Verify Autodiscover requests",
					DisplayFilter:  buildStreamFilter(stream) + " && http.request",
					ExpectedNormal: "1-2 Autodiscover requests with successful XML response",
					AbnormalSign:   "Multiple repeated requests (>5) with 401, 404, or timeout",
					CustomColumns:  []string{"http.request.uri", "http.response.code"},
				},
			},

			ImmediateActions: []RemediationAction{
				{
					Description:    "Verify CAS array health and Autodiscover endpoint",
					Commands:       []string{"Test-OutlookWebServices -Identity user@domain.com"},
					Verification:   "Autodiscover endpoint returns valid XML response",
					EstimatedTime:  "2 minutes",
					RequiresChange: false,
					SuccessRate:    0.75,
				},
			},

			ShortTermFixes: []RemediationAction{
				{
					Description:    "Restart MSExchangeAutodiscoverAppPool",
					Commands:       []string{"Restart-WebAppPool -Name MSExchangeAutodiscoverAppPool"},
					Verification:   "App pool running and responding to requests",
					EstimatedTime:  "5 minutes",
					RequiresChange: true,
					SuccessRate:    0.80,
				},
			},

			KnowledgeBaseRef: "KB-M365-EXO-001",
		}
		issues = append(issues, issue)
	}

	return issues
}

// Microsoft 365 Teams Issue Detection
func detectM365TeamsIssues(stream *models.StreamData, classification ServiceClassification, health HealthScore) []DetectedIssue {
	if classification.Category != CategoryM365Teams {
		return nil
	}

	issues := []DetectedIssue{}

	// Teams media quality issues
	if health.Status == HealthStatusCritical {
		for _, flag := range health.PerformanceFlags {
			if flag.Type == "high_jitter" || flag.Type == "voip_packet_loss" {
				issue := DetectedIssue{
					ID:              "M365-TEAMS-001",
					Title:           "Teams Media Quality Degraded",
					TechnicalDesc:   "High jitter or packet loss affecting Teams audio/video quality",
					BusinessImpact:  "Poor call quality, audio dropouts, video freezing",
					Severity:        SeverityCritical,
					Confidence:      0.90,
					Category:        CategoryM365Issues,
					RootCause:       "Network congestion, QoS misconfiguration, or insufficient bandwidth",
					AffectedService: "Microsoft Teams",

					BaseFilter:      buildStreamFilter(stream),
					ExpandedFilter:  buildExpandedFilter(stream),
					OptimizedFilter: buildOptimizedFilter(stream),

					ImmediateActions: []RemediationAction{
						{
							Description:    "Verify QoS policy applied to Teams traffic",
							Commands:       []string{"Get-NetQosPolicy | Where-Object {$_.AppPathNameMatchCondition -like '*Teams*'}"},
							Verification:   "QoS policy active, STUN port reachable",
							EstimatedTime:  "3 minutes",
							RequiresChange: false,
							SuccessRate:    0.75,
						},
					},

					ShortTermFixes: []RemediationAction{
						{
							Description:    "Enable QoS DSCP marking for Teams",
							Commands:       []string{"New-NetQosPolicy -Name 'Teams Audio' -AppPathNameMatchCondition 'Teams.exe' -DSCPAction 46"},
							Verification:   "Teams traffic marked with correct DSCP values",
							EstimatedTime:  "15 minutes",
							RequiresChange: true,
							SuccessRate:    0.85,
						},
					},

					KnowledgeBaseRef: "KB-M365-TEAMS-001",
				}
				issues = append(issues, issue)
				break
			}
		}
	}

	return issues
}

// Microsoft 365 SharePoint Issue Detection
func detectM365SharePointIssues(stream *models.StreamData, classification ServiceClassification, health HealthScore) []DetectedIssue {
	if classification.Category != CategoryM365SharePoint {
		return nil
	}

	issues := []DetectedIssue{}

	// Large file upload timeout
	if stream.Duration > 60 && stream.TotalBytes > 10*1024*1024 {
		issue := DetectedIssue{
			ID:              "M365-SPO-001",
			Title:           "SharePoint Large File Upload Timeout",
			TechnicalDesc:   "Large file upload to SharePoint taking excessive time or timing out",
			BusinessImpact:  "Users cannot upload documents, collaboration disrupted",
			Severity:        SeverityHigh,
			Confidence:      0.80,
			Category:        CategoryM365Issues,
			RootCause:       "Bandwidth limitation, upload throttling, or network instability",
			AffectedService: "SharePoint Online",

			BaseFilter:      buildStreamFilter(stream),
			ExpandedFilter:  buildExpandedFilter(stream),
			OptimizedFilter: buildOptimizedFilter(stream),

			ImmediateActions: []RemediationAction{
				{
					Description:    "Check SharePoint throttling limits",
					Commands:       []string{"Review Office 365 service health dashboard"},
					Verification:   "No active throttling or service degradation",
					EstimatedTime:  "2 minutes",
					RequiresChange: false,
					SuccessRate:    0.70,
				},
			},

			ShortTermFixes: []RemediationAction{
				{
					Description:    "Use OneDrive sync client instead of web upload",
					Commands:       []string{"Install OneDrive sync client", "Configure sync for document library"},
					Verification:   "Files sync successfully without timeout",
					EstimatedTime:  "10 minutes",
					RequiresChange: false,
					SuccessRate:    0.90,
				},
			},

			KnowledgeBaseRef: "KB-M365-SPO-001",
		}
		issues = append(issues, issue)
	}

	return issues
}

// Microsoft 365 OneDrive Issue Detection
func detectM365OneDriveIssues(stream *models.StreamData, classification ServiceClassification, health HealthScore) []DetectedIssue {
	if classification.Category != CategoryM365OneDrive {
		return nil
	}

	issues := []DetectedIssue{}

	// Sync conflict detection
	if health.Status == HealthStatusDegraded {
		issue := DetectedIssue{
			ID:              "M365-OD-001",
			Title:           "OneDrive Sync Conflict Detected",
			TechnicalDesc:   "OneDrive sync client experiencing conflicts or repeated sync attempts",
			BusinessImpact:  "File version conflicts, data loss risk, user confusion",
			Severity:        SeverityMedium,
			Confidence:      0.75,
			Category:        CategoryM365Issues,
			RootCause:       "Concurrent edits, network interruption, or client cache corruption",
			AffectedService: "OneDrive for Business",

			BaseFilter:      buildStreamFilter(stream),
			ExpandedFilter:  buildExpandedFilter(stream),
			OptimizedFilter: buildOptimizedFilter(stream),

			ImmediateActions: []RemediationAction{
				{
					Description:    "Check OneDrive sync client status",
					Commands:       []string{"Check OneDrive system tray icon for errors"},
					Verification:   "Sync status shows up to date",
					EstimatedTime:  "1 minute",
					RequiresChange: false,
					SuccessRate:    0.80,
				},
			},

			ShortTermFixes: []RemediationAction{
				{
					Description:    "Reset OneDrive sync client",
					Commands:       []string{"%localappdata%\\Microsoft\\OneDrive\\onedrive.exe /reset"},
					Verification:   "OneDrive resyncs successfully",
					EstimatedTime:  "10 minutes",
					RequiresChange: false,
					SuccessRate:    0.85,
				},
			},

			KnowledgeBaseRef: "KB-M365-OD-001",
		}
		issues = append(issues, issue)
	}

	return issues
}

// Helper functions for filter generation
func buildStreamFilter(stream *models.StreamData) string {
	return fmt.Sprintf("(ip.addr == %s && ip.addr == %s) && (%s.port == %d && %s.port == %d)",
		stream.SrcIP, stream.DstIP,
		stream.Protocol, stream.SrcPort,
		stream.Protocol, stream.DstPort)
}

func buildExpandedFilter(stream *models.StreamData) string {
	// Include DNS queries and ICMP messages
	base := buildStreamFilter(stream)
	dns := fmt.Sprintf("(dns && (ip.src == %s || ip.dst == %s))", stream.SrcIP, stream.DstIP)
	icmp := fmt.Sprintf("(icmp && (ip.src == %s || ip.dst == %s))", stream.SrcIP, stream.DstIP)
	return fmt.Sprintf("(%s) || (%s) || (%s)", base, dns, icmp)
}

func buildOptimizedFilter(stream *models.StreamData) string {
	// Remove keepalives and duplicate ACKs
	base := buildStreamFilter(stream)
	return fmt.Sprintf("(%s) && !(tcp.analysis.duplicate_ack) && !(tcp.analysis.keep_alive)", base)
}
