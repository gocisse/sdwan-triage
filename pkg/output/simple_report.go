package output

import (
	"fmt"
	"strings"

	"github.com/fatih/color"
	"github.com/gocisse/sdwan-triage/pkg/models"
)

// GenerateSimpleReport generates a plain English report for non-technical users
func GenerateSimpleReport(report *models.TriageReport, pcapFile string) {
	bold := color.New(color.Bold)
	green := color.New(color.FgGreen)
	yellow := color.New(color.FgYellow)
	red := color.New(color.FgRed)

	fmt.Println()
	bold.Println("═══════════════════════════════════════════════════════════════")
	bold.Println("           NETWORK HEALTH REPORT (Plain English)")
	bold.Println("═══════════════════════════════════════════════════════════════")
	fmt.Println()

	// Overall Health Status
	fmt.Println("📊 OVERALL NETWORK HEALTH")
	fmt.Println(strings.Repeat("─", 60))

	healthStatus := getHealthStatus(report)
	switch healthStatus {
	case "Healthy":
		green.Printf("✓ Your network is healthy and performing well\n")
	case "Warning":
		yellow.Printf("⚠ Your network has some issues that need attention\n")
	case "Critical":
		red.Printf("✗ Your network has serious problems requiring immediate action\n")
	}
	fmt.Println()

	// What's Happening
	fmt.Println("🔍 WHAT'S HAPPENING ON YOUR NETWORK")
	fmt.Println(strings.Repeat("─", 60))

	if report.PacketLoss != nil && report.PacketLoss.LossPercentage > 0 {
		if report.PacketLoss.LossPercentage > 5 {
			red.Printf("• %.1f%% of your data is being lost in transmission\n", report.PacketLoss.LossPercentage)
			fmt.Println("  This means: Some of your data isn't reaching its destination")
			fmt.Println("  Impact: Slow performance, failed downloads, choppy video calls")
		} else if report.PacketLoss.LossPercentage > 1 {
			yellow.Printf("• %.1f%% packet loss detected\n", report.PacketLoss.LossPercentage)
			fmt.Println("  This means: Minor data loss is occurring")
			fmt.Println("  Impact: Occasional slowdowns or glitches")
		}
	}

	if len(report.TCPRetransmissions) > 0 {
		if len(report.TCPRetransmissions) > 100 {
			red.Printf("• %d connection problems detected\n", len(report.TCPRetransmissions))
			fmt.Println("  This means: Your devices are having trouble communicating")
			fmt.Println("  Impact: Slow file transfers, laggy applications")
		} else {
			yellow.Printf("• %d minor connection issues\n", len(report.TCPRetransmissions))
		}
	}

	if len(report.DNSAnomalies) > 0 {
		yellow.Printf("• %d website lookup problems\n", len(report.DNSAnomalies))
		fmt.Println("  This means: Your network is having trouble finding websites")
		fmt.Println("  Impact: Websites may load slowly or not at all")
	}

	if len(report.FailedHandshakes) > 0 {
		red.Printf("• %d failed connection attempts\n", len(report.FailedHandshakes))
		fmt.Println("  This means: Devices can't establish connections to services")
		fmt.Println("  Impact: Applications may not work or time out")
	}

	// Security Issues
	if hasSecurityIssues(report) {
		fmt.Println()
		fmt.Println("🔒 SECURITY CONCERNS")
		fmt.Println(strings.Repeat("─", 60))

		if len(report.Security.DDoSFindings) > 0 {
			red.Printf("• Possible attack detected (%d incidents)\n", len(report.Security.DDoSFindings))
			fmt.Println("  This means: Someone may be trying to overwhelm your network")
			fmt.Println("  Action needed: Contact your IT team or network administrator")
		}

		if len(report.Security.PortScanFindings) > 0 {
			yellow.Printf("• Someone is probing your network (%d scans)\n", len(report.Security.PortScanFindings))
			fmt.Println("  This means: An external system is checking for vulnerabilities")
			fmt.Println("  Action needed: Review firewall settings")
		}

		if len(report.Security.IOCFindings) > 0 {
			red.Printf("• Suspicious activity detected (%d indicators)\n", len(report.Security.IOCFindings))
			fmt.Println("  This means: Potential malware or security threat found")
			fmt.Println("  Action needed: Run antivirus scan immediately")
		}
	}

	// Protocol Detection
	if len(report.SMBFlows) > 0 || len(report.LDAPFlows) > 0 || len(report.KerberosFlows) > 0 {
		fmt.Println()
		fmt.Println("💼 BUSINESS APPLICATIONS DETECTED")
		fmt.Println(strings.Repeat("─", 60))

		if len(report.SMBFlows) > 0 {
			green.Printf("• File sharing is active (%d connections)\n", len(report.SMBFlows))
			fmt.Println("  This means: Users are accessing shared files and folders")
		}

		if len(report.LDAPFlows) > 0 {
			green.Printf("• Directory services detected (%d queries)\n", len(report.LDAPFlows))
			fmt.Println("  This means: User authentication and directory lookups are working")
		}

		if len(report.KerberosFlows) > 0 {
			green.Printf("• Secure authentication active (%d sessions)\n", len(report.KerberosFlows))
			fmt.Println("  This means: Users are logging in securely to network resources")
		}
	}

	// Baseline Comparison
	if report.BaselineComparison != nil && report.BaselineComparison.HasBaseline {
		fmt.Println()
		fmt.Println("📈 IS THIS NORMAL?")
		fmt.Println(strings.Repeat("─", 60))

		if report.BaselineComparison.IsNormal {
			green.Println("✓ Network activity is within normal ranges")
		} else {
			yellow.Println("⚠ Network activity differs from normal patterns")

			for _, deviation := range report.BaselineComparison.Deviations {
				if deviation.Severity == "High" || deviation.Severity == "Critical" {
					red.Printf("  • %s: %.1f%% change\n", deviation.Description, deviation.Change)
				} else {
					yellow.Printf("  • %s: %.1f%% change\n", deviation.Description, deviation.Change)
				}
			}
		}

		if report.BaselineComparison.Recommendation != "" {
			fmt.Println()
			fmt.Printf("  Recommendation: %s\n", report.BaselineComparison.Recommendation)
		}
	}

	// What You Should Do
	fmt.Println()
	fmt.Println("💡 RECOMMENDED ACTIONS")
	fmt.Println(strings.Repeat("─", 60))

	actions := getRecommendedActions(report)
	if len(actions) == 0 {
		green.Println("✓ No immediate actions required - your network looks good!")
	} else {
		for i, action := range actions {
			fmt.Printf("%d. %s\n", i+1, action)
		}
	}

	fmt.Println()
	fmt.Println("═══════════════════════════════════════════════════════════════")
	fmt.Println()
}

func getHealthStatus(report *models.TriageReport) string {
	criticalIssues := 0
	warningIssues := 0

	// Check for critical issues
	if len(report.Security.DDoSFindings) > 0 {
		criticalIssues++
	}
	if len(report.Security.IOCFindings) > 0 {
		criticalIssues++
	}
	if len(report.FailedHandshakes) > 50 {
		criticalIssues++
	}
	if report.PacketLoss != nil && report.PacketLoss.LossPercentage > 5 {
		criticalIssues++
	}

	// Check for warnings
	if len(report.TCPRetransmissions) > 100 {
		warningIssues++
	}
	if len(report.DNSAnomalies) > 10 {
		warningIssues++
	}
	if len(report.Security.PortScanFindings) > 0 {
		warningIssues++
	}
	if report.PacketLoss != nil && report.PacketLoss.LossPercentage > 1 {
		warningIssues++
	}

	if criticalIssues > 0 {
		return "Critical"
	}
	if warningIssues > 0 {
		return "Warning"
	}
	return "Healthy"
}

func hasSecurityIssues(report *models.TriageReport) bool {
	return len(report.Security.DDoSFindings) > 0 ||
		len(report.Security.PortScanFindings) > 0 ||
		len(report.Security.IOCFindings) > 0 ||
		len(report.SuspiciousTraffic) > 0
}

func getRecommendedActions(report *models.TriageReport) []string {
	actions := make([]string, 0)

	if len(report.Security.DDoSFindings) > 0 {
		actions = append(actions, "Contact your network administrator immediately about potential DDoS attack")
	}

	if len(report.Security.IOCFindings) > 0 {
		actions = append(actions, "Run a full antivirus scan on all systems")
		actions = append(actions, "Check for unauthorized software or devices on the network")
	}

	if report.PacketLoss != nil && report.PacketLoss.LossPercentage > 5 {
		actions = append(actions, "Check network cables and connections for damage")
		actions = append(actions, "Restart network equipment (router, switches)")
		actions = append(actions, "Contact your ISP if problem persists")
	}

	if len(report.FailedHandshakes) > 50 {
		actions = append(actions, "Check if firewall is blocking legitimate traffic")
		actions = append(actions, "Verify server availability and capacity")
	}

	if len(report.DNSAnomalies) > 20 {
		actions = append(actions, "Check DNS server settings")
		actions = append(actions, "Consider using alternative DNS servers (e.g., 8.8.8.8)")
	}

	if len(report.Security.PortScanFindings) > 0 {
		actions = append(actions, "Review and update firewall rules")
		actions = append(actions, "Enable intrusion detection/prevention systems")
	}

	if len(actions) == 0 && len(report.TCPRetransmissions) > 100 {
		actions = append(actions, "Monitor network performance over time")
		actions = append(actions, "Consider upgrading network equipment if issues persist")
	}

	return actions
}
