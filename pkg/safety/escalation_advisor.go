package safety

import (
	"fmt"
	"strings"
)

// EscalationRecommendation contains escalation guidance
type EscalationRecommendation struct {
	ShouldEscalate bool              `json:"should_escalate"`
	Urgency        EscalationUrgency `json:"urgency"`
	Reasons        []string          `json:"reasons"`
	Contact        ContactInfo       `json:"contact"`
	WhatToSay      string            `json:"what_to_say"`
	WhatToInclude  []string          `json:"what_to_include"`
	WhatNotToDo    []string          `json:"what_not_to_do"`
	TimeToEscalate string            `json:"time_to_escalate"`
}

// EscalationUrgency indicates how urgent the escalation is
type EscalationUrgency string

const (
	UrgencyImmediate EscalationUrgency = "IMMEDIATE" // Drop everything, call now
	UrgencyHigh      EscalationUrgency = "HIGH"      // Within 15 minutes
	UrgencyMedium    EscalationUrgency = "MEDIUM"    // Within 1 hour
	UrgencyLow       EscalationUrgency = "LOW"       // Within 4 hours
)

// ContactInfo contains who to contact for escalation
type ContactInfo struct {
	Role           string   `json:"role"`
	Team           string   `json:"team"`
	ContactMethods []string `json:"contact_methods"`
	BackupContact  string   `json:"backup_contact,omitempty"`
	VendorTAC      string   `json:"vendor_tac,omitempty"`
}

// CustomerContext contains customer-specific information
type CustomerContext struct {
	CustomerID           string
	CustomerName         string
	HasExecutiveAffected bool
	IsCriticalBusiness   bool
	HasSLA               bool
	SLALevel             string
	VendorName           string
}

// ShouldEscalate determines if and how to escalate an issue
func ShouldEscalate(ctx IssueContext, customer CustomerContext) EscalationRecommendation {
	reasons := []string{}
	urgency := UrgencyLow

	// CRITICAL: Multiple services affected
	if ctx.AffectsMultipleServices {
		reasons = append(reasons, "🔴 Multiple services affected - likely infrastructure issue")
		urgency = maxUrgency(urgency, UrgencyImmediate)
	}

	// CRITICAL: High business impact (executive users)
	if customer.HasExecutiveAffected {
		reasons = append(reasons, "🔴 Executive users affected - high business visibility")
		urgency = maxUrgency(urgency, UrgencyImmediate)
	}

	// CRITICAL: Unknown/unusual pattern
	if ctx.Confidence < 0.5 && ctx.CriticalStreamCount > 0 {
		reasons = append(reasons, "🟠 Unusual pattern with critical symptoms - expert review needed")
		urgency = maxUrgency(urgency, UrgencyHigh)
	}

	// CRITICAL: Vendor-specific bug suspected
	if ctx.VendorBugSuspected {
		reasons = append(reasons, "🟠 Matches known vendor bug pattern - TAC engagement needed")
		urgency = maxUrgency(urgency, UrgencyHigh)
	}

	// HIGH: Issue is recurring
	if ctx.IsRecurring {
		reasons = append(reasons, "🟡 Issue recurring after previous fix - different root cause likely")
		urgency = maxUrgency(urgency, UrgencyMedium)
	}

	// HIGH: Custom application affected
	if ctx.IsCustomApplication {
		reasons = append(reasons, "🟡 Custom application affected - requires SME knowledge")
		urgency = maxUrgency(urgency, UrgencyMedium)
	}

	// HIGH: Multiple users affected
	if ctx.AffectsMultipleUsers {
		reasons = append(reasons, "🟡 Multiple users affected - coordinated response needed")
		urgency = maxUrgency(urgency, UrgencyMedium)
	}

	// HIGH: Critical severity
	if ctx.Severity == "Critical" {
		reasons = append(reasons, "🔴 Critical severity issue detected")
		urgency = maxUrgency(urgency, UrgencyHigh)
	}

	// MEDIUM: SLA customer
	if customer.HasSLA && customer.SLALevel == "Premium" {
		reasons = append(reasons, "🟡 Premium SLA customer - expedited response required")
		urgency = maxUrgency(urgency, UrgencyMedium)
	}

	if len(reasons) == 0 {
		return EscalationRecommendation{
			ShouldEscalate: false,
			Urgency:        UrgencyLow,
		}
	}

	return EscalationRecommendation{
		ShouldEscalate: true,
		Urgency:        urgency,
		Reasons:        reasons,
		Contact:        GetAppropriateContact(ctx, customer, urgency),
		WhatToSay:      GenerateEscalationScript(ctx, customer, reasons),
		WhatToInclude:  GetEscalationAttachments(ctx),
		WhatNotToDo:    GetEscalationWarnings(ctx),
		TimeToEscalate: getTimeToEscalate(urgency),
	}
}

// GetAppropriateContact determines who to contact based on issue type
func GetAppropriateContact(ctx IssueContext, customer CustomerContext, urgency EscalationUrgency) ContactInfo {
	// SD-WAN control plane issues
	if strings.Contains(ctx.IssueID, "SDWAN") || strings.Contains(ctx.IssueID, "VIPTELA") ||
		strings.Contains(ctx.IssueID, "VELOCLOUD") || strings.Contains(ctx.IssueID, "ARUBA") {
		contact := ContactInfo{
			Role:           "Senior Network Engineer (SD-WAN Certified)",
			Team:           "Network Operations",
			ContactMethods: []string{"Teams: #sdwan-support", "Phone: ext. 5555", "Email: sdwan-team@company.com"},
			BackupContact:  "Network Operations Manager",
		}

		// Add vendor TAC for critical issues
		if urgency == UrgencyImmediate || ctx.VendorBugSuspected {
			switch {
			case strings.Contains(ctx.IssueID, "VIPTELA"):
				contact.VendorTAC = "Cisco TAC: 1-800-553-2447 (Contract required)"
			case strings.Contains(ctx.IssueID, "VELOCLOUD"):
				contact.VendorTAC = "VMware Support: support.vmware.com"
			case strings.Contains(ctx.IssueID, "ARUBA"):
				contact.VendorTAC = "Aruba TAC: 1-800-943-4526"
			}
		}

		return contact
	}

	// Security issues
	if strings.Contains(ctx.IssueID, "SEC") || strings.Contains(ctx.IssueID, "THREAT") {
		return ContactInfo{
			Role:           "Security Analyst",
			Team:           "Security Operations Center (SOC)",
			ContactMethods: []string{"Phone: SOC Hotline ext. 9999", "Email: soc@company.com", "Slack: #security-incidents"},
			BackupContact:  "CISO Office",
		}
	}

	// Microsoft 365 issues
	if strings.Contains(ctx.IssueID, "M365") {
		return ContactInfo{
			Role:           "M365 Administrator",
			Team:           "Cloud Services",
			ContactMethods: []string{"Teams: #m365-support", "Email: m365-admin@company.com"},
			BackupContact:  "Senior Network Engineer",
		}
	}

	// DNS issues
	if strings.Contains(ctx.IssueID, "DNS") {
		return ContactInfo{
			Role:           "Infrastructure Engineer",
			Team:           "Infrastructure Operations",
			ContactMethods: []string{"Teams: #infra-support", "Email: infra-team@company.com"},
			BackupContact:  "Senior Network Engineer",
		}
	}

	// Default: Senior Network Engineer
	return ContactInfo{
		Role:           "Senior Network Engineer",
		Team:           "Network Operations",
		ContactMethods: []string{"Teams: #network-support", "Phone: ext. 5555", "Email: network-team@company.com"},
		BackupContact:  "Network Operations Manager",
	}
}

// GenerateEscalationScript creates a script for what to say when escalating
func GenerateEscalationScript(ctx IssueContext, customer CustomerContext, reasons []string) string {
	var sb strings.Builder

	sb.WriteString("📞 WHAT TO SAY WHEN YOU CALL:\n\n")
	sb.WriteString("\"Hi, I have a ")

	// Severity
	switch ctx.Severity {
	case "Critical":
		sb.WriteString("CRITICAL ")
	case "High":
		sb.WriteString("high-priority ")
	default:
		sb.WriteString("")
	}

	sb.WriteString("SD-WAN issue that needs escalation.\n\n")

	// Issue summary
	sb.WriteString(fmt.Sprintf("The triage tool detected: %s\n", ctx.Title))
	sb.WriteString(fmt.Sprintf("Issue ID: %s\n", ctx.IssueID))
	sb.WriteString(fmt.Sprintf("Confidence: %.0f%%\n\n", ctx.Confidence*100))

	// Why escalating
	sb.WriteString("I'm escalating because:\n")
	for _, reason := range reasons {
		sb.WriteString(fmt.Sprintf("- %s\n", strings.TrimPrefix(reason, "🔴 ")))
	}
	sb.WriteString("\n")

	// What's been done
	sb.WriteString("What I've already done:\n")
	sb.WriteString("- Ran the SD-WAN triage tool\n")
	sb.WriteString("- Verified scope of impact\n")
	sb.WriteString("- Documented symptoms in attached report\n\n")

	// What's needed
	sb.WriteString("What I need:\n")
	if ctx.AffectsMultipleServices {
		sb.WriteString("- Senior engineer to take ownership of infrastructure investigation\n")
	}
	if ctx.VendorBugSuspected {
		sb.WriteString("- Possible vendor TAC engagement\n")
	}
	sb.WriteString("- Guidance on next steps\n\n")

	// Customer context
	if customer.CustomerName != "" {
		sb.WriteString(fmt.Sprintf("Customer: %s\n", customer.CustomerName))
	}
	if customer.HasExecutiveAffected {
		sb.WriteString("⚠️ Executive users are affected\n")
	}
	if customer.HasSLA {
		sb.WriteString(fmt.Sprintf("SLA Level: %s\n", customer.SLALevel))
	}

	sb.WriteString("\nI have the HTML report and PCAP ready to share.\"\n")

	return sb.String()
}

// GetEscalationAttachments returns list of things to include in escalation
func GetEscalationAttachments(ctx IssueContext) []string {
	attachments := []string{
		"📄 HTML diagnostic report",
		"📦 PCAP file (or relevant excerpt)",
		"📸 Screenshot of SD-WAN controller dashboard",
		"📝 Timeline of when issue started",
		"👥 List of affected users (if known)",
	}

	if ctx.AffectsMultipleServices {
		attachments = append(attachments, "📋 List of all affected services")
	}

	if strings.Contains(ctx.IssueID, "VIPTELA") || strings.Contains(ctx.IssueID, "VELOCLOUD") {
		attachments = append(attachments, "📊 SD-WAN controller event logs")
	}

	return attachments
}

// GetEscalationWarnings returns things NOT to do during escalation
func GetEscalationWarnings(ctx IssueContext) []string {
	warnings := []string{
		"❌ Don't restart services without senior approval",
		"❌ Don't make configuration changes",
		"❌ Don't tell users 'it's being fixed' until confirmed",
	}

	if ctx.AffectsMultipleServices {
		warnings = append(warnings, "❌ Don't apply single-service fixes to infrastructure issues")
	}

	if strings.Contains(ctx.IssueID, "THREAT") || strings.Contains(ctx.IssueID, "SEC") {
		warnings = append(warnings, "❌ Don't alert the user (potential security incident)")
		warnings = append(warnings, "❌ Don't disconnect the device without SOC guidance")
	}

	return warnings
}

// Helper functions

func maxUrgency(a, b EscalationUrgency) EscalationUrgency {
	urgencyOrder := map[EscalationUrgency]int{
		UrgencyLow:       0,
		UrgencyMedium:    1,
		UrgencyHigh:      2,
		UrgencyImmediate: 3,
	}

	if urgencyOrder[a] > urgencyOrder[b] {
		return a
	}
	return b
}

func getTimeToEscalate(urgency EscalationUrgency) string {
	switch urgency {
	case UrgencyImmediate:
		return "NOW - Call immediately"
	case UrgencyHigh:
		return "Within 15 minutes"
	case UrgencyMedium:
		return "Within 1 hour"
	case UrgencyLow:
		return "Within 4 hours"
	default:
		return "As soon as practical"
	}
}

// EscalationDecisionTree helps junior engineers decide when to escalate
type EscalationDecisionTree struct {
	Question    string                  `json:"question"`
	YesPath     *EscalationDecisionTree `json:"yes_path,omitempty"`
	NoPath      *EscalationDecisionTree `json:"no_path,omitempty"`
	Decision    string                  `json:"decision,omitempty"`
	Explanation string                  `json:"explanation,omitempty"`
}

// GetEscalationDecisionTree returns the decision tree for escalation
func GetEscalationDecisionTree() *EscalationDecisionTree {
	return &EscalationDecisionTree{
		Question: "Are multiple users affected?",
		YesPath: &EscalationDecisionTree{
			Question: "Are multiple services affected (not just one app)?",
			YesPath: &EscalationDecisionTree{
				Decision:    "🚨 ESCALATE IMMEDIATELY",
				Explanation: "Multiple users AND multiple services = infrastructure issue. This is beyond junior engineer scope.",
			},
			NoPath: &EscalationDecisionTree{
				Question: "Is this a critical business service (email, phone, core app)?",
				YesPath: &EscalationDecisionTree{
					Decision:    "🚨 ESCALATE WITHIN 15 MINUTES",
					Explanation: "Critical service affecting multiple users needs senior attention.",
				},
				NoPath: &EscalationDecisionTree{
					Decision:    "📋 Document and escalate within 1 hour",
					Explanation: "Non-critical service, but multiple users means it's not a local issue.",
				},
			},
		},
		NoPath: &EscalationDecisionTree{
			Question: "Is the confidence score below 70%?",
			YesPath: &EscalationDecisionTree{
				Question: "Is this the only finding (no other issues detected)?",
				YesPath: &EscalationDecisionTree{
					Decision:    "⚠️ Validate carefully, escalate if unsure",
					Explanation: "Low confidence + only finding = unusual pattern. Get expert opinion.",
				},
				NoPath: &EscalationDecisionTree{
					Decision:    "✅ Focus on higher-confidence findings first",
					Explanation: "Other findings may be more reliable. Start there.",
				},
			},
			NoPath: &EscalationDecisionTree{
				Question: "Have you completed all validation steps?",
				YesPath: &EscalationDecisionTree{
					Decision:    "✅ Safe to attempt remediation",
					Explanation: "Single user, good confidence, validated. You can try the fix.",
				},
				NoPath: &EscalationDecisionTree{
					Decision:    "⏸️ Complete validation first",
					Explanation: "Don't skip validation. It prevents mistakes.",
				},
			},
		},
	}
}

// FormatDecisionTree formats the decision tree for display
func FormatDecisionTree(tree *EscalationDecisionTree, indent int) string {
	var sb strings.Builder
	prefix := strings.Repeat("  ", indent)

	if tree.Decision != "" {
		sb.WriteString(fmt.Sprintf("%s→ %s\n", prefix, tree.Decision))
		sb.WriteString(fmt.Sprintf("%s  %s\n", prefix, tree.Explanation))
		return sb.String()
	}

	sb.WriteString(fmt.Sprintf("%s❓ %s\n", prefix, tree.Question))

	if tree.YesPath != nil {
		sb.WriteString(fmt.Sprintf("%s  YES:\n", prefix))
		sb.WriteString(FormatDecisionTree(tree.YesPath, indent+2))
	}

	if tree.NoPath != nil {
		sb.WriteString(fmt.Sprintf("%s  NO:\n", prefix))
		sb.WriteString(FormatDecisionTree(tree.NoPath, indent+2))
	}

	return sb.String()
}
