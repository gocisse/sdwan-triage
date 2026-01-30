package safety

import (
	"fmt"
	"strings"
)

// MistakeDetection contains the result of mistake detection
type MistakeDetection struct {
	IsMistake     bool      `json:"is_mistake"`
	MistakeType   string    `json:"mistake_type,omitempty"`
	Warning       string    `json:"warning,omitempty"`
	CorrectAction string    `json:"correct_action,omitempty"`
	Explanation   string    `json:"explanation,omitempty"`
	RiskLevel     RiskLevel `json:"risk_level,omitempty"`
	BlockAction   bool      `json:"block_action"`
}

// MistakeType categorizes common mistakes
type MistakeType string

const (
	MistakeRestartWhenNetworkIssue  MistakeType = "restart_when_network_issue"
	MistakeLocalFixWhenGlobalIssue  MistakeType = "local_fix_when_global_issue"
	MistakeIgnoreLowConfidence      MistakeType = "ignore_low_confidence"
	MistakeSkipValidation           MistakeType = "skip_validation"
	MistakeBlameWrongComponent      MistakeType = "blame_wrong_component"
	MistakeOverlayVsUnderlay        MistakeType = "overlay_vs_underlay"
	MistakeIgnoreMultipleServices   MistakeType = "ignore_multiple_services"
	MistakeApplyFixWithoutRootCause MistakeType = "apply_fix_without_root_cause"
)

// DetectCommonMistake analyzes an engineer's proposed action for common mistakes
func DetectCommonMistake(proposedAction string, ctx IssueContext) MistakeDetection {
	actionLower := strings.ToLower(proposedAction)

	// MISTAKE 1: Restarting service when multiple services are affected (network issue)
	if isServiceRestart(proposedAction) && ctx.AffectsMultipleServices {
		return MistakeDetection{
			IsMistake:   true,
			MistakeType: string(MistakeRestartWhenNetworkIssue),
			Warning: formatMistakeWarning(
				"MISTAKE DETECTED: Service Restart Won't Help",
				"You're trying to restart a service, but this issue affects MULTIPLE services.",
				"This strongly suggests a NETWORK problem, not a service problem.",
			),
			CorrectAction: strings.Join([]string{
				"1. Check SD-WAN tunnel health first",
				"2. Verify network path to affected services",
				"3. Escalate to network team if tunnels are degraded",
			}, "\n"),
			Explanation: "Restarting a service when the real problem is the network will:\n" +
				"• Cause unnecessary downtime\n" +
				"• Not fix the actual problem\n" +
				"• Waste time while users continue to suffer",
			RiskLevel:   RiskHigh,
			BlockAction: true,
		}
	}

	// MISTAKE 2: Applying local/client fix when multiple users affected
	if isLocalFix(proposedAction) && ctx.AffectsMultipleUsers {
		return MistakeDetection{
			IsMistake:   true,
			MistakeType: string(MistakeLocalFixWhenGlobalIssue),
			Warning: formatMistakeWarning(
				"MISTAKE DETECTED: Local Fix Won't Help",
				"You're looking at a client-side fix, but this affects MULTIPLE users.",
				"Fixing one computer won't help the others.",
			),
			CorrectAction: strings.Join([]string{
				"1. Document all affected users",
				"2. Escalate to network/infrastructure team",
				"3. Wait for coordinated fix that helps everyone",
			}, "\n"),
			Explanation: "Local fixes for global issues:\n" +
				"• Only help one person temporarily\n" +
				"• Waste time that could be spent on real fix\n" +
				"• May mask symptoms, making diagnosis harder",
			RiskLevel:   RiskMedium,
			BlockAction: true,
		}
	}

	// MISTAKE 3: Ignoring low confidence when it's the only finding
	if strings.Contains(actionLower, "ignore") && ctx.Confidence < 0.7 && ctx.CriticalStreamCount == 1 {
		return MistakeDetection{
			IsMistake:   true,
			MistakeType: string(MistakeIgnoreLowConfidence),
			Warning: formatMistakeWarning(
				"CAUTION: Don't Ignore This Finding",
				"This issue has low confidence, but it's the ONLY finding.",
				"Low confidence means unusual pattern, not necessarily wrong.",
			),
			CorrectAction: strings.Join([]string{
				"1. Treat this as suspicious and validate carefully",
				"2. Look for additional symptoms not captured here",
				"3. When in doubt, escalate for expert review",
			}, "\n"),
			Explanation: "Low confidence findings that are the only finding:\n" +
				"• Often indicate unusual but real problems\n" +
				"• May be the first sign of a new issue type\n" +
				"• Deserve careful investigation, not dismissal",
			RiskLevel:   RiskMedium,
			BlockAction: false, // Warning only, don't block
		}
	}

	// MISTAKE 4: Blaming Microsoft/cloud when SD-WAN path is degraded
	if (strings.Contains(actionLower, "microsoft") ||
		strings.Contains(actionLower, "cloud") ||
		strings.Contains(actionLower, "datacenter")) &&
		strings.Contains(ctx.ServiceCategory, "M365") {
		return MistakeDetection{
			IsMistake:   true,
			MistakeType: string(MistakeOverlayVsUnderlay),
			Warning: formatMistakeWarning(
				"CAUTION: Check SD-WAN Path First",
				"Before blaming Microsoft/cloud, verify the SD-WAN path is healthy.",
				"The issue might be your network path, not the destination.",
			),
			CorrectAction: strings.Join([]string{
				"1. Check SD-WAN tunnel to Microsoft endpoints",
				"2. Verify internet breakout path health",
				"3. Test from a different location if possible",
				"4. Only contact Microsoft if SD-WAN path is confirmed healthy",
			}, "\n"),
			Explanation: "The 'Overlay vs Underlay' trap:\n" +
				"• M365 issues often look like Microsoft problems\n" +
				"• But the SD-WAN path to Microsoft might be the real issue\n" +
				"• Always check your network first before blaming external services",
			RiskLevel:   RiskLow,
			BlockAction: false,
		}
	}

	// MISTAKE 5: Restarting Exchange when it's an Autodiscover loop
	if strings.Contains(actionLower, "exchange") &&
		strings.Contains(actionLower, "restart") &&
		strings.Contains(ctx.IssueID, "EXO") {
		return MistakeDetection{
			IsMistake:   true,
			MistakeType: string(MistakeApplyFixWithoutRootCause),
			Warning: formatMistakeWarning(
				"MISTAKE DETECTED: Wrong Fix for Autodiscover Issue",
				"Restarting Exchange won't fix an Autodiscover loop.",
				"The issue is likely DNS, network path, or client configuration.",
			),
			CorrectAction: strings.Join([]string{
				"1. Check DNS resolution for autodiscover records",
				"2. Verify network path to Exchange Online",
				"3. Check if issue affects multiple users",
				"4. Only restart specific app pool if confirmed necessary",
			}, "\n"),
			Explanation: "Autodiscover loops are usually caused by:\n" +
				"• DNS misconfiguration\n" +
				"• Network path issues\n" +
				"• Proxy/firewall interference\n" +
				"Restarting Exchange affects all users and rarely fixes these issues.",
			RiskLevel:   RiskHigh,
			BlockAction: true,
		}
	}

	// MISTAKE 6: Skipping validation steps
	if strings.Contains(actionLower, "skip") || strings.Contains(actionLower, "bypass") {
		return MistakeDetection{
			IsMistake:   true,
			MistakeType: string(MistakeSkipValidation),
			Warning: formatMistakeWarning(
				"CAUTION: Don't Skip Validation",
				"Validation steps exist to prevent misdiagnosis.",
				"Skipping them increases the risk of applying the wrong fix.",
			),
			CorrectAction: strings.Join([]string{
				"1. Complete the validation checklist",
				"2. Document your findings at each step",
				"3. Only proceed to remediation after validation",
			}, "\n"),
			Explanation: "Validation prevents:\n" +
				"• Applying fixes that don't address root cause\n" +
				"• Causing outages from misdirected actions\n" +
				"• Wasting time on wrong investigation paths",
			RiskLevel:   RiskMedium,
			BlockAction: true,
		}
	}

	// No mistake detected
	return MistakeDetection{
		IsMistake:   false,
		BlockAction: false,
	}
}

// formatMistakeWarning creates a formatted warning message
func formatMistakeWarning(title, line1, line2 string) string {
	return fmt.Sprintf("❌ %s\n\n%s\n%s", title, line1, line2)
}

// CommonMistakeScenarios provides educational content about common mistakes
var CommonMistakeScenarios = []MistakeScenario{
	{
		Name:        "The 'Tool Says Restart It' Syndrome",
		Description: "Engineer sees 'Fix: Restart MSExchangeAutodiscoverAppPool' and applies it without validating root cause.",
		Consequence: "Causes production outage affecting 500 users. Real issue was SD-WAN tunnel, not Exchange.",
		Prevention:  "Always complete validation steps. Check if multiple services are affected before restarting anything.",
		Frequency:   "Very Common",
	},
	{
		Name:        "Overlay vs Underlay Blindness",
		Description: "Tool shows M365 TLS timeout. Engineer blames Microsoft/datacenter.",
		Consequence: "Wastes 4 hours investigating Microsoft while SD-WAN path to all internet is degraded.",
		Prevention:  "Always check SD-WAN tunnel health before blaming external services.",
		Frequency:   "Common",
	},
	{
		Name:        "Confidence Score Misinterpretation",
		Description: "Low confidence (60%) on critical issue. Engineer ignores because 'score is low'.",
		Consequence: "Issue escalates to outage. Score was low due to unusual pattern, not inaccuracy.",
		Prevention:  "Low confidence = unusual pattern, not necessarily wrong. Validate carefully.",
		Frequency:   "Common",
	},
	{
		Name:        "Analysis Paralysis",
		Description: "Tool shows 15 different potential issues. Engineer overwhelmed.",
		Consequence: "Spends hours investigating minor warnings. Misses the actual critical problem.",
		Prevention:  "Focus on critical issues first. Use junior mode to see only top 1-2 issues.",
		Frequency:   "Very Common",
	},
	{
		Name:        "Single User Fix for Multi-User Problem",
		Description: "Multiple users affected but engineer applies client-side fix to one computer.",
		Consequence: "One user temporarily helped. Problem persists for everyone else.",
		Prevention:  "Always check scope first: 'Is this affecting one user or many?'",
		Frequency:   "Common",
	},
}

// MistakeScenario describes a common mistake scenario
type MistakeScenario struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Consequence string `json:"consequence"`
	Prevention  string `json:"prevention"`
	Frequency   string `json:"frequency"`
}

// ActionRiskAssessment evaluates the risk of a proposed action
type ActionRiskAssessment struct {
	Action           string    `json:"action"`
	RiskLevel        RiskLevel `json:"risk_level"`
	AffectedScope    string    `json:"affected_scope"`
	Reversible       bool      `json:"reversible"`
	RollbackPlan     string    `json:"rollback_plan,omitempty"`
	RequiresApproval bool      `json:"requires_approval"`
	ApprovalLevel    string    `json:"approval_level,omitempty"`
	Warnings         []string  `json:"warnings,omitempty"`
}

// AssessActionRisk evaluates the risk of a proposed remediation action
func AssessActionRisk(action string, ctx IssueContext) ActionRiskAssessment {
	assessment := ActionRiskAssessment{
		Action:   action,
		Warnings: make([]string, 0),
	}

	actionLower := strings.ToLower(action)

	// Determine risk level based on action type
	if containsAny(actionLower, []string{"restart", "reboot", "stop", "shutdown"}) {
		assessment.RiskLevel = RiskHigh
		assessment.AffectedScope = "Service/System"
		assessment.Reversible = true
		assessment.RollbackPlan = "Service will restart automatically or can be manually started"
		assessment.RequiresApproval = true
		assessment.ApprovalLevel = "Senior Engineer"
		assessment.Warnings = append(assessment.Warnings, "This action will cause service interruption")
	} else if containsAny(actionLower, []string{"delete", "remove", "clear", "reset"}) {
		assessment.RiskLevel = RiskHigh
		assessment.AffectedScope = "Data/Configuration"
		assessment.Reversible = false
		assessment.RequiresApproval = true
		assessment.ApprovalLevel = "Senior Engineer + Backup Verification"
		assessment.Warnings = append(assessment.Warnings, "This action may not be reversible")
	} else if containsAny(actionLower, []string{"change", "modify", "update", "set"}) {
		assessment.RiskLevel = RiskMedium
		assessment.AffectedScope = "Configuration"
		assessment.Reversible = true
		assessment.RollbackPlan = "Restore previous configuration"
		assessment.RequiresApproval = true
		assessment.ApprovalLevel = "Senior Engineer"
	} else if containsAny(actionLower, []string{"check", "show", "display", "get", "list", "ping", "traceroute", "nslookup"}) {
		assessment.RiskLevel = RiskNone
		assessment.AffectedScope = "None (read-only)"
		assessment.Reversible = true
		assessment.RequiresApproval = false
	} else {
		assessment.RiskLevel = RiskLow
		assessment.AffectedScope = "Unknown"
		assessment.Reversible = true
		assessment.RequiresApproval = false
	}

	// Add context-specific warnings
	if ctx.AffectsMultipleUsers && assessment.RiskLevel >= RiskMedium {
		assessment.Warnings = append(assessment.Warnings,
			"⚠️ Multiple users affected - action will impact all of them")
		assessment.RequiresApproval = true
	}

	if ctx.AffectsMultipleServices && assessment.RiskLevel >= RiskMedium {
		assessment.Warnings = append(assessment.Warnings,
			"⚠️ Multiple services affected - consider if this is the right fix")
		assessment.RequiresApproval = true
	}

	if ctx.Severity == "Critical" {
		assessment.Warnings = append(assessment.Warnings,
			"🔴 Critical issue - ensure you have the right fix before acting")
	}

	return assessment
}

// containsAny checks if string contains any of the substrings
func containsAny(s string, substrings []string) bool {
	for _, sub := range substrings {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

// SafeActionSuggestions provides safe alternatives to risky actions
func SafeActionSuggestions(riskyAction string) []string {
	actionLower := strings.ToLower(riskyAction)

	if strings.Contains(actionLower, "restart") {
		return []string{
			"First: Check service status (read-only)",
			"First: Review service logs for errors",
			"First: Verify if multiple users affected",
			"First: Check SD-WAN path health",
			"Then: If still needed, get senior approval for restart",
		}
	}

	if strings.Contains(actionLower, "delete") || strings.Contains(actionLower, "clear") {
		return []string{
			"First: Create backup of current state",
			"First: Document what will be deleted",
			"First: Verify this won't affect other users",
			"First: Get senior approval",
			"Then: Proceed with deletion if approved",
		}
	}

	if strings.Contains(actionLower, "change") || strings.Contains(actionLower, "modify") {
		return []string{
			"First: Document current configuration",
			"First: Understand what the change will affect",
			"First: Verify change window if applicable",
			"First: Get senior approval",
			"Then: Apply change with rollback plan ready",
		}
	}

	return []string{
		"First: Verify scope of impact",
		"First: Document current state",
		"First: Get senior approval if unsure",
	}
}
