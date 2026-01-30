package safety

import (
	"fmt"
	"strings"
)

// EngineerLevel represents the experience level of the engineer
type EngineerLevel int

const (
	LevelJunior EngineerLevel = iota
	LevelIntermediate
	LevelSenior
)

// RiskLevel categorizes the risk of an action
type RiskLevel string

const (
	RiskNone     RiskLevel = "NONE"     // Read-only, completely safe
	RiskLow      RiskLevel = "LOW"      // Affects single user only
	RiskMedium   RiskLevel = "MEDIUM"   // Affects single service
	RiskHigh     RiskLevel = "HIGH"     // Affects multiple services/users
	RiskCritical RiskLevel = "CRITICAL" // Production-wide impact
)

// ValidationStep represents a single step in the validation workflow
type ValidationStep struct {
	Order              int       `json:"order"`
	Title              string    `json:"title"`
	Description        string    `json:"description"`
	Action             string    `json:"action"`
	Safety             string    `json:"safety"`
	RiskLevel          RiskLevel `json:"risk_level"`
	MustComplete       bool      `json:"must_complete"`
	Blocking           bool      `json:"blocking"`
	EscalationRequired bool      `json:"escalation_required"`
	RollbackPlan       string    `json:"rollback_plan,omitempty"`
	ExpectedOutcome    string    `json:"expected_outcome,omitempty"`
	IfYes              string    `json:"if_yes,omitempty"`
	IfNo               string    `json:"if_no,omitempty"`
}

// SafePath represents a safe remediation path with validation steps
type SafePath struct {
	IssueID             string           `json:"issue_id"`
	IssueTitle          string           `json:"issue_title"`
	Steps               []ValidationStep `json:"steps"`
	RequiresEscalation  bool             `json:"requires_escalation"`
	EscalationReason    string           `json:"escalation_reason,omitempty"`
	SafeToSelfRemediate bool             `json:"safe_to_self_remediate"`
	MaxRiskLevel        RiskLevel        `json:"max_risk_level"`
}

// IssueContext contains context about the detected issue
type IssueContext struct {
	IssueID                 string
	Title                   string
	Severity                string
	Confidence              float64
	AffectsMultipleUsers    bool
	AffectsMultipleServices bool
	IsRecurring             bool
	IsCustomApplication     bool
	VendorBugSuspected      bool
	ServiceCategory         string
	StreamCount             int
	CriticalStreamCount     int
}

// GenerateSafeRemediationPath creates a safe validation workflow for an issue
func GenerateSafeRemediationPath(ctx IssueContext) SafePath {
	path := SafePath{
		IssueID:    ctx.IssueID,
		IssueTitle: ctx.Title,
		Steps:      make([]ValidationStep, 0),
	}

	stepOrder := 1

	// STEP 1: Always safe - Gather context (MANDATORY)
	path.Steps = append(path.Steps, ValidationStep{
		Order:           stepOrder,
		Title:           "📋 Check Scope of Impact",
		Description:     "Determine if this affects one user or many users",
		Action:          "Ask 2-3 colleagues: 'Are you experiencing the same issue?'",
		Safety:          "Completely safe - just communication, no system changes",
		RiskLevel:       RiskNone,
		MustComplete:    true,
		Blocking:        true,
		ExpectedOutcome: "You'll know if this is isolated or widespread",
		IfYes:           "Multiple users affected → This is likely a network/infrastructure issue",
		IfNo:            "Only you affected → This might be a local issue",
	})
	stepOrder++

	// STEP 2: Safe diagnostics - Check SD-WAN health (MANDATORY)
	path.Steps = append(path.Steps, ValidationStep{
		Order:           stepOrder,
		Title:           "🔍 Verify SD-WAN Path Health",
		Description:     "Check if the SD-WAN tunnel to the destination is healthy",
		Action:          "Check SD-WAN controller dashboard for tunnel status",
		Safety:          "Read-only check - no impact to production",
		RiskLevel:       RiskNone,
		MustComplete:    true,
		Blocking:        true,
		ExpectedOutcome: "Tunnel status: UP/DOWN, packet loss %, latency",
		IfYes:           "Tunnel healthy → Issue is likely application-specific",
		IfNo:            "Tunnel degraded → SD-WAN path is the root cause",
	})
	stepOrder++

	// STEP 3: Check for multiple services affected
	if ctx.AffectsMultipleServices {
		path.Steps = append(path.Steps, ValidationStep{
			Order:              stepOrder,
			Title:              "🚨 ESCALATE - Infrastructure Issue Detected",
			Description:        "Multiple services are affected - this indicates a network-wide problem",
			Action:             "Contact Senior Network Engineer immediately",
			Safety:             "Proper escalation prevents misdirected fixes that could worsen the situation",
			RiskLevel:          RiskNone,
			MustComplete:       true,
			Blocking:           true,
			EscalationRequired: true,
			ExpectedOutcome:    "Senior engineer takes ownership of infrastructure investigation",
		})
		path.RequiresEscalation = true
		path.EscalationReason = "Multiple services affected - infrastructure-level issue suspected"
		path.SafeToSelfRemediate = false
		path.MaxRiskLevel = RiskHigh
		return path
	}

	// STEP 4: Check for multiple users affected
	if ctx.AffectsMultipleUsers {
		path.Steps = append(path.Steps, ValidationStep{
			Order:              stepOrder,
			Title:              "🚨 ESCALATE - Multiple Users Affected",
			Description:        "This issue affects multiple users - do NOT apply local fixes",
			Action:             "Contact Senior Network Engineer or Service Desk Lead",
			Safety:             "Local fixes won't help and may mask the real problem",
			RiskLevel:          RiskNone,
			MustComplete:       true,
			Blocking:           true,
			EscalationRequired: true,
			ExpectedOutcome:    "Coordinated response to multi-user issue",
		})
		path.RequiresEscalation = true
		path.EscalationReason = "Multiple users affected - coordinated response required"
		path.SafeToSelfRemediate = false
		path.MaxRiskLevel = RiskMedium
		return path
	}

	// STEP 5: Vendor bug check
	if ctx.VendorBugSuspected {
		path.Steps = append(path.Steps, ValidationStep{
			Order:              stepOrder,
			Title:              "⚠️ Known Vendor Bug Pattern Detected",
			Description:        "This matches a known vendor bug - TAC engagement may be needed",
			Action:             "Document symptoms and escalate to senior engineer for TAC case",
			Safety:             "Vendor bugs require official patches, not workarounds",
			RiskLevel:          RiskNone,
			MustComplete:       true,
			Blocking:           true,
			EscalationRequired: true,
			ExpectedOutcome:    "TAC case opened with proper documentation",
		})
		stepOrder++
	}

	// STEP 6: Recurring issue check
	if ctx.IsRecurring {
		path.Steps = append(path.Steps, ValidationStep{
			Order:           stepOrder,
			Title:           "🔄 Recurring Issue - Different Approach Needed",
			Description:     "This issue has occurred before - the previous fix didn't address root cause",
			Action:          "Document timeline and escalate for root cause analysis",
			Safety:          "Repeating the same fix will likely fail again",
			RiskLevel:       RiskNone,
			MustComplete:    true,
			Blocking:        true,
			ExpectedOutcome: "Root cause analysis initiated",
		})
		path.RequiresEscalation = true
		path.EscalationReason = "Recurring issue - root cause analysis required"
		stepOrder++
	}

	// STEP 7: Low confidence warning
	if ctx.Confidence < 0.7 {
		path.Steps = append(path.Steps, ValidationStep{
			Order:           stepOrder,
			Title:           "⚠️ Low Confidence Finding - Extra Validation Required",
			Description:     fmt.Sprintf("Confidence score is %.0f%% - this pattern is unusual", ctx.Confidence*100),
			Action:          "Gather additional evidence before proceeding",
			Safety:          "Low confidence means unusual pattern, not necessarily wrong",
			RiskLevel:       RiskNone,
			MustComplete:    true,
			Blocking:        true,
			ExpectedOutcome: "Additional symptoms documented",
			IfYes:           "Additional symptoms found → Proceed with caution",
			IfNo:            "No additional symptoms → Escalate for expert review",
		})
		stepOrder++
	}

	// STEP 8: Safe remediation (only if single user, single service)
	if !ctx.AffectsMultipleUsers && !ctx.AffectsMultipleServices {
		path.Steps = append(path.Steps, ValidationStep{
			Order:           stepOrder,
			Title:           "✅ Apply Local Fix",
			Description:     "Issue appears isolated to single user - safe to apply remediation",
			Action:          "Execute the provided remediation commands",
			Safety:          "Low risk - affects only the single affected user",
			RiskLevel:       RiskLow,
			MustComplete:    false,
			Blocking:        false,
			RollbackPlan:    "Reboot the affected computer to revert changes",
			ExpectedOutcome: "Issue resolved for the affected user",
		})
		path.SafeToSelfRemediate = true
		path.MaxRiskLevel = RiskLow
	}

	return path
}

// ValidationChecklist generates a checklist for junior engineers
func ValidationChecklist(ctx IssueContext) []string {
	checklist := []string{
		"☐ Verified issue affects only one user (asked colleagues)",
		"☐ Checked SD-WAN controller dashboard for tunnel health",
		"☐ Confirmed no maintenance window is active",
		"☐ Documented current symptoms and timeline",
	}

	if ctx.Severity == "Critical" {
		checklist = append(checklist, "☐ Notified supervisor of critical issue")
	}

	if ctx.AffectsMultipleServices {
		checklist = append(checklist, "☐ ESCALATED to senior engineer (multiple services affected)")
	}

	if ctx.Confidence < 0.7 {
		checklist = append(checklist, "☐ Gathered additional evidence (low confidence finding)")
	}

	checklist = append(checklist, "☐ Ready to document outcome after remediation")

	return checklist
}

// SafetyGate checks if an action should be blocked
type SafetyGate struct {
	Allowed        bool   `json:"allowed"`
	Reason         string `json:"reason"`
	RequiredAction string `json:"required_action,omitempty"`
	Alternative    string `json:"alternative,omitempty"`
}

// CheckSafetyGate evaluates if a remediation action is safe to proceed
func CheckSafetyGate(ctx IssueContext, proposedAction string, level EngineerLevel) SafetyGate {
	// Senior engineers bypass most gates
	if level == LevelSenior {
		return SafetyGate{
			Allowed: true,
			Reason:  "Senior engineer mode - safety gates bypassed",
		}
	}

	// GATE 1: Block high-risk actions for junior engineers
	if level == LevelJunior && isHighRiskAction(proposedAction) {
		return SafetyGate{
			Allowed:        false,
			Reason:         "⚠️ This action affects production services. Senior engineer approval required.",
			RequiredAction: "Get approval from senior engineer before proceeding",
			Alternative:    "Run diagnostic commands first to gather more information",
		}
	}

	// GATE 2: Block service restarts when multiple services affected
	if ctx.AffectsMultipleServices && isServiceRestart(proposedAction) {
		return SafetyGate{
			Allowed:        false,
			Reason:         "🚫 Cannot restart service when multiple services are affected. This suggests a network issue, not a service issue.",
			RequiredAction: "Escalate to network team for infrastructure investigation",
			Alternative:    "Check SD-WAN tunnel health instead",
		}
	}

	// GATE 3: Block local fixes when multiple users affected
	if ctx.AffectsMultipleUsers && isLocalFix(proposedAction) {
		return SafetyGate{
			Allowed:        false,
			Reason:         "🚫 Local fixes won't help when multiple users are affected. This is an infrastructure issue.",
			RequiredAction: "Escalate to senior engineer for coordinated response",
			Alternative:    "Document all affected users and symptoms",
		}
	}

	// GATE 4: Require validation completion
	if !hasCompletedValidation(ctx) {
		return SafetyGate{
			Allowed:        false,
			Reason:         "⏸️ Please complete validation steps before applying remediation",
			RequiredAction: "Complete the validation checklist",
			Alternative:    "Start with 'Check Scope of Impact' step",
		}
	}

	return SafetyGate{
		Allowed: true,
		Reason:  "✅ Safe to proceed with remediation",
	}
}

// Helper functions

func isHighRiskAction(action string) bool {
	highRiskKeywords := []string{
		"restart", "reboot", "stop", "disable", "delete",
		"remove", "clear", "reset", "shutdown", "kill",
		"terminate", "drop", "block", "deny",
	}

	actionLower := strings.ToLower(action)
	for _, keyword := range highRiskKeywords {
		if strings.Contains(actionLower, keyword) {
			return true
		}
	}
	return false
}

func isServiceRestart(action string) bool {
	restartKeywords := []string{
		"restart", "Restart-Service", "Restart-WebAppPool",
		"systemctl restart", "service restart", "iisreset",
	}

	for _, keyword := range restartKeywords {
		if strings.Contains(action, keyword) {
			return true
		}
	}
	return false
}

func isLocalFix(action string) bool {
	localKeywords := []string{
		"client", "workstation", "laptop", "desktop",
		"user profile", "local cache", "browser",
	}

	actionLower := strings.ToLower(action)
	for _, keyword := range localKeywords {
		if strings.Contains(actionLower, keyword) {
			return true
		}
	}
	return false
}

func hasCompletedValidation(ctx IssueContext) bool {
	// In a real implementation, this would check a validation state
	// For now, we assume validation is required
	return false
}

// ProgressiveDisclosure controls what information to show based on engineer level
type ProgressiveDisclosure struct {
	Level           EngineerLevel
	ShowTechnical   bool
	ShowWireshark   bool
	ShowAllIssues   bool
	ShowRemediation bool
	MaxIssuesShown  int
}

// GetDisclosureSettings returns appropriate settings for engineer level
func GetDisclosureSettings(level EngineerLevel) ProgressiveDisclosure {
	switch level {
	case LevelJunior:
		return ProgressiveDisclosure{
			Level:           LevelJunior,
			ShowTechnical:   false, // Hidden by default, expandable
			ShowWireshark:   false, // Hidden by default, expandable
			ShowAllIssues:   false, // Show only top 1-2 critical
			ShowRemediation: false, // Show only safe first step
			MaxIssuesShown:  2,
		}
	case LevelIntermediate:
		return ProgressiveDisclosure{
			Level:           LevelIntermediate,
			ShowTechnical:   true,
			ShowWireshark:   true,
			ShowAllIssues:   false, // Show top 5
			ShowRemediation: true,
			MaxIssuesShown:  5,
		}
	case LevelSenior:
		return ProgressiveDisclosure{
			Level:           LevelSenior,
			ShowTechnical:   true,
			ShowWireshark:   true,
			ShowAllIssues:   true, // Show all
			ShowRemediation: true,
			MaxIssuesShown:  -1, // No limit
		}
	}

	return GetDisclosureSettings(LevelJunior) // Default to safest
}
