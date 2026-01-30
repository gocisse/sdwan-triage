package output

import (
	"fmt"
	"html/template"
	"strings"

	"github.com/gocisse/sdwan-triage/pkg/models"
	"github.com/gocisse/sdwan-triage/pkg/safety"
)

// JuniorModeConfig configures junior engineer mode output
type JuniorModeConfig struct {
	Enabled            bool
	MaxIssuesShown     int
	ShowTechnical      bool
	ShowWireshark      bool
	ShowAllRemediation bool
}

// DefaultJuniorModeConfig returns default junior mode settings
func DefaultJuniorModeConfig() JuniorModeConfig {
	return JuniorModeConfig{
		Enabled:            true,
		MaxIssuesShown:     2,
		ShowTechnical:      false,
		ShowWireshark:      false,
		ShowAllRemediation: false,
	}
}

// JuniorModeIssue represents an issue formatted for junior engineers
type JuniorModeIssue struct {
	IssueID           string
	Severity          string
	SeverityIcon      string
	SeverityColor     string
	Confidence        float64
	ConfidenceDisplay string
	ConfidenceWarning string

	// Simple language fields
	WhatsHappening string
	WhyUsersCare   string
	FirstThingToDo string
	DontDoThisYet  string
	WhenToEscalate string

	// Validation workflow
	ValidationSteps     []ValidationStepDisplay
	ValidationChecklist []string

	// Safety gates
	SafetyGate     SafetyGateDisplay
	MistakeWarning string

	// Escalation
	ShouldEscalate    bool
	EscalationUrgency string
	EscalationReasons []string
	EscalationScript  string
	WhatToInclude     []string
	WhatNotToDo       []string

	// Technical details (hidden by default)
	TechnicalDetails string
	WiresharkFilter  string
	RemediationSteps []RemediationStepDisplay
}

// ValidationStepDisplay represents a validation step for display
type ValidationStepDisplay struct {
	Order        int
	Title        string
	Description  string
	Action       string
	Safety       string
	RiskLevel    string
	RiskColor    string
	MustComplete bool
	IsBlocking   bool
	IfYes        string
	IfNo         string
}

// SafetyGateDisplay represents a safety gate result for display
type SafetyGateDisplay struct {
	Allowed        bool
	Reason         string
	RequiredAction string
	Alternative    string
}

// RemediationStepDisplay represents a remediation step for display
type RemediationStepDisplay struct {
	Description  string
	Commands     []string
	RiskLevel    string
	RiskColor    string
	Verification string
	RollbackPlan string
}

// GenerateJuniorModeHTML generates the junior engineer mode HTML section
func GenerateJuniorModeHTML(streams []*models.StreamData, config JuniorModeConfig) template.HTML {
	if !config.Enabled || len(streams) == 0 {
		return template.HTML("")
	}

	var sb strings.Builder

	// Junior Mode Header
	sb.WriteString(`
<div class="junior-mode-section">
    <div class="junior-mode-header">
        <div class="junior-mode-badge">👷 JUNIOR ENGINEER MODE</div>
        <h2>Guided Troubleshooting</h2>
        <p class="junior-mode-subtitle">Follow these steps carefully. When in doubt, escalate.</p>
    </div>
`)

	// Quick Reference Card
	sb.WriteString(generateQuickReferenceCard())

	// Process and display top issues
	issues := processStreamsForJuniorMode(streams, config)

	if len(issues) == 0 {
		sb.WriteString(`
    <div class="junior-mode-success">
        <div class="success-icon">✅</div>
        <h3>No Critical Issues Detected</h3>
        <p>The analysis didn't find any issues requiring immediate attention.</p>
        <p><strong>Next step:</strong> Monitor the situation and re-run analysis if users report problems.</p>
    </div>
`)
	} else {
		// Show top issues
		for i, issue := range issues {
			if config.MaxIssuesShown > 0 && i >= config.MaxIssuesShown {
				break
			}
			sb.WriteString(generateJuniorIssueCard(issue, i+1, config))
		}

		// If there are more issues, show a collapsed section
		if len(issues) > config.MaxIssuesShown {
			sb.WriteString(fmt.Sprintf(`
    <div class="more-issues-collapsed">
        <button class="expand-more-issues" onclick="toggleMoreIssues()">
            📋 Show %d More Issues (Lower Priority)
        </button>
        <div class="more-issues-content" style="display: none;">
`, len(issues)-config.MaxIssuesShown))

			for i := config.MaxIssuesShown; i < len(issues); i++ {
				sb.WriteString(generateJuniorIssueCard(issues[i], i+1, config))
			}

			sb.WriteString(`
        </div>
    </div>
`)
		}
	}

	// Decision Tree Helper
	sb.WriteString(generateDecisionTreeHelper())

	// Training Reminder
	sb.WriteString(generateTrainingReminder())

	sb.WriteString(`
</div>
`)

	// Add CSS
	sb.WriteString(generateJuniorModeCSS())

	// Add JavaScript
	sb.WriteString(generateJuniorModeJS())

	return template.HTML(sb.String())
}

// processStreamsForJuniorMode analyzes streams and creates junior-friendly issues
func processStreamsForJuniorMode(streams []*models.StreamData, config JuniorModeConfig) []JuniorModeIssue {
	issues := make([]JuniorModeIssue, 0)

	// For now, create sample issues based on stream analysis
	// In production, this would integrate with the issue detector
	for _, stream := range streams {
		// Check for issues based on stream characteristics
		if hasIssue(stream) {
			issue := createJuniorModeIssue(stream)
			issues = append(issues, issue)
		}
	}

	// Sort by severity (Critical first)
	sortIssuesBySeverity(issues)

	return issues
}

func hasIssue(stream *models.StreamData) bool {
	// Check for retransmissions, resets, or long duration
	for _, seg := range stream.Segments {
		if seg.HasReset || seg.IsRetransmit {
			return true
		}
	}
	return stream.Duration > 10 // Long duration might indicate timeout
}

func createJuniorModeIssue(stream *models.StreamData) JuniorModeIssue {
	// Determine issue type based on stream characteristics
	issueID := "TCP-002" // Default to retransmission issue
	severity := "Medium"
	confidence := 0.75

	// Check for specific patterns
	hasReset := false
	retransmitCount := 0
	for _, seg := range stream.Segments {
		if seg.HasReset {
			hasReset = true
		}
		if seg.IsRetransmit {
			retransmitCount++
		}
	}

	if hasReset {
		issueID = "TCP-RST-001"
		severity = "High"
		confidence = 0.85
	} else if retransmitCount > 5 {
		issueID = "TCP-002"
		severity = "High"
		confidence = 0.80
	}

	// Get translation if available
	translation, exists := safety.GetTranslation(issueID)
	if !exists {
		// Create generic translation
		translation = safety.IssueTranslation{
			IssueID:           issueID,
			BusinessImpact:    "Network communication is experiencing problems that may slow down applications.",
			UserSymptoms:      "• Applications may be slow\n• Connections may drop\n• File transfers may fail",
			SafeFirstStep:     "Ask 2-3 coworkers if they're experiencing the same slowness.",
			CommonMistake:     "Don't restart services yet - this might be a network path issue.",
			EscalationTrigger: "If multiple people have the same problem, contact the network team.",
		}
	}

	// Create issue context for safety analysis
	ctx := safety.IssueContext{
		IssueID:                 issueID,
		Title:                   translation.CustomerFacingSummary,
		Severity:                severity,
		Confidence:              confidence,
		AffectsMultipleUsers:    false, // Would be determined by broader analysis
		AffectsMultipleServices: false,
	}

	// Generate validation path
	safePath := safety.GenerateSafeRemediationPath(ctx)

	// Check escalation
	escalation := safety.ShouldEscalate(ctx, safety.CustomerContext{})

	// Build the junior mode issue
	issue := JuniorModeIssue{
		IssueID:           issueID,
		Severity:          severity,
		SeverityIcon:      getSeverityIcon(severity),
		SeverityColor:     getSeverityColor(severity),
		Confidence:        confidence,
		ConfidenceDisplay: fmt.Sprintf("%.0f%%", confidence*100),

		WhatsHappening: translation.BusinessImpact,
		WhyUsersCare:   translation.UserSymptoms,
		FirstThingToDo: translation.SafeFirstStep,
		DontDoThisYet:  translation.CommonMistake,
		WhenToEscalate: translation.EscalationTrigger,

		ValidationChecklist: safety.ValidationChecklist(ctx),

		ShouldEscalate:    escalation.ShouldEscalate,
		EscalationUrgency: string(escalation.Urgency),
		EscalationReasons: escalation.Reasons,
		EscalationScript:  escalation.WhatToSay,
		WhatToInclude:     escalation.WhatToInclude,
		WhatNotToDo:       escalation.WhatNotToDo,

		TechnicalDetails: translation.TechnicalDescription,
		WiresharkFilter:  buildStreamFilter(stream),
	}

	// Add confidence warning if low
	if confidence < 0.7 {
		issue.ConfidenceWarning = "⚠️ Unusual pattern - validate carefully before acting"
	}

	// Convert validation steps
	for _, step := range safePath.Steps {
		issue.ValidationSteps = append(issue.ValidationSteps, ValidationStepDisplay{
			Order:        step.Order,
			Title:        step.Title,
			Description:  step.Description,
			Action:       step.Action,
			Safety:       step.Safety,
			RiskLevel:    string(step.RiskLevel),
			RiskColor:    getRiskColor(step.RiskLevel),
			MustComplete: step.MustComplete,
			IsBlocking:   step.Blocking,
			IfYes:        step.IfYes,
			IfNo:         step.IfNo,
		})
	}

	return issue
}

func generateJuniorIssueCard(issue JuniorModeIssue, index int, config JuniorModeConfig) string {
	var sb strings.Builder

	// Issue card container
	sb.WriteString(fmt.Sprintf(`
    <div class="junior-issue-card severity-%s" data-issue-id="%s">
        <div class="issue-header">
            <div class="issue-number">#%d</div>
            <div class="severity-badge" style="background-color: %s;">%s %s</div>
            <div class="confidence-badge" title="How certain the tool is about this finding">
                Confidence: %s
            </div>
        </div>
`, strings.ToLower(issue.Severity), issue.IssueID, index, issue.SeverityColor, issue.SeverityIcon, issue.Severity, issue.ConfidenceDisplay))

	// Confidence warning if applicable
	if issue.ConfidenceWarning != "" {
		sb.WriteString(fmt.Sprintf(`
        <div class="confidence-warning">%s</div>
`, issue.ConfidenceWarning))
	}

	// What's happening (always visible)
	sb.WriteString(fmt.Sprintf(`
        <div class="issue-section whats-happening">
            <h4>❓ What's Happening</h4>
            <p>%s</p>
        </div>
`, issue.WhatsHappening))

	// Why users care
	sb.WriteString(fmt.Sprintf(`
        <div class="issue-section why-care">
            <h4>😟 Why This Matters</h4>
            <div class="symptoms-list">%s</div>
        </div>
`, formatSymptoms(issue.WhyUsersCare)))

	// First thing to do (highlighted)
	sb.WriteString(fmt.Sprintf(`
        <div class="issue-section first-step highlighted">
            <h4>✅ First Thing To Do (Completely Safe)</h4>
            <p>%s</p>
        </div>
`, issue.FirstThingToDo))

	// Don't do this yet (warning)
	if issue.DontDoThisYet != "" {
		sb.WriteString(fmt.Sprintf(`
        <div class="issue-section dont-do warning">
            <h4>⛔ Don't Do This Yet</h4>
            <p>%s</p>
        </div>
`, issue.DontDoThisYet))
	}

	// Escalation section (if needed)
	if issue.ShouldEscalate {
		sb.WriteString(fmt.Sprintf(`
        <div class="issue-section escalation-required">
            <h4>🚨 Escalation Required - %s</h4>
            <div class="escalation-reasons">
                <strong>Why:</strong>
                <ul>
`, issue.EscalationUrgency))
		for _, reason := range issue.EscalationReasons {
			sb.WriteString(fmt.Sprintf("                    <li>%s</li>\n", reason))
		}
		sb.WriteString(`                </ul>
            </div>
`)

		// What to say script
		if issue.EscalationScript != "" {
			sb.WriteString(fmt.Sprintf(`
            <div class="escalation-script">
                <strong>📞 What To Say:</strong>
                <pre>%s</pre>
            </div>
`, issue.EscalationScript))
		}

		// What to include
		if len(issue.WhatToInclude) > 0 {
			sb.WriteString(`
            <div class="what-to-include">
                <strong>📎 Include These:</strong>
                <ul>
`)
			for _, item := range issue.WhatToInclude {
				sb.WriteString(fmt.Sprintf("                    <li>%s</li>\n", item))
			}
			sb.WriteString(`                </ul>
            </div>
`)
		}

		// What NOT to do
		if len(issue.WhatNotToDo) > 0 {
			sb.WriteString(`
            <div class="what-not-to-do">
                <strong>🚫 Do NOT:</strong>
                <ul>
`)
			for _, item := range issue.WhatNotToDo {
				sb.WriteString(fmt.Sprintf("                    <li>%s</li>\n", item))
			}
			sb.WriteString(`                </ul>
            </div>
`)
		}

		sb.WriteString(`        </div>
`)
	} else {
		// When to escalate (guidance)
		sb.WriteString(fmt.Sprintf(`
        <div class="issue-section when-escalate">
            <h4>🚨 When To Escalate</h4>
            <p>%s</p>
        </div>
`, issue.WhenToEscalate))
	}

	// Validation checklist (expandable)
	sb.WriteString(`
        <div class="issue-section validation-section">
            <button class="expand-btn" onclick="toggleSection(this, 'validation')">
                📋 Validation Checklist (Complete Before Any Fix)
            </button>
            <div class="expandable-content validation" style="display: none;">
                <ul class="validation-checklist">
`)
	for _, item := range issue.ValidationChecklist {
		sb.WriteString(fmt.Sprintf("                    <li><label><input type=\"checkbox\"> %s</label></li>\n", strings.TrimPrefix(item, "☐ ")))
	}
	sb.WriteString(`                </ul>
            </div>
        </div>
`)

	// Validation steps (expandable)
	if len(issue.ValidationSteps) > 0 {
		sb.WriteString(`
        <div class="issue-section steps-section">
            <button class="expand-btn" onclick="toggleSection(this, 'steps')">
                🔍 Detailed Validation Steps
            </button>
            <div class="expandable-content steps" style="display: none;">
`)
		for _, step := range issue.ValidationSteps {
			sb.WriteString(fmt.Sprintf(`
                <div class="validation-step risk-%s">
                    <div class="step-header">
                        <span class="step-number">Step %d</span>
                        <span class="step-title">%s</span>
                        <span class="risk-badge" style="background-color: %s;">%s Risk</span>
                    </div>
                    <p class="step-description">%s</p>
                    <div class="step-action"><strong>Action:</strong> %s</div>
                    <div class="step-safety"><strong>Safety:</strong> %s</div>
`, strings.ToLower(string(step.RiskLevel)), step.Order, step.Title, step.RiskColor, step.RiskLevel, step.Description, step.Action, step.Safety))

			if step.IfYes != "" {
				sb.WriteString(fmt.Sprintf(`                    <div class="step-branch yes"><strong>If YES:</strong> %s</div>
`, step.IfYes))
			}
			if step.IfNo != "" {
				sb.WriteString(fmt.Sprintf(`                    <div class="step-branch no"><strong>If NO:</strong> %s</div>
`, step.IfNo))
			}
			sb.WriteString(`                </div>
`)
		}
		sb.WriteString(`            </div>
        </div>
`)
	}

	// Technical details (expandable, hidden by default)
	if !config.ShowTechnical {
		sb.WriteString(fmt.Sprintf(`
        <div class="issue-section technical-section">
            <button class="expand-btn secondary" onclick="toggleSection(this, 'technical')">
                🔧 Technical Details (For Advanced Users)
            </button>
            <div class="expandable-content technical" style="display: none;">
                <p>%s</p>
`, issue.TechnicalDetails))

		if issue.WiresharkFilter != "" {
			sb.WriteString(fmt.Sprintf(`
                <div class="wireshark-filter">
                    <strong>Wireshark Filter:</strong>
                    <code>%s</code>
                    <button class="copy-btn" onclick="copyToClipboard('%s')">📋 Copy</button>
                </div>
`, issue.WiresharkFilter, issue.WiresharkFilter))
		}

		sb.WriteString(`            </div>
        </div>
`)
	}

	sb.WriteString(`    </div>
`)

	return sb.String()
}

func generateQuickReferenceCard() string {
	return `
    <div class="quick-reference-card">
        <h3>🎯 Quick Reference</h3>
        <div class="reference-grid">
            <div class="reference-item">
                <span class="reference-icon">1️⃣</span>
                <span class="reference-text"><strong>Check Scope First</strong><br>Ask colleagues if they have the same issue</span>
            </div>
            <div class="reference-item">
                <span class="reference-icon">2️⃣</span>
                <span class="reference-text"><strong>Multiple Users?</strong><br>→ Escalate, don't fix locally</span>
            </div>
            <div class="reference-item">
                <span class="reference-icon">3️⃣</span>
                <span class="reference-text"><strong>Check SD-WAN</strong><br>Verify tunnel health before blaming apps</span>
            </div>
            <div class="reference-item">
                <span class="reference-icon">4️⃣</span>
                <span class="reference-text"><strong>When Unsure</strong><br>→ Escalate, don't guess</span>
            </div>
        </div>
    </div>
`
}

func generateDecisionTreeHelper() string {
	return `
    <div class="decision-tree-section">
        <button class="expand-btn" onclick="toggleSection(this, 'decision-tree')">
            🌳 Should I Escalate? (Decision Helper)
        </button>
        <div class="expandable-content decision-tree" style="display: none;">
            <div class="decision-tree">
                <div class="decision-node">
                    <div class="question">❓ Are multiple users affected?</div>
                    <div class="branches">
                        <div class="branch yes">
                            <div class="answer">YES →</div>
                            <div class="decision-node">
                                <div class="question">Are multiple services affected?</div>
                                <div class="branches">
                                    <div class="branch yes">
                                        <div class="answer">YES →</div>
                                        <div class="result escalate">🚨 ESCALATE IMMEDIATELY<br><small>Infrastructure issue</small></div>
                                    </div>
                                    <div class="branch no">
                                        <div class="answer">NO →</div>
                                        <div class="result escalate">🚨 ESCALATE WITHIN 15 MIN<br><small>Multi-user issue</small></div>
                                    </div>
                                </div>
                            </div>
                        </div>
                        <div class="branch no">
                            <div class="answer">NO →</div>
                            <div class="decision-node">
                                <div class="question">Is confidence below 70%?</div>
                                <div class="branches">
                                    <div class="branch yes">
                                        <div class="answer">YES →</div>
                                        <div class="result caution">⚠️ Validate carefully<br><small>Escalate if unsure</small></div>
                                    </div>
                                    <div class="branch no">
                                        <div class="answer">NO →</div>
                                        <div class="result safe">✅ May proceed<br><small>After validation</small></div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
`
}

func generateTrainingReminder() string {
	return `
    <div class="training-reminder">
        <h4>📚 Remember Your Training</h4>
        <ul>
            <li><strong>Scope first:</strong> Always check if multiple users are affected</li>
            <li><strong>Network before apps:</strong> Check SD-WAN health before blaming services</li>
            <li><strong>Low confidence ≠ wrong:</strong> Unusual patterns need careful validation</li>
            <li><strong>When in doubt:</strong> Escalate - it's always the right choice</li>
        </ul>
    </div>
`
}

func generateJuniorModeCSS() string {
	return `
<style>
.junior-mode-section {
    background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
    border-radius: 12px;
    padding: 24px;
    margin: 20px 0;
    border: 2px solid #0f3460;
}

.junior-mode-header {
    text-align: center;
    margin-bottom: 24px;
}

.junior-mode-badge {
    display: inline-block;
    background: linear-gradient(90deg, #00b4d8, #0077b6);
    color: white;
    padding: 8px 20px;
    border-radius: 20px;
    font-weight: bold;
    font-size: 14px;
    margin-bottom: 12px;
}

.junior-mode-header h2 {
    color: #e0e0e0;
    margin: 8px 0;
}

.junior-mode-subtitle {
    color: #a0a0a0;
    font-size: 14px;
}

.quick-reference-card {
    background: rgba(0, 180, 216, 0.1);
    border: 1px solid #0077b6;
    border-radius: 8px;
    padding: 16px;
    margin-bottom: 20px;
}

.quick-reference-card h3 {
    color: #00b4d8;
    margin: 0 0 12px 0;
    font-size: 16px;
}

.reference-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 12px;
}

.reference-item {
    display: flex;
    align-items: flex-start;
    gap: 8px;
}

.reference-icon {
    font-size: 20px;
}

.reference-text {
    color: #c0c0c0;
    font-size: 13px;
    line-height: 1.4;
}

.junior-issue-card {
    background: rgba(255, 255, 255, 0.05);
    border-radius: 8px;
    padding: 20px;
    margin-bottom: 16px;
    border-left: 4px solid #666;
}

.junior-issue-card.severity-critical {
    border-left-color: #ef4444;
}

.junior-issue-card.severity-high {
    border-left-color: #f97316;
}

.junior-issue-card.severity-medium {
    border-left-color: #eab308;
}

.junior-issue-card.severity-low {
    border-left-color: #22c55e;
}

.issue-header {
    display: flex;
    align-items: center;
    gap: 12px;
    margin-bottom: 16px;
    flex-wrap: wrap;
}

.issue-number {
    background: #333;
    color: #fff;
    padding: 4px 10px;
    border-radius: 4px;
    font-weight: bold;
}

.severity-badge {
    padding: 4px 12px;
    border-radius: 4px;
    color: white;
    font-weight: bold;
    font-size: 13px;
}

.confidence-badge {
    background: rgba(255, 255, 255, 0.1);
    padding: 4px 12px;
    border-radius: 4px;
    color: #a0a0a0;
    font-size: 12px;
}

.confidence-warning {
    background: rgba(234, 179, 8, 0.2);
    border: 1px solid #eab308;
    color: #fbbf24;
    padding: 8px 12px;
    border-radius: 4px;
    margin-bottom: 16px;
    font-size: 13px;
}

.issue-section {
    margin-bottom: 16px;
}

.issue-section h4 {
    color: #e0e0e0;
    margin: 0 0 8px 0;
    font-size: 14px;
}

.issue-section p {
    color: #c0c0c0;
    margin: 0;
    line-height: 1.5;
}

.issue-section.highlighted {
    background: rgba(34, 197, 94, 0.15);
    border: 1px solid #22c55e;
    padding: 12px;
    border-radius: 6px;
}

.issue-section.warning {
    background: rgba(239, 68, 68, 0.15);
    border: 1px solid #ef4444;
    padding: 12px;
    border-radius: 6px;
}

.issue-section.escalation-required {
    background: rgba(239, 68, 68, 0.2);
    border: 2px solid #ef4444;
    padding: 16px;
    border-radius: 8px;
}

.escalation-script pre {
    background: #1a1a2e;
    padding: 12px;
    border-radius: 4px;
    white-space: pre-wrap;
    font-size: 12px;
    color: #a0a0a0;
    margin-top: 8px;
}

.symptoms-list {
    color: #c0c0c0;
    white-space: pre-line;
    font-size: 13px;
}

.expand-btn {
    background: rgba(255, 255, 255, 0.1);
    border: 1px solid #444;
    color: #e0e0e0;
    padding: 10px 16px;
    border-radius: 6px;
    cursor: pointer;
    width: 100%;
    text-align: left;
    font-size: 14px;
    transition: background 0.2s;
}

.expand-btn:hover {
    background: rgba(255, 255, 255, 0.15);
}

.expand-btn.secondary {
    background: rgba(255, 255, 255, 0.05);
    color: #a0a0a0;
}

.expandable-content {
    margin-top: 12px;
    padding: 12px;
    background: rgba(0, 0, 0, 0.2);
    border-radius: 6px;
}

.validation-checklist {
    list-style: none;
    padding: 0;
    margin: 0;
}

.validation-checklist li {
    padding: 8px 0;
    border-bottom: 1px solid #333;
}

.validation-checklist li:last-child {
    border-bottom: none;
}

.validation-checklist label {
    color: #c0c0c0;
    cursor: pointer;
    display: flex;
    align-items: center;
    gap: 8px;
}

.validation-step {
    background: rgba(255, 255, 255, 0.05);
    border-radius: 6px;
    padding: 12px;
    margin-bottom: 12px;
}

.step-header {
    display: flex;
    align-items: center;
    gap: 12px;
    margin-bottom: 8px;
}

.step-number {
    background: #0077b6;
    color: white;
    padding: 2px 8px;
    border-radius: 4px;
    font-size: 12px;
}

.step-title {
    color: #e0e0e0;
    font-weight: bold;
}

.risk-badge {
    padding: 2px 8px;
    border-radius: 4px;
    color: white;
    font-size: 11px;
    margin-left: auto;
}

.step-description {
    color: #a0a0a0;
    font-size: 13px;
    margin: 8px 0;
}

.step-action, .step-safety {
    color: #c0c0c0;
    font-size: 12px;
    margin: 4px 0;
}

.step-branch {
    background: rgba(255, 255, 255, 0.05);
    padding: 8px;
    border-radius: 4px;
    margin-top: 8px;
    font-size: 12px;
}

.step-branch.yes {
    border-left: 3px solid #22c55e;
}

.step-branch.no {
    border-left: 3px solid #f97316;
}

.wireshark-filter {
    background: #1a1a2e;
    padding: 12px;
    border-radius: 4px;
    margin-top: 12px;
}

.wireshark-filter code {
    display: block;
    color: #00b4d8;
    margin: 8px 0;
    font-family: monospace;
}

.copy-btn {
    background: #0077b6;
    color: white;
    border: none;
    padding: 4px 12px;
    border-radius: 4px;
    cursor: pointer;
    font-size: 12px;
}

.copy-btn:hover {
    background: #00b4d8;
}

.decision-tree-section {
    margin: 20px 0;
}

.decision-tree {
    padding: 16px;
}

.decision-node {
    margin: 12px 0;
}

.question {
    background: #0077b6;
    color: white;
    padding: 12px 16px;
    border-radius: 8px;
    font-weight: bold;
    margin-bottom: 12px;
}

.branches {
    display: flex;
    gap: 16px;
    margin-left: 20px;
}

.branch {
    flex: 1;
}

.answer {
    color: #a0a0a0;
    font-size: 13px;
    margin-bottom: 8px;
}

.result {
    padding: 12px;
    border-radius: 6px;
    text-align: center;
    font-weight: bold;
}

.result.escalate {
    background: rgba(239, 68, 68, 0.2);
    border: 1px solid #ef4444;
    color: #ef4444;
}

.result.caution {
    background: rgba(234, 179, 8, 0.2);
    border: 1px solid #eab308;
    color: #eab308;
}

.result.safe {
    background: rgba(34, 197, 94, 0.2);
    border: 1px solid #22c55e;
    color: #22c55e;
}

.result small {
    display: block;
    font-weight: normal;
    margin-top: 4px;
    opacity: 0.8;
}

.training-reminder {
    background: rgba(0, 119, 182, 0.1);
    border: 1px solid #0077b6;
    border-radius: 8px;
    padding: 16px;
    margin-top: 20px;
}

.training-reminder h4 {
    color: #00b4d8;
    margin: 0 0 12px 0;
}

.training-reminder ul {
    margin: 0;
    padding-left: 20px;
    color: #c0c0c0;
}

.training-reminder li {
    margin: 8px 0;
    line-height: 1.4;
}

.junior-mode-success {
    text-align: center;
    padding: 40px;
}

.success-icon {
    font-size: 48px;
    margin-bottom: 16px;
}

.junior-mode-success h3 {
    color: #22c55e;
    margin: 0 0 12px 0;
}

.junior-mode-success p {
    color: #a0a0a0;
    margin: 8px 0;
}

.more-issues-collapsed {
    margin-top: 16px;
}

.expand-more-issues {
    background: rgba(255, 255, 255, 0.05);
    border: 1px dashed #444;
    color: #a0a0a0;
    padding: 12px;
    border-radius: 6px;
    cursor: pointer;
    width: 100%;
    text-align: center;
}

.expand-more-issues:hover {
    background: rgba(255, 255, 255, 0.1);
}

@media (max-width: 768px) {
    .reference-grid {
        grid-template-columns: 1fr;
    }
    
    .branches {
        flex-direction: column;
    }
    
    .issue-header {
        flex-direction: column;
        align-items: flex-start;
    }
}
</style>
`
}

func generateJuniorModeJS() string {
	return `
<script>
function toggleSection(btn, sectionClass) {
    const content = btn.nextElementSibling;
    if (content.style.display === 'none') {
        content.style.display = 'block';
        btn.innerHTML = btn.innerHTML.replace('📋', '📂').replace('🔍', '📂').replace('🔧', '📂').replace('🌳', '📂');
    } else {
        content.style.display = 'none';
        btn.innerHTML = btn.innerHTML.replace('📂', '📋');
    }
}

function toggleMoreIssues() {
    const content = document.querySelector('.more-issues-content');
    const btn = document.querySelector('.expand-more-issues');
    if (content.style.display === 'none') {
        content.style.display = 'block';
        btn.textContent = '📂 Hide Additional Issues';
    } else {
        content.style.display = 'none';
        btn.textContent = btn.textContent.replace('Hide', 'Show');
    }
}

function copyToClipboard(text) {
    navigator.clipboard.writeText(text).then(() => {
        const btn = event.target;
        const original = btn.textContent;
        btn.textContent = '✓ Copied!';
        setTimeout(() => btn.textContent = original, 2000);
    });
}
</script>
`
}

// Helper functions

func getSeverityIcon(severity string) string {
	switch severity {
	case "Critical":
		return "🔴"
	case "High":
		return "🟠"
	case "Medium":
		return "🟡"
	case "Low":
		return "🟢"
	default:
		return "⚪"
	}
}

func getSeverityColor(severity string) string {
	switch severity {
	case "Critical":
		return "#ef4444"
	case "High":
		return "#f97316"
	case "Medium":
		return "#eab308"
	case "Low":
		return "#22c55e"
	default:
		return "#6b7280"
	}
}

func getRiskColor(riskLevel safety.RiskLevel) string {
	switch riskLevel {
	case safety.RiskNone:
		return "#22c55e"
	case safety.RiskLow:
		return "#84cc16"
	case safety.RiskMedium:
		return "#eab308"
	case safety.RiskHigh:
		return "#f97316"
	case safety.RiskCritical:
		return "#ef4444"
	default:
		return "#6b7280"
	}
}

func formatSymptoms(symptoms string) string {
	// Convert bullet points to HTML list
	lines := strings.Split(symptoms, "\n")
	var result strings.Builder
	result.WriteString("<ul>")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" {
			line = strings.TrimPrefix(line, "• ")
			line = strings.TrimPrefix(line, "- ")
			result.WriteString(fmt.Sprintf("<li>%s</li>", line))
		}
	}
	result.WriteString("</ul>")
	return result.String()
}

func sortIssuesBySeverity(issues []JuniorModeIssue) {
	severityOrder := map[string]int{
		"Critical": 0,
		"High":     1,
		"Medium":   2,
		"Low":      3,
	}

	for i := 0; i < len(issues); i++ {
		for j := i + 1; j < len(issues); j++ {
			if severityOrder[issues[i].Severity] > severityOrder[issues[j].Severity] {
				issues[i], issues[j] = issues[j], issues[i]
			}
		}
	}
}

func buildStreamFilter(stream *models.StreamData) string {
	return fmt.Sprintf("(ip.addr == %s && ip.addr == %s) && (tcp.port == %d && tcp.port == %d)",
		stream.SrcIP, stream.DstIP, stream.SrcPort, stream.DstPort)
}
