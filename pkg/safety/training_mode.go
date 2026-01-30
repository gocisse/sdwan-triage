package safety

import (
	"fmt"
	"strings"
)

// TrainingModule represents a training module for junior engineers
type TrainingModule struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Duration    string   `json:"duration"`
	Lessons     []Lesson `json:"lessons"`
	Required    bool     `json:"required"` // Must complete before using tool
}

// Lesson represents a single lesson within a module
type Lesson struct {
	ID            string     `json:"id"`
	Title         string     `json:"title"`
	Content       string     `json:"content"`
	KeyPoints     []string   `json:"key_points"`
	Quiz          []Question `json:"quiz,omitempty"`
	Exercise      *Exercise  `json:"exercise,omitempty"`
	Certification bool       `json:"certification"` // Must pass to proceed
}

// Question represents a quiz question
type Question struct {
	ID          string   `json:"id"`
	Question    string   `json:"question"`
	Options     []string `json:"options"`
	CorrectIdx  int      `json:"correct_idx"`
	Explanation string   `json:"explanation"`
}

// Exercise represents a hands-on exercise
type Exercise struct {
	Scenario string   `json:"scenario"`
	Task     string   `json:"task"`
	Hints    []string `json:"hints"`
	Solution string   `json:"solution"`
}

// TrainingProgress tracks an engineer's training progress
type TrainingProgress struct {
	EngineerID        string         `json:"engineer_id"`
	CompletedModules  []string       `json:"completed_modules"`
	QuizScores        map[string]int `json:"quiz_scores"`
	Certified         bool           `json:"certified"`
	CertificationDate string         `json:"certification_date,omitempty"`
}

// GetTrainingCurriculum returns the complete training curriculum
func GetTrainingCurriculum() []TrainingModule {
	return []TrainingModule{
		{
			ID:          "module-1",
			Name:        "Module 1: When to Trust the Tool",
			Description: "Learn how to interpret tool findings and confidence scores",
			Duration:    "15 minutes",
			Required:    true,
			Lessons: []Lesson{
				{
					ID:    "1-1",
					Title: "Understanding Confidence Scores",
					Content: `Confidence scores tell you how certain the tool is about a finding.

• 90-100%: Very high confidence - the tool is very sure
• 75-89%: Good confidence - likely accurate
• 60-74%: Moderate confidence - unusual pattern, validate carefully
• Below 60%: Low confidence - unusual pattern, escalate for review

IMPORTANT: Low confidence does NOT mean wrong!
Low confidence means the pattern is unusual. It could be:
- A new type of issue the tool hasn't seen before
- A real problem with unusual characteristics
- Something that needs expert review

Never ignore a finding just because confidence is low.`,
					KeyPoints: []string{
						"High confidence = tool is sure",
						"Low confidence = unusual pattern, NOT necessarily wrong",
						"Always validate, regardless of confidence",
						"When in doubt, escalate",
					},
					Quiz: []Question{
						{
							ID:       "q1-1-1",
							Question: "You see a 60% confidence finding. What should you do?",
							Options: []string{
								"Ignore it - confidence is too low",
								"Treat it as suspicious and validate carefully",
								"Immediately escalate to senior engineer",
								"Apply the remediation anyway",
							},
							CorrectIdx:  1,
							Explanation: "Low confidence doesn't mean wrong - it means unusual. Validate carefully and escalate if unsure.",
						},
						{
							ID:       "q1-1-2",
							Question: "A 95% confidence finding appears. Can you skip validation?",
							Options: []string{
								"Yes - 95% is very reliable",
								"No - always complete validation steps",
								"Only if it's not critical",
								"Only if you're in a hurry",
							},
							CorrectIdx:  1,
							Explanation: "Always complete validation steps, regardless of confidence. Even high-confidence findings can be wrong in unusual situations.",
						},
					},
				},
				{
					ID:    "1-2",
					Title: "The Most Common Mistake",
					Content: `THE #1 MISTAKE: Restarting a service when the real problem is the network.

Scenario: Tool says "Exchange Autodiscover timeout"
Wrong action: Restart Exchange server
Right action: Check if SD-WAN tunnel is healthy first

Why this matters:
- Restarting Exchange affects ALL users
- If the network is the problem, restart won't help
- You've caused an outage AND the problem persists

RULE: Never restart a service until you've confirmed:
1. The issue is isolated to that service
2. Other services are NOT affected
3. The network path is healthy`,
					KeyPoints: []string{
						"Check network before blaming services",
						"Verify scope before any restart",
						"Multiple services affected = network issue",
						"Single service affected = maybe service issue",
					},
					Quiz: []Question{
						{
							ID:       "q1-2-1",
							Question: "Tool shows 'Exchange timeout'. What's your FIRST step?",
							Options: []string{
								"Restart Exchange server",
								"Restart the Autodiscover app pool",
								"Check if other services are also affected",
								"Contact Microsoft support",
							},
							CorrectIdx:  2,
							Explanation: "Always check scope first. If other services are affected, it's likely a network issue, not Exchange.",
						},
					},
					Certification: true,
				},
			},
		},
		{
			ID:          "module-2",
			Name:        "Module 2: The Validation Workflow",
			Description: "Learn the mandatory validation steps before any remediation",
			Duration:    "10 minutes",
			Required:    true,
			Lessons: []Lesson{
				{
					ID:    "2-1",
					Title: "Always Check Scope First",
					Content: `Before ANY fix, determine if the issue affects one user or many.

This single check prevents 80% of misdiagnoses.

HOW TO CHECK:
1. Ask 2-3 colleagues: "Are you experiencing the same issue?"
2. Check if multiple services are affected
3. Look at the SD-WAN controller dashboard

IF MULTIPLE USERS AFFECTED:
→ This is NOT a local issue
→ Do NOT apply client-side fixes
→ Escalate to network team

IF SINGLE USER AFFECTED:
→ Might be local issue
→ Safe to try client-side fixes
→ Document and proceed carefully`,
					KeyPoints: []string{
						"Always ask colleagues first",
						"Multiple users = escalate",
						"Single user = may proceed carefully",
						"This check takes 2 minutes and saves hours",
					},
					Quiz: []Question{
						{
							ID:       "q2-1-1",
							Question: "Why is 'check scope' the first step?",
							Options: []string{
								"It's company policy",
								"It determines if you should escalate or fix locally",
								"It makes you look thorough",
								"It's optional but recommended",
							},
							CorrectIdx:  1,
							Explanation: "Scope determines everything. Multi-user issues need escalation; single-user issues may be fixed locally.",
						},
					},
					Exercise: &Exercise{
						Scenario: "User reports Outlook is slow. Tool shows TLS timeout to Microsoft.",
						Task:     "What are your first 3 actions?",
						Hints: []string{
							"Think about scope first",
							"Don't touch anything yet",
							"Gather information before acting",
						},
						Solution: "1. Ask colleagues if Outlook is slow for them too\n2. Check SD-WAN dashboard for tunnel health\n3. If multiple users affected, escalate. If single user, proceed with validation.",
					},
				},
				{
					ID:    "2-2",
					Title: "The Complete Validation Checklist",
					Content: `Before ANY remediation, complete this checklist:

☐ SCOPE: Is this affecting one user or many?
☐ SERVICES: Is this affecting one service or many?
☐ NETWORK: Is the SD-WAN tunnel healthy?
☐ TIMING: Did this start during a maintenance window?
☐ CHANGES: Were any changes made recently?
☐ DOCUMENTATION: Have I documented current symptoms?

If ANY of these indicate a larger issue:
→ STOP
→ ESCALATE
→ Do NOT proceed with local fixes

Only proceed with remediation if:
✓ Single user affected
✓ Single service affected
✓ Network path is healthy
✓ No recent changes
✓ Symptoms documented`,
					KeyPoints: []string{
						"Complete ALL checklist items",
						"Any red flag = escalate",
						"Document before you act",
						"When in doubt, don't proceed",
					},
					Certification: true,
				},
			},
		},
		{
			ID:          "module-3",
			Name:        "Module 3: Safe Remediation",
			Description: "Learn risk levels and when it's safe to act",
			Duration:    "10 minutes",
			Required:    true,
			Lessons: []Lesson{
				{
					ID:    "3-1",
					Title: "Understanding Risk Levels",
					Content: `Every action has a risk level:

🟢 NONE (Read-only):
- Checking status, viewing logs, ping, traceroute
- Always safe to do
- No approval needed

🟡 LOW (Single user impact):
- Clearing browser cache, restarting user's app
- Safe if single user confirmed
- Document what you did

🟠 MEDIUM (Service impact):
- Restarting a service, changing configuration
- Requires senior approval
- Have rollback plan ready

🔴 HIGH (Multi-service/production impact):
- Restarting servers, major config changes
- Requires senior approval + change window
- Never do without explicit authorization

RULE: Junior engineers should only perform 🟢 and 🟡 actions.
Anything 🟠 or 🔴 requires escalation.`,
					KeyPoints: []string{
						"Know your risk level before acting",
						"Junior = green and yellow only",
						"Orange and red = escalate",
						"When unsure, assume higher risk",
					},
					Quiz: []Question{
						{
							ID:       "q3-1-1",
							Question: "Which action can a junior engineer do without approval?",
							Options: []string{
								"Restart the Exchange server",
								"Clear a user's browser cache",
								"Change firewall rules",
								"Restart the SD-WAN controller",
							},
							CorrectIdx:  1,
							Explanation: "Clearing browser cache is LOW risk (single user). All other options are MEDIUM or HIGH risk requiring approval.",
						},
						{
							ID:       "q3-1-2",
							Question: "You're unsure if an action is LOW or MEDIUM risk. What do you do?",
							Options: []string{
								"Assume LOW and proceed",
								"Assume MEDIUM and get approval",
								"Try it and see what happens",
								"Skip it entirely",
							},
							CorrectIdx:  1,
							Explanation: "When unsure, always assume higher risk. Getting unnecessary approval is better than causing an outage.",
						},
					},
					Certification: true,
				},
			},
		},
		{
			ID:          "module-4",
			Name:        "Module 4: Overlay vs Underlay",
			Description: "Learn to distinguish between application and network issues",
			Duration:    "10 minutes",
			Required:    false,
			Lessons: []Lesson{
				{
					ID:    "4-1",
					Title: "The Overlay vs Underlay Trap",
					Content: `One of the most common mistakes: Blaming the application when the network is the problem.

OVERLAY = The application/service (Microsoft 365, SAP, etc.)
UNDERLAY = The network path (SD-WAN tunnels, internet, WAN)

THE TRAP:
- User says "Outlook is slow"
- Tool shows "M365 TLS timeout"
- You think: "Microsoft problem!"
- Reality: SD-WAN tunnel to Microsoft is degraded

HOW TO AVOID:
1. ALWAYS check SD-WAN tunnel health first
2. Check if OTHER cloud services are also slow
3. If multiple destinations affected = network issue
4. Only blame the application if network is confirmed healthy

REMEMBER: The application is usually innocent until the network is proven healthy.`,
					KeyPoints: []string{
						"Check network before blaming apps",
						"Multiple slow destinations = network",
						"Single slow destination = maybe app",
						"SD-WAN tunnel health is key",
					},
					Quiz: []Question{
						{
							ID:       "q4-1-1",
							Question: "User reports Teams is slow. What do you check first?",
							Options: []string{
								"Microsoft service health dashboard",
								"User's computer performance",
								"SD-WAN tunnel to Microsoft",
								"Teams application logs",
							},
							CorrectIdx:  2,
							Explanation: "Always check the network path first. If SD-WAN tunnel is degraded, that's your root cause.",
						},
					},
				},
			},
		},
	}
}

// QuizResult contains the result of a quiz attempt
type QuizResult struct {
	ModuleID       string `json:"module_id"`
	LessonID       string `json:"lesson_id"`
	Score          int    `json:"score"`
	TotalQuestions int    `json:"total_questions"`
	Passed         bool   `json:"passed"`
	PassingScore   int    `json:"passing_score"`
	Feedback       string `json:"feedback"`
}

// EvaluateQuiz evaluates quiz answers and returns result
func EvaluateQuiz(lesson Lesson, answers []int) QuizResult {
	if len(lesson.Quiz) == 0 {
		return QuizResult{Passed: true}
	}

	correct := 0
	for i, q := range lesson.Quiz {
		if i < len(answers) && answers[i] == q.CorrectIdx {
			correct++
		}
	}

	score := (correct * 100) / len(lesson.Quiz)
	passingScore := 80
	passed := score >= passingScore

	feedback := ""
	if passed {
		feedback = "✅ Great job! You've demonstrated understanding of this topic."
	} else {
		feedback = fmt.Sprintf("❌ You scored %d%%. Review the material and try again. You need %d%% to pass.", score, passingScore)
	}

	return QuizResult{
		LessonID:       lesson.ID,
		Score:          score,
		TotalQuestions: len(lesson.Quiz),
		Passed:         passed,
		PassingScore:   passingScore,
		Feedback:       feedback,
	}
}

// GenerateTrainingReport generates a training completion report
func GenerateTrainingReport(progress TrainingProgress) string {
	var sb strings.Builder

	sb.WriteString("═══════════════════════════════════════════════════════════════\n")
	sb.WriteString("           SD-WAN TRIAGE TOOL - TRAINING REPORT\n")
	sb.WriteString("═══════════════════════════════════════════════════════════════\n\n")

	sb.WriteString(fmt.Sprintf("Engineer ID: %s\n", progress.EngineerID))

	if progress.Certified {
		sb.WriteString(fmt.Sprintf("Status: ✅ CERTIFIED (Date: %s)\n", progress.CertificationDate))
	} else {
		sb.WriteString("Status: ⏳ Training In Progress\n")
	}

	sb.WriteString("\n─── Module Completion ───\n")

	curriculum := GetTrainingCurriculum()
	for _, module := range curriculum {
		completed := contains(progress.CompletedModules, module.ID)
		status := "⬜"
		if completed {
			status = "✅"
		}
		required := ""
		if module.Required {
			required = " (Required)"
		}
		sb.WriteString(fmt.Sprintf("%s %s%s\n", status, module.Name, required))
	}

	sb.WriteString("\n─── Quiz Scores ───\n")
	for moduleID, score := range progress.QuizScores {
		sb.WriteString(fmt.Sprintf("  %s: %d%%\n", moduleID, score))
	}

	if !progress.Certified {
		sb.WriteString("\n─── Next Steps ───\n")
		sb.WriteString("Complete all required modules to become certified.\n")
		sb.WriteString("Certification allows you to use the tool in production.\n")
	}

	sb.WriteString("\n═══════════════════════════════════════════════════════════════\n")

	return sb.String()
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// RealTimeGuidance provides context-sensitive guidance during tool use
type RealTimeGuidance struct {
	Context   string `json:"context"`
	Message   string `json:"message"`
	Tip       string `json:"tip"`
	NextStep  string `json:"next_step"`
	Warning   string `json:"warning,omitempty"`
	LearnMore string `json:"learn_more,omitempty"`
}

// GetGuidanceForContext returns appropriate guidance based on current context
func GetGuidanceForContext(context string, severity string, confidence float64, affectsMultiple bool) RealTimeGuidance {
	switch context {
	case "viewing_critical_issue":
		if confidence > 0.8 {
			return RealTimeGuidance{
				Context:  context,
				Message:  "🔴 High-confidence critical issue detected",
				Tip:      "This finding is very reliable. Prioritize this investigation.",
				NextStep: "Check if this affects multiple users before any action.",
			}
		}
		return RealTimeGuidance{
			Context:  context,
			Message:  "🔴 Critical issue with moderate confidence",
			Tip:      "The pattern is unusual but the severity is high.",
			NextStep: "Validate carefully and consider escalating for expert review.",
			Warning:  "Don't ignore this just because confidence is moderate.",
		}

	case "viewing_remediation":
		if affectsMultiple {
			return RealTimeGuidance{
				Context:  context,
				Message:  "⚠️ Multiple users/services affected",
				Tip:      "Local fixes won't help a widespread issue.",
				NextStep: "Escalate to senior engineer instead of applying this fix.",
				Warning:  "Applying local fixes to infrastructure issues wastes time.",
			}
		}
		return RealTimeGuidance{
			Context:  context,
			Message:  "📋 Review remediation carefully",
			Tip:      "Understand what the fix does before applying it.",
			NextStep: "Complete validation checklist, then proceed if appropriate.",
		}

	case "viewing_confidence_score":
		if confidence < 0.7 {
			return RealTimeGuidance{
				Context:   context,
				Message:   fmt.Sprintf("📊 Confidence: %.0f%% (unusual pattern)", confidence*100),
				Tip:       "Low confidence means unusual, not necessarily wrong.",
				NextStep:  "Gather additional evidence before acting.",
				LearnMore: "See Module 1: Understanding Confidence Scores",
			}
		}
		return RealTimeGuidance{
			Context:  context,
			Message:  fmt.Sprintf("📊 Confidence: %.0f%% (reliable)", confidence*100),
			Tip:      "This finding is likely accurate.",
			NextStep: "Proceed with validation workflow.",
		}

	case "about_to_remediate":
		return RealTimeGuidance{
			Context:  context,
			Message:  "⏸️ Before you proceed...",
			Tip:      "Have you completed all validation steps?",
			NextStep: "Review the validation checklist one more time.",
			Warning:  "Skipping validation is the #1 cause of misdiagnosis.",
		}

	default:
		return RealTimeGuidance{
			Context:  context,
			Message:  "💡 Remember the basics",
			Tip:      "Check scope → Validate → Then act",
			NextStep: "Follow the validation workflow.",
		}
	}
}
