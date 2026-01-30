package safety

import (
	"fmt"
	"strings"
)

// ClarityLevel represents the level of technical detail in explanations
type ClarityLevel int

const (
	ClarityTechnical    ClarityLevel = iota // For senior engineers - full technical detail
	ClarityProfessional                     // For IT staff - balanced detail
	ClarityBusiness                         // For junior engineers/managers - simple language
)

// SimpleExplanation contains the translated issue explanation
type SimpleExplanation struct {
	Level            ClarityLevel `json:"level"`
	WhatsHappening   string       `json:"whats_happening"`
	WhyUsersCare     string       `json:"why_users_care"`
	FirstThingToDo   string       `json:"first_thing_to_do"`
	DontDoThisYet    string       `json:"dont_do_this_yet"`
	IfThisDoesntWork string       `json:"if_this_doesnt_work"`
	TechnicalDetails string       `json:"technical_details,omitempty"`
	WiresharkFilter  string       `json:"wireshark_filter,omitempty"`
}

// IssueTranslation contains all the translation data for an issue
type IssueTranslation struct {
	IssueID               string
	TechnicalDescription  string
	CustomerFacingSummary string
	UserExperience        string
	BusinessImpact        string
	UserSymptoms          string
	SafeFirstStep         string
	CommonMistake         string
	EscalationTrigger     string
	ValidationSteps       []string
}

// TranslateIssue converts technical findings to appropriate language level
func TranslateIssue(translation IssueTranslation, level ClarityLevel) SimpleExplanation {
	switch level {
	case ClarityTechnical:
		return SimpleExplanation{
			Level:            ClarityTechnical,
			WhatsHappening:   translation.TechnicalDescription,
			TechnicalDetails: translation.TechnicalDescription,
		}

	case ClarityProfessional:
		return SimpleExplanation{
			Level:            ClarityProfessional,
			WhatsHappening:   translation.CustomerFacingSummary,
			WhyUsersCare:     translation.UserExperience,
			FirstThingToDo:   translation.ValidationSteps[0],
			TechnicalDetails: translation.TechnicalDescription,
		}

	case ClarityBusiness:
		return SimpleExplanation{
			Level:            ClarityBusiness,
			WhatsHappening:   translation.BusinessImpact,
			WhyUsersCare:     translation.UserSymptoms,
			FirstThingToDo:   translation.SafeFirstStep,
			DontDoThisYet:    translation.CommonMistake,
			IfThisDoesntWork: translation.EscalationTrigger,
		}
	}

	return TranslateIssue(translation, ClarityBusiness)
}

// IssueTranslationLibrary contains pre-built translations for common issues
var IssueTranslationLibrary = map[string]IssueTranslation{
	// Microsoft 365 Issues
	"M365-EXO-001": {
		IssueID:               "M365-EXO-001",
		TechnicalDescription:  "Exchange Autodiscover loop detected. Client making repeated Autodiscover requests (>50 packets) over extended period (>30s) without successful configuration retrieval.",
		CustomerFacingSummary: "Outlook is having trouble finding your email settings automatically.",
		UserExperience:        "Outlook keeps asking for your password or shows 'Trying to connect...' for a long time.",
		BusinessImpact:        "Your computer is trying to connect to Microsoft's email server, but the connection keeps failing and retrying.",
		UserSymptoms:          "• Outlook won't open or takes forever to load\n• You keep getting password prompts\n• Emails aren't sending or receiving",
		SafeFirstStep:         "Ask 2-3 coworkers: 'Is Outlook working for you right now?'\nThis tells us if it's just your computer or a bigger problem.",
		CommonMistake:         "Don't restart the Exchange server yet - this might be a network issue, not an Exchange issue.",
		EscalationTrigger:     "If coworkers also have Outlook problems, call the Senior Network Engineer immediately.",
		ValidationSteps:       []string{"Check if multiple users affected", "Verify SD-WAN tunnel to Microsoft", "Check Exchange service health"},
	},

	"M365-TEAMS-001": {
		IssueID:               "M365-TEAMS-001",
		TechnicalDescription:  "Teams media quality degraded. High jitter (>100ms) or packet loss (>1%) detected on RTP streams to Teams media servers.",
		CustomerFacingSummary: "Microsoft Teams calls are experiencing poor audio/video quality.",
		UserExperience:        "Teams calls have choppy audio, frozen video, or people cutting in and out.",
		BusinessImpact:        "Your Teams calls sound robotic or keep freezing because the network connection to Microsoft is unstable.",
		UserSymptoms:          "• Voice sounds choppy or robotic\n• Video freezes or pixelates\n• People can't hear you or you can't hear them\n• Calls drop unexpectedly",
		SafeFirstStep:         "Ask others in the same meeting: 'Is my audio/video bad for everyone, or just some people?'",
		CommonMistake:         "Don't blame Microsoft or the user's headset yet - this is usually a network path issue.",
		EscalationTrigger:     "If multiple people in different locations have the same problem, escalate to network team.",
		ValidationSteps:       []string{"Check if issue affects all participants", "Verify QoS policy for Teams", "Check SD-WAN path to Teams"},
	},

	// DNS Issues
	"DNS-001": {
		IssueID:               "DNS-001",
		TechnicalDescription:  "DNS resolution timeout detected. Query to DNS server exceeded 2 second threshold without response.",
		CustomerFacingSummary: "Website names aren't being translated to addresses quickly enough.",
		UserExperience:        "Websites take forever to load, or you see 'DNS_PROBE_FINISHED_NXDOMAIN' errors.",
		BusinessImpact:        "When you type a website name, your computer asks a special server 'what's the address?' - that server isn't responding fast enough.",
		UserSymptoms:          "• Websites won't load or take 30+ seconds\n• You see 'This site can't be reached' errors\n• Some websites work, others don't",
		SafeFirstStep:         "Try opening google.com - if that works but other sites don't, it might be a specific DNS issue.",
		CommonMistake:         "Don't change DNS settings on individual computers - this could be a server-wide issue.",
		EscalationTrigger:     "If multiple people can't reach websites, contact the network team about DNS servers.",
		ValidationSteps:       []string{"Test DNS resolution manually", "Check DNS server health", "Verify network path to DNS"},
	},

	// TCP Transport Issues
	"TCP-001": {
		IssueID:               "TCP-001",
		TechnicalDescription:  "TCP zero-window condition detected. Receiver advertising zero receive window, causing sender to pause transmission.",
		CustomerFacingSummary: "Data transfer is being paused because the receiving computer is overwhelmed.",
		UserExperience:        "File transfers stall, applications freeze, or connections timeout.",
		BusinessImpact:        "The computer receiving data is saying 'slow down, I can't keep up!' - this causes everything to pause.",
		UserSymptoms:          "• File copies freeze at random percentages\n• Applications become unresponsive\n• 'Connection timed out' errors",
		SafeFirstStep:         "Check if the destination computer is running slowly (high CPU or memory usage).",
		CommonMistake:         "Don't blame the network - this is usually the receiving computer being overloaded.",
		EscalationTrigger:     "If the destination is a server affecting multiple users, escalate to the server team.",
		ValidationSteps:       []string{"Check destination system resources", "Verify application health", "Check for memory leaks"},
	},

	"TCP-002": {
		IssueID:               "TCP-002",
		TechnicalDescription:  "High TCP retransmission rate (>5%) detected. Significant packet loss on network path causing performance degradation.",
		CustomerFacingSummary: "Network is losing packets and having to resend them, slowing everything down.",
		UserExperience:        "Everything feels slow - websites, file transfers, applications.",
		BusinessImpact:        "Data packets are getting lost on the way to their destination, so they have to be sent again. This makes everything slower.",
		UserSymptoms:          "• Everything network-related is slow\n• File transfers take much longer than expected\n• Video calls are choppy",
		SafeFirstStep:         "Ask coworkers: 'Is the network slow for you too?' - this tells us if it's widespread.",
		CommonMistake:         "Don't restart individual applications - this is a network path issue.",
		EscalationTrigger:     "If multiple people experience slowness, escalate to network team immediately.",
		ValidationSteps:       []string{"Verify scope of impact", "Check SD-WAN tunnel health", "Review network utilization"},
	},

	// TLS Issues
	"TLS-001": {
		IssueID:               "TLS-001",
		TechnicalDescription:  "TLS handshake timeout detected. SSL/TLS negotiation exceeded 5 second threshold.",
		CustomerFacingSummary: "Secure connection setup is taking too long.",
		UserExperience:        "HTTPS websites won't load, or you see certificate errors.",
		BusinessImpact:        "When your browser tries to create a secure connection, the handshake process is timing out.",
		UserSymptoms:          "• Secure websites won't load\n• 'Connection not secure' warnings\n• Banking/shopping sites fail",
		SafeFirstStep:         "Try a different secure website (like your bank) - does it also fail?",
		CommonMistake:         "Don't disable security settings - this could be a network or proxy issue.",
		EscalationTrigger:     "If all HTTPS sites fail, contact network team about SSL inspection or proxy issues.",
		ValidationSteps:       []string{"Test multiple HTTPS sites", "Check proxy/SSL inspection", "Verify certificate chain"},
	},

	// SD-WAN Control Plane Issues
	"SDWAN-CTRL-001": {
		IssueID:               "SDWAN-CTRL-001",
		TechnicalDescription:  "SD-WAN controller unreachable. Control plane connection to orchestrator failed or timed out.",
		CustomerFacingSummary: "The SD-WAN management system can't communicate with this site.",
		UserExperience:        "Network might work but can't be managed or monitored remotely.",
		BusinessImpact:        "The central system that manages your network connection can't reach this location.",
		UserSymptoms:          "• Site shows 'offline' in SD-WAN dashboard\n• Policy changes don't apply\n• No visibility into site health",
		SafeFirstStep:         "Check if users at this site can still access the internet and internal resources.",
		CommonMistake:         "Don't restart the SD-WAN device without senior approval - this could cause an outage.",
		EscalationTrigger:     "Escalate to senior network engineer - SD-WAN control plane issues require expert handling.",
		ValidationSteps:       []string{"Verify user connectivity", "Check controller dashboard", "Review recent changes"},
	},

	// Vendor-Specific Issues
	"VIPTELA-OMP-001": {
		IssueID:               "VIPTELA-OMP-001",
		TechnicalDescription:  "OMP route flap detected. Rapid OMP session state changes indicating overlay routing instability.",
		CustomerFacingSummary: "Cisco SD-WAN routing is unstable, causing traffic to take different paths.",
		UserExperience:        "Connections drop randomly, some sites unreachable intermittently.",
		BusinessImpact:        "The SD-WAN system keeps changing how it routes traffic, causing connections to break.",
		UserSymptoms:          "• Random disconnections\n• Some sites work, then don't, then work again\n• VoIP calls drop",
		SafeFirstStep:         "Check the vManage dashboard - are multiple sites showing issues?",
		CommonMistake:         "Don't clear OMP sessions without understanding why they're flapping.",
		EscalationTrigger:     "Escalate to Cisco-certified engineer - OMP issues require deep SD-WAN expertise.",
		ValidationSteps:       []string{"Check vManage for alerts", "Review BFD session status", "Check WAN link quality"},
	},

	"VELOCLOUD-VCMP-001": {
		IssueID:               "VELOCLOUD-VCMP-001",
		TechnicalDescription:  "VCMP connection failure. VeloCloud Management Protocol connection to orchestrator failing.",
		CustomerFacingSummary: "VMware SD-WAN Edge can't communicate with the central controller.",
		UserExperience:        "Site may work but can't receive policy updates or be monitored.",
		BusinessImpact:        "The SD-WAN device at this location has lost contact with the management system.",
		UserSymptoms:          "• Edge shows offline in VCO\n• Configuration changes don't apply\n• No monitoring data",
		SafeFirstStep:         "Verify users can still access internet and internal resources.",
		CommonMistake:         "Don't restart the Edge without checking if it will reconnect automatically.",
		EscalationTrigger:     "Escalate to VMware SD-WAN certified engineer for VCMP troubleshooting.",
		ValidationSteps:       []string{"Check Edge local status", "Verify firewall allows VCMP", "Check VCO for events"},
	},

	// Security Issues
	"SEC-TLS-001": {
		IssueID:               "SEC-TLS-001",
		TechnicalDescription:  "TLS inspection breaking application. SSL/TLS inspection proxy causing connection failures for trusted service.",
		CustomerFacingSummary: "Security inspection is accidentally blocking a legitimate application.",
		UserExperience:        "Specific application won't connect, shows certificate errors.",
		BusinessImpact:        "The security system that checks encrypted traffic is interfering with a trusted application.",
		UserSymptoms:          "• Specific app won't connect\n• Certificate warnings for known-good sites\n• 'Connection reset' errors",
		SafeFirstStep:         "Note which specific application or website is failing.",
		CommonMistake:         "Don't disable SSL inspection entirely - just bypass the specific application.",
		EscalationTrigger:     "Contact security team to add application to SSL inspection bypass list.",
		ValidationSteps:       []string{"Identify affected application", "Check SSL inspection policy", "Verify certificate chain"},
	},

	"THREAT-C2-001": {
		IssueID:               "THREAT-C2-001",
		TechnicalDescription:  "Potential C2 beaconing detected. Regular interval communication pattern consistent with command and control beaconing.",
		CustomerFacingSummary: "Suspicious communication pattern detected that might indicate malware.",
		UserExperience:        "User may not notice anything - this is detected by traffic analysis.",
		BusinessImpact:        "A computer might be infected with malware that's 'phoning home' to an attacker.",
		UserSymptoms:          "• Usually no visible symptoms\n• Possible slow computer performance\n• Unexplained network activity",
		SafeFirstStep:         "DO NOT alert the user yet - this could tip off an attacker. Contact security team first.",
		CommonMistake:         "Don't disconnect the computer or alert the user without security team guidance.",
		EscalationTrigger:     "IMMEDIATELY escalate to security team - potential active threat.",
		ValidationSteps:       []string{"Document the finding", "Do not touch the endpoint", "Contact security team"},
	},
}

// GetTranslation retrieves a translation from the library
func GetTranslation(issueID string) (IssueTranslation, bool) {
	translation, exists := IssueTranslationLibrary[issueID]
	return translation, exists
}

// GenerateJuniorFriendlyExplanation creates a complete junior-friendly explanation
func GenerateJuniorFriendlyExplanation(issueID, title, technicalDesc, businessImpact, severity string, confidence float64) string {
	// Check if we have a pre-built translation
	if translation, exists := GetTranslation(issueID); exists {
		simple := TranslateIssue(translation, ClarityBusiness)
		return formatJuniorExplanation(simple, severity, confidence)
	}

	// Generate generic explanation for unknown issues
	return generateGenericExplanation(title, technicalDesc, businessImpact, severity, confidence)
}

func formatJuniorExplanation(simple SimpleExplanation, severity string, confidence float64) string {
	var sb strings.Builder

	// Header with severity indicator
	severityIcon := getSeverityIcon(severity)
	sb.WriteString(fmt.Sprintf("%s %s\n\n", severityIcon, strings.ToUpper(severity)))

	// What's happening
	sb.WriteString("❓ WHAT'S HAPPENING:\n")
	sb.WriteString(simple.WhatsHappening)
	sb.WriteString("\n\n")

	// Why users care
	sb.WriteString("😟 WHY THIS MATTERS:\n")
	sb.WriteString(simple.WhyUsersCare)
	sb.WriteString("\n\n")

	// First thing to do (always safe)
	sb.WriteString("✅ FIRST THING TO DO (completely safe):\n")
	sb.WriteString(simple.FirstThingToDo)
	sb.WriteString("\n\n")

	// What not to do yet
	if simple.DontDoThisYet != "" {
		sb.WriteString("⛔ DON'T DO THIS YET:\n")
		sb.WriteString(simple.DontDoThisYet)
		sb.WriteString("\n\n")
	}

	// Escalation trigger
	if simple.IfThisDoesntWork != "" {
		sb.WriteString("🚨 WHEN TO ESCALATE:\n")
		sb.WriteString(simple.IfThisDoesntWork)
		sb.WriteString("\n\n")
	}

	// Confidence explanation
	if confidence < 0.7 {
		sb.WriteString(fmt.Sprintf("⚠️ CONFIDENCE: %.0f%% (unusual pattern - validate carefully)\n", confidence*100))
	} else if confidence < 0.85 {
		sb.WriteString(fmt.Sprintf("📊 CONFIDENCE: %.0f%% (likely accurate)\n", confidence*100))
	} else {
		sb.WriteString(fmt.Sprintf("✓ CONFIDENCE: %.0f%% (high confidence)\n", confidence*100))
	}

	return sb.String()
}

func generateGenericExplanation(title, technicalDesc, businessImpact, severity string, confidence float64) string {
	var sb strings.Builder

	severityIcon := getSeverityIcon(severity)
	sb.WriteString(fmt.Sprintf("%s %s\n\n", severityIcon, title))

	sb.WriteString("❓ WHAT'S HAPPENING:\n")
	sb.WriteString(businessImpact)
	sb.WriteString("\n\n")

	sb.WriteString("✅ FIRST THING TO DO:\n")
	sb.WriteString("Ask 2-3 coworkers if they're experiencing the same issue.\n")
	sb.WriteString("This helps determine if it's a local or widespread problem.\n\n")

	sb.WriteString("🚨 WHEN TO ESCALATE:\n")
	sb.WriteString("If multiple people have the same issue, contact your senior engineer.\n\n")

	sb.WriteString(fmt.Sprintf("📊 CONFIDENCE: %.0f%%\n", confidence*100))

	return sb.String()
}

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

// ConfidenceExplanation provides context for confidence scores
type ConfidenceExplanation struct {
	Score          float64 `json:"score"`
	Interpretation string  `json:"interpretation"`
	Recommendation string  `json:"recommendation"`
	Breakdown      string  `json:"breakdown,omitempty"`
}

// ExplainConfidence provides junior-friendly confidence score explanation
func ExplainConfidence(score float64, isOnlyFinding bool) ConfidenceExplanation {
	if score >= 0.9 {
		return ConfidenceExplanation{
			Score:          score,
			Interpretation: "Very high confidence - the tool is very sure about this finding",
			Recommendation: "This finding is reliable. Proceed with the recommended validation steps.",
		}
	}

	if score >= 0.75 {
		return ConfidenceExplanation{
			Score:          score,
			Interpretation: "Good confidence - this is likely the correct diagnosis",
			Recommendation: "Follow the validation workflow. This finding is probably accurate.",
		}
	}

	if score >= 0.6 {
		if isOnlyFinding {
			return ConfidenceExplanation{
				Score:          score,
				Interpretation: "Moderate confidence, but this is the only finding",
				Recommendation: "⚠️ Don't ignore this just because confidence is moderate. Validate carefully and look for additional symptoms.",
			}
		}
		return ConfidenceExplanation{
			Score:          score,
			Interpretation: "Moderate confidence - the pattern is somewhat unusual",
			Recommendation: "Gather additional evidence before acting. Consider escalating for expert review.",
		}
	}

	return ConfidenceExplanation{
		Score:          score,
		Interpretation: "Low confidence - this is an unusual pattern",
		Recommendation: "🚨 Low confidence doesn't mean wrong - it means unusual. Escalate to senior engineer for validation.",
	}
}
