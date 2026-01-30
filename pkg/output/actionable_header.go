package output

import (
	"fmt"
	"html/template"
	"strings"
	"time"

	"github.com/gocisse/sdwan-triage/pkg/analyzer"
	"github.com/gocisse/sdwan-triage/pkg/models"
)

// ActionableStream contains all diagnostic information for a stream
type ActionableStream struct {
	// Basic info
	SrcIP       string
	SrcPort     uint16
	DstIP       string
	DstPort     uint16
	Protocol    string
	Bytes       uint64
	Packets     uint64
	Duration    float64
	Application string

	// Classification
	TrafficType analyzer.TrafficClassification
	Health      string // "Healthy", "Degraded", "Critical"
	HealthIcon  string // 🟢, 🟡, 🔴
	HealthColor string // green, yellow, red

	// Problem detection
	PrimaryIssue     *analyzer.IssueType
	AllIssues        []StreamIssue
	RootCause        string
	BusinessImpact   string
	TechnicalDetails []string

	// Investigation
	WiresharkFilter    string
	SmartFilters       SmartFilterSet
	InvestigationSteps []InvestigationStep

	// Remediation
	Remediation RemediationChecklist

	// Timeline
	Events    []TimelineEvent
	FirstSeen time.Time
	LastSeen  time.Time
}

// SmartFilterSet contains context-aware Wireshark filters
type SmartFilterSet struct {
	Basic      string // Simple filter for this stream
	Optimized  string // Exclude keepalives/empty packets
	Related    string // Broader context (all traffic to this service)
	TimeWindow string // Filter to incident time only
	Exclusions string // Focus on problem packets
	OneClick   string // Copy-paste ready
}

// InvestigationStep is a guided Wireshark analysis step
type InvestigationStep struct {
	Order      int
	Title      string
	Filter     string
	WhatToLook string
	GoodSign   string
	BadSign    string
	YourResult string // What was found in this stream
}

// RemediationChecklist contains actionable fix steps
type RemediationChecklist struct {
	Immediate RemediationItem
	ShortTerm RemediationItem
	LongTerm  RemediationItem
	Commands  []string
}

// RemediationItem is a single remediation action
type RemediationItem struct {
	Action   string
	Command  string
	Priority string // "Now", "Today", "This Week"
	Done     bool
}

// ActionableStreamGenerator creates actionable stream analysis
type ActionableStreamGenerator struct {
	classifier    *analyzer.TrafficClassifier
	issueDetector *IssueDetector
	previewGen    *PreviewGenerator
}

// NewActionableStreamGenerator creates a new generator
func NewActionableStreamGenerator() *ActionableStreamGenerator {
	return &ActionableStreamGenerator{
		classifier:    analyzer.NewTrafficClassifier(),
		issueDetector: NewIssueDetector(),
		previewGen:    NewPreviewGenerator(),
	}
}

// GenerateActionableStream creates a complete actionable analysis for a stream
func (g *ActionableStreamGenerator) GenerateActionableStream(stream *models.StreamData) *ActionableStream {
	// Classify the traffic
	classification := g.classifier.ClassifyStream(stream)

	// Detect issues
	issues := g.issueDetector.DetectIssues(stream)

	// Determine health status
	health, healthIcon, healthColor := g.determineHealth(issues)

	// Match to known issue pattern
	primaryIssue := g.matchPrimaryIssue(stream, issues)

	// Build actionable stream
	as := &ActionableStream{
		SrcIP:       stream.SrcIP,
		SrcPort:     stream.SrcPort,
		DstIP:       stream.DstIP,
		DstPort:     stream.DstPort,
		Protocol:    stream.Protocol,
		Bytes:       stream.TotalBytes,
		Packets:     stream.PacketCount,
		Duration:    stream.Duration,
		Application: stream.Application,

		TrafficType: classification,
		Health:      health,
		HealthIcon:  healthIcon,
		HealthColor: healthColor,

		PrimaryIssue: primaryIssue,
		AllIssues:    issues,

		FirstSeen: stream.FirstSeen,
		LastSeen:  stream.LastSeen,
	}

	// Generate filters
	as.WiresharkFilter = g.buildBasicFilter(stream)
	as.SmartFilters = g.buildSmartFilters(stream, classification)

	// Generate investigation steps
	if primaryIssue != nil {
		as.InvestigationSteps = g.buildInvestigationSteps(primaryIssue, stream)
		as.Remediation = g.buildRemediation(primaryIssue)
		as.RootCause = g.determineRootCause(primaryIssue, stream)
		as.BusinessImpact = g.determineBusinessImpact(primaryIssue, classification)
		as.TechnicalDetails = g.extractTechnicalDetails(stream, issues)
	}

	return as
}

// determineHealth calculates overall stream health
func (g *ActionableStreamGenerator) determineHealth(issues []StreamIssue) (string, string, string) {
	hasCritical := false
	hasWarning := false

	for _, issue := range issues {
		if issue.Severity == "Critical" {
			hasCritical = true
		} else if issue.Severity == "Warning" {
			hasWarning = true
		}
	}

	if hasCritical {
		return "Critical", "🔴", "red"
	}
	if hasWarning {
		return "Degraded", "🟡", "yellow"
	}
	return "Healthy", "🟢", "green"
}

// matchPrimaryIssue finds the most relevant known issue pattern
func (g *ActionableStreamGenerator) matchPrimaryIssue(stream *models.StreamData, issues []StreamIssue) *analyzer.IssueType {
	// Analyze stream characteristics
	hasRetransmissions := false
	hasReset := false
	hasLargeGap := false
	maxGap := 0.0
	tlsVersion := ""
	isComplete := true

	for _, seg := range stream.Segments {
		if seg.IsRetransmit {
			hasRetransmissions = true
		}
		if seg.HasReset {
			hasReset = true
		}
		if seg.GapFromPrev > 5.0 {
			hasLargeGap = true
			if seg.GapFromPrev > maxGap {
				maxGap = seg.GapFromPrev
			}
		}

		// Check TLS version
		if len(seg.Data) >= 3 && seg.Data[0] == 0x16 {
			version := uint16(seg.Data[1])<<8 | uint16(seg.Data[2])
			switch version {
			case 0x0301:
				tlsVersion = "TLS 1.0"
			case 0x0302:
				tlsVersion = "TLS 1.1"
			case 0x0300:
				tlsVersion = "SSLv3"
			}
		}
	}

	// Check if TLS handshake completed
	if stream.Application == "TLS" || stream.Application == "HTTPS" {
		hasAppData := false
		for _, seg := range stream.Segments {
			if len(seg.Data) > 0 && seg.Data[0] == 0x17 {
				hasAppData = true
				break
			}
		}
		isComplete = hasAppData
	}

	// Match to issue
	issueCode := analyzer.MatchIssueToStream(hasRetransmissions, hasReset, hasLargeGap, maxGap,
		tlsVersion, stream.Application, isComplete)

	if issueCode != "" {
		if issue, ok := analyzer.GetIssueByCode(issueCode); ok {
			return &issue
		}
	}

	return nil
}

// buildBasicFilter creates a simple Wireshark filter
func (g *ActionableStreamGenerator) buildBasicFilter(stream *models.StreamData) string {
	if stream.Protocol == "TCP" {
		return fmt.Sprintf("ip.addr == %s && ip.addr == %s && tcp.port == %d && tcp.port == %d",
			stream.SrcIP, stream.DstIP, stream.SrcPort, stream.DstPort)
	}
	return fmt.Sprintf("ip.addr == %s && ip.addr == %s && udp.port == %d && udp.port == %d",
		stream.SrcIP, stream.DstIP, stream.SrcPort, stream.DstPort)
}

// buildSmartFilters creates context-aware filter set
func (g *ActionableStreamGenerator) buildSmartFilters(stream *models.StreamData, classification analyzer.TrafficClassification) SmartFilterSet {
	basic := g.buildBasicFilter(stream)

	// Optimized: exclude empty packets
	optimized := basic + " && tcp.len > 0"
	if stream.Protocol == "UDP" {
		optimized = basic + " && udp.length > 8"
	}

	// Related: broader context based on classification
	related := basic
	if classification.SNI != "" {
		related = fmt.Sprintf("tls.handshake.extensions_server_name contains \"%s\"", classification.SNI)
	} else if classification.Category == "Microsoft 365" {
		related = fmt.Sprintf("ip.addr == %s && (tls.handshake.extensions_server_name contains \"office365\" || tls.handshake.extensions_server_name contains \"microsoft\")", stream.SrcIP)
	} else if stream.DstPort == 445 {
		related = fmt.Sprintf("ip.addr == %s && tcp.port == 445", stream.SrcIP)
	}

	// Time window
	timeWindow := fmt.Sprintf("frame.time >= \"%s\" && frame.time <= \"%s\" && %s",
		stream.FirstSeen.Format("2006-01-02 15:04:05"),
		stream.LastSeen.Add(time.Second).Format("2006-01-02 15:04:05"),
		basic)

	// Exclusions: focus on problem packets
	exclusions := basic + " && (tcp.analysis.retransmission || tcp.analysis.lost_segment || tcp.flags.reset == 1)"

	return SmartFilterSet{
		Basic:      basic,
		Optimized:  optimized,
		Related:    related,
		TimeWindow: timeWindow,
		Exclusions: exclusions,
		OneClick:   basic, // Default to basic for one-click
	}
}

// buildInvestigationSteps creates guided analysis steps
func (g *ActionableStreamGenerator) buildInvestigationSteps(issue *analyzer.IssueType, stream *models.StreamData) []InvestigationStep {
	steps := make([]InvestigationStep, 0, len(issue.WiresharkChecks))

	for _, check := range issue.WiresharkChecks {
		step := InvestigationStep{
			Order:      check.Order,
			Title:      check.Title,
			Filter:     check.Filter,
			WhatToLook: check.WhatToLook,
			GoodSign:   check.GoodSign,
			BadSign:    check.BadSign,
		}

		// Add stream-specific findings
		step.YourResult = g.analyzeStepForStream(check, stream)

		steps = append(steps, step)
	}

	return steps
}

// analyzeStepForStream provides stream-specific analysis for each step
func (g *ActionableStreamGenerator) analyzeStepForStream(check analyzer.WiresharkCheck, stream *models.StreamData) string {
	switch check.Title {
	case "Verify TCP Handshake":
		// Check for SYN retransmissions
		synCount := 0
		for _, seg := range stream.Segments {
			if seg.IsRetransmit && seg.Direction == "client_to_server" {
				synCount++
			}
		}
		if synCount > 0 {
			return fmt.Sprintf("⚠️ %d retransmissions detected during connection setup", synCount)
		}
		return "✓ Connection established"

	case "Measure TLS Latency":
		// Find gap in TLS handshake
		for _, seg := range stream.Segments {
			if seg.GapFromPrev > 5.0 {
				return fmt.Sprintf("⚠️ %.1fs gap detected (exceeds threshold)", seg.GapFromPrev)
			}
		}
		return "✓ TLS timing within normal range"

	case "Check Path Issues":
		for _, seg := range stream.Segments {
			if seg.HasReset {
				return "⚠️ TCP RST detected - connection was reset"
			}
		}
		return "✓ No path issues detected"

	case "Analyze Retransmissions":
		retransmitCount := 0
		for _, seg := range stream.Segments {
			if seg.IsRetransmit {
				retransmitCount++
			}
		}
		if retransmitCount > 0 {
			pct := float64(retransmitCount) / float64(stream.PacketCount) * 100
			return fmt.Sprintf("⚠️ %d retransmissions (%.1f%% of packets)", retransmitCount, pct)
		}
		return "✓ No retransmissions"

	default:
		return "— Analysis pending"
	}
}

// buildRemediation creates actionable fix checklist
func (g *ActionableStreamGenerator) buildRemediation(issue *analyzer.IssueType) RemediationChecklist {
	return RemediationChecklist{
		Immediate: RemediationItem{
			Action:   issue.Remediation.Immediate,
			Priority: "Now",
		},
		ShortTerm: RemediationItem{
			Action:   issue.Remediation.ShortTerm,
			Priority: "Today",
		},
		LongTerm: RemediationItem{
			Action:   issue.Remediation.LongTerm,
			Priority: "This Week",
		},
		Commands: issue.Remediation.Commands,
	}
}

// determineRootCause provides likely root cause based on issue and stream data
func (g *ActionableStreamGenerator) determineRootCause(issue *analyzer.IssueType, stream *models.StreamData) string {
	if len(issue.RootCauses) > 0 {
		// Return most likely cause based on stream characteristics
		return issue.RootCauses[0]
	}
	return "Unknown - requires further investigation"
}

// determineBusinessImpact explains user-facing impact
func (g *ActionableStreamGenerator) determineBusinessImpact(issue *analyzer.IssueType, classification analyzer.TrafficClassification) string {
	// Customize impact based on traffic type
	baseImpact := issue.Impact

	switch classification.Category {
	case "Microsoft 365":
		if strings.Contains(classification.Service, "Outlook") {
			return "User experiencing slow email sync or 'Trying to connect...' in Outlook"
		}
		if strings.Contains(classification.Service, "Teams") {
			return "Teams calls may drop or have poor quality. Chat messages delayed."
		}
		return "Microsoft 365 services degraded for this user"

	case "File Sharing":
		return "Slow file access, long wait times when opening documents from network shares"

	case "VoIP":
		return "Call quality issues - choppy audio, dropped calls, one-way audio"

	case "Remote Access":
		return "Slow or unresponsive remote desktop/SSH sessions"

	default:
		return baseImpact
	}
}

// extractTechnicalDetails pulls specific details from stream
func (g *ActionableStreamGenerator) extractTechnicalDetails(stream *models.StreamData, issues []StreamIssue) []string {
	details := make([]string, 0)

	// Add timing details
	if len(stream.Segments) > 0 {
		details = append(details, fmt.Sprintf("First packet: %s", stream.FirstSeen.Format("15:04:05.000")))
	}

	// Add gap information
	for _, seg := range stream.Segments {
		if seg.GapFromPrev > 5.0 {
			details = append(details, fmt.Sprintf("%.1fs gap at %s", seg.GapFromPrev, seg.Timestamp.Format("15:04:05")))
		}
	}

	// Add retransmission count
	retransmitCount := 0
	for _, seg := range stream.Segments {
		if seg.IsRetransmit {
			retransmitCount++
		}
	}
	if retransmitCount > 0 {
		details = append(details, fmt.Sprintf("%d retransmissions detected", retransmitCount))
	}

	return details
}

// FormatText generates CLI-friendly text output
func (as *ActionableStream) FormatText() string {
	var sb strings.Builder

	// Header box
	sb.WriteString("╔══════════════════════════════════════════════════════════════════╗\n")
	sb.WriteString(fmt.Sprintf("║  %s %s: %s %s ║\n",
		as.TrafficType.Icon, strings.ToUpper(as.TrafficType.Category), as.TrafficType.Description, as.HealthIcon))
	sb.WriteString(fmt.Sprintf("║  %s:%d ↔ %s:%d (%s)%s║\n",
		as.SrcIP, as.SrcPort, as.DstIP, as.DstPort, as.Protocol,
		strings.Repeat(" ", 20)))
	sb.WriteString(fmt.Sprintf("║  ⏱️ %.2fs | 📦 %s | 🔢 %d packets | %s %s%s║\n",
		as.Duration, formatBytesCompact(as.Bytes), as.Packets, as.HealthIcon, as.Health,
		strings.Repeat(" ", 10)))

	if as.PrimaryIssue != nil {
		sb.WriteString("╠══════════════════════════════════════════════════════════════════╣\n")
		sb.WriteString(fmt.Sprintf("║  %s PRIMARY ISSUE: %s%s║\n",
			as.PrimaryIssue.Icon, as.PrimaryIssue.Title, strings.Repeat(" ", 10)))
		sb.WriteString("║                                                                  ║\n")
		sb.WriteString("║  🔍 TECHNICAL DETAILS:                                           ║\n")
		for _, detail := range as.TechnicalDetails {
			sb.WriteString(fmt.Sprintf("║     • %s%s║\n", detail, strings.Repeat(" ", 40-len(detail))))
		}
		sb.WriteString("║                                                                  ║\n")
		sb.WriteString(fmt.Sprintf("║  📍 BUSINESS IMPACT: %s ║\n", as.BusinessImpact))
	}

	// Investigation section
	if len(as.InvestigationSteps) > 0 {
		sb.WriteString("╠══════════════════════════════════════════════════════════════════╣\n")
		sb.WriteString("║  🎯 INVESTIGATE WITH WIRESHARK:                                  ║\n")
		sb.WriteString(fmt.Sprintf("║     Filter: %s ║\n", as.WiresharkFilter))
		sb.WriteString("║                                                                  ║\n")
		for _, step := range as.InvestigationSteps {
			sb.WriteString(fmt.Sprintf("║     Step %d: %s ║\n", step.Order, step.Title))
			sb.WriteString(fmt.Sprintf("║        Filter: %s ║\n", step.Filter))
			sb.WriteString(fmt.Sprintf("║        %s ║\n", step.YourResult))
		}
	}

	// Remediation section
	if as.PrimaryIssue != nil {
		sb.WriteString("╠══════════════════════════════════════════════════════════════════╣\n")
		sb.WriteString("║  🔧 REMEDIATION PLAN:                                            ║\n")
		sb.WriteString(fmt.Sprintf("║     [ ] IMMEDIATE (Now): %s ║\n", truncateForBox(as.Remediation.Immediate.Action, 40)))
		sb.WriteString(fmt.Sprintf("║     [ ] SHORT-TERM (Today): %s ║\n", truncateForBox(as.Remediation.ShortTerm.Action, 38)))
		sb.WriteString(fmt.Sprintf("║     [ ] LONG-TERM (This week): %s ║\n", truncateForBox(as.Remediation.LongTerm.Action, 35)))
	}

	sb.WriteString("╚══════════════════════════════════════════════════════════════════╝\n")

	return sb.String()
}

// FormatHTML generates rich HTML output
func (as *ActionableStream) FormatHTML() template.HTML {
	var sb strings.Builder

	// Determine card class based on health
	cardClass := "actionable-card " + as.HealthColor

	sb.WriteString(fmt.Sprintf(`<div class="%s">`, cardClass))

	// Header
	sb.WriteString(`<div class="actionable-header">`)
	sb.WriteString(fmt.Sprintf(`<div class="header-title">
		<span class="traffic-icon">%s</span>
		<span class="traffic-type">%s</span>
		<span class="traffic-desc">%s</span>
		<span class="health-badge %s">%s %s</span>
	</div>`,
		as.TrafficType.Icon, as.TrafficType.Category, as.TrafficType.Description,
		as.HealthColor, as.HealthIcon, as.Health))

	sb.WriteString(fmt.Sprintf(`<div class="header-endpoints">%s:%d ↔ %s:%d (%s)</div>`,
		as.SrcIP, as.SrcPort, as.DstIP, as.DstPort, as.Protocol))

	sb.WriteString(fmt.Sprintf(`<div class="header-stats">
		<span>⏱️ %s</span>
		<span>📦 %s</span>
		<span>🔢 %d packets</span>
	</div>`, formatDurationCompact(as.Duration), formatBytesCompact(as.Bytes), as.Packets))

	if as.TrafficType.SNI != "" {
		sb.WriteString(fmt.Sprintf(`<div class="header-sni">🔒 %s</div>`, template.HTMLEscapeString(as.TrafficType.SNI)))
	}
	sb.WriteString(`</div>`)

	// Problem section (if issues exist)
	if as.PrimaryIssue != nil {
		sb.WriteString(`<div class="actionable-problem">`)
		sb.WriteString(fmt.Sprintf(`<div class="problem-title">%s PRIMARY ISSUE: %s</div>`,
			as.PrimaryIssue.Icon, as.PrimaryIssue.Title))

		sb.WriteString(`<div class="problem-details">`)
		sb.WriteString(`<div class="detail-section"><strong>🔍 Technical Details:</strong><ul>`)
		for _, detail := range as.TechnicalDetails {
			sb.WriteString(fmt.Sprintf(`<li>%s</li>`, template.HTMLEscapeString(detail)))
		}
		sb.WriteString(`</ul></div>`)

		sb.WriteString(fmt.Sprintf(`<div class="detail-section"><strong>📍 Business Impact:</strong> %s</div>`,
			template.HTMLEscapeString(as.BusinessImpact)))

		sb.WriteString(fmt.Sprintf(`<div class="detail-section"><strong>🔍 Root Cause:</strong> %s</div>`,
			template.HTMLEscapeString(as.RootCause)))
		sb.WriteString(`</div></div>`)
	}

	// Investigation guide
	if len(as.InvestigationSteps) > 0 {
		sb.WriteString(`<div class="actionable-investigation">`)
		sb.WriteString(`<div class="investigation-title">🎯 WIRESHARK INVESTIGATION GUIDE</div>`)

		sb.WriteString(`<div class="filter-section">`)
		sb.WriteString(fmt.Sprintf(`<div class="filter-row">
			<span class="filter-label">Basic Filter:</span>
			<code class="filter-code" onclick="copyToClipboard('%s')">%s</code>
			<button class="copy-btn" onclick="copyToClipboard('%s')">📋</button>
		</div>`, template.JSEscapeString(as.SmartFilters.Basic),
			template.HTMLEscapeString(as.SmartFilters.Basic),
			template.JSEscapeString(as.SmartFilters.Basic)))

		sb.WriteString(fmt.Sprintf(`<div class="filter-row">
			<span class="filter-label">Optimized:</span>
			<code class="filter-code">%s</code>
		</div>`, template.HTMLEscapeString(as.SmartFilters.Optimized)))

		sb.WriteString(fmt.Sprintf(`<div class="filter-row">
			<span class="filter-label">Problem Focus:</span>
			<code class="filter-code">%s</code>
		</div>`, template.HTMLEscapeString(as.SmartFilters.Exclusions)))
		sb.WriteString(`</div>`)

		sb.WriteString(`<div class="investigation-steps">`)
		for _, step := range as.InvestigationSteps {
			resultClass := "result-pending"
			if strings.HasPrefix(step.YourResult, "✓") {
				resultClass = "result-good"
			} else if strings.HasPrefix(step.YourResult, "⚠️") {
				resultClass = "result-bad"
			}

			sb.WriteString(fmt.Sprintf(`<div class="investigation-step">
				<div class="step-header">Step %d: %s</div>
				<div class="step-filter"><code>%s</code></div>
				<div class="step-guidance">
					<span class="good-sign">✓ Good: %s</span>
					<span class="bad-sign">✗ Bad: %s</span>
				</div>
				<div class="step-result %s">%s</div>
			</div>`, step.Order, step.Title, template.HTMLEscapeString(step.Filter),
				step.GoodSign, step.BadSign, resultClass, step.YourResult))
		}
		sb.WriteString(`</div></div>`)
	}

	// Remediation checklist
	if as.PrimaryIssue != nil {
		sb.WriteString(`<div class="actionable-remediation">`)
		sb.WriteString(`<div class="remediation-title">🔧 REMEDIATION PLAN</div>`)
		sb.WriteString(`<div class="remediation-checklist">`)

		sb.WriteString(fmt.Sprintf(`<div class="remediation-item immediate">
			<input type="checkbox" id="rem-imm-%s">
			<label for="rem-imm-%s"><strong>IMMEDIATE (Now):</strong> %s</label>
		</div>`, as.SrcIP, as.SrcIP, template.HTMLEscapeString(as.Remediation.Immediate.Action)))

		sb.WriteString(fmt.Sprintf(`<div class="remediation-item short-term">
			<input type="checkbox" id="rem-short-%s">
			<label for="rem-short-%s"><strong>SHORT-TERM (Today):</strong> %s</label>
		</div>`, as.SrcIP, as.SrcIP, template.HTMLEscapeString(as.Remediation.ShortTerm.Action)))

		sb.WriteString(fmt.Sprintf(`<div class="remediation-item long-term">
			<input type="checkbox" id="rem-long-%s">
			<label for="rem-long-%s"><strong>LONG-TERM (This Week):</strong> %s</label>
		</div>`, as.SrcIP, as.SrcIP, template.HTMLEscapeString(as.Remediation.LongTerm.Action)))

		if len(as.Remediation.Commands) > 0 {
			sb.WriteString(`<div class="remediation-commands"><strong>Commands:</strong><ul>`)
			for _, cmd := range as.Remediation.Commands {
				sb.WriteString(fmt.Sprintf(`<li><code>%s</code></li>`, template.HTMLEscapeString(cmd)))
			}
			sb.WriteString(`</ul></div>`)
		}
		sb.WriteString(`</div></div>`)
	}

	// Action buttons
	sb.WriteString(`<div class="actionable-buttons">`)
	sb.WriteString(fmt.Sprintf(`<button class="action-btn" onclick="copyToClipboard('%s')">📋 Copy Filter</button>`,
		template.JSEscapeString(as.SmartFilters.Basic)))
	sb.WriteString(`<button class="action-btn" onclick="exportStream(this)">💾 Export PCAP</button>`)
	sb.WriteString(`<button class="action-btn" onclick="generateTACReport(this)">🎫 Create TAC Case</button>`)
	sb.WriteString(`</div>`)

	sb.WriteString(`</div>`)

	return template.HTML(sb.String())
}

// Helper functions
func formatBytesCompact(bytes uint64) string {
	if bytes < 1024 {
		return fmt.Sprintf("%d B", bytes)
	}
	if bytes < 1024*1024 {
		return fmt.Sprintf("%.1f KB", float64(bytes)/1024)
	}
	return fmt.Sprintf("%.1f MB", float64(bytes)/(1024*1024))
}

func formatDurationCompact(seconds float64) string {
	if seconds < 1 {
		return fmt.Sprintf("%.0fms", seconds*1000)
	}
	if seconds < 60 {
		return fmt.Sprintf("%.2fs", seconds)
	}
	return fmt.Sprintf("%.1fm", seconds/60)
}

func truncateForBox(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s + strings.Repeat(" ", maxLen-len(s))
	}
	return s[:maxLen-3] + "..."
}

// GetActionableStreamCSS returns CSS for actionable stream cards
func GetActionableStreamCSS() string {
	return `
/* Actionable Stream Cards - Dark Mode Compatible */
.actionable-card {
    border: 1px solid var(--color-border);
    border-radius: 12px;
    margin-bottom: 20px;
    overflow: hidden;
    background: var(--color-card);
    box-shadow: var(--shadow-md);
}

.actionable-card.green { border-left: 5px solid #22c55e; }
.actionable-card.yellow { border-left: 5px solid #eab308; }
.actionable-card.red { border-left: 5px solid #ef4444; }

.actionable-header {
    background: linear-gradient(135deg, #1e293b 0%, #334155 100%);
    color: white;
    padding: 16px 20px;
}

.header-title {
    display: flex;
    align-items: center;
    gap: 10px;
    margin-bottom: 8px;
}

.traffic-icon { font-size: 1.5em; }
.traffic-type { font-weight: bold; font-size: 1.1em; }
.traffic-desc { color: #94a3b8; }

.health-badge {
    margin-left: auto;
    padding: 4px 12px;
    border-radius: 20px;
    font-size: 0.85em;
}
.health-badge.green { background: rgba(34,197,94,0.2); color: #4ade80; }
.health-badge.yellow { background: rgba(234,179,8,0.2); color: #fbbf24; }
.health-badge.red { background: rgba(239,68,68,0.2); color: #f87171; }

.header-endpoints {
    font-family: monospace;
    font-size: 0.9em;
    color: #cbd5e1;
    margin-bottom: 8px;
}

.header-stats {
    display: flex;
    gap: 20px;
    font-size: 0.85em;
    color: #94a3b8;
}

.header-sni {
    margin-top: 8px;
    padding: 4px 8px;
    background: rgba(255,255,255,0.1);
    border-radius: 4px;
    font-size: 0.85em;
    display: inline-block;
}

.actionable-problem {
    padding: 16px 20px;
    background: rgba(239, 68, 68, 0.1);
    border-bottom: 1px solid rgba(239, 68, 68, 0.3);
}

.problem-title {
    font-weight: bold;
    color: #f87171;
    margin-bottom: 12px;
    font-size: 1.05em;
}

.problem-details {
    font-size: 0.9em;
    color: var(--color-text-secondary);
}

.detail-section {
    margin-bottom: 10px;
}

.detail-section ul {
    margin: 5px 0 0 20px;
    padding: 0;
}

.actionable-investigation {
    padding: 16px 20px;
    background: rgba(59, 130, 246, 0.1);
    border-bottom: 1px solid rgba(59, 130, 246, 0.3);
}

.investigation-title {
    font-weight: bold;
    color: #60a5fa;
    margin-bottom: 12px;
}

.filter-section {
    background: var(--color-surface);
    padding: 12px;
    border-radius: 8px;
    margin-bottom: 16px;
    border: 1px solid var(--color-border);
}

.filter-row {
    display: flex;
    align-items: center;
    gap: 10px;
    margin-bottom: 8px;
}

.filter-label {
    min-width: 100px;
    font-size: 0.85em;
    color: var(--color-text-muted);
}

.filter-code {
    flex: 1;
    background: var(--color-card);
    padding: 6px 10px;
    border-radius: 4px;
    font-size: 0.8em;
    cursor: pointer;
    word-break: break-all;
    color: #22d3ee;
    font-family: 'Courier New', monospace;
    border: 1px solid var(--color-border);
}

.filter-code:hover {
    background: rgba(59, 130, 246, 0.1);
    border-color: rgba(59, 130, 246, 0.3);
}

.copy-btn {
    padding: 4px 8px;
    border: 1px solid var(--color-border);
    border-radius: 4px;
    background: var(--color-card);
    cursor: pointer;
    color: var(--color-text-secondary);
}

.copy-btn:hover {
    background: rgba(59, 130, 246, 0.1);
    color: #60a5fa;
}

.investigation-steps {
    display: flex;
    flex-direction: column;
    gap: 12px;
}

.investigation-step {
    background: var(--color-surface);
    padding: 12px;
    border-radius: 8px;
    border-left: 3px solid #3b82f6;
    border: 1px solid var(--color-border);
    border-left: 3px solid #3b82f6;
}

.step-header {
    font-weight: bold;
    margin-bottom: 6px;
    color: var(--color-text-primary);
}

.step-filter code {
    background: var(--color-card);
    padding: 2px 6px;
    border-radius: 3px;
    font-size: 0.8em;
    color: #22d3ee;
    border: 1px solid var(--color-border);
}

.step-guidance {
    display: flex;
    gap: 20px;
    margin: 8px 0;
    font-size: 0.85em;
}

.good-sign { color: #4ade80; }
.bad-sign { color: #f87171; }

.step-result {
    padding: 6px 10px;
    border-radius: 4px;
    font-size: 0.9em;
}

.result-good { background: rgba(34, 197, 94, 0.15); color: #4ade80; }
.result-bad { background: rgba(239, 68, 68, 0.15); color: #f87171; }
.result-pending { background: var(--color-surface); color: var(--color-text-muted); }

.actionable-remediation {
    padding: 16px 20px;
    background: rgba(16, 185, 129, 0.1);
    border-bottom: 1px solid rgba(16, 185, 129, 0.3);
}

.remediation-title {
    font-weight: bold;
    color: #4ade80;
    margin-bottom: 12px;
}

.remediation-checklist {
    display: flex;
    flex-direction: column;
    gap: 10px;
}

.remediation-item {
    display: flex;
    align-items: flex-start;
    gap: 10px;
    padding: 10px;
    background: var(--color-surface);
    border-radius: 6px;
    border: 1px solid var(--color-border);
    color: var(--color-text-secondary);
}

.remediation-item input[type="checkbox"] {
    margin-top: 3px;
}

.remediation-item.immediate { border-left: 3px solid #ef4444; }
.remediation-item.short-term { border-left: 3px solid #f59e0b; }
.remediation-item.long-term { border-left: 3px solid #3b82f6; }

.remediation-commands {
    margin-top: 12px;
    padding: 10px;
    background: var(--color-surface);
    border-radius: 6px;
    border: 1px solid var(--color-border);
}

.remediation-commands code {
    background: var(--color-card);
    padding: 2px 6px;
    border-radius: 3px;
    font-size: 0.85em;
    color: #22d3ee;
}

.actionable-buttons {
    display: flex;
    gap: 10px;
    padding: 16px 20px;
    background: var(--color-surface);
}

.action-btn {
    padding: 10px 16px;
    border: 1px solid var(--color-border);
    border-radius: 6px;
    background: var(--color-card);
    cursor: pointer;
    font-size: 0.9em;
    transition: all 0.2s;
    color: var(--color-text-secondary);
}

.action-btn:hover {
    background: rgba(59, 130, 246, 0.1);
    border-color: rgba(59, 130, 246, 0.3);
    color: #60a5fa;
}

.action-btn.primary {
    background: #3b82f6;
    color: white;
    border-color: #3b82f6;
}

.action-btn.primary:hover {
    background: #2563eb;
}
`
}
