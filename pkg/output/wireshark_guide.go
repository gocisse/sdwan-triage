package output

import (
	"fmt"
	"html/template"
	"strings"

	"github.com/gocisse/sdwan-triage/pkg/analyzer"
	"github.com/gocisse/sdwan-triage/pkg/models"
)

// WiresharkGuide provides comprehensive Wireshark analysis guidance
type WiresharkGuide struct {
	StreamFilter  string
	DisplayFilter string
	Profile       string
	Columns       []WiresharkColumn
	ColorRules    []WiresharkColorRule
	AnalysisSteps []WiresharkAnalysisStep
	QuickFilters  []QuickFilter
}

// WiresharkColumn defines a custom column for Wireshark
type WiresharkColumn struct {
	Title string
	Field string
	Width int
}

// WiresharkColorRule defines a temporary color rule
type WiresharkColorRule struct {
	Name       string
	Filter     string
	Foreground string
	Background string
}

// WiresharkAnalysisStep is a detailed analysis step
type WiresharkAnalysisStep struct {
	Order       int
	Title       string
	Filter      string
	Description string
	WhatToLook  string
	GoodSign    string
	BadSign     string
	Screenshot  string
	Tips        []string
	YourResult  string // Stream-specific analysis result
}

// QuickFilter is a pre-built filter for common tasks
type QuickFilter struct {
	Name        string
	Filter      string
	Description string
	Category    string
}

// WiresharkGuideGenerator creates Wireshark analysis guides
type WiresharkGuideGenerator struct{}

// NewWiresharkGuideGenerator creates a new guide generator
func NewWiresharkGuideGenerator() *WiresharkGuideGenerator {
	return &WiresharkGuideGenerator{}
}

// GenerateGuide creates a complete Wireshark guide for a stream and issue
func (g *WiresharkGuideGenerator) GenerateGuide(stream *models.StreamData, issue *analyzer.IssueType) *WiresharkGuide {
	guide := &WiresharkGuide{
		StreamFilter:  g.buildStreamFilter(stream),
		DisplayFilter: g.buildDisplayFilter(stream, issue),
		Profile:       g.recommendProfile(issue),
		Columns:       g.recommendColumns(issue),
		ColorRules:    g.buildColorRules(issue),
		AnalysisSteps: g.buildAnalysisSteps(stream, issue),
		QuickFilters:  g.buildQuickFilters(stream, issue),
	}
	return guide
}

// buildStreamFilter creates the base filter for the stream
func (g *WiresharkGuideGenerator) buildStreamFilter(stream *models.StreamData) string {
	if stream.Protocol == "TCP" {
		return fmt.Sprintf("ip.addr == %s && ip.addr == %s && tcp.port == %d && tcp.port == %d",
			stream.SrcIP, stream.DstIP, stream.SrcPort, stream.DstPort)
	}
	return fmt.Sprintf("ip.addr == %s && ip.addr == %s && udp.port == %d && udp.port == %d",
		stream.SrcIP, stream.DstIP, stream.SrcPort, stream.DstPort)
}

// buildDisplayFilter creates an optimized display filter
func (g *WiresharkGuideGenerator) buildDisplayFilter(stream *models.StreamData, issue *analyzer.IssueType) string {
	base := g.buildStreamFilter(stream)

	if issue == nil {
		return base
	}

	// Add issue-specific filter enhancements
	switch issue.Code {
	case "TLS_HANDSHAKE_STALL", "TLS_HANDSHAKE_INCOMPLETE":
		return base + " && tls"
	case "TCP_RETRANSMISSION_BURST":
		return base + " && tcp.analysis.retransmission"
	case "TCP_RESET_UNEXPECTED":
		return base + " && tcp.flags.reset == 1"
	case "SMB_SLOW_TRANSFER":
		return base + " && smb2"
	default:
		return base
	}
}

// recommendProfile suggests a Wireshark profile
func (g *WiresharkGuideGenerator) recommendProfile(issue *analyzer.IssueType) string {
	if issue == nil {
		return "Default"
	}

	switch issue.Code {
	case "TLS_HANDSHAKE_STALL", "TLS_HANDSHAKE_INCOMPLETE", "WEAK_TLS_VERSION":
		return "TLS Analysis"
	case "TCP_RETRANSMISSION_BURST", "TCP_RESET_UNEXPECTED", "LARGE_TIME_GAP":
		return "TCP Analysis"
	case "SMB_SLOW_TRANSFER", "SMB_SIGNING_OVERHEAD":
		return "SMB Analysis"
	case "VOIP_JITTER_HIGH", "VOIP_PACKET_LOSS":
		return "VoIP Analysis"
	default:
		return "Default"
	}
}

// recommendColumns suggests custom columns based on issue type
func (g *WiresharkGuideGenerator) recommendColumns(issue *analyzer.IssueType) []WiresharkColumn {
	// Base columns always useful
	columns := []WiresharkColumn{
		{Title: "Time", Field: "frame.time_relative", Width: 100},
		{Title: "Delta", Field: "frame.time_delta_displayed", Width: 80},
		{Title: "Source", Field: "ip.src", Width: 120},
		{Title: "Dest", Field: "ip.dst", Width: 120},
	}

	if issue == nil {
		return columns
	}

	// Add issue-specific columns
	switch issue.Code {
	case "TLS_HANDSHAKE_STALL", "TLS_HANDSHAKE_INCOMPLETE":
		columns = append(columns,
			WiresharkColumn{Title: "TLS Type", Field: "tls.handshake.type", Width: 80},
			WiresharkColumn{Title: "TLS Version", Field: "tls.record.version", Width: 80},
			WiresharkColumn{Title: "SNI", Field: "tls.handshake.extensions_server_name", Width: 150},
		)
	case "TCP_RETRANSMISSION_BURST":
		columns = append(columns,
			WiresharkColumn{Title: "Seq", Field: "tcp.seq", Width: 100},
			WiresharkColumn{Title: "Ack", Field: "tcp.ack", Width: 100},
			WiresharkColumn{Title: "Len", Field: "tcp.len", Width: 60},
			WiresharkColumn{Title: "Analysis", Field: "tcp.analysis.flags", Width: 150},
		)
	case "SMB_SLOW_TRANSFER":
		columns = append(columns,
			WiresharkColumn{Title: "SMB Cmd", Field: "smb2.cmd", Width: 80},
			WiresharkColumn{Title: "File", Field: "smb2.filename", Width: 200},
			WiresharkColumn{Title: "Status", Field: "smb2.nt_status", Width: 100},
		)
	case "VOIP_JITTER_HIGH", "VOIP_PACKET_LOSS":
		columns = append(columns,
			WiresharkColumn{Title: "RTP Seq", Field: "rtp.seq", Width: 80},
			WiresharkColumn{Title: "RTP TS", Field: "rtp.timestamp", Width: 100},
			WiresharkColumn{Title: "Jitter", Field: "rtp.analysis.jitter", Width: 80},
		)
	}

	return columns
}

// buildColorRules creates temporary color rules for the issue
func (g *WiresharkGuideGenerator) buildColorRules(issue *analyzer.IssueType) []WiresharkColorRule {
	rules := []WiresharkColorRule{
		// Always useful rules
		{Name: "Retransmissions", Filter: "tcp.analysis.retransmission", Foreground: "#ffffff", Background: "#ff6b6b"},
		{Name: "TCP RST", Filter: "tcp.flags.reset == 1", Foreground: "#ffffff", Background: "#dc2626"},
		{Name: "ICMP Errors", Filter: "icmp.type == 3", Foreground: "#ffffff", Background: "#f59e0b"},
	}

	if issue == nil {
		return rules
	}

	// Add issue-specific rules
	switch issue.Code {
	case "TLS_HANDSHAKE_STALL":
		rules = append(rules,
			WiresharkColorRule{Name: "TLS ClientHello", Filter: "tls.handshake.type == 1", Foreground: "#000000", Background: "#93c5fd"},
			WiresharkColorRule{Name: "TLS ServerHello", Filter: "tls.handshake.type == 2", Foreground: "#000000", Background: "#86efac"},
		)
	case "LARGE_TIME_GAP":
		rules = append(rules,
			WiresharkColorRule{Name: "Large Gap", Filter: "frame.time_delta > 5", Foreground: "#000000", Background: "#fbbf24"},
		)
	}

	return rules
}

// buildAnalysisSteps creates detailed step-by-step analysis
func (g *WiresharkGuideGenerator) buildAnalysisSteps(stream *models.StreamData, issue *analyzer.IssueType) []WiresharkAnalysisStep {
	if issue == nil {
		return g.buildGenericSteps(stream)
	}

	steps := make([]WiresharkAnalysisStep, 0)

	// Convert issue checks to detailed steps
	for _, check := range issue.WiresharkChecks {
		step := WiresharkAnalysisStep{
			Order:      check.Order,
			Title:      check.Title,
			Filter:     check.Filter,
			WhatToLook: check.WhatToLook,
			GoodSign:   check.GoodSign,
			BadSign:    check.BadSign,
		}

		// Add detailed descriptions and tips
		step.Description, step.Tips = g.enrichStep(check, issue.Code)
		steps = append(steps, step)
	}

	return steps
}

// enrichStep adds detailed descriptions and tips to analysis steps
func (g *WiresharkGuideGenerator) enrichStep(check analyzer.WiresharkCheck, issueCode string) (string, []string) {
	var description string
	var tips []string

	switch check.Title {
	case "Verify TCP Handshake":
		description = "The TCP 3-way handshake (SYN → SYN-ACK → ACK) establishes the connection. Delays here indicate network path issues."
		tips = []string{
			"Right-click → Follow → TCP Stream to see full conversation",
			"Check Statistics → TCP Stream Graphs → Round Trip Time",
			"Compare TTL values to detect asymmetric routing",
		}

	case "Measure TLS Latency":
		description = "TLS handshake adds 1-2 round trips. ClientHello to ServerHello should be <1 second on healthy networks."
		tips = []string{
			"Filter: tls.handshake.type == 1 for ClientHello",
			"Filter: tls.handshake.type == 2 for ServerHello",
			"Check time delta between these packets",
		}

	case "Check Path Issues":
		description = "ICMP errors and unexpected TCP RSTs indicate network path problems or firewall interference."
		tips = []string{
			"ICMP Type 3 = Destination Unreachable",
			"ICMP Type 11 = Time Exceeded (TTL)",
			"RST from unexpected IP = middlebox interference",
		}

	case "Analyze Retransmissions":
		description = "Retransmissions indicate packet loss. High rates (>5%) suggest network congestion or errors."
		tips = []string{
			"Statistics → TCP Stream Graphs → Throughput shows impact",
			"Look for patterns - bursts vs random",
			"Check interface error counters on network devices",
		}

	case "Check SMB Version":
		description = "SMB version significantly impacts performance. SMB1 is very slow over WAN."
		tips = []string{
			"SMB 3.x supports multichannel and compression",
			"SMB 2.x is acceptable but not optimal",
			"SMB 1.x should be disabled for security and performance",
		}

	default:
		description = check.WhatToLook
		tips = []string{"Apply the filter and observe the results"}
	}

	return description, tips
}

// buildGenericSteps creates generic analysis steps when no specific issue
func (g *WiresharkGuideGenerator) buildGenericSteps(stream *models.StreamData) []WiresharkAnalysisStep {
	return []WiresharkAnalysisStep{
		{
			Order:       1,
			Title:       "Overview",
			Filter:      g.buildStreamFilter(stream),
			Description: "Start by viewing all packets in the stream",
			WhatToLook:  "Overall packet count, timing, and flow",
			GoodSign:    "Steady bidirectional traffic",
			BadSign:     "One-way traffic, large gaps, or errors",
		},
		{
			Order:       2,
			Title:       "Check for Errors",
			Filter:      g.buildStreamFilter(stream) + " && (tcp.analysis.flags || icmp)",
			Description: "Look for TCP analysis flags and ICMP errors",
			WhatToLook:  "Retransmissions, resets, ICMP errors",
			GoodSign:    "No errors flagged",
			BadSign:     "Multiple errors or warnings",
		},
		{
			Order:       3,
			Title:       "Analyze Timing",
			Filter:      g.buildStreamFilter(stream),
			Description: "Check packet timing and gaps",
			WhatToLook:  "Time delta between packets",
			GoodSign:    "Consistent timing",
			BadSign:     "Large gaps (>1s) or irregular timing",
		},
	}
}

// buildQuickFilters creates pre-built filters for common tasks
func (g *WiresharkGuideGenerator) buildQuickFilters(stream *models.StreamData, issue *analyzer.IssueType) []QuickFilter {
	base := g.buildStreamFilter(stream)

	filters := []QuickFilter{
		{Name: "This Stream Only", Filter: base, Description: "Show only packets in this conversation", Category: "Basic"},
		{Name: "Exclude Empty", Filter: base + " && tcp.len > 0", Description: "Hide ACK-only packets", Category: "Basic"},
		{Name: "Retransmissions", Filter: base + " && tcp.analysis.retransmission", Description: "Show only retransmitted packets", Category: "Problems"},
		{Name: "TCP Errors", Filter: base + " && tcp.analysis.flags", Description: "Show packets with TCP analysis flags", Category: "Problems"},
		{Name: "Large Gaps", Filter: base + " && frame.time_delta > 1", Description: "Show packets after >1s gap", Category: "Timing"},
	}

	// Add protocol-specific filters
	switch stream.Application {
	case "TLS", "HTTPS":
		filters = append(filters,
			QuickFilter{Name: "TLS Handshake", Filter: base + " && tls.handshake", Description: "TLS handshake messages only", Category: "Protocol"},
			QuickFilter{Name: "TLS Alerts", Filter: base + " && tls.alert", Description: "TLS alert messages", Category: "Protocol"},
			QuickFilter{Name: "TLS App Data", Filter: base + " && tls.record.content_type == 23", Description: "Encrypted application data", Category: "Protocol"},
		)
	case "SMB":
		filters = append(filters,
			QuickFilter{Name: "SMB Commands", Filter: base + " && smb2.cmd", Description: "SMB2 commands", Category: "Protocol"},
			QuickFilter{Name: "SMB Errors", Filter: base + " && smb2.nt_status != 0", Description: "SMB operations with errors", Category: "Protocol"},
			QuickFilter{Name: "SMB Files", Filter: base + " && smb2.filename", Description: "File operations", Category: "Protocol"},
		)
	case "HTTP":
		filters = append(filters,
			QuickFilter{Name: "HTTP Requests", Filter: base + " && http.request", Description: "HTTP requests only", Category: "Protocol"},
			QuickFilter{Name: "HTTP Responses", Filter: base + " && http.response", Description: "HTTP responses only", Category: "Protocol"},
			QuickFilter{Name: "HTTP Errors", Filter: base + " && http.response.code >= 400", Description: "HTTP 4xx/5xx errors", Category: "Protocol"},
		)
	case "DNS":
		filters = append(filters,
			QuickFilter{Name: "DNS Queries", Filter: "dns.flags.response == 0", Description: "DNS queries only", Category: "Protocol"},
			QuickFilter{Name: "DNS Responses", Filter: "dns.flags.response == 1", Description: "DNS responses only", Category: "Protocol"},
			QuickFilter{Name: "DNS Errors", Filter: "dns.flags.rcode != 0", Description: "DNS errors (NXDOMAIN, etc)", Category: "Protocol"},
		)
	}

	return filters
}

// FormatText generates CLI-friendly text output
func (guide *WiresharkGuide) FormatText() string {
	var sb strings.Builder

	sb.WriteString("🎯 WIRESHARK INVESTIGATION GUIDE\n")
	sb.WriteString("═══════════════════════════════════════════════════════════════\n\n")

	sb.WriteString(fmt.Sprintf("📋 Base Filter:\n   %s\n\n", guide.StreamFilter))

	if guide.DisplayFilter != guide.StreamFilter {
		sb.WriteString(fmt.Sprintf("🔍 Optimized Filter:\n   %s\n\n", guide.DisplayFilter))
	}

	sb.WriteString(fmt.Sprintf("📊 Recommended Profile: %s\n\n", guide.Profile))

	// Analysis steps
	sb.WriteString("📝 ANALYSIS STEPS:\n")
	sb.WriteString("───────────────────────────────────────────────────────────────\n")

	for _, step := range guide.AnalysisSteps {
		sb.WriteString(fmt.Sprintf("\nStep %d: %s\n", step.Order, step.Title))
		sb.WriteString(fmt.Sprintf("   Filter: %s\n", step.Filter))
		sb.WriteString(fmt.Sprintf("   Look for: %s\n", step.WhatToLook))
		sb.WriteString(fmt.Sprintf("   ✓ Good: %s\n", step.GoodSign))
		sb.WriteString(fmt.Sprintf("   ✗ Bad: %s\n", step.BadSign))

		if len(step.Tips) > 0 {
			sb.WriteString("   💡 Tips:\n")
			for _, tip := range step.Tips {
				sb.WriteString(fmt.Sprintf("      • %s\n", tip))
			}
		}
	}

	// Quick filters
	sb.WriteString("\n📋 QUICK FILTERS:\n")
	sb.WriteString("───────────────────────────────────────────────────────────────\n")

	for _, qf := range guide.QuickFilters {
		sb.WriteString(fmt.Sprintf("   [%s] %s\n", qf.Category, qf.Name))
		sb.WriteString(fmt.Sprintf("      %s\n", qf.Filter))
	}

	return sb.String()
}

// FormatHTML generates rich HTML output
func (guide *WiresharkGuide) FormatHTML() template.HTML {
	var sb strings.Builder

	sb.WriteString(`<div class="wireshark-guide">`)
	sb.WriteString(`<div class="guide-header">🎯 Wireshark Investigation Guide</div>`)

	// Filters section
	sb.WriteString(`<div class="guide-filters">`)
	sb.WriteString(`<div class="filter-group">`)
	sb.WriteString(fmt.Sprintf(`<div class="filter-item">
		<span class="filter-label">📋 Base Filter:</span>
		<code class="filter-code clickable" onclick="copyToClipboard('%s')">%s</code>
		<button class="copy-btn" onclick="copyToClipboard('%s')">📋 Copy</button>
	</div>`, template.JSEscapeString(guide.StreamFilter),
		template.HTMLEscapeString(guide.StreamFilter),
		template.JSEscapeString(guide.StreamFilter)))

	if guide.DisplayFilter != guide.StreamFilter {
		sb.WriteString(fmt.Sprintf(`<div class="filter-item">
			<span class="filter-label">🔍 Optimized:</span>
			<code class="filter-code clickable" onclick="copyToClipboard('%s')">%s</code>
		</div>`, template.JSEscapeString(guide.DisplayFilter),
			template.HTMLEscapeString(guide.DisplayFilter)))
	}
	sb.WriteString(`</div></div>`)

	// Analysis steps
	sb.WriteString(`<div class="guide-steps">`)
	sb.WriteString(`<div class="steps-header">📝 Analysis Steps</div>`)

	for _, step := range guide.AnalysisSteps {
		sb.WriteString(fmt.Sprintf(`<div class="analysis-step">
			<div class="step-number">%d</div>
			<div class="step-content">
				<div class="step-title">%s</div>
				<div class="step-filter"><code>%s</code></div>
				<div class="step-description">%s</div>
				<div class="step-indicators">
					<span class="good-indicator">✓ %s</span>
					<span class="bad-indicator">✗ %s</span>
				</div>`,
			step.Order, step.Title,
			template.HTMLEscapeString(step.Filter),
			step.Description,
			step.GoodSign, step.BadSign))

		if len(step.Tips) > 0 {
			sb.WriteString(`<div class="step-tips"><strong>💡 Tips:</strong><ul>`)
			for _, tip := range step.Tips {
				sb.WriteString(fmt.Sprintf(`<li>%s</li>`, tip))
			}
			sb.WriteString(`</ul></div>`)
		}

		sb.WriteString(`</div></div>`)
	}
	sb.WriteString(`</div>`)

	// Quick filters
	sb.WriteString(`<div class="guide-quick-filters">`)
	sb.WriteString(`<div class="quick-header">📋 Quick Filters (click to copy)</div>`)
	sb.WriteString(`<div class="quick-grid">`)

	for _, qf := range guide.QuickFilters {
		sb.WriteString(fmt.Sprintf(`<div class="quick-filter" onclick="copyToClipboard('%s')">
			<span class="qf-category">%s</span>
			<span class="qf-name">%s</span>
			<span class="qf-desc">%s</span>
		</div>`, template.JSEscapeString(qf.Filter), qf.Category, qf.Name, qf.Description))
	}

	sb.WriteString(`</div></div>`)
	sb.WriteString(`</div>`)

	return template.HTML(sb.String())
}

// GetWiresharkGuideCSS returns CSS for the Wireshark guide
func GetWiresharkGuideCSS() string {
	return `
/* Wireshark Guide - Dark Mode Compatible */
.wireshark-guide {
    background: var(--color-surface);
    border: 1px solid var(--color-border);
    border-radius: 12px;
    padding: 20px;
    margin: 16px 0;
}

.guide-header {
    font-size: 1.1em;
    font-weight: bold;
    color: #60a5fa;
    margin-bottom: 16px;
    padding-bottom: 12px;
    border-bottom: 2px solid #3b82f6;
}

.guide-filters {
    background: var(--color-card);
    padding: 16px;
    border-radius: 8px;
    margin-bottom: 16px;
    border: 1px solid var(--color-border);
}

.filter-item {
    display: flex;
    align-items: center;
    gap: 10px;
    margin-bottom: 10px;
}

.filter-label {
    min-width: 120px;
    font-weight: 500;
    color: var(--color-text-secondary);
}

.filter-code {
    flex: 1;
    background: var(--color-surface);
    padding: 8px 12px;
    border-radius: 6px;
    font-family: 'Courier New', monospace;
    font-size: 0.85em;
    word-break: break-all;
    color: #22d3ee;
    border: 1px solid var(--color-border);
}

.filter-code.clickable {
    cursor: pointer;
    transition: all 0.2s;
}

.filter-code.clickable:hover {
    background: rgba(59, 130, 246, 0.1);
    border-color: rgba(59, 130, 246, 0.3);
}

.copy-btn {
    padding: 6px 12px;
    border: 1px solid var(--color-border);
    border-radius: 6px;
    background: var(--color-card);
    cursor: pointer;
    font-size: 0.85em;
    color: var(--color-text-secondary);
}

.copy-btn:hover {
    background: rgba(59, 130, 246, 0.1);
    color: #60a5fa;
}

.guide-steps {
    margin-bottom: 16px;
}

.steps-header {
    font-weight: bold;
    color: var(--color-text-primary);
    margin-bottom: 12px;
}

.analysis-step {
    display: flex;
    gap: 12px;
    background: var(--color-card);
    padding: 16px;
    border-radius: 8px;
    margin-bottom: 12px;
    border: 1px solid var(--color-border);
    border-left: 4px solid #3b82f6;
}

.step-number {
    width: 32px;
    height: 32px;
    background: #3b82f6;
    color: white;
    border-radius: 50%;
    display: flex;
    align-items: center;
    justify-content: center;
    font-weight: bold;
    flex-shrink: 0;
}

.step-content {
    flex: 1;
}

.step-title {
    font-weight: bold;
    color: var(--color-text-primary);
    margin-bottom: 6px;
}

.step-filter code {
    background: var(--color-surface);
    padding: 4px 8px;
    border-radius: 4px;
    font-size: 0.85em;
    color: #22d3ee;
    border: 1px solid var(--color-border);
}

.step-description {
    color: var(--color-text-secondary);
    font-size: 0.9em;
    margin: 8px 0;
}

.step-indicators {
    display: flex;
    gap: 20px;
    font-size: 0.85em;
    margin-top: 8px;
}

.good-indicator { color: #4ade80; }
.bad-indicator { color: #f87171; }

.step-tips {
    margin-top: 10px;
    padding: 10px;
    background: rgba(245, 158, 11, 0.15);
    border-radius: 6px;
    font-size: 0.85em;
    color: #fbbf24;
    border: 1px solid rgba(245, 158, 11, 0.3);
}

.step-tips ul {
    margin: 5px 0 0 20px;
    padding: 0;
    color: var(--color-text-secondary);
}

.guide-quick-filters {
    background: var(--color-card);
    padding: 16px;
    border-radius: 8px;
    border: 1px solid var(--color-border);
}

.quick-header {
    font-weight: bold;
    color: var(--color-text-primary);
    margin-bottom: 12px;
}

.quick-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(250px, 1fr));
    gap: 10px;
}

.quick-filter {
    padding: 10px;
    background: var(--color-surface);
    border: 1px solid var(--color-border);
    border-radius: 6px;
    cursor: pointer;
    transition: all 0.2s;
}

.quick-filter:hover {
    background: rgba(59, 130, 246, 0.1);
    border-color: rgba(59, 130, 246, 0.3);
}

.qf-category {
    display: inline-block;
    padding: 2px 6px;
    background: rgba(99, 102, 241, 0.2);
    border-radius: 4px;
    font-size: 0.7em;
    color: #a5b4fc;
    margin-bottom: 4px;
}

.qf-name {
    display: block;
    font-weight: 500;
    color: var(--color-text-primary);
}

.qf-desc {
    display: block;
    font-size: 0.8em;
    color: var(--color-text-muted);
}
`
}

// GetWiresharkQuickReference returns a quick reference card for common filters
func GetWiresharkQuickReference() string {
	return `
<div class="wireshark-reference">
    <h3>🔍 Wireshark Quick Reference</h3>
    
    <div class="ref-section">
        <h4>Issue Icons & Filters</h4>
        <table class="ref-table">
            <tr><th>Icon</th><th>Issue</th><th>Wireshark Filter</th><th>Priority</th></tr>
            <tr><td>💥</td><td>Timeout/Stall</td><td><code>tcp.analysis.retransmission</code></td><td>Immediate</td></tr>
            <tr><td>🔄</td><td>Retransmissions</td><td><code>tcp.analysis.lost_segment</code></td><td>Immediate</td></tr>
            <tr><td>⏱️</td><td>Large gap</td><td><code>frame.time_delta > 5</code></td><td>Today</td></tr>
            <tr><td>⚠️</td><td>Protocol warning</td><td><code>tls.alert.level == 2</code></td><td>This week</td></tr>
            <tr><td>📉</td><td>Slow throughput</td><td><code>tcp.window_size < 640</code></td><td>This week</td></tr>
        </table>
    </div>

    <div class="ref-section">
        <h4>📊 SD-WAN Protocol Quick Reference</h4>
        <table class="ref-table">
            <tr><th>Vendor</th><th>Control Ports</th><th>Data Ports</th><th>Protocol</th></tr>
            <tr><td>Cisco Viptela</td><td>TCP 12346, 830</td><td>IPsec ESP (50)</td><td>DTLS, TLS</td></tr>
            <tr><td>VeloCloud</td><td>UDP 2426</td><td>UDP 2426</td><td>VCMP (UDP)</td></tr>
            <tr><td>Silver Peak</td><td>TCP 443, 179</td><td>UDP 4980, TCP 4163</td><td>HTTPS, IPsec</td></tr>
            <tr><td>Fortinet</td><td>UDP 500, 4500</td><td>IPsec ESP (50)</td><td>IKEv2, IPsec</td></tr>
            <tr><td>Prisma</td><td>TCP 443</td><td>UDP 4501</td><td>GlobalProtect</td></tr>
            <tr><td>Versa</td><td>TCP 12346, 443</td><td>IPsec ESP/AH</td><td>TLS, IPsec</td></tr>
        </table>
    </div>
    
    <div class="ref-section">
        <h4>🔍 Vendor-Agnostic SD-WAN Discovery</h4>
        <div class="ref-filter">
            <strong>SD-WAN Control All Vendors:</strong>
            <code>udp.port in {2426, 3784, 3785, 4784, 4785, 500, 4500} || tcp.port in {12346, 830, 179, 443, 541}</code>
        </div>
        <div class="ref-filter">
            <strong>SD-WAN Data All Vendors:</strong>
            <code>ip.proto == 50 || ip.proto == 51 || udp.port in {2426, 4980, 4501}</code>
        </div>
        <div class="ref-filter">
            <strong>Detect DTLS (common for SD-WAN tunnel setup):</strong>
            <code>dtls</code>
        </div>
        <div class="ref-filter">
            <strong>Find certificate exchanges (SD-WAN auth):</strong>
            <code>tls.handshake.type == 11</code>
        </div>
    </div>

    <div class="ref-section">
        <h4>🏢 Cisco Viptela</h4>
        <div class="ref-filter">
            <strong>vBond orchestration (DTLS-wrapped):</strong>
            <code>tcp.port == 12346</code>
        </div>
        <div class="ref-filter">
            <strong>OMP routing protocol (TLS over NETCONF):</strong>
            <code>tls && tcp.port == 830</code>
        </div>
        <div class="ref-filter">
            <strong>BFD for path monitoring:</strong>
            <code>udp.port in {3784, 3785, 4784, 4785}</code>
        </div>
        <div class="ref-filter">
            <strong>IPsec ESP data plane (overlay):</strong>
            <code>ip.proto == 50</code>
        </div>
    </div>

    <div class="ref-section">
        <h4>🔷 VMware VeloCloud</h4>
        <div class="ref-filter">
            <strong>VCMP Control & Data Tunnel (UDP only):</strong>
            <code>udp.port == 2426</code>
        </div>
        <div class="ref-filter">
            <strong>DTLS handshake for tunnel (v2):</strong>
            <code>dtls && udp.port == 2426</code>
        </div>
        <div class="ref-filter">
            <strong>VCMP keepalives and path probes:</strong>
            <code>udp.port == 2426 && udp.length < 100</code>
        </div>
        <div class="ref-filter">
            <strong>Edge activation DNS:</strong>
            <code>dns.qry.name contains "velocloud.net" || dns.qry.name contains "velocloud.com"</code>
        </div>
    </div>

    <div class="ref-section">
        <h4>🚀 Silver Peak / Aruba EdgeConnect</h4>
        <div class="ref-filter">
            <strong>Orchestrator communication (HTTPS):</strong>
            <code>tcp.port == 443</code>
        </div>
        <div class="ref-filter">
            <strong>BGP for route exchange (overlay):</strong>
            <code>tcp.port == 179</code>
        </div>
        <div class="ref-filter">
            <strong>Tunnel bonding UDP data:</strong>
            <code>udp.port == 4980</code>
        </div>
        <div class="ref-filter">
            <strong>Boost acceleration:</strong>
            <code>tcp.port == 4163</code>
        </div>
        <div class="ref-filter">
            <strong>Path conditioning probes:</strong>
            <code>icmp && icmp.type == 8 && data.len == 64</code>
        </div>
    </div>

    <div class="ref-section">
        <h4>🛡️ Fortinet (FortiGate SD-WAN)</h4>
        <div class="ref-filter">
            <strong>ADVPN shortcut IKE/IPsec:</strong>
            <code>udp.port == 500 || udp.port == 4500</code>
        </div>
        <div class="ref-filter">
            <strong>FGCP HA sync between FortiGates:</strong>
            <code>udp.port == 708</code>
        </div>
        <div class="ref-filter">
            <strong>SD-WAN SLA probes:</strong>
            <code>icmp && data.len == 32 && icmp.type == 8</code>
        </div>
        <div class="ref-filter">
            <strong>FortiManager policy push:</strong>
            <code>tcp.port == 541</code>
        </div>
        <div class="ref-filter">
            <strong>SSL VPN (if used for SD-WAN):</strong>
            <code>tcp.port == 10443</code>
        </div>
    </div>

    <div class="ref-section">
        <h4>🔒 Palo Alto Prisma Access</h4>
        <div class="ref-filter">
            <strong>GlobalProtect data plane:</strong>
            <code>udp.port == 4501</code>
        </div>
        <div class="ref-filter">
            <strong>Prisma Cloud Management (TLS):</strong>
            <code>tls && tcp.port == 443</code>
        </div>
        <div class="ref-filter">
            <strong>BGP over IPSec (SD-WAN routes):</strong>
            <code>tcp.port == 179</code>
        </div>
    </div>

    <div class="ref-section">
        <h4>🌐 Versa Networks (FlexVNF)</h4>
        <div class="ref-filter">
            <strong>Versa Director API (HTTPS):</strong>
            <code>tls && tcp.port == 443</code>
        </div>
        <div class="ref-filter">
            <strong>Device to Director/Controller:</strong>
            <code>tcp.port == 12346 || tcp.port == 443</code>
        </div>
        <div class="ref-filter">
            <strong>IPsec tunnels (ESP/AH):</strong>
            <code>ip.proto == 50 || ip.proto == 51</code>
        </div>
        <div class="ref-filter">
            <strong>BFD sessions:</strong>
            <code>udp.port in {3784, 3785, 4784, 4785}</code>
        </div>
    </div>

    <div class="ref-section">
        <h4>🛠️ Generic Troubleshooting Filters</h4>
        <div class="ref-filter">
            <strong>SD-WAN Performance Issues:</strong>
            <code>tcp.analysis.retransmission || tcp.analysis.fast_retransmission || tcp.analysis.spurious_retransmission</code>
        </div>
        <div class="ref-filter">
            <strong>Failed authentication (TLS/DTLS):</strong>
            <code>tls.alert_message.level == 2 || dtls.alert_message.level == 2</code>
        </div>
        <div class="ref-filter">
            <strong>Control plane connection resets:</strong>
            <code>(udp.port == 2426 || tcp.port == 12346 || tcp.port == 830) && tcp.flags.reset == 1</code>
        </div>
        <div class="ref-filter">
            <strong>MTU issues:</strong>
            <code>icmp.type == 3 && icmp.code == 4</code>
        </div>
        <div class="ref-filter">
            <strong>BFD sessions:</strong>
            <code>udp.port in {3784, 3785, 4784, 4785}</code>
        </div>
        <div class="ref-filter">
            <strong>High jitter indicator:</strong>
            <code>tcp.options.timestamp && tcp.analysis.out_of_order</code>
        </div>
        <div class="ref-filter">
            <strong>Microsoft 365 traffic:</strong>
            <code>tls.handshake.extensions_server_name contains "office365" || tls.handshake.extensions_server_name contains "microsoft"</code>
        </div>
    </div>

    <div class="ref-section" style="background: rgba(59, 130, 246, 0.1); border: 1px solid rgba(59, 130, 246, 0.3); border-radius: 8px; padding: 16px; margin-top: 16px;">
        <h4 style="color: #60a5fa; margin-top: 0;">💡 Pro Tips</h4>
        <ul style="color: var(--color-text-secondary); margin: 0; padding-left: 20px; line-height: 1.8;">
            <li><strong>Combine with host filters:</strong> <code>ip.addr == &lt;Edge_IP&gt; && (tcp.port == 12346 || udp.port == 2426)</code></li>
            <li><strong>Time-based analysis:</strong> Use <code>frame.time_relative</code> to find session establishment</li>
            <li><strong>SD-WAN rule debug:</strong> Filter on <code>ip.tos</code> or <code>dscp</code> values to see traffic class handling</li>
            <li><strong>Control vs Data:</strong> Control plane is usually TCP/DTLS; data plane is UDP ESP or VXLAN</li>
            <li><strong>VeloCloud note:</strong> VCMP uses UDP 2426 for both control AND data - not TCP!</li>
        </ul>
    </div>
</div>
`
}

// GetWiresharkReferenceCSS returns CSS for the quick reference
func GetWiresharkReferenceCSS() string {
	return `
/* Wireshark Reference - Dark Mode Compatible */
.wireshark-reference {
    background: var(--color-card);
    border: 1px solid var(--color-border);
    border-radius: 12px;
    padding: 20px;
    margin: 20px 0;
}

.wireshark-reference h3 {
    color: #60a5fa;
    margin-bottom: 16px;
    padding-bottom: 10px;
    border-bottom: 2px solid #3b82f6;
}

.wireshark-reference h4 {
    color: var(--color-text-primary);
    margin: 16px 0 10px 0;
}

.ref-section {
    margin-bottom: 20px;
}

.ref-table {
    width: 100%;
    border-collapse: collapse;
    font-size: 0.9em;
}

.ref-table th, .ref-table td {
    padding: 10px 12px;
    text-align: left;
    border-bottom: 1px solid var(--color-border);
    color: var(--color-text-secondary);
}

.ref-table th {
    background: var(--color-surface);
    font-weight: 600;
    color: var(--color-text-primary);
}

.ref-table code {
    background: var(--color-surface);
    padding: 4px 8px;
    border-radius: 4px;
    font-size: 0.85em;
    color: #22d3ee;
    font-family: 'Courier New', monospace;
    border: 1px solid var(--color-border);
}

.ref-filter {
    margin-bottom: 10px;
    padding: 12px;
    background: var(--color-surface);
    border-radius: 6px;
    border: 1px solid var(--color-border);
}

.ref-filter strong {
    display: block;
    margin-bottom: 6px;
    color: var(--color-text-secondary);
}

.ref-filter code {
    display: block;
    background: var(--color-card);
    padding: 10px;
    border-radius: 4px;
    font-size: 0.85em;
    word-break: break-all;
    color: #22d3ee;
    font-family: 'Courier New', monospace;
    border: 1px solid var(--color-border);
    cursor: pointer;
}

.ref-filter code:hover {
    background: rgba(59, 130, 246, 0.1);
    border-color: rgba(59, 130, 246, 0.3);
}
`
}
