package output

import (
	"encoding/json"
	"fmt"
	"html/template"
	"strings"

	"github.com/gocisse/sdwan-triage/pkg/analyzer"
	"github.com/gocisse/sdwan-triage/pkg/models"
)

// StreamSectionHTML generates the HTML for the stream reassembly section
func StreamSectionHTML(streams []models.StreamViewData) template.HTML {
	if len(streams) == 0 {
		return template.HTML(`<p class="no-data">No stream data captured. Streams are captured for TCP/UDP flows with payload data.</p>`)
	}

	var sb strings.Builder

	sb.WriteString(`<div class="stream-section">
		<div class="stream-intro">
			<p>📡 <strong>Follow TCP/UDP Stream</strong> - View reconstructed application-layer conversations. 
			Click on a stream to expand and see the full payload exchange. Arrows show direction: <span style="color:#2563eb">→ Client to Server</span> | <span style="color:#16a34a">← Server to Client</span></p>
		</div>
		<div class="stream-list">`)

	for i, stream := range streams {
		if i >= 20 { // Limit to 20 streams in HTML
			sb.WriteString(fmt.Sprintf(`<p class="stream-truncated">... and %d more streams (showing top 20 by bytes)</p>`, len(streams)-20))
			break
		}

		// Determine stream status icon based on application
		statusIcon := "🟢"
		if strings.Contains(stream.Application, "Unknown") {
			statusIcon = "⚪"
		} else if stream.Application == "TLS" || stream.Application == "HTTPS" {
			statusIcon = "🔒"
		} else if stream.Application == "HTTP" {
			statusIcon = "🌐"
		} else if stream.Application == "DNS" {
			statusIcon = "🔍"
		} else if stream.Application == "SMB" {
			statusIcon = "📁"
		} else if stream.Application == "SSH" {
			statusIcon = "🔑"
		}

		sb.WriteString(fmt.Sprintf(`
		<details class="stream-item" id="stream-%d">
			<summary class="stream-header">
				<span class="stream-icon">%s</span>
				<span class="stream-label">%s</span>
				<span class="stream-meta">
					<span class="stream-bytes">%s</span>
					<span class="stream-packets">%d pkts</span>
					<span class="stream-duration">%s</span>
				</span>
			</summary>
			<div class="stream-content">
				<div class="stream-actions">
					<button class="btn-copy-filter" onclick="copyToClipboard('%s')" title="Copy Wireshark filter">
						📋 Copy Wireshark Filter
					</button>
					<code class="wireshark-filter">%s</code>
				</div>
				<div class="stream-conversation">`,
			i, statusIcon, template.HTMLEscapeString(stream.Label),
			stream.TotalBytes, stream.PacketCount, stream.Duration,
			template.JSEscapeString(stream.WiresharkFilter),
			template.HTMLEscapeString(stream.WiresharkFilter)))

		// Add segments as conversation view
		for j, seg := range stream.Segments {
			if j >= 50 { // Limit segments shown
				sb.WriteString(fmt.Sprintf(`<div class="segment-truncated">... %d more segments</div>`, len(stream.Segments)-50))
				break
			}

			// Build CSS classes
			dirClass := seg.DirectionCSS
			anomalyClass := ""
			if seg.IsAnomaly {
				anomalyClass = " anomaly"
			}

			// Direction arrow and label
			dirArrow := "→"
			dirLabel := "Client → Server"
			if seg.Direction == "←" {
				dirArrow = "←"
				dirLabel = "Server → Client"
			}

			sb.WriteString(fmt.Sprintf(`
					<div class="conversation-segment %s%s">
						<div class="segment-meta">
							<span class="segment-time" title="Absolute time">%s</span>
							<span class="segment-rel-time" title="Relative to stream start">%s</span>
						</div>
						<div class="segment-direction-indicator %s">
							<span class="direction-arrow">%s</span>
							<span class="direction-label">%s</span>
						</div>
						<div class="segment-body">`,
				dirClass, anomalyClass, seg.Timestamp, seg.TimestampRel, dirClass, dirArrow, dirLabel))

			// Show anomaly indicator if present
			if seg.IsAnomaly {
				sb.WriteString(fmt.Sprintf(`
							<div class="anomaly-indicator" title="%s">
								<span class="anomaly-icon">%s</span>
								<span class="anomaly-text">%s</span>
							</div>`,
					template.HTMLEscapeString(seg.AnomalyReason),
					seg.AnomalyIcon,
					template.HTMLEscapeString(seg.AnomalyReason)))
			}

			// Plain English summary (primary display) - always show this prominently
			if seg.PlainEnglish != "" {
				sb.WriteString(fmt.Sprintf(`
							<div class="segment-plain-english">%s</div>`,
					template.HTMLEscapeString(seg.PlainEnglish)))
			}

			// Data summary for binary data OR preview for text
			if seg.DataSummary != "" {
				// Binary data - show clean summary with optional hex toggle
				sb.WriteString(fmt.Sprintf(`
							<div class="segment-data-summary">%s</div>`,
					template.HTMLEscapeString(seg.DataSummary)))

				if seg.ShowHexToggle && seg.DataHex != "" {
					sb.WriteString(fmt.Sprintf(`
							<details class="hex-toggle">
								<summary class="hex-toggle-btn">🔍 Show Hex Dump</summary>
								<pre class="segment-hex">%s</pre>
							</details>`,
						template.HTMLEscapeString(seg.DataHex)))
				}
			} else if seg.DataPreview != "" {
				// Text data - show preview with expandable full content
				sb.WriteString(fmt.Sprintf(`
							<details class="text-content-toggle">
								<summary class="text-preview">%s</summary>
								<pre class="segment-text-full">%s</pre>
							</details>`,
					template.HTMLEscapeString(truncatePreview(seg.DataPreview, 80)),
					template.HTMLEscapeString(seg.DataFull)))

				if seg.ShowHexToggle && seg.DataHex != "" {
					sb.WriteString(fmt.Sprintf(`
							<details class="hex-toggle">
								<summary class="hex-toggle-btn">🔍 Show Hex Dump</summary>
								<pre class="segment-hex">%s</pre>
							</details>`,
						template.HTMLEscapeString(seg.DataHex)))
				}
			}

			// Size indicator
			sb.WriteString(fmt.Sprintf(`
							<span class="segment-size">%s</span>
						</div>
					</div>`, seg.LengthDisplay))
		}

		sb.WriteString(`
				</div>
			</div>
		</details>`)
	}

	sb.WriteString(`
		</div>
	</div>`)

	return template.HTML(sb.String())
}

// truncatePreview truncates a string for preview display
func truncatePreview(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

// EnhancedStreamSectionHTML generates enhanced HTML with smart classification and issue detection
func EnhancedStreamSectionHTML(streams []*models.StreamData) template.HTML {
	if len(streams) == 0 {
		return template.HTML(`<p class="no-data">No stream data captured.</p>`)
	}

	classifier := analyzer.NewTrafficClassifier()
	issueDetector := NewIssueDetector()
	previewGen := NewPreviewGenerator()
	timelineViz := NewTimelineVisualizer()

	var sb strings.Builder

	sb.WriteString(`<div class="enhanced-stream-section">
		<div class="stream-intro">
			<p>📡 <strong>Follow TCP/UDP Stream</strong> - Human-readable traffic analysis. 
			Click to expand. <span class="legend">🟢 Healthy | 🟡 Warning | 🔴 Critical</span></p>
		</div>
		<div class="stream-cards">`)

	for i, stream := range streams {
		if i >= 20 {
			sb.WriteString(fmt.Sprintf(`<p class="stream-truncated">... and %d more streams</p>`, len(streams)-20))
			break
		}

		// Classify the stream
		classification := classifier.ClassifyStream(stream)

		// Detect issues
		issues := issueDetector.DetectIssues(stream)
		_, healthColor := issueDetector.GetHealthStatus(issues)

		// Generate timeline
		timeline := timelineViz.GenerateHTMLTimeline(stream)

		// Build the enhanced stream card
		sb.WriteString(fmt.Sprintf(`
		<details class="stream-card %s" id="stream-%d">
			<summary class="stream-card-header">
				<div class="stream-health-indicator %s"></div>
				<div class="stream-card-title">
					<span class="stream-icon">%s</span>
					<span class="stream-endpoints">%s:%d → %s:%d</span>
				</div>
				<div class="stream-card-type">
					<span class="type-icon">%s</span>
					<span class="type-label">%s</span>
					<span class="type-desc">%s</span>
				</div>
				<div class="stream-card-stats">
					<span class="stat">⏱️ %s</span>
					<span class="stat">📦 %s</span>
					<span class="stat">🔢 %d pkts</span>
				</div>
			</summary>
			<div class="stream-card-body">`,
			healthColor, i,
			healthColor,
			classification.Icon,
			stream.SrcIP, stream.SrcPort, stream.DstIP, stream.DstPort,
			classification.Icon, classification.Category, classification.Description,
			formatStreamDuration(stream.Duration), formatStreamBytes(stream.TotalBytes), stream.PacketCount))

		// Enhanced header box
		sb.WriteString(fmt.Sprintf(`
				<div class="stream-info-box">
					<div class="info-row">
						<span class="info-label">📊 STREAM:</span>
						<span class="info-value">%s:%d → %s:%d</span>
					</div>
					<div class="info-row">
						<span class="info-label">💡 TYPE:</span>
						<span class="info-value">%s %s (%s)</span>
					</div>`,
			stream.SrcIP, stream.SrcPort, stream.DstIP, stream.DstPort,
			classification.Icon, classification.Category, classification.Description))

		if classification.SNI != "" {
			sb.WriteString(fmt.Sprintf(`
					<div class="info-row">
						<span class="info-label">🔒 SERVER:</span>
						<span class="info-value">%s</span>
					</div>`, template.HTMLEscapeString(classification.SNI)))
		}

		if len(issues) > 0 {
			issueTexts := make([]string, 0)
			for _, issue := range issues {
				if len(issueTexts) < 3 {
					issueTexts = append(issueTexts, issue.Icon+" "+issue.Description)
				}
			}
			sb.WriteString(fmt.Sprintf(`
					<div class="info-row issues">
						<span class="info-label">⚠️ ISSUES:</span>
						<span class="info-value">%s</span>
					</div>`, strings.Join(issueTexts, ", ")))
		}

		sb.WriteString(`
				</div>`)

		// Action buttons
		sb.WriteString(fmt.Sprintf(`
				<div class="stream-actions">
					<button class="btn-action" onclick="copyToClipboard('%s')">📋 Copy Wireshark Filter</button>
					<button class="btn-action" onclick="toggleTimeline(this)">📈 View Timeline</button>
				</div>`,
			template.JSEscapeString(generateWiresharkFilter(stream))))

		// Timeline (hidden by default)
		if timeline != "" {
			sb.WriteString(fmt.Sprintf(`
				<div class="stream-timeline-container" style="display:none;">
					%s
				</div>`, timeline))
		}

		// Conversation segments with smart previews
		sb.WriteString(`
				<div class="stream-conversation">`)

		for j, seg := range stream.Segments {
			if j >= 30 {
				sb.WriteString(fmt.Sprintf(`<div class="segment-truncated">... %d more segments</div>`, len(stream.Segments)-30))
				break
			}

			// Generate smart preview
			preview := previewGen.SmartPayloadPreview(seg.Data, stream.Application, seg.Direction, classification.SNI)

			dirClass := "client-to-server"
			dirArrow := "→"
			dirLabel := "Client → Server"
			if seg.Direction == "server_to_client" {
				dirClass = "server-to-client"
				dirArrow = "←"
				dirLabel = "Server → Client"
			}

			anomalyClass := ""
			anomalyBadge := ""
			if seg.IsRetransmit {
				anomalyClass = " anomaly"
				anomalyBadge = `<span class="anomaly-badge">🔄 RETRY</span>`
			} else if seg.HasReset {
				anomalyClass = " anomaly critical"
				anomalyBadge = `<span class="anomaly-badge critical">💥 RESET</span>`
			} else if seg.GapFromPrev > 5.0 {
				anomalyClass = " anomaly"
				anomalyBadge = fmt.Sprintf(`<span class="anomaly-badge">⏱️ GAP+%.1fs</span>`, seg.GapFromPrev)
			}

			relTime := seg.Timestamp.Sub(stream.FirstSeen).Seconds()

			sb.WriteString(fmt.Sprintf(`
					<div class="conv-segment %s%s">
						<div class="seg-meta">
							<span class="seg-time">%s</span>
							<span class="seg-rel">+%.3fs</span>
						</div>
						<div class="seg-dir %s">
							<span class="dir-arrow">%s</span>
							<span class="dir-label">%s</span>
						</div>
						<div class="seg-content">
							%s
							<div class="seg-preview">%s</div>
							<span class="seg-size">%s</span>
						</div>
					</div>`,
				dirClass, anomalyClass,
				seg.Timestamp.Format("15:04:05.000"), relTime,
				dirClass, dirArrow, dirLabel,
				anomalyBadge,
				template.HTMLEscapeString(preview),
				formatStreamBytes(uint64(seg.Length))))
		}

		sb.WriteString(`
				</div>
			</div>
		</details>`)
	}

	sb.WriteString(`
		</div>
	</div>`)

	return template.HTML(sb.String())
}

// Helper functions for enhanced stream display
func formatStreamDuration(seconds float64) string {
	if seconds < 0.001 {
		return "<1ms"
	}
	if seconds < 1 {
		return fmt.Sprintf("%.0fms", seconds*1000)
	}
	if seconds < 60 {
		return fmt.Sprintf("%.2fs", seconds)
	}
	return fmt.Sprintf("%.1fm", seconds/60)
}

func formatStreamBytes(bytes uint64) string {
	if bytes < 1024 {
		return fmt.Sprintf("%d B", bytes)
	}
	if bytes < 1024*1024 {
		return fmt.Sprintf("%.1f KB", float64(bytes)/1024)
	}
	return fmt.Sprintf("%.1f MB", float64(bytes)/(1024*1024))
}

func generateWiresharkFilter(stream *models.StreamData) string {
	if stream.Protocol == "TCP" {
		return fmt.Sprintf("(ip.addr == %s && ip.addr == %s && tcp.port == %d && tcp.port == %d)",
			stream.SrcIP, stream.DstIP, stream.SrcPort, stream.DstPort)
	}
	return fmt.Sprintf("(ip.addr == %s && ip.addr == %s && udp.port == %d && udp.port == %d)",
		stream.SrcIP, stream.DstIP, stream.SrcPort, stream.DstPort)
}

// GetEnhancedStreamCSS returns CSS for the enhanced stream display
func GetEnhancedStreamCSS() string {
	return `
/* Enhanced Stream Cards */
.enhanced-stream-section {
    margin: 20px 0;
}

.stream-cards {
    display: flex;
    flex-direction: column;
    gap: 12px;
}

.stream-card {
    border: 1px solid #e2e8f0;
    border-radius: 12px;
    overflow: hidden;
    background: #fff;
    transition: all 0.2s;
}

.stream-card[open] {
    box-shadow: 0 4px 12px rgba(0,0,0,0.1);
}

.stream-card.green {
    border-left: 4px solid #22c55e;
}

.stream-card.yellow {
    border-left: 4px solid #eab308;
}

.stream-card.red {
    border-left: 4px solid #ef4444;
}

.stream-card-header {
    display: grid;
    grid-template-columns: 8px 1fr auto auto;
    gap: 12px;
    align-items: center;
    padding: 12px 16px;
    cursor: pointer;
    background: #f8fafc;
}

.stream-card-header:hover {
    background: #f1f5f9;
}

.stream-health-indicator {
    width: 8px;
    height: 8px;
    border-radius: 50%;
}

.stream-health-indicator.green { background: #22c55e; }
.stream-health-indicator.yellow { background: #eab308; }
.stream-health-indicator.red { background: #ef4444; }

.stream-card-title {
    display: flex;
    align-items: center;
    gap: 8px;
    font-family: monospace;
    font-size: 0.9em;
}

.stream-card-type {
    display: flex;
    align-items: center;
    gap: 6px;
    padding: 4px 12px;
    background: #e0f2fe;
    border-radius: 20px;
    font-size: 0.85em;
}

.stream-card-stats {
    display: flex;
    gap: 12px;
    font-size: 0.85em;
    color: #64748b;
}

.stream-card-body {
    padding: 16px;
    border-top: 1px solid #e2e8f0;
}

.stream-info-box {
    background: linear-gradient(135deg, #1e293b 0%, #334155 100%);
    color: white;
    padding: 16px;
    border-radius: 8px;
    margin-bottom: 16px;
    font-family: monospace;
    font-size: 0.9em;
}

.info-row {
    display: flex;
    gap: 12px;
    padding: 4px 0;
}

.info-label {
    color: #94a3b8;
    min-width: 100px;
}

.info-row.issues .info-value {
    color: #fbbf24;
}

.stream-actions {
    display: flex;
    gap: 8px;
    margin-bottom: 16px;
}

.btn-action {
    padding: 8px 16px;
    border: 1px solid #e2e8f0;
    border-radius: 6px;
    background: #fff;
    cursor: pointer;
    font-size: 0.85em;
    transition: all 0.2s;
}

.btn-action:hover {
    background: #f1f5f9;
    border-color: #cbd5e1;
}

/* Conversation segments */
.conv-segment {
    display: grid;
    grid-template-columns: 90px 100px 1fr;
    gap: 12px;
    padding: 10px;
    margin-bottom: 8px;
    border-radius: 6px;
    font-size: 0.85em;
}

.conv-segment.client-to-server {
    background: linear-gradient(90deg, #dbeafe 0%, #f8fafc 100%);
    border-left: 3px solid #2563eb;
}

.conv-segment.server-to-client {
    background: linear-gradient(90deg, #dcfce7 0%, #f8fafc 100%);
    border-left: 3px solid #16a34a;
}

.conv-segment.anomaly {
    background: linear-gradient(90deg, #fef3c7 0%, #fffbeb 100%) !important;
    border-left-color: #f59e0b !important;
}

.conv-segment.anomaly.critical {
    background: linear-gradient(90deg, #fee2e2 0%, #fef2f2 100%) !important;
    border-left-color: #ef4444 !important;
}

.seg-meta {
    display: flex;
    flex-direction: column;
    font-size: 0.9em;
}

.seg-time { color: #64748b; }
.seg-rel { color: #94a3b8; font-size: 0.9em; }

.seg-dir {
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    padding: 6px;
    border-radius: 4px;
    color: white;
    font-size: 0.8em;
}

.seg-dir.client-to-server { background: #2563eb; }
.seg-dir.server-to-client { background: #16a34a; }

.dir-arrow { font-size: 1.2em; font-weight: bold; }
.dir-label { font-size: 0.7em; white-space: nowrap; }

.seg-content {
    display: flex;
    flex-direction: column;
    gap: 4px;
}

.seg-preview {
    background: #fff;
    padding: 8px;
    border-radius: 4px;
    border: 1px solid #e2e8f0;
    font-family: monospace;
    word-break: break-all;
}

.seg-size {
    align-self: flex-start;
    padding: 2px 8px;
    background: #e2e8f0;
    border-radius: 4px;
    font-size: 0.8em;
    color: #64748b;
}

.anomaly-badge {
    display: inline-block;
    padding: 2px 8px;
    background: #fef3c7;
    border: 1px solid #f59e0b;
    border-radius: 4px;
    font-size: 0.8em;
    color: #92400e;
    margin-bottom: 4px;
}

.anomaly-badge.critical {
    background: #fee2e2;
    border-color: #ef4444;
    color: #991b1b;
}
`
}

// ActionableStreamSectionHTML generates the full actionable stream analysis section
func ActionableStreamSectionHTML(streams []*models.StreamData) template.HTML {
	if len(streams) == 0 {
		return template.HTML(`<p class="no-data">No stream data captured.</p>`)
	}

	generator := NewActionableStreamGenerator()
	wsGuideGen := NewWiresharkGuideGenerator()
	filterBuilder := NewFilterBuilder()

	var sb strings.Builder

	sb.WriteString(`<div class="actionable-stream-section">
		<div class="section-intro">
			<h3>📡 Actionable Stream Analysis</h3>
			<p>Human-readable traffic analysis with investigation guides and remediation plans. 
			<span class="legend">🟢 Healthy | 🟡 Degraded | 🔴 Critical</span></p>
		</div>`)

	// Add Wireshark quick reference
	sb.WriteString(GetWiresharkQuickReference())

	sb.WriteString(`<div class="stream-cards">`)

	for i, stream := range streams {
		if i >= 15 { // Limit to 15 streams for performance
			sb.WriteString(fmt.Sprintf(`<p class="stream-truncated">... and %d more streams (showing top 15 by importance)</p>`, len(streams)-15))
			break
		}

		// Generate actionable analysis
		actionable := generator.GenerateActionableStream(stream)

		// Generate Wireshark guide if there's an issue
		var wsGuide *WiresharkGuide
		if actionable.PrimaryIssue != nil {
			wsGuide = wsGuideGen.GenerateGuide(stream, actionable.PrimaryIssue)
		}

		// Generate smart filters
		var classification *analyzer.TrafficClassification
		if actionable.TrafficType.Category != "" {
			classification = &actionable.TrafficType
		}
		filters := filterBuilder.BuildSmartFilters(stream, classification, actionable.PrimaryIssue)

		// Build the actionable card
		sb.WriteString(fmt.Sprintf(`
		<details class="actionable-stream-card %s" id="stream-%d">
			<summary class="card-summary">
				<div class="health-dot %s"></div>
				<div class="card-title">
					<span class="traffic-icon">%s</span>
					<span class="traffic-category">%s</span>
					<span class="traffic-desc">%s</span>
				</div>
				<div class="card-endpoints">%s:%d ↔ %s:%d</div>
				<div class="card-stats">
					<span>⏱️ %s</span>
					<span>📦 %s</span>
					<span>🔢 %d pkts</span>
				</div>
				<div class="health-badge %s">%s %s</div>
			</summary>
			<div class="card-body">`,
			actionable.HealthColor, i,
			actionable.HealthColor,
			actionable.TrafficType.Icon, actionable.TrafficType.Category, actionable.TrafficType.Description,
			stream.SrcIP, stream.SrcPort, stream.DstIP, stream.DstPort,
			formatStreamDuration(stream.Duration), formatStreamBytes(stream.TotalBytes), stream.PacketCount,
			actionable.HealthColor, actionable.HealthIcon, actionable.Health))

		// Info box header
		sb.WriteString(fmt.Sprintf(`
				<div class="info-box">
					<div class="info-row"><span class="label">📊 STREAM:</span> %s:%d → %s:%d (%s)</div>
					<div class="info-row"><span class="label">💡 TYPE:</span> %s %s - %s</div>`,
			stream.SrcIP, stream.SrcPort, stream.DstIP, stream.DstPort, stream.Protocol,
			actionable.TrafficType.Icon, actionable.TrafficType.Category, actionable.TrafficType.Description))

		if actionable.TrafficType.SNI != "" {
			sb.WriteString(fmt.Sprintf(`<div class="info-row"><span class="label">🔒 SERVER:</span> %s</div>`,
				template.HTMLEscapeString(actionable.TrafficType.SNI)))
		}
		sb.WriteString(`</div>`)

		// Problem section (if issues detected)
		if actionable.PrimaryIssue != nil {
			sb.WriteString(fmt.Sprintf(`
				<div class="problem-section">
					<div class="problem-header">%s PRIMARY ISSUE: %s</div>
					<div class="problem-details">
						<div class="detail-group">
							<strong>🔍 Technical Details:</strong>
							<ul>`, actionable.PrimaryIssue.Icon, actionable.PrimaryIssue.Title))

			for _, detail := range actionable.TechnicalDetails {
				sb.WriteString(fmt.Sprintf(`<li>%s</li>`, template.HTMLEscapeString(detail)))
			}
			sb.WriteString(`</ul></div>`)

			sb.WriteString(fmt.Sprintf(`
						<div class="detail-group">
							<strong>📍 Business Impact:</strong> %s
						</div>
						<div class="detail-group">
							<strong>🔍 Likely Root Cause:</strong> %s
						</div>
					</div>
				</div>`, template.HTMLEscapeString(actionable.BusinessImpact),
				template.HTMLEscapeString(actionable.RootCause)))
		}

		// Wireshark investigation guide
		if wsGuide != nil {
			sb.WriteString(`
				<div class="investigation-section">
					<div class="section-header">🎯 WIRESHARK INVESTIGATION GUIDE</div>`)

			// Filters
			sb.WriteString(`<div class="filter-grid">`)
			sb.WriteString(fmt.Sprintf(`
				<div class="filter-card">
					<div class="filter-label">📋 Basic Filter</div>
					<code class="filter-code" onclick="copyToClipboard('%s')">%s</code>
					<button class="copy-btn" onclick="copyToClipboard('%s')">Copy</button>
				</div>`,
				template.JSEscapeString(filters.Basic.Filter),
				template.HTMLEscapeString(filters.Basic.Filter),
				template.JSEscapeString(filters.Basic.Filter)))

			sb.WriteString(fmt.Sprintf(`
				<div class="filter-card">
					<div class="filter-label">🔍 Problem Focus</div>
					<code class="filter-code" onclick="copyToClipboard('%s')">%s</code>
				</div>`,
				template.JSEscapeString(filters.Exclusions.Filter),
				template.HTMLEscapeString(filters.Exclusions.Filter)))
			sb.WriteString(`</div>`)

			// Analysis steps
			sb.WriteString(`<div class="analysis-steps">`)
			for _, step := range wsGuide.AnalysisSteps {
				resultClass := "pending"
				if strings.HasPrefix(step.YourResult, "✓") {
					resultClass = "good"
				} else if strings.HasPrefix(step.YourResult, "⚠️") {
					resultClass = "bad"
				}

				sb.WriteString(fmt.Sprintf(`
					<div class="analysis-step">
						<div class="step-num">%d</div>
						<div class="step-content">
							<div class="step-title">%s</div>
							<code class="step-filter">%s</code>
							<div class="step-indicators">
								<span class="good">✓ %s</span>
								<span class="bad">✗ %s</span>
							</div>
							<div class="step-result %s">%s</div>
						</div>
					</div>`,
					step.Order, step.Title,
					template.HTMLEscapeString(step.Filter),
					step.GoodSign, step.BadSign,
					resultClass, step.YourResult))
			}
			sb.WriteString(`</div></div>`)
		}

		// Remediation section
		if actionable.PrimaryIssue != nil {
			sb.WriteString(`
				<div class="remediation-section">
					<div class="section-header">🔧 REMEDIATION PLAN</div>
					<div class="remediation-list">`)

			sb.WriteString(fmt.Sprintf(`
						<div class="remediation-item immediate">
							<input type="checkbox" id="rem-imm-%d">
							<label for="rem-imm-%d">
								<strong>IMMEDIATE (Now):</strong> %s
							</label>
						</div>`, i, i, template.HTMLEscapeString(actionable.Remediation.Immediate.Action)))

			sb.WriteString(fmt.Sprintf(`
						<div class="remediation-item short-term">
							<input type="checkbox" id="rem-short-%d">
							<label for="rem-short-%d">
								<strong>SHORT-TERM (Today):</strong> %s
							</label>
						</div>`, i, i, template.HTMLEscapeString(actionable.Remediation.ShortTerm.Action)))

			sb.WriteString(fmt.Sprintf(`
						<div class="remediation-item long-term">
							<input type="checkbox" id="rem-long-%d">
							<label for="rem-long-%d">
								<strong>LONG-TERM (This Week):</strong> %s
							</label>
						</div>`, i, i, template.HTMLEscapeString(actionable.Remediation.LongTerm.Action)))

			if len(actionable.Remediation.Commands) > 0 {
				sb.WriteString(`<div class="remediation-commands"><strong>Commands:</strong><ul>`)
				for _, cmd := range actionable.Remediation.Commands {
					sb.WriteString(fmt.Sprintf(`<li><code>%s</code></li>`, template.HTMLEscapeString(cmd)))
				}
				sb.WriteString(`</ul></div>`)
			}
			sb.WriteString(`</div></div>`)
		}

		// Action buttons
		sb.WriteString(fmt.Sprintf(`
				<div class="action-buttons">
					<button class="action-btn primary" onclick="copyToClipboard('%s')">📋 Copy Wireshark Filter</button>
					<button class="action-btn" onclick="toggleTimeline(this)">📈 View Timeline</button>
					<button class="action-btn" onclick="exportStream(%d)">💾 Export PCAP</button>
				</div>`,
			template.JSEscapeString(filters.Basic.Filter), i))

		sb.WriteString(`
			</div>
		</details>`)
	}

	sb.WriteString(`</div></div>`)

	return template.HTML(sb.String())
}

// GetActionableStreamSectionCSS returns all CSS for actionable stream section
func GetActionableStreamSectionCSS() string {
	return GetActionableStreamCSS() + GetWiresharkGuideCSS() + GetWiresharkReferenceCSS() + GetFilterSetCSS() + `
/* Actionable Stream Section - Dark Mode Compatible */
.actionable-stream-section {
    margin: 20px 0;
}

.section-intro {
    margin-bottom: 20px;
}

.section-intro h3 {
    margin: 0 0 8px 0;
    color: var(--color-text-primary);
}

.section-intro .legend {
    font-size: 0.9em;
    color: var(--color-text-muted);
}

.actionable-stream-card {
    border: 1px solid var(--color-border);
    border-radius: 12px;
    margin-bottom: 16px;
    overflow: hidden;
    background: var(--color-card);
}

.actionable-stream-card[open] {
    box-shadow: var(--shadow-md);
}

.actionable-stream-card.green { border-left: 5px solid #22c55e; }
.actionable-stream-card.yellow { border-left: 5px solid #eab308; }
.actionable-stream-card.red { border-left: 5px solid #ef4444; }

.card-summary {
    display: grid;
    grid-template-columns: 12px 1fr auto auto auto;
    gap: 12px;
    align-items: center;
    padding: 14px 18px;
    cursor: pointer;
    background: var(--color-surface);
}

.card-summary:hover { background: rgba(59, 130, 246, 0.05); }

.health-dot {
    width: 12px;
    height: 12px;
    border-radius: 50%;
}
.health-dot.green { background: #22c55e; }
.health-dot.yellow { background: #eab308; }
.health-dot.red { background: #ef4444; }

.card-title {
    display: flex;
    align-items: center;
    gap: 8px;
}

.traffic-icon { font-size: 1.3em; }
.traffic-category { font-weight: 600; color: var(--color-text-primary); }
.traffic-desc { color: var(--color-text-muted); font-size: 0.9em; }

.card-endpoints {
    font-family: 'Courier New', monospace;
    font-size: 0.85em;
    color: #22d3ee;
}

.card-stats {
    display: flex;
    gap: 12px;
    font-size: 0.85em;
    color: var(--color-text-muted);
}

.health-badge {
    padding: 4px 12px;
    border-radius: 20px;
    font-size: 0.85em;
    font-weight: 500;
}
.health-badge.green { background: rgba(34, 197, 94, 0.15); color: #4ade80; }
.health-badge.yellow { background: rgba(234, 179, 8, 0.15); color: #fbbf24; }
.health-badge.red { background: rgba(239, 68, 68, 0.15); color: #f87171; }

.card-body {
    padding: 20px;
    border-top: 1px solid var(--color-border);
}

.info-box {
    background: linear-gradient(135deg, #1e293b 0%, #334155 100%);
    color: white;
    padding: 16px;
    border-radius: 8px;
    margin-bottom: 16px;
    font-family: 'Courier New', monospace;
    font-size: 0.9em;
}

.info-row {
    padding: 4px 0;
}

.info-row .label {
    color: #94a3b8;
}

.problem-section {
    background: rgba(239, 68, 68, 0.1);
    border: 1px solid rgba(239, 68, 68, 0.3);
    border-radius: 8px;
    padding: 16px;
    margin-bottom: 16px;
}

.problem-header {
    font-weight: bold;
    color: #f87171;
    font-size: 1.05em;
    margin-bottom: 12px;
}

.problem-details {
    font-size: 0.9em;
    color: var(--color-text-secondary);
}

.detail-group {
    margin-bottom: 10px;
}

.detail-group ul {
    margin: 5px 0 0 20px;
    padding: 0;
}

.investigation-section {
    background: rgba(59, 130, 246, 0.1);
    border: 1px solid rgba(59, 130, 246, 0.3);
    border-radius: 8px;
    padding: 16px;
    margin-bottom: 16px;
}

.section-header {
    font-weight: bold;
    color: #60a5fa;
    margin-bottom: 12px;
}

.filter-grid {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 12px;
    margin-bottom: 16px;
}

.filter-card {
    background: var(--color-surface);
    padding: 12px;
    border-radius: 6px;
    border: 1px solid var(--color-border);
}

.filter-label {
    font-size: 0.85em;
    color: var(--color-text-muted);
    margin-bottom: 6px;
}

.filter-code {
    display: block;
    background: var(--color-card);
    padding: 8px;
    border-radius: 4px;
    font-size: 0.8em;
    word-break: break-all;
    cursor: pointer;
    margin-bottom: 6px;
    color: #22d3ee;
    font-family: 'Courier New', monospace;
    border: 1px solid var(--color-border);
}

.filter-code:hover {
    background: rgba(59, 130, 246, 0.1);
    border-color: rgba(59, 130, 246, 0.3);
}

.analysis-steps {
    display: flex;
    flex-direction: column;
    gap: 10px;
}

.analysis-step {
    display: flex;
    gap: 12px;
    background: var(--color-surface);
    padding: 12px;
    border-radius: 6px;
    border: 1px solid var(--color-border);
    border-left: 3px solid #3b82f6;
}

.step-num {
    width: 28px;
    height: 28px;
    background: #3b82f6;
    color: white;
    border-radius: 50%;
    display: flex;
    align-items: center;
    justify-content: center;
    font-weight: bold;
    font-size: 0.85em;
    flex-shrink: 0;
}

.step-content { flex: 1; }
.step-title { font-weight: 600; margin-bottom: 4px; color: var(--color-text-primary); }
.step-filter { font-size: 0.8em; display: block; margin-bottom: 6px; }

.step-indicators {
    display: flex;
    gap: 16px;
    font-size: 0.85em;
    margin-bottom: 6px;
}
.step-indicators .good { color: #4ade80; }
.step-indicators .bad { color: #f87171; }

.step-result {
    padding: 6px 10px;
    border-radius: 4px;
    font-size: 0.9em;
}
.step-result.good { background: rgba(34, 197, 94, 0.15); color: #4ade80; }
.step-result.bad { background: rgba(239, 68, 68, 0.15); color: #f87171; }
.step-result.pending { background: var(--color-surface); color: var(--color-text-muted); }

.remediation-section {
    background: rgba(16, 185, 129, 0.1);
    border: 1px solid rgba(16, 185, 129, 0.3);
    border-radius: 8px;
    padding: 16px;
    margin-bottom: 16px;
}

.remediation-section .section-header {
    color: #4ade80;
}

.remediation-list {
    display: flex;
    flex-direction: column;
    gap: 10px;
}

.remediation-item {
    display: flex;
    align-items: flex-start;
    gap: 10px;
    padding: 12px;
    background: var(--color-surface);
    border-radius: 6px;
    border: 1px solid var(--color-border);
    color: var(--color-text-secondary);
}

.remediation-item input[type="checkbox"] { margin-top: 3px; }

.remediation-item.immediate { border-left: 3px solid #ef4444; }
.remediation-item.short-term { border-left: 3px solid #f59e0b; }
.remediation-item.long-term { border-left: 3px solid #3b82f6; }

.remediation-commands {
    margin-top: 12px;
    padding: 12px;
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

.action-buttons {
    display: flex;
    gap: 10px;
    padding-top: 16px;
    border-top: 1px solid var(--color-border);
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

// BandwidthGraphHTML generates the HTML and JavaScript for the bandwidth time series graph
func BandwidthGraphHTML(timeSeries *models.BandwidthTimeSeries) template.HTML {
	if timeSeries == nil || len(timeSeries.Buckets) == 0 {
		return template.HTML(`<p class="no-data">No bandwidth data available.</p>`)
	}

	// Convert buckets to JSON for D3.js
	bucketsJSON, err := json.Marshal(timeSeries.Buckets)
	if err != nil {
		return template.HTML(`<p class="error">Error generating bandwidth graph data.</p>`)
	}

	var sb strings.Builder

	sb.WriteString(fmt.Sprintf(`
	<div class="bandwidth-section">
		<div class="bandwidth-summary">
			<div class="bandwidth-stat">
				<span class="stat-label">Peak Throughput</span>
				<span class="stat-value">%s/s</span>
			</div>
			<div class="bandwidth-stat">
				<span class="stat-label">Average Throughput</span>
				<span class="stat-value">%s/s</span>
			</div>
			<div class="bandwidth-stat">
				<span class="stat-label">Total Data</span>
				<span class="stat-value">%s</span>
			</div>
			<div class="bandwidth-stat">
				<span class="stat-label">Duration</span>
				<span class="stat-value">%s</span>
			</div>
		</div>
		<div id="bandwidth-chart" class="bandwidth-chart"></div>
		<div id="bandwidth-tooltip" class="bandwidth-tooltip"></div>
	</div>
	<script>
	(function() {
		const bandwidthData = %s;
		
		if (bandwidthData.length === 0) return;
		
		const container = document.getElementById('bandwidth-chart');
		const tooltip = document.getElementById('bandwidth-tooltip');
		
		const margin = {top: 20, right: 80, bottom: 50, left: 80};
		const width = container.clientWidth - margin.left - margin.right || 800;
		const height = 300 - margin.top - margin.bottom;
		
		const svg = d3.select('#bandwidth-chart')
			.append('svg')
			.attr('width', width + margin.left + margin.right)
			.attr('height', height + margin.top + margin.bottom)
			.append('g')
			.attr('transform', 'translate(' + margin.left + ',' + margin.top + ')');
		
		// Parse timestamps
		const data = bandwidthData.map(d => ({
			...d,
			date: new Date(d.timestamp_unix * 1000),
			bytesTotal: d.bytes_in + d.bytes_out
		}));
		
		// Scales
		const x = d3.scaleTime()
			.domain(d3.extent(data, d => d.date))
			.range([0, width]);
		
		const maxBytes = d3.max(data, d => Math.max(d.bytes_in, d.bytes_out));
		const y = d3.scaleLinear()
			.domain([0, maxBytes * 1.1])
			.range([height, 0]);
		
		// Area generators
		const areaIn = d3.area()
			.x(d => x(d.date))
			.y0(height)
			.y1(d => y(d.bytes_in))
			.curve(d3.curveMonotoneX);
		
		const areaOut = d3.area()
			.x(d => x(d.date))
			.y0(height)
			.y1(d => y(d.bytes_out))
			.curve(d3.curveMonotoneX);
		
		// Draw areas
		svg.append('path')
			.datum(data)
			.attr('class', 'area-in')
			.attr('fill', 'rgba(52, 152, 219, 0.5)')
			.attr('stroke', '#3498db')
			.attr('stroke-width', 2)
			.attr('d', areaIn);
		
		svg.append('path')
			.datum(data)
			.attr('class', 'area-out')
			.attr('fill', 'rgba(231, 76, 60, 0.3)')
			.attr('stroke', '#e74c3c')
			.attr('stroke-width', 2)
			.attr('d', areaOut);
		
		// Axes
		svg.append('g')
			.attr('transform', 'translate(0,' + height + ')')
			.call(d3.axisBottom(x).ticks(6).tickFormat(d3.timeFormat('%%H:%%M:%%S')))
			.selectAll('text')
			.style('text-anchor', 'end')
			.attr('dx', '-.8em')
			.attr('dy', '.15em')
			.attr('transform', 'rotate(-45)');
		
		svg.append('g')
			.call(d3.axisLeft(y).ticks(5).tickFormat(d => formatBytes(d)));
		
		// Y-axis label
		svg.append('text')
			.attr('transform', 'rotate(-90)')
			.attr('y', 0 - margin.left + 20)
			.attr('x', 0 - (height / 2))
			.attr('dy', '1em')
			.style('text-anchor', 'middle')
			.style('font-size', '12px')
			.text('Bytes per interval');
		
		// Legend
		const legend = svg.append('g')
			.attr('transform', 'translate(' + (width - 100) + ', 0)');
		
		legend.append('rect').attr('x', 0).attr('y', 0).attr('width', 15).attr('height', 15).attr('fill', '#3498db');
		legend.append('text').attr('x', 20).attr('y', 12).text('Inbound').style('font-size', '12px');
		
		legend.append('rect').attr('x', 0).attr('y', 20).attr('width', 15).attr('height', 15).attr('fill', '#e74c3c');
		legend.append('text').attr('x', 20).attr('y', 32).text('Outbound').style('font-size', '12px');
		
		// Hover interaction
		const focus = svg.append('g').style('display', 'none');
		focus.append('line').attr('class', 'focus-line').attr('y1', 0).attr('y2', height).style('stroke', '#666').style('stroke-dasharray', '3,3');
		
		svg.append('rect')
			.attr('class', 'overlay')
			.attr('width', width)
			.attr('height', height)
			.style('fill', 'none')
			.style('pointer-events', 'all')
			.on('mouseover', () => { focus.style('display', null); tooltip.style.display = 'block'; })
			.on('mouseout', () => { focus.style('display', 'none'); tooltip.style.display = 'none'; })
			.on('mousemove', function(event) {
				const bisect = d3.bisector(d => d.date).left;
				const x0 = x.invert(d3.pointer(event)[0]);
				const i = bisect(data, x0, 1);
				const d0 = data[i - 1];
				const d1 = data[i];
				const d = d1 && (x0 - d0.date > d1.date - x0) ? d1 : d0;
				
				if (d) {
					focus.attr('transform', 'translate(' + x(d.date) + ',0)');
					tooltip.innerHTML = '<strong>' + d.date.toLocaleTimeString() + '</strong><br>' +
						'📥 In: ' + formatBytes(d.bytes_in) + '<br>' +
						'📤 Out: ' + formatBytes(d.bytes_out) + '<br>' +
						'🔗 Active Flows: ' + d.active_flows + '<br>' +
						'📊 Top Protocol: ' + (d.top_protocol || 'N/A');
					tooltip.style.left = (event.pageX + 15) + 'px';
					tooltip.style.top = (event.pageY - 30) + 'px';
				}
			});
		
		function formatBytes(bytes) {
			if (bytes < 1024) return bytes + ' B';
			if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
			if (bytes < 1024 * 1024 * 1024) return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
			return (bytes / (1024 * 1024 * 1024)).toFixed(1) + ' GB';
		}
	})();
	</script>`,
		formatBytesGo(timeSeries.PeakBytesPerSec),
		formatBytesGo(timeSeries.AvgBytesPerSec),
		formatBytesGo(timeSeries.TotalBytes),
		formatDurationGo(timeSeries.EndTime.Sub(timeSeries.StartTime).Seconds()),
		string(bucketsJSON)))

	return template.HTML(sb.String())
}

// PlainEnglishSummaryHTML generates the HTML for the plain English summary section
func PlainEnglishSummaryHTML(summary *models.PlainEnglishSummary) template.HTML {
	if summary == nil {
		return template.HTML("")
	}

	var sb strings.Builder

	sb.WriteString(fmt.Sprintf(`
	<div class="plain-english-summary %s">
		<div class="summary-header">
			<span class="health-icon">%s</span>
			<span class="health-status">Network Status: <strong>%s</strong></span>
		</div>`,
		summary.HealthColor, summary.HealthIcon, summary.OverallHealth))

	// Key findings
	if len(summary.KeyFindings) > 0 {
		sb.WriteString(`<div class="summary-section"><h4>📋 Key Findings</h4><ul>`)
		for _, finding := range summary.KeyFindings {
			sb.WriteString(fmt.Sprintf(`<li>%s</li>`, template.HTMLEscapeString(finding)))
		}
		sb.WriteString(`</ul></div>`)
	}

	// Security alerts
	if len(summary.SecurityAlerts) > 0 {
		sb.WriteString(`<div class="summary-section security-alerts"><h4>🛡️ Security Alerts</h4><ul>`)
		for _, alert := range summary.SecurityAlerts {
			sb.WriteString(fmt.Sprintf(`<li>%s</li>`, template.HTMLEscapeString(alert)))
		}
		sb.WriteString(`</ul></div>`)
	}

	// Performance issues
	if len(summary.PerformanceIssues) > 0 {
		sb.WriteString(`<div class="summary-section performance-issues"><h4>⚡ Performance Issues</h4><ul>`)
		for _, issue := range summary.PerformanceIssues {
			sb.WriteString(fmt.Sprintf(`<li>%s</li>`, template.HTMLEscapeString(issue)))
		}
		sb.WriteString(`</ul></div>`)
	}

	// Traffic gaps
	if len(summary.TrafficGaps) > 0 {
		sb.WriteString(`<div class="summary-section traffic-gaps"><h4>📉 Traffic Gaps Detected</h4><ul>`)
		for _, gap := range summary.TrafficGaps {
			sb.WriteString(fmt.Sprintf(`<li>%s</li>`, template.HTMLEscapeString(gap)))
		}
		sb.WriteString(`</ul></div>`)
	}

	// Quick actions
	if len(summary.QuickActions) > 0 {
		sb.WriteString(`<div class="summary-section quick-actions"><h4>🎯 Recommended Next Steps</h4><ol>`)
		for _, action := range summary.QuickActions {
			sb.WriteString(fmt.Sprintf(`<li>%s</li>`, template.HTMLEscapeString(action)))
		}
		sb.WriteString(`</ol></div>`)
	}

	sb.WriteString(`</div>`)

	return template.HTML(sb.String())
}

// TrafficGapsHTML generates HTML for traffic gaps section
func TrafficGapsHTML(gaps []models.TrafficGapInfo) template.HTML {
	if len(gaps) == 0 {
		return template.HTML(`<p class="no-gaps">✅ No significant traffic gaps detected.</p>`)
	}

	var sb strings.Builder
	sb.WriteString(`<div class="traffic-gaps-list">`)

	for _, gap := range gaps {
		severity := "warning"
		icon := "🟡"
		if gap.DurationSec > 10 {
			severity = "critical"
			icon = "🔴"
		}

		sb.WriteString(fmt.Sprintf(`
		<div class="traffic-gap %s">
			<span class="gap-icon">%s</span>
			<span class="gap-duration">%.1fs gap</span>
			<span class="gap-time">%s</span>
		</div>`,
			severity, icon, gap.DurationSec, gap.Description))
	}

	sb.WriteString(`</div>`)
	return template.HTML(sb.String())
}

// Helper functions
func formatBytesGo(bytes uint64) string {
	if bytes < 1024 {
		return fmt.Sprintf("%d B", bytes)
	}
	if bytes < 1024*1024 {
		return fmt.Sprintf("%.1f KB", float64(bytes)/1024)
	}
	if bytes < 1024*1024*1024 {
		return fmt.Sprintf("%.1f MB", float64(bytes)/(1024*1024))
	}
	return fmt.Sprintf("%.1f GB", float64(bytes)/(1024*1024*1024))
}

func formatDurationGo(seconds float64) string {
	if seconds < 1 {
		return fmt.Sprintf("%.0fms", seconds*1000)
	}
	if seconds < 60 {
		return fmt.Sprintf("%.1fs", seconds)
	}
	if seconds < 3600 {
		return fmt.Sprintf("%.1fm", seconds/60)
	}
	return fmt.Sprintf("%.1fh", seconds/3600)
}
