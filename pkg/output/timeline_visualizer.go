package output

import (
	"fmt"
	"strings"
	"time"

	"github.com/gocisse/sdwan-triage/pkg/models"
)

// TimelineEvent represents an event on the timeline
type TimelineEvent struct {
	Timestamp   time.Time
	RelativePos float64 // 0.0 to 1.0 position on timeline
	Icon        string
	Label       string
	Severity    string // "normal", "warning", "critical"
}

// TimelineVisualizer creates ASCII timeline visualizations
type TimelineVisualizer struct{}

// NewTimelineVisualizer creates a new timeline visualizer
func NewTimelineVisualizer() *TimelineVisualizer {
	return &TimelineVisualizer{}
}

// VisualTimeline generates an ASCII timeline for a stream
func (tv *TimelineVisualizer) VisualTimeline(stream *models.StreamData, width int) string {
	if len(stream.Segments) == 0 {
		return ""
	}

	if width < 40 {
		width = 40
	}
	if width > 100 {
		width = 100
	}

	// Calculate time range
	startTime := stream.FirstSeen
	endTime := stream.LastSeen
	duration := endTime.Sub(startTime)

	if duration < time.Millisecond {
		return "" // Too short to visualize
	}

	// Calculate time per character
	timePerChar := duration / time.Duration(width)

	var sb strings.Builder

	// Header
	sb.WriteString(fmt.Sprintf("📈 Traffic Timeline (each char = %s):\n", tv.formatTimePerChar(timePerChar)))

	// Build activity map
	activity := make([]int, width)
	events := make([]TimelineEvent, 0)

	var lastTimestamp time.Time
	for i, seg := range stream.Segments {
		// Calculate position
		relTime := seg.Timestamp.Sub(startTime)
		pos := int(float64(relTime) / float64(duration) * float64(width-1))
		if pos >= width {
			pos = width - 1
		}
		if pos < 0 {
			pos = 0
		}

		// Add to activity
		activity[pos] += seg.Length

		// Check for notable events
		if i == 0 {
			// First packet
			events = append(events, TimelineEvent{
				Timestamp:   seg.Timestamp,
				RelativePos: float64(pos) / float64(width),
				Icon:        "▼",
				Label:       tv.getFirstPacketLabel(stream.Application, seg),
				Severity:    "normal",
			})
		}

		// Check for gaps
		if i > 0 && !lastTimestamp.IsZero() {
			gap := seg.Timestamp.Sub(lastTimestamp)
			if gap > 5*time.Second {
				events = append(events, TimelineEvent{
					Timestamp:   seg.Timestamp,
					RelativePos: float64(pos) / float64(width),
					Icon:        "▼",
					Label:       fmt.Sprintf("⏱️ GAP+%.1fs - possible timeout?", gap.Seconds()),
					Severity:    "warning",
				})
			}
		}

		// Check for anomalies
		if seg.HasReset {
			events = append(events, TimelineEvent{
				Timestamp:   seg.Timestamp,
				RelativePos: float64(pos) / float64(width),
				Icon:        "▼",
				Label:       "💥 Connection reset",
				Severity:    "critical",
			})
		}

		lastTimestamp = seg.Timestamp
	}

	// Generate the timeline bar
	sb.WriteString("  ")
	maxActivity := 1
	for _, a := range activity {
		if a > maxActivity {
			maxActivity = a
		}
	}

	for _, a := range activity {
		if a == 0 {
			sb.WriteString("·")
		} else {
			// Scale activity to intensity
			intensity := float64(a) / float64(maxActivity)
			if intensity < 0.2 {
				sb.WriteString("░")
			} else if intensity < 0.5 {
				sb.WriteString("▒")
			} else if intensity < 0.8 {
				sb.WriteString("▓")
			} else {
				sb.WriteString("█")
			}
		}
	}
	sb.WriteString("\n")

	// Time labels
	sb.WriteString("  ")
	sb.WriteString(startTime.Format("15:04:05"))
	padding := width - 16 // 8 chars for each timestamp
	if padding > 0 {
		sb.WriteString(strings.Repeat(" ", padding))
	}
	sb.WriteString(endTime.Format("15:04:05"))
	sb.WriteString("\n")

	// Event markers (limit to 5 most important)
	importantEvents := tv.selectImportantEvents(events, 5)
	for _, event := range importantEvents {
		pos := int(event.RelativePos * float64(width))
		if pos < 0 {
			pos = 0
		}
		if pos >= width {
			pos = width - 1
		}

		sb.WriteString("  ")
		sb.WriteString(strings.Repeat(" ", pos))
		sb.WriteString(event.Icon)
		sb.WriteString(" ")
		sb.WriteString(event.Label)
		sb.WriteString("\n")
	}

	return sb.String()
}

// formatTimePerChar formats the time per character for display
func (tv *TimelineVisualizer) formatTimePerChar(d time.Duration) string {
	if d < time.Millisecond {
		return fmt.Sprintf("%.0fµs", float64(d.Microseconds()))
	}
	if d < time.Second {
		return fmt.Sprintf("%.0fms", float64(d.Milliseconds()))
	}
	if d < time.Minute {
		return fmt.Sprintf("%.2fs", d.Seconds())
	}
	return fmt.Sprintf("%.1fm", d.Minutes())
}

// getFirstPacketLabel returns a label for the first packet
func (tv *TimelineVisualizer) getFirstPacketLabel(application string, seg models.StreamSegment) string {
	switch application {
	case "TLS", "HTTPS":
		if len(seg.Data) > 5 && seg.Data[0] == 0x16 && seg.Data[5] == 0x01 {
			return "TLS handshake starts"
		}
		return "Connection starts"
	case "HTTP":
		return "HTTP request starts"
	case "SMB":
		return "SMB session starts"
	case "DNS":
		return "DNS query"
	case "SSH":
		return "SSH connection starts"
	default:
		return "First data transfer"
	}
}

// selectImportantEvents selects the most important events to display
func (tv *TimelineVisualizer) selectImportantEvents(events []TimelineEvent, maxEvents int) []TimelineEvent {
	if len(events) <= maxEvents {
		return events
	}

	// Prioritize: critical > warning > normal
	// Also prioritize first and last events
	result := make([]TimelineEvent, 0, maxEvents)

	// Always include first event
	if len(events) > 0 {
		result = append(result, events[0])
	}

	// Add critical events
	for _, e := range events[1:] {
		if e.Severity == "critical" && len(result) < maxEvents {
			result = append(result, e)
		}
	}

	// Add warning events
	for _, e := range events[1:] {
		if e.Severity == "warning" && len(result) < maxEvents {
			// Check if not already added
			found := false
			for _, r := range result {
				if r.Timestamp == e.Timestamp {
					found = true
					break
				}
			}
			if !found {
				result = append(result, e)
			}
		}
	}

	return result
}

// GenerateHTMLTimeline generates an HTML/SVG timeline for the report
func (tv *TimelineVisualizer) GenerateHTMLTimeline(stream *models.StreamData) string {
	if len(stream.Segments) == 0 {
		return ""
	}

	startTime := stream.FirstSeen
	endTime := stream.LastSeen
	duration := endTime.Sub(startTime)

	if duration < time.Millisecond {
		return ""
	}

	var sb strings.Builder

	sb.WriteString(`<div class="stream-timeline">`)
	sb.WriteString(`<div class="timeline-header">📈 Traffic Timeline</div>`)
	sb.WriteString(`<div class="timeline-bar">`)

	// Generate timeline segments
	const segments = 50
	activity := make([]int, segments)
	maxActivity := 1

	for _, seg := range stream.Segments {
		relTime := seg.Timestamp.Sub(startTime)
		pos := int(float64(relTime) / float64(duration) * float64(segments-1))
		if pos >= segments {
			pos = segments - 1
		}
		if pos < 0 {
			pos = 0
		}
		activity[pos] += seg.Length
		if activity[pos] > maxActivity {
			maxActivity = activity[pos]
		}
	}

	for i, a := range activity {
		intensity := float64(a) / float64(maxActivity)
		var colorClass string
		if a == 0 {
			colorClass = "empty"
		} else if intensity < 0.3 {
			colorClass = "low"
		} else if intensity < 0.6 {
			colorClass = "medium"
		} else {
			colorClass = "high"
		}

		// Check for gaps at this position
		hasGap := tv.hasGapAtPosition(stream, i, segments, duration)
		if hasGap {
			colorClass = "gap"
		}

		sb.WriteString(fmt.Sprintf(`<div class="timeline-segment %s" title="Segment %d"></div>`, colorClass, i))
	}

	sb.WriteString(`</div>`)

	// Time labels
	sb.WriteString(`<div class="timeline-labels">`)
	sb.WriteString(fmt.Sprintf(`<span class="timeline-start">%s</span>`, startTime.Format("15:04:05")))
	sb.WriteString(fmt.Sprintf(`<span class="timeline-end">%s</span>`, endTime.Format("15:04:05")))
	sb.WriteString(`</div>`)

	sb.WriteString(`</div>`)

	return sb.String()
}

// hasGapAtPosition checks if there's a significant gap at a timeline position
func (tv *TimelineVisualizer) hasGapAtPosition(stream *models.StreamData, pos int, totalSegments int, duration time.Duration) bool {
	if len(stream.Segments) < 2 {
		return false
	}

	segmentDuration := duration / time.Duration(totalSegments)
	posStart := stream.FirstSeen.Add(time.Duration(pos) * segmentDuration)
	posEnd := posStart.Add(segmentDuration)

	// Check if any segment falls in this time range
	hasActivity := false
	for _, seg := range stream.Segments {
		if seg.Timestamp.After(posStart) && seg.Timestamp.Before(posEnd) {
			hasActivity = true
			break
		}
	}

	// If no activity and we're not at the edges, it might be a gap
	if !hasActivity && pos > 0 && pos < totalSegments-1 {
		// Check if there's activity before and after
		hasBefore := false
		hasAfter := false
		for _, seg := range stream.Segments {
			if seg.Timestamp.Before(posStart) {
				hasBefore = true
			}
			if seg.Timestamp.After(posEnd) {
				hasAfter = true
			}
		}
		return hasBefore && hasAfter
	}

	return false
}

// GetTimelineCSS returns CSS styles for the HTML timeline
func (tv *TimelineVisualizer) GetTimelineCSS() string {
	return `
.stream-timeline {
    margin: 15px 0;
    padding: 10px;
    background: #f8fafc;
    border-radius: 8px;
}

.timeline-header {
    font-size: 0.9em;
    color: #64748b;
    margin-bottom: 8px;
}

.timeline-bar {
    display: flex;
    height: 24px;
    border-radius: 4px;
    overflow: hidden;
    background: #e2e8f0;
}

.timeline-segment {
    flex: 1;
    min-width: 2px;
}

.timeline-segment.empty {
    background: #e2e8f0;
}

.timeline-segment.low {
    background: #93c5fd;
}

.timeline-segment.medium {
    background: #3b82f6;
}

.timeline-segment.high {
    background: #1d4ed8;
}

.timeline-segment.gap {
    background: #fbbf24;
}

.timeline-labels {
    display: flex;
    justify-content: space-between;
    margin-top: 4px;
    font-size: 0.75em;
    color: #94a3b8;
}
`
}
