package output

import (
	"fmt"
	"strings"

	"github.com/gocisse/sdwan-triage/pkg/models"
)

// ANSI color codes for terminal output
const (
	ColorReset  = "\033[0m"
	ColorRed    = "\033[31m"
	ColorGreen  = "\033[32m"
	ColorYellow = "\033[33m"
	ColorBlue   = "\033[34m"
	ColorOrange = "\033[38;5;208m"
	ColorBold   = "\033[1m"
	ColorDim    = "\033[2m"
)

// HandshakeFormatter formats TCP handshake flows with color coding
type HandshakeFormatter struct {
	useColors bool
}

// NewHandshakeFormatter creates a new handshake formatter
func NewHandshakeFormatter(useColors bool) *HandshakeFormatter {
	return &HandshakeFormatter{
		useColors: useColors,
	}
}

// FormatHandshakeFlow formats a single handshake flow with color coding
func (f *HandshakeFormatter) FormatHandshakeFlow(flow models.TCPHandshakeFlow) string {
	var sb strings.Builder

	// Format the flow identifier
	flowID := fmt.Sprintf("%s:%d → %s:%d", flow.SrcIP, flow.SrcPort, flow.DstIP, flow.DstPort)
	sb.WriteString(flowID)
	sb.WriteString("\n")

	// Format the handshake steps based on state
	switch flow.State {
	case "SYN":
		sb.WriteString(f.formatStep("└─ SYN", ColorBlue, 1))
		sb.WriteString("\n")

	case "SYN-ACK":
		sb.WriteString(f.formatStep("└─ SYN", ColorBlue, 1))
		sb.WriteString("\n")
		sb.WriteString(f.formatStep("└─ SYN-ACK", ColorOrange, 1))
		sb.WriteString("\n")

	case "Handshake Complete":
		sb.WriteString(f.formatStep("└─ SYN", ColorBlue, 1))
		if flow.SynToSynAckMs > 0 {
			sb.WriteString(f.formatDim(fmt.Sprintf(" (%.2f ms)", flow.SynToSynAckMs)))
		}
		sb.WriteString("\n")
		sb.WriteString(f.formatStep("└─ SYN-ACK", ColorOrange, 1))
		if flow.SynAckToAckMs > 0 {
			sb.WriteString(f.formatDim(fmt.Sprintf(" (%.2f ms)", flow.SynAckToAckMs)))
		}
		sb.WriteString("\n")
		sb.WriteString(f.formatStep("  └─ Handshake Complete", ColorGreen, 2))
		if flow.TotalHandshakeMs > 0 {
			sb.WriteString(f.formatDim(fmt.Sprintf(" [Total: %.2f ms]", flow.TotalHandshakeMs)))
		}
		sb.WriteString("\n")

	case "Handshake Failed":
		sb.WriteString(f.formatStep("└─ SYN", ColorBlue, 1))
		sb.WriteString("\n")
		sb.WriteString(f.formatStep("└─ Handshake Failed", ColorRed, 1))
		sb.WriteString("\n")
		if flow.FailureReason != "" {
			sb.WriteString(f.formatStep("   Reason: "+flow.FailureReason, ColorRed, 2))
			sb.WriteString("\n")
		}
	}

	return sb.String()
}

// FormatHandshakeFlowCompact formats a flow in compact single-line format
func (f *HandshakeFormatter) FormatHandshakeFlowCompact(flow models.TCPHandshakeFlow) string {
	flowID := fmt.Sprintf("%s:%d → %s:%d", flow.SrcIP, flow.SrcPort, flow.DstIP, flow.DstPort)

	var stateStr string
	var color string

	switch flow.State {
	case "SYN":
		stateStr = "[SYN]"
		color = ColorBlue
	case "SYN-ACK":
		stateStr = "[SYN-ACK]"
		color = ColorOrange
	case "Handshake Complete":
		stateStr = "[✓ Complete]"
		color = ColorGreen
		if flow.TotalHandshakeMs > 0 {
			stateStr += fmt.Sprintf(" %.2fms", flow.TotalHandshakeMs)
		}
	case "Handshake Failed":
		stateStr = "[✗ Failed]"
		color = ColorRed
		if flow.FailureReason != "" {
			stateStr += fmt.Sprintf(" - %s", flow.FailureReason)
		}
	}

	if f.useColors {
		return fmt.Sprintf("%-45s %s%s%s", flowID, color, stateStr, ColorReset)
	}
	return fmt.Sprintf("%-45s %s", flowID, stateStr)
}

// FormatHandshakeSummary formats summary statistics
func (f *HandshakeFormatter) FormatHandshakeSummary(total, successful, failed, incomplete int, successRate, avgTime float64) string {
	var sb strings.Builder

	sb.WriteString(f.formatBold("TCP Handshake Summary"))
	sb.WriteString("\n")
	sb.WriteString(strings.Repeat("─", 50))
	sb.WriteString("\n")

	sb.WriteString(fmt.Sprintf("Total Flows:       %d\n", total))
	sb.WriteString(fmt.Sprintf("Successful:        %s%d%s (%.1f%%)\n",
		f.getColor(ColorGreen), successful, f.getColor(ColorReset), successRate))
	sb.WriteString(fmt.Sprintf("Failed:            %s%d%s\n",
		f.getColor(ColorRed), failed, f.getColor(ColorReset)))
	sb.WriteString(fmt.Sprintf("Incomplete:        %s%d%s\n",
		f.getColor(ColorYellow), incomplete, f.getColor(ColorReset)))

	if successful > 0 && avgTime > 0 {
		sb.WriteString(fmt.Sprintf("Avg Handshake Time: %.2f ms\n", avgTime))
	}

	return sb.String()
}

// FormatColorLegend formats the color legend for junior engineers
func (f *HandshakeFormatter) FormatColorLegend() string {
	if !f.useColors {
		return `
Handshake State Legend:
  [SYN]           - Client initiated connection
  [SYN-ACK]       - Server responded
  [✓ Complete]    - Handshake successful
  [✗ Failed]      - Handshake failed
`
	}

	return fmt.Sprintf(`
%sHandshake State Legend:%s
  %s[SYN]%s           - Client initiated connection
  %s[SYN-ACK]%s       - Server responded
  %s[✓ Complete]%s    - Handshake successful
  %s[✗ Failed]%s      - Handshake failed
`,
		ColorBold, ColorReset,
		ColorBlue, ColorReset,
		ColorOrange, ColorReset,
		ColorGreen, ColorReset,
		ColorRed, ColorReset,
	)
}

// FormatTroubleshootingTips formats troubleshooting tips for common failures
func (f *HandshakeFormatter) FormatTroubleshootingTips(flows []models.TCPHandshakeFlow) string {
	if len(flows) == 0 {
		return ""
	}

	// Count failure types
	synTimeouts := 0
	ackTimeouts := 0

	for _, flow := range flows {
		if strings.Contains(flow.FailureReason, "SYN-ACK timeout") {
			synTimeouts++
		} else if strings.Contains(flow.FailureReason, "ACK timeout") {
			ackTimeouts++
		}
	}

	if synTimeouts == 0 && ackTimeouts == 0 {
		return ""
	}

	var sb strings.Builder
	sb.WriteString("\n")
	sb.WriteString(f.formatBold("Troubleshooting Tips"))
	sb.WriteString("\n")
	sb.WriteString(strings.Repeat("─", 50))
	sb.WriteString("\n")

	if synTimeouts > 0 {
		sb.WriteString(f.formatStep("⚠️  SYN-ACK Timeouts Detected:", ColorYellow, 0))
		sb.WriteString("\n")
		sb.WriteString("   • Check if server is reachable (ping, traceroute)\n")
		sb.WriteString("   • Verify firewall rules allow traffic on destination port\n")
		sb.WriteString("   • Ensure service is listening on the destination port\n")
		sb.WriteString("   • Check for network congestion or packet loss\n")
		sb.WriteString("\n")
	}

	if ackTimeouts > 0 {
		sb.WriteString(f.formatStep("⚠️  ACK Timeouts Detected:", ColorYellow, 0))
		sb.WriteString("\n")
		sb.WriteString("   • Check client-side network connectivity\n")
		sb.WriteString("   • Verify no packet loss on return path\n")
		sb.WriteString("   • Inspect client firewall rules\n")
		sb.WriteString("   • Check for asymmetric routing issues\n")
		sb.WriteString("\n")
	}

	return sb.String()
}

// FormatHandshakeTable formats handshakes in a tabular format
func (f *HandshakeFormatter) FormatHandshakeTable(flows []models.TCPHandshakeFlow, maxRows int) string {
	if len(flows) == 0 {
		return "No TCP handshake flows detected.\n"
	}

	var sb strings.Builder

	// Header
	sb.WriteString(f.formatBold("TCP Handshake Flows"))
	sb.WriteString("\n")
	sb.WriteString(strings.Repeat("═", 100))
	sb.WriteString("\n")

	// Column headers
	header := fmt.Sprintf("%-40s %-20s %-15s %s\n",
		"Flow", "State", "Time (ms)", "Details")
	sb.WriteString(f.formatBold(header))
	sb.WriteString(strings.Repeat("─", 100))
	sb.WriteString("\n")

	// Rows
	count := 0
	for _, flow := range flows {
		if maxRows > 0 && count >= maxRows {
			remaining := len(flows) - maxRows
			sb.WriteString(fmt.Sprintf("\n... and %d more flows\n", remaining))
			break
		}

		flowID := fmt.Sprintf("%s:%d → %s:%d", flow.SrcIP, flow.SrcPort, flow.DstIP, flow.DstPort)
		if len(flowID) > 40 {
			flowID = flowID[:37] + "..."
		}

		var stateStr string
		var color string
		var timeStr string
		var details string

		switch flow.State {
		case "Handshake Complete":
			stateStr = "✓ Complete"
			color = ColorGreen
			if flow.TotalHandshakeMs > 0 {
				timeStr = fmt.Sprintf("%.2f", flow.TotalHandshakeMs)
			}
		case "Handshake Failed":
			stateStr = "✗ Failed"
			color = ColorRed
			details = flow.FailureReason
		case "SYN":
			stateStr = "SYN"
			color = ColorBlue
		case "SYN-ACK":
			stateStr = "SYN-ACK"
			color = ColorOrange
		}

		if f.useColors {
			row := fmt.Sprintf("%-40s %s%-20s%s %-15s %s\n",
				flowID, color, stateStr, ColorReset, timeStr, details)
			sb.WriteString(row)
		} else {
			row := fmt.Sprintf("%-40s %-20s %-15s %s\n",
				flowID, stateStr, timeStr, details)
			sb.WriteString(row)
		}

		count++
	}

	sb.WriteString(strings.Repeat("═", 100))
	sb.WriteString("\n")

	return sb.String()
}

// Helper methods

func (f *HandshakeFormatter) formatStep(text, color string, indent int) string {
	indentStr := strings.Repeat("  ", indent)
	if f.useColors {
		return fmt.Sprintf("%s%s%s%s", indentStr, color, text, ColorReset)
	}
	return indentStr + text
}

func (f *HandshakeFormatter) formatBold(text string) string {
	if f.useColors {
		return fmt.Sprintf("%s%s%s", ColorBold, text, ColorReset)
	}
	return text
}

func (f *HandshakeFormatter) formatDim(text string) string {
	if f.useColors {
		return fmt.Sprintf("%s%s%s", ColorDim, text, ColorReset)
	}
	return text
}

func (f *HandshakeFormatter) getColor(color string) string {
	if f.useColors {
		return color
	}
	return ""
}

// FormatFailedHandshakesOnly formats only failed handshakes
func (f *HandshakeFormatter) FormatFailedHandshakesOnly(flows []models.TCPHandshakeFlow) string {
	var failedFlows []models.TCPHandshakeFlow
	for _, flow := range flows {
		if flow.State == "Handshake Failed" {
			failedFlows = append(failedFlows, flow)
		}
	}

	if len(failedFlows) == 0 {
		return f.formatStep("✓ No failed handshakes detected", ColorGreen, 0) + "\n"
	}

	var sb strings.Builder
	sb.WriteString(f.formatBold(fmt.Sprintf("Failed Handshakes (%d)", len(failedFlows))))
	sb.WriteString("\n")
	sb.WriteString(strings.Repeat("─", 80))
	sb.WriteString("\n\n")

	for _, flow := range failedFlows {
		sb.WriteString(f.FormatHandshakeFlow(flow))
		sb.WriteString("\n")
	}

	return sb.String()
}

// FormatSuccessfulHandshakesOnly formats only successful handshakes
func (f *HandshakeFormatter) FormatSuccessfulHandshakesOnly(flows []models.TCPHandshakeFlow) string {
	var successfulFlows []models.TCPHandshakeFlow
	for _, flow := range flows {
		if flow.State == "Handshake Complete" {
			successfulFlows = append(successfulFlows, flow)
		}
	}

	if len(successfulFlows) == 0 {
		return "No successful handshakes detected\n"
	}

	var sb strings.Builder
	sb.WriteString(f.formatBold(fmt.Sprintf("Successful Handshakes (%d)", len(successfulFlows))))
	sb.WriteString("\n")
	sb.WriteString(strings.Repeat("─", 80))
	sb.WriteString("\n\n")

	// Show first 10 in detail, rest in compact format
	for i, flow := range successfulFlows {
		if i < 10 {
			sb.WriteString(f.FormatHandshakeFlow(flow))
		} else {
			sb.WriteString(f.FormatHandshakeFlowCompact(flow))
		}
		sb.WriteString("\n")
	}

	return sb.String()
}
