package output

import (
	"fmt"
	"os"
	"strings"

	"github.com/gocisse/sdwan-triage/pkg/detector"
	"github.com/gocisse/sdwan-triage/pkg/models"
)

// PrintHandshakeAnalysis prints TCP handshake analysis to console
func PrintHandshakeAnalysis(report *models.TriageReport, showAll bool, failedOnly bool) {
	if len(report.TCPHandshakeFlows) == 0 {
		return
	}

	// Check if terminal supports colors
	useColors := isTerminalColorSupported()
	formatter := NewHandshakeFormatter(useColors)

	// Print header
	fmt.Println()
	fmt.Println(strings.Repeat("═", 80))
	fmt.Println(formatter.formatBold("TCP HANDSHAKE ANALYSIS"))
	fmt.Println(strings.Repeat("═", 80))
	fmt.Println()

	// Print color legend
	fmt.Println(formatter.FormatColorLegend())

	// Get statistics
	stats := detector.GetHandshakeStatistics(report.TCPHandshakeFlows)

	// Print summary
	fmt.Println(formatter.FormatHandshakeSummary(
		stats.Total,
		stats.Successful,
		stats.Failed,
		stats.Incomplete,
		stats.SuccessRate,
		stats.AverageHandshakeTime,
	))
	fmt.Println()

	// Print failure pattern if there are failures
	if stats.Failed > 0 {
		pattern := detector.GetFailurePattern(report.TCPHandshakeFlows)
		fmt.Println(formatter.formatBold("Pattern Analysis:"))
		fmt.Println(pattern)
		fmt.Println()
	}

	// Print flows based on mode
	if failedOnly {
		// Show only failed handshakes
		fmt.Println(formatter.FormatFailedHandshakesOnly(report.TCPHandshakeFlows))

		// Print troubleshooting tips
		tips := formatter.FormatTroubleshootingTips(report.TCPHandshakeFlows)
		if tips != "" {
			fmt.Println(tips)
		}
	} else if showAll {
		// Show all handshakes in table format
		fmt.Println(formatter.FormatHandshakeTable(report.TCPHandshakeFlows, 50))

		// Print troubleshooting tips if there are failures
		if stats.Failed > 0 {
			tips := formatter.FormatTroubleshootingTips(report.TCPHandshakeFlows)
			if tips != "" {
				fmt.Println(tips)
			}
		}
	} else {
		// Default: Show summary with failed handshakes
		if stats.Failed > 0 {
			fmt.Println(formatter.FormatFailedHandshakesOnly(report.TCPHandshakeFlows))

			// Print troubleshooting tips
			tips := formatter.FormatTroubleshootingTips(report.TCPHandshakeFlows)
			if tips != "" {
				fmt.Println(tips)
			}
		} else {
			fmt.Println(formatter.formatStep("✓ All TCP handshakes completed successfully!", ColorGreen, 0))
			fmt.Println()

			// Show top 5 successful handshakes
			if stats.Successful > 0 {
				fmt.Println(formatter.formatBold("Sample Successful Handshakes (Top 5):"))
				fmt.Println(strings.Repeat("─", 80))
				fmt.Println()

				count := 0
				for _, flow := range report.TCPHandshakeFlows {
					if flow.State == "Handshake Complete" && count < 5 {
						fmt.Println(formatter.FormatHandshakeFlowCompact(flow))
						count++
					}
				}
				fmt.Println()
			}
		}
	}

	fmt.Println(strings.Repeat("═", 80))
	fmt.Println()
}

// PrintHandshakeSummaryBrief prints a brief handshake summary (for main output)
func PrintHandshakeSummaryBrief(report *models.TriageReport) {
	if len(report.TCPHandshakeFlows) == 0 {
		return
	}

	useColors := isTerminalColorSupported()
	stats := detector.GetHandshakeStatistics(report.TCPHandshakeFlows)

	if stats.Failed > 0 {
		if useColors {
			fmt.Printf("  %sTCP Handshakes:%s %d total, %s%d failed%s (%.1f%% success rate)\n",
				ColorBold, ColorReset,
				stats.Total,
				ColorRed, stats.Failed, ColorReset,
				stats.SuccessRate)
		} else {
			fmt.Printf("  TCP Handshakes: %d total, %d failed (%.1f%% success rate)\n",
				stats.Total, stats.Failed, stats.SuccessRate)
		}
	} else {
		if useColors {
			fmt.Printf("  %sTCP Handshakes:%s %d total, %s%d successful%s (100%% success rate)\n",
				ColorBold, ColorReset,
				stats.Total,
				ColorGreen, stats.Successful, ColorReset)
		} else {
			fmt.Printf("  TCP Handshakes: %d total, %d successful (100%% success rate)\n",
				stats.Total, stats.Successful)
		}
	}

	if stats.AverageHandshakeTime > 0 {
		fmt.Printf("  Average Handshake Time: %.2f ms\n", stats.AverageHandshakeTime)
	}
}

// isTerminalColorSupported checks if the terminal supports ANSI colors
func isTerminalColorSupported() bool {
	// Check if stdout is a terminal
	if fileInfo, _ := os.Stdout.Stat(); (fileInfo.Mode() & os.ModeCharDevice) != 0 {
		// Check TERM environment variable
		term := os.Getenv("TERM")
		if term == "" {
			return false
		}
		// Most modern terminals support colors
		if strings.Contains(term, "color") || strings.Contains(term, "xterm") ||
			strings.Contains(term, "screen") || strings.Contains(term, "tmux") ||
			term == "linux" || term == "cygwin" {
			return true
		}
	}
	return false
}
