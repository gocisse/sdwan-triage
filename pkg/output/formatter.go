package output

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"

	"github.com/fatih/color"
	"github.com/gocisse/sdwan-triage/pkg/models"
)

// PrintExecutiveSummary prints a high-level summary of findings
func PrintExecutiveSummary(r *models.TriageReport) {
	color.New(color.Bold, color.FgCyan).Println("═══════════════════════════════════════════════════════════════")
	color.New(color.Bold, color.FgCyan).Println("              SD-WAN NETWORK TRIAGE - EXECUTIVE SUMMARY")
	color.New(color.Bold, color.FgCyan).Println("═══════════════════════════════════════════════════════════════")

	// Calculate totals
	criticalIssues := len(r.DNSAnomalies) + len(r.ARPConflicts)
	performanceIssues := len(r.TCPRetransmissions) + len(r.FailedHandshakes) + len(r.RTTAnalysis)
	securityConcerns := len(r.SuspiciousTraffic)
	for _, cert := range r.TLSCerts {
		if cert.IsExpired || cert.IsSelfSigned {
			securityConcerns++
		}
	}

	fmt.Println()

	// Health Status
	if criticalIssues == 0 && performanceIssues == 0 && securityConcerns == 0 {
		color.Green("✓ NETWORK HEALTH: GOOD - No significant issues detected")
	} else if criticalIssues > 0 {
		color.Red("✗ NETWORK HEALTH: CRITICAL - Immediate attention required")
	} else if performanceIssues > 5 || securityConcerns > 0 {
		color.Yellow("⚠ NETWORK HEALTH: WARNING - Issues detected that need review")
	} else {
		color.Cyan("○ NETWORK HEALTH: FAIR - Minor issues detected")
	}

	fmt.Println()

	// Summary counts
	fmt.Println("FINDINGS SUMMARY:")
	fmt.Printf("  • DNS Anomalies:        %d\n", len(r.DNSAnomalies))
	fmt.Printf("  • TCP Retransmissions:  %d\n", len(r.TCPRetransmissions))
	fmt.Printf("  • Failed Handshakes:    %d\n", len(r.FailedHandshakes))
	fmt.Printf("  • ARP Conflicts:        %d\n", len(r.ARPConflicts))
	fmt.Printf("  • HTTP Errors:          %d\n", len(r.HTTPErrors))
	fmt.Printf("  • TLS Certificates:     %d\n", len(r.TLSCerts))
	fmt.Printf("  • Suspicious Traffic:   %d\n", len(r.SuspiciousTraffic))
	fmt.Printf("  • High RTT Flows:       %d\n", len(r.RTTAnalysis))
	fmt.Printf("  • Devices Detected:     %d\n", len(r.DeviceFingerprinting))

	fmt.Println()

	// Traffic summary
	fmt.Printf("TRAFFIC SUMMARY:\n")
	fmt.Printf("  • Total Bytes:          %s\n", formatBytes(r.TotalBytes))
	fmt.Printf("  • HTTP/2 Flows:         %d\n", len(r.HTTP2Flows))
	fmt.Printf("  • QUIC Flows:           %d\n", len(r.QUICFlows))

	fmt.Println()
}

// PrintDetailedReport prints detailed findings
func PrintDetailedReport(r *models.TriageReport) {
	color.New(color.Bold, color.FgCyan).Println("═══════════════════════════════════════════════════════════════")
	color.New(color.Bold, color.FgCyan).Println("                    DETAILED ANALYSIS REPORT")
	color.New(color.Bold, color.FgCyan).Println("═══════════════════════════════════════════════════════════════")
	fmt.Println()

	// DNS Anomalies
	if len(r.DNSAnomalies) > 0 {
		color.Yellow("━━━ DNS ANOMALIES ━━━")
		for i, anomaly := range r.DNSAnomalies {
			if i >= 10 {
				fmt.Printf("  ... and %d more\n", len(r.DNSAnomalies)-10)
				break
			}
			fmt.Printf("  • Query: %s -> %s (Server: %s)\n", anomaly.Query, anomaly.AnswerIP, anomaly.ServerIP)
			fmt.Printf("    Reason: %s\n", anomaly.Reason)
		}
		fmt.Println()
	}

	// TCP Retransmissions
	if len(r.TCPRetransmissions) > 0 {
		color.Yellow("━━━ TCP RETRANSMISSIONS ━━━")
		for i, flow := range r.TCPRetransmissions {
			if i >= 10 {
				fmt.Printf("  ... and %d more\n", len(r.TCPRetransmissions)-10)
				break
			}
			fmt.Printf("  • %s:%d -> %s:%d\n", flow.SrcIP, flow.SrcPort, flow.DstIP, flow.DstPort)
		}
		fmt.Println()
	}

	// ARP Conflicts
	if len(r.ARPConflicts) > 0 {
		color.Red("━━━ ARP CONFLICTS ━━━")
		for _, conflict := range r.ARPConflicts {
			fmt.Printf("  • IP %s claimed by: %s and %s\n", conflict.IP, conflict.MAC1, conflict.MAC2)
		}
		fmt.Println()
	}

	// HTTP Errors
	if len(r.HTTPErrors) > 0 {
		color.Yellow("━━━ HTTP ERRORS ━━━")
		for i, err := range r.HTTPErrors {
			if i >= 10 {
				fmt.Printf("  ... and %d more\n", len(r.HTTPErrors)-10)
				break
			}
			fmt.Printf("  • %d %s %s%s\n", err.Code, err.Method, err.Host, err.Path)
		}
		fmt.Println()
	}

	// TLS Certificates
	if len(r.TLSCerts) > 0 {
		color.Cyan("━━━ TLS CERTIFICATES ━━━")
		for i, cert := range r.TLSCerts {
			if i >= 10 {
				fmt.Printf("  ... and %d more\n", len(r.TLSCerts)-10)
				break
			}
			status := "✓"
			if cert.IsExpired {
				status = color.RedString("EXPIRED")
			} else if cert.IsSelfSigned {
				status = color.YellowString("SELF-SIGNED")
			}
			fmt.Printf("  • %s (%s) - %s\n", cert.ServerName, cert.Subject, status)
		}
		fmt.Println()
	}

	// Suspicious Traffic
	if len(r.SuspiciousTraffic) > 0 {
		color.Red("━━━ SUSPICIOUS TRAFFIC ━━━")
		for i, flow := range r.SuspiciousTraffic {
			if i >= 10 {
				fmt.Printf("  ... and %d more\n", len(r.SuspiciousTraffic)-10)
				break
			}
			fmt.Printf("  • %s:%d -> %s:%d (%s)\n", flow.SrcIP, flow.SrcPort, flow.DstIP, flow.DstPort, flow.Protocol)
			fmt.Printf("    Reason: %s\n", flow.Reason)
		}
		fmt.Println()
	}

	// Device Fingerprinting
	if len(r.DeviceFingerprinting) > 0 {
		color.Cyan("━━━ DEVICE FINGERPRINTING ━━━")
		for i, device := range r.DeviceFingerprinting {
			if i >= 10 {
				fmt.Printf("  ... and %d more\n", len(r.DeviceFingerprinting)-10)
				break
			}
			fmt.Printf("  • %s: %s (%s) - Confidence: %s\n", device.SrcIP, device.OSGuess, device.DeviceType, device.Confidence)
		}
		fmt.Println()
	}

	// Top Traffic Flows
	if len(r.TrafficAnalysis) > 0 {
		color.Cyan("━━━ TOP TRAFFIC FLOWS ━━━")
		for i, flow := range r.TrafficAnalysis {
			if i >= 5 {
				break
			}
			fmt.Printf("  • %s:%d -> %s:%d: %s (%.1f%%)\n",
				flow.SrcIP, flow.SrcPort, flow.DstIP, flow.DstPort,
				formatBytes(flow.TotalBytes), flow.Percentage)
		}
		fmt.Println()
	}
}

// ExportToCSV exports the report to a CSV file
func ExportToCSV(r *models.TriageReport, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	// DNS Anomalies
	if len(r.DNSAnomalies) > 0 {
		writer.Write([]string{"=== DNS ANOMALIES ==="})
		writer.Write([]string{"Timestamp", "Query", "Answer IP", "Server IP", "Server MAC", "Reason"})
		for _, anomaly := range r.DNSAnomalies {
			writer.Write([]string{
				fmt.Sprintf("%.6f", anomaly.Timestamp),
				anomaly.Query,
				anomaly.AnswerIP,
				anomaly.ServerIP,
				anomaly.ServerMAC,
				anomaly.Reason,
			})
		}
		writer.Write([]string{})
	}

	// TCP Retransmissions
	if len(r.TCPRetransmissions) > 0 {
		writer.Write([]string{"=== TCP RETRANSMISSIONS ==="})
		writer.Write([]string{"Source IP", "Source Port", "Dest IP", "Dest Port"})
		for _, flow := range r.TCPRetransmissions {
			writer.Write([]string{
				flow.SrcIP,
				fmt.Sprintf("%d", flow.SrcPort),
				flow.DstIP,
				fmt.Sprintf("%d", flow.DstPort),
			})
		}
		writer.Write([]string{})
	}

	// ARP Conflicts
	if len(r.ARPConflicts) > 0 {
		writer.Write([]string{"=== ARP CONFLICTS ==="})
		writer.Write([]string{"IP", "MAC 1", "MAC 2"})
		for _, conflict := range r.ARPConflicts {
			writer.Write([]string{conflict.IP, conflict.MAC1, conflict.MAC2})
		}
		writer.Write([]string{})
	}

	// HTTP Errors
	if len(r.HTTPErrors) > 0 {
		writer.Write([]string{"=== HTTP ERRORS ==="})
		writer.Write([]string{"Timestamp", "Method", "Host", "Path", "Status Code"})
		for _, err := range r.HTTPErrors {
			writer.Write([]string{
				fmt.Sprintf("%.6f", err.Timestamp),
				err.Method,
				err.Host,
				err.Path,
				fmt.Sprintf("%d", err.Code),
			})
		}
		writer.Write([]string{})
	}

	// TLS Certificates
	if len(r.TLSCerts) > 0 {
		writer.Write([]string{"=== TLS CERTIFICATES ==="})
		writer.Write([]string{"Server IP", "Server Port", "Server Name", "Subject", "Issuer", "Not Before", "Not After", "Expired", "Self-Signed"})
		for _, cert := range r.TLSCerts {
			writer.Write([]string{
				cert.ServerIP,
				fmt.Sprintf("%d", cert.ServerPort),
				cert.ServerName,
				cert.Subject,
				cert.Issuer,
				cert.NotBefore,
				cert.NotAfter,
				fmt.Sprintf("%t", cert.IsExpired),
				fmt.Sprintf("%t", cert.IsSelfSigned),
			})
		}
		writer.Write([]string{})
	}

	// Suspicious Traffic
	if len(r.SuspiciousTraffic) > 0 {
		writer.Write([]string{"=== SUSPICIOUS TRAFFIC ==="})
		writer.Write([]string{"Source IP", "Source Port", "Dest IP", "Dest Port", "Protocol", "Reason"})
		for _, flow := range r.SuspiciousTraffic {
			writer.Write([]string{
				flow.SrcIP,
				fmt.Sprintf("%d", flow.SrcPort),
				flow.DstIP,
				fmt.Sprintf("%d", flow.DstPort),
				flow.Protocol,
				flow.Reason,
			})
		}
	}

	return nil
}

// ExportToHTML exports the report to an HTML file with D3.js visualizations
func ExportToHTML(r *models.TriageReport, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	// Generate HTML with D3.js visualizations
	// GetD3HTMLTemplate includes styles inline
	html := GetD3HTMLTemplate()
	html += generateReportContent(r)
	html += GetD3ScriptsTemplate()
	html += generateD3DataInit(r)
	html += `</body></html>`

	_, err = file.WriteString(html)
	return err
}

// generateReportContent creates the main report HTML content
func generateReportContent(r *models.TriageReport) string {
	html := `<div class="container">`

	// Executive Summary Card
	html += `<div class="card">
		<div class="card-header">
			<i class="fas fa-chart-line"></i>
			<h2>Executive Summary</h2>
		</div>
		<div class="card-body">`

	criticalIssues := len(r.DNSAnomalies) + len(r.ARPConflicts)
	performanceIssues := len(r.TCPRetransmissions) + len(r.FailedHandshakes)
	securityConcerns := len(r.SuspiciousTraffic)

	if criticalIssues == 0 && performanceIssues == 0 && securityConcerns == 0 {
		html += `<div class="alert alert-success">✓ Network Health: GOOD - No significant issues detected</div>`
	} else if criticalIssues > 0 {
		html += `<div class="alert alert-danger">✗ Network Health: CRITICAL - Immediate attention required</div>`
	} else {
		html += `<div class="alert alert-warning">⚠ Network Health: WARNING - Issues detected</div>`
	}

	html += fmt.Sprintf(`
		<div class="stats-grid">
			<div class="stat-item"><span class="stat-value">%d</span><span class="stat-label">DNS Anomalies</span></div>
			<div class="stat-item"><span class="stat-value">%d</span><span class="stat-label">TCP Retransmissions</span></div>
			<div class="stat-item"><span class="stat-value">%d</span><span class="stat-label">ARP Conflicts</span></div>
			<div class="stat-item"><span class="stat-value">%d</span><span class="stat-label">Suspicious Traffic</span></div>
			<div class="stat-item"><span class="stat-value">%d</span><span class="stat-label">TLS Certificates</span></div>
			<div class="stat-item"><span class="stat-value">%s</span><span class="stat-label">Total Traffic</span></div>
		</div>
	`, len(r.DNSAnomalies), len(r.TCPRetransmissions), len(r.ARPConflicts),
		len(r.SuspiciousTraffic), len(r.TLSCerts), formatBytes(r.TotalBytes))

	html += `</div></div>`

	// Network Diagram placeholder
	html += `<div class="card">
		<div class="card-header">
			<i class="fas fa-project-diagram"></i>
			<h2>Network Topology</h2>
		</div>
		<div class="card-body">
			<div id="network-diagram" style="height: 500px;"></div>
		</div>
	</div>`

	// Timeline placeholder
	html += `<div class="card">
		<div class="card-header">
			<i class="fas fa-clock"></i>
			<h2>Event Timeline</h2>
		</div>
		<div class="card-body">
			<div id="timeline" style="height: 300px;"></div>
		</div>
	</div>`

	html += `</div>` // Close container

	return html
}

// formatBytes formats bytes into human-readable string
func formatBytes(bytes uint64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := uint64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

// generateD3DataInit creates JavaScript to initialize D3.js visualizations with actual data
func generateD3DataInit(r *models.TriageReport) string {
	// Build network nodes and links from traffic analysis
	nodes := []map[string]interface{}{}
	links := []map[string]interface{}{}
	nodeMap := make(map[string]bool)

	// Add nodes from traffic flows
	for _, flow := range r.TrafficAnalysis {
		if !nodeMap[flow.SrcIP] {
			nodeMap[flow.SrcIP] = true
			nodes = append(nodes, map[string]interface{}{
				"id":    flow.SrcIP,
				"label": flow.SrcIP,
				"group": categorizeIPForD3(flow.SrcIP),
			})
		}
		if !nodeMap[flow.DstIP] {
			nodeMap[flow.DstIP] = true
			nodes = append(nodes, map[string]interface{}{
				"id":    flow.DstIP,
				"label": flow.DstIP,
				"group": categorizeIPForD3(flow.DstIP),
			})
		}
		links = append(links, map[string]interface{}{
			"source":   flow.SrcIP,
			"target":   flow.DstIP,
			"value":    5,
			"hasIssue": false,
		})
	}

	// Add nodes from TCP retransmissions (mark as issues)
	for _, flow := range r.TCPRetransmissions {
		if !nodeMap[flow.SrcIP] {
			nodeMap[flow.SrcIP] = true
			nodes = append(nodes, map[string]interface{}{
				"id":    flow.SrcIP,
				"label": flow.SrcIP,
				"group": categorizeIPForD3(flow.SrcIP),
			})
		}
		if !nodeMap[flow.DstIP] {
			nodeMap[flow.DstIP] = true
			nodes = append(nodes, map[string]interface{}{
				"id":    flow.DstIP,
				"label": flow.DstIP,
				"group": categorizeIPForD3(flow.DstIP),
			})
		}
	}

	nodesJSON, _ := json.Marshal(nodes)
	linksJSON, _ := json.Marshal(links)

	// Build timeline events
	timelineEvents := []map[string]interface{}{}
	for _, event := range r.Timeline {
		timelineEvents = append(timelineEvents, map[string]interface{}{
			"timestamp": event.Timestamp,
			"type":      event.EventType,
			"source":    event.SourceIP,
			"target":    event.DestinationIP,
			"detail":    event.Detail,
		})
	}
	timelineJSON, _ := json.Marshal(timelineEvents)

	// Build Sankey data
	sankeyNodes := []map[string]string{
		{"name": "Internal Network"},
		{"name": "Gateway"},
		{"name": "Internet"},
	}
	sankeyLinks := []map[string]interface{}{}

	totalBytes := uint64(0)
	for _, flow := range r.TrafficAnalysis {
		totalBytes += flow.TotalBytes
	}

	if totalBytes > 0 {
		sankeyLinks = append(sankeyLinks, map[string]interface{}{
			"source": 0,
			"target": 1,
			"value":  float64(totalBytes),
		})
		sankeyLinks = append(sankeyLinks, map[string]interface{}{
			"source": 1,
			"target": 2,
			"value":  float64(totalBytes),
		})
	}

	sankeyData := map[string]interface{}{
		"nodes": sankeyNodes,
		"links": sankeyLinks,
	}
	sankeyJSON, _ := json.Marshal(sankeyData)

	return fmt.Sprintf(`
        <script>
            // Initialize D3.js visualizations with data
            document.addEventListener('DOMContentLoaded', function() {
                try {
                    // Network Diagram
                    const networkData = {
                        nodes: %s,
                        links: %s
                    };
                    if (networkData.nodes.length > 0 && typeof createNetworkDiagram === 'function') {
                        createNetworkDiagram(networkData.nodes, networkData.links);
                    }
                    
                    // Timeline
                    const timelineData = %s;
                    if (timelineData.length > 0 && typeof createTimeline === 'function') {
                        createTimeline(timelineData);
                    }
                    
                    // Sankey Diagram
                    const sankeyData = %s;
                    if (sankeyData.nodes.length > 0 && typeof createSankeyDiagram === 'function') {
                        createSankeyDiagram(sankeyData);
                    }
                } catch (error) {
                    console.error("Error initializing D3 visualizations:", error);
                }
            });
        </script>
    `, string(nodesJSON), string(linksJSON), string(timelineJSON), string(sankeyJSON))
}

// categorizeIPForD3 categorizes an IP for D3 visualization
func categorizeIPForD3(ip string) string {
	if models.IsPrivateOrReservedIP(ip) {
		// Check if it's a gateway (.1 or .254)
		if len(ip) > 0 {
			lastDot := -1
			for i := len(ip) - 1; i >= 0; i-- {
				if ip[i] == '.' {
					lastDot = i
					break
				}
			}
			if lastDot > 0 {
				lastOctet := ip[lastDot+1:]
				if lastOctet == "1" || lastOctet == "254" {
					return "router"
				}
			}
		}
		return "internal"
	}
	return "external"
}
