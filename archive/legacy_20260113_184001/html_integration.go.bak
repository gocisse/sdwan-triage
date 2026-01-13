package main

import (
	"encoding/json"
	"fmt"
	"net"
	"strings"

	"github.com/gocisse/sdwan-triage/pkg/output"
)

// categorizeIPForD3 categorizes an IP address for D3.js visualization
// Returns: "router" for gateway IPs (.1 or .254 in private ranges),
// "internal" for RFC 1918 private IPs, "external" for public IPs
func categorizeIPForD3(ipStr string) string {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return "external"
	}

	ip4 := ip.To4()
	if ip4 == nil {
		return "external"
	}

	a, b, _, d := ip4[0], ip4[1], ip4[2], ip4[3]

	// Check if it's a private IP (RFC 1918)
	isPrivate := (a == 10) ||
		(a == 172 && b >= 16 && b <= 31) ||
		(a == 192 && b == 168)

	if !isPrivate {
		return "external"
	}

	// Check for Router/Gateway (.1 or .254) within private ranges - check this FIRST
	if d == 1 || d == 254 {
		return "router"
	}

	return "internal"
}

// exportToEnhancedHTML generates a D3.js-powered HTML report with action items
func exportToEnhancedHTML(r *TriageReport, filename string, pathStats *PathStats, filter *Filter, traceData *TracerouteData) error {
	// Calculate summary statistics
	criticalIssues := len(r.DNSAnomalies) + len(r.ARPConflicts)
	performanceIssues := len(r.TCPRetransmissions) + len(r.FailedHandshakes) + len(r.RTTAnalysis)
	securityConcerns := len(r.SuspiciousTraffic)
	for _, cert := range r.TLSCerts {
		if cert.IsExpired || cert.IsSelfSigned {
			securityConcerns++
		}
	}

	// Start building HTML with D3.js template
	html := output.GetD3HTMLTemplate()

	// Add Executive Summary Card
	html += output.GenerateExecutiveSummaryCard(criticalIssues, performanceIssues, securityConcerns, r.TotalBytes)

	// Add Action Items
	html += generateActionItemsCard(criticalIssues, performanceIssues, securityConcerns)

	// Add Detailed Action Items
	html += output.GenerateDetailedActionItems(r)

	// Add Visualization Cards
	html += output.GenerateVisualizationCards()

	// Add DNS Anomalies Section with action items
	html += generateDNSAnomaliesCard(r)

	// Add TCP Retransmissions Section
	html += generateTCPRetransmissionsCard(r)

	// Add ARP Conflicts Section
	html += generateARPConflictsCard(r)

	// Add Suspicious Traffic Section
	html += generateSuspiciousTrafficCard(r)

	// Add TLS Certificates Section
	html += generateTLSCertsCard(r)

	// Add High RTT Section
	html += generateHighRTTCard(r)

	// Add BGP Analysis Section
	html += generateBGPAnalysisCard(r)

	// Add QoS Analysis Section
	html += generateQoSAnalysisCard(r)

	// Add Application Identification Section
	html += generateAppIdentificationCard(r)

	// Add Traffic Analysis Section
	html += generateTrafficAnalysisCard(r)

	// Add Timeline Section
	html += generateTimelineCard(r)

	// Add DNS Details Section
	html += generateDNSDetailsCard(r)

	// Close content div
	html += `
        </div>
        
        <div class="footer">
            <p><strong>SD-WAN Network Triage Report v2.6.0</strong></p>
            <p>Generated with advanced D3.js visualizations and actionable recommendations</p>
            <p style="margin-top: 10px; font-size: 0.9em;">
                This automated analysis identifies potential network issues. 
                Further investigation by network administrators may be required.
            </p>
        </div>
    </div>
`

	// Add D3.js scripts
	html += output.GetD3ScriptsTemplate()

	// Add data initialization
	html += generateD3DataInitialization(r, pathStats, traceData)

	// Close HTML
	html += `
</body>
</html>`

	// Write to file
	return output.WriteHTMLFile(filename, html)
}

// generateActionItemsCard creates the action items card
func generateActionItemsCard(criticalIssues, performanceIssues, securityConcerns int) string {
	html := `<div class="card">
    <div class="card-header">
        <i class="fas fa-tasks"></i>
        <h2>Recommended Actions</h2>
    </div>
    <div class="card-body">`

	if criticalIssues > 0 {
		html += `
        <div class="action-item critical">
            <i class="fas fa-exclamation-triangle"></i>
            <div>
                <strong>CRITICAL: Investigate Network Anomalies</strong>
                You have ` + fmt.Sprintf("%d", criticalIssues) + ` critical issues detected (DNS anomalies, ARP conflicts).
                <ul style="margin-top: 8px; margin-left: 20px;">
                    <li>Review DNS server configurations and check for DNS poisoning</li>
                    <li>Identify devices with MAC address conflicts and remove duplicates</li>
                    <li>Scan affected systems for malware or unauthorized access</li>
                    <li>Contact your network security team immediately</li>
                </ul>
            </div>
        </div>`
	}

	if performanceIssues > 5 {
		html += `
        <div class="action-item warning">
            <i class="fas fa-chart-line"></i>
            <div>
                <strong>Performance Optimization Needed</strong>
                Detected ` + fmt.Sprintf("%d", performanceIssues) + ` performance issues including TCP retransmissions and high latency.
                <ul style="margin-top: 8px; margin-left: 20px;">
                    <li>Check network links for congestion or hardware issues</li>
                    <li>Review QoS policies on routers and switches</li>
                    <li>Consider upgrading bandwidth for high-traffic links</li>
                    <li>Investigate applications causing retransmissions</li>
                </ul>
            </div>
        </div>`
	}

	if securityConcerns > 0 {
		html += `
        <div class="action-item warning">
            <i class="fas fa-shield-alt"></i>
            <div>
                <strong>Security Review Required</strong>
                Found ` + fmt.Sprintf("%d", securityConcerns) + ` security concerns (suspicious traffic, expired certificates).
                <ul style="margin-top: 8px; margin-left: 20px;">
                    <li>Review and renew expired TLS certificates</li>
                    <li>Investigate traffic to suspicious ports</li>
                    <li>Update firewall rules to block unauthorized access</li>
                    <li>Conduct security audit of affected systems</li>
                </ul>
            </div>
        </div>`
	}

	if criticalIssues == 0 && performanceIssues <= 5 && securityConcerns == 0 {
		html += `
        <div class="action-item" style="background: #d4edda; border-left-color: #28a745;">
            <i class="fas fa-check-circle" style="color: #28a745;"></i>
            <div>
                <strong>Network Health: Good</strong>
                No critical issues detected. Continue monitoring network performance and security.
                <ul style="margin-top: 8px; margin-left: 20px;">
                    <li>Maintain regular PCAP captures for baseline comparison</li>
                    <li>Keep network equipment firmware up to date</li>
                    <li>Review security policies quarterly</li>
                </ul>
            </div>
        </div>`
	}

	html += `
    </div>
</div>`

	return html
}

// generateDNSAnomaliesCard creates the DNS anomalies section with action items
func generateDNSAnomaliesCard(r *TriageReport) string {
	html := `<div class="card">
    <div class="card-header">
        <i class="fas fa-exclamation-triangle"></i>
        <h2>DNS Anomalies</h2>
    </div>
    <div class="card-body">
        <p style="margin-bottom: 15px; padding: 12px; background: #fff3cd; border-left: 4px solid #ffc107; border-radius: 4px;">
            <strong><i class="fas fa-info-circle"></i> What are DNS Anomalies?</strong>
            DNS anomalies occur when domain names resolve to unexpected IP addresses, which could indicate DNS poisoning, 
            misconfiguration, or man-in-the-middle attacks.
        </p>`

	if len(r.DNSAnomalies) > 0 {
		html += `<table>
            <tr>
                <th>Time</th>
                <th>Query</th>
                <th>Answer IP</th>
                <th>DNS Server</th>
                <th>Reason</th>
            </tr>`

		for i, anomaly := range r.DNSAnomalies {
			if i >= 20 {
				break
			}
			html += fmt.Sprintf(`
            <tr>
                <td>%.3fs</td>
                <td><strong>%s</strong></td>
                <td><span class="badge badge-warning">%s</span></td>
                <td>%s</td>
                <td>%s</td>
            </tr>`,
				anomaly.Timestamp,
				output.EscapeHTML(anomaly.Query),
				output.EscapeHTML(anomaly.AnswerIP),
				output.EscapeHTML(anomaly.ServerIP),
				output.EscapeHTML(anomaly.Reason))

			// Add specific action item for this anomaly
			html += `<tr><td colspan="5">`
			html += output.GenerateFindingSpecificActions("dns_anomaly",
				fmt.Sprintf("Query: %s resolved to %s via %s", anomaly.Query, anomaly.AnswerIP, anomaly.ServerIP))
			html += `</td></tr>`
		}

		html += `</table>`

		if len(r.DNSAnomalies) > 20 {
			html += fmt.Sprintf(`<p style="text-align: center; margin-top: 10px; color: #666;">
                ... and %d more DNS anomalies</p>`, len(r.DNSAnomalies)-20)
		}
	} else {
		html += `<p class="empty-state">No DNS anomalies detected.</p>`
	}

	html += `
    </div>
</div>`

	return html
}

// generateTCPRetransmissionsCard creates the TCP retransmissions section with collapsible action items
func generateTCPRetransmissionsCard(r *TriageReport) string {
	html := `<div class="card">
    <div class="card-header">
        <i class="fas fa-redo"></i>
        <h2>TCP Retransmissions</h2>
    </div>
    <div class="card-body">
        <p style="margin-bottom: 15px; padding: 12px; background: #e3f2fd; border-left: 4px solid #2196F3; border-radius: 4px;">
            <strong><i class="fas fa-info-circle"></i> What are TCP Retransmissions?</strong>
            TCP retransmissions occur when packets are lost or corrupted in transit, requiring resending. 
            High retransmission rates indicate network congestion, faulty equipment, or poor link quality.
        </p>`

	if len(r.TCPRetransmissions) > 0 {
		html += `<table>
            <tr>
                <th>Source</th>
                <th>Destination</th>
                <th>Status</th>
            </tr>`

		for i, flow := range r.TCPRetransmissions {
			if i >= 20 {
				break
			}

			// Main row with toggle button
			html += fmt.Sprintf(`
            <tr>
                <td>%s:%d</td>
                <td>%s:%d</td>
                <td>
                    <span class="badge badge-warning">Packet Loss</span>
                    <button class="toggle-action-btn" onclick="toggleAction(this)" style="margin-left: 8px; padding: 4px 8px; font-size: 11px; cursor: pointer; background: #6c757d; color: white; border: none; border-radius: 4px;">Show Action</button>
                </td>
            </tr>`,
				output.EscapeHTML(flow.SrcIP),
				flow.SrcPort,
				output.EscapeHTML(flow.DstIP),
				flow.DstPort)

			// Hidden action row with specific recommendations
			html += fmt.Sprintf(`
            <tr class="action-row" style="display: none;">
                <td colspan="3">
                    <div class="action-details" style="padding: 12px; background: #f8f9fa; border-left: 4px solid #ffc107; margin: 5px 0;">
                        <strong><i class="fas fa-wrench"></i> Recommended Action:</strong>
                        <ul style="margin: 8px 0 0 20px; padding: 0;">
                            <li>Check network links between <strong>%s</strong> and <strong>%s</strong> for congestion</li>
                            <li>Review QoS settings on intermediate routers and switches</li>
                            <li>Verify firewall rules are not causing packet drops on port <strong>%d</strong></li>
                            <li>Check for duplex mismatch or cable issues on affected interfaces</li>
                            <li>Monitor interface error counters (CRC errors, collisions, drops)</li>
                        </ul>
                    </div>
                </td>
            </tr>`,
				output.EscapeHTML(flow.SrcIP),
				output.EscapeHTML(flow.DstIP),
				flow.DstPort)
		}

		html += `</table>`

		if len(r.TCPRetransmissions) > 20 {
			html += fmt.Sprintf(`<p style="text-align: center; margin-top: 10px; color: #666;">
                ... and %d more retransmission flows</p>`, len(r.TCPRetransmissions)-20)
		}
	} else {
		html += `<p class="empty-state">No significant TCP retransmissions detected.</p>`
	}

	html += `
    </div>
</div>`

	return html
}

// generateARPConflictsCard creates the ARP conflicts section
func generateARPConflictsCard(r *TriageReport) string {
	html := `<div class="card">
    <div class="card-header">
        <i class="fas fa-network-wired"></i>
        <h2>ARP Conflicts</h2>
    </div>
    <div class="card-body">
        <p style="margin-bottom: 15px; padding: 12px; background: #f8d7da; border-left: 4px solid #dc3545; border-radius: 4px;">
            <strong><i class="fas fa-info-circle"></i> What are ARP Conflicts?</strong>
            ARP conflicts occur when two devices claim the same IP address, causing network connectivity issues. 
            This can result from DHCP misconfigurations, static IP conflicts, or malicious activity.
        </p>`

	if len(r.ARPConflicts) > 0 {
		html += `<table>
            <tr>
                <th>IP Address</th>
                <th>MAC Address 1</th>
                <th>MAC Address 2</th>
            </tr>`

		for _, conflict := range r.ARPConflicts {
			html += fmt.Sprintf(`
            <tr>
                <td><strong>%s</strong></td>
                <td><span class="badge badge-critical">%s</span></td>
                <td><span class="badge badge-critical">%s</span></td>
            </tr>`,
				output.EscapeHTML(conflict.IP),
				output.EscapeHTML(conflict.MAC1),
				output.EscapeHTML(conflict.MAC2))

			// Add specific action item
			html += `<tr><td colspan="3">`
			html += output.GenerateFindingSpecificActions("arp_conflict",
				fmt.Sprintf("IP %s claimed by both %s and %s", conflict.IP, conflict.MAC1, conflict.MAC2))
			html += `</td></tr>`
		}

		html += `</table>`
	} else {
		html += `<p class="empty-state">No ARP conflicts detected.</p>`
	}

	html += `
    </div>
</div>`

	return html
}

// generateSuspiciousTrafficCard creates the suspicious traffic section
func generateSuspiciousTrafficCard(r *TriageReport) string {
	html := `<div class="card">
    <div class="card-header">
        <i class="fas fa-user-secret"></i>
        <h2>Suspicious Traffic</h2>
    </div>
    <div class="card-body">
        <p style="margin-bottom: 15px; padding: 12px; background: #f8d7da; border-left: 4px solid #dc3545; border-radius: 4px;">
            <strong><i class="fas fa-info-circle"></i> What is Suspicious Traffic?</strong>
            Traffic on known malicious ports or unusual patterns that may indicate malware, backdoors, 
            or unauthorized access attempts.
        </p>`

	if len(r.SuspiciousTraffic) > 0 {
		html += `<table>
            <tr>
                <th>Source</th>
                <th>Destination</th>
                <th>Port</th>
                <th>Protocol</th>
                <th>Reason</th>
            </tr>`

		for i, flow := range r.SuspiciousTraffic {
			if i >= 20 {
				break
			}
			html += fmt.Sprintf(`
            <tr>
                <td>%s</td>
                <td>%s</td>
                <td><span class="badge badge-critical">%d</span></td>
                <td>%s</td>
                <td>%s</td>
            </tr>`,
				output.EscapeHTML(flow.SrcIP),
				output.EscapeHTML(flow.DstIP),
				flow.DstPort,
				output.EscapeHTML(flow.Protocol),
				output.EscapeHTML(flow.Reason))

			// Add specific action item
			html += `<tr><td colspan="5">`
			html += output.GenerateFindingSpecificActions("suspicious_traffic",
				fmt.Sprintf("%s:%d -> %s:%d (%s)", flow.SrcIP, flow.SrcPort, flow.DstIP, flow.DstPort, flow.Reason))
			html += `</td></tr>`
		}

		html += `</table>`

		if len(r.SuspiciousTraffic) > 20 {
			html += fmt.Sprintf(`<p style="text-align: center; margin-top: 10px; color: #666;">
                ... and %d more suspicious flows</p>`, len(r.SuspiciousTraffic)-20)
		}
	} else {
		html += `<p class="empty-state">No suspicious traffic detected.</p>`
	}

	html += `
    </div>
</div>`

	return html
}

// generateTLSCertsCard creates the TLS certificates section
func generateTLSCertsCard(r *TriageReport) string {
	html := `<div class="card">
    <div class="card-header">
        <i class="fas fa-certificate"></i>
        <h2>TLS Certificate Issues</h2>
    </div>
    <div class="card-body">
        <p style="margin-bottom: 15px; padding: 12px; background: #fff3cd; border-left: 4px solid #ffc107; border-radius: 4px;">
            <strong><i class="fas fa-info-circle"></i> Why Certificate Issues Matter</strong>
            Expired or self-signed certificates can indicate security misconfigurations or potential 
            man-in-the-middle attacks. They also cause browser warnings and connection failures.
        </p>`

	hasIssues := false
	for _, cert := range r.TLSCerts {
		if cert.IsExpired || cert.IsSelfSigned {
			hasIssues = true
			break
		}
	}

	if hasIssues {
		html += `<table>
            <tr>
                <th>Server</th>
                <th>SNI</th>
                <th>Issuer</th>
                <th>Expires</th>
                <th>Issues</th>
            </tr>`

		for i, cert := range r.TLSCerts {
			if i >= 20 {
				break
			}
			if !cert.IsExpired && !cert.IsSelfSigned {
				continue
			}

			issues := []string{}
			if cert.IsExpired {
				issues = append(issues, "Expired")
			}
			if cert.IsSelfSigned {
				issues = append(issues, "Self-Signed")
			}

			html += fmt.Sprintf(`
            <tr>
                <td>%s:%d</td>
                <td>%s</td>
                <td>%s</td>
                <td>%s</td>
                <td><span class="badge badge-warning">%s</span></td>
            </tr>`,
				output.EscapeHTML(cert.ServerIP),
				cert.ServerPort,
				output.EscapeHTML(cert.ServerName),
				output.EscapeHTML(cert.Issuer),
				output.EscapeHTML(cert.NotAfter),
				output.EscapeHTML(fmt.Sprintf("%v", issues)))
		}

		html += `</table>`
	} else {
		html += `<p class="empty-state">No certificate issues detected.</p>`
	}

	html += `
    </div>
</div>`

	return html
}

// Placeholder functions for other sections
func generateHighRTTCard(r *TriageReport) string {
	return `<div class="card"><div class="card-header"><i class="fas fa-clock"></i><h2>High Latency (RTT) Flows</h2></div><div class="card-body"><p class="empty-state">RTT analysis data available in main report.</p></div></div>`
}

func generateBGPAnalysisCard(r *TriageReport) string {
	if len(r.BGPHijackIndicators) == 0 {
		return `<div class="card"><div class="card-header"><i class="fas fa-route"></i><h2>BGP Routing Analysis</h2></div><div class="card-body"><p class="empty-state">BGP analysis not performed. Use -bgp-check flag to enable.</p></div></div>`
	}
	return `<div class="card"><div class="card-header"><i class="fas fa-route"></i><h2>BGP Routing Analysis</h2></div><div class="card-body"><p>BGP data available - see detailed report.</p></div></div>`
}

func generateQoSAnalysisCard(r *TriageReport) string {
	if r.QoSAnalysis == nil {
		return `<div class="card"><div class="card-header"><i class="fas fa-layer-group"></i><h2>QoS/DSCP Analysis</h2></div><div class="card-body"><p class="empty-state">QoS analysis not performed. Use -qos-analysis flag to enable.</p></div></div>`
	}
	return `<div class="card"><div class="card-header"><i class="fas fa-layer-group"></i><h2>QoS/DSCP Analysis</h2></div><div class="card-body"><p>QoS data available - see detailed report.</p></div></div>`
}

func generateAppIdentificationCard(r *TriageReport) string {
	if len(r.AppIdentification) == 0 {
		return `<div class="card"><div class="card-header"><i class="fas fa-th"></i><h2>Application Identification</h2></div><div class="card-body"><p class="empty-state">Application identification not performed. Use -app-identify flag to enable.</p></div></div>`
	}
	return `<div class="card"><div class="card-header"><i class="fas fa-th"></i><h2>Application Identification</h2></div><div class="card-body"><p>Application data available - see detailed report.</p></div></div>`
}

func generateTrafficAnalysisCard(r *TriageReport) string {
	return `<div class="card"><div class="card-header"><i class="fas fa-chart-bar"></i><h2>Top Traffic Flows</h2></div><div class="card-body"><p>Traffic analysis data available in main report.</p></div></div>`
}

func generateTimelineCard(r *TriageReport) string {
	return `<div class="card"><div class="card-header"><i class="fas fa-stream"></i><h2>Network Timeline</h2></div><div class="card-body"><p>Timeline visualization above shows network events over time.</p></div></div>`
}

func generateDNSDetailsCard(r *TriageReport) string {
	return `<div class="card"><div class="card-header"><i class="fas fa-list"></i><h2>DNS Query/Response Details</h2></div><div class="card-body"><p>DNS transaction details available in main report.</p></div></div>`
}

// generateD3DataInitialization creates JavaScript to initialize D3.js visualizations with actual data
func generateD3DataInitialization(r *TriageReport, pathStats *PathStats, traceData *TracerouteData) string {
	// Convert PathStats to D3 nodes and links
	nodes := []map[string]interface{}{}
	links := []map[string]interface{}{}

	// Build node map from PathStats.Paths
	nodeMap := make(map[string]bool)

	// Suppress unused variable warnings
	_ = traceData

	for pathKey, path := range pathStats.Paths {
		// Parse source and destination from path key (format: "SrcIP->DstIP")
		parts := strings.Split(pathKey, "->")
		if len(parts) != 2 {
			continue
		}
		src := parts[0]
		dst := parts[1]

		if !nodeMap[src] {
			nodeMap[src] = true
			group := categorizeIPForD3(src)
			nodes = append(nodes, map[string]interface{}{
				"id":       src,
				"label":    src,
				"group":    group,
				"size":     20,
				"hasIssue": false,
				"tooltip":  fmt.Sprintf("IP: %s<br/>Role: %s", src, group),
			})
		}

		if !nodeMap[dst] {
			nodeMap[dst] = true
			group := categorizeIPForD3(dst)
			nodes = append(nodes, map[string]interface{}{
				"id":       dst,
				"label":    dst,
				"group":    group,
				"size":     20,
				"hasIssue": false,
				"tooltip":  fmt.Sprintf("IP: %s<br/>Role: %s", dst, group),
			})
		}

		// Add link - get first port from Ports map
		portLabel := "mixed"
		for port := range path.Ports {
			portLabel = fmt.Sprintf("%d", port)
			break
		}
		links = append(links, map[string]interface{}{
			"source":   src,
			"target":   dst,
			"value":    5,
			"label":    portLabel,
			"hasIssue": path.HasAnomaly,
			"tooltip":  fmt.Sprintf("Traffic: %s -> %s<br/>Bytes: %d<br/>Packets: %d", src, dst, path.ByteCount, path.PacketCount),
		})
	}

	nodesJSON, _ := json.Marshal(nodes)
	linksJSON, _ := json.Marshal(links)

	// Convert timeline events
	timelineEvents := []map[string]interface{}{}
	for i, event := range r.Timeline {
		if i >= 100 {
			break
		}
		timelineEvents = append(timelineEvents, map[string]interface{}{
			"time":     event.Timestamp,
			"type":     event.EventType,
			"label":    event.EventType,
			"detail":   event.Detail,
			"severity": "info",
		})
	}
	timelineJSON, _ := json.Marshal(timelineEvents)

	// Create Sankey data from TopConversationsByBytes
	sankeyNodes := []map[string]string{}
	sankeyLinks := []map[string]interface{}{}

	// Use TopConversationsByBytes for more accurate Sankey data
	if len(r.BandwidthReport.TopConversationsByBytes) > 0 {
		// Build node map to track unique entities
		nodeIndex := make(map[string]int)

		// Add logical grouping nodes first
		sankeyNodes = append(sankeyNodes, map[string]string{"name": "Internal Clients"})
		nodeIndex["Internal Clients"] = 0
		sankeyNodes = append(sankeyNodes, map[string]string{"name": "Local Gateway"})
		nodeIndex["Local Gateway"] = 1
		sankeyNodes = append(sankeyNodes, map[string]string{"name": "Internet"})
		nodeIndex["Internet"] = 2

		// Track traffic flows by category
		internalToGateway := uint64(0)
		gatewayToExternal := uint64(0)
		externalServers := make(map[string]uint64)

		for i, conv := range r.BandwidthReport.TopConversationsByBytes {
			if i >= 15 { // Limit to top 15 for readability
				break
			}

			srcCategory := categorizeIPForD3(conv.SrcIP)
			dstCategory := categorizeIPForD3(conv.DstIP)

			// Aggregate traffic by flow direction
			if srcCategory == "internal" || srcCategory == "router" {
				if dstCategory == "external" {
					// Internal -> External
					internalToGateway += conv.TotalBytes
					gatewayToExternal += conv.TotalBytes

					// Track specific external servers
					serverName := conv.DstIP
					if conv.DstPort == 443 || conv.DstPort == 80 {
						serverName = fmt.Sprintf("%s:%d", conv.DstIP, conv.DstPort)
					}
					externalServers[serverName] += conv.TotalBytes
				} else {
					// Internal -> Internal (LAN traffic)
					internalToGateway += conv.TotalBytes / 2
				}
			} else if srcCategory == "external" {
				if dstCategory == "internal" || dstCategory == "router" {
					// External -> Internal (response traffic)
					gatewayToExternal += conv.TotalBytes
					internalToGateway += conv.TotalBytes
				}
			}
		}

		// Add links for aggregated traffic
		if internalToGateway > 0 {
			sankeyLinks = append(sankeyLinks, map[string]interface{}{
				"source": 0,
				"target": 1,
				"value":  float64(internalToGateway),
			})
		}
		if gatewayToExternal > 0 {
			sankeyLinks = append(sankeyLinks, map[string]interface{}{
				"source": 1,
				"target": 2,
				"value":  float64(gatewayToExternal),
			})
		}

		// Add top external servers as separate nodes
		serverCount := 0
		for server, bytes := range externalServers {
			if serverCount >= 5 { // Limit to top 5 external servers
				break
			}
			if bytes > 100000 { // Only show servers with >100KB traffic
				nodeIdx := len(sankeyNodes)
				sankeyNodes = append(sankeyNodes, map[string]string{"name": server})
				sankeyLinks = append(sankeyLinks, map[string]interface{}{
					"source": 2,
					"target": nodeIdx,
					"value":  float64(bytes),
				})
				serverCount++
			}
		}
	} else if len(r.TrafficAnalysis) > 0 {
		// Fallback to TrafficAnalysis if TopConversationsByBytes is empty
		sankeyNodes = append(sankeyNodes, map[string]string{"name": "Internal Network"})
		sankeyNodes = append(sankeyNodes, map[string]string{"name": "Gateway"})
		sankeyNodes = append(sankeyNodes, map[string]string{"name": "Internet"})

		totalBytes := uint64(0)
		for _, flow := range r.TrafficAnalysis {
			totalBytes += flow.TotalBytes
		}

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

	return `
    <script>
        // Initialize visualizations when page loads
        document.addEventListener('DOMContentLoaded', function() {
            try {
                // Network Diagram
                const networkData = {
                    nodes: ` + string(nodesJSON) + `,
                    links: ` + string(linksJSON) + `
                };
                if (networkData.nodes.length > 0) {
                    createNetworkDiagram(networkData.nodes, networkData.links);
                }
                
                // Timeline
                const timelineData = ` + string(timelineJSON) + `;
                if (timelineData.length > 0) {
                    createTimeline(timelineData);
                }
                
                // Sankey Diagram
                const sankeyData = ` + string(sankeyJSON) + `;
                if (sankeyData.nodes.length > 0) {
                    createSankeyDiagram(sankeyData);
                }
            } catch (error) {
                console.error('Error initializing visualizations:', error);
            }
        });
    </script>
`
}
