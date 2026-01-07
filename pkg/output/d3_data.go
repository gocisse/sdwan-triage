package output

import (
	"fmt"
)

// GenerateD3NetworkData converts PathStats to D3.js nodes and links
func GenerateD3NetworkData(pathStats interface{}, filter interface{}, traceData interface{}) ([]D3Node, []D3Link) {
	nodes := []D3Node{}
	links := []D3Link{}
	nodeMap := make(map[string]bool)

	// This is a placeholder - in the full implementation, we'd convert the actual PathStats
	// For now, return empty arrays to avoid compilation errors
	return nodes, links
}

// GenerateD3TimelineData converts timeline events to D3.js format
func GenerateD3TimelineData(timelineEvents interface{}) []D3TimelineEvent {
	events := []D3TimelineEvent{}

	// This is a placeholder - in the full implementation, we'd convert actual timeline events
	return events
}

// GenerateD3SankeyData converts traffic analysis to Sankey diagram format
func GenerateD3SankeyData(trafficAnalysis interface{}) map[string]interface{} {
	data := map[string]interface{}{
		"nodes": []SankeyNode{},
		"links": []SankeyLink{},
	}

	// This is a placeholder - in the full implementation, we'd convert actual traffic data
	return data
}

// GenerateDetailedActionItems creates specific action items based on findings
func GenerateDetailedActionItems(report interface{}) string {
	html := `<div class="card">
    <div class="card-header">
        <i class="fas fa-clipboard-check"></i>
        <h2>Detailed Action Items</h2>
    </div>
    <div class="card-body">`

	// DNS Anomalies Actions
	html += `
        <button class="collapsible">DNS Anomalies - Recommended Actions</button>
        <div class="collapsible-content">
            <div class="collapsible-content-inner">
                <div class="action-item critical">
                    <i class="fas fa-exclamation-triangle"></i>
                    <div>
                        <strong>Immediate Action Required</strong>
                        <ul style="margin-top: 8px; margin-left: 20px;">
                            <li><strong>Verify DNS Server:</strong> Check if the DNS server IP matches your configured DNS servers</li>
                            <li><strong>Scan for Malware:</strong> Run antivirus/antimalware scan on affected client devices</li>
                            <li><strong>Check Gateway:</strong> Verify gateway device is not compromised (check MAC address)</li>
                            <li><strong>Network Isolation:</strong> Consider isolating affected devices until investigation is complete</li>
                            <li><strong>DNS Security:</strong> Implement DNSSEC if not already enabled</li>
                            <li><strong>Monitor Traffic:</strong> Continue monitoring for additional DNS anomalies</li>
                        </ul>
                    </div>
                </div>
            </div>
        </div>`

	// TCP Retransmissions Actions
	html += `
        <button class="collapsible">TCP Retransmissions - Performance Optimization</button>
        <div class="collapsible-content">
            <div class="collapsible-content-inner">
                <div class="action-item warning">
                    <i class="fas fa-tachometer-alt"></i>
                    <div>
                        <strong>Performance Investigation Steps</strong>
                        <ul style="margin-top: 8px; margin-left: 20px;">
                            <li><strong>Check Physical Links:</strong> Inspect cables, connectors, and network interface cards</li>
                            <li><strong>Review Switch/Router Logs:</strong> Look for errors, CRC errors, or interface resets</li>
                            <li><strong>Bandwidth Analysis:</strong> Check if links are saturated (>80% utilization)</li>
                            <li><strong>QoS Configuration:</strong> Review and adjust Quality of Service policies</li>
                            <li><strong>MTU Settings:</strong> Verify MTU is consistent across the path (typically 1500)</li>
                            <li><strong>Duplex Mismatch:</strong> Ensure all interfaces are auto-negotiating or manually set to full-duplex</li>
                            <li><strong>Buffer Tuning:</strong> Check router/switch buffer settings for congestion</li>
                        </ul>
                    </div>
                </div>
            </div>
        </div>`

	// ARP Conflicts Actions
	html += `
        <button class="collapsible">ARP Conflicts - Network Integrity</button>
        <div class="collapsible-content">
            <div class="collapsible-content-inner">
                <div class="action-item critical">
                    <i class="fas fa-network-wired"></i>
                    <div>
                        <strong>ARP Conflict Resolution</strong>
                        <ul style="margin-top: 8px; margin-left: 20px;">
                            <li><strong>Identify Devices:</strong> Use MAC address lookup to identify both devices claiming the same IP</li>
                            <li><strong>Check DHCP:</strong> Verify DHCP server is not assigning duplicate IPs</li>
                            <li><strong>Static IP Audit:</strong> Review all static IP assignments for conflicts</li>
                            <li><strong>Remove Rogue Device:</strong> Physically locate and remove/reconfigure the conflicting device</li>
                            <li><strong>Enable Port Security:</strong> Configure switch port security to prevent MAC spoofing</li>
                            <li><strong>ARP Inspection:</strong> Enable Dynamic ARP Inspection (DAI) on switches</li>
                        </ul>
                    </div>
                </div>
            </div>
        </div>`

	// TLS Certificate Issues Actions
	html += `
        <button class="collapsible">TLS Certificate Issues - Security Compliance</button>
        <div class="collapsible-content">
            <div class="collapsible-content-inner">
                <div class="action-item warning">
                    <i class="fas fa-certificate"></i>
                    <div>
                        <strong>Certificate Management Actions</strong>
                        <ul style="margin-top: 8px; margin-left: 20px;">
                            <li><strong>Renew Expired Certificates:</strong> Obtain and install new certificates from trusted CA</li>
                            <li><strong>Replace Self-Signed Certs:</strong> Use proper CA-signed certificates in production</li>
                            <li><strong>Certificate Monitoring:</strong> Implement automated certificate expiration monitoring</li>
                            <li><strong>Update Certificate Store:</strong> Ensure client devices have updated root CA certificates</li>
                            <li><strong>Review Certificate Chain:</strong> Verify complete certificate chain is properly configured</li>
                            <li><strong>Enable HSTS:</strong> Configure HTTP Strict Transport Security headers</li>
                        </ul>
                    </div>
                </div>
            </div>
        </div>`

	// Suspicious Traffic Actions
	html += `
        <button class="collapsible">Suspicious Traffic - Security Investigation</button>
        <div class="collapsible-content">
            <div class="collapsible-content-inner">
                <div class="action-item critical">
                    <i class="fas fa-user-secret"></i>
                    <div>
                        <strong>Security Incident Response</strong>
                        <ul style="margin-top: 8px; margin-left: 20px;">
                            <li><strong>Isolate Affected Systems:</strong> Quarantine devices communicating on suspicious ports</li>
                            <li><strong>Malware Scan:</strong> Run comprehensive security scans on identified devices</li>
                            <li><strong>Firewall Rules:</strong> Block suspicious ports at firewall/router level</li>
                            <li><strong>Log Analysis:</strong> Review system and application logs for unauthorized access</li>
                            <li><strong>Password Reset:</strong> Force password changes on potentially compromised accounts</li>
                            <li><strong>Incident Report:</strong> Document findings and notify security team/management</li>
                            <li><strong>Forensic Analysis:</strong> Consider engaging security professionals for deep investigation</li>
                        </ul>
                    </div>
                </div>
            </div>
        </div>`

	// High RTT Actions
	html += `
        <button class="collapsible">High Latency (RTT) - Performance Tuning</button>
        <div class="collapsible-content">
            <div class="collapsible-content-inner">
                <div class="action-item warning">
                    <i class="fas fa-clock"></i>
                    <div>
                        <strong>Latency Reduction Strategies</strong>
                        <ul style="margin-top: 8px; margin-left: 20px;">
                            <li><strong>Traceroute Analysis:</strong> Identify which hop is introducing latency</li>
                            <li><strong>ISP Investigation:</strong> Contact ISP if latency is on WAN links</li>
                            <li><strong>Route Optimization:</strong> Consider alternate routes or BGP path selection</li>
                            <li><strong>WAN Acceleration:</strong> Implement WAN optimization/SD-WAN solutions</li>
                            <li><strong>Caching:</strong> Deploy caching proxies for frequently accessed content</li>
                            <li><strong>CDN Usage:</strong> Use Content Delivery Networks for web applications</li>
                            <li><strong>Application Tuning:</strong> Optimize application protocols (HTTP/2, QUIC)</li>
                        </ul>
                    </div>
                </div>
            </div>
        </div>`

	// BGP Issues Actions
	html += `
        <button class="collapsible">BGP Routing Issues - Advanced Troubleshooting</button>
        <div class="collapsible-content">
            <div class="collapsible-content-inner">
                <div class="action-item critical">
                    <i class="fas fa-route"></i>
                    <div>
                        <strong>BGP Investigation Steps</strong>
                        <ul style="margin-top: 8px; margin-left: 20px;">
                            <li><strong>Verify AS Path:</strong> Confirm traffic is routing through expected autonomous systems</li>
                            <li><strong>Check BGP Tables:</strong> Review BGP routing tables on border routers</li>
                            <li><strong>Route Filtering:</strong> Implement BGP route filtering and prefix lists</li>
                            <li><strong>RPKI Validation:</strong> Enable Resource Public Key Infrastructure validation</li>
                            <li><strong>Contact Upstream:</strong> Notify upstream provider of potential hijack</li>
                            <li><strong>Monitoring:</strong> Set up BGP monitoring and alerting systems</li>
                        </ul>
                    </div>
                </div>
            </div>
        </div>`

	// QoS Issues Actions
	html += `
        <button class="collapsible">QoS/DSCP Issues - Traffic Management</button>
        <div class="collapsible-content">
            <div class="collapsible-content-inner">
                <div class="action-item warning">
                    <i class="fas fa-layer-group"></i>
                    <div>
                        <strong>QoS Configuration Review</strong>
                        <ul style="margin-top: 8px; margin-left: 20px;">
                            <li><strong>Verify DSCP Marking:</strong> Ensure applications are marking traffic correctly</li>
                            <li><strong>QoS Policy Check:</strong> Review router/switch QoS policies and queuing</li>
                            <li><strong>Bandwidth Allocation:</strong> Adjust bandwidth guarantees for priority traffic</li>
                            <li><strong>Queue Depth:</strong> Tune queue depths to prevent drops on priority traffic</li>
                            <li><strong>Traffic Shaping:</strong> Implement traffic shaping for non-critical applications</li>
                            <li><strong>End-to-End QoS:</strong> Ensure QoS is configured across entire path</li>
                        </ul>
                    </div>
                </div>
            </div>
        </div>`

	html += `
    </div>
</div>`

	return html
}

// GenerateFindingSpecificActions creates action items for specific findings
func GenerateFindingSpecificActions(findingType, detail string) string {
	actions := map[string]string{
		"dns_anomaly": fmt.Sprintf(`
			<div class="action-item critical" style="margin-top: 10px;">
				<i class="fas fa-tools"></i>
				<div>
					<strong>Action for this DNS anomaly:</strong>
					<p style="margin-top: 5px;">%s</p>
					<ul style="margin-top: 5px; margin-left: 20px;">
						<li>Verify DNS server configuration matches expected values</li>
						<li>Check if gateway device MAC address is legitimate</li>
						<li>Scan client device for malware or DNS hijacking</li>
					</ul>
				</div>
			</div>`, EscapeHTML(detail)),

		"tcp_retransmit": fmt.Sprintf(`
			<div class="action-item warning" style="margin-top: 10px;">
				<i class="fas fa-tools"></i>
				<div>
					<strong>Action for this retransmission:</strong>
					<p style="margin-top: 5px;">%s</p>
					<ul style="margin-top: 5px; margin-left: 20px;">
						<li>Check network path for congestion or packet loss</li>
						<li>Verify physical connections and interface statistics</li>
						<li>Review QoS policies for this traffic class</li>
					</ul>
				</div>
			</div>`, EscapeHTML(detail)),

		"arp_conflict": fmt.Sprintf(`
			<div class="action-item critical" style="margin-top: 10px;">
				<i class="fas fa-tools"></i>
				<div>
					<strong>Action for this ARP conflict:</strong>
					<p style="margin-top: 5px;">%s</p>
					<ul style="margin-top: 5px; margin-left: 20px;">
						<li>Identify both devices using MAC address lookup</li>
						<li>Remove or reconfigure the duplicate device</li>
						<li>Check DHCP server for IP assignment issues</li>
					</ul>
				</div>
			</div>`, EscapeHTML(detail)),

		"suspicious_traffic": fmt.Sprintf(`
			<div class="action-item critical" style="margin-top: 10px;">
				<i class="fas fa-tools"></i>
				<div>
					<strong>Action for suspicious traffic:</strong>
					<p style="margin-top: 5px;">%s</p>
					<ul style="margin-top: 5px; margin-left: 20px;">
						<li>Isolate the source device immediately</li>
						<li>Run comprehensive malware scan</li>
						<li>Block the suspicious port at firewall level</li>
						<li>Review system logs for unauthorized access</li>
					</ul>
				</div>
			</div>`, EscapeHTML(detail)),
	}

	if action, exists := actions[findingType]; exists {
		return action
	}
	return ""
}

// generateActionItemsCard generates HTML for actionable recommendations
func generateActionItemsCard(criticalIssues, performanceIssues, securityConcerns int) string {
	healthStatus := "HEALTHY"
	healthColor := "success"
	healthIcon := "fa-check-circle"

	if criticalIssues > 0 || securityConcerns > 3 {
		healthStatus = "CRITICAL"
		healthColor = "critical"
		healthIcon = "fa-exclamation-triangle"
	} else if performanceIssues > 5 || securityConcerns > 0 {
		healthStatus = "WARNING"
		healthColor = "warning"
		healthIcon = "fa-exclamation-circle"
	}

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

// GenerateExecutiveSummaryCard creates the executive summary card with health status
func GenerateExecutiveSummaryCard(criticalIssues, performanceIssues, securityConcerns int, totalBytes uint64) string {
	healthStatus := "HEALTHY"
	healthColor := "success"
	healthIcon := "fa-check-circle"

	if criticalIssues > 0 || securityConcerns > 3 {
		healthStatus = "CRITICAL"
		healthColor = "critical"
		healthIcon = "fa-exclamation-triangle"
	} else if performanceIssues > 5 || securityConcerns > 0 {
		healthStatus = "WARNING"
		healthColor = "warning"
		healthIcon = "fa-exclamation-circle"
	}

	html := `<div class="card">
    <div class="card-header">
        <i class="fas fa-chart-pie"></i>
        <h2>Executive Summary</h2>
    </div>
    <div class="card-body">
        <div class="stat-card ` + healthColor + `" style="margin-bottom: 20px;">
            <h3><i class="fas ` + healthIcon + `"></i> Network Health Status</h3>
            <div class="number">` + healthStatus + `</div>
        </div>
        
        <div class="summary-grid">
            <div class="stat-card` + func() string {
		if criticalIssues > 0 {
			return " critical"
		}
		return ""
	}() + `">
                <h3>Critical Issues</h3>
                <div class="number">` + fmt.Sprintf("%d", criticalIssues) + `</div>
                <p style="font-size: 0.85em; margin-top: 5px;">DNS anomalies, ARP conflicts</p>
            </div>
            
            <div class="stat-card` + func() string {
		if performanceIssues > 5 {
			return " warning"
		}
		return ""
	}() + `">
                <h3>Performance Issues</h3>
                <div class="number">` + fmt.Sprintf("%d", performanceIssues) + `</div>
                <p style="font-size: 0.85em; margin-top: 5px;">Retransmissions, high latency</p>
            </div>
            
            <div class="stat-card` + func() string {
		if securityConcerns > 0 {
			return " warning"
		}
		return ""
	}() + `">
                <h3>Security Concerns</h3>
                <div class="number">` + fmt.Sprintf("%d", securityConcerns) + `</div>
                <p style="font-size: 0.85em; margin-top: 5px;">Suspicious traffic, cert issues</p>
            </div>
            
            <div class="stat-card">
                <h3>Total Traffic</h3>
                <div class="number">` + fmt.Sprintf("%.1f", float64(totalBytes)/(1024*1024)) + `</div>
                <p style="font-size: 0.85em; margin-top: 5px;">Megabytes analyzed</p>
            </div>
        </div>
        
        <div style="margin-top: 20px; padding: 15px; background: #e3f2fd; border-left: 4px solid #2196F3; border-radius: 4px;">
            <strong><i class="fas fa-info-circle"></i> What This Means:</strong>
            <p style="margin-top: 8px;">` + func() string {
		if healthStatus == "CRITICAL" {
			return "Your network has critical issues that require immediate attention. Review the findings below and take action on high-priority items first."
		} else if healthStatus == "WARNING" {
			return "Your network is operational but has some issues that should be addressed to prevent future problems."
		}
		return "Your network appears healthy with no critical issues detected. Continue regular monitoring and maintenance."
	}() + `</p>
        </div>
    </div>
</div>`

	return html
}

// GenerateVisualizationCards creates cards for D3.js visualizations
func GenerateVisualizationCards() string {
	return `
<div class="card">
    <div class="card-header">
        <i class="fas fa-project-diagram"></i>
        <h2>Interactive Network Topology</h2>
    </div>
    <div class="card-body">
        <p style="margin-bottom: 15px; padding: 12px; background: #e3f2fd; border-left: 4px solid #2196F3; border-radius: 4px;">
            <strong><i class="fas fa-mouse-pointer"></i> Interactive Features:</strong>
            Drag nodes to rearrange, zoom with mouse wheel, hover for details. Red nodes indicate issues.
        </p>
        <div id="d3-network-diagram"></div>
        <div class="legend">
            <div class="legend-item">
                <div class="legend-color" style="background: #4CAF50;"></div>
                <span>Internal Devices</span>
            </div>
            <div class="legend-item">
                <div class="legend-color" style="background: #2196F3;"></div>
                <span>Routers/Gateways</span>
            </div>
            <div class="legend-item">
                <div class="legend-color" style="background: #FF9800;"></div>
                <span>External Servers</span>
            </div>
            <div class="legend-item">
                <div class="legend-color" style="background: #dc3545;"></div>
                <span>Devices with Issues</span>
            </div>
        </div>
    </div>
</div>

<div class="card">
    <div class="card-header">
        <i class="fas fa-clock"></i>
        <h2>Network Activity Timeline</h2>
    </div>
    <div class="card-body">
        <p style="margin-bottom: 15px; padding: 12px; background: #e3f2fd; border-left: 4px solid #2196F3; border-radius: 4px;">
            <strong><i class="fas fa-chart-line"></i> Timeline View:</strong>
            Shows network events over time. Hover over markers for event details. Zoom and pan to explore.
        </p>
        <div id="d3-timeline"></div>
    </div>
</div>

<div class="card">
    <div class="card-header">
        <i class="fas fa-exchange-alt"></i>
        <h2>Traffic Flow Analysis</h2>
    </div>
    <div class="card-body">
        <p style="margin-bottom: 15px; padding: 12px; background: #e3f2fd; border-left: 4px solid #2196F3; border-radius: 4px;">
            <strong><i class="fas fa-stream"></i> Sankey Diagram:</strong>
            Visualizes traffic volume between network segments. Wider flows indicate higher traffic volume.
        </p>
        <div id="d3-traffic-flow"></div>
    </div>
</div>`
}
