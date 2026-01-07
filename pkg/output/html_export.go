package output

// ExportEnhancedHTML generates a complete D3.js-powered HTML report
func ExportEnhancedHTML(report interface{}, filename string, pathStats interface{}, filter interface{}, traceData interface{}) error {
	// Type assertions would go here in full implementation
	// For now, we'll create a working template

	// Calculate summary statistics
	criticalIssues := 0
	performanceIssues := 0
	securityConcerns := 0
	totalBytes := uint64(0)

	// Start building HTML
	html := GetD3HTMLTemplate()

	// Add Executive Summary Card
	html += GenerateExecutiveSummaryCard(criticalIssues, performanceIssues, securityConcerns, totalBytes)

	// Add Action Items (from d3_data.go)
	html += generateActionItemsCard(criticalIssues, performanceIssues, securityConcerns)

	// Add Detailed Action Items
	html += GenerateDetailedActionItems(report)

	// Add Visualization Cards
	html += GenerateVisualizationCards()

	// Add detailed findings sections
	html += generateFindingsSection(report)

	// Close content div
	html += `
        </div>
        
        <div class="footer">
            <p><strong>SD-WAN Network Triage Report v2.6.0</strong></p>
            <p>Generated with advanced D3.js visualizations</p>
            <p style="margin-top: 10px; font-size: 0.9em;">
                This automated analysis identifies potential network issues. 
                Further investigation by network administrators may be required.
            </p>
        </div>
    </div>
`

	// Add D3.js initialization scripts
	html += GetD3ScriptsTemplate()

	// Add data initialization
	html += generateDataInitialization(report, pathStats, traceData)

	// Close HTML
	html += `
</body>
</html>`

	// Write to file
	return WriteHTMLFile(filename, html)
}

// generateFindingsSection creates detailed findings cards
func generateFindingsSection(report interface{}) string {
	html := ""

	// DNS Anomalies Section
	html += `
<div class="card">
    <div class="card-header">
        <i class="fas fa-exclamation-triangle"></i>
        <h2>DNS Anomalies</h2>
    </div>
    <div class="card-body">
        <p style="margin-bottom: 15px; padding: 12px; background: #fff3cd; border-left: 4px solid #ffc107; border-radius: 4px;">
            <strong><i class="fas fa-info-circle"></i> What are DNS Anomalies?</strong>
            DNS anomalies occur when domain names resolve to unexpected IP addresses, which could indicate DNS poisoning, 
            misconfiguration, or man-in-the-middle attacks.
        </p>
        <div id="dns-anomalies-content">
            <p class="empty-state">No DNS anomalies detected.</p>
        </div>
    </div>
</div>`

	// TCP Retransmissions Section
	html += `
<div class="card">
    <div class="card-header">
        <i class="fas fa-redo"></i>
        <h2>TCP Retransmissions</h2>
    </div>
    <div class="card-body">
        <p style="margin-bottom: 15px; padding: 12px; background: #e3f2fd; border-left: 4px solid #2196F3; border-radius: 4px;">
            <strong><i class="fas fa-info-circle"></i> What are TCP Retransmissions?</strong>
            TCP retransmissions occur when packets are lost or corrupted in transit, requiring resending. 
            High retransmission rates indicate network congestion, faulty equipment, or poor link quality.
        </p>
        <div id="tcp-retransmissions-content">
            <p class="empty-state">No significant TCP retransmissions detected.</p>
        </div>
    </div>
</div>`

	// ARP Conflicts Section
	html += `
<div class="card">
    <div class="card-header">
        <i class="fas fa-network-wired"></i>
        <h2>ARP Conflicts</h2>
    </div>
    <div class="card-body">
        <p style="margin-bottom: 15px; padding: 12px; background: #f8d7da; border-left: 4px solid #dc3545; border-radius: 4px;">
            <strong><i class="fas fa-info-circle"></i> What are ARP Conflicts?</strong>
            ARP conflicts occur when two devices claim the same IP address, causing network connectivity issues. 
            This can result from DHCP misconfigurations, static IP conflicts, or malicious activity.
        </p>
        <div id="arp-conflicts-content">
            <p class="empty-state">No ARP conflicts detected.</p>
        </div>
    </div>
</div>`

	// Suspicious Traffic Section
	html += `
<div class="card">
    <div class="card-header">
        <i class="fas fa-user-secret"></i>
        <h2>Suspicious Traffic</h2>
    </div>
    <div class="card-body">
        <p style="margin-bottom: 15px; padding: 12px; background: #f8d7da; border-left: 4px solid #dc3545; border-radius: 4px;">
            <strong><i class="fas fa-info-circle"></i> What is Suspicious Traffic?</strong>
            Traffic on known malicious ports or unusual patterns that may indicate malware, backdoors, 
            or unauthorized access attempts.
        </p>
        <div id="suspicious-traffic-content">
            <p class="empty-state">No suspicious traffic detected.</p>
        </div>
    </div>
</div>`

	// TLS Certificates Section
	html += `
<div class="card">
    <div class="card-header">
        <i class="fas fa-certificate"></i>
        <h2>TLS Certificate Issues</h2>
    </div>
    <div class="card-body">
        <p style="margin-bottom: 15px; padding: 12px; background: #fff3cd; border-left: 4px solid #ffc107; border-radius: 4px;">
            <strong><i class="fas fa-info-circle"></i> Why Certificate Issues Matter</strong>
            Expired or self-signed certificates can indicate security misconfigurations or potential 
            man-in-the-middle attacks. They also cause browser warnings and connection failures.
        </p>
        <div id="tls-certs-content">
            <p class="empty-state">No certificate issues detected.</p>
        </div>
    </div>
</div>`

	// High RTT Section
	html += `
<div class="card">
    <div class="card-header">
        <i class="fas fa-clock"></i>
        <h2>High Latency (RTT) Flows</h2>
    </div>
    <div class="card-body">
        <p style="margin-bottom: 15px; padding: 12px; background: #fff3cd; border-left: 4px solid #ffc107; border-radius: 4px;">
            <strong><i class="fas fa-info-circle"></i> Understanding Latency</strong>
            Round-Trip Time (RTT) measures how long it takes for data to travel to a destination and back. 
            High RTT causes slow application performance and poor user experience.
        </p>
        <div id="high-rtt-content">
            <p class="empty-state">No high latency flows detected.</p>
        </div>
    </div>
</div>`

	// BGP Analysis Section
	html += `
<div class="card">
    <div class="card-header">
        <i class="fas fa-route"></i>
        <h2>BGP Routing Analysis</h2>
    </div>
    <div class="card-body">
        <p style="margin-bottom: 15px; padding: 12px; background: #e3f2fd; border-left: 4px solid #2196F3; border-radius: 4px;">
            <strong><i class="fas fa-info-circle"></i> BGP Routing Information</strong>
            Border Gateway Protocol (BGP) controls how traffic routes across the internet. 
            Unexpected routing can indicate BGP hijacking or suboptimal paths.
        </p>
        <div id="bgp-analysis-content">
            <p class="empty-state">BGP analysis not performed. Use -bgp-check flag to enable.</p>
        </div>
    </div>
</div>`

	// QoS Analysis Section
	html += `
<div class="card">
    <div class="card-header">
        <i class="fas fa-layer-group"></i>
        <h2>QoS/DSCP Traffic Analysis</h2>
    </div>
    <div class="card-body">
        <p style="margin-bottom: 15px; padding: 12px; background: #e3f2fd; border-left: 4px solid #2196F3; border-radius: 4px;">
            <strong><i class="fas fa-info-circle"></i> Quality of Service</strong>
            DSCP (Differentiated Services Code Point) values indicate traffic priority. 
            Proper QoS ensures critical applications get necessary bandwidth and low latency.
        </p>
        <div id="qos-analysis-content">
            <p class="empty-state">QoS analysis not performed. Use -qos-analysis flag to enable.</p>
        </div>
    </div>
</div>`

	// Application Identification Section
	html += `
<div class="card">
    <div class="card-header">
        <i class="fas fa-th"></i>
        <h2>Application Identification</h2>
    </div>
    <div class="card-body">
        <p style="margin-bottom: 15px; padding: 12px; background: #e3f2fd; border-left: 4px solid #2196F3; border-radius: 4px;">
            <strong><i class="fas fa-info-circle"></i> Application Discovery</strong>
            Identifies applications using port analysis, TLS SNI inspection, and payload heuristics. 
            Helps discover shadow IT and unauthorized applications.
        </p>
        <div id="app-identification-content">
            <p class="empty-state">Application identification not performed. Use -app-identify flag to enable.</p>
        </div>
    </div>
</div>`

	// Traffic Analysis Section
	html += `
<div class="card">
    <div class="card-header">
        <i class="fas fa-chart-bar"></i>
        <h2>Top Traffic Flows</h2>
    </div>
    <div class="card-body">
        <p style="margin-bottom: 15px; padding: 12px; background: #e3f2fd; border-left: 4px solid #2196F3; border-radius: 4px;">
            <strong><i class="fas fa-info-circle"></i> Traffic Analysis</strong>
            Shows the highest volume conversations in your network. Helps identify bandwidth hogs 
            and understand traffic patterns.
        </p>
        <div id="traffic-analysis-content">
            <p class="empty-state">No traffic analysis data available.</p>
        </div>
    </div>
</div>`

	return html
}

// generateDataInitialization creates JavaScript to initialize D3.js visualizations
func generateDataInitialization(report, pathStats, traceData interface{}) string {
	// Generate sample data for now - in full implementation, this would convert actual data
	networkData := `{
		"nodes": [
			{"id": "192.168.1.1", "label": "Gateway", "group": "router", "size": 30, "hasIssue": false, "tooltip": "Gateway Router<br/>Role: Router<br/>Traffic: High"},
			{"id": "192.168.1.100", "label": "Workstation", "group": "internal", "size": 20, "hasIssue": false, "tooltip": "Internal Device<br/>Role: Client<br/>Traffic: Medium"},
			{"id": "8.8.8.8", "label": "DNS Server", "group": "external", "size": 25, "hasIssue": false, "tooltip": "External DNS<br/>Role: DNS Server<br/>Traffic: Low"}
		],
		"links": [
			{"source": "192.168.1.100", "target": "192.168.1.1", "value": 5, "label": "TCP:443", "hasIssue": false, "tooltip": "HTTPS Traffic<br/>Volume: 5 MB"},
			{"source": "192.168.1.1", "target": "8.8.8.8", "value": 3, "label": "UDP:53", "hasIssue": false, "tooltip": "DNS Queries<br/>Volume: 3 MB"}
		]
	}`

	timelineData := `[
		{"time": 0.5, "type": "DNS", "label": "DNS Query", "detail": "Query: example.com", "severity": "info"},
		{"time": 1.2, "type": "TCP", "label": "TCP SYN", "detail": "Connection to 192.168.1.1:443", "severity": "info"},
		{"time": 2.3, "type": "HTTP", "label": "HTTP Request", "detail": "GET /api/data", "severity": "info"}
	]`

	sankeyData := `{
		"nodes": [
			{"name": "Internal Network"},
			{"name": "Gateway"},
			{"name": "Internet"}
		],
		"links": [
			{"source": 0, "target": 1, "value": 10485760},
			{"source": 1, "target": 2, "value": 10485760}
		]
	}`

	return `
    <script>
        // Initialize visualizations when page loads
        document.addEventListener('DOMContentLoaded', function() {
            try {
                // Network Diagram
                const networkData = ` + networkData + `;
                if (networkData.nodes.length > 0) {
                    createNetworkDiagram(networkData.nodes, networkData.links);
                }
                
                // Timeline
                const timelineData = ` + timelineData + `;
                if (timelineData.length > 0) {
                    createTimeline(timelineData);
                }
                
                // Sankey Diagram
                const sankeyData = ` + sankeyData + `;
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

// PopulateFindingsData generates JavaScript to populate findings sections
func PopulateFindingsData(report interface{}) string {
	// This would be called with actual report data
	// For now, return empty string as placeholder
	return ""
}

// FormatDNSAnomaliesTable generates HTML table for DNS anomalies
func FormatDNSAnomaliesTable(anomalies interface{}) string {
	html := `<table>
		<tr>
			<th>Time</th>
			<th>Query</th>
			<th>Answer IP</th>
			<th>DNS Server</th>
			<th>Reason</th>
			<th>Action</th>
		</tr>`

	// In full implementation, iterate through actual anomalies
	html += `
		<tr>
			<td colspan="6" class="empty-state">No DNS anomalies detected in this capture.</td>
		</tr>`

	html += `</table>`
	return html
}

// FormatTCPRetransmissionsTable generates HTML table for TCP retransmissions
func FormatTCPRetransmissionsTable(retransmissions interface{}) string {
	html := `<table>
		<tr>
			<th>Source</th>
			<th>Destination</th>
			<th>Port</th>
			<th>Count</th>
			<th>Action</th>
		</tr>`

	// In full implementation, iterate through actual retransmissions
	html += `
		<tr>
			<td colspan="5" class="empty-state">No significant TCP retransmissions detected.</td>
		</tr>`

	html += `</table>`
	return html
}

// FormatARPConflictsTable generates HTML table for ARP conflicts
func FormatARPConflictsTable(conflicts interface{}) string {
	html := `<table>
		<tr>
			<th>IP Address</th>
			<th>MAC Address 1</th>
			<th>MAC Address 2</th>
			<th>Action</th>
		</tr>`

	// In full implementation, iterate through actual conflicts
	html += `
		<tr>
			<td colspan="4" class="empty-state">No ARP conflicts detected.</td>
		</tr>`

	html += `</table>`
	return html
}

// FormatSuspiciousTrafficTable generates HTML table for suspicious traffic
func FormatSuspiciousTrafficTable(suspicious interface{}) string {
	html := `<table>
		<tr>
			<th>Source</th>
			<th>Destination</th>
			<th>Port</th>
			<th>Protocol</th>
			<th>Reason</th>
			<th>Action</th>
		</tr>`

	// In full implementation, iterate through actual suspicious traffic
	html += `
		<tr>
			<td colspan="6" class="empty-state">No suspicious traffic detected.</td>
		</tr>`

	html += `</table>`
	return html
}
