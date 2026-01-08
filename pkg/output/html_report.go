package output

import (
	"bytes"
	"embed"
	"encoding/json"
	"fmt"
	"html"
	"html/template"
	"os"
	"sort"
	"time"

	"github.com/gocisse/sdwan-triage/pkg/models"
)

//go:embed assets/css/report.css
var cssContent string

//go:embed assets/js/visualizations.js
var jsContent string

//go:embed assets/templates/report.html
var templateContent embed.FS

// ReportData holds all data needed for the HTML template
type ReportData struct {
	// Header info
	GeneratedAt string
	FileName    string
	PacketCount int // Will be set from report
	Version     string
	Year        int

	// Health status
	HealthStatus  string // "good", "warning", "critical"
	RiskScore     int
	RiskLevel     string // "low", "medium", "high"
	TotalFindings int

	// Statistics
	Stats struct {
		DNSAnomalies       int
		TCPRetransmissions int
		ARPConflicts       int
		SuspiciousTraffic  int
		TLSCerts           int
		TotalTraffic       string
	}

	// Next steps
	NextSteps []string

	// Findings
	DNSAnomalies       []DNSAnomalyView
	ARPConflicts       []ARPConflictView
	SuspiciousTraffic  []SuspiciousFlowView
	TCPRetransmissions []TCPFlowView
	HighRTTFlows       []RTTFlowView
	TopFlows           []TrafficFlowView
	DeviceFingerprints []DeviceFingerprintView

	// Embedded assets
	CSS template.CSS
	JS  template.JS

	// Visualization data (JSON strings)
	NetworkDataJSON  template.JS
	TimelineDataJSON template.JS
	SankeyDataJSON   template.JS
}

// View structs for template rendering (with escaped/formatted data)
type DNSAnomalyView struct {
	Query    string
	AnswerIP string
	ServerIP string
	Reason   string
}

type ARPConflictView struct {
	IP   string
	MAC1 string
	MAC2 string
}

type SuspiciousFlowView struct {
	SrcIP   string
	DstIP   string
	DstPort uint16
	Reason  string
}

type TCPFlowView struct {
	SrcIP   string
	SrcPort uint16
	DstIP   string
	DstPort uint16
}

type RTTFlowView struct {
	SrcIP   string
	SrcPort uint16
	DstIP   string
	DstPort uint16
	AvgRTT  float64
	MaxRTT  float64
}

type TrafficFlowView struct {
	SrcIP          string
	SrcPort        uint16
	DstIP          string
	DstPort        uint16
	Protocol       string
	BytesFormatted string
	Percentage     float64
}

type DeviceFingerprintView struct {
	IP         string
	OSType     string
	OSName     string
	Confidence string
}

// GenerateHTMLReport generates a professional HTML report using templates
func GenerateHTMLReport(r *models.TriageReport, filename string, pcapFile string) error {
	// Prepare template data
	data := prepareReportData(r, pcapFile)

	// Parse template
	tmpl, err := template.New("report").Parse(getTemplateContent())
	if err != nil {
		return fmt.Errorf("failed to parse template: %w", err)
	}

	// Execute template
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return fmt.Errorf("failed to execute template: %w", err)
	}

	// Write to file
	if err := os.WriteFile(filename, buf.Bytes(), 0644); err != nil {
		return fmt.Errorf("failed to write HTML file: %w", err)
	}

	return nil
}

// prepareReportData converts TriageReport to ReportData for template rendering
func prepareReportData(r *models.TriageReport, pcapFile string) *ReportData {
	data := &ReportData{
		GeneratedAt: time.Now().Format("2006-01-02 15:04:05"),
		FileName:    html.EscapeString(pcapFile),
		PacketCount: 0, // PacketCount not in TriageReport, set externally,
		Version:     "2.7.0",
		Year:        time.Now().Year(),
		CSS:         template.CSS(cssContent),
		JS:          template.JS(jsContent),
	}

	// Calculate health status and risk score
	criticalIssues := len(r.DNSAnomalies) + len(r.ARPConflicts)
	performanceIssues := len(r.TCPRetransmissions) + len(r.FailedHandshakes)
	securityConcerns := len(r.SuspiciousTraffic)

	data.TotalFindings = criticalIssues + performanceIssues + securityConcerns

	// Calculate risk score (0-100)
	data.RiskScore = calculateRiskScore(criticalIssues, performanceIssues, securityConcerns)
	if data.RiskScore < 30 {
		data.RiskLevel = "low"
		data.HealthStatus = "good"
	} else if data.RiskScore < 70 {
		data.RiskLevel = "medium"
		data.HealthStatus = "warning"
	} else {
		data.RiskLevel = "high"
		data.HealthStatus = "critical"
	}

	// Statistics
	data.Stats.DNSAnomalies = len(r.DNSAnomalies)
	data.Stats.TCPRetransmissions = len(r.TCPRetransmissions)
	data.Stats.ARPConflicts = len(r.ARPConflicts)
	data.Stats.SuspiciousTraffic = len(r.SuspiciousTraffic)
	data.Stats.TLSCerts = len(r.TLSCerts)
	data.Stats.TotalTraffic = formatBytesForTemplate(r.TotalBytes)

	// Generate next steps
	data.NextSteps = generateNextSteps(r)

	// Convert findings to view structs (with escaping)
	data.DNSAnomalies = convertDNSAnomalies(r.DNSAnomalies)
	data.ARPConflicts = convertARPConflicts(r.ARPConflicts)
	data.SuspiciousTraffic = convertSuspiciousTraffic(r.SuspiciousTraffic)
	data.TCPRetransmissions = convertTCPRetransmissions(r.TCPRetransmissions)
	data.HighRTTFlows = convertRTTFlows(r.RTTAnalysis)
	data.TopFlows = convertTopFlows(r.TrafficAnalysis, r.TotalBytes)
	data.DeviceFingerprints = convertDeviceFingerprints(r.DeviceFingerprinting)

	// Generate visualization data
	data.NetworkDataJSON = template.JS(generateNetworkJSON(r))
	data.TimelineDataJSON = template.JS(generateTimelineJSON(r))
	data.SankeyDataJSON = template.JS(generateSankeyJSON(r))

	return data
}

func calculateRiskScore(critical, performance, security int) int {
	score := critical*20 + security*15 + performance/10
	if score > 100 {
		return 100
	}
	return score
}

func generateNextSteps(r *models.TriageReport) []string {
	steps := []string{}

	if len(r.DNSAnomalies) > 0 {
		steps = append(steps, "Investigate DNS anomalies - potential DNS poisoning or hijacking detected")
	}
	if len(r.ARPConflicts) > 0 {
		steps = append(steps, "Resolve ARP conflicts - check for duplicate IPs or ARP spoofing attacks")
	}
	if len(r.SuspiciousTraffic) > 0 {
		steps = append(steps, "Review suspicious traffic - potential malware or unauthorized access detected")
	}
	if len(r.TCPRetransmissions) > 10 {
		steps = append(steps, "Address network performance issues - high TCP retransmission rate indicates congestion or packet loss")
	}
	if len(r.FailedHandshakes) > 0 {
		steps = append(steps, "Investigate failed TCP handshakes - possible connectivity or firewall issues")
	}

	if len(steps) == 0 {
		steps = append(steps, "Continue monitoring network health - no immediate actions required")
	}

	// Limit to top 3
	if len(steps) > 3 {
		steps = steps[:3]
	}

	return steps
}

// Conversion functions with HTML escaping
func convertDNSAnomalies(anomalies []models.DNSAnomaly) []DNSAnomalyView {
	result := make([]DNSAnomalyView, len(anomalies))
	for i, a := range anomalies {
		result[i] = DNSAnomalyView{
			Query:    html.EscapeString(a.Query),
			AnswerIP: html.EscapeString(a.AnswerIP),
			ServerIP: html.EscapeString(a.ServerIP),
			Reason:   html.EscapeString(a.Reason),
		}
	}
	return result
}

func convertARPConflicts(conflicts []models.ARPConflict) []ARPConflictView {
	result := make([]ARPConflictView, len(conflicts))
	for i, c := range conflicts {
		result[i] = ARPConflictView{
			IP:   html.EscapeString(c.IP),
			MAC1: html.EscapeString(c.MAC1),
			MAC2: html.EscapeString(c.MAC2),
		}
	}
	return result
}

func convertSuspiciousTraffic(flows []models.SuspiciousFlow) []SuspiciousFlowView {
	result := make([]SuspiciousFlowView, len(flows))
	for i, f := range flows {
		result[i] = SuspiciousFlowView{
			SrcIP:   html.EscapeString(f.SrcIP),
			DstIP:   html.EscapeString(f.DstIP),
			DstPort: f.DstPort,
			Reason:  html.EscapeString(f.Reason),
		}
	}
	return result
}

func convertTCPRetransmissions(flows []models.TCPFlow) []TCPFlowView {
	result := make([]TCPFlowView, 0, len(flows))
	// Limit to first 50 for display
	limit := len(flows)
	if limit > 50 {
		limit = 50
	}
	for i := 0; i < limit; i++ {
		f := flows[i]
		result = append(result, TCPFlowView{
			SrcIP:   html.EscapeString(f.SrcIP),
			SrcPort: f.SrcPort,
			DstIP:   html.EscapeString(f.DstIP),
			DstPort: f.DstPort,
		})
	}
	return result
}

func convertRTTFlows(flows []models.RTTFlow) []RTTFlowView {
	result := make([]RTTFlowView, len(flows))
	for i, f := range flows {
		result[i] = RTTFlowView{
			SrcIP:   html.EscapeString(f.SrcIP),
			SrcPort: f.SrcPort,
			DstIP:   html.EscapeString(f.DstIP),
			DstPort: f.DstPort,
			AvgRTT:  f.AvgRTT,
			MaxRTT:  f.MaxRTT,
		}
	}
	return result
}

func convertTopFlows(flows []models.TrafficFlow, totalBytes uint64) []TrafficFlowView {
	// Sort by bytes descending
	sorted := make([]models.TrafficFlow, len(flows))
	copy(sorted, flows)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].TotalBytes > sorted[j].TotalBytes
	})

	// Limit to top 20
	limit := len(sorted)
	if limit > 20 {
		limit = 20
	}

	result := make([]TrafficFlowView, limit)
	for i := 0; i < limit; i++ {
		f := sorted[i]
		pct := float64(0)
		if totalBytes > 0 {
			pct = float64(f.TotalBytes) / float64(totalBytes) * 100
		}
		result[i] = TrafficFlowView{
			SrcIP:          html.EscapeString(f.SrcIP),
			SrcPort:        f.SrcPort,
			DstIP:          html.EscapeString(f.DstIP),
			DstPort:        f.DstPort,
			Protocol:       f.Protocol,
			BytesFormatted: formatBytesForTemplate(f.TotalBytes),
			Percentage:     pct,
		}
	}
	return result
}

func convertDeviceFingerprints(fps []models.DeviceFingerprint) []DeviceFingerprintView {
	result := make([]DeviceFingerprintView, len(fps))
	for i, f := range fps {
		result[i] = DeviceFingerprintView{
			IP:         html.EscapeString(f.SrcIP),
			OSType:     html.EscapeString(f.DeviceType),
			OSName:     html.EscapeString(f.OSGuess),
			Confidence: html.EscapeString(f.Confidence),
		}
	}
	return result
}

// JSON generation for visualizations
func generateNetworkJSON(r *models.TriageReport) string {
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
				"group": categorizeIPForVisualization(flow.SrcIP),
			})
		}
		if !nodeMap[flow.DstIP] {
			nodeMap[flow.DstIP] = true
			nodes = append(nodes, map[string]interface{}{
				"id":    flow.DstIP,
				"label": flow.DstIP,
				"group": categorizeIPForVisualization(flow.DstIP),
			})
		}
		links = append(links, map[string]interface{}{
			"source":   flow.SrcIP,
			"target":   flow.DstIP,
			"value":    5,
			"hasIssue": false,
		})
	}

	// Mark anomaly nodes
	for _, anomaly := range r.DNSAnomalies {
		if nodeMap[anomaly.AnswerIP] {
			for i := range nodes {
				if nodes[i]["id"] == anomaly.AnswerIP {
					nodes[i]["group"] = "anomaly"
				}
			}
		}
	}

	data := map[string]interface{}{
		"nodes": nodes,
		"links": links,
	}
	jsonBytes, _ := json.Marshal(data)
	return string(jsonBytes)
}

func generateTimelineJSON(r *models.TriageReport) string {
	events := []map[string]interface{}{}
	for _, event := range r.Timeline {
		events = append(events, map[string]interface{}{
			"timestamp": event.Timestamp,
			"type":      event.EventType,
			"source":    event.SourceIP,
			"target":    event.DestinationIP,
			"detail":    event.Detail,
		})
	}
	jsonBytes, _ := json.Marshal(events)
	return string(jsonBytes)
}

func generateSankeyJSON(r *models.TriageReport) string {
	nodes := []map[string]string{
		{"name": "Internal Network"},
		{"name": "Gateway"},
		{"name": "Internet"},
	}
	links := []map[string]interface{}{}

	totalBytes := uint64(0)
	for _, flow := range r.TrafficAnalysis {
		totalBytes += flow.TotalBytes
	}

	if totalBytes > 0 {
		links = append(links, map[string]interface{}{
			"source": 0,
			"target": 1,
			"value":  float64(totalBytes),
		})
		links = append(links, map[string]interface{}{
			"source": 1,
			"target": 2,
			"value":  float64(totalBytes),
		})
	}

	data := map[string]interface{}{
		"nodes": nodes,
		"links": links,
	}
	jsonBytes, _ := json.Marshal(data)
	return string(jsonBytes)
}

func categorizeIPForVisualization(ip string) string {
	if models.IsPrivateOrReservedIP(ip) {
		// Check for gateway pattern
		if len(ip) > 0 {
			for i := len(ip) - 1; i >= 0; i-- {
				if ip[i] == '.' {
					lastOctet := ip[i+1:]
					if lastOctet == "1" || lastOctet == "254" {
						return "router"
					}
					break
				}
			}
		}
		return "internal"
	}
	return "external"
}

func formatBytesForTemplate(bytes uint64) string {
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

func getTemplateContent() string {
	return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SD-WAN Network Triage Report</title>
    <script src="https://d3js.org/d3.v7.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/d3-sankey@0.12.3/dist/d3-sankey.min.js"></script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>{{.CSS}}</style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1><i class="fas fa-network-wired"></i> SD-WAN Network Triage Report</h1>
            <p class="subtitle">Comprehensive Network Analysis</p>
            <p class="meta">Generated: {{.GeneratedAt}} | File: {{.FileName}} | Packets: {{.PacketCount}}</p>
        </div>

        <div class="content">
            <div class="card">
                <div class="card-header">
                    <i class="fas fa-chart-line"></i>
                    <h2>Executive Summary</h2>
                </div>
                <div class="card-body">
                    {{if eq .HealthStatus "good"}}
                    <div class="health-badge health-good">
                        <i class="fas fa-check-circle"></i>&nbsp; Network Health: GOOD
                    </div>
                    {{else if eq .HealthStatus "warning"}}
                    <div class="health-badge health-warning">
                        <i class="fas fa-exclamation-triangle"></i>&nbsp; Network Health: WARNING
                    </div>
                    {{else}}
                    <div class="health-badge health-critical">
                        <i class="fas fa-times-circle"></i>&nbsp; Network Health: CRITICAL
                    </div>
                    {{end}}

                    <div style="display: flex; align-items: center; gap: 30px; margin: 20px 0;">
                        <div class="risk-score risk-{{.RiskLevel}}">{{.RiskScore}}</div>
                        <div>
                            <strong>Risk Score</strong><br/>
                            <span style="color: #6c757d;">Based on {{.TotalFindings}} findings</span>
                        </div>
                    </div>

                    <div class="stats-grid">
                        <div class="stat-card">
                            <span class="stat-value">{{.Stats.DNSAnomalies}}</span>
                            <span class="stat-label">DNS Anomalies</span>
                        </div>
                        <div class="stat-card">
                            <span class="stat-value">{{.Stats.TCPRetransmissions}}</span>
                            <span class="stat-label">TCP Retransmissions</span>
                        </div>
                        <div class="stat-card">
                            <span class="stat-value">{{.Stats.ARPConflicts}}</span>
                            <span class="stat-label">ARP Conflicts</span>
                        </div>
                        <div class="stat-card">
                            <span class="stat-value">{{.Stats.SuspiciousTraffic}}</span>
                            <span class="stat-label">Suspicious Traffic</span>
                        </div>
                        <div class="stat-card">
                            <span class="stat-value">{{.Stats.TLSCerts}}</span>
                            <span class="stat-label">TLS Certificates</span>
                        </div>
                        <div class="stat-card">
                            <span class="stat-value">{{.Stats.TotalTraffic}}</span>
                            <span class="stat-label">Total Traffic</span>
                        </div>
                    </div>

                    {{if .NextSteps}}
                    <div class="next-steps">
                        <h3><i class="fas fa-tasks"></i> Recommended Next Steps</h3>
                        <ol>
                            {{range .NextSteps}}
                            <li>{{.}}</li>
                            {{end}}
                        </ol>
                    </div>
                    {{end}}
                </div>
            </div>

            <div class="card">
                <div class="tabs">
                    <button class="tab active" data-tab="tab-security"><i class="fas fa-shield-alt"></i> Security</button>
                    <button class="tab" data-tab="tab-performance"><i class="fas fa-tachometer-alt"></i> Performance</button>
                    <button class="tab" data-tab="tab-traffic"><i class="fas fa-exchange-alt"></i> Traffic</button>
                    <button class="tab" data-tab="tab-visualizations"><i class="fas fa-project-diagram"></i> Visualizations</button>
                </div>

                <div id="tab-security" class="tab-content active">
                    {{if .DNSAnomalies}}
                    <details open>
                        <summary><i class="fas fa-dns"></i> DNS Anomalies ({{len .DNSAnomalies}})</summary>
                        <div>
                            <table class="data-table">
                                <thead>
                                    <tr>
                                        <th data-sort>Query</th>
                                        <th data-sort>Answer IP</th>
                                        <th data-sort>Server</th>
                                        <th>Reason</th>
                                        <th>Action</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {{range .DNSAnomalies}}
                                    <tr>
                                        <td><code>{{.Query}}</code></td>
                                        <td><code>{{.AnswerIP}}</code></td>
                                        <td><code>{{.ServerIP}}</code></td>
                                        <td class="severity-high">{{.Reason}}</td>
                                        <td><button class="btn btn-sm btn-secondary" onclick="toggleAction(this)">Show Action</button></td>
                                    </tr>
                                    <tr class="action-row">
                                        <td colspan="5">
                                            <div class="action-content">
                                                <h4><i class="fas fa-wrench"></i> Recommended Action</h4>
                                                <ul>
                                                    <li>Verify DNS server configuration at <strong>{{.ServerIP}}</strong></li>
                                                    <li>Check for DNS hijacking or poisoning attempts</li>
                                                    <li>Review firewall rules for DNS traffic</li>
                                                </ul>
                                            </div>
                                        </td>
                                    </tr>
                                    {{end}}
                                </tbody>
                            </table>
                        </div>
                    </details>
                    {{else}}
                    <div class="alert alert-success"><i class="fas fa-check"></i> No DNS anomalies detected</div>
                    {{end}}

                    {{if .ARPConflicts}}
                    <details>
                        <summary><i class="fas fa-network-wired"></i> ARP Conflicts ({{len .ARPConflicts}})</summary>
                        <div>
                            <table class="data-table">
                                <thead><tr><th>IP</th><th>MAC 1</th><th>MAC 2</th><th>Action</th></tr></thead>
                                <tbody>
                                    {{range .ARPConflicts}}
                                    <tr>
                                        <td><code>{{.IP}}</code></td>
                                        <td><code>{{.MAC1}}</code></td>
                                        <td><code>{{.MAC2}}</code></td>
                                        <td><button class="btn btn-sm btn-secondary" onclick="toggleAction(this)">Show Action</button></td>
                                    </tr>
                                    <tr class="action-row">
                                        <td colspan="4"><div class="action-content"><h4>Recommended Action</h4><ul><li>Investigate ARP spoofing</li><li>Check DHCP for duplicates</li></ul></div></td>
                                    </tr>
                                    {{end}}
                                </tbody>
                            </table>
                        </div>
                    </details>
                    {{else}}
                    <div class="alert alert-success"><i class="fas fa-check"></i> No ARP conflicts detected</div>
                    {{end}}

                    {{if .SuspiciousTraffic}}
                    <details>
                        <summary><i class="fas fa-exclamation-triangle"></i> Suspicious Traffic ({{len .SuspiciousTraffic}})</summary>
                        <div>
                            <table class="data-table">
                                <thead><tr><th>Source</th><th>Destination</th><th>Port</th><th>Reason</th></tr></thead>
                                <tbody>
                                    {{range .SuspiciousTraffic}}
                                    <tr>
                                        <td><code>{{.SrcIP}}</code></td>
                                        <td><code>{{.DstIP}}</code></td>
                                        <td>{{.DstPort}}</td>
                                        <td class="severity-high">{{.Reason}}</td>
                                    </tr>
                                    {{end}}
                                </tbody>
                            </table>
                        </div>
                    </details>
                    {{else}}
                    <div class="alert alert-success"><i class="fas fa-check"></i> No suspicious traffic detected</div>
                    {{end}}
                </div>

                <div id="tab-performance" class="tab-content">
                    {{if .TCPRetransmissions}}
                    <details open>
                        <summary><i class="fas fa-redo"></i> TCP Retransmissions ({{len .TCPRetransmissions}})</summary>
                        <div>
                            <table class="data-table">
                                <thead><tr><th>Source</th><th>Destination</th><th>Port</th><th>Action</th></tr></thead>
                                <tbody>
                                    {{range .TCPRetransmissions}}
                                    <tr>
                                        <td><code>{{.SrcIP}}:{{.SrcPort}}</code></td>
                                        <td><code>{{.DstIP}}:{{.DstPort}}</code></td>
                                        <td>{{.DstPort}}</td>
                                        <td><button class="btn btn-sm btn-secondary" onclick="toggleAction(this)">Show Action</button></td>
                                    </tr>
                                    <tr class="action-row">
                                        <td colspan="4"><div class="action-content"><h4>Recommended Action</h4><ul><li>Check network path for congestion</li><li>Review QoS settings</li><li>Verify MTU configuration</li></ul></div></td>
                                    </tr>
                                    {{end}}
                                </tbody>
                            </table>
                        </div>
                    </details>
                    {{else}}
                    <div class="alert alert-success"><i class="fas fa-check"></i> No TCP retransmissions detected</div>
                    {{end}}

                    {{if .HighRTTFlows}}
                    <details>
                        <summary><i class="fas fa-clock"></i> High RTT Flows ({{len .HighRTTFlows}})</summary>
                        <div>
                            <table class="data-table">
                                <thead><tr><th>Source</th><th>Destination</th><th>Avg RTT (ms)</th><th>Max RTT (ms)</th></tr></thead>
                                <tbody>
                                    {{range .HighRTTFlows}}
                                    <tr>
                                        <td><code>{{.SrcIP}}:{{.SrcPort}}</code></td>
                                        <td><code>{{.DstIP}}:{{.DstPort}}</code></td>
                                        <td class="severity-medium">{{printf "%.1f" .AvgRTT}}</td>
                                        <td>{{printf "%.1f" .MaxRTT}}</td>
                                    </tr>
                                    {{end}}
                                </tbody>
                            </table>
                        </div>
                    </details>
                    {{end}}
                </div>

                <div id="tab-traffic" class="tab-content">
                    {{if .TopFlows}}
                    <details open>
                        <summary><i class="fas fa-sort-amount-down"></i> Top Traffic Flows ({{len .TopFlows}})</summary>
                        <div>
                            <table class="data-table">
                                <thead><tr><th>Source</th><th>Destination</th><th>Protocol</th><th>Bytes</th><th>%</th></tr></thead>
                                <tbody>
                                    {{range .TopFlows}}
                                    <tr>
                                        <td><code>{{.SrcIP}}:{{.SrcPort}}</code></td>
                                        <td><code>{{.DstIP}}:{{.DstPort}}</code></td>
                                        <td>{{.Protocol}}</td>
                                        <td>{{.BytesFormatted}}</td>
                                        <td>{{printf "%.1f" .Percentage}}%</td>
                                    </tr>
                                    {{end}}
                                </tbody>
                            </table>
                        </div>
                    </details>
                    {{end}}

                    {{if .DeviceFingerprints}}
                    <details>
                        <summary><i class="fas fa-fingerprint"></i> Device Fingerprints ({{len .DeviceFingerprints}})</summary>
                        <div>
                            <table class="data-table">
                                <thead><tr><th>IP</th><th>OS Type</th><th>OS Name</th><th>Confidence</th></tr></thead>
                                <tbody>
                                    {{range .DeviceFingerprints}}
                                    <tr>
                                        <td><code>{{.IP}}</code></td>
                                        <td>{{.OSType}}</td>
                                        <td>{{.OSName}}</td>
                                        <td>{{.Confidence}}</td>
                                    </tr>
                                    {{end}}
                                </tbody>
                            </table>
                        </div>
                    </details>
                    {{end}}
                </div>

                <div id="tab-visualizations" class="tab-content">
                    <details open>
                        <summary><i class="fas fa-project-diagram"></i> Network Topology</summary>
                        <div><div id="network-diagram" class="viz-container" style="height: 500px;"></div></div>
                    </details>
                    <details>
                        <summary><i class="fas fa-clock"></i> Event Timeline</summary>
                        <div><div id="timeline-diagram" class="viz-container" style="height: 300px;"></div></div>
                    </details>
                    <details>
                        <summary><i class="fas fa-stream"></i> Traffic Flow (Sankey)</summary>
                        <div><div id="sankey-diagram" class="viz-container" style="height: 400px;"></div></div>
                    </details>
                </div>
            </div>
        </div>

        <div class="footer">
            <p>Generated by SD-WAN Triage Tool v{{.Version}} | &copy; {{.Year}}</p>
        </div>
    </div>

    <script>
        var networkData = {{.NetworkDataJSON}};
        var timelineData = {{.TimelineDataJSON}};
        var sankeyData = {{.SankeyDataJSON}};
    </script>
    <script>{{.JS}}</script>
</body>
</html>`
}
