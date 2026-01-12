package output

import (
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"time"

	"github.com/gocisse/sdwan-triage/pkg/models"
)

// GenerateMultiPageHTMLReport generates a multi-page HTML report structure
func GenerateMultiPageHTMLReport(r *models.TriageReport, outputDir string, pcapFile string) error {
	// Create output directory if it doesn't exist
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	// Copy CSS and JS assets to output directory
	if err := writeAssetFiles(outputDir); err != nil {
		return fmt.Errorf("failed to write asset files: %w", err)
	}

	// Prepare common data for all pages
	data := prepareReportData(r, pcapFile)

	// Generate each page
	pages := []struct {
		name     string
		filename string
		genFunc  func(*ReportData, string) error
	}{
		{"Dashboard", "index.html", generateDashboardPage},
		{"Executive Summary", "executive-summary.html", generateExecutiveSummaryPage},
		{"Security", "security.html", generateSecurityPage},
		{"Performance", "performance.html", generatePerformancePage},
		{"Protocols", "protocols.html", generateProtocolsPage},
		{"Network", "network.html", generateNetworkPage},
		{"Traffic", "traffic.html", generateTrafficPage},
		{"Visualizations", "visualizations.html", generateVisualizationsPage},
	}

	for _, page := range pages {
		outputPath := filepath.Join(outputDir, page.filename)
		if err := page.genFunc(data, outputPath); err != nil {
			return fmt.Errorf("failed to generate %s: %w", page.name, err)
		}
	}

	return nil
}

// writeAssetFiles writes CSS and JS files to the output directory
func writeAssetFiles(outputDir string) error {
	// Create assets directory
	assetsDir := filepath.Join(outputDir, "assets")
	if err := os.MkdirAll(assetsDir, 0755); err != nil {
		return err
	}

	// Write CSS file
	cssPath := filepath.Join(assetsDir, "report.css")
	if err := os.WriteFile(cssPath, []byte(cssContent), 0644); err != nil {
		return err
	}

	// Write JS file
	jsPath := filepath.Join(assetsDir, "visualizations.js")
	if err := os.WriteFile(jsPath, []byte(jsContent), 0644); err != nil {
		return err
	}

	return nil
}

// PageData extends ReportData with page-specific information
type PageData struct {
	*ReportData
	CurrentPage string
	PageTitle   string
}

// getBaseTemplate returns the base HTML template with navigation
func getBaseTemplate() string {
	return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{.PageTitle}} - SD-WAN Network Triage Report</title>
    <script src="https://d3js.org/d3.v7.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/d3-sankey@0.12.3/dist/d3-sankey.min.js"></script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <link rel="stylesheet" href="assets/report.css">
</head>
<body>
    <div class="app-container">
        <!-- Sidebar Navigation -->
        <aside class="sidebar" id="sidebar">
            <div class="sidebar-header">
                <div class="sidebar-logo"><i class="fas fa-network-wired"></i></div>
                <div>
                    <div class="sidebar-title">SD-WAN Triage</div>
                    <div class="sidebar-subtitle">Network Analysis</div>
                </div>
            </div>
            <nav class="nav-menu">
                <div class="nav-section">
                    <div class="nav-section-title">Overview</div>
                    <a href="index.html" class="nav-item {{if eq .CurrentPage "dashboard"}}active{{end}}"><i class="fas fa-tachometer-alt"></i> Dashboard</a>
                    <a href="executive-summary.html" class="nav-item {{if eq .CurrentPage "executive-summary"}}active{{end}}"><i class="fas fa-chart-line"></i> Executive Summary</a>
                </div>
                <div class="nav-section">
                    <div class="nav-section-title">Security</div>
                    <a href="security.html" class="nav-item {{if eq .CurrentPage "security"}}active{{end}}"><i class="fas fa-shield-alt"></i> Security Findings {{if gt .Stats.SuspiciousTraffic 0}}<span class="nav-badge">{{.Stats.SuspiciousTraffic}}</span>{{end}}</a>
                </div>
                <div class="nav-section">
                    <div class="nav-section-title">Performance</div>
                    <a href="performance.html" class="nav-item {{if eq .CurrentPage "performance"}}active{{end}}"><i class="fas fa-exchange-alt"></i> Performance {{if gt .Stats.TCPRetransmissions 10}}<span class="nav-badge">{{.Stats.TCPRetransmissions}}</span>{{end}}</a>
                </div>
                <div class="nav-section">
                    <div class="nav-section-title">Traffic</div>
                    <a href="traffic.html" class="nav-item {{if eq .CurrentPage "traffic"}}active{{end}}"><i class="fas fa-stream"></i> Traffic Flows</a>
                    <a href="protocols.html" class="nav-item {{if eq .CurrentPage "protocols"}}active{{end}}"><i class="fas fa-layer-group"></i> Protocols</a>
                    <a href="network.html" class="nav-item {{if eq .CurrentPage "network"}}active{{end}}"><i class="fas fa-laptop"></i> Network & Devices</a>
                </div>
                <div class="nav-section">
                    <div class="nav-section-title">Visualizations</div>
                    <a href="visualizations.html" class="nav-item {{if eq .CurrentPage "visualizations"}}active{{end}}"><i class="fas fa-project-diagram"></i> Charts & Maps</a>
                </div>
            </nav>
            <div class="theme-toggle">
                <span class="theme-toggle-label"><i class="fas fa-moon"></i> Dark Mode</span>
                <div class="theme-switch" onclick="toggleTheme()"></div>
            </div>
        </aside>

        <!-- Main Content -->
        <main class="main-content">
            <header class="top-header">
                <div class="header-left">
                    <button class="mobile-menu-btn" onclick="toggleSidebar()"><i class="fas fa-bars"></i></button>
                    <div class="breadcrumb">
                        <a href="index.html">Dashboard</a>
                        <span class="breadcrumb-separator">/</span>
                        <span class="breadcrumb-current">{{.PageTitle}}</span>
                    </div>
                </div>
                <div class="header-right">
                    <div class="header-meta">
                        <div><strong>{{.FileName}}</strong></div>
                        <div>{{.GeneratedAt}} • {{.PacketCount}} packets</div>
                    </div>
                </div>
            </header>

            <div class="page-content">
                {{template "content" .}}
            </div>
        </main>
    </div>
    <script src="assets/visualizations.js"></script>
</body>
</html>`
}

func generateDashboardPage(data *ReportData, outputPath string) error {
	pageData := &PageData{
		ReportData:  data,
		CurrentPage: "dashboard",
		PageTitle:   "Dashboard",
	}

	contentTemplate := `{{define "content"}}
                <!-- KPI Dashboard Section -->
                <section id="dashboard">
                    <div class="kpi-grid">
                        <div class="kpi-card">
                            <div class="kpi-icon {{if eq .HealthStatus "good"}}success{{else if eq .HealthStatus "warning"}}warning{{else}}danger{{end}}">
                                {{if eq .HealthStatus "good"}}<i class="fas fa-check-circle"></i>{{else if eq .HealthStatus "warning"}}<i class="fas fa-exclamation-triangle"></i>{{else}}<i class="fas fa-times-circle"></i>{{end}}
                            </div>
                            <div class="kpi-content">
                                <div class="kpi-label">Network Health</div>
                                <div class="kpi-value">{{if eq .HealthStatus "good"}}Good{{else if eq .HealthStatus "warning"}}Warning{{else}}Critical{{end}}</div>
                            </div>
                        </div>
                        <div class="kpi-card">
                            <div class="kpi-icon {{if gt .Stats.SuspiciousTraffic 0}}danger{{else}}success{{end}}">
                                <i class="fas fa-shield-alt"></i>
                            </div>
                            <div class="kpi-content">
                                <div class="kpi-label">Security Issues</div>
                                <div class="kpi-value">{{.Stats.SuspiciousTraffic}}</div>
                            </div>
                        </div>
                        <div class="kpi-card">
                            <div class="kpi-icon {{if gt .Stats.TCPRetransmissions 10}}warning{{else}}info{{end}}">
                                <i class="fas fa-redo"></i>
                            </div>
                            <div class="kpi-content">
                                <div class="kpi-label">TCP Retransmissions</div>
                                <div class="kpi-value">{{.Stats.TCPRetransmissions}}</div>
                            </div>
                        </div>
                        <div class="kpi-card">
                            <div class="kpi-icon info">
                                <i class="fas fa-database"></i>
                            </div>
                            <div class="kpi-content">
                                <div class="kpi-label">Total Traffic</div>
                                <div class="kpi-value">{{.Stats.TotalTraffic}}</div>
                            </div>
                        </div>
                    </div>

                    <div class="card">
                        <div class="card-header">
                            <i class="fas fa-exclamation-circle"></i>
                            <h2>Primary Concern</h2>
                        </div>
                        <div class="card-body">
                            {{if .TopIssue}}
                            <div class="alert alert-warning">
                                <strong>{{.TopIssue}}</strong> ({{.TopIssueCount}} instances detected)
                            </div>
                            {{else}}
                            <div class="alert alert-success">
                                <i class="fas fa-check-circle"></i> No critical issues detected
                            </div>
                            {{end}}

                            {{if .RecommendedActions}}
                            <h4>Recommended Actions:</h4>
                            <ul>
                                {{range .RecommendedActions}}
                                <li>{{.}}</li>
                                {{end}}
                            </ul>
                            {{end}}
                        </div>
                    </div>

                    <div class="card">
                        <div class="card-header">
                            <i class="fas fa-list-check"></i>
                            <h2>Quick Links</h2>
                        </div>
                        <div class="card-body">
                            <div class="quick-links-grid">
                                <a href="security.html" class="quick-link-card">
                                    <i class="fas fa-shield-alt"></i>
                                    <h3>Security Analysis</h3>
                                    <p>{{.Stats.DDoSAttacks}} DDoS • {{.Stats.PortScans}} Port Scans • {{.Stats.IOCMatches}} IOCs</p>
                                </a>
                                <a href="performance.html" class="quick-link-card">
                                    <i class="fas fa-tachometer-alt"></i>
                                    <h3>Performance</h3>
                                    <p>{{.Stats.TCPRetransmissions}} Retrans • {{.Stats.HighRTTFlows}} High RTT</p>
                                </a>
                                <a href="traffic.html" class="quick-link-card">
                                    <i class="fas fa-stream"></i>
                                    <h3>Traffic Analysis</h3>
                                    <p>Top flows and conversations</p>
                                </a>
                                <a href="visualizations.html" class="quick-link-card">
                                    <i class="fas fa-chart-pie"></i>
                                    <h3>Visualizations</h3>
                                    <p>Network maps and charts</p>
                                </a>
                            </div>
                        </div>
                    </div>
                </section>
{{end}}`

	return renderPage(getBaseTemplate()+contentTemplate, pageData, outputPath)
}

func generateExecutiveSummaryPage(data *ReportData, outputPath string) error {
	pageData := &PageData{
		ReportData:  data,
		CurrentPage: "executive-summary",
		PageTitle:   "Executive Summary",
	}

	contentTemplate := `{{define "content"}}
                <section id="executive-summary">
                    <div class="card">
                        <div class="card-header">
                            <i class="fas fa-chart-line"></i>
                            <h2>Executive Summary</h2>
                        </div>
                        <div class="card-body">
                            {{.ExecutiveSummaryExplanation}}
                            
                            {{if eq .HealthStatus "good"}}
                            <div class="health-badge health-good">
                                <i class="fas fa-check-circle"></i> Network Health: GOOD
                            </div>
                            {{else if eq .HealthStatus "warning"}}
                            <div class="health-badge health-warning">
                                <i class="fas fa-exclamation-triangle"></i> Network Health: WARNING
                            </div>
                            {{else}}
                            <div class="health-badge health-critical">
                                <i class="fas fa-times-circle"></i> Network Health: CRITICAL
                            </div>
                            {{end}}

                            <div class="stats-grid">
                                <div class="stat-card">
                                    <span class="stat-value">{{.Stats.TotalTraffic}}</span>
                                    <span class="stat-label"><i class="fas fa-database"></i> Total Traffic</span>
                                </div>
                                <div class="stat-card">
                                    <span class="stat-value">{{.Stats.DevicesDetected}}</span>
                                    <span class="stat-label"><i class="fas fa-laptop"></i> Devices Detected</span>
                                </div>
                                <div class="stat-card {{if gt .Stats.DNSAnomalies 0}}stat-warning{{end}}">
                                    <span class="stat-value">{{.Stats.DNSAnomalies}}</span>
                                    <span class="stat-label"><i class="fas fa-globe"></i> DNS Anomalies</span>
                                </div>
                                <div class="stat-card {{if gt .Stats.TCPRetransmissions 10}}stat-warning{{end}}">
                                    <span class="stat-value">{{.Stats.TCPRetransmissions}}</span>
                                    <span class="stat-label"><i class="fas fa-redo"></i> TCP Retransmissions</span>
                                </div>
                                <div class="stat-card {{if gt .Stats.ARPConflicts 0}}stat-danger{{end}}">
                                    <span class="stat-value">{{.Stats.ARPConflicts}}</span>
                                    <span class="stat-label"><i class="fas fa-network-wired"></i> ARP Conflicts</span>
                                </div>
                                <div class="stat-card {{if gt .Stats.SuspiciousTraffic 0}}stat-danger{{end}}">
                                    <span class="stat-value">{{.Stats.SuspiciousTraffic}}</span>
                                    <span class="stat-label"><i class="fas fa-exclamation-triangle"></i> Suspicious Traffic</span>
                                </div>
                                <div class="stat-card">
                                    <span class="stat-value">{{.Stats.TLSCerts}}</span>
                                    <span class="stat-label"><i class="fas fa-lock"></i> TLS Certificates</span>
                                </div>
                                <div class="stat-card {{if gt .Stats.HTTPErrors 0}}stat-warning{{end}}">
                                    <span class="stat-value">{{.Stats.HTTPErrors}}</span>
                                    <span class="stat-label"><i class="fas fa-globe"></i> HTTP Errors</span>
                                </div>
                            </div>

                            <div class="risk-assessment">
                                <h3><i class="fas fa-chart-bar"></i> Risk Assessment</h3>
                                <div class="risk-meter">
                                    <div class="risk-score {{.RiskLevel}}">{{.RiskScore}}</div>
                                    <div class="risk-label">Risk Score (0-100)</div>
                                </div>
                                <div class="risk-breakdown">
                                    <div class="risk-category">
                                        <span class="risk-category-label">Security Threats:</span>
                                        <span class="risk-category-value">{{.Stats.DDoSAttacks}} DDoS, {{.Stats.PortScans}} Scans, {{.Stats.IOCMatches}} IOCs</span>
                                    </div>
                                    <div class="risk-category">
                                        <span class="risk-category-label">Performance Issues:</span>
                                        <span class="risk-category-value">{{.Stats.TCPRetransmissions}} Retransmissions, {{.Stats.FailedHandshakes}} Failed Handshakes</span>
                                    </div>
                                    <div class="risk-category">
                                        <span class="risk-category-label">Configuration Concerns:</span>
                                        <span class="risk-category-value">{{.Stats.DNSAnomalies}} DNS, {{.Stats.ARPConflicts}} ARP, {{.Stats.TLSWeaknesses}} TLS</span>
                                    </div>
                                </div>
                            </div>

                            {{if .NextSteps}}
                            <div class="next-steps">
                                <h3><i class="fas fa-tasks"></i> Next Steps</h3>
                                <ol>
                                    {{range .NextSteps}}
                                    <li>{{.}}</li>
                                    {{end}}
                                </ol>
                            </div>
                            {{end}}
                        </div>
                    </div>

                    <!-- Wireshark Filter Guide -->
                    <div class="card" id="wireshark-guide">
                        <div class="card-header">
                            <i class="fas fa-filter"></i>
                            <h2>Wireshark Filter Quick Reference</h2>
                        </div>
                        <div class="card-body">
                            <p>Every finding in this report includes a ready-to-use Wireshark filter. Click the <strong>Copy</strong> button next to any filter, then paste it into Wireshark's display filter bar.</p>
                            
                            <h3>Quick Examples:</h3>
                            <div class="filter-examples">
                                <p><strong>View all TCP retransmissions:</strong></p>
                                <code class="wireshark-filter">tcp.analysis.retransmission</code>
                                <button class="copy-filter-btn" onclick="copyToClipboard('tcp.analysis.retransmission')" title="Copy filter">
                                    <i class="fas fa-copy"></i> Copy
                                </button>
                                
                                <p><strong>View DNS queries:</strong></p>
                                <code class="wireshark-filter">dns and dns.flags.response == 0</code>
                                <button class="copy-filter-btn" onclick="copyToClipboard('dns and dns.flags.response == 0')" title="Copy filter">
                                    <i class="fas fa-copy"></i> Copy
                                </button>
                                
                                <p><strong>View failed TCP handshakes:</strong></p>
                                <code class="wireshark-filter">tcp.flags.syn == 1 and tcp.flags.ack == 0</code>
                                <button class="copy-filter-btn" onclick="copyToClipboard('tcp.flags.syn == 1 and tcp.flags.ack == 0')" title="Copy filter">
                                    <i class="fas fa-copy"></i> Copy
                                </button>
                            </div>
                        </div>
                    </div>
                </section>
{{end}}`

	return renderPage(getBaseTemplate()+contentTemplate, pageData, outputPath)
}

// renderPage renders a template to a file
func renderPage(templateStr string, data interface{}, outputPath string) error {
	tmpl, err := template.New("page").Funcs(template.FuncMap{
		"formatUnixTimeShort": func(t interface{}) string {
			switch v := t.(type) {
			case int64:
				return time.Unix(v, 0).Format("15:04:05")
			case float64:
				return time.Unix(int64(v), 0).Format("15:04:05")
			case int:
				return time.Unix(int64(v), 0).Format("15:04:05")
			default:
				return fmt.Sprintf("%v", t)
			}
		},
	}).Parse(templateStr)
	if err != nil {
		return fmt.Errorf("failed to parse template: %w", err)
	}

	f, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer f.Close()

	if err := tmpl.Execute(f, data); err != nil {
		return fmt.Errorf("failed to execute template: %w", err)
	}

	return nil
}
