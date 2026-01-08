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
	"strings"
	"time"

	"github.com/gocisse/sdwan-triage/pkg/models"
)

//go:embed assets/css/report.css
var cssContent string

//go:embed assets/js/visualizations.js
var jsContent string

//go:embed assets/templates/report.html
var templateContent embed.FS

// formatUnixTime converts a Unix timestamp (float64 seconds since epoch) to human-readable format
func formatUnixTime(unixTimeFloat float64) string {
	if unixTimeFloat == 0 {
		return "-"
	}
	sec := int64(unixTimeFloat)
	nsec := int64((unixTimeFloat - float64(sec)) * 1e9)
	t := time.Unix(sec, nsec).UTC()
	return t.Format("Monday, January 2, 2006 15:04:05 UTC")
}

// formatUnixTimeShort converts a Unix timestamp to a shorter format for tables
func formatUnixTimeShort(unixTimeFloat float64) string {
	if unixTimeFloat == 0 {
		return "-"
	}
	sec := int64(unixTimeFloat)
	nsec := int64((unixTimeFloat - float64(sec)) * 1e9)
	t := time.Unix(sec, nsec).UTC()
	return t.Format("2006-01-02 15:04:05")
}

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
		HTTPErrors         int
		FailedHandshakes   int
		HTTP2Flows         int
		QUICFlows          int
		HighRTTFlows       int
		DevicesDetected    int
		DNSQueries         int
		BGPIndicators      int
	}

	// Next steps
	NextSteps []string

	// Security Findings
	DNSAnomalies      []DNSAnomalyView
	ARPConflicts      []ARPConflictView
	SuspiciousTraffic []SuspiciousFlowView
	HTTPErrors        []HTTPErrorView
	TLSCerts          []TLSCertView
	BGPIndicators     []BGPIndicatorView

	// Performance Findings
	TCPRetransmissions []TCPFlowView
	HighRTTFlows       []RTTFlowView
	FailedHandshakes   []FailedHandshakeView

	// Protocol Analysis
	DNSDetails           []DNSDetailView
	HTTP2Flows           []HTTP2FlowView
	QUICFlows            []QUICFlowView
	TCPHandshakeStats    TCPHandshakeStatsView
	SYNFlows             []TCPHandshakeFlowView
	SYNACKFlows          []TCPHandshakeFlowView
	SuccessfulHandshakes []TCPHandshakeFlowView
	AppIdentifications   []AppIdentificationView

	// Traffic Analysis
	TopFlows           []TrafficFlowView
	DeviceFingerprints []DeviceFingerprintView
	ProtocolStats      []ProtocolStatView
	TopTalkers         []TopTalkerView
	ApplicationStats   []AppStatView

	// QoS Analysis
	QoSEnabled      bool
	QoSClasses      []QoSClassView
	QoSMismatches   []QoSMismatchView
	QoSTotalPackets uint64

	// Embedded assets
	CSS template.CSS
	JS  template.JS

	// Visualization data (JSON strings)
	NetworkDataJSON   template.JS
	TimelineDataJSON  template.JS
	SankeyDataJSON    template.JS
	ProtocolStatsJSON template.JS
	TopTalkersJSON    template.JS
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

type HTTPErrorView struct {
	Method     string
	URL        string
	StatusCode int
	Reason     string
	SrcIP      string
	DstIP      string
}

type TLSCertView struct {
	Subject    string
	Issuer     string
	NotBefore  string
	NotAfter   string
	ServerIP   string
	ServerName string
}

type FailedHandshakeView struct {
	SrcIP   string
	SrcPort uint16
	DstIP   string
	DstPort uint16
}

type ProtocolStatView struct {
	Protocol string
	Bytes    uint64
	Percent  float64
	Color    string
}

type TopTalkerView struct {
	IP      string
	Bytes   uint64
	Percent float64
	Type    string
}

type BGPIndicatorView struct {
	IPAddress      string
	IPPrefix       string
	ExpectedASN    int
	ExpectedASName string
	ObservedASN    int
	ObservedASName string
	Confidence     string
	Reason         string
	IsAnomaly      bool
}

type DNSDetailView struct {
	QueryName     string
	QueryType     string
	SourceIP      string
	DestinationIP string
	AnswerIPs     string
	ResponseCode  string
	IsAnomalous   bool
	Detail        string
}

type HTTP2FlowView struct {
	SrcIP   string
	SrcPort uint16
	DstIP   string
	DstPort uint16
}

type QUICFlowView struct {
	SrcIP      string
	SrcPort    uint16
	DstIP      string
	DstPort    uint16
	ServerName string
}

type TCPHandshakeStatsView struct {
	TotalSYN        int
	TotalSYNACK     int
	SuccessfulCount int
	FailedCount     int
}

type TCPHandshakeFlowView struct {
	SrcIP     string
	SrcPort   uint16
	DstIP     string
	DstPort   uint16
	Timestamp float64
}

type AppIdentificationView struct {
	Name         string
	Category     string
	Protocol     string
	Port         uint16
	SNI          string
	ByteCount    string
	PacketCount  uint64
	Confidence   string
	IdentifiedBy string
	IsSuspicious bool
	Reason       string
}

type AppStatView struct {
	Name        string
	Port        uint16
	Protocol    string
	PacketCount uint64
	ByteCount   string
}

type QoSClassView struct {
	ClassName       string
	DSCPValue       uint8
	PacketCount     uint64
	ByteCount       string
	Percentage      float64
	RetransmitCount uint64
	RetransmitRate  float64
}

type QoSMismatchView struct {
	Flow          string
	ExpectedClass string
	ActualClass   string
	Reason        string
}

// GenerateHTMLReport generates a professional HTML report using templates
func GenerateHTMLReport(r *models.TriageReport, filename string, pcapFile string) error {
	// Prepare template data
	data := prepareReportData(r, pcapFile)

	// Create template with custom functions
	funcMap := template.FuncMap{
		"formatUnixTime":      formatUnixTime,
		"formatUnixTimeShort": formatUnixTimeShort,
	}

	// Parse template with functions
	tmpl, err := template.New("report").Funcs(funcMap).Parse(getTemplateContent())
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

	// Statistics - comprehensive
	data.Stats.DNSAnomalies = len(r.DNSAnomalies)
	data.Stats.TCPRetransmissions = len(r.TCPRetransmissions)
	data.Stats.ARPConflicts = len(r.ARPConflicts)
	data.Stats.SuspiciousTraffic = len(r.SuspiciousTraffic)
	data.Stats.TLSCerts = len(r.TLSCerts)
	data.Stats.TotalTraffic = formatBytesForTemplate(r.TotalBytes)
	data.Stats.HTTPErrors = len(r.HTTPErrors)
	data.Stats.FailedHandshakes = len(r.FailedHandshakes)
	data.Stats.HTTP2Flows = len(r.HTTP2Flows)
	data.Stats.QUICFlows = len(r.QUICFlows)
	data.Stats.HighRTTFlows = len(r.RTTAnalysis)
	data.Stats.DevicesDetected = len(r.DeviceFingerprinting)
	data.Stats.DNSQueries = len(r.DNSDetails)
	data.Stats.BGPIndicators = len(r.BGPHijackIndicators)

	// Generate next steps
	data.NextSteps = generateNextSteps(r)

	// Security Findings
	data.DNSAnomalies = convertDNSAnomalies(r.DNSAnomalies)
	data.ARPConflicts = convertARPConflicts(r.ARPConflicts)
	data.SuspiciousTraffic = convertSuspiciousTraffic(r.SuspiciousTraffic)
	data.HTTPErrors = convertHTTPErrors(r.HTTPErrors)
	data.TLSCerts = convertTLSCerts(r.TLSCerts)
	data.BGPIndicators = convertBGPIndicators(r.BGPHijackIndicators)

	// Performance Findings
	data.TCPRetransmissions = convertTCPRetransmissions(r.TCPRetransmissions)
	data.HighRTTFlows = convertRTTFlows(r.RTTAnalysis)
	data.FailedHandshakes = convertFailedHandshakes(r.FailedHandshakes)

	// Protocol Analysis
	data.DNSDetails = convertDNSDetails(r.DNSDetails)
	data.HTTP2Flows = convertHTTP2Flows(r.HTTP2Flows)
	data.QUICFlows = convertQUICFlows(r.QUICFlows)
	data.TCPHandshakeStats = convertTCPHandshakeStats(r.TCPHandshakes)
	data.SYNFlows = convertTCPHandshakeFlows(r.TCPHandshakes.SYNFlows)
	data.SYNACKFlows = convertTCPHandshakeFlows(r.TCPHandshakes.SYNACKFlows)
	data.SuccessfulHandshakes = convertTCPHandshakeFlows(r.TCPHandshakes.SuccessfulHandshakes)
	data.AppIdentifications = convertAppIdentifications(r.AppIdentification)

	// Traffic Analysis
	data.TopFlows = convertTopFlows(r.TrafficAnalysis, r.TotalBytes)
	data.DeviceFingerprints = convertDeviceFingerprints(r.DeviceFingerprinting)
	data.ApplicationStats = convertApplicationStats(r.ApplicationBreakdown)

	// Generate protocol stats and top talkers
	data.ProtocolStats, data.TopTalkers = generateTrafficStats(r)

	// QoS Analysis
	if r.QoSAnalysis != nil {
		data.QoSEnabled = true
		data.QoSTotalPackets = r.QoSAnalysis.TotalPackets
		data.QoSClasses = convertQoSClasses(r.QoSAnalysis.ClassDistribution)
		data.QoSMismatches = convertQoSMismatches(r.QoSAnalysis.MismatchedQoS)
	}

	// Generate visualization data
	data.NetworkDataJSON = template.JS(generateNetworkJSON(r))
	data.TimelineDataJSON = template.JS(generateTimelineJSON(r))
	data.SankeyDataJSON = template.JS(generateSankeyJSON(r))
	data.ProtocolStatsJSON = template.JS(generateProtocolStatsJSON(data.ProtocolStats))
	data.TopTalkersJSON = template.JS(generateTopTalkersJSON(data.TopTalkers))

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

func convertHTTPErrors(errors []models.HTTPError) []HTTPErrorView {
	result := make([]HTTPErrorView, len(errors))
	for i, e := range errors {
		result[i] = HTTPErrorView{
			Method:     html.EscapeString(e.Method),
			URL:        html.EscapeString(e.Host + e.Path),
			StatusCode: e.Code,
			Reason:     "",
			SrcIP:      html.EscapeString(e.Host),
			DstIP:      "",
		}
	}
	return result
}

func convertTLSCerts(certs []models.TLSCertInfo) []TLSCertView {
	result := make([]TLSCertView, len(certs))
	for i, c := range certs {
		result[i] = TLSCertView{
			Subject:    html.EscapeString(c.Subject),
			Issuer:     html.EscapeString(c.Issuer),
			NotBefore:  c.NotBefore,
			NotAfter:   c.NotAfter,
			ServerIP:   html.EscapeString(c.ServerIP),
			ServerName: html.EscapeString(c.ServerName),
		}
	}
	return result
}

func convertFailedHandshakes(flows []models.TCPFlow) []FailedHandshakeView {
	result := make([]FailedHandshakeView, len(flows))
	for i, f := range flows {
		result[i] = FailedHandshakeView{
			SrcIP:   html.EscapeString(f.SrcIP),
			SrcPort: f.SrcPort,
			DstIP:   html.EscapeString(f.DstIP),
			DstPort: f.DstPort,
		}
	}
	return result
}

func generateTrafficStats(r *models.TriageReport) ([]ProtocolStatView, []TopTalkerView) {
	// Protocol stats from application breakdown
	protocolBytes := make(map[string]uint64)
	for _, app := range r.ApplicationBreakdown {
		protocolBytes[app.Protocol] += app.ByteCount
	}

	totalBytes := r.TotalBytes
	if totalBytes == 0 {
		for _, b := range protocolBytes {
			totalBytes += b
		}
	}

	colors := map[string]string{
		"TCP":   "#667eea",
		"UDP":   "#28a745",
		"ICMP":  "#ffc107",
		"Other": "#6c757d",
	}

	var protocolStats []ProtocolStatView
	for proto, bytes := range protocolBytes {
		pct := float64(0)
		if totalBytes > 0 {
			pct = float64(bytes) / float64(totalBytes) * 100
		}
		color := colors[proto]
		if color == "" {
			color = colors["Other"]
		}
		protocolStats = append(protocolStats, ProtocolStatView{
			Protocol: proto,
			Bytes:    bytes,
			Percent:  pct,
			Color:    color,
		})
	}

	// Top talkers from traffic analysis
	ipBytes := make(map[string]uint64)
	for _, flow := range r.TrafficAnalysis {
		ipBytes[flow.SrcIP] += flow.TotalBytes
		ipBytes[flow.DstIP] += flow.TotalBytes
	}

	type ipStat struct {
		ip    string
		bytes uint64
	}
	var ipList []ipStat
	for ip, bytes := range ipBytes {
		ipList = append(ipList, ipStat{ip, bytes})
	}
	sort.Slice(ipList, func(i, j int) bool {
		return ipList[i].bytes > ipList[j].bytes
	})

	limit := 10
	if len(ipList) < limit {
		limit = len(ipList)
	}

	topTalkers := make([]TopTalkerView, limit)
	for i := 0; i < limit; i++ {
		pct := float64(0)
		if totalBytes > 0 {
			pct = float64(ipList[i].bytes) / float64(totalBytes) * 100
		}
		ipType := "external"
		if models.IsPrivateOrReservedIP(ipList[i].ip) {
			ipType = "internal"
		}
		topTalkers[i] = TopTalkerView{
			IP:      ipList[i].ip,
			Bytes:   ipList[i].bytes,
			Percent: pct,
			Type:    ipType,
		}
	}

	return protocolStats, topTalkers
}

func generateProtocolStatsJSON(stats []ProtocolStatView) string {
	jsonBytes, _ := json.Marshal(stats)
	return string(jsonBytes)
}

func generateTopTalkersJSON(talkers []TopTalkerView) string {
	jsonBytes, _ := json.Marshal(talkers)
	return string(jsonBytes)
}

func convertBGPIndicators(indicators []models.BGPIndicator) []BGPIndicatorView {
	result := make([]BGPIndicatorView, len(indicators))
	for i, ind := range indicators {
		result[i] = BGPIndicatorView{
			IPAddress:      html.EscapeString(ind.IPAddress),
			IPPrefix:       html.EscapeString(ind.IPPrefix),
			ExpectedASN:    ind.ExpectedASN,
			ExpectedASName: html.EscapeString(ind.ExpectedASName),
			ObservedASN:    ind.ObservedASN,
			ObservedASName: html.EscapeString(ind.ObservedASName),
			Confidence:     html.EscapeString(ind.Confidence),
			Reason:         html.EscapeString(ind.Reason),
			IsAnomaly:      ind.IsAnomaly,
		}
	}
	return result
}

func convertDNSDetails(records []models.DNSRecord) []DNSDetailView {
	result := make([]DNSDetailView, len(records))
	for i, r := range records {
		answerIPs := ""
		if len(r.AnswerIPs) > 0 {
			answerIPs = strings.Join(r.AnswerIPs, ", ")
		}
		respCode := ""
		if r.ResponseCode != nil {
			respCode = fmt.Sprintf("%d", *r.ResponseCode)
		}
		result[i] = DNSDetailView{
			QueryName:     html.EscapeString(r.QueryName),
			QueryType:     html.EscapeString(r.QueryType),
			SourceIP:      html.EscapeString(r.SourceIP),
			DestinationIP: html.EscapeString(r.DestinationIP),
			AnswerIPs:     html.EscapeString(answerIPs),
			ResponseCode:  respCode,
			IsAnomalous:   r.IsAnomalous,
			Detail:        html.EscapeString(r.Detail),
		}
	}
	return result
}

func convertHTTP2Flows(flows []models.TCPFlow) []HTTP2FlowView {
	result := make([]HTTP2FlowView, len(flows))
	for i, f := range flows {
		result[i] = HTTP2FlowView{
			SrcIP:   html.EscapeString(f.SrcIP),
			SrcPort: f.SrcPort,
			DstIP:   html.EscapeString(f.DstIP),
			DstPort: f.DstPort,
		}
	}
	return result
}

func convertQUICFlows(flows []models.UDPFlow) []QUICFlowView {
	result := make([]QUICFlowView, len(flows))
	for i, f := range flows {
		result[i] = QUICFlowView{
			SrcIP:      html.EscapeString(f.SrcIP),
			SrcPort:    f.SrcPort,
			DstIP:      html.EscapeString(f.DstIP),
			DstPort:    f.DstPort,
			ServerName: html.EscapeString(f.ServerName),
		}
	}
	return result
}

func convertTCPHandshakeStats(hs models.TCPHandshakeAnalysis) TCPHandshakeStatsView {
	return TCPHandshakeStatsView{
		TotalSYN:        len(hs.SYNFlows),
		TotalSYNACK:     len(hs.SYNACKFlows),
		SuccessfulCount: len(hs.SuccessfulHandshakes),
		FailedCount:     len(hs.FailedHandshakeAttempts),
	}
}

func convertTCPHandshakeFlows(flows []models.TCPHandshakeFlow) []TCPHandshakeFlowView {
	result := make([]TCPHandshakeFlowView, len(flows))
	for i, f := range flows {
		result[i] = TCPHandshakeFlowView{
			SrcIP:     html.EscapeString(f.SrcIP),
			SrcPort:   f.SrcPort,
			DstIP:     html.EscapeString(f.DstIP),
			DstPort:   f.DstPort,
			Timestamp: f.Timestamp,
		}
	}
	return result
}

func convertAppIdentifications(apps []models.IdentifiedApp) []AppIdentificationView {
	result := make([]AppIdentificationView, len(apps))
	for i, a := range apps {
		result[i] = AppIdentificationView{
			Name:         html.EscapeString(a.Name),
			Category:     html.EscapeString(a.Category),
			Protocol:     html.EscapeString(a.Protocol),
			Port:         a.Port,
			SNI:          html.EscapeString(a.SNI),
			ByteCount:    formatBytesForTemplate(a.ByteCount),
			PacketCount:  a.PacketCount,
			Confidence:   html.EscapeString(a.Confidence),
			IdentifiedBy: html.EscapeString(a.IdentifiedBy),
			IsSuspicious: a.IsSuspicious,
			Reason:       html.EscapeString(a.SuspiciousReason),
		}
	}
	return result
}

func convertApplicationStats(breakdown map[string]models.AppCategory) []AppStatView {
	var result []AppStatView
	for _, app := range breakdown {
		result = append(result, AppStatView{
			Name:        html.EscapeString(app.Name),
			Port:        app.Port,
			Protocol:    html.EscapeString(app.Protocol),
			PacketCount: app.PacketCount,
			ByteCount:   formatBytesForTemplate(app.ByteCount),
		})
	}
	// Sort by packet count descending
	sort.Slice(result, func(i, j int) bool {
		return result[i].PacketCount > result[j].PacketCount
	})
	return result
}

func convertQoSClasses(classes map[string]*models.QoSClassMetrics) []QoSClassView {
	var result []QoSClassView
	for _, c := range classes {
		if c != nil {
			result = append(result, QoSClassView{
				ClassName:       html.EscapeString(c.ClassName),
				DSCPValue:       c.DSCPValue,
				PacketCount:     c.PacketCount,
				ByteCount:       formatBytesForTemplate(c.ByteCount),
				Percentage:      c.Percentage,
				RetransmitCount: c.RetransmitCount,
				RetransmitRate:  c.RetransmitRate,
			})
		}
	}
	// Sort by packet count descending
	sort.Slice(result, func(i, j int) bool {
		return result[i].PacketCount > result[j].PacketCount
	})
	return result
}

func convertQoSMismatches(mismatches []models.QoSMismatch) []QoSMismatchView {
	result := make([]QoSMismatchView, len(mismatches))
	for i, m := range mismatches {
		result[i] = QoSMismatchView{
			Flow:          html.EscapeString(m.Flow),
			ExpectedClass: html.EscapeString(m.ExpectedClass),
			ActualClass:   html.EscapeString(m.ActualClass),
			Reason:        html.EscapeString(m.Reason),
		}
	}
	return result
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
                        <div class="stat-card">
                            <span class="stat-value">{{.Stats.HTTP2Flows}}</span>
                            <span class="stat-label"><i class="fas fa-bolt"></i> HTTP/2 Flows</span>
                        </div>
                        <div class="stat-card">
                            <span class="stat-value">{{.Stats.QUICFlows}}</span>
                            <span class="stat-label"><i class="fas fa-rocket"></i> QUIC Flows</span>
                        </div>
                        <div class="stat-card {{if gt .Stats.HighRTTFlows 0}}stat-warning{{end}}">
                            <span class="stat-value">{{.Stats.HighRTTFlows}}</span>
                            <span class="stat-label"><i class="fas fa-clock"></i> High RTT Flows</span>
                        </div>
                        <div class="stat-card">
                            <span class="stat-value">{{.Stats.DNSQueries}}</span>
                            <span class="stat-label"><i class="fas fa-search"></i> DNS Queries</span>
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
                    <button class="tab" data-tab="tab-protocols"><i class="fas fa-layer-group"></i> Protocols</button>
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

                    {{if .HTTPErrors}}
                    <details>
                        <summary><i class="fas fa-globe"></i> HTTP Errors ({{len .HTTPErrors}})</summary>
                        <div>
                            <table class="data-table">
                                <thead><tr><th>Method</th><th>URL</th><th>Status</th><th>Source</th><th>Destination</th></tr></thead>
                                <tbody>
                                    {{range .HTTPErrors}}
                                    <tr>
                                        <td>{{.Method}}</td>
                                        <td><code>{{.URL}}</code></td>
                                        <td class="severity-high">{{.StatusCode}} {{.Reason}}</td>
                                        <td><code>{{.SrcIP}}</code></td>
                                        <td><code>{{.DstIP}}</code></td>
                                    </tr>
                                    {{end}}
                                </tbody>
                            </table>
                        </div>
                    </details>
                    {{end}}

                    {{if .TLSCerts}}
                    <details>
                        <summary><i class="fas fa-lock"></i> TLS Certificates ({{len .TLSCerts}})</summary>
                        <div>
                            <table class="data-table">
                                <thead><tr><th>Subject</th><th>Issuer</th><th>Valid From</th><th>Valid Until</th><th>Server</th></tr></thead>
                                <tbody>
                                    {{range .TLSCerts}}
                                    <tr>
                                        <td>{{.Subject}}</td>
                                        <td>{{.Issuer}}</td>
                                        <td>{{.NotBefore}}</td>
                                        <td>{{.NotAfter}}</td>
                                        <td><code>{{.ServerIP}}</code> ({{.ServerName}})</td>
                                    </tr>
                                    {{end}}
                                </tbody>
                            </table>
                        </div>
                    </details>
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

                    {{if .FailedHandshakes}}
                    <details>
                        <summary><i class="fas fa-handshake-slash"></i> Failed TCP Handshakes ({{len .FailedHandshakes}})</summary>
                        <div>
                            <table class="data-table">
                                <thead><tr><th>Source</th><th>Destination</th><th>Port</th><th>Action</th></tr></thead>
                                <tbody>
                                    {{range .FailedHandshakes}}
                                    <tr>
                                        <td><code>{{.SrcIP}}:{{.SrcPort}}</code></td>
                                        <td><code>{{.DstIP}}:{{.DstPort}}</code></td>
                                        <td>{{.DstPort}}</td>
                                        <td><button class="btn btn-sm btn-secondary" onclick="toggleAction(this)">Show Action</button></td>
                                    </tr>
                                    <tr class="action-row">
                                        <td colspan="4"><div class="action-content"><h4>Recommended Action</h4><ul><li>Check if destination service is running</li><li>Verify firewall rules allow connection</li><li>Check for network connectivity issues</li></ul></div></td>
                                    </tr>
                                    {{end}}
                                </tbody>
                            </table>
                        </div>
                    </details>
                    {{end}}
                </div>

                <div id="tab-protocols" class="tab-content">
                    <div class="protocol-summary">
                        <h3><i class="fas fa-handshake"></i> TCP Handshake Analysis</h3>
                        <div class="stats-grid" style="grid-template-columns: repeat(4, 1fr);">
                            <div class="stat-card">
                                <span class="stat-value">{{.TCPHandshakeStats.TotalSYN}}</span>
                                <span class="stat-label">SYN Packets</span>
                            </div>
                            <div class="stat-card">
                                <span class="stat-value">{{.TCPHandshakeStats.TotalSYNACK}}</span>
                                <span class="stat-label">SYN-ACK Packets</span>
                            </div>
                            <div class="stat-card">
                                <span class="stat-value">{{.TCPHandshakeStats.SuccessfulCount}}</span>
                                <span class="stat-label">Successful Handshakes</span>
                            </div>
                            <div class="stat-card {{if gt .TCPHandshakeStats.FailedCount 0}}stat-warning{{end}}">
                                <span class="stat-value">{{.TCPHandshakeStats.FailedCount}}</span>
                                <span class="stat-label">Failed Handshakes</span>
                            </div>
                        </div>
                    </div>

                    {{if .SYNFlows}}
                    <details>
                        <summary><i class="fas fa-flag"></i> SYN Flows ({{len .SYNFlows}})</summary>
                        <div>
                            <table class="data-table">
                                <thead><tr><th>Source</th><th>Destination</th><th>Timestamp</th></tr></thead>
                                <tbody>
                                    {{range .SYNFlows}}
                                    <tr>
                                        <td><code>{{.SrcIP}}:{{.SrcPort}}</code></td>
                                        <td><code>{{.DstIP}}:{{.DstPort}}</code></td>
                                        <td>{{formatUnixTimeShort .Timestamp}}</td>
                                    </tr>
                                    {{end}}
                                </tbody>
                            </table>
                        </div>
                    </details>
                    {{end}}

                    {{if .SYNACKFlows}}
                    <details>
                        <summary><i class="fas fa-reply"></i> SYN-ACK Flows ({{len .SYNACKFlows}})</summary>
                        <div>
                            <table class="data-table">
                                <thead><tr><th>Source</th><th>Destination</th><th>Timestamp</th></tr></thead>
                                <tbody>
                                    {{range .SYNACKFlows}}
                                    <tr>
                                        <td><code>{{.SrcIP}}:{{.SrcPort}}</code></td>
                                        <td><code>{{.DstIP}}:{{.DstPort}}</code></td>
                                        <td>{{formatUnixTimeShort .Timestamp}}</td>
                                    </tr>
                                    {{end}}
                                </tbody>
                            </table>
                        </div>
                    </details>
                    {{end}}

                    {{if .SuccessfulHandshakes}}
                    <details>
                        <summary><i class="fas fa-check-circle"></i> Successful Handshakes ({{len .SuccessfulHandshakes}})</summary>
                        <div>
                            <table class="data-table">
                                <thead><tr><th>Source</th><th>Destination</th><th>Timestamp</th></tr></thead>
                                <tbody>
                                    {{range .SuccessfulHandshakes}}
                                    <tr>
                                        <td><code>{{.SrcIP}}:{{.SrcPort}}</code></td>
                                        <td><code>{{.DstIP}}:{{.DstPort}}</code></td>
                                        <td>{{formatUnixTimeShort .Timestamp}}</td>
                                    </tr>
                                    {{end}}
                                </tbody>
                            </table>
                        </div>
                    </details>
                    {{end}}

                    {{if .DNSDetails}}
                    <details open>
                        <summary><i class="fas fa-globe"></i> DNS Query Details ({{len .DNSDetails}})</summary>
                        <div>
                            <table class="data-table">
                                <thead><tr><th>Query Name</th><th>Type</th><th>Source</th><th>DNS Server</th><th>Answer IPs</th><th>Status</th></tr></thead>
                                <tbody>
                                    {{range .DNSDetails}}
                                    <tr class="{{if .IsAnomalous}}severity-row-high{{end}}">
                                        <td><code>{{.QueryName}}</code></td>
                                        <td>{{.QueryType}}</td>
                                        <td><code>{{.SourceIP}}</code></td>
                                        <td><code>{{.DestinationIP}}</code></td>
                                        <td><code>{{.AnswerIPs}}</code></td>
                                        <td>{{if .IsAnomalous}}<span class="badge badge-danger">Anomaly</span>{{else}}<span class="badge badge-success">OK</span>{{end}}</td>
                                    </tr>
                                    {{end}}
                                </tbody>
                            </table>
                        </div>
                    </details>
                    {{else}}
                    <div class="alert alert-info"><i class="fas fa-info-circle"></i> No DNS queries recorded</div>
                    {{end}}

                    {{if .HTTP2Flows}}
                    <details>
                        <summary><i class="fas fa-bolt"></i> HTTP/2 Flows ({{len .HTTP2Flows}})</summary>
                        <div>
                            <table class="data-table">
                                <thead><tr><th>Source</th><th>Destination</th><th>Port</th></tr></thead>
                                <tbody>
                                    {{range .HTTP2Flows}}
                                    <tr>
                                        <td><code>{{.SrcIP}}:{{.SrcPort}}</code></td>
                                        <td><code>{{.DstIP}}:{{.DstPort}}</code></td>
                                        <td>{{.DstPort}}</td>
                                    </tr>
                                    {{end}}
                                </tbody>
                            </table>
                        </div>
                    </details>
                    {{end}}

                    {{if .QUICFlows}}
                    <details>
                        <summary><i class="fas fa-rocket"></i> QUIC Flows ({{len .QUICFlows}})</summary>
                        <div>
                            <table class="data-table">
                                <thead><tr><th>Source</th><th>Destination</th><th>Server Name (SNI)</th></tr></thead>
                                <tbody>
                                    {{range .QUICFlows}}
                                    <tr>
                                        <td><code>{{.SrcIP}}:{{.SrcPort}}</code></td>
                                        <td><code>{{.DstIP}}:{{.DstPort}}</code></td>
                                        <td>{{.ServerName}}</td>
                                    </tr>
                                    {{end}}
                                </tbody>
                            </table>
                        </div>
                    </details>
                    {{end}}

                    {{if .ApplicationStats}}
                    <details>
                        <summary><i class="fas fa-cubes"></i> Application Breakdown ({{len .ApplicationStats}})</summary>
                        <div>
                            <table class="data-table">
                                <thead><tr><th>Application</th><th>Protocol</th><th>Port</th><th>Packets</th><th>Bytes</th></tr></thead>
                                <tbody>
                                    {{range .ApplicationStats}}
                                    <tr>
                                        <td><strong>{{.Name}}</strong></td>
                                        <td>{{.Protocol}}</td>
                                        <td>{{.Port}}</td>
                                        <td>{{.PacketCount}}</td>
                                        <td>{{.ByteCount}}</td>
                                    </tr>
                                    {{end}}
                                </tbody>
                            </table>
                        </div>
                    </details>
                    {{end}}

                    {{if .QoSEnabled}}
                    <details>
                        <summary><i class="fas fa-sliders-h"></i> QoS/DSCP Analysis ({{.QoSTotalPackets}} packets)</summary>
                        <div>
                            {{if .QoSClasses}}
                            <table class="data-table">
                                <thead><tr><th>Traffic Class</th><th>DSCP</th><th>Packets</th><th>Bytes</th><th>%</th><th>Retransmits</th></tr></thead>
                                <tbody>
                                    {{range .QoSClasses}}
                                    <tr>
                                        <td><strong>{{.ClassName}}</strong></td>
                                        <td>{{.DSCPValue}}</td>
                                        <td>{{.PacketCount}}</td>
                                        <td>{{.ByteCount}}</td>
                                        <td>{{printf "%.1f" .Percentage}}%</td>
                                        <td>{{.RetransmitCount}} ({{printf "%.2f" .RetransmitRate}}%)</td>
                                    </tr>
                                    {{end}}
                                </tbody>
                            </table>
                            {{end}}
                            {{if .QoSMismatches}}
                            <h4 style="margin-top: 20px;"><i class="fas fa-exclamation-triangle"></i> QoS Mismatches</h4>
                            <table class="data-table">
                                <thead><tr><th>Flow</th><th>Expected</th><th>Actual</th><th>Reason</th></tr></thead>
                                <tbody>
                                    {{range .QoSMismatches}}
                                    <tr class="severity-row-medium">
                                        <td><code>{{.Flow}}</code></td>
                                        <td>{{.ExpectedClass}}</td>
                                        <td>{{.ActualClass}}</td>
                                        <td>{{.Reason}}</td>
                                    </tr>
                                    {{end}}
                                </tbody>
                            </table>
                            {{end}}
                        </div>
                    </details>
                    {{end}}

                    {{if .BGPIndicators}}
                    <details>
                        <summary><i class="fas fa-route"></i> BGP Hijack Indicators ({{len .BGPIndicators}})</summary>
                        <div>
                            <table class="data-table">
                                <thead><tr><th>IP Address</th><th>Prefix</th><th>Expected AS</th><th>Observed AS</th><th>Confidence</th><th>Status</th></tr></thead>
                                <tbody>
                                    {{range .BGPIndicators}}
                                    <tr class="{{if .IsAnomaly}}severity-row-high{{end}}">
                                        <td><code>{{.IPAddress}}</code></td>
                                        <td>{{.IPPrefix}}</td>
                                        <td>AS{{.ExpectedASN}} ({{.ExpectedASName}})</td>
                                        <td>{{if .ObservedASN}}AS{{.ObservedASN}} ({{.ObservedASName}}){{else}}-{{end}}</td>
                                        <td>{{.Confidence}}</td>
                                        <td>{{if .IsAnomaly}}<span class="badge badge-danger">Anomaly</span>{{else}}<span class="badge badge-success">OK</span>{{end}}</td>
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
                        <summary><i class="fas fa-chart-pie"></i> Protocol Distribution</summary>
                        <div><div id="protocol-chart" class="viz-container" style="height: 350px;"></div></div>
                    </details>
                    <details open>
                        <summary><i class="fas fa-users"></i> Top Talkers</summary>
                        <div><div id="top-talkers-chart" class="viz-container" style="height: 350px;"></div></div>
                    </details>
                    <details>
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
        var protocolStats = {{.ProtocolStatsJSON}};
        var topTalkers = {{.TopTalkersJSON}};
    </script>
    <script>{{.JS}}</script>
</body>
</html>`
}
