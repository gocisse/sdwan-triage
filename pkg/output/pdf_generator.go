package output

import (
	"fmt"
	"time"

	"github.com/gocisse/sdwan-triage/pkg/config"
	"github.com/gocisse/sdwan-triage/pkg/models"
	"github.com/jung-kurt/gofpdf"
)

// PDFGenerator handles PDF report generation using pure Go
type PDFGenerator struct {
	pdf      *gofpdf.Fpdf
	config   *config.Config
	pageNum  int
	fileName string
}

// Color definitions for the PDF
var (
	colorPrimary   = []int{41, 128, 185}  // Blue
	colorSuccess   = []int{40, 167, 69}   // Green
	colorWarning   = []int{255, 193, 7}   // Yellow
	colorDanger    = []int{220, 53, 69}   // Red
	colorLight     = []int{248, 249, 250} // Light gray
	colorTableHead = []int{233, 236, 239} // Table header gray
)

// NewPDFGenerator creates a new PDF generator
func NewPDFGenerator() *PDFGenerator {
	return &PDFGenerator{}
}

// IsAvailable always returns true for pure Go implementation
func (g *PDFGenerator) IsAvailable() bool {
	return true
}

// GetInstallInstructions returns empty string as no external deps needed
func (g *PDFGenerator) GetInstallInstructions() string {
	return ""
}

// GeneratePDF generates a PDF report from the TriageReport
func (g *PDFGenerator) GeneratePDF(report *models.TriageReport, pdfPath, pcapFile string) error {
	cfg := config.DefaultConfig()
	return g.GeneratePDFWithConfig(report, pdfPath, pcapFile, cfg)
}

// GeneratePDFWithConfig generates a PDF report with custom configuration
func (g *PDFGenerator) GeneratePDFWithConfig(report *models.TriageReport, pdfPath, pcapFile string, cfg *config.Config) error {
	g.config = cfg
	g.fileName = pdfPath

	// Initialize PDF - Portrait, millimeters, A4
	g.pdf = gofpdf.New("P", "mm", "A4", "")
	g.pdf.SetMargins(15, 15, 15)
	g.pdf.SetAutoPageBreak(true, 20)

	// Set up footer with page numbers
	g.pdf.SetFooterFunc(func() {
		g.pdf.SetY(-15)
		g.pdf.SetFont("Arial", "I", 8)
		g.pdf.SetTextColor(128, 128, 128)
		g.pdf.CellFormat(0, 10, fmt.Sprintf("Page %d - SD-WAN Triage Report", g.pdf.PageNo()), "", 0, "C", false, 0, "")
	})

	// Add first page
	g.pdf.AddPage()

	// Generate report sections
	g.addTitle(pcapFile)
	g.addExecutiveSummary(report)
	g.addRiskAssessment(report)
	g.addRecommendedActions(report)

	// Add findings tables
	if len(report.DNSAnomalies) > 0 {
		g.addDNSAnomaliesTable(report)
	}
	if len(report.TCPRetransmissions) > 0 {
		g.addTCPRetransmissionsTable(report)
	}
	if len(report.ARPConflicts) > 0 {
		g.addARPConflictsTable(report)
	}
	if len(report.SuspiciousTraffic) > 0 {
		g.addSuspiciousTrafficTable(report)
	}
	if len(report.FailedHandshakes) > 0 {
		g.addFailedHandshakesTable(report)
	}
	if len(report.Security.DDoSFindings) > 0 {
		g.addDDoSFindingsTable(report)
	}
	if len(report.Security.PortScanFindings) > 0 {
		g.addPortScanFindingsTable(report)
	}

	// Add traffic summary
	g.addTrafficSummary(report)

	// Output file
	return g.pdf.OutputFileAndClose(pdfPath)
}

// addTitle adds the report title and header
func (g *PDFGenerator) addTitle(pcapFile string) {
	// Title background
	g.pdf.SetFillColor(colorPrimary[0], colorPrimary[1], colorPrimary[2])
	g.pdf.Rect(0, 0, 210, 45, "F")

	// Title text
	g.pdf.SetTextColor(255, 255, 255)
	g.pdf.SetFont("Arial", "B", 24)
	g.pdf.SetY(12)
	g.pdf.CellFormat(0, 10, "SD-WAN Network Triage Report", "", 1, "C", false, 0, "")

	g.pdf.SetFont("Arial", "", 12)
	g.pdf.CellFormat(0, 8, "Comprehensive Network Analysis", "", 1, "C", false, 0, "")

	g.pdf.SetFont("Arial", "I", 10)
	g.pdf.CellFormat(0, 6, fmt.Sprintf("Generated: %s | File: %s", time.Now().Format("2006-01-02 15:04:05"), pcapFile), "", 1, "C", false, 0, "")

	// Reset text color
	g.pdf.SetTextColor(0, 0, 0)
	g.pdf.Ln(10)
}

// addExecutiveSummary adds the executive summary section
func (g *PDFGenerator) addExecutiveSummary(report *models.TriageReport) {
	g.addSectionHeader("Executive Summary")

	// Calculate stats
	dnsAnomalies := len(report.DNSAnomalies)
	tcpRetrans := len(report.TCPRetransmissions)
	arpConflicts := len(report.ARPConflicts)
	suspiciousTraffic := len(report.SuspiciousTraffic)
	failedHandshakes := len(report.FailedHandshakes)
	httpErrors := len(report.HTTPErrors)
	highRTTFlows := len(report.RTTAnalysis)
	devicesDetected := len(report.DeviceFingerprinting)

	// Stats grid
	g.pdf.SetFont("Arial", "", 10)

	// Row 1
	g.addStatCell("DNS Anomalies", fmt.Sprintf("%d", dnsAnomalies), dnsAnomalies > 0)
	g.addStatCell("TCP Retransmissions", fmt.Sprintf("%d", tcpRetrans), tcpRetrans > 10)
	g.addStatCell("ARP Conflicts", fmt.Sprintf("%d", arpConflicts), arpConflicts > 0)
	g.addStatCell("Suspicious Traffic", fmt.Sprintf("%d", suspiciousTraffic), suspiciousTraffic > 0)
	g.pdf.Ln(12)

	// Row 2
	g.addStatCell("Failed Handshakes", fmt.Sprintf("%d", failedHandshakes), failedHandshakes > 0)
	g.addStatCell("HTTP Errors", fmt.Sprintf("%d", httpErrors), httpErrors > 0)
	g.addStatCell("High RTT Flows", fmt.Sprintf("%d", highRTTFlows), highRTTFlows > 0)
	g.addStatCell("Devices Detected", fmt.Sprintf("%d", devicesDetected), false)
	g.pdf.Ln(12)

	// Traffic summary
	g.pdf.SetFont("Arial", "B", 10)
	g.pdf.CellFormat(45, 8, "Total Traffic:", "", 0, "L", false, 0, "")
	g.pdf.SetFont("Arial", "", 10)
	g.pdf.CellFormat(45, 8, formatBytesForTemplate(report.TotalBytes), "", 0, "L", false, 0, "")

	g.pdf.SetFont("Arial", "B", 10)
	g.pdf.CellFormat(35, 8, "HTTP/2 Flows:", "", 0, "L", false, 0, "")
	g.pdf.SetFont("Arial", "", 10)
	g.pdf.CellFormat(25, 8, fmt.Sprintf("%d", len(report.HTTP2Flows)), "", 0, "L", false, 0, "")

	g.pdf.SetFont("Arial", "B", 10)
	g.pdf.CellFormat(30, 8, "QUIC Flows:", "", 0, "L", false, 0, "")
	g.pdf.SetFont("Arial", "", 10)
	g.pdf.CellFormat(0, 8, fmt.Sprintf("%d", len(report.QUICFlows)), "", 1, "L", false, 0, "")

	g.pdf.Ln(5)
}

// addRiskAssessment adds the risk score section
func (g *PDFGenerator) addRiskAssessment(report *models.TriageReport) {
	g.addSectionHeader("Risk Assessment")

	// Risk score box
	riskColor := colorSuccess
	switch report.RiskLevel {
	case "Medium":
		riskColor = colorWarning
	case "High":
		riskColor = []int{253, 126, 20} // Orange
	case "Critical":
		riskColor = colorDanger
	}

	// Risk score display
	g.pdf.SetFillColor(riskColor[0], riskColor[1], riskColor[2])
	startX := g.pdf.GetX()
	startY := g.pdf.GetY()
	g.pdf.Rect(startX, startY, 40, 25, "F")

	g.pdf.SetTextColor(255, 255, 255)
	g.pdf.SetFont("Arial", "B", 24)
	g.pdf.SetXY(startX, startY+3)
	g.pdf.CellFormat(40, 12, fmt.Sprintf("%d", report.RiskScore), "", 0, "C", false, 0, "")
	g.pdf.SetFont("Arial", "", 10)
	g.pdf.SetXY(startX, startY+15)
	g.pdf.CellFormat(40, 8, report.RiskLevel, "", 0, "C", false, 0, "")

	// Risk details
	g.pdf.SetTextColor(0, 0, 0)
	g.pdf.SetXY(startX+45, startY)
	g.pdf.SetFont("Arial", "B", 12)
	g.pdf.CellFormat(0, 8, "Risk Score Analysis", "", 1, "L", false, 0, "")

	g.pdf.SetX(startX + 45)
	g.pdf.SetFont("Arial", "", 10)

	if report.TopIssue != "" {
		g.pdf.CellFormat(0, 6, fmt.Sprintf("Primary Concern: %d %s", report.TopIssueCount, report.TopIssue), "", 1, "L", false, 0, "")
		g.pdf.SetX(startX + 45)
	}

	// Calculate total findings
	totalFindings := len(report.DNSAnomalies) + len(report.ARPConflicts) + len(report.TCPRetransmissions) +
		len(report.SuspiciousTraffic) + len(report.FailedHandshakes)
	g.pdf.CellFormat(0, 6, fmt.Sprintf("Total Findings: %d", totalFindings), "", 1, "L", false, 0, "")

	g.pdf.SetY(startY + 30)
	g.pdf.Ln(5)
}

// addRecommendedActions adds the recommended actions section
func (g *PDFGenerator) addRecommendedActions(report *models.TriageReport) {
	if len(report.RecommendedActions) == 0 {
		return
	}

	g.addSectionHeader("Recommended Actions")

	for i, action := range report.RecommendedActions {
		if i >= 5 {
			break // Limit to 5 actions
		}

		// Determine action severity color
		actionColor := colorSuccess
		if len(action) > 8 {
			switch action[:8] {
			case "CRITICAL":
				actionColor = colorDanger
			case "HIGH: TL", "HIGH: Ex":
				actionColor = []int{253, 126, 20}
			case "MEDIUM: ":
				actionColor = colorWarning
			}
		}

		// Action indicator
		g.pdf.SetFillColor(actionColor[0], actionColor[1], actionColor[2])
		startX := g.pdf.GetX()
		startY := g.pdf.GetY()
		g.pdf.Rect(startX, startY, 3, 8, "F")

		g.pdf.SetX(startX + 5)
		g.pdf.SetFont("Arial", "", 9)
		g.pdf.MultiCell(170, 5, action, "", "L", false)
		g.pdf.Ln(2)
	}

	g.pdf.Ln(5)
}

// addDNSAnomaliesTable adds the DNS anomalies table
func (g *PDFGenerator) addDNSAnomaliesTable(report *models.TriageReport) {
	g.checkPageBreak(50)
	g.addSectionHeader("DNS Anomalies")

	// Table header
	g.pdf.SetFont("Arial", "B", 9)
	g.pdf.SetFillColor(colorTableHead[0], colorTableHead[1], colorTableHead[2])
	g.pdf.CellFormat(55, 8, "Query", "1", 0, "L", true, 0, "")
	g.pdf.CellFormat(35, 8, "Answer IP", "1", 0, "L", true, 0, "")
	g.pdf.CellFormat(30, 8, "Server", "1", 0, "L", true, 0, "")
	g.pdf.CellFormat(60, 8, "Reason", "1", 1, "L", true, 0, "")

	// Table rows
	g.pdf.SetFont("Arial", "", 8)
	maxRows := minInt(10, len(report.DNSAnomalies))
	for i := 0; i < maxRows; i++ {
		anomaly := report.DNSAnomalies[i]
		g.pdf.CellFormat(55, 7, truncateString(anomaly.Query, 30), "1", 0, "L", false, 0, "")
		g.pdf.CellFormat(35, 7, anomaly.AnswerIP, "1", 0, "L", false, 0, "")
		g.pdf.CellFormat(30, 7, anomaly.ServerIP, "1", 0, "L", false, 0, "")
		g.pdf.CellFormat(60, 7, truncateString(anomaly.Reason, 35), "1", 1, "L", false, 0, "")
	}

	if len(report.DNSAnomalies) > 10 {
		g.pdf.SetFont("Arial", "I", 8)
		g.pdf.CellFormat(0, 6, fmt.Sprintf("... and %d more", len(report.DNSAnomalies)-10), "", 1, "L", false, 0, "")
	}

	g.pdf.Ln(5)
}

// addTCPRetransmissionsTable adds the TCP retransmissions table
func (g *PDFGenerator) addTCPRetransmissionsTable(report *models.TriageReport) {
	g.checkPageBreak(50)
	g.addSectionHeader("TCP Retransmissions")

	// Table header
	g.pdf.SetFont("Arial", "B", 9)
	g.pdf.SetFillColor(colorTableHead[0], colorTableHead[1], colorTableHead[2])
	g.pdf.CellFormat(55, 8, "Source", "1", 0, "L", true, 0, "")
	g.pdf.CellFormat(55, 8, "Destination", "1", 0, "L", true, 0, "")
	g.pdf.CellFormat(35, 8, "Source Port", "1", 0, "C", true, 0, "")
	g.pdf.CellFormat(35, 8, "Dest Port", "1", 1, "C", true, 0, "")

	// Table rows
	g.pdf.SetFont("Arial", "", 8)
	maxRows := minInt(10, len(report.TCPRetransmissions))
	for i := 0; i < maxRows; i++ {
		retrans := report.TCPRetransmissions[i]
		g.pdf.CellFormat(55, 7, retrans.SrcIP, "1", 0, "L", false, 0, "")
		g.pdf.CellFormat(55, 7, retrans.DstIP, "1", 0, "L", false, 0, "")
		g.pdf.CellFormat(35, 7, fmt.Sprintf("%d", retrans.SrcPort), "1", 0, "C", false, 0, "")
		g.pdf.CellFormat(35, 7, fmt.Sprintf("%d", retrans.DstPort), "1", 1, "C", false, 0, "")
	}

	if len(report.TCPRetransmissions) > 10 {
		g.pdf.SetFont("Arial", "I", 8)
		g.pdf.CellFormat(0, 6, fmt.Sprintf("... and %d more", len(report.TCPRetransmissions)-10), "", 1, "L", false, 0, "")
	}

	g.pdf.Ln(5)
}

// addARPConflictsTable adds the ARP conflicts table
func (g *PDFGenerator) addARPConflictsTable(report *models.TriageReport) {
	g.checkPageBreak(40)
	g.addSectionHeader("ARP Conflicts")

	// Table header
	g.pdf.SetFont("Arial", "B", 9)
	g.pdf.SetFillColor(colorTableHead[0], colorTableHead[1], colorTableHead[2])
	g.pdf.CellFormat(50, 8, "IP Address", "1", 0, "L", true, 0, "")
	g.pdf.CellFormat(65, 8, "MAC Address 1", "1", 0, "L", true, 0, "")
	g.pdf.CellFormat(65, 8, "MAC Address 2", "1", 1, "L", true, 0, "")

	// Table rows
	g.pdf.SetFont("Arial", "", 8)
	maxRows := minInt(10, len(report.ARPConflicts))
	for i := 0; i < maxRows; i++ {
		conflict := report.ARPConflicts[i]
		g.pdf.CellFormat(50, 7, conflict.IP, "1", 0, "L", false, 0, "")
		g.pdf.CellFormat(65, 7, conflict.MAC1, "1", 0, "L", false, 0, "")
		g.pdf.CellFormat(65, 7, conflict.MAC2, "1", 1, "L", false, 0, "")
	}

	g.pdf.Ln(5)
}

// addSuspiciousTrafficTable adds the suspicious traffic table
func (g *PDFGenerator) addSuspiciousTrafficTable(report *models.TriageReport) {
	g.checkPageBreak(50)
	g.addSectionHeader("Suspicious Traffic")

	// Table header
	g.pdf.SetFont("Arial", "B", 9)
	g.pdf.SetFillColor(colorTableHead[0], colorTableHead[1], colorTableHead[2])
	g.pdf.CellFormat(45, 8, "Source", "1", 0, "L", true, 0, "")
	g.pdf.CellFormat(45, 8, "Destination", "1", 0, "L", true, 0, "")
	g.pdf.CellFormat(90, 8, "Reason", "1", 1, "L", true, 0, "")

	// Table rows
	g.pdf.SetFont("Arial", "", 8)
	maxRows := minInt(10, len(report.SuspiciousTraffic))
	for i := 0; i < maxRows; i++ {
		traffic := report.SuspiciousTraffic[i]
		g.pdf.CellFormat(45, 7, traffic.SrcIP, "1", 0, "L", false, 0, "")
		g.pdf.CellFormat(45, 7, traffic.DstIP, "1", 0, "L", false, 0, "")
		g.pdf.CellFormat(90, 7, truncateString(traffic.Reason, 50), "1", 1, "L", false, 0, "")
	}

	if len(report.SuspiciousTraffic) > 10 {
		g.pdf.SetFont("Arial", "I", 8)
		g.pdf.CellFormat(0, 6, fmt.Sprintf("... and %d more", len(report.SuspiciousTraffic)-10), "", 1, "L", false, 0, "")
	}

	g.pdf.Ln(5)
}

// addFailedHandshakesTable adds the failed handshakes table
func (g *PDFGenerator) addFailedHandshakesTable(report *models.TriageReport) {
	g.checkPageBreak(50)
	g.addSectionHeader("Failed TCP Handshakes")

	// Table header
	g.pdf.SetFont("Arial", "B", 9)
	g.pdf.SetFillColor(colorTableHead[0], colorTableHead[1], colorTableHead[2])
	g.pdf.CellFormat(55, 8, "Source", "1", 0, "L", true, 0, "")
	g.pdf.CellFormat(55, 8, "Destination", "1", 0, "L", true, 0, "")
	g.pdf.CellFormat(35, 8, "Source Port", "1", 0, "C", true, 0, "")
	g.pdf.CellFormat(35, 8, "Dest Port", "1", 1, "C", true, 0, "")

	// Table rows
	g.pdf.SetFont("Arial", "", 8)
	maxRows := minInt(10, len(report.FailedHandshakes))
	for i := 0; i < maxRows; i++ {
		handshake := report.FailedHandshakes[i]
		g.pdf.CellFormat(55, 7, handshake.SrcIP, "1", 0, "L", false, 0, "")
		g.pdf.CellFormat(55, 7, handshake.DstIP, "1", 0, "L", false, 0, "")
		g.pdf.CellFormat(35, 7, fmt.Sprintf("%d", handshake.SrcPort), "1", 0, "C", false, 0, "")
		g.pdf.CellFormat(35, 7, fmt.Sprintf("%d", handshake.DstPort), "1", 1, "C", false, 0, "")
	}

	if len(report.FailedHandshakes) > 10 {
		g.pdf.SetFont("Arial", "I", 8)
		g.pdf.CellFormat(0, 6, fmt.Sprintf("... and %d more", len(report.FailedHandshakes)-10), "", 1, "L", false, 0, "")
	}

	g.pdf.Ln(5)
}

// addDDoSFindingsTable adds the DDoS findings table
func (g *PDFGenerator) addDDoSFindingsTable(report *models.TriageReport) {
	g.checkPageBreak(50)
	g.addSectionHeader("DDoS Attack Indicators")

	// Table header
	g.pdf.SetFont("Arial", "B", 9)
	g.pdf.SetFillColor(colorTableHead[0], colorTableHead[1], colorTableHead[2])
	g.pdf.CellFormat(40, 8, "Source IP", "1", 0, "L", true, 0, "")
	g.pdf.CellFormat(40, 8, "Target IP", "1", 0, "L", true, 0, "")
	g.pdf.CellFormat(35, 8, "Type", "1", 0, "L", true, 0, "")
	g.pdf.CellFormat(30, 8, "Packets", "1", 0, "C", true, 0, "")
	g.pdf.CellFormat(35, 8, "Severity", "1", 1, "L", true, 0, "")

	// Table rows
	g.pdf.SetFont("Arial", "", 8)
	maxRows := minInt(10, len(report.Security.DDoSFindings))
	for i := 0; i < maxRows; i++ {
		finding := report.Security.DDoSFindings[i]
		g.pdf.CellFormat(40, 7, finding.SourceIP, "1", 0, "L", false, 0, "")
		g.pdf.CellFormat(40, 7, finding.TargetIP, "1", 0, "L", false, 0, "")
		g.pdf.CellFormat(35, 7, finding.Type, "1", 0, "L", false, 0, "")
		g.pdf.CellFormat(30, 7, fmt.Sprintf("%d", finding.PacketCount), "1", 0, "C", false, 0, "")
		g.pdf.CellFormat(35, 7, finding.Severity, "1", 1, "L", false, 0, "")
	}

	g.pdf.Ln(5)
}

// addPortScanFindingsTable adds the port scan findings table
func (g *PDFGenerator) addPortScanFindingsTable(report *models.TriageReport) {
	g.checkPageBreak(50)
	g.addSectionHeader("Port Scan Indicators")

	// Table header
	g.pdf.SetFont("Arial", "B", 9)
	g.pdf.SetFillColor(colorTableHead[0], colorTableHead[1], colorTableHead[2])
	g.pdf.CellFormat(50, 8, "Source IP", "1", 0, "L", true, 0, "")
	g.pdf.CellFormat(50, 8, "Target IP", "1", 0, "L", true, 0, "")
	g.pdf.CellFormat(40, 8, "Type", "1", 0, "L", true, 0, "")
	g.pdf.CellFormat(40, 8, "Ports Scanned", "1", 1, "C", true, 0, "")

	// Table rows
	g.pdf.SetFont("Arial", "", 8)
	maxRows := minInt(10, len(report.Security.PortScanFindings))
	for i := 0; i < maxRows; i++ {
		finding := report.Security.PortScanFindings[i]
		g.pdf.CellFormat(50, 7, finding.SourceIP, "1", 0, "L", false, 0, "")
		g.pdf.CellFormat(50, 7, finding.TargetIP, "1", 0, "L", false, 0, "")
		g.pdf.CellFormat(40, 7, finding.Type, "1", 0, "L", false, 0, "")
		g.pdf.CellFormat(40, 7, fmt.Sprintf("%d", finding.PortsScanned), "1", 1, "C", false, 0, "")
	}

	g.pdf.Ln(5)
}

// addTrafficSummary adds the traffic summary section
func (g *PDFGenerator) addTrafficSummary(report *models.TriageReport) {
	if len(report.TrafficAnalysis) == 0 {
		return
	}

	g.checkPageBreak(60)
	g.addSectionHeader("Top Traffic Flows")

	// Table header
	g.pdf.SetFont("Arial", "B", 9)
	g.pdf.SetFillColor(colorTableHead[0], colorTableHead[1], colorTableHead[2])
	g.pdf.CellFormat(45, 8, "Source", "1", 0, "L", true, 0, "")
	g.pdf.CellFormat(45, 8, "Destination", "1", 0, "L", true, 0, "")
	g.pdf.CellFormat(25, 8, "Protocol", "1", 0, "C", true, 0, "")
	g.pdf.CellFormat(35, 8, "Bytes", "1", 0, "R", true, 0, "")
	g.pdf.CellFormat(30, 8, "Percentage", "1", 1, "R", true, 0, "")

	// Table rows
	g.pdf.SetFont("Arial", "", 8)
	maxRows := minInt(10, len(report.TrafficAnalysis))
	for i := 0; i < maxRows; i++ {
		flow := report.TrafficAnalysis[i]
		srcAddr := fmt.Sprintf("%s:%d", flow.SrcIP, flow.SrcPort)
		dstAddr := fmt.Sprintf("%s:%d", flow.DstIP, flow.DstPort)

		g.pdf.CellFormat(45, 7, truncateString(srcAddr, 25), "1", 0, "L", false, 0, "")
		g.pdf.CellFormat(45, 7, truncateString(dstAddr, 25), "1", 0, "L", false, 0, "")
		g.pdf.CellFormat(25, 7, flow.Protocol, "1", 0, "C", false, 0, "")
		g.pdf.CellFormat(35, 7, formatBytesForTemplate(flow.TotalBytes), "1", 0, "R", false, 0, "")
		g.pdf.CellFormat(30, 7, fmt.Sprintf("%.1f%%", flow.Percentage), "1", 1, "R", false, 0, "")
	}

	g.pdf.Ln(5)
}

// Helper functions

// addSectionHeader adds a styled section header
func (g *PDFGenerator) addSectionHeader(title string) {
	g.pdf.SetFont("Arial", "B", 14)
	g.pdf.SetTextColor(colorPrimary[0], colorPrimary[1], colorPrimary[2])
	g.pdf.CellFormat(0, 10, title, "", 1, "L", false, 0, "")
	g.pdf.SetTextColor(0, 0, 0)

	// Underline
	g.pdf.SetDrawColor(colorPrimary[0], colorPrimary[1], colorPrimary[2])
	g.pdf.Line(15, g.pdf.GetY(), 195, g.pdf.GetY())
	g.pdf.Ln(3)
}

// addStatCell adds a stat cell to the grid
func (g *PDFGenerator) addStatCell(label, value string, isWarning bool) {
	startX := g.pdf.GetX()

	if isWarning {
		g.pdf.SetFillColor(colorWarning[0], colorWarning[1], colorWarning[2])
	} else {
		g.pdf.SetFillColor(colorLight[0], colorLight[1], colorLight[2])
	}

	g.pdf.Rect(startX, g.pdf.GetY(), 43, 10, "F")

	g.pdf.SetFont("Arial", "B", 10)
	g.pdf.CellFormat(20, 10, value, "", 0, "C", false, 0, "")
	g.pdf.SetFont("Arial", "", 8)
	g.pdf.CellFormat(23, 10, label, "", 0, "L", false, 0, "")
	g.pdf.SetX(startX + 45)
}

// checkPageBreak checks if we need a new page
func (g *PDFGenerator) checkPageBreak(height float64) {
	if g.pdf.GetY()+height > 280 {
		g.pdf.AddPage()
	}
}

// truncateString truncates a string to maxLen characters
func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

// minInt returns the minimum of two integers
func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// PDFOptions contains options for PDF generation (kept for compatibility)
type PDFOptions struct {
	PageSize     string
	Orientation  string
	MarginTop    string
	MarginBottom string
	MarginLeft   string
	MarginRight  string
	Grayscale    bool
	LowQuality   bool
}

// DefaultPDFOptions returns default PDF generation options
func DefaultPDFOptions() PDFOptions {
	return PDFOptions{
		PageSize:     "A4",
		Orientation:  "Portrait",
		MarginTop:    "15mm",
		MarginBottom: "15mm",
		MarginLeft:   "15mm",
		MarginRight:  "15mm",
		Grayscale:    false,
		LowQuality:   false,
	}
}
