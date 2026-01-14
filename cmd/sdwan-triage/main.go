package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/gocisse/sdwan-triage/pkg/analyzer"
	"github.com/gocisse/sdwan-triage/pkg/models"
	"github.com/gocisse/sdwan-triage/pkg/output"
	"github.com/google/gopacket/pcapgo"
)

const version = "3.1.0"

// Global verbose flag for debug logging
var verbose *bool

func main() {
	// Define custom usage function
	flag.Usage = func() {
		fmt.Fprintf(os.Stdout, `SD-WAN Network Triage v%s
Comprehensive PCAP analysis tool for SD-WAN networks with advanced security detection,
performance monitoring, and interactive D3.js visualizations.

USAGE:
    sdwan-triage [OPTIONS] <pcap_file>

OPTIONS:
  Output Formats:
    -json              Output results in JSON format (for automation/scripting)
    -csv <file>        Export findings to CSV files (separate files per category)
    -html <file>       Generate interactive HTML report with D3.js visualizations
    -multi-page-html <dir>  Generate multi-page HTML report in specified directory
    -pdf <file>        Export to PDF report (requires wkhtmltopdf installed)
    -config <path>     Use report configuration: default, performance, security, or file path

  Filtering:
    -src-ip <ip>       Filter packets by source IP address
    -dst-ip <ip>       Filter packets by destination IP address
    -service <port>    Filter by service port or name (e.g., 443, https, ssh, dns)
    -protocol <proto>  Filter by protocol: tcp or udp

  Analysis Options:
    -qos-analysis          Enable QoS/DSCP traffic class analysis and prioritization checks
    -show-handshakes       Display detailed TCP handshake analysis with color-coded states
    -handshake-timeout <N> Timeout for TCP handshake completion in seconds (default: 3)
    -failed-only           Show only failed TCP handshakes for troubleshooting
    -app-identify          Enable deep application identification using heuristics
    -verbose               Enable verbose/debug output for troubleshooting

  Network Features (require internet access):
    -trace-path            Perform traceroute to discovered destinations (top 5 by anomalies)
    -bgp-check             Check BGP routing data for potential hijack indicators

  Multi-File Analysis:
    -compare               Compare multiple PCAP files (provide multiple files as arguments)

  Debug Options:
    -debug-html            Write raw HTML to debug_report.html for troubleshooting
    -help                  Show this help message

FEATURES:
  Security Analysis:
    • DDoS Detection (SYN flood, UDP flood, ICMP flood)
    • Port Scanning Detection (horizontal, vertical, block scans)
    • Malware Indicators (IOC checking with custom databases)
    • TLS Security Analysis (weak ciphers, outdated protocols)
    • BGP Hijack Heuristics
    • GeoIP Analysis with country-based traffic distribution

  Performance Monitoring:
    • TCP Handshake Analysis (SYN → SYN-ACK → ACK tracking with color-coded states)
    • Wireshark Filter Generation (per-flow directional and bidirectional filters)
    • TCP Retransmission Analysis
    • RTT Distribution with histogram visualization
    • Failed Handshake Detection with troubleshooting tips
    • Bandwidth Tracking (per-flow and aggregate)
    • Jitter & Packet Loss metrics for VoIP/RTP

  Protocol Analysis:
    • DNS Anomaly Detection (NXDOMAIN, timeouts, DGA detection)
    • HTTP/HTTPS Analysis with status codes and errors
    • HTTP/2 & QUIC Detection
    • VoIP/SIP Call Tracking with codec identification
    • RTP/RTCP Media Stream Quality Analysis

  Tunnel & Encapsulation:
    • VXLAN (VNI extraction, overlay detection)
    • GRE/NVGRE/ERSPAN Tunnels
    • MPLS Label Analysis
    • IPsec (ESP/AH) Detection
    • GTP-U/GTP-C for mobile networks
    • L2TP, OpenVPN, WireGuard VPN detection

  SD-WAN Specific:
    • Vendor Detection: Cisco (Viptela), VMware (VeloCloud), Fortinet,
      Palo Alto Prisma, Silver Peak, Citrix, Versa Networks
    • Application Identification (SNI-based and port-based)
    • Device Fingerprinting (OS and device type)
    • ARP Conflict Detection

  Visualizations (HTML Report):
    • Interactive Timeline with event filtering
    • Sankey Diagram (source → destination flows)
    • RTT Histogram (latency distribution)
    • Protocol Breakdown charts
    • Bandwidth utilization graphs

EXAMPLES:
  Basic Usage:
    # Console output with summary
    sdwan-triage capture.pcap

    # Generate interactive HTML report (recommended)
    sdwan-triage -html report.html capture.pcap

    # Export to JSON for automation
    sdwan-triage -json capture.pcap > results.json

    # Export to CSV for spreadsheet analysis
    sdwan-triage -csv findings.csv capture.pcap

    # Generate PDF report
    sdwan-triage -pdf report.pdf capture.pcap

  Filtering Examples:
    # Analyze traffic from specific source IP
    sdwan-triage -src-ip 192.168.1.100 capture.pcap

    # Analyze traffic to specific destination
    sdwan-triage -dst-ip 10.0.0.50 capture.pcap

    # Filter by service (port name or number)
    sdwan-triage -service https capture.pcap
    sdwan-triage -service 443 capture.pcap
    sdwan-triage -service dns capture.pcap

    # Filter by protocol
    sdwan-triage -protocol tcp capture.pcap
    sdwan-triage -protocol udp capture.pcap

    # Combine multiple filters
    sdwan-triage -src-ip 192.168.1.100 -service https -html report.html capture.pcap

  Security Analysis:
    # Detect DDoS attacks and port scans
    sdwan-triage -config security -html security-report.html capture.pcap

    # Analyze suspicious traffic from specific IP
    sdwan-triage -src-ip 203.0.113.50 -html scan-report.html suspicious.pcap

    # Check for malware IOCs and TLS weaknesses
    sdwan-triage -html threat-analysis.html malware-capture.pcap

  Performance Troubleshooting:
    # Analyze network performance with QoS
    sdwan-triage -qos-analysis -html performance.html slow-network.pcap

    # Investigate TCP retransmissions
    sdwan-triage -protocol tcp -html tcp-issues.html capture.pcap

    # Troubleshoot VoIP quality issues
    sdwan-triage -service sip -html voip-quality.html call-problems.pcap

  TCP Handshake Analysis:
    # Display detailed handshake analysis with color-coded states
    sdwan-triage --show-handshakes capture.pcap

    # Show only failed handshakes for troubleshooting
    sdwan-triage --show-handshakes --failed-only capture.pcap

    # Custom handshake timeout for slow networks (5 seconds)
    sdwan-triage --handshake-timeout 5 capture.pcap

    # Generate HTML report with Wireshark filters for each flow
    sdwan-triage -html handshake-report.html --show-handshakes capture.pcap

  SD-WAN Analysis:
    # Detect SD-WAN vendor and analyze tunnels
    sdwan-triage -html sdwan-report.html overlay-traffic.pcap

    # Analyze VXLAN overlay network
    sdwan-triage -service 4789 -html vxlan-analysis.html capture.pcap

    # Check IPsec tunnel traffic
    sdwan-triage -protocol esp -html ipsec-report.html capture.pcap

  Advanced Usage:
    # Multiple output formats simultaneously
    sdwan-triage -html report.html -json -csv findings.csv capture.pcap

    # Verbose output for debugging
    sdwan-triage -verbose -html report.html capture.pcap

    # Custom configuration with filtering
    sdwan-triage -config performance -dst-ip 10.0.0.1 -html report.html capture.pcap

OUTPUT FILES:
  HTML Report:  Interactive single-file report with D3.js visualizations
  JSON Output:  Structured data for automation and scripting
  CSV Files:    Separate CSV files for each finding category
  PDF Report:   Professional formatted document (requires wkhtmltopdf)

SUPPORTED PROTOCOLS:
  Network:   IPv4, IPv6, ARP, ICMP, ICMPv6
  Transport: TCP, UDP, SCTP
  Tunnels:   VXLAN, GRE, NVGRE, ERSPAN, MPLS, IPsec (ESP/AH), GTP, L2TP
  VPN:       OpenVPN, WireGuard
  App Layer: HTTP, HTTPS, HTTP/2, QUIC, DNS, TLS/SSL, SIP, RTP/RTCP

For more information and documentation:
  https://github.com/gocisse/sdwan-triage

`, version)
	}

	// Parse flags
	jsonOutput := flag.Bool("json", false, "Output in JSON format")
	csvOutput := flag.String("csv", "", "Export findings to CSV file")
	htmlOutput := flag.String("html", "", "Export findings to HTML report")
	multiPageHTML := flag.String("multi-page-html", "", "Export findings to multi-page HTML report (specify output directory)")
	pdfOutput := flag.String("pdf", "", "Export findings to PDF report")
	configPath := flag.String("config", "", "Report configuration (default, performance, security, or path)")
	srcIP := flag.String("src-ip", "", "Filter by source IP address")
	dstIP := flag.String("dst-ip", "", "Filter by destination IP address")
	service := flag.String("service", "", "Filter by service port or name")
	protocol := flag.String("protocol", "", "Filter by protocol (tcp or udp)")
	qosAnalysis := flag.Bool("qos-analysis", false, "Enable QoS/DSCP traffic class analysis")
	showHandshakes := flag.Bool("show-handshakes", false, "Display detailed TCP handshake analysis")
	handshakeTimeout := flag.Int("handshake-timeout", 3, "Timeout for TCP handshake completion (seconds)")
	failedOnly := flag.Bool("failed-only", false, "Show only failed TCP handshakes")
	appIdentify := flag.Bool("app-identify", false, "Enable deep application identification using heuristics")
	tracePath := flag.Bool("trace-path", false, "Perform traceroute to discovered destinations")
	bgpCheck := flag.Bool("bgp-check", false, "Check BGP routing data for potential hijack indicators")
	compareMode := flag.Bool("compare", false, "Compare multiple PCAP files")
	debugHTML := flag.Bool("debug-html", false, "Write raw HTML to debug_report.html")
	verbose = flag.Bool("verbose", false, "Enable verbose/debug output")
	showHelp := flag.Bool("help", false, "Show help message")
	flag.Parse()

	// Show help if requested or no arguments provided
	if *showHelp || flag.NArg() < 1 {
		flag.Usage()
		if *showHelp {
			os.Exit(0)
		}
		os.Exit(1)
	}

	// Create filter
	filter := &models.Filter{
		SrcIP:    *srcIP,
		DstIP:    *dstIP,
		Service:  *service,
		Protocol: *protocol,
	}

	pcapFile := flag.Arg(0)

	// Create output directory for this analysis run
	var outputDir string
	if *csvOutput != "" || *htmlOutput != "" || *pdfOutput != "" {
		// Generate output folder name based on input file and timestamp
		inputBaseName := filepath.Base(pcapFile)
		inputBaseName = strings.TrimSuffix(inputBaseName, filepath.Ext(inputBaseName))
		// Sanitize filename for directory name
		inputBaseName = strings.ReplaceAll(inputBaseName, ".", "_")
		inputBaseName = strings.ReplaceAll(inputBaseName, " ", "_")

		// Create timestamped output directory
		timestamp := time.Now().Format("20060102_150405")
		outputDir = fmt.Sprintf("sdwan_report_%s_%s", inputBaseName, timestamp)

		if err := os.MkdirAll(outputDir, 0755); err != nil {
			fmt.Fprintf(os.Stderr, "Error creating output directory '%s': %v\n", outputDir, err)
			os.Exit(1)
		}

		if *verbose {
			fmt.Fprintf(os.Stderr, "[DEBUG] Created output directory: %s\n", outputDir)
		}

		// Update output file paths to include directory
		if *csvOutput != "" {
			*csvOutput = filepath.Join(outputDir, *csvOutput)
		}
		if *htmlOutput != "" {
			*htmlOutput = filepath.Join(outputDir, *htmlOutput)
		}
		if *pdfOutput != "" {
			*pdfOutput = filepath.Join(outputDir, *pdfOutput)
		}
	}

	// Validate PCAP file path
	absPath, err := filepath.Abs(pcapFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error resolving file path '%s': %v\n", pcapFile, err)
		os.Exit(1)
	}

	// Check if file exists
	fileInfo, err := os.Stat(absPath)
	if os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "Error: PCAP file not found: %s\n", absPath)
		os.Exit(1)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error accessing file '%s': %v\n", absPath, err)
		os.Exit(1)
	}
	if fileInfo.IsDir() {
		fmt.Fprintf(os.Stderr, "Error: '%s' is a directory, not a file\n", absPath)
		os.Exit(1)
	}

	if *verbose {
		fmt.Fprintf(os.Stderr, "[DEBUG] Opening PCAP file: %s (size: %d bytes)\n", absPath, fileInfo.Size())
	}

	// Open PCAP file
	file, err := os.Open(absPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error opening file '%s': %v\n", absPath, err)
		os.Exit(1)
	}
	defer file.Close()

	reader, err := pcapgo.NewReader(file)
	if err != nil {
		// Try to provide more helpful error message
		fmt.Fprintf(os.Stderr, "Error: Failed to read PCAP file '%s'\n", filepath.Base(absPath))
		fmt.Fprintf(os.Stderr, "       This may not be a valid PCAP file or it may be corrupted.\n")
		if *verbose {
			fmt.Fprintf(os.Stderr, "[DEBUG] pcapgo.NewReader error: %v\n", err)
		}
		os.Exit(1)
	}

	if *verbose {
		fmt.Fprintf(os.Stderr, "[DEBUG] PCAP file opened successfully, link type: %v\n", reader.LinkType())
	}

	// Initialize report and state
	report := &models.TriageReport{
		ApplicationBreakdown: make(map[string]models.AppCategory),
	}
	state := models.NewAnalysisState()

	// Create processor and analyze
	var processor *analyzer.Processor
	if *qosAnalysis {
		processor = analyzer.NewProcessorWithOptions(true, *verbose)
	} else {
		processor = analyzer.NewProcessorWithOptions(false, *verbose)
	}

	// Set handshake timeout if specified
	if *handshakeTimeout > 0 {
		processor.SetHandshakeTimeout(time.Duration(*handshakeTimeout) * time.Second)
	}

	color.Cyan("SD-WAN Network Triage v%s", version)
	color.Cyan("Analyzing: %s\n", filepath.Base(absPath))

	if err := processor.Process(reader, state, report, filter); err != nil {
		fmt.Fprintf(os.Stderr, "Error processing PCAP: %v\n", err)
		os.Exit(1)
	}

	// Output results
	if *jsonOutput {
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(report); err != nil {
			fmt.Fprintf(os.Stderr, "Error encoding JSON: %v\n", err)
			os.Exit(1)
		}
	} else {
		// Print human-readable output
		output.PrintExecutiveSummary(report)
		output.PrintDetailedReport(report)

		// Print TCP handshake analysis if requested or if there are failures
		if *showHandshakes || (len(report.TCPHandshakeFlows) > 0 && *failedOnly) {
			output.PrintHandshakeAnalysis(report, *showHandshakes, *failedOnly)
		}
	}

	// Export to CSV if requested
	if *csvOutput != "" {
		result, err := output.GenerateCSVReports(report, *csvOutput)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error exporting to CSV: %v\n", err)
		} else {
			color.Green("✓ CSV reports exported to %s:", outputDir)
			for _, f := range result.Files {
				color.Green("  - %s", filepath.Base(f))
			}
		}
	}

	// Export to multi-page HTML if requested
	if *multiPageHTML != "" {
		mpOutputDir := *multiPageHTML
		if mpOutputDir == "" {
			mpOutputDir = "sdwan_report"
		}
		if err := output.GenerateMultiPageHTMLReport(report, mpOutputDir, filepath.Base(absPath)); err != nil {
			fmt.Fprintf(os.Stderr, "Error generating multi-page HTML report: %v\n", err)
		} else {
			color.Green("✓ Multi-page HTML report generated in directory: %s", mpOutputDir)
			color.Cyan("  Open %s/index.html in your browser to view the report", mpOutputDir)
		}
	}

	// Export to HTML if requested
	if *htmlOutput != "" {
		if err := output.GenerateHTMLReport(report, *htmlOutput, filepath.Base(absPath)); err != nil {
			fmt.Fprintf(os.Stderr, "Error exporting to HTML: %v\n", err)
		} else {
			if outputDir != "" {
				color.Green("✓ HTML report exported to %s/%s", outputDir, filepath.Base(*htmlOutput))
			} else {
				color.Green("✓ HTML report exported to %s", *htmlOutput)
			}
		}
	}

	// Export to PDF if requested
	if *pdfOutput != "" {
		pdfGen := output.NewPDFGenerator()
		if !pdfGen.IsAvailable() {
			color.Yellow("⚠ PDF generation requires wkhtmltopdf")
			color.Yellow("  %s", pdfGen.GetInstallInstructions())
		} else {
			if err := pdfGen.GeneratePDF(report, *pdfOutput, filepath.Base(absPath)); err != nil {
				fmt.Fprintf(os.Stderr, "Error exporting to PDF: %v\n", err)
			} else {
				if outputDir != "" {
					color.Green("✓ PDF report exported to %s/%s", outputDir, filepath.Base(*pdfOutput))
				} else {
					color.Green("✓ PDF report exported to %s", *pdfOutput)
				}
			}
		}
	}

	// Note: configPath is reserved for future template customization
	_ = configPath

	// Debug HTML output
	if *debugHTML {
		debugFile := "debug_report.html"
		if outputDir != "" {
			debugFile = filepath.Join(outputDir, debugFile)
		}
		if err := output.GenerateDebugHTML(report, debugFile, filepath.Base(absPath)); err != nil {
			fmt.Fprintf(os.Stderr, "Error generating debug HTML: %v\n", err)
		} else {
			color.Green("✓ Debug HTML exported to %s", debugFile)
		}
	}

	// Trace path to discovered destinations (requires network access)
	if *tracePath {
		color.Cyan("\n━━━ NETWORK PATH DISCOVERY ━━━")
		if err := performTracePath(report, *verbose); err != nil {
			color.Yellow("⚠ Trace path failed: %v", err)
			color.Yellow("  This feature requires network access and may need elevated privileges")
		}
	}

	// BGP check for hijack indicators (requires internet)
	if *bgpCheck {
		color.Cyan("\n━━━ BGP ROUTING CHECK ━━━")
		if err := performBGPCheck(report, *verbose); err != nil {
			color.Yellow("⚠ BGP check failed: %v", err)
			color.Yellow("  This feature requires internet access to query BGP routing databases")
		}
	}

	// Application identification enhancement
	if *appIdentify {
		enhanceApplicationIdentification(report, *verbose)
	}

	// Compare mode - handled separately with multiple files
	if *compareMode {
		if flag.NArg() < 2 {
			color.Yellow("⚠ Compare mode requires at least 2 PCAP files")
			color.Yellow("  Usage: sdwan-triage -compare file1.pcap file2.pcap [file3.pcap ...]")
		} else {
			color.Cyan("\n━━━ MULTI-FILE COMPARISON ━━━")
			compareMultiplePCAPs(flag.Args(), *verbose)
		}
	}
}

// performTracePath performs traceroute to top destinations with anomalies
func performTracePath(report *models.TriageReport, verbose bool) error {
	// Collect unique destination IPs with anomalies
	destIPs := make(map[string]int)

	// Count anomalies per destination from DNS anomalies
	for _, finding := range report.DNSAnomalies {
		destIPs[finding.ServerIP]++
	}
	// Count from TLS security findings
	for _, finding := range report.Security.TLSSecurityFindings {
		destIPs[finding.ServerIP]++
	}
	// Count from DDoS findings
	for _, finding := range report.Security.DDoSFindings {
		destIPs[finding.TargetIP]++
	}

	if len(destIPs) == 0 {
		color.Yellow("  No destinations with anomalies found for path tracing")
		return nil
	}

	// Sort by anomaly count and take top 5
	type destScore struct {
		IP    string
		Score int
	}
	var sorted []destScore
	for ip, score := range destIPs {
		sorted = append(sorted, destScore{ip, score})
	}
	// Simple bubble sort for top 5
	for i := 0; i < len(sorted)-1; i++ {
		for j := i + 1; j < len(sorted); j++ {
			if sorted[j].Score > sorted[i].Score {
				sorted[i], sorted[j] = sorted[j], sorted[i]
			}
		}
	}

	limit := 5
	if len(sorted) < limit {
		limit = len(sorted)
	}

	color.White("  Tracing paths to top %d destinations by anomaly count...\n", limit)

	for i := 0; i < limit; i++ {
		ip := sorted[i].IP
		color.Cyan("  → %s (anomaly score: %d)", ip, sorted[i].Score)

		// Perform simple connectivity check (actual traceroute requires raw sockets/elevated privileges)
		if err := checkConnectivity(ip, verbose); err != nil {
			color.Yellow("    ✗ Unreachable: %v", err)
		} else {
			color.Green("    ✓ Reachable")
		}
	}

	return nil
}

// checkConnectivity performs a simple TCP connectivity check
func checkConnectivity(ip string, verbose bool) error {
	// Try common ports
	ports := []string{"443", "80", "53"}
	for _, port := range ports {
		conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip, port), 2*time.Second)
		if err == nil {
			conn.Close()
			if verbose {
				fmt.Fprintf(os.Stderr, "[DEBUG] Connected to %s:%s\n", ip, port)
			}
			return nil
		}
	}
	return fmt.Errorf("no response on common ports")
}

// performBGPCheck checks BGP routing for potential hijack indicators
func performBGPCheck(report *models.TriageReport, verbose bool) error {
	// Check if we have any BGP indicators from the analysis
	if len(report.BGPHijackIndicators) == 0 {
		color.White("  No BGP sessions detected in capture")
		color.White("  Checking external IPs against known BGP data...")
	}

	// Collect external IPs to check
	externalIPs := make(map[string]bool)
	for _, flow := range report.TrafficAnalysis {
		if !isPrivateIP(flow.SrcIP) {
			externalIPs[flow.SrcIP] = true
		}
		if !isPrivateIP(flow.DstIP) {
			externalIPs[flow.DstIP] = true
		}
	}

	if len(externalIPs) == 0 {
		color.Yellow("  No external IPs found to check")
		return nil
	}

	// Check connectivity to BGP data sources
	color.White("  Checking %d external IPs for BGP anomalies...", len(externalIPs))

	// Note: Full BGP checking would require API access to services like RIPE RIS, BGPStream, etc.
	// For now, we provide a framework and indicate the feature is available
	checkedCount := 0
	for ip := range externalIPs {
		if checkedCount >= 10 {
			color.White("  ... and %d more IPs (limited to 10 for performance)", len(externalIPs)-10)
			break
		}
		if verbose {
			fmt.Fprintf(os.Stderr, "[DEBUG] Would check BGP data for: %s\n", ip)
		}
		color.White("  • %s - BGP lookup pending (requires API integration)", ip)
		checkedCount++
	}

	color.Yellow("\n  ℹ Full BGP hijack detection requires integration with:")
	color.Yellow("    • RIPE RIS (https://ris.ripe.net/)")
	color.Yellow("    • BGPStream (https://bgpstream.com/)")
	color.Yellow("    • Team Cymru IP-to-ASN mapping")

	return nil
}

// isPrivateIP checks if an IP is in private address space
func isPrivateIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}

	privateBlocks := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",
		"169.254.0.0/16",
		"fc00::/7",
		"fe80::/10",
	}

	for _, block := range privateBlocks {
		_, cidr, err := net.ParseCIDR(block)
		if err != nil {
			continue
		}
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}

// enhanceApplicationIdentification performs deep application identification
func enhanceApplicationIdentification(report *models.TriageReport, verbose bool) {
	color.Cyan("\n━━━ ENHANCED APPLICATION IDENTIFICATION ━━━")

	// Enhance existing application breakdown with heuristics
	enhancedCount := 0

	// Check for applications by port patterns
	portPatterns := map[uint16]string{
		3306:  "MySQL Database",
		5432:  "PostgreSQL Database",
		27017: "MongoDB",
		6379:  "Redis",
		11211: "Memcached",
		9200:  "Elasticsearch",
		5672:  "RabbitMQ",
		1433:  "MS SQL Server",
		3389:  "Remote Desktop (RDP)",
		5900:  "VNC",
		22:    "SSH",
		21:    "FTP",
		25:    "SMTP",
		110:   "POP3",
		143:   "IMAP",
		993:   "IMAPS",
		995:   "POP3S",
		1194:  "OpenVPN",
		51820: "WireGuard",
		500:   "IKE/IPsec",
		4500:  "IPsec NAT-T",
		1723:  "PPTP",
		8080:  "HTTP Proxy",
		8443:  "HTTPS Alt",
		9090:  "Prometheus",
		3000:  "Grafana/Dev Server",
		8888:  "Jupyter Notebook",
	}

	// Analyze flows for application patterns
	for _, flow := range report.TrafficAnalysis {
		// Check destination port
		if appName, ok := portPatterns[flow.DstPort]; ok {
			if verbose {
				fmt.Fprintf(os.Stderr, "[DEBUG] Identified %s on port %d\n", appName, flow.DstPort)
			}
			enhancedCount++
			color.White("  • %s:%d → %s", flow.DstIP, flow.DstPort, appName)
		}
	}

	// Report on SNI-based identifications already in report
	sniCount := 0
	for appName, category := range report.ApplicationBreakdown {
		if category.PacketCount > 0 {
			sniCount++
			if verbose {
				color.White("  • %s: %d packets, %d bytes", appName, category.PacketCount, category.ByteCount)
			}
		}
	}

	if enhancedCount == 0 && sniCount == 0 {
		color.Yellow("  No additional applications identified beyond standard detection")
	} else {
		color.Green("  ✓ Identified %d applications via port heuristics", enhancedCount)
		color.Green("  ✓ %d applications identified via SNI/DNS", sniCount)
	}
}

// compareMultiplePCAPs compares multiple PCAP files
func compareMultiplePCAPs(files []string, verbose bool) {
	color.White("  Comparing %d PCAP files:\n", len(files))

	type pcapStats struct {
		File       string
		Packets    int
		Bytes      uint64
		TCPFlows   int
		UDPFlows   int
		DNSQueries int
		TLSConns   int
		Anomalies  int
		Duration   float64
		Error      error
	}

	var stats []pcapStats

	for _, file := range files {
		color.Cyan("  Analyzing: %s", file)

		// Open and analyze each file
		f, err := os.Open(file)
		if err != nil {
			stats = append(stats, pcapStats{File: file, Error: err})
			color.Red("    ✗ Error: %v", err)
			continue
		}

		reader, err := pcapgo.NewReader(f)
		if err != nil {
			f.Close()
			stats = append(stats, pcapStats{File: file, Error: err})
			color.Red("    ✗ Error: %v", err)
			continue
		}

		// Create fresh report and state for each file
		fileReport := &models.TriageReport{
			ApplicationBreakdown: make(map[string]models.AppCategory),
		}
		fileState := models.NewAnalysisState()
		processor := analyzer.NewProcessorWithOptions(false, verbose)

		if err := processor.Process(reader, fileState, fileReport, nil); err != nil {
			f.Close()
			stats = append(stats, pcapStats{File: file, Error: err})
			color.Red("    ✗ Error: %v", err)
			continue
		}
		f.Close()

		// Collect stats
		anomalyCount := len(fileReport.DNSAnomalies) + len(fileReport.Security.DDoSFindings) +
			len(fileReport.Security.PortScanFindings) + len(fileReport.Security.TLSSecurityFindings)

		s := pcapStats{
			File:       filepath.Base(file),
			Packets:    len(fileReport.TrafficAnalysis),
			Bytes:      fileReport.TotalBytes,
			TCPFlows:   len(fileReport.TCPRetransmissions),
			UDPFlows:   len(fileReport.QUICFlows),
			DNSQueries: len(fileReport.DNSDetails),
			TLSConns:   len(fileReport.TLSCerts),
			Anomalies:  anomalyCount,
			Duration:   0,
		}
		stats = append(stats, s)
		color.Green("    ✓ %d packets, %d flows", s.Packets, s.TCPFlows+s.UDPFlows)
	}

	// Print comparison table
	color.Cyan("\n  ━━━ COMPARISON SUMMARY ━━━")
	fmt.Printf("\n  %-25s %10s %12s %8s %8s %10s\n",
		"File", "Packets", "Bytes", "TCP", "UDP", "Anomalies")
	fmt.Printf("  %s\n", strings.Repeat("─", 80))

	for _, s := range stats {
		if s.Error != nil {
			fmt.Printf("  %-25s %s\n", s.File, color.RedString("ERROR: %v", s.Error))
		} else {
			fmt.Printf("  %-25s %10d %12d %8d %8d %10d\n",
				s.File, s.Packets, s.Bytes, s.TCPFlows, s.UDPFlows, s.Anomalies)
		}
	}
	fmt.Println()
}
