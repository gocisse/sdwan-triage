package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/gocisse/sdwan-triage/pkg/analyzer"
	"github.com/gocisse/sdwan-triage/pkg/config"
	"github.com/gocisse/sdwan-triage/pkg/models"
	"github.com/gocisse/sdwan-triage/pkg/output"
)

// Build-time variables — stamped via -ldflags "-X main.version=... -X main.buildCommit=... -X main.buildDate=..."
var (
	version     = "4.5.2"
	buildCommit = "unknown"
	buildDate   = "unknown"
)

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
    sdwan-triage -web [-port PORT] [-no-browser]

OPTIONS:
  Output Formats:
    -json              Output results in JSON format (for automation/scripting)
    -csv <file>        Export findings to CSV files (separate files per category)
    -html <file>       Generate interactive HTML report with D3.js visualizations
    -multi-page-html <dir>  Generate multi-page HTML report in specified directory
    -pdf <file>        Export to PDF report (requires wkhtmltopdf installed)
    -simple            Generate plain English report for non-technical users
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

  Web Application Mode:
    -web                   Start the interactive web application instead of CLI mode
    -port <N>              HTTP server port for web mode (default: 8080, auto-retries if busy)
    -no-browser            Do not auto-open browser when starting web mode

  Enterprise Integrations (web mode only):
    -servicenow-url <url>       ServiceNow instance URL for auto-ticket creation
    -servicenow-user <user>     ServiceNow username
    -servicenow-password <pass> ServiceNow password

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

  LAN Protocol Analysis (VRRP, CDP, LLDP, HSRP, STP):
    # Re-analyze capture with VRRP detection
    sdwan-triage analyze vrrp-capture.pcap

    # Check for VRRP flapping
    sdwan-triage analyze vrrp-capture.pcap | jq '.lan_protocols.vrrp_sessions[] | select(.is_flapping == true)'

    # View VRRP timeline events
    sdwan-triage analyze vrrp-capture.pcap | jq '.timeline[] | select(.protocol == "VRRP")'

    # Discover CDP devices
    sdwan-triage -html report.html capture.pcap | jq '.lan_protocols.cdp_devices[]'

    # Check HSRP failover events
    sdwan-triage analyze capture.pcap | jq '.timeline[] | select(.protocol == "HSRP")'

  Web Application Mode:
    # Start the interactive web UI (opens browser automatically)
    sdwan-triage -web

    # Start web UI on a custom port without auto-opening browser
    sdwan-triage -web -port 9090 -no-browser

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
  LAN:       VRRP, CDP, LLDP, HSRP, STP (with flapping detection)

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
	simpleOutput := flag.Bool("simple", false, "Generate plain English report for non-technical users")
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
	noExternalLookup := flag.Bool("no-external-lookup", false, "Disable all external network lookups (BGP, traceroute)")
	compareMode := flag.Bool("compare", false, "Compare multiple PCAP files")
	debugHTML := flag.Bool("debug-html", false, "Write raw HTML to debug_report.html")
	verbose = flag.Bool("verbose", false, "Enable verbose/debug output")
	showHelp := flag.Bool("help", false, "Show help message")
	webMode := flag.Bool("web", false, "Start the interactive web application")
	webPort := flag.Int("port", 8080, "HTTP server port for web mode (auto-retries if busy)")
	noBrowser := flag.Bool("no-browser", false, "Do not auto-open browser in web mode")

	// Enterprise integration flags
	serviceNowURL := flag.String("servicenow-url", "", "ServiceNow instance URL (e.g. https://instance.service-now.com)")
	serviceNowUser := flag.String("servicenow-user", "", "ServiceNow username for ticket creation")
	serviceNowPassword := flag.String("servicenow-password", "", "ServiceNow password for ticket creation")

	flag.Parse()

	// Web application mode — start server and return
	if *webMode {
		intOpts := &IntegrationOptions{
			ServiceNowURL:      *serviceNowURL,
			ServiceNowUser:     *serviceNowUser,
			ServiceNowPassword: *serviceNowPassword,
		}
		runWebServer(*webPort, *noBrowser, intOpts)
		return
	}

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

	// Open capture file (auto-detects pcap vs pcapng)
	capHandle, err := analyzer.OpenCapture(absPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: Failed to read capture file '%s'\n", filepath.Base(absPath))
		fmt.Fprintf(os.Stderr, "       Supported formats: .pcap and .pcapng\n")
		if *verbose {
			fmt.Fprintf(os.Stderr, "[DEBUG] OpenCapture error: %v\n", err)
		}
		os.Exit(1)
	}
	defer capHandle.Close()
	reader := capHandle.Reader

	if *verbose {
		fmt.Fprintf(os.Stderr, "[DEBUG] Capture file opened successfully (format: %s, link type: %v)\n", capHandle.Format, reader.LinkType())
	}

	// Initialize report and state
	report := &models.TriageReport{
		ApplicationBreakdown: make(map[string]models.AppCategory),
	}
	state := models.NewAnalysisState()

	// Load threshold configuration if specified
	thresholds, err := config.LoadThresholds(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading config: %v\n", err)
		os.Exit(1)
	}

	// Create processor and analyze
	var processor *analyzer.Processor
	if *qosAnalysis {
		processor = analyzer.NewProcessorWithOptions(true, *verbose)
	} else {
		processor = analyzer.NewProcessorWithOptions(false, *verbose)
	}

	// Apply custom thresholds from config
	processor.ApplyThresholds(thresholds)

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
	} else if *simpleOutput {
		// Print plain English report for non-technical users
		output.GenerateSimpleReport(report, filepath.Base(absPath))
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

	// Config was loaded earlier for threshold customization
	if *verbose && *configPath != "" {
		fmt.Fprintf(os.Stderr, "[DEBUG] Loaded config from: %s\n", *configPath)
		fmt.Fprintf(os.Stderr, "[DEBUG] DDoS SYN threshold: %d\n", thresholds.DDoS.SYNThreshold)
		fmt.Fprintf(os.Stderr, "[DEBUG] High RTT threshold: %.1fms\n", thresholds.Performance.HighRTTMs)
	}

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
		if *noExternalLookup {
			color.Yellow("⚠ Trace path skipped (--no-external-lookup is set)")
		} else {
			color.Cyan("\n━━━ NETWORK PATH DISCOVERY ━━━")
			if err := performTracePath(report, *verbose); err != nil {
				color.Yellow("⚠ Trace path failed: %v", err)
				color.Yellow("  This feature requires network access and may need elevated privileges")
			}
		}
	}

	// BGP check for hijack indicators (requires internet)
	if *bgpCheck {
		if *noExternalLookup {
			color.Yellow("⚠ BGP check skipped (--no-external-lookup is set)")
		} else {
			color.Cyan("\n━━━ BGP ROUTING CHECK ━━━")
			if err := performBGPCheck(report, *verbose); err != nil {
				color.Yellow("⚠ BGP check failed: %v", err)
				color.Yellow("  This feature requires internet access to query BGP routing databases")
			}
		}
	}

	// Application identification enhancement
	if *appIdentify {
		enhanceApplicationIdentification(report, *verbose)
	}

	// Compare mode - handled separately with multiple files
	if *compareMode {
		if flag.NArg() < 2 {
			color.Yellow("⚠ Compare mode requires 2 PCAP files (LAN-side and WAN-side)")
			color.Yellow("  Usage: sdwan-triage -compare lan.pcap wan.pcap")
		} else {
			color.Cyan("\n━━━ PCAP COMPARISON MODE ━━━")
			runPCAPComparison(flag.Arg(0), flag.Arg(1), *verbose, *jsonOutput, *htmlOutput)
		}
	}
}

// runPCAPComparison performs a deep packet-level comparison between two PCAP files.
func runPCAPComparison(fileA, fileB string, verboseMode bool, jsonOut bool, htmlFile string) {
	comp := analyzer.NewComparator(verboseMode)

	color.White("  LAN-side (A): %s", fileA)
	color.White("  WAN-side (B): %s", fileB)
	fmt.Println()

	report, err := comp.Compare(fileA, fileB)
	if err != nil {
		color.Red("  ✗ Comparison failed: %v", err)
		os.Exit(1)
	}

	// Print results
	printComparisonReport(report)

	// JSON output
	if jsonOut {
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(report); err != nil {
			fmt.Fprintf(os.Stderr, "Error encoding JSON: %v\n", err)
		}
	}
}

// printComparisonReport displays the comparison results in the terminal.
func printComparisonReport(report *analyzer.ComparisonReport) {
	// Path Integrity Score — large banner
	scoreColor := color.New(color.FgGreen, color.Bold)
	if report.PathIntegrityScore < 80 {
		scoreColor = color.New(color.FgYellow, color.Bold)
	}
	if report.PathIntegrityScore < 50 {
		scoreColor = color.New(color.FgRed, color.Bold)
	}

	fmt.Println()
	color.Cyan("  ╔══════════════════════════════════════════╗")
	scoreColor.Fprintf(os.Stdout, "  ║  Path Integrity Score: %5.1f%% (%s)  \n", report.PathIntegrityScore, report.IntegrityRating)
	color.Cyan("  ╚══════════════════════════════════════════╝")
	fmt.Println()

	// Tunnel detection banner
	if report.TunnelDetected {
		color.Cyan("  ━━━ TUNNEL ENCAPSULATION DETECTED ━━━")
		for _, t := range report.TunnelTypes {
			cnt := report.TunnelBreakdown[t]
			color.Cyan("  ● %s: %d packets", t, cnt)
		}
		if report.EncapsulatedCount > 0 {
			decapOK := report.EncapsulatedCount - report.EncryptedCount
			fmt.Printf("  Decapsulated (inner extracted): %d\n", decapOK)
		}
		if report.EncryptedCount > 0 {
			color.Yellow("  ⚠ %d packets encrypted (ESP/DTLS) — inner flow hidden by encryption", report.EncryptedCount)
			color.Yellow("    Matching based on outer header correlation for encrypted packets")
		}
		fmt.Println()
	}

	// Summary stats
	color.White("  ━━━ PACKET SUMMARY ━━━")
	fmt.Printf("  %-30s %d\n", "Packets in LAN capture (A):", report.TotalPacketsA)
	fmt.Printf("  %-30s %d\n", "Packets in WAN capture (B):", report.TotalPacketsB)
	color.Green("  %-30s %d", "Matched (PRESENT_BOTH):", report.MatchedCount)
	if report.MissingBCount > 0 {
		color.Red("  %-30s %d (dropped by device)", "Missing from WAN (MISSING_B):", report.MissingBCount)
	} else {
		fmt.Printf("  %-30s %d\n", "Missing from WAN (MISSING_B):", report.MissingBCount)
	}
	if report.MissingACount > 0 {
		color.Yellow("  %-30s %d (asymmetric/injected)", "Missing from LAN (MISSING_A):", report.MissingACount)
	} else {
		fmt.Printf("  %-30s %d\n", "Missing from LAN (MISSING_A):", report.MissingACount)
	}
	if report.ModifiedCount > 0 {
		color.Yellow("  %-30s %d", "Modified (TTL/DSCP/NAT):", report.ModifiedCount)
	} else {
		fmt.Printf("  %-30s %d\n", "Modified:", report.ModifiedCount)
	}
	if report.EncryptedCount > 0 {
		color.Cyan("  %-30s %d (inner flow hidden)", "Encrypted tunnel packets:", report.EncryptedCount)
	}
	fmt.Println()

	// Modification details
	if report.ModifiedCount > 0 {
		color.White("  ━━━ MODIFICATION DETAILS ━━━")
		if report.NATDetected {
			color.Yellow("  ⚠ NAT translation detected between LAN and WAN")
		}
		if report.TTLChanges > 0 {
			fmt.Printf("  TTL changes: %d (expected — each hop decrements TTL)\n", report.TTLChanges)
		}
		if report.DSCPChanges > 0 {
			color.Yellow("  DSCP/QoS remarking: %d packets (QoS policy applied)", report.DSCPChanges)
		}
		fmt.Println()
	}

	// Per-flow summary (top 20 worst flows)
	if len(report.FlowSummaries) > 0 {
		color.White("  ━━━ FLOW COMPARISON (sorted by match rate, worst first) ━━━")
		fmt.Printf("\n  %-42s %6s %6s %6s %6s %6s %7s\n",
			"Flow", "PktsA", "PktsB", "Match", "DropB", "DropA", "Rate")
		fmt.Printf("  %s\n", strings.Repeat("─", 88))

		limit := 20
		if len(report.FlowSummaries) < limit {
			limit = len(report.FlowSummaries)
		}
		for i := 0; i < limit; i++ {
			fs := report.FlowSummaries[i]
			flowStr := fmt.Sprintf("%s:%d→%s:%d/%s", fs.SrcIP, fs.SrcPort, fs.DstIP, fs.DstPort, fs.Protocol)
			if len(flowStr) > 42 {
				flowStr = flowStr[:39] + "..."
			}

			rateStr := fmt.Sprintf("%.0f%%", fs.MatchRate*100)
			if fs.MatchRate < 0.5 {
				color.Red("  %-42s %6d %6d %6d %6d %6d %7s", flowStr, fs.PacketsA, fs.PacketsB, fs.Matched, fs.MissingB, fs.MissingA, rateStr)
			} else if fs.MatchRate < 0.95 {
				color.Yellow("  %-42s %6d %6d %6d %6d %6d %7s", flowStr, fs.PacketsA, fs.PacketsB, fs.Matched, fs.MissingB, fs.MissingA, rateStr)
			} else {
				fmt.Printf("  %-42s %6d %6d %6d %6d %6d %7s\n", flowStr, fs.PacketsA, fs.PacketsB, fs.Matched, fs.MissingB, fs.MissingA, rateStr)
			}
		}
		if len(report.FlowSummaries) > limit {
			fmt.Printf("  ... and %d more flows\n", len(report.FlowSummaries)-limit)
		}
		fmt.Println()
	}

	// Top discrepancies (first 10)
	if len(report.Discrepancies) > 0 {
		color.White("  ━━━ TOP DISCREPANCIES ━━━")
		limit := 10
		if len(report.Discrepancies) < limit {
			limit = len(report.Discrepancies)
		}
		for i := 0; i < limit; i++ {
			d := report.Discrepancies[i]
			switch d.State {
			case analyzer.StateMissingB:
				color.Red("  [MISSING_B] #%d %s %s:%d→%s:%d %s — %s",
					d.PacketIndex, d.Timestamp, d.SrcIP, d.SrcPort, d.DstIP, d.DstPort, d.Protocol, d.Detail)
			case analyzer.StateMissingA:
				color.Yellow("  [MISSING_A] #%d %s %s:%d→%s:%d %s — %s",
					d.PacketIndex, d.Timestamp, d.SrcIP, d.SrcPort, d.DstIP, d.DstPort, d.Protocol, d.Detail)
			case analyzer.StateModified:
				color.Yellow("  [MODIFIED]  #%d %s %s:%d→%s:%d %s — %s",
					d.PacketIndex, d.Timestamp, d.SrcIP, d.SrcPort, d.DstIP, d.DstPort, d.Protocol, d.Detail)
			}
		}
		if len(report.Discrepancies) > limit {
			fmt.Printf("  ... and %d more discrepancies\n", len(report.Discrepancies)-limit)
		}
	}

	fmt.Println()
	color.Cyan("  Analysis completed in %v", report.AnalysisDuration)
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

// bgpPrefixResponse represents the RIPE stat API response for prefix overview
type bgpPrefixResponse struct {
	Status     string `json:"status"`
	StatusCode int    `json:"status_code"`
	Data       struct {
		Resource string `json:"resource"`
		ASNs     []struct {
			ASN    int    `json:"asn"`
			Holder string `json:"holder"`
		} `json:"asns"`
		Block struct {
			Resource string `json:"resource"`
			Desc     string `json:"desc"`
			Name     string `json:"name"`
		} `json:"block"`
		Announced bool   `json:"announced"`
		IsLess    string `json:"is_less_specific"`
	} `json:"data"`
}

// bgpLookupResult holds the result of a single BGP prefix lookup
type bgpLookupResult struct {
	IP        string
	ASN       int
	ASHolder  string
	Prefix    string
	Announced bool
	Error     error
}

// performBGPCheck queries RIPE stat API for BGP prefix information on external IPs
func performBGPCheck(report *models.TriageReport, verbose bool) error {
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

	// Also check IPs from security findings
	for _, finding := range report.Security.DDoSFindings {
		if finding.SourceIP != "" && !isPrivateIP(finding.SourceIP) {
			externalIPs[finding.SourceIP] = true
		}
	}

	if len(externalIPs) == 0 {
		color.Yellow("  No external IPs found to check")
		return nil
	}

	// Limit to top 10 IPs to avoid API abuse
	limit := 10
	if len(externalIPs) < limit {
		limit = len(externalIPs)
	}

	color.White("  Querying RIPE stat API for %d external IPs (of %d total)...\n", limit, len(externalIPs))

	// HTTP client with 5s timeout
	client := &http.Client{
		Timeout: 5 * time.Second,
	}

	checked := 0
	var anomalies []string
	asnMap := make(map[int]string) // ASN -> holder name

	for ip := range externalIPs {
		if checked >= limit {
			break
		}
		checked++

		result := queryRIPEstat(client, ip, verbose)
		if result.Error != nil {
			if verbose {
				fmt.Fprintf(os.Stderr, "[DEBUG] BGP lookup failed for %s: %v\n", ip, result.Error)
			}
			color.Yellow("  • %s — lookup failed: %v", ip, result.Error)
			continue
		}

		if !result.Announced {
			anomalies = append(anomalies, fmt.Sprintf("%s (not announced in BGP)", ip))
			color.Red("  ✗ %s — NOT ANNOUNCED in BGP (potential bogon or hijack)", ip)
		} else {
			asnMap[result.ASN] = result.ASHolder
			if verbose {
				color.Green("  ✓ %s — AS%d (%s)", ip, result.ASN, result.ASHolder)
			} else {
				color.White("  • %s — AS%d (%s)", ip, result.ASN, result.ASHolder)
			}
		}
	}

	if len(externalIPs) > limit {
		color.White("  ... and %d more IPs not checked (limited to %d)", len(externalIPs)-limit, limit)
	}

	// Summary
	fmt.Println()
	color.White("  BGP Summary:")
	color.White("    Unique ASNs observed: %d", len(asnMap))
	for asn, holder := range asnMap {
		color.White("    • AS%d — %s", asn, holder)
	}

	if len(anomalies) > 0 {
		color.Red("\n  ⚠ %d IP(s) with BGP anomalies:", len(anomalies))
		for _, a := range anomalies {
			color.Red("    • %s", a)
		}
	} else {
		color.Green("\n  ✓ No BGP anomalies detected")
	}

	return nil
}

// queryRIPEstat queries the RIPE stat API for prefix overview of an IP
func queryRIPEstat(client *http.Client, ip string, verbose bool) bgpLookupResult {
	result := bgpLookupResult{IP: ip}

	url := fmt.Sprintf("https://stat.ripe.net/data/prefix-overview/data.json?resource=%s&sourceapp=sdwan-triage", ip)

	if verbose {
		fmt.Fprintf(os.Stderr, "[DEBUG] BGP query: %s\n", url)
	}

	resp, err := client.Get(url)
	if err != nil {
		result.Error = fmt.Errorf("API request failed: %w", err)
		return result
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		result.Error = fmt.Errorf("API returned status %d", resp.StatusCode)
		return result
	}

	var apiResp bgpPrefixResponse
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		result.Error = fmt.Errorf("failed to parse response: %w", err)
		return result
	}

	result.Announced = apiResp.Data.Announced
	result.Prefix = apiResp.Data.Resource

	if len(apiResp.Data.ASNs) > 0 {
		result.ASN = apiResp.Data.ASNs[0].ASN
		result.ASHolder = apiResp.Data.ASNs[0].Holder
	}

	return result
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
