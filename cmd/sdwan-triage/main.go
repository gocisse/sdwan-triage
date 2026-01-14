package main

import (
	"encoding/json"
	"flag"
	"fmt"
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

const version = "2.9.0"

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
    -verbose               Enable verbose/debug output for troubleshooting
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
}
