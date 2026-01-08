package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/fatih/color"
	"github.com/gocisse/sdwan-triage/pkg/analyzer"
	"github.com/gocisse/sdwan-triage/pkg/models"
	"github.com/gocisse/sdwan-triage/pkg/output"
	"github.com/google/gopacket/pcapgo"
)

const version = "2.7.0"

// Global verbose flag for debug logging
var verbose *bool

func main() {
	// Define custom usage function
	flag.Usage = func() {
		fmt.Fprintf(os.Stdout, `SD-WAN Network Triage: Analyze PCAP files for network issues, security threats, and traffic patterns.

USAGE:
    sdwan-triage [OPTIONS] <pcap_file>

OPTIONS:
    -json              Output in JSON format
    -csv <file>        Export findings to CSV file
    -html <file>       Export findings to HTML report with D3.js visualizations
    -src-ip <ip>       Filter by source IP address
    -dst-ip <ip>       Filter by destination IP address
    -service <port>    Filter by service port or name (e.g., 443, https, ssh)
    -protocol <proto>  Filter by protocol (tcp or udp)
    -qos-analysis      Enable QoS/DSCP traffic class analysis
    -verbose           Enable verbose/debug output
    -help              Show this help message

EXAMPLES:
    # Basic analysis with human-readable output
    sdwan-triage capture.pcap

    # Generate HTML report with visualizations
    sdwan-triage -html report.html capture.pcap

    # Export to JSON for automation
    sdwan-triage -json capture.pcap > results.json

    # Filter by source IP
    sdwan-triage -src-ip 192.168.1.100 capture.pcap

    # Filter by service
    sdwan-triage -service https capture.pcap

VERSION:
    SD-WAN Triage v%s

`, version)
	}

	// Parse flags
	jsonOutput := flag.Bool("json", false, "Output in JSON format")
	csvOutput := flag.String("csv", "", "Export findings to CSV file")
	htmlOutput := flag.String("html", "", "Export findings to HTML report")
	srcIP := flag.String("src-ip", "", "Filter by source IP address")
	dstIP := flag.String("dst-ip", "", "Filter by destination IP address")
	service := flag.String("service", "", "Filter by service port or name")
	protocol := flag.String("protocol", "", "Filter by protocol (tcp or udp)")
	qosAnalysis := flag.Bool("qos-analysis", false, "Enable QoS/DSCP traffic class analysis")
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
	}

	// Export to CSV if requested
	if *csvOutput != "" {
		if err := output.ExportToCSV(report, *csvOutput); err != nil {
			fmt.Fprintf(os.Stderr, "Error exporting to CSV: %v\n", err)
		} else {
			color.Green("✓ CSV report exported to %s", *csvOutput)
		}
	}

	// Export to HTML if requested
	if *htmlOutput != "" {
		if err := output.ExportToHTML(report, *htmlOutput); err != nil {
			fmt.Fprintf(os.Stderr, "Error exporting to HTML: %v\n", err)
		} else {
			color.Green("✓ HTML report exported to %s", *htmlOutput)
		}
	}
}
