package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/fatih/color"
	"github.com/gocisse/sdwan-triage/pkg/analyzer"
	"github.com/gocisse/sdwan-triage/pkg/models"
	"github.com/gocisse/sdwan-triage/pkg/output"
	"github.com/google/gopacket/pcapgo"
)

const version = "2.6.0"

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

	// Open PCAP file
	file, err := os.Open(pcapFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error opening file: %v\n", err)
		os.Exit(1)
	}
	defer file.Close()

	reader, err := pcapgo.NewReader(file)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating PCAP reader: %v\n", err)
		os.Exit(1)
	}

	// Initialize report and state
	report := &models.TriageReport{
		ApplicationBreakdown: make(map[string]models.AppCategory),
	}
	state := models.NewAnalysisState()

	// Create processor and analyze
	var processor *analyzer.Processor
	if *qosAnalysis {
		processor = analyzer.NewProcessorWithOptions(true)
	} else {
		processor = analyzer.NewProcessor()
	}

	color.Cyan("SD-WAN Network Triage v%s", version)
	color.Cyan("Analyzing: %s\n", pcapFile)

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
