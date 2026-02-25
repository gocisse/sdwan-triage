package analyzer

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gocisse/sdwan-triage/pkg/models"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

// PCAPExporter handles exporting filtered packets to new PCAP files
type PCAPExporter struct {
	sourcePath string
	outputDir  string
	verbose    bool
}

// NewPCAPExporter creates a new PCAP exporter
func NewPCAPExporter(sourcePath, outputDir string, verbose bool) *PCAPExporter {
	return &PCAPExporter{
		sourcePath: sourcePath,
		outputDir:  outputDir,
		verbose:    verbose,
	}
}

// ExportFilter defines criteria for exporting packets
type ExportFilter struct {
	SrcIP       string
	DstIP       string
	SrcPort     uint16
	DstPort     uint16
	Protocol    string // "TCP", "UDP", or empty for both
	FlowID      string // Alternative: use flow ID directly
	Description string // Human-readable description for filename
}

// ExportResult contains the result of an export operation
type ExportResult struct {
	Success     bool
	OutputPath  string
	PacketCount int
	ByteCount   uint64
	Error       error
	Duration    time.Duration
}

// ExportStream exports packets matching a specific stream/flow to a new PCAP file
func (pe *PCAPExporter) ExportStream(filter ExportFilter) (*ExportResult, error) {
	startTime := time.Now()
	result := &ExportResult{}

	// Open source capture (auto-detects pcap vs pcapng)
	capHandle, err := OpenCapture(pe.sourcePath)
	if err != nil {
		result.Error = fmt.Errorf("failed to open source capture: %w", err)
		return result, result.Error
	}
	defer capHandle.Close()

	reader := capHandle.Reader

	// Generate output filename
	outputFilename := pe.generateFilename(filter)
	outputPath := filepath.Join(pe.outputDir, outputFilename)

	// Create output directory if needed
	if err := os.MkdirAll(pe.outputDir, 0755); err != nil {
		result.Error = fmt.Errorf("failed to create output directory: %w", err)
		return result, result.Error
	}

	// Create output file
	outputFile, err := os.Create(outputPath)
	if err != nil {
		result.Error = fmt.Errorf("failed to create output file: %w", err)
		return result, result.Error
	}
	defer outputFile.Close()

	// Create PCAP writer
	writer := pcapgo.NewWriter(outputFile)
	if err := writer.WriteFileHeader(65536, reader.LinkType()); err != nil {
		result.Error = fmt.Errorf("failed to write PCAP header: %w", err)
		return result, result.Error
	}

	// Process packets
	packetCount := 0
	var byteCount uint64

	for {
		data, ci, err := reader.ReadPacketData()
		if err == io.EOF {
			break
		}
		if err != nil {
			continue // Skip bad packets
		}

		// Parse packet
		packet := gopacket.NewPacket(data, reader.LinkType(), gopacket.DecodeOptions{Lazy: true, NoCopy: true})
		if packet == nil {
			continue
		}

		// Check if packet matches filter
		if !pe.matchesFilter(packet, filter) {
			continue
		}

		// Write packet to output
		if err := writer.WritePacket(ci, data); err != nil {
			continue // Skip on write error
		}

		packetCount++
		byteCount += uint64(len(data))
	}

	result.Success = true
	result.OutputPath = outputPath
	result.PacketCount = packetCount
	result.ByteCount = byteCount
	result.Duration = time.Since(startTime)

	if pe.verbose {
		fmt.Printf("Exported %d packets (%s) to %s\n",
			packetCount, formatBytes(byteCount), outputPath)
	}

	return result, nil
}

// matchesFilter checks if a packet matches the export filter
func (pe *PCAPExporter) matchesFilter(packet gopacket.Packet, filter ExportFilter) bool {
	// Get network layer
	networkLayer := packet.NetworkLayer()
	if networkLayer == nil {
		return false
	}

	srcIP := networkLayer.NetworkFlow().Src().String()
	dstIP := networkLayer.NetworkFlow().Dst().String()

	// Check IP filter (bidirectional match)
	if filter.SrcIP != "" && filter.DstIP != "" {
		// Must match either direction
		match1 := srcIP == filter.SrcIP && dstIP == filter.DstIP
		match2 := srcIP == filter.DstIP && dstIP == filter.SrcIP
		if !match1 && !match2 {
			return false
		}
	} else if filter.SrcIP != "" {
		if srcIP != filter.SrcIP && dstIP != filter.SrcIP {
			return false
		}
	} else if filter.DstIP != "" {
		if srcIP != filter.DstIP && dstIP != filter.DstIP {
			return false
		}
	}

	// Get transport layer
	transportLayer := packet.TransportLayer()
	if transportLayer == nil {
		// If we need port filtering, skip packets without transport layer
		if filter.SrcPort != 0 || filter.DstPort != 0 || filter.Protocol != "" {
			return false
		}
		return true
	}

	var srcPort, dstPort uint16
	var protocol string

	switch t := transportLayer.(type) {
	case *layers.TCP:
		srcPort = uint16(t.SrcPort)
		dstPort = uint16(t.DstPort)
		protocol = "TCP"
	case *layers.UDP:
		srcPort = uint16(t.SrcPort)
		dstPort = uint16(t.DstPort)
		protocol = "UDP"
	default:
		return filter.Protocol == "" && filter.SrcPort == 0 && filter.DstPort == 0
	}

	// Check protocol filter
	if filter.Protocol != "" && protocol != filter.Protocol {
		return false
	}

	// Check port filter (bidirectional match)
	if filter.SrcPort != 0 && filter.DstPort != 0 {
		match1 := srcPort == filter.SrcPort && dstPort == filter.DstPort
		match2 := srcPort == filter.DstPort && dstPort == filter.SrcPort
		if !match1 && !match2 {
			return false
		}
	} else if filter.SrcPort != 0 {
		if srcPort != filter.SrcPort && dstPort != filter.SrcPort {
			return false
		}
	} else if filter.DstPort != 0 {
		if srcPort != filter.DstPort && dstPort != filter.DstPort {
			return false
		}
	}

	return true
}

// generateFilename generates a descriptive filename for the export
func (pe *PCAPExporter) generateFilename(filter ExportFilter) string {
	var parts []string

	parts = append(parts, "sdwan-triage")

	if filter.Description != "" {
		// Sanitize description
		desc := strings.ReplaceAll(filter.Description, " ", "_")
		desc = strings.ReplaceAll(desc, "/", "-")
		desc = strings.ReplaceAll(desc, ":", "-")
		parts = append(parts, desc)
	}

	if filter.SrcIP != "" {
		parts = append(parts, strings.ReplaceAll(filter.SrcIP, ":", "-"))
	}

	if filter.SrcPort != 0 {
		parts = append(parts, fmt.Sprintf("%d", filter.SrcPort))
	}

	if filter.DstIP != "" {
		parts = append(parts, "to")
		parts = append(parts, strings.ReplaceAll(filter.DstIP, ":", "-"))
	}

	if filter.DstPort != 0 {
		parts = append(parts, fmt.Sprintf("%d", filter.DstPort))
	}

	if filter.Protocol != "" {
		parts = append(parts, strings.ToLower(filter.Protocol))
	}

	// Add timestamp
	parts = append(parts, time.Now().Format("20060102_150405"))

	return strings.Join(parts, "_") + ".pcap"
}

// ExportMultipleStreams exports multiple streams to separate PCAP files
func (pe *PCAPExporter) ExportMultipleStreams(filters []ExportFilter) ([]*ExportResult, error) {
	results := make([]*ExportResult, 0, len(filters))

	for _, filter := range filters {
		result, _ := pe.ExportStream(filter)
		results = append(results, result)
	}

	return results, nil
}

// ExportFromStreamData exports a stream based on StreamData
func (pe *PCAPExporter) ExportFromStreamData(stream *models.StreamData) (*ExportResult, error) {
	filter := ExportFilter{
		SrcIP:       stream.SrcIP,
		SrcPort:     stream.SrcPort,
		DstIP:       stream.DstIP,
		DstPort:     stream.DstPort,
		Protocol:    stream.Protocol,
		Description: stream.Application,
	}
	return pe.ExportStream(filter)
}

// GenerateExportRequests creates export requests for interesting streams
func GenerateExportRequests(report *models.TriageReport) []models.StreamExportRequest {
	requests := make([]models.StreamExportRequest, 0)

	// Add failed handshakes
	for _, flow := range report.FailedHandshakes {
		requests = append(requests, models.StreamExportRequest{
			SrcIP:       flow.SrcIP,
			SrcPort:     flow.SrcPort,
			DstIP:       flow.DstIP,
			DstPort:     flow.DstPort,
			Protocol:    "TCP",
			Description: "failed_handshake",
		})
	}

	// Add DNS anomalies
	for _, anomaly := range report.DNSAnomalies {
		requests = append(requests, models.StreamExportRequest{
			SrcIP:       anomaly.ServerIP,
			DstIP:       anomaly.ServerIP,
			Protocol:    "UDP",
			Description: fmt.Sprintf("dns_anomaly_%s", sanitizeForFilename(anomaly.Query)),
		})
	}

	// Add TLS security issues
	for _, finding := range report.Security.TLSSecurityFindings {
		requests = append(requests, models.StreamExportRequest{
			DstIP:       finding.ServerIP,
			DstPort:     finding.ServerPort,
			Protocol:    "TCP",
			Description: fmt.Sprintf("tls_issue_%s", finding.WeaknessType),
		})
	}

	// Add high RTT flows
	for _, flow := range report.RTTAnalysis {
		if flow.AvgRTT > 200 { // Only export very high RTT flows
			requests = append(requests, models.StreamExportRequest{
				SrcIP:       flow.SrcIP,
				SrcPort:     flow.SrcPort,
				DstIP:       flow.DstIP,
				DstPort:     flow.DstPort,
				Protocol:    "TCP",
				Description: fmt.Sprintf("high_rtt_%.0fms", flow.AvgRTT),
			})
		}
	}

	return requests
}

// sanitizeForFilename removes characters that are problematic in filenames
func sanitizeForFilename(s string) string {
	s = strings.ReplaceAll(s, "/", "-")
	s = strings.ReplaceAll(s, "\\", "-")
	s = strings.ReplaceAll(s, ":", "-")
	s = strings.ReplaceAll(s, "*", "-")
	s = strings.ReplaceAll(s, "?", "-")
	s = strings.ReplaceAll(s, "\"", "-")
	s = strings.ReplaceAll(s, "<", "-")
	s = strings.ReplaceAll(s, ">", "-")
	s = strings.ReplaceAll(s, "|", "-")
	s = strings.ReplaceAll(s, " ", "_")
	if len(s) > 50 {
		s = s[:50]
	}
	return s
}

// GenerateWiresharkFilter generates a Wireshark display filter for a stream
func GenerateWiresharkFilter(stream *models.StreamData) string {
	if stream.Protocol == "TCP" {
		return fmt.Sprintf("(ip.addr == %s && ip.addr == %s && tcp.port == %d && tcp.port == %d)",
			stream.SrcIP, stream.DstIP, stream.SrcPort, stream.DstPort)
	}
	return fmt.Sprintf("(ip.addr == %s && ip.addr == %s && udp.port == %d && udp.port == %d)",
		stream.SrcIP, stream.DstIP, stream.SrcPort, stream.DstPort)
}

// GenerateWiresharkFilterFromFlow generates a Wireshark filter from a TCPFlow
func GenerateWiresharkFilterFromFlow(flow models.TCPFlow) string {
	return fmt.Sprintf("(ip.addr == %s && ip.addr == %s && tcp.port == %d && tcp.port == %d)",
		flow.SrcIP, flow.DstIP, flow.SrcPort, flow.DstPort)
}
