package output

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/gocisse/sdwan-triage/pkg/models"
)

func TestGenerateHTMLReport(t *testing.T) {
	// Create a mock TriageReport
	report := &models.TriageReport{
		TotalBytes: 5000000,
		RiskScore:  25,
		RiskLevel:  "Medium",
		TrafficAnalysis: []models.TrafficFlow{
			{SrcIP: "192.168.1.1", DstIP: "10.0.0.1", Protocol: "TCP", TotalBytes: 1000, SrcPort: 80, DstPort: 443},
		},
		TCPRetransmissions: []models.TCPFlow{
			{SrcIP: "192.168.1.1", DstIP: "10.0.0.1", SrcPort: 80, DstPort: 443},
		},
		DNSAnomalies: []models.DNSAnomaly{
			{Query: "test.example.com", AnswerIP: "1.2.3.4", Reason: "suspicious"},
		},
		RTTAnalysis: []models.RTTFlow{
			{SrcIP: "192.168.1.1", DstIP: "10.0.0.1", AvgRTT: 50.5, MaxRTT: 100.0, MinRTT: 20.0},
		},
	}

	// Create a temporary file for the HTML output
	tmpDir := t.TempDir()
	outputFile := filepath.Join(tmpDir, "test_report.html")

	// Generate the HTML report
	err := GenerateHTMLReport(report, outputFile, "test.pcap")
	if err != nil {
		t.Fatalf("GenerateHTMLReport failed: %v", err)
	}

	// Verify the file was created
	if _, err := os.Stat(outputFile); os.IsNotExist(err) {
		t.Fatalf("output file was not created: %s", outputFile)
	}

	// Read the file and verify it contains expected content
	content, err := os.ReadFile(outputFile)
	if err != nil {
		t.Fatalf("failed to read output file: %v", err)
	}

	htmlContent := string(content)

	// Check for basic HTML structure
	expectedElements := []string{
		"<!DOCTYPE html>",
		"<html",
		"<head>",
		"<body>",
		"</html>",
	}
	for _, elem := range expectedElements {
		if !contains(htmlContent, elem) {
			t.Errorf("expected HTML to contain %q", elem)
		}
	}
}

func TestGenerateEnterpriseHTMLReport(t *testing.T) {
	// Create a mock TriageReport with more data
	report := &models.TriageReport{
		TotalBytes: 10000000,
		RiskScore:  50,
		RiskLevel:  "High",
		TopIssue:   "DDoS Attack Detected",
		TrafficAnalysis: []models.TrafficFlow{
			{SrcIP: "192.168.1.1", DstIP: "10.0.0.1", Protocol: "TCP", TotalBytes: 5000, SrcPort: 80, DstPort: 443},
			{SrcIP: "192.168.1.2", DstIP: "10.0.0.2", Protocol: "UDP", TotalBytes: 3000, SrcPort: 53, DstPort: 53},
		},
		TCPRetransmissions: []models.TCPFlow{
			{SrcIP: "192.168.1.1", DstIP: "10.0.0.1", SrcPort: 80, DstPort: 443},
			{SrcIP: "192.168.1.2", DstIP: "10.0.0.2", SrcPort: 8080, DstPort: 80},
		},
		Security: models.SecurityAnalysis{
			DDoSFindings: []models.DDoSFinding{
				{SourceIP: "10.0.0.1", Type: "SYN Flood", PacketCount: 1000, Severity: "High"},
			},
		},
	}

	// Create a temporary file for the HTML output
	tmpDir := t.TempDir()
	outputFile := filepath.Join(tmpDir, "enterprise_report.html")

	// Generate the enterprise HTML report
	err := GenerateEnterpriseHTMLReport(report, outputFile, "enterprise_test.pcap")
	if err != nil {
		t.Fatalf("GenerateEnterpriseHTMLReport failed: %v", err)
	}

	// Verify the file was created
	if _, err := os.Stat(outputFile); os.IsNotExist(err) {
		t.Fatalf("output file was not created: %s", outputFile)
	}

	// Verify file size is reasonable (should be at least 10KB for a report)
	info, err := os.Stat(outputFile)
	if err != nil {
		t.Fatalf("failed to stat output file: %v", err)
	}
	if info.Size() < 10000 {
		t.Errorf("expected report to be at least 10KB, got %d bytes", info.Size())
	}
}

func TestGenerateSplitHTMLReport(t *testing.T) {
	// Create a mock TriageReport with many flows to test chunking
	report := &models.TriageReport{
		TotalBytes: 50000000,
		RiskScore:  15,
		RiskLevel:  "Low",
	}

	// Create 600 traffic flows to ensure at least 2 chunks
	for i := 0; i < 600; i++ {
		report.TrafficAnalysis = append(report.TrafficAnalysis, models.TrafficFlow{
			SrcIP:      "192.168.1.1",
			DstIP:      "10.0.0.1",
			Protocol:   "TCP",
			TotalBytes: uint64(i * 1000),
			SrcPort:    uint16(i % 65535),
			DstPort:    443,
		})
	}

	// Create a temporary file for the HTML output
	tmpDir := t.TempDir()
	outputFile := filepath.Join(tmpDir, "split_report.html")

	// Generate the split HTML report
	err := GenerateSplitHTMLReport(report, outputFile, "split_test.pcap")
	if err != nil {
		t.Fatalf("GenerateSplitHTMLReport failed: %v", err)
	}

	// Verify the file was created
	if _, err := os.Stat(outputFile); os.IsNotExist(err) {
		t.Fatalf("output file was not created: %s", outputFile)
	}

	// Read the file and verify it contains split report markers
	content, err := os.ReadFile(outputFile)
	if err != nil {
		t.Fatalf("failed to read output file: %v", err)
	}

	htmlContent := string(content)

	// Check for split report specific elements
	expectedElements := []string{
		"report-summary",
		"flow-chunk-0",
		"window.getFlowChunk",
		"window.totalFlowChunks",
	}
	for _, elem := range expectedElements {
		if !contains(htmlContent, elem) {
			t.Errorf("expected split HTML to contain %q", elem)
		}
	}
}

func TestPrepareReportData(t *testing.T) {
	// Create a mock TriageReport
	report := &models.TriageReport{
		TotalBytes: 5000000,
		RiskScore:  30,
		RiskLevel:  "Medium",
		TopIssue:   "TCP Retransmissions",
		TrafficAnalysis: []models.TrafficFlow{
			{SrcIP: "192.168.1.1", DstIP: "10.0.0.1", Protocol: "TCP", TotalBytes: 1000, SrcPort: 80, DstPort: 443},
		},
		TCPRetransmissions: []models.TCPFlow{
			{SrcIP: "192.168.1.1", DstIP: "10.0.0.1", SrcPort: 80, DstPort: 443},
		},
	}

	// Prepare the report data
	data := prepareReportData(report, "test.pcap")

	// Verify basic fields
	if data.FileName != "test.pcap" {
		t.Errorf("expected filename 'test.pcap', got %q", data.FileName)
	}
	if data.RiskScore != 30 {
		t.Errorf("expected risk score 30, got %d", data.RiskScore)
	}
	if data.RiskLevel != "medium" {
		t.Errorf("expected risk level 'medium', got %q", data.RiskLevel)
	}
	if data.TopIssue != "TCP Retransmissions" {
		t.Errorf("expected top issue 'TCP Retransmissions', got %q", data.TopIssue)
	}
}

func TestFormatBytesForTemplate(t *testing.T) {
	tests := []struct {
		bytes    uint64
		expected string
	}{
		{500, "500 B"},
		{1024, "1.0 KB"},
		{1536, "1.5 KB"},
		{1048576, "1.0 MB"},
		{1572864, "1.5 MB"},
		{1073741824, "1.0 GB"},
	}

	for _, test := range tests {
		result := formatBytesForTemplate(test.bytes)
		if result != test.expected {
			t.Errorf("formatBytesForTemplate(%d) = %q, expected %q", test.bytes, result, test.expected)
		}
	}
}
