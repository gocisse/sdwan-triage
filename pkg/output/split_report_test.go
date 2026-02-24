package output

import (
	"testing"

	"github.com/gocisse/sdwan-triage/pkg/models"
)

func TestSplitReportData(t *testing.T) {
	// Create a mock TriageReport with various data types
	report := &models.TriageReport{
		TotalBytes: 5000000,
		TrafficAnalysis: []models.TrafficFlow{
			{SrcIP: "192.168.1.1", DstIP: "10.0.0.1", Protocol: "TCP", TotalBytes: 1000},
			{SrcIP: "192.168.1.2", DstIP: "10.0.0.2", Protocol: "UDP", TotalBytes: 2000},
			{SrcIP: "192.168.1.3", DstIP: "10.0.0.3", Protocol: "TCP", TotalBytes: 3000},
		},
		TCPRetransmissions: []models.TCPFlow{
			{SrcIP: "192.168.1.1", DstIP: "10.0.0.1", SrcPort: 80, DstPort: 443},
			{SrcIP: "192.168.1.2", DstIP: "10.0.0.2", SrcPort: 8080, DstPort: 80},
		},
		RTTAnalysis: []models.RTTFlow{
			{SrcIP: "192.168.1.1", DstIP: "10.0.0.1", AvgRTT: 50.5, MaxRTT: 100.0},
			{SrcIP: "192.168.1.2", DstIP: "10.0.0.2", AvgRTT: 75.0, MaxRTT: 150.0},
		},
		DNSAnomalies: []models.DNSAnomaly{
			{Query: "test.example.com", AnswerIP: "1.2.3.4", Reason: "suspicious"},
		},
	}

	// Test with default chunk size
	summary, chunks := SplitReportData(report, DefaultChunkSize)

	// Verify summary
	if summary.TotalFlows != 3 {
		t.Errorf("expected total flows 3, got %d", summary.TotalFlows)
	}
	if summary.Counts.TCPRetransmissions != 2 {
		t.Errorf("expected retransmission count 2, got %d", summary.Counts.TCPRetransmissions)
	}
	if summary.Counts.DNSAnomalies != 1 {
		t.Errorf("expected DNS anomaly count 1, got %d", summary.Counts.DNSAnomalies)
	}

	// Verify chunks
	if len(chunks) == 0 {
		t.Error("expected at least one chunk")
	}

	// First chunk should have index 0
	if chunks[0].ChunkIndex != 0 {
		t.Errorf("expected first chunk index 0, got %d", chunks[0].ChunkIndex)
	}
}

func TestSplitReportDataWithLargeDataset(t *testing.T) {
	// Create a report with many traffic flows to test pagination
	report := &models.TriageReport{
		TotalBytes: 50000000,
	}

	// Create 1500 traffic flows (should result in 3 chunks with default size of 500)
	for i := 0; i < 1500; i++ {
		report.TrafficAnalysis = append(report.TrafficAnalysis, models.TrafficFlow{
			SrcIP:      "192.168.1.1",
			DstIP:      "10.0.0.1",
			Protocol:   "TCP",
			TotalBytes: uint64(i * 1000),
		})
	}

	summary, chunks := SplitReportData(report, DefaultChunkSize)

	// Verify summary
	if summary.TotalFlows != 1500 {
		t.Errorf("expected total flows 1500, got %d", summary.TotalFlows)
	}

	// Should have 3 chunks (500 flows each)
	if len(chunks) != 3 {
		t.Errorf("expected 3 chunks, got %d", len(chunks))
	}

	// Verify each chunk has correct index
	for i, chunk := range chunks {
		if chunk.ChunkIndex != i {
			t.Errorf("chunk %d has wrong index %d", i, chunk.ChunkIndex)
		}
	}

	// Verify total flows across chunks equals original
	totalFlowsInChunks := 0
	for _, chunk := range chunks {
		totalFlowsInChunks += len(chunk.Flows)
	}
	if totalFlowsInChunks != 1500 {
		t.Errorf("expected 1500 total flows in chunks, got %d", totalFlowsInChunks)
	}
}

func TestSplitReportDataWithEmptyReport(t *testing.T) {
	// Test with empty report
	report := &models.TriageReport{}

	summary, chunks := SplitReportData(report, DefaultChunkSize)

	// Should have zero counts
	if summary.TotalFlows != 0 {
		t.Errorf("expected total flows 0, got %d", summary.TotalFlows)
	}

	// Should have no chunks or one empty chunk
	if len(chunks) > 1 {
		t.Errorf("expected at most 1 chunk for empty report, got %d", len(chunks))
	}
}

func TestMarshalSummaryJSON(t *testing.T) {
	summary := &ReportSummary{
		FileName:    "test.pcap",
		FileSize:    "1.5 MB",
		PacketCount: 1000,
		Duration:    "60s",
		GeneratedAt: "2024-01-01T00:00:00Z",
		TotalFlows:  100,
		Counts: ReportCounts{
			TCPRetransmissions: 5,
			DNSAnomalies:       2,
		},
		FlowChunks: 1,
	}

	jsonBytes, err := MarshalSummaryJSON(summary)
	if err != nil {
		t.Fatalf("failed to marshal summary: %v", err)
	}

	// Verify JSON is valid and contains expected fields
	jsonStr := string(jsonBytes)
	if len(jsonStr) == 0 {
		t.Error("expected non-empty JSON output")
	}

	// Check for key fields
	expectedFields := []string{"file_name", "packet_count", "total_flows", "counts"}
	for _, field := range expectedFields {
		if !contains(jsonStr, field) {
			t.Errorf("expected JSON to contain field %q", field)
		}
	}
}

func TestMarshalChunkJSON(t *testing.T) {
	chunk := &FlowDataChunk{
		ChunkIndex:  0,
		TotalChunks: 3,
		Flows: []models.TrafficFlow{
			{SrcIP: "192.168.1.1", DstIP: "10.0.0.1", Protocol: "TCP", TotalBytes: 1000},
		},
	}

	jsonBytes, err := MarshalChunkJSON(chunk)
	if err != nil {
		t.Fatalf("failed to marshal chunk: %v", err)
	}

	// Verify JSON is valid
	jsonStr := string(jsonBytes)
	if len(jsonStr) == 0 {
		t.Error("expected non-empty JSON output")
	}

	// Check for chunk metadata
	expectedFields := []string{"chunk_index", "total_chunks", "flows"}
	for _, field := range expectedFields {
		if !contains(jsonStr, field) {
			t.Errorf("expected JSON to contain field %q", field)
		}
	}
}

// Helper function to check if a string contains a substring
func contains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
