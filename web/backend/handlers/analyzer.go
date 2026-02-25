// Analyzer integration module - connects the web handlers to the existing analysis engine

package handlers

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/gocisse/sdwan-triage/pkg/analyzer"
	"github.com/gocisse/sdwan-triage/pkg/models"
	"github.com/gocisse/sdwan-triage/pkg/output"
	"github.com/gocisse/sdwan-triage/web/backend/storage"
)

// WebResultsWrapper wraps TriageReport with metadata fields expected by the frontend
type WebResultsWrapper struct {
	// Metadata fields for frontend display
	FileName      string `json:"file_name"`
	FileSize      string `json:"file_size"`
	PacketCount   int    `json:"packet_count"`
	Duration      string `json:"duration"`
	GeneratedAt   string `json:"generated_at"`
	CaptureFormat string `json:"capture_format,omitempty"` // "pcap" or "pcapng"

	// Embed all TriageReport fields
	*models.TriageReport
}

// AnalyzePCAP performs the actual PCAP analysis using the existing engine
func AnalyzePCAP(store *storage.Storage, job *storage.AnalysisJob) (string, string, error) {
	log.Printf("[ANALYSIS] Starting analysis for job: %s, file: %s", job.ID, job.FileName)

	// Update progress: Starting
	store.UpdateProgress(job.ID, 5, "Opening PCAP file...", 60)

	// Open capture file (auto-detects pcap vs pcapng)
	capHandle, err := analyzer.OpenCapture(job.FilePath)
	if err != nil {
		log.Printf("[ANALYSIS] Failed to open capture file: %v", err)
		return "", "", fmt.Errorf("failed to open capture file: %w", err)
	}
	defer capHandle.Close()
	reader := capHandle.Reader

	log.Printf("[ANALYSIS] Capture file opened (format: %s): %s", capHandle.Format, job.FilePath)

	// Update progress: Analyzing
	store.UpdateProgress(job.ID, 10, "Analyzing packets...", 50)

	// Create processor with options (qosEnabled=true, verbose=false)
	processor := analyzer.NewProcessorWithOptions(true, false)

	// Initialize analysis state and report
	state := models.NewAnalysisState()
	report := &models.TriageReport{}

	// Use the existing Process method which handles everything
	startTime := time.Now()

	// Start a goroutine to update progress periodically
	done := make(chan bool, 1)
	go func() {
		progress := 10
		for {
			select {
			case <-done:
				return
			case <-time.After(500 * time.Millisecond):
				// Check if cancelled
				currentJob, err := store.GetJob(job.ID)
				if err != nil || currentJob.Status == storage.StatusCancelled {
					return
				}

				// Increment progress slowly
				if progress < 80 {
					progress += 2
				}
				elapsed := time.Since(startTime)
				remaining := estimateRemaining(progress, elapsed)
				store.UpdateProgress(job.ID, progress, "Analyzing packets...", int(remaining.Seconds()))
			}
		}
	}()

	// Process the PCAP file using the existing analyzer
	err = processor.Process(reader, state, report, nil)
	done <- true // Stop progress updates

	analysisDuration := time.Since(startTime)
	log.Printf("[ANALYSIS] Packet processing completed in %v", analysisDuration)

	if err != nil {
		log.Printf("[ANALYSIS] Analysis failed: %v", err)
		return "", "", fmt.Errorf("analysis failed: %w", err)
	}

	// Check if cancelled
	currentJob, err := store.GetJob(job.ID)
	if err != nil || currentJob.Status == storage.StatusCancelled {
		log.Printf("[ANALYSIS] Analysis cancelled")
		return "", "", fmt.Errorf("analysis cancelled")
	}

	// Update progress: Generating reports
	store.UpdateProgress(job.ID, 85, "Generating JSON results...", 10)

	// Create results directory
	resultsDir := filepath.Join(store.GetResultsDir(), job.ID)
	if err := os.MkdirAll(resultsDir, 0755); err != nil {
		log.Printf("[ANALYSIS] Failed to create results directory: %v", err)
		return "", "", fmt.Errorf("failed to create results directory: %w", err)
	}

	// Count packets from the report data
	packetCount := countPacketsFromReport(report)
	log.Printf("[ANALYSIS] Total packets analyzed: %d", packetCount)

	// Wrap report with metadata for frontend
	webResults := &WebResultsWrapper{
		FileName:      job.FileName,
		FileSize:      formatBytes(job.FileSize),
		PacketCount:   packetCount,
		Duration:      analysisDuration.Round(time.Millisecond).String(),
		GeneratedAt:   time.Now().Format(time.RFC3339),
		CaptureFormat: string(capHandle.Format),
		TriageReport:  report,
	}

	// Save JSON results with metadata
	jsonPath := filepath.Join(resultsDir, "results.json")
	jsonData, err := json.MarshalIndent(webResults, "", "  ")
	if err != nil {
		log.Printf("[ANALYSIS] Failed to marshal results: %v", err)
		return "", "", fmt.Errorf("failed to marshal results: %w", err)
	}
	if err := os.WriteFile(jsonPath, jsonData, 0644); err != nil {
		log.Printf("[ANALYSIS] Failed to write JSON results: %v", err)
		return "", "", fmt.Errorf("failed to write JSON results: %w", err)
	}

	log.Printf("[ANALYSIS] JSON results saved to: %s (%d bytes)", jsonPath, len(jsonData))

	// Update progress: Generating HTML
	store.UpdateProgress(job.ID, 95, "Generating HTML report...", 3)

	// Generate HTML report
	htmlPath := filepath.Join(resultsDir, "report.html")
	if err := output.GenerateHTMLReport(report, htmlPath, "enterprise"); err != nil {
		log.Printf("[ANALYSIS] Failed to generate HTML report: %v", err)
		return "", "", fmt.Errorf("failed to generate HTML report: %w", err)
	}

	log.Printf("[ANALYSIS] HTML report saved to: %s", htmlPath)

	// Update progress: Complete
	store.UpdateProgress(job.ID, 100, "Analysis complete!", 0)

	log.Printf("[ANALYSIS] Analysis completed successfully for job: %s", job.ID)

	return jsonPath, htmlPath, nil
}

// countPacketsFromReport estimates packet count from report data
func countPacketsFromReport(report *models.TriageReport) int {
	// Sum up packet counts from various sources in the report
	count := 0

	// Count from traffic analysis (use number of flows as estimate)
	count += len(report.TrafficAnalysis)

	// Count from TCP flows
	count += len(report.TCPRetransmissions)
	count += len(report.TLSFlows)
	count += len(report.HTTP2Flows)
	count += len(report.FailedHandshakes)

	// Count from UDP flows
	count += len(report.QUICFlows)

	// Add DNS records
	count += len(report.DNSDetails)

	// Add timeline events as proxy for packet activity
	count += len(report.Timeline)

	// If we have QoS analysis, use that packet count
	if report.QoSAnalysis != nil && report.QoSAnalysis.TotalPackets > 0 {
		return int(report.QoSAnalysis.TotalPackets)
	}

	// Estimate from total bytes if available (assume ~500 bytes per packet average)
	if count == 0 && report.TotalBytes > 0 {
		count = int(report.TotalBytes / 500)
	}

	return count
}

// calculateProgress calculates the progress percentage
func calculateProgress(current, estimated int) int {
	if estimated <= 0 {
		return 50 // Default to 50% if we can't estimate
	}

	progress := (current * 80) / estimated // Max 80% for packet processing
	if progress > 80 {
		progress = 80
	}
	if progress < 5 {
		progress = 5
	}
	return progress
}

// estimateRemaining estimates the remaining time
func estimateRemaining(progress int, elapsed time.Duration) time.Duration {
	if progress <= 5 {
		return 60 * time.Second // Default estimate
	}

	totalEstimate := elapsed * time.Duration(100) / time.Duration(progress)
	remaining := totalEstimate - elapsed

	if remaining < 0 {
		remaining = 0
	}
	return remaining
}

// formatBytes formats bytes to human-readable string
func formatBytes(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}
