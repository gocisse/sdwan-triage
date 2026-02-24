package output

import (
	"encoding/json"
	"fmt"
	"html/template"
	"math"
	"os"
	"strings"

	"github.com/gocisse/sdwan-triage/pkg/models"
)

// ReportSummary contains lightweight summary data suitable for inline embedding.
// This is rendered immediately without blocking the browser.
type ReportSummary struct {
	// Metadata
	FileName    string `json:"file_name"`
	FileSize    string `json:"file_size"`
	PacketCount int    `json:"packet_count"`
	Duration    string `json:"duration"`
	GeneratedAt string `json:"generated_at"`

	// Risk
	RiskScore          int      `json:"risk_score"`
	RiskLevel          string   `json:"risk_level"`
	TopIssue           string   `json:"top_issue"`
	TopIssueCount      int      `json:"top_issue_count"`
	RecommendedActions []string `json:"recommended_actions,omitempty"`

	// Counts (for sidebar badges and executive summary)
	Counts ReportCounts `json:"counts"`

	// Small datasets that are always inline (typically <100 items)
	DNSAnomalies      []models.DNSAnomaly     `json:"dns_anomalies,omitempty"`
	ARPConflicts      []models.ARPConflict    `json:"arp_conflicts,omitempty"`
	SuspiciousTraffic []models.SuspiciousFlow `json:"suspicious_traffic,omitempty"`
	BGPIndicators     []models.BGPIndicator   `json:"bgp_hijack_indicators,omitempty"`
	SDWANVendors      []models.SDWANVendor    `json:"sdwan_vendors,omitempty"`
	RootCauseChains   []models.RootCauseChain `json:"root_cause_chains,omitempty"`

	// Security (usually small)
	Security *models.SecurityAnalysis `json:"security,omitempty"`

	// Chunk metadata — tells the frontend how many paginated chunks exist
	FlowChunks int `json:"flow_chunks"` // Number of flow data chunks
	TotalFlows int `json:"total_flows"` // Total flow count across all chunks
}

// ReportCounts holds finding counts for the sidebar and executive summary.
type ReportCounts struct {
	DNSAnomalies       int    `json:"dns_anomalies"`
	TCPRetransmissions int    `json:"tcp_retransmissions"`
	ARPConflicts       int    `json:"arp_conflicts"`
	SuspiciousTraffic  int    `json:"suspicious_traffic"`
	FailedHandshakes   int    `json:"failed_handshakes"`
	TLSCerts           int    `json:"tls_certs"`
	HTTPErrors         int    `json:"http_errors"`
	BGPIndicators      int    `json:"bgp_indicators"`
	DDoSAttacks        int    `json:"ddos_attacks"`
	PortScans          int    `json:"port_scans"`
	IOCMatches         int    `json:"ioc_matches"`
	TLSWeaknesses      int    `json:"tls_weaknesses"`
	HighRTTFlows       int    `json:"high_rtt_flows"`
	DevicesDetected    int    `json:"devices_detected"`
	TunnelsDetected    int    `json:"tunnels_detected"`
	TotalBytes         uint64 `json:"total_bytes"`
}

// FlowDataChunk contains a page of flow data for lazy loading.
type FlowDataChunk struct {
	ChunkIndex  int                  `json:"chunk_index"`
	TotalChunks int                  `json:"total_chunks"`
	Flows       []models.TrafficFlow `json:"flows"`

	// Also paginate large TCP datasets
	TCPRetransmissions []models.TCPFlow       `json:"tcp_retransmissions,omitempty"`
	RTTAnalysis        []models.RTTFlow       `json:"rtt_analysis,omitempty"`
	Timeline           []models.TimelineEvent `json:"timeline,omitempty"`
}

const (
	// DefaultChunkSize is the number of flows per chunk.
	// Tuned so each chunk is ~200KB of JSON, keeping parse time under 50ms.
	DefaultChunkSize = 500
)

// SplitReportData splits a TriageReport into a lightweight summary and paginated flow chunks.
// The summary is small enough to embed inline in HTML (<50KB typically).
// Flow chunks are written as separate JSON blobs that the frontend fetches on demand.
func SplitReportData(r *models.TriageReport, chunkSize int) (*ReportSummary, []FlowDataChunk) {
	if chunkSize <= 0 {
		chunkSize = DefaultChunkSize
	}

	// Build counts
	counts := ReportCounts{
		DNSAnomalies:       len(r.DNSAnomalies),
		TCPRetransmissions: len(r.TCPRetransmissions),
		ARPConflicts:       len(r.ARPConflicts),
		SuspiciousTraffic:  len(r.SuspiciousTraffic),
		FailedHandshakes:   len(r.FailedHandshakes),
		TLSCerts:           len(r.TLSCerts),
		HTTPErrors:         len(r.HTTPErrors),
		BGPIndicators:      len(r.BGPHijackIndicators),
		TLSWeaknesses:      len(r.Security.TLSSecurityFindings),
		DDoSAttacks:        len(r.Security.DDoSFindings),
		PortScans:          len(r.Security.PortScanFindings),
		IOCMatches:         len(r.Security.IOCFindings),
		HighRTTFlows:       len(r.RTTAnalysis),
		DevicesDetected:    len(r.DeviceFingerprinting),
		TunnelsDetected:    len(r.TunnelAnalysis),
		TotalBytes:         r.TotalBytes,
	}

	// Collect all flow-like data for chunking
	allFlows := r.TrafficAnalysis
	totalFlows := len(allFlows)
	numChunks := int(math.Ceil(float64(totalFlows) / float64(chunkSize)))
	if numChunks < 1 {
		numChunks = 1 // At least one chunk even if empty
	}

	// Also chunk retransmissions and timeline
	allRetrans := r.TCPRetransmissions
	allRTT := r.RTTAnalysis
	allTimeline := r.Timeline

	// Build chunks
	chunks := make([]FlowDataChunk, 0, numChunks)
	for i := 0; i < numChunks; i++ {
		start := i * chunkSize
		end := start + chunkSize

		chunk := FlowDataChunk{
			ChunkIndex:  i,
			TotalChunks: numChunks,
		}

		// Flows
		if start < len(allFlows) {
			if end > len(allFlows) {
				end = len(allFlows)
			}
			chunk.Flows = allFlows[start:end]
		}

		// Distribute retransmissions across chunks proportionally
		retransStart := i * chunkSize
		retransEnd := retransStart + chunkSize
		if retransStart < len(allRetrans) {
			if retransEnd > len(allRetrans) {
				retransEnd = len(allRetrans)
			}
			chunk.TCPRetransmissions = allRetrans[retransStart:retransEnd]
		}

		// RTT analysis
		rttStart := i * chunkSize
		rttEnd := rttStart + chunkSize
		if rttStart < len(allRTT) {
			if rttEnd > len(allRTT) {
				rttEnd = len(allRTT)
			}
			chunk.RTTAnalysis = allRTT[rttStart:rttEnd]
		}

		// Timeline (only in first chunk)
		if i == 0 && len(allTimeline) > 0 {
			maxTimeline := chunkSize
			if len(allTimeline) < maxTimeline {
				maxTimeline = len(allTimeline)
			}
			chunk.Timeline = allTimeline[:maxTimeline]
		}

		chunks = append(chunks, chunk)
	}

	// Build summary
	summary := &ReportSummary{
		RiskScore:          r.RiskScore,
		RiskLevel:          r.RiskLevel,
		TopIssue:           r.TopIssue,
		TopIssueCount:      r.TopIssueCount,
		RecommendedActions: r.RecommendedActions,
		Counts:             counts,
		DNSAnomalies:       r.DNSAnomalies,
		ARPConflicts:       r.ARPConflicts,
		SuspiciousTraffic:  r.SuspiciousTraffic,
		BGPIndicators:      r.BGPHijackIndicators,
		RootCauseChains:    r.RootCauseChains,
		Security:           &r.Security,
		FlowChunks:         numChunks,
		TotalFlows:         totalFlows,
	}

	return summary, chunks
}

// MarshalSummaryJSON returns the summary as compact JSON.
func MarshalSummaryJSON(summary *ReportSummary) ([]byte, error) {
	return json.Marshal(summary)
}

// MarshalChunkJSON returns a single flow chunk as compact JSON.
func MarshalChunkJSON(chunk *FlowDataChunk) ([]byte, error) {
	return json.Marshal(chunk)
}

// GenerateSplitHTMLReport generates an HTML report with split data:
//   - Summary JSON is embedded inline in a <script> tag
//   - Flow chunks are embedded as separate <script type="application/json"> tags
//     with data-chunk-index attributes for lazy parsing
//
// This is the recommended report format for large PCAPs (>10k flows) as it:
//   - Reduces initial page load time by deferring large JSON parsing
//   - Enables progressive/lazy loading of flow data in the frontend
//   - Keeps the summary lightweight for immediate display
func GenerateSplitHTMLReport(r *models.TriageReport, filename string, pcapFile string) error {
	summary, chunks := SplitReportData(r, DefaultChunkSize)

	summaryJSON, err := MarshalSummaryJSON(summary)
	if err != nil {
		return fmt.Errorf("failed to marshal summary: %w", err)
	}

	// Build chunk script tags with lazy-load markers
	var chunkScripts strings.Builder
	for _, chunk := range chunks {
		chunkJSON, err := MarshalChunkJSON(&chunk)
		if err != nil {
			return fmt.Errorf("failed to marshal chunk %d: %w", chunk.ChunkIndex, err)
		}
		// Use data-lazy attribute to signal frontend to parse on-demand
		fmt.Fprintf(&chunkScripts,
			`<script type="application/json" id="flow-chunk-%d" data-chunk-index="%d" data-lazy="true">%s</script>`+"\n",
			chunk.ChunkIndex, chunk.ChunkIndex, string(chunkJSON),
		)
	}

	// Generate the report with split data injection
	return generateSplitHTMLReportInternal(r, filename, pcapFile, summaryJSON, chunkScripts.String(), summary)
}

// generateSplitHTMLReportInternal creates the HTML with split data injection.
// It embeds the summary JSON inline and adds chunk script tags for lazy loading.
func generateSplitHTMLReportInternal(r *models.TriageReport, filename string, pcapFile string, summaryJSON []byte, chunkScripts string, summary *ReportSummary) error {
	// Build the ReportData view model for the template
	data := prepareReportData(r, pcapFile)

	// Add split-specific fields to the template data
	// These are injected as additional script tags in the HTML head
	type SplitReportData struct {
		ReportData
		SummaryJSON   string `html:"summary_json"`
		ChunkScripts  string `html:"chunk_scripts"`
		FlowChunks    int    `html:"flow_chunks"`
		TotalFlows    int    `html:"total_flows"`
		IsSplitReport bool   `html:"is_split_report"`
	}

	splitData := SplitReportData{
		ReportData:    *data,
		SummaryJSON:   string(summaryJSON),
		ChunkScripts:  chunkScripts,
		FlowChunks:    summary.FlowChunks,
		TotalFlows:    summary.TotalFlows,
		IsSplitReport: true,
	}

	// Parse and execute the enterprise template with split data
	tmpl, err := template.New("enterprise-split").Funcs(template.FuncMap{
		"safe": func(s string) template.HTML { return template.HTML(s) },
	}).Parse(getEnterpriseSplitTemplate())
	if err != nil {
		return fmt.Errorf("failed to parse split template: %w", err)
	}

	// Create output file
	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	defer file.Close()

	if err := tmpl.Execute(file, splitData); err != nil {
		return fmt.Errorf("failed to execute template: %w", err)
	}

	return nil
}

// getEnterpriseSplitTemplate returns the HTML template with split data injection points.
// This extends the standard enterprise template with lazy-load chunk support.
func getEnterpriseSplitTemplate() string {
	// This is a minimal wrapper that injects split data into the enterprise template
	// The full template is in enterprise-dashboard.html, this adds the split-specific parts
	return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SD-WAN Triage Report</title>
    <style>` + enterpriseCSSContent + `</style>
</head>
<body>
    <!-- Split Report Summary (inline for immediate display) -->
    <script type="application/json" id="report-summary">{{.SummaryJSON | safe}}</script>
    
    <!-- Flow Data Chunks (lazy-loaded) -->
    {{.ChunkScripts | safe}}
    
    <!-- Main Report Content -->
    <div id="app"></div>
    
    <script>
        // Lazy-load chunk parser
        window.getFlowChunk = function(index) {
            const chunk = document.getElementById('flow-chunk-' + index);
            if (chunk && chunk.getAttribute('data-lazy') === 'true') {
                try {
                    return JSON.parse(chunk.textContent);
                } catch (e) {
                    console.error('Failed to parse chunk ' + index, e);
                    return null;
                }
            }
            return null;
        };
        
        // Get summary data immediately
        window.getReportSummary = function() {
            const summary = document.getElementById('report-summary');
            if (summary) {
                try {
                    return JSON.parse(summary.textContent);
                } catch (e) {
                    console.error('Failed to parse summary', e);
                    return null;
                }
            }
            return null;
        };
        
        // Total chunks available
        window.totalFlowChunks = {{.FlowChunks}};
        window.totalFlows = {{.TotalFlows}};
    </script>
    <script>` + jsContent + `</script>
</body>
</html>`
}
