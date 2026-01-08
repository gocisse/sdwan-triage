package output

import (
	"encoding/csv"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gocisse/sdwan-triage/pkg/models"
)

// CSVExportResult contains info about generated CSV files
type CSVExportResult struct {
	Files   []string
	BaseDir string
}

// GenerateCSVReports generates multiple CSV files for different finding types
func GenerateCSVReports(r *models.TriageReport, baseFilename string) (*CSVExportResult, error) {
	// Create output directory based on filename
	dir := filepath.Dir(baseFilename)
	baseName := strings.TrimSuffix(filepath.Base(baseFilename), filepath.Ext(baseFilename))

	result := &CSVExportResult{
		Files:   []string{},
		BaseDir: dir,
	}

	// Generate summary CSV
	summaryFile := filepath.Join(dir, baseName+"_summary.csv")
	if err := generateSummaryCSV(r, summaryFile); err != nil {
		return nil, fmt.Errorf("failed to generate summary CSV: %w", err)
	}
	result.Files = append(result.Files, summaryFile)

	// Generate DNS anomalies CSV if any exist
	if len(r.DNSAnomalies) > 0 {
		dnsFile := filepath.Join(dir, baseName+"_dns_anomalies.csv")
		if err := generateDNSAnomaliesCSV(r.DNSAnomalies, dnsFile); err != nil {
			return nil, fmt.Errorf("failed to generate DNS anomalies CSV: %w", err)
		}
		result.Files = append(result.Files, dnsFile)
	}

	// Generate TCP retransmissions CSV if any exist
	if len(r.TCPRetransmissions) > 0 {
		tcpFile := filepath.Join(dir, baseName+"_tcp_retransmissions.csv")
		if err := generateTCPRetransmissionsCSV(r.TCPRetransmissions, tcpFile); err != nil {
			return nil, fmt.Errorf("failed to generate TCP retransmissions CSV: %w", err)
		}
		result.Files = append(result.Files, tcpFile)
	}

	// Generate ARP conflicts CSV if any exist
	if len(r.ARPConflicts) > 0 {
		arpFile := filepath.Join(dir, baseName+"_arp_conflicts.csv")
		if err := generateARPConflictsCSV(r.ARPConflicts, arpFile); err != nil {
			return nil, fmt.Errorf("failed to generate ARP conflicts CSV: %w", err)
		}
		result.Files = append(result.Files, arpFile)
	}

	// Generate suspicious traffic CSV if any exist
	if len(r.SuspiciousTraffic) > 0 {
		suspFile := filepath.Join(dir, baseName+"_suspicious_traffic.csv")
		if err := generateSuspiciousTrafficCSV(r.SuspiciousTraffic, suspFile); err != nil {
			return nil, fmt.Errorf("failed to generate suspicious traffic CSV: %w", err)
		}
		result.Files = append(result.Files, suspFile)
	}

	// Generate traffic analysis CSV
	if len(r.TrafficAnalysis) > 0 {
		trafficFile := filepath.Join(dir, baseName+"_traffic_flows.csv")
		if err := generateTrafficFlowsCSV(r.TrafficAnalysis, r.TotalBytes, trafficFile); err != nil {
			return nil, fmt.Errorf("failed to generate traffic flows CSV: %w", err)
		}
		result.Files = append(result.Files, trafficFile)
	}

	// Generate timeline events CSV if any exist
	if len(r.Timeline) > 0 {
		timelineFile := filepath.Join(dir, baseName+"_timeline_events.csv")
		if err := generateTimelineCSV(r.Timeline, timelineFile); err != nil {
			return nil, fmt.Errorf("failed to generate timeline CSV: %w", err)
		}
		result.Files = append(result.Files, timelineFile)
	}

	// Generate device fingerprints CSV if any exist
	if len(r.DeviceFingerprinting) > 0 {
		devicesFile := filepath.Join(dir, baseName+"_device_fingerprints.csv")
		if err := generateDeviceFingerprintsCSV(r.DeviceFingerprinting, devicesFile); err != nil {
			return nil, fmt.Errorf("failed to generate device fingerprints CSV: %w", err)
		}
		result.Files = append(result.Files, devicesFile)
	}

	// Generate RTT analysis CSV if any exist
	if len(r.RTTAnalysis) > 0 {
		rttFile := filepath.Join(dir, baseName+"_rtt_analysis.csv")
		if err := generateRTTAnalysisCSV(r.RTTAnalysis, rttFile); err != nil {
			return nil, fmt.Errorf("failed to generate RTT analysis CSV: %w", err)
		}
		result.Files = append(result.Files, rttFile)
	}

	// Generate HTTP errors CSV if any exist
	if len(r.HTTPErrors) > 0 {
		httpFile := filepath.Join(dir, baseName+"_http_errors.csv")
		if err := generateHTTPErrorsCSV(r.HTTPErrors, httpFile); err != nil {
			return nil, fmt.Errorf("failed to generate HTTP errors CSV: %w", err)
		}
		result.Files = append(result.Files, httpFile)
	}

	// Generate TLS certificates CSV if any exist
	if len(r.TLSCerts) > 0 {
		tlsFile := filepath.Join(dir, baseName+"_tls_certificates.csv")
		if err := generateTLSCertsCSV(r.TLSCerts, tlsFile); err != nil {
			return nil, fmt.Errorf("failed to generate TLS certificates CSV: %w", err)
		}
		result.Files = append(result.Files, tlsFile)
	}

	// Generate failed handshakes CSV if any exist
	if len(r.FailedHandshakes) > 0 {
		handshakeFile := filepath.Join(dir, baseName+"_failed_handshakes.csv")
		if err := generateFailedHandshakesCSV(r.FailedHandshakes, handshakeFile); err != nil {
			return nil, fmt.Errorf("failed to generate failed handshakes CSV: %w", err)
		}
		result.Files = append(result.Files, handshakeFile)
	}

	return result, nil
}

// generateSummaryCSV creates a summary CSV with overall statistics
func generateSummaryCSV(r *models.TriageReport, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	// Write header
	if err := writer.Write([]string{"Metric", "Value", "Description"}); err != nil {
		return err
	}

	// Calculate health status
	criticalIssues := len(r.DNSAnomalies) + len(r.ARPConflicts)
	performanceIssues := len(r.TCPRetransmissions) + len(r.FailedHandshakes)
	securityConcerns := len(r.SuspiciousTraffic)

	healthStatus := "GOOD"
	if criticalIssues > 0 {
		healthStatus = "CRITICAL"
	} else if performanceIssues > 0 || securityConcerns > 0 {
		healthStatus = "WARNING"
	}

	// Write summary rows
	rows := [][]string{
		{"Report Generated", time.Now().Format("2006-01-02 15:04:05"), "Timestamp of report generation"},
		{"Network Health Status", healthStatus, "Overall network health assessment"},
		{"Total Packets Analyzed", "N/A", "Number of packets processed"},
		{"Total Traffic Volume", formatBytesForCSV(r.TotalBytes), "Total bytes transferred"},
		{"DNS Anomalies", fmt.Sprintf("%d", len(r.DNSAnomalies)), "Suspicious DNS responses detected"},
		{"TCP Retransmissions", fmt.Sprintf("%d", len(r.TCPRetransmissions)), "TCP packets requiring retransmission"},
		{"Failed TCP Handshakes", fmt.Sprintf("%d", len(r.FailedHandshakes)), "TCP connections that failed to establish"},
		{"ARP Conflicts", fmt.Sprintf("%d", len(r.ARPConflicts)), "IP addresses with multiple MAC addresses"},
		{"Suspicious Traffic Flows", fmt.Sprintf("%d", len(r.SuspiciousTraffic)), "Traffic to/from suspicious ports"},
		{"TLS Certificates", fmt.Sprintf("%d", len(r.TLSCerts)), "TLS certificates observed"},
		{"Devices Detected", fmt.Sprintf("%d", len(r.DeviceFingerprinting)), "Unique devices identified by fingerprint"},
		{"High RTT Flows", fmt.Sprintf("%d", len(r.RTTAnalysis)), "Flows with high round-trip time"},
		{"HTTP/2 Flows", fmt.Sprintf("%d", len(r.HTTP2Flows)), "HTTP/2 connections detected"},
		{"QUIC Flows", fmt.Sprintf("%d", len(r.QUICFlows)), "QUIC connections detected"},
	}

	for _, row := range rows {
		if err := writer.Write(row); err != nil {
			return err
		}
	}

	return nil
}

// generateDNSAnomaliesCSV creates a CSV for DNS anomalies
func generateDNSAnomaliesCSV(anomalies []models.DNSAnomaly, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	// Write header
	header := []string{
		"Finding Type",
		"Query Domain",
		"Answer IP",
		"DNS Server IP",
		"Reason",
		"Plain Language Description",
		"Severity Level",
		"Recommended Action",
	}
	if err := writer.Write(header); err != nil {
		return err
	}

	// Write data rows
	for _, a := range anomalies {
		description := fmt.Sprintf("DNS query for '%s' returned suspicious IP '%s' from server '%s'",
			a.Query, a.AnswerIP, a.ServerIP)
		action := "Verify DNS server configuration; check for DNS hijacking; consider using DNS-over-HTTPS"

		row := []string{
			"DNS Anomaly",
			a.Query,
			a.AnswerIP,
			a.ServerIP,
			a.Reason,
			description,
			"High",
			action,
		}
		if err := writer.Write(row); err != nil {
			return err
		}
	}

	return nil
}

// generateTCPRetransmissionsCSV creates a CSV for TCP retransmissions
func generateTCPRetransmissionsCSV(flows []models.TCPFlow, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	// Write header
	header := []string{
		"Finding Type",
		"Source IP",
		"Source Port",
		"Destination IP",
		"Destination Port",
		"Plain Language Description",
		"Severity Level",
		"Recommended Action",
	}
	if err := writer.Write(header); err != nil {
		return err
	}

	// Write data rows
	for _, f := range flows {
		description := fmt.Sprintf("TCP retransmission detected from %s:%d to %s:%d indicating packet loss or congestion",
			f.SrcIP, f.SrcPort, f.DstIP, f.DstPort)
		action := "Check network path for congestion; review QoS settings; verify MTU configuration"

		row := []string{
			"TCP Retransmission",
			f.SrcIP,
			fmt.Sprintf("%d", f.SrcPort),
			f.DstIP,
			fmt.Sprintf("%d", f.DstPort),
			description,
			"Medium",
			action,
		}
		if err := writer.Write(row); err != nil {
			return err
		}
	}

	return nil
}

// generateARPConflictsCSV creates a CSV for ARP conflicts
func generateARPConflictsCSV(conflicts []models.ARPConflict, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	// Write header
	header := []string{
		"Finding Type",
		"IP Address",
		"MAC Address 1",
		"MAC Address 2",
		"Plain Language Description",
		"Severity Level",
		"Recommended Action",
	}
	if err := writer.Write(header); err != nil {
		return err
	}

	// Write data rows
	for _, c := range conflicts {
		description := fmt.Sprintf("IP address %s is claimed by two different MAC addresses: %s and %s",
			c.IP, c.MAC1, c.MAC2)
		action := "Investigate potential ARP spoofing attack; check DHCP for duplicate assignments; enable DAI on switches"

		row := []string{
			"ARP Conflict",
			c.IP,
			c.MAC1,
			c.MAC2,
			description,
			"High",
			action,
		}
		if err := writer.Write(row); err != nil {
			return err
		}
	}

	return nil
}

// generateSuspiciousTrafficCSV creates a CSV for suspicious traffic
func generateSuspiciousTrafficCSV(flows []models.SuspiciousFlow, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	// Write header
	header := []string{
		"Finding Type",
		"Source IP",
		"Source Port",
		"Destination IP",
		"Destination Port",
		"Reason",
		"Plain Language Description",
		"Severity Level",
		"Recommended Action",
	}
	if err := writer.Write(header); err != nil {
		return err
	}

	// Write data rows
	for _, f := range flows {
		description := fmt.Sprintf("Suspicious traffic from %s:%d to %s:%d - %s",
			f.SrcIP, f.SrcPort, f.DstIP, f.DstPort, f.Reason)
		action := "Block traffic to suspicious endpoints; investigate source device for malware; review firewall logs"

		row := []string{
			"Suspicious Traffic",
			f.SrcIP,
			fmt.Sprintf("%d", f.SrcPort),
			f.DstIP,
			fmt.Sprintf("%d", f.DstPort),
			f.Reason,
			description,
			"High",
			action,
		}
		if err := writer.Write(row); err != nil {
			return err
		}
	}

	return nil
}

// generateTrafficFlowsCSV creates a CSV for traffic analysis
func generateTrafficFlowsCSV(flows []models.TrafficFlow, totalBytes uint64, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	// Write header
	header := []string{
		"Source IP",
		"Source Port",
		"Destination IP",
		"Destination Port",
		"Protocol",
		"Total Bytes",
		"Bytes (Human Readable)",
		"Percentage of Total",
	}
	if err := writer.Write(header); err != nil {
		return err
	}

	// Write data rows
	for _, f := range flows {
		pct := float64(0)
		if totalBytes > 0 {
			pct = float64(f.TotalBytes) / float64(totalBytes) * 100
		}

		row := []string{
			f.SrcIP,
			fmt.Sprintf("%d", f.SrcPort),
			f.DstIP,
			fmt.Sprintf("%d", f.DstPort),
			f.Protocol,
			fmt.Sprintf("%d", f.TotalBytes),
			formatBytesForCSV(f.TotalBytes),
			fmt.Sprintf("%.2f%%", pct),
		}
		if err := writer.Write(row); err != nil {
			return err
		}
	}

	return nil
}

// generateTimelineCSV creates a CSV for timeline events
func generateTimelineCSV(events []models.TimelineEvent, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	// Write header
	header := []string{
		"Timestamp",
		"Event Type",
		"Source IP",
		"Destination IP",
		"Detail",
	}
	if err := writer.Write(header); err != nil {
		return err
	}

	// Write data rows
	for _, e := range events {
		timestamp := time.Unix(int64(e.Timestamp), 0).Format("2006-01-02 15:04:05.000")

		row := []string{
			timestamp,
			e.EventType,
			e.SourceIP,
			e.DestinationIP,
			e.Detail,
		}
		if err := writer.Write(row); err != nil {
			return err
		}
	}

	return nil
}

// generateDeviceFingerprintsCSV creates a CSV for device fingerprints
func generateDeviceFingerprintsCSV(fingerprints []models.DeviceFingerprint, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	// Write header
	header := []string{
		"IP Address",
		"OS Type",
		"OS Name",
		"Confidence Level",
	}
	if err := writer.Write(header); err != nil {
		return err
	}

	// Write data rows
	for _, f := range fingerprints {
		row := []string{
			f.SrcIP,
			f.DeviceType,
			f.OSGuess,
			f.Confidence,
		}
		if err := writer.Write(row); err != nil {
			return err
		}
	}

	return nil
}

// generateRTTAnalysisCSV creates a CSV for RTT analysis
func generateRTTAnalysisCSV(flows []models.RTTFlow, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	// Write header
	header := []string{
		"Source IP",
		"Source Port",
		"Destination IP",
		"Destination Port",
		"Minimum RTT (ms)",
		"Maximum RTT (ms)",
		"Average RTT (ms)",
		"Sample Size",
	}
	if err := writer.Write(header); err != nil {
		return err
	}

	// Write data rows
	for _, f := range flows {
		row := []string{
			f.SrcIP,
			fmt.Sprintf("%d", f.SrcPort),
			f.DstIP,
			fmt.Sprintf("%d", f.DstPort),
			fmt.Sprintf("%.2f", f.MinRTT),
			fmt.Sprintf("%.2f", f.MaxRTT),
			fmt.Sprintf("%.2f", f.AvgRTT),
			fmt.Sprintf("%d", f.SampleSize),
		}
		if err := writer.Write(row); err != nil {
			return err
		}
	}

	return nil
}

// generateHTTPErrorsCSV creates a CSV for HTTP errors
func generateHTTPErrorsCSV(errors []models.HTTPError, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	header := []string{
		"Finding Type",
		"Method",
		"URL",
		"Status Code",
		"Reason",
		"Source IP",
		"Destination IP",
		"Plain Language Description",
		"Severity Level",
		"Recommended Action",
	}
	if err := writer.Write(header); err != nil {
		return err
	}

	for _, e := range errors {
		url := e.Host + e.Path
		description := fmt.Sprintf("HTTP %s request to %s returned error %d",
			e.Method, url, e.Code)
		action := "Check server availability; verify URL is correct; review server logs"

		row := []string{
			"HTTP Error",
			e.Method,
			url,
			fmt.Sprintf("%d", e.Code),
			"",
			e.Host,
			"",
			description,
			"Medium",
			action,
		}
		if err := writer.Write(row); err != nil {
			return err
		}
	}

	return nil
}

// generateTLSCertsCSV creates a CSV for TLS certificates
func generateTLSCertsCSV(certs []models.TLSCertInfo, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	header := []string{
		"Subject",
		"Issuer",
		"Valid From",
		"Valid Until",
		"Server IP",
		"Server Name",
		"Fingerprint",
	}
	if err := writer.Write(header); err != nil {
		return err
	}

	for _, c := range certs {
		row := []string{
			c.Subject,
			c.Issuer,
			c.NotBefore,
			c.NotAfter,
			c.ServerIP,
			c.ServerName,
			c.Fingerprint,
		}
		if err := writer.Write(row); err != nil {
			return err
		}
	}

	return nil
}

// generateFailedHandshakesCSV creates a CSV for failed TCP handshakes
func generateFailedHandshakesCSV(flows []models.TCPFlow, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	header := []string{
		"Finding Type",
		"Source IP",
		"Source Port",
		"Destination IP",
		"Destination Port",
		"Plain Language Description",
		"Severity Level",
		"Recommended Action",
	}
	if err := writer.Write(header); err != nil {
		return err
	}

	for _, f := range flows {
		description := fmt.Sprintf("TCP handshake from %s:%d to %s:%d failed (RST received)",
			f.SrcIP, f.SrcPort, f.DstIP, f.DstPort)
		action := "Check if destination service is running; verify firewall rules; check network connectivity"

		row := []string{
			"Failed TCP Handshake",
			f.SrcIP,
			fmt.Sprintf("%d", f.SrcPort),
			f.DstIP,
			fmt.Sprintf("%d", f.DstPort),
			description,
			"Medium",
			action,
		}
		if err := writer.Write(row); err != nil {
			return err
		}
	}

	return nil
}

// formatBytesForCSV formats bytes for CSV output
func formatBytesForCSV(bytes uint64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := uint64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.2f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

// GenerateSingleCSV generates a single consolidated CSV file (legacy support)
func GenerateSingleCSV(r *models.TriageReport, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	// Write header
	header := []string{
		"Category",
		"Finding Type",
		"Source IP",
		"Source Port",
		"Destination IP",
		"Destination Port",
		"Detail",
		"Severity",
		"Recommended Action",
	}
	if err := writer.Write(header); err != nil {
		return err
	}

	// DNS Anomalies
	for _, a := range r.DNSAnomalies {
		row := []string{
			"Security",
			"DNS Anomaly",
			a.ServerIP,
			"53",
			a.AnswerIP,
			"",
			fmt.Sprintf("Query: %s - %s", a.Query, a.Reason),
			"High",
			"Verify DNS configuration; check for DNS hijacking",
		}
		writer.Write(row)
	}

	// TCP Retransmissions
	for _, f := range r.TCPRetransmissions {
		row := []string{
			"Performance",
			"TCP Retransmission",
			f.SrcIP,
			fmt.Sprintf("%d", f.SrcPort),
			f.DstIP,
			fmt.Sprintf("%d", f.DstPort),
			"Packet retransmission detected",
			"Medium",
			"Check network path for congestion",
		}
		writer.Write(row)
	}

	// ARP Conflicts
	for _, c := range r.ARPConflicts {
		row := []string{
			"Security",
			"ARP Conflict",
			c.IP,
			"",
			"",
			"",
			fmt.Sprintf("MAC conflict: %s vs %s", c.MAC1, c.MAC2),
			"High",
			"Investigate ARP spoofing; check DHCP",
		}
		writer.Write(row)
	}

	// Suspicious Traffic
	for _, f := range r.SuspiciousTraffic {
		row := []string{
			"Security",
			"Suspicious Traffic",
			f.SrcIP,
			fmt.Sprintf("%d", f.SrcPort),
			f.DstIP,
			fmt.Sprintf("%d", f.DstPort),
			f.Reason,
			"High",
			"Block suspicious endpoints; investigate for malware",
		}
		writer.Write(row)
	}

	// Traffic Flows (top 20)
	count := 0
	for _, f := range r.TrafficAnalysis {
		if count >= 20 {
			break
		}
		row := []string{
			"Traffic",
			"Traffic Flow",
			f.SrcIP,
			fmt.Sprintf("%d", f.SrcPort),
			f.DstIP,
			fmt.Sprintf("%d", f.DstPort),
			fmt.Sprintf("%s - %s", f.Protocol, formatBytesForCSV(f.TotalBytes)),
			"Info",
			"",
		}
		writer.Write(row)
		count++
	}

	return nil
}
