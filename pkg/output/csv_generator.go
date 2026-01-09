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

	// Generate DDoS findings CSV if any exist
	if len(r.Security.DDoSFindings) > 0 {
		ddosFile := filepath.Join(dir, baseName+"_ddos_findings.csv")
		if err := generateDDoSFindingsCSV(r.Security.DDoSFindings, ddosFile); err != nil {
			return nil, fmt.Errorf("failed to generate DDoS findings CSV: %w", err)
		}
		result.Files = append(result.Files, ddosFile)
	}

	// Generate port scan findings CSV if any exist
	if len(r.Security.PortScanFindings) > 0 {
		portScanFile := filepath.Join(dir, baseName+"_port_scan_findings.csv")
		if err := generatePortScanFindingsCSV(r.Security.PortScanFindings, portScanFile); err != nil {
			return nil, fmt.Errorf("failed to generate port scan findings CSV: %w", err)
		}
		result.Files = append(result.Files, portScanFile)
	}

	// Generate IOC findings CSV if any exist
	if len(r.Security.IOCFindings) > 0 {
		iocFile := filepath.Join(dir, baseName+"_ioc_findings.csv")
		if err := generateIOCFindingsCSV(r.Security.IOCFindings, iocFile); err != nil {
			return nil, fmt.Errorf("failed to generate IOC findings CSV: %w", err)
		}
		result.Files = append(result.Files, iocFile)
	}

	// Generate TLS security findings CSV if any exist
	if len(r.Security.TLSSecurityFindings) > 0 {
		tlsSecFile := filepath.Join(dir, baseName+"_tls_security_findings.csv")
		if err := generateTLSSecurityFindingsCSV(r.Security.TLSSecurityFindings, tlsSecFile); err != nil {
			return nil, fmt.Errorf("failed to generate TLS security findings CSV: %w", err)
		}
		result.Files = append(result.Files, tlsSecFile)
	}

	// Generate ICMP analysis CSV if any exist
	if len(r.ICMPAnalysis) > 0 {
		icmpFile := filepath.Join(dir, baseName+"_icmp_analysis.csv")
		if err := generateICMPAnalysisCSV(r.ICMPAnalysis, icmpFile); err != nil {
			return nil, fmt.Errorf("failed to generate ICMP analysis CSV: %w", err)
		}
		result.Files = append(result.Files, icmpFile)
	}

	// Generate tunnel findings CSV if any exist
	if len(r.TunnelAnalysis) > 0 {
		tunnelFile := filepath.Join(dir, baseName+"_tunnel_findings.csv")
		if err := generateTunnelFindingsCSV(r.TunnelAnalysis, tunnelFile); err != nil {
			return nil, fmt.Errorf("failed to generate tunnel findings CSV: %w", err)
		}
		result.Files = append(result.Files, tunnelFile)
	}

	// Generate SD-WAN vendors CSV if any exist
	if len(r.SDWANVendors) > 0 {
		sdwanFile := filepath.Join(dir, baseName+"_sdwan_vendors.csv")
		if err := generateSDWANVendorsCSV(r.SDWANVendors, sdwanFile); err != nil {
			return nil, fmt.Errorf("failed to generate SD-WAN vendors CSV: %w", err)
		}
		result.Files = append(result.Files, sdwanFile)
	}

	// Generate VoIP analysis CSV if any exist
	if r.VoIPAnalysis != nil && (len(r.VoIPAnalysis.SIPCalls) > 0 || len(r.VoIPAnalysis.RTPStreams) > 0) {
		voipFile := filepath.Join(dir, baseName+"_voip_analysis.csv")
		if err := generateVoIPAnalysisCSV(r.VoIPAnalysis, voipFile); err != nil {
			return nil, fmt.Errorf("failed to generate VoIP analysis CSV: %w", err)
		}
		result.Files = append(result.Files, voipFile)
	}

	// Generate GeoIP summary CSV if any exist
	if len(r.LocationSummary) > 0 {
		geoFile := filepath.Join(dir, baseName+"_geo_locations.csv")
		if err := generateGeoLocationsCSV(r.LocationSummary, geoFile); err != nil {
			return nil, fmt.Errorf("failed to generate geo locations CSV: %w", err)
		}
		result.Files = append(result.Files, geoFile)
	}

	// Generate DNS details CSV if any exist
	if len(r.DNSDetails) > 0 {
		dnsDetailsFile := filepath.Join(dir, baseName+"_dns_details.csv")
		if err := generateDNSDetailsCSV(r.DNSDetails, dnsDetailsFile); err != nil {
			return nil, fmt.Errorf("failed to generate DNS details CSV: %w", err)
		}
		result.Files = append(result.Files, dnsDetailsFile)
	}

	// Generate BGP indicators CSV if any exist
	if len(r.BGPHijackIndicators) > 0 {
		bgpFile := filepath.Join(dir, baseName+"_bgp_indicators.csv")
		if err := generateBGPIndicatorsCSV(r.BGPHijackIndicators, bgpFile); err != nil {
			return nil, fmt.Errorf("failed to generate BGP indicators CSV: %w", err)
		}
		result.Files = append(result.Files, bgpFile)
	}

	// Generate app identification CSV if any exist
	if len(r.AppIdentification) > 0 {
		appFile := filepath.Join(dir, baseName+"_app_identification.csv")
		if err := generateAppIdentificationCSV(r.AppIdentification, appFile); err != nil {
			return nil, fmt.Errorf("failed to generate app identification CSV: %w", err)
		}
		result.Files = append(result.Files, appFile)
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
	criticalIssues := len(r.DNSAnomalies) + len(r.ARPConflicts) + len(r.Security.DDoSFindings) + len(r.Security.IOCFindings)
	performanceIssues := len(r.TCPRetransmissions) + len(r.FailedHandshakes)
	securityConcerns := len(r.SuspiciousTraffic) + len(r.Security.PortScanFindings) + len(r.Security.TLSSecurityFindings)

	// Count ICMP anomalies
	icmpAnomalyCount := 0
	for _, f := range r.ICMPAnalysis {
		if f.IsAnomaly {
			icmpAnomalyCount++
		}
	}

	// Count VoIP calls
	voipCallCount := 0
	if r.VoIPAnalysis != nil {
		voipCallCount = r.VoIPAnalysis.TotalCalls
	}

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
		// Original metrics
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
		// Security Analysis metrics
		{"DDoS Attacks Detected", fmt.Sprintf("%d", len(r.Security.DDoSFindings)), "DDoS attack patterns identified"},
		{"Port Scans Detected", fmt.Sprintf("%d", len(r.Security.PortScanFindings)), "Port scanning activities detected"},
		{"IOC Matches", fmt.Sprintf("%d", len(r.Security.IOCFindings)), "Indicators of Compromise matched"},
		{"TLS Security Weaknesses", fmt.Sprintf("%d", len(r.Security.TLSSecurityFindings)), "Weak TLS configurations detected"},
		// Network Analysis metrics
		{"ICMP Anomalies", fmt.Sprintf("%d", icmpAnomalyCount), "Anomalous ICMP traffic patterns"},
		{"Tunnels Detected", fmt.Sprintf("%d", len(r.TunnelAnalysis)), "Encapsulation protocols detected (VXLAN, GRE, IPsec, etc.)"},
		{"SD-WAN Vendors Detected", fmt.Sprintf("%d", len(r.SDWANVendors)), "SD-WAN vendor signatures identified"},
		{"VoIP Calls", fmt.Sprintf("%d", voipCallCount), "SIP/RTP voice calls detected"},
		{"Geographic Locations", fmt.Sprintf("%d", len(r.LocationSummary)), "Unique geographic locations observed"},
		// Protocol Analysis metrics
		{"BGP Hijack Indicators", fmt.Sprintf("%d", len(r.BGPHijackIndicators)), "Potential BGP hijack indicators"},
		{"DNS Queries Recorded", fmt.Sprintf("%d", len(r.DNSDetails)), "Total DNS queries captured"},
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

// generateDDoSFindingsCSV creates a CSV for DDoS attack findings
func generateDDoSFindingsCSV(findings []models.DDoSFinding, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	header := []string{
		"Timestamp (UTC)",
		"Source IP",
		"Target IP",
		"Attack Type",
		"Packet Count",
		"Threshold",
		"Duration (s)",
		"Severity",
		"Description",
		"Recommended Action",
	}
	if err := writer.Write(header); err != nil {
		return err
	}

	for _, f := range findings {
		ts := formatTimestampForCSV(f.Timestamp)
		description := fmt.Sprintf("%s attack detected from %s with %d packets (threshold: %d)",
			f.Type, f.SourceIP, f.PacketCount, f.Threshold)
		action := "Block source IP; enable rate limiting; configure DDoS protection"

		row := []string{
			ts,
			f.SourceIP,
			f.TargetIP,
			f.Type,
			fmt.Sprintf("%d", f.PacketCount),
			fmt.Sprintf("%d", f.Threshold),
			fmt.Sprintf("%.2f", f.Duration),
			f.Severity,
			description,
			action,
		}
		if err := writer.Write(row); err != nil {
			return err
		}
	}

	return nil
}

// generatePortScanFindingsCSV creates a CSV for port scan findings
func generatePortScanFindingsCSV(findings []models.PortScanFinding, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	header := []string{
		"Timestamp (UTC)",
		"Source IP",
		"Target IP",
		"Scan Type",
		"Ports Scanned",
		"Sample Ports",
		"Severity",
		"Description",
		"Recommended Action",
	}
	if err := writer.Write(header); err != nil {
		return err
	}

	for _, f := range findings {
		ts := formatTimestampForCSV(f.Timestamp)
		samplePorts := ""
		for i, p := range f.SamplePorts {
			if i > 0 {
				samplePorts += ","
			}
			samplePorts += fmt.Sprintf("%d", p)
			if i >= 9 {
				samplePorts += "..."
				break
			}
		}
		description := fmt.Sprintf("%s port scan from %s targeting %d ports",
			f.Type, f.SourceIP, f.PortsScanned)
		action := "Block source IP; review firewall rules; enable IDS/IPS"

		row := []string{
			ts,
			f.SourceIP,
			f.TargetIP,
			f.Type,
			fmt.Sprintf("%d", f.PortsScanned),
			samplePorts,
			f.Severity,
			description,
			action,
		}
		if err := writer.Write(row); err != nil {
			return err
		}
	}

	return nil
}

// generateIOCFindingsCSV creates a CSV for IOC match findings
func generateIOCFindingsCSV(findings []models.IOCFinding, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	header := []string{
		"Timestamp (UTC)",
		"Matched Value",
		"Match Type",
		"IOC Category",
		"Source IP",
		"Destination IP",
		"Confidence",
		"Description",
		"Recommended Action",
	}
	if err := writer.Write(header); err != nil {
		return err
	}

	for _, f := range findings {
		ts := formatTimestampForCSV(f.Timestamp)
		action := "Block communication; isolate affected systems; investigate for compromise"

		row := []string{
			ts,
			f.MatchedValue,
			f.Type,
			f.IOCType,
			f.SourceIP,
			f.DestIP,
			f.Confidence,
			f.Description,
			action,
		}
		if err := writer.Write(row); err != nil {
			return err
		}
	}

	return nil
}

// generateTLSSecurityFindingsCSV creates a CSV for TLS security findings
func generateTLSSecurityFindingsCSV(findings []models.TLSSecurityFinding, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	header := []string{
		"Timestamp (UTC)",
		"Server IP",
		"Server Port",
		"Server Name",
		"TLS Version",
		"Cipher Suite",
		"Weakness Type",
		"Severity",
		"Description",
		"Recommended Action",
	}
	if err := writer.Write(header); err != nil {
		return err
	}

	for _, f := range findings {
		ts := formatTimestampForCSV(f.Timestamp)
		action := "Upgrade TLS version; disable weak ciphers; enable PFS"

		row := []string{
			ts,
			f.ServerIP,
			fmt.Sprintf("%d", f.ServerPort),
			f.ServerName,
			f.TLSVersion,
			f.CipherSuite,
			f.WeaknessType,
			f.Severity,
			f.Description,
			action,
		}
		if err := writer.Write(row); err != nil {
			return err
		}
	}

	return nil
}

// generateICMPAnalysisCSV creates a CSV for ICMP analysis findings
func generateICMPAnalysisCSV(findings []models.ICMPFinding, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	header := []string{
		"Timestamp (UTC)",
		"Source IP",
		"Destination IP",
		"ICMP Type",
		"ICMP Code",
		"Type Name",
		"Count",
		"Is Anomaly",
		"Description",
	}
	if err := writer.Write(header); err != nil {
		return err
	}

	for _, f := range findings {
		ts := formatTimestampForCSV(f.Timestamp)
		isAnomaly := "No"
		if f.IsAnomaly {
			isAnomaly = "Yes"
		}

		row := []string{
			ts,
			f.SourceIP,
			f.DestIP,
			fmt.Sprintf("%d", f.Type),
			fmt.Sprintf("%d", f.Code),
			f.TypeName,
			fmt.Sprintf("%d", f.Count),
			isAnomaly,
			f.Description,
		}
		if err := writer.Write(row); err != nil {
			return err
		}
	}

	return nil
}

// generateTunnelFindingsCSV creates a CSV for tunnel/encapsulation findings
func generateTunnelFindingsCSV(tunnels []models.TunnelFinding, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	header := []string{
		"Tunnel Type",
		"Source IP",
		"Source Port",
		"Destination IP",
		"Destination Port",
		"Identifier (VNI/Key/Label)",
		"Inner Protocol",
		"Packet Count",
		"Byte Count",
		"First Seen (UTC)",
		"Last Seen (UTC)",
	}
	if err := writer.Write(header); err != nil {
		return err
	}

	for _, t := range tunnels {
		firstSeen := formatTimestampForCSV(t.FirstSeen)
		lastSeen := formatTimestampForCSV(t.LastSeen)
		srcPort := ""
		dstPort := ""
		if t.SrcPort > 0 {
			srcPort = fmt.Sprintf("%d", t.SrcPort)
		}
		if t.DstPort > 0 {
			dstPort = fmt.Sprintf("%d", t.DstPort)
		}
		identifier := ""
		if t.Identifier > 0 {
			identifier = fmt.Sprintf("%d", t.Identifier)
		}

		row := []string{
			t.Type,
			t.SrcIP,
			srcPort,
			t.DstIP,
			dstPort,
			identifier,
			t.InnerProto,
			fmt.Sprintf("%d", t.PacketCount),
			fmt.Sprintf("%d", t.ByteCount),
			firstSeen,
			lastSeen,
		}
		if err := writer.Write(row); err != nil {
			return err
		}
	}

	return nil
}

// generateSDWANVendorsCSV creates a CSV for SD-WAN vendor detection
func generateSDWANVendorsCSV(vendors []models.SDWANVendor, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	header := []string{
		"Vendor Name",
		"Confidence",
		"Detection Method",
		"Packet Count",
		"First Seen (UTC)",
		"Last Seen (UTC)",
	}
	if err := writer.Write(header); err != nil {
		return err
	}

	for _, v := range vendors {
		firstSeen := formatTimestampForCSV(v.FirstSeen)
		lastSeen := formatTimestampForCSV(v.LastSeen)

		row := []string{
			v.Name,
			v.Confidence,
			v.DetectedBy,
			fmt.Sprintf("%d", v.PacketCount),
			firstSeen,
			lastSeen,
		}
		if err := writer.Write(row); err != nil {
			return err
		}
	}

	return nil
}

// generateVoIPAnalysisCSV creates a CSV for VoIP/SIP/RTP analysis
func generateVoIPAnalysisCSV(voip *models.VoIPAnalysis, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	// Write summary section
	writer.Write([]string{"VoIP Analysis Summary"})
	writer.Write([]string{"Metric", "Value"})
	writer.Write([]string{"Total SIP Calls", fmt.Sprintf("%d", voip.TotalCalls)})
	writer.Write([]string{"Established Calls", fmt.Sprintf("%d", voip.EstablishedCalls)})
	writer.Write([]string{"Failed Calls", fmt.Sprintf("%d", voip.FailedCalls)})
	writer.Write([]string{"Total RTP Streams", fmt.Sprintf("%d", voip.TotalRTPStreams)})
	writer.Write([]string{"Average Jitter (ms)", fmt.Sprintf("%.2f", voip.AvgJitter)})
	writer.Write([]string{"Packet Loss Rate (%)", fmt.Sprintf("%.2f", voip.PacketLossRate)})
	writer.Write([]string{""})

	// Write SIP calls section
	if len(voip.SIPCalls) > 0 {
		writer.Write([]string{"SIP Calls"})
		writer.Write([]string{"Call ID", "From URI", "To URI", "State", "Source IP", "Destination IP", "Start Time (UTC)", "End Time (UTC)"})
		for _, call := range voip.SIPCalls {
			startTime := formatTimestampForCSV(call.StartTime)
			endTime := formatTimestampForCSV(call.EndTime)
			writer.Write([]string{
				call.CallID,
				call.FromURI,
				call.ToURI,
				call.State,
				call.SrcIP,
				call.DstIP,
				startTime,
				endTime,
			})
		}
		writer.Write([]string{""})
	}

	// Write RTP streams section
	if len(voip.RTPStreams) > 0 {
		writer.Write([]string{"RTP Streams"})
		writer.Write([]string{"SSRC", "Source IP", "Destination IP", "Payload Type", "Packet Count", "Byte Count", "Lost Packets", "Jitter (ms)"})
		for _, stream := range voip.RTPStreams {
			writer.Write([]string{
				fmt.Sprintf("%d", stream.SSRC),
				stream.SrcIP,
				stream.DstIP,
				stream.PayloadType,
				fmt.Sprintf("%d", stream.PacketCount),
				fmt.Sprintf("%d", stream.ByteCount),
				fmt.Sprintf("%d", stream.LostPackets),
				fmt.Sprintf("%.2f", stream.Jitter),
			})
		}
	}

	return nil
}

// generateGeoLocationsCSV creates a CSV for geographic location summary
func generateGeoLocationsCSV(locations map[string]int, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	header := []string{"Location", "IP Count"}
	if err := writer.Write(header); err != nil {
		return err
	}

	for location, count := range locations {
		row := []string{location, fmt.Sprintf("%d", count)}
		if err := writer.Write(row); err != nil {
			return err
		}
	}

	return nil
}

// formatTimestampForCSV converts Unix timestamp to human-readable format for CSV
func formatTimestampForCSV(unixTime float64) string {
	if unixTime == 0 {
		return ""
	}
	sec := int64(unixTime)
	nsec := int64((unixTime - float64(sec)) * 1e9)
	t := time.Unix(sec, nsec).UTC()
	return t.Format("2006-01-02 15:04:05")
}

// generateDNSDetailsCSV creates a CSV for full DNS query/response details
func generateDNSDetailsCSV(records []models.DNSRecord, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	header := []string{
		"Query Timestamp (UTC)",
		"Query Name",
		"Query Type",
		"Source IP",
		"Destination IP",
		"Response Timestamp (UTC)",
		"Response Code",
		"Answer IPs",
		"Answer Names",
		"Is Anomalous",
		"Detail",
	}
	if err := writer.Write(header); err != nil {
		return err
	}

	for _, r := range records {
		queryTs := formatTimestampForCSV(r.QueryTimestamp)
		responseTs := ""
		if r.ResponseTimestamp != nil {
			responseTs = formatTimestampForCSV(*r.ResponseTimestamp)
		}
		responseCode := ""
		if r.ResponseCode != nil {
			responseCode = fmt.Sprintf("%d", *r.ResponseCode)
		}
		answerIPs := strings.Join(r.AnswerIPs, ";")
		answerNames := strings.Join(r.AnswerNames, ";")
		isAnomalous := "No"
		if r.IsAnomalous {
			isAnomalous = "Yes"
		}

		row := []string{
			queryTs,
			r.QueryName,
			r.QueryType,
			r.SourceIP,
			r.DestinationIP,
			responseTs,
			responseCode,
			answerIPs,
			answerNames,
			isAnomalous,
			r.Detail,
		}
		if err := writer.Write(row); err != nil {
			return err
		}
	}

	return nil
}

// generateBGPIndicatorsCSV creates a CSV for BGP hijack indicators
func generateBGPIndicatorsCSV(indicators []models.BGPIndicator, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	header := []string{
		"IP Address",
		"IP Prefix",
		"Expected ASN",
		"Expected AS Name",
		"Observed ASN",
		"Observed AS Name",
		"Confidence",
		"Reason",
		"Related Domain",
		"Is Anomaly",
	}
	if err := writer.Write(header); err != nil {
		return err
	}

	for _, ind := range indicators {
		isAnomaly := "No"
		if ind.IsAnomaly {
			isAnomaly = "Yes"
		}
		observedASN := ""
		if ind.ObservedASN > 0 {
			observedASN = fmt.Sprintf("%d", ind.ObservedASN)
		}

		row := []string{
			ind.IPAddress,
			ind.IPPrefix,
			fmt.Sprintf("%d", ind.ExpectedASN),
			ind.ExpectedASName,
			observedASN,
			ind.ObservedASName,
			ind.Confidence,
			ind.Reason,
			ind.RelatedDomain,
			isAnomaly,
		}
		if err := writer.Write(row); err != nil {
			return err
		}
	}

	return nil
}

// generateAppIdentificationCSV creates a CSV for identified applications
func generateAppIdentificationCSV(apps []models.IdentifiedApp, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	header := []string{
		"Application Name",
		"Category",
		"Protocol",
		"Port",
		"SNI/Domain",
		"Packet Count",
		"Byte Count",
		"Confidence",
		"Identified By",
		"Is Suspicious",
		"Suspicious Reason",
	}
	if err := writer.Write(header); err != nil {
		return err
	}

	for _, app := range apps {
		port := ""
		if app.Port > 0 {
			port = fmt.Sprintf("%d", app.Port)
		}
		isSuspicious := "No"
		if app.IsSuspicious {
			isSuspicious = "Yes"
		}

		row := []string{
			app.Name,
			app.Category,
			app.Protocol,
			port,
			app.SNI,
			fmt.Sprintf("%d", app.PacketCount),
			fmt.Sprintf("%d", app.ByteCount),
			app.Confidence,
			app.IdentifiedBy,
			isSuspicious,
			app.SuspiciousReason,
		}
		if err := writer.Write(row); err != nil {
			return err
		}
	}

	return nil
}
