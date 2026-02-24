// Enhanced handlers for wizard, topology, comparison, and trends endpoints

package handlers

import (
	"encoding/json"
	"net/http"
	"os"
	"sort"
	"strings"

	"github.com/gin-gonic/gin"
)

// TopologyNode represents a device in the network topology
type TopologyNode struct {
	ID       string   `json:"id"`
	IP       string   `json:"ip"`
	Label    string   `json:"label"`
	Type     string   `json:"type"`
	Issues   []string `json:"issues"`
	Severity string   `json:"severity"`
	Bytes    int64    `json:"bytes_total"`
}

// TopologyLink represents a connection between two devices
type TopologyLink struct {
	Source   string   `json:"source"`
	Target   string   `json:"target"`
	Bytes    int64    `json:"bytes"`
	Protocol string   `json:"protocol"`
	Health   string   `json:"health"`
	Issues   []string `json:"issues"`
}

// TopologyResponse is the API response for network topology
type TopologyResponse struct {
	Nodes []TopologyNode `json:"nodes"`
	Links []TopologyLink `json:"links"`
}

// WizardRequest is the request body for the wizard endpoint
type WizardRequest struct {
	SymptomID string            `json:"symptom_id"`
	Answers   map[string]string `json:"answers"`
}

// WizardFinding represents a prioritized finding from the wizard
type WizardFinding struct {
	FindingKey  string `json:"finding_key"`
	Label       string `json:"label"`
	IsRootCause bool   `json:"is_root_cause"`
	Confidence  string `json:"confidence"`
	Explanation string `json:"explanation"`
	Count       int    `json:"count"`
	Severity    string `json:"severity"`
}

// WizardResponse is the API response for the wizard endpoint
type WizardResponse struct {
	SymptomID string          `json:"symptom_id"`
	Findings  []WizardFinding `json:"findings"`
	Total     int             `json:"total"`
}

// CompareRequest is the request body for comparing two analyses
type CompareRequest struct {
	BaselineID string `json:"baseline_id"`
	CurrentID  string `json:"current_id"`
}

// CompareMetric represents a single comparison metric
type CompareMetric struct {
	Label      string  `json:"label"`
	Baseline   float64 `json:"baseline"`
	Current    float64 `json:"current"`
	Change     float64 `json:"change_pct"`
	Improved   bool    `json:"improved"`
	Unit       string  `json:"unit"`
}

// CompareResponse is the API response for comparing two analyses
type CompareResponse struct {
	BaselineID   string          `json:"baseline_id"`
	CurrentID    string          `json:"current_id"`
	Metrics      []CompareMetric `json:"metrics"`
	NewIssues    []string        `json:"new_issues"`
	ResolvedIssues []string      `json:"resolved_issues"`
	Summary      string          `json:"summary"`
}

// GetTopology generates network topology from analysis results
func (h *Handlers) GetTopology(c *gin.Context) {
	id := c.Param("id")

	// Load results
	resultsPath := h.store.GetResultsPath(id)
	if resultsPath == "" {
		c.JSON(http.StatusNotFound, gin.H{"error": "Results not found"})
		return
	}

	data, err := os.ReadFile(resultsPath)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to read results"})
		return
	}

	var results map[string]interface{}
	if err := json.Unmarshal(data, &results); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to parse results"})
		return
	}

	// Build topology from traffic analysis
	nodes := make(map[string]*TopologyNode)
	var links []TopologyLink

	// Extract traffic flows
	if traffic, ok := results["traffic_analysis"].([]interface{}); ok {
		for _, flow := range traffic {
			if f, ok := flow.(map[string]interface{}); ok {
				srcIP, _ := f["src_ip"].(string)
				dstIP, _ := f["dst_ip"].(string)
				protocol, _ := f["protocol"].(string)
				totalBytes, _ := f["total_bytes"].(float64)

				if srcIP == "" || dstIP == "" {
					continue
				}

				// Add/update source node
				if _, exists := nodes[srcIP]; !exists {
					nodes[srcIP] = &TopologyNode{
						ID:       srcIP,
						IP:       srcIP,
						Label:    srcIP,
						Type:     inferDeviceType(srcIP, results),
						Severity: "healthy",
						Issues:   []string{},
					}
				}
				nodes[srcIP].Bytes += int64(totalBytes)

				// Add/update dest node
				if _, exists := nodes[dstIP]; !exists {
					nodes[dstIP] = &TopologyNode{
						ID:       dstIP,
						IP:       dstIP,
						Label:    dstIP,
						Type:     inferDeviceType(dstIP, results),
						Severity: "healthy",
						Issues:   []string{},
					}
				}
				nodes[dstIP].Bytes += int64(totalBytes)

				// Add link
				links = append(links, TopologyLink{
					Source:   srcIP,
					Target:   dstIP,
					Bytes:    int64(totalBytes),
					Protocol: protocol,
					Health:   "healthy",
					Issues:   []string{},
				})
			}
		}
	}

	// Mark nodes with issues
	markNodeIssues(nodes, results)

	// Convert to slices and limit
	nodeSlice := make([]TopologyNode, 0, len(nodes))
	for _, n := range nodes {
		nodeSlice = append(nodeSlice, *n)
	}

	// Sort by bytes and limit to top 20
	sort.Slice(nodeSlice, func(i, j int) bool {
		return nodeSlice[i].Bytes > nodeSlice[j].Bytes
	})
	if len(nodeSlice) > 20 {
		nodeSlice = nodeSlice[:20]
	}

	// Filter links to only include visible nodes
	visibleIPs := make(map[string]bool)
	for _, n := range nodeSlice {
		visibleIPs[n.ID] = true
	}
	filteredLinks := make([]TopologyLink, 0)
	for _, l := range links {
		if visibleIPs[l.Source] && visibleIPs[l.Target] {
			filteredLinks = append(filteredLinks, l)
		}
	}

	c.JSON(http.StatusOK, TopologyResponse{
		Nodes: nodeSlice,
		Links: filteredLinks,
	})
}

// PostWizard handles the troubleshooting wizard endpoint
func (h *Handlers) PostWizard(c *gin.Context) {
	id := c.Param("id")

	var req WizardRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}

	// Load results
	resultsPath := h.store.GetResultsPath(id)
	if resultsPath == "" {
		c.JSON(http.StatusNotFound, gin.H{"error": "Results not found"})
		return
	}

	data, err := os.ReadFile(resultsPath)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to read results"})
		return
	}

	var results map[string]interface{}
	if err := json.Unmarshal(data, &results); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to parse results"})
		return
	}

	// Extract active findings from results
	findings := extractActiveFindings(results)

	// Sort by severity (critical first)
	sevOrder := map[string]int{"Critical": 0, "Warning": 1, "Info": 2}
	sort.Slice(findings, func(i, j int) bool {
		return sevOrder[findings[i].Severity] < sevOrder[findings[j].Severity]
	})

	// Mark first as root cause
	if len(findings) > 0 {
		findings[0].IsRootCause = true
		findings[0].Confidence = "high"
	}

	c.JSON(http.StatusOK, WizardResponse{
		SymptomID: req.SymptomID,
		Findings:  findings,
		Total:     len(findings),
	})
}

// PostCompare compares two analysis results
func (h *Handlers) PostCompare(c *gin.Context) {
	var req CompareRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}

	baselinePath := h.store.GetResultsPath(req.BaselineID)
	currentPath := h.store.GetResultsPath(req.CurrentID)

	if baselinePath == "" || currentPath == "" {
		c.JSON(http.StatusNotFound, gin.H{"error": "One or both analysis results not found"})
		return
	}

	baselineData, err := os.ReadFile(baselinePath)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to read baseline results"})
		return
	}

	currentData, err := os.ReadFile(currentPath)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to read current results"})
		return
	}

	var baseline, current map[string]interface{}
	json.Unmarshal(baselineData, &baseline)
	json.Unmarshal(currentData, &current)

	// Compare key metrics
	metrics := compareResults(baseline, current)

	// Find new and resolved issues
	baselineFindings := extractFindingKeys(baseline)
	currentFindings := extractFindingKeys(current)

	var newIssues, resolvedIssues []string
	for _, f := range currentFindings {
		if !contains(baselineFindings, f) {
			newIssues = append(newIssues, f)
		}
	}
	for _, f := range baselineFindings {
		if !contains(currentFindings, f) {
			resolvedIssues = append(resolvedIssues, f)
		}
	}

	// Generate summary
	improved := 0
	for _, m := range metrics {
		if m.Improved {
			improved++
		}
	}
	summary := "No significant changes detected."
	if len(resolvedIssues) > 0 {
		summary = strings.Join(resolvedIssues, ", ") + " resolved."
	}
	if len(newIssues) > 0 {
		summary += " New issues: " + strings.Join(newIssues, ", ") + "."
	}

	c.JSON(http.StatusOK, CompareResponse{
		BaselineID:     req.BaselineID,
		CurrentID:      req.CurrentID,
		Metrics:        metrics,
		NewIssues:      newIssues,
		ResolvedIssues: resolvedIssues,
		Summary:        summary,
	})
}

// GetTrends returns historical trend data for an analysis
func (h *Handlers) GetTrends(c *gin.Context) {
	// For now, return the list of all analyses as trend data points
	// In a full implementation, this would track metrics over time in Redis
	jobs, err := h.store.ListJobs(50, 0)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to load history"})
		return
	}

	type TrendPoint struct {
		ID        string `json:"id"`
		FileName  string `json:"file_name"`
		CreatedAt string `json:"created_at"`
		RiskScore int    `json:"risk_score"`
		Issues    int    `json:"issues"`
	}

	var points []TrendPoint
	for _, job := range jobs {
		if job.Status != "completed" {
			continue
		}
		// Try to load risk score from results
		riskScore := 0
		issueCount := 0
		resultsPath := h.store.GetResultsPath(job.ID)
		if resultsPath != "" {
			if data, err := os.ReadFile(resultsPath); err == nil {
				var results map[string]interface{}
				if json.Unmarshal(data, &results) == nil {
					if rs, ok := results["risk_score"].(float64); ok {
						riskScore = int(rs)
					}
					issueCount = len(extractFindingKeys(results))
				}
			}
		}
		points = append(points, TrendPoint{
			ID:        job.ID,
			FileName:  job.FileName,
			CreatedAt: job.CreatedAt.Format("2006-01-02T15:04:05Z"),
			RiskScore: riskScore,
			Issues:    issueCount,
		})
	}

	c.JSON(http.StatusOK, gin.H{
		"trend_points": points,
		"total":        len(points),
	})
}

// --- Helper functions ---

func inferDeviceType(ip string, results map[string]interface{}) string {
	if strings.HasPrefix(ip, "10.") || strings.HasPrefix(ip, "172.") || strings.HasPrefix(ip, "192.168.") {
		return "client"
	}
	return "server"
}

func markNodeIssues(nodes map[string]*TopologyNode, results map[string]interface{}) {
	// Check DDoS findings
	if security, ok := results["security"].(map[string]interface{}); ok {
		if ddos, ok := security["ddos_findings"].([]interface{}); ok {
			for _, d := range ddos {
				if finding, ok := d.(map[string]interface{}); ok {
					if src, ok := finding["source_ip"].(string); ok {
						if n, exists := nodes[src]; exists {
							n.Issues = append(n.Issues, "DDoS source")
							n.Severity = "critical"
						}
					}
				}
			}
		}
	}

	// Check C2 beaconing
	if c2, ok := results["c2_beaconing_findings"].([]interface{}); ok {
		for _, b := range c2 {
			if beacon, ok := b.(map[string]interface{}); ok {
				if src, ok := beacon["source_ip"].(string); ok {
					if n, exists := nodes[src]; exists {
						n.Issues = append(n.Issues, "C2 beaconing")
						n.Severity = "critical"
					}
				}
			}
		}
	}

	// Check ARP conflicts
	if arps, ok := results["arp_conflicts"].([]interface{}); ok {
		for _, a := range arps {
			if conflict, ok := a.(map[string]interface{}); ok {
				if ip, ok := conflict["ip_address"].(string); ok {
					if n, exists := nodes[ip]; exists {
						n.Issues = append(n.Issues, "ARP conflict")
						if n.Severity != "critical" {
							n.Severity = "warning"
						}
					}
				}
			}
		}
	}
}

func extractActiveFindings(results map[string]interface{}) []WizardFinding {
	var findings []WizardFinding

	if security, ok := results["security"].(map[string]interface{}); ok {
		if ddos, ok := security["ddos_findings"].([]interface{}); ok && len(ddos) > 0 {
			findings = append(findings, WizardFinding{
				FindingKey: "ddos_syn_flood", Label: "DDoS Attacks", Count: len(ddos), Severity: "Critical", Confidence: "high",
				Explanation: "DDoS attack patterns detected in the capture.",
			})
		}
		if scans, ok := security["port_scan_findings"].([]interface{}); ok && len(scans) > 0 {
			findings = append(findings, WizardFinding{
				FindingKey: "port_scan", Label: "Port Scanning", Count: len(scans), Severity: "Warning", Confidence: "medium",
				Explanation: "Port scanning activity detected.",
			})
		}
		if tls, ok := security["tls_security_findings"].([]interface{}); ok && len(tls) > 0 {
			findings = append(findings, WizardFinding{
				FindingKey: "tls_weakness", Label: "TLS Weaknesses", Count: len(tls), Severity: "Warning", Confidence: "high",
				Explanation: "TLS security weaknesses found.",
			})
		}
	}

	if dns, ok := results["dns_anomalies"].([]interface{}); ok && len(dns) > 0 {
		findings = append(findings, WizardFinding{
			FindingKey: "dns_anomaly", Label: "DNS Anomalies", Count: len(dns), Severity: "Warning", Confidence: "medium",
			Explanation: "Suspicious DNS activity detected.",
		})
	}

	if c2, ok := results["c2_beaconing_findings"].([]interface{}); ok && len(c2) > 0 {
		findings = append(findings, WizardFinding{
			FindingKey: "c2_beaconing", Label: "C2 Beaconing", Count: len(c2), Severity: "Critical", Confidence: "high",
			Explanation: "Command-and-Control beaconing patterns detected.",
		})
	}

	if tunnel, ok := results["dns_tunneling_findings"].([]interface{}); ok && len(tunnel) > 0 {
		findings = append(findings, WizardFinding{
			FindingKey: "dns_tunneling", Label: "DNS Tunneling", Count: len(tunnel), Severity: "Critical", Confidence: "high",
			Explanation: "DNS tunneling activity suspected.",
		})
	}

	if retrans, ok := results["tcp_retransmissions"].([]interface{}); ok && len(retrans) > 0 {
		findings = append(findings, WizardFinding{
			FindingKey: "tcp_retransmission", Label: "TCP Retransmissions", Count: len(retrans), Severity: "Warning", Confidence: "high",
			Explanation: "High TCP retransmission rate indicating packet loss.",
		})
	}

	return findings
}

func extractFindingKeys(results map[string]interface{}) []string {
	var keys []string
	if security, ok := results["security"].(map[string]interface{}); ok {
		if ddos, ok := security["ddos_findings"].([]interface{}); ok && len(ddos) > 0 {
			keys = append(keys, "DDoS Attacks")
		}
		if scans, ok := security["port_scan_findings"].([]interface{}); ok && len(scans) > 0 {
			keys = append(keys, "Port Scanning")
		}
	}
	if dns, ok := results["dns_anomalies"].([]interface{}); ok && len(dns) > 0 {
		keys = append(keys, "DNS Anomalies")
	}
	if c2, ok := results["c2_beaconing_findings"].([]interface{}); ok && len(c2) > 0 {
		keys = append(keys, "C2 Beaconing")
	}
	if retrans, ok := results["tcp_retransmissions"].([]interface{}); ok && len(retrans) > 0 {
		keys = append(keys, "TCP Retransmissions")
	}
	return keys
}

func compareResults(baseline, current map[string]interface{}) []CompareMetric {
	var metrics []CompareMetric

	// Compare risk scores
	baseRisk, _ := baseline["risk_score"].(float64)
	currRisk, _ := current["risk_score"].(float64)
	if baseRisk > 0 || currRisk > 0 {
		change := 0.0
		if baseRisk > 0 {
			change = ((currRisk - baseRisk) / baseRisk) * 100
		}
		metrics = append(metrics, CompareMetric{
			Label:    "Risk Score",
			Baseline: baseRisk,
			Current:  currRisk,
			Change:   change,
			Improved: currRisk < baseRisk,
			Unit:     "score",
		})
	}

	// Compare packet counts
	basePkts, _ := baseline["packet_count"].(float64)
	currPkts, _ := current["packet_count"].(float64)
	if basePkts > 0 || currPkts > 0 {
		metrics = append(metrics, CompareMetric{
			Label:    "Packets Analyzed",
			Baseline: basePkts,
			Current:  currPkts,
			Change:   0,
			Improved: false,
			Unit:     "packets",
		})
	}

	return metrics
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
