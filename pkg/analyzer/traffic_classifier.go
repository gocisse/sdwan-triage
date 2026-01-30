package analyzer

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/gocisse/sdwan-triage/pkg/models"
)

// TrafficClassification contains smart classification of a stream
type TrafficClassification struct {
	Category     string   // "Microsoft 365", "SMB File Sharing", "SNMP Monitoring", etc.
	Service      string   // "Outlook", "Teams", "SharePoint", etc.
	Description  string   // Human-readable summary
	Icon         string   // Emoji icon for the traffic type
	Importance   string   // "Critical", "High", "Medium", "Low"
	Issues       []string // Detected problems
	SNI          string   // For HTTPS: outlook.office365.com
	DeviceName   string   // For SNMP: Meraki MS320-48FP
	FilePath     string   // For SMB: \\server\share\file.doc
	Vendor       string   // Detected vendor (Cisco, Meraki, etc.)
	IsEncrypted  bool     // Whether traffic is encrypted
	HealthStatus string   // "Healthy", "Warning", "Critical"
	HealthColor  string   // CSS color class
	QuickSummary string   // One-line summary for NOC display
}

// TrafficProfile defines known service profiles
type TrafficProfile struct {
	Category    string
	Service     string
	Icon        string
	Importance  string
	Description string
}

// KnownServices maps SNI/hostname patterns to traffic profiles
var KnownServices = map[string]TrafficProfile{
	// Microsoft 365
	"outlook.office365.com":      {Category: "Microsoft 365", Service: "Outlook/Exchange", Icon: "📧", Importance: "High", Description: "Email sync"},
	"outlook.office.com":         {Category: "Microsoft 365", Service: "Outlook/Exchange", Icon: "📧", Importance: "High", Description: "Email sync"},
	"teams.microsoft.com":        {Category: "Microsoft 365", Service: "Teams", Icon: "💬", Importance: "High", Description: "Teams communication"},
	"teams.live.com":             {Category: "Microsoft 365", Service: "Teams", Icon: "💬", Importance: "High", Description: "Teams communication"},
	"sharepoint.com":             {Category: "Microsoft 365", Service: "SharePoint", Icon: "📄", Importance: "Medium", Description: "Document sharing"},
	"onedrive.live.com":          {Category: "Microsoft 365", Service: "OneDrive", Icon: "☁️", Importance: "Medium", Description: "Cloud storage sync"},
	"graph.microsoft.com":        {Category: "Microsoft 365", Service: "Graph API", Icon: "🔗", Importance: "Medium", Description: "Microsoft API"},
	"login.microsoftonline.com":  {Category: "Microsoft 365", Service: "Authentication", Icon: "🔐", Importance: "Critical", Description: "SSO login"},
	"login.live.com":             {Category: "Microsoft 365", Service: "Authentication", Icon: "🔐", Importance: "Critical", Description: "Microsoft login"},
	"officeclient.microsoft.com": {Category: "Microsoft 365", Service: "Office Apps", Icon: "📊", Importance: "Medium", Description: "Office activation"},

	// Google Workspace
	"google.com":       {Category: "Google", Service: "Search/Services", Icon: "🔍", Importance: "Low", Description: "Google services"},
	"googleapis.com":   {Category: "Google", Service: "API", Icon: "🔗", Importance: "Medium", Description: "Google API"},
	"gmail.com":        {Category: "Google", Service: "Gmail", Icon: "📧", Importance: "High", Description: "Email"},
	"drive.google.com": {Category: "Google", Service: "Drive", Icon: "☁️", Importance: "Medium", Description: "Cloud storage"},
	"meet.google.com":  {Category: "Google", Service: "Meet", Icon: "📹", Importance: "High", Description: "Video conferencing"},

	// Cloud Providers
	"amazonaws.com":         {Category: "AWS", Service: "Cloud Services", Icon: "☁️", Importance: "High", Description: "AWS cloud"},
	"s3.amazonaws.com":      {Category: "AWS", Service: "S3 Storage", Icon: "🗄️", Importance: "Medium", Description: "Object storage"},
	"azure.com":             {Category: "Azure", Service: "Cloud Services", Icon: "☁️", Importance: "High", Description: "Azure cloud"},
	"blob.core.windows.net": {Category: "Azure", Service: "Blob Storage", Icon: "🗄️", Importance: "Medium", Description: "Azure storage"},
	"cloudflare.com":        {Category: "Cloudflare", Service: "CDN/Security", Icon: "🛡️", Importance: "Medium", Description: "CDN/WAF"},

	// Security & Updates
	"windowsupdate.com":          {Category: "Windows Update", Service: "System Updates", Icon: "🔄", Importance: "Medium", Description: "OS updates"},
	"update.microsoft.com":       {Category: "Windows Update", Service: "System Updates", Icon: "🔄", Importance: "Medium", Description: "OS updates"},
	"download.windowsupdate.com": {Category: "Windows Update", Service: "System Updates", Icon: "🔄", Importance: "Medium", Description: "Update download"},
	"ctldl.windowsupdate.com":    {Category: "Windows Update", Service: "Certificate Trust", Icon: "🔒", Importance: "Low", Description: "Certificate updates"},

	// Collaboration
	"zoom.us":   {Category: "Zoom", Service: "Video Conferencing", Icon: "📹", Importance: "High", Description: "Video calls"},
	"slack.com": {Category: "Slack", Service: "Messaging", Icon: "💬", Importance: "High", Description: "Team chat"},
	"webex.com": {Category: "Webex", Service: "Video Conferencing", Icon: "📹", Importance: "High", Description: "Video calls"},

	// SD-WAN Vendors
	"meraki.com":           {Category: "SD-WAN", Service: "Meraki Dashboard", Icon: "🌐", Importance: "Critical", Description: "Network management"},
	"velocloud.net":        {Category: "SD-WAN", Service: "VeloCloud", Icon: "🌐", Importance: "Critical", Description: "SD-WAN orchestration"},
	"silverpeak.cloud":     {Category: "SD-WAN", Service: "Silver Peak", Icon: "🌐", Importance: "Critical", Description: "SD-WAN management"},
	"paloaltonetworks.com": {Category: "SD-WAN", Service: "Palo Alto", Icon: "🛡️", Importance: "Critical", Description: "Security/SD-WAN"},
}

// SNMPEnterprises maps SNMP enterprise OIDs to vendor names
var SNMPEnterprises = map[string]string{
	"29671": "Meraki",
	"9":     "Cisco",
	"311":   "Microsoft",
	"2636":  "Juniper",
	"6876":  "VMware",
	"8072":  "Net-SNMP",
	"25506": "H3C/HPE",
	"2011":  "Huawei",
	"6486":  "Alcatel-Lucent",
	"1991":  "Foundry/Brocade",
	"11":    "HP",
	"43":    "3Com",
	"207":   "Allied Telesis",
	"1916":  "Extreme Networks",
	"6527":  "Nokia/Alcatel",
	"4526":  "Netgear",
	"171":   "D-Link",
	"14988": "MikroTik",
	"12356": "Fortinet",
	"2620":  "Check Point",
}

// PortServices maps common ports to service descriptions
var PortServices = map[uint16]TrafficProfile{
	22:   {Category: "Remote Access", Service: "SSH", Icon: "🔑", Importance: "High", Description: "Secure shell"},
	23:   {Category: "Remote Access", Service: "Telnet", Icon: "⚠️", Importance: "Critical", Description: "Insecure remote access"},
	25:   {Category: "Email", Service: "SMTP", Icon: "📧", Importance: "Medium", Description: "Email delivery"},
	53:   {Category: "Infrastructure", Service: "DNS", Icon: "🔍", Importance: "Critical", Description: "Name resolution"},
	80:   {Category: "Web", Service: "HTTP", Icon: "🌐", Importance: "Medium", Description: "Unencrypted web"},
	110:  {Category: "Email", Service: "POP3", Icon: "📧", Importance: "Medium", Description: "Email retrieval"},
	123:  {Category: "Infrastructure", Service: "NTP", Icon: "🕐", Importance: "Medium", Description: "Time sync"},
	143:  {Category: "Email", Service: "IMAP", Icon: "📧", Importance: "Medium", Description: "Email access"},
	161:  {Category: "Monitoring", Service: "SNMP", Icon: "📊", Importance: "Medium", Description: "Network monitoring"},
	162:  {Category: "Monitoring", Service: "SNMP Trap", Icon: "🚨", Importance: "High", Description: "Network alerts"},
	389:  {Category: "Directory", Service: "LDAP", Icon: "📂", Importance: "High", Description: "Directory services"},
	443:  {Category: "Web", Service: "HTTPS", Icon: "🔒", Importance: "Medium", Description: "Encrypted web"},
	445:  {Category: "File Sharing", Service: "SMB", Icon: "📁", Importance: "High", Description: "Windows file sharing"},
	465:  {Category: "Email", Service: "SMTPS", Icon: "📧", Importance: "Medium", Description: "Secure email"},
	514:  {Category: "Logging", Service: "Syslog", Icon: "📝", Importance: "Medium", Description: "System logging"},
	587:  {Category: "Email", Service: "Submission", Icon: "📧", Importance: "Medium", Description: "Email submission"},
	636:  {Category: "Directory", Service: "LDAPS", Icon: "📂", Importance: "High", Description: "Secure directory"},
	993:  {Category: "Email", Service: "IMAPS", Icon: "📧", Importance: "Medium", Description: "Secure IMAP"},
	995:  {Category: "Email", Service: "POP3S", Icon: "📧", Importance: "Medium", Description: "Secure POP3"},
	1433: {Category: "Database", Service: "MSSQL", Icon: "🗃️", Importance: "Critical", Description: "SQL Server"},
	1521: {Category: "Database", Service: "Oracle", Icon: "🗃️", Importance: "Critical", Description: "Oracle DB"},
	3306: {Category: "Database", Service: "MySQL", Icon: "🗃️", Importance: "Critical", Description: "MySQL/MariaDB"},
	3389: {Category: "Remote Access", Service: "RDP", Icon: "🖥️", Importance: "High", Description: "Remote Desktop"},
	5060: {Category: "VoIP", Service: "SIP", Icon: "📞", Importance: "High", Description: "Voice signaling"},
	5061: {Category: "VoIP", Service: "SIPS", Icon: "📞", Importance: "High", Description: "Secure voice"},
	5432: {Category: "Database", Service: "PostgreSQL", Icon: "🗃️", Importance: "Critical", Description: "PostgreSQL"},
	5900: {Category: "Remote Access", Service: "VNC", Icon: "🖥️", Importance: "High", Description: "VNC remote"},
	6379: {Category: "Database", Service: "Redis", Icon: "🗃️", Importance: "High", Description: "Redis cache"},
	8080: {Category: "Web", Service: "HTTP-Alt", Icon: "🌐", Importance: "Medium", Description: "Alt HTTP"},
	8443: {Category: "Web", Service: "HTTPS-Alt", Icon: "🔒", Importance: "Medium", Description: "Alt HTTPS"},
}

// TrafficClassifier classifies network streams
type TrafficClassifier struct {
	sniPatterns []*regexp.Regexp
}

// NewTrafficClassifier creates a new traffic classifier
func NewTrafficClassifier() *TrafficClassifier {
	return &TrafficClassifier{}
}

// ClassifyStream classifies a stream and returns human-readable information
func (tc *TrafficClassifier) ClassifyStream(stream *models.StreamData) TrafficClassification {
	classification := TrafficClassification{
		Category:     "Unknown",
		Service:      "Unknown",
		Description:  "Unclassified traffic",
		Icon:         "❓",
		Importance:   "Low",
		Issues:       make([]string, 0),
		HealthStatus: "Healthy",
		HealthColor:  "green",
	}

	// Extract SNI from TLS streams
	sni := tc.extractSNIFromStream(stream)
	if sni != "" {
		classification.SNI = sni
		classification.IsEncrypted = true
	}

	// Classify by application protocol first
	switch stream.Application {
	case "TLS", "HTTPS":
		tc.classifyTLS(&classification, stream, sni)
	case "SMB":
		tc.classifySMB(&classification, stream)
	case "DNS":
		tc.classifyDNS(&classification, stream)
	case "HTTP":
		tc.classifyHTTP(&classification, stream)
	case "SSH":
		tc.classifySSH(&classification, stream)
	case "SIP":
		tc.classifySIP(&classification, stream)
	default:
		// Fallback to port-based classification
		tc.classifyByPort(&classification, stream)
	}

	// Detect issues
	tc.detectIssues(&classification, stream)

	// Generate quick summary
	classification.QuickSummary = tc.generateQuickSummary(&classification, stream)

	return classification
}

// classifyTLS classifies TLS/HTTPS traffic
func (tc *TrafficClassifier) classifyTLS(c *TrafficClassification, stream *models.StreamData, sni string) {
	c.Category = "HTTPS"
	c.Service = "Encrypted Web"
	c.Icon = "🔒"
	c.Importance = "Medium"
	c.IsEncrypted = true

	if sni == "" {
		c.Description = "Encrypted HTTPS traffic"
		return
	}

	// Check against known services
	for pattern, profile := range KnownServices {
		if strings.Contains(sni, pattern) || strings.HasSuffix(sni, pattern) {
			c.Category = profile.Category
			c.Service = profile.Service
			c.Icon = profile.Icon
			c.Importance = profile.Importance
			c.Description = profile.Description
			return
		}
	}

	// Fallback: use SNI as description
	c.Description = fmt.Sprintf("HTTPS to %s", sni)
}

// classifySMB classifies SMB file sharing traffic
func (tc *TrafficClassifier) classifySMB(c *TrafficClassification, stream *models.StreamData) {
	c.Category = "File Sharing"
	c.Service = "SMB/CIFS"
	c.Icon = "📁"
	c.Importance = "High"
	c.Description = "Windows file sharing"

	// Try to extract file path from stream data
	filePath := tc.extractSMBPath(stream)
	if filePath != "" {
		c.FilePath = filePath
		c.Description = fmt.Sprintf("File: %s", filePath)
	}

	// Detect SMB version from stream
	smbVersion := tc.detectSMBVersion(stream)
	if smbVersion != "" {
		c.Service = smbVersion
	}
}

// classifyDNS classifies DNS traffic
func (tc *TrafficClassifier) classifyDNS(c *TrafficClassification, stream *models.StreamData) {
	c.Category = "Infrastructure"
	c.Service = "DNS"
	c.Icon = "🔍"
	c.Importance = "Critical"
	c.Description = "Name resolution"
}

// classifyHTTP classifies HTTP traffic
func (tc *TrafficClassifier) classifyHTTP(c *TrafficClassification, stream *models.StreamData) {
	c.Category = "Web"
	c.Service = "HTTP"
	c.Icon = "🌐"
	c.Importance = "Medium"
	c.Description = "Unencrypted web traffic"
	c.Issues = append(c.Issues, "⚠️ Unencrypted HTTP - consider HTTPS")
}

// classifySSH classifies SSH traffic
func (tc *TrafficClassifier) classifySSH(c *TrafficClassification, stream *models.StreamData) {
	c.Category = "Remote Access"
	c.Service = "SSH"
	c.Icon = "🔑"
	c.Importance = "High"
	c.IsEncrypted = true
	c.Description = "Secure shell access"
}

// classifySIP classifies SIP/VoIP traffic
func (tc *TrafficClassifier) classifySIP(c *TrafficClassification, stream *models.StreamData) {
	c.Category = "VoIP"
	c.Service = "SIP"
	c.Icon = "📞"
	c.Importance = "High"
	c.Description = "Voice/video signaling"
}

// classifyByPort classifies traffic by port number
func (tc *TrafficClassifier) classifyByPort(c *TrafficClassification, stream *models.StreamData) {
	// Check destination port first, then source
	ports := []uint16{stream.DstPort, stream.SrcPort}

	for _, port := range ports {
		if profile, ok := PortServices[port]; ok {
			c.Category = profile.Category
			c.Service = profile.Service
			c.Icon = profile.Icon
			c.Importance = profile.Importance
			c.Description = profile.Description
			return
		}
	}

	// Unknown traffic
	c.Description = fmt.Sprintf("%s traffic on port %d", stream.Protocol, stream.DstPort)
}

// extractSNIFromStream extracts SNI from TLS ClientHello in stream segments
func (tc *TrafficClassifier) extractSNIFromStream(stream *models.StreamData) string {
	for _, seg := range stream.Segments {
		if seg.Direction == "client_to_server" && len(seg.Data) > 50 {
			// Check for TLS ClientHello
			if seg.Data[0] == 0x16 && seg.Data[1] == 0x03 {
				sni := extractSNIFromData(seg.Data)
				if sni != "" {
					return sni
				}
			}
		}
	}
	return ""
}

// extractSNIFromData extracts SNI from TLS ClientHello data
func extractSNIFromData(data []byte) string {
	if len(data) < 50 {
		return ""
	}

	// Search for SNI extension (type 0x0000)
	for i := 0; i < len(data)-10; i++ {
		if data[i] == 0x00 && data[i+1] == 0x00 {
			if i+4 < len(data) {
				extLen := int(data[i+2])<<8 | int(data[i+3])
				if extLen > 0 && extLen < 256 && i+4+extLen <= len(data) {
					if i+9 < len(data) {
						nameLen := int(data[i+7])<<8 | int(data[i+8])
						if nameLen > 0 && nameLen < 256 && i+9+nameLen <= len(data) {
							name := string(data[i+9 : i+9+nameLen])
							if isValidHostname(name) {
								return name
							}
						}
					}
				}
			}
		}
	}
	return ""
}

// isValidHostname checks if a string looks like a valid hostname
func isValidHostname(s string) bool {
	if len(s) < 3 || len(s) > 253 {
		return false
	}
	for _, c := range s {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') || c == '.' || c == '-') {
			return false
		}
	}
	return strings.Contains(s, ".")
}

// extractSMBPath extracts file path from SMB traffic
func (tc *TrafficClassifier) extractSMBPath(stream *models.StreamData) string {
	for _, seg := range stream.Segments {
		if len(seg.Data) < 10 {
			continue
		}

		// Look for SMB2 header
		if len(seg.Data) >= 4 && seg.Data[0] == 0xFE && seg.Data[1] == 'S' && seg.Data[2] == 'M' && seg.Data[3] == 'B' {
			// Try to find filename in Create request
			path := tc.extractSMB2Filename(seg.Data)
			if path != "" {
				return path
			}
		}
	}
	return ""
}

// extractSMB2Filename extracts filename from SMB2 Create request
func (tc *TrafficClassifier) extractSMB2Filename(data []byte) string {
	// This is a simplified extraction - real SMB2 parsing is complex
	// Look for readable path patterns
	for i := 0; i < len(data)-4; i++ {
		// Look for backslash patterns (UNC paths)
		if data[i] == '\\' && i+1 < len(data) {
			// Try to extract path
			end := i
			for j := i; j < len(data) && j < i+256; j++ {
				if data[j] == 0 || data[j] < 32 {
					end = j
					break
				}
				end = j + 1
			}
			if end > i+2 {
				path := string(data[i:end])
				if strings.Contains(path, "\\") {
					return path
				}
			}
		}
	}
	return ""
}

// detectSMBVersion detects SMB version from stream data
func (tc *TrafficClassifier) detectSMBVersion(stream *models.StreamData) string {
	for _, seg := range stream.Segments {
		if len(seg.Data) >= 4 {
			if seg.Data[0] == 0xFE && seg.Data[1] == 'S' && seg.Data[2] == 'M' && seg.Data[3] == 'B' {
				return "SMB2/3"
			}
			if seg.Data[0] == 0xFF && seg.Data[1] == 'S' && seg.Data[2] == 'M' && seg.Data[3] == 'B' {
				return "SMB1"
			}
		}
	}
	return "SMB"
}

// detectIssues detects problems in the stream
func (tc *TrafficClassifier) detectIssues(c *TrafficClassification, stream *models.StreamData) {
	// Check for TLS version issues
	for _, seg := range stream.Segments {
		if len(seg.Data) >= 3 && seg.Data[0] == 0x16 {
			version := uint16(seg.Data[1])<<8 | uint16(seg.Data[2])
			switch version {
			case 0x0300:
				c.Issues = append(c.Issues, "⚠️ SSLv3 detected - VULNERABLE")
				c.HealthStatus = "Critical"
				c.HealthColor = "red"
			case 0x0301:
				c.Issues = append(c.Issues, "⚠️ TLS 1.0 - upgrade recommended")
				if c.HealthStatus != "Critical" {
					c.HealthStatus = "Warning"
					c.HealthColor = "yellow"
				}
			case 0x0302:
				c.Issues = append(c.Issues, "⚠️ TLS 1.1 - upgrade recommended")
				if c.HealthStatus != "Critical" {
					c.HealthStatus = "Warning"
					c.HealthColor = "yellow"
				}
			}
		}

		// Check for anomalies in segments
		if seg.IsRetransmit {
			c.Issues = append(c.Issues, "🔄 Retransmissions detected")
			if c.HealthStatus == "Healthy" {
				c.HealthStatus = "Warning"
				c.HealthColor = "yellow"
			}
		}
		if seg.HasReset {
			c.Issues = append(c.Issues, "💥 Connection reset")
			c.HealthStatus = "Critical"
			c.HealthColor = "red"
		}
		if seg.GapFromPrev > 5.0 {
			c.Issues = append(c.Issues, fmt.Sprintf("⏱️ %.1fs gap - possible timeout", seg.GapFromPrev))
			if c.HealthStatus == "Healthy" {
				c.HealthStatus = "Warning"
				c.HealthColor = "yellow"
			}
		}
	}

	// Check for unencrypted sensitive traffic
	if !c.IsEncrypted && (c.Importance == "High" || c.Importance == "Critical") {
		if stream.Application != "DNS" && stream.Application != "SNMP" {
			c.Issues = append(c.Issues, "⚠️ Sensitive traffic not encrypted")
		}
	}

	// Deduplicate issues
	c.Issues = uniqueStrings(c.Issues)
}

// generateQuickSummary generates a one-line summary for NOC display
func (tc *TrafficClassifier) generateQuickSummary(c *TrafficClassification, stream *models.StreamData) string {
	var parts []string

	// Icon and service
	parts = append(parts, fmt.Sprintf("%s %s", c.Icon, c.Service))

	// Target (SNI, file path, or IP)
	if c.SNI != "" {
		parts = append(parts, fmt.Sprintf("→ %s", c.SNI))
	} else if c.FilePath != "" {
		parts = append(parts, fmt.Sprintf("→ %s", c.FilePath))
	} else if c.DeviceName != "" {
		parts = append(parts, fmt.Sprintf("→ %s", c.DeviceName))
	}

	// Status indicator
	switch c.HealthStatus {
	case "Critical":
		parts = append(parts, "🔴")
	case "Warning":
		parts = append(parts, "🟡")
	default:
		parts = append(parts, "🟢")
	}

	return strings.Join(parts, " ")
}

// uniqueStrings removes duplicates from a string slice
func uniqueStrings(input []string) []string {
	seen := make(map[string]bool)
	result := make([]string, 0)
	for _, s := range input {
		if !seen[s] {
			seen[s] = true
			result = append(result, s)
		}
	}
	return result
}

// ClassifySNMPDevice classifies SNMP traffic and extracts device info
func (tc *TrafficClassifier) ClassifySNMPDevice(data []byte) (vendor string, deviceName string) {
	// Look for enterprise OID in SNMP data
	for oid, vendorName := range SNMPEnterprises {
		oidBytes := fmt.Sprintf(".1.3.6.1.4.1.%s", oid)
		if strings.Contains(string(data), oidBytes) {
			vendor = vendorName
			break
		}
	}

	// Try to extract sysName or sysDescr
	// Look for readable device names in the data
	for i := 0; i < len(data)-10; i++ {
		// Look for common device name patterns
		if isReadableString(data[i:min(i+50, len(data))]) {
			candidate := extractReadableString(data[i:min(i+100, len(data))])
			if len(candidate) > 5 && len(candidate) < 100 {
				// Check if it looks like a device name
				if strings.Contains(candidate, "Meraki") ||
					strings.Contains(candidate, "Cisco") ||
					strings.Contains(candidate, "Switch") ||
					strings.Contains(candidate, "Router") ||
					strings.Contains(candidate, "AP") {
					deviceName = candidate
					break
				}
			}
		}
	}

	return vendor, deviceName
}

// isReadableString checks if data starts with readable ASCII
func isReadableString(data []byte) bool {
	if len(data) < 3 {
		return false
	}
	readable := 0
	for i := 0; i < min(10, len(data)); i++ {
		if data[i] >= 32 && data[i] < 127 {
			readable++
		}
	}
	return readable >= 5
}

// extractReadableString extracts readable ASCII from data
func extractReadableString(data []byte) string {
	var sb strings.Builder
	for _, b := range data {
		if b >= 32 && b < 127 {
			sb.WriteByte(b)
		} else if sb.Len() > 0 {
			break
		}
	}
	return strings.TrimSpace(sb.String())
}
