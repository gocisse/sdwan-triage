package analyzer

import (
	"strings"

	"github.com/gocisse/sdwan-triage/pkg/models"
)

// ServiceCategory represents the business function of traffic
type ServiceCategory string

const (
	// Microsoft 365 Services
	CategoryM365Exchange   ServiceCategory = "Microsoft 365 Exchange"
	CategoryM365Teams      ServiceCategory = "Microsoft 365 Teams"
	CategoryM365SharePoint ServiceCategory = "Microsoft 365 SharePoint"
	CategoryM365OneDrive   ServiceCategory = "Microsoft 365 OneDrive"

	// Business Applications
	CategorySAP       ServiceCategory = "SAP ERP"
	CategoryOracle    ServiceCategory = "Oracle Database"
	CategoryCustomERP ServiceCategory = "Custom ERP"

	// Infrastructure Services
	CategoryDNS      ServiceCategory = "DNS Resolution"
	CategoryNTP      ServiceCategory = "NTP Time Sync"
	CategoryLDAP     ServiceCategory = "LDAP Directory"
	CategoryKerberos ServiceCategory = "Kerberos Auth"

	// SD-WAN Control Plane
	CategoryCiscoViptela ServiceCategory = "Cisco SD-WAN Control"
	CategoryVeloCloud    ServiceCategory = "VMware VeloCloud Control"
	CategoryAruba        ServiceCategory = "Aruba SD-WAN Control"
	CategoryPaloAlto     ServiceCategory = "Palo Alto SD-WAN Control"
	CategorySilverPeak   ServiceCategory = "Silver Peak SD-WAN Control"
	CategoryFortinet     ServiceCategory = "Fortinet SD-WAN Control"

	// General Categories
	CategoryWebBrowsing ServiceCategory = "Web Browsing"
	CategoryFileSharing ServiceCategory = "File Sharing"
	CategoryVoIP        ServiceCategory = "VoIP/RTC"
	CategoryVideo       ServiceCategory = "Video Streaming"
	CategoryUnknown     ServiceCategory = "Unknown"
)

// ServiceClassification contains detailed service identification
type ServiceClassification struct {
	Category         ServiceCategory
	SubService       string
	Confidence       float64 // 0.0 to 1.0
	TypicalBaseline  PerformanceBaseline
	VendorIdentified string // For SD-WAN control plane
}

// PerformanceBaseline defines expected performance metrics
type PerformanceBaseline struct {
	ExpectedLatencyMs      float64
	ExpectedJitterMs       float64
	ExpectedPacketLossRate float64
	ExpectedThroughputMbps float64
	HandshakeTimeoutSec    float64
}

// AdvancedClassifier provides deep traffic classification
type AdvancedClassifier struct {
	// Microsoft 365 detection patterns
	m365Domains map[string]ServiceCategory

	// Business application ports
	businessAppPorts map[uint16]ServiceCategory

	// SD-WAN control plane signatures
	sdwanSignatures []SDWANSignature
}

// SDWANSignature identifies vendor-specific control plane traffic
type SDWANSignature struct {
	Vendor      string
	Category    ServiceCategory
	Ports       []uint16
	HostPattern string
	Protocol    string
}

// NewAdvancedClassifier creates a new classifier with detection rules
func NewAdvancedClassifier() *AdvancedClassifier {
	ac := &AdvancedClassifier{
		m365Domains:      make(map[string]ServiceCategory),
		businessAppPorts: make(map[uint16]ServiceCategory),
	}

	// Microsoft 365 domain patterns
	ac.m365Domains["outlook.office365.com"] = CategoryM365Exchange
	ac.m365Domains["outlook.office.com"] = CategoryM365Exchange
	ac.m365Domains["smtp.office365.com"] = CategoryM365Exchange
	ac.m365Domains["teams.microsoft.com"] = CategoryM365Teams
	ac.m365Domains["teams.live.com"] = CategoryM365Teams
	ac.m365Domains["*.teams.microsoft.com"] = CategoryM365Teams
	ac.m365Domains["sharepoint.com"] = CategoryM365SharePoint
	ac.m365Domains["*.sharepoint.com"] = CategoryM365SharePoint
	ac.m365Domains["onedrive.live.com"] = CategoryM365OneDrive
	ac.m365Domains["*.onedrive.com"] = CategoryM365OneDrive

	// Business application ports
	ac.businessAppPorts[3200] = CategorySAP    // SAP Router
	ac.businessAppPorts[3300] = CategorySAP    // SAP Gateway
	ac.businessAppPorts[3600] = CategorySAP    // SAP Message Server
	ac.businessAppPorts[1521] = CategoryOracle // Oracle TNS Listener
	ac.businessAppPorts[1526] = CategoryOracle // Oracle TNS Listener Alt
	ac.businessAppPorts[389] = CategoryLDAP    // LDAP
	ac.businessAppPorts[636] = CategoryLDAP    // LDAPS
	ac.businessAppPorts[3268] = CategoryLDAP   // Global Catalog
	ac.businessAppPorts[88] = CategoryKerberos // Kerberos
	ac.businessAppPorts[123] = CategoryNTP     // NTP

	// SD-WAN control plane signatures
	ac.sdwanSignatures = []SDWANSignature{
		{
			Vendor:      "Cisco Viptela",
			Category:    CategoryCiscoViptela,
			Ports:       []uint16{12346, 12366, 12386, 23456},
			HostPattern: "viptela",
			Protocol:    "DTLS",
		},
		{
			Vendor:      "VMware VeloCloud",
			Category:    CategoryVeloCloud,
			Ports:       []uint16{2426, 8080, 8443},
			HostPattern: "velocloud",
			Protocol:    "VCMP",
		},
		{
			Vendor:      "Aruba EdgeConnect",
			Category:    CategoryAruba,
			Ports:       []uint16{4980, 4981},
			HostPattern: "silverpeak",
			Protocol:    "Tunnel",
		},
		{
			Vendor:      "Palo Alto Prisma",
			Category:    CategoryPaloAlto,
			Ports:       []uint16{4501, 4502},
			HostPattern: "prisma",
			Protocol:    "IPsec",
		},
		{
			Vendor:      "Silver Peak",
			Category:    CategorySilverPeak,
			Ports:       []uint16{4980, 4981},
			HostPattern: "silverpeak",
			Protocol:    "Tunnel",
		},
		{
			Vendor:      "Fortinet",
			Category:    CategoryFortinet,
			Ports:       []uint16{541, 8013},
			HostPattern: "fortinet",
			Protocol:    "ADVPN",
		},
	}

	return ac
}

// ClassifyStream performs deep classification of a stream
func (ac *AdvancedClassifier) ClassifyStream(stream *models.StreamData) ServiceClassification {
	// Check SD-WAN control plane first (highest priority)
	if sdwan := ac.detectSDWANControlPlane(stream); sdwan.Category != CategoryUnknown {
		return sdwan
	}

	// Check Microsoft 365 services
	if m365 := ac.detectMicrosoft365(stream); m365.Category != CategoryUnknown {
		return m365
	}

	// Check business applications
	if biz := ac.detectBusinessApp(stream); biz.Category != CategoryUnknown {
		return biz
	}

	// Check infrastructure services
	if infra := ac.detectInfrastructure(stream); infra.Category != CategoryUnknown {
		return infra
	}

	// Fallback to protocol-based classification
	return ac.classifyByProtocol(stream)
}

// detectSDWANControlPlane identifies SD-WAN vendor control plane traffic
func (ac *AdvancedClassifier) detectSDWANControlPlane(stream *models.StreamData) ServiceClassification {
	for _, sig := range ac.sdwanSignatures {
		// Check port match
		portMatch := false
		for _, port := range sig.Ports {
			if stream.DstPort == port || stream.SrcPort == port {
				portMatch = true
				break
			}
		}

		if !portMatch {
			continue
		}

		// Check hostname pattern if available
		if sig.HostPattern != "" && stream.ServerName != "" {
			if strings.Contains(strings.ToLower(stream.ServerName), sig.HostPattern) {
				return ServiceClassification{
					Category:         sig.Category,
					SubService:       sig.Protocol,
					Confidence:       0.95,
					VendorIdentified: sig.Vendor,
					TypicalBaseline: PerformanceBaseline{
						ExpectedLatencyMs:      100,
						ExpectedJitterMs:       10,
						ExpectedPacketLossRate: 0.001,
						HandshakeTimeoutSec:    5,
					},
				}
			}
		}

		// Port match alone gives medium confidence
		if portMatch {
			return ServiceClassification{
				Category:         sig.Category,
				SubService:       sig.Protocol,
				Confidence:       0.7,
				VendorIdentified: sig.Vendor,
				TypicalBaseline: PerformanceBaseline{
					ExpectedLatencyMs:      100,
					ExpectedJitterMs:       10,
					ExpectedPacketLossRate: 0.001,
					HandshakeTimeoutSec:    5,
				},
			}
		}
	}

	return ServiceClassification{Category: CategoryUnknown}
}

// detectMicrosoft365 identifies Microsoft 365 services
func (ac *AdvancedClassifier) detectMicrosoft365(stream *models.StreamData) ServiceClassification {
	if stream.ServerName == "" {
		return ServiceClassification{Category: CategoryUnknown}
	}

	serverLower := strings.ToLower(stream.ServerName)

	// Direct domain match
	if category, exists := ac.m365Domains[serverLower]; exists {
		return ac.buildM365Classification(category, stream.ServerName, 0.95)
	}

	// Wildcard pattern matching
	for domain, category := range ac.m365Domains {
		if strings.HasPrefix(domain, "*.") {
			baseDomain := strings.TrimPrefix(domain, "*.")
			if strings.HasSuffix(serverLower, baseDomain) {
				return ac.buildM365Classification(category, stream.ServerName, 0.9)
			}
		}
	}

	// Heuristic matching for M365
	if strings.Contains(serverLower, "office365") || strings.Contains(serverLower, "microsoft.com") {
		if strings.Contains(serverLower, "outlook") || strings.Contains(serverLower, "exchange") {
			return ac.buildM365Classification(CategoryM365Exchange, stream.ServerName, 0.75)
		}
		if strings.Contains(serverLower, "teams") {
			return ac.buildM365Classification(CategoryM365Teams, stream.ServerName, 0.75)
		}
		if strings.Contains(serverLower, "sharepoint") {
			return ac.buildM365Classification(CategoryM365SharePoint, stream.ServerName, 0.75)
		}
		if strings.Contains(serverLower, "onedrive") {
			return ac.buildM365Classification(CategoryM365OneDrive, stream.ServerName, 0.75)
		}
	}

	return ServiceClassification{Category: CategoryUnknown}
}

// buildM365Classification creates a classification for Microsoft 365 services
func (ac *AdvancedClassifier) buildM365Classification(category ServiceCategory, serverName string, confidence float64) ServiceClassification {
	baseline := PerformanceBaseline{
		ExpectedLatencyMs:      150,
		ExpectedJitterMs:       20,
		ExpectedPacketLossRate: 0.01,
		ExpectedThroughputMbps: 10,
		HandshakeTimeoutSec:    3,
	}

	// Teams has stricter requirements
	if category == CategoryM365Teams {
		baseline.ExpectedLatencyMs = 50
		baseline.ExpectedJitterMs = 10
		baseline.ExpectedPacketLossRate = 0.005
	}

	return ServiceClassification{
		Category:        category,
		SubService:      serverName,
		Confidence:      confidence,
		TypicalBaseline: baseline,
	}
}

// detectBusinessApp identifies business applications
func (ac *AdvancedClassifier) detectBusinessApp(stream *models.StreamData) ServiceClassification {
	if category, exists := ac.businessAppPorts[stream.DstPort]; exists {
		return ac.buildBusinessAppClassification(category, stream.DstPort, 0.85)
	}

	if category, exists := ac.businessAppPorts[stream.SrcPort]; exists {
		return ac.buildBusinessAppClassification(category, stream.SrcPort, 0.85)
	}

	return ServiceClassification{Category: CategoryUnknown}
}

// buildBusinessAppClassification creates a classification for business apps
func (ac *AdvancedClassifier) buildBusinessAppClassification(category ServiceCategory, port uint16, confidence float64) ServiceClassification {
	baseline := PerformanceBaseline{
		ExpectedLatencyMs:      100,
		ExpectedJitterMs:       50,
		ExpectedPacketLossRate: 0.001,
		ExpectedThroughputMbps: 1,
		HandshakeTimeoutSec:    5,
	}

	// Database applications need lower latency
	if category == CategoryOracle || category == CategorySAP {
		baseline.ExpectedLatencyMs = 50
	}

	return ServiceClassification{
		Category:        category,
		SubService:      "",
		Confidence:      confidence,
		TypicalBaseline: baseline,
	}
}

// detectInfrastructure identifies infrastructure services
func (ac *AdvancedClassifier) detectInfrastructure(stream *models.StreamData) ServiceClassification {
	// DNS
	if stream.DstPort == 53 || stream.SrcPort == 53 {
		return ServiceClassification{
			Category:   CategoryDNS,
			Confidence: 1.0,
			TypicalBaseline: PerformanceBaseline{
				ExpectedLatencyMs:      50,
				ExpectedJitterMs:       10,
				ExpectedPacketLossRate: 0.001,
				HandshakeTimeoutSec:    2,
			},
		}
	}

	// Check business app ports for infrastructure
	if category, exists := ac.businessAppPorts[stream.DstPort]; exists {
		if category == CategoryNTP || category == CategoryLDAP || category == CategoryKerberos {
			return ac.buildBusinessAppClassification(category, stream.DstPort, 1.0)
		}
	}

	return ServiceClassification{Category: CategoryUnknown}
}

// classifyByProtocol provides fallback classification based on protocol
func (ac *AdvancedClassifier) classifyByProtocol(stream *models.StreamData) ServiceClassification {
	baseline := PerformanceBaseline{
		ExpectedLatencyMs:      200,
		ExpectedJitterMs:       50,
		ExpectedPacketLossRate: 0.01,
		ExpectedThroughputMbps: 1,
		HandshakeTimeoutSec:    5,
	}

	// HTTPS/TLS
	if stream.DstPort == 443 || stream.SrcPort == 443 {
		return ServiceClassification{
			Category:        CategoryWebBrowsing,
			Confidence:      0.6,
			TypicalBaseline: baseline,
		}
	}

	// SMB
	if stream.DstPort == 445 || stream.SrcPort == 445 {
		return ServiceClassification{
			Category:        CategoryFileSharing,
			Confidence:      0.9,
			TypicalBaseline: baseline,
		}
	}

	// RTP/VoIP (common ports)
	if (stream.DstPort >= 16384 && stream.DstPort <= 32767) ||
		(stream.SrcPort >= 16384 && stream.SrcPort <= 32767) {
		return ServiceClassification{
			Category:   CategoryVoIP,
			Confidence: 0.5,
			TypicalBaseline: PerformanceBaseline{
				ExpectedLatencyMs:      150,
				ExpectedJitterMs:       30,
				ExpectedPacketLossRate: 0.01,
				HandshakeTimeoutSec:    3,
			},
		}
	}

	return ServiceClassification{
		Category:        CategoryUnknown,
		Confidence:      0.0,
		TypicalBaseline: baseline,
	}
}
