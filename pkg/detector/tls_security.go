package detector

import (
	"fmt"
	"time"

	"github.com/gocisse/sdwan-triage/pkg/models"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// Weak TLS versions
var weakTLSVersions = map[uint16]string{
	0x0300: "SSL 3.0",
	0x0301: "TLS 1.0",
	0x0302: "TLS 1.1",
}

// Weak cipher suites (subset of known weak ciphers)
var weakCipherSuites = map[uint16]string{
	0x0000: "TLS_NULL_WITH_NULL_NULL",
	0x0001: "TLS_RSA_WITH_NULL_MD5",
	0x0002: "TLS_RSA_WITH_NULL_SHA",
	0x0004: "TLS_RSA_WITH_RC4_128_MD5",
	0x0005: "TLS_RSA_WITH_RC4_128_SHA",
	0x000A: "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
	0x0013: "TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA",
	0x0016: "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA",
	0x002F: "TLS_RSA_WITH_AES_128_CBC_SHA",
	0x0033: "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
	0x0035: "TLS_RSA_WITH_AES_256_CBC_SHA",
	0x0039: "TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
	0x003C: "TLS_RSA_WITH_AES_128_CBC_SHA256",
	0x003D: "TLS_RSA_WITH_AES_256_CBC_SHA256",
	0x0041: "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA",
	0x0084: "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA",
	0x009C: "TLS_RSA_WITH_AES_128_GCM_SHA256",
	0x009D: "TLS_RSA_WITH_AES_256_GCM_SHA384",
	0xC007: "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA",
	0xC011: "TLS_ECDHE_RSA_WITH_RC4_128_SHA",
}

// TLS version names
var tlsVersionNames = map[uint16]string{
	0x0300: "SSL 3.0",
	0x0301: "TLS 1.0",
	0x0302: "TLS 1.1",
	0x0303: "TLS 1.2",
	0x0304: "TLS 1.3",
}

// TLSSecurityAnalyzer handles TLS security weakness detection
type TLSSecurityAnalyzer struct {
	checkedConnections map[string]bool
}

// NewTLSSecurityAnalyzer creates a new TLS security analyzer
func NewTLSSecurityAnalyzer() *TLSSecurityAnalyzer {
	return &TLSSecurityAnalyzer{
		checkedConnections: make(map[string]bool),
	}
}

// Analyze processes TLS handshake packets for security weaknesses
func (t *TLSSecurityAnalyzer) Analyze(packet gopacket.Packet, state *models.AnalysisState, report *models.TriageReport) {
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		return
	}

	tcp, ok := tcpLayer.(*layers.TCP)
	if !ok {
		return
	}

	// Only check on typical TLS ports or if payload looks like TLS
	payload := tcp.Payload
	if len(payload) < 6 {
		return
	}

	// Check for TLS handshake (content type 22)
	if payload[0] != 22 {
		return
	}

	ipInfo := ExtractIPInfo(packet)
	if ipInfo == nil {
		return
	}

	srcIP := ipInfo.SrcIP
	dstIP := ipInfo.DstIP
	srcPort := uint16(tcp.SrcPort)
	dstPort := uint16(tcp.DstPort)
	timestamp := packet.Metadata().Timestamp

	// Parse TLS record
	t.analyzeTLSHandshake(payload, srcIP, dstIP, srcPort, dstPort, timestamp, state, report)
}

func (t *TLSSecurityAnalyzer) analyzeTLSHandshake(payload []byte, srcIP, dstIP string, srcPort, dstPort uint16, timestamp time.Time, state *models.AnalysisState, report *models.TriageReport) {
	if len(payload) < 6 {
		return
	}

	// TLS record header: content_type (1) + version (2) + length (2)
	recordVersion := uint16(payload[1])<<8 | uint16(payload[2])
	recordLength := int(payload[3])<<8 | int(payload[4])

	if len(payload) < 5+recordLength || recordLength < 4 {
		return
	}

	// Handshake header starts at offset 5
	handshakeType := payload[5]

	// Check for ServerHello (type 2) - this tells us what was negotiated
	if handshakeType == 2 {
		t.analyzeServerHello(payload[5:], srcIP, dstIP, srcPort, dstPort, recordVersion, timestamp, state, report)
	}

	// Check for ClientHello (type 1) - can detect weak cipher offers
	if handshakeType == 1 {
		t.analyzeClientHello(payload[5:], srcIP, dstIP, srcPort, dstPort, timestamp, state, report)
	}
}

func (t *TLSSecurityAnalyzer) analyzeServerHello(data []byte, srcIP, dstIP string, srcPort, dstPort uint16, recordVersion uint16, timestamp time.Time, state *models.AnalysisState, report *models.TriageReport) {
	if len(data) < 39 {
		return
	}

	// ServerHello structure:
	// handshake_type (1) + length (3) + version (2) + random (32) + session_id_length (1) + ...
	serverVersion := uint16(data[4])<<8 | uint16(data[5])

	// Skip random (32 bytes)
	sessionIDLen := int(data[38])
	if len(data) < 39+sessionIDLen+2 {
		return
	}

	// Cipher suite follows session ID
	cipherOffset := 39 + sessionIDLen
	cipherSuite := uint16(data[cipherOffset])<<8 | uint16(data[cipherOffset+1])

	// Connection key for deduplication
	connKey := fmt.Sprintf("%s:%d->%s:%d", srcIP, srcPort, dstIP, dstPort)
	if t.checkedConnections[connKey] {
		return
	}
	t.checkedConnections[connKey] = true

	// Get server name from SNI cache if available
	serverName := ""
	reverseKey := fmt.Sprintf("%s:%d->%s:%d", dstIP, dstPort, srcIP, srcPort)
	if sni, ok := state.TLSSNICache[reverseKey]; ok {
		serverName = sni
	}

	// Check for weak TLS version
	if versionName, isWeak := weakTLSVersions[serverVersion]; isWeak {
		t.reportWeakness(srcIP, srcPort, serverName, versionName, "", "Weak TLS Version", timestamp, report)
	}

	// Check for weak cipher suite
	if cipherName, isWeak := weakCipherSuites[cipherSuite]; isWeak {
		versionName := tlsVersionNames[serverVersion]
		if versionName == "" {
			versionName = fmt.Sprintf("0x%04X", serverVersion)
		}
		t.reportWeakness(srcIP, srcPort, serverName, versionName, cipherName, "Weak Cipher Suite", timestamp, report)
	}
}

func (t *TLSSecurityAnalyzer) analyzeClientHello(data []byte, srcIP, dstIP string, srcPort, dstPort uint16, timestamp time.Time, state *models.AnalysisState, report *models.TriageReport) {
	// ClientHello analysis - check if client is offering weak ciphers
	// This is less critical than ServerHello but can indicate outdated clients
	if len(data) < 43 {
		return
	}

	// Skip to cipher suites
	// handshake_type (1) + length (3) + version (2) + random (32) + session_id_length (1)
	sessionIDLen := int(data[38])
	if len(data) < 39+sessionIDLen+2 {
		return
	}

	cipherSuitesOffset := 39 + sessionIDLen
	cipherSuitesLen := int(data[cipherSuitesOffset])<<8 | int(data[cipherSuitesOffset+1])

	if len(data) < cipherSuitesOffset+2+cipherSuitesLen {
		return
	}

	// Count weak ciphers offered
	weakCount := 0
	for i := 0; i < cipherSuitesLen; i += 2 {
		offset := cipherSuitesOffset + 2 + i
		if offset+1 >= len(data) {
			break
		}
		cipher := uint16(data[offset])<<8 | uint16(data[offset+1])
		if _, isWeak := weakCipherSuites[cipher]; isWeak {
			weakCount++
		}
	}

	// Report if client offers many weak ciphers (indicates outdated client)
	if weakCount > 5 {
		connKey := fmt.Sprintf("%s:%d->%s:%d-client", srcIP, srcPort, dstIP, dstPort)
		if !t.checkedConnections[connKey] {
			t.checkedConnections[connKey] = true
			// Note: This is informational, not a direct vulnerability
		}
	}
}

func (t *TLSSecurityAnalyzer) reportWeakness(serverIP string, serverPort uint16, serverName, tlsVersion, cipherSuite, weaknessType string, timestamp time.Time, report *models.TriageReport) {
	// Check for duplicates
	for _, finding := range report.Security.TLSSecurityFindings {
		if finding.ServerIP == serverIP && finding.ServerPort == serverPort && finding.WeaknessType == weaknessType {
			return
		}
	}

	severity := "Medium"
	description := ""

	switch weaknessType {
	case "Weak TLS Version":
		if tlsVersion == "SSL 3.0" {
			severity = "Critical"
			description = "SSL 3.0 is vulnerable to POODLE attack and should not be used"
		} else if tlsVersion == "TLS 1.0" {
			severity = "High"
			description = "TLS 1.0 is deprecated and vulnerable to BEAST attack"
		} else {
			severity = "Medium"
			description = "TLS 1.1 is deprecated and should be upgraded to TLS 1.2 or higher"
		}
	case "Weak Cipher Suite":
		if cipherSuite != "" {
			if contains(cipherSuite, "RC4") {
				severity = "High"
				description = fmt.Sprintf("RC4 cipher is broken and should not be used: %s", cipherSuite)
			} else if contains(cipherSuite, "NULL") {
				severity = "Critical"
				description = fmt.Sprintf("NULL cipher provides no encryption: %s", cipherSuite)
			} else if contains(cipherSuite, "3DES") {
				severity = "Medium"
				description = fmt.Sprintf("3DES cipher is weak due to small block size: %s", cipherSuite)
			} else if contains(cipherSuite, "CBC") && !contains(cipherSuite, "ECDHE") && !contains(cipherSuite, "DHE") {
				severity = "Medium"
				description = fmt.Sprintf("CBC cipher without forward secrecy: %s", cipherSuite)
			} else {
				description = fmt.Sprintf("Weak cipher suite detected: %s", cipherSuite)
			}
		}
	}

	finding := models.TLSSecurityFinding{
		Timestamp:    float64(timestamp.UnixNano()) / 1e9,
		ServerIP:     serverIP,
		ServerPort:   serverPort,
		ServerName:   serverName,
		TLSVersion:   tlsVersion,
		CipherSuite:  cipherSuite,
		WeaknessType: weaknessType,
		Severity:     severity,
		Description:  description,
	}

	report.Security.TLSSecurityFindings = append(report.Security.TLSSecurityFindings, finding)
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsHelper(s, substr))
}

func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
