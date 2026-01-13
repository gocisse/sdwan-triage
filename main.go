package main

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/fatih/color"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

// === Data Structures ===
type TriageReport struct {
	DNSAnomalies                []DNSAnomaly                 `json:"dns_anomalies"`
	TCPRetransmissions          []TCPFlow                    `json:"tcp_retransmissions"`
	FailedHandshakes            []TCPFlow                    `json:"failed_handshakes"`
	TCPHandshakes               TCPHandshakeAnalysis         `json:"tcp_handshakes"`
	TCPHandshakeCorrelatedFlows []TCPHandshakeCorrelatedFlow `json:"tcp_handshake_correlated_flows,omitempty"`
	ARPConflicts                []ARPConflict                `json:"arp_conflicts"`
	HTTPErrors                  []HTTPError                  `json:"http_errors"`
	TLSCerts                    []TLSCertInfo                `json:"tls_certs"`
	TLSFlows                    []TCPFlow                    `json:"tls_flows"`
	HTTP2Flows                  []TCPFlow                    `json:"http2_flows"`
	QUICFlows                   []UDPFlow                    `json:"quic_flows"`
	TrafficAnalysis             []TrafficFlow                `json:"traffic_analysis"`
	ApplicationBreakdown        map[string]AppCategory       `json:"application_breakdown"`
	SuspiciousTraffic           []SuspiciousFlow             `json:"suspicious_traffic"`
	RTTAnalysis                 []RTTFlow                    `json:"rtt_analysis"`
	DeviceFingerprinting        []DeviceFingerprint          `json:"device_fingerprinting"`
	BandwidthReport             BandwidthReport              `json:"bandwidth_report"`
	Timeline                    []TimelineEvent              `json:"timeline"`
	DNSDetails                  []DNSRecord                  `json:"dns_details"`
	BGPHijackIndicators         []BGPIndicator               `json:"bgp_hijack_indicators,omitempty"`
	QoSAnalysis                 *QoSReport                   `json:"qos_analysis,omitempty"`
	AppIdentification           []IdentifiedApp              `json:"app_identification,omitempty"`
	TotalBytes                  uint64                       `json:"total_bytes"`
}

type TimelineEvent struct {
	Timestamp       float64 `json:"timestamp"`
	EventType       string  `json:"event_type"`
	SourceIP        string  `json:"source_ip"`
	DestinationIP   string  `json:"destination_ip"`
	SourcePort      *uint16 `json:"source_port,omitempty"`
	DestinationPort *uint16 `json:"destination_port,omitempty"`
	Protocol        string  `json:"protocol"`
	Detail          string  `json:"detail"`
}

type DNSRecord struct {
	QueryTimestamp    float64  `json:"query_timestamp"`
	QueryName         string   `json:"query_name"`
	QueryType         string   `json:"query_type"`
	SourceIP          string   `json:"source_ip"`
	DestinationIP     string   `json:"destination_ip"`
	ResponseTimestamp *float64 `json:"response_timestamp,omitempty"`
	ResponseCode      *uint16  `json:"response_code,omitempty"`
	AnswerIPs         []string `json:"answer_ips"`
	AnswerNames       []string `json:"answer_names"`
	IsAnomalous       bool     `json:"is_anomalous"`
	Detail            string   `json:"detail"`
}

type DNSAnomaly struct {
	Timestamp float64 `json:"timestamp"`
	Query     string  `json:"query"`
	AnswerIP  string  `json:"answer_ip"`
	ServerIP  string  `json:"server_ip"`
	ServerMAC string  `json:"server_mac"`
	Reason    string  `json:"reason"`
}

type TCPFlow struct {
	SrcIP   string `json:"src_ip"`
	SrcPort uint16 `json:"src_port"`
	DstIP   string `json:"dst_ip"`
	DstPort uint16 `json:"dst_port"`
}

type TCPHandshakeFlow struct {
	SrcIP     string  `json:"src_ip"`
	SrcPort   uint16  `json:"src_port"`
	DstIP     string  `json:"dst_ip"`
	DstPort   uint16  `json:"dst_port"`
	Timestamp float64 `json:"timestamp"`
	Count     int     `json:"count"`
}

type TCPHandshakeAnalysis struct {
	SYNFlows                []TCPHandshakeFlow `json:"syn_flows"`
	SYNACKFlows             []TCPHandshakeFlow `json:"synack_flows"`
	SuccessfulHandshakes    []TCPHandshakeFlow `json:"successful_handshakes"`
	FailedHandshakeAttempts []TCPHandshakeFlow `json:"failed_handshake_attempts"`
}

// TCPHandshakeEvent represents a single event in a TCP handshake sequence
type TCPHandshakeEvent struct {
	Type      string  `json:"type"`      // "SYN", "SYN-ACK", "Handshake Complete"
	Timestamp float64 `json:"timestamp"` // Unix timestamp
}

// TCPHandshakeCorrelatedFlow represents a TCP handshake flow with all its events grouped together
type TCPHandshakeCorrelatedFlow struct {
	FlowID  string              `json:"flow_id"` // e.g., "SrcIP:SrcPort->DstIP:DstPort"
	SrcIP   string              `json:"src_ip"`
	SrcPort uint16              `json:"src_port"`
	DstIP   string              `json:"dst_ip"`
	DstPort uint16              `json:"dst_port"`
	Events  []TCPHandshakeEvent `json:"events"` // Ordered list of events for this flow
	Status  string              `json:"status"` // "Complete", "Failed", "Pending"
}

type TrafficFlowSummary struct {
	SrcIP            string        `json:"src_ip"`
	SrcPort          uint16        `json:"src_port"`
	DstIP            string        `json:"dst_ip"`
	DstPort          uint16        `json:"dst_port"`
	Protocol         string        `json:"protocol"`
	TotalBytes       uint64        `json:"total_bytes"`
	TotalPackets     uint64        `json:"total_packets"`
	Duration         time.Duration `json:"duration"`
	AvgBitsPerSecond float64       `json:"avg_bits_per_second"`
	FirstSeen        time.Time     `json:"first_seen"`
	LastSeen         time.Time     `json:"last_seen"`
}

type TimeBucket struct {
	Timestamp    time.Time `json:"timestamp"`
	TotalBytes   uint64    `json:"total_bytes"`
	TotalPackets uint64    `json:"total_packets"`
}

type BandwidthReport struct {
	TopConversationsByBytes   []TrafficFlowSummary `json:"top_conversations_by_bytes"`
	TopConversationsByPackets []TrafficFlowSummary `json:"top_conversations_by_packets"`
	TimeSeriesData            []TimeBucket         `json:"time_series_data"`
}

type UDPFlow struct {
	SrcIP      string `json:"src_ip"`
	SrcPort    uint16 `json:"src_port"`
	DstIP      string `json:"dst_ip"`
	DstPort    uint16 `json:"dst_port"`
	ServerName string `json:"server_name,omitempty"`
}

type ARPConflict struct {
	IP   string `json:"ip"`
	MAC1 string `json:"mac1"`
	MAC2 string `json:"mac2"`
}

type HTTPError struct {
	Timestamp float64 `json:"timestamp"`
	Method    string  `json:"method"`
	Host      string  `json:"host"`
	Path      string  `json:"path"`
	Code      int     `json:"status_code"`
}

type TLSCertInfo struct {
	Timestamp    float64  `json:"timestamp"`
	ServerIP     string   `json:"server_ip"`
	ServerPort   uint16   `json:"server_port"`
	ServerName   string   `json:"server_name"`
	Issuer       string   `json:"issuer"`
	Subject      string   `json:"subject"`
	NotBefore    string   `json:"not_before"`
	NotAfter     string   `json:"not_after"`
	Fingerprint  string   `json:"fingerprint"`
	IsExpired    bool     `json:"is_expired"`
	IsSelfSigned bool     `json:"is_self_signed"`
	DNSNames     []string `json:"dns_names,omitempty"`
}

type TrafficFlow struct {
	SrcIP      string  `json:"src_ip"`
	SrcPort    uint16  `json:"src_port"`
	DstIP      string  `json:"dst_ip"`
	DstPort    uint16  `json:"dst_port"`
	Protocol   string  `json:"protocol"`
	TotalBytes uint64  `json:"total_bytes"`
	Percentage float64 `json:"percentage"`
}

type AppCategory struct {
	Name        string `json:"name"`
	Port        uint16 `json:"port"`
	Protocol    string `json:"protocol"`
	PacketCount uint64 `json:"packet_count"`
	ByteCount   uint64 `json:"byte_count"`
}

type SuspiciousFlow struct {
	SrcIP       string `json:"src_ip"`
	SrcPort     uint16 `json:"src_port"`
	DstIP       string `json:"dst_ip"`
	DstPort     uint16 `json:"dst_port"`
	Protocol    string `json:"protocol"`
	Reason      string `json:"reason"`
	Description string `json:"description"`
}

type RTTFlow struct {
	SrcIP      string  `json:"src_ip"`
	SrcPort    uint16  `json:"src_port"`
	DstIP      string  `json:"dst_ip"`
	DstPort    uint16  `json:"dst_port"`
	MinRTT     float64 `json:"min_rtt_ms"`
	MaxRTT     float64 `json:"max_rtt_ms"`
	AvgRTT     float64 `json:"avg_rtt_ms"`
	SampleSize int     `json:"sample_size"`
}

type DeviceFingerprint struct {
	SrcIP      string `json:"src_ip"`
	DeviceType string `json:"device_type"`
	OSGuess    string `json:"os_guess"`
	Confidence string `json:"confidence"`
	Details    string `json:"details"`
}

// BGP Analysis structures
type BGPIndicator struct {
	IPAddress      string `json:"ip_address"`
	IPPrefix       string `json:"ip_prefix"`
	ExpectedASN    int    `json:"expected_asn"`
	ExpectedASName string `json:"expected_as_name"`
	ObservedASN    int    `json:"observed_asn,omitempty"`
	ObservedASName string `json:"observed_as_name,omitempty"`
	Confidence     string `json:"confidence"`
	Reason         string `json:"reason"`
	RelatedDomain  string `json:"related_domain,omitempty"`
	IsAnomaly      bool   `json:"is_anomaly"`
}

// QoS Analysis structures
type QoSReport struct {
	ClassDistribution map[string]*QoSClassMetrics `json:"class_distribution"`
	TotalPackets      uint64                      `json:"total_packets"`
	MismatchedQoS     []QoSMismatch               `json:"mismatched_qos,omitempty"`
}

type QoSClassMetrics struct {
	ClassName       string  `json:"class_name"`
	DSCPValue       uint8   `json:"dscp_value"`
	PacketCount     uint64  `json:"packet_count"`
	ByteCount       uint64  `json:"byte_count"`
	Percentage      float64 `json:"percentage"`
	AvgRTT          float64 `json:"avg_rtt_ms,omitempty"`
	RetransmitCount uint64  `json:"retransmit_count"`
	RetransmitRate  float64 `json:"retransmit_rate_percent"`
}

type QoSMismatch struct {
	Flow          string `json:"flow"`
	ExpectedClass string `json:"expected_class"`
	ActualClass   string `json:"actual_class"`
	Reason        string `json:"reason"`
}

// Application Identification structures
type IdentifiedApp struct {
	Name             string   `json:"name"`
	Category         string   `json:"category"`
	Protocol         string   `json:"protocol"`
	Port             uint16   `json:"port,omitempty"`
	SNI              string   `json:"sni,omitempty"`
	ALPN             string   `json:"alpn,omitempty"`
	PacketCount      uint64   `json:"packet_count"`
	ByteCount        uint64   `json:"byte_count"`
	Confidence       string   `json:"confidence"`
	IdentifiedBy     string   `json:"identified_by"`
	SampleFlows      []string `json:"sample_flows,omitempty"`
	IsSuspicious     bool     `json:"is_suspicious"`
	SuspiciousReason string   `json:"suspicious_reason,omitempty"`
}

// Private IP blocks (RFC 1918 + localhost + link-local)
var privateIPBlocks = []*net.IPNet{
	{IP: net.IP{10, 0, 0, 0}, Mask: net.CIDRMask(8, 32)},
	{IP: net.IP{172, 16, 0, 0}, Mask: net.CIDRMask(12, 32)},
	{IP: net.IP{192, 168, 0, 0}, Mask: net.CIDRMask(16, 32)},
	{IP: net.IP{127, 0, 0, 0}, Mask: net.CIDRMask(8, 32)},
	{IP: net.IP{169, 254, 0, 0}, Mask: net.CIDRMask(16, 32)},
	{IP: net.ParseIP("::1"), Mask: net.CIDRMask(128, 128)},
}

// Public TLD regex
var publicDomainRegex = regexp.MustCompile(`\.(com|net|org|edu|gov|mil|int|co|io|ai|dev|app|cloud|ai)$`)

// Application port mappings
var wellKnownPorts = map[uint16]string{
	20:   "FTP-Data",
	21:   "FTP",
	22:   "SSH",
	23:   "Telnet",
	25:   "SMTP",
	53:   "DNS",
	80:   "HTTP",
	110:  "POP3",
	143:  "IMAP",
	443:  "HTTPS",
	445:  "SMB",
	465:  "SMTPS",
	587:  "SMTP-Submission",
	993:  "IMAPS",
	995:  "POP3S",
	3306: "MySQL",
	3389: "RDP",
	5432: "PostgreSQL",
	5900: "VNC",
	6379: "Redis",
	8080: "HTTP-Alt",
	8443: "HTTPS-Alt",
}

// Suspicious/high-risk ports
var suspiciousPorts = map[uint16]string{
	6667:  "IRC (potential botnet C&C)",
	6668:  "IRC (potential botnet C&C)",
	6669:  "IRC (potential botnet C&C)",
	1337:  "Common malware port",
	31337: "Back Orifice trojan",
	12345: "NetBus trojan",
	27374: "SubSeven trojan",
	9001:  "Tor network",
	9030:  "Tor network",
	4444:  "Metasploit default",
	5555:  "Android Debug Bridge (potential unauthorized access)",
	7777:  "Common backdoor port",
	8888:  "Common proxy/malware port",
}

// DSCP class mappings for QoS analysis
var dscpClasses = map[uint8]string{
	0:  "BE",   // Best Effort (Default)
	8:  "CS1",  // Class Selector 1 (Scavenger)
	10: "AF11", // Assured Forwarding 11
	12: "AF12", // Assured Forwarding 12
	14: "AF13", // Assured Forwarding 13
	16: "CS2",  // Class Selector 2
	18: "AF21", // Assured Forwarding 21
	20: "AF22", // Assured Forwarding 22
	22: "AF23", // Assured Forwarding 23
	24: "CS3",  // Class Selector 3
	26: "AF31", // Assured Forwarding 31
	28: "AF32", // Assured Forwarding 32
	30: "AF33", // Assured Forwarding 33
	32: "CS4",  // Class Selector 4
	34: "AF41", // Assured Forwarding 41
	36: "AF42", // Assured Forwarding 42
	38: "AF43", // Assured Forwarding 43
	40: "CS5",  // Class Selector 5
	46: "EF",   // Expedited Forwarding (VoIP)
	48: "CS6",  // Class Selector 6 (Network Control)
	56: "CS7",  // Class Selector 7 (Network Control)
}

// DSCP class descriptions for reporting
var dscpDescriptions = map[string]string{
	"BE":   "Best Effort - Default traffic class",
	"CS1":  "Scavenger - Low priority background traffic",
	"AF11": "Assured Forwarding 11 - Low drop probability",
	"AF12": "Assured Forwarding 12 - Medium drop probability",
	"AF13": "Assured Forwarding 13 - High drop probability",
	"CS2":  "Class Selector 2 - OAM traffic",
	"AF21": "Assured Forwarding 21 - Low drop probability",
	"AF22": "Assured Forwarding 22 - Medium drop probability",
	"AF23": "Assured Forwarding 23 - High drop probability",
	"CS3":  "Class Selector 3 - Signaling",
	"AF31": "Assured Forwarding 31 - Low drop probability",
	"AF32": "Assured Forwarding 32 - Medium drop probability",
	"AF33": "Assured Forwarding 33 - High drop probability",
	"CS4":  "Class Selector 4 - Real-time interactive",
	"AF41": "Assured Forwarding 41 - Low drop probability",
	"AF42": "Assured Forwarding 42 - Medium drop probability",
	"AF43": "Assured Forwarding 43 - High drop probability",
	"CS5":  "Class Selector 5 - Broadcast video",
	"EF":   "Expedited Forwarding - VoIP/Real-time",
	"CS6":  "Class Selector 6 - Network control",
	"CS7":  "Class Selector 7 - Network control",
}

// Application signatures for heuristic identification
var appSignatures = map[string]struct {
	pattern     string
	category    string
	description string
}{
	"SSH":        {pattern: "SSH-", category: "Remote Access", description: "Secure Shell"},
	"HTTP":       {pattern: "HTTP/", category: "Web", description: "Hypertext Transfer Protocol"},
	"TLS":        {pattern: "\x16\x03", category: "Encrypted", description: "TLS Handshake"},
	"DNS":        {pattern: "", category: "Network", description: "Domain Name System"},
	"SMB":        {pattern: "\xffSMB", category: "File Sharing", description: "Server Message Block"},
	"RDP":        {pattern: "\x03\x00", category: "Remote Access", description: "Remote Desktop Protocol"},
	"MySQL":      {pattern: "", category: "Database", description: "MySQL Database"},
	"PostgreSQL": {pattern: "", category: "Database", description: "PostgreSQL Database"},
}

// === Internal Tracking Structures ===
type tcpFlowState struct {
	lastSeq       uint32
	lastAck       uint32
	expectedSeq   uint32
	seqSeen       map[uint32]bool
	rttSamples    []float64
	sentTimes     map[uint32]time.Time
	totalBytes    uint64
	dupAckCount   int
	lastDupAck    uint32
	outOfOrderSeq map[uint32]bool
}

type udpFlowState struct {
	totalBytes uint64
}

type httpRequest struct {
	method    string
	host      string
	path      string
	timestamp time.Time
}

type dnsQueryInfo struct {
	queryName     string
	queryType     string
	sourceIP      string
	destinationIP string
	timestamp     time.Time
}

type tcpFingerprint struct {
	windowSize uint16
	ttl        uint8
	mss        uint16
	hasTS      bool
	hasSACK    bool
	hasWS      bool
	dfFlag     bool
}

// Filter holds packet filtering criteria
type Filter struct {
	srcIP    string
	dstIP    string
	service  string
	protocol string
}

// isEmpty returns true if no filters are set
func (f *Filter) isEmpty() bool {
	return f.srcIP == "" && f.dstIP == "" && f.service == "" && f.protocol == ""
}

// Path represents a communication path between two endpoints
type Path struct {
	SrcIP       string
	DstIP       string
	Protocols   map[string]bool
	Ports       map[uint16]bool
	PacketCount int
	ByteCount   uint64
	HasAnomaly  bool // Set to true if retransmissions or high latency detected
}

// PathStats holds all communication paths for diagram generation
type PathStats struct {
	Paths map[string]*Path // Key: "SrcIP->DstIP"
	mu    sync.Mutex
}

// TracerouteHop represents a single hop in a traceroute path
type TracerouteHop struct {
	HopNumber int
	IP        string
	Hostname  string
	RTT       string
}

// TracerouteData stores traceroute results for destinations
type TracerouteData struct {
	Paths map[string][]TracerouteHop // Key: destination IP
	mu    sync.Mutex
}

// === Helper Functions ===
func isPublicDomain(domain string) bool {
	domain = strings.TrimRight(strings.ToLower(domain), ".")
	return publicDomainRegex.MatchString(domain)
}

func isPrivateOrReservedIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	for _, block := range privateIPBlocks {
		if block.Contains(ip) {
			return true
		}
	}
	return false
}

func isPrivateIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	for _, block := range privateIPBlocks {
		if block.Contains(ip) {
			return true
		}
	}
	return false
}

// Parse TLS handshake and extract certificates
func parseTLSHandshake(payload []byte) ([]*x509.Certificate, string) {
	if len(payload) < 6 {
		return nil, ""
	}

	// TLS record: type(1) + version(2) + length(2) + data
	if payload[0] != 0x16 { // Handshake
		return nil, ""
	}

	recordLen := int(binary.BigEndian.Uint16(payload[3:5]))
	if len(payload) < 5+recordLen {
		return nil, ""
	}

	handshakeData := payload[5 : 5+recordLen]
	sni := extractSNIFromHandshake(handshakeData)
	certs := extractCertsFromHandshake(handshakeData)

	return certs, sni
}

// Extract SNI from TLS ClientHello
func extractSNIFromHandshake(data []byte) string {
	if len(data) < 4 || data[0] != 0x01 { // ClientHello
		return ""
	}

	// Skip handshake header (4 bytes) + client version (2) + random (32)
	if len(data) < 38 {
		return ""
	}

	pos := 38
	// Session ID length
	if pos >= len(data) {
		return ""
	}
	sessionIDLen := int(data[pos])
	pos += 1 + sessionIDLen

	// Cipher suites length
	if pos+2 > len(data) {
		return ""
	}
	cipherSuitesLen := int(binary.BigEndian.Uint16(data[pos : pos+2]))
	pos += 2 + cipherSuitesLen

	// Compression methods length
	if pos >= len(data) {
		return ""
	}
	compressionLen := int(data[pos])
	pos += 1 + compressionLen

	// Extensions
	if pos+2 > len(data) {
		return ""
	}
	extensionsLen := int(binary.BigEndian.Uint16(data[pos : pos+2]))
	pos += 2

	endPos := pos + extensionsLen
	for pos+4 <= endPos && pos+4 <= len(data) {
		extType := binary.BigEndian.Uint16(data[pos : pos+2])
		extLen := int(binary.BigEndian.Uint16(data[pos+2 : pos+4]))
		pos += 4

		if pos+extLen > len(data) {
			break
		}

		// Server Name Indication (0x0000)
		if extType == 0x0000 && extLen > 5 {
			listLen := int(binary.BigEndian.Uint16(data[pos : pos+2]))
			if pos+2+listLen <= len(data) && listLen > 3 {
				nameType := data[pos+2]
				if nameType == 0x00 { // host_name
					nameLen := int(binary.BigEndian.Uint16(data[pos+3 : pos+5]))
					if pos+5+nameLen <= len(data) {
						return string(data[pos+5 : pos+5+nameLen])
					}
				}
			}
		}
		pos += extLen
	}

	return ""
}

// Extract certificates from TLS Certificate message
func extractCertsFromHandshake(data []byte) []*x509.Certificate {
	if len(data) < 4 || data[0] != 0x0b { // Certificate message
		return nil
	}

	// Skip handshake header (4 bytes)
	if len(data) < 7 {
		return nil
	}

	pos := 4
	certsLen := int(data[pos])<<16 | int(data[pos+1])<<8 | int(data[pos+2])
	pos += 3

	if pos+certsLen > len(data) {
		return nil
	}

	var certs []*x509.Certificate
	endPos := pos + certsLen

	for pos+3 <= endPos {
		certLen := int(data[pos])<<16 | int(data[pos+1])<<8 | int(data[pos+2])
		pos += 3

		if pos+certLen > len(data) {
			break
		}

		certData := data[pos : pos+certLen]
		if cert, err := x509.ParseCertificate(certData); err == nil {
			certs = append(certs, cert)
		}
		pos += certLen
	}

	return certs
}

// Extract ALPN protocols from TLS ClientHello
func extractALPNProtocols(data []byte) []string {
	// TLS record: type(1) + version(2) + length(2) + handshake
	if len(data) < 43 || data[0] != 0x16 { // Handshake record
		return nil
	}

	// Skip TLS record header (5 bytes)
	pos := 5

	// Handshake type should be ClientHello (0x01)
	if pos >= len(data) || data[pos] != 0x01 {
		return nil
	}

	// Skip handshake header: type(1) + length(3) + version(2) + random(32)
	pos += 1 + 3 + 2 + 32

	if pos >= len(data) {
		return nil
	}

	// Session ID length
	sessionIDLen := int(data[pos])
	pos += 1 + sessionIDLen

	if pos+2 > len(data) {
		return nil
	}

	// Cipher suites length
	cipherSuitesLen := int(binary.BigEndian.Uint16(data[pos : pos+2]))
	pos += 2 + cipherSuitesLen

	if pos+1 > len(data) {
		return nil
	}

	// Compression methods length
	compressionLen := int(data[pos])
	pos += 1 + compressionLen

	if pos+2 > len(data) {
		return nil
	}

	// Extensions length
	extensionsLen := int(binary.BigEndian.Uint16(data[pos : pos+2]))
	pos += 2

	if pos+extensionsLen > len(data) {
		return nil
	}

	endPos := pos + extensionsLen

	// Parse extensions
	for pos+4 <= endPos {
		extType := binary.BigEndian.Uint16(data[pos : pos+2])
		extLen := int(binary.BigEndian.Uint16(data[pos+2 : pos+4]))
		pos += 4

		if pos+extLen > len(data) {
			break
		}

		// ALPN extension (0x0010)
		if extType == 0x0010 && extLen > 2 {
			alpnListLen := int(binary.BigEndian.Uint16(data[pos : pos+2]))
			alpnPos := pos + 2

			if alpnPos+alpnListLen > len(data) {
				break
			}

			var protocols []string
			alpnEnd := alpnPos + alpnListLen

			for alpnPos < alpnEnd && alpnPos < len(data) {
				if alpnPos+1 > len(data) {
					break
				}
				protoLen := int(data[alpnPos])
				alpnPos++

				if alpnPos+protoLen > len(data) {
					break
				}

				protocol := string(data[alpnPos : alpnPos+protoLen])
				protocols = append(protocols, protocol)
				alpnPos += protoLen
			}

			return protocols
		}

		pos += extLen
	}

	return nil
}

// Extract SNI from QUIC Initial packet
func extractQUICServerName(payload []byte) string {
	if len(payload) < 1200 { // QUIC Initial packets are typically padded
		return ""
	}

	// QUIC long header: flags(1) + version(4) + DCID len(1) + DCID + SCID len(1) + SCID + token...
	if payload[0]&0xC0 != 0xC0 {
		return ""
	}

	pos := 5 // Skip flags + version
	if pos >= len(payload) {
		return ""
	}

	// Destination Connection ID
	dcidLen := int(payload[pos])
	pos += 1 + dcidLen

	if pos >= len(payload) {
		return ""
	}

	// Source Connection ID
	scidLen := int(payload[pos])
	pos += 1 + scidLen

	// Token (for Initial packets)
	if pos >= len(payload) {
		return ""
	}

	// Variable-length integer for token length
	tokenLen, bytesRead := decodeQUICVarInt(payload[pos:])
	pos += bytesRead + int(tokenLen)

	if pos >= len(payload) {
		return ""
	}

	// Length of packet number + payload
	_, bytesRead = decodeQUICVarInt(payload[pos:])
	pos += bytesRead

	// Skip packet number (1-4 bytes, we'll assume 1 for simplicity)
	pos += 1

	// Look for TLS ClientHello in the CRYPTO frame
	// This is a simplified heuristic - real QUIC parsing is more complex
	if pos+100 < len(payload) {
		return extractSNIFromHandshake(payload[pos:])
	}

	return ""
}

// Decode QUIC variable-length integer
func decodeQUICVarInt(data []byte) (uint64, int) {
	if len(data) == 0 {
		return 0, 0
	}

	firstByte := data[0]
	prefix := firstByte >> 6

	switch prefix {
	case 0:
		return uint64(firstByte & 0x3F), 1
	case 1:
		if len(data) < 2 {
			return 0, 0
		}
		return uint64(binary.BigEndian.Uint16(data[:2]) & 0x3FFF), 2
	case 2:
		if len(data) < 4 {
			return 0, 0
		}
		return uint64(binary.BigEndian.Uint32(data[:4]) & 0x3FFFFFFF), 4
	case 3:
		if len(data) < 8 {
			return 0, 0
		}
		return binary.BigEndian.Uint64(data[:8]) & 0x3FFFFFFFFFFFFFFF, 8
	}

	return 0, 0
}
func parseHTTPRequest(payload []byte) *httpRequest {
	payloadStr := string(payload)
	lines := strings.Split(payloadStr, "\r\n")

	if len(lines) == 0 {
		return nil
	}

	// Parse request line: METHOD PATH HTTP/1.x
	parts := strings.Fields(lines[0])
	if len(parts) < 3 || !strings.HasPrefix(parts[2], "HTTP/") {
		return nil
	}

	req := &httpRequest{
		method:    parts[0],
		path:      parts[1],
		timestamp: time.Now(),
	}

	// Extract Host header
	for _, line := range lines[1:] {
		if strings.HasPrefix(strings.ToLower(line), "host:") {
			req.host = strings.TrimSpace(line[5:])
			break
		}
	}

	return req
}

// Extract TCP fingerprint from SYN packet
func extractTCPFingerprint(tcp *layers.TCP, ip4 *layers.IPv4) *tcpFingerprint {
	fp := &tcpFingerprint{
		windowSize: tcp.Window,
		ttl:        ip4.TTL,
		dfFlag:     (ip4.Flags & layers.IPv4DontFragment) != 0,
	}

	for _, opt := range tcp.Options {
		switch opt.OptionType {
		case layers.TCPOptionKindMSS:
			if len(opt.OptionData) == 2 {
				fp.mss = binary.BigEndian.Uint16(opt.OptionData)
			}
		case layers.TCPOptionKindTimestamps:
			fp.hasTS = true
		case layers.TCPOptionKindSACKPermitted:
			fp.hasSACK = true
		case layers.TCPOptionKindWindowScale:
			fp.hasWS = true
		}
	}

	return fp
}

// Guess OS/Device type from TCP fingerprint
func guessOSFromFingerprint(fp *tcpFingerprint) (string, string, string) {
	// Windows signatures
	if fp.windowSize == 8192 && fp.ttl >= 128 && fp.ttl <= 130 {
		return "Windows", "Windows 7/8/10", "High"
	}
	if fp.windowSize == 65535 && fp.ttl >= 128 && fp.ttl <= 130 && fp.hasWS {
		return "Windows", "Windows 10/11", "High"
	}

	// Linux signatures
	if fp.ttl >= 64 && fp.ttl <= 65 && fp.mss == 1460 && fp.hasSACK {
		return "Linux", "Linux 2.6+/Ubuntu/Debian", "Medium"
	}
	if fp.windowSize == 29200 && fp.ttl == 64 {
		return "Linux", "Linux (recent kernel)", "High"
	}

	// macOS/iOS signatures
	if fp.windowSize == 65535 && fp.ttl == 64 && fp.mss == 1460 {
		return "Apple", "macOS/iOS", "Medium"
	}

	// Android signatures
	if fp.windowSize == 65535 && fp.ttl >= 64 && fp.ttl <= 65 && fp.hasTS && fp.hasSACK {
		return "Android", "Android device", "Low"
	}

	// Router/Network device signatures
	if fp.ttl >= 254 && fp.ttl <= 255 {
		return "Network Device", "Router/Switch/Firewall", "Medium"
	}

	// IoT device heuristics (small window, basic options)
	if fp.windowSize < 8192 && !fp.hasTS && !fp.hasWS {
		return "IoT Device", "Embedded/IoT device", "Low"
	}

	return "Unknown", "Unable to determine", "Low"
}

// Categorize port to application
func categorizePort(port uint16, protocol string) string {
	if appName, ok := wellKnownPorts[port]; ok {
		return appName
	}

	// Additional heuristics
	if port >= 49152 && port <= 65535 {
		return "Ephemeral"
	}
	if port >= 1024 && port < 49152 {
		return "Registered"
	}

	return "Unknown"
}

// Check if port is suspicious
func isSuspiciousPort(port uint16) (bool, string) {
	if reason, ok := suspiciousPorts[port]; ok {
		return true, reason
	}
	return false, ""
}

// resolveServiceToPort converts service name to port number
func resolveServiceToPort(service string) (uint16, bool) {
	// Service name to port mapping
	serviceMap := map[string]uint16{
		"ftp":      21,
		"ssh":      22,
		"telnet":   23,
		"smtp":     25,
		"dns":      53,
		"http":     80,
		"https":    443,
		"smb":      445,
		"mysql":    3306,
		"rdp":      3389,
		"postgres": 5432,
		"vnc":      5900,
		"redis":    6379,
	}

	// Try direct port number
	if port, err := fmt.Sscanf(service, "%d", new(uint16)); err == nil && port == 1 {
		var p uint16
		fmt.Sscanf(service, "%d", &p)
		return p, true
	}

	// Try service name lookup
	if port, ok := serviceMap[strings.ToLower(service)]; ok {
		return port, true
	}

	return 0, false
}

// trackPath records communication paths for diagram generation
func trackPath(pathStats *PathStats, srcIP, dstIP string, packet gopacket.Packet) {
	if srcIP == "" || dstIP == "" {
		return
	}

	pathStats.mu.Lock()
	defer pathStats.mu.Unlock()

	key := fmt.Sprintf("%s->%s", srcIP, dstIP)
	path, exists := pathStats.Paths[key]
	if !exists {
		path = &Path{
			SrcIP:     srcIP,
			DstIP:     dstIP,
			Protocols: make(map[string]bool),
			Ports:     make(map[uint16]bool),
		}
		pathStats.Paths[key] = path
	}

	path.PacketCount++

	// Track protocols
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		path.Protocols["TCP"] = true
		tcp := tcpLayer.(*layers.TCP)
		path.Ports[uint16(tcp.SrcPort)] = true
		path.Ports[uint16(tcp.DstPort)] = true
		if appLayer := packet.ApplicationLayer(); appLayer != nil {
			path.ByteCount += uint64(len(appLayer.Payload()))
		}
	} else if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		path.Protocols["UDP"] = true
		udp := udpLayer.(*layers.UDP)
		path.Ports[uint16(udp.SrcPort)] = true
		path.Ports[uint16(udp.DstPort)] = true
		if appLayer := packet.ApplicationLayer(); appLayer != nil {
			path.ByteCount += uint64(len(appLayer.Payload()))
		}
	}

	// Track total bytes from network layer
	if netLayer := packet.NetworkLayer(); netLayer != nil {
		if ip4, ok := netLayer.(*layers.IPv4); ok {
			path.ByteCount += uint64(ip4.Length)
		}
	}
}

// markPathAnomaly marks a path as having an anomaly (retransmission, high latency, etc.)
func markPathAnomaly(pathStats *PathStats, srcIP, dstIP string) {
	pathStats.mu.Lock()
	defer pathStats.mu.Unlock()

	key := fmt.Sprintf("%s->%s", srcIP, dstIP)
	if path, exists := pathStats.Paths[key]; exists {
		path.HasAnomaly = true
	}
}

// executeTraceroute runs traceroute command and parses the output
func executeTraceroute(targetIP string) ([]TracerouteHop, error) {
	// Determine OS and use appropriate command
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("tracert", "-h", "15", "-w", "1000", targetIP)
	} else {
		cmd = exec.Command("traceroute", "-m", "15", "-w", "1", targetIP)
	}

	// Set timeout for the entire traceroute operation
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd = exec.CommandContext(ctx, cmd.Path, cmd.Args[1:]...)

	output, err := cmd.CombinedOutput()
	if err != nil {
		// Traceroute might return non-zero exit code even with partial results
		if len(output) == 0 {
			return nil, fmt.Errorf("traceroute failed: %v", err)
		}
	}

	return parseTracerouteOutput(string(output), runtime.GOOS)
}

// parseTracerouteOutput extracts hop information from traceroute output
func parseTracerouteOutput(output string, osType string) ([]TracerouteHop, error) {
	var hops []TracerouteHop
	lines := strings.Split(output, "\n")

	// Regex patterns for different OS outputs
	var hopRegex *regexp.Regexp
	if osType == "windows" {
		// Windows tracert format: "  1    <1 ms    <1 ms    <1 ms  192.168.1.1"
		hopRegex = regexp.MustCompile(`^\s*(\d+)\s+.*?\s+([\d\.]+)\s*$`)
	} else {
		// Unix traceroute format: " 1  192.168.1.1 (192.168.1.1)  0.123 ms"
		hopRegex = regexp.MustCompile(`^\s*(\d+)\s+(?:(\S+)\s+)?\(?([\d\.]+)\)?`)
	}

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		matches := hopRegex.FindStringSubmatch(line)
		if len(matches) >= 3 {
			hopNum := 0
			fmt.Sscanf(matches[1], "%d", &hopNum)

			var ip, hostname string
			if osType == "windows" {
				ip = matches[2]
				hostname = ""
			} else {
				if len(matches) >= 4 {
					hostname = matches[2]
					ip = matches[3]
				} else {
					ip = matches[2]
				}
			}

			// Skip asterisks and timeouts
			if ip == "*" || ip == "" {
				continue
			}

			// Extract RTT if present
			rttRegex := regexp.MustCompile(`([\d\.]+)\s*ms`)
			rttMatches := rttRegex.FindStringSubmatch(line)
			rtt := ""
			if len(rttMatches) >= 2 {
				rtt = rttMatches[1] + "ms"
			}

			hops = append(hops, TracerouteHop{
				HopNumber: hopNum,
				IP:        ip,
				Hostname:  hostname,
				RTT:       rtt,
			})
		}
	}

	return hops, nil
}

// collectTracerouteTargets identifies top destination IPs to trace
func collectTracerouteTargets(pathStats *PathStats, report *TriageReport, maxTargets int) []string {
	pathStats.mu.Lock()
	defer pathStats.mu.Unlock()

	// Prioritize destinations with anomalies
	priorityTargets := make(map[string]int) // IP -> priority score

	// High priority: destinations with anomalies
	for _, path := range pathStats.Paths {
		if path.HasAnomaly {
			priorityTargets[path.DstIP] = 100
		}
	}

	// Medium priority: destinations in DNS anomalies
	for _, dns := range report.DNSAnomalies {
		if _, exists := priorityTargets[dns.AnswerIP]; !exists {
			priorityTargets[dns.AnswerIP] = 50
		}
	}

	// Add high-traffic destinations
	type pathScore struct {
		ip    string
		score int
	}
	var scored []pathScore
	for _, path := range pathStats.Paths {
		score := priorityTargets[path.DstIP]
		if score == 0 {
			// Score based on packet count for non-anomalous paths
			score = path.PacketCount / 100
		}
		scored = append(scored, pathScore{path.DstIP, score})
	}

	// Sort by score descending
	for i := 0; i < len(scored); i++ {
		for j := i + 1; j < len(scored); j++ {
			if scored[j].score > scored[i].score {
				scored[i], scored[j] = scored[j], scored[i]
			}
		}
	}

	// Collect unique targets up to maxTargets
	seen := make(map[string]bool)
	var targets []string
	for _, ps := range scored {
		if !seen[ps.ip] && !isPrivateOrReservedIP(ps.ip) {
			targets = append(targets, ps.ip)
			seen[ps.ip] = true
			if len(targets) >= maxTargets {
				break
			}
		}
	}

	return targets
}

// sanitizeMermaidID converts IP addresses to valid Mermaid node IDs
func sanitizeMermaidID(ip string) string {
	return strings.ReplaceAll(ip, ".", "_")
}

// generateMermaidDiagram creates a Mermaid.js diagram definition from collected paths
func generateMermaidDiagram(pathStats *PathStats, filter *Filter) string {
	pathStats.mu.Lock()
	defer pathStats.mu.Unlock()

	if len(pathStats.Paths) == 0 {
		return ""
	}

	// Sort paths by packet count to show most significant flows
	type pathEntry struct {
		key  string
		path *Path
	}
	var sortedPaths []pathEntry
	for key, path := range pathStats.Paths {
		sortedPaths = append(sortedPaths, pathEntry{key, path})
	}

	// Sort by packet count descending
	for i := 0; i < len(sortedPaths); i++ {
		for j := i + 1; j < len(sortedPaths); j++ {
			if sortedPaths[j].path.PacketCount > sortedPaths[i].path.PacketCount {
				sortedPaths[i], sortedPaths[j] = sortedPaths[j], sortedPaths[i]
			}
		}
	}

	// Limit to top 15 paths for readability
	maxPaths := 15
	if len(sortedPaths) > maxPaths {
		sortedPaths = sortedPaths[:maxPaths]
	}

	mermaid := "graph LR\n"

	// Add nodes and edges
	for _, entry := range sortedPaths {
		path := entry.path
		srcID := sanitizeMermaidID(path.SrcIP)
		dstID := sanitizeMermaidID(path.DstIP)

		// Build protocol/port label
		protocols := []string{}
		for proto := range path.Protocols {
			protocols = append(protocols, proto)
		}
		protocolStr := strings.Join(protocols, "/")

		// Get primary port (most common)
		var primaryPort uint16
		for port := range path.Ports {
			primaryPort = port
			break
		}

		// Format bytes
		var sizeStr string
		if path.ByteCount > 1024*1024 {
			sizeStr = fmt.Sprintf("%.1fMB", float64(path.ByteCount)/(1024*1024))
		} else if path.ByteCount > 1024 {
			sizeStr = fmt.Sprintf("%.1fKB", float64(path.ByteCount)/1024)
		} else {
			sizeStr = fmt.Sprintf("%dB", path.ByteCount)
		}

		label := fmt.Sprintf("%s:%d %s", protocolStr, primaryPort, sizeStr)

		// Add edge with label
		if path.HasAnomaly {
			mermaid += fmt.Sprintf("    %s[\"%s\"] -.->|\"%s\"| %s[\"%s\"]\n", srcID, path.SrcIP, label, dstID, path.DstIP)
		} else {
			mermaid += fmt.Sprintf("    %s[\"%s\"] -->|\"%s\"| %s[\"%s\"]\n", srcID, path.SrcIP, label, dstID, path.DstIP)
		}
	}

	// Add styling for anomaly nodes
	mermaid += "\n"
	for _, entry := range sortedPaths {
		path := entry.path
		if path.HasAnomaly {
			srcID := sanitizeMermaidID(path.SrcIP)
			dstID := sanitizeMermaidID(path.DstIP)
			mermaid += fmt.Sprintf("    style %s fill:#ffcccc,stroke:#ff0000,stroke-width:3px\n", srcID)
			mermaid += fmt.Sprintf("    style %s fill:#ffcccc,stroke:#ff0000,stroke-width:3px\n", dstID)
		}
	}

	return mermaid
}

// categorizeIP determines if an IP is internal, external, or a potential gateway
func categorizeIP(ip string) string {
	if isPrivateOrReservedIP(ip) {
		// Check if it's a common gateway IP
		if strings.HasSuffix(ip, ".1") || strings.HasSuffix(ip, ".254") {
			return "router"
		}
		return "internal"
	}
	return "external"
}

// generateVisJSData creates vis.js compatible nodes and edges data from paths
func generateVisJSData(pathStats *PathStats, filter *Filter, traceData *TracerouteData) (string, string) {
	pathStats.mu.Lock()
	defer pathStats.mu.Unlock()

	if len(pathStats.Paths) == 0 {
		return "[]", "[]"
	}

	// Collect unique nodes
	nodeMap := make(map[string]bool)
	nodeAnomalies := make(map[string]bool)
	hopNodes := make(map[string]bool) // Track traceroute hop nodes

	// Sort paths by packet count
	type pathEntry struct {
		key  string
		path *Path
	}
	var sortedPaths []pathEntry
	for key, path := range pathStats.Paths {
		sortedPaths = append(sortedPaths, pathEntry{key, path})
		nodeMap[path.SrcIP] = true
		nodeMap[path.DstIP] = true
		if path.HasAnomaly {
			nodeAnomalies[path.SrcIP] = true
			nodeAnomalies[path.DstIP] = true
		}
	}

	// Sort by packet count
	for i := 0; i < len(sortedPaths); i++ {
		for j := i + 1; j < len(sortedPaths); j++ {
			if sortedPaths[j].path.PacketCount > sortedPaths[i].path.PacketCount {
				sortedPaths[i], sortedPaths[j] = sortedPaths[j], sortedPaths[i]
			}
		}
	}

	// Limit to top 20 paths for interactive diagram
	maxPaths := 20
	if len(sortedPaths) > maxPaths {
		sortedPaths = sortedPaths[:maxPaths]
	}

	// Generate nodes JSON
	nodesJSON := "[\n"
	first := true
	for ip := range nodeMap {
		if !first {
			nodesJSON += ",\n"
		}
		first = false

		category := categorizeIP(ip)
		label := ip
		group := category

		// Customize label based on category
		if category == "router" {
			label = fmt.Sprintf("Gateway\\n%s", ip)
		} else if category == "internal" {
			label = fmt.Sprintf("Internal\\n%s", ip)
		} else {
			label = fmt.Sprintf("External\\n%s", ip)
		}

		color := ""
		if nodeAnomalies[ip] {
			color = `"color": {"background": "#ffcccc", "border": "#ff0000", "highlight": {"background": "#ff9999", "border": "#cc0000"}},`
		}

		nodesJSON += fmt.Sprintf(`        {"id": "%s", "label": "%s", "group": "%s", %s "title": "IP: %s"}`,
			ip, label, group, color, ip)
	}
	nodesJSON += "\n    ]"

	// Generate edges JSON
	edgesJSON := "[\n"
	first = true
	for _, entry := range sortedPaths {
		path := entry.path
		if !first {
			edgesJSON += ",\n"
		}
		first = false

		// Build protocol/port label
		protocols := []string{}
		for proto := range path.Protocols {
			protocols = append(protocols, proto)
		}
		protocolStr := strings.Join(protocols, "/")

		// Get primary port
		var primaryPort uint16
		for port := range path.Ports {
			primaryPort = port
			break
		}

		// Format bytes
		var sizeStr string
		if path.ByteCount > 1024*1024 {
			sizeStr = fmt.Sprintf("%.1fMB", float64(path.ByteCount)/(1024*1024))
		} else if path.ByteCount > 1024 {
			sizeStr = fmt.Sprintf("%.1fKB", float64(path.ByteCount)/1024)
		} else {
			sizeStr = fmt.Sprintf("%dB", path.ByteCount)
		}

		label := fmt.Sprintf("%s:%d\\n%s", protocolStr, primaryPort, sizeStr)
		title := fmt.Sprintf("%s:%d - %d packets, %s transferred", protocolStr, primaryPort, path.PacketCount, sizeStr)

		edgeColor := ""
		dashes := "false"
		if path.HasAnomaly {
			edgeColor = `"color": {"color": "#ff0000", "highlight": "#cc0000"},`
			dashes = "true"
			title += " - ISSUES DETECTED"
		}

		edgesJSON += fmt.Sprintf(`        {"from": "%s", "to": "%s", "label": "%s", "title": "%s", %s "dashes": %s, "arrows": "to"}`,
			path.SrcIP, path.DstIP, label, title, edgeColor, dashes)
	}

	// Add traceroute hop nodes and edges if available
	if traceData != nil && len(traceData.Paths) > 0 {
		traceData.mu.Lock()
		for destIP, hops := range traceData.Paths {
			// Add hop nodes
			for _, hop := range hops {
				if !nodeMap[hop.IP] && !hopNodes[hop.IP] {
					hopNodes[hop.IP] = true
					nodesJSON = strings.TrimSuffix(nodesJSON, "\n    ]")
					hopLabel := fmt.Sprintf("Hop %d\\n%s", hop.HopNumber, hop.IP)
					if hop.Hostname != "" {
						hopLabel = fmt.Sprintf("Hop %d\\n%s\\n(%s)", hop.HopNumber, hop.Hostname, hop.IP)
					}
					hopTitle := fmt.Sprintf("Traceroute Hop %d: %s", hop.HopNumber, hop.IP)
					if hop.RTT != "" {
						hopTitle += fmt.Sprintf(" - RTT: %s", hop.RTT)
					}
					nodesJSON += fmt.Sprintf(`,
        {"id": "%s", "label": "%s", "group": "tracehop", "shape": "triangle", "title": "%s"}`,
						hop.IP, hopLabel, hopTitle)
				}
			}

			// Add edge chain through hops
			if len(hops) > 0 {
				edgesJSON = strings.TrimSuffix(edgesJSON, "\n    ]")

				// Find source IP from paths
				var srcIP string
				for _, path := range pathStats.Paths {
					if path.DstIP == destIP {
						srcIP = path.SrcIP
						break
					}
				}

				// Create edge chain: Src -> Hop1 -> Hop2 -> ... -> Dest
				prevIP := srcIP
				for i, hop := range hops {
					if prevIP != "" {
						hopLabel := fmt.Sprintf("Hop %d", hop.HopNumber)
						if hop.RTT != "" {
							hopLabel += fmt.Sprintf("\\n%s", hop.RTT)
						}
						edgesJSON += fmt.Sprintf(`,
        {"from": "%s", "to": "%s", "label": "%s", "title": "Traceroute path", "color": {"color": "#9C27B0"}, "width": 1, "arrows": "to"}`,
							prevIP, hop.IP, hopLabel)
					}
					prevIP = hop.IP

					// Last hop connects to destination
					if i == len(hops)-1 && prevIP != destIP {
						edgesJSON += fmt.Sprintf(`,
        {"from": "%s", "to": "%s", "label": "Final", "title": "Traceroute path", "color": {"color": "#9C27B0"}, "width": 1, "arrows": "to"}`,
							prevIP, destIP)
					}
				}
			}
		}
		traceData.mu.Unlock()

		// Close the arrays
		nodesJSON += "\n    ]"
	}

	edgesJSON += "\n    ]"

	return nodesJSON, edgesJSON
}

// === Main ===
func main() {
	// Define custom usage function
	flag.Usage = func() {
		fmt.Fprintf(os.Stdout, `SD-WAN Network Triage: Analyze PCAP files for network issues, security threats, and traffic patterns.

USAGE:
    sdwan-triage [options] <capture.pcap>

OPTIONS:
  Filtering Options:
    -src-ip <IP>              Analyze traffic only from this source IP address
    -dst-ip <IP>              Analyze traffic only to this destination IP address
    -service <port_or_name>   Analyze traffic for this service (e.g., 'https', 'ssh', '80', '443')
    -protocol <tcp|udp>       Analyze traffic using this protocol (tcp or udp)

  Export Options:
    -json                     Output results in JSON format to stdout
    -csv <filename>           Export results to a CSV file (default: output.csv)
    -html <filename>          Export results to an HTML report file (default: output.html)

  Network Path Discovery:
    -trace-path               Perform traceroute to discovered destinations (requires network access)
                              Discovers actual network paths and visualizes intermediate hops
                              Limited to top 5 destinations prioritized by anomalies

  Advanced Analysis:
    -bgp-check                Check BGP routing data for potential hijack indicators (requires internet)
    -qos-analysis             Enable QoS/DSCP traffic class analysis
    -app-identify             Enable deep application identification using heuristics

  External Integration:
    -syslog-server <addr:port> Send alerts to Syslog server (address:port)
    -splunk-hec-url <url>     Splunk HTTP Event Collector URL
    -splunk-token <token>     Splunk HEC authentication token

  Multi-File Comparison:
    -compare                  Compare multiple PCAP files (provide multiple files as arguments)

  Debug Options:
    -debug-html               Write raw HTML to debug_report.html for troubleshooting

  Help:
    -h, --help                Show this help message

EXAMPLES:
    # Full analysis with interactive terminal output
    ./sdwan-triage TestFile.pcap

    # Filter by source IP address
    ./sdwan-triage -src-ip 192.168.100.203 TestFile.pcap

    # Filter by service name
    ./sdwan-triage -service https TestFile.pcap

    # Filter by protocol and port number
    ./sdwan-triage -protocol tcp -service 443 TestFile.pcap

    # Combine filters for precise analysis
    ./sdwan-triage -src-ip 192.168.100.203 -protocol tcp -service ssh TestFile.pcap

    # Export to HTML with custom filename
    ./sdwan-triage -html network-report.html TestFile.pcap

    # Filter and export to CSV
    ./sdwan-triage -csv ssh-traffic.csv -service ssh TestFile.pcap

    # Export to JSON for programmatic processing
    ./sdwan-triage -json TestFile.pcap > results.json

    # Discover network paths with traceroute (requires network access)
    ./sdwan-triage -html report.html -trace-path TestFile.pcap

    # Combine traceroute with filters
    ./sdwan-triage -html https-paths.html -service https -trace-path TestFile.pcap

    # Check BGP routing for potential hijacks
    ./sdwan-triage -bgp-check TestFile.pcap

    # Enable QoS/DSCP analysis
    ./sdwan-triage -qos-analysis TestFile.pcap

    # Deep application identification
    ./sdwan-triage -app-identify TestFile.pcap

    # Send alerts to Syslog server
    ./sdwan-triage -syslog-server 192.168.1.100:514 TestFile.pcap

    # Send events to Splunk
    ./sdwan-triage -splunk-hec-url https://splunk:8088/services/collector -splunk-token abc123 TestFile.pcap

    # Compare two PCAP files
    ./sdwan-triage -compare before.pcap after.pcap

DESCRIPTION:
    This tool performs comprehensive network analysis on PCAP capture files to identify:
    - Security threats (DNS poisoning, ARP spoofing, suspicious ports)
    - Performance issues (TCP retransmissions, high latency, failed connections)
    - Traffic patterns (bandwidth hogs, application breakdown, device fingerprinting)
    - Network paths (traceroute to destinations showing intermediate hops)

    The analysis includes detailed explanations and actionable recommendations for
    network engineers and IT administrators.

    Interactive HTML reports include:
    - D3.js force-directed network graphs with advanced interactivity
    - D3.js timeline visualization for network events
    - D3.js Sankey/Chord diagrams for traffic flow analysis
    - Card-based layout with actionable recommendations
    - Traceroute path visualization with intermediate hop discovery (optional)
    - Color-coded nodes and rich tooltips for detailed information
    - Plain-language explanations suitable for non-technical stakeholders

    Advanced features:
    - BGP routing analysis for hijack detection
    - QoS/DSCP traffic class analysis
    - Deep application identification (port, SNI, payload heuristics)
    - External integration (Syslog, Splunk HEC)
    - Multi-PCAP comparison for before/after analysis

VERSION:
    SD-WAN Triage v2.6.0

`)
	}

	var jsonOutput = flag.Bool("json", false, "Output in JSON format")
	var csvOutput = flag.String("csv", "", "Export findings to CSV file")
	var htmlOutput = flag.String("html", "", "Export findings to HTML report")
	var multiPageHTML = flag.String("multi-page-html", "", "Export findings to multi-page HTML report (specify output directory)")
	var debugHTML = flag.Bool("debug-html", false, "Write raw HTML to debug_report.html for troubleshooting diagram issues")
	var srcIP = flag.String("src-ip", "", "Filter by source IP address")
	var dstIP = flag.String("dst-ip", "", "Filter by destination IP address")
	var service = flag.String("service", "", "Filter by service port or name")
	var protocol = flag.String("protocol", "", "Filter by protocol (tcp or udp)")
	var tracePath = flag.Bool("trace-path", false, "Perform traceroute to discovered destinations (requires network access)")
	var bgpCheck = flag.Bool("bgp-check", false, "Check BGP routing data for potential hijack indicators (requires internet)")
	var qosAnalysis = flag.Bool("qos-analysis", false, "Enable QoS/DSCP traffic class analysis")
	var appIdentify = flag.Bool("app-identify", false, "Enable deep application identification using heuristics")
	var syslogServer = flag.String("syslog-server", "", "Send alerts to Syslog server (address:port)")
	var splunkHECURL = flag.String("splunk-hec-url", "", "Splunk HTTP Event Collector URL")
	var splunkToken = flag.String("splunk-token", "", "Splunk HEC authentication token")
	var compareMode = flag.Bool("compare", false, "Compare multiple PCAP files (provide multiple files as arguments)")
	var showHelp = flag.Bool("help", false, "Show help message")
	flag.Parse()

	// Show help if requested or no arguments provided
	if *showHelp || flag.NArg() < 1 {
		flag.Usage()
		if *showHelp {
			os.Exit(0)
		}
		os.Exit(1)
	}

	// Create filter from command-line arguments
	filter := &Filter{
		srcIP:    *srcIP,
		dstIP:    *dstIP,
		service:  *service,
		protocol: *protocol,
	}

	// Handle compare mode with multiple PCAP files
	if *compareMode {
		if flag.NArg() < 2 {
			fmt.Fprintf(os.Stderr, "Error: -compare mode requires at least 2 PCAP files\n")
			os.Exit(1)
		}
		pcapFiles := flag.Args()
		compareReports(pcapFiles, filter, *jsonOutput, *htmlOutput, *csvOutput)
		return
	}

	pcapFile := flag.Arg(0)
	report := &TriageReport{}

	file, err := os.Open(pcapFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error opening pcap: %v\n", err)
		os.Exit(1)
	}
	defer file.Close()

	reader, err := pcapgo.NewReader(file)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading pcap: %v\n", err)
		os.Exit(1)
	}

	// State tracking
	synSent := make(map[string]gopacket.Packet)
	synAckReceived := make(map[string]bool)
	arpIPToMAC := make(map[string]string)
	dnsQueries := make(map[uint16]string)
	tcpFlows := make(map[string]*tcpFlowState)
	udpFlows := make(map[string]*udpFlowState)
	httpRequests := make(map[string]*httpRequest)
	tlsSNICache := make(map[string]string)
	deviceFingerprints := make(map[string]*tcpFingerprint)
	appStats := make(map[string]*AppCategory)
	pathStats := &PathStats{Paths: make(map[string]*Path)}
	conversations := make(map[string]*TrafficFlowSummary)
	timeBuckets := make(map[int64]*TimeBucket)
	var timelineEvents []TimelineEvent
	dnsQueryTracker := make(map[uint16]*dnsQueryInfo)
	var dnsRecords []DNSRecord
	var captureStartTime time.Time
	captureStartSet := false
	var mu sync.Mutex

	// Initialize ApplicationBreakdown map
	report.ApplicationBreakdown = make(map[string]AppCategory)

	// Track seen HTTP/2 and TLS flows to avoid duplicates
	http2FlowsSeen := make(map[string]bool)
	tlsFlowsSeen := make(map[string]bool)

	packetSource := gopacket.NewPacketSource(reader, reader.LinkType())
	for packet := range packetSource.Packets() {
		// Set capture start time from first packet
		if !captureStartSet {
			captureStartTime = packet.Metadata().Timestamp
			captureStartSet = true
		}
		analyzePacket(packet, synSent, synAckReceived, arpIPToMAC, dnsQueries, tcpFlows, udpFlows, httpRequests, tlsSNICache, deviceFingerprints, appStats, report, &mu, filter, pathStats, conversations, timeBuckets, &timelineEvents, dnsQueryTracker, &dnsRecords, captureStartTime, http2FlowsSeen, tlsFlowsSeen)
	}

	// Finalize failed handshakes
	for key, pkt := range synSent {
		if !synAckReceived[key] {
			netLayer := pkt.NetworkLayer()
			transport := pkt.TransportLayer()
			if netLayer == nil || transport == nil {
				continue
			}
			if ip4, ok := netLayer.(*layers.IPv4); ok {
				if tcp, ok := transport.(*layers.TCP); ok {
					report.FailedHandshakes = append(report.FailedHandshakes, TCPFlow{
						SrcIP: ip4.SrcIP.String(), SrcPort: uint16(tcp.SrcPort),
						DstIP: ip4.DstIP.String(), DstPort: uint16(tcp.DstPort),
					})
				}
			}
		}
	}

	// Finalize failed handshake attempts for TCP Handshake Analysis
	// Identify SYN flows that never received a SYN-ACK response
	for _, synFlow := range report.TCPHandshakes.SYNFlows {
		// Check if this SYN flow has a corresponding successful handshake
		hasSuccess := false
		for _, successFlow := range report.TCPHandshakes.SuccessfulHandshakes {
			if synFlow.SrcIP == successFlow.SrcIP &&
				synFlow.SrcPort == successFlow.SrcPort &&
				synFlow.DstIP == successFlow.DstIP &&
				synFlow.DstPort == successFlow.DstPort {
				hasSuccess = true
				break
			}
		}

		// If no successful handshake found, mark as failed attempt
		if !hasSuccess {
			report.TCPHandshakes.FailedHandshakeAttempts = append(report.TCPHandshakes.FailedHandshakeAttempts, synFlow)
		}
	}

	// Build correlated TCP handshake flows for visualization
	correlatedFlows := make(map[string]*TCPHandshakeCorrelatedFlow)

	// Add SYN events
	for _, synFlow := range report.TCPHandshakes.SYNFlows {
		flowID := fmt.Sprintf("%s:%d->%s:%d", synFlow.SrcIP, synFlow.SrcPort, synFlow.DstIP, synFlow.DstPort)
		if _, exists := correlatedFlows[flowID]; !exists {
			correlatedFlows[flowID] = &TCPHandshakeCorrelatedFlow{
				FlowID:  flowID,
				SrcIP:   synFlow.SrcIP,
				SrcPort: synFlow.SrcPort,
				DstIP:   synFlow.DstIP,
				DstPort: synFlow.DstPort,
				Events:  []TCPHandshakeEvent{},
				Status:  "Pending",
			}
		}
		correlatedFlows[flowID].Events = append(correlatedFlows[flowID].Events, TCPHandshakeEvent{
			Type:      "SYN",
			Timestamp: synFlow.Timestamp,
		})
	}

	// Add SYN-ACK events (note: SYN-ACK comes from the opposite direction)
	for _, synAckFlow := range report.TCPHandshakes.SYNACKFlows {
		// SYN-ACK is sent from DstIP:DstPort back to SrcIP:SrcPort
		// So we need to find the original flow in the opposite direction
		flowID := fmt.Sprintf("%s:%d->%s:%d", synAckFlow.DstIP, synAckFlow.DstPort, synAckFlow.SrcIP, synAckFlow.SrcPort)
		if flow, exists := correlatedFlows[flowID]; exists {
			flow.Events = append(flow.Events, TCPHandshakeEvent{
				Type:      "SYN-ACK",
				Timestamp: synAckFlow.Timestamp,
			})
		}
	}

	// Add Handshake Complete events and set status
	for _, successFlow := range report.TCPHandshakes.SuccessfulHandshakes {
		flowID := fmt.Sprintf("%s:%d->%s:%d", successFlow.SrcIP, successFlow.SrcPort, successFlow.DstIP, successFlow.DstPort)
		if flow, exists := correlatedFlows[flowID]; exists {
			flow.Events = append(flow.Events, TCPHandshakeEvent{
				Type:      "Handshake Complete",
				Timestamp: successFlow.Timestamp,
			})
			flow.Status = "Complete"
		}
	}

	// Mark failed flows
	for _, failedFlow := range report.TCPHandshakes.FailedHandshakeAttempts {
		flowID := fmt.Sprintf("%s:%d->%s:%d", failedFlow.SrcIP, failedFlow.SrcPort, failedFlow.DstIP, failedFlow.DstPort)
		if flow, exists := correlatedFlows[flowID]; exists {
			if flow.Status != "Complete" {
				flow.Status = "Failed"
			}
		}
	}

	// Convert map to slice and sort events by timestamp within each flow
	for _, flow := range correlatedFlows {
		// Sort events by timestamp
		for i := 0; i < len(flow.Events); i++ {
			for j := i + 1; j < len(flow.Events); j++ {
				if flow.Events[j].Timestamp < flow.Events[i].Timestamp {
					flow.Events[i], flow.Events[j] = flow.Events[j], flow.Events[i]
				}
			}
		}
		report.TCPHandshakeCorrelatedFlows = append(report.TCPHandshakeCorrelatedFlows, *flow)
	}

	// Sort correlated flows by first event timestamp
	for i := 0; i < len(report.TCPHandshakeCorrelatedFlows); i++ {
		for j := i + 1; j < len(report.TCPHandshakeCorrelatedFlows); j++ {
			if len(report.TCPHandshakeCorrelatedFlows[j].Events) > 0 &&
				len(report.TCPHandshakeCorrelatedFlows[i].Events) > 0 &&
				report.TCPHandshakeCorrelatedFlows[j].Events[0].Timestamp < report.TCPHandshakeCorrelatedFlows[i].Events[0].Timestamp {
				report.TCPHandshakeCorrelatedFlows[i], report.TCPHandshakeCorrelatedFlows[j] = report.TCPHandshakeCorrelatedFlows[j], report.TCPHandshakeCorrelatedFlows[i]
			}
		}
	}

	// Finalize bandwidth report - calculate rates and sort conversations
	var allConversations []TrafficFlowSummary
	for _, conv := range conversations {
		// Calculate duration and average bitrate
		conv.Duration = conv.LastSeen.Sub(conv.FirstSeen)
		if conv.Duration > 0 {
			durationSeconds := conv.Duration.Seconds()
			conv.AvgBitsPerSecond = (float64(conv.TotalBytes) * 8) / durationSeconds
		}
		allConversations = append(allConversations, *conv)
	}

	// Sort by bytes (descending) for top conversations by bytes
	conversationsByBytes := make([]TrafficFlowSummary, len(allConversations))
	copy(conversationsByBytes, allConversations)
	for i := 0; i < len(conversationsByBytes); i++ {
		for j := i + 1; j < len(conversationsByBytes); j++ {
			if conversationsByBytes[j].TotalBytes > conversationsByBytes[i].TotalBytes {
				conversationsByBytes[i], conversationsByBytes[j] = conversationsByBytes[j], conversationsByBytes[i]
			}
		}
	}

	// Sort by packets (descending) for top conversations by packets
	conversationsByPackets := make([]TrafficFlowSummary, len(allConversations))
	copy(conversationsByPackets, allConversations)
	for i := 0; i < len(conversationsByPackets); i++ {
		for j := i + 1; j < len(conversationsByPackets); j++ {
			if conversationsByPackets[j].TotalPackets > conversationsByPackets[i].TotalPackets {
				conversationsByPackets[i], conversationsByPackets[j] = conversationsByPackets[j], conversationsByPackets[i]
			}
		}
	}

	// Select top 20 conversations by bytes
	topN := 20
	if len(conversationsByBytes) < topN {
		topN = len(conversationsByBytes)
	}
	report.BandwidthReport.TopConversationsByBytes = conversationsByBytes[:topN]

	// Select top 20 conversations by packets
	topN = 20
	if len(conversationsByPackets) < topN {
		topN = len(conversationsByPackets)
	}
	report.BandwidthReport.TopConversationsByPackets = conversationsByPackets[:topN]

	// Sort time buckets by timestamp for time series data
	var timeSeriesData []TimeBucket
	for _, bucket := range timeBuckets {
		timeSeriesData = append(timeSeriesData, *bucket)
	}
	for i := 0; i < len(timeSeriesData); i++ {
		for j := i + 1; j < len(timeSeriesData); j++ {
			if timeSeriesData[j].Timestamp.Before(timeSeriesData[i].Timestamp) {
				timeSeriesData[i], timeSeriesData[j] = timeSeriesData[j], timeSeriesData[i]
			}
		}
	}
	report.BandwidthReport.TimeSeriesData = timeSeriesData

	// Finalize timeline events - sort by timestamp
	for i := 0; i < len(timelineEvents); i++ {
		for j := i + 1; j < len(timelineEvents); j++ {
			if timelineEvents[j].Timestamp < timelineEvents[i].Timestamp {
				timelineEvents[i], timelineEvents[j] = timelineEvents[j], timelineEvents[i]
			}
		}
	}
	report.Timeline = timelineEvents

	// Finalize DNS records - sort by query timestamp
	for i := 0; i < len(dnsRecords); i++ {
		for j := i + 1; j < len(dnsRecords); j++ {
			if dnsRecords[j].QueryTimestamp < dnsRecords[i].QueryTimestamp {
				dnsRecords[i], dnsRecords[j] = dnsRecords[j], dnsRecords[i]
			}
		}
	}
	report.DNSDetails = dnsRecords

	// Finalize traffic analysis - find top bandwidth consumers
	type flowBytes struct {
		key   string
		bytes uint64
	}
	var allFlows []flowBytes

	for key, flow := range tcpFlows {
		allFlows = append(allFlows, flowBytes{key: key, bytes: flow.totalBytes})
	}
	for key, flow := range udpFlows {
		allFlows = append(allFlows, flowBytes{key: key, bytes: flow.totalBytes})
	}

	// Sort by bytes descending
	for i := 0; i < len(allFlows); i++ {
		for j := i + 1; j < len(allFlows); j++ {
			if allFlows[j].bytes > allFlows[i].bytes {
				allFlows[i], allFlows[j] = allFlows[j], allFlows[i]
			}
		}
	}

	// Top 10 flows or flows > 10% of total traffic
	threshold := float64(report.TotalBytes) * 0.10
	for i := 0; i < len(allFlows) && i < 10; i++ {
		flow := allFlows[i]
		percentage := float64(flow.bytes) / float64(report.TotalBytes) * 100

		if flow.bytes > uint64(threshold) || i < 5 {
			parts := strings.Split(flow.key, "->")
			if len(parts) == 2 {
				srcParts := strings.Split(parts[0], ":")
				dstParts := strings.Split(parts[1], ":")
				if len(srcParts) == 2 && len(dstParts) == 2 {
					protocol := "TCP"
					if _, ok := udpFlows[flow.key]; ok {
						protocol = "UDP"
					}

					var srcPortVal, dstPortVal uint16
					fmt.Sscanf(srcParts[1], "%d", &srcPortVal)
					fmt.Sscanf(dstParts[1], "%d", &dstPortVal)

					report.TrafficAnalysis = append(report.TrafficAnalysis, TrafficFlow{
						SrcIP:      srcParts[0],
						SrcPort:    srcPortVal,
						DstIP:      dstParts[0],
						DstPort:    dstPortVal,
						Protocol:   protocol,
						TotalBytes: flow.bytes,
						Percentage: percentage,
					})
				}
			}
		}
	}

	// Finalize RTT analysis - flows with high average RTT
	for key, flow := range tcpFlows {
		if len(flow.rttSamples) > 0 {
			var sum, min, max float64
			min = flow.rttSamples[0]
			max = flow.rttSamples[0]

			for _, rtt := range flow.rttSamples {
				sum += rtt
				if rtt < min {
					min = rtt
				}
				if rtt > max {
					max = rtt
				}
			}

			avg := sum / float64(len(flow.rttSamples))

			// Report flows with avg RTT > 100ms
			if avg > 100 {
				parts := strings.Split(key, "->")
				if len(parts) == 2 {
					srcParts := strings.Split(parts[0], ":")
					dstParts := strings.Split(parts[1], ":")
					if len(srcParts) == 2 && len(dstParts) == 2 {
						var srcPortVal, dstPortVal uint16
						fmt.Sscanf(srcParts[1], "%d", &srcPortVal)
						fmt.Sscanf(dstParts[1], "%d", &dstPortVal)

						report.RTTAnalysis = append(report.RTTAnalysis, RTTFlow{
							SrcIP:      srcParts[0],
							SrcPort:    srcPortVal,
							DstIP:      dstParts[0],
							DstPort:    dstPortVal,
							MinRTT:     min,
							MaxRTT:     max,
							AvgRTT:     avg,
							SampleSize: len(flow.rttSamples),
						})
						// Mark path with anomaly for diagram highlighting
						markPathAnomaly(pathStats, srcParts[0], dstParts[0])
					}
				}
			}
		}
	}

	// Finalize device fingerprinting
	for ip, fp := range deviceFingerprints {
		deviceType, osGuess, confidence := guessOSFromFingerprint(fp)
		details := fmt.Sprintf("TTL=%d, Win=%d, MSS=%d, TS=%v, SACK=%v",
			fp.ttl, fp.windowSize, fp.mss, fp.hasTS, fp.hasSACK)

		report.DeviceFingerprinting = append(report.DeviceFingerprinting, DeviceFingerprint{
			SrcIP:      ip,
			DeviceType: deviceType,
			OSGuess:    osGuess,
			Confidence: confidence,
			Details:    details,
		})
	}

	// Finalize application breakdown
	for _, app := range appStats {
		report.ApplicationBreakdown[app.Name] = *app
	}

	// Perform traceroute if requested
	traceData := &TracerouteData{Paths: make(map[string][]TracerouteHop)}
	if *tracePath {
		color.Yellow("⚡ Performing traceroute to discovered destinations...")
		targets := collectTracerouteTargets(pathStats, report, 5) // Limit to top 5 targets

		for i, target := range targets {
			fmt.Printf("   [%d/%d] Tracing route to %s...\n", i+1, len(targets), target)
			hops, err := executeTraceroute(target)
			if err != nil {
				fmt.Printf("   ⚠ Warning: traceroute to %s failed: %v\n", target, err)
				continue
			}
			if len(hops) > 0 {
				traceData.mu.Lock()
				traceData.Paths[target] = hops
				traceData.mu.Unlock()
				fmt.Printf("   ✓ Discovered %d hops to %s\n", len(hops), target)
			}
		}
		fmt.Println()
	}

	// Perform BGP analysis if enabled
	if *bgpCheck {
		performBGPAnalysis(report)
	}

	// Send alerts to external systems if configured
	if *syslogServer != "" {
		if err := sendToSyslog(*syslogServer, report); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: Failed to send to Syslog: %v\n", err)
		}
	}

	if *splunkHECURL != "" && *splunkToken != "" {
		if err := sendToSplunk(*splunkHECURL, *splunkToken, report); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: Failed to send to Splunk: %v\n", err)
		}
	}

	// Suppress unused variable warnings for features that need packet-level integration
	_ = qosAnalysis
	_ = appIdentify

	// Handle output formats
	if *jsonOutput {
		data, _ := json.MarshalIndent(report, "", "  ")
		fmt.Println(string(data))
	} else if *csvOutput != "" {
		filename := *csvOutput
		if filename == "" {
			filename = "output.csv"
		}
		if err := exportToCSV(report, filename); err != nil {
			fmt.Fprintf(os.Stderr, "Error exporting to CSV: %v\n", err)
			os.Exit(1)
		}
		color.Green("✓ Findings exported to %s", filename)
	} else if *multiPageHTML != "" {
		outputDir := *multiPageHTML
		if outputDir == "" {
			outputDir = "sdwan_report"
		}
		// Generate multi-page HTML report
		// Note: Using the existing single-page HTML for now as multi-page requires models.TriageReport
		// TODO: Implement conversion from main.go TriageReport to models.TriageReport
		color.Yellow("⚠ Multi-page HTML generation requires refactoring - using single-page HTML instead")
		filename := filepath.Join(outputDir, "report.html")
		if err := os.MkdirAll(outputDir, 0755); err != nil {
			fmt.Fprintf(os.Stderr, "Error creating output directory: %v\n", err)
			os.Exit(1)
		}
		if err := exportToEnhancedHTML(report, filename, pathStats, filter, traceData); err != nil {
			fmt.Fprintf(os.Stderr, "Error generating HTML report: %v\n", err)
			os.Exit(1)
		}
		color.Green("✓ HTML report generated: %s", filename)
		color.Cyan("  Note: Multi-page structure will be available in a future update")
	} else if *htmlOutput != "" {
		filename := *htmlOutput
		if filename == "" {
			filename = "output.html"
		}
		// Use enhanced D3.js-powered HTML export
		if err := exportToEnhancedHTML(report, filename, pathStats, filter, traceData); err != nil {
			fmt.Fprintf(os.Stderr, "Error exporting to HTML: %v\n", err)
			os.Exit(1)
		}
		color.Green("✓ D3.js-enhanced report exported to %s", filename)

		// Debug HTML - write raw HTML to separate file for troubleshooting
		if *debugHTML {
			debugFilename := "debug_report.html"
			if err := exportToEnhancedHTML(report, debugFilename, pathStats, filter, traceData); err != nil {
				fmt.Fprintf(os.Stderr, "Error exporting debug HTML: %v\n", err)
			} else {
				color.Yellow("✓ Debug HTML written to %s (inspect browser console for JS errors)", debugFilename)
			}
		}
	} else {
		printExecutiveSummary(report)
		fmt.Println()
		printHuman(report)

		// Debug HTML - write raw HTML even without -html flag for troubleshooting
		if *debugHTML {
			debugFilename := "debug_report.html"
			if err := exportToEnhancedHTML(report, debugFilename, pathStats, filter, traceData); err != nil {
				fmt.Fprintf(os.Stderr, "Error exporting debug HTML: %v\n", err)
			} else {
				color.Yellow("✓ Debug HTML written to %s (inspect browser console for JS errors)", debugFilename)
			}
		}
	}
}

func analyzePacket(
	packet gopacket.Packet,
	synSent map[string]gopacket.Packet,
	synAckReceived map[string]bool,
	arpIPToMAC map[string]string,
	dnsQueries map[uint16]string,
	tcpFlows map[string]*tcpFlowState,
	udpFlows map[string]*udpFlowState,
	httpRequests map[string]*httpRequest,
	tlsSNICache map[string]string,
	deviceFingerprints map[string]*tcpFingerprint,
	appStats map[string]*AppCategory,
	report *TriageReport,
	mu *sync.Mutex,
	filter *Filter,
	pathStats *PathStats,
	conversations map[string]*TrafficFlowSummary,
	timeBuckets map[int64]*TimeBucket,
	timelineEvents *[]TimelineEvent,
	dnsQueryTracker map[uint16]*dnsQueryInfo,
	dnsRecords *[]DNSRecord,
	captureStartTime time.Time,
	http2FlowsSeen map[string]bool,
	tlsFlowsSeen map[string]bool,
) {
	// Apply filters if specified
	if !filter.isEmpty() {
		netLayer := packet.NetworkLayer()
		if netLayer == nil {
			return
		}

		var srcIP, dstIP string
		if ip4, ok := netLayer.(*layers.IPv4); ok {
			srcIP = ip4.SrcIP.String()
			dstIP = ip4.DstIP.String()
		} else {
			return
		}

		// Track path for diagram generation
		trackPath(pathStats, srcIP, dstIP, packet)

		// Check source IP filter
		if filter.srcIP != "" && srcIP != filter.srcIP {
			return
		}

		// Check destination IP filter
		if filter.dstIP != "" && dstIP != filter.dstIP {
			return
		}

		// Check protocol filter
		if filter.protocol != "" {
			transportLayer := packet.TransportLayer()
			if transportLayer == nil {
				return
			}

			protocol := strings.ToLower(filter.protocol)
			switch protocol {
			case "tcp":
				if _, ok := transportLayer.(*layers.TCP); !ok {
					return
				}
			case "udp":
				if _, ok := transportLayer.(*layers.UDP); !ok {
					return
				}
			default:
				return
			}
		}

		// Check service/port filter
		if filter.service != "" {
			transportLayer := packet.TransportLayer()
			if transportLayer == nil {
				return
			}

			// Resolve service name to port if needed
			targetPort, ok := resolveServiceToPort(filter.service)
			if !ok {
				return
			}

			// Check both source and destination ports
			matched := false
			if tcp, ok := transportLayer.(*layers.TCP); ok {
				if uint16(tcp.SrcPort) == targetPort || uint16(tcp.DstPort) == targetPort {
					matched = true
				}
			} else if udp, ok := transportLayer.(*layers.UDP); ok {
				if uint16(udp.SrcPort) == targetPort || uint16(udp.DstPort) == targetPort {
					matched = true
				}
			}

			if !matched {
				return
			}
		}
	}

	// Track all paths for diagram generation (after filters)
	netLayer := packet.NetworkLayer()
	if netLayer != nil {
		if ip4, ok := netLayer.(*layers.IPv4); ok {
			trackPath(pathStats, ip4.SrcIP.String(), ip4.DstIP.String(), packet)
		}
	}

	// Track conversations for bandwidth analysis
	if netLayer != nil {
		var flowKey string
		var protocol string
		var srcIP, dstIP string
		var srcPort, dstPort uint16

		if ip4, ok := netLayer.(*layers.IPv4); ok {
			srcIP = ip4.SrcIP.String()
			dstIP = ip4.DstIP.String()

			transportLayer := packet.TransportLayer()
			if transportLayer != nil {
				if tcp, ok := transportLayer.(*layers.TCP); ok {
					protocol = "TCP"
					srcPort = uint16(tcp.SrcPort)
					dstPort = uint16(tcp.DstPort)
					flowKey = fmt.Sprintf("%s:%d->%s:%d/TCP", srcIP, srcPort, dstIP, dstPort)
				} else if udp, ok := transportLayer.(*layers.UDP); ok {
					protocol = "UDP"
					srcPort = uint16(udp.SrcPort)
					dstPort = uint16(udp.DstPort)
					flowKey = fmt.Sprintf("%s:%d->%s:%d/UDP", srcIP, srcPort, dstIP, dstPort)
				}
			} else {
				protocol = "ICMP"
				flowKey = fmt.Sprintf("%s->%s/ICMP", srcIP, dstIP)
			}

			if flowKey != "" {
				timestamp := packet.Metadata().Timestamp
				packetSize := uint64(len(packet.Data()))

				mu.Lock()
				conv, exists := conversations[flowKey]
				if !exists {
					conv = &TrafficFlowSummary{
						SrcIP:        srcIP,
						SrcPort:      srcPort,
						DstIP:        dstIP,
						DstPort:      dstPort,
						Protocol:     protocol,
						TotalBytes:   0,
						TotalPackets: 0,
						FirstSeen:    timestamp,
						LastSeen:     timestamp,
					}
					conversations[flowKey] = conv
				}

				conv.TotalBytes += packetSize
				conv.TotalPackets++
				if timestamp.After(conv.LastSeen) {
					conv.LastSeen = timestamp
				}
				if timestamp.Before(conv.FirstSeen) {
					conv.FirstSeen = timestamp
				}

				// Track time series data (bucket by second)
				bucketTime := timestamp.Unix()
				bucket, bucketExists := timeBuckets[bucketTime]
				if !bucketExists {
					bucket = &TimeBucket{
						Timestamp:    time.Unix(bucketTime, 0),
						TotalBytes:   0,
						TotalPackets: 0,
					}
					timeBuckets[bucketTime] = bucket
				}
				bucket.TotalBytes += packetSize
				bucket.TotalPackets++

				mu.Unlock()
			}
		}
	}

	// DNS
	if dnsLayer := packet.Layer(layers.LayerTypeDNS); dnsLayer != nil {
		dns := dnsLayer.(*layers.DNS)
		netLayer := packet.NetworkLayer()
		linkLayer := packet.LinkLayer()
		if netLayer == nil || linkLayer == nil {
			return
		}

		var srcIP, dstIP string
		if ip4, ok := netLayer.(*layers.IPv4); ok {
			srcIP = ip4.SrcIP.String()
			dstIP = ip4.DstIP.String()
		} else {
			srcIP = netLayer.NetworkFlow().Src().String()
			dstIP = netLayer.NetworkFlow().Dst().String()
		}

		eth, _ := linkLayer.(*layers.Ethernet)
		mac := ""
		if eth != nil {
			mac = eth.SrcMAC.String()
		}

		relativeTime := packet.Metadata().Timestamp.Sub(captureStartTime).Seconds()
		dnsPort := uint16(53)

		if !dns.QR { // Query
			if len(dns.Questions) > 0 {
				queryName := string(dns.Questions[0].Name)
				queryType := dns.Questions[0].Type.String()

				mu.Lock()
				dnsQueries[dns.ID] = queryName

				// Track DNS query for later matching with response
				dnsQueryTracker[dns.ID] = &dnsQueryInfo{
					queryName:     queryName,
					queryType:     queryType,
					sourceIP:      srcIP,
					destinationIP: dstIP,
					timestamp:     packet.Metadata().Timestamp,
				}

				// Add timeline event for DNS query
				*timelineEvents = append(*timelineEvents, TimelineEvent{
					Timestamp:       relativeTime,
					EventType:       "DNS_Query",
					SourceIP:        srcIP,
					DestinationIP:   dstIP,
					SourcePort:      nil,
					DestinationPort: &dnsPort,
					Protocol:        "UDP",
					Detail:          fmt.Sprintf("Query: %s (%s)", queryName, queryType),
				})
				mu.Unlock()
			}
		} else { // Response
			mu.Lock()
			queryName := dnsQueries[dns.ID]
			queryInfo := dnsQueryTracker[dns.ID]

			// Collect answer IPs and names
			var answerIPs []string
			var answerNames []string
			isAnomalous := false
			anomalyReason := ""

			for _, ans := range dns.Answers {
				if ans.IP != nil {
					ansIP := ans.IP.String()
					answerIPs = append(answerIPs, ansIP)

					if isPublicDomain(queryName) && isPrivateOrReservedIP(ansIP) {
						isAnomalous = true
						anomalyReason = "Public domain resolved to private/reserved IP"
						report.DNSAnomalies = append(report.DNSAnomalies, DNSAnomaly{
							Timestamp: relativeTime,
							Query:     queryName,
							AnswerIP:  ansIP,
							ServerIP:  srcIP,
							ServerMAC: mac,
							Reason:    anomalyReason,
						})

						// Add timeline event for DNS anomaly
						*timelineEvents = append(*timelineEvents, TimelineEvent{
							Timestamp:       relativeTime,
							EventType:       "DNS_Anomaly",
							SourceIP:        srcIP,
							DestinationIP:   dstIP,
							SourcePort:      &dnsPort,
							DestinationPort: nil,
							Protocol:        "UDP",
							Detail:          fmt.Sprintf("%s -> %s (ANOMALY: %s)", queryName, ansIP, anomalyReason),
						})
					}
				}
				if ans.CNAME != nil {
					answerNames = append(answerNames, string(ans.CNAME))
				}
			}

			// Create DNS record with query/response pair
			responseTime := relativeTime
			responseCode := uint16(dns.ResponseCode)

			queryType := "A"
			queryTimestamp := relativeTime
			querySrcIP := dstIP // Response destination is query source
			queryDstIP := srcIP // Response source is query destination

			if queryInfo != nil {
				queryType = queryInfo.queryType
				queryTimestamp = queryInfo.timestamp.Sub(captureStartTime).Seconds()
				querySrcIP = queryInfo.sourceIP
				queryDstIP = queryInfo.destinationIP
			}

			detail := fmt.Sprintf("Query: %s (%s)", queryName, queryType)
			if len(answerIPs) > 0 {
				detail += fmt.Sprintf(" -> %s", strings.Join(answerIPs, ", "))
			}
			if isAnomalous {
				detail += " [ANOMALOUS]"
			}

			*dnsRecords = append(*dnsRecords, DNSRecord{
				QueryTimestamp:    queryTimestamp,
				QueryName:         queryName,
				QueryType:         queryType,
				SourceIP:          querySrcIP,
				DestinationIP:     queryDstIP,
				ResponseTimestamp: &responseTime,
				ResponseCode:      &responseCode,
				AnswerIPs:         answerIPs,
				AnswerNames:       answerNames,
				IsAnomalous:       isAnomalous,
				Detail:            detail,
			})

			// Clean up tracker
			delete(dnsQueryTracker, dns.ID)
			mu.Unlock()
		}
	}

	// TCP
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		netLayer := packet.NetworkLayer()
		if netLayer == nil {
			return
		}
		if ip4, ok := netLayer.(*layers.IPv4); ok {
			// Debug: Check for port 443 packets
			if (tcp.DstPort == 443 || tcp.SrcPort == 443) && len(tcp.Payload) >= 6 {
				fmt.Printf("DEBUG TCP: Port 443 packet, payload len=%d, first bytes: %02x %02x\n",
					len(tcp.Payload), tcp.Payload[0], tcp.Payload[1])
			}
			key := fmt.Sprintf("%s:%d->%s:%d", ip4.SrcIP.String(), tcp.SrcPort, ip4.DstIP.String(), tcp.DstPort)
			revKey := fmt.Sprintf("%s:%d->%s:%d", ip4.DstIP.String(), tcp.DstPort, ip4.SrcIP.String(), tcp.SrcPort)

			// Device fingerprinting on SYN packets
			if tcp.SYN && !tcp.ACK {
				synSent[key] = packet
				fp := extractTCPFingerprint(tcp, ip4)
				mu.Lock()
				deviceFingerprints[ip4.SrcIP.String()] = fp

				// Track SYN packets for handshake analysis
				timestamp := packet.Metadata().Timestamp.Sub(captureStartTime).Seconds()

				// Add timeline event for TCP SYN
				srcPort := uint16(tcp.SrcPort)
				dstPort := uint16(tcp.DstPort)
				*timelineEvents = append(*timelineEvents, TimelineEvent{
					Timestamp:       timestamp,
					EventType:       "TCP_SYN",
					SourceIP:        ip4.SrcIP.String(),
					DestinationIP:   ip4.DstIP.String(),
					SourcePort:      &srcPort,
					DestinationPort: &dstPort,
					Protocol:        "TCP",
					Detail:          fmt.Sprintf("Connection attempt to port %d", tcp.DstPort),
				})
				found := false
				for i := range report.TCPHandshakes.SYNFlows {
					if report.TCPHandshakes.SYNFlows[i].SrcIP == ip4.SrcIP.String() &&
						report.TCPHandshakes.SYNFlows[i].SrcPort == uint16(tcp.SrcPort) &&
						report.TCPHandshakes.SYNFlows[i].DstIP == ip4.DstIP.String() &&
						report.TCPHandshakes.SYNFlows[i].DstPort == uint16(tcp.DstPort) {
						report.TCPHandshakes.SYNFlows[i].Count++
						report.TCPHandshakes.SYNFlows[i].Timestamp = timestamp
						found = true
						break
					}
				}
				if !found {
					report.TCPHandshakes.SYNFlows = append(report.TCPHandshakes.SYNFlows, TCPHandshakeFlow{
						SrcIP:     ip4.SrcIP.String(),
						SrcPort:   uint16(tcp.SrcPort),
						DstIP:     ip4.DstIP.String(),
						DstPort:   uint16(tcp.DstPort),
						Timestamp: timestamp,
						Count:     1,
					})
				}
				mu.Unlock()
			}
			if tcp.SYN && tcp.ACK {
				synAckReceived[revKey] = true

				mu.Lock()
				// Track SYN-ACK packets for handshake analysis
				timestamp := packet.Metadata().Timestamp.Sub(packet.Metadata().CaptureInfo.Timestamp).Seconds()
				found := false
				for i := range report.TCPHandshakes.SYNACKFlows {
					if report.TCPHandshakes.SYNACKFlows[i].SrcIP == ip4.SrcIP.String() &&
						report.TCPHandshakes.SYNACKFlows[i].SrcPort == uint16(tcp.SrcPort) &&
						report.TCPHandshakes.SYNACKFlows[i].DstIP == ip4.DstIP.String() &&
						report.TCPHandshakes.SYNACKFlows[i].DstPort == uint16(tcp.DstPort) {
						report.TCPHandshakes.SYNACKFlows[i].Count++
						report.TCPHandshakes.SYNACKFlows[i].Timestamp = timestamp
						found = true
						break
					}
				}
				if !found {
					report.TCPHandshakes.SYNACKFlows = append(report.TCPHandshakes.SYNACKFlows, TCPHandshakeFlow{
						SrcIP:     ip4.SrcIP.String(),
						SrcPort:   uint16(tcp.SrcPort),
						DstIP:     ip4.DstIP.String(),
						DstPort:   uint16(tcp.DstPort),
						Timestamp: timestamp,
						Count:     1,
					})
				}

				// Check if this SYN-ACK corresponds to a previous SYN (successful handshake)
				for _, synFlow := range report.TCPHandshakes.SYNFlows {
					// Check if SYN was sent in opposite direction (DstIP:DstPort -> SrcIP:SrcPort)
					if synFlow.SrcIP == ip4.DstIP.String() &&
						synFlow.SrcPort == uint16(tcp.DstPort) &&
						synFlow.DstIP == ip4.SrcIP.String() &&
						synFlow.DstPort == uint16(tcp.SrcPort) {

						// Record successful handshake (from original SYN perspective)
						successFound := false
						for i := range report.TCPHandshakes.SuccessfulHandshakes {
							if report.TCPHandshakes.SuccessfulHandshakes[i].SrcIP == synFlow.SrcIP &&
								report.TCPHandshakes.SuccessfulHandshakes[i].SrcPort == synFlow.SrcPort &&
								report.TCPHandshakes.SuccessfulHandshakes[i].DstIP == synFlow.DstIP &&
								report.TCPHandshakes.SuccessfulHandshakes[i].DstPort == synFlow.DstPort {
								report.TCPHandshakes.SuccessfulHandshakes[i].Count++
								successFound = true
								break
							}
						}
						if !successFound {
							report.TCPHandshakes.SuccessfulHandshakes = append(report.TCPHandshakes.SuccessfulHandshakes, TCPHandshakeFlow{
								SrcIP:     synFlow.SrcIP,
								SrcPort:   synFlow.SrcPort,
								DstIP:     synFlow.DstIP,
								DstPort:   synFlow.DstPort,
								Timestamp: timestamp,
								Count:     1,
							})
						}
						break
					}
				}
				mu.Unlock()
			}

			// Enhanced retransmission detection with sequence and acknowledgment tracking
			flowKey := fmt.Sprintf("%s:%d->%s:%d", ip4.SrcIP.String(), tcp.SrcPort, ip4.DstIP.String(), tcp.DstPort)
			mu.Lock()
			flow, exists := tcpFlows[flowKey]
			if !exists {
				flow = &tcpFlowState{
					lastSeq:       tcp.Seq,
					lastAck:       tcp.Ack,
					expectedSeq:   tcp.Seq,
					seqSeen:       make(map[uint32]bool),
					rttSamples:    []float64{},
					sentTimes:     make(map[uint32]time.Time),
					totalBytes:    0,
					dupAckCount:   0,
					lastDupAck:    0,
					outOfOrderSeq: make(map[uint32]bool),
				}
				tcpFlows[flowKey] = flow
			}

			// Track bytes for traffic analysis
			packetLen := uint64(len(packet.Data()))
			flow.totalBytes += packetLen
			report.TotalBytes += packetLen

			// RTT calculation
			if len(tcp.Payload) > 0 {
				flow.sentTimes[tcp.Seq] = packet.Metadata().Timestamp
			}
			if tcp.ACK {
				// Check if we have a sent time for this ACK
				revFlow, revExists := tcpFlows[revKey]
				if revExists {
					if sentTime, ok := revFlow.sentTimes[tcp.Ack]; ok {
						rtt := packet.Metadata().Timestamp.Sub(sentTime).Seconds() * 1000 // ms
						if rtt > 0 && rtt < 10000 {                                       // Sanity check: RTT < 10 seconds
							flow.rttSamples = append(flow.rttSamples, rtt)
							delete(revFlow.sentTimes, tcp.Ack) // Clean up
						}
					}
				}
				flow.lastAck = tcp.Ack
			}

			// Enhanced TCP retransmission detection (similar to Wireshark's tcp.analysis.flags)
			srcIP := ip4.SrcIP.String()
			dstIP := ip4.DstIP.String()
			payloadLen := uint32(len(tcp.Payload))
			retransTimestamp := packet.Metadata().Timestamp.Sub(captureStartTime).Seconds()
			retransSrcPort := uint16(tcp.SrcPort)
			retransDstPort := uint16(tcp.DstPort)

			// Detect various TCP anomalies
			if len(tcp.Payload) > 0 || tcp.SYN || tcp.FIN {
				// 1. Retransmission: same sequence number seen before with payload
				if flow.seqSeen[tcp.Seq] && payloadLen > 0 {
					report.TCPRetransmissions = append(report.TCPRetransmissions, TCPFlow{
						SrcIP: srcIP, SrcPort: uint16(tcp.SrcPort),
						DstIP: dstIP, DstPort: uint16(tcp.DstPort),
					})
					markPathAnomaly(pathStats, srcIP, dstIP)

					// Add timeline event for retransmission (limit to avoid flooding)
					if len(*timelineEvents) < 10000 {
						*timelineEvents = append(*timelineEvents, TimelineEvent{
							Timestamp:       retransTimestamp,
							EventType:       "TCP_Retransmission",
							SourceIP:        srcIP,
							DestinationIP:   dstIP,
							SourcePort:      &retransSrcPort,
							DestinationPort: &retransDstPort,
							Protocol:        "TCP",
							Detail:          "Duplicate sequence number - packet retransmitted",
						})
					}
				}

				// 2. Out-of-order: sequence number is less than expected
				if flow.expectedSeq > 0 && tcp.Seq < flow.expectedSeq && !flow.outOfOrderSeq[tcp.Seq] {
					// This is an out-of-order segment (might be retransmitted later)
					flow.outOfOrderSeq[tcp.Seq] = true
					report.TCPRetransmissions = append(report.TCPRetransmissions, TCPFlow{
						SrcIP: srcIP, SrcPort: uint16(tcp.SrcPort),
						DstIP: dstIP, DstPort: uint16(tcp.DstPort),
					})
					markPathAnomaly(pathStats, srcIP, dstIP)
				}

				// 3. Spurious retransmission: sequence number already ACKed
				if tcp.ACK && flow.lastAck > 0 && tcp.Seq < flow.lastAck && payloadLen > 0 {
					report.TCPRetransmissions = append(report.TCPRetransmissions, TCPFlow{
						SrcIP: srcIP, SrcPort: uint16(tcp.SrcPort),
						DstIP: dstIP, DstPort: uint16(tcp.DstPort),
					})
					markPathAnomaly(pathStats, srcIP, dstIP)
				}

				// Track sequence numbers
				if payloadLen > 0 {
					flow.seqSeen[tcp.Seq] = true
					// Update expected sequence number
					nextSeq := tcp.Seq + payloadLen
					if nextSeq > flow.expectedSeq {
						flow.expectedSeq = nextSeq
					}
				}

				// Handle SYN/FIN flags for sequence tracking
				if tcp.SYN || tcp.FIN {
					flow.expectedSeq = tcp.Seq + 1
				}

				flow.lastSeq = tcp.Seq
			}

			// 4. Fast retransmission detection via duplicate ACKs
			if tcp.ACK && payloadLen == 0 {
				if tcp.Ack == flow.lastDupAck {
					flow.dupAckCount++
					// Wireshark typically flags after 3 duplicate ACKs
					if flow.dupAckCount >= 3 {
						// This indicates packet loss and likely fast retransmission
						report.TCPRetransmissions = append(report.TCPRetransmissions, TCPFlow{
							SrcIP: srcIP, SrcPort: uint16(tcp.SrcPort),
							DstIP: dstIP, DstPort: uint16(tcp.DstPort),
						})
						markPathAnomaly(pathStats, srcIP, dstIP)
						flow.dupAckCount = 0 // Reset after detection
					}
				} else {
					flow.lastDupAck = tcp.Ack
					flow.dupAckCount = 1
				}
			}

			// 5. Zero window probe detection
			if tcp.ACK && payloadLen == 1 && tcp.Window == 0 {
				report.TCPRetransmissions = append(report.TCPRetransmissions, TCPFlow{
					SrcIP: srcIP, SrcPort: uint16(tcp.SrcPort),
					DstIP: dstIP, DstPort: uint16(tcp.DstPort),
				})
				markPathAnomaly(pathStats, srcIP, dstIP)
			}

			// Application categorization
			appName := categorizePort(uint16(tcp.DstPort), "TCP")
			appKey := fmt.Sprintf("%s/TCP/%d", appName, tcp.DstPort)
			if app, ok := appStats[appKey]; ok {
				app.PacketCount++
				app.ByteCount += packetLen
			} else {
				appStats[appKey] = &AppCategory{
					Name:        appName,
					Port:        uint16(tcp.DstPort),
					Protocol:    "TCP",
					PacketCount: 1,
					ByteCount:   packetLen,
				}
			}

			// Suspicious port detection
			if isSusp, reason := isSuspiciousPort(uint16(tcp.DstPort)); isSusp {
				report.SuspiciousTraffic = append(report.SuspiciousTraffic, SuspiciousFlow{
					SrcIP:       ip4.SrcIP.String(),
					SrcPort:     uint16(tcp.SrcPort),
					DstIP:       ip4.DstIP.String(),
					DstPort:     uint16(tcp.DstPort),
					Protocol:    "TCP",
					Reason:      reason,
					Description: fmt.Sprintf("Traffic detected on port %d, commonly associated with %s. Verify if this is expected.", tcp.DstPort, reason),
				})
			}

			mu.Unlock()

			// Parse HTTP requests
			if len(tcp.Payload) > 0 {
				if req := parseHTTPRequest(tcp.Payload); req != nil {
					mu.Lock()
					httpRequests[flowKey] = req
					mu.Unlock()
				}
			}

			// Parse TLS handshakes for certificates and SNI
			if len(tcp.Payload) > 0 && (tcp.DstPort == 443 || tcp.SrcPort == 443) {
				// Detect TLS Handshake record (0x16 = Handshake, 0x03 = TLS version)
				isTLSHandshake := len(tcp.Payload) >= 6 &&
					tcp.Payload[0] == 0x16 && // TLS Handshake record type
					tcp.Payload[1] == 0x03 // TLS version major (0x03 for TLS 1.x)

				if len(tcp.Payload) >= 6 && tcp.Payload[0] == 0x16 {
					fmt.Printf("DEBUG: Port 443 packet with 0x16: %s:%d -> %s:%d, payload[0-1]: %02x %02x, isTLS: %v\n",
						ip4.SrcIP.String(), tcp.SrcPort, ip4.DstIP.String(), tcp.DstPort,
						tcp.Payload[0], tcp.Payload[1], isTLSHandshake)
				}

				if isTLSHandshake {
					mu.Lock()
					if !tlsFlowsSeen[flowKey] {
						tlsFlowsSeen[flowKey] = true
						report.TLSFlows = append(report.TLSFlows, TCPFlow{
							SrcIP:   ip4.SrcIP.String(),
							SrcPort: uint16(tcp.SrcPort),
							DstIP:   ip4.DstIP.String(),
							DstPort: uint16(tcp.DstPort),
						})
						fmt.Printf("DEBUG: TLS flow detected: %s:%d -> %s:%d\n",
							ip4.SrcIP.String(), tcp.SrcPort, ip4.DstIP.String(), tcp.DstPort)
					}
					mu.Unlock()
				}

				certs, sni := parseTLSHandshake(tcp.Payload)
				if sni != "" {
					mu.Lock()
					tlsSNICache[flowKey] = sni
					mu.Unlock()
				}
				if len(certs) > 0 {
					cert := certs[0]
					fingerprint := sha256.Sum256(cert.Raw)

					mu.Lock()
					cachedSNI := tlsSNICache[flowKey]
					mu.Unlock()

					isExpired := time.Now().After(cert.NotAfter) || time.Now().Before(cert.NotBefore)
					isSelfSigned := cert.Issuer.String() == cert.Subject.String()

					report.TLSCerts = append(report.TLSCerts, TLSCertInfo{
						Timestamp:    packet.Metadata().Timestamp.Sub(packet.Metadata().CaptureInfo.Timestamp).Seconds(),
						ServerIP:     ip4.DstIP.String(),
						ServerPort:   uint16(tcp.DstPort),
						ServerName:   cachedSNI,
						Subject:      cert.Subject.String(),
						Issuer:       cert.Issuer.String(),
						NotBefore:    cert.NotBefore.Format("2006-01-02 15:04:05"),
						NotAfter:     cert.NotAfter.Format("2006-01-02 15:04:05"),
						Fingerprint:  hex.EncodeToString(fingerprint[:]),
						IsExpired:    isExpired,
						IsSelfSigned: isSelfSigned,
						DNSNames:     cert.DNSNames,
					})
				}
			}
		}
	}

	// ARP
	if arpLayer := packet.Layer(layers.LayerTypeARP); arpLayer != nil {
		arp := arpLayer.(*layers.ARP)
		if arp.Operation == layers.ARPReply {
			ipStr := net.IP(arp.SourceProtAddress).String()
			macStr := net.HardwareAddr(arp.SourceHwAddress).String()
			if existingMAC, exists := arpIPToMAC[ipStr]; exists && existingMAC != macStr {
				report.ARPConflicts = append(report.ARPConflicts, ARPConflict{
					IP:   ipStr,
					MAC1: existingMAC,
					MAC2: macStr,
				})

				// Add timeline event for ARP conflict
				arpTimestamp := packet.Metadata().Timestamp.Sub(captureStartTime).Seconds()
				mu.Lock()
				*timelineEvents = append(*timelineEvents, TimelineEvent{
					Timestamp:       arpTimestamp,
					EventType:       "ARP_Conflict",
					SourceIP:        ipStr,
					DestinationIP:   "",
					SourcePort:      nil,
					DestinationPort: nil,
					Protocol:        "ARP",
					Detail:          fmt.Sprintf("IP %s claimed by multiple MACs: %s and %s (potential spoofing)", ipStr, existingMAC, macStr),
				})
				mu.Unlock()
			} else {
				arpIPToMAC[ipStr] = macStr
			}
		}
	}

	// HTTP - Enhanced parsing with request/response correlation
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp := tcpLayer.(*layers.TCP)
		netLayer := packet.NetworkLayer()
		if netLayer == nil {
			return
		}
		if ip4, ok := netLayer.(*layers.IPv4); ok {
			payload := string(tcp.Payload)
			if len(payload) > 12 && strings.HasPrefix(payload, "HTTP/1.") {
				lines := strings.Split(payload, "\r\n")
				if len(lines) > 0 {
					parts := strings.Fields(lines[0])
					if len(parts) >= 2 {
						var statusCode int
						fmt.Sscanf(parts[1], "%d", &statusCode)
						if statusCode >= 400 {
							// Try to find matching request
							reverseKey := fmt.Sprintf("%s:%d->%s:%d", ip4.DstIP.String(), tcp.DstPort, ip4.SrcIP.String(), tcp.SrcPort)
							mu.Lock()
							req := httpRequests[reverseKey]
							mu.Unlock()

							method := "UNKNOWN"
							host := ""
							path := ""
							if req != nil {
								method = req.method
								host = req.host
								path = req.path
							}

							httpTimestamp := packet.Metadata().Timestamp.Sub(captureStartTime).Seconds()
							report.HTTPErrors = append(report.HTTPErrors, HTTPError{
								Timestamp: httpTimestamp,
								Method:    method,
								Host:      host,
								Path:      path,
								Code:      statusCode,
							})

							// Add timeline event for HTTP error
							httpSrcPort := uint16(tcp.SrcPort)
							httpDstPort := uint16(tcp.DstPort)
							*timelineEvents = append(*timelineEvents, TimelineEvent{
								Timestamp:       httpTimestamp,
								EventType:       "HTTP_Error",
								SourceIP:        ip4.SrcIP.String(),
								DestinationIP:   ip4.DstIP.String(),
								SourcePort:      &httpSrcPort,
								DestinationPort: &httpDstPort,
								Protocol:        "TCP",
								Detail:          fmt.Sprintf("HTTP %d %s %s%s", statusCode, method, host, path),
							})
						}
					}
				}
			}
		}
	}

	// HTTP/2 detection via ALPN in TLS ClientHello or heuristics
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp := tcpLayer.(*layers.TCP)
		payload := tcp.Payload

		// Method 1: Parse ALPN protocols from TLS ClientHello
		if len(payload) > 43 {
			protocols := extractALPNProtocols(payload)
			for _, proto := range protocols {
				// Check for HTTP/2 protocols: "h2" or "h2c"
				if proto == "h2" || proto == "h2c" {
					netLayer := packet.NetworkLayer()
					if ip4, ok := netLayer.(*layers.IPv4); ok {
						// Create flow key to avoid duplicates
						flowKey := fmt.Sprintf("%s:%d->%s:%d",
							ip4.SrcIP.String(), tcp.SrcPort,
							ip4.DstIP.String(), tcp.DstPort)

						mu.Lock()
						if !http2FlowsSeen[flowKey] {
							http2FlowsSeen[flowKey] = true
							report.HTTP2Flows = append(report.HTTP2Flows, TCPFlow{
								SrcIP: ip4.SrcIP.String(), SrcPort: uint16(tcp.SrcPort),
								DstIP: ip4.DstIP.String(), DstPort: uint16(tcp.DstPort),
							})
						}
						mu.Unlock()
					}
					break
				}
			}
		}

		// Method 2: Heuristic detection for established HTTP/2 connections
		// Look for HTTP/2 connection preface: "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
		// or HTTP/2 frame magic (starts with 24-byte length + type + flags)
		if (tcp.DstPort == 443 || tcp.SrcPort == 443) && len(payload) > 24 {
			// Check for HTTP/2 connection preface
			if len(payload) >= 24 && string(payload[:24]) == "PRI * HTTP/2.0\r\n\r\nSM\r\n" {
				netLayer := packet.NetworkLayer()
				if ip4, ok := netLayer.(*layers.IPv4); ok {
					flowKey := fmt.Sprintf("%s:%d->%s:%d",
						ip4.SrcIP.String(), tcp.SrcPort,
						ip4.DstIP.String(), tcp.DstPort)

					mu.Lock()
					if !http2FlowsSeen[flowKey] {
						http2FlowsSeen[flowKey] = true
						report.HTTP2Flows = append(report.HTTP2Flows, TCPFlow{
							SrcIP: ip4.SrcIP.String(), SrcPort: uint16(tcp.SrcPort),
							DstIP: ip4.DstIP.String(), DstPort: uint16(tcp.DstPort),
						})
					}
					mu.Unlock()
				}
			}
		}
	}

	// UDP - Traffic tracking and application categorization
	if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp := udpLayer.(*layers.UDP)
		netLayer := packet.NetworkLayer()
		if netLayer != nil {
			if ip4, ok := netLayer.(*layers.IPv4); ok {
				flowKey := fmt.Sprintf("%s:%d->%s:%d", ip4.SrcIP.String(), udp.SrcPort, ip4.DstIP.String(), udp.DstPort)
				packetLen := uint64(len(packet.Data()))

				mu.Lock()
				flow, exists := udpFlows[flowKey]
				if !exists {
					flow = &udpFlowState{totalBytes: 0}
					udpFlows[flowKey] = flow
				}
				flow.totalBytes += packetLen
				report.TotalBytes += packetLen

				// Application categorization
				appName := categorizePort(uint16(udp.DstPort), "UDP")
				appKey := fmt.Sprintf("%s/UDP/%d", appName, udp.DstPort)
				if app, ok := appStats[appKey]; ok {
					app.PacketCount++
					app.ByteCount += packetLen
				} else {
					appStats[appKey] = &AppCategory{
						Name:        appName,
						Port:        uint16(udp.DstPort),
						Protocol:    "UDP",
						PacketCount: 1,
						ByteCount:   packetLen,
					}
				}

				// Suspicious port detection
				if isSusp, reason := isSuspiciousPort(uint16(udp.DstPort)); isSusp {
					report.SuspiciousTraffic = append(report.SuspiciousTraffic, SuspiciousFlow{
						SrcIP:       ip4.SrcIP.String(),
						SrcPort:     uint16(udp.SrcPort),
						DstIP:       ip4.DstIP.String(),
						DstPort:     uint16(udp.DstPort),
						Protocol:    "UDP",
						Reason:      reason,
						Description: fmt.Sprintf("Traffic detected on port %d, commonly associated with %s. Verify if this is expected.", udp.DstPort, reason),
					})
				}
				mu.Unlock()

				// QUIC - Enhanced detection with SNI extraction
				if udp.DstPort == 443 || udp.SrcPort == 443 {
					payload := udp.Payload
					if len(payload) > 0 {
						// QUIC long header: first 2 bits = 0b11 (0xC0)
						if payload[0]&0xC0 == 0xC0 {
							sni := extractQUICServerName(payload)
							report.QUICFlows = append(report.QUICFlows, UDPFlow{
								SrcIP:      ip4.SrcIP.String(),
								SrcPort:    uint16(udp.SrcPort),
								DstIP:      ip4.DstIP.String(),
								DstPort:    uint16(udp.DstPort),
								ServerName: sni,
							})
						}
					}
				}
			}
		}
	}
}

// === Export Functions ===
func exportToCSV(r *TriageReport, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	// Write header with plain-language column names
	file.WriteString("Finding Type,Plain Language Description,Source IP,Source Port,Destination IP,Destination Port,Severity Level,Recommended Action\n")

	// DNS Anomalies
	for _, d := range r.DNSAnomalies {
		description := fmt.Sprintf("Suspicious Redirect: Requests for website '%s' were directed to a local/private address (%s) instead of the real server. This is a strong indicator of DNS poisoning where an attacker or misconfigured device is attempting to intercept traffic.", d.Query, d.AnswerIP)
		file.WriteString(fmt.Sprintf("DNS Poisoning,%s,%s,53,%s,53,Critical,Verify DNS server configuration and check all devices for malware or unauthorized DNS settings\n",
			description, d.ServerIP, d.AnswerIP))
	}

	// TCP Retransmissions
	for _, t := range r.TCPRetransmissions {
		description := fmt.Sprintf("High Network Latency: Packets sent from device %s experienced delays reaching %s. The same data had to be sent multiple times indicating network congestion or connection problems between these points.", t.SrcIP, t.DstIP)
		file.WriteString(fmt.Sprintf("Network Congestion,%s,%s,%d,%s,%d,Warning,Check network links and Quality of Service (QoS) settings between these devices\n",
			description, t.SrcIP, t.SrcPort, t.DstIP, t.DstPort))
	}

	// Failed Handshakes
	for _, t := range r.FailedHandshakes {
		description := fmt.Sprintf("Connection Failed: Device %s attempted to connect to %s but the connection could not be established. The destination might be down, unreachable, or blocking the connection.", t.SrcIP, t.DstIP)
		file.WriteString(fmt.Sprintf("Failed Connection,%s,%s,%d,%s,%d,Warning,Check if destination service is running and verify firewall rules allow this connection\n",
			description, t.SrcIP, t.SrcPort, t.DstIP, t.DstPort))
	}

	// ARP Conflicts
	for _, a := range r.ARPConflicts {
		description := fmt.Sprintf("Duplicate Device Found: The network address %s appears to be used by two different physical devices (MAC addresses: %s and %s). This is often a sign of an unauthorized device or network misconfiguration potentially leading to Man-in-the-Middle attacks.", a.IP, a.MAC1, a.MAC2)
		file.WriteString(fmt.Sprintf("ARP Spoofing,%s,%s,N/A,%s,N/A,Critical,Immediately investigate network for unauthorized devices and potential security breach\n",
			description, a.IP, a.IP))
	}

	// HTTP Errors
	for _, h := range r.HTTPErrors {
		file.WriteString(fmt.Sprintf("Application,HTTP Error,%s,%s,\"HTTP %d %s %s%s\",Warning,\"Check application server logs\"\n",
			h.Host, h.Host, h.Code, h.Method, h.Host, h.Path))
	}

	// Suspicious Traffic
	for _, s := range r.SuspiciousTraffic {
		description := fmt.Sprintf("Suspicious Activity Detected: Device %s is communicating on port %d which is commonly associated with: %s. This may indicate malware infection or unauthorized software.", s.SrcIP, s.DstPort, s.Reason)
		file.WriteString(fmt.Sprintf("Suspicious Port Activity,%s,%s,%d,%s,%d,Critical,Immediately investigate source device for malware infection or unauthorized software\n",
			description, s.SrcIP, s.SrcPort, s.DstIP, s.DstPort))
	}

	// Traffic Analysis
	for _, f := range r.TrafficAnalysis {
		severity := "Info"
		action := "Monitor this connection for normal business activity"
		if f.Percentage > 10 {
			severity = "Warning"
			action = "Investigate this high-bandwidth connection - could be legitimate data transfer or potential data exfiltration"
		}
		description := fmt.Sprintf("High Bandwidth Usage: Connection between %s and %s consumed %.2f MB of data (%.1f%% of all network traffic). This represents a significant portion of network capacity.", f.SrcIP, f.DstIP, float64(f.TotalBytes)/(1024*1024), f.Percentage)
		file.WriteString(fmt.Sprintf("Bandwidth Consumer,%s,%s,%d,%s,%d,%s,%s\n",
			description, f.SrcIP, f.SrcPort, f.DstIP, f.DstPort, severity, action))
	}

	// RTT Analysis
	for _, rtt := range r.RTTAnalysis {
		description := fmt.Sprintf("Slow Response Time: Communication between %s and %s is experiencing high latency (average delay: %.1f milliseconds). Even with good bandwidth, high delays severely impact application performance especially for interactive applications.", rtt.SrcIP, rtt.DstIP, rtt.AvgRTT)
		file.WriteString(fmt.Sprintf("High Latency,%s,%s,%d,%s,%d,Warning,Investigate network routing paths and WAN links for latency issues between these locations\n",
			description, rtt.SrcIP, rtt.SrcPort, rtt.DstIP, rtt.DstPort))
	}

	// TLS Certificates
	for _, c := range r.TLSCerts {
		severity := "Info"
		action := "Verify certificate is from trusted CA"
		if c.IsExpired {
			severity = "Critical"
			action = "Renew expired certificate immediately"
		} else if c.IsSelfSigned {
			severity = "Warning"
			action = "Verify self-signed certificate is expected"
		}
		file.WriteString(fmt.Sprintf("Security,TLS Certificate,%s:%d,%s,\"Server: %s Issuer: %s Expired: %v Self-Signed: %v\","+severity+",\"%s\"\n",
			c.ServerIP, c.ServerPort, c.ServerName, c.ServerName, c.Issuer, c.IsExpired, c.IsSelfSigned, action))
	}

	// Device Fingerprinting
	for _, d := range r.DeviceFingerprinting {
		file.WriteString(fmt.Sprintf("Info,Device Fingerprint,%s,%s,\"%s - %s (Confidence: %s)\",Info,\"For network topology understanding\"\n",
			d.SrcIP, d.OSGuess, d.DeviceType, d.OSGuess, d.Confidence))
	}

	// TCP Handshake Analysis - SYN Flows
	for _, flow := range r.TCPHandshakes.SYNFlows {
		description := fmt.Sprintf("TCP Connection Initiation: Detected TCP connection attempt from %s:%d to %s:%d. SYN packet observed initiating a connection.", flow.SrcIP, flow.SrcPort, flow.DstIP, flow.DstPort)
		if flow.Count > 1 {
			description = fmt.Sprintf("TCP Connection Initiation: Detected %d TCP connection attempts from %s:%d to %s:%d. Multiple SYN packets observed.", flow.Count, flow.SrcIP, flow.SrcPort, flow.DstIP, flow.DstPort)
		}
		file.WriteString(fmt.Sprintf("TCP Handshake - SYN,%s,%s,%d,%s,%d,Info,Normal connection establishment behavior\n",
			description, flow.SrcIP, flow.SrcPort, flow.DstIP, flow.DstPort))
	}

	// TCP Handshake Analysis - SYN-ACK Flows
	for _, flow := range r.TCPHandshakes.SYNACKFlows {
		description := fmt.Sprintf("TCP Connection Response: Detected TCP connection response from %s:%d to %s:%d. SYN-ACK packet observed responding to a connection request.", flow.SrcIP, flow.SrcPort, flow.DstIP, flow.DstPort)
		if flow.Count > 1 {
			description = fmt.Sprintf("TCP Connection Response: Detected %d TCP connection responses from %s:%d to %s:%d. Multiple SYN-ACK packets observed.", flow.Count, flow.SrcIP, flow.SrcPort, flow.DstIP, flow.DstPort)
		}
		file.WriteString(fmt.Sprintf("TCP Handshake - SYN-ACK,%s,%s,%d,%s,%d,Info,Normal connection establishment behavior\n",
			description, flow.SrcIP, flow.SrcPort, flow.DstIP, flow.DstPort))
	}

	// TCP Handshake Analysis - Successful Handshakes
	for _, flow := range r.TCPHandshakes.SuccessfulHandshakes {
		description := fmt.Sprintf("Successful TCP Handshake: Detected successful TCP handshake initiation from %s:%d to %s:%d. Both SYN and SYN-ACK packets observed indicating successful connection establishment.", flow.DstIP, flow.DstPort, flow.SrcIP, flow.SrcPort)
		if flow.Count > 1 {
			description = fmt.Sprintf("Successful TCP Handshakes: Detected %d successful TCP handshake initiations from %s:%d to %s:%d.", flow.Count, flow.DstIP, flow.DstPort, flow.SrcIP, flow.SrcPort)
		}
		file.WriteString(fmt.Sprintf("TCP Handshake - Success,%s,%s,%d,%s,%d,Info,Connection established successfully\n",
			description, flow.SrcIP, flow.SrcPort, flow.DstIP, flow.DstPort))
	}

	// TCP Handshake Analysis - Failed Handshake Attempts
	for _, flow := range r.TCPHandshakes.FailedHandshakeAttempts {
		description := fmt.Sprintf("Potential TCP Handshake Failure: SYN packet sent from %s:%d to %s:%d but no corresponding SYN-ACK response was observed in this capture. This could indicate the destination is down, unreachable, or blocking the connection.", flow.SrcIP, flow.SrcPort, flow.DstIP, flow.DstPort)
		if flow.Count > 1 {
			description = fmt.Sprintf("Potential TCP Handshake Failures: %d SYN packets sent from %s:%d to %s:%d but no corresponding SYN-ACK responses were observed. The destination may be down, unreachable, or blocking connections.", flow.Count, flow.SrcIP, flow.SrcPort, flow.DstIP, flow.DstPort)
		}
		file.WriteString(fmt.Sprintf("TCP Handshake - Failed,%s,%s,%d,%s,%d,Warning,Investigate destination reachability and verify firewall rules allow this connection\n",
			description, flow.SrcIP, flow.SrcPort, flow.DstIP, flow.DstPort))
	}

	// Bandwidth & Conversation Analysis - Top Conversations by Bytes
	for i, conv := range r.BandwidthReport.TopConversationsByBytes {
		if i >= 20 {
			break
		}

		mbps := conv.AvgBitsPerSecond / 1_000_000
		durationStr := conv.Duration.Round(time.Millisecond).String()
		severity := "Info"
		action := "Monitor for normal business activity"

		description := fmt.Sprintf("High Bandwidth Conversation: Flow from %s:%d to %s:%d (%s) transferred %.2f MB over %s, averaging %.2f Mbps. This represents significant data transfer.",
			conv.SrcIP, conv.SrcPort, conv.DstIP, conv.DstPort, conv.Protocol,
			float64(conv.TotalBytes)/(1024*1024), durationStr, mbps)

		if conv.TotalBytes > 10*1024*1024 {
			severity = "Warning"
			action = "Investigate this high-bandwidth connection - could be legitimate data transfer, video streaming, or potential data exfiltration"
		}

		if conv.Protocol == "ICMP" {
			file.WriteString(fmt.Sprintf("Bandwidth - High Usage,%s,%s,N/A,%s,N/A,%s,%s\n",
				description, conv.SrcIP, conv.DstIP, severity, action))
		} else {
			file.WriteString(fmt.Sprintf("Bandwidth - High Usage,%s,%s,%d,%s,%d,%s,%s\n",
				description, conv.SrcIP, conv.SrcPort, conv.DstIP, conv.DstPort, severity, action))
		}
	}

	// Bandwidth & Conversation Analysis - Top Conversations by Packets
	for i, conv := range r.BandwidthReport.TopConversationsByPackets {
		if i >= 20 {
			break
		}

		durationStr := conv.Duration.Round(time.Millisecond).String()
		packetsPerSec := float64(0)
		if conv.Duration.Seconds() > 0 {
			packetsPerSec = float64(conv.TotalPackets) / conv.Duration.Seconds()
		}

		severity := "Info"
		action := "Normal connection activity"

		description := fmt.Sprintf("Chatty Connection: Flow from %s:%d to %s:%d (%s) generated %d packets over %s (%.1f pkt/s). This indicates many small requests/responses which can impact performance due to protocol overhead.",
			conv.SrcIP, conv.SrcPort, conv.DstIP, conv.DstPort, conv.Protocol,
			conv.TotalPackets, durationStr, packetsPerSec)

		if conv.TotalPackets > 10000 {
			severity = "Warning"
			action = "Review application design for efficiency - consider batching requests or optimizing protocol usage"
		}

		if conv.Protocol == "ICMP" {
			file.WriteString(fmt.Sprintf("Conversation - High Packet Count,%s,%s,N/A,%s,N/A,%s,%s\n",
				description, conv.SrcIP, conv.DstIP, severity, action))
		} else {
			file.WriteString(fmt.Sprintf("Conversation - High Packet Count,%s,%s,%d,%s,%d,%s,%s\n",
				description, conv.SrcIP, conv.SrcPort, conv.DstIP, conv.DstPort, severity, action))
		}
	}

	// Timeline Events (limit to first 100 for CSV)
	for i, event := range r.Timeline {
		if i >= 100 {
			break
		}
		srcPort := "N/A"
		dstPort := "N/A"
		if event.SourcePort != nil {
			srcPort = fmt.Sprintf("%d", *event.SourcePort)
		}
		if event.DestinationPort != nil {
			dstPort = fmt.Sprintf("%d", *event.DestinationPort)
		}
		file.WriteString(fmt.Sprintf("Timeline,%s,%.3fs,%s,%s,%s,%s,%s,%s\n",
			event.EventType, event.Timestamp, event.SourceIP, srcPort, event.DestinationIP, dstPort, event.Protocol, event.Detail))
	}

	// DNS Details
	for i, record := range r.DNSDetails {
		if i >= 50 {
			break
		}
		responseStr := "No response"
		if record.ResponseTimestamp != nil {
			if len(record.AnswerIPs) > 0 {
				responseStr = strings.Join(record.AnswerIPs, "; ")
			} else if len(record.AnswerNames) > 0 {
				responseStr = strings.Join(record.AnswerNames, "; ")
			} else {
				responseStr = "No records"
			}
		}
		status := "OK"
		if record.IsAnomalous {
			status = "ANOMALY"
		}
		file.WriteString(fmt.Sprintf("DNS Detail,%s (%s),%.3fs,%s,%s,%s,%s,%s\n",
			record.QueryName, record.QueryType, record.QueryTimestamp, record.SourceIP, record.DestinationIP, responseStr, status, record.Detail))
	}

	return nil
}

func exportToHTML(r *TriageReport, filename string, pathStats *PathStats, filter *Filter, traceData *TracerouteData) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	// Calculate summary stats
	criticalIssues := len(r.DNSAnomalies) + len(r.ARPConflicts)
	performanceIssues := len(r.TCPRetransmissions) + len(r.FailedHandshakes) + len(r.RTTAnalysis)
	securityConcerns := len(r.SuspiciousTraffic)
	for _, cert := range r.TLSCerts {
		if cert.IsExpired || cert.IsSelfSigned {
			securityConcerns++
		}
	}

	healthStatus := "HEALTHY"
	healthColor := "#28a745"
	if criticalIssues > 0 || securityConcerns > 3 {
		healthStatus = "CRITICAL"
		healthColor = "#dc3545"
	} else if performanceIssues > 5 || securityConcerns > 0 {
		healthStatus = "WARNING"
		healthColor = "#ffc107"
	}

	// Generate Mermaid diagram
	mermaidDiagram := generateMermaidDiagram(pathStats, filter)

	// Generate vis.js data with traceroute information
	visNodesJSON, visEdgesJSON := generateVisJSData(pathStats, filter, traceData)

	// Write HTML
	html := `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SD-WAN Network Triage Report</title>
    <script src="https://cdn.jsdelivr.net/npm/mermaid@10/dist/mermaid.min.js"></script>
    <script src="https://unpkg.com/vis-network/standalone/umd/vis-network.min.js"></script>
    <script>
        mermaid.initialize({ startOnLoad: true, theme: 'default', securityLevel: 'loose' });
    </script>
    <style>
        #interactive-diagram {
            height: 600px;
            border: 1px solid #e0e0e0;
            border-radius: 8px;
            background: white;
            margin: 20px 0;
        }
    </style>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif; 
               background: #f5f7fa; padding: 20px; line-height: 1.6; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 30px; 
                     border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        h1 { color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 15px; margin-bottom: 30px; }
        h2 { color: #34495e; margin-top: 30px; margin-bottom: 15px; padding-left: 10px; 
             border-left: 4px solid #3498db; }
        .summary { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
                   color: white; padding: 25px; border-radius: 8px; margin-bottom: 30px; }
        .summary h2 { color: white; border-left: 4px solid white; margin-top: 0; }
        .health-status { font-size: 24px; font-weight: bold; padding: 15px; 
                        border-radius: 5px; text-align: center; margin: 20px 0; }
        .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); 
                gap: 15px; margin-top: 20px; }
        .stat-card { background: rgba(255,255,255,0.2); padding: 15px; border-radius: 5px; }
        .stat-card h3 { font-size: 14px; opacity: 0.9; margin-bottom: 5px; }
        .stat-card .number { font-size: 32px; font-weight: bold; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th { background: #3498db; color: white; padding: 12px; text-align: left; font-weight: 600; }
        td { padding: 10px 12px; border-bottom: 1px solid #ecf0f1; }
        tr:hover { background: #f8f9fa; }
        .badge { display: inline-block; padding: 4px 12px; border-radius: 12px; 
                font-size: 12px; font-weight: 600; }
        .badge-critical { background: #dc3545; color: white; }
        .badge-warning { background: #ffc107; color: #000; }
        .badge-info { background: #17a2b8; color: white; }
        .section { margin-bottom: 40px; }
        .empty-state { text-align: center; padding: 40px; color: #95a5a6; font-style: italic; }
        .footer { margin-top: 40px; padding-top: 20px; border-top: 1px solid #ecf0f1; 
                 text-align: center; color: #7f8c8d; font-size: 14px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔍 SD-WAN Network Triage Report</h1>
        
        <p style="margin-bottom: 30px; padding: 15px; background: #e8f4f8; border-left: 4px solid #3498db; border-radius: 4px;">
            <strong>About This Report:</strong> This report analyzes a network packet capture (PCAP) file to identify potential issues, 
            security concerns, and traffic patterns. The analysis includes automated detection of common network problems, 
            security threats, and performance bottlenecks. While this tool identifies potential issues, further investigation 
            by network administrators may be required to confirm findings and implement solutions.
        </p>
        
        <div class="summary">
            <h2>Executive Summary</h2>
            <div class="health-status" style="background-color: ` + healthColor + `;">
                Risk Level: ` + healthStatus + `
            </div>
            <div class="stats">
                <div class="stat-card">
                    <h3>Critical Issues</h3>
                    <div class="number">` + fmt.Sprintf("%d", criticalIssues) + `</div>
                </div>
                <div class="stat-card">
                    <h3>Performance Issues</h3>
                    <div class="number">` + fmt.Sprintf("%d", performanceIssues) + `</div>
                </div>
                <div class="stat-card">
                    <h3>Security Concerns</h3>
                    <div class="number">` + fmt.Sprintf("%d", securityConcerns) + `</div>
                </div>
                <div class="stat-card">
                    <h3>Total Traffic</h3>
                    <div class="number">` + fmt.Sprintf("%.1f MB", float64(r.TotalBytes)/(1024*1024)) + `</div>
                </div>
            </div>
        </div>
`

	// Traffic Flow Diagram
	if mermaidDiagram != "" {
		html += `        <div class="section">
            <h2>🔀 Traffic Flow Diagram</h2>
            <p style="margin-bottom: 15px; padding: 10px; background: #e8f4f8; border-left: 4px solid #3498db; border-radius: 4px;">
                <strong>About This Diagram:</strong> This visualization shows the communication paths detected in the analyzed traffic. 
                Each arrow represents data flowing between two network endpoints. The label on each arrow shows the protocol, 
                port number, and total data transferred. <strong style="color: #dc3545;">Red highlighted nodes and dashed lines</strong> 
                indicate paths where issues were detected (packet loss, high latency, or retransmissions).
            </p>
            <div class="mermaid" style="background: white; padding: 20px; border-radius: 8px; border: 1px solid #e0e0e0;">
` + mermaidDiagram + `
            </div>
            <p style="margin-top: 15px; padding: 10px; background: #fff3cd; border-left: 4px solid #ffc107; border-radius: 4px;">
                <strong>⚠️ Investigation Tip:</strong> Focus on the red-highlighted nodes in the diagram. These represent devices 
                experiencing network problems. Check the physical connections, network equipment, and routing between these points.
            </p>
        </div>
`
	}

	// Interactive vis.js diagram
	if visNodesJSON != "[]" && visEdgesJSON != "[]" {
		html += `        <div class="section">
            <h2>🌐 Interactive Network Diagram</h2>
            <p style="margin-bottom: 15px; padding: 10px; background: #e8f4f8; border-left: 4px solid #3498db; border-radius: 4px;">
                <strong>Interactive Features:</strong> This diagram allows you to explore the network topology interactively. 
                <strong>Drag nodes</strong> to rearrange the layout, <strong>zoom</strong> with your mouse wheel, and <strong>hover</strong> 
                over nodes and connections to see detailed information. 
                <span style="color: #dc3545; font-weight: bold;">Red nodes and dashed lines</span> indicate devices and connections 
                experiencing issues (retransmissions, packet loss, or high latency).
            </p>
            <div id="interactive-diagram"></div>
            <p style="margin-top: 15px; padding: 10px; background: #fff3cd; border-left: 4px solid #ffc107; border-radius: 4px;">
                <strong>Legend:</strong><br>
                • <strong style="color: #4CAF50;">Green boxes</strong>: Internal network devices<br>
                • <strong style="color: #2196F3;">Blue diamonds</strong>: Potential gateways/routers<br>
                • <strong style="color: #FF9800;">Orange boxes</strong>: External servers<br>
                • <strong style="color: #9C27B0;">Purple triangles</strong>: Traceroute hops (intermediate network devices)<br>
                • <strong style="color: #dc3545;">Red nodes/dashed lines</strong>: Devices with detected issues<br>
                • <strong style="color: #9C27B0;">Purple arrows</strong>: Discovered traceroute paths<br>
                • <strong>Gray arrows</strong>: Direct traffic flows from PCAP<br>
                • <strong>Arrow labels</strong>: Protocol, port, data volume, or hop number
            </p>
            <p style="margin-top: 10px; padding: 10px; background: #e3f2fd; border-left: 4px solid #2196F3; border-radius: 4px;">
                <strong>ℹ️ About Traceroute Data:</strong> If traceroute was enabled (-trace-path flag), the purple paths show 
                the route discovered at analysis time from this machine to the destinations. Note that the actual path taken by 
                the historical PCAP traffic may have been different if network topology or routing changed between capture and analysis time.
            </p>
        </div>

        <script type="text/javascript">
            // Network data
            var nodes = new vis.DataSet(` + visNodesJSON + `);
            var edges = new vis.DataSet(` + visEdgesJSON + `);

            // Create network
            var container = document.getElementById('interactive-diagram');
            var data = {
                nodes: nodes,
                edges: edges
            };
            var options = {
                nodes: {
                    shape: 'box',
                    size: 25,
                    font: {
                        size: 14,
                        face: 'Arial',
                        color: '#333'
                    },
                    borderWidth: 2,
                    shadow: true
                },
                edges: {
                    width: 2,
                    color: {
                        color: '#848484',
                        highlight: '#2B7CE9',
                        hover: '#2B7CE9'
                    },
                    arrows: {
                        to: {
                            enabled: true,
                            scaleFactor: 0.5
                        }
                    },
                    font: {
                        size: 11,
                        align: 'middle'
                    },
                    smooth: {
                        type: 'continuous'
                    },
                    shadow: true
                },
                groups: {
                    internal: {
                        color: {
                            background: '#C8E6C9',
                            border: '#4CAF50',
                            highlight: {
                                background: '#A5D6A7',
                                border: '#388E3C'
                            }
                        }
                    },
                    router: {
                        color: {
                            background: '#BBDEFB',
                            border: '#2196F3',
                            highlight: {
                                background: '#90CAF9',
                                border: '#1976D2'
                            }
                        },
                        shape: 'diamond',
                        size: 30
                    },
                    external: {
                        color: {
                            background: '#FFE0B2',
                            border: '#FF9800',
                            highlight: {
                                background: '#FFCC80',
                                border: '#F57C00'
                            }
                        }
                    },
                    tracehop: {
                        color: {
                            background: '#E1BEE7',
                            border: '#9C27B0',
                            highlight: {
                                background: '#CE93D8',
                                border: '#7B1FA2'
                            }
                        },
                        shape: 'triangle',
                        size: 20
                    }
                },
                physics: {
                    enabled: true,
                    barnesHut: {
                        gravitationalConstant: -8000,
                        centralGravity: 0.3,
                        springLength: 200,
                        springConstant: 0.04,
                        damping: 0.09,
                        avoidOverlap: 0.1
                    },
                    stabilization: {
                        iterations: 200
                    }
                },
                interaction: {
                    hover: true,
                    tooltipDelay: 100,
                    zoomView: true,
                    dragView: true
                }
            };
            try {
                var network = new vis.Network(container, data, options);

                // Stabilization progress
                network.on("stabilizationProgress", function(params) {
                    var maxWidth = 496;
                    var minWidth = 20;
                    var widthFactor = params.iterations/params.total;
                    var width = Math.max(minWidth, maxWidth * widthFactor);
                });

                network.once("stabilizationIterationsDone", function() {
                    network.setOptions({ physics: false });
                });
            } catch (e) {
                console.error("Error initializing Vis.js network:", e);
                document.getElementById('interactive-diagram').innerHTML = '<p style="color: red; padding: 20px;">Error: Could not render diagram. Check browser console for details.</p>';
            }
        </script>
`
	}

	// DNS Anomalies
	if len(r.DNSAnomalies) > 0 {
		html += `        <div class="section">
            <h2>🚨 Potential Security Threats - DNS Poisoning</h2>
            <p style="margin-bottom: 15px; padding: 10px; background: #fff3cd; border-left: 4px solid #ffc107; border-radius: 4px;">
                <strong>What This Means:</strong> Requests for legitimate websites are being redirected to unexpected addresses. 
                This is a strong indicator of DNS poisoning, where an attacker or misconfigured device is attempting to 
                intercept your network traffic. This could be used for phishing attacks or to steal sensitive information.
            </p>
            <table>
                <tr><th>Website Requested</th><th>Redirected To</th><th>DNS Server</th><th>Plain Language Explanation</th><th>Risk</th></tr>
`
		for _, d := range r.DNSAnomalies {
			explanation := fmt.Sprintf("Requests for '%s' were sent to a local/private address (%s) instead of the real server", d.Query, d.AnswerIP)
			html += fmt.Sprintf(`                <tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td><span class="badge badge-critical">CRITICAL</span></td></tr>
`, d.Query, d.AnswerIP, d.ServerIP, explanation)
		}
		html += `            </table>
            <p><strong>⚠️ Recommended Action:</strong> Immediately verify your DNS server configuration and scan all network devices for malware or unauthorized DNS settings.</p>
        </div>
`
	}

	// TCP Retransmissions
	if len(r.TCPRetransmissions) > 0 {
		html += `        <div class="section">
            <h2>⚡ Network Performance Indicators - Packet Loss</h2>
            <p style="margin-bottom: 15px; padding: 10px; background: #fff3cd; border-left: 4px solid #ffc107; border-radius: 4px;">
                <strong>What This Means:</strong> Data packets had to be sent multiple times because they didn't arrive at their destination. 
                This usually indicates network congestion or connection problems, which can severely slow down applications and user experience. 
                Think of it like having to repeat yourself multiple times on a bad phone connection.
            </p>
            <p>Total retransmissions detected: <strong>` + fmt.Sprintf("%d", len(r.TCPRetransmissions)) + `</strong> (showing first 20)</p>
            <table>
                <tr><th>From Device</th><th>To Device</th><th>Impact</th></tr>
`
		for i, t := range r.TCPRetransmissions {
			if i >= 20 {
				break
			}
			html += fmt.Sprintf(`                <tr><td>%s:%d</td><td>%s:%d</td><td><span class="badge badge-warning">Slow Performance</span></td></tr>
`, t.SrcIP, t.SrcPort, t.DstIP, t.DstPort)
		}
		html += `            </table>
            <p><strong>⚠️ Recommended Action:</strong> Check network cables, switches, and routers between these devices. Consider reviewing Quality of Service (QoS) settings to prioritize important traffic.</p>
        </div>
`
	}

	// TCP Handshake Analysis
	if len(r.TCPHandshakes.SYNFlows) > 0 || len(r.TCPHandshakes.SYNACKFlows) > 0 {
		html += `        <div class="section">
            <h2>🔌 TCP Handshake Analysis</h2>
            <p style="margin-bottom: 15px; padding: 10px; background: #e8f4f8; border-left: 4px solid #3498db; border-radius: 4px;">
                <strong>What This Means:</strong> This section tracks TCP connection establishment patterns. Every TCP connection 
                starts with a "handshake" where the client sends a SYN packet, and the server responds with a SYN-ACK packet. 
                Monitoring these patterns helps identify connection issues, unreachable services, and network behavior.
            </p>
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-bottom: 20px;">
                <div style="background: #e3f2fd; padding: 15px; border-radius: 5px; border-left: 4px solid #2196F3;">
                    <h3 style="margin: 0 0 10px 0; color: #1976D2; font-size: 14px;">SYN Packets</h3>
                    <div style="font-size: 32px; font-weight: bold; color: #1976D2;">` + fmt.Sprintf("%d", len(r.TCPHandshakes.SYNFlows)) + `</div>
                    <p style="margin: 5px 0 0 0; font-size: 12px; color: #666;">Connection attempts</p>
                </div>
                <div style="background: #e8f5e9; padding: 15px; border-radius: 5px; border-left: 4px solid #4CAF50;">
                    <h3 style="margin: 0 0 10px 0; color: #388E3C; font-size: 14px;">SYN-ACK Packets</h3>
                    <div style="font-size: 32px; font-weight: bold; color: #388E3C;">` + fmt.Sprintf("%d", len(r.TCPHandshakes.SYNACKFlows)) + `</div>
                    <p style="margin: 5px 0 0 0; font-size: 12px; color: #666;">Connection responses</p>
                </div>
                <div style="background: #f3e5f5; padding: 15px; border-radius: 5px; border-left: 4px solid #9C27B0;">
                    <h3 style="margin: 0 0 10px 0; color: #7B1FA2; font-size: 14px;">Successful Handshakes</h3>
                    <div style="font-size: 32px; font-weight: bold; color: #7B1FA2;">` + fmt.Sprintf("%d", len(r.TCPHandshakes.SuccessfulHandshakes)) + `</div>
                    <p style="margin: 5px 0 0 0; font-size: 12px; color: #666;">Completed connections</p>
                </div>
                <div style="background: #fff3e0; padding: 15px; border-radius: 5px; border-left: 4px solid #FF9800;">
                    <h3 style="margin: 0 0 10px 0; color: #F57C00; font-size: 14px;">Failed Attempts</h3>
                    <div style="font-size: 32px; font-weight: bold; color: #F57C00;">` + fmt.Sprintf("%d", len(r.TCPHandshakes.FailedHandshakeAttempts)) + `</div>
                    <p style="margin: 5px 0 0 0; font-size: 12px; color: #666;">No response received</p>
                </div>
            </div>
`

		// Top SYN Flows
		if len(r.TCPHandshakes.SYNFlows) > 0 {
			// Sort by count
			synFlows := make([]TCPHandshakeFlow, len(r.TCPHandshakes.SYNFlows))
			copy(synFlows, r.TCPHandshakes.SYNFlows)
			for i := 0; i < len(synFlows); i++ {
				for j := i + 1; j < len(synFlows); j++ {
					if synFlows[j].Count > synFlows[i].Count {
						synFlows[i], synFlows[j] = synFlows[j], synFlows[i]
					}
				}
			}

			html += `            <h3 style="margin-top: 20px; color: #1976D2;">Top Connection Initiators (SYN Packets)</h3>
            <table>
                <tr><th>Source</th><th>Destination</th><th>Attempts</th><th>Description</th></tr>
`
			for i, flow := range synFlows {
				if i >= 10 {
					break
				}
				description := fmt.Sprintf("Detected TCP connection initiation from %s:%d to %s:%d", flow.SrcIP, flow.SrcPort, flow.DstIP, flow.DstPort)
				html += fmt.Sprintf(`                <tr><td>%s:%d</td><td>%s:%d</td><td>%d</td><td>%s</td></tr>
`, flow.SrcIP, flow.SrcPort, flow.DstIP, flow.DstPort, flow.Count, description)
			}
			html += `            </table>
`
		}

		// Failed Handshake Attempts
		if len(r.TCPHandshakes.FailedHandshakeAttempts) > 0 {
			html += `            <h3 style="margin-top: 20px; color: #F57C00;">⚠️ Potential Handshake Failures</h3>
            <p style="padding: 10px; background: #fff3cd; border-left: 4px solid #ffc107; border-radius: 4px;">
                <strong>What This Means:</strong> These connections sent SYN packets but never received a SYN-ACK response. 
                This typically indicates the destination is down, unreachable, or blocking the connection.
            </p>
            <table>
                <tr><th>Source</th><th>Destination</th><th>Failed Attempts</th><th>Description</th></tr>
`
			for i, flow := range r.TCPHandshakes.FailedHandshakeAttempts {
				if i >= 10 {
					break
				}
				description := fmt.Sprintf("SYN packet sent from %s:%d to %s:%d but no SYN-ACK response observed. Destination may be down, unreachable, or blocking connections.", flow.SrcIP, flow.SrcPort, flow.DstIP, flow.DstPort)
				html += fmt.Sprintf(`                <tr><td>%s:%d</td><td>%s:%d</td><td>%d</td><td>%s</td></tr>
`, flow.SrcIP, flow.SrcPort, flow.DstIP, flow.DstPort, flow.Count, description)
			}
			html += `            </table>
            <p><strong>⚠️ Recommended Action:</strong> Investigate destination reachability and verify firewall rules allow these connections.</p>
`
		}

		html += `        </div>
`
	}

	// Suspicious Traffic
	if len(r.SuspiciousTraffic) > 0 {
		html += `        <div class="section">
            <h2>🔒 Suspicious Port Activity</h2>
            <table>
                <tr><th>Source</th><th>Destination</th><th>Protocol</th><th>Reason</th><th>Severity</th></tr>
`
		for _, s := range r.SuspiciousTraffic {
			html += fmt.Sprintf(`                <tr><td>%s:%d</td><td>%s:%d</td><td>%s</td><td>%s</td><td><span class="badge badge-critical">CRITICAL</span></td></tr>
`, s.SrcIP, s.SrcPort, s.DstIP, s.DstPort, s.Protocol, s.Reason)
		}
		html += `            </table>
            <p><strong>⚠️ Action Required:</strong> Investigate source systems for malware or unauthorized software.</p>
        </div>
`
	}

	// Traffic Analysis
	if len(r.TrafficAnalysis) > 0 {
		html += `        <div class="section">
            <h2>📊 Top Bandwidth Consumers</h2>
            <table>
                <tr><th>Flow</th><th>Protocol</th><th>Data Transferred</th><th>% of Total</th><th>Status</th></tr>
`
		for i, f := range r.TrafficAnalysis {
			if i >= 10 {
				break
			}
			badge := "badge-info"
			status := "Normal"
			if f.Percentage > 10 {
				badge = "badge-warning"
				status = "Bandwidth Hog"
			}
			html += fmt.Sprintf(`                <tr><td>%s:%d → %s:%d</td><td>%s</td><td>%.2f MB</td><td>%.1f%%</td><td><span class="badge %s">%s</span></td></tr>
`, f.SrcIP, f.SrcPort, f.DstIP, f.DstPort, f.Protocol, float64(f.TotalBytes)/(1024*1024), f.Percentage, badge, status)
		}
		html += `            </table>
        </div>
`
	}

	// RTT Analysis
	if len(r.RTTAnalysis) > 0 {
		html += `        <div class="section">
            <h2>🐌 High Latency Flows</h2>
            <table>
                <tr><th>Flow</th><th>Avg RTT</th><th>Min RTT</th><th>Max RTT</th><th>Samples</th></tr>
`
		for _, rtt := range r.RTTAnalysis {
			html += fmt.Sprintf(`                <tr><td>%s:%d → %s:%d</td><td>%.1f ms</td><td>%.1f ms</td><td>%.1f ms</td><td>%d</td></tr>
`, rtt.SrcIP, rtt.SrcPort, rtt.DstIP, rtt.DstPort, rtt.AvgRTT, rtt.MinRTT, rtt.MaxRTT, rtt.SampleSize)
		}
		html += `            </table>
            <p><strong>⚠️ Action Required:</strong> Investigate routing paths and WAN links for latency issues.</p>
        </div>
`
	}

	// Application Breakdown
	if len(r.ApplicationBreakdown) > 0 {
		html += `        <div class="section">
            <h2>📱 Application Breakdown</h2>
            <table>
                <tr><th>Application</th><th>Port</th><th>Protocol</th><th>Packets</th><th>Data</th></tr>
`
		type appStat struct {
			name string
			app  AppCategory
		}
		var apps []appStat
		for name, app := range r.ApplicationBreakdown {
			apps = append(apps, appStat{name: name, app: app})
		}
		for i := 0; i < len(apps); i++ {
			for j := i + 1; j < len(apps); j++ {
				if apps[j].app.ByteCount > apps[i].app.ByteCount {
					apps[i], apps[j] = apps[j], apps[i]
				}
			}
		}
		for i, a := range apps {
			if i >= 15 {
				break
			}
			html += fmt.Sprintf(`                <tr><td>%s</td><td>%d</td><td>%s</td><td>%d</td><td>%.2f MB</td></tr>
`, a.app.Name, a.app.Port, a.app.Protocol, a.app.PacketCount, float64(a.app.ByteCount)/(1024*1024))
		}
		html += `            </table>
        </div>
`
	}

	// Bandwidth & Conversation Analysis
	if len(r.BandwidthReport.TopConversationsByBytes) > 0 || len(r.BandwidthReport.TopConversationsByPackets) > 0 {
		html += `        <div class="section">
            <h2>📊 Bandwidth & Conversation Analysis</h2>
            <p style="margin-bottom: 15px; padding: 10px; background: #e8f4f8; border-left: 4px solid #3498db; border-radius: 4px;">
                <strong>What This Means:</strong> This section identifies the biggest bandwidth consumers and most active 
                network conversations, similar to Wireshark's Conversations tool. Use this data to identify bandwidth hogs, 
                chatty protocols, and optimize network resource allocation.
            </p>
`

		if len(r.BandwidthReport.TopConversationsByBytes) > 0 {
			html += `            <h3 style="margin-top: 20px; color: #2196F3;">🔝 Top Conversations by Bandwidth</h3>
            <table>
                <tr><th>Flow</th><th>Protocol</th><th>Total Data</th><th>Packets</th><th>Duration</th><th>Avg Rate</th><th>Status</th></tr>
`
			for i, conv := range r.BandwidthReport.TopConversationsByBytes {
				if i >= 10 {
					break
				}

				mbps := conv.AvgBitsPerSecond / 1_000_000
				durationStr := conv.Duration.Round(time.Millisecond).String()
				badge := "badge-info"
				status := "Normal"

				if conv.TotalBytes > 10*1024*1024 {
					badge = "badge-warning"
					status = "High Bandwidth"
				}

				flowStr := ""
				if conv.Protocol == "ICMP" {
					flowStr = fmt.Sprintf("%s → %s", conv.SrcIP, conv.DstIP)
				} else {
					flowStr = fmt.Sprintf("%s:%d → %s:%d", conv.SrcIP, conv.SrcPort, conv.DstIP, conv.DstPort)
				}

				html += fmt.Sprintf(`                <tr><td>%s</td><td>%s</td><td>%.2f MB</td><td>%d</td><td>%s</td><td>%.2f Mbps</td><td><span class="badge %s">%s</span></td></tr>
`, flowStr, conv.Protocol, float64(conv.TotalBytes)/(1024*1024), conv.TotalPackets, durationStr, mbps, badge, status)
			}
			html += `            </table>
`
		}

		if len(r.BandwidthReport.TopConversationsByPackets) > 0 {
			html += `            <h3 style="margin-top: 20px; color: #9C27B0;">💬 Top Conversations by Packet Count</h3>
            <table>
                <tr><th>Flow</th><th>Protocol</th><th>Packets</th><th>Total Data</th><th>Duration</th><th>Packet Rate</th><th>Status</th></tr>
`
			for i, conv := range r.BandwidthReport.TopConversationsByPackets {
				if i >= 10 {
					break
				}

				durationStr := conv.Duration.Round(time.Millisecond).String()
				packetsPerSec := float64(0)
				if conv.Duration.Seconds() > 0 {
					packetsPerSec = float64(conv.TotalPackets) / conv.Duration.Seconds()
				}

				badge := "badge-info"
				status := "Normal"

				if conv.TotalPackets > 10000 {
					badge = "badge-warning"
					status = "Chatty"
				}

				flowStr := ""
				if conv.Protocol == "ICMP" {
					flowStr = fmt.Sprintf("%s → %s", conv.SrcIP, conv.DstIP)
				} else {
					flowStr = fmt.Sprintf("%s:%d → %s:%d", conv.SrcIP, conv.SrcPort, conv.DstIP, conv.DstPort)
				}

				html += fmt.Sprintf(`                <tr><td>%s</td><td>%s</td><td>%d</td><td>%.2f MB</td><td>%s</td><td>%.1f pkt/s</td><td><span class="badge %s">%s</span></td></tr>
`, flowStr, conv.Protocol, conv.TotalPackets, float64(conv.TotalBytes)/(1024*1024), durationStr, packetsPerSec, badge, status)
			}
			html += `            </table>
`
		}

		html += `            <p style="margin-top: 15px; padding: 10px; background: #fff3cd; border-left: 4px solid #ffc107; border-radius: 4px;">
                <strong>💡 Tip:</strong> High bandwidth flows may indicate legitimate data transfers (backups, video streaming) 
                or potential issues (data exfiltration, bandwidth abuse). Chatty connections with many small packets can impact 
                performance due to protocol overhead - consider optimizing application design or batching requests.
            </p>
        </div>
`
	}

	// Device Fingerprinting
	if len(r.DeviceFingerprinting) > 0 {
		html += `        <div class="section">
            <h2>💻 Identified Devices</h2>
            <table>
                <tr><th>IP Address</th><th>Device Type</th><th>OS Guess</th><th>Confidence</th></tr>
`
		for i, d := range r.DeviceFingerprinting {
			if i >= 15 {
				break
			}
			html += fmt.Sprintf(`                <tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>
`, d.SrcIP, d.DeviceType, d.OSGuess, d.Confidence)
		}
		html += `            </table>
        </div>
`
	}

	// Network Activity Timeline
	if len(r.Timeline) > 0 {
		html += `        <div class="section">
            <h2>📅 Network Activity Timeline</h2>
            <p style="margin-bottom: 15px; padding: 10px; background: #e8f4f8; border-left: 4px solid #3498db; border-radius: 4px;">
                <strong>What This Means:</strong> This chronological view shows significant network events detected during the capture.
                Use this to understand the sequence of events leading to issues.
            </p>
            <p>Total events: <strong>` + fmt.Sprintf("%d", len(r.Timeline)) + `</strong> (showing first 50)</p>
            <div style="max-height: 400px; overflow-y: auto; border: 1px solid #ddd; border-radius: 4px; padding: 10px; background: #f9f9f9;">
                <table style="font-size: 12px;">
                    <tr><th>Time</th><th>Event</th><th>Source</th><th>Destination</th><th>Protocol</th><th>Details</th></tr>
`
		for i, event := range r.Timeline {
			if i >= 50 {
				break
			}
			srcInfo := event.SourceIP
			if event.SourcePort != nil {
				srcInfo = fmt.Sprintf("%s:%d", event.SourceIP, *event.SourcePort)
			}
			dstInfo := event.DestinationIP
			if event.DestinationPort != nil {
				dstInfo = fmt.Sprintf("%s:%d", event.DestinationIP, *event.DestinationPort)
			}

			badgeClass := "badge-info"
			switch event.EventType {
			case "DNS_Anomaly", "ARP_Conflict", "HTTP_Error":
				badgeClass = "badge-danger"
			case "TCP_Retransmission":
				badgeClass = "badge-warning"
			case "TCP_SYN":
				badgeClass = "badge-success"
			}

			html += fmt.Sprintf(`                    <tr><td>%.3fs</td><td><span class="badge %s">%s</span></td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>
`, event.Timestamp, badgeClass, event.EventType, srcInfo, dstInfo, event.Protocol, event.Detail)
		}
		html += `                </table>
            </div>
        </div>
`
	}

	// DNS Query/Response Details
	if len(r.DNSDetails) > 0 {
		html += `        <div class="section">
            <h2>🔍 DNS Query/Response Details</h2>
            <p style="margin-bottom: 15px; padding: 10px; background: #e8f4f8; border-left: 4px solid #3498db; border-radius: 4px;">
                <strong>What This Means:</strong> Detailed DNS resolution tracking showing query-response pairs.
                This provides granular visibility into DNS resolution for confirming poisoning or other issues.
            </p>
            <p>Total DNS transactions: <strong>` + fmt.Sprintf("%d", len(r.DNSDetails)) + `</strong> (showing first 30)</p>
            <table>
                <tr><th>Time</th><th>Query</th><th>Type</th><th>From</th><th>To</th><th>Response</th><th>Status</th></tr>
`
		for i, record := range r.DNSDetails {
			if i >= 30 {
				break
			}

			responseStr := "No response"
			if record.ResponseTimestamp != nil {
				if len(record.AnswerIPs) > 0 {
					responseStr = strings.Join(record.AnswerIPs, ", ")
				} else if len(record.AnswerNames) > 0 {
					responseStr = strings.Join(record.AnswerNames, ", ")
				} else {
					responseStr = "No records"
				}
			}

			badge := "badge-success"
			status := "OK"
			if record.IsAnomalous {
				badge = "badge-danger"
				status = "ANOMALY"
			}

			html += fmt.Sprintf(`                <tr><td>%.3fs</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td><span class="badge %s">%s</span></td></tr>
`, record.QueryTimestamp, record.QueryName, record.QueryType, record.SourceIP, record.DestinationIP, responseStr, badge, status)
		}
		html += `            </table>
        </div>
`
	}

	// Footer
	html += `        <div class="footer">
            <p>Generated by SD-WAN Network Triage Tool | ` + time.Now().Format("2006-01-02 15:04:05") + `</p>
            <p>This report provides comprehensive network analysis including security threats, performance issues, and traffic patterns.</p>
        </div>
    </div>
</body>
</html>`

	_, err = file.WriteString(html)
	return err
}

// === Human Output ===
func printExecutiveSummary(r *TriageReport) {
	color.New(color.Bold, color.FgCyan).Println("═══════════════════════════════════════════════════════════════")
	color.New(color.Bold, color.FgCyan).Println("              SD-WAN NETWORK TRIAGE - EXECUTIVE SUMMARY")
	color.New(color.Bold, color.FgCyan).Println("═══════════════════════════════════════════════════════════════")
	fmt.Println()

	// Calculate severity scores
	criticalIssues := len(r.DNSAnomalies) + len(r.ARPConflicts)
	performanceIssues := len(r.TCPRetransmissions) + len(r.FailedHandshakes) + len(r.RTTAnalysis)
	securityConcerns := len(r.SuspiciousTraffic)
	expiredCerts := 0
	selfSignedCerts := 0
	for _, cert := range r.TLSCerts {
		if cert.IsExpired {
			expiredCerts++
		}
		if cert.IsSelfSigned {
			selfSignedCerts++
		}
	}
	securityConcerns += expiredCerts + selfSignedCerts

	// Determine overall health
	healthStatus := "GREEN"
	healthColor := color.FgGreen
	recommendation := "Network appears healthy. Continue monitoring."

	if criticalIssues > 0 || securityConcerns > 3 {
		healthStatus = "RED"
		healthColor = color.FgRed
		recommendation = "IMMEDIATE ACTION REQUIRED: Critical security or network issues detected."
	} else if performanceIssues > 5 || securityConcerns > 0 {
		healthStatus = "YELLOW"
		healthColor = color.FgYellow
		recommendation = "Investigation recommended: Performance degradation or security concerns detected."
	}

	color.New(color.Bold).Print("Overall Health Status: ")
	color.New(color.Bold, healthColor).Println(healthStatus)
	fmt.Println()

	// Issue breakdown
	if criticalIssues > 0 {
		color.Red("Critical Issues Found: %d", criticalIssues)
		if len(r.DNSAnomalies) > 0 {
			fmt.Printf("  • DNS Poisoning/Anomalies: %d\n", len(r.DNSAnomalies))
		}
		if len(r.ARPConflicts) > 0 {
			fmt.Printf("  • ARP Spoofing/Conflicts: %d\n", len(r.ARPConflicts))
		}
		fmt.Println()
	}

	if performanceIssues > 0 {
		color.Yellow("Performance Issues: %d", performanceIssues)
		if len(r.TCPRetransmissions) > 0 {
			fmt.Printf("  • TCP Retransmissions: %d (indicates packet loss/congestion)\n", len(r.TCPRetransmissions))
		}
		if len(r.FailedHandshakes) > 0 {
			fmt.Printf("  • Failed TCP Handshakes: %d (unreachable services)\n", len(r.FailedHandshakes))
		}
		if len(r.RTTAnalysis) > 0 {
			fmt.Printf("  • High Latency Flows: %d (RTT > 100ms)\n", len(r.RTTAnalysis))
		}
		fmt.Println()
	}

	if securityConcerns > 0 {
		color.Magenta("Security Concerns: %d", securityConcerns)
		if len(r.SuspiciousTraffic) > 0 {
			fmt.Printf("  • Suspicious Port Activity: %d\n", len(r.SuspiciousTraffic))
		}
		if expiredCerts > 0 {
			fmt.Printf("  • Expired TLS Certificates: %d\n", expiredCerts)
		}
		if selfSignedCerts > 0 {
			fmt.Printf("  • Self-Signed Certificates: %d\n", selfSignedCerts)
		}
		fmt.Println()
	}

	// Traffic summary
	if len(r.TrafficAnalysis) > 0 {
		color.Blue("Traffic Analysis:")
		fmt.Printf("  • Total Traffic: %.2f MB\n", float64(r.TotalBytes)/(1024*1024))
		fmt.Printf("  • Top Bandwidth Consumer: %s:%d → %s:%d (%.1f%%)\n",
			r.TrafficAnalysis[0].SrcIP, r.TrafficAnalysis[0].SrcPort,
			r.TrafficAnalysis[0].DstIP, r.TrafficAnalysis[0].DstPort,
			r.TrafficAnalysis[0].Percentage)
		fmt.Println()
	}

	// Recommendations
	color.New(color.Bold).Println("Recommendations:")
	fmt.Printf("  %s\n", recommendation)

	if len(r.DNSAnomalies) > 0 {
		fmt.Println("  • Investigate DNS server configuration for potential poisoning")
	}
	if len(r.ARPConflicts) > 0 {
		fmt.Println("  • Check for ARP spoofing attacks or IP conflicts")
	}
	if len(r.TCPRetransmissions) > 10 {
		fmt.Println("  • Review network links for congestion or packet loss")
	}
	if len(r.RTTAnalysis) > 0 {
		fmt.Println("  • Investigate high-latency paths for routing issues")
	}
	if len(r.SuspiciousTraffic) > 0 {
		fmt.Println("  • Review suspicious port activity for unauthorized services")
	}
	if expiredCerts > 0 {
		fmt.Println("  • Renew expired TLS certificates immediately")
	}
}

func printHuman(r *TriageReport) {
	color.New(color.Bold, color.FgCyan).Println("\n═══════════════════════════════════════════════════════════════")
	color.New(color.Bold, color.FgCyan).Println("                    DETAILED ANALYSIS REPORT")
	color.New(color.Bold, color.FgCyan).Println("═══════════════════════════════════════════════════════════════\n")

	if len(r.DNSAnomalies) > 0 {
		color.Red("━━━ [!] DNS POISONING DETECTED ━━━")
		fmt.Println("\nDNS Poisoning Detected: The following domains resolved to private/reserved IP addresses.")
		fmt.Println("This means an attacker or misconfigured server is redirecting traffic intended for public")
		fmt.Println("domains to local addresses, potentially for phishing or eavesdropping.")
		fmt.Println("\nAFFECTED DOMAINS:")
		for _, d := range r.DNSAnomalies {
			fmt.Printf("  • Domain '%s' resolved to %s\n", d.Query, d.AnswerIP)
			fmt.Printf("    Via DNS server: %s [MAC: %s]\n", d.ServerIP, d.ServerMAC)
			fmt.Printf("    ⚠ ACTION: Verify DNS server configuration and check for malware\n\n")
		}
	}

	if len(r.TCPRetransmissions) > 0 {
		color.Yellow("━━━ [!] TCP RETRANSMISSIONS DETECTED ━━━")
		fmt.Println("\nTCP Retransmissions Detected: Multiple attempts were made to send the same TCP packets.")
		fmt.Println("This usually indicates packet loss or network congestion on the path, which can severely")
		fmt.Println("degrade application performance and user experience.")
		fmt.Printf("\nTOTAL RETRANSMISSIONS: %d\n", len(r.TCPRetransmissions))
		fmt.Println("AFFECTED FLOWS (showing first 5):")
		for i, t := range r.TCPRetransmissions {
			if i >= 5 {
				break
			}
			fmt.Printf("  • %s:%d → %s:%d\n", t.SrcIP, t.SrcPort, t.DstIP, t.DstPort)
		}
		if len(r.TCPRetransmissions) > 5 {
			fmt.Printf("  ... and %d more\n", len(r.TCPRetransmissions)-5)
		}
		fmt.Println("⚠ ACTION: Check network links and QoS settings for congestion\n")
	}

	if len(r.FailedHandshakes) > 0 {
		color.Yellow("━━━ [!] FAILED TCP HANDSHAKES ━━━")
		fmt.Println("\nTCP Handshake Failed: Connection attempts failed to complete the three-way handshake.")
		fmt.Println("The destination might be down, unreachable, or blocking the connection. This prevents")
		fmt.Println("applications from establishing connections and will cause service failures.")
		fmt.Printf("\nTOTAL FAILED CONNECTIONS: %d\n", len(r.FailedHandshakes))
		fmt.Println("AFFECTED DESTINATIONS (showing first 5):")
		for i, t := range r.FailedHandshakes {
			if i >= 5 {
				break
			}
			fmt.Printf("  • %s:%d attempting to reach %s:%d\n", t.SrcIP, t.SrcPort, t.DstIP, t.DstPort)
		}
		if len(r.FailedHandshakes) > 5 {
			fmt.Printf("  ... and %d more\n", len(r.FailedHandshakes)-5)
		}
		fmt.Println("⚠ ACTION: Check firewall rules and destination service status\n")
	}

	// TCP Handshake Analysis Section
	if len(r.TCPHandshakes.SYNFlows) > 0 || len(r.TCPHandshakes.SYNACKFlows) > 0 {
		color.Cyan("━━━ [*] TCP HANDSHAKE ANALYSIS ━━━")
		fmt.Println("\nTCP Connection Establishment Analysis: Tracking SYN and SYN-ACK packets to understand")
		fmt.Println("connection initiation patterns, successful handshakes, and potential failures.")

		fmt.Printf("\nSUMMARY:\n")
		fmt.Printf("  • SYN packets (connection attempts): %d\n", len(r.TCPHandshakes.SYNFlows))
		fmt.Printf("  • SYN-ACK packets (responses): %d\n", len(r.TCPHandshakes.SYNACKFlows))
		fmt.Printf("  • Successful handshake initiations: %d\n", len(r.TCPHandshakes.SuccessfulHandshakes))
		fmt.Printf("  • Potential handshake failures: %d\n", len(r.TCPHandshakes.FailedHandshakeAttempts))

		if len(r.TCPHandshakes.SYNFlows) > 0 {
			// Sort SYN flows by count (most active first)
			synFlows := make([]TCPHandshakeFlow, len(r.TCPHandshakes.SYNFlows))
			copy(synFlows, r.TCPHandshakes.SYNFlows)
			for i := 0; i < len(synFlows); i++ {
				for j := i + 1; j < len(synFlows); j++ {
					if synFlows[j].Count > synFlows[i].Count {
						synFlows[i], synFlows[j] = synFlows[j], synFlows[i]
					}
				}
			}

			fmt.Println("\nTOP CONNECTION INITIATORS (SYN packets):")
			for i, flow := range synFlows {
				if i >= 10 {
					break
				}
				fmt.Printf("  • %s:%d → %s:%d", flow.SrcIP, flow.SrcPort, flow.DstIP, flow.DstPort)
				if flow.Count > 1 {
					fmt.Printf(" (%d attempts)", flow.Count)
				}
				fmt.Println()
				fmt.Printf("    Detected TCP connection initiation from %s:%d to %s:%d.\n",
					flow.SrcIP, flow.SrcPort, flow.DstIP, flow.DstPort)
			}
			if len(synFlows) > 10 {
				fmt.Printf("  ... and %d more\n", len(synFlows)-10)
			}
		}

		if len(r.TCPHandshakes.SYNACKFlows) > 0 {
			// Sort SYN-ACK flows by count
			synackFlows := make([]TCPHandshakeFlow, len(r.TCPHandshakes.SYNACKFlows))
			copy(synackFlows, r.TCPHandshakes.SYNACKFlows)
			for i := 0; i < len(synackFlows); i++ {
				for j := i + 1; j < len(synackFlows); j++ {
					if synackFlows[j].Count > synackFlows[i].Count {
						synackFlows[i], synackFlows[j] = synackFlows[j], synackFlows[i]
					}
				}
			}

			fmt.Println("\nTOP CONNECTION RESPONDERS (SYN-ACK packets):")
			for i, flow := range synackFlows {
				if i >= 10 {
					break
				}
				fmt.Printf("  • %s:%d → %s:%d", flow.SrcIP, flow.SrcPort, flow.DstIP, flow.DstPort)
				if flow.Count > 1 {
					fmt.Printf(" (%d responses)", flow.Count)
				}
				fmt.Println()
				fmt.Printf("    Detected TCP connection response from %s:%d to %s:%d.\n",
					flow.SrcIP, flow.SrcPort, flow.DstIP, flow.DstPort)
			}
			if len(synackFlows) > 10 {
				fmt.Printf("  ... and %d more\n", len(synackFlows)-10)
			}
		}

		if len(r.TCPHandshakes.SuccessfulHandshakes) > 0 {
			fmt.Println("\nSUCCESSFUL HANDSHAKE INITIATIONS (SYN → SYN-ACK observed):")
			for i, flow := range r.TCPHandshakes.SuccessfulHandshakes {
				if i >= 10 {
					break
				}
				fmt.Printf("  • %s:%d ↔ %s:%d", flow.SrcIP, flow.SrcPort, flow.DstIP, flow.DstPort)
				if flow.Count > 1 {
					fmt.Printf(" (%d successful handshakes)", flow.Count)
				}
				fmt.Println()
				fmt.Printf("    Detected successful TCP handshake initiation from %s:%d to %s:%d.\n",
					flow.DstIP, flow.DstPort, flow.SrcIP, flow.SrcPort)
			}
			if len(r.TCPHandshakes.SuccessfulHandshakes) > 10 {
				fmt.Printf("  ... and %d more\n", len(r.TCPHandshakes.SuccessfulHandshakes)-10)
			}
		}

		if len(r.TCPHandshakes.FailedHandshakeAttempts) > 0 {
			color.Yellow("\nPOTENTIAL HANDSHAKE FAILURES (SYN sent, no SYN-ACK received):")
			for i, flow := range r.TCPHandshakes.FailedHandshakeAttempts {
				if i >= 10 {
					break
				}
				fmt.Printf("  • %s:%d → %s:%d", flow.SrcIP, flow.SrcPort, flow.DstIP, flow.DstPort)
				if flow.Count > 1 {
					fmt.Printf(" (%d failed attempts)", flow.Count)
				}
				fmt.Println()
				fmt.Printf("    Detected potential TCP handshake failure: SYN packet sent from %s:%d to %s:%d,\n",
					flow.SrcIP, flow.SrcPort, flow.DstIP, flow.DstPort)
				fmt.Printf("    but no corresponding SYN-ACK response was observed in this capture. This could\n")
				fmt.Printf("    indicate the destination is down, unreachable, or blocking the connection.\n")
			}
			if len(r.TCPHandshakes.FailedHandshakeAttempts) > 10 {
				fmt.Printf("  ... and %d more\n", len(r.TCPHandshakes.FailedHandshakeAttempts)-10)
			}
			fmt.Println("⚠ ACTION: Investigate unreachable destinations and verify firewall rules")
		}
		fmt.Println()
	}

	if len(r.ARPConflicts) > 0 {
		color.Red("━━━ [!] ARP SPOOFING DETECTED ━━━")
		fmt.Println("\nARP Conflict Detected: The same IP address is being claimed by multiple MAC addresses.")
		fmt.Println("This is a classic sign of ARP spoofing, often used in man-in-the-middle attacks to")
		fmt.Println("intercept network traffic. This is a serious security threat.")
		fmt.Println("\nCONFLICTING ADDRESSES:")
		for _, a := range r.ARPConflicts {
			fmt.Printf("  • IP %s claimed by:\n", a.IP)
			fmt.Printf("    - MAC: %s\n", a.MAC1)
			fmt.Printf("    - MAC: %s\n", a.MAC2)
		}
		fmt.Println("⚠ ACTION: Investigate network for unauthorized devices and potential attacks\n")
	}

	if len(r.HTTPErrors) > 0 {
		color.Magenta("━━━ [!] HTTP ERRORS DETECTED ━━━")
		fmt.Println("\nHTTP Errors Detected: Received error responses (4xx/5xx) from web servers.")
		fmt.Println("This indicates the web server or application is having problems fulfilling requests.")
		fmt.Printf("\nTOTAL HTTP ERRORS: %d\n", len(r.HTTPErrors))
		fmt.Println("ERROR DETAILS:")
		for i, h := range r.HTTPErrors {
			if i >= 10 {
				break
			}
			if h.Host != "" && h.Path != "" {
				fmt.Printf("  • %d %s %s%s\n", h.Code, h.Method, h.Host, h.Path)
			} else {
				fmt.Printf("  • Status %d (Method: %s)\n", h.Code, h.Method)
			}
		}
		if len(r.HTTPErrors) > 10 {
			fmt.Printf("  ... and %d more\n", len(r.HTTPErrors)-10)
		}
		fmt.Println("⚠ ACTION: Check application server logs for root cause\n")
	}

	if len(r.SuspiciousTraffic) > 0 {
		color.Magenta("━━━ [!] SUSPICIOUS PORT ACTIVITY ━━━")
		fmt.Println("\nSuspicious Traffic Detected: Connections to ports commonly associated with malware,")
		fmt.Println("botnets, or unauthorized services. This may indicate compromised systems or policy violations.")
		fmt.Printf("\nSUSPICIOUS CONNECTIONS: %d\n", len(r.SuspiciousTraffic))
		for i, s := range r.SuspiciousTraffic {
			if i >= 10 {
				break
			}
			fmt.Printf("  • %s:%d → %s:%d (%s)\n", s.SrcIP, s.SrcPort, s.DstIP, s.DstPort, s.Protocol)
			fmt.Printf("    %s\n", s.Description)
		}
		if len(r.SuspiciousTraffic) > 10 {
			fmt.Printf("  ... and %d more\n", len(r.SuspiciousTraffic)-10)
		}
		fmt.Println("⚠ ACTION: Investigate source systems for malware or unauthorized software\n")
	}

	if len(r.TrafficAnalysis) > 0 {
		color.Blue("━━━ [*] TRAFFIC ANALYSIS - BANDWIDTH CONSUMERS ━━━")
		fmt.Println("\nTop bandwidth-consuming flows identified. Large flows may indicate legitimate data")
		fmt.Println("transfers, but could also represent bandwidth hogs or data exfiltration.")
		fmt.Printf("\nTOTAL TRAFFIC ANALYZED: %.2f MB\n", float64(r.TotalBytes)/(1024*1024))
		fmt.Println("TOP FLOWS:")
		for i, f := range r.TrafficAnalysis {
			if i >= 10 {
				break
			}
			fmt.Printf("  • Flow %s:%d → %s:%d (%s)\n", f.SrcIP, f.SrcPort, f.DstIP, f.DstPort, f.Protocol)
			fmt.Printf("    Consumed %.2f MB (%.1f%% of total traffic)", float64(f.TotalBytes)/(1024*1024), f.Percentage)
			if f.Percentage > 10 {
				fmt.Printf(" ⚠ BANDWIDTH HOG")
			}
			fmt.Println()
		}
		fmt.Println()
	}

	if len(r.RTTAnalysis) > 0 {
		color.Yellow("━━━ [!] HIGH LATENCY DETECTED ━━━")
		fmt.Println("\nHigh Round-Trip Time (RTT) detected on TCP flows. Even with good bandwidth, high")
		fmt.Println("latency severely impacts application performance, especially for interactive applications.")
		fmt.Printf("\nHIGH LATENCY FLOWS: %d (RTT > 100ms)\n", len(r.RTTAnalysis))
		for i, rtt := range r.RTTAnalysis {
			if i >= 10 {
				break
			}
			fmt.Printf("  • %s:%d → %s:%d\n", rtt.SrcIP, rtt.SrcPort, rtt.DstIP, rtt.DstPort)
			fmt.Printf("    Avg RTT: %.1fms (Min: %.1fms, Max: %.1fms, Samples: %d)\n",
				rtt.AvgRTT, rtt.MinRTT, rtt.MaxRTT, rtt.SampleSize)
		}
		if len(r.RTTAnalysis) > 10 {
			fmt.Printf("  ... and %d more\n", len(r.RTTAnalysis)-10)
		}
		fmt.Println("⚠ ACTION: Investigate routing paths and WAN links for latency issues\n")
	}

	if len(r.ApplicationBreakdown) > 0 {
		color.Cyan("━━━ [*] APPLICATION BREAKDOWN ━━━")
		fmt.Println("\nTraffic categorized by application/service based on port analysis.")
		fmt.Println("TOP APPLICATIONS:")

		type appStat struct {
			name string
			app  AppCategory
		}
		var apps []appStat
		for name, app := range r.ApplicationBreakdown {
			apps = append(apps, appStat{name: name, app: app})
		}

		for i := 0; i < len(apps); i++ {
			for j := i + 1; j < len(apps); j++ {
				if apps[j].app.ByteCount > apps[i].app.ByteCount {
					apps[i], apps[j] = apps[j], apps[i]
				}
			}
		}

		for i, a := range apps {
			if i >= 15 {
				break
			}
			fmt.Printf("  • %s (Port %d/%s): %d packets, %.2f MB\n",
				a.app.Name, a.app.Port, a.app.Protocol,
				a.app.PacketCount, float64(a.app.ByteCount)/(1024*1024))
		}
		fmt.Println()
	}

	if len(r.BandwidthReport.TopConversationsByBytes) > 0 || len(r.BandwidthReport.TopConversationsByPackets) > 0 {
		color.Cyan("━━━ [*] BANDWIDTH & CONVERSATION ANALYSIS ━━━")
		fmt.Println("\nDetailed analysis of network conversations showing the biggest bandwidth consumers and")
		fmt.Println("most active connections. This helps identify data-intensive applications and chatty protocols.")

		if len(r.BandwidthReport.TopConversationsByBytes) > 0 {
			fmt.Println("\n🔝 TOP CONVERSATIONS BY BANDWIDTH (Bytes Transferred):")
			for i, conv := range r.BandwidthReport.TopConversationsByBytes {
				if i >= 10 {
					break
				}

				mbps := conv.AvgBitsPerSecond / 1_000_000
				durationStr := conv.Duration.Round(time.Millisecond).String()

				if conv.Protocol == "ICMP" {
					fmt.Printf("  • %s → %s (%s)\n", conv.SrcIP, conv.DstIP, conv.Protocol)
				} else {
					fmt.Printf("  • %s:%d → %s:%d (%s)\n",
						conv.SrcIP, conv.SrcPort, conv.DstIP, conv.DstPort, conv.Protocol)
				}

				fmt.Printf("    Total: %.2f MB | Packets: %d | Duration: %s | Avg Rate: %.2f Mbps\n",
					float64(conv.TotalBytes)/(1024*1024), conv.TotalPackets, durationStr, mbps)

				if conv.TotalBytes > 10*1024*1024 {
					fmt.Printf("    ⚠ High Bandwidth Usage: This flow transferred %.2f MB over %s, averaging %.2f Mbps.\n",
						float64(conv.TotalBytes)/(1024*1024), durationStr, mbps)
					fmt.Printf("    This indicates a significant data transfer that may be legitimate (file transfer, video\n")
					fmt.Printf("    streaming, backup) or could represent data exfiltration or bandwidth abuse.\n")
				}
			}
			if len(r.BandwidthReport.TopConversationsByBytes) > 10 {
				fmt.Printf("  ... and %d more conversations\n", len(r.BandwidthReport.TopConversationsByBytes)-10)
			}
		}

		if len(r.BandwidthReport.TopConversationsByPackets) > 0 {
			fmt.Println("\n💬 TOP CONVERSATIONS BY PACKET COUNT (Most Active):")
			for i, conv := range r.BandwidthReport.TopConversationsByPackets {
				if i >= 10 {
					break
				}

				durationStr := conv.Duration.Round(time.Millisecond).String()
				packetsPerSec := float64(0)
				if conv.Duration.Seconds() > 0 {
					packetsPerSec = float64(conv.TotalPackets) / conv.Duration.Seconds()
				}

				if conv.Protocol == "ICMP" {
					fmt.Printf("  • %s → %s (%s)\n", conv.SrcIP, conv.DstIP, conv.Protocol)
				} else {
					fmt.Printf("  • %s:%d → %s:%d (%s)\n",
						conv.SrcIP, conv.SrcPort, conv.DstIP, conv.DstPort, conv.Protocol)
				}

				fmt.Printf("    Packets: %d | Total: %.2f MB | Duration: %s | Rate: %.1f pkt/s\n",
					conv.TotalPackets, float64(conv.TotalBytes)/(1024*1024), durationStr, packetsPerSec)

				if conv.TotalPackets > 10000 {
					fmt.Printf("    ⚠ Chatty Connection: This flow generated %d packets over %s (%.1f pkt/s).\n",
						conv.TotalPackets, durationStr, packetsPerSec)
					fmt.Printf("    This indicates a connection making many small requests/responses, which can impact\n")
					fmt.Printf("    performance due to protocol overhead and may indicate inefficient application design.\n")
				}
			}
			if len(r.BandwidthReport.TopConversationsByPackets) > 10 {
				fmt.Printf("  ... and %d more conversations\n", len(r.BandwidthReport.TopConversationsByPackets)-10)
			}
		}

		fmt.Println("ℹ Use this data to identify bandwidth hogs and optimize network resource allocation\n")
	}

	if len(r.DeviceFingerprinting) > 0 {
		color.Cyan("━━━ [*] DEVICE FINGERPRINTING ━━━")
		fmt.Println("\nDevice/OS identification based on TCP/IP stack fingerprinting. This helps understand")
		fmt.Println("network topology and identify potentially unauthorized or unexpected device types.")
		fmt.Println("\nIDENTIFIED DEVICES:")
		for i, d := range r.DeviceFingerprinting {
			if i >= 15 {
				break
			}
			fmt.Printf("  • %s: %s (%s)\n", d.SrcIP, d.OSGuess, d.DeviceType)
			fmt.Printf("    Confidence: %s | %s\n", d.Confidence, d.Details)
		}
		if len(r.DeviceFingerprinting) > 15 {
			fmt.Printf("  ... and %d more\n", len(r.DeviceFingerprinting)-15)
		}
		fmt.Println("ℹ For informational purposes to understand network topology\n")
	}

	if len(r.TLSCerts) > 0 {
		color.Cyan("━━━ [*] TLS CERTIFICATE INFORMATION ━━━")
		fmt.Println("\nTLS Certificate Info: Connections use certificates for encryption. Verify certificates")
		fmt.Println("are valid and issued by trusted Certificate Authorities (CAs).")
		fmt.Println("\nCERTIFICATES OBSERVED:")
		for i, c := range r.TLSCerts {
			if i >= 10 {
				break
			}
			status := ""
			warning := ""
			if c.IsExpired {
				status = " [EXPIRED]"
				warning = " ⚠ SECURITY RISK"
			} else if c.IsSelfSigned {
				status = " [SELF-SIGNED]"
				warning = " ⚠ VERIFY TRUST"
			}
			sniInfo := c.ServerName
			if sniInfo == "" {
				sniInfo = "no SNI"
			}
			fmt.Printf("  • %s:%d (%s)%s%s\n", c.ServerIP, c.ServerPort, sniInfo, status, warning)
			fmt.Printf("    Issuer: %s\n", c.Issuer)
			if len(c.DNSNames) > 0 && len(c.DNSNames) <= 3 {
				fmt.Printf("    SANs: %s\n", strings.Join(c.DNSNames, ", "))
			} else if len(c.DNSNames) > 3 {
				fmt.Printf("    SANs: %s, ... (%d total)\n", strings.Join(c.DNSNames[:3], ", "), len(c.DNSNames))
			}
		}
		if len(r.TLSCerts) > 10 {
			fmt.Printf("  ... and %d more\n", len(r.TLSCerts)-10)
		}
		fmt.Println()
	}

	if len(r.HTTP2Flows) > 0 {
		color.Blue("━━━ [*] MODERN PROTOCOLS - HTTP/2 ━━━")
		fmt.Println("\nHTTP/2 Detected: Modern protocol that improves performance but may bypass traditional")
		fmt.Println("security controls. Ensure your security infrastructure supports HTTP/2 inspection.")
		fmt.Printf("\nHTTP/2 FLOWS: %d\n", len(r.HTTP2Flows))
		for i, f := range r.HTTP2Flows {
			if i >= 5 {
				break
			}
			fmt.Printf("  • %s:%d → %s:%d\n", f.SrcIP, f.SrcPort, f.DstIP, f.DstPort)
		}
		if len(r.HTTP2Flows) > 5 {
			fmt.Printf("  ... and %d more\n", len(r.HTTP2Flows)-5)
		}
		fmt.Println()
	}

	if len(r.QUICFlows) > 0 {
		color.Blue("━━━ [*] MODERN PROTOCOLS - QUIC ━━━")
		fmt.Println("\nQUIC Detected: Google's UDP-based protocol used by Chrome and modern applications.")
		fmt.Println("QUIC encrypts more metadata than TLS, which can limit visibility for security tools.")
		fmt.Printf("\nQUIC FLOWS: %d\n", len(r.QUICFlows))
		for i, f := range r.QUICFlows {
			if i >= 5 {
				break
			}
			if f.ServerName != "" {
				fmt.Printf("  • %s:%d → %s:%d (%s)\n", f.SrcIP, f.SrcPort, f.DstIP, f.DstPort, f.ServerName)
			} else {
				fmt.Printf("  • %s:%d → %s:%d\n", f.SrcIP, f.SrcPort, f.DstIP, f.DstPort)
			}
		}
		if len(r.QUICFlows) > 5 {
			fmt.Printf("  ... and %d more\n", len(r.QUICFlows)-5)
		}
		fmt.Println()
	}

	// Network Activity Timeline
	if len(r.Timeline) > 0 {
		color.Cyan("━━━ [*] NETWORK ACTIVITY TIMELINE ━━━")
		fmt.Println("\nChronological view of significant network events detected during the capture.")
		fmt.Println("This helps understand the sequence of events leading to issues.")
		fmt.Printf("\nTOTAL EVENTS: %d (showing first 50)\n\n", len(r.Timeline))

		for i, event := range r.Timeline {
			if i >= 50 {
				break
			}

			portInfo := ""
			if event.SourcePort != nil && event.DestinationPort != nil {
				portInfo = fmt.Sprintf(":%d -> %s:%d", *event.SourcePort, event.DestinationIP, *event.DestinationPort)
			} else if event.DestinationPort != nil {
				portInfo = fmt.Sprintf(" -> %s:%d", event.DestinationIP, *event.DestinationPort)
			} else if event.DestinationIP != "" {
				portInfo = fmt.Sprintf(" -> %s", event.DestinationIP)
			}

			fmt.Printf("[Time: %.3fs] [%s] %s%s %s [%s]\n",
				event.Timestamp, event.EventType, event.SourceIP, portInfo, event.Protocol, event.Detail)
		}

		if len(r.Timeline) > 50 {
			fmt.Printf("\n  ... and %d more events\n", len(r.Timeline)-50)
		}
		fmt.Println()
	}

	// DNS Query/Response Details
	if len(r.DNSDetails) > 0 {
		color.Cyan("━━━ [*] DNS QUERY/RESPONSE DETAILS ━━━")
		fmt.Println("\nDetailed DNS resolution tracking showing query-response pairs.")
		fmt.Println("This provides granular visibility into DNS resolution for confirming poisoning or issues.")
		fmt.Printf("\nTOTAL DNS TRANSACTIONS: %d (showing first 30)\n\n", len(r.DNSDetails))

		for i, record := range r.DNSDetails {
			if i >= 30 {
				break
			}

			anomalyFlag := ""
			if record.IsAnomalous {
				anomalyFlag = " [ANOMALOUS!]"
			}

			fmt.Printf("[Time: %.3fs] Query: %s (%s) from %s -> %s%s\n",
				record.QueryTimestamp, record.QueryName, record.QueryType, record.SourceIP, record.DestinationIP, anomalyFlag)

			if record.ResponseTimestamp != nil {
				responseStr := ""
				if len(record.AnswerIPs) > 0 {
					responseStr = strings.Join(record.AnswerIPs, ", ")
				} else if len(record.AnswerNames) > 0 {
					responseStr = strings.Join(record.AnswerNames, ", ")
				} else {
					responseStr = "No answer records"
				}
				fmt.Printf("             Response: %s (code: %d)\n", responseStr, *record.ResponseCode)
			} else {
				fmt.Printf("             Response: No response observed\n")
			}
		}

		if len(r.DNSDetails) > 30 {
			fmt.Printf("\n  ... and %d more DNS transactions\n", len(r.DNSDetails)-30)
		}
		fmt.Println()
	}

	// BGP Analysis
	if len(r.BGPHijackIndicators) > 0 {
		color.Cyan("━━━ [*] BGP ROUTING ANALYSIS ━━━")
		fmt.Println("\nBGP routing information for external IPs detected in the capture.")
		fmt.Println("This helps identify potential BGP hijacking or routing anomalies.")
		fmt.Printf("\nIPs ANALYZED: %d\n\n", len(r.BGPHijackIndicators))

		for _, indicator := range r.BGPHijackIndicators {
			statusIcon := "✓"
			if indicator.IsAnomaly {
				statusIcon = "⚠"
				color.Red("  %s %s -> AS%d (%s)", statusIcon, indicator.IPAddress, indicator.ExpectedASN, indicator.ExpectedASName)
			} else {
				fmt.Printf("  %s %s -> AS%d (%s)\n", statusIcon, indicator.IPAddress, indicator.ExpectedASN, indicator.ExpectedASName)
			}
			fmt.Printf("    Prefix: %s | %s\n", indicator.IPPrefix, indicator.Reason)
		}
		fmt.Println()
	}

	// QoS Analysis
	if r.QoSAnalysis != nil && len(r.QoSAnalysis.ClassDistribution) > 0 {
		color.Cyan("━━━ [*] QoS/DSCP TRAFFIC ANALYSIS ━━━")
		fmt.Println("\nTraffic distribution by DSCP class (Differentiated Services Code Point).")
		fmt.Println("This shows how traffic is prioritized in your SD-WAN environment.")
		fmt.Printf("\nTOTAL PACKETS: %d\n\n", r.QoSAnalysis.TotalPackets)

		fmt.Printf("%-10s %-8s %12s %12s %10s %12s\n", "CLASS", "DSCP", "PACKETS", "BYTES", "PERCENT", "RETRANSMIT")
		fmt.Println(strings.Repeat("-", 70))

		for className, metrics := range r.QoSAnalysis.ClassDistribution {
			retransmitStr := fmt.Sprintf("%.2f%%", metrics.RetransmitRate)
			if metrics.RetransmitRate > 1.0 && (className == "EF" || strings.HasPrefix(className, "AF4")) {
				color.Red("%-10s %-8d %12d %12d %9.1f%% %12s", className, metrics.DSCPValue, metrics.PacketCount, metrics.ByteCount, metrics.Percentage, retransmitStr)
			} else {
				fmt.Printf("%-10s %-8d %12d %12d %9.1f%% %12s\n", className, metrics.DSCPValue, metrics.PacketCount, metrics.ByteCount, metrics.Percentage, retransmitStr)
			}
		}

		if len(r.QoSAnalysis.MismatchedQoS) > 0 {
			color.Yellow("\n⚠️ QoS ISSUES DETECTED:")
			for _, mismatch := range r.QoSAnalysis.MismatchedQoS {
				fmt.Printf("  • %s: %s\n", mismatch.Flow, mismatch.Reason)
			}
		}
		fmt.Println()
	}

	// Application Identification
	if len(r.AppIdentification) > 0 {
		color.Cyan("━━━ [*] APPLICATION IDENTIFICATION ━━━")
		fmt.Println("\nApplications identified through port analysis, SNI inspection, and payload heuristics.")
		fmt.Printf("\nAPPLICATIONS IDENTIFIED: %d (showing top 20)\n\n", len(r.AppIdentification))

		fmt.Printf("%-25s %-15s %-10s %12s %12s %-12s\n", "APPLICATION", "CATEGORY", "PROTOCOL", "PACKETS", "BYTES", "IDENTIFIED BY")
		fmt.Println(strings.Repeat("-", 95))

		for i, app := range r.AppIdentification {
			if i >= 20 {
				break
			}
			if app.IsSuspicious {
				color.Red("%-25s %-15s %-10s %12d %12d %-12s [SUSPICIOUS: %s]",
					app.Name, app.Category, app.Protocol, app.PacketCount, app.ByteCount, app.IdentifiedBy, app.SuspiciousReason)
			} else {
				fmt.Printf("%-25s %-15s %-10s %12d %12d %-12s\n",
					app.Name, app.Category, app.Protocol, app.PacketCount, app.ByteCount, app.IdentifiedBy)
			}
		}

		if len(r.AppIdentification) > 20 {
			fmt.Printf("\n  ... and %d more applications\n", len(r.AppIdentification)-20)
		}
		fmt.Println()
	}

	if len(r.DNSAnomalies)+len(r.TCPRetransmissions)+len(r.FailedHandshakes)+len(r.ARPConflicts)+len(r.SuspiciousTraffic) == 0 {
		color.Green("\n[✓] No critical anomalies detected. Network appears healthy.")
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// === BGP Analysis Functions ===

// BGPViewResponse represents the response from bgpview.io API
type BGPViewResponse struct {
	Status string `json:"status"`
	Data   struct {
		IP     string `json:"ip"`
		Prefix string `json:"prefix"`
		ASNs   []struct {
			ASN         int    `json:"asn"`
			Name        string `json:"name"`
			Description string `json:"description"`
			CountryCode string `json:"country_code"`
		} `json:"asns"`
	} `json:"data"`
}

func fetchBGPData(ip string) (*BGPViewResponse, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	url := fmt.Sprintf("https://api.bgpview.io/ip/%s", ip)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "SD-WAN-Triage-Tool/2.5.0")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("BGP API returned status %d", resp.StatusCode)
	}

	var bgpResp BGPViewResponse
	if err := json.NewDecoder(resp.Body).Decode(&bgpResp); err != nil {
		return nil, err
	}

	return &bgpResp, nil
}

func performBGPAnalysis(report *TriageReport) {
	color.Yellow("Performing BGP routing analysis (this may take a moment)...")

	// Collect unique external IPs to check
	targetIPs := make(map[string]bool)

	// Add IPs from DNS anomalies
	for _, anomaly := range report.DNSAnomalies {
		if !isPrivateIP(net.ParseIP(anomaly.AnswerIP)) {
			targetIPs[anomaly.AnswerIP] = true
		}
	}

	// Add IPs from high RTT flows
	for _, rtt := range report.RTTAnalysis {
		if !isPrivateIP(net.ParseIP(rtt.DstIP)) {
			targetIPs[rtt.DstIP] = true
		}
	}

	// Add IPs from top traffic flows (limit to top 10)
	for i, flow := range report.TrafficAnalysis {
		if i >= 10 {
			break
		}
		if !isPrivateIP(net.ParseIP(flow.DstIP)) {
			targetIPs[flow.DstIP] = true
		}
	}

	// Limit to 20 IPs to avoid rate limiting
	count := 0
	for ip := range targetIPs {
		if count >= 20 {
			break
		}

		bgpData, err := fetchBGPData(ip)
		if err != nil {
			continue
		}

		if bgpData.Status == "ok" && len(bgpData.Data.ASNs) > 0 {
			asn := bgpData.Data.ASNs[0]

			indicator := BGPIndicator{
				IPAddress:      ip,
				IPPrefix:       bgpData.Data.Prefix,
				ExpectedASN:    asn.ASN,
				ExpectedASName: asn.Name,
				Confidence:     "Medium",
				Reason:         fmt.Sprintf("IP %s belongs to AS%d (%s)", ip, asn.ASN, asn.Name),
				IsAnomaly:      false,
			}

			// Check for known suspicious ASNs or unexpected routing
			// This is a simplified check - in production, you'd compare against known good paths
			if asn.CountryCode != "" {
				indicator.Reason += fmt.Sprintf(" [Country: %s]", asn.CountryCode)
			}

			report.BGPHijackIndicators = append(report.BGPHijackIndicators, indicator)
		}

		count++
		time.Sleep(500 * time.Millisecond) // Rate limiting
	}

	color.Green("✓ BGP analysis complete. Checked %d IPs.", count)
}

// === QoS Analysis Functions ===

type qosTracker struct {
	classes      map[string]*QoSClassMetrics
	flowDSCP     map[string]uint8
	totalPackets uint64
	mu           sync.Mutex
}

func newQoSTracker() *qosTracker {
	return &qosTracker{
		classes:  make(map[string]*QoSClassMetrics),
		flowDSCP: make(map[string]uint8),
	}
}

func (q *qosTracker) trackPacket(dscp uint8, packetLen uint64, flowKey string) {
	q.mu.Lock()
	defer q.mu.Unlock()

	className := getDSCPClassName(dscp)

	if _, exists := q.classes[className]; !exists {
		q.classes[className] = &QoSClassMetrics{
			ClassName: className,
			DSCPValue: dscp,
		}
	}

	q.classes[className].PacketCount++
	q.classes[className].ByteCount += packetLen
	q.totalPackets++
	q.flowDSCP[flowKey] = dscp
}

func (q *qosTracker) trackRetransmission(flowKey string) {
	q.mu.Lock()
	defer q.mu.Unlock()

	if dscp, exists := q.flowDSCP[flowKey]; exists {
		className := getDSCPClassName(dscp)
		if class, exists := q.classes[className]; exists {
			class.RetransmitCount++
		}
	}
}

func getDSCPClassName(dscp uint8) string {
	if name, exists := dscpClasses[dscp]; exists {
		return name
	}
	return fmt.Sprintf("DSCP-%d", dscp)
}

func finalizeQoSAnalysis(tracker *qosTracker) *QoSReport {
	tracker.mu.Lock()
	defer tracker.mu.Unlock()

	report := &QoSReport{
		ClassDistribution: tracker.classes,
		TotalPackets:      tracker.totalPackets,
	}

	// Calculate percentages and retransmit rates
	for _, class := range tracker.classes {
		if tracker.totalPackets > 0 {
			class.Percentage = float64(class.PacketCount) / float64(tracker.totalPackets) * 100
		}
		if class.PacketCount > 0 {
			class.RetransmitRate = float64(class.RetransmitCount) / float64(class.PacketCount) * 100
		}
	}

	// Check for QoS mismatches (high priority traffic with high retransmit rate)
	for className, class := range tracker.classes {
		if (className == "EF" || strings.HasPrefix(className, "AF4")) && class.RetransmitRate > 1.0 {
			report.MismatchedQoS = append(report.MismatchedQoS, QoSMismatch{
				Flow:          className,
				ExpectedClass: "Low loss",
				ActualClass:   fmt.Sprintf("%.2f%% retransmit rate", class.RetransmitRate),
				Reason:        "High priority traffic experiencing packet loss - check QoS policy",
			})
		}
	}

	return report
}

// === Application Identification Functions ===

type appTracker struct {
	apps    map[string]*IdentifiedApp
	sniApps map[string]*IdentifiedApp
	mu      sync.Mutex
}

func newAppTracker() *appTracker {
	return &appTracker{
		apps:    make(map[string]*IdentifiedApp),
		sniApps: make(map[string]*IdentifiedApp),
	}
}

func (a *appTracker) identifyByPort(port uint16, protocol string, packetLen uint64, flowKey string) {
	a.mu.Lock()
	defer a.mu.Unlock()

	appName := ""
	category := "Unknown"

	if name, exists := wellKnownPorts[port]; exists {
		appName = name
		category = getAppCategory(name)
	} else if reason, exists := suspiciousPorts[port]; exists {
		appName = fmt.Sprintf("Suspicious-%d", port)
		category = "Suspicious"

		key := fmt.Sprintf("port-%d", port)
		if _, exists := a.apps[key]; !exists {
			a.apps[key] = &IdentifiedApp{
				Name:             appName,
				Category:         category,
				Protocol:         protocol,
				Port:             port,
				Confidence:       "High",
				IdentifiedBy:     "Port",
				IsSuspicious:     true,
				SuspiciousReason: reason,
			}
		}
		a.apps[key].PacketCount++
		a.apps[key].ByteCount += packetLen
		return
	}

	if appName != "" {
		key := fmt.Sprintf("port-%d", port)
		if _, exists := a.apps[key]; !exists {
			a.apps[key] = &IdentifiedApp{
				Name:         appName,
				Category:     category,
				Protocol:     protocol,
				Port:         port,
				Confidence:   "Medium",
				IdentifiedBy: "Port",
			}
		}
		a.apps[key].PacketCount++
		a.apps[key].ByteCount += packetLen
	}
}

func (a *appTracker) identifyBySNI(sni string, packetLen uint64) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if sni == "" {
		return
	}

	appName := categorizeByDomain(sni)
	category := "Web Service"

	if _, exists := a.sniApps[sni]; !exists {
		a.sniApps[sni] = &IdentifiedApp{
			Name:         appName,
			Category:     category,
			Protocol:     "TLS",
			SNI:          sni,
			Confidence:   "High",
			IdentifiedBy: "SNI",
		}
	}
	a.sniApps[sni].PacketCount++
	a.sniApps[sni].ByteCount += packetLen
}

func (a *appTracker) identifyByPayload(payload []byte, port uint16, protocol string, packetLen uint64) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if len(payload) < 4 {
		return
	}

	// SSH detection
	if len(payload) >= 4 && string(payload[:4]) == "SSH-" {
		key := "payload-SSH"
		if _, exists := a.apps[key]; !exists {
			a.apps[key] = &IdentifiedApp{
				Name:         "SSH",
				Category:     "Remote Access",
				Protocol:     protocol,
				Port:         port,
				Confidence:   "High",
				IdentifiedBy: "Payload",
			}
		}
		a.apps[key].PacketCount++
		a.apps[key].ByteCount += packetLen
		return
	}

	// HTTP detection
	if len(payload) >= 4 && (string(payload[:4]) == "GET " || string(payload[:4]) == "POST" || string(payload[:4]) == "HTTP") {
		key := "payload-HTTP"
		if _, exists := a.apps[key]; !exists {
			a.apps[key] = &IdentifiedApp{
				Name:         "HTTP",
				Category:     "Web",
				Protocol:     protocol,
				Port:         port,
				Confidence:   "High",
				IdentifiedBy: "Payload",
			}
		}
		a.apps[key].PacketCount++
		a.apps[key].ByteCount += packetLen
		return
	}

	// SMB detection
	if len(payload) >= 4 && payload[0] == 0xff && string(payload[1:4]) == "SMB" {
		key := "payload-SMB"
		if _, exists := a.apps[key]; !exists {
			a.apps[key] = &IdentifiedApp{
				Name:         "SMB",
				Category:     "File Sharing",
				Protocol:     protocol,
				Port:         port,
				Confidence:   "High",
				IdentifiedBy: "Payload",
			}
		}
		a.apps[key].PacketCount++
		a.apps[key].ByteCount += packetLen
	}
}

func categorizeByDomain(domain string) string {
	domain = strings.ToLower(domain)

	// Common service patterns
	patterns := map[string]string{
		"google":     "Google Services",
		"facebook":   "Facebook",
		"microsoft":  "Microsoft Services",
		"apple":      "Apple Services",
		"amazon":     "Amazon Services",
		"netflix":    "Netflix",
		"youtube":    "YouTube",
		"zoom":       "Zoom",
		"slack":      "Slack",
		"github":     "GitHub",
		"cloudflare": "Cloudflare",
		"akamai":     "Akamai CDN",
	}

	for pattern, name := range patterns {
		if strings.Contains(domain, pattern) {
			return name
		}
	}

	return domain
}

func getAppCategory(appName string) string {
	categories := map[string]string{
		"HTTP":       "Web",
		"HTTPS":      "Web",
		"HTTP-Alt":   "Web",
		"HTTPS-Alt":  "Web",
		"FTP":        "File Transfer",
		"FTP-Data":   "File Transfer",
		"SSH":        "Remote Access",
		"Telnet":     "Remote Access",
		"RDP":        "Remote Access",
		"VNC":        "Remote Access",
		"DNS":        "Network",
		"SMTP":       "Email",
		"SMTPS":      "Email",
		"POP3":       "Email",
		"POP3S":      "Email",
		"IMAP":       "Email",
		"IMAPS":      "Email",
		"MySQL":      "Database",
		"PostgreSQL": "Database",
		"Redis":      "Database",
		"SMB":        "File Sharing",
	}

	if cat, exists := categories[appName]; exists {
		return cat
	}
	return "Other"
}

func finalizeAppIdentification(tracker *appTracker) []IdentifiedApp {
	tracker.mu.Lock()
	defer tracker.mu.Unlock()

	var apps []IdentifiedApp

	// Add port-based apps
	for _, app := range tracker.apps {
		apps = append(apps, *app)
	}

	// Add SNI-based apps
	for _, app := range tracker.sniApps {
		apps = append(apps, *app)
	}

	// Sort by packet count
	for i := 0; i < len(apps); i++ {
		for j := i + 1; j < len(apps); j++ {
			if apps[j].PacketCount > apps[i].PacketCount {
				apps[i], apps[j] = apps[j], apps[i]
			}
		}
	}

	return apps
}

// === External Integration Functions ===

func sendToSyslog(server string, report *TriageReport) error {
	conn, err := net.Dial("udp", server)
	if err != nil {
		return fmt.Errorf("failed to connect to syslog server: %v", err)
	}
	defer conn.Close()

	// Send alerts for critical findings
	alertCount := 0

	// DNS Anomalies
	for _, anomaly := range report.DNSAnomalies {
		msg := fmt.Sprintf("<14>SD-WAN-Triage: DNS_ANOMALY query=%s answer=%s server=%s reason=%s",
			anomaly.Query, anomaly.AnswerIP, anomaly.ServerIP, anomaly.Reason)
		conn.Write([]byte(msg))
		alertCount++
	}

	// ARP Conflicts
	for _, conflict := range report.ARPConflicts {
		msg := fmt.Sprintf("<12>SD-WAN-Triage: ARP_CONFLICT ip=%s mac1=%s mac2=%s",
			conflict.IP, conflict.MAC1, conflict.MAC2)
		conn.Write([]byte(msg))
		alertCount++
	}

	// High retransmission flows
	for _, flow := range report.TCPRetransmissions {
		msg := fmt.Sprintf("<13>SD-WAN-Triage: TCP_RETRANSMISSION src=%s:%d dst=%s:%d",
			flow.SrcIP, flow.SrcPort, flow.DstIP, flow.DstPort)
		conn.Write([]byte(msg))
		alertCount++
		if alertCount >= 100 {
			break
		}
	}

	color.Green("✓ Sent %d alerts to Syslog server %s", alertCount, server)
	return nil
}

func sendToSplunk(hecURL, token string, report *TriageReport) error {
	client := &http.Client{Timeout: 30 * time.Second}

	// Create events for critical findings
	events := []map[string]interface{}{}

	// DNS Anomalies
	for _, anomaly := range report.DNSAnomalies {
		events = append(events, map[string]interface{}{
			"event": map[string]interface{}{
				"type":      "DNS_ANOMALY",
				"query":     anomaly.Query,
				"answer_ip": anomaly.AnswerIP,
				"server_ip": anomaly.ServerIP,
				"reason":    anomaly.Reason,
				"timestamp": anomaly.Timestamp,
			},
			"sourcetype": "sdwan:triage",
			"source":     "sdwan-triage-tool",
		})
	}

	// ARP Conflicts
	for _, conflict := range report.ARPConflicts {
		events = append(events, map[string]interface{}{
			"event": map[string]interface{}{
				"type": "ARP_CONFLICT",
				"ip":   conflict.IP,
				"mac1": conflict.MAC1,
				"mac2": conflict.MAC2,
			},
			"sourcetype": "sdwan:triage",
			"source":     "sdwan-triage-tool",
		})
	}

	// BGP Indicators
	for _, indicator := range report.BGPHijackIndicators {
		if indicator.IsAnomaly {
			events = append(events, map[string]interface{}{
				"event": map[string]interface{}{
					"type":         "BGP_ANOMALY",
					"ip":           indicator.IPAddress,
					"prefix":       indicator.IPPrefix,
					"expected_asn": indicator.ExpectedASN,
					"reason":       indicator.Reason,
				},
				"sourcetype": "sdwan:triage",
				"source":     "sdwan-triage-tool",
			})
		}
	}

	// Send events in batches
	for _, event := range events {
		jsonData, err := json.Marshal(event)
		if err != nil {
			continue
		}

		req, err := http.NewRequest("POST", hecURL, strings.NewReader(string(jsonData)))
		if err != nil {
			continue
		}

		req.Header.Set("Authorization", "Splunk "+token)
		req.Header.Set("Content-Type", "application/json")

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		resp.Body.Close()
	}

	color.Green("✓ Sent %d events to Splunk HEC", len(events))
	return nil
}

// === Multi-PCAP Comparison Functions ===

type ComparisonReport struct {
	Files          []string               `json:"files"`
	Reports        []*TriageReport        `json:"reports"`
	Differences    []ComparisonDifference `json:"differences"`
	CommonFindings []string               `json:"common_findings"`
	UniqueFindings map[string][]string    `json:"unique_findings"`
}

type ComparisonDifference struct {
	Category    string `json:"category"`
	Description string `json:"description"`
	File1Value  string `json:"file1_value"`
	File2Value  string `json:"file2_value"`
	Severity    string `json:"severity"`
}

func compareReports(pcapFiles []string, filter *Filter, jsonOutput bool, htmlOutput string, csvOutput string) {
	color.Cyan("Comparing %d PCAP files...\n", len(pcapFiles))

	var reports []*TriageReport

	// Analyze each PCAP file
	for i, pcapFile := range pcapFiles {
		color.Yellow("Analyzing file %d/%d: %s", i+1, len(pcapFiles), pcapFile)

		report, err := analyzeSinglePCAP(pcapFile, filter)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error analyzing %s: %v\n", pcapFile, err)
			continue
		}
		reports = append(reports, report)
	}

	if len(reports) < 2 {
		fmt.Fprintf(os.Stderr, "Error: Need at least 2 successfully analyzed files to compare\n")
		os.Exit(1)
	}

	// Generate comparison report
	comparison := generateComparison(pcapFiles, reports)

	// Output comparison
	if jsonOutput {
		jsonData, _ := json.MarshalIndent(comparison, "", "  ")
		fmt.Println(string(jsonData))
	} else {
		printComparisonReport(comparison)
	}
}

func analyzeSinglePCAP(pcapFile string, filter *Filter) (*TriageReport, error) {
	file, err := os.Open(pcapFile)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	reader, err := pcapgo.NewReader(file)
	if err != nil {
		return nil, err
	}

	report := &TriageReport{}
	report.ApplicationBreakdown = make(map[string]AppCategory)

	// Simplified analysis for comparison mode
	packetSource := gopacket.NewPacketSource(reader, reader.LinkType())

	for packet := range packetSource.Packets() {
		if packet == nil {
			continue
		}

		// Basic packet counting
		if packet.NetworkLayer() != nil {
			report.TotalBytes += uint64(len(packet.Data()))
		}

		// DNS analysis
		if dnsLayer := packet.Layer(layers.LayerTypeDNS); dnsLayer != nil {
			dns := dnsLayer.(*layers.DNS)
			if dns.QR && len(dns.Answers) > 0 {
				for _, q := range dns.Questions {
					queryName := string(q.Name)
					for _, a := range dns.Answers {
						if a.IP != nil && isPrivateIP(a.IP) && publicDomainRegex.MatchString(queryName) {
							report.DNSAnomalies = append(report.DNSAnomalies, DNSAnomaly{
								Query:    queryName,
								AnswerIP: a.IP.String(),
								Reason:   "Public domain resolving to private IP",
							})
						}
					}
				}
			}
		}
	}

	return report, nil
}

func generateComparison(files []string, reports []*TriageReport) *ComparisonReport {
	comparison := &ComparisonReport{
		Files:          files,
		Reports:        reports,
		UniqueFindings: make(map[string][]string),
	}

	if len(reports) < 2 {
		return comparison
	}

	r1, r2 := reports[0], reports[1]

	// Compare DNS anomalies
	if len(r1.DNSAnomalies) != len(r2.DNSAnomalies) {
		comparison.Differences = append(comparison.Differences, ComparisonDifference{
			Category:    "DNS Anomalies",
			Description: "Different number of DNS anomalies detected",
			File1Value:  fmt.Sprintf("%d anomalies", len(r1.DNSAnomalies)),
			File2Value:  fmt.Sprintf("%d anomalies", len(r2.DNSAnomalies)),
			Severity:    "High",
		})
	}

	// Compare ARP conflicts
	if len(r1.ARPConflicts) != len(r2.ARPConflicts) {
		comparison.Differences = append(comparison.Differences, ComparisonDifference{
			Category:    "ARP Conflicts",
			Description: "Different number of ARP conflicts detected",
			File1Value:  fmt.Sprintf("%d conflicts", len(r1.ARPConflicts)),
			File2Value:  fmt.Sprintf("%d conflicts", len(r2.ARPConflicts)),
			Severity:    "High",
		})
	}

	// Compare TCP retransmissions
	if len(r1.TCPRetransmissions) != len(r2.TCPRetransmissions) {
		diff := len(r2.TCPRetransmissions) - len(r1.TCPRetransmissions)
		severity := "Low"
		if diff > 100 || diff < -100 {
			severity = "Medium"
		}
		comparison.Differences = append(comparison.Differences, ComparisonDifference{
			Category:    "TCP Retransmissions",
			Description: "Different number of TCP retransmissions",
			File1Value:  fmt.Sprintf("%d retransmissions", len(r1.TCPRetransmissions)),
			File2Value:  fmt.Sprintf("%d retransmissions", len(r2.TCPRetransmissions)),
			Severity:    severity,
		})
	}

	// Compare total bytes
	if r1.TotalBytes != r2.TotalBytes {
		comparison.Differences = append(comparison.Differences, ComparisonDifference{
			Category:    "Traffic Volume",
			Description: "Different total traffic volume",
			File1Value:  fmt.Sprintf("%.2f MB", float64(r1.TotalBytes)/(1024*1024)),
			File2Value:  fmt.Sprintf("%.2f MB", float64(r2.TotalBytes)/(1024*1024)),
			Severity:    "Info",
		})
	}

	// Find unique DNS anomalies
	r1Queries := make(map[string]bool)
	for _, a := range r1.DNSAnomalies {
		r1Queries[a.Query] = true
	}
	for _, a := range r2.DNSAnomalies {
		if !r1Queries[a.Query] {
			comparison.UniqueFindings[files[1]] = append(comparison.UniqueFindings[files[1]],
				fmt.Sprintf("New DNS anomaly: %s -> %s", a.Query, a.AnswerIP))
		}
	}

	r2Queries := make(map[string]bool)
	for _, a := range r2.DNSAnomalies {
		r2Queries[a.Query] = true
	}
	for _, a := range r1.DNSAnomalies {
		if !r2Queries[a.Query] {
			comparison.UniqueFindings[files[0]] = append(comparison.UniqueFindings[files[0]],
				fmt.Sprintf("DNS anomaly not in second capture: %s -> %s", a.Query, a.AnswerIP))
		}
	}

	return comparison
}

func printComparisonReport(comparison *ComparisonReport) {
	color.Cyan("\n━━━ PCAP COMPARISON REPORT ━━━\n")

	fmt.Printf("Files compared:\n")
	for i, f := range comparison.Files {
		fmt.Printf("  [%d] %s\n", i+1, f)
	}
	fmt.Println()

	if len(comparison.Differences) == 0 {
		color.Green("No significant differences found between captures.\n")
		return
	}

	color.Yellow("━━━ DIFFERENCES FOUND ━━━\n")
	for _, diff := range comparison.Differences {
		severityColor := color.New(color.FgWhite)
		switch diff.Severity {
		case "High":
			severityColor = color.New(color.FgRed)
		case "Medium":
			severityColor = color.New(color.FgYellow)
		case "Low":
			severityColor = color.New(color.FgCyan)
		}

		severityColor.Printf("[%s] ", diff.Severity)
		fmt.Printf("%s: %s\n", diff.Category, diff.Description)
		fmt.Printf("  File 1: %s\n", diff.File1Value)
		fmt.Printf("  File 2: %s\n\n", diff.File2Value)
	}

	if len(comparison.UniqueFindings) > 0 {
		color.Yellow("━━━ UNIQUE FINDINGS ━━━\n")
		for file, findings := range comparison.UniqueFindings {
			fmt.Printf("Unique to %s:\n", file)
			for _, finding := range findings {
				fmt.Printf("  • %s\n", finding)
			}
			fmt.Println()
		}
	}
}
