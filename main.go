package main

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"regexp"
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
	DNSAnomalies         []DNSAnomaly           `json:"dns_anomalies"`
	TCPRetransmissions   []TCPFlow              `json:"tcp_retransmissions"`
	FailedHandshakes     []TCPFlow              `json:"failed_handshakes"`
	ARPConflicts         []ARPConflict          `json:"arp_conflicts"`
	HTTPErrors           []HTTPError            `json:"http_errors"`
	TLSCerts             []TLSCertInfo          `json:"tls_certs"`
	HTTP2Flows           []TCPFlow              `json:"http2_flows"`
	QUICFlows            []UDPFlow              `json:"quic_flows"`
	TrafficAnalysis      []TrafficFlow          `json:"traffic_analysis"`
	ApplicationBreakdown map[string]AppCategory `json:"application_breakdown"`
	SuspiciousTraffic    []SuspiciousFlow       `json:"suspicious_traffic"`
	RTTAnalysis          []RTTFlow              `json:"rtt_analysis"`
	DeviceFingerprinting []DeviceFingerprint    `json:"device_fingerprinting"`
	TotalBytes           uint64                 `json:"total_bytes"`
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

// === Internal Tracking Structures ===
type tcpFlowState struct {
	lastSeq    uint32
	lastAck    uint32
	seqSeen    map[uint32]bool
	rttSamples []float64
	sentTimes  map[uint32]time.Time
	totalBytes uint64
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

		label := fmt.Sprintf("%s:%d|%s", protocolStr, primaryPort, sizeStr)

		// Add edge with label
		if path.HasAnomaly {
			mermaid += fmt.Sprintf("    %s[\"%s\"] -.->|%s| %s[\"%s\"]\n", srcID, path.SrcIP, label, dstID, path.DstIP)
		} else {
			mermaid += fmt.Sprintf("    %s[\"%s\"] -->|%s| %s[\"%s\"]\n", srcID, path.SrcIP, label, dstID, path.DstIP)
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

DESCRIPTION:
    This tool performs comprehensive network analysis on PCAP capture files to identify:
    - Security threats (DNS poisoning, ARP spoofing, suspicious ports)
    - Performance issues (TCP retransmissions, high latency, failed connections)
    - Traffic patterns (bandwidth hogs, application breakdown, device fingerprinting)

    The analysis includes detailed explanations and actionable recommendations for
    network engineers and IT administrators.

VERSION:
    SD-WAN Triage v2.0.0

`)
	}

	var jsonOutput = flag.Bool("json", false, "Output in JSON format")
	var csvOutput = flag.String("csv", "", "Export findings to CSV file")
	var htmlOutput = flag.String("html", "", "Export findings to HTML report")
	var srcIP = flag.String("src-ip", "", "Filter by source IP address")
	var dstIP = flag.String("dst-ip", "", "Filter by destination IP address")
	var service = flag.String("service", "", "Filter by service port or name")
	var protocol = flag.String("protocol", "", "Filter by protocol (tcp or udp)")
	var showHelp = flag.Bool("help", false, "Show help message")
	flag.Parse()

	// Show help if requested or no arguments provided
	if *showHelp || flag.NArg() != 1 {
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
	var mu sync.Mutex

	// Initialize ApplicationBreakdown map
	report.ApplicationBreakdown = make(map[string]AppCategory)

	packetSource := gopacket.NewPacketSource(reader, reader.LinkType())
	for packet := range packetSource.Packets() {
		analyzePacket(packet, synSent, synAckReceived, arpIPToMAC, dnsQueries, tcpFlows, udpFlows, httpRequests, tlsSNICache, deviceFingerprints, appStats, report, &mu, filter, pathStats)
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
	} else if *htmlOutput != "" {
		filename := *htmlOutput
		if filename == "" {
			filename = "output.html"
		}
		if err := exportToHTML(report, filename, pathStats, filter); err != nil {
			fmt.Fprintf(os.Stderr, "Error exporting to HTML: %v\n", err)
			os.Exit(1)
		}
		color.Green("✓ Report exported to %s", filename)
	} else {
		printExecutiveSummary(report)
		fmt.Println()
		printHuman(report)
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

	// DNS
	if dnsLayer := packet.Layer(layers.LayerTypeDNS); dnsLayer != nil {
		dns := dnsLayer.(*layers.DNS)
		netLayer := packet.NetworkLayer()
		linkLayer := packet.LinkLayer()
		if netLayer == nil || linkLayer == nil {
			return
		}
		ip := netLayer.NetworkFlow().Dst().String()
		eth, _ := linkLayer.(*layers.Ethernet)
		mac := eth.SrcMAC.String()

		if !dns.QR { // Query
			if len(dns.Questions) > 0 {
				mu.Lock()
				dnsQueries[dns.ID] = string(dns.Questions[0].Name)
				mu.Unlock()
			}
		} else { // Response
			mu.Lock()
			queryName := dnsQueries[dns.ID]
			mu.Unlock()

			for _, ans := range dns.Answers {
				if ans.IP != nil {
					ansIP := ans.IP.String()
					if isPublicDomain(queryName) && isPrivateOrReservedIP(ansIP) {
						report.DNSAnomalies = append(report.DNSAnomalies, DNSAnomaly{
							Timestamp: packet.Metadata().Timestamp.Sub(packet.Metadata().CaptureInfo.Timestamp).Seconds(),
							Query:     queryName,
							AnswerIP:  ansIP,
							ServerIP:  ip,
							ServerMAC: mac,
							Reason:    "Public domain resolved to private/reserved IP",
						})
					}
				}
			}
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
			key := fmt.Sprintf("%s:%d->%s:%d", ip4.SrcIP.String(), tcp.SrcPort, ip4.DstIP.String(), tcp.DstPort)
			revKey := fmt.Sprintf("%s:%d->%s:%d", ip4.DstIP.String(), tcp.DstPort, ip4.SrcIP.String(), tcp.SrcPort)

			// Device fingerprinting on SYN packets
			if tcp.SYN && !tcp.ACK {
				synSent[key] = packet
				fp := extractTCPFingerprint(tcp, ip4)
				mu.Lock()
				deviceFingerprints[ip4.SrcIP.String()] = fp
				mu.Unlock()
			}
			if tcp.SYN && tcp.ACK {
				synAckReceived[revKey] = true
			}

			// Enhanced retransmission detection with sequence and acknowledgment tracking
			flowKey := fmt.Sprintf("%s:%d->%s:%d", ip4.SrcIP.String(), tcp.SrcPort, ip4.DstIP.String(), tcp.DstPort)
			mu.Lock()
			flow, exists := tcpFlows[flowKey]
			if !exists {
				flow = &tcpFlowState{
					lastSeq:    tcp.Seq,
					lastAck:    tcp.Ack,
					seqSeen:    make(map[uint32]bool),
					rttSamples: []float64{},
					sentTimes:  make(map[uint32]time.Time),
					totalBytes: 0,
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

			// Detect retransmission: same sequence number seen before with payload
			if len(tcp.Payload) > 0 {
				if flow.seqSeen[tcp.Seq] {
					srcIP := ip4.SrcIP.String()
					dstIP := ip4.DstIP.String()
					report.TCPRetransmissions = append(report.TCPRetransmissions, TCPFlow{
						SrcIP: srcIP, SrcPort: uint16(tcp.SrcPort),
						DstIP: dstIP, DstPort: uint16(tcp.DstPort),
					})
					// Mark path with anomaly for diagram highlighting
					markPathAnomaly(pathStats, srcIP, dstIP)
				} else {
					flow.seqSeen[tcp.Seq] = true
				}
				flow.lastSeq = tcp.Seq
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

							report.HTTPErrors = append(report.HTTPErrors, HTTPError{
								Timestamp: packet.Metadata().Timestamp.Sub(packet.Metadata().CaptureInfo.Timestamp).Seconds(),
								Method:    method,
								Host:      host,
								Path:      path,
								Code:      statusCode,
							})
						}
					}
				}
			}
		}
	}

	// HTTP/2 detection via ALPN in TLS handshake
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp := tcpLayer.(*layers.TCP)
		payload := tcp.Payload
		// TLS handshake starts with 0x16 (handshake record type)
		if len(payload) > 5 && payload[0] == 0x16 && payload[1] == 0x03 {
			// Check for ALPN "h2" in ClientHello (simplified heuristic)
			if len(payload) > 100 && strings.Contains(string(payload), "h2") {
				netLayer := packet.NetworkLayer()
				if ip4, ok := netLayer.(*layers.IPv4); ok {
					report.HTTP2Flows = append(report.HTTP2Flows, TCPFlow{
						SrcIP: ip4.SrcIP.String(), SrcPort: uint16(tcp.SrcPort),
						DstIP: ip4.DstIP.String(), DstPort: uint16(tcp.DstPort),
					})
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

	return nil
}

func exportToHTML(r *TriageReport, filename string, pathStats *PathStats, filter *Filter) error {
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

	// Write HTML
	html := `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SD-WAN Network Triage Report</title>
    <script src="https://cdn.jsdelivr.net/npm/mermaid@10/dist/mermaid.min.js"></script>
    <script>
        mermaid.initialize({ startOnLoad: true, theme: 'default', securityLevel: 'loose' });
    </script>
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
