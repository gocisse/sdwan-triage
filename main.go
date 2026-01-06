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
	DNSAnomalies       []DNSAnomaly  `json:"dns_anomalies"`
	TCPRetransmissions []TCPFlow     `json:"tcp_retransmissions"`
	FailedHandshakes   []TCPFlow     `json:"failed_handshakes"`
	ARPConflicts       []ARPConflict `json:"arp_conflicts"`
	HTTPErrors         []HTTPError   `json:"http_errors"`
	TLSCerts           []TLSCertInfo `json:"tls_certs"`
	HTTP2Flows         []TCPFlow     `json:"http2_flows"`
	QUICFlows          []UDPFlow     `json:"quic_flows"`
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

// === Internal Tracking Structures ===
type tcpFlowState struct {
	lastSeq uint32
	lastAck uint32
	seqSeen map[uint32]bool
}

type httpRequest struct {
	method    string
	host      string
	path      string
	timestamp time.Time
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

// Parse HTTP request from TCP payload
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

// === Main ===
func main() {
	var jsonOutput = flag.Bool("json", false, "Output in JSON format")
	flag.Parse()

	if flag.NArg() != 1 {
		fmt.Fprintf(os.Stderr, "Usage: %s [-json] <capture.pcap>\n", os.Args[0])
		os.Exit(1)
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
	httpRequests := make(map[string]*httpRequest)
	tlsSNICache := make(map[string]string)
	var mu sync.Mutex

	packetSource := gopacket.NewPacketSource(reader, reader.LinkType())
	for packet := range packetSource.Packets() {
		analyzePacket(packet, synSent, synAckReceived, arpIPToMAC, dnsQueries, tcpFlows, httpRequests, tlsSNICache, report, &mu)
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

	if *jsonOutput {
		data, _ := json.MarshalIndent(report, "", "  ")
		fmt.Println(string(data))
	} else {
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
	httpRequests map[string]*httpRequest,
	tlsSNICache map[string]string,
	report *TriageReport,
	mu *sync.Mutex,
) {
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

			if tcp.SYN && !tcp.ACK {
				synSent[key] = packet
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
					lastSeq: tcp.Seq,
					lastAck: tcp.Ack,
					seqSeen: make(map[uint32]bool),
				}
				tcpFlows[flowKey] = flow
			}

			// Detect retransmission: same sequence number seen before with payload
			if len(tcp.Payload) > 0 {
				if flow.seqSeen[tcp.Seq] {
					report.TCPRetransmissions = append(report.TCPRetransmissions, TCPFlow{
						SrcIP: ip4.SrcIP.String(), SrcPort: uint16(tcp.SrcPort),
						DstIP: ip4.DstIP.String(), DstPort: uint16(tcp.DstPort),
					})
				} else {
					flow.seqSeen[tcp.Seq] = true
				}
				flow.lastSeq = tcp.Seq
			}
			if tcp.ACK {
				flow.lastAck = tcp.Ack
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

	// QUIC - Enhanced detection with SNI extraction
	if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp := udpLayer.(*layers.UDP)
		if udp.DstPort == 443 || udp.SrcPort == 443 {
			payload := udp.Payload
			if len(payload) > 0 {
				// QUIC long header: first 2 bits = 0b11 (0xC0)
				if payload[0]&0xC0 == 0xC0 {
					netLayer := packet.NetworkLayer()
					if ip4, ok := netLayer.(*layers.IPv4); ok {
						// Try to extract SNI from QUIC Initial packet
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

// === Human Output ===
func printHuman(r *TriageReport) {
	if len(r.DNSAnomalies) > 0 {
		color.Red("[!] DNS Anomalies")
		for _, d := range r.DNSAnomalies {
			fmt.Printf("    %s → %s (via %s [%s]) — %s\n",
				d.Query, d.AnswerIP, d.ServerIP, d.ServerMAC, d.Reason)
		}
		fmt.Println()
	}
	if len(r.TCPRetransmissions) > 0 {
		color.Yellow("[!] TCP Retransmissions (%d)", len(r.TCPRetransmissions))
		for i, t := range r.TCPRetransmissions {
			if i >= 5 {
				break
			}
			fmt.Printf("    %s:%d → %s:%d\n", t.SrcIP, t.SrcPort, t.DstIP, t.DstPort)
		}
		if len(r.TCPRetransmissions) > 5 {
			fmt.Println("    ...")
		}
		fmt.Println()
	}
	if len(r.FailedHandshakes) > 0 {
		color.Yellow("[!] Failed Handshakes (%d)", len(r.FailedHandshakes))
		for i, t := range r.FailedHandshakes {
			if i >= 5 {
				break
			}
			fmt.Printf("    %s:%d → %s:%d\n", t.SrcIP, t.SrcPort, t.DstIP, t.DstPort)
		}
		if len(r.FailedHandshakes) > 5 {
			fmt.Println("    ...")
		}
		fmt.Println()
	}
	if len(r.ARPConflicts) > 0 {
		color.Red("[!] ARP Conflicts")
		for _, a := range r.ARPConflicts {
			fmt.Printf("    IP %s: %s vs %s\n", a.IP, a.MAC1, a.MAC2)
		}
		fmt.Println()
	}
	if len(r.HTTPErrors) > 0 {
		color.Magenta("[!] HTTP Errors")
		for _, h := range r.HTTPErrors {
			if h.Host != "" && h.Path != "" {
				fmt.Printf("    %d %s %s%s\n", h.Code, h.Method, h.Host, h.Path)
			} else {
				fmt.Printf("    %d (Method: %s, Host: %s)\n", h.Code, h.Method, h.Host)
			}
		}
		fmt.Println()
	}
	if len(r.TLSCerts) > 0 {
		color.Cyan("[*] TLS Certificates")
		for _, c := range r.TLSCerts {
			status := ""
			if c.IsExpired {
				status = " [EXPIRED]"
			} else if c.IsSelfSigned {
				status = " [SELF-SIGNED]"
			}
			sniInfo := c.ServerName
			if sniInfo == "" {
				sniInfo = "no SNI"
			}
			fmt.Printf("    %s:%d (%s) — %s%s\n", c.ServerIP, c.ServerPort, sniInfo, c.Issuer, status)
			if len(c.DNSNames) > 0 && len(c.DNSNames) <= 3 {
				fmt.Printf("      SANs: %s\n", strings.Join(c.DNSNames, ", "))
			} else if len(c.DNSNames) > 3 {
				fmt.Printf("      SANs: %s, ... (%d total)\n", strings.Join(c.DNSNames[:3], ", "), len(c.DNSNames))
			}
		}
		fmt.Println()
	}
	if len(r.HTTP2Flows) > 0 {
		color.Blue("[*] HTTP/2 Flows (%d)", len(r.HTTP2Flows))
		for _, f := range r.HTTP2Flows[:min(5, len(r.HTTP2Flows))] {
			fmt.Printf("    %s:%d → %s:%d\n", f.SrcIP, f.SrcPort, f.DstIP, f.DstPort)
		}
		if len(r.HTTP2Flows) > 5 {
			fmt.Println("    ...")
		}
		fmt.Println()
	}
	if len(r.QUICFlows) > 0 {
		color.Blue("[*] QUIC Flows (%d)", len(r.QUICFlows))
		for _, f := range r.QUICFlows[:min(5, len(r.QUICFlows))] {
			if f.ServerName != "" {
				fmt.Printf("    %s:%d → %s:%d (%s)\n", f.SrcIP, f.SrcPort, f.DstIP, f.DstPort, f.ServerName)
			} else {
				fmt.Printf("    %s:%d → %s:%d\n", f.SrcIP, f.SrcPort, f.DstIP, f.DstPort)
			}
		}
		if len(r.QUICFlows) > 5 {
			fmt.Println("    ...")
		}
		fmt.Println()
	}
	if len(r.DNSAnomalies)+len(r.TCPRetransmissions)+len(r.FailedHandshakes)+len(r.ARPConflicts) == 0 {
		color.Green("[✓] No critical anomalies detected.")
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
