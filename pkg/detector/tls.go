package detector

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/gocisse/sdwan-triage/pkg/models"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// TLSAnalyzer handles TLS packet analysis
type TLSAnalyzer struct{}

// NewTLSAnalyzer creates a new TLS analyzer
func NewTLSAnalyzer() *TLSAnalyzer {
	return &TLSAnalyzer{}
}

// Analyze processes TLS packets and extracts certificate info
func (t *TLSAnalyzer) Analyze(packet gopacket.Packet, state *models.AnalysisState, report *models.TriageReport) {
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		return
	}

	tcp, ok := tcpLayer.(*layers.TCP)
	if !ok || len(tcp.Payload) < 6 {
		return
	}

	// Get IP info (supports IPv4 and IPv6)
	ipInfo := ExtractIPInfo(packet)
	if ipInfo == nil {
		return
	}
	srcIP := ipInfo.SrcIP
	dstIP := ipInfo.DstIP

	srcPort := uint16(tcp.SrcPort)
	dstPort := uint16(tcp.DstPort)
	flowKey := fmt.Sprintf("%s:%d", dstIP, dstPort)
	timestamp := float64(packet.Metadata().Timestamp.UnixNano()) / 1e9

	payload := tcp.Payload

	// Check for TLS handshake
	if payload[0] != 0x16 { // TLS Handshake
		return
	}

	// Track TLS flow (any TLS handshake on port 443)
	if (dstPort == 443 || srcPort == 443) && payload[0] == 0x16 && payload[1] == 0x03 {
		tlsFlowKey := fmt.Sprintf("%s:%d->%s:%d", srcIP, srcPort, dstIP, dstPort)
		if !state.TLSFlowsSeen[tlsFlowKey] {
			state.TLSFlowsSeen[tlsFlowKey] = true
			report.TLSFlows = append(report.TLSFlows, models.TCPFlow{
				SrcIP:   srcIP,
				SrcPort: srcPort,
				DstIP:   dstIP,
				DstPort: dstPort,
			})
		}
	}

	// Extract SNI from ClientHello
	if sni := extractSNI(payload); sni != "" {
		state.TLSSNICache[flowKey] = sni
	}

	// Extract ALPN protocols and detect HTTP/2
	alpnProtocols := extractALPN(payload)
	for _, proto := range alpnProtocols {
		if proto == "h2" || proto == "h2c" {
			// HTTP/2 detected via ALPN
			http2FlowKey := fmt.Sprintf("%s:%d->%s:%d", srcIP, srcPort, dstIP, dstPort)
			if !state.HTTP2FlowsSeen[http2FlowKey] {
				state.HTTP2FlowsSeen[http2FlowKey] = true
				report.HTTP2Flows = append(report.HTTP2Flows, models.TCPFlow{
					SrcIP:   srcIP,
					SrcPort: srcPort,
					DstIP:   dstIP,
					DstPort: dstPort,
				})
			}
			break
		}
	}

	// Extract certificates from Certificate message
	certs := extractCertificates(payload)
	if len(certs) > 0 {
		cert := certs[0] // Primary certificate

		// Calculate fingerprint
		fingerprint := sha256.Sum256(cert.Raw)
		fingerprintStr := hex.EncodeToString(fingerprint[:])

		// Check if already recorded
		found := false
		for _, existing := range report.TLSCerts {
			if existing.Fingerprint == fingerprintStr {
				found = true
				break
			}
		}

		if !found {
			certInfo := models.TLSCertInfo{
				Timestamp:    timestamp,
				ServerIP:     srcIP,
				ServerPort:   srcPort,
				ServerName:   state.TLSSNICache[flowKey],
				Issuer:       cert.Issuer.String(),
				Subject:      cert.Subject.String(),
				NotBefore:    cert.NotBefore.Format(time.RFC3339),
				NotAfter:     cert.NotAfter.Format(time.RFC3339),
				Fingerprint:  fingerprintStr,
				IsExpired:    time.Now().After(cert.NotAfter),
				IsSelfSigned: cert.Issuer.String() == cert.Subject.String(),
				DNSNames:     cert.DNSNames,
			}

			report.TLSCerts = append(report.TLSCerts, certInfo)

			// Add timeline event for certificate issues
			if certInfo.IsExpired || certInfo.IsSelfSigned {
				eventType := "TLS Certificate Issue"
				detail := ""
				if certInfo.IsExpired {
					detail = fmt.Sprintf("Expired certificate for %s (expired: %s)", certInfo.ServerName, certInfo.NotAfter)
				} else if certInfo.IsSelfSigned {
					detail = fmt.Sprintf("Self-signed certificate for %s", certInfo.ServerName)
				}

				event := models.TimelineEvent{
					Timestamp:     timestamp,
					EventType:     eventType,
					SourceIP:      srcIP,
					DestinationIP: dstIP,
					Protocol:      "TLS",
					Detail:        detail,
				}
				srcPortPtr := srcPort
				dstPortPtr := dstPort
				event.SourcePort = &srcPortPtr
				event.DestinationPort = &dstPortPtr
				report.Timeline = append(report.Timeline, event)
			}
		}
	}
}

// extractSNI extracts Server Name Indication from TLS ClientHello
func extractSNI(data []byte) string {
	if len(data) < 6 || data[0] != 0x16 { // TLS Handshake
		return ""
	}

	// Skip TLS record header (5 bytes)
	if len(data) < 5 {
		return ""
	}

	recordLen := int(data[3])<<8 | int(data[4])
	if len(data) < 5+recordLen {
		return ""
	}

	handshake := data[5:]
	if len(handshake) < 4 || handshake[0] != 0x01 { // ClientHello
		return ""
	}

	// Skip handshake header (4 bytes)
	if len(handshake) < 4 {
		return ""
	}

	hsLen := int(handshake[1])<<16 | int(handshake[2])<<8 | int(handshake[3])
	if len(handshake) < 4+hsLen {
		return ""
	}

	clientHello := handshake[4:]

	// Skip version (2 bytes) + random (32 bytes)
	if len(clientHello) < 34 {
		return ""
	}
	pos := 34

	// Skip session ID
	if pos >= len(clientHello) {
		return ""
	}
	sessionIDLen := int(clientHello[pos])
	pos += 1 + sessionIDLen

	// Skip cipher suites
	if pos+2 > len(clientHello) {
		return ""
	}
	cipherSuitesLen := int(clientHello[pos])<<8 | int(clientHello[pos+1])
	pos += 2 + cipherSuitesLen

	// Skip compression methods
	if pos >= len(clientHello) {
		return ""
	}
	compressionLen := int(clientHello[pos])
	pos += 1 + compressionLen

	// Parse extensions
	if pos+2 > len(clientHello) {
		return ""
	}
	extensionsLen := int(clientHello[pos])<<8 | int(clientHello[pos+1])
	pos += 2

	extensionsEnd := pos + extensionsLen
	if extensionsEnd > len(clientHello) {
		extensionsEnd = len(clientHello)
	}

	for pos+4 <= extensionsEnd {
		extType := int(clientHello[pos])<<8 | int(clientHello[pos+1])
		extLen := int(clientHello[pos+2])<<8 | int(clientHello[pos+3])
		pos += 4

		if extType == 0 { // SNI extension
			if pos+extLen <= extensionsEnd && extLen > 5 {
				// Skip SNI list length (2 bytes) and type (1 byte)
				sniLen := int(clientHello[pos+3])<<8 | int(clientHello[pos+4])
				if pos+5+sniLen <= extensionsEnd {
					return string(clientHello[pos+5 : pos+5+sniLen])
				}
			}
		}

		pos += extLen
	}

	return ""
}

// extractALPN extracts ALPN protocols from TLS ClientHello
func extractALPN(data []byte) []string {
	var protocols []string

	if len(data) < 6 || data[0] != 0x16 { // TLS Handshake
		return protocols
	}

	// Skip TLS record header (5 bytes)
	if len(data) < 5 {
		return protocols
	}

	recordLen := int(data[3])<<8 | int(data[4])
	if len(data) < 5+recordLen {
		return protocols
	}

	handshake := data[5:]
	if len(handshake) < 4 || handshake[0] != 0x01 { // ClientHello
		return protocols
	}

	// Skip handshake header (4 bytes)
	hsLen := int(handshake[1])<<16 | int(handshake[2])<<8 | int(handshake[3])
	if len(handshake) < 4+hsLen {
		return protocols
	}

	clientHello := handshake[4:]

	// Skip version (2 bytes) + random (32 bytes)
	if len(clientHello) < 34 {
		return protocols
	}
	pos := 34

	// Skip session ID
	if pos >= len(clientHello) {
		return protocols
	}
	sessionIDLen := int(clientHello[pos])
	pos += 1 + sessionIDLen

	// Skip cipher suites
	if pos+2 > len(clientHello) {
		return protocols
	}
	cipherSuitesLen := int(clientHello[pos])<<8 | int(clientHello[pos+1])
	pos += 2 + cipherSuitesLen

	// Skip compression methods
	if pos >= len(clientHello) {
		return protocols
	}
	compressionLen := int(clientHello[pos])
	pos += 1 + compressionLen

	// Parse extensions
	if pos+2 > len(clientHello) {
		return protocols
	}
	extensionsLen := int(clientHello[pos])<<8 | int(clientHello[pos+1])
	pos += 2

	extensionsEnd := pos + extensionsLen
	if extensionsEnd > len(clientHello) {
		extensionsEnd = len(clientHello)
	}

	// Look for ALPN extension (type 16)
	for pos+4 <= extensionsEnd {
		extType := int(clientHello[pos])<<8 | int(clientHello[pos+1])
		extLen := int(clientHello[pos+2])<<8 | int(clientHello[pos+3])
		pos += 4

		if extType == 16 { // ALPN extension
			if pos+extLen <= extensionsEnd && extLen > 2 {
				// ALPN extension format: length (2 bytes) + protocols
				alpnLen := int(clientHello[pos])<<8 | int(clientHello[pos+1])
				alpnPos := pos + 2
				alpnEnd := alpnPos + alpnLen

				if alpnEnd <= pos+extLen {
					// Parse protocol list
					for alpnPos < alpnEnd {
						if alpnPos >= len(clientHello) {
							break
						}
						protoLen := int(clientHello[alpnPos])
						alpnPos++

						if alpnPos+protoLen <= alpnEnd && alpnPos+protoLen <= len(clientHello) {
							proto := string(clientHello[alpnPos : alpnPos+protoLen])
							protocols = append(protocols, proto)
							alpnPos += protoLen
						} else {
							break
						}
					}
				}
			}
			break
		}

		pos += extLen
	}

	return protocols
}

// extractCertificates extracts X.509 certificates from TLS Certificate message
func extractCertificates(data []byte) []*x509.Certificate {
	var certs []*x509.Certificate

	if len(data) < 6 || data[0] != 0x16 { // TLS Handshake
		return certs
	}

	// Skip TLS record header
	recordLen := int(data[3])<<8 | int(data[4])
	if len(data) < 5+recordLen {
		return certs
	}

	handshake := data[5:]
	if len(handshake) < 4 || handshake[0] != 0x0b { // Certificate message
		return certs
	}

	// Skip handshake header
	hsLen := int(handshake[1])<<16 | int(handshake[2])<<8 | int(handshake[3])
	if len(handshake) < 4+hsLen {
		return certs
	}

	certData := handshake[4:]

	// Skip certificates length (3 bytes)
	if len(certData) < 3 {
		return certs
	}
	certsLen := int(certData[0])<<16 | int(certData[1])<<8 | int(certData[2])
	certData = certData[3:]

	if len(certData) < certsLen {
		return certs
	}

	pos := 0
	for pos+3 <= certsLen {
		certLen := int(certData[pos])<<16 | int(certData[pos+1])<<8 | int(certData[pos+2])
		pos += 3

		if pos+certLen > certsLen {
			break
		}

		cert, err := x509.ParseCertificate(certData[pos : pos+certLen])
		if err == nil {
			certs = append(certs, cert)
		}

		pos += certLen
	}

	return certs
}
