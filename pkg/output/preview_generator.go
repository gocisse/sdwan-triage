package output

import (
	"encoding/binary"
	"fmt"
	"strings"
	"unicode"

	"github.com/gocisse/sdwan-triage/pkg/models"
)

// PreviewGenerator generates smart human-readable payload previews
type PreviewGenerator struct{}

// NewPreviewGenerator creates a new preview generator
func NewPreviewGenerator() *PreviewGenerator {
	return &PreviewGenerator{}
}

// SmartPayloadPreview generates a human-readable preview of packet payload
func (pg *PreviewGenerator) SmartPayloadPreview(data []byte, application string, direction string, sni string) string {
	if len(data) == 0 {
		return "[Empty payload]"
	}

	dirLabel := "→"
	if direction == "server_to_client" {
		dirLabel = "←"
	}

	// Check for specific protocols first
	switch application {
	case "TLS", "HTTPS":
		return pg.previewTLS(data, direction, sni)
	case "HTTP":
		return pg.previewHTTP(data, direction)
	case "SMB":
		return pg.previewSMB(data, direction)
	case "DNS":
		return pg.previewDNS(data)
	case "SSH":
		return pg.previewSSH(data, direction)
	case "SIP":
		return pg.previewSIP(data, direction)
	}

	// Check payload content
	if pg.isPrintableASCII(data) {
		return pg.previewText(data, dirLabel)
	}

	// Try to detect protocol from content
	if len(data) >= 5 && data[0] == 0x16 && data[1] == 0x03 {
		return pg.previewTLS(data, direction, sni)
	}

	if len(data) >= 4 {
		// SMB detection
		if (data[0] == 0xFE || data[0] == 0xFF) && data[1] == 'S' && data[2] == 'M' && data[3] == 'B' {
			return pg.previewSMB(data, direction)
		}
		// HTTP detection
		if strings.HasPrefix(string(data), "GET ") || strings.HasPrefix(string(data), "POST ") ||
			strings.HasPrefix(string(data), "HTTP/") || strings.HasPrefix(string(data), "PUT ") {
			return pg.previewHTTP(data, direction)
		}
	}

	// SNMP detection (ASN.1 SEQUENCE)
	if len(data) >= 2 && data[0] == 0x30 {
		preview := pg.previewSNMP(data, direction)
		if preview != "" {
			return preview
		}
	}

	// Fallback to binary summary with best guess
	return pg.previewBinary(data, dirLabel)
}

// previewTLS generates TLS-specific preview
func (pg *PreviewGenerator) previewTLS(data []byte, direction string, sni string) string {
	if len(data) < 5 {
		return "🔒 TLS: Incomplete record"
	}

	contentType := data[0]
	version := uint16(data[1])<<8 | uint16(data[2])
	recordLen := int(data[3])<<8 | int(data[4])

	versionStr := pg.tlsVersionString(version)

	switch contentType {
	case 0x14: // ChangeCipherSpec
		return fmt.Sprintf("🔒 %s: ChangeCipherSpec (encryption starting)", versionStr)

	case 0x15: // Alert
		alertLevel := "unknown"
		alertDesc := "unknown"
		if len(data) > 6 {
			switch data[5] {
			case 1:
				alertLevel = "warning"
			case 2:
				alertLevel = "fatal"
			}
			alertDesc = pg.tlsAlertDescription(data[6])
		}
		return fmt.Sprintf("🔒 %s: Alert (%s: %s)", versionStr, alertLevel, alertDesc)

	case 0x16: // Handshake
		if len(data) > 5 {
			hsType := data[5]
			switch hsType {
			case 0x01: // ClientHello
				if sni != "" {
					return fmt.Sprintf("🔒 %s: ClientHello → %s", versionStr, sni)
				}
				// Try to extract SNI
				extractedSNI := pg.extractSNI(data)
				if extractedSNI != "" {
					return fmt.Sprintf("🔒 %s: ClientHello → %s", versionStr, extractedSNI)
				}
				return fmt.Sprintf("🔒 %s: ClientHello (initiating secure connection)", versionStr)
			case 0x02:
				return fmt.Sprintf("🔒 %s: ServerHello (connection accepted)", versionStr)
			case 0x0b:
				return fmt.Sprintf("🔒 %s: Certificate (server identity proof)", versionStr)
			case 0x0c:
				return fmt.Sprintf("🔒 %s: ServerKeyExchange (key negotiation)", versionStr)
			case 0x0d:
				return fmt.Sprintf("🔒 %s: CertificateRequest (client auth required)", versionStr)
			case 0x0e:
				return fmt.Sprintf("🔒 %s: ServerHelloDone (handshake phase complete)", versionStr)
			case 0x10:
				return fmt.Sprintf("🔒 %s: ClientKeyExchange (key exchange)", versionStr)
			case 0x0f:
				return fmt.Sprintf("🔒 %s: CertificateVerify (client auth)", versionStr)
			case 0x14:
				return fmt.Sprintf("🔒 %s: Finished (handshake complete, encrypted)", versionStr)
			default:
				return fmt.Sprintf("🔒 %s: Handshake message (type %d)", versionStr, hsType)
			}
		}
		return fmt.Sprintf("🔒 %s: Handshake", versionStr)

	case 0x17: // Application Data
		if sni != "" {
			return fmt.Sprintf("🔒 Encrypted data to %s [%d bytes]", sni, recordLen)
		}
		return fmt.Sprintf("🔒 %s: Encrypted application data [%d bytes]", versionStr, recordLen)

	default:
		return fmt.Sprintf("🔒 %s: Record type 0x%02X [%d bytes]", versionStr, contentType, recordLen)
	}
}

// previewHTTP generates HTTP-specific preview
func (pg *PreviewGenerator) previewHTTP(data []byte, direction string) string {
	lines := strings.SplitN(string(data), "\r\n", 10)
	if len(lines) == 0 {
		return "🌐 HTTP: Empty"
	}

	firstLine := strings.TrimSpace(lines[0])

	if direction == "client_to_server" {
		// Request
		parts := strings.SplitN(firstLine, " ", 3)
		if len(parts) >= 2 {
			method := parts[0]
			path := parts[1]
			if len(path) > 50 {
				path = path[:47] + "..."
			}

			// Find Host header
			host := ""
			for _, line := range lines[1:] {
				if strings.HasPrefix(strings.ToLower(line), "host:") {
					host = strings.TrimSpace(line[5:])
					break
				}
			}

			if host != "" {
				return fmt.Sprintf("🌐 HTTP %s %s (Host: %s)", method, path, host)
			}
			return fmt.Sprintf("🌐 HTTP %s %s", method, path)
		}
	} else {
		// Response
		if strings.HasPrefix(firstLine, "HTTP/") {
			parts := strings.SplitN(firstLine, " ", 3)
			if len(parts) >= 2 {
				status := parts[1]
				reason := ""
				if len(parts) >= 3 {
					reason = parts[2]
				}

				// Find Content-Type
				contentType := ""
				contentLen := ""
				for _, line := range lines[1:] {
					lower := strings.ToLower(line)
					if strings.HasPrefix(lower, "content-type:") {
						contentType = strings.TrimSpace(line[13:])
						if idx := strings.Index(contentType, ";"); idx > 0 {
							contentType = contentType[:idx]
						}
					}
					if strings.HasPrefix(lower, "content-length:") {
						contentLen = strings.TrimSpace(line[15:])
					}
				}

				result := fmt.Sprintf("🌐 HTTP %s %s", status, reason)
				if contentType != "" {
					result += fmt.Sprintf(" (%s)", contentType)
				}
				if contentLen != "" {
					result += fmt.Sprintf(" [%s bytes]", contentLen)
				}
				return result
			}
		}
	}

	return fmt.Sprintf("🌐 HTTP: %s", truncateString(firstLine, 60))
}

// previewSMB generates SMB-specific preview
func (pg *PreviewGenerator) previewSMB(data []byte, direction string) string {
	if len(data) < 4 {
		return "📁 SMB: Incomplete"
	}

	isSMB2 := data[0] == 0xFE && data[1] == 'S' && data[2] == 'M' && data[3] == 'B'
	isSMB1 := data[0] == 0xFF && data[1] == 'S' && data[2] == 'M' && data[3] == 'B'

	if isSMB2 && len(data) >= 16 {
		cmd := binary.LittleEndian.Uint16(data[12:14])
		cmdName := pg.smb2CommandName(cmd)

		// Try to extract filename for file operations
		if cmd == 0x0005 || cmd == 0x0008 || cmd == 0x0009 { // Create, Read, Write
			filename := pg.extractSMBFilename(data)
			if filename != "" {
				return fmt.Sprintf("📁 SMB2 %s: %s", cmdName, filename)
			}
		}

		return fmt.Sprintf("📁 SMB2 %s", cmdName)
	}

	if isSMB1 && len(data) >= 5 {
		cmd := data[4]
		cmdName := pg.smb1CommandName(cmd)
		return fmt.Sprintf("📁 SMB1 %s", cmdName)
	}

	return fmt.Sprintf("📁 SMB data [%d bytes]", len(data))
}

// previewDNS generates DNS-specific preview
func (pg *PreviewGenerator) previewDNS(data []byte) string {
	if len(data) < 12 {
		return "🔍 DNS: Incomplete"
	}

	flags := uint16(data[2])<<8 | uint16(data[3])
	isResponse := (flags & 0x8000) != 0
	rcode := flags & 0x000F
	qdCount := int(data[4])<<8 | int(data[5])
	anCount := int(data[6])<<8 | int(data[7])

	// Extract query name
	queryName := pg.extractDNSName(data, 12)

	if isResponse {
		status := "OK"
		switch rcode {
		case 0:
			status = "OK"
		case 1:
			status = "Format Error"
		case 2:
			status = "Server Failure"
		case 3:
			status = "NXDOMAIN (not found)"
		case 5:
			status = "Refused"
		default:
			status = fmt.Sprintf("Error %d", rcode)
		}

		if queryName != "" {
			return fmt.Sprintf("🔍 DNS Response: %s → %s (%d answers)", queryName, status, anCount)
		}
		return fmt.Sprintf("🔍 DNS Response: %s (%d answers)", status, anCount)
	}

	// Query
	if queryName != "" {
		return fmt.Sprintf("🔍 DNS Query: %s", queryName)
	}
	return fmt.Sprintf("🔍 DNS Query (%d questions)", qdCount)
}

// previewSSH generates SSH-specific preview
func (pg *PreviewGenerator) previewSSH(data []byte, direction string) string {
	if strings.HasPrefix(string(data), "SSH-") {
		// Version exchange
		version := strings.TrimSpace(strings.SplitN(string(data), "\n", 2)[0])
		return fmt.Sprintf("🔑 %s (version exchange)", version)
	}

	// Encrypted SSH data
	return fmt.Sprintf("🔑 SSH encrypted data [%d bytes]", len(data))
}

// previewSIP generates SIP-specific preview
func (pg *PreviewGenerator) previewSIP(data []byte, direction string) string {
	lines := strings.SplitN(string(data), "\r\n", 5)
	if len(lines) == 0 {
		return "📞 SIP: Empty"
	}

	firstLine := strings.TrimSpace(lines[0])

	if strings.HasPrefix(firstLine, "SIP/") {
		// Response
		parts := strings.SplitN(firstLine, " ", 3)
		if len(parts) >= 2 {
			return fmt.Sprintf("📞 SIP Response: %s", strings.Join(parts[1:], " "))
		}
	}

	// Request
	parts := strings.SplitN(firstLine, " ", 2)
	if len(parts) >= 1 {
		method := parts[0]
		switch method {
		case "INVITE":
			return "📞 SIP INVITE (starting call)"
		case "ACK":
			return "📞 SIP ACK (call confirmed)"
		case "BYE":
			return "📞 SIP BYE (ending call)"
		case "CANCEL":
			return "📞 SIP CANCEL (canceling call)"
		case "REGISTER":
			return "📞 SIP REGISTER (registering)"
		case "OPTIONS":
			return "📞 SIP OPTIONS (capability query)"
		default:
			return fmt.Sprintf("📞 SIP %s", method)
		}
	}

	return "📞 SIP message"
}

// previewSNMP generates SNMP-specific preview
func (pg *PreviewGenerator) previewSNMP(data []byte, direction string) string {
	if len(data) < 10 || data[0] != 0x30 {
		return ""
	}

	// Try to find PDU type
	for i := 2; i < len(data)-2 && i < 50; i++ {
		pduType := data[i]
		switch pduType {
		case 0xA0:
			return "📊 SNMP GetRequest (querying device)"
		case 0xA1:
			return "📊 SNMP GetNextRequest (walking MIB)"
		case 0xA2:
			device := pg.extractSNMPDeviceName(data)
			if device != "" {
				return fmt.Sprintf("📊 SNMP GetResponse: %s", device)
			}
			return "📊 SNMP GetResponse (device info)"
		case 0xA3:
			return "📊 SNMP SetRequest (configuring device)"
		case 0xA4:
			return "🚨 SNMP Trap (device alert)"
		case 0xA5:
			return "📊 SNMP GetBulkRequest (bulk query)"
		case 0xA6:
			return "📊 SNMP InformRequest"
		case 0xA7:
			return "🚨 SNMP v2 Trap (device alert)"
		}
	}

	return fmt.Sprintf("📊 SNMP message [%d bytes]", len(data))
}

// previewText generates preview for printable text
func (pg *PreviewGenerator) previewText(data []byte, dirLabel string) string {
	text := strings.TrimSpace(string(data))
	if len(text) > 80 {
		text = text[:77] + "..."
	}
	// Replace newlines for single-line display
	text = strings.ReplaceAll(text, "\r\n", " ")
	text = strings.ReplaceAll(text, "\n", " ")
	text = strings.ReplaceAll(text, "\r", " ")

	return fmt.Sprintf("%s \"%s\"", dirLabel, text)
}

// previewBinary generates preview for binary data with best guess
func (pg *PreviewGenerator) previewBinary(data []byte, dirLabel string) string {
	guess := pg.guessBinaryType(data)
	if guess != "" {
		return fmt.Sprintf("🔢 %s [%d bytes]", guess, len(data))
	}
	return fmt.Sprintf("🔢 Binary data [%d bytes]", len(data))
}

// Helper functions

func (pg *PreviewGenerator) tlsVersionString(version uint16) string {
	switch version {
	case 0x0300:
		return "SSLv3 ⚠️"
	case 0x0301:
		return "TLS 1.0"
	case 0x0302:
		return "TLS 1.1"
	case 0x0303:
		return "TLS 1.2"
	case 0x0304:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("TLS 0x%04X", version)
	}
}

func (pg *PreviewGenerator) tlsAlertDescription(code byte) string {
	alerts := map[byte]string{
		0:   "close_notify",
		10:  "unexpected_message",
		20:  "bad_record_mac",
		21:  "decryption_failed",
		22:  "record_overflow",
		30:  "decompression_failure",
		40:  "handshake_failure",
		42:  "bad_certificate",
		43:  "unsupported_certificate",
		44:  "certificate_revoked",
		45:  "certificate_expired",
		46:  "certificate_unknown",
		47:  "illegal_parameter",
		48:  "unknown_ca",
		49:  "access_denied",
		50:  "decode_error",
		51:  "decrypt_error",
		70:  "protocol_version",
		71:  "insufficient_security",
		80:  "internal_error",
		90:  "user_canceled",
		100: "no_renegotiation",
		110: "unsupported_extension",
	}
	if desc, ok := alerts[code]; ok {
		return desc
	}
	return fmt.Sprintf("alert_%d", code)
}

func (pg *PreviewGenerator) smb2CommandName(cmd uint16) string {
	commands := map[uint16]string{
		0x0000: "Negotiate",
		0x0001: "Session Setup",
		0x0002: "Logoff",
		0x0003: "Tree Connect",
		0x0004: "Tree Disconnect",
		0x0005: "Create (Open File)",
		0x0006: "Close",
		0x0007: "Flush",
		0x0008: "Read",
		0x0009: "Write",
		0x000A: "Lock",
		0x000B: "IOCTL",
		0x000C: "Cancel",
		0x000D: "Echo",
		0x000E: "Query Directory",
		0x000F: "Change Notify",
		0x0010: "Query Info",
		0x0011: "Set Info",
		0x0012: "Oplock Break",
	}
	if name, ok := commands[cmd]; ok {
		return name
	}
	return fmt.Sprintf("Command 0x%04X", cmd)
}

func (pg *PreviewGenerator) smb1CommandName(cmd byte) string {
	commands := map[byte]string{
		0x00: "Create Directory",
		0x01: "Delete Directory",
		0x02: "Open",
		0x03: "Create",
		0x04: "Close",
		0x05: "Flush",
		0x06: "Delete",
		0x07: "Rename",
		0x08: "Query Info",
		0x0A: "Read",
		0x0B: "Write",
		0x24: "Locking",
		0x25: "Transaction",
		0x2D: "Open AndX",
		0x2E: "Read AndX",
		0x2F: "Write AndX",
		0x72: "Negotiate",
		0x73: "Session Setup",
		0x74: "Logoff",
		0x75: "Tree Connect",
	}
	if name, ok := commands[cmd]; ok {
		return name
	}
	return fmt.Sprintf("Command 0x%02X", cmd)
}

func (pg *PreviewGenerator) extractSNI(data []byte) string {
	if len(data) < 50 {
		return ""
	}

	for i := 0; i < len(data)-10; i++ {
		if data[i] == 0x00 && data[i+1] == 0x00 {
			if i+4 < len(data) {
				extLen := int(data[i+2])<<8 | int(data[i+3])
				if extLen > 0 && extLen < 256 && i+4+extLen <= len(data) {
					if i+9 < len(data) {
						nameLen := int(data[i+7])<<8 | int(data[i+8])
						if nameLen > 0 && nameLen < 256 && i+9+nameLen <= len(data) {
							name := string(data[i+9 : i+9+nameLen])
							if pg.isValidHostname(name) {
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

func (pg *PreviewGenerator) isValidHostname(s string) bool {
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

func (pg *PreviewGenerator) extractDNSName(data []byte, offset int) string {
	var name strings.Builder
	i := offset
	for i < len(data) && i < offset+256 {
		labelLen := int(data[i])
		if labelLen == 0 {
			break
		}
		if labelLen > 63 || i+1+labelLen > len(data) {
			break
		}
		if name.Len() > 0 {
			name.WriteByte('.')
		}
		name.Write(data[i+1 : i+1+labelLen])
		i += 1 + labelLen
	}
	return name.String()
}

func (pg *PreviewGenerator) extractSMBFilename(data []byte) string {
	// Look for readable path patterns in SMB data
	for i := 0; i < len(data)-4; i++ {
		if data[i] == '\\' && i+1 < len(data) {
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

func (pg *PreviewGenerator) extractSNMPDeviceName(data []byte) string {
	// Look for readable device names in SNMP response
	for i := 0; i < len(data)-10; i++ {
		if pg.isReadableStart(data[i:]) {
			candidate := pg.extractReadable(data[i:pg.minVal(i+100, len(data))])
			if len(candidate) > 5 && len(candidate) < 100 {
				if strings.Contains(candidate, "Meraki") ||
					strings.Contains(candidate, "Cisco") ||
					strings.Contains(candidate, "Switch") ||
					strings.Contains(candidate, "Router") {
					return candidate
				}
			}
		}
	}
	return ""
}

func (pg *PreviewGenerator) isReadableStart(data []byte) bool {
	if len(data) < 3 {
		return false
	}
	readable := 0
	for i := 0; i < pg.minVal(5, len(data)); i++ {
		if data[i] >= 32 && data[i] < 127 {
			readable++
		}
	}
	return readable >= 3
}

func (pg *PreviewGenerator) extractReadable(data []byte) string {
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

func (pg *PreviewGenerator) isPrintableASCII(data []byte) bool {
	if len(data) == 0 {
		return false
	}
	printable := 0
	for _, b := range data[:pg.minVal(len(data), 100)] {
		if (b >= 32 && b < 127) || b == '\n' || b == '\r' || b == '\t' {
			printable++
		}
	}
	return float64(printable)/float64(pg.minVal(len(data), 100)) > 0.8
}

func (pg *PreviewGenerator) guessBinaryType(data []byte) string {
	if len(data) < 4 {
		return ""
	}

	// Check magic bytes
	if data[0] == 0x89 && data[1] == 'P' && data[2] == 'N' && data[3] == 'G' {
		return "PNG image"
	}
	if data[0] == 0xFF && data[1] == 0xD8 && data[2] == 0xFF {
		return "JPEG image"
	}
	if data[0] == 'G' && data[1] == 'I' && data[2] == 'F' {
		return "GIF image"
	}
	if data[0] == 'P' && data[1] == 'K' && data[2] == 0x03 && data[3] == 0x04 {
		return "ZIP/Office archive"
	}
	if data[0] == 0x1F && data[1] == 0x8B {
		return "Gzip compressed"
	}
	if data[0] == '%' && data[1] == 'P' && data[2] == 'D' && data[3] == 'F' {
		return "PDF document"
	}

	return ""
}

func (pg *PreviewGenerator) truncateStr(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

func (pg *PreviewGenerator) minVal(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// GenerateSegmentPreview generates a complete preview for a stream segment
func (pg *PreviewGenerator) GenerateSegmentPreview(seg *models.StreamSegment, application string, sni string) string {
	return pg.SmartPayloadPreview(seg.Data, application, seg.Direction, sni)
}

// IsBinaryData checks if data is primarily binary (not text)
func (pg *PreviewGenerator) IsBinaryData(data []byte) bool {
	return !pg.isPrintableASCII(data)
}

// FormatBinarySize formats a byte count as human-readable size
func FormatBinarySize(bytes int) string {
	if bytes < 1024 {
		return fmt.Sprintf("%d B", bytes)
	}
	if bytes < 1024*1024 {
		return fmt.Sprintf("%.1f KB", float64(bytes)/1024)
	}
	if bytes < 1024*1024*1024 {
		return fmt.Sprintf("%.1f MB", float64(bytes)/(1024*1024))
	}
	return fmt.Sprintf("%.1f GB", float64(bytes)/(1024*1024*1024))
}

// SanitizeForDisplay removes non-printable characters for safe display
func SanitizeForDisplay(data []byte) string {
	var sb strings.Builder
	for _, b := range data {
		if unicode.IsPrint(rune(b)) || b == '\n' || b == '\r' || b == '\t' {
			sb.WriteByte(b)
		} else {
			sb.WriteByte('.')
		}
	}
	return sb.String()
}
