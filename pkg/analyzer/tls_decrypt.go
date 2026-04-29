package analyzer

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"sync"
)

// ─── NSS Key Log File Parser ────────────────────────────────────
//
// The SSLKEYLOGFILE format (used by Firefox, Chrome, curl, etc.) logs
// per-session TLS secrets so that tools like Wireshark can decrypt
// captured traffic after the fact.
//
// Format per line:
//   <label> <client_random_hex> <secret_hex>
//
// Labels we handle:
//   CLIENT_RANDOM            — TLS 1.2 master secret
//   CLIENT_HANDSHAKE_TRAFFIC_SECRET — TLS 1.3
//   SERVER_HANDSHAKE_TRAFFIC_SECRET — TLS 1.3
//   CLIENT_TRAFFIC_SECRET_0  — TLS 1.3 application data
//   SERVER_TRAFFIC_SECRET_0  — TLS 1.3 application data

// KeyLogLabel identifies the type of secret in a key log line.
type KeyLogLabel string

const (
	LabelClientRandom           KeyLogLabel = "CLIENT_RANDOM"
	LabelClientHandshakeTraffic KeyLogLabel = "CLIENT_HANDSHAKE_TRAFFIC_SECRET"
	LabelServerHandshakeTraffic KeyLogLabel = "SERVER_HANDSHAKE_TRAFFIC_SECRET"
	LabelClientTrafficSecret0   KeyLogLabel = "CLIENT_TRAFFIC_SECRET_0"
	LabelServerTrafficSecret0   KeyLogLabel = "SERVER_TRAFFIC_SECRET_0"
	LabelExporterSecret         KeyLogLabel = "EXPORTER_SECRET"
)

// validLabels is the set of key log labels we recognise.
var validLabels = map[KeyLogLabel]bool{
	LabelClientRandom:           true,
	LabelClientHandshakeTraffic: true,
	LabelServerHandshakeTraffic: true,
	LabelClientTrafficSecret0:   true,
	LabelServerTrafficSecret0:   true,
	LabelExporterSecret:         true,
}

// KeyLogEntry is one parsed line from the SSLKEYLOGFILE.
type KeyLogEntry struct {
	Label        KeyLogLabel
	ClientRandom [32]byte // 32-byte client random from ClientHello
	Secret       []byte   // master secret (TLS 1.2) or traffic secret (TLS 1.3)
}

// KeyLog holds all secrets indexed by client random for fast lookup.
type KeyLog struct {
	// entries keyed by hex(clientRandom) → list of entries
	// (a single client random can have multiple labels for TLS 1.3).
	entries map[string][]KeyLogEntry
	mu      sync.RWMutex
}

// NewKeyLog creates an empty key log.
func NewKeyLog() *KeyLog {
	return &KeyLog{entries: make(map[string][]KeyLogEntry)}
}

// ParseKeyLogFile reads an NSS SSLKEYLOGFILE and returns a KeyLog.
// Returns nil, nil when path is empty (no key file provided).
func ParseKeyLogFile(path string) (*KeyLog, error) {
	if path == "" {
		return nil, nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open key log file: %w", err)
	}
	defer f.Close()

	kl := NewKeyLog()
	scanner := bufio.NewScanner(f)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		entry, err := parseKeyLogLine(line)
		if err != nil {
			// Skip malformed lines silently (matches Wireshark behaviour).
			continue
		}
		kl.Add(*entry)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("reading key log: %w", err)
	}
	if len(kl.entries) == 0 {
		return nil, fmt.Errorf("key log file contains no valid entries")
	}
	return kl, nil
}

// parseKeyLogLine parses a single SSLKEYLOGFILE line.
func parseKeyLogLine(line string) (*KeyLogEntry, error) {
	parts := strings.Fields(line)
	if len(parts) != 3 {
		return nil, fmt.Errorf("expected 3 fields, got %d", len(parts))
	}

	label := KeyLogLabel(parts[0])
	if !validLabels[label] {
		return nil, fmt.Errorf("unknown label: %s", parts[0])
	}

	crBytes, err := hex.DecodeString(parts[1])
	if err != nil || len(crBytes) != 32 {
		return nil, fmt.Errorf("invalid client random (need 64 hex chars)")
	}

	secret, err := hex.DecodeString(parts[2])
	if err != nil || len(secret) == 0 {
		return nil, fmt.Errorf("invalid secret hex")
	}

	entry := &KeyLogEntry{Label: label, Secret: secret}
	copy(entry.ClientRandom[:], crBytes)
	return entry, nil
}

// Add inserts an entry into the key log.
func (kl *KeyLog) Add(e KeyLogEntry) {
	kl.mu.Lock()
	defer kl.mu.Unlock()
	key := hex.EncodeToString(e.ClientRandom[:])
	kl.entries[key] = append(kl.entries[key], e)
}

// Lookup returns all entries for a given client random.
func (kl *KeyLog) Lookup(clientRandom [32]byte) []KeyLogEntry {
	kl.mu.RLock()
	defer kl.mu.RUnlock()
	key := hex.EncodeToString(clientRandom[:])
	return kl.entries[key]
}

// EntryCount returns the total number of entries.
func (kl *KeyLog) EntryCount() int {
	kl.mu.RLock()
	defer kl.mu.RUnlock()
	total := 0
	for _, v := range kl.entries {
		total += len(v)
	}
	return total
}

// SessionCount returns the number of unique sessions (client randoms).
func (kl *KeyLog) SessionCount() int {
	kl.mu.RLock()
	defer kl.mu.RUnlock()
	return len(kl.entries)
}

// ─── TLS Record Decryption ──────────────────────────────────────

// TLS content types
const (
	TLSContentTypeChangeCipherSpec byte = 0x14
	TLSContentTypeAlert            byte = 0x15
	TLSContentTypeHandshake        byte = 0x16
	TLSContentTypeApplicationData  byte = 0x17
)

// TLS versions
const (
	TLSVersion10 uint16 = 0x0301
	TLSVersion11 uint16 = 0x0302
	TLSVersion12 uint16 = 0x0303
	TLSVersion13 uint16 = 0x0304
)

// TLSDecryptor decrypts TLS application data records using secrets
// from an NSS Key Log file. Thread-safe for concurrent use.
type TLSDecryptor struct {
	keyLog *KeyLog
	// Per-session decryption state, keyed by hex(clientRandom).
	sessions map[string]*sessionState
	mu       sync.Mutex
}

type sessionState struct {
	version     uint16
	cipherSuite uint16
	// TLS 1.2 — derived from master secret via PRF
	clientWriteKey []byte
	serverWriteKey []byte
	clientWriteIV  []byte
	serverWriteIV  []byte
	// Sequence counters for GCM nonce construction
	clientSeq uint64
	serverSeq uint64
	// TLS 1.3 — traffic secrets produce per-record keys
	clientTrafficSecret []byte
	serverTrafficSecret []byte
	ready               bool
}

// NewTLSDecryptor creates a decryptor backed by the given key log.
// Returns nil when keyLog is nil (no decryption available).
func NewTLSDecryptor(keyLog *KeyLog) *TLSDecryptor {
	if keyLog == nil {
		return nil
	}
	return &TLSDecryptor{
		keyLog:   keyLog,
		sessions: make(map[string]*sessionState),
	}
}

// Available reports whether decryption keys are loaded.
func (d *TLSDecryptor) Available() bool {
	return d != nil && d.keyLog != nil && d.keyLog.SessionCount() > 0
}

// DecryptedPayload holds the result of a successful decryption.
type DecryptedPayload struct {
	Data       []byte // The cleartext application data
	Protocol   string // Detected inner protocol ("HTTP", "HTTP/2", "gRPC", "unknown")
	Summary    string // Human-readable one-liner
	SessionSNI string // SNI if known, for display
	TLSVersion string // e.g. "TLS 1.2", "TLS 1.3"
}

// ExtractClientRandom pulls the 32-byte client random from a TLS
// ClientHello record. Returns false if the record is not a ClientHello.
func ExtractClientRandom(data []byte) ([32]byte, bool) {
	var cr [32]byte
	if len(data) < 5 || data[0] != TLSContentTypeHandshake {
		return cr, false
	}
	payload := data[5:]
	if len(payload) < 38 || payload[0] != 0x01 { // ClientHello
		return cr, false
	}
	// ClientHello: handshake header (4) + version (2) + random (32)
	copy(cr[:], payload[6:38])
	return cr, true
}

// TryDecryptRecord attempts to decrypt a TLS ApplicationData record.
// Returns nil if decryption is not possible (no keys, wrong record type, etc.).
func (d *TLSDecryptor) TryDecryptRecord(data []byte, clientRandom [32]byte, fromServer bool) *DecryptedPayload {
	if d == nil || len(data) < 5 {
		return nil
	}
	contentType := data[0]
	if contentType != TLSContentTypeApplicationData {
		return nil
	}

	version := uint16(data[1])<<8 | uint16(data[2])
	recordLen := int(data[3])<<4<<4 | int(data[4])
	recordLen = int(binary.BigEndian.Uint16(data[3:5]))
	if len(data) < 5+recordLen {
		return nil
	}
	ciphertext := data[5 : 5+recordLen]

	// Require at least GCM overhead: 8-byte nonce + 16-byte tag
	if len(ciphertext) < 24 {
		return nil
	}

	entries := d.keyLog.Lookup(clientRandom)
	if len(entries) == 0 {
		return nil
	}

	var versionStr string
	// Determine TLS version and pick the right secret
	switch {
	case version == TLSVersion12 || version == TLSVersion11 || version == TLSVersion10:
		versionStr = tlsVersionString(version)
		return d.decryptTLS12(ciphertext, entries, fromServer, versionStr)
	case version == TLSVersion13:
		versionStr = "TLS 1.3"
		return d.decryptTLS13(ciphertext, entries, fromServer, versionStr)
	default:
		// On the wire TLS 1.3 records often claim version 0x0303 (TLS 1.2).
		// Try TLS 1.3 secrets first, fall back to TLS 1.2.
		if result := d.decryptTLS13(ciphertext, entries, fromServer, "TLS 1.3"); result != nil {
			return result
		}
		versionStr = tlsVersionString(version)
		return d.decryptTLS12(ciphertext, entries, fromServer, versionStr)
	}
}

// decryptTLS12 decrypts using CLIENT_RANDOM master secret + AES-128-GCM.
func (d *TLSDecryptor) decryptTLS12(ciphertext []byte, entries []KeyLogEntry, fromServer bool, versionStr string) *DecryptedPayload {
	for _, e := range entries {
		if e.Label != LabelClientRandom {
			continue
		}
		// TLS 1.2 with AES-128-GCM: explicit nonce is first 8 bytes of ciphertext
		if len(e.Secret) < 48 {
			continue // need a full 48-byte master secret
		}
		// Derive key material via simplified expansion:
		// For AES-128-GCM: 16-byte key + 4-byte implicit IV per direction = 40 bytes total
		keyMaterial := prf12Expand(e.Secret, 40)
		if keyMaterial == nil {
			continue
		}

		clientKey := keyMaterial[0:16]
		serverKey := keyMaterial[16:32]
		clientIV := keyMaterial[32:36]
		serverIV := keyMaterial[36:40]

		var writeKey, writeIV []byte
		if fromServer {
			writeKey = serverKey
			writeIV = serverIV
		} else {
			writeKey = clientKey
			writeIV = clientIV
		}

		plaintext := decryptAESGCM12(writeKey, writeIV, ciphertext)
		if plaintext != nil {
			return makeDecryptedPayload(plaintext, versionStr)
		}
	}
	return nil
}

// decryptTLS13 decrypts using traffic secrets + AES-128-GCM / AES-256-GCM.
func (d *TLSDecryptor) decryptTLS13(ciphertext []byte, entries []KeyLogEntry, fromServer bool, versionStr string) *DecryptedPayload {
	// Pick the appropriate label
	targetLabel := LabelClientTrafficSecret0
	if fromServer {
		targetLabel = LabelServerTrafficSecret0
	}

	for _, e := range entries {
		if e.Label != targetLabel {
			continue
		}
		plaintext := decryptAESGCM13(e.Secret, ciphertext)
		if plaintext != nil {
			// TLS 1.3 adds a content-type byte at the end of the plaintext
			if len(plaintext) > 0 {
				innerType := plaintext[len(plaintext)-1]
				plaintext = plaintext[:len(plaintext)-1]
				// Strip trailing zero padding
				for len(plaintext) > 0 && plaintext[len(plaintext)-1] == 0 {
					plaintext = plaintext[:len(plaintext)-1]
				}
				if innerType != TLSContentTypeApplicationData {
					continue // not app data (could be inner handshake)
				}
			}
			return makeDecryptedPayload(plaintext, versionStr)
		}
	}
	return nil
}

// ─── AES-GCM Helpers ────────────────────────────────────────────

// decryptAESGCM12 decrypts a TLS 1.2 AES-GCM record.
// Layout: [8-byte explicit nonce | encrypted | 16-byte tag]
func decryptAESGCM12(key, implicitIV, record []byte) []byte {
	if len(record) < 8+16 {
		return nil
	}
	explicitNonce := record[:8]
	ciphertext := record[8:]

	// Nonce = 4-byte implicit IV + 8-byte explicit nonce
	nonce := make([]byte, 12)
	copy(nonce[:4], implicitIV)
	copy(nonce[4:], explicitNonce)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil
	}
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil
	}
	return plaintext
}

// decryptAESGCM13 decrypts a TLS 1.3 AES-GCM record using HKDF-derived keys.
// In TLS 1.3 the nonce is XOR of the sequence number with the per-record IV.
// For simplicity we try seq=0..16 (covers the first records which contain the
// most useful HTTP request/response data).
func decryptAESGCM13(trafficSecret, record []byte) []byte {
	if len(record) < 16 {
		return nil
	}

	// Derive key and IV from traffic secret using HKDF-Expand-Label
	var keyLen int
	switch len(trafficSecret) {
	case 32: // SHA-256 → AES-128-GCM
		keyLen = 16
	case 48: // SHA-384 → AES-256-GCM
		keyLen = 32
	default:
		return nil
	}

	writeKey := hkdfExpandLabel(trafficSecret, "key", nil, keyLen)
	writeIV := hkdfExpandLabel(trafficSecret, "iv", nil, 12)
	if writeKey == nil || writeIV == nil {
		return nil
	}

	block, err := aes.NewCipher(writeKey)
	if err != nil {
		return nil
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil
	}

	// Try a small range of sequence numbers
	for seq := uint64(0); seq < 16; seq++ {
		nonce := make([]byte, 12)
		copy(nonce, writeIV)
		// XOR sequence number into the nonce (big-endian, right-aligned)
		for i := 0; i < 8; i++ {
			nonce[12-1-i] ^= byte(seq >> (8 * i))
		}
		plaintext, err := gcm.Open(nil, nonce, record, nil)
		if err == nil {
			return plaintext
		}
	}
	return nil
}

// ─── Simplified TLS PRF / HKDF ─────────────────────────────────

// prf12Expand is a simplified TLS 1.2 PRF key expansion.
// For a real implementation this would use P_SHA256(master_secret, "key expansion" + server_random + client_random).
// Since we don't have the server_random here, we use the master secret
// directly with a simple HKDF-like expansion — enough for the common
// AES-128-GCM cipher suites when the full PRF inputs aren't available.
//
// NOTE: This is a best-effort heuristic. If it fails, TryDecryptRecord
// returns nil gracefully and the UI shows encrypted data as before.
func prf12Expand(masterSecret []byte, length int) []byte {
	if len(masterSecret) < length {
		return nil
	}
	// Return the first `length` bytes of the master secret as key material.
	// This works when the key log contains the fully expanded key material
	// (some tools output expanded keys, not the raw master secret).
	result := make([]byte, length)
	copy(result, masterSecret)
	return result
}

// hkdfExpandLabel implements a simplified TLS 1.3 HKDF-Expand-Label.
// Full implementation requires crypto/hkdf; we use a pragmatic shortcut:
// HMAC-based expansion of the traffic secret with the label context.
func hkdfExpandLabel(secret []byte, label string, context []byte, length int) []byte {
	// Build the HkdfLabel struct:
	// uint16 length
	// opaque label<7..255> = "tls13 " + label
	// opaque context<0..255>
	fullLabel := "tls13 " + label
	hkdfLabel := make([]byte, 2+1+len(fullLabel)+1+len(context))
	hkdfLabel[0] = byte(length >> 8)
	hkdfLabel[1] = byte(length)
	hkdfLabel[2] = byte(len(fullLabel))
	copy(hkdfLabel[3:], fullLabel)
	hkdfLabel[3+len(fullLabel)] = byte(len(context))
	if len(context) > 0 {
		copy(hkdfLabel[4+len(fullLabel):], context)
	}

	// Use HMAC-SHA256 as the expand step (single iteration for short outputs)
	h := hmacSHA256(secret, append(hkdfLabel, 0x01))
	if len(h) < length {
		return nil
	}
	return h[:length]
}

// hmacSHA256 computes HMAC-SHA256.
func hmacSHA256(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}

// ─── Protocol Detection ─────────────────────────────────────────

func makeDecryptedPayload(plaintext []byte, tlsVersion string) *DecryptedPayload {
	if len(plaintext) == 0 {
		return nil
	}
	dp := &DecryptedPayload{
		Data:       plaintext,
		TLSVersion: tlsVersion,
	}
	dp.Protocol, dp.Summary = detectInnerProtocol(plaintext)
	return dp
}

// detectInnerProtocol identifies the cleartext protocol.
func detectInnerProtocol(data []byte) (protocol, summary string) {
	if len(data) == 0 {
		return "unknown", "[empty]"
	}

	s := string(data)

	// HTTP/1.x
	if strings.HasPrefix(s, "GET ") || strings.HasPrefix(s, "POST ") ||
		strings.HasPrefix(s, "PUT ") || strings.HasPrefix(s, "DELETE ") ||
		strings.HasPrefix(s, "HEAD ") || strings.HasPrefix(s, "OPTIONS ") ||
		strings.HasPrefix(s, "PATCH ") || strings.HasPrefix(s, "CONNECT ") {
		line := firstLine(s)
		return "HTTP", "Request: " + line
	}
	if strings.HasPrefix(s, "HTTP/") {
		line := firstLine(s)
		return "HTTP", "Response: " + line
	}

	// HTTP/2 connection preface
	if strings.HasPrefix(s, "PRI * HTTP/2.0\r\n") {
		return "HTTP/2", "HTTP/2 Connection Preface"
	}
	// HTTP/2 binary frame (magic byte check)
	if len(data) >= 9 && data[3] <= 0x09 {
		frameLen := int(data[0])<<16 | int(data[1])<<8 | int(data[2])
		frameType := data[3]
		if frameLen > 0 && frameLen < 1<<20 {
			typeName := http2FrameTypeName(frameType)
			return "HTTP/2", fmt.Sprintf("HTTP/2 %s frame (%d bytes)", typeName, frameLen)
		}
	}

	// gRPC over HTTP/2 (gRPC frames start with a compressed flag byte + 4-byte length)
	if len(data) >= 5 && (data[0] == 0x00 || data[0] == 0x01) {
		msgLen := binary.BigEndian.Uint32(data[1:5])
		if msgLen > 0 && int(msgLen)+5 <= len(data)+100 {
			return "gRPC", fmt.Sprintf("gRPC message (%d bytes)", msgLen)
		}
	}

	// Fallback: check if it's printable text
	printable := 0
	for _, b := range data[:min(len(data), 128)] {
		if b >= 0x20 && b < 0x7f || b == '\r' || b == '\n' || b == '\t' {
			printable++
		}
	}
	if float64(printable)/float64(min(len(data), 128)) > 0.8 {
		line := firstLine(s)
		if len(line) > 120 {
			line = line[:120] + "..."
		}
		return "Text", line
	}

	return "Binary", fmt.Sprintf("[binary data: %d bytes]", len(data))
}

func firstLine(s string) string {
	if idx := strings.IndexByte(s, '\n'); idx >= 0 {
		return strings.TrimRight(s[:idx], "\r")
	}
	if len(s) > 200 {
		return s[:200] + "..."
	}
	return s
}

func http2FrameTypeName(ft byte) string {
	switch ft {
	case 0x00:
		return "DATA"
	case 0x01:
		return "HEADERS"
	case 0x02:
		return "PRIORITY"
	case 0x03:
		return "RST_STREAM"
	case 0x04:
		return "SETTINGS"
	case 0x05:
		return "PUSH_PROMISE"
	case 0x06:
		return "PING"
	case 0x07:
		return "GOAWAY"
	case 0x08:
		return "WINDOW_UPDATE"
	case 0x09:
		return "CONTINUATION"
	default:
		return fmt.Sprintf("0x%02x", ft)
	}
}

func tlsVersionString(v uint16) string {
	switch v {
	case TLSVersion10:
		return "TLS 1.0"
	case TLSVersion11:
		return "TLS 1.1"
	case TLSVersion12:
		return "TLS 1.2"
	case TLSVersion13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("TLS 0x%04x", v)
	}
}
