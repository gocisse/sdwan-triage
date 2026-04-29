package analyzer

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

// ─── Key Log Parsing Tests ──────────────────────────────────────

func TestParseKeyLogLine_ClientRandom(t *testing.T) {
	cr := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	secret := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	line := "CLIENT_RANDOM " + cr + " " + secret

	entry, err := parseKeyLogLine(line)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if entry.Label != LabelClientRandom {
		t.Errorf("label = %q, want CLIENT_RANDOM", entry.Label)
	}
	if hex.EncodeToString(entry.ClientRandom[:]) != cr {
		t.Errorf("client random mismatch")
	}
	if hex.EncodeToString(entry.Secret) != secret {
		t.Errorf("secret mismatch")
	}
}

func TestParseKeyLogLine_TLS13Labels(t *testing.T) {
	cr := "0102030405060708091011121314151617181920212223242526272829303132"
	secret := "aabbccdd"

	for _, label := range []KeyLogLabel{
		LabelClientHandshakeTraffic,
		LabelServerHandshakeTraffic,
		LabelClientTrafficSecret0,
		LabelServerTrafficSecret0,
		LabelExporterSecret,
	} {
		line := string(label) + " " + cr + " " + secret
		entry, err := parseKeyLogLine(line)
		if err != nil {
			t.Fatalf("label %s: unexpected error: %v", label, err)
		}
		if entry.Label != label {
			t.Errorf("got label %q, want %q", entry.Label, label)
		}
	}
}

func TestParseKeyLogLine_InvalidLabel(t *testing.T) {
	line := "UNKNOWN_LABEL aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa bbbb"
	_, err := parseKeyLogLine(line)
	if err == nil {
		t.Error("expected error for unknown label")
	}
}

func TestParseKeyLogLine_ShortClientRandom(t *testing.T) {
	line := "CLIENT_RANDOM aabb ccdd"
	_, err := parseKeyLogLine(line)
	if err == nil {
		t.Error("expected error for short client random")
	}
}

func TestParseKeyLogLine_InvalidHex(t *testing.T) {
	cr := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	line := "CLIENT_RANDOM " + cr + " ZZZZ"
	_, err := parseKeyLogLine(line)
	if err == nil {
		t.Error("expected error for invalid hex secret")
	}
}

func TestParseKeyLogLine_WrongFieldCount(t *testing.T) {
	_, err := parseKeyLogLine("CLIENT_RANDOM onlytwo")
	if err == nil {
		t.Error("expected error for wrong field count")
	}
}

func TestParseKeyLogFile_Valid(t *testing.T) {
	content := `# NSS Key Log File
CLIENT_RANDOM aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
CLIENT_TRAFFIC_SECRET_0 cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd
`
	dir := t.TempDir()
	path := filepath.Join(dir, "keylog.txt")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("write temp file: %v", err)
	}

	kl, err := ParseKeyLogFile(path)
	if err != nil {
		t.Fatalf("ParseKeyLogFile: %v", err)
	}
	if kl.SessionCount() != 2 {
		t.Errorf("SessionCount = %d, want 2", kl.SessionCount())
	}
	if kl.EntryCount() != 2 {
		t.Errorf("EntryCount = %d, want 2", kl.EntryCount())
	}
}

func TestParseKeyLogFile_EmptyPath(t *testing.T) {
	kl, err := ParseKeyLogFile("")
	if err != nil {
		t.Errorf("empty path should return nil, nil; got err: %v", err)
	}
	if kl != nil {
		t.Errorf("expected nil keylog for empty path")
	}
}

func TestParseKeyLogFile_AllCommentsOrEmpty(t *testing.T) {
	content := "# just comments\n\n# another comment\n"
	dir := t.TempDir()
	path := filepath.Join(dir, "empty.txt")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}

	_, err := ParseKeyLogFile(path)
	if err == nil {
		t.Error("expected error for file with no valid entries")
	}
}

func TestParseKeyLogFile_MissingFile(t *testing.T) {
	_, err := ParseKeyLogFile("/nonexistent/keylog.txt")
	if err == nil {
		t.Error("expected error for missing file")
	}
}

func TestKeyLog_LookupAndAdd(t *testing.T) {
	kl := NewKeyLog()
	cr := [32]byte{}
	for i := range cr {
		cr[i] = byte(i)
	}

	e1 := KeyLogEntry{Label: LabelClientRandom, ClientRandom: cr, Secret: []byte("secret1")}
	e2 := KeyLogEntry{Label: LabelClientTrafficSecret0, ClientRandom: cr, Secret: []byte("secret2")}
	kl.Add(e1)
	kl.Add(e2)

	entries := kl.Lookup(cr)
	if len(entries) != 2 {
		t.Fatalf("Lookup returned %d entries, want 2", len(entries))
	}

	if kl.SessionCount() != 1 {
		t.Errorf("SessionCount = %d, want 1", kl.SessionCount())
	}
	if kl.EntryCount() != 2 {
		t.Errorf("EntryCount = %d, want 2", kl.EntryCount())
	}
}

func TestKeyLog_LookupMiss(t *testing.T) {
	kl := NewKeyLog()
	cr := [32]byte{0xff}
	entries := kl.Lookup(cr)
	if len(entries) != 0 {
		t.Errorf("expected empty, got %d entries", len(entries))
	}
}

// ─── Client Random Extraction ───────────────────────────────────

func TestExtractClientRandom_Valid(t *testing.T) {
	// Minimal ClientHello: TLS record header (5) + handshake type (1) + hs length (3) + version (2) + random (32)
	data := make([]byte, 5+1+3+2+32)
	data[0] = 0x16 // Handshake
	data[1] = 0x03 // TLS 1.2
	data[2] = 0x03
	data[3] = 0x00 // Record length high
	data[4] = byte(len(data) - 5)
	data[5] = 0x01 // ClientHello
	// handshake length bytes [6..8]
	data[6] = 0x00
	data[7] = 0x00
	data[8] = byte(2 + 32)
	// version [9..10]
	data[9] = 0x03
	data[10] = 0x03
	// random [11..42] — fill with known pattern
	for i := 0; i < 32; i++ {
		data[11+i] = byte(i + 1)
	}

	cr, ok := ExtractClientRandom(data)
	if !ok {
		t.Fatal("ExtractClientRandom returned false")
	}
	for i := 0; i < 32; i++ {
		if cr[i] != byte(i+1) {
			t.Fatalf("client random byte %d = %d, want %d", i, cr[i], i+1)
		}
	}
}

func TestExtractClientRandom_NotHandshake(t *testing.T) {
	data := []byte{0x17, 0x03, 0x03, 0x00, 0x10} // ApplicationData
	_, ok := ExtractClientRandom(data)
	if ok {
		t.Error("expected false for ApplicationData record")
	}
}

func TestExtractClientRandom_TooShort(t *testing.T) {
	data := []byte{0x16, 0x03}
	_, ok := ExtractClientRandom(data)
	if ok {
		t.Error("expected false for short data")
	}
}

// ─── Decryptor Availability ─────────────────────────────────────

func TestTLSDecryptor_NilSafe(t *testing.T) {
	var d *TLSDecryptor
	if d.Available() {
		t.Error("nil decryptor should not be available")
	}
	cr := [32]byte{}
	result := d.TryDecryptRecord([]byte{0x17, 0x03, 0x03, 0x00, 0x30}, cr, true)
	if result != nil {
		t.Error("expected nil from nil decryptor")
	}
}

func TestTLSDecryptor_NoKeys(t *testing.T) {
	kl := NewKeyLog()
	d := NewTLSDecryptor(kl)
	if d.Available() {
		t.Error("empty keylog should not be available")
	}
}

func TestNewTLSDecryptor_NilKeyLog(t *testing.T) {
	d := NewTLSDecryptor(nil)
	if d != nil {
		t.Error("expected nil decryptor when keylog is nil")
	}
}

// ─── Protocol Detection ─────────────────────────────────────────

func TestDetectInnerProtocol_HTTP(t *testing.T) {
	tests := []struct {
		input     string
		wantProto string
	}{
		{"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n", "HTTP"},
		{"POST /api/data HTTP/1.1\r\n", "HTTP"},
		{"HTTP/1.1 200 OK\r\n", "HTTP"},
		{"PUT /resource HTTP/1.1\r\n", "HTTP"},
		{"DELETE /item/123 HTTP/1.1\r\n", "HTTP"},
	}
	for _, tt := range tests {
		proto, _ := detectInnerProtocol([]byte(tt.input))
		if proto != tt.wantProto {
			t.Errorf("detectInnerProtocol(%q) = %q, want %q", tt.input[:20], proto, tt.wantProto)
		}
	}
}

func TestDetectInnerProtocol_HTTP2Preface(t *testing.T) {
	proto, _ := detectInnerProtocol([]byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"))
	if proto != "HTTP/2" {
		t.Errorf("got %q, want HTTP/2", proto)
	}
}

func TestDetectInnerProtocol_Binary(t *testing.T) {
	data := make([]byte, 64)
	for i := range data {
		data[i] = byte(i + 0x80) // high bytes → not printable, not HTTP/2 frame
	}
	proto, _ := detectInnerProtocol(data)
	if proto != "Binary" {
		t.Errorf("got %q, want Binary", proto)
	}
}

func TestDetectInnerProtocol_Empty(t *testing.T) {
	proto, _ := detectInnerProtocol(nil)
	if proto != "unknown" {
		t.Errorf("got %q, want unknown", proto)
	}
}

// ─── AES-GCM Round-Trip (TLS 1.2 style) ────────────────────────

func TestDecryptAESGCM12_RoundTrip(t *testing.T) {
	key := make([]byte, 16)
	for i := range key {
		key[i] = byte(i)
	}
	implicitIV := []byte{0xaa, 0xbb, 0xcc, 0xdd}
	explicitNonce := []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01}

	// Build nonce
	nonce := make([]byte, 12)
	copy(nonce[:4], implicitIV)
	copy(nonce[4:], explicitNonce)

	// Encrypt
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	plaintext := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)

	// Build TLS 1.2 record: explicitNonce + ciphertext
	record := append(explicitNonce, ciphertext...)

	got := decryptAESGCM12(key, implicitIV, record)
	if got == nil {
		t.Fatal("decryptAESGCM12 returned nil")
	}
	if string(got) != string(plaintext) {
		t.Errorf("decrypted = %q, want %q", got, plaintext)
	}
}

func TestDecryptAESGCM12_BadKey(t *testing.T) {
	key := make([]byte, 16)
	iv := make([]byte, 4)
	record := make([]byte, 8+32+16) // nonce + some ciphertext + tag
	got := decryptAESGCM12(key, iv, record)
	// Should return nil (bad ciphertext / authentication failure)
	if got != nil {
		t.Error("expected nil for invalid ciphertext")
	}
}

// ─── TLS Version String ─────────────────────────────────────────

func TestTLSVersionString(t *testing.T) {
	tests := []struct {
		v    uint16
		want string
	}{
		{0x0301, "TLS 1.0"},
		{0x0302, "TLS 1.1"},
		{0x0303, "TLS 1.2"},
		{0x0304, "TLS 1.3"},
		{0x0305, "TLS 0x0305"},
	}
	for _, tt := range tests {
		if got := tlsVersionString(tt.v); got != tt.want {
			t.Errorf("tlsVersionString(0x%04x) = %q, want %q", tt.v, got, tt.want)
		}
	}
}
