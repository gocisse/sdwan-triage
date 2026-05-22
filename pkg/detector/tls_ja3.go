package detector

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"strings"
)

// GREASE values defined by RFC 8701 — these must be excluded from JA3/JA3S
// to produce stable fingerprints regardless of GREASE randomization.
var greaseValues = map[uint16]bool{
	0x0a0a: true, 0x1a1a: true, 0x2a2a: true, 0x3a3a: true,
	0x4a4a: true, 0x5a5a: true, 0x6a6a: true, 0x7a7a: true,
	0x8a8a: true, 0x9a9a: true, 0xaaaa: true, 0xbaba: true,
	0xcaca: true, 0xdada: true, 0xeaea: true, 0xfafa: true,
}

func isGREASE(val uint16) bool {
	return greaseValues[val]
}

// JA3Result holds the computed JA3 fingerprint
type JA3Result struct {
	Hash      string // MD5 hex digest
	RawString string // The full JA3 string before hashing (useful for debugging)
}

// ComputeJA3 computes the JA3 fingerprint from a TLS ClientHello payload.
// The payload must start at the TLS record layer (content type byte).
// Returns nil if the payload is not a valid ClientHello.
//
// JA3 string format: SSLVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats
// Each list is dash-separated. GREASE values are excluded.
func ComputeJA3(payload []byte) *JA3Result {
	// Must be a TLS Handshake record
	if len(payload) < 6 || payload[0] != 0x16 {
		return nil
	}

	// TLS record header: content_type(1) + version(2) + length(2)
	recordLen := int(payload[3])<<8 | int(payload[4])
	if len(payload) < 5+recordLen {
		return nil
	}

	handshake := payload[5:]
	// Must be ClientHello (handshake type 0x01)
	if len(handshake) < 4 || handshake[0] != 0x01 {
		return nil
	}

	hsLen := int(handshake[1])<<16 | int(handshake[2])<<8 | int(handshake[3])
	if len(handshake) < 4+hsLen {
		return nil
	}

	ch := handshake[4:] // ClientHello body

	// ClientHello: version(2) + random(32) = 34 bytes minimum
	if len(ch) < 34 {
		return nil
	}

	// TLS version from ClientHello (not the record layer version)
	tlsVersion := uint16(ch[0])<<8 | uint16(ch[1])
	pos := 34 // past version + random

	// Session ID
	if pos >= len(ch) {
		return nil
	}
	sessionIDLen := int(ch[pos])
	pos += 1 + sessionIDLen

	// Cipher Suites
	if pos+2 > len(ch) {
		return nil
	}
	cipherSuitesLen := int(ch[pos])<<8 | int(ch[pos+1])
	pos += 2

	if pos+cipherSuitesLen > len(ch) {
		return nil
	}
	var cipherSuites []uint16
	for i := 0; i < cipherSuitesLen; i += 2 {
		cs := uint16(ch[pos+i])<<8 | uint16(ch[pos+i+1])
		if !isGREASE(cs) {
			cipherSuites = append(cipherSuites, cs)
		}
	}
	pos += cipherSuitesLen

	// Compression Methods
	if pos >= len(ch) {
		return nil
	}
	compressionLen := int(ch[pos])
	pos += 1 + compressionLen

	// Extensions
	var extensions []uint16
	var ellipticCurves []uint16
	var ecPointFormats []uint8

	if pos+2 <= len(ch) {
		extensionsLen := int(ch[pos])<<8 | int(ch[pos+1])
		pos += 2

		extensionsEnd := pos + extensionsLen
		if extensionsEnd > len(ch) {
			extensionsEnd = len(ch)
		}

		for pos+4 <= extensionsEnd {
			extType := uint16(ch[pos])<<8 | uint16(ch[pos+1])
			extLen := int(ch[pos+2])<<8 | int(ch[pos+3])
			pos += 4

			if !isGREASE(extType) {
				extensions = append(extensions, extType)
			}

			extData := ch[pos:]
			if pos+extLen <= extensionsEnd {
				extData = ch[pos : pos+extLen]
			}

			// Supported Groups (elliptic_curves) — extension type 10
			if extType == 0x000a && len(extData) >= 2 {
				groupsLen := int(extData[0])<<8 | int(extData[1])
				for i := 2; i+1 < 2+groupsLen && i+1 < len(extData); i += 2 {
					group := uint16(extData[i])<<8 | uint16(extData[i+1])
					if !isGREASE(group) {
						ellipticCurves = append(ellipticCurves, group)
					}
				}
			}

			// EC Point Formats — extension type 11
			if extType == 0x000b && len(extData) >= 1 {
				formatsLen := int(extData[0])
				for i := 1; i < 1+formatsLen && i < len(extData); i++ {
					ecPointFormats = append(ecPointFormats, extData[i])
				}
			}

			pos += extLen
		}
	}

	// Build JA3 string: SSLVersion,Ciphers,Extensions,EllipticCurves,ECPointFormats
	ja3Str := fmt.Sprintf("%d,%s,%s,%s,%s",
		tlsVersion,
		uint16ListToDash(cipherSuites),
		uint16ListToDash(extensions),
		uint16ListToDash(ellipticCurves),
		uint8ListToDash(ecPointFormats),
	)

	hash := md5.Sum([]byte(ja3Str))
	return &JA3Result{
		Hash:      hex.EncodeToString(hash[:]),
		RawString: ja3Str,
	}
}

// ComputeJA3S computes the JA3S fingerprint from a TLS ServerHello payload.
// The payload must start at the TLS record layer (content type byte).
// Returns nil if the payload is not a valid ServerHello.
//
// JA3S string format: SSLVersion,CipherSuite,Extensions
func ComputeJA3S(payload []byte) *JA3Result {
	// Must be a TLS Handshake record
	if len(payload) < 6 || payload[0] != 0x16 {
		return nil
	}

	recordLen := int(payload[3])<<8 | int(payload[4])
	if len(payload) < 5+recordLen {
		return nil
	}

	handshake := payload[5:]
	// Must be ServerHello (handshake type 0x02)
	if len(handshake) < 4 || handshake[0] != 0x02 {
		return nil
	}

	hsLen := int(handshake[1])<<16 | int(handshake[2])<<8 | int(handshake[3])
	if len(handshake) < 4+hsLen {
		return nil
	}

	sh := handshake[4:] // ServerHello body

	// ServerHello: version(2) + random(32) = 34 bytes minimum
	if len(sh) < 34 {
		return nil
	}

	tlsVersion := uint16(sh[0])<<8 | uint16(sh[1])
	pos := 34

	// Session ID
	if pos >= len(sh) {
		return nil
	}
	sessionIDLen := int(sh[pos])
	pos += 1 + sessionIDLen

	// Cipher Suite (single, 2 bytes)
	if pos+2 > len(sh) {
		return nil
	}
	cipherSuite := uint16(sh[pos])<<8 | uint16(sh[pos+1])
	pos += 2

	// Compression Method (single, 1 byte)
	if pos >= len(sh) {
		return nil
	}
	pos += 1

	// Extensions
	var extensions []uint16
	if pos+2 <= len(sh) {
		extensionsLen := int(sh[pos])<<8 | int(sh[pos+1])
		pos += 2

		extensionsEnd := pos + extensionsLen
		if extensionsEnd > len(sh) {
			extensionsEnd = len(sh)
		}

		for pos+4 <= extensionsEnd {
			extType := uint16(sh[pos])<<8 | uint16(sh[pos+1])
			extLen := int(sh[pos+2])<<8 | int(sh[pos+3])
			pos += 4

			if !isGREASE(extType) {
				extensions = append(extensions, extType)
			}

			pos += extLen
		}
	}

	// Build JA3S string: SSLVersion,CipherSuite,Extensions
	ja3sStr := fmt.Sprintf("%d,%d,%s",
		tlsVersion,
		cipherSuite,
		uint16ListToDash(extensions),
	)

	hash := md5.Sum([]byte(ja3sStr))
	return &JA3Result{
		Hash:      hex.EncodeToString(hash[:]),
		RawString: ja3sStr,
	}
}

// uint16ListToDash joins a uint16 slice into a dash-separated string
func uint16ListToDash(vals []uint16) string {
	parts := make([]string, len(vals))
	for i, v := range vals {
		parts[i] = fmt.Sprintf("%d", v)
	}
	return strings.Join(parts, "-")
}

// uint8ListToDash joins a uint8 slice into a dash-separated string
func uint8ListToDash(vals []uint8) string {
	parts := make([]string, len(vals))
	for i, v := range vals {
		parts[i] = fmt.Sprintf("%d", v)
	}
	return strings.Join(parts, "-")
}
