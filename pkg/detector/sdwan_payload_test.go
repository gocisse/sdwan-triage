package detector

import (
	"testing"
)

func TestAnalyzePayload_ViptelaDTLS(t *testing.T) {
	// Viptela DTLS overlay: 0x16 0xFE 0xFD
	payload := []byte{0x16, 0xFE, 0xFD, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03}
	vendor, sig := AnalyzePayload(payload)
	if vendor != "viptela" {
		t.Errorf("vendor = %q, want %q", vendor, "viptela")
	}
	if sig == "" {
		t.Error("expected non-empty signature description")
	}
}

func TestAnalyzePayload_VeloCloudVCMP(t *testing.T) {
	// VeloCloud VCMP header: "VCMP"
	payload := []byte{0x56, 0x43, 0x4D, 0x50, 0x01, 0x02, 0x03, 0x04}
	vendor, sig := AnalyzePayload(payload)
	if vendor != "velocloud" {
		t.Errorf("vendor = %q, want %q", vendor, "velocloud")
	}
	if sig == "" {
		t.Error("expected non-empty signature description")
	}
}

func TestAnalyzePayload_FortinetFGCP(t *testing.T) {
	// FortiGate FGCP Heartbeat: "FGCP"
	payload := []byte{0x46, 0x47, 0x43, 0x50, 0x00, 0x01, 0x02, 0x03}
	vendor, sig := AnalyzePayload(payload)
	if vendor != "fortinet" {
		t.Errorf("vendor = %q, want %q", vendor, "fortinet")
	}
	if sig == "" {
		t.Error("expected non-empty signature description")
	}
}

func TestAnalyzePayload_NoMatch(t *testing.T) {
	payload := []byte{0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04}
	vendor, sig := AnalyzePayload(payload)
	if vendor != "" {
		t.Errorf("vendor = %q, want empty for unknown payload", vendor)
	}
	if sig != "" {
		t.Errorf("sig = %q, want empty for unknown payload", sig)
	}
}

func TestAnalyzePayload_TooShort(t *testing.T) {
	vendor, sig := AnalyzePayload([]byte{0x01})
	if vendor != "" || sig != "" {
		t.Error("expected empty result for payload shorter than 2 bytes")
	}
}

func TestAnalyzePayload_SilverPeak(t *testing.T) {
	// Silver Peak tunnel: "SPEC"
	payload := []byte{0x53, 0x50, 0x45, 0x43, 0x00, 0x00, 0x00, 0x00}
	vendor, sig := AnalyzePayload(payload)
	if vendor != "silverpeak" {
		t.Errorf("vendor = %q, want %q", vendor, "silverpeak")
	}
	if sig == "" {
		t.Error("expected non-empty signature description")
	}
}

func TestAnalyzePayload_VersaFlexVNF(t *testing.T) {
	// Versa FlexVNF: "VRSA"
	payload := []byte{0x56, 0x52, 0x53, 0x41, 0x01, 0x02, 0x03, 0x04}
	vendor, sig := AnalyzePayload(payload)
	if vendor != "versa" {
		t.Errorf("vendor = %q, want %q", vendor, "versa")
	}
	if sig == "" {
		t.Error("expected non-empty signature description")
	}
}

func TestIsStandardPort(t *testing.T) {
	standardPorts := []uint16{53, 80, 443, 8080, 8443, 22, 23, 25, 110, 143, 993, 995, 3389}
	for _, port := range standardPorts {
		if !isStandardPort(port) {
			t.Errorf("port %d should be standard", port)
		}
	}

	nonStandardPorts := []uint16{12346, 2426, 541, 4163, 4980, 4566, 9999}
	for _, port := range nonStandardPorts {
		if isStandardPort(port) {
			t.Errorf("port %d should NOT be standard", port)
		}
	}
}

func TestIsValidHostname(t *testing.T) {
	valid := []string{"vmanage.example.com", "vbond-01.cisco.com", "vedge.test.net"}
	for _, h := range valid {
		if !isValidHostname(h) {
			t.Errorf("%q should be valid hostname", h)
		}
	}

	invalid := []string{"", "nodots", "has spaces.com", "has_underscore.com"}
	for _, h := range invalid {
		if isValidHostname(h) {
			t.Errorf("%q should be invalid hostname", h)
		}
	}
}

func TestMatchPayloadSignature_FixedOffset(t *testing.T) {
	sig := PayloadSignature{Offset: 2, Magic: []byte{0xAA, 0xBB}}
	payload := []byte{0x00, 0x00, 0xAA, 0xBB, 0x00}

	if !matchPayloadSignature(payload, sig) {
		t.Error("expected match at offset 2")
	}

	noMatch := []byte{0xAA, 0xBB, 0x00, 0x00, 0x00}
	if matchPayloadSignature(noMatch, sig) {
		t.Error("should not match at wrong offset")
	}
}

func TestMatchPayloadSignature_ScanAnywhere(t *testing.T) {
	sig := PayloadSignature{Offset: -1, Magic: []byte{0xCC, 0xDD}}
	payload := []byte{0x00, 0x01, 0x02, 0xCC, 0xDD, 0x03}

	if !matchPayloadSignature(payload, sig) {
		t.Error("expected match anywhere in payload")
	}
}

func TestPayloadHexDump(t *testing.T) {
	payload := []byte{0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02}
	dump := PayloadHexDump(payload, 4)
	if dump != "deadbeef" {
		t.Errorf("dump = %q, want %q", dump, "deadbeef")
	}
}
