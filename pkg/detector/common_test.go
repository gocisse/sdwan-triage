package detector

import (
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func TestExtractIPInfo_NilPacket(t *testing.T) {
	result := ExtractIPInfo(nil)
	if result != nil {
		t.Errorf("ExtractIPInfo(nil) = %v, want nil", result)
	}
}

func TestExtractIPInfo_IPv4(t *testing.T) {
	// Create a mock IPv4 packet
	ip4 := &layers.IPv4{
		SrcIP:    []byte{192, 168, 1, 100},
		DstIP:    []byte{8, 8, 8, 8},
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{}
	err := ip4.SerializeTo(buf, opts)
	if err != nil {
		t.Skipf("Could not serialize IPv4 packet: %v", err)
	}

	packet := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeIPv4, gopacket.Default)
	result := ExtractIPInfo(packet)

	if result == nil {
		t.Fatal("ExtractIPInfo returned nil for valid IPv4 packet")
	}

	if result.IsIPv6 {
		t.Error("Expected IsIPv6 = false for IPv4 packet")
	}
}

func TestGetTransportPorts_NilPacket(t *testing.T) {
	srcPort, dstPort, protocol := GetTransportPorts(nil)
	if srcPort != 0 || dstPort != 0 || protocol != "" {
		t.Errorf("GetTransportPorts(nil) = (%d, %d, %q), want (0, 0, \"\")",
			srcPort, dstPort, protocol)
	}
}

func TestSafeGetTCPLayer_NilPacket(t *testing.T) {
	result := SafeGetTCPLayer(nil)
	if result != nil {
		t.Errorf("SafeGetTCPLayer(nil) = %v, want nil", result)
	}
}

func TestSafeGetUDPLayer_NilPacket(t *testing.T) {
	result := SafeGetUDPLayer(nil)
	if result != nil {
		t.Errorf("SafeGetUDPLayer(nil) = %v, want nil", result)
	}
}

func TestSafeGetDNSLayer_NilPacket(t *testing.T) {
	result := SafeGetDNSLayer(nil)
	if result != nil {
		t.Errorf("SafeGetDNSLayer(nil) = %v, want nil", result)
	}
}

func TestSafeGetARPLayer_NilPacket(t *testing.T) {
	result := SafeGetARPLayer(nil)
	if result != nil {
		t.Errorf("SafeGetARPLayer(nil) = %v, want nil", result)
	}
}

func TestSafeGetEthernetLayer_NilPacket(t *testing.T) {
	result := SafeGetEthernetLayer(nil)
	if result != nil {
		t.Errorf("SafeGetEthernetLayer(nil) = %v, want nil", result)
	}
}

func TestSafeGetTimestamp_NilPacket(t *testing.T) {
	result := SafeGetTimestamp(nil)
	if result != 0 {
		t.Errorf("SafeGetTimestamp(nil) = %v, want 0", result)
	}
}

func TestPacketIPInfo_Fields(t *testing.T) {
	info := &PacketIPInfo{
		SrcIP:    "192.168.1.1",
		DstIP:    "8.8.8.8",
		TTL:      64,
		IsIPv6:   false,
		Protocol: 6, // TCP
	}

	if info.SrcIP != "192.168.1.1" {
		t.Errorf("SrcIP = %q, want %q", info.SrcIP, "192.168.1.1")
	}
	if info.DstIP != "8.8.8.8" {
		t.Errorf("DstIP = %q, want %q", info.DstIP, "8.8.8.8")
	}
	if info.TTL != 64 {
		t.Errorf("TTL = %d, want %d", info.TTL, 64)
	}
	if info.IsIPv6 {
		t.Error("IsIPv6 = true, want false")
	}
	if info.Protocol != 6 {
		t.Errorf("Protocol = %d, want %d", info.Protocol, 6)
	}
}
