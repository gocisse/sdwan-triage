package detectors

import (
	"encoding/binary"

	"github.com/gocisse/sdwan-triage/pkg/models"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type SMBDetector struct {
	flows map[string]*models.SMBFlow
}

func NewSMBDetector() *SMBDetector {
	return &SMBDetector{
		flows: make(map[string]*models.SMBFlow),
	}
}

func (d *SMBDetector) ProcessPacket(packet gopacket.Packet) {
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		return
	}

	tcp, _ := tcpLayer.(*layers.TCP)

	// SMB typically runs on ports 445 (SMB) or 139 (NetBIOS)
	if tcp.DstPort != 445 && tcp.SrcPort != 445 && tcp.DstPort != 139 && tcp.SrcPort != 139 {
		return
	}

	appLayer := packet.ApplicationLayer()
	if appLayer == nil {
		return
	}

	payload := appLayer.Payload()
	if len(payload) < 4 {
		return
	}

	// Check for SMB/SMB2/SMB3 signature
	var version string
	var isEncrypted bool

	// SMB1: 0xFF 'S' 'M' 'B'
	if payload[0] == 0xFF && payload[1] == 'S' && payload[2] == 'M' && payload[3] == 'B' {
		version = "SMB1"
	} else if payload[0] == 0xFE && payload[1] == 'S' && payload[2] == 'M' && payload[3] == 'B' {
		// SMB2/SMB3: 0xFE 'S' 'M' 'B'
		version = "SMB2/SMB3"
		// Check for encryption transform header (0xFD 'S' 'M' 'B')
		if len(payload) > 4 && payload[0] == 0xFD {
			isEncrypted = true
		}
	} else {
		return // Not SMB traffic
	}

	networkLayer := packet.NetworkLayer()
	if networkLayer == nil {
		return
	}

	var srcIP, dstIP string
	if ipv4Layer := packet.Layer(layers.LayerTypeIPv4); ipv4Layer != nil {
		ipv4, _ := ipv4Layer.(*layers.IPv4)
		srcIP = ipv4.SrcIP.String()
		dstIP = ipv4.DstIP.String()
	} else if ipv6Layer := packet.Layer(layers.LayerTypeIPv6); ipv6Layer != nil {
		ipv6, _ := ipv6Layer.(*layers.IPv6)
		srcIP = ipv6.SrcIP.String()
		dstIP = ipv6.DstIP.String()
	} else {
		return
	}

	flowKey := srcIP + ":" + dstIP + ":" + version
	timestamp := float64(packet.Metadata().Timestamp.Unix()) + float64(packet.Metadata().Timestamp.Nanosecond())/1e9

	flow, exists := d.flows[flowKey]
	if !exists {
		flow = &models.SMBFlow{
			SrcIP:       srcIP,
			DstIP:       dstIP,
			SrcPort:     uint16(tcp.SrcPort),
			DstPort:     uint16(tcp.DstPort),
			Version:     version,
			FirstSeen:   timestamp,
			IsEncrypted: isEncrypted,
		}
		d.flows[flowKey] = flow
	}

	flow.PacketCount++
	flow.ByteCount += uint64(len(payload))
	flow.LastSeen = timestamp

	// Parse SMB command if available
	if len(payload) >= 8 {
		if version == "SMB1" && len(payload) >= 9 {
			command := payload[4]
			flow.Command = getSMB1Command(command)
		} else if version == "SMB2/SMB3" && len(payload) >= 16 {
			command := binary.LittleEndian.Uint16(payload[12:14])
			flow.Command = getSMB2Command(command)
		}
	}
}

func (d *SMBDetector) GetFlows() []models.SMBFlow {
	flows := make([]models.SMBFlow, 0, len(d.flows))
	for _, flow := range d.flows {
		flows = append(flows, *flow)
	}
	return flows
}

func getSMB1Command(cmd byte) string {
	commands := map[byte]string{
		0x72: "Negotiate Protocol",
		0x73: "Session Setup",
		0x75: "Tree Connect",
		0x2D: "Open File",
		0x2E: "Read File",
		0x2F: "Write File",
		0x04: "Close",
		0x71: "Tree Disconnect",
		0x74: "Logoff",
	}
	if name, ok := commands[cmd]; ok {
		return name
	}
	return "Unknown"
}

func getSMB2Command(cmd uint16) string {
	commands := map[uint16]string{
		0x0000: "Negotiate",
		0x0001: "Session Setup",
		0x0002: "Logoff",
		0x0003: "Tree Connect",
		0x0004: "Tree Disconnect",
		0x0005: "Create",
		0x0006: "Close",
		0x0008: "Read",
		0x0009: "Write",
		0x0010: "Query Info",
		0x0011: "Set Info",
	}
	if name, ok := commands[cmd]; ok {
		return name
	}
	return "Unknown"
}
