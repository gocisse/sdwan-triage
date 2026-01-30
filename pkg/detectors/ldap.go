package detectors

import (
	"github.com/gocisse/sdwan-triage/pkg/models"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type LDAPDetector struct {
	flows map[string]*models.LDAPFlow
}

func NewLDAPDetector() *LDAPDetector {
	return &LDAPDetector{
		flows: make(map[string]*models.LDAPFlow),
	}
}

func (d *LDAPDetector) ProcessPacket(packet gopacket.Packet) {
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		return
	}

	tcp, _ := tcpLayer.(*layers.TCP)

	// LDAP typically runs on port 389 (LDAP) or 636 (LDAPS)
	isLDAP := tcp.DstPort == 389 || tcp.SrcPort == 389
	isLDAPS := tcp.DstPort == 636 || tcp.SrcPort == 636

	if !isLDAP && !isLDAPS {
		return
	}

	appLayer := packet.ApplicationLayer()
	if appLayer == nil {
		return
	}

	payload := appLayer.Payload()
	if len(payload) < 2 {
		return
	}

	// LDAP uses ASN.1 BER encoding, starts with 0x30 (SEQUENCE)
	if payload[0] != 0x30 {
		return
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

	flowKey := srcIP + ":" + dstIP
	timestamp := float64(packet.Metadata().Timestamp.Unix()) + float64(packet.Metadata().Timestamp.Nanosecond())/1e9

	flow, exists := d.flows[flowKey]
	if !exists {
		flow = &models.LDAPFlow{
			SrcIP:     srcIP,
			DstIP:     dstIP,
			SrcPort:   uint16(tcp.SrcPort),
			DstPort:   uint16(tcp.DstPort),
			FirstSeen: timestamp,
			IsSecure:  isLDAPS,
		}
		d.flows[flowKey] = flow
	}

	flow.PacketCount++
	flow.ByteCount += uint64(len(payload))
	flow.LastSeen = timestamp

	// Parse LDAP operation type from ASN.1 tag
	if len(payload) >= 8 {
		operation := parseLDAPOperation(payload)
		if operation != "" {
			flow.Operation = operation
		}
	}
}

func (d *LDAPDetector) GetFlows() []models.LDAPFlow {
	flows := make([]models.LDAPFlow, 0, len(d.flows))
	for _, flow := range d.flows {
		flows = append(flows, *flow)
	}
	return flows
}

func parseLDAPOperation(payload []byte) string {
	// LDAP operations are encoded as context-specific tags
	// Search through the payload for operation tags
	for i := 0; i < len(payload)-1; i++ {
		if payload[i] >= 0x60 && payload[i] <= 0x7F {
			tag := payload[i] & 0x1F
			operations := map[byte]string{
				0x00: "bind",
				0x01: "bind response",
				0x02: "unbind",
				0x03: "search",
				0x04: "search result entry",
				0x05: "search result done",
				0x06: "modify",
				0x07: "modify response",
				0x08: "add",
				0x09: "add response",
				0x0A: "delete",
				0x0B: "delete response",
				0x0C: "modify DN",
				0x0D: "modify DN response",
				0x0E: "compare",
				0x0F: "compare response",
			}
			if op, ok := operations[tag]; ok {
				return op
			}
		}
	}
	return ""
}
