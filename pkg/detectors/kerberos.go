package detectors

import (
	"github.com/gocisse/sdwan-triage/pkg/models"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type KerberosDetector struct {
	flows map[string]*models.KerberosFlow
}

func NewKerberosDetector() *KerberosDetector {
	return &KerberosDetector{
		flows: make(map[string]*models.KerberosFlow),
	}
}

func (d *KerberosDetector) ProcessPacket(packet gopacket.Packet) {
	// Kerberos can run over TCP or UDP
	var srcPort, dstPort uint16
	var payload []byte

	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		srcPort = uint16(tcp.SrcPort)
		dstPort = uint16(tcp.DstPort)

		if appLayer := packet.ApplicationLayer(); appLayer != nil {
			payload = appLayer.Payload()
		}
	} else if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp, _ := udpLayer.(*layers.UDP)
		srcPort = uint16(udp.SrcPort)
		dstPort = uint16(udp.DstPort)

		if appLayer := packet.ApplicationLayer(); appLayer != nil {
			payload = appLayer.Payload()
		}
	} else {
		return
	}

	// Kerberos typically runs on port 88
	if srcPort != 88 && dstPort != 88 {
		return
	}

	if len(payload) < 4 {
		return
	}

	// Kerberos uses ASN.1 DER encoding
	// Check for Kerberos application tag (0x6A for AS-REQ, 0x6B for AS-REP, etc.)
	if payload[0] != 0x6A && payload[0] != 0x6B && payload[0] != 0x6C &&
		payload[0] != 0x6D && payload[0] != 0x6E && payload[0] != 0x6F {
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

	messageType := getKerberosMessageType(payload[0])

	flow, exists := d.flows[flowKey]
	if !exists {
		flow = &models.KerberosFlow{
			SrcIP:       srcIP,
			DstIP:       dstIP,
			SrcPort:     srcPort,
			DstPort:     dstPort,
			MessageType: messageType,
			FirstSeen:   timestamp,
		}
		d.flows[flowKey] = flow
	}

	flow.PacketCount++
	flow.ByteCount += uint64(len(payload))
	flow.LastSeen = timestamp

	// Update message type if it's more specific
	if messageType != "" {
		flow.MessageType = messageType
	}
}

func (d *KerberosDetector) GetFlows() []models.KerberosFlow {
	flows := make([]models.KerberosFlow, 0, len(d.flows))
	for _, flow := range d.flows {
		flows = append(flows, *flow)
	}
	return flows
}

func getKerberosMessageType(tag byte) string {
	messageTypes := map[byte]string{
		0x6A: "AS-REQ",  // Authentication Service Request
		0x6B: "AS-REP",  // Authentication Service Reply
		0x6C: "TGS-REQ", // Ticket Granting Service Request
		0x6D: "TGS-REP", // Ticket Granting Service Reply
		0x6E: "AP-REQ",  // Application Request
		0x6F: "AP-REP",  // Application Reply
		0x74: "KRB-SAFE",
		0x75: "KRB-PRIV",
		0x76: "KRB-CRED",
		0x7E: "KRB-ERROR",
	}
	if msgType, ok := messageTypes[tag]; ok {
		return msgType
	}
	return "Unknown"
}
