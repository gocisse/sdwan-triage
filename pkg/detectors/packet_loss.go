package detectors

import (
	"github.com/gocisse/sdwan-triage/pkg/models"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type PacketLossDetector struct {
	tcpFlows        map[string]*tcpFlowState
	totalPackets    uint64
	retransmissions uint64
}

type tcpFlowState struct {
	srcIP           string
	dstIP           string
	srcPort         uint16
	dstPort         uint16
	seqNumbers      map[uint32]bool
	packetsSent     uint64
	retransmissions uint64
	outOfOrder      uint64
	duplicates      uint64
}

func NewPacketLossDetector() *PacketLossDetector {
	return &PacketLossDetector{
		tcpFlows: make(map[string]*tcpFlowState),
	}
}

func (d *PacketLossDetector) ProcessPacket(packet gopacket.Packet) {
	d.totalPackets++

	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		return
	}

	tcp, _ := tcpLayer.(*layers.TCP)
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

	flowKey := getFlowKey(srcIP, dstIP, uint16(tcp.SrcPort), uint16(tcp.DstPort))

	flow, exists := d.tcpFlows[flowKey]
	if !exists {
		flow = &tcpFlowState{
			srcIP:      srcIP,
			dstIP:      dstIP,
			srcPort:    uint16(tcp.SrcPort),
			dstPort:    uint16(tcp.DstPort),
			seqNumbers: make(map[uint32]bool),
		}
		d.tcpFlows[flowKey] = flow
	}

	flow.packetsSent++

	// Check for retransmission
	if tcp.SYN || tcp.FIN || tcp.RST {
		return
	}

	seqNum := tcp.Seq
	if _, seen := flow.seqNumbers[seqNum]; seen {
		// Duplicate or retransmission
		flow.retransmissions++
		d.retransmissions++
	} else {
		flow.seqNumbers[seqNum] = true
	}
}

func (d *PacketLossDetector) GetMetrics() *models.PacketLossMetrics {
	if d.totalPackets == 0 {
		return nil
	}

	metrics := &models.PacketLossMetrics{
		TotalPacketsSent:     d.totalPackets,
		TotalPacketsReceived: d.totalPackets - d.retransmissions,
		PacketsLost:          d.retransmissions,
		LossPercentage:       (float64(d.retransmissions) / float64(d.totalPackets)) * 100,
		RetransmissionRate:   (float64(d.retransmissions) / float64(d.totalPackets)) * 100,
		PerFlowLoss:          make([]models.FlowPacketLoss, 0),
	}

	// Calculate per-flow loss for flows with significant loss
	for _, flow := range d.tcpFlows {
		if flow.retransmissions > 0 && flow.packetsSent > 10 {
			lossPercentage := (float64(flow.retransmissions) / float64(flow.packetsSent)) * 100
			if lossPercentage > 1.0 { // Only report flows with >1% loss
				metrics.PerFlowLoss = append(metrics.PerFlowLoss, models.FlowPacketLoss{
					SrcIP:          flow.srcIP,
					DstIP:          flow.dstIP,
					SrcPort:        flow.srcPort,
					DstPort:        flow.dstPort,
					Protocol:       "TCP",
					PacketsSent:    flow.packetsSent,
					PacketsLost:    flow.retransmissions,
					LossPercentage: lossPercentage,
				})
			}
		}
	}

	return metrics
}

func getFlowKey(srcIP, dstIP string, srcPort, dstPort uint16) string {
	return srcIP + ":" + string(rune(srcPort)) + "->" + dstIP + ":" + string(rune(dstPort))
}
