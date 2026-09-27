package detectors

import (
	"strconv"

	"github.com/gocisse/sdwan-triage/pkg/models"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// Bounds. Per-flow memory must not grow with the number of segments, and the
// number of tracked flows must not grow without limit on flow-heavy captures.
const (
	// maxTrackedFlows caps the per-flow table. Beyond this, new flows still count
	// toward totals but are not tracked individually (they cannot be judged for
	// retransmission without state, so they contribute zero loss).
	maxTrackedFlows = 100000
)

type PacketLossDetector struct {
	tcpFlows        map[string]*tcpFlowState
	totalPackets    uint64
	retransmissions uint64
	untrackedFlows  uint64 // flows dropped because maxTrackedFlows was reached
}

type tcpFlowState struct {
	srcIP           string
	dstIP           string
	srcPort         uint16
	dstPort         uint16
	seq             *models.SeqHistory // bounded recent sequence-number history
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
		if len(d.tcpFlows) >= maxTrackedFlows {
			d.untrackedFlows++
			return
		}
		flow = &tcpFlowState{
			srcIP:   srcIP,
			dstIP:   dstIP,
			srcPort: uint16(tcp.SrcPort),
			dstPort: uint16(tcp.DstPort),
			seq:     models.NewSeqHistory(models.DefaultSeqHistorySize),
		}
		d.tcpFlows[flowKey] = flow
	}

	flow.packetsSent++

	// Control segments are never counted as retransmissions.
	if tcp.SYN || tcp.FIN || tcp.RST {
		return
	}

	// Only data segments consume sequence space. Pure ACKs legitimately repeat
	// the same sequence number (and share it with the next data segment), so
	// counting them here reported ~25% "loss" on healthy captures.
	if len(tcp.Payload) == 0 {
		return
	}

	seqNum := tcp.Seq
	if flow.seq.Seen(seqNum) {
		// Duplicate or retransmission
		flow.retransmissions++
		d.retransmissions++
	} else {
		flow.seq.Record(seqNum, packet.Metadata().Timestamp)
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

// UntrackedFlows reports how many flows were not tracked because the flow table
// limit was reached.
func (d *PacketLossDetector) UntrackedFlows() uint64 { return d.untrackedFlows }

func getFlowKey(srcIP, dstIP string, srcPort, dstPort uint16) string {
	// Decimal ports: the previous string(rune(port)) encoding collided for
	// ports in the surrogate range and produced control characters.
	return srcIP + ":" + strconv.Itoa(int(srcPort)) + "->" + dstIP + ":" + strconv.Itoa(int(dstPort))
}
