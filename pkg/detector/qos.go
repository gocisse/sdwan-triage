package detector

import (
	"fmt"

	"github.com/gocisse/sdwan-triage/pkg/models"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// QoSAnalyzer handles QoS/DSCP traffic analysis
type QoSAnalyzer struct {
	enabled  bool
	classes  map[string]*models.QoSClassMetrics
	flowDSCP map[string]uint8
}

// NewQoSAnalyzer creates a new QoS analyzer
func NewQoSAnalyzer(enabled bool) *QoSAnalyzer {
	return &QoSAnalyzer{
		enabled:  enabled,
		classes:  make(map[string]*models.QoSClassMetrics),
		flowDSCP: make(map[string]uint8),
	}
}

// Analyze processes packets for QoS/DSCP analysis
func (q *QoSAnalyzer) Analyze(packet gopacket.Packet, state *models.AnalysisState, report *models.TriageReport) {
	if !q.enabled {
		return
	}

	ip4Layer := packet.Layer(layers.LayerTypeIPv4)
	if ip4Layer == nil {
		return
	}

	ip4 := ip4Layer.(*layers.IPv4)

	// Extract DSCP value (top 6 bits of TOS field)
	dscp := ip4.TOS >> 2

	// Get class name
	className := getDSCPClassName(dscp)

	// Get packet size
	packetSize := uint64(ip4.Length)

	// Update class metrics
	if q.classes[className] == nil {
		q.classes[className] = &models.QoSClassMetrics{
			ClassName: className,
			DSCPValue: dscp,
		}
	}

	q.classes[className].PacketCount++
	q.classes[className].ByteCount += packetSize

	// Track per-flow DSCP for mismatch detection
	var srcIP, dstIP string
	var srcPort, dstPort uint16

	srcIP = ip4.SrcIP.String()
	dstIP = ip4.DstIP.String()

	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp := tcpLayer.(*layers.TCP)
		srcPort = uint16(tcp.SrcPort)
		dstPort = uint16(tcp.DstPort)
	} else if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp := udpLayer.(*layers.UDP)
		srcPort = uint16(udp.SrcPort)
		dstPort = uint16(udp.DstPort)
	}

	flowKey := fmt.Sprintf("%s:%d->%s:%d", srcIP, srcPort, dstIP, dstPort)

	// Check for DSCP mismatch within same flow
	if existingDSCP, exists := q.flowDSCP[flowKey]; exists {
		if existingDSCP != dscp {
			// DSCP changed within flow - potential misconfiguration
			mismatch := models.QoSMismatch{
				Flow:          flowKey,
				ExpectedClass: getDSCPClassName(existingDSCP),
				ActualClass:   className,
				Reason:        "DSCP marking changed within flow",
			}

			// Check if already recorded
			found := false
			if report.QoSAnalysis != nil {
				for _, existing := range report.QoSAnalysis.MismatchedQoS {
					if existing.Flow == flowKey {
						found = true
						break
					}
				}
			}

			if !found {
				if report.QoSAnalysis == nil {
					report.QoSAnalysis = &models.QoSReport{
						ClassDistribution: make(map[string]*models.QoSClassMetrics),
					}
				}
				report.QoSAnalysis.MismatchedQoS = append(report.QoSAnalysis.MismatchedQoS, mismatch)
			}
		}
	} else {
		q.flowDSCP[flowKey] = dscp
	}
}

// Finalize calculates final QoS statistics and updates the report
func (q *QoSAnalyzer) Finalize(report *models.TriageReport) {
	if !q.enabled || len(q.classes) == 0 {
		return
	}

	// Calculate total packets
	var totalPackets uint64
	for _, metrics := range q.classes {
		totalPackets += metrics.PacketCount
	}

	// Calculate percentages
	for _, metrics := range q.classes {
		if totalPackets > 0 {
			metrics.Percentage = float64(metrics.PacketCount) / float64(totalPackets) * 100
		}
	}

	// Update report
	if report.QoSAnalysis == nil {
		report.QoSAnalysis = &models.QoSReport{
			ClassDistribution: make(map[string]*models.QoSClassMetrics),
		}
	}

	report.QoSAnalysis.TotalPackets = totalPackets
	for className, metrics := range q.classes {
		report.QoSAnalysis.ClassDistribution[className] = metrics
	}
}

// getDSCPClassName returns the class name for a DSCP value
func getDSCPClassName(dscp uint8) string {
	if className, ok := models.DSCPClasses[dscp]; ok {
		return className
	}
	return fmt.Sprintf("Unknown(%d)", dscp)
}
