package analyzer

import (
	"fmt"
	"io"
	"os"
	"runtime/debug"
	"sort"
	"strings"
	"time"

	"github.com/gocisse/sdwan-triage/pkg/detector"
	"github.com/gocisse/sdwan-triage/pkg/models"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcapgo"
)

// Processor handles PCAP file processing
type Processor struct {
	dnsAnalyzer         *detector.DNSAnalyzer
	tcpAnalyzer         *detector.TCPAnalyzer
	arpAnalyzer         *detector.ARPAnalyzer
	httpAnalyzer        *detector.HTTPAnalyzer
	tlsAnalyzer         *detector.TLSAnalyzer
	trafficAnalyzer     *detector.TrafficAnalyzer
	quicAnalyzer        *detector.QUICAnalyzer
	qosAnalyzer         *detector.QoSAnalyzer
	ddosAnalyzer        *detector.DDoSAnalyzer
	portScanAnalyzer    *detector.PortScanAnalyzer
	iocAnalyzer         *detector.IOCAnalyzer
	tlsSecurityAnalyzer *detector.TLSSecurityAnalyzer
	icmpAnalyzer        *detector.ICMPAnalyzer
	qosEnabled          bool
	verbose             bool
	skippedPackets      int
	errorCount          int
}

// NewProcessor creates a new PCAP processor with all analyzers
func NewProcessor() *Processor {
	return NewProcessorWithOptions(false, false)
}

// NewProcessorWithOptions creates a processor with configurable options
func NewProcessorWithOptions(qosEnabled bool, verbose bool) *Processor {
	return &Processor{
		dnsAnalyzer:         detector.NewDNSAnalyzer(),
		tcpAnalyzer:         detector.NewTCPAnalyzer(),
		arpAnalyzer:         detector.NewARPAnalyzer(),
		httpAnalyzer:        detector.NewHTTPAnalyzer(),
		tlsAnalyzer:         detector.NewTLSAnalyzer(),
		trafficAnalyzer:     detector.NewTrafficAnalyzer(),
		quicAnalyzer:        detector.NewQUICAnalyzer(),
		qosAnalyzer:         detector.NewQoSAnalyzer(qosEnabled),
		ddosAnalyzer:        detector.NewDDoSAnalyzer(),
		portScanAnalyzer:    detector.NewPortScanAnalyzer(),
		iocAnalyzer:         detector.NewIOCAnalyzer(),
		tlsSecurityAnalyzer: detector.NewTLSSecurityAnalyzer(),
		icmpAnalyzer:        detector.NewICMPAnalyzer(),
		qosEnabled:          qosEnabled,
		verbose:             verbose,
		skippedPackets:      0,
		errorCount:          0,
	}
}

// logDebug logs a debug message if verbose mode is enabled
func (p *Processor) logDebug(format string, args ...interface{}) {
	if p.verbose {
		fmt.Fprintf(os.Stderr, "[DEBUG] "+format+"\n", args...)
	}
}

// logWarning logs a warning message
func (p *Processor) logWarning(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "[WARNING] "+format+"\n", args...)
}

// Process reads and analyzes all packets from a PCAP file
func (p *Processor) Process(reader *pcapgo.Reader, state *models.AnalysisState, report *models.TriageReport, filter *models.Filter) error {
	packetCount := 0
	startTime := time.Now()

	for {
		data, ci, err := reader.ReadPacketData()
		if err == io.EOF {
			break
		}
		if err != nil {
			// Don't fail on individual packet read errors, log and continue
			p.errorCount++
			if p.errorCount <= 5 {
				p.logWarning("Error reading packet %d: %v", packetCount+1, err)
			} else if p.errorCount == 6 {
				p.logWarning("Suppressing further packet read errors...")
			}
			continue
		}

		// Safely create packet with error handling
		packet := gopacket.NewPacket(data, reader.LinkType(), gopacket.Default)
		if packet == nil {
			p.skippedPackets++
			p.logDebug("Skipping nil packet at position %d", packetCount+1)
			continue
		}

		// Safely set metadata
		if packet.Metadata() != nil {
			packet.Metadata().Timestamp = ci.Timestamp
			packet.Metadata().CaptureLength = ci.CaptureLength
			packet.Metadata().Length = ci.Length
		}

		// Apply filter if set
		if filter != nil && !filter.IsEmpty() && !p.matchesFilter(packet, filter) {
			continue
		}

		// Run all analyzers with panic recovery
		p.safeAnalyzePacket(packet, state, report, packetCount)
		packetCount++

		// Progress indicator every 10000 packets
		if packetCount%10000 == 0 {
			elapsed := time.Since(startTime)
			fmt.Printf("\rProcessed %d packets (%.0f pps)...", packetCount, float64(packetCount)/elapsed.Seconds())
		}
	}

	// Print summary
	fmt.Printf("\rProcessed %d packets in %v\n", packetCount, time.Since(startTime).Round(time.Millisecond))

	// Report any issues encountered
	if p.skippedPackets > 0 || p.errorCount > 0 {
		p.logWarning("Analysis completed with issues: %d packets skipped, %d read errors", p.skippedPackets, p.errorCount)
	}

	// Finalize report
	p.finalizeReport(state, report)

	return nil
}

// safeAnalyzePacket wraps analyzePacket with panic recovery
func (p *Processor) safeAnalyzePacket(packet gopacket.Packet, state *models.AnalysisState, report *models.TriageReport, packetNum int) {
	defer func() {
		if r := recover(); r != nil {
			p.skippedPackets++
			p.logWarning("Panic recovered during packet %d analysis: %v", packetNum, r)
			if p.verbose {
				fmt.Fprintf(os.Stderr, "[DEBUG] Stack trace:\n%s\n", debug.Stack())
			}
		}
	}()

	p.analyzePacket(packet, state, report)
}

// analyzePacket runs all protocol analyzers on a packet
func (p *Processor) analyzePacket(packet gopacket.Packet, state *models.AnalysisState, report *models.TriageReport) {
	// DNS analysis
	p.dnsAnalyzer.Analyze(packet, state, report)

	// TCP analysis (includes handshake, retransmission, RTT, fingerprinting)
	p.tcpAnalyzer.Analyze(packet, state, report)

	// ARP analysis
	p.arpAnalyzer.Analyze(packet, state, report)

	// HTTP analysis
	p.httpAnalyzer.Analyze(packet, state, report)

	// TLS analysis
	p.tlsAnalyzer.Analyze(packet, state, report)

	// QUIC analysis
	p.quicAnalyzer.Analyze(packet, state, report)

	// QoS/DSCP analysis
	p.qosAnalyzer.Analyze(packet, state, report)

	// Traffic analysis (app stats, suspicious ports)
	p.trafficAnalyzer.Analyze(packet, state, report)

	// Security analysis
	p.ddosAnalyzer.AnalyzeTCP(packet, state, report)
	p.ddosAnalyzer.AnalyzeUDP(packet, state, report)
	p.ddosAnalyzer.AnalyzeICMP(packet, state, report)
	p.portScanAnalyzer.Analyze(packet, state, report)
	p.iocAnalyzer.AnalyzeIP(packet, state, report)
	p.iocAnalyzer.AnalyzeDNS(packet, state, report)
	p.tlsSecurityAnalyzer.Analyze(packet, state, report)
	p.icmpAnalyzer.Analyze(packet, state, report)
}

// matchesFilter checks if a packet matches the configured filter
func (p *Processor) matchesFilter(packet gopacket.Packet, filter *models.Filter) bool {
	// Get IP addresses
	var srcIP, dstIP string
	if ip4Layer := packet.NetworkLayer(); ip4Layer != nil {
		srcIP = ip4Layer.NetworkFlow().Src().String()
		dstIP = ip4Layer.NetworkFlow().Dst().String()
	}

	// Check source IP filter
	if filter.SrcIP != "" && srcIP != filter.SrcIP {
		return false
	}

	// Check destination IP filter
	if filter.DstIP != "" && dstIP != filter.DstIP {
		return false
	}

	// Check protocol filter
	if filter.Protocol != "" {
		protocol := ""
		if packet.TransportLayer() != nil {
			protocol = packet.TransportLayer().LayerType().String()
		}
		if protocol != filter.Protocol && protocol != "TCP" && protocol != "UDP" {
			return false
		}
	}

	// Check service/port filter
	if filter.Service != "" {
		port, ok := models.ResolveServiceToPort(filter.Service)
		if ok {
			var srcPort, dstPort uint16
			if transportLayer := packet.TransportLayer(); transportLayer != nil {
				flow := transportLayer.TransportFlow()
				srcPort = uint16(flow.Src().Raw()[0])<<8 | uint16(flow.Src().Raw()[1])
				dstPort = uint16(flow.Dst().Raw()[0])<<8 | uint16(flow.Dst().Raw()[1])
			}
			if srcPort != port && dstPort != port {
				return false
			}
		}
	}

	return true
}

// finalizeReport processes collected state into final report data
func (p *Processor) finalizeReport(state *models.AnalysisState, report *models.TriageReport) {
	// Calculate RTT statistics from TCP flows
	for flowKey, flowState := range state.TCPFlows {
		if len(flowState.RTTSamples) > 0 {
			var minRTT, maxRTT, sumRTT float64
			minRTT = flowState.RTTSamples[0]
			maxRTT = flowState.RTTSamples[0]

			for _, rtt := range flowState.RTTSamples {
				sumRTT += rtt
				if rtt < minRTT {
					minRTT = rtt
				}
				if rtt > maxRTT {
					maxRTT = rtt
				}
			}

			avgRTT := sumRTT / float64(len(flowState.RTTSamples))

			// Only report high RTT flows (>100ms average)
			if avgRTT > 100 {
				// Parse flow key to get IPs and ports
				var srcIP, dstIP string
				var srcPort, dstPort int

				// Parse flow key format: "srcIP:srcPort->dstIP:dstPort"
				parts := strings.Split(flowKey, "->")
				if len(parts) == 2 {
					srcParts := strings.Split(parts[0], ":")
					dstParts := strings.Split(parts[1], ":")
					if len(srcParts) >= 2 && len(dstParts) >= 2 {
						srcIP = strings.Join(srcParts[:len(srcParts)-1], ":")
						fmt.Sscanf(srcParts[len(srcParts)-1], "%d", &srcPort)
						dstIP = strings.Join(dstParts[:len(dstParts)-1], ":")
						fmt.Sscanf(dstParts[len(dstParts)-1], "%d", &dstPort)
					}
				}

				rttFlow := models.RTTFlow{
					SrcIP:      srcIP,
					SrcPort:    uint16(srcPort),
					DstIP:      dstIP,
					DstPort:    uint16(dstPort),
					MinRTT:     minRTT,
					MaxRTT:     maxRTT,
					AvgRTT:     avgRTT,
					SampleSize: len(flowState.RTTSamples),
				}
				report.RTTAnalysis = append(report.RTTAnalysis, rttFlow)
			}
		}
	}

	// Build application breakdown from stats
	if report.ApplicationBreakdown == nil {
		report.ApplicationBreakdown = make(map[string]models.AppCategory)
	}
	for key, stats := range state.AppStats {
		report.ApplicationBreakdown[key] = *stats
	}

	// Build traffic analysis summary
	p.buildTrafficSummary(state, report)

	// Finalize QoS analysis
	p.qosAnalyzer.Finalize(report)

	// Sort timeline by timestamp
	sort.Slice(report.Timeline, func(i, j int) bool {
		return report.Timeline[i].Timestamp < report.Timeline[j].Timestamp
	})
}

// buildTrafficSummary creates traffic flow summary from collected data
func (p *Processor) buildTrafficSummary(state *models.AnalysisState, report *models.TriageReport) {
	// Aggregate traffic by flow
	flowBytes := make(map[string]uint64)

	for flowKey, flowState := range state.TCPFlows {
		flowBytes[flowKey] = flowState.TotalBytes
	}

	for flowKey, flowState := range state.UDPFlows {
		flowBytes[flowKey] = flowState.TotalBytes
	}

	// Convert to TrafficFlow slice and sort by bytes
	var flows []models.TrafficFlow
	for flowKey, bytes := range flowBytes {
		// Parse flow key format: "srcIP:srcPort->dstIP:dstPort"
		var srcIP, dstIP string
		var srcPort, dstPort int

		// Use strings.Split for more reliable parsing
		parts := strings.Split(flowKey, "->")
		if len(parts) == 2 {
			srcParts := strings.Split(parts[0], ":")
			dstParts := strings.Split(parts[1], ":")
			if len(srcParts) >= 2 && len(dstParts) >= 2 {
				srcIP = strings.Join(srcParts[:len(srcParts)-1], ":")
				fmt.Sscanf(srcParts[len(srcParts)-1], "%d", &srcPort)
				dstIP = strings.Join(dstParts[:len(dstParts)-1], ":")
				fmt.Sscanf(dstParts[len(dstParts)-1], "%d", &dstPort)
			}
		}

		flow := models.TrafficFlow{
			SrcIP:      srcIP,
			SrcPort:    uint16(srcPort),
			DstIP:      dstIP,
			DstPort:    uint16(dstPort),
			Protocol:   "TCP", // Default, could be improved
			TotalBytes: bytes,
		}
		flows = append(flows, flow)
	}

	// Sort by bytes descending
	sort.Slice(flows, func(i, j int) bool {
		return flows[i].TotalBytes > flows[j].TotalBytes
	})

	// Calculate percentages and take top 20
	totalBytes := report.TotalBytes
	if totalBytes == 0 {
		for _, f := range flows {
			totalBytes += f.TotalBytes
		}
	}

	limit := 20
	if len(flows) < limit {
		limit = len(flows)
	}

	for i := 0; i < limit; i++ {
		if totalBytes > 0 {
			flows[i].Percentage = float64(flows[i].TotalBytes) / float64(totalBytes) * 100
		}
		report.TrafficAnalysis = append(report.TrafficAnalysis, flows[i])
	}
}
