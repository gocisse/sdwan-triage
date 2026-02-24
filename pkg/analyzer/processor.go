package analyzer

import (
	"fmt"
	"io"
	"os"
	"runtime/debug"
	"sort"
	"strings"
	"time"

	"github.com/gocisse/sdwan-triage/pkg/config"
	"github.com/gocisse/sdwan-triage/pkg/detector"
	"github.com/gocisse/sdwan-triage/pkg/detectors"
	"github.com/gocisse/sdwan-triage/pkg/models"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

// Processor handles PCAP file processing
type Processor struct {
	dnsAnalyzer          *detector.DNSAnalyzer
	tcpAnalyzer          *detector.TCPAnalyzer
	arpAnalyzer          *detector.ARPAnalyzer
	httpAnalyzer         *detector.HTTPAnalyzer
	tlsAnalyzer          *detector.TLSAnalyzer
	trafficAnalyzer      *detector.TrafficAnalyzer
	quicAnalyzer         *detector.QUICAnalyzer
	qosAnalyzer          *detector.QoSAnalyzer
	ddosAnalyzer         *detector.DDoSAnalyzer
	portScanAnalyzer     *detector.PortScanAnalyzer
	iocAnalyzer          *detector.IOCAnalyzer
	tlsSecurityAnalyzer  *detector.TLSSecurityAnalyzer
	icmpAnalyzer         *detector.ICMPAnalyzer
	icmpv6Analyzer       *detector.ICMPv6Analyzer
	geoipAnalyzer        *detector.GeoIPAnalyzer
	sdwanAnalyzer        *detector.SDWANVendorAnalyzer
	sipAnalyzer          *detector.SIPAnalyzer
	rtpAnalyzer          *detector.RTPAnalyzer
	tunnelAnalyzer       *detector.TunnelAnalyzer
	bgpAnalyzer          *detector.BGPAnalyzer
	handshakeTracker     *detector.TCPHandshakeTracker
	packetLossDetector   *detectors.PacketLossDetector
	smbDetector          *detectors.SMBDetector
	ldapDetector         *detectors.LDAPDetector
	kerberosDetector     *detectors.KerberosDetector
	lanProtocolAnalyzer  *detector.LANProtocolAnalyzer
	dhcpAnalyzer         *detector.DHCPAnalyzer
	ntpAnalyzer          *detector.NTPAnalyzer
	dnsTunnelingAnalyzer *detector.DNSTunnelingAnalyzer
	c2BeaconingAnalyzer  *detector.C2BeaconingAnalyzer
	tcpAdvancedAnalyzer  *detector.TCPAdvancedAnalyzer
	arubaDetector        *ArubaIssueDetector
	viptelaDetector      *ViptelaIssueDetector
	veloCloudDetector    *VeloCloudIssueDetector
	streamReassembler    *StreamReassembler
	bandwidthAnalyzer    *BandwidthAnalyzer
	correlator           *UnderlayOverlayCorrelator // Underlay/overlay event correlation
	registry             *DetectorRegistry          // Parallel detector execution engine
	handshakeTimeout     time.Duration
	qosEnabled           bool
	verbose              bool
	skippedPackets       int
	errorCount           int
}

// NewProcessor creates a new PCAP processor with all analyzers
func NewProcessor() *Processor {
	return NewProcessorWithOptions(false, false)
}

// NewProcessorWithOptions creates a processor with configurable options
func NewProcessorWithOptions(qosEnabled bool, verbose bool) *Processor {
	p := &Processor{
		dnsAnalyzer:          detector.NewDNSAnalyzer(),
		tcpAnalyzer:          detector.NewTCPAnalyzer(),
		arpAnalyzer:          detector.NewARPAnalyzer(),
		httpAnalyzer:         detector.NewHTTPAnalyzer(),
		tlsAnalyzer:          detector.NewTLSAnalyzer(),
		trafficAnalyzer:      detector.NewTrafficAnalyzer(),
		quicAnalyzer:         detector.NewQUICAnalyzer(),
		qosAnalyzer:          detector.NewQoSAnalyzer(qosEnabled),
		ddosAnalyzer:         detector.NewDDoSAnalyzer(),
		portScanAnalyzer:     detector.NewPortScanAnalyzer(),
		iocAnalyzer:          detector.NewIOCAnalyzer(),
		tlsSecurityAnalyzer:  detector.NewTLSSecurityAnalyzer(),
		icmpAnalyzer:         detector.NewICMPAnalyzer(),
		icmpv6Analyzer:       detector.NewICMPv6Analyzer(),
		geoipAnalyzer:        detector.NewGeoIPAnalyzer(),
		sdwanAnalyzer:        detector.NewSDWANVendorAnalyzer(),
		sipAnalyzer:          detector.NewSIPAnalyzer(),
		rtpAnalyzer:          detector.NewRTPAnalyzer(),
		tunnelAnalyzer:       detector.NewTunnelAnalyzer(),
		bgpAnalyzer:          detector.NewBGPAnalyzer(),
		handshakeTracker:     detector.NewTCPHandshakeTracker(),
		packetLossDetector:   detectors.NewPacketLossDetector(),
		smbDetector:          detectors.NewSMBDetector(),
		ldapDetector:         detectors.NewLDAPDetector(),
		kerberosDetector:     detectors.NewKerberosDetector(),
		lanProtocolAnalyzer:  detector.NewLANProtocolAnalyzer(),
		dhcpAnalyzer:         detector.NewDHCPAnalyzer(),
		ntpAnalyzer:          detector.NewNTPAnalyzer(),
		dnsTunnelingAnalyzer: detector.NewDNSTunnelingAnalyzer(),
		c2BeaconingAnalyzer:  detector.NewC2BeaconingAnalyzer(),
		tcpAdvancedAnalyzer:  detector.NewTCPAdvancedAnalyzer(),
		arubaDetector:        NewArubaIssueDetector(),
		viptelaDetector:      NewViptelaIssueDetector(),
		veloCloudDetector:    NewVeloCloudIssueDetector(),
		streamReassembler:    NewStreamReassembler(verbose),
		bandwidthAnalyzer:    NewBandwidthAnalyzer(1000, verbose), // 1 second buckets
		correlator:           NewUnderlayOverlayCorrelator(),
		handshakeTimeout:     3 * time.Second, // Default 3 second timeout
		qosEnabled:           qosEnabled,
		verbose:              verbose,
		skippedPackets:       0,
		errorCount:           0,
	}

	// Wire correlator callbacks into BGP and TCP analyzers
	p.bgpAnalyzer.OnBGPEvent = p.correlator.RecordBGPEvent
	p.tcpAnalyzer.OnRetransmission = p.correlator.RecordRetransmission
	p.tcpAnalyzer.OnRTTSpike = p.correlator.RecordRTTSpike

	// Build the parallel detector registry
	p.registry = p.buildDetectorRegistry()

	return p
}

// SetHandshakeTimeout sets the timeout for TCP handshake completion
func (p *Processor) SetHandshakeTimeout(timeout time.Duration) {
	p.handshakeTimeout = timeout
}

// ApplyThresholds applies custom detection thresholds from configuration
func (p *Processor) ApplyThresholds(cfg *config.ThresholdsConfig) {
	if cfg == nil {
		return
	}

	// Apply DDoS thresholds
	if cfg.DDoS.SYNThreshold > 0 {
		p.ddosAnalyzer.SetSYNThreshold(cfg.DDoS.SYNThreshold)
	}
	if cfg.DDoS.UDPThreshold > 0 {
		p.ddosAnalyzer.SetUDPThreshold(cfg.DDoS.UDPThreshold)
	}
	if cfg.DDoS.ICMPThreshold > 0 {
		p.ddosAnalyzer.SetICMPThreshold(cfg.DDoS.ICMPThreshold)
	}

	// Apply port scan thresholds
	if cfg.PortScan.HorizontalThreshold > 0 {
		p.portScanAnalyzer.SetHorizontalThreshold(cfg.PortScan.HorizontalThreshold)
	}
	if cfg.PortScan.VerticalThreshold > 0 {
		p.portScanAnalyzer.SetVerticalThreshold(cfg.PortScan.VerticalThreshold)
	}

	// Apply performance thresholds
	if cfg.Performance.HighRTTMs > 0 {
		p.tcpAnalyzer.SetHighRTTThreshold(cfg.Performance.HighRTTMs)
	}
	if cfg.Performance.RetransmitWarn > 0 {
		p.tcpAnalyzer.SetRetransmitThreshold(cfg.Performance.RetransmitWarn)
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

		// Early filter check: Apply filter before packet creation for performance
		// This avoids expensive packet parsing for filtered packets
		if filter != nil && !filter.IsEmpty() {
			// Quick pre-filter check on raw data if possible
			if !p.quickFilterCheck(data, reader.LinkType(), filter) {
				continue
			}
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

		// Final filter check with full packet (if quick check passed)
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

			// Periodic cleanup of stale stream data to prevent memory bloat
			// Evict streams that haven't been seen for 30+ seconds
			if p.streamReassembler != nil {
				evicted := p.streamReassembler.CleanupStaleFlows(30 * time.Second)
				if evicted > 0 && p.verbose {
					p.logDebug("Evicted %d stale streams", evicted)
				}
			}
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

// buildDetectorRegistry classifies all detectors into independent (parallel) and stateful (sequential) groups.
func (p *Processor) buildDetectorRegistry() *DetectorRegistry {
	reg := NewDetectorRegistry(p.verbose)

	// ── Independent Analyzers (safe to run in parallel) ──
	// These detectors read packet layers and write to report slices.
	// Report writes are serialized by report.Mu in the registry.
	// AnalysisState LRU caches are internally thread-safe.
	reg.RegisterIndependent(
		// Protocol parsers
		NewAnalyzerFunc("DNS", p.dnsAnalyzer.Analyze),
		NewAnalyzerFunc("ARP", p.arpAnalyzer.Analyze),
		NewAnalyzerFunc("HTTP", p.httpAnalyzer.Analyze),
		NewAnalyzerFunc("TLS", p.tlsAnalyzer.Analyze),
		NewAnalyzerFunc("QUIC", p.quicAnalyzer.Analyze),
		NewAnalyzerFunc("QoS", p.qosAnalyzer.Analyze),
		NewAnalyzerFunc("TLS-Security", p.tlsSecurityAnalyzer.Analyze),
		NewAnalyzerFunc("ICMP", p.icmpAnalyzer.Analyze),
		NewAnalyzerFunc("ICMPv6", p.icmpv6Analyzer.Analyze),

		// Advanced network analysis
		NewAnalyzerFunc("GeoIP", p.geoipAnalyzer.Analyze),
		NewAnalyzerFunc("SDWAN-Vendor", p.sdwanAnalyzer.Analyze),
		NewAnalyzerFunc("SIP", p.sipAnalyzer.Analyze),
		NewAnalyzerFunc("RTP", p.rtpAnalyzer.Analyze),
		NewAnalyzerFunc("Tunnel", p.tunnelAnalyzer.Analyze),
		NewAnalyzerFunc("BGP", p.bgpAnalyzer.Analyze),

		// LAN protocol detection
		NewAnalyzerFunc("LAN-Protocols", p.lanProtocolAnalyzer.Analyze),

		// DHCP / NTP / DNS Tunneling
		NewAnalyzerFunc("DHCP", p.dhcpAnalyzer.Analyze),
		NewAnalyzerFunc("NTP", p.ntpAnalyzer.Analyze),
		NewAnalyzerFunc("DNS-Tunneling", p.dnsTunnelingAnalyzer.Analyze),

		// IOC matching
		NewAnalyzerFunc("IOC-IP", p.iocAnalyzer.AnalyzeIP),
		NewAnalyzerFunc("IOC-DNS", p.iocAnalyzer.AnalyzeDNS),

		// TCP advanced (window issues, out-of-order)
		NewAnalyzerFunc("TCP-Advanced", p.tcpAdvancedAnalyzer.Analyze),

		// Packet-only detectors (no state/report dependency)
		NewPacketOnlyAnalyzer("PacketLoss", p.packetLossDetector.ProcessPacket),
		NewPacketOnlyAnalyzer("SMB", p.smbDetector.ProcessPacket),
		NewPacketOnlyAnalyzer("LDAP", p.ldapDetector.ProcessPacket),
		NewPacketOnlyAnalyzer("Kerberos", p.kerberosDetector.ProcessPacket),

		// Stream reassembly and bandwidth (packet-only)
		NewPacketOnlyAnalyzer("StreamReassembly", p.streamReassembler.ProcessPacket),
		NewPacketOnlyAnalyzer("Bandwidth", p.bandwidthAnalyzer.ProcessPacket),
	)

	// ── Stateful Analyzers (must run sequentially) ──
	// These detectors write to shared SecurityState maps (DDoS counters, port scan tracking)
	// or maintain ordering-dependent state (TCP flow tracking, handshake correlation).
	// SecurityState maps are protected by SecurityState.mu.
	reg.RegisterStateful(
		// TCP flow tracking (writes to TCPFlowState, handshake state)
		NewAnalyzerFunc("TCP", p.tcpAnalyzer.Analyze),
		NewAnalyzerFunc("TCP-Handshake", p.handshakeTracker.TrackHandshake),

		// Traffic analysis (writes to UDPFlowState, AppStats)
		NewAnalyzerFunc("Traffic", p.trafficAnalyzer.Analyze),

		// Security detectors (write to SecurityState maps)
		NewAnalyzerFunc("DDoS-TCP", p.ddosAnalyzer.AnalyzeTCP),
		NewAnalyzerFunc("DDoS-UDP", p.ddosAnalyzer.AnalyzeUDP),
		NewAnalyzerFunc("DDoS-ICMP", p.ddosAnalyzer.AnalyzeICMP),
		NewAnalyzerFunc("PortScan", p.portScanAnalyzer.Analyze),

		// C2 beaconing (maintains internal interval tracking state)
		NewAnalyzerFunc("C2-TCP", p.c2BeaconingAnalyzer.AnalyzeTCP),
		NewAnalyzerFunc("C2-UDP", p.c2BeaconingAnalyzer.AnalyzeUDP),
	)

	return reg
}

// analyzePacket runs all protocol analyzers on a packet via the parallel detector registry.
func (p *Processor) analyzePacket(packet gopacket.Packet, state *models.AnalysisState, report *models.TriageReport) {
	p.registry.AnalyzePacket(packet, state, report)
}

// quickFilterCheck performs a fast pre-filter check on raw packet data
// This avoids expensive packet parsing for packets that won't match the filter
func (p *Processor) quickFilterCheck(data []byte, linkType layers.LinkType, filter *models.Filter) bool {
	// For now, we'll parse the packet minimally
	// In the future, this could be optimized with raw byte inspection
	// For IP filters, we could check IP headers directly without full parsing
	packet := gopacket.NewPacket(data, linkType, gopacket.DecodeOptions{Lazy: true, NoCopy: true})
	if packet == nil {
		return false
	}
	return p.matchesFilter(packet, filter)
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
	// Check for handshake timeouts
	p.handshakeTracker.CheckTimeouts(time.Now(), p.handshakeTimeout, report)

	// Export all remaining handshake flows to report (including incomplete ones)
	p.handshakeTracker.ExportAllFlows(report)

	// Build RTT histogram from collected samples
	p.buildRTTHistogram(state, report)

	// Build correlated TCP handshake flows for visualization
	p.buildTCPHandshakeCorrelatedFlows(report)

	// Calculate RTT statistics from TCP flows (using bounded cache iterator)
	state.ForEachTCPFlow(func(flowKey string, flowState *models.TCPFlowState) bool {
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
		return true // continue iteration
	})

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

	// Add packet loss metrics
	if metrics := p.packetLossDetector.GetMetrics(); metrics != nil {
		report.PacketLoss = metrics
	}

	// Add protocol detection results
	report.SMBFlows = p.smbDetector.GetFlows()
	report.LDAPFlows = p.ldapDetector.GetFlows()
	report.KerberosFlows = p.kerberosDetector.GetFlows()

	// Add LAN protocol findings (VRRP, CDP, LLDP, HSRP, STP)
	report.LANProtocols = p.lanProtocolAnalyzer.GetFindings()

	// Finalize TCP advanced analysis (out-of-order flows)
	p.tcpAdvancedAnalyzer.Finalize(report)

	// Add stream reassembly data (top 50 streams by bytes)
	topStreams := p.streamReassembler.GetTopStreams(50)
	report.RawStreams = topStreams // Store raw streams for actionable analysis
	for _, stream := range topStreams {
		viewData := p.streamReassembler.FormatStreamForDisplay(stream)
		report.Streams = append(report.Streams, viewData)
	}

	// Run vendor-specific DPI detectors on reassembled streams
	for _, stream := range topStreams {
		var vendorIssues []DetectedIssue
		vendorIssues = append(vendorIssues, p.arubaDetector.DetectArubaIssues(stream)...)
		vendorIssues = append(vendorIssues, p.viptelaDetector.DetectViptelaIssues(stream)...)
		vendorIssues = append(vendorIssues, p.veloCloudDetector.DetectVeloCloudIssues(stream)...)
		for _, issue := range vendorIssues {
			report.VendorDPIIssues = append(report.VendorDPIIssues, models.VendorDPIIssue{
				Vendor:          string(issue.Category),
				IssueID:         issue.ID,
				Title:           issue.Title,
				Description:     issue.TechnicalDesc,
				BusinessImpact:  issue.BusinessImpact,
				Severity:        string(issue.Severity),
				Confidence:      issue.Confidence,
				Category:        string(issue.Category),
				RootCause:       issue.RootCause,
				WiresharkFilter: issue.BaseFilter,
			})
		}
	}

	// Correlate underlay/overlay events (BGP → TCP retransmissions/RTT spikes)
	p.correlator.Finalize(report)

	// Add bandwidth time series data
	report.BandwidthTimeSeries = p.bandwidthAnalyzer.GetTimeSeries()

	// Detect and add traffic gaps (gaps > 2 seconds)
	gaps := p.bandwidthAnalyzer.DetectTrafficGaps(2.0)
	for _, gap := range gaps {
		report.TrafficGaps = append(report.TrafficGaps, models.TrafficGapInfo{
			StartTime:   float64(gap.StartTime.UnixNano()) / 1e9,
			EndTime:     float64(gap.EndTime.UnixNano()) / 1e9,
			DurationSec: gap.DurationSec,
			Description: fmt.Sprintf("%.1f-second gap in traffic", gap.DurationSec),
		})
	}

	// Sort timeline by timestamp
	sort.Slice(report.Timeline, func(i, j int) bool {
		return report.Timeline[i].Timestamp < report.Timeline[j].Timestamp
	})

	// Calculate risk score and generate recommendations
	p.calculateRiskScore(report)

	// Generate plain English summary (after risk score is calculated)
	report.PlainEnglishSummary = p.bandwidthAnalyzer.GetPlainEnglishSummary(report, gaps)
}

// calculateRiskScore calculates the overall risk score and generates recommendations
func (p *Processor) calculateRiskScore(report *models.TriageReport) {
	score := 0
	issues := make(map[string]int)

	// Critical findings (+10 points each)
	if len(report.ARPConflicts) > 0 {
		score += len(report.ARPConflicts) * 10
		issues["ARP Conflicts"] = len(report.ARPConflicts)
	}
	if len(report.DNSAnomalies) > 0 {
		score += len(report.DNSAnomalies) * 10
		issues["DNS Anomalies"] = len(report.DNSAnomalies)
	}
	if len(report.Security.DDoSFindings) > 0 {
		score += len(report.Security.DDoSFindings) * 10
		issues["DDoS Indicators"] = len(report.Security.DDoSFindings)
	}
	if len(report.Security.TLSSecurityFindings) > 0 {
		score += len(report.Security.TLSSecurityFindings) * 10
		issues["TLS Security Issues"] = len(report.Security.TLSSecurityFindings)
	}
	if len(report.Security.IOCFindings) > 0 {
		score += len(report.Security.IOCFindings) * 10
		issues["IOC Matches"] = len(report.Security.IOCFindings)
	}

	// Warning findings (+5 points each, capped)
	if len(report.TCPRetransmissions) > 0 {
		retransScore := len(report.TCPRetransmissions)
		if retransScore > 20 {
			retransScore = 20 // Cap at 100 points
		}
		score += retransScore * 5
		issues["TCP Retransmissions"] = len(report.TCPRetransmissions)
	}
	if len(report.FailedHandshakes) > 0 {
		score += len(report.FailedHandshakes) * 5
		issues["Failed Handshakes"] = len(report.FailedHandshakes)
	}
	if len(report.SuspiciousTraffic) > 0 {
		score += len(report.SuspiciousTraffic) * 5
		issues["Suspicious Traffic"] = len(report.SuspiciousTraffic)
	}
	if len(report.Security.PortScanFindings) > 0 {
		score += len(report.Security.PortScanFindings) * 5
		issues["Port Scan Indicators"] = len(report.Security.PortScanFindings)
	}
	if len(report.RTTAnalysis) > 0 {
		score += len(report.RTTAnalysis) * 2
		issues["High RTT Flows"] = len(report.RTTAnalysis)
	}
	if len(report.HTTPErrors) > 0 {
		score += len(report.HTTPErrors) * 2
		issues["HTTP Errors"] = len(report.HTTPErrors)
	}

	// New detector findings
	if len(report.DHCPFindings) > 0 {
		for _, f := range report.DHCPFindings {
			if f.Type == "Rogue Server" || f.Type == "Starvation" {
				score += 15
			} else {
				score += 5
			}
		}
		issues["DHCP Issues"] = len(report.DHCPFindings)
	}
	if len(report.NTPFindings) > 0 {
		for _, f := range report.NTPFindings {
			if f.Type == "Amplification" {
				score += 10
			} else {
				score += 3
			}
		}
		issues["NTP Issues"] = len(report.NTPFindings)
	}
	if len(report.DNSTunnelingFindings) > 0 {
		score += len(report.DNSTunnelingFindings) * 15
		issues["DNS Tunneling"] = len(report.DNSTunnelingFindings)
	}
	if len(report.C2BeaconingFindings) > 0 {
		score += len(report.C2BeaconingFindings) * 15
		issues["C2 Beaconing"] = len(report.C2BeaconingFindings)
	}
	if len(report.TCPWindowFindings) > 0 {
		score += len(report.TCPWindowFindings) * 3
		issues["TCP Window Issues"] = len(report.TCPWindowFindings)
	}
	if len(report.TCPOutOfOrderFlows) > 0 {
		score += len(report.TCPOutOfOrderFlows) * 3
		issues["TCP Out-of-Order"] = len(report.TCPOutOfOrderFlows)
	}

	// Set risk level based on score
	report.RiskScore = score
	switch {
	case score == 0:
		report.RiskLevel = "Low"
	case score <= 10:
		report.RiskLevel = "Low"
	case score <= 20:
		report.RiskLevel = "Medium"
	case score <= 50:
		report.RiskLevel = "High"
	default:
		report.RiskLevel = "Critical"
	}

	// Find top issue
	maxCount := 0
	topIssue := ""
	for issue, count := range issues {
		if count > maxCount {
			maxCount = count
			topIssue = issue
		}
	}
	report.TopIssue = topIssue
	report.TopIssueCount = maxCount

	// Generate recommended actions
	report.RecommendedActions = p.generateRecommendations(report, issues)
}

// generateRecommendations creates actionable recommendations based on findings
func (p *Processor) generateRecommendations(report *models.TriageReport, issues map[string]int) []string {
	var actions []string

	// Critical actions first
	if issues["ARP Conflicts"] > 0 {
		actions = append(actions, "CRITICAL: Investigate ARP spoofing immediately. Locate the device causing the conflict and verify network security.")
	}
	if issues["DNS Anomalies"] > 0 {
		actions = append(actions, "CRITICAL: Review DNS anomalies for potential DNS hijacking or poisoning attacks.")
	}
	if issues["DDoS Indicators"] > 0 {
		actions = append(actions, "CRITICAL: Potential DDoS attack detected. Enable rate limiting and contact your ISP if needed.")
	}
	if issues["IOC Matches"] > 0 {
		actions = append(actions, "CRITICAL: Indicators of Compromise detected. Isolate affected systems and perform forensic analysis.")
	}
	if issues["TLS Security Issues"] > 0 {
		actions = append(actions, "HIGH: TLS security vulnerabilities found. Update certificates and disable weak cipher suites.")
	}

	// Warning actions
	if issues["TCP Retransmissions"] > 50 {
		actions = append(actions, "HIGH: Excessive TCP retransmissions indicate network congestion or hardware issues. Check links between affected hosts.")
	} else if issues["TCP Retransmissions"] > 10 {
		actions = append(actions, "MEDIUM: TCP retransmissions detected. Monitor network links for potential issues.")
	}
	if issues["Failed Handshakes"] > 0 {
		actions = append(actions, "MEDIUM: Failed TCP handshakes may indicate firewall blocks, service unavailability, or network issues.")
	}
	if issues["Suspicious Traffic"] > 0 {
		actions = append(actions, "MEDIUM: Suspicious traffic patterns detected. Review for potential malware or unauthorized access.")
	}
	if issues["Port Scan Indicators"] > 0 {
		actions = append(actions, "MEDIUM: Port scanning activity detected. Review source IPs and consider blocking if malicious.")
	}
	if issues["High RTT Flows"] > 0 {
		actions = append(actions, "LOW: High latency flows detected. Check for network congestion or routing issues.")
	}
	if issues["DHCP Issues"] > 0 {
		actions = append(actions, "CRITICAL: DHCP anomalies detected. Check for rogue DHCP servers or starvation attacks. Run 'show ip dhcp server statistics' on your router.")
	}
	if issues["NTP Issues"] > 0 {
		actions = append(actions, "HIGH: NTP anomalies detected. Check for NTP amplification attacks and verify NTP server configuration.")
	}
	if issues["DNS Tunneling"] > 0 {
		actions = append(actions, "CRITICAL: DNS tunneling suspected. Investigate the source host for malware. Block suspicious domains and enable DNS security.")
	}
	if issues["C2 Beaconing"] > 0 {
		actions = append(actions, "CRITICAL: C2 beaconing pattern detected. Isolate the source host immediately and perform forensic analysis.")
	}
	if issues["TCP Window Issues"] > 0 {
		actions = append(actions, "MEDIUM: TCP window size issues detected. Check receiver host for memory/CPU pressure or application bottlenecks.")
	}
	if issues["TCP Out-of-Order"] > 0 {
		actions = append(actions, "MEDIUM: TCP out-of-order packets detected. Check for asymmetric routing, load balancer issues, or link problems.")
	}

	// Limit to top 5 actions
	if len(actions) > 5 {
		actions = actions[:5]
	}

	// If no issues, add positive message
	if len(actions) == 0 {
		actions = append(actions, "No critical issues detected. Continue monitoring network health.")
	}

	return actions
}

// buildTrafficSummary creates traffic flow summary from collected data
func (p *Processor) buildTrafficSummary(state *models.AnalysisState, report *models.TriageReport) {
	// Track flow bytes with protocol information
	type flowInfo struct {
		bytes    uint64
		protocol string
	}
	flowData := make(map[string]flowInfo)

	// Add TCP flows (using bounded cache iterator)
	state.ForEachTCPFlow(func(flowKey string, flowState *models.TCPFlowState) bool {
		flowData[flowKey] = flowInfo{bytes: flowState.TotalBytes, protocol: "TCP"}
		return true
	})

	// Add UDP flows (using bounded cache iterator)
	state.ForEachUDPFlow(func(flowKey string, flowState *models.UDPFlowState) bool {
		flowData[flowKey] = flowInfo{bytes: flowState.TotalBytes, protocol: "UDP"}
		return true
	})

	// Convert to TrafficFlow slice and sort by bytes
	var flows []models.TrafficFlow
	for flowKey, info := range flowData {
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
			Protocol:   info.protocol,
			TotalBytes: info.bytes,
		}
		flows = append(flows, flow)
	}

	// Sort by bytes descending
	sort.Slice(flows, func(i, j int) bool {
		return flows[i].TotalBytes > flows[j].TotalBytes
	})

	// Calculate percentages for all flows
	totalBytes := report.TotalBytes
	if totalBytes == 0 {
		for _, f := range flows {
			totalBytes += f.TotalBytes
		}
	}

	// Include all flows
	for i := range flows {
		if totalBytes > 0 {
			flows[i].Percentage = float64(flows[i].TotalBytes) / float64(totalBytes) * 100
		}
		report.TrafficAnalysis = append(report.TrafficAnalysis, flows[i])
	}

	// Finalize VoIP analysis
	p.finalizeVoIPAnalysis(report)

	// Finalize tunnel analysis
	p.finalizeTunnelAnalysis(report)

	// Finalize SD-WAN vendor detection
	p.finalizeSDWANAnalysis(report)

	// Finalize GeoIP analysis
	report.LocationSummary = p.geoipAnalyzer.GetLocationSummary()
	report.LocationIPs = p.geoipAnalyzer.GetCountryIPs()
}

// finalizeVoIPAnalysis populates VoIP analysis results
func (p *Processor) finalizeVoIPAnalysis(report *models.TriageReport) {
	sipCalls := p.sipAnalyzer.GetCalls()
	rtpStreams := p.rtpAnalyzer.GetStreams()

	if len(sipCalls) == 0 && len(rtpStreams) == 0 {
		return
	}

	voip := &models.VoIPAnalysis{}

	// Convert SIP calls
	for _, call := range sipCalls {
		voip.TotalCalls++
		switch call.State {
		case "ESTABLISHED":
			voip.EstablishedCalls++
		case "FAILED_CLIENT", "FAILED_SERVER", "FAILED_GLOBAL":
			voip.FailedCalls++
		}

		voip.SIPCalls = append(voip.SIPCalls, models.SIPCallInfo{
			CallID:    call.CallID,
			FromURI:   call.FromURI,
			ToURI:     call.ToURI,
			State:     call.State,
			StartTime: float64(call.StartTime.UnixNano()) / 1e9,
			EndTime:   float64(call.EndTime.UnixNano()) / 1e9,
			SrcIP:     call.SrcIP,
			DstIP:     call.DstIP,
		})
	}

	// Convert RTP streams
	var totalJitter float64
	var totalLost, totalPackets uint64
	for _, stream := range rtpStreams {
		voip.TotalRTPStreams++
		totalJitter += stream.Jitter
		totalLost += stream.LostPackets
		totalPackets += stream.PacketCount

		voip.RTPStreams = append(voip.RTPStreams, models.RTPStreamInfo{
			SSRC:        stream.SSRC,
			SrcIP:       stream.SrcIP,
			DstIP:       stream.DstIP,
			PayloadType: stream.PayloadName,
			PacketCount: stream.PacketCount,
			ByteCount:   stream.ByteCount,
			LostPackets: stream.LostPackets,
			Jitter:      stream.Jitter,
		})
	}

	if voip.TotalRTPStreams > 0 {
		voip.AvgJitter = totalJitter / float64(voip.TotalRTPStreams)
	}
	if totalPackets > 0 {
		voip.PacketLossRate = float64(totalLost) / float64(totalPackets) * 100
	}

	report.VoIPAnalysis = voip
}

// finalizeTunnelAnalysis populates tunnel analysis results
func (p *Processor) finalizeTunnelAnalysis(report *models.TriageReport) {
	tunnels := p.tunnelAnalyzer.GetTunnels()

	for _, tunnel := range tunnels {
		report.TunnelAnalysis = append(report.TunnelAnalysis, models.TunnelFinding{
			Type:        tunnel.Type,
			SrcIP:       tunnel.SrcIP,
			DstIP:       tunnel.DstIP,
			SrcPort:     tunnel.SrcPort,
			DstPort:     tunnel.DstPort,
			Identifier:  tunnel.VNI,
			InnerProto:  tunnel.InnerProto,
			PacketCount: tunnel.PacketCount,
			ByteCount:   tunnel.ByteCount,
			FirstSeen:   float64(tunnel.FirstSeen.UnixNano()) / 1e9,
			LastSeen:    float64(tunnel.LastSeen.UnixNano()) / 1e9,
			// DPI-enhanced fields
			DetectionMethod: tunnel.DetectionMethod,
			Confidence:      tunnel.Confidence,
			ProtocolVersion: tunnel.ProtocolVersion,
			SessionState:    tunnel.SessionState,
			IsAuthorized:    tunnel.IsAuthorized,
			// SD-WAN specific fields
			SDWANPath: tunnel.SDWANPath,
		})
	}
}

// finalizeSDWANAnalysis populates SD-WAN vendor detection results
func (p *Processor) finalizeSDWANAnalysis(report *models.TriageReport) {
	// Prune vendors detected only by weak evidence (shared ports like 443)
	p.sdwanAnalyzer.Finalize()
	vendors := p.sdwanAnalyzer.GetDetectedVendors()

	for _, vendor := range vendors {
		report.SDWANVendors = append(report.SDWANVendors, models.SDWANVendor{
			Name:        vendor.Vendor,
			Confidence:  vendor.Confidence,
			DetectedBy:  vendor.DetectedBy,
			PacketCount: vendor.PacketCount,
			FirstSeen:   float64(vendor.FirstSeen.UnixNano()) / 1e9,
			LastSeen:    float64(vendor.LastSeen.UnixNano()) / 1e9,
		})
	}
}

// buildRTTHistogram creates histogram buckets from RTT samples
func (p *Processor) buildRTTHistogram(state *models.AnalysisState, report *models.TriageReport) {
	histogram := make(map[string]int)

	// Initialize buckets
	buckets := []string{
		"0-10ms",
		"10-50ms",
		"50-100ms",
		"100-200ms",
		"200-500ms",
		"500-1000ms",
		"1000ms+",
	}
	for _, bucket := range buckets {
		histogram[bucket] = 0
	}

	// Collect all RTT samples from TCP flows (using bounded cache iterator)
	state.ForEachTCPFlow(func(_ string, flowState *models.TCPFlowState) bool {
		for _, rtt := range flowState.RTTSamples {
			// Categorize RTT into buckets
			switch {
			case rtt < 10:
				histogram["0-10ms"]++
			case rtt < 50:
				histogram["10-50ms"]++
			case rtt < 100:
				histogram["50-100ms"]++
			case rtt < 200:
				histogram["100-200ms"]++
			case rtt < 500:
				histogram["200-500ms"]++
			case rtt < 1000:
				histogram["500-1000ms"]++
			default:
				histogram["1000ms+"]++
			}
		}
		return true
	})

	report.RTTHistogram = histogram
}

// buildTCPHandshakeCorrelatedFlows creates correlated TCP handshake flows for visualization
func (p *Processor) buildTCPHandshakeCorrelatedFlows(report *models.TriageReport) {
	correlatedFlows := make(map[string]*models.TCPHandshakeCorrelatedFlow)

	// Add SYN events
	for _, synFlow := range report.TCPHandshakes.SYNFlows {
		flowID := fmt.Sprintf("%s:%d->%s:%d", synFlow.SrcIP, synFlow.SrcPort, synFlow.DstIP, synFlow.DstPort)
		if _, exists := correlatedFlows[flowID]; !exists {
			correlatedFlows[flowID] = &models.TCPHandshakeCorrelatedFlow{
				FlowID:  flowID,
				SrcIP:   synFlow.SrcIP,
				SrcPort: synFlow.SrcPort,
				DstIP:   synFlow.DstIP,
				DstPort: synFlow.DstPort,
				Events:  []models.TCPHandshakeEvent{},
				Status:  "Pending",
			}
		}
		correlatedFlows[flowID].Events = append(correlatedFlows[flowID].Events, models.TCPHandshakeEvent{
			Type:      "SYN",
			Timestamp: synFlow.Timestamp,
		})
	}

	// Add SYN-ACK events (note: SYN-ACK comes from the opposite direction)
	for _, synAckFlow := range report.TCPHandshakes.SYNACKFlows {
		// SYN-ACK is sent from DstIP:DstPort back to SrcIP:SrcPort
		// So we need to find the original flow in the opposite direction
		flowID := fmt.Sprintf("%s:%d->%s:%d", synAckFlow.DstIP, synAckFlow.DstPort, synAckFlow.SrcIP, synAckFlow.SrcPort)
		if flow, exists := correlatedFlows[flowID]; exists {
			flow.Events = append(flow.Events, models.TCPHandshakeEvent{
				Type:      "SYN-ACK",
				Timestamp: synAckFlow.Timestamp,
			})
		}
	}

	// Add Handshake Complete events and set status
	for _, successFlow := range report.TCPHandshakes.SuccessfulHandshakes {
		flowID := fmt.Sprintf("%s:%d->%s:%d", successFlow.SrcIP, successFlow.SrcPort, successFlow.DstIP, successFlow.DstPort)
		if flow, exists := correlatedFlows[flowID]; exists {
			flow.Events = append(flow.Events, models.TCPHandshakeEvent{
				Type:      "Handshake Complete",
				Timestamp: successFlow.Timestamp,
			})
			flow.Status = "Complete"
		}
	}

	// Mark failed flows
	for _, failedFlow := range report.TCPHandshakes.FailedHandshakeAttempts {
		flowID := fmt.Sprintf("%s:%d->%s:%d", failedFlow.SrcIP, failedFlow.SrcPort, failedFlow.DstIP, failedFlow.DstPort)
		if flow, exists := correlatedFlows[flowID]; exists {
			if flow.Status != "Complete" {
				flow.Status = "Failed"
			}
		}
	}

	// Convert map to slice and sort events by timestamp within each flow
	for _, flow := range correlatedFlows {
		// Sort events by timestamp
		sort.Slice(flow.Events, func(i, j int) bool {
			return flow.Events[i].Timestamp < flow.Events[j].Timestamp
		})
		report.TCPHandshakeCorrelatedFlows = append(report.TCPHandshakeCorrelatedFlows, *flow)
	}

	// Sort correlated flows by first event timestamp
	sort.Slice(report.TCPHandshakeCorrelatedFlows, func(i, j int) bool {
		if len(report.TCPHandshakeCorrelatedFlows[i].Events) > 0 && len(report.TCPHandshakeCorrelatedFlows[j].Events) > 0 {
			return report.TCPHandshakeCorrelatedFlows[i].Events[0].Timestamp < report.TCPHandshakeCorrelatedFlows[j].Events[0].Timestamp
		}
		return false
	})
}
