package detector

import (
	"fmt"
	"time"

	"github.com/gocisse/sdwan-triage/pkg/models"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// DHCP constants
const (
	DHCPServerPort = 67
	DHCPClientPort = 68

	// DHCP Message Types
	DHCPDiscover = 1
	DHCPOffer    = 2
	DHCPRequest  = 3
	DHCPDecline  = 4
	DHCPAck      = 5
	DHCPNak      = 6
	DHCPRelease  = 7
	DHCPInform   = 8

	// Thresholds
	DHCPStarvationThreshold = 50  // Discover packets from same MAC in window
	DHCPNAKStormThreshold   = 10  // NAKs in detection window
	DHCPDetectionWindowSec  = 60.0
)

// DHCPAnalyzer handles DHCP packet analysis
type DHCPAnalyzer struct {
	servers       map[string]*dhcpServerInfo
	discoverCount map[string]*dhcpFloodCounter
	nakCount      int
	nakFirstSeen  time.Time
	lastReset     time.Time
}

type dhcpServerInfo struct {
	IP          string
	MAC         string
	OfferCount  int
	FirstSeen   time.Time
	LastSeen    time.Time
}

type dhcpFloodCounter struct {
	MAC       string
	Count     int
	FirstSeen time.Time
	LastSeen  time.Time
}

// NewDHCPAnalyzer creates a new DHCP analyzer
func NewDHCPAnalyzer() *DHCPAnalyzer {
	return &DHCPAnalyzer{
		servers:       make(map[string]*dhcpServerInfo),
		discoverCount: make(map[string]*dhcpFloodCounter),
		lastReset:     time.Time{},
	}
}

// Analyze processes packets for DHCP anomalies
func (d *DHCPAnalyzer) Analyze(packet gopacket.Packet, state *models.AnalysisState, report *models.TriageReport) {
	udpLayer := packet.Layer(layers.LayerTypeUDP)
	if udpLayer == nil {
		return
	}

	udp := udpLayer.(*layers.UDP)
	srcPort := uint16(udp.SrcPort)
	dstPort := uint16(udp.DstPort)

	// Only process DHCP traffic
	if (srcPort != DHCPServerPort && srcPort != DHCPClientPort) &&
		(dstPort != DHCPServerPort && dstPort != DHCPClientPort) {
		return
	}

	payload := udp.Payload
	if len(payload) < 240 { // Minimum DHCP packet size
		return
	}

	timestamp := packet.Metadata().Timestamp
	d.maybeResetCounters(timestamp)

	// Parse DHCP message type from options
	msgType := d.extractDHCPMessageType(payload)
	if msgType == 0 {
		return
	}

	// Get MAC and IP info
	ipInfo := ExtractIPInfo(packet)
	var srcMAC string
	if ethLayer := packet.Layer(layers.LayerTypeEthernet); ethLayer != nil {
		eth := ethLayer.(*layers.Ethernet)
		srcMAC = eth.SrcMAC.String()
	}

	srcIP := ""
	if ipInfo != nil {
		srcIP = ipInfo.SrcIP
	}

	ts := float64(timestamp.UnixNano()) / 1e9

	switch msgType {
	case DHCPDiscover:
		// Track DHCP Discover floods (starvation attack)
		d.trackDiscover(srcMAC, timestamp, ts, report)

	case DHCPOffer:
		// Track DHCP servers for rogue server detection
		d.trackServer(srcIP, srcMAC, timestamp, ts, report)

	case DHCPNak:
		// Track NAK storms
		d.trackNAK(srcIP, timestamp, ts, report)
	}
}

func (d *DHCPAnalyzer) trackDiscover(clientMAC string, timestamp time.Time, ts float64, report *models.TriageReport) {
	if clientMAC == "" {
		return
	}

	counter, exists := d.discoverCount[clientMAC]
	if !exists {
		counter = &dhcpFloodCounter{
			MAC:       clientMAC,
			Count:     0,
			FirstSeen: timestamp,
		}
		d.discoverCount[clientMAC] = counter
	}

	counter.Count++
	counter.LastSeen = timestamp

	// Check for starvation attack
	if counter.Count >= DHCPStarvationThreshold {
		// Only report once per MAC
		for _, f := range report.DHCPFindings {
			if f.ClientMAC == clientMAC && f.Type == "Starvation" {
				return
			}
		}

		report.DHCPFindings = append(report.DHCPFindings, models.DHCPFinding{
			Timestamp:   ts,
			Type:        "Starvation",
			ClientMAC:   clientMAC,
			Severity:    "Critical",
			Description: fmt.Sprintf("DHCP starvation attack suspected: %d DISCOVER packets from MAC %s in %.0f seconds", counter.Count, clientMAC, counter.LastSeen.Sub(counter.FirstSeen).Seconds()),
			PacketCount: counter.Count,
		})
	}
}

func (d *DHCPAnalyzer) trackServer(serverIP, serverMAC string, timestamp time.Time, ts float64, report *models.TriageReport) {
	if serverIP == "" {
		return
	}

	server, exists := d.servers[serverIP]
	if !exists {
		server = &dhcpServerInfo{
			IP:        serverIP,
			MAC:       serverMAC,
			FirstSeen: timestamp,
		}
		d.servers[serverIP] = server
	}

	server.OfferCount++
	server.LastSeen = timestamp

	// If we see more than 2 DHCP servers, flag potential rogue
	if len(d.servers) > 1 {
		// Only report once
		for _, f := range report.DHCPFindings {
			if f.Type == "Rogue Server" {
				return
			}
		}

		knownServers := make([]string, 0, len(d.servers))
		for ip := range d.servers {
			knownServers = append(knownServers, ip)
		}

		report.DHCPFindings = append(report.DHCPFindings, models.DHCPFinding{
			Timestamp:    ts,
			Type:         "Rogue Server",
			ServerIP:     serverIP,
			ServerMAC:    serverMAC,
			Severity:     "Critical",
			Description:  fmt.Sprintf("Multiple DHCP servers detected (%d servers). Possible rogue DHCP server at %s", len(d.servers), serverIP),
			PacketCount:  server.OfferCount,
			KnownServers: knownServers,
		})
	}
}

func (d *DHCPAnalyzer) trackNAK(serverIP string, timestamp time.Time, ts float64, report *models.TriageReport) {
	if d.nakCount == 0 {
		d.nakFirstSeen = timestamp
	}
	d.nakCount++

	if d.nakCount >= DHCPNAKStormThreshold {
		// Only report once
		for _, f := range report.DHCPFindings {
			if f.Type == "NAK Storm" {
				return
			}
		}

		report.DHCPFindings = append(report.DHCPFindings, models.DHCPFinding{
			Timestamp:   ts,
			Type:        "NAK Storm",
			ServerIP:    serverIP,
			Severity:    "Warning",
			Description: fmt.Sprintf("DHCP NAK storm detected: %d NAKs in %.0f seconds from server %s", d.nakCount, timestamp.Sub(d.nakFirstSeen).Seconds(), serverIP),
			PacketCount: d.nakCount,
		})
	}
}

func (d *DHCPAnalyzer) extractDHCPMessageType(payload []byte) uint8 {
	// DHCP options start at offset 240 (after fixed fields)
	if len(payload) < 241 {
		return 0
	}

	// Check magic cookie (99.130.83.99)
	if len(payload) >= 240 && payload[236] == 99 && payload[237] == 130 && payload[238] == 83 && payload[239] == 99 {
		// Parse options
		offset := 240
		for offset < len(payload)-1 {
			optType := payload[offset]
			if optType == 255 { // End option
				break
			}
			if optType == 0 { // Padding
				offset++
				continue
			}
			if offset+1 >= len(payload) {
				break
			}
			optLen := int(payload[offset+1])
			if offset+2+optLen > len(payload) {
				break
			}

			if optType == 53 && optLen == 1 { // DHCP Message Type
				return payload[offset+2]
			}

			offset += 2 + optLen
		}
	}

	return 0
}

func (d *DHCPAnalyzer) maybeResetCounters(timestamp time.Time) {
	if d.lastReset.IsZero() {
		d.lastReset = timestamp
		return
	}

	if timestamp.Sub(d.lastReset).Seconds() >= DHCPDetectionWindowSec {
		d.discoverCount = make(map[string]*dhcpFloodCounter)
		d.nakCount = 0
		d.lastReset = timestamp
	}
}
