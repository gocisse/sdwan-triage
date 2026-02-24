package detector

import (
	"fmt"
	"time"

	"github.com/gocisse/sdwan-triage/pkg/models"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// NTP constants
const (
	NTPPortNum               = 123
	NTPAmplificationMinSize  = 468  // Monlist response is typically 468+ bytes
	NTPAmplificationThreshold = 10  // Number of large NTP responses to flag
	NTPStratumChangeThreshold = 3   // Number of stratum changes to flag
)

// NTP mode constants
const (
	NTPModeClient          = 3
	NTPModeServer          = 4
	NTPModeBroadcast       = 5
	NTPModeControl         = 6
	NTPModePrivate         = 7 // Used for monlist
)

// NTPAnalyzer handles NTP packet analysis
type NTPAnalyzer struct {
	servers          map[string]*ntpServerInfo
	largeResponses   map[string]int // IP -> count of large responses
	lastReset        time.Time
}

type ntpServerInfo struct {
	IP           string
	Stratum      uint8
	PrevStratum  uint8
	StratumChanges int
	FirstSeen    time.Time
	LastSeen     time.Time
	PacketCount  int
}

// NewNTPAnalyzer creates a new NTP analyzer
func NewNTPAnalyzer() *NTPAnalyzer {
	return &NTPAnalyzer{
		servers:        make(map[string]*ntpServerInfo),
		largeResponses: make(map[string]int),
	}
}

// Analyze processes packets for NTP anomalies
func (n *NTPAnalyzer) Analyze(packet gopacket.Packet, state *models.AnalysisState, report *models.TriageReport) {
	udpLayer := packet.Layer(layers.LayerTypeUDP)
	if udpLayer == nil {
		return
	}

	udp := udpLayer.(*layers.UDP)
	srcPort := uint16(udp.SrcPort)
	dstPort := uint16(udp.DstPort)

	// Only process NTP traffic
	if srcPort != NTPPortNum && dstPort != NTPPortNum {
		return
	}

	payload := udp.Payload
	if len(payload) < 1 {
		return
	}

	ipInfo := ExtractIPInfo(packet)
	if ipInfo == nil {
		return
	}

	timestamp := packet.Metadata().Timestamp
	ts := float64(timestamp.UnixNano()) / 1e9

	// Parse NTP header
	flags := payload[0]
	mode := flags & 0x07
	version := (flags >> 3) & 0x07
	_ = version

	// Check for NTP amplification (large responses from server)
	if srcPort == NTPPortNum && len(payload) >= NTPAmplificationMinSize {
		n.trackLargeResponse(ipInfo.SrcIP, ipInfo.DstIP, len(payload), timestamp, ts, report)
	}

	// Check for monlist/private mode (mode 7) - used in amplification attacks
	if mode == NTPModePrivate && srcPort == NTPPortNum {
		n.reportMonlist(ipInfo.SrcIP, ipInfo.DstIP, len(payload), ts, report)
	}

	// Track NTP servers and stratum changes
	if srcPort == NTPPortNum && (mode == NTPModeServer || mode == NTPModeBroadcast) && len(payload) >= 48 {
		stratum := payload[1]
		n.trackServer(ipInfo.SrcIP, stratum, timestamp, ts, report)
	}
}

func (n *NTPAnalyzer) trackLargeResponse(srcIP, dstIP string, size int, timestamp time.Time, ts float64, report *models.TriageReport) {
	n.largeResponses[srcIP]++

	if n.largeResponses[srcIP] >= NTPAmplificationThreshold {
		// Only report once per source
		for _, f := range report.NTPFindings {
			if f.SourceIP == srcIP && f.Type == "Amplification" {
				return
			}
		}

		report.NTPFindings = append(report.NTPFindings, models.NTPFinding{
			Timestamp:    ts,
			Type:         "Amplification",
			SourceIP:     srcIP,
			DestIP:       dstIP,
			Severity:     "Critical",
			Description:  fmt.Sprintf("NTP amplification attack suspected: %d large responses (avg %d+ bytes) from %s", n.largeResponses[srcIP], NTPAmplificationMinSize, srcIP),
			PacketCount:  n.largeResponses[srcIP],
			ResponseSize: size,
		})
	}
}

func (n *NTPAnalyzer) reportMonlist(srcIP, dstIP string, size int, ts float64, report *models.TriageReport) {
	// Only report once per source
	for _, f := range report.NTPFindings {
		if f.SourceIP == srcIP && f.Type == "Monlist Response" {
			return
		}
	}

	report.NTPFindings = append(report.NTPFindings, models.NTPFinding{
		Timestamp:    ts,
		Type:         "Monlist Response",
		SourceIP:     srcIP,
		DestIP:       dstIP,
		Severity:     "Warning",
		Description:  fmt.Sprintf("NTP monlist response detected from %s (%d bytes). Monlist is commonly exploited for DDoS amplification", srcIP, size),
		PacketCount:  1,
		ResponseSize: size,
	})
}

func (n *NTPAnalyzer) trackServer(serverIP string, stratum uint8, timestamp time.Time, ts float64, report *models.TriageReport) {
	server, exists := n.servers[serverIP]
	if !exists {
		n.servers[serverIP] = &ntpServerInfo{
			IP:        serverIP,
			Stratum:   stratum,
			FirstSeen: timestamp,
			LastSeen:  timestamp,
			PacketCount: 1,
		}
		return
	}

	server.PacketCount++
	server.LastSeen = timestamp

	// Detect stratum changes
	if server.Stratum != stratum && stratum > 0 && server.Stratum > 0 {
		server.PrevStratum = server.Stratum
		server.Stratum = stratum
		server.StratumChanges++

		if server.StratumChanges >= NTPStratumChangeThreshold {
			// Only report once per server
			for _, f := range report.NTPFindings {
				if f.SourceIP == serverIP && f.Type == "Stratum Change" {
					return
				}
			}

			report.NTPFindings = append(report.NTPFindings, models.NTPFinding{
				Timestamp:   ts,
				Type:        "Stratum Change",
				SourceIP:    serverIP,
				Stratum:     stratum,
				Severity:    "Warning",
				Description: fmt.Sprintf("NTP server %s has changed stratum %d times (last: %d -> %d). This may indicate NTP server instability or manipulation", serverIP, server.StratumChanges, server.PrevStratum, stratum),
				PacketCount: server.PacketCount,
			})
		}
	}
}
