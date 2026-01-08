package detector

import (
	"fmt"

	"github.com/gocisse/sdwan-triage/pkg/models"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// ARPAnalyzer handles ARP packet analysis
type ARPAnalyzer struct{}

// NewARPAnalyzer creates a new ARP analyzer
func NewARPAnalyzer() *ARPAnalyzer {
	return &ARPAnalyzer{}
}

// Analyze processes an ARP packet and detects conflicts
func (a *ARPAnalyzer) Analyze(packet gopacket.Packet, state *models.AnalysisState, report *models.TriageReport) {
	arpLayer := packet.Layer(layers.LayerTypeARP)
	if arpLayer == nil {
		return
	}

	arp, ok := arpLayer.(*layers.ARP)
	if !ok {
		return
	}

	// Only process ARP replies (operation 2)
	if arp.Operation != 2 {
		return
	}

	srcIP := formatIP(arp.SourceProtAddress)
	srcMAC := formatMAC(arp.SourceHwAddress)

	// Check for IP/MAC conflicts
	if existingMAC, exists := state.ARPIPToMAC[srcIP]; exists {
		if existingMAC != srcMAC {
			// ARP conflict detected
			conflict := models.ARPConflict{
				IP:   srcIP,
				MAC1: existingMAC,
				MAC2: srcMAC,
			}

			// Check if this conflict is already recorded
			found := false
			for _, existing := range report.ARPConflicts {
				if existing.IP == srcIP {
					found = true
					break
				}
			}

			if !found {
				report.ARPConflicts = append(report.ARPConflicts, conflict)

				// Add timeline event
				timestamp := float64(packet.Metadata().Timestamp.UnixNano()) / 1e9
				event := models.TimelineEvent{
					Timestamp: timestamp,
					EventType: "ARP Conflict",
					SourceIP:  srcIP,
					Protocol:  "ARP",
					Detail:    "IP address claimed by multiple MAC addresses: " + existingMAC + " and " + srcMAC,
				}
				report.Timeline = append(report.Timeline, event)
			}
		}
	} else {
		// First time seeing this IP, record the MAC
		state.ARPIPToMAC[srcIP] = srcMAC
	}
}

// formatIP converts a byte slice to IP string
func formatIP(ip []byte) string {
	if len(ip) == 4 {
		return fmt.Sprintf("%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3])
	}
	return ""
}

// formatMAC converts a byte slice to MAC string
func formatMAC(mac []byte) string {
	if len(mac) == 6 {
		return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5])
	}
	return ""
}
