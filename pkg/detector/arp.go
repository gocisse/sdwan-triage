package detector

import (
	"fmt"

	"github.com/gocisse/sdwan-triage/pkg/models"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// ARPAnalyzer handles ARP packet analysis
type ARPAnalyzer struct {
	// firstFrame: capture frame of the first ARP reply seen for each IP (Phase 4.35),
	// parallel to state.ARPIPToMAC, used only to reference the evidence of a conflict.
	firstFrame map[string]uint64
}

// NewARPAnalyzer creates a new ARP analyzer
func NewARPAnalyzer() *ARPAnalyzer {
	return &ARPAnalyzer{firstFrame: make(map[string]uint64)}
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

	frame, _ := currentFrame(report, packet.Metadata().Timestamp)

	// Check for IP/MAC conflicts
	if existingMAC, exists := state.ARPIPToMAC[srcIP]; exists {
		if existingMAC != srcMAC {
			// Is this IP already recorded as a conflict?
			idx := -1
			for i, existing := range report.ARPConflicts {
				if existing.IP == srcIP {
					idx = i
					break
				}
			}

			if idx < 0 {
				// ARP conflict detected
				conflict := models.ARPConflict{
					IP:        srcIP,
					MAC1:      existingMAC,
					MAC2:      srcMAC,
					MAC1Frame: a.firstFrame[srcIP],
					MAC2Frame: frame,
				}
				conflict.Classify()
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
				report.AddTimelineEvent(event)
			} else {
				// A further MAC answering for an IP that is already a conflict: remember it
				// (bounded) so the classification covers every MAC that answered.
				c := &report.ARPConflicts[idx]
				known := srcMAC == c.MAC1 || srcMAC == c.MAC2
				for _, m := range c.OtherMACs {
					known = known || m == srcMAC
				}
				if !known && len(c.OtherMACs) < arpMaxOtherMACs {
					c.OtherMACs = append(c.OtherMACs, srcMAC)
					c.Classify()
				}
			}
		}
	} else {
		// First time seeing this IP, record the MAC
		state.ARPIPToMAC[srcIP] = srcMAC
		a.firstFrame[srcIP] = frame
	}
}

// arpMaxOtherMACs bounds the additional MACs remembered per conflicting IP.
const arpMaxOtherMACs = 8

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
