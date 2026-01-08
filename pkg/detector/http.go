package detector

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/gocisse/sdwan-triage/pkg/models"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// HTTPAnalyzer handles HTTP packet analysis
type HTTPAnalyzer struct{}

// NewHTTPAnalyzer creates a new HTTP analyzer
func NewHTTPAnalyzer() *HTTPAnalyzer {
	return &HTTPAnalyzer{}
}

// Analyze processes HTTP packets and detects errors
func (h *HTTPAnalyzer) Analyze(packet gopacket.Packet, state *models.AnalysisState, report *models.TriageReport) {
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		return
	}

	tcp, ok := tcpLayer.(*layers.TCP)
	if !ok || len(tcp.Payload) == 0 {
		return
	}

	// Get IP info
	var srcIP, dstIP string
	if ip4Layer := packet.Layer(layers.LayerTypeIPv4); ip4Layer != nil {
		ip4 := ip4Layer.(*layers.IPv4)
		srcIP = ip4.SrcIP.String()
		dstIP = ip4.DstIP.String()
	}

	srcPort := uint16(tcp.SrcPort)
	dstPort := uint16(tcp.DstPort)
	flowKey := fmt.Sprintf("%s:%d->%s:%d", srcIP, srcPort, dstIP, dstPort)
	timestamp := float64(packet.Metadata().Timestamp.UnixNano()) / 1e9

	payload := string(tcp.Payload)

	// Check for HTTP request
	if isHTTPRequest(payload) {
		req := parseHTTPRequest(payload)
		if req != nil {
			state.HTTPRequests[flowKey] = req
		}
	}

	// Check for HTTP response
	if isHTTPResponse(payload) {
		statusCode := parseHTTPStatusCode(payload)
		if statusCode >= 400 {
			// Look up the original request
			reverseFlowKey := fmt.Sprintf("%s:%d->%s:%d", dstIP, dstPort, srcIP, srcPort)
			req := state.HTTPRequests[reverseFlowKey]

			httpError := models.HTTPError{
				Timestamp: timestamp,
				Code:      statusCode,
			}

			if req != nil {
				httpError.Method = req.Method
				httpError.Host = req.Host
				httpError.Path = req.Path
			} else {
				httpError.Method = "UNKNOWN"
				httpError.Host = dstIP
				httpError.Path = "/"
			}

			report.HTTPErrors = append(report.HTTPErrors, httpError)

			// Add timeline event
			event := models.TimelineEvent{
				Timestamp:     timestamp,
				EventType:     "HTTP Error",
				SourceIP:      srcIP,
				DestinationIP: dstIP,
				Protocol:      "HTTP",
				Detail:        fmt.Sprintf("%d %s %s%s", statusCode, httpError.Method, httpError.Host, httpError.Path),
			}
			srcPortPtr := srcPort
			dstPortPtr := dstPort
			event.SourcePort = &srcPortPtr
			event.DestinationPort = &dstPortPtr
			report.Timeline = append(report.Timeline, event)
		}
	}

	// Check for HTTP/2 connection preface
	if strings.HasPrefix(payload, "PRI * HTTP/2.0") {
		flow := models.TCPFlow{
			SrcIP:   srcIP,
			SrcPort: srcPort,
			DstIP:   dstIP,
			DstPort: dstPort,
		}

		// Check if already recorded
		found := false
		for _, existing := range report.HTTP2Flows {
			if existing.SrcIP == srcIP && existing.DstIP == dstIP &&
				existing.SrcPort == srcPort && existing.DstPort == dstPort {
				found = true
				break
			}
		}

		if !found {
			report.HTTP2Flows = append(report.HTTP2Flows, flow)
		}
	}
}

// isHTTPRequest checks if payload starts with an HTTP method
func isHTTPRequest(payload string) bool {
	methods := []string{"GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ", "PATCH ", "CONNECT "}
	for _, method := range methods {
		if strings.HasPrefix(payload, method) {
			return true
		}
	}
	return false
}

// isHTTPResponse checks if payload starts with HTTP response
func isHTTPResponse(payload string) bool {
	return strings.HasPrefix(payload, "HTTP/")
}

// parseHTTPRequest extracts request details
func parseHTTPRequest(payload string) *models.HTTPRequest {
	lines := strings.Split(payload, "\r\n")
	if len(lines) == 0 {
		return nil
	}

	// Parse request line
	parts := strings.SplitN(lines[0], " ", 3)
	if len(parts) < 2 {
		return nil
	}

	req := &models.HTTPRequest{
		Method: parts[0],
		Path:   parts[1],
	}

	// Parse headers for Host
	for _, line := range lines[1:] {
		if strings.HasPrefix(strings.ToLower(line), "host:") {
			req.Host = strings.TrimSpace(line[5:])
			break
		}
	}

	return req
}

// parseHTTPStatusCode extracts status code from response
func parseHTTPStatusCode(payload string) int {
	lines := strings.Split(payload, "\r\n")
	if len(lines) == 0 {
		return 0
	}

	// Parse status line: HTTP/1.1 200 OK
	parts := strings.SplitN(lines[0], " ", 3)
	if len(parts) < 2 {
		return 0
	}

	code, err := strconv.Atoi(parts[1])
	if err != nil {
		return 0
	}

	return code
}
