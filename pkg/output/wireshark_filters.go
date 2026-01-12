package output

import (
	"fmt"
	"strings"

	"github.com/gocisse/sdwan-triage/pkg/models"
)

// WiresharkFilterGenerator generates Wireshark display filters for various finding types
type WiresharkFilterGenerator struct{}

// NewWiresharkFilterGenerator creates a new filter generator
func NewWiresharkFilterGenerator() *WiresharkFilterGenerator {
	return &WiresharkFilterGenerator{}
}

// GenerateFlowFilter creates a filter for a specific flow between two IPs
func (wfg *WiresharkFilterGenerator) GenerateFlowFilter(srcIP, dstIP string, port uint16, protocol string) string {
	if port > 0 {
		if protocol == "TCP" || protocol == "tcp" {
			return fmt.Sprintf("ip.addr == %s and ip.addr == %s and tcp.port == %d", srcIP, dstIP, port)
		} else if protocol == "UDP" || protocol == "udp" {
			return fmt.Sprintf("ip.addr == %s and ip.addr == %s and udp.port == %d", srcIP, dstIP, port)
		}
	}
	return fmt.Sprintf("ip.addr == %s and ip.addr == %s", srcIP, dstIP)
}

// GenerateTCPRetransmissionFilter creates a filter for TCP retransmissions
func (wfg *WiresharkFilterGenerator) GenerateTCPRetransmissionFilter(srcIP, dstIP string, port uint16) string {
	if port > 0 {
		return fmt.Sprintf("tcp.analysis.retransmission and ip.addr == %s and ip.addr == %s and tcp.port == %d", srcIP, dstIP, port)
	}
	return fmt.Sprintf("tcp.analysis.retransmission and ip.addr == %s and ip.addr == %s", srcIP, dstIP)
}

// GenerateTCPSYNFilter creates a filter for TCP SYN packets
func (wfg *WiresharkFilterGenerator) GenerateTCPSYNFilter(srcIP, dstIP string, port uint16) string {
	if port > 0 {
		return fmt.Sprintf("ip.src == %s and ip.dst == %s and tcp.dstport == %d and tcp.flags.syn == 1 and tcp.flags.ack == 0", srcIP, dstIP, port)
	}
	return fmt.Sprintf("ip.src == %s and ip.dst == %s and tcp.flags.syn == 1 and tcp.flags.ack == 0", srcIP, dstIP)
}

// GenerateFailedHandshakeFilter creates a filter for failed TCP handshakes
func (wfg *WiresharkFilterGenerator) GenerateFailedHandshakeFilter(srcIP, dstIP string, port uint16) string {
	if port > 0 {
		return fmt.Sprintf("(tcp.flags.syn == 1 and tcp.flags.ack == 0) and ip.addr == %s and ip.addr == %s and tcp.port == %d", srcIP, dstIP, port)
	}
	return fmt.Sprintf("(tcp.flags.syn == 1 and tcp.flags.ack == 0) and ip.addr == %s and ip.addr == %s", srcIP, dstIP)
}

// GenerateDNSQueryFilter creates a filter for DNS queries
func (wfg *WiresharkFilterGenerator) GenerateDNSQueryFilter(queryName, srcIP, dnsServer string) string {
	filters := []string{"dns", "dns.flags.response == 0"}

	if queryName != "" {
		filters = append(filters, fmt.Sprintf("dns.qry.name == \"%s\"", queryName))
	}
	if srcIP != "" {
		filters = append(filters, fmt.Sprintf("ip.src == %s", srcIP))
	}
	if dnsServer != "" {
		filters = append(filters, fmt.Sprintf("ip.dst == %s", dnsServer))
	}

	return strings.Join(filters, " and ")
}

// GenerateDNSResponseFilter creates a filter for DNS responses
func (wfg *WiresharkFilterGenerator) GenerateDNSResponseFilter(queryName, dnsServer, clientIP string) string {
	filters := []string{"dns", "dns.flags.response == 1"}

	if queryName != "" {
		filters = append(filters, fmt.Sprintf("dns.qry.name == \"%s\"", queryName))
	}
	if dnsServer != "" {
		filters = append(filters, fmt.Sprintf("ip.src == %s", dnsServer))
	}
	if clientIP != "" {
		filters = append(filters, fmt.Sprintf("ip.dst == %s", clientIP))
	}

	return strings.Join(filters, " and ")
}

// GenerateDNSAnomalyFilter creates a filter for DNS anomalies
func (wfg *WiresharkFilterGenerator) GenerateDNSAnomalyFilter(anomaly models.DNSAnomaly) string {
	if anomaly.Query != "" {
		return fmt.Sprintf("dns and dns.qry.name == \"%s\" and ip.addr == %s", anomaly.Query, anomaly.ServerIP)
	}
	return fmt.Sprintf("dns and ip.addr == %s", anomaly.ServerIP)
}

// GenerateARPConflictFilter creates a filter for ARP conflicts
func (wfg *WiresharkFilterGenerator) GenerateARPConflictFilter(ip string, mac1, mac2 string) string {
	if mac1 != "" && mac2 != "" {
		return fmt.Sprintf("arp and arp.src.proto_ipv4 == %s and (eth.src == %s or eth.src == %s)", ip, mac1, mac2)
	}
	return fmt.Sprintf("arp and arp.src.proto_ipv4 == %s", ip)
}

// GenerateHTTPErrorFilter creates a filter for HTTP errors
func (wfg *WiresharkFilterGenerator) GenerateHTTPErrorFilter(statusCode int, srcIP, dstIP string) string {
	filters := []string{"http"}

	if statusCode > 0 {
		filters = append(filters, fmt.Sprintf("http.response.code == %d", statusCode))
	}
	if srcIP != "" {
		filters = append(filters, fmt.Sprintf("ip.addr == %s", srcIP))
	}
	if dstIP != "" {
		filters = append(filters, fmt.Sprintf("ip.addr == %s", dstIP))
	}

	return strings.Join(filters, " and ")
}

// GenerateTLSFilter creates a filter for TLS/SSL traffic
func (wfg *WiresharkFilterGenerator) GenerateTLSFilter(srcIP, dstIP string, port uint16) string {
	filters := []string{"tls"}

	if srcIP != "" {
		filters = append(filters, fmt.Sprintf("ip.addr == %s", srcIP))
	}
	if dstIP != "" {
		filters = append(filters, fmt.Sprintf("ip.addr == %s", dstIP))
	}
	if port > 0 {
		filters = append(filters, fmt.Sprintf("tcp.port == %d", port))
	}

	return strings.Join(filters, " and ")
}

// GenerateHighRTTFilter creates a filter for high RTT flows
func (wfg *WiresharkFilterGenerator) GenerateHighRTTFilter(srcIP, dstIP string, port uint16) string {
	if port > 0 {
		return fmt.Sprintf("tcp and ip.addr == %s and ip.addr == %s and tcp.port == %d", srcIP, dstIP, port)
	}
	return fmt.Sprintf("tcp and ip.addr == %s and ip.addr == %s", srcIP, dstIP)
}

// GenerateSuspiciousTrafficFilter creates a filter for suspicious traffic
func (wfg *WiresharkFilterGenerator) GenerateSuspiciousTrafficFilter(srcIP, dstIP string, port uint16, protocol string) string {
	return wfg.GenerateFlowFilter(srcIP, dstIP, port, protocol)
}

// GeneratePortScanFilter creates a filter for port scan detection
func (wfg *WiresharkFilterGenerator) GeneratePortScanFilter(scannerIP string) string {
	return fmt.Sprintf("ip.src == %s and tcp.flags.syn == 1 and tcp.flags.ack == 0", scannerIP)
}

// GenerateDDoSFilter creates a filter for DDoS traffic
func (wfg *WiresharkFilterGenerator) GenerateDDoSFilter(targetIP string, attackType string) string {
	switch strings.ToLower(attackType) {
	case "syn flood":
		return fmt.Sprintf("ip.dst == %s and tcp.flags.syn == 1 and tcp.flags.ack == 0", targetIP)
	case "udp flood":
		return fmt.Sprintf("ip.dst == %s and udp", targetIP)
	case "icmp flood":
		return fmt.Sprintf("ip.dst == %s and icmp", targetIP)
	default:
		return fmt.Sprintf("ip.dst == %s", targetIP)
	}
}

// GenerateICMPFilter creates a filter for ICMP traffic
func (wfg *WiresharkFilterGenerator) GenerateICMPFilter(srcIP, dstIP string, icmpType int) string {
	filters := []string{"icmp"}

	if srcIP != "" {
		filters = append(filters, fmt.Sprintf("ip.src == %s", srcIP))
	}
	if dstIP != "" {
		filters = append(filters, fmt.Sprintf("ip.dst == %s", dstIP))
	}
	if icmpType >= 0 {
		filters = append(filters, fmt.Sprintf("icmp.type == %d", icmpType))
	}

	return strings.Join(filters, " and ")
}

// GenerateTimelineEventFilter creates a filter from timeline event data
func (wfg *WiresharkFilterGenerator) GenerateTimelineEventFilter(eventType, srcIP, dstIP string, srcPort, dstPort *uint16) string {
	switch strings.ToUpper(eventType) {
	case "TCP SYN":
		if dstPort != nil {
			return wfg.GenerateTCPSYNFilter(srcIP, dstIP, *dstPort)
		}
		return wfg.GenerateTCPSYNFilter(srcIP, dstIP, 0)
	case "DNS QUERY":
		return wfg.GenerateDNSQueryFilter("", srcIP, dstIP)
	case "DNS RESPONSE":
		return wfg.GenerateDNSResponseFilter("", srcIP, dstIP)
	case "TCP RETRANSMISSION":
		if srcPort != nil {
			return wfg.GenerateTCPRetransmissionFilter(srcIP, dstIP, *srcPort)
		}
		return wfg.GenerateTCPRetransmissionFilter(srcIP, dstIP, 0)
	case "HTTP ERROR":
		return wfg.GenerateHTTPErrorFilter(0, srcIP, dstIP)
	default:
		return wfg.GenerateFlowFilter(srcIP, dstIP, 0, "")
	}
}

// GenerateNetworkRangeFilter creates a filter for traffic between network ranges
func (wfg *WiresharkFilterGenerator) GenerateNetworkRangeFilter(srcRange, dstRange string) string {
	if srcRange != "" && dstRange != "" {
		return fmt.Sprintf("ip.src == %s and ip.dst == %s", srcRange, dstRange)
	} else if srcRange != "" {
		return fmt.Sprintf("ip.src == %s", srcRange)
	} else if dstRange != "" {
		return fmt.Sprintf("ip.dst == %s", dstRange)
	}
	return "ip"
}

// GetFilterGuideHTML returns HTML documentation for using Wireshark filters
func (wfg *WiresharkFilterGenerator) GetFilterGuideHTML() string {
	return `
<div class="card" id="wireshark-filter-guide">
    <div class="card-header">
        <i class="fas fa-filter"></i>
        <h2>Wireshark Filter Guide</h2>
    </div>
    <div class="card-body">
        <div class="explanation-content">
            <h3>How to Use Wireshark Filters with This Report</h3>
            
            <h4>📋 Quick Start</h4>
            <ol>
                <li><strong>Copy the Filter:</strong> Click the "Copy" button next to any Wireshark filter in this report</li>
                <li><strong>Open Wireshark:</strong> Load your PCAP file in Wireshark</li>
                <li><strong>Apply Filter:</strong> Paste the filter into the display filter bar at the top</li>
                <li><strong>Press Enter:</strong> Wireshark will show only the packets matching the filter</li>
            </ol>

            <h4>🔍 Extracting Filters from Report Data</h4>
            <p>This report contains network analysis data in JavaScript variables. You can extract additional filters by:</p>
            <ol>
                <li><strong>View Page Source:</strong> Press <code>Ctrl+U</code> (or <code>Cmd+Option+U</code> on Mac) to view the HTML source</li>
                <li><strong>Search for Data:</strong> Press <code>Ctrl+F</code> and search for:
                    <ul>
                        <li><code>var timelineData</code> - Event timeline with IPs, ports, and event types</li>
                        <li><code>var networkData</code> - Flow data for retransmissions and issues</li>
                        <li><code>var sankeyData</code> - Top-level traffic flow aggregations</li>
                    </ul>
                </li>
                <li><strong>Identify IPs and Ports:</strong> Look for IP addresses and port numbers in the data</li>
                <li><strong>Build Your Filter:</strong> Use the examples below to construct custom filters</li>
            </ol>

            <h4>📝 Common Filter Patterns</h4>
            
            <details>
                <summary><strong>Basic Flow Filters</strong></summary>
                <div class="filter-examples">
                    <p><strong>Traffic between two IPs:</strong></p>
                    <code>ip.addr == 192.168.1.100 and ip.addr == 8.8.8.8</code>
                    
                    <p><strong>Specific port:</strong></p>
                    <code>ip.addr == 192.168.1.100 and tcp.port == 443</code>
                    
                    <p><strong>Source to destination:</strong></p>
                    <code>ip.src == 192.168.1.100 and ip.dst == 8.8.8.8</code>
                </div>
            </details>

            <details>
                <summary><strong>TCP Analysis Filters</strong></summary>
                <div class="filter-examples">
                    <p><strong>TCP Retransmissions:</strong></p>
                    <code>tcp.analysis.retransmission and ip.addr == 192.168.1.100</code>
                    
                    <p><strong>TCP SYN packets (connection attempts):</strong></p>
                    <code>tcp.flags.syn == 1 and tcp.flags.ack == 0</code>
                    
                    <p><strong>Failed handshakes (SYN with no response):</strong></p>
                    <code>tcp.flags.syn == 1 and tcp.flags.ack == 0 and ip.addr == 192.168.1.100</code>
                    
                    <p><strong>TCP resets:</strong></p>
                    <code>tcp.flags.reset == 1</code>
                </div>
            </details>

            <details>
                <summary><strong>DNS Filters</strong></summary>
                <div class="filter-examples">
                    <p><strong>DNS queries:</strong></p>
                    <code>dns and dns.flags.response == 0</code>
                    
                    <p><strong>DNS responses:</strong></p>
                    <code>dns and dns.flags.response == 1</code>
                    
                    <p><strong>Specific domain query:</strong></p>
                    <code>dns.qry.name == "example.com"</code>
                    
                    <p><strong>DNS failures (NXDOMAIN):</strong></p>
                    <code>dns.flags.rcode == 3</code>
                </div>
            </details>

            <details>
                <summary><strong>Security Filters</strong></summary>
                <div class="filter-examples">
                    <p><strong>Port scan detection:</strong></p>
                    <code>ip.src == 192.168.1.100 and tcp.flags.syn == 1 and tcp.flags.ack == 0</code>
                    
                    <p><strong>SYN flood (DDoS):</strong></p>
                    <code>ip.dst == 192.168.1.1 and tcp.flags.syn == 1 and tcp.flags.ack == 0</code>
                    
                    <p><strong>ARP conflicts:</strong></p>
                    <code>arp and arp.src.proto_ipv4 == 192.168.1.100</code>
                    
                    <p><strong>Suspicious high-port connections:</strong></p>
                    <code>tcp.dstport > 49152 and tcp.flags.syn == 1</code>
                </div>
            </details>

            <details>
                <summary><strong>HTTP/HTTPS Filters</strong></summary>
                <div class="filter-examples">
                    <p><strong>HTTP errors (4xx, 5xx):</strong></p>
                    <code>http.response.code >= 400</code>
                    
                    <p><strong>Specific error code:</strong></p>
                    <code>http.response.code == 404</code>
                    
                    <p><strong>TLS/SSL traffic:</strong></p>
                    <code>tls and ip.addr == 192.168.1.100</code>
                    
                    <p><strong>TLS handshake:</strong></p>
                    <code>tls.handshake.type == 1</code>
                </div>
            </details>

            <h4>💡 Pro Tips</h4>
            <ul>
                <li><strong>Combine Filters:</strong> Use <code>and</code>, <code>or</code>, and parentheses: <code>(ip.addr == 192.168.1.100) and (tcp.port == 443 or tcp.port == 80)</code></li>
                <li><strong>Exclude Traffic:</strong> Use <code>!</code> or <code>not</code>: <code>ip.addr == 192.168.1.100 and !dns</code></li>
                <li><strong>Follow TCP Stream:</strong> Right-click a packet → Follow → TCP Stream to see the entire conversation</li>
                <li><strong>Save Filters:</strong> Click the bookmark icon in Wireshark to save frequently used filters</li>
                <li><strong>Time-based Filtering:</strong> Use <code>frame.time >= "2024-01-01 10:00:00"</code> to filter by time</li>
            </ul>

            <h4>🎯 Using Timeline Data</h4>
            <p>The <code>timelineData</code> variable in this report contains events with:</p>
            <ul>
                <li><code>source</code> - Source IP address</li>
                <li><code>target</code> - Destination IP address</li>
                <li><code>type</code> - Event type (TCP SYN, DNS Query, etc.)</li>
                <li><code>timestamp</code> - Unix timestamp</li>
            </ul>
            <p>Example from timeline: <code>{"source":"192.168.100.203","target":"8.8.8.8","type":"TCP SYN"}</code></p>
            <p>Wireshark filter: <code>ip.src == 192.168.100.203 and ip.dst == 8.8.8.8 and tcp.flags.syn == 1 and tcp.flags.ack == 0</code></p>

            <h4>📊 Using Sankey Flow Data</h4>
            <p>The <code>sankeyData</code> shows aggregated flows between network segments:</p>
            <ul>
                <li><strong>Internal → Gateway:</strong> <code>ip.src == 192.168.0.0/16 and ip.dst == 192.168.1.1</code></li>
                <li><strong>Gateway → Internet:</strong> <code>ip.src == 192.168.1.1 and not ip.dst == 192.168.0.0/16</code></li>
                <li><strong>All Internal Traffic:</strong> <code>ip.src == 192.168.0.0/16 and ip.dst == 192.168.0.0/16</code></li>
            </ul>
        </div>
    </div>
</div>
`
}
