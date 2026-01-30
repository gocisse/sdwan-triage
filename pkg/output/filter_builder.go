package output

import (
	"fmt"
	"html/template"
	"strings"
	"time"

	"github.com/gocisse/sdwan-triage/pkg/analyzer"
	"github.com/gocisse/sdwan-triage/pkg/models"
)

// SmartFilter contains context-aware Wireshark filters
type SmartFilter struct {
	Name        string
	Filter      string
	Description string
	Category    string // "Basic", "Optimized", "Related", "TimeWindow", "Problem"
}

// FilterSet is a complete set of smart filters for a stream
type FilterSet struct {
	Basic       SmartFilter
	Optimized   SmartFilter
	Related     SmartFilter
	TimeWindow  SmartFilter
	Exclusions  SmartFilter
	ProblemOnly SmartFilter
	OneClick    string // The recommended filter for quick copy
	AllFilters  []SmartFilter
}

// FilterBuilder creates smart context-aware filters
type FilterBuilder struct{}

// NewFilterBuilder creates a new filter builder
func NewFilterBuilder() *FilterBuilder {
	return &FilterBuilder{}
}

// BuildSmartFilters creates a complete filter set for a stream
func (fb *FilterBuilder) BuildSmartFilters(stream *models.StreamData, classification *analyzer.TrafficClassification, issue *analyzer.IssueType) *FilterSet {
	fs := &FilterSet{}

	// Basic filter
	fs.Basic = SmartFilter{
		Name:        "This Stream",
		Filter:      fb.buildBasicFilter(stream),
		Description: "Show only packets in this conversation",
		Category:    "Basic",
	}

	// Optimized filter (exclude empty packets)
	fs.Optimized = SmartFilter{
		Name:        "Exclude Empty",
		Filter:      fb.buildOptimizedFilter(stream),
		Description: "Hide ACK-only and keepalive packets",
		Category:    "Optimized",
	}

	// Related filter (broader context)
	fs.Related = SmartFilter{
		Name:        "Related Traffic",
		Filter:      fb.buildRelatedFilter(stream, classification),
		Description: "All traffic to this service/destination",
		Category:    "Related",
	}

	// Time window filter
	fs.TimeWindow = SmartFilter{
		Name:        "Incident Window",
		Filter:      fb.buildTimeWindowFilter(stream),
		Description: "Filter to incident time only",
		Category:    "TimeWindow",
	}

	// Exclusions filter (focus on problems)
	fs.Exclusions = SmartFilter{
		Name:        "Problem Packets",
		Filter:      fb.buildExclusionsFilter(stream),
		Description: "Show only packets with issues",
		Category:    "Problem",
	}

	// Problem-specific filter
	if issue != nil {
		fs.ProblemOnly = SmartFilter{
			Name:        "Issue Focus",
			Filter:      fb.buildIssueFilter(stream, issue),
			Description: fmt.Sprintf("Focus on %s", issue.Title),
			Category:    "Problem",
		}
	}

	// One-click is the basic filter by default
	fs.OneClick = fs.Basic.Filter

	// Compile all filters
	fs.AllFilters = []SmartFilter{
		fs.Basic,
		fs.Optimized,
		fs.Related,
		fs.TimeWindow,
		fs.Exclusions,
	}
	if issue != nil {
		fs.AllFilters = append(fs.AllFilters, fs.ProblemOnly)
	}

	return fs
}

// buildBasicFilter creates the simple stream filter
func (fb *FilterBuilder) buildBasicFilter(stream *models.StreamData) string {
	if stream.Protocol == "TCP" {
		return fmt.Sprintf("ip.addr == %s && ip.addr == %s && tcp.port == %d && tcp.port == %d",
			stream.SrcIP, stream.DstIP, stream.SrcPort, stream.DstPort)
	}
	return fmt.Sprintf("ip.addr == %s && ip.addr == %s && udp.port == %d && udp.port == %d",
		stream.SrcIP, stream.DstIP, stream.SrcPort, stream.DstPort)
}

// buildOptimizedFilter excludes empty/keepalive packets
func (fb *FilterBuilder) buildOptimizedFilter(stream *models.StreamData) string {
	base := fb.buildBasicFilter(stream)
	if stream.Protocol == "TCP" {
		return base + " && tcp.len > 0"
	}
	return base + " && udp.length > 8"
}

// buildRelatedFilter creates broader context filter
func (fb *FilterBuilder) buildRelatedFilter(stream *models.StreamData, classification *analyzer.TrafficClassification) string {
	if classification == nil {
		return fb.buildBasicFilter(stream)
	}

	// Use SNI for HTTPS traffic
	if classification.SNI != "" {
		return fmt.Sprintf("tls.handshake.extensions_server_name contains \"%s\"", classification.SNI)
	}

	// Use category-specific filters
	switch classification.Category {
	case "Microsoft 365":
		return fmt.Sprintf("ip.addr == %s && (tls.handshake.extensions_server_name contains \"office365\" || tls.handshake.extensions_server_name contains \"microsoft\" || tls.handshake.extensions_server_name contains \"outlook\")", stream.SrcIP)

	case "Google":
		return fmt.Sprintf("ip.addr == %s && (tls.handshake.extensions_server_name contains \"google\" || tls.handshake.extensions_server_name contains \"googleapis\")", stream.SrcIP)

	case "AWS":
		return fmt.Sprintf("ip.addr == %s && tls.handshake.extensions_server_name contains \"amazonaws\"", stream.SrcIP)

	case "File Sharing":
		return fmt.Sprintf("ip.addr == %s && tcp.port == 445", stream.SrcIP)

	case "VoIP":
		return fmt.Sprintf("ip.addr == %s && (udp.port == 5060 || rtp)", stream.SrcIP)

	default:
		// All traffic to this destination
		return fmt.Sprintf("ip.addr == %s && ip.addr == %s", stream.SrcIP, stream.DstIP)
	}
}

// buildTimeWindowFilter creates time-bounded filter
func (fb *FilterBuilder) buildTimeWindowFilter(stream *models.StreamData) string {
	base := fb.buildBasicFilter(stream)

	// Add 1 second buffer on each side
	startTime := stream.FirstSeen.Add(-time.Second)
	endTime := stream.LastSeen.Add(time.Second)

	return fmt.Sprintf("frame.time >= \"%s\" && frame.time <= \"%s\" && %s",
		startTime.Format("2006-01-02 15:04:05"),
		endTime.Format("2006-01-02 15:04:05"),
		base)
}

// buildExclusionsFilter focuses on problem packets
func (fb *FilterBuilder) buildExclusionsFilter(stream *models.StreamData) string {
	base := fb.buildBasicFilter(stream)
	return base + " && (tcp.analysis.retransmission || tcp.analysis.lost_segment || tcp.analysis.duplicate_ack || tcp.flags.reset == 1 || icmp)"
}

// buildIssueFilter creates issue-specific filter
func (fb *FilterBuilder) buildIssueFilter(stream *models.StreamData, issue *analyzer.IssueType) string {
	base := fb.buildBasicFilter(stream)

	switch issue.Code {
	case "TLS_HANDSHAKE_STALL", "TLS_HANDSHAKE_INCOMPLETE":
		return base + " && tls.handshake"

	case "TCP_RETRANSMISSION_BURST":
		return base + " && tcp.analysis.retransmission"

	case "TCP_RESET_UNEXPECTED":
		return base + " && tcp.flags.reset == 1"

	case "LARGE_TIME_GAP":
		return base + " && frame.time_delta > 1"

	case "WEAK_TLS_VERSION":
		return base + " && (tls.record.version == 0x0301 || tls.record.version == 0x0302 || tls.record.version == 0x0300)"

	case "SMB_SLOW_TRANSFER":
		return base + " && smb2"

	case "DNS_SLOW_RESPONSE", "DNS_NXDOMAIN":
		return "dns && ip.addr == " + stream.DstIP

	case "VOIP_JITTER_HIGH", "VOIP_PACKET_LOSS":
		return base + " && rtp"

	case "ZERO_WINDOW":
		return base + " && tcp.window_size == 0"

	case "MTU_FRAGMENTATION":
		return base + " && (ip.flags.mf == 1 || ip.frag_offset > 0)"

	default:
		return base
	}
}

// BuildProtocolFilters creates protocol-specific filter suggestions
func (fb *FilterBuilder) BuildProtocolFilters(stream *models.StreamData) []SmartFilter {
	base := fb.buildBasicFilter(stream)
	filters := make([]SmartFilter, 0)

	switch stream.Application {
	case "TLS", "HTTPS":
		filters = append(filters,
			SmartFilter{Name: "TLS Handshake", Filter: base + " && tls.handshake", Description: "TLS handshake messages", Category: "Protocol"},
			SmartFilter{Name: "TLS Alerts", Filter: base + " && tls.alert", Description: "TLS alert messages", Category: "Protocol"},
			SmartFilter{Name: "TLS App Data", Filter: base + " && tls.record.content_type == 23", Description: "Encrypted application data", Category: "Protocol"},
			SmartFilter{Name: "ClientHello", Filter: base + " && tls.handshake.type == 1", Description: "TLS ClientHello only", Category: "Protocol"},
			SmartFilter{Name: "ServerHello", Filter: base + " && tls.handshake.type == 2", Description: "TLS ServerHello only", Category: "Protocol"},
		)

	case "HTTP":
		filters = append(filters,
			SmartFilter{Name: "HTTP Requests", Filter: base + " && http.request", Description: "HTTP requests", Category: "Protocol"},
			SmartFilter{Name: "HTTP Responses", Filter: base + " && http.response", Description: "HTTP responses", Category: "Protocol"},
			SmartFilter{Name: "HTTP Errors", Filter: base + " && http.response.code >= 400", Description: "HTTP 4xx/5xx errors", Category: "Protocol"},
			SmartFilter{Name: "HTTP POST", Filter: base + " && http.request.method == \"POST\"", Description: "POST requests only", Category: "Protocol"},
		)

	case "SMB":
		filters = append(filters,
			SmartFilter{Name: "SMB Commands", Filter: base + " && smb2.cmd", Description: "SMB2 commands", Category: "Protocol"},
			SmartFilter{Name: "SMB Errors", Filter: base + " && smb2.nt_status != 0", Description: "SMB errors", Category: "Protocol"},
			SmartFilter{Name: "SMB Read/Write", Filter: base + " && (smb2.cmd == 8 || smb2.cmd == 9)", Description: "File read/write operations", Category: "Protocol"},
			SmartFilter{Name: "SMB Files", Filter: base + " && smb2.filename", Description: "File operations with names", Category: "Protocol"},
		)

	case "DNS":
		filters = append(filters,
			SmartFilter{Name: "DNS Queries", Filter: "dns.flags.response == 0 && ip.addr == " + stream.SrcIP, Description: "DNS queries", Category: "Protocol"},
			SmartFilter{Name: "DNS Responses", Filter: "dns.flags.response == 1 && ip.addr == " + stream.SrcIP, Description: "DNS responses", Category: "Protocol"},
			SmartFilter{Name: "DNS NXDOMAIN", Filter: "dns.flags.rcode == 3 && ip.addr == " + stream.SrcIP, Description: "Non-existent domain", Category: "Protocol"},
			SmartFilter{Name: "DNS Slow", Filter: "dns && frame.time_delta > 0.5", Description: "Slow DNS responses", Category: "Protocol"},
		)

	case "SSH":
		filters = append(filters,
			SmartFilter{Name: "SSH Only", Filter: base + " && ssh", Description: "SSH protocol messages", Category: "Protocol"},
		)

	case "SIP":
		filters = append(filters,
			SmartFilter{Name: "SIP Messages", Filter: base + " && sip", Description: "SIP signaling", Category: "Protocol"},
			SmartFilter{Name: "SIP INVITE", Filter: base + " && sip.Method == \"INVITE\"", Description: "Call setup", Category: "Protocol"},
			SmartFilter{Name: "SIP BYE", Filter: base + " && sip.Method == \"BYE\"", Description: "Call teardown", Category: "Protocol"},
		)
	}

	// Add common TCP analysis filters
	if stream.Protocol == "TCP" {
		filters = append(filters,
			SmartFilter{Name: "Retransmissions", Filter: base + " && tcp.analysis.retransmission", Description: "Retransmitted packets", Category: "TCP Analysis"},
			SmartFilter{Name: "Duplicate ACKs", Filter: base + " && tcp.analysis.duplicate_ack", Description: "Duplicate acknowledgments", Category: "TCP Analysis"},
			SmartFilter{Name: "Zero Window", Filter: base + " && tcp.window_size == 0", Description: "Zero window conditions", Category: "TCP Analysis"},
			SmartFilter{Name: "TCP RST", Filter: base + " && tcp.flags.reset == 1", Description: "Connection resets", Category: "TCP Analysis"},
			SmartFilter{Name: "TCP FIN", Filter: base + " && tcp.flags.fin == 1", Description: "Connection close", Category: "TCP Analysis"},
		)
	}

	return filters
}

// FormatFilterSetText formats filter set for CLI output
func (fs *FilterSet) FormatText() string {
	var sb strings.Builder

	sb.WriteString("📋 WIRESHARK FILTERS (copy-paste ready):\n")
	sb.WriteString("═══════════════════════════════════════════════════════════════\n\n")

	for _, f := range fs.AllFilters {
		sb.WriteString(fmt.Sprintf("%s (%s):\n", f.Name, f.Category))
		sb.WriteString(fmt.Sprintf("   %s\n", f.Filter))
		sb.WriteString(fmt.Sprintf("   → %s\n\n", f.Description))
	}

	return sb.String()
}

// FormatFilterSetHTML formats filter set for HTML output
func (fs *FilterSet) FormatHTML() template.HTML {
	var sb strings.Builder

	sb.WriteString(`<div class="filter-set">`)
	sb.WriteString(`<div class="filter-set-header">📋 Wireshark Filters</div>`)
	sb.WriteString(`<div class="filter-list">`)

	for _, f := range fs.AllFilters {
		sb.WriteString(fmt.Sprintf(`<div class="filter-item" data-category="%s">
			<div class="filter-header">
				<span class="filter-name">%s</span>
				<span class="filter-category">%s</span>
				<button class="copy-btn" onclick="copyToClipboard('%s')">📋 Copy</button>
			</div>
			<code class="filter-code" onclick="copyToClipboard('%s')">%s</code>
			<div class="filter-desc">%s</div>
		</div>`,
			f.Category, f.Name, f.Category,
			template.JSEscapeString(f.Filter),
			template.JSEscapeString(f.Filter),
			template.HTMLEscapeString(f.Filter),
			f.Description))
	}

	sb.WriteString(`</div></div>`)

	return template.HTML(sb.String())
}

// GetFilterSetCSS returns CSS for filter set display
func GetFilterSetCSS() string {
	return `
/* Filter Set - Dark Mode Compatible */
.filter-set {
    background: var(--color-surface);
    border: 1px solid var(--color-border);
    border-radius: 10px;
    padding: 16px;
    margin: 12px 0;
}

.filter-set-header {
    font-weight: bold;
    color: #60a5fa;
    margin-bottom: 12px;
    font-size: 1.05em;
}

.filter-list {
    display: flex;
    flex-direction: column;
    gap: 10px;
}

.filter-item {
    background: var(--color-card);
    padding: 12px;
    border-radius: 8px;
    border: 1px solid var(--color-border);
    border-left: 3px solid #3b82f6;
}

.filter-item[data-category="Problem"] {
    border-left-color: #ef4444;
}

.filter-item[data-category="Optimized"] {
    border-left-color: #22c55e;
}

.filter-item[data-category="Related"] {
    border-left-color: #8b5cf6;
}

.filter-header {
    display: flex;
    align-items: center;
    gap: 10px;
    margin-bottom: 8px;
}

.filter-name {
    font-weight: 600;
    color: var(--color-text-primary);
}

.filter-category {
    padding: 2px 8px;
    background: rgba(99, 102, 241, 0.2);
    border-radius: 4px;
    font-size: 0.75em;
    color: #a5b4fc;
}

.filter-code {
    display: block;
    background: var(--color-surface);
    padding: 10px;
    border-radius: 6px;
    font-family: 'Courier New', monospace;
    font-size: 0.85em;
    word-break: break-all;
    cursor: pointer;
    transition: all 0.2s;
    color: #22d3ee;
    border: 1px solid var(--color-border);
}

.filter-code:hover {
    background: rgba(59, 130, 246, 0.1);
    border-color: rgba(59, 130, 246, 0.3);
}

.filter-desc {
    margin-top: 6px;
    font-size: 0.85em;
    color: var(--color-text-muted);
}

.copy-btn {
    margin-left: auto;
    padding: 4px 10px;
    border: 1px solid var(--color-border);
    border-radius: 4px;
    background: var(--color-card);
    cursor: pointer;
    font-size: 0.8em;
    color: var(--color-text-secondary);
}

.copy-btn:hover {
    background: rgba(59, 130, 246, 0.1);
    color: #60a5fa;
}
`
}

// CommonSDWANFilters returns pre-built filters for common SD-WAN troubleshooting
func CommonSDWANFilters() []SmartFilter {
	return []SmartFilter{
		// Retransmission analysis
		{Name: "All Retransmissions", Filter: "tcp.analysis.retransmission || tcp.analysis.fast_retransmission", Description: "All TCP retransmissions in capture", Category: "TCP Issues"},
		{Name: "Lost Segments", Filter: "tcp.analysis.lost_segment", Description: "Packets indicating segment loss", Category: "TCP Issues"},
		{Name: "Duplicate ACKs", Filter: "tcp.analysis.duplicate_ack_num > 2", Description: "Triple+ duplicate ACKs (fast retransmit)", Category: "TCP Issues"},
		{Name: "Out of Order", Filter: "tcp.analysis.out_of_order", Description: "Out of order packets", Category: "TCP Issues"},
		{Name: "Zero Window", Filter: "tcp.window_size == 0", Description: "Receiver buffer full", Category: "TCP Issues"},

		// Connection issues
		{Name: "TCP Resets", Filter: "tcp.flags.reset == 1", Description: "Connection resets", Category: "Connection"},
		{Name: "Failed Connections", Filter: "tcp.flags.syn == 1 && tcp.flags.ack == 0 && tcp.analysis.retransmission", Description: "SYN retransmissions (connection failures)", Category: "Connection"},
		{Name: "ICMP Errors", Filter: "icmp.type == 3 || icmp.type == 11", Description: "ICMP unreachable or TTL exceeded", Category: "Connection"},

		// Timing analysis
		{Name: "Large Gaps", Filter: "frame.time_delta > 5", Description: "Packets after >5 second gap", Category: "Timing"},
		{Name: "Slow Responses", Filter: "frame.time_delta > 1 && frame.time_delta < 30", Description: "1-30 second delays", Category: "Timing"},

		// TLS/SSL
		{Name: "TLS Handshakes", Filter: "tls.handshake", Description: "All TLS handshake messages", Category: "TLS"},
		{Name: "TLS Alerts", Filter: "tls.alert", Description: "TLS alert messages", Category: "TLS"},
		{Name: "Weak TLS", Filter: "tls.record.version == 0x0301 || tls.record.version == 0x0302", Description: "TLS 1.0/1.1 (deprecated)", Category: "TLS"},
		{Name: "Certificate Issues", Filter: "tls.handshake.type == 11", Description: "Certificate messages", Category: "TLS"},

		// Microsoft 365
		{Name: "Microsoft 365", Filter: "tls.handshake.extensions_server_name contains \"office365\" || tls.handshake.extensions_server_name contains \"microsoft\" || tls.handshake.extensions_server_name contains \"outlook\"", Description: "M365 traffic by SNI", Category: "Cloud"},
		{Name: "Teams/Skype", Filter: "tls.handshake.extensions_server_name contains \"teams\" || tls.handshake.extensions_server_name contains \"skype\" || udp.port == 3478 || udp.port == 3479", Description: "Teams/Skype traffic", Category: "Cloud"},

		// VoIP
		{Name: "VoIP Signaling", Filter: "sip || h323 || mgcp || skinny", Description: "Voice signaling protocols", Category: "VoIP"},
		{Name: "RTP Streams", Filter: "rtp", Description: "RTP media streams", Category: "VoIP"},
		{Name: "RTCP Reports", Filter: "rtcp", Description: "RTP control protocol", Category: "VoIP"},

		// SMB/File sharing
		{Name: "SMB Traffic", Filter: "smb || smb2", Description: "All SMB traffic", Category: "File Sharing"},
		{Name: "SMB Errors", Filter: "smb2.nt_status != 0", Description: "SMB operations with errors", Category: "File Sharing"},

		// DNS
		{Name: "DNS Queries", Filter: "dns.flags.response == 0", Description: "DNS queries only", Category: "DNS"},
		{Name: "DNS Failures", Filter: "dns.flags.rcode != 0", Description: "DNS errors (NXDOMAIN, etc)", Category: "DNS"},
		{Name: "Slow DNS", Filter: "dns && frame.time_delta > 0.5", Description: "DNS taking >500ms", Category: "DNS"},

		// SD-WAN Discovery (Vendor-Agnostic)
		{Name: "SD-WAN Control All", Filter: "udp.port in {2426, 3784, 3785, 4784, 4785, 500, 4500} || tcp.port in {12346, 830, 179, 443, 541}", Description: "All SD-WAN control plane ports", Category: "SD-WAN Discovery"},
		{Name: "SD-WAN Data All", Filter: "ip.proto == 50 || ip.proto == 51 || udp.port in {2426, 4980, 4501}", Description: "All SD-WAN data plane traffic", Category: "SD-WAN Discovery"},
		{Name: "DTLS Traffic", Filter: "dtls", Description: "DTLS (common for SD-WAN tunnel setup)", Category: "SD-WAN Discovery"},
		{Name: "Certificate Exchanges", Filter: "tls.handshake.type == 11", Description: "SD-WAN authentication certificates", Category: "SD-WAN Discovery"},
		{Name: "IPsec ESP/AH", Filter: "ip.proto == 50 || ip.proto == 51", Description: "IPsec ESP/AH tunnel traffic", Category: "SD-WAN Discovery"},
		{Name: "IKE/NAT-T", Filter: "udp.port == 500 || udp.port == 4500", Description: "IKE and IPsec NAT traversal", Category: "SD-WAN Discovery"},

		// Cisco Viptela
		{Name: "Viptela vBond", Filter: "tcp.port == 12346", Description: "vBond orchestration (DTLS-wrapped)", Category: "Cisco Viptela"},
		{Name: "Viptela OMP", Filter: "tls && tcp.port == 830", Description: "OMP routing protocol (TLS over NETCONF)", Category: "Cisco Viptela"},
		{Name: "Viptela BFD", Filter: "udp.port in {3784, 3785, 4784, 4785}", Description: "BFD path monitoring", Category: "Cisco Viptela"},
		{Name: "Viptela Data Plane", Filter: "ip.proto == 50", Description: "IPsec ESP data plane (overlay)", Category: "Cisco Viptela"},

		// VMware VeloCloud (CORRECTED - UDP only)
		{Name: "VeloCloud VCMP", Filter: "udp.port == 2426", Description: "VCMP control & data tunnel (UDP)", Category: "VMware VeloCloud"},
		{Name: "VeloCloud DTLS", Filter: "dtls && udp.port == 2426", Description: "DTLS handshake for tunnel (v2)", Category: "VMware VeloCloud"},
		{Name: "VeloCloud Keepalives", Filter: "udp.port == 2426 && udp.length < 100", Description: "VCMP keepalives and path probes", Category: "VMware VeloCloud"},
		{Name: "VeloCloud DNS", Filter: "dns.qry.name contains \"velocloud.net\" || dns.qry.name contains \"velocloud.com\"", Description: "Edge activation DNS queries", Category: "VMware VeloCloud"},

		// Silver Peak / Aruba EdgeConnect
		{Name: "Silver Peak Control", Filter: "tcp.port == 443", Description: "Orchestrator communication (HTTPS)", Category: "Silver Peak"},
		{Name: "Silver Peak BGP", Filter: "tcp.port == 179", Description: "BGP for route exchange (overlay)", Category: "Silver Peak"},
		{Name: "Silver Peak Bonding", Filter: "udp.port == 4980", Description: "Tunnel bonding UDP data", Category: "Silver Peak"},
		{Name: "Silver Peak Boost", Filter: "tcp.port == 4163", Description: "Boost acceleration protocol", Category: "Silver Peak"},
		{Name: "Silver Peak Probes", Filter: "icmp && icmp.type == 8 && data.len == 64", Description: "Path conditioning probes", Category: "Silver Peak"},

		// Fortinet SD-WAN
		{Name: "FortiGate IKE/IPsec", Filter: "udp.port == 500 || udp.port == 4500", Description: "ADVPN shortcut IKE/IPsec", Category: "Fortinet"},
		{Name: "FortiGate HA Sync", Filter: "udp.port == 708", Description: "FGCP HA sync between FortiGates", Category: "Fortinet"},
		{Name: "FortiGate SLA Probes", Filter: "icmp && data.len == 32 && icmp.type == 8", Description: "SD-WAN SLA probes", Category: "Fortinet"},
		{Name: "FortiManager", Filter: "tcp.port == 541", Description: "FortiManager policy push", Category: "Fortinet"},
		{Name: "FortiGate SSL VPN", Filter: "tcp.port == 10443", Description: "SSL VPN (if used for SD-WAN)", Category: "Fortinet"},

		// Palo Alto Prisma
		{Name: "GlobalProtect Data", Filter: "udp.port == 4501", Description: "GlobalProtect data plane", Category: "Palo Alto"},
		{Name: "Prisma Management", Filter: "tls && tcp.port == 443", Description: "Prisma Cloud management (TLS)", Category: "Palo Alto"},
		{Name: "Prisma BGP", Filter: "tcp.port == 179", Description: "BGP over IPSec (SD-WAN routes)", Category: "Palo Alto"},

		// Versa Networks
		{Name: "Versa Director", Filter: "tls && tcp.port == 443", Description: "Versa Director API (HTTPS)", Category: "Versa Networks"},
		{Name: "Versa Control", Filter: "tcp.port == 12346 || tcp.port == 443", Description: "Device to Director/Controller", Category: "Versa Networks"},
		{Name: "Versa Tunnels", Filter: "ip.proto == 50 || ip.proto == 51", Description: "IPsec tunnels (ESP/AH)", Category: "Versa Networks"},
		{Name: "Versa BFD", Filter: "udp.port in {3784, 3785, 4784, 4785}", Description: "BFD sessions", Category: "Versa Networks"},

		// Path Quality / BFD / SLA
		{Name: "BFD Sessions", Filter: "udp.port in {3784, 3785, 4784, 4785}", Description: "Bidirectional Forwarding Detection", Category: "Path Quality"},
		{Name: "MTU Issues", Filter: "icmp.type == 3 && icmp.code == 4", Description: "ICMP fragmentation needed", Category: "Path Quality"},
		{Name: "High Jitter", Filter: "tcp.options.timestamp && tcp.analysis.out_of_order", Description: "High jitter indicator (TCP timestamps)", Category: "Path Quality"},

		// Troubleshooting
		{Name: "SD-WAN Performance", Filter: "tcp.analysis.retransmission || tcp.analysis.fast_retransmission || tcp.analysis.spurious_retransmission", Description: "All retransmission types", Category: "Troubleshooting"},
		{Name: "Auth Failures", Filter: "tls.alert_message.level == 2 || dtls.alert_message.level == 2", Description: "Failed authentication (TLS/DTLS)", Category: "Troubleshooting"},
		{Name: "Control Resets", Filter: "(udp.port == 2426 || tcp.port == 12346 || tcp.port == 830) && tcp.flags.reset == 1", Description: "Control plane connection resets", Category: "Troubleshooting"},
	}
}
