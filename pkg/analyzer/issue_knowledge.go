package analyzer

// IssueType defines a known issue pattern with remediation guidance
type IssueType struct {
	Code            string           // "TLS_HANDSHAKE_STALL"
	Icon            string           // "💥"
	Severity        string           // "Critical", "Warning", "Info"
	Title           string           // "TLS handshake stalled >30 seconds"
	Description     string           // Technical explanation
	RootCauses      []string         // Most likely causes
	Impact          string           // User experience impact
	WiresharkChecks []WiresharkCheck // What to look for in Wireshark
	Remediation     RemediationPlan
}

// WiresharkCheck defines a specific Wireshark analysis step
type WiresharkCheck struct {
	Order      int
	Title      string
	Filter     string
	WhatToLook string
	GoodSign   string
	BadSign    string
}

// RemediationPlan provides actionable fix steps
type RemediationPlan struct {
	Immediate  string   // 5-minute fix
	ShortTerm  string   // Today
	LongTerm   string   // This week
	Commands   []string // Specific CLI commands
	References []string // Documentation links
}

// IssueKnowledgeBase contains all known issue patterns
var IssueKnowledgeBase = map[string]IssueType{
	"TLS_HANDSHAKE_STALL": {
		Code:        "TLS_HANDSHAKE_STALL",
		Icon:        "💥",
		Severity:    "Critical",
		Title:       "TLS handshake stalled >30 seconds",
		Description: "Client sent ClientHello but ServerHello was significantly delayed, indicating network path issues or server problems.",
		RootCauses: []string{
			"SD-WAN tunnel congestion or packet loss",
			"Asymmetric routing causing TCP issues",
			"Firewall/IPS deep packet inspection delay",
			"Remote server overload or unresponsive",
			"MTU/fragmentation issues on WAN path",
		},
		Impact: "Application timeout, user sees 'Connecting...' spinner or connection failure. Critical for real-time applications.",
		WiresharkChecks: []WiresharkCheck{
			{Order: 1, Title: "Verify TCP Handshake", Filter: "tcp.flags.syn==1", WhatToLook: "SYN→SYN-ACK→ACK timing", GoodSign: "Complete in <500ms", BadSign: "SYN retransmissions or >1s delay"},
			{Order: 2, Title: "Measure TLS Latency", Filter: "tls.handshake.type==1 || tls.handshake.type==2", WhatToLook: "ClientHello to ServerHello time", GoodSign: "<1 second", BadSign: ">5 seconds (your issue)"},
			{Order: 3, Title: "Check Path Issues", Filter: "icmp || tcp.flags.reset==1", WhatToLook: "ICMP errors or unexpected RSTs", GoodSign: "None present", BadSign: "ICMP unreachable or RST from middlebox"},
			{Order: 4, Title: "Analyze Retransmissions", Filter: "tcp.analysis.retransmission", WhatToLook: "Packet loss indicators", GoodSign: "None or minimal", BadSign: "Multiple retransmissions during handshake"},
		},
		Remediation: RemediationPlan{
			Immediate: "Check SD-WAN tunnel health to destination subnet. Verify tunnel is UP and latency is acceptable.",
			ShortTerm: "Review QoS policy - ensure HTTPS traffic to this destination has appropriate priority (DSCP 46/EF or 34/AF41).",
			LongTerm:  "Consider local internet breakout for cloud services (M365, AWS, etc.) to bypass SD-WAN latency.",
			Commands: []string{
				"show sdwan tunnel statistics",
				"show sdwan app-route statistics",
				"ping <dest_ip> source <local_ip>",
			},
		},
	},

	"TLS_HANDSHAKE_INCOMPLETE": {
		Code:        "TLS_HANDSHAKE_INCOMPLETE",
		Icon:        "⚠️",
		Severity:    "Warning",
		Title:       "TLS handshake did not complete",
		Description: "TLS negotiation started but never finished. Connection may have been interrupted or rejected.",
		RootCauses: []string{
			"Certificate validation failure",
			"Cipher suite mismatch",
			"Firewall blocking TLS inspection",
			"Client/server TLS version incompatibility",
		},
		Impact: "Connection fails silently, application shows generic error or timeout.",
		WiresharkChecks: []WiresharkCheck{
			{Order: 1, Title: "Check for TLS Alerts", Filter: "tls.alert", WhatToLook: "Alert messages from client or server", GoodSign: "No alerts", BadSign: "handshake_failure, certificate_unknown"},
			{Order: 2, Title: "Verify Cipher Negotiation", Filter: "tls.handshake.ciphersuite", WhatToLook: "Agreed cipher suite", GoodSign: "Modern cipher selected", BadSign: "No cipher agreement"},
			{Order: 3, Title: "Check Certificate Chain", Filter: "tls.handshake.certificate", WhatToLook: "Certificate exchange", GoodSign: "Valid cert chain", BadSign: "Missing or expired cert"},
		},
		Remediation: RemediationPlan{
			Immediate: "Check if destination is reachable via direct path (bypass SD-WAN if possible for testing).",
			ShortTerm: "Verify TLS inspection policy isn't blocking legitimate traffic. Check certificate trust store.",
			LongTerm:  "Update TLS policies to support modern cipher suites. Consider certificate pinning issues.",
			Commands: []string{
				"openssl s_client -connect <host>:443 -servername <host>",
				"curl -v https://<host>",
			},
		},
	},

	"TCP_RETRANSMISSION_BURST": {
		Code:        "TCP_RETRANSMISSION_BURST",
		Icon:        "🔄",
		Severity:    "Warning",
		Title:       "Burst of TCP retransmissions detected",
		Description: "Multiple packets required retransmission, indicating packet loss on the network path.",
		RootCauses: []string{
			"SD-WAN tunnel packet loss",
			"ISP link congestion",
			"Interface errors (CRC, collisions)",
			"QoS policy dropping packets",
			"Buffer overflow on network device",
		},
		Impact: "Degraded throughput, increased latency, possible application timeouts.",
		WiresharkChecks: []WiresharkCheck{
			{Order: 1, Title: "Count Retransmissions", Filter: "tcp.analysis.retransmission", WhatToLook: "Total retransmission count", GoodSign: "<1% of total packets", BadSign: ">5% indicates serious loss"},
			{Order: 2, Title: "Identify Loss Pattern", Filter: "tcp.analysis.lost_segment", WhatToLook: "Where packets are being lost", GoodSign: "Random distribution", BadSign: "Concentrated bursts"},
			{Order: 3, Title: "Check for Duplicates", Filter: "tcp.analysis.duplicate_ack", WhatToLook: "Duplicate ACK patterns", GoodSign: "Occasional", BadSign: "Triple+ duplicates (fast retransmit trigger)"},
		},
		Remediation: RemediationPlan{
			Immediate: "Check interface error counters on SD-WAN edge devices. Look for input/output errors.",
			ShortTerm: "Review SD-WAN tunnel health metrics. Check for path flapping or high jitter.",
			LongTerm:  "Consider FEC (Forward Error Correction) if available. Upgrade WAN bandwidth if consistently congested.",
			Commands: []string{
				"show interface counters errors",
				"show sdwan tunnel statistics | include loss",
				"show sdwan app-route statistics",
			},
		},
	},

	"TCP_RESET_UNEXPECTED": {
		Code:        "TCP_RESET_UNEXPECTED",
		Icon:        "💥",
		Severity:    "Critical",
		Title:       "Unexpected TCP RST received",
		Description: "Connection was forcibly terminated by RST packet, often from a middlebox or firewall.",
		RootCauses: []string{
			"Firewall policy blocking connection",
			"IPS/IDS detecting suspicious traffic",
			"NAT session timeout",
			"Server application crash",
			"Load balancer health check failure",
		},
		Impact: "Connection immediately terminated. User sees 'Connection reset' or application error.",
		WiresharkChecks: []WiresharkCheck{
			{Order: 1, Title: "Identify RST Source", Filter: "tcp.flags.reset==1", WhatToLook: "IP sending the RST", GoodSign: "RST from expected server", BadSign: "RST from unknown IP (middlebox)"},
			{Order: 2, Title: "Check RST Timing", Filter: "tcp.flags.reset==1", WhatToLook: "When RST was sent", GoodSign: "After normal FIN exchange", BadSign: "During active data transfer"},
			{Order: 3, Title: "Look for ICMP", Filter: "icmp.type==3", WhatToLook: "ICMP Destination Unreachable", GoodSign: "None", BadSign: "Admin prohibited or port unreachable"},
		},
		Remediation: RemediationPlan{
			Immediate: "Identify the device sending RST (check TTL to estimate hop count). Check firewall logs.",
			ShortTerm: "Review firewall/IPS policies for the affected flow. Check NAT session timeouts.",
			LongTerm:  "Implement proper connection tracking. Consider increasing NAT/firewall session timeouts.",
			Commands: []string{
				"show access-lists | include deny",
				"show conn detail | include <ip>",
				"show xlate | include <ip>",
			},
		},
	},

	"LARGE_TIME_GAP": {
		Code:        "LARGE_TIME_GAP",
		Icon:        "⏱️",
		Severity:    "Warning",
		Title:       "Large time gap in conversation",
		Description: "Significant pause (>5 seconds) in packet flow, indicating stall or delay.",
		RootCauses: []string{
			"Application processing delay",
			"Server-side database query",
			"Network path failover",
			"SD-WAN tunnel reconvergence",
			"TCP zero-window (receiver overwhelmed)",
		},
		Impact: "User experiences 'hanging' or slow response. May trigger application timeouts.",
		WiresharkChecks: []WiresharkCheck{
			{Order: 1, Title: "Identify Gap Location", Filter: "frame.time_delta > 5", WhatToLook: "Which packet follows the gap", GoodSign: "Gap after request (server thinking)", BadSign: "Gap mid-transfer (network issue)"},
			{Order: 2, Title: "Check Window Size", Filter: "tcp.window_size == 0", WhatToLook: "Zero window advertisements", GoodSign: "None", BadSign: "Zero window = receiver stall"},
			{Order: 3, Title: "Look for Keepalives", Filter: "tcp.analysis.keep_alive", WhatToLook: "TCP keepalive during gap", GoodSign: "Keepalives maintaining session", BadSign: "No keepalives (session may timeout)"},
		},
		Remediation: RemediationPlan{
			Immediate: "Determine if gap is network or application. Check if server is responding to other clients.",
			ShortTerm: "Review application logs for the gap timeframe. Check for slow database queries.",
			LongTerm:  "Implement application-level health monitoring. Consider async processing for long operations.",
			Commands: []string{
				"show sdwan tunnel statistics",
				"ping <dest> source <src> repeat 100",
			},
		},
	},

	"WEAK_TLS_VERSION": {
		Code:        "WEAK_TLS_VERSION",
		Icon:        "⚠️",
		Severity:    "Warning",
		Title:       "Outdated TLS version in use",
		Description: "Connection using TLS 1.0 or 1.1, which are deprecated and have known vulnerabilities.",
		RootCauses: []string{
			"Legacy application not updated",
			"Old server configuration",
			"Compatibility mode enabled",
			"Client forcing old TLS version",
		},
		Impact: "Security vulnerability. May fail compliance audits (PCI-DSS, HIPAA).",
		WiresharkChecks: []WiresharkCheck{
			{Order: 1, Title: "Identify TLS Version", Filter: "tls.record.version", WhatToLook: "Negotiated TLS version", GoodSign: "TLS 1.2 or 1.3", BadSign: "TLS 1.0 (0x0301) or 1.1 (0x0302)"},
			{Order: 2, Title: "Check Cipher Suite", Filter: "tls.handshake.ciphersuite", WhatToLook: "Selected cipher", GoodSign: "AES-GCM, ChaCha20", BadSign: "RC4, DES, 3DES, MD5"},
		},
		Remediation: RemediationPlan{
			Immediate: "Document affected systems for security team. No immediate action if working.",
			ShortTerm: "Plan upgrade path for legacy systems. Test TLS 1.2 compatibility.",
			LongTerm:  "Enforce TLS 1.2 minimum across all systems. Update server configurations.",
			Commands: []string{
				"openssl s_client -connect <host>:443 -tls1_2",
				"nmap --script ssl-enum-ciphers -p 443 <host>",
			},
		},
	},

	"SMB_SLOW_TRANSFER": {
		Code:        "SMB_SLOW_TRANSFER",
		Icon:        "📁",
		Severity:    "Warning",
		Title:       "SMB file transfer slower than expected",
		Description: "File transfer throughput is significantly below expected WAN capacity.",
		RootCauses: []string{
			"SMB signing overhead",
			"Small read/write buffer sizes",
			"High latency WAN path",
			"SMB1 protocol in use",
			"Antivirus scanning on file server",
		},
		Impact: "Slow file access, long wait times for users accessing network shares.",
		WiresharkChecks: []WiresharkCheck{
			{Order: 1, Title: "Check SMB Version", Filter: "smb2 || smb", WhatToLook: "SMB dialect negotiated", GoodSign: "SMB 3.x", BadSign: "SMB 1.x (very slow)"},
			{Order: 2, Title: "Analyze Buffer Sizes", Filter: "smb2.max_read_size || smb2.max_write_size", WhatToLook: "Negotiated buffer sizes", GoodSign: ">1MB", BadSign: "64KB default (not optimized)"},
			{Order: 3, Title: "Count Round Trips", Filter: "smb2.cmd", WhatToLook: "Requests per file operation", GoodSign: "Minimal round trips", BadSign: "Excessive small requests"},
		},
		Remediation: RemediationPlan{
			Immediate: "Check if SMB multichannel is enabled. Verify SMB version being used.",
			ShortTerm: "Increase SMB buffer sizes on client and server. Enable SMB compression if available.",
			LongTerm:  "Consider WAN optimization or file sync solutions for remote offices.",
			Commands: []string{
				"Get-SmbServerConfiguration | Select EnableMultiChannel,MaxChannelPerSession",
				"Get-SmbConnection | Select ServerName,Dialect,NumOpens",
				"Set-SmbClientConfiguration -MaxCachedOpenFileCount 20",
			},
		},
	},

	"SMB_SIGNING_OVERHEAD": {
		Code:        "SMB_SIGNING_OVERHEAD",
		Icon:        "📁",
		Severity:    "Info",
		Title:       "SMB signing causing performance overhead",
		Description: "SMB message signing is enabled, adding CPU overhead and extra bytes per packet.",
		RootCauses: []string{
			"Domain policy requiring SMB signing",
			"Security compliance requirement",
			"Default Windows Server configuration",
		},
		Impact: "10-15% throughput reduction. More noticeable on high-latency WAN links.",
		WiresharkChecks: []WiresharkCheck{
			{Order: 1, Title: "Verify Signing Status", Filter: "smb2.flags.signed==1", WhatToLook: "Signed packets", GoodSign: "Expected if policy requires", BadSign: "Unexpected if causing issues"},
		},
		Remediation: RemediationPlan{
			Immediate: "Document current signing policy. No immediate action needed.",
			ShortTerm: "Evaluate if signing is required for this traffic. Consider exceptions for specific shares.",
			LongTerm:  "Balance security vs performance. Consider SMB encryption instead (provides integrity).",
			Commands: []string{
				"Get-SmbServerConfiguration | Select RequireSecuritySignature,EnableSecuritySignature",
			},
		},
	},

	"DNS_SLOW_RESPONSE": {
		Code:        "DNS_SLOW_RESPONSE",
		Icon:        "🔍",
		Severity:    "Warning",
		Title:       "DNS response time exceeds threshold",
		Description: "DNS query took longer than 1 second to resolve, impacting application startup.",
		RootCauses: []string{
			"DNS server overloaded",
			"Recursive query to slow upstream",
			"Network latency to DNS server",
			"DNS server not local to site",
		},
		Impact: "Slow application startup, web page loading delays, service discovery issues.",
		WiresharkChecks: []WiresharkCheck{
			{Order: 1, Title: "Measure DNS Latency", Filter: "dns", WhatToLook: "Query to response time", GoodSign: "<100ms", BadSign: ">1 second"},
			{Order: 2, Title: "Check for Retries", Filter: "dns.flags.response==0", WhatToLook: "Multiple queries for same name", GoodSign: "Single query", BadSign: "Multiple retries"},
		},
		Remediation: RemediationPlan{
			Immediate: "Verify DNS server is reachable and responding. Test with nslookup/dig.",
			ShortTerm: "Consider local DNS caching or forwarder at each site.",
			LongTerm:  "Deploy local DNS servers at remote sites. Implement DNS-based load balancing.",
			Commands: []string{
				"nslookup <domain> <dns_server>",
				"dig @<dns_server> <domain> +stats",
			},
		},
	},

	"DNS_NXDOMAIN": {
		Code:        "DNS_NXDOMAIN",
		Icon:        "🔍",
		Severity:    "Info",
		Title:       "DNS query returned NXDOMAIN",
		Description: "Requested domain does not exist. May indicate misconfiguration or typo.",
		RootCauses: []string{
			"Typo in hostname",
			"Domain not yet propagated",
			"Internal DNS zone missing record",
			"Split-brain DNS misconfiguration",
		},
		Impact: "Application cannot resolve hostname, connection fails before starting.",
		WiresharkChecks: []WiresharkCheck{
			{Order: 1, Title: "Identify Failed Domain", Filter: "dns.flags.rcode==3", WhatToLook: "Which domain failed", GoodSign: "Expected failure (typo)", BadSign: "Valid domain failing"},
		},
		Remediation: RemediationPlan{
			Immediate: "Verify the domain name is correct. Check for typos.",
			ShortTerm: "Check internal DNS zones if internal hostname. Verify DNS forwarding.",
			LongTerm:  "Implement DNS monitoring for critical domains.",
			Commands: []string{
				"nslookup <domain>",
				"dig <domain> +trace",
			},
		},
	},

	"HTTP_SLOW_RESPONSE": {
		Code:        "HTTP_SLOW_RESPONSE",
		Icon:        "🌐",
		Severity:    "Warning",
		Title:       "HTTP response time exceeds threshold",
		Description: "Web server took longer than expected to respond to request.",
		RootCauses: []string{
			"Server-side processing delay",
			"Database query performance",
			"Backend service timeout",
			"Network latency",
		},
		Impact: "Slow page loads, poor user experience, potential timeouts.",
		WiresharkChecks: []WiresharkCheck{
			{Order: 1, Title: "Measure TTFB", Filter: "http.request || http.response", WhatToLook: "Time to First Byte", GoodSign: "<500ms", BadSign: ">2 seconds"},
			{Order: 2, Title: "Check Response Code", Filter: "http.response.code", WhatToLook: "HTTP status", GoodSign: "200 OK", BadSign: "5xx errors"},
		},
		Remediation: RemediationPlan{
			Immediate: "Check if server is under load. Verify backend services are healthy.",
			ShortTerm: "Review application logs for slow queries. Enable server-side caching.",
			LongTerm:  "Implement CDN for static content. Optimize database queries.",
			Commands: []string{
				"curl -w '%{time_total}' -o /dev/null -s https://<host>",
			},
		},
	},

	"HTTP_UNENCRYPTED": {
		Code:        "HTTP_UNENCRYPTED",
		Icon:        "⚠️",
		Severity:    "Warning",
		Title:       "Unencrypted HTTP traffic detected",
		Description: "Sensitive traffic sent over plain HTTP instead of HTTPS.",
		RootCauses: []string{
			"Legacy application",
			"Misconfigured redirect",
			"Internal traffic assumption",
		},
		Impact: "Data exposed to interception. Compliance violation risk.",
		WiresharkChecks: []WiresharkCheck{
			{Order: 1, Title: "Identify HTTP Traffic", Filter: "http && !ssl", WhatToLook: "Unencrypted requests", GoodSign: "Only non-sensitive data", BadSign: "Credentials or PII visible"},
		},
		Remediation: RemediationPlan{
			Immediate: "Document affected applications. Assess data sensitivity.",
			ShortTerm: "Enable HTTPS redirect. Obtain SSL certificates.",
			LongTerm:  "Enforce HTTPS-only policy. Implement HSTS.",
			Commands: []string{
				"curl -I http://<host>",
			},
		},
	},

	"VOIP_JITTER_HIGH": {
		Code:        "VOIP_JITTER_HIGH",
		Icon:        "📞",
		Severity:    "Critical",
		Title:       "High jitter detected in VoIP stream",
		Description: "Packet inter-arrival time variance exceeds acceptable threshold for voice quality.",
		RootCauses: []string{
			"Network congestion",
			"QoS not applied",
			"SD-WAN path instability",
			"Insufficient bandwidth",
		},
		Impact: "Choppy audio, dropped words, poor call quality.",
		WiresharkChecks: []WiresharkCheck{
			{Order: 1, Title: "Analyze RTP Stream", Filter: "rtp", WhatToLook: "Jitter and packet loss", GoodSign: "Jitter <30ms, loss <1%", BadSign: "Jitter >50ms or loss >3%"},
			{Order: 2, Title: "Check DSCP Marking", Filter: "ip.dsfield.dscp", WhatToLook: "QoS marking on packets", GoodSign: "DSCP 46 (EF)", BadSign: "DSCP 0 (best effort)"},
		},
		Remediation: RemediationPlan{
			Immediate: "Verify QoS policy is applied to VoIP traffic. Check for bandwidth saturation.",
			ShortTerm: "Prioritize voice traffic with DSCP EF. Implement traffic shaping.",
			LongTerm:  "Deploy dedicated voice VLAN. Consider SD-WAN voice optimization.",
			Commands: []string{
				"show policy-map interface",
				"show class-map",
			},
		},
	},

	"VOIP_PACKET_LOSS": {
		Code:        "VOIP_PACKET_LOSS",
		Icon:        "📞",
		Severity:    "Critical",
		Title:       "Packet loss in VoIP stream",
		Description: "RTP packets being dropped, causing audio gaps.",
		RootCauses: []string{
			"Network congestion",
			"Interface errors",
			"QoS queue overflow",
			"WAN link saturation",
		},
		Impact: "Missing audio, one-way audio, call drops.",
		WiresharkChecks: []WiresharkCheck{
			{Order: 1, Title: "Check RTP Sequence", Filter: "rtp", WhatToLook: "Sequence number gaps", GoodSign: "Continuous sequence", BadSign: "Gaps in sequence numbers"},
		},
		Remediation: RemediationPlan{
			Immediate: "Check interface error counters. Verify WAN bandwidth utilization.",
			ShortTerm: "Implement strict priority queuing for voice. Increase queue depth.",
			LongTerm:  "Upgrade WAN bandwidth. Deploy voice-aware SD-WAN.",
			Commands: []string{
				"show interface | include errors",
				"show policy-map interface | include Voice",
			},
		},
	},

	"SSH_SLOW_AUTH": {
		Code:        "SSH_SLOW_AUTH",
		Icon:        "🔑",
		Severity:    "Warning",
		Title:       "SSH authentication delay",
		Description: "SSH login taking longer than expected, often due to DNS or key exchange issues.",
		RootCauses: []string{
			"Reverse DNS lookup timeout",
			"GSSAPI authentication attempt",
			"Slow key exchange",
			"PAM module delay",
		},
		Impact: "Slow SSH login experience, automation scripts timing out.",
		WiresharkChecks: []WiresharkCheck{
			{Order: 1, Title: "Check Key Exchange", Filter: "ssh.message_code", WhatToLook: "Key exchange timing", GoodSign: "<2 seconds", BadSign: ">10 seconds"},
		},
		Remediation: RemediationPlan{
			Immediate: "Test with 'ssh -v' to identify slow phase.",
			ShortTerm: "Disable GSSAPI if not needed. Add 'UseDNS no' to sshd_config.",
			LongTerm:  "Optimize SSH configuration. Consider SSH certificates.",
			Commands: []string{
				"ssh -v <host>",
				"grep -E 'UseDNS|GSSAPIAuthentication' /etc/ssh/sshd_config",
			},
		},
	},

	"SNMP_TIMEOUT": {
		Code:        "SNMP_TIMEOUT",
		Icon:        "📊",
		Severity:    "Warning",
		Title:       "SNMP request timeout",
		Description: "SNMP query did not receive response, monitoring data missing.",
		RootCauses: []string{
			"SNMP not enabled on device",
			"Community string mismatch",
			"ACL blocking SNMP",
			"Device overloaded",
		},
		Impact: "Monitoring gaps, alerting failures, capacity planning blind spots.",
		WiresharkChecks: []WiresharkCheck{
			{Order: 1, Title: "Check SNMP Flow", Filter: "snmp", WhatToLook: "Request without response", GoodSign: "GetRequest followed by GetResponse", BadSign: "GetRequest with no response"},
		},
		Remediation: RemediationPlan{
			Immediate: "Verify SNMP is enabled on target device. Check community string.",
			ShortTerm: "Review ACLs allowing SNMP from monitoring server.",
			LongTerm:  "Migrate to SNMPv3 for security. Implement SNMP monitoring redundancy.",
			Commands: []string{
				"snmpwalk -v2c -c <community> <host> system",
				"show snmp",
			},
		},
	},

	"ASYMMETRIC_ROUTING": {
		Code:        "ASYMMETRIC_ROUTING",
		Icon:        "⚠️",
		Severity:    "Warning",
		Title:       "Possible asymmetric routing detected",
		Description: "Traffic flow appears to be taking different paths in each direction.",
		RootCauses: []string{
			"Multiple default routes",
			"SD-WAN path selection",
			"Load balancer configuration",
			"IGP/BGP route asymmetry",
		},
		Impact: "Stateful firewall issues, TCP performance problems, intermittent connectivity.",
		WiresharkChecks: []WiresharkCheck{
			{Order: 1, Title: "Check TTL Values", Filter: "ip.ttl", WhatToLook: "TTL differences between directions", GoodSign: "Consistent TTL pattern", BadSign: "Significantly different TTLs"},
			{Order: 2, Title: "Look for One-Way Traffic", Filter: "tcp", WhatToLook: "Missing ACKs or responses", GoodSign: "Bidirectional flow", BadSign: "Requests without responses"},
		},
		Remediation: RemediationPlan{
			Immediate: "Verify routing tables on both endpoints. Check for multiple paths.",
			ShortTerm: "Implement policy routing to ensure symmetric paths.",
			LongTerm:  "Review SD-WAN policy for path selection. Consider stateful failover.",
			Commands: []string{
				"show ip route <dest>",
				"traceroute <dest>",
				"show sdwan policy from-vsmart",
			},
		},
	},

	"MTU_FRAGMENTATION": {
		Code:        "MTU_FRAGMENTATION",
		Icon:        "📦",
		Severity:    "Warning",
		Title:       "IP fragmentation detected",
		Description: "Packets being fragmented due to MTU mismatch, reducing efficiency.",
		RootCauses: []string{
			"Tunnel overhead reducing effective MTU",
			"Mismatched interface MTU",
			"PMTUD blocked by firewall",
			"VPN/GRE encapsulation",
		},
		Impact: "Reduced throughput, increased latency, potential packet loss if fragments lost.",
		WiresharkChecks: []WiresharkCheck{
			{Order: 1, Title: "Find Fragmented Packets", Filter: "ip.flags.mf==1 || ip.frag_offset>0", WhatToLook: "Fragmentation occurring", GoodSign: "No fragmentation", BadSign: "Frequent fragmentation"},
			{Order: 2, Title: "Check ICMP Needs Frag", Filter: "icmp.type==3 && icmp.code==4", WhatToLook: "PMTUD messages", GoodSign: "PMTUD working", BadSign: "No PMTUD (blocked)"},
		},
		Remediation: RemediationPlan{
			Immediate: "Identify where fragmentation is occurring. Check tunnel MTU settings.",
			ShortTerm: "Adjust MTU on tunnel interfaces. Enable TCP MSS clamping.",
			LongTerm:  "Standardize MTU across network. Ensure PMTUD is not blocked.",
			Commands: []string{
				"ping -M do -s 1472 <dest>",
				"show interface | include MTU",
				"ip tcp adjust-mss 1360",
			},
		},
	},

	"ZERO_WINDOW": {
		Code:        "ZERO_WINDOW",
		Icon:        "⏸️",
		Severity:    "Warning",
		Title:       "TCP zero window condition",
		Description: "Receiver advertised zero window, pausing data transmission.",
		RootCauses: []string{
			"Application not reading data fast enough",
			"Server CPU overload",
			"Disk I/O bottleneck",
			"Memory pressure",
		},
		Impact: "Data transfer stalls, throughput drops to zero temporarily.",
		WiresharkChecks: []WiresharkCheck{
			{Order: 1, Title: "Find Zero Windows", Filter: "tcp.window_size==0", WhatToLook: "Zero window advertisements", GoodSign: "None or brief", BadSign: "Prolonged zero window"},
			{Order: 2, Title: "Check Window Updates", Filter: "tcp.analysis.window_update", WhatToLook: "Recovery from zero window", GoodSign: "Quick recovery", BadSign: "Slow or no recovery"},
		},
		Remediation: RemediationPlan{
			Immediate: "Check server CPU and memory utilization. Verify application health.",
			ShortTerm: "Increase TCP buffer sizes. Optimize application processing.",
			LongTerm:  "Scale application horizontally. Implement flow control at application layer.",
			Commands: []string{
				"sysctl net.ipv4.tcp_rmem",
				"sysctl net.ipv4.tcp_wmem",
			},
		},
	},
}

// GetIssueByCode retrieves an issue type by its code
func GetIssueByCode(code string) (IssueType, bool) {
	issue, ok := IssueKnowledgeBase[code]
	return issue, ok
}

// GetIssuesBySeverity returns all issues of a given severity
func GetIssuesBySeverity(severity string) []IssueType {
	var result []IssueType
	for _, issue := range IssueKnowledgeBase {
		if issue.Severity == severity {
			result = append(result, issue)
		}
	}
	return result
}

// MatchIssueToStream analyzes a stream and returns the most relevant issue
func MatchIssueToStream(hasRetransmissions bool, hasReset bool, hasLargeGap bool, gapSeconds float64,
	tlsVersion string, application string, isComplete bool) string {

	// Priority-based matching
	if hasReset {
		return "TCP_RESET_UNEXPECTED"
	}

	if hasLargeGap && gapSeconds > 30 && (application == "TLS" || application == "HTTPS") {
		return "TLS_HANDSHAKE_STALL"
	}

	if (application == "TLS" || application == "HTTPS") && !isComplete {
		return "TLS_HANDSHAKE_INCOMPLETE"
	}

	if tlsVersion == "TLS 1.0" || tlsVersion == "TLS 1.1" || tlsVersion == "SSLv3" {
		return "WEAK_TLS_VERSION"
	}

	if hasRetransmissions {
		return "TCP_RETRANSMISSION_BURST"
	}

	if hasLargeGap {
		return "LARGE_TIME_GAP"
	}

	if application == "SMB" {
		return "SMB_SLOW_TRANSFER"
	}

	if application == "HTTP" {
		return "HTTP_UNENCRYPTED"
	}

	return ""
}
