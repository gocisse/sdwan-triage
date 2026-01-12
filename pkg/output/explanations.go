package output

import (
	"fmt"
	"html/template"
	"strings"
)

// FindingExplanation contains educational content for a finding
type FindingExplanation struct {
	Title             string
	Definition        string
	Impact            string
	Detection         string
	WiresharkFilter   string
	RecommendedAction string
}

// Helper function to generate HTML for explanation section
func (e FindingExplanation) ToHTML() template.HTML {
	html := fmt.Sprintf(`
		<div class="finding-explanation">
			<details class="explanation-details">
				<summary class="explanation-summary"><i class="fas fa-info-circle"></i> What is %s?</summary>
				<div class="explanation-content">
					<div class="explanation-section">
						<h4><i class="fas fa-book"></i> Definition</h4>
						<p>%s</p>
					</div>
					<div class="explanation-section">
						<h4><i class="fas fa-exclamation-triangle"></i> Why is this a problem?</h4>
						<p>%s</p>
					</div>
					<div class="explanation-section">
						<h4><i class="fas fa-search"></i> How was it detected?</h4>
						<p>%s</p>
					</div>
					<div class="explanation-section">
						<h4><i class="fas fa-filter"></i> Wireshark Filter</h4>
						<p>Use this filter in Wireshark to examine the specific traffic:</p>
						<code class="wireshark-filter">%s</code>
						<button class="copy-filter-btn" onclick="copyToClipboard('%s')" title="Copy filter to clipboard">
							<i class="fas fa-copy"></i> Copy
						</button>
					</div>
					<div class="explanation-section">
						<h4><i class="fas fa-wrench"></i> Recommended Actions</h4>
						<p>%s</p>
					</div>
				</div>
			</details>
		</div>
	`, e.Title, e.Definition, e.Impact, e.Detection, e.WiresharkFilter,
		strings.ReplaceAll(e.WiresharkFilter, "'", "\\'"), e.RecommendedAction)

	return template.HTML(html)
}

// TCP Retransmission Explanation
func GenerateTCPRetransmissionExplanation(srcIP, dstIP string, count int) FindingExplanation {
	return FindingExplanation{
		Title:             "High TCP Retransmission",
		Definition:        "TCP retransmission occurs when a packet sent by one host is not acknowledged by the receiving host within a certain time frame (RTO - Retransmission Timeout). The sender then resends the packet to ensure reliable delivery.",
		Impact:            fmt.Sprintf("Excessive retransmissions (%d detected) indicate network packet loss, congestion, or high latency. This leads to degraded application performance, slower data transfer speeds, and poor user experience. Applications may appear sluggish or unresponsive.", count),
		Detection:         fmt.Sprintf("The tool identified %d retransmission events for the flow %s → %s by analyzing TCP sequence numbers and detecting duplicate packets or packets marked with retransmission flags.", count, srcIP, dstIP),
		WiresharkFilter:   fmt.Sprintf("tcp.analysis.retransmission and ip.addr == %s and ip.addr == %s", srcIP, dstIP),
		RecommendedAction: fmt.Sprintf("1. Open the PCAP file in Wireshark and apply the filter above. 2. Examine the Time column to identify when retransmissions occur. 3. Check the TCP Stream (right-click packet → Follow → TCP Stream) to see the full conversation. 4. Investigate network links, switches, routers, and QoS settings between %s and %s. 5. Check for bandwidth saturation, interface errors, or duplex mismatches. 6. Use ping and traceroute to test connectivity and latency.", srcIP, dstIP),
	}
}

// DNS Anomaly Explanation
func GenerateDNSAnomalyExplanation(query, answerIP, reason string) FindingExplanation {
	filter := fmt.Sprintf("dns and dns.qry.name == \"%s\"", query)
	if answerIP != "" {
		filter = fmt.Sprintf("dns and (dns.qry.name == \"%s\" or ip.addr == %s)", query, answerIP)
	}

	return FindingExplanation{
		Title:             "DNS Anomaly Detected",
		Definition:        fmt.Sprintf("A DNS anomaly is an unusual or suspicious pattern in DNS query/response traffic. This specific anomaly involves the query '%s' and was flagged due to: %s", query, reason),
		Impact:            "DNS anomalies can indicate malware communication (C2 servers), DNS tunneling for data exfiltration, DGA (Domain Generation Algorithm) activity, or DNS cache poisoning attempts. They may also point to misconfigured DNS servers or network issues causing resolution failures.",
		Detection:         fmt.Sprintf("The tool detected this anomaly by analyzing DNS query patterns, response codes, timing, and comparing against known suspicious indicators. Reason: %s", reason),
		WiresharkFilter:   filter,
		RecommendedAction: fmt.Sprintf("1. Apply the Wireshark filter to examine all DNS traffic for '%s'. 2. Check DNS response codes (NXDOMAIN, SERVFAIL, etc.) using filter 'dns.flags.rcode'. 3. Investigate the querying host for potential malware. 4. Review DNS server logs for additional context. 5. Check if the domain is on threat intelligence feeds. 6. Verify DNS server configuration and upstream resolvers.", query),
	}
}

// ARP Conflict Explanation
func GenerateARPConflictExplanation(ip, mac1, mac2 string) FindingExplanation {
	return FindingExplanation{
		Title:             "ARP Conflict Detected",
		Definition:        fmt.Sprintf("An ARP (Address Resolution Protocol) conflict occurs when two different devices claim the same IP address (%s). In this case, MAC addresses %s and %s are both responding to ARP requests for this IP.", ip, mac1, mac2),
		Impact:            "ARP conflicts cause intermittent network connectivity issues, packet loss, and communication failures. Devices may randomly lose network access as the ARP cache flips between the conflicting MAC addresses. This can also indicate ARP spoofing attacks or DHCP server misconfigurations.",
		Detection:         fmt.Sprintf("The tool detected multiple ARP announcements for IP %s from different MAC addresses (%s and %s), indicating a conflict.", ip, mac1, mac2),
		WiresharkFilter:   fmt.Sprintf("arp and arp.src.proto_ipv4 == %s", ip),
		RecommendedAction: fmt.Sprintf("1. Use the Wireshark filter to see all ARP traffic for IP %s. 2. Identify which MAC addresses are claiming this IP. 3. Use 'arp.opcode == 2' to see ARP replies specifically. 4. Locate the physical devices using MAC address lookup. 5. Check DHCP server for duplicate static assignments. 6. Verify no rogue DHCP servers exist. 7. Reconfigure or disconnect the conflicting device. 8. Consider implementing DHCP snooping and Dynamic ARP Inspection (DAI) on switches.", ip),
	}
}

// Failed TCP Handshake Explanation
func GenerateFailedHandshakeExplanation(srcIP, dstIP string, srcPort, dstPort uint16) FindingExplanation {
	return FindingExplanation{
		Title:             "Failed TCP Handshake",
		Definition:        fmt.Sprintf("A failed TCP handshake occurs when the three-way handshake (SYN → SYN-ACK → ACK) does not complete successfully between %s:%d and %s:%d. This prevents a TCP connection from being established.", srcIP, srcPort, dstIP, dstPort),
		Impact:            "Failed handshakes indicate that services are unreachable, firewalls are blocking traffic, servers are down, or network routing issues exist. Users experience connection timeouts and cannot access the intended service.",
		Detection:         fmt.Sprintf("The tool detected a SYN packet from %s:%d to %s:%d that was not followed by a SYN-ACK response, or the handshake was reset (RST) before completion.", srcIP, srcPort, dstIP, dstPort),
		WiresharkFilter:   fmt.Sprintf("tcp.flags.syn == 1 and ip.src == %s and ip.dst == %s and tcp.srcport == %d and tcp.dstport == %d", srcIP, dstIP, srcPort, dstPort),
		RecommendedAction: fmt.Sprintf("1. Apply the filter to see the SYN packets. 2. Check if SYN-ACK responses exist using 'tcp.flags.syn == 1 and tcp.flags.ack == 1'. 3. Look for RST (reset) packets with 'tcp.flags.reset == 1'. 4. Verify the service on %s:%d is running and listening. 5. Check firewall rules on both source and destination. 6. Test connectivity with telnet or nc: 'telnet %s %d'. 7. Review routing tables and ensure proper network paths exist.", dstIP, dstPort, dstIP, dstPort),
	}
}

// HTTP Error Explanation
func GenerateHTTPErrorExplanation(statusCode int, method, url string) FindingExplanation {
	var errorType, meaning string

	if statusCode >= 400 && statusCode < 500 {
		errorType = "Client Error (4xx)"
		switch statusCode {
		case 400:
			meaning = "Bad Request - The server cannot process the request due to client error (malformed syntax, invalid request, etc.)"
		case 401:
			meaning = "Unauthorized - Authentication is required and has failed or not been provided"
		case 403:
			meaning = "Forbidden - The server understood the request but refuses to authorize it"
		case 404:
			meaning = "Not Found - The requested resource does not exist on the server"
		case 408:
			meaning = "Request Timeout - The server timed out waiting for the request"
		default:
			meaning = "Client-side error - The request contains bad syntax or cannot be fulfilled"
		}
	} else if statusCode >= 500 {
		errorType = "Server Error (5xx)"
		switch statusCode {
		case 500:
			meaning = "Internal Server Error - The server encountered an unexpected condition"
		case 502:
			meaning = "Bad Gateway - The server received an invalid response from an upstream server"
		case 503:
			meaning = "Service Unavailable - The server is temporarily unable to handle the request (overload or maintenance)"
		case 504:
			meaning = "Gateway Timeout - The server did not receive a timely response from an upstream server"
		default:
			meaning = "Server-side error - The server failed to fulfill a valid request"
		}
	}

	return FindingExplanation{
		Title:      fmt.Sprintf("HTTP %d Error", statusCode),
		Definition: fmt.Sprintf("HTTP status code %d (%s) was returned for %s request to %s. %s", statusCode, errorType, method, url, meaning),
		Impact: fmt.Sprintf("HTTP errors indicate application-level problems. %s errors suggest issues with the client request or permissions, while %s errors indicate server-side failures. Users experience failed page loads, broken functionality, or access denied messages.",
			func() string {
				if statusCode < 500 {
					return "4xx"
				}
				return "5xx"
			}(),
			func() string {
				if statusCode < 500 {
					return "5xx"
				}
				return "4xx"
			}()),
		Detection:         fmt.Sprintf("The tool captured HTTP response packets with status code %d for the request: %s %s", statusCode, method, url),
		WiresharkFilter:   fmt.Sprintf("http.response.code == %d", statusCode),
		RecommendedAction: fmt.Sprintf("1. Use the filter to see all HTTP %d responses. 2. Examine the full HTTP conversation with 'http.request.method == \"%s\"'. 3. For 4xx errors: verify URL correctness, check authentication credentials, review permissions. 4. For 5xx errors: check server logs, verify backend services are running, check database connectivity. 5. Use 'http.response.code >= 400' to see all errors. 6. Follow the HTTP stream to see request/response headers and body.", statusCode, method),
	}
}

// DDoS Attack Explanation
func GenerateDDoSExplanation(attackType, sourceIP string, packetCount int) FindingExplanation {
	var filter, definition, impact string

	switch attackType {
	case "SYN Flood":
		filter = fmt.Sprintf("tcp.flags.syn == 1 and tcp.flags.ack == 0 and ip.src == %s", sourceIP)
		definition = fmt.Sprintf("A SYN flood attack involves sending a large number of TCP SYN packets (%d detected) from %s without completing the handshake, exhausting server resources.", packetCount, sourceIP)
		impact = "SYN floods consume server memory and connection table entries, preventing legitimate users from establishing connections. The server becomes unresponsive or crashes."
	case "UDP Flood":
		filter = fmt.Sprintf("udp and ip.src == %s", sourceIP)
		definition = fmt.Sprintf("A UDP flood attack sends a high volume of UDP packets (%d detected) from %s to overwhelm the target with traffic.", packetCount, sourceIP)
		impact = "UDP floods consume bandwidth and processing resources, causing network congestion and service degradation. Legitimate traffic is crowded out."
	case "ICMP Flood":
		filter = fmt.Sprintf("icmp and ip.src == %s", sourceIP)
		definition = fmt.Sprintf("An ICMP flood (ping flood) sends excessive ICMP Echo Request packets (%d detected) from %s to overwhelm the target.", packetCount, sourceIP)
		impact = "ICMP floods consume bandwidth and CPU resources processing ping requests, degrading network performance and potentially causing outages."
	default:
		filter = fmt.Sprintf("ip.src == %s", sourceIP)
		definition = fmt.Sprintf("A DDoS attack pattern was detected with %d packets from %s.", packetCount, sourceIP)
		impact = "DDoS attacks aim to make services unavailable by overwhelming them with traffic."
	}

	return FindingExplanation{
		Title:             fmt.Sprintf("%s DDoS Attack", attackType),
		Definition:        definition,
		Impact:            impact,
		Detection:         fmt.Sprintf("The tool detected an abnormally high packet rate (%d packets) from source %s, exceeding normal traffic thresholds and matching %s attack patterns.", packetCount, sourceIP, attackType),
		WiresharkFilter:   filter,
		RecommendedAction: fmt.Sprintf("1. Apply the filter to examine the attack traffic. 2. Use 'Statistics → Conversations' to see traffic volume per IP. 3. Check if source IP %s is spoofed or part of a botnet. 4. Implement rate limiting and SYN cookies on affected servers. 5. Configure firewall rules to block or rate-limit traffic from %s. 6. Contact ISP for upstream filtering if attack is large-scale. 7. Consider DDoS mitigation services (Cloudflare, AWS Shield, etc.). 8. Use 'ip.src == %s and frame.time_relative < 1' to see attack intensity in first second.", sourceIP, sourceIP, sourceIP),
	}
}

// Port Scan Explanation
func GeneratePortScanExplanation(scanType, sourceIP string, portCount int) FindingExplanation {
	var filter, definition string

	switch scanType {
	case "Horizontal":
		filter = fmt.Sprintf("ip.src == %s and tcp.flags.syn == 1 and tcp.flags.ack == 0", sourceIP)
		definition = fmt.Sprintf("A horizontal port scan targets the same port across multiple hosts. Source %s scanned %d different destinations, likely probing for a specific vulnerable service.", sourceIP, portCount)
	case "Vertical":
		filter = fmt.Sprintf("ip.src == %s and tcp.flags.syn == 1", sourceIP)
		definition = fmt.Sprintf("A vertical port scan targets multiple ports on the same host. Source %s scanned %d different ports, attempting to discover all available services.", sourceIP, portCount)
	default:
		filter = fmt.Sprintf("ip.src == %s and tcp.flags.syn == 1", sourceIP)
		definition = fmt.Sprintf("A port scan was detected from %s targeting %d ports/hosts, attempting to discover open services and potential vulnerabilities.", sourceIP, portCount)
	}

	return FindingExplanation{
		Title:             fmt.Sprintf("%s Port Scan", scanType),
		Definition:        definition,
		Impact:            "Port scans are reconnaissance activities that precede attacks. Attackers use scans to map your network, identify running services, and find vulnerabilities to exploit. While scanning itself may not be harmful, it indicates malicious intent and often precedes actual attacks.",
		Detection:         fmt.Sprintf("The tool detected %s scanning %d ports/hosts in a short time period, with connection attempts that match port scanning patterns (rapid SYN packets without completing handshakes).", sourceIP, portCount),
		WiresharkFilter:   filter,
		RecommendedAction: fmt.Sprintf("1. Apply the filter to see the scan traffic. 2. Use 'tcp.flags.syn == 1 and tcp.flags.ack == 0 and ip.src == %s' to see SYN packets. 3. Check for responses with 'tcp.flags.reset == 1' (closed ports) or 'tcp.flags.syn == 1 and tcp.flags.ack == 1' (open ports). 4. Identify which ports were targeted using 'Statistics → Conversations → TCP'. 5. Block source IP %s at the firewall. 6. Review firewall rules to ensure only necessary ports are exposed. 7. Implement IDS/IPS to detect and block scanning. 8. Check if any services on scanned ports have known vulnerabilities.", sourceIP, sourceIP),
	}
}

// IOC Match Explanation
func GenerateIOCExplanation(iocType, indicator, sourceIP string) FindingExplanation {
	var filter, definition string

	switch iocType {
	case "Malicious IP":
		filter = fmt.Sprintf("ip.addr == %s", indicator)
		definition = fmt.Sprintf("Communication was detected with IP address %s, which is listed in threat intelligence databases as malicious. This IP is associated with malware, command & control servers, or other malicious activity.", indicator)
	case "Malicious Domain":
		filter = fmt.Sprintf("dns.qry.name contains \"%s\"", indicator)
		definition = fmt.Sprintf("A DNS query was made for domain '%s', which is listed in threat intelligence databases as malicious. This domain is associated with malware, phishing, or command & control infrastructure.", indicator)
	default:
		filter = fmt.Sprintf("ip.src == %s", sourceIP)
		definition = fmt.Sprintf("An Indicator of Compromise (IOC) was matched: %s. This suggests potential malware infection or malicious activity.", indicator)
	}

	return FindingExplanation{
		Title:             "Indicator of Compromise (IOC) Match",
		Definition:        definition,
		Impact:            "IOC matches indicate potential malware infections, data breaches, or ongoing attacks. Compromised systems may be exfiltrating data, receiving commands from attackers, or participating in botnets. Immediate investigation is critical to prevent further damage.",
		Detection:         fmt.Sprintf("The tool compared network traffic against threat intelligence databases and found a match for %s from source %s.", indicator, sourceIP),
		WiresharkFilter:   filter,
		RecommendedAction: fmt.Sprintf("1. Apply the filter to see all traffic involving the IOC. 2. Identify the internal host communicating with the malicious indicator (likely %s). 3. Isolate the affected system from the network immediately. 4. Run antivirus/antimalware scans on the host. 5. Check for persistence mechanisms (scheduled tasks, registry keys, startup items). 6. Review system logs for suspicious activity. 7. Capture memory dump for forensic analysis. 8. Reset credentials for accounts used on the compromised system. 9. Report to security team/SOC for incident response.", sourceIP),
	}
}

// TLS Weakness Explanation
func GenerateTLSWeaknessExplanation(weakness, serverIP string, serverPort uint16) FindingExplanation {
	var definition, impact string

	if strings.Contains(weakness, "TLS") || strings.Contains(weakness, "SSL") {
		definition = fmt.Sprintf("The server at %s:%d is using an outdated or weak TLS/SSL protocol version: %s. Modern security standards require TLS 1.2 or higher.", serverIP, serverPort, weakness)
		impact = "Weak TLS versions (SSL 3.0, TLS 1.0, TLS 1.1) have known vulnerabilities (POODLE, BEAST, etc.) that allow attackers to decrypt traffic, perform man-in-the-middle attacks, and steal sensitive data like passwords and session tokens."
	} else {
		definition = fmt.Sprintf("The server at %s:%d is using a weak cipher suite: %s. This cipher has known cryptographic weaknesses.", serverIP, serverPort, weakness)
		impact = "Weak ciphers can be broken by attackers, allowing them to decrypt encrypted traffic and access sensitive information. This undermines the security that TLS/SSL is meant to provide."
	}

	return FindingExplanation{
		Title:             "TLS/SSL Security Weakness",
		Definition:        definition,
		Impact:            impact,
		Detection:         fmt.Sprintf("The tool analyzed TLS handshake packets and identified the use of %s on server %s:%d during the ClientHello/ServerHello exchange.", weakness, serverIP, serverPort),
		WiresharkFilter:   fmt.Sprintf("ssl.handshake.type == 1 and ip.addr == %s and tcp.port == %d", serverIP, serverPort),
		RecommendedAction: fmt.Sprintf("1. Apply the filter to see TLS handshakes with %s:%d. 2. Use 'ssl.handshake.ciphersuite' to see cipher suites offered. 3. Check 'ssl.record.version' for protocol versions. 4. Update server configuration to disable weak protocols (SSL 3.0, TLS 1.0, TLS 1.1). 5. Configure strong cipher suites (AES-GCM, ChaCha20). 6. Use tools like 'testssl.sh' or 'nmap --script ssl-enum-ciphers' to audit the server. 7. Obtain and install valid TLS certificates. 8. Enable HSTS (HTTP Strict Transport Security) headers.", serverIP, serverPort),
	}
}

// High RTT Explanation
func GenerateHighRTTExplanation(srcIP, dstIP string, avgRTT float64) FindingExplanation {
	return FindingExplanation{
		Title:             "High Round-Trip Time (RTT)",
		Definition:        fmt.Sprintf("Round-Trip Time (RTT) is the time it takes for a packet to travel from source to destination and back. The flow between %s and %s has an average RTT of %.2f ms, which is considered high.", srcIP, dstIP, avgRTT),
		Impact:            fmt.Sprintf("High RTT (%.2f ms) causes slow application response times, delayed page loads, and poor user experience. Real-time applications like VoIP, video conferencing, and online gaming are severely affected. Each request-response cycle is delayed, multiplying the impact.", avgRTT),
		Detection:         fmt.Sprintf("The tool calculated RTT by measuring the time between TCP data packets and their corresponding ACK packets for the flow %s ↔ %s.", srcIP, dstIP),
		WiresharkFilter:   fmt.Sprintf("tcp and ip.addr == %s and ip.addr == %s", srcIP, dstIP),
		RecommendedAction: fmt.Sprintf("1. Apply the filter to see the TCP conversation. 2. Use 'Statistics → TCP Stream Graphs → Round Trip Time' to visualize RTT over time. 3. Check for consistent high RTT (routing issue) vs. spikes (congestion). 4. Use traceroute to identify where latency is introduced: 'traceroute %s'. 5. Check for WAN link saturation or QoS misconfigurations. 6. Verify routing is optimal (no unnecessary hops). 7. Test with ping: 'ping -c 100 %s' and analyze statistics. 8. Consider using CDN or edge caching for frequently accessed content.", dstIP, dstIP),
	}
}

// ICMP Anomaly Explanation
func GenerateICMPAnomalyExplanation(icmpType, sourceIP string, count int) FindingExplanation {
	return FindingExplanation{
		Title:             fmt.Sprintf("ICMP Anomaly: %s", icmpType),
		Definition:        fmt.Sprintf("An unusual pattern of ICMP (Internet Control Message Protocol) traffic was detected. %d %s messages were observed from %s, which exceeds normal operational levels.", count, icmpType, sourceIP),
		Impact:            "Abnormal ICMP traffic can indicate network scanning, DDoS attacks (ping floods), or network misconfigurations. Excessive ICMP can consume bandwidth and processing resources. Some ICMP types (redirects, unreachables) may indicate routing problems or attacks.",
		Detection:         fmt.Sprintf("The tool counted %d ICMP %s packets from %s, which exceeds the threshold for normal network operations.", count, icmpType, sourceIP),
		WiresharkFilter:   fmt.Sprintf("icmp and ip.src == %s", sourceIP),
		RecommendedAction: fmt.Sprintf("1. Apply the filter to examine ICMP traffic from %s. 2. Use 'icmp.type' to filter specific ICMP types (0=Echo Reply, 3=Dest Unreachable, 8=Echo Request, etc.). 3. Check if this is a ping flood with 'icmp.type == 8'. 4. For Destination Unreachable (type 3), investigate routing issues. 5. For Redirect (type 5), verify router configurations. 6. Use 'Statistics → ICMP' to see ICMP type distribution. 7. Consider rate-limiting ICMP at firewalls. 8. Investigate source %s for potential compromise or misconfiguration.", sourceIP, sourceIP),
	}
}

// Executive Summary Explanation
func GetExecutiveSummaryExplanation() string {
	return `<div class="executive-summary-explanation">
		<p class="info-box">
			<i class="fas fa-info-circle"></i>
			<strong>About this Summary:</strong> This executive summary provides a high-level overview of your network's health based on analysis of the captured traffic. 
			The <strong>Risk Level</strong> indicates the overall severity of findings detected (Low, Medium, High, or Critical), calculated from the number and type of security issues, performance problems, and anomalies found. 
			The counters below highlight the most significant categories of issues that require attention. Use this summary to quickly assess network health and prioritize troubleshooting efforts.
		</p>
	</div>`
}

// Protocol Analysis Guide
func GetProtocolAnalysisGuide() template.HTML {
	return template.HTML(`
		<div class="protocol-guide">
			<details class="guide-section">
				<summary><i class="fas fa-book-open"></i> Protocol Analysis Guide</summary>
				<div class="guide-content">
					<h4>Understanding Network Protocols</h4>
					
					<div class="protocol-explanation">
						<h5><i class="fas fa-exchange-alt"></i> TCP Handshakes</h5>
						<p><strong>Normal Behavior:</strong> TCP uses a three-way handshake to establish connections:</p>
						<ol>
							<li><strong>SYN:</strong> Client sends SYN packet to server</li>
							<li><strong>SYN-ACK:</strong> Server responds with SYN-ACK</li>
							<li><strong>ACK:</strong> Client sends final ACK to complete handshake</li>
						</ol>
						<p><strong>Abnormal Behavior:</strong> Failed handshakes occur when SYN packets receive no response (server down/firewalled) or receive RST (connection refused).</p>
						<p><strong>Wireshark Filters:</strong></p>
						<ul>
							<li><code>tcp.flags.syn == 1 and tcp.flags.ack == 0</code> - See SYN packets (connection attempts)</li>
							<li><code>tcp.flags.syn == 1 and tcp.flags.ack == 1</code> - See SYN-ACK packets (server responses)</li>
							<li><code>tcp.flags.reset == 1</code> - See RST packets (connection refused/aborted)</li>
							<li><code>tcp.analysis.flags</code> - See TCP analysis flags (retransmissions, out-of-order, etc.)</li>
						</ul>
					</div>
					
					<div class="protocol-explanation">
						<h5><i class="fas fa-globe"></i> HTTP/HTTPS</h5>
						<p><strong>Normal Behavior:</strong> HTTP requests receive 2xx (success) or 3xx (redirect) responses.</p>
						<p><strong>Abnormal Behavior:</strong> 4xx errors indicate client-side issues (404 Not Found, 403 Forbidden). 5xx errors indicate server-side failures (500 Internal Server Error, 503 Service Unavailable).</p>
						<p><strong>Wireshark Filters:</strong></p>
						<ul>
							<li><code>http.response.code >= 400</code> - See all HTTP errors</li>
							<li><code>http.response.code >= 500</code> - See server errors only</li>
							<li><code>http.request.method == "GET"</code> - See GET requests</li>
							<li><code>http.request.method == "POST"</code> - See POST requests</li>
							<li><code>ssl.handshake.type == 1</code> - See HTTPS ClientHello packets</li>
						</ul>
					</div>
					
					<div class="protocol-explanation">
						<h5><i class="fas fa-search"></i> DNS</h5>
						<p><strong>Normal Behavior:</strong> DNS queries receive responses with answer records. Response time is typically under 100ms.</p>
						<p><strong>Abnormal Behavior:</strong> NXDOMAIN (domain doesn't exist), timeouts (no response), excessive queries to random domains (DGA malware), or queries to suspicious domains.</p>
						<p><strong>Wireshark Filters:</strong></p>
						<ul>
							<li><code>dns.flags.response == 0</code> - See DNS queries</li>
							<li><code>dns.flags.response == 1</code> - See DNS responses</li>
							<li><code>dns.flags.rcode == 3</code> - See NXDOMAIN responses</li>
							<li><code>dns.time > 1</code> - See slow DNS responses (>1 second)</li>
							<li><code>dns.qry.name contains "suspicious"</code> - Search for specific domains</li>
						</ul>
					</div>
					
					<div class="protocol-explanation">
						<h5><i class="fas fa-network-wired"></i> ARP</h5>
						<p><strong>Normal Behavior:</strong> ARP requests receive a single response mapping an IP to a MAC address.</p>
						<p><strong>Abnormal Behavior:</strong> Multiple MAC addresses claiming the same IP (conflict), excessive ARP requests (scanning), or gratuitous ARP from unexpected sources (spoofing).</p>
						<p><strong>Wireshark Filters:</strong></p>
						<ul>
							<li><code>arp.opcode == 1</code> - See ARP requests (who-has)</li>
							<li><code>arp.opcode == 2</code> - See ARP replies (is-at)</li>
							<li><code>arp.duplicate-address-detected</code> - See ARP conflicts</li>
							<li><code>arp.src.proto_ipv4 == 192.168.1.1</code> - See ARP for specific IP</li>
						</ul>
					</div>
				</div>
			</details>
		</div>
	`)
}
