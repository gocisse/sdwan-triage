package output

import "fmt"

// This file contains the page generation functions for the multi-page HTML report

func generateSecurityPage(data *ReportData, outputPath string) error {
	pageData := &PageData{
		ReportData:  data,
		CurrentPage: "security",
		PageTitle:   "Security Findings",
	}

	contentTemplate := `{{define "content"}}
                <section id="security-findings">
                    <div class="card">
                        <div class="card-header">
                            <i class="fas fa-shield-alt"></i>
                            <h2>Security Findings</h2>
                        </div>
                        <div class="card-body">
                            <div class="stats-grid">
                                <div class="stat-card {{if gt .Stats.DDoSAttacks 0}}stat-danger{{end}}">
                                    <span class="stat-value">{{.Stats.DDoSAttacks}}</span>
                                    <span class="stat-label"><i class="fas fa-bomb"></i> DDoS Attacks</span>
                                </div>
                                <div class="stat-card {{if gt .Stats.PortScans 0}}stat-warning{{end}}">
                                    <span class="stat-value">{{.Stats.PortScans}}</span>
                                    <span class="stat-label"><i class="fas fa-crosshairs"></i> Port Scans</span>
                                </div>
                                <div class="stat-card {{if gt .Stats.IOCMatches 0}}stat-danger{{end}}">
                                    <span class="stat-value">{{.Stats.IOCMatches}}</span>
                                    <span class="stat-label"><i class="fas fa-skull-crossbones"></i> IOC Matches</span>
                                </div>
                                <div class="stat-card {{if gt .Stats.TLSWeaknesses 0}}stat-warning{{end}}">
                                    <span class="stat-value">{{.Stats.TLSWeaknesses}}</span>
                                    <span class="stat-label"><i class="fas fa-unlock-alt"></i> TLS Weaknesses</span>
                                </div>
                            </div>
                        </div>
                    </div>

                    <div id="dns-analysis">
                    {{if .DNSAnomalies}}
                    <div class="card">
                        <div class="card-header">
                            <i class="fas fa-dns"></i>
                            <h2>DNS Anomalies ({{len .DNSAnomalies}})</h2>
                        </div>
                        <div class="card-body">
                            <table class="data-table">
                                <thead>
                                    <tr>
                                        <th data-sort>Query</th>
                                        <th data-sort>Answer IP</th>
                                        <th data-sort>Server</th>
                                        <th>Reason</th>
                                        <th>Action</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {{range .DNSAnomalies}}
                                    <tr>
                                        <td><code>{{.Query}}</code></td>
                                        <td><code>{{.AnswerIP}}</code></td>
                                        <td><code>{{.ServerIP}}</code></td>
                                        <td class="severity-high">{{.Reason}}</td>
                                        <td><button class="btn btn-sm btn-secondary" onclick="toggleAction(this)">Show Details</button></td>
                                    </tr>
                                    <tr class="action-row">
                                        <td colspan="5">
                                            <div class="action-content">
                                                {{.Explanation}}
                                            </div>
                                        </td>
                                    </tr>
                                    {{end}}
                                </tbody>
                            </table>
                        </div>
                    </div>
                    {{end}}
                    </div>

                    <div id="arp-conflicts">
                    {{if .ARPConflicts}}
                    <div class="card">
                        <div class="card-header">
                            <i class="fas fa-network-wired"></i>
                            <h2>ARP Conflicts ({{len .ARPConflicts}})</h2>
                        </div>
                        <div class="card-body">
                            <table class="data-table">
                                <thead><tr><th>IP</th><th>MAC 1</th><th>MAC 2</th><th>Action</th></tr></thead>
                                <tbody>
                                    {{range .ARPConflicts}}
                                    <tr>
                                        <td><code>{{.IP}}</code></td>
                                        <td><code>{{.MAC1}}</code></td>
                                        <td><code>{{.MAC2}}</code></td>
                                        <td><button class="btn btn-sm btn-secondary" onclick="toggleAction(this)">Show Details</button></td>
                                    </tr>
                                    <tr class="action-row">
                                        <td colspan="4">
                                            <div class="action-content">
                                                {{.Explanation}}
                                            </div>
                                        </td>
                                    </tr>
                                    {{end}}
                                </tbody>
                            </table>
                        </div>
                    </div>
                    {{end}}
                    </div>

                    {{if .DDoSFindings}}
                    <div class="card">
                        <div class="card-header">
                            <i class="fas fa-bomb"></i>
                            <h2>DDoS Attacks Detected ({{len .DDoSFindings}})</h2>
                        </div>
                        <div class="card-body">
                            <table class="data-table">
                                <thead><tr><th>Time</th><th>Source IP</th><th>Target IP</th><th>Type</th><th>Packets</th><th>Severity</th><th>Action</th></tr></thead>
                                <tbody>
                                    {{range .DDoSFindings}}
                                    <tr class="severity-row-{{if eq .Severity "Critical"}}critical{{else if eq .Severity "High"}}high{{else}}medium{{end}}">
                                        <td>{{formatUnixTimeShort .Timestamp}}</td>
                                        <td><code>{{.SourceIP}}</code></td>
                                        <td><code>{{.TargetIP}}</code></td>
                                        <td><span class="badge badge-danger">{{.Type}}</span></td>
                                        <td>{{.PacketCount}} (threshold: {{.Threshold}})</td>
                                        <td><span class="badge badge-{{if eq .Severity "Critical"}}danger{{else if eq .Severity "High"}}warning{{else}}info{{end}}">{{.Severity}}</span></td>
                                        <td><button class="btn btn-sm btn-secondary" onclick="toggleAction(this)">Show Details</button></td>
                                    </tr>
                                    <tr class="action-row">
                                        <td colspan="7">
                                            <div class="action-content">
                                                {{.Explanation}}
                                            </div>
                                        </td>
                                    </tr>
                                    {{end}}
                                </tbody>
                            </table>
                        </div>
                    </div>
                    {{end}}

                    {{if .PortScanFindings}}
                    <div class="card">
                        <div class="card-header">
                            <i class="fas fa-search"></i>
                            <h2>Port Scanning Detected ({{len .PortScanFindings}})</h2>
                        </div>
                        <div class="card-body">
                            <table class="data-table">
                                <thead><tr><th>Time</th><th>Source IP</th><th>Target</th><th>Scan Type</th><th>Ports Scanned</th><th>Severity</th><th>Action</th></tr></thead>
                                <tbody>
                                    {{range .PortScanFindings}}
                                    <tr>
                                        <td>{{formatUnixTimeShort .Timestamp}}</td>
                                        <td><code>{{.SourceIP}}</code></td>
                                        <td><code>{{.TargetIP}}</code></td>
                                        <td><span class="badge badge-warning">{{.Type}}</span></td>
                                        <td>{{.PortsScanned}} {{if .SamplePorts}}({{.SamplePorts}}){{end}}</td>
                                        <td><span class="badge badge-{{if eq .Severity "Critical"}}danger{{else if eq .Severity "High"}}warning{{else}}info{{end}}">{{.Severity}}</span></td>
                                        <td><button class="btn btn-sm btn-secondary" onclick="toggleAction(this)">Show Details</button></td>
                                    </tr>
                                    <tr class="action-row">
                                        <td colspan="7">
                                            <div class="action-content">
                                                {{.Explanation}}
                                            </div>
                                        </td>
                                    </tr>
                                    {{end}}
                                </tbody>
                            </table>
                        </div>
                    </div>
                    {{end}}

                    {{if .IOCFindings}}
                    <div class="card">
                        <div class="card-header">
                            <i class="fas fa-skull-crossbones"></i>
                            <h2>IOC Matches ({{len .IOCFindings}})</h2>
                        </div>
                        <div class="card-body">
                            <table class="data-table">
                                <thead><tr><th>Time</th><th>Matched Value</th><th>Type</th><th>Category</th><th>Confidence</th><th>Description</th><th>Action</th></tr></thead>
                                <tbody>
                                    {{range .IOCFindings}}
                                    <tr class="severity-row-high">
                                        <td>{{formatUnixTimeShort .Timestamp}}</td>
                                        <td><code>{{.MatchedValue}}</code></td>
                                        <td>{{.Type}}</td>
                                        <td><span class="badge badge-danger">{{.IOCType}}</span></td>
                                        <td>{{.Confidence}}</td>
                                        <td>{{.Description}}</td>
                                        <td><button class="btn btn-sm btn-secondary" onclick="toggleAction(this)">Show Details</button></td>
                                    </tr>
                                    <tr class="action-row">
                                        <td colspan="7">
                                            <div class="action-content">
                                                {{.Explanation}}
                                            </div>
                                        </td>
                                    </tr>
                                    {{end}}
                                </tbody>
                            </table>
                        </div>
                    </div>
                    {{end}}

                    {{if .TLSSecurityFindings}}
                    <div class="card">
                        <div class="card-header">
                            <i class="fas fa-unlock-alt"></i>
                            <h2>TLS Security Weaknesses ({{len .TLSSecurityFindings}})</h2>
                        </div>
                        <div class="card-body">
                            <table class="data-table">
                                <thead><tr><th>Time</th><th>Server</th><th>TLS Version</th><th>Cipher Suite</th><th>Weakness</th><th>Severity</th><th>Action</th></tr></thead>
                                <tbody>
                                    {{range .TLSSecurityFindings}}
                                    <tr>
                                        <td>{{formatUnixTimeShort .Timestamp}}</td>
                                        <td><code>{{.ServerIP}}:{{.ServerPort}}</code> {{if .ServerName}}({{.ServerName}}){{end}}</td>
                                        <td>{{.TLSVersion}}</td>
                                        <td><code>{{.CipherSuite}}</code></td>
                                        <td>{{.WeaknessType}}</td>
                                        <td><span class="badge badge-{{if eq .Severity "Critical"}}danger{{else if eq .Severity "High"}}warning{{else}}info{{end}}">{{.Severity}}</span></td>
                                        <td><button class="btn btn-sm btn-secondary" onclick="toggleAction(this)">Show Details</button></td>
                                    </tr>
                                    <tr class="action-row">
                                        <td colspan="7">
                                            <div class="action-content">
                                                {{.Explanation}}
                                            </div>
                                        </td>
                                    </tr>
                                    {{end}}
                                </tbody>
                            </table>
                        </div>
                    </div>
                    {{end}}

                    {{if .ICMPFindings}}
                    <div class="card">
                        <div class="card-header">
                            <i class="fas fa-satellite-dish"></i>
                            <h2>ICMP Analysis ({{len .ICMPFindings}})</h2>
                        </div>
                        <div class="card-body">
                            <table class="data-table">
                                <thead><tr><th>Source</th><th>Destination</th><th>Type</th><th>Count</th><th>Status</th><th>Action</th></tr></thead>
                                <tbody>
                                    {{range .ICMPFindings}}
                                    <tr class="{{if .IsAnomaly}}severity-row-medium{{end}}">
                                        <td><code>{{.SourceIP}}</code></td>
                                        <td><code>{{.DestIP}}</code></td>
                                        <td>{{.TypeName}} ({{.Type}}/{{.Code}})</td>
                                        <td>{{.Count}}</td>
                                        <td>{{if .IsAnomaly}}<span class="badge badge-warning">Anomaly</span> {{.Description}}{{else}}<span class="badge badge-success">Normal</span>{{end}}</td>
                                        <td>{{if .IsAnomaly}}<button class="btn btn-sm btn-secondary" onclick="toggleAction(this)">Show Details</button>{{end}}</td>
                                    </tr>
                                    {{if .IsAnomaly}}
                                    <tr class="action-row">
                                        <td colspan="6">
                                            <div class="action-content">
                                                {{.Explanation}}
                                            </div>
                                        </td>
                                    </tr>
                                    {{end}}
                                    {{end}}
                                </tbody>
                            </table>
                        </div>
                    </div>
                    {{end}}

                    <!-- Comprehensive Wireshark Filter Guide -->
                    <div class="card" id="wireshark-filter-guide">
                        <div class="card-header">
                            <i class="fas fa-graduation-cap"></i>
                            <h2>Wireshark Filter Guide for Junior Technicians</h2>
                        </div>
                        <div class="card-body">
                            <div class="explanation-content">
                                <h3>📋 How to Use Filters from This Report</h3>
                                <ol>
                                    <li><strong>Copy the Filter:</strong> Click any "Copy" button next to Wireshark filters in this report</li>
                                    <li><strong>Open Wireshark:</strong> Load your PCAP file</li>
                                    <li><strong>Apply Filter:</strong> Paste into the display filter bar (top of Wireshark window)</li>
                                    <li><strong>Press Enter:</strong> View only matching packets</li>
                                </ol>

                                <h3>🔍 Extracting Data from Report Source</h3>
                                <p>This HTML report contains embedded network data in JavaScript variables. To extract additional filters:</p>
                                <ol>
                                    <li>Press <code>Ctrl+U</code> (Windows/Linux) or <code>Cmd+Option+U</code> (Mac) to view page source</li>
                                    <li>Press <code>Ctrl+F</code> to search for these variables:
                                        <ul>
                                            <li><code>var timelineData</code> - Events with timestamps, IPs, ports</li>
                                            <li><code>var networkData</code> - Flow data for issues like retransmissions</li>
                                            <li><code>var sankeyData</code> - Aggregated traffic flows</li>
                                        </ul>
                                    </li>
                                    <li>Find IP addresses and ports in the JSON data</li>
                                    <li>Build custom filters using patterns below</li>
                                </ol>

                                <h3>📝 Filter Pattern Library</h3>
                                
                                <details open>
                                    <summary><strong>Basic Flow Filters</strong></summary>
                                    <div class="filter-examples">
                                        <p><strong>Traffic between two IPs:</strong></p>
                                        <code class="wireshark-filter">ip.addr == 192.168.1.100 and ip.addr == 8.8.8.8</code>
                                        <button class="copy-filter-btn" onclick="copyToClipboard('ip.addr == 192.168.1.100 and ip.addr == 8.8.8.8')"><i class="fas fa-copy"></i> Copy</button>
                                        
                                        <p><strong>Specific TCP port:</strong></p>
                                        <code class="wireshark-filter">ip.addr == 192.168.1.100 and tcp.port == 443</code>
                                        <button class="copy-filter-btn" onclick="copyToClipboard('ip.addr == 192.168.1.100 and tcp.port == 443')"><i class="fas fa-copy"></i> Copy</button>
                                        
                                        <p><strong>Specific UDP port:</strong></p>
                                        <code class="wireshark-filter">ip.addr == 192.168.1.100 and udp.port == 53</code>
                                        <button class="copy-filter-btn" onclick="copyToClipboard('ip.addr == 192.168.1.100 and udp.port == 53')"><i class="fas fa-copy"></i> Copy</button>
                                    </div>
                                </details>

                                <details>
                                    <summary><strong>Security Analysis Filters</strong></summary>
                                    <div class="filter-examples">
                                        <p><strong>Port scan detection (SYN packets from scanner):</strong></p>
                                        <code class="wireshark-filter">ip.src == 203.0.113.50 and tcp.flags.syn == 1 and tcp.flags.ack == 0</code>
                                        <button class="copy-filter-btn" onclick="copyToClipboard('ip.src == 203.0.113.50 and tcp.flags.syn == 1 and tcp.flags.ack == 0')"><i class="fas fa-copy"></i> Copy</button>
                                        
                                        <p><strong>SYN flood (DDoS) to target:</strong></p>
                                        <code class="wireshark-filter">ip.dst == 192.168.1.1 and tcp.flags.syn == 1 and tcp.flags.ack == 0</code>
                                        <button class="copy-filter-btn" onclick="copyToClipboard('ip.dst == 192.168.1.1 and tcp.flags.syn == 1 and tcp.flags.ack == 0')"><i class="fas fa-copy"></i> Copy</button>
                                        
                                        <p><strong>UDP flood to target:</strong></p>
                                        <code class="wireshark-filter">ip.dst == 192.168.1.1 and udp</code>
                                        <button class="copy-filter-btn" onclick="copyToClipboard('ip.dst == 192.168.1.1 and udp')"><i class="fas fa-copy"></i> Copy</button>
                                        
                                        <p><strong>ICMP flood:</strong></p>
                                        <code class="wireshark-filter">ip.dst == 192.168.1.1 and icmp</code>
                                        <button class="copy-filter-btn" onclick="copyToClipboard('ip.dst == 192.168.1.1 and icmp')"><i class="fas fa-copy"></i> Copy</button>
                                        
                                        <p><strong>ARP conflicts for specific IP:</strong></p>
                                        <code class="wireshark-filter">arp and arp.src.proto_ipv4 == 192.168.1.100</code>
                                        <button class="copy-filter-btn" onclick="copyToClipboard('arp and arp.src.proto_ipv4 == 192.168.1.100')"><i class="fas fa-copy"></i> Copy</button>
                                    </div>
                                </details>

                                <details>
                                    <summary><strong>DNS Analysis Filters</strong></summary>
                                    <div class="filter-examples">
                                        <p><strong>All DNS queries:</strong></p>
                                        <code class="wireshark-filter">dns and dns.flags.response == 0</code>
                                        <button class="copy-filter-btn" onclick="copyToClipboard('dns and dns.flags.response == 0')"><i class="fas fa-copy"></i> Copy</button>
                                        
                                        <p><strong>All DNS responses:</strong></p>
                                        <code class="wireshark-filter">dns and dns.flags.response == 1</code>
                                        <button class="copy-filter-btn" onclick="copyToClipboard('dns and dns.flags.response == 1')"><i class="fas fa-copy"></i> Copy</button>
                                        
                                        <p><strong>Query for specific domain:</strong></p>
                                        <code class="wireshark-filter">dns.qry.name == "example.com"</code>
                                        <button class="copy-filter-btn" onclick='copyToClipboard("dns.qry.name == \"example.com\"")'><i class="fas fa-copy"></i> Copy</button>
                                        
                                        <p><strong>DNS failures (NXDOMAIN):</strong></p>
                                        <code class="wireshark-filter">dns.flags.rcode == 3</code>
                                        <button class="copy-filter-btn" onclick="copyToClipboard('dns.flags.rcode == 3')"><i class="fas fa-copy"></i> Copy</button>
                                        
                                        <p><strong>DNS to specific server:</strong></p>
                                        <code class="wireshark-filter">ip.dst == 8.8.8.8 and dns</code>
                                        <button class="copy-filter-btn" onclick="copyToClipboard('ip.dst == 8.8.8.8 and dns')"><i class="fas fa-copy"></i> Copy</button>
                                    </div>
                                </details>

                                <details>
                                    <summary><strong>TLS/SSL Security Filters</strong></summary>
                                    <div class="filter-examples">
                                        <p><strong>All TLS traffic:</strong></p>
                                        <code class="wireshark-filter">tls</code>
                                        <button class="copy-filter-btn" onclick="copyToClipboard('tls')"><i class="fas fa-copy"></i> Copy</button>
                                        
                                        <p><strong>TLS handshakes:</strong></p>
                                        <code class="wireshark-filter">tls.handshake.type == 1</code>
                                        <button class="copy-filter-btn" onclick="copyToClipboard('tls.handshake.type == 1')"><i class="fas fa-copy"></i> Copy</button>
                                        
                                        <p><strong>TLS to specific server:</strong></p>
                                        <code class="wireshark-filter">tls and ip.addr == 93.184.216.34</code>
                                        <button class="copy-filter-btn" onclick="copyToClipboard('tls and ip.addr == 93.184.216.34')"><i class="fas fa-copy"></i> Copy</button>
                                        
                                        <p><strong>Weak TLS versions (SSLv3, TLS 1.0, 1.1):</strong></p>
                                        <code class="wireshark-filter">tls.handshake.version <= 0x0302</code>
                                        <button class="copy-filter-btn" onclick="copyToClipboard('tls.handshake.version <= 0x0302')"><i class="fas fa-copy"></i> Copy</button>
                                    </div>
                                </details>

                                <h3>💡 Advanced Techniques</h3>
                                <ul>
                                    <li><strong>Combine filters:</strong> <code>(ip.addr == 192.168.1.100) and (tcp.port == 443 or tcp.port == 80)</code></li>
                                    <li><strong>Exclude traffic:</strong> <code>ip.addr == 192.168.1.100 and !dns</code></li>
                                    <li><strong>Network ranges:</strong> <code>ip.src == 192.168.0.0/16</code></li>
                                    <li><strong>Time-based:</strong> <code>frame.time >= "2024-01-01 10:00:00"</code></li>
                                    <li><strong>Follow streams:</strong> Right-click packet → Follow → TCP Stream</li>
                                </ul>

                                <h3>🎯 Using Timeline Data Example</h3>
                                <p>If you find this in the page source:</p>
                                <code>{"source":"192.168.100.203","target":"8.8.8.8","type":"TCP SYN","timestamp":1704110400}</code>
                                <p>Build this filter:</p>
                                <code class="wireshark-filter">ip.src == 192.168.100.203 and ip.dst == 8.8.8.8 and tcp.flags.syn == 1 and tcp.flags.ack == 0</code>
                                <button class="copy-filter-btn" onclick="copyToClipboard('ip.src == 192.168.100.203 and ip.dst == 8.8.8.8 and tcp.flags.syn == 1 and tcp.flags.ack == 0')"><i class="fas fa-copy"></i> Copy</button>
                            </div>
                        </div>
                    </div>
                </section>
{{end}}`

	return renderPage(getBaseTemplate()+contentTemplate, pageData, outputPath)
}

func generatePerformancePage(data *ReportData, outputPath string) error {
	pageData := &PageData{
		ReportData:  data,
		CurrentPage: "performance",
		PageTitle:   "Performance Analysis",
	}

	contentTemplate := `{{define "content"}}
                <section id="performance">
                    <div class="card">
                        <div class="card-header">
                            <i class="fas fa-tachometer-alt"></i>
                            <h2>Performance Metrics</h2>
                        </div>
                        <div class="card-body">
                            <div class="stats-grid">
                                <div class="stat-card {{if gt .Stats.TCPRetransmissions 10}}stat-warning{{end}}">
                                    <span class="stat-value">{{.Stats.TCPRetransmissions}}</span>
                                    <span class="stat-label"><i class="fas fa-redo"></i> TCP Retransmissions</span>
                                </div>
                                <div class="stat-card {{if gt .Stats.FailedHandshakes 0}}stat-warning{{end}}">
                                    <span class="stat-value">{{.Stats.FailedHandshakes}}</span>
                                    <span class="stat-label"><i class="fas fa-handshake-slash"></i> Failed Handshakes</span>
                                </div>
                                <div class="stat-card {{if gt .Stats.HighRTTFlows 0}}stat-warning{{end}}">
                                    <span class="stat-value">{{.Stats.HighRTTFlows}}</span>
                                    <span class="stat-label"><i class="fas fa-clock"></i> High RTT Flows</span>
                                </div>
                                <div class="stat-card {{if gt .Stats.HTTPErrors 0}}stat-warning{{end}}">
                                    <span class="stat-value">{{.Stats.HTTPErrors}}</span>
                                    <span class="stat-label"><i class="fas fa-globe"></i> HTTP Errors</span>
                                </div>
                            </div>
                        </div>
                    </div>

                    <div id="tcp-analysis">
                    {{if .TCPRetransmissions}}
                    <div class="card">
                        <div class="card-header">
                            <i class="fas fa-redo"></i>
                            <h2>TCP Retransmissions ({{len .TCPRetransmissions}})</h2>
                        </div>
                        <div class="card-body">
                            <table class="data-table">
                                <thead><tr><th>Source</th><th>Destination</th><th>Port</th><th>Action</th></tr></thead>
                                <tbody>
                                    {{range .TCPRetransmissions}}
                                    <tr>
                                        <td><code>{{.SrcIP}}:{{.SrcPort}}</code></td>
                                        <td><code>{{.DstIP}}:{{.DstPort}}</code></td>
                                        <td>{{.DstPort}}</td>
                                        <td><button class="btn btn-sm btn-secondary" onclick="toggleAction(this)">Show Details</button></td>
                                    </tr>
                                    <tr class="action-row">
                                        <td colspan="4">
                                            <div class="action-content">
                                                {{.Explanation}}
                                            </div>
                                        </td>
                                    </tr>
                                    {{end}}
                                </tbody>
                            </table>
                        </div>
                    </div>
                    {{end}}
                    </div>

                    <div id="latency">
                    {{if .HighRTTFlows}}
                    <div class="card">
                        <div class="card-header">
                            <i class="fas fa-clock"></i>
                            <h2>High RTT Flows ({{len .HighRTTFlows}})</h2>
                        </div>
                        <div class="card-body">
                            <table class="data-table">
                                <thead><tr><th>Source</th><th>Destination</th><th>Avg RTT (ms)</th><th>Max RTT (ms)</th><th>Action</th></tr></thead>
                                <tbody>
                                    {{range .HighRTTFlows}}
                                    <tr>
                                        <td><code>{{.SrcIP}}:{{.SrcPort}}</code></td>
                                        <td><code>{{.DstIP}}:{{.DstPort}}</code></td>
                                        <td class="severity-medium">{{printf "%.1f" .AvgRTT}}</td>
                                        <td>{{printf "%.1f" .MaxRTT}}</td>
                                        <td><button class="btn btn-sm btn-secondary" onclick="toggleAction(this)">Show Details</button></td>
                                    </tr>
                                    <tr class="action-row">
                                        <td colspan="5">
                                            <div class="action-content">
                                                {{.Explanation}}
                                            </div>
                                        </td>
                                    </tr>
                                    {{end}}
                                </tbody>
                            </table>
                        </div>
                    </div>
                    {{end}}
                    </div>

                    {{if .HTTPErrors}}
                    <div class="card">
                        <div class="card-header">
                            <i class="fas fa-globe"></i>
                            <h2>HTTP Errors ({{len .HTTPErrors}})</h2>
                        </div>
                        <div class="card-body">
                            <table class="data-table">
                                <thead><tr><th>Method</th><th>URL</th><th>Status</th><th>Source</th><th>Destination</th><th>Action</th></tr></thead>
                                <tbody>
                                    {{range .HTTPErrors}}
                                    <tr>
                                        <td>{{.Method}}</td>
                                        <td><code>{{.URL}}</code></td>
                                        <td class="severity-high">{{.StatusCode}} {{.Reason}}</td>
                                        <td><code>{{.SrcIP}}</code></td>
                                        <td><code>{{.DstIP}}</code></td>
                                        <td><button class="btn btn-sm btn-secondary" onclick="toggleAction(this)">Show Details</button></td>
                                    </tr>
                                    <tr class="action-row">
                                        <td colspan="6">
                                            <div class="action-content">
                                                {{.Explanation}}
                                            </div>
                                        </td>
                                    </tr>
                                    {{end}}
                                </tbody>
                            </table>
                        </div>
                    </div>
                    {{end}}

                    {{if .FailedHandshakes}}
                    <div class="card">
                        <div class="card-header">
                            <i class="fas fa-handshake-slash"></i>
                            <h2>Failed TCP Handshakes ({{len .FailedHandshakes}})</h2>
                        </div>
                        <div class="card-body">
                            <table class="data-table">
                                <thead><tr><th>Source</th><th>Destination</th><th>Port</th><th>Action</th></tr></thead>
                                <tbody>
                                    {{range .FailedHandshakes}}
                                    <tr>
                                        <td><code>{{.SrcIP}}:{{.SrcPort}}</code></td>
                                        <td><code>{{.DstIP}}:{{.DstPort}}</code></td>
                                        <td>{{.DstPort}}</td>
                                        <td><button class="btn btn-sm btn-secondary" onclick="toggleAction(this)">Show Details</button></td>
                                    </tr>
                                    <tr class="action-row">
                                        <td colspan="4">
                                            <div class="action-content">
                                                {{.Explanation}}
                                            </div>
                                        </td>
                                    </tr>
                                    {{end}}
                                </tbody>
                            </table>
                        </div>
                    </div>
                    {{end}}
                </section>
{{end}}`

	return renderPage(getBaseTemplate()+contentTemplate, pageData, outputPath)
}

func generateProtocolsPage(data *ReportData, outputPath string) error {
	pageData := &PageData{
		ReportData:  data,
		CurrentPage: "protocols",
		PageTitle:   "Protocol Analysis",
	}

	contentTemplate := `{{define "content"}}
                <section id="protocols">
                    {{.ProtocolGuide}}

                    <div class="card">
                        <div class="card-header">
                            <i class="fas fa-handshake"></i>
                            <h2>TCP Handshake Analysis</h2>
                        </div>
                        <div class="card-body">
                            <div class="stats-grid" style="grid-template-columns: repeat(4, 1fr);">
                                <div class="stat-card">
                                    <span class="stat-value">{{.TCPHandshakeStats.TotalSYN}}</span>
                                    <span class="stat-label">SYN Packets</span>
                                </div>
                                <div class="stat-card">
                                    <span class="stat-value">{{.TCPHandshakeStats.TotalSYNACK}}</span>
                                    <span class="stat-label">SYN-ACK Packets</span>
                                </div>
                                <div class="stat-card">
                                    <span class="stat-value">{{.TCPHandshakeStats.SuccessfulCount}}</span>
                                    <span class="stat-label">Successful Handshakes</span>
                                </div>
                                <div class="stat-card {{if gt .TCPHandshakeStats.FailedCount 0}}stat-warning{{end}}">
                                    <span class="stat-value">{{.TCPHandshakeStats.FailedCount}}</span>
                                    <span class="stat-label">Failed Handshakes</span>
                                </div>
                            </div>
                        </div>
                    </div>

                    {{if .HTTP2Flows}}
                    <div class="card">
                        <div class="card-header">
                            <i class="fas fa-bolt"></i>
                            <h2>HTTP/2 Flows ({{len .HTTP2Flows}})</h2>
                        </div>
                        <div class="card-body">
                            <table class="data-table">
                                <thead><tr><th>Source</th><th>Destination</th><th>Streams</th><th>Method</th></tr></thead>
                                <tbody>
                                    {{range .HTTP2Flows}}
                                    <tr>
                                        <td><code>{{.SrcIP}}:{{.SrcPort}}</code></td>
                                        <td><code>{{.DstIP}}:{{.DstPort}}</code></td>
                                        <td>{{.StreamCount}}</td>
                                        <td>{{.Method}}</td>
                                    </tr>
                                    {{end}}
                                </tbody>
                            </table>
                        </div>
                    </div>
                    {{end}}

                    {{if .QUICFlows}}
                    <div class="card">
                        <div class="card-header">
                            <i class="fas fa-rocket"></i>
                            <h2>QUIC Flows ({{len .QUICFlows}})</h2>
                        </div>
                        <div class="card-body">
                            <table class="data-table">
                                <thead><tr><th>Source</th><th>Destination</th><th>Version</th><th>SNI</th></tr></thead>
                                <tbody>
                                    {{range .QUICFlows}}
                                    <tr>
                                        <td><code>{{.SrcIP}}:{{.SrcPort}}</code></td>
                                        <td><code>{{.DstIP}}:{{.DstPort}}</code></td>
                                        <td>{{.Version}}</td>
                                        <td>{{.SNI}}</td>
                                    </tr>
                                    {{end}}
                                </tbody>
                            </table>
                        </div>
                    </div>
                    {{end}}
                </section>
{{end}}`

	return renderPage(getBaseTemplate()+contentTemplate, pageData, outputPath)
}

func generateNetworkPage(data *ReportData, outputPath string) error {
	pageData := &PageData{
		ReportData:  data,
		CurrentPage: "network",
		PageTitle:   "Network & Devices",
	}

	contentTemplate := `{{define "content"}}
                <section id="network">
                    {{if .SDWANVendors}}
                    <div class="card">
                        <div class="card-header">
                            <i class="fas fa-building"></i>
                            <h2>SD-WAN Vendors Detected ({{len .SDWANVendors}})</h2>
                        </div>
                        <div class="card-body">
                            <table class="data-table">
                                <thead><tr><th>Vendor</th><th>Confidence</th><th>Detected By</th><th>Packets</th></tr></thead>
                                <tbody>
                                    {{range .SDWANVendors}}
                                    <tr>
                                        <td><strong>{{.Name}}</strong></td>
                                        <td>{{.Confidence}}</td>
                                        <td>{{.DetectedBy}}</td>
                                        <td>{{.PacketCount}}</td>
                                    </tr>
                                    {{end}}
                                </tbody>
                            </table>
                        </div>
                    </div>
                    {{end}}

                    {{if .TunnelFindings}}
                    <div class="card">
                        <div class="card-header">
                            <i class="fas fa-tunnel"></i>
                            <h2>Tunnel Detection ({{len .TunnelFindings}})</h2>
                        </div>
                        <div class="card-body">
                            <table class="data-table">
                                <thead><tr><th>Type</th><th>Source</th><th>Destination</th><th>Inner Protocol</th><th>Packets</th></tr></thead>
                                <tbody>
                                    {{range .TunnelFindings}}
                                    <tr>
                                        <td><span class="badge badge-info">{{.Type}}</span></td>
                                        <td><code>{{.SrcIP}}:{{.SrcPort}}</code></td>
                                        <td><code>{{.DstIP}}:{{.DstPort}}</code></td>
                                        <td>{{.InnerProtocol}}</td>
                                        <td>{{.PacketCount}}</td>
                                    </tr>
                                    {{end}}
                                </tbody>
                            </table>
                        </div>
                    </div>
                    {{end}}

                    {{if .GeoLocations}}
                    <div class="card">
                        <div class="card-header">
                            <i class="fas fa-globe-americas"></i>
                            <h2>Geographic Distribution ({{len .GeoLocations}})</h2>
                        </div>
                        <div class="card-body">
                            <table class="data-table">
                                <thead><tr><th>Country</th><th>Connections</th></tr></thead>
                                <tbody>
                                    {{range .GeoLocations}}
                                    <tr>
                                        <td>{{.Country}}</td>
                                        <td>{{.Count}}</td>
                                    </tr>
                                    {{end}}
                                </tbody>
                            </table>
                        </div>
                    </div>
                    {{end}}

                    {{if .VoIPAnalysis}}
                    <div class="card">
                        <div class="card-header">
                            <i class="fas fa-phone"></i>
                            <h2>VoIP Analysis</h2>
                        </div>
                        <div class="card-body">
                            <p><strong>Total Calls:</strong> {{.VoIPAnalysis.TotalCalls}} | <strong>Established:</strong> {{.VoIPAnalysis.EstablishedCalls}} | <strong>Failed:</strong> {{.VoIPAnalysis.FailedCalls}}</p>
                            <p><strong>RTP Streams:</strong> {{.VoIPAnalysis.TotalRTPStreams}} | <strong>Avg Jitter:</strong> {{printf "%.2f" .VoIPAnalysis.AvgJitter}}ms | <strong>Packet Loss:</strong> {{printf "%.2f" .VoIPAnalysis.PacketLossRate}}%</p>
                            
                            {{if .VoIPAnalysis.SIPCalls}}
                            <h3>SIP Calls</h3>
                            <table class="data-table">
                                <thead><tr><th>Call ID</th><th>From</th><th>To</th><th>State</th><th>Source</th><th>Destination</th></tr></thead>
                                <tbody>
                                    {{range .VoIPAnalysis.SIPCalls}}
                                    <tr>
                                        <td><code>{{.CallID}}</code></td>
                                        <td>{{.FromURI}}</td>
                                        <td>{{.ToURI}}</td>
                                        <td>{{.State}}</td>
                                        <td><code>{{.SrcIP}}</code></td>
                                        <td><code>{{.DstIP}}</code></td>
                                    </tr>
                                    {{end}}
                                </tbody>
                            </table>
                            {{end}}
                        </div>
                    </div>
                    {{end}}
                </section>
{{end}}`

	return renderPage(getBaseTemplate()+contentTemplate, pageData, outputPath)
}

func generateTrafficPage(data *ReportData, outputPath string) error {
	pageData := &PageData{
		ReportData:  data,
		CurrentPage: "traffic",
		PageTitle:   "Traffic Analysis",
	}

	contentTemplate := `{{define "content"}}
                <section id="traffic">
                    {{if .TopFlows}}
                    <div class="card">
                        <div class="card-header">
                            <i class="fas fa-stream"></i>
                            <h2>Top Traffic Flows ({{len .TopFlows}})</h2>
                        </div>
                        <div class="card-body">
                            <table class="data-table">
                                <thead><tr><th>Source</th><th>Destination</th><th>Protocol</th><th>Bytes</th><th>Packets</th></tr></thead>
                                <tbody>
                                    {{range .TopFlows}}
                                    <tr>
                                        <td><code>{{.SrcIP}}:{{.SrcPort}}</code></td>
                                        <td><code>{{.DstIP}}:{{.DstPort}}</code></td>
                                        <td>{{.Protocol}}</td>
                                        <td>{{.BytesFormatted}}</td>
                                        <td>{{printf "%.1f" .Percentage}}%</td>
                                    </tr>
                                    {{end}}
                                </tbody>
                            </table>
                        </div>
                    </div>
                    {{end}}

                    {{if .TopTalkers}}
                    <div class="card">
                        <div class="card-header">
                            <i class="fas fa-users"></i>
                            <h2>Top Talkers ({{len .TopTalkers}})</h2>
                        </div>
                        <div class="card-body">
                            <table class="data-table">
                                <thead><tr><th>IP Address</th><th>Type</th><th>Bytes</th><th>Percentage</th></tr></thead>
                                <tbody>
                                    {{range .TopTalkers}}
                                    <tr>
                                        <td><code>{{.IP}}</code></td>
                                        <td>{{.Type}}</td>
                                        <td>{{.Bytes}}</td>
                                        <td>{{printf "%.1f" .Percent}}%</td>
                                    </tr>
                                    {{end}}
                                </tbody>
                            </table>
                        </div>
                    </div>
                    {{end}}

                    {{if .ProtocolStats}}
                    <div class="card">
                        <div class="card-header">
                            <i class="fas fa-chart-pie"></i>
                            <h2>Protocol Distribution ({{len .ProtocolStats}})</h2>
                        </div>
                        <div class="card-body">
                            <table class="data-table">
                                <thead><tr><th>Protocol</th><th>Bytes</th><th>Percentage</th></tr></thead>
                                <tbody>
                                    {{range .ProtocolStats}}
                                    <tr>
                                        <td><strong>{{.Protocol}}</strong></td>
                                        <td>{{.Bytes}}</td>
                                        <td>{{printf "%.1f" .Percent}}%</td>
                                    </tr>
                                    {{end}}
                                </tbody>
                            </table>
                        </div>
                    </div>
                    {{end}}

                    {{if .BandwidthReport}}
                    <div class="card">
                        <div class="card-header">
                            <i class="fas fa-tachometer-alt"></i>
                            <h2>Bandwidth Analysis</h2>
                        </div>
                        <div class="card-body">
                            <div class="stats-grid">
                                <div class="stat-card">
                                    <span class="stat-value">{{.BandwidthReport.PeakBandwidth}}</span>
                                    <span class="stat-label">Peak Bandwidth</span>
                                </div>
                                <div class="stat-card">
                                    <span class="stat-value">{{.BandwidthReport.AvgBandwidth}}</span>
                                    <span class="stat-label">Average Bandwidth</span>
                                </div>
                                <div class="stat-card">
                                    <span class="stat-value">{{.BandwidthReport.TotalBytes}}</span>
                                    <span class="stat-label">Total Data</span>
                                </div>
                                <div class="stat-card">
                                    <span class="stat-value">{{.BandwidthReport.Duration}}</span>
                                    <span class="stat-label">Capture Duration</span>
                                </div>
                            </div>
                        </div>
                    </div>
                    {{end}}
                </section>
{{end}}`

	return renderPage(getBaseTemplate()+contentTemplate, pageData, outputPath)
}

func generateVisualizationsPage(data *ReportData, outputPath string) error {
	pageData := &PageData{
		ReportData:  data,
		CurrentPage: "visualizations",
		PageTitle:   "Visualizations",
	}

	contentTemplate := fmt.Sprintf(`{{define "content"}}
                <section id="visualizations">
                    <div class="card">
                        <div class="card-header">
                            <i class="fas fa-chart-pie"></i>
                            <h2>Protocol Distribution</h2>
                        </div>
                        <div class="card-body">
                            <div id="protocol-chart" class="viz-container" style="height: 350px;"></div>
                        </div>
                    </div>

                    <div class="card">
                        <div class="card-header">
                            <i class="fas fa-project-diagram"></i>
                            <h2>Network Topology</h2>
                        </div>
                        <div class="card-body">
                            <div id="network-diagram" class="viz-container" style="height: 600px;"></div>
                        </div>
                    </div>

                    <div class="card">
                        <div class="card-header">
                            <i class="fas fa-history"></i>
                            <h2>Traffic Timeline</h2>
                        </div>
                        <div class="card-body">
                            <div id="timeline" class="viz-container" style="height: 400px;"></div>
                        </div>
                    </div>

                    <div class="card">
                        <div class="card-header">
                            <i class="fas fa-stream"></i>
                            <h2>Traffic Flow (Sankey)</h2>
                        </div>
                        <div class="card-body">
                            <div id="sankey-diagram" class="viz-container" style="height: 500px;"></div>
                        </div>
                    </div>

                    <div class="card">
                        <div class="card-header">
                            <i class="fas fa-chart-bar"></i>
                            <h2>RTT Distribution</h2>
                        </div>
                        <div class="card-body">
                            <div id="rtt-histogram" class="viz-container" style="height: 350px;"></div>
                        </div>
                    </div>
                </section>

                <script>
                    // Inject visualization data
                    const networkData = %s;
                    const timelineData = %s;
                    const sankeyData = %s;
                    const protocolData = %s;
                    const topTalkersData = %s;
                    const rttData = %s;

                    // Initialize visualizations when DOM is ready
                    document.addEventListener('DOMContentLoaded', function() {
                        if (typeof renderNetworkDiagram === 'function') renderNetworkDiagram();
                        if (typeof renderTimeline === 'function') renderTimeline();
                        if (typeof renderSankeyDiagram === 'function') renderSankeyDiagram();
                        if (typeof renderProtocolChart === 'function') renderProtocolChart();
                        if (typeof renderTopTalkersChart === 'function') renderTopTalkersChart();
                        if (typeof renderRTTHistogram === 'function') renderRTTHistogram();
                    });
                </script>
{{end}}`, "{{.NetworkDataJSON}}", "{{.TimelineDataJSON}}", "{{.SankeyDataJSON}}",
		"{{.ProtocolStatsJSON}}", "{{.TopTalkersJSON}}", "{{.RTTHistogramJSON}}")

	return renderPage(getBaseTemplate()+contentTemplate, pageData, outputPath)
}
