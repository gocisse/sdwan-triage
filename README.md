# SD-WAN Network Triage

[![Release](https://img.shields.io/github/v/release/gocisse/sdwan-triage)](https://github.com/gocisse/sdwan-triage/releases/latest)
[![Go Version](https://img.shields.io/badge/Go-1.21+-00ADD8?logo=go)](https://golang.org/)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-macOS%20|%20Linux%20|%20Windows-lightgrey)](https://github.com/gocisse/sdwan-triage/releases)

**Comprehensive PCAP analysis tool for SD-WAN networks** with advanced security detection, performance monitoring, and interactive D3.js visualizations. Designed for network engineers, security analysts, and NOC teams.

![SD-WAN Triage Dashboard](https://raw.githubusercontent.com/gocisse/sdwan-triage/main/docs/dashboard-preview.png)

## 🚀 Quick Start

```bash
# Download latest release (macOS Apple Silicon example)
curl -LO https://github.com/gocisse/sdwan-triage/releases/latest/download/sdwan-triage-darwin-arm64.zip
unzip sdwan-triage-darwin-arm64.zip
chmod +x sdwan-triage-darwin-arm64

# Analyze a PCAP file and generate HTML report
./sdwan-triage-darwin-arm64 -html report.html capture.pcap

# Open the interactive report in your browser
open report.html
```

## ✨ Features

### 🔒 Security Analysis
| Feature | Description |
|---------|-------------|
| **DDoS Detection** | SYN flood, UDP flood, ICMP flood with severity levels |
| **Port Scanning** | Horizontal, vertical, and block scan detection |
| **TLS Security** | Weak ciphers, outdated protocols, certificate analysis |
| **Malware Indicators** | IOC checking with custom databases |
| **BGP Hijack Heuristics** | Route anomaly detection |
| **GeoIP Analysis** | Country-based traffic distribution with IP lists |

### 📊 Performance Monitoring
| Feature | Description |
|---------|-------------|
| **TCP Handshake Analysis** | SYN → SYN-ACK → ACK tracking with color-coded states |
| **Retransmission Analysis** | Identify packet loss and network congestion |
| **RTT Distribution** | Latency histogram visualization |
| **Bandwidth Tracking** | Per-flow and aggregate throughput |
| **Jitter & Packet Loss** | VoIP/RTP quality metrics |
| **Wireshark Filters** | Auto-generated filters for each flow |

### 🌐 Protocol Analysis
| Feature | Description |
|---------|-------------|
| **DNS Anomalies** | NXDOMAIN, timeouts, DGA detection |
| **HTTP/HTTPS** | Status codes, errors, HTTP/2 & QUIC |
| **VoIP/SIP** | Call tracking with codec identification |
| **RTP/RTCP** | Media stream quality analysis |

### 🔗 Tunnel & Encapsulation Detection
| Protocol | Details |
|----------|---------|
| **VXLAN** | VNI extraction, overlay detection |
| **GRE/NVGRE/ERSPAN** | Tunnel identification |
| **MPLS** | Label analysis |
| **IPsec** | ESP/AH detection |
| **GTP-U/GTP-C** | Mobile network tunnels |
| **VPN** | L2TP, OpenVPN, WireGuard |

### 🏢 SD-WAN Vendor Detection
Automatic identification with vendor-specific Wireshark filters:

| Vendor | Ports | Protocol |
|--------|-------|----------|
| **Cisco Viptela** | UDP 12346 (data), UDP/TCP 23456 (control) | DTLS |
| **VMware VeloCloud** | UDP 2426 | VCMP |
| **Fortinet SD-WAN** | UDP/TCP 541 | Proprietary |
| **Palo Alto Prisma** | UDP 4501 | IPsec |
| **Silver Peak** | UDP 4163 | Proprietary |
| **Aruba EdgeConnect** | UDP 4500/500 | IPsec NAT-T |
| **Versa Networks** | UDP 4790 | Proprietary |
| **Citrix SD-WAN** | UDP 4980 | Proprietary |

### 📈 Interactive Visualizations (HTML Report)
- **Timeline** - Event filtering with zoom
- **Sankey Diagram** - Source → destination flow visualization
- **RTT Histogram** - Latency distribution
- **Protocol Breakdown** - Traffic composition charts
- **Bandwidth Graphs** - Utilization over time
- **Device Fingerprinting** - OS and device type detection

## 📦 Installation

### Pre-built Binaries

Download from [Releases](https://github.com/gocisse/sdwan-triage/releases/latest):

```bash
# macOS (Apple Silicon)
curl -LO https://github.com/gocisse/sdwan-triage/releases/latest/download/sdwan-triage-darwin-arm64.zip

# macOS (Intel)
curl -LO https://github.com/gocisse/sdwan-triage/releases/latest/download/sdwan-triage-darwin-amd64.zip

# Linux (x86_64)
curl -LO https://github.com/gocisse/sdwan-triage/releases/latest/download/sdwan-triage-linux-amd64.zip

# Linux (ARM64)
curl -LO https://github.com/gocisse/sdwan-triage/releases/latest/download/sdwan-triage-linux-arm64.zip

# Windows (x86_64)
curl -LO https://github.com/gocisse/sdwan-triage/releases/latest/download/sdwan-triage-windows-amd64.zip
```

### Build from Source

```bash
# Clone repository
git clone https://github.com/gocisse/sdwan-triage.git
cd sdwan-triage

# Build
go build -o sdwan-triage ./cmd/sdwan-triage

# Verify
./sdwan-triage -help
```

**Requirements:** Go 1.21+

## 🎯 Usage

### Basic Commands

```bash
# Console output with summary
sdwan-triage capture.pcap

# Generate interactive HTML report (recommended)
sdwan-triage -html report.html capture.pcap

# Multi-page HTML report
sdwan-triage -multi-page-html ./report-dir capture.pcap

# Export to JSON for automation
sdwan-triage -json capture.pcap > results.json

# Export to CSV for spreadsheet analysis
sdwan-triage -csv findings.csv capture.pcap

# Generate PDF report (requires wkhtmltopdf)
sdwan-triage -pdf report.pdf capture.pcap

# Simple plain English report for non-technical users
sdwan-triage -simple capture.pcap
```

### Filtering Options

```bash
# Filter by source IP
sdwan-triage -src-ip 192.168.1.100 capture.pcap

# Filter by destination IP
sdwan-triage -dst-ip 10.0.0.50 capture.pcap

# Filter by service (port name or number)
sdwan-triage -service https capture.pcap
sdwan-triage -service 443 capture.pcap
sdwan-triage -service dns capture.pcap

# Filter by protocol
sdwan-triage -protocol tcp capture.pcap
sdwan-triage -protocol udp capture.pcap
```

### Advanced Analysis

```bash
# Enable QoS/DSCP analysis
sdwan-triage -qos-analysis -html qos-report.html capture.pcap

# Show detailed TCP handshake analysis
sdwan-triage -show-handshakes capture.pcap

# Show only failed handshakes for troubleshooting
sdwan-triage -failed-only capture.pcap

# Enable deep application identification
sdwan-triage -app-identify capture.pcap

# Verbose debug output
sdwan-triage -verbose capture.pcap
```

### Network Features (Require Internet)

```bash
# Perform traceroute to discovered destinations
sdwan-triage -trace-path capture.pcap

# Check BGP routing for hijack indicators
sdwan-triage -bgp-check capture.pcap
```

### Multi-File Comparison

```bash
# Compare multiple PCAP files
sdwan-triage -compare before.pcap after.pcap
```

## 📋 Command Reference

| Option | Description |
|--------|-------------|
| `-html <file>` | Generate interactive HTML report with D3.js visualizations |
| `-multi-page-html <dir>` | Generate multi-page HTML report in directory |
| `-json` | Output results in JSON format |
| `-csv <file>` | Export findings to CSV files |
| `-pdf <file>` | Export to PDF (requires wkhtmltopdf) |
| `-simple` | Plain English report for non-technical users |
| `-config <path>` | Use config: default, performance, security, or file path |
| `-src-ip <ip>` | Filter by source IP address |
| `-dst-ip <ip>` | Filter by destination IP address |
| `-service <port>` | Filter by service port or name |
| `-protocol <proto>` | Filter by protocol: tcp or udp |
| `-qos-analysis` | Enable QoS/DSCP traffic class analysis |
| `-show-handshakes` | Display detailed TCP handshake analysis |
| `-handshake-timeout <N>` | Timeout for TCP handshake (default: 3s) |
| `-failed-only` | Show only failed TCP handshakes |
| `-app-identify` | Enable deep application identification |
| `-trace-path` | Perform traceroute to destinations |
| `-bgp-check` | Check BGP routing data |
| `-compare` | Compare multiple PCAP files |
| `-verbose` | Enable verbose/debug output |
| `-debug-html` | Write raw HTML for troubleshooting |
| `-help` | Show help message |

## 📊 Example Output

### Console Summary
```
SD-WAN Network Triage v4.0.0
Analyzing: capture.pcap
Processed 78613 packets in 1.7s

═══════════════════════════════════════════════════════════════
              SD-WAN NETWORK TRIAGE - EXECUTIVE SUMMARY
═══════════════════════════════════════════════════════════════

✗ NETWORK HEALTH: CRITICAL - Immediate attention required

FINDINGS SUMMARY:
  • DNS Anomalies:        43
  • TCP Retransmissions:  1240
  • Failed Handshakes:    31
  • HTTP Errors:          6
  • TLS Certificates:     1
  • Suspicious Traffic:   8
  • High RTT Flows:       254
  • Devices Detected:     41

TRAFFIC SUMMARY:
  • Total Bytes:          30.3 MB
  • TLS Connections:      618
  • HTTP/2 Flows:         147
  • QUIC Flows:           6
```

### HTML Report Features
The interactive HTML report includes:
- **Executive Summary** with risk scoring
- **Device Fingerprinting** table with OS detection
- **Geographic Distribution** with country breakdown
- **Top Traffic Flows** with bandwidth analysis
- **Security Findings** with severity levels
- **Wireshark Filters** for each finding
- **Protocol Troubleshooting Guides**

## 🏗️ Project Structure

```
sdwan-triage/
├── cmd/sdwan-triage/     # Main application entry point
├── pkg/
│   ├── analyzer/         # PCAP processing and analysis
│   ├── detector/         # Protocol and security detectors
│   ├── models/           # Data structures
│   ├── output/           # Report generators (HTML, JSON, CSV, PDF)
│   └── safety/           # Validation and safety checks
├── releases/             # Pre-built binaries
└── templates/            # HTML report templates
```

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- [gopacket](https://github.com/google/gopacket) - Packet processing library
- [D3.js](https://d3js.org/) - Interactive visualizations
- SD-WAN vendor communities for port and protocol documentation

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/gocisse/sdwan-triage/issues)
- **Discussions**: [GitHub Discussions](https://github.com/gocisse/sdwan-triage/discussions)

---

**Made with ❤️ for the network engineering community**
