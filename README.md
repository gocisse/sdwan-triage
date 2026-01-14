# SD-WAN Triage v2.9.0

[![GitHub release](https://img.shields.io/github/v/release/gocisse/sdwan-triage.svg)](https://github.com/gocisse/sdwan-triage/releases/)
[![Go Report Card](https://goreportcard.com/badge/github.com/gocisse/sdwan-triage)](https://goreportcard.com/report/github.com/gocisse/sdwan-triage)
[![Go Version](https://img.shields.io/badge/Go-1.23.3+-00ADD8?logo=go)](https://go.dev/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

> **Comprehensive PCAP analysis tool for SD-WAN networks with advanced security detection, performance monitoring, and interactive D3.js visualizations.**

---

## 📋 Overview

**SD-WAN Triage** is a powerful network analysis tool designed specifically for SD-WAN environments. It performs deep packet inspection on PCAP files to identify network issues, security threats, performance bottlenecks, and traffic patterns. The tool generates interactive HTML reports with D3.js visualizations, making complex network data easy to understand and actionable.

### Key Features

- 🔍 **Comprehensive PCAP Analysis** - Deep packet inspection with protocol-aware parsing
- 🛡️ **Security Threat Detection** - DDoS, port scanning, malware IOCs, TLS weaknesses
- 📊 **Interactive D3.js Reports** - Timeline, Sankey diagrams, RTT histograms, network topology
- 🌐 **SD-WAN Focused** - Vendor detection (Cisco, VMware, Fortinet, Palo Alto, etc.)
- 🔐 **Tunnel Analysis** - VXLAN, GRE, MPLS, IPsec, GTP, L2TP, OpenVPN, WireGuard
- 📞 **VoIP/RTP Analysis** - SIP call tracking, jitter, packet loss, quality metrics
- 🚀 **Performance Monitoring** - TCP retransmissions, RTT analysis, bandwidth tracking
- 🌍 **GeoIP Analysis** - IP geolocation and country-based traffic distribution
- 📈 **QoS/DSCP Analysis** - Traffic class identification and prioritization verification
- 🎯 **Application Identification** - HTTP/HTTPS, DNS, QUIC, HTTP/2 detection

---

## 🚀 Installation

### Prerequisites

- **Go 1.23.3+** (only required for building from source)
- **wkhtmltopdf** (optional, only for PDF export)

### Option 1: Download Pre-built Binaries (Recommended)

Download the latest release for your platform from the [GitHub Releases](https://github.com/gocisse/sdwan-triage/releases/) page:

```bash
# Linux/macOS
wget https://github.com/gocisse/sdwan-triage/releases/download/v2.9.0/sdwan-triage-linux-amd64
chmod +x sdwan-triage-linux-amd64
mv sdwan-triage-linux-amd64 /usr/local/bin/sdwan-triage

# macOS (ARM64)
wget https://github.com/gocisse/sdwan-triage/releases/download/v2.9.0/sdwan-triage-darwin-arm64
chmod +x sdwan-triage-darwin-arm64
mv sdwan-triage-darwin-arm64 /usr/local/bin/sdwan-triage
```

### Option 2: Build from Source

```bash
# Clone the repository
git clone https://github.com/gocisse/sdwan-triage.git
cd sdwan-triage

# Build the binary
go build -o sdwan-triage ./cmd/sdwan-triage

# Optional: Install to system path
sudo mv sdwan-triage /usr/local/bin/
```

### Optional: Install wkhtmltopdf for PDF Export

```bash
# Ubuntu/Debian
sudo apt-get install wkhtmltopdf

# macOS
brew install wkhtmltopdf

# RHEL/CentOS
sudo yum install wkhtmltopdf
```

---

## ⚡ Quick Start

Analyze a PCAP file and generate an interactive HTML report:

```bash
./sdwan-triage -html report.html sample.pcap
```

**Expected Output:**
```
SD-WAN Network Triage v2.9.0
Analyzing: sample.pcap
✓ Processed 17,564 packets in 2.3s
✓ Generated report.html
```

Open `report.html` in your browser to view:
- Interactive timeline visualization
- Network topology Sankey diagram
- RTT distribution histogram
- Security findings and anomalies
- Performance metrics and recommendations

---

## ✨ Features

### Security Analysis
- ✅ **DDoS Detection** - SYN flood, UDP flood, ICMP flood with configurable thresholds
- ✅ **Port Scanning Detection** - Horizontal, vertical, and block scan patterns
- ✅ **Malware Indicators (IOC)** - IP and domain-based threat detection with custom IOC databases
- ✅ **TLS Security Analysis** - Weak cipher suites, outdated protocols (SSL 3.0, TLS 1.0/1.1)
- ✅ **BGP Hijack Heuristics** - Suspicious BGP announcements and AS path anomalies
- ✅ **GeoIP Analysis** - IP geolocation with country-based traffic distribution

### Network Performance
- ✅ **TCP Retransmission Analysis** - Identifies lossy connections and network congestion
- ✅ **RTT Distribution** - Round-trip time analysis with histogram visualization
- ✅ **Failed Handshake Detection** - TCP connection establishment issues
- ✅ **Bandwidth Tracking** - Per-flow and aggregate bandwidth utilization
- ✅ **QoS/DSCP Analysis** - Traffic class identification and prioritization verification
- ✅ **Jitter & Packet Loss** - VoIP/RTP quality metrics

### Protocol Analysis
- ✅ **DNS Anomaly Detection** - NXDOMAIN, timeouts, suspicious queries, DGA detection
- ✅ **HTTP/HTTPS Analysis** - Status codes, errors, TLS certificate validation
- ✅ **HTTP/2 & QUIC Detection** - Modern protocol identification
- ✅ **VoIP/SIP Analysis** - Call tracking, codec identification, registration monitoring
- ✅ **RTP/RTCP Analysis** - Media stream quality, jitter, packet loss

### Tunnel & Encapsulation
- ✅ **VXLAN Analysis** - VNI extraction, overlay network detection
- ✅ **GRE Tunnels** - GRE, NVGRE, ERSPAN detection
- ✅ **MPLS Label Analysis** - Label stack inspection and tracking
- ✅ **IPsec Detection** - ESP and AH protocol identification
- ✅ **GTP Tunnels** - GTP-U and GTP-C for mobile networks
- ✅ **L2TP, OpenVPN, WireGuard** - VPN protocol detection with DPI (v2.8.0+)
- ✅ **False Positive Prevention** - Smart whitelisting for DNS servers and common services (v2.9.0)

### SD-WAN Specific
- ✅ **Vendor Detection** - Cisco (Viptela), VMware (VeloCloud), Fortinet, Palo Alto Prisma, Silver Peak, Citrix, Versa
- ✅ **Application Identification** - SNI-based and port-based application detection
- ✅ **Device Fingerprinting** - OS and device type identification
- ✅ **ARP Conflict Detection** - IP/MAC address conflicts

### Visualization & Reporting
- ✅ **Interactive Timeline** - D3.js-powered event timeline with filtering
- ✅ **Sankey Diagram** - Flow visualization showing source → destination relationships
- ✅ **RTT Histogram** - Round-trip time distribution chart
- ✅ **Protocol Breakdown** - Traffic composition pie charts
- ✅ **Bandwidth Graphs** - Time-series bandwidth utilization
- ✅ **Exportable Reports** - HTML, JSON, CSV, PDF formats

---

## 📖 Usage

### Basic Commands

```bash
# Basic analysis with console output
./sdwan-triage capture.pcap

# Generate interactive HTML report
./sdwan-triage -html report.html capture.pcap

# Export to JSON for automation/scripting
./sdwan-triage -json capture.pcap > results.json

# Export to CSV for spreadsheet analysis
./sdwan-triage -csv findings.csv capture.pcap

# Generate PDF report (requires wkhtmltopdf)
./sdwan-triage -pdf report.pdf capture.pcap
```

### Filtering Options

```bash
# Filter by source IP address
./sdwan-triage -src-ip 192.168.1.100 capture.pcap

# Filter by destination IP address
./sdwan-triage -dst-ip 10.0.0.50 capture.pcap

# Filter by service/port (name or number)
./sdwan-triage -service https capture.pcap
./sdwan-triage -service 443 capture.pcap

# Filter by protocol
./sdwan-triage -protocol tcp capture.pcap
./sdwan-triage -protocol udp capture.pcap

# Combine multiple filters
./sdwan-triage -src-ip 192.168.1.100 -service https -html report.html capture.pcap
```

### Advanced Options

```bash
# Enable QoS/DSCP analysis
./sdwan-triage -qos-analysis capture.pcap

# Enable verbose/debug output
./sdwan-triage -verbose capture.pcap

# Use custom report configuration
./sdwan-triage -config security -html report.html capture.pcap
./sdwan-triage -config performance -html report.html capture.pcap

# Combine multiple output formats
./sdwan-triage -html report.html -json -csv findings.csv capture.pcap
```

### Real-World Examples

```bash
# Analyze SD-WAN traffic for security threats
./sdwan-triage -html security-report.html -config security sdwan-capture.pcap

# Troubleshoot VoIP quality issues
./sdwan-triage -service sip -html voip-analysis.html call-quality.pcap

# Investigate network performance degradation
./sdwan-triage -qos-analysis -html performance.html slow-network.pcap

# Detect port scanning activity from specific IP
./sdwan-triage -src-ip 203.0.113.50 -html scan-report.html suspicious.pcap

# Analyze tunnel encapsulation in SD-WAN overlay
./sdwan-triage -html tunnel-report.html overlay-traffic.pcap
```

---

## 📊 Output Formats

### HTML Report (Recommended)
**Use Case:** Interactive analysis, presentations, detailed investigation

**Features:**
- Interactive D3.js visualizations (timeline, Sankey, histograms)
- Collapsible sections for easy navigation
- Color-coded severity levels
- Embedded CSS and JavaScript (single-file portability)
- Dark/light theme support
- Export-friendly (print to PDF from browser)

**Example:**
```bash
./sdwan-triage -html report.html capture.pcap
```

### JSON Output
**Use Case:** Automation, scripting, integration with SIEM/monitoring tools

**Features:**
- Structured data format
- All findings and metrics included
- Easy to parse with `jq`, Python, or other tools
- Suitable for CI/CD pipelines

**Example:**
```bash
./sdwan-triage -json capture.pcap | jq '.dns_anomalies'
```

### CSV Export
**Use Case:** Spreadsheet analysis, data import, reporting

**Features:**
- Separate CSV files for each finding type
- Compatible with Excel, Google Sheets, databases
- Easy filtering and sorting
- Suitable for long-term archival

**Example:**
```bash
./sdwan-triage -csv findings.csv capture.pcap
# Generates: findings_dns.csv, findings_tcp.csv, findings_security.csv, etc.
```

### PDF Report
**Use Case:** Documentation, compliance, offline sharing

**Features:**
- Professional formatting
- Includes all findings and visualizations
- Suitable for audit trails and compliance reports
- Requires `wkhtmltopdf` installed

**Example:**
```bash
./sdwan-triage -pdf report.pdf capture.pcap
```

---

## 🏗️ Architecture

### Processing Pipeline

```
┌─────────────┐
│ PCAP File   │
└──────┬──────┘
       │
       ▼
┌─────────────────────────────────────────┐
│  Packet Capture Reader (gopacket)      │
│  - Parses PCAP/PCAPNG formats          │
│  - Extracts packet metadata             │
└──────┬──────────────────────────────────┘
       │
       ▼
┌─────────────────────────────────────────┐
│  Protocol Analyzers (pkg/detector/)    │
│  ├─ TCP/UDP/ICMP Analysis              │
│  ├─ DNS/HTTP/TLS Parsing               │
│  ├─ Security Detectors (DDoS, Scans)   │
│  ├─ Tunnel Analyzers (VXLAN, GRE)     │
│  ├─ VoIP/RTP Quality Metrics           │
│  └─ SD-WAN Vendor Detection            │
└──────┬──────────────────────────────────┘
       │
       ▼
┌─────────────────────────────────────────┐
│  Analysis Engine (pkg/analyzer/)       │
│  - Correlates findings across layers   │
│  - Calculates metrics (RTT, jitter)    │
│  - Identifies anomalies and patterns   │
│  - Builds timeline and flow graphs     │
└──────┬──────────────────────────────────┘
       │
       ▼
┌─────────────────────────────────────────┐
│  Report Generator (pkg/output/)        │
│  ├─ HTML: D3.js visualizations         │
│  ├─ JSON: Structured data              │
│  ├─ CSV: Tabular exports               │
│  └─ PDF: Formatted documents           │
└──────┬──────────────────────────────────┘
       │
       ▼
┌─────────────┐
│ Output File │
└─────────────┘
```

### Key Components

- **`cmd/sdwan-triage/`** - Command-line interface and main entry point
- **`pkg/analyzer/`** - Core analysis engine and packet processing
- **`pkg/detector/`** - Protocol-specific analyzers and security detectors
- **`pkg/models/`** - Data structures and report models
- **`pkg/output/`** - Report generation (HTML, JSON, CSV, PDF)

---

## 🤝 Contributing

We welcome contributions! Here's how you can help:

### Reporting Bugs

1. Check the [Issues](https://github.com/gocisse/sdwan-triage/issues) page for existing reports
2. Create a new issue with:
   - Clear description of the problem
   - Steps to reproduce
   - Expected vs. actual behavior
   - Sample PCAP file (if possible)
   - Version information (`./sdwan-triage -help`)

### Requesting Features

1. Open a [Feature Request](https://github.com/gocisse/sdwan-triage/issues/new) issue
2. Describe the use case and expected behavior
3. Provide examples or references if applicable

### Submitting Pull Requests

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes with clear commit messages
4. Add tests for new functionality
5. Ensure all tests pass (`go test ./...`)
6. Run linter (`golangci-lint run`)
7. Submit a pull request with a clear description

### Development Setup

```bash
# Clone your fork
git clone https://github.com/YOUR_USERNAME/sdwan-triage.git
cd sdwan-triage

# Install dependencies
go mod download

# Run tests
go test ./...

# Build
go build -o sdwan-triage ./cmd/sdwan-triage

# Run linter (optional)
golangci-lint run
```

---

## 📄 License

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.

```
MIT License

Copyright (c) 2025 gocisse

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

**SPDX-License-Identifier:** MIT

---

## 🔗 Links

- **GitHub Repository:** [https://github.com/gocisse/sdwan-triage](https://github.com/gocisse/sdwan-triage)
- **Issue Tracker:** [https://github.com/gocisse/sdwan-triage/issues](https://github.com/gocisse/sdwan-triage/issues)
- **Releases:** [https://github.com/gocisse/sdwan-triage/releases](https://github.com/gocisse/sdwan-triage/releases)
- **Documentation:** [FEATURE_VERIFICATION_REPORT.md](FEATURE_VERIFICATION_REPORT.md)

---

## 🙏 Acknowledgments

- **gopacket** - Packet processing library by Google
- **D3.js** - Data visualization framework
- **gofpdf** - PDF generation library
- **fatih/color** - Terminal color output

---

## 📞 Support

For questions, issues, or feature requests:
- 📧 Open an issue on [GitHub](https://github.com/gocisse/sdwan-triage/issues)
- 💬 Check existing [discussions](https://github.com/gocisse/sdwan-triage/discussions)
- 📖 Read the [Feature Verification Report](FEATURE_VERIFICATION_REPORT.md)

---

**Built with ❤️ for network engineers and security professionals**
