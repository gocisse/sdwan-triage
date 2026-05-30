<p align="center">
  <img src="Pharaoh.svg.png" alt="SD-WAN Triage Tool" width="180" />
</p>

<h1 align="center">SD-WAN Triage Tool</h1>

<p align="center">
  <strong>The Forensic Platform for SD-WAN Troubleshooting & Security Analysis</strong>
</p>

<p align="center">
  <a href="https://github.com/gocisse/sdwan-triage/releases/tag/v6.2.0.0"><img src="https://img.shields.io/badge/Release-v6.2.0-blue?style=for-the-badge" alt="Release v6.2.0" /></a>
  <a href="https://go.dev/"><img src="https://img.shields.io/badge/Go-1.25-00ADD8?style=for-the-badge&logo=go&logoColor=white" alt="Go Version" /></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" alt="License: MIT" /></a>
  <a href="#platform-support"><img src="https://img.shields.io/badge/Platform-Mac%20%7C%20Linux%20%7C%20Win-orange?style=for-the-badge" alt="Platform: Mac/Linux/Win" /></a>
</p>

---

## Executive Summary

**SD-WAN Triage** is a single-binary forensic platform for offline PCAP analysis. Upload a packet capture, and within seconds receive a comprehensive network health assessment — spanning security threats, performance bottlenecks, protocol anomalies, and device fingerprinting — all in an interactive web dashboard or detailed CLI report.

What sets it apart is **LAN vs WAN Path Integrity Verification**: capture traffic on both sides of the SD-WAN edge, and the tool will automatically correlate packets, detect what was dropped, modified, or NAT'd in transit, and compute a **Path Integrity Score** that quantifies how faithfully the SD-WAN overlay is delivering your traffic.

**Zero dependencies. No agents. No cloud. Just one binary and your PCAP.**

---

## Key Features

### 🛡️ Threat Intelligence Integration
Cross-reference every packet against **STIX 2.1** threat feeds. Load directories of IOC bundles and instantly flag C2 servers, malware domains, botnet nodes, phishing infrastructure, and ransomware indicators — all with O(1) map lookups for zero performance penalty.

### 🔍 LAN vs WAN Comparison
Automated **streaming packet correlation** across two capture files. Identifies dropped packets, TTL/DSCP modifications, NAT translations, failed handshakes, retransmission storms, and latency spikes. Produces a **Forensic Comparison Summary** with one-way latency percentiles and flow-level drop analysis.

### 🗺️ GeoIP Visualization
Every external IP is geolocated using an **embedded MaxMind GeoLite2 database** (compiled into the binary). The web dashboard renders an interactive world map of traffic flows with country, city, and coordinate data.

### 🔐 JA3/JA3S Fingerprinting
Extracts TLS client (JA3) and server (JA3S) fingerprints from handshakes. Matches against known malware, bot, and application fingerprint databases. Displays hashes with one-click copy and direct links to abuse.ch lookup.

### 📊 Interactive Timeline
Click and drag across the packet-rate histogram to **time-filter all panels** simultaneously — findings, conversations, protocol stats, and the flow table all respond to the selected time window. Press Escape to reset.

### 🎓 Wireshark Academy
Every finding card is a **3-step guided troubleshooting workflow** (Verify → Diagnose → Resolve) with persistent checklists, risk warnings, vendor-specific CLI commands, and an educational Wireshark comparison modal featuring interactive TCP header SVG diagrams.

### 🌐 Global Filtering
Real-time filtering by Source IP, Destination IP, Port/Service, and Protocol directly in the Web UI. Partial matching (e.g., `10.0` matches all IPs in that subnet), service name resolution (e.g., `https` → port 443), and composable stacking with the timeline scrubber.

### 📡 35+ Protocol Analyzers
DDoS detection, port scanning, DNS tunneling, C2 beaconing, TCP anomalies (retransmissions, zero window, out-of-order), DHCP rogue servers, NTP amplification, ARP spoofing, VRRP/HSRP/STP, ICMP anomalies, SIP/RTP voice quality, and more.

---

## Installation

### Quick Start (Binaries)

Download the latest release for your platform from [GitHub Releases](https://github.com/gocisse/sdwan-triage/releases/latest):

**macOS (Apple Silicon)**
```bash
curl -LO https://github.com/gocisse/sdwan-triage/releases/download/v6.2.0.0/sdwan-triage-v6.2.0.0-darwin-arm64.tar.gz
tar xzf sdwan-triage-v6.2.0.0-darwin-arm64.tar.gz
chmod +x sdwan-triage-darwin-arm64
./sdwan-triage-darwin-arm64 -web
```

**macOS (Intel)**
```bash
curl -LO https://github.com/gocisse/sdwan-triage/releases/download/v6.2.0.0/sdwan-triage-v6.2.0.0-darwin-amd64.tar.gz
tar xzf sdwan-triage-v6.2.0.0-darwin-amd64.tar.gz
chmod +x sdwan-triage-darwin-amd64
./sdwan-triage-darwin-amd64 -web
```

**Linux (amd64)**
```bash
curl -LO https://github.com/gocisse/sdwan-triage/releases/download/v6.2.0.0/sdwan-triage-v6.2.0.0-linux-amd64.tar.gz
tar xzf sdwan-triage-v6.2.0.0-linux-amd64.tar.gz
chmod +x sdwan-triage-linux-amd64
./sdwan-triage-linux-amd64 -web
```

**Windows (amd64)**
```powershell
# Download and extract sdwan-triage-v6.2.0.0-windows-amd64.zip from GitHub Releases
.\sdwan-triage-windows-amd64.exe -web
```

### From Source

```bash
git clone https://github.com/gocisse/sdwan-triage.git
cd sdwan-triage
make build           # Build for current platform
make release         # Cross-compile for all platforms
```

> Requires Go 1.25+ and Node.js 18+ (for frontend build).

---

## Usage

### Web Mode

```bash
# Start web server (opens browser automatically on port 8080)
./sdwan-triage -web

# Custom port, no auto-open browser
./sdwan-triage -web -port 9090 -no-browser

# Web mode with threat intelligence feeds
./sdwan-triage -web --threat-intel ./feeds/
```

**Default credentials:** `admin` / `admin` (change after first login).

### CLI Mode

```bash
# Single PCAP analysis
./sdwan-triage capture.pcap

# LAN vs WAN comparison
./sdwan-triage -compare -lan capture-lan.pcap -wan capture-wan.pcap

# Analysis with threat intelligence
./sdwan-triage --threat-intel ./feeds/ capture.pcap

# Filter by IP and protocol
./sdwan-triage -src-ip 10.0.0.1 -protocol tcp capture.pcap

# JSON output
./sdwan-triage -json capture.pcap > report.json
```

### Threat Intel Feeds (STIX 2.1)

Place STIX 2.1 JSON bundle files in a directory:

```bash
./sdwan-triage --threat-intel ./feeds/ capture.pcap
```

A sample feed is included at `feeds/example-threat-feed.json`. Supported indicator types: `ipv4-addr`, `ipv6-addr`, `domain-name`, `file:hashes`, `url:value`.

---

## Screenshots

| Dashboard | Findings |
|-----------|----------|
| ![Dashboard](docs/dashboard.png) | ![Findings](docs/findings.png) |

| Threat Intel | Comparison |
|-------------|------------|
| ![Threat Intel](docs/threat-intel.png) | ![Comparison](docs/comparison.png) |

---

## Platform Support

| Platform | Architecture | Binary |
|----------|-------------|--------|
| Linux | amd64 | `sdwan-triage-linux-amd64` |
| macOS | Intel (amd64) | `sdwan-triage-darwin-amd64` |
| macOS | Apple Silicon (arm64) | `sdwan-triage-darwin-arm64` |
| Windows | amd64 | `sdwan-triage-windows-amd64.exe` |

All binaries are statically linked (`CGO_ENABLED=0`) and include the embedded React frontend + GeoIP database (~97MB).

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    Single Binary                        │
│  ┌──────────────────┐  ┌─────────────────────────────┐  │
│  │   Go Backend     │  │   Embedded React Frontend   │  │
│  │                  │  │                             │  │
│  │  35+ Analyzers   │  │  Dashboard + Visualizations │  │
│  │  STIX Parser     │  │  D3.js Maps + Timeline      │  │
│  │  Streaming       │  │  Wireshark Academy          │  │
│  │  Comparator      │  │  Global Filtering           │  │
│  │  GeoIP (embed)   │  │  Forensic Workflows         │  │
│  └──────────────────┘  └─────────────────────────────┘  │
│  ┌──────────────────────────────────────────────────────┤
│  │  Gin HTTP Server  │  SQLite Auth  │  Redis Storage  │
│  └──────────────────────────────────────────────────────┤
└─────────────────────────────────────────────────────────┘
```

---

## Contributing

Contributions are welcome! Please open an issue or submit a pull request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.

---

<p align="center">
  <sub>Built with ❤️ for network engineers who refuse to fly blind.</sub>
</p>
