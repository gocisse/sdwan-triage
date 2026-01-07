# SD-WAN Triage v2.6.0 Release Notes

**Release Date:** January 7, 2026

## 🎉 Major Features

### D3.js Interactive Visualizations
This release introduces a completely redesigned HTML report with modern D3.js-powered visualizations replacing the previous Vis.js implementation.

#### Force-Directed Network Graph
- **Interactive zoom, pan, and drag** for exploring network topology
- **Smart IP categorization** with color-coded nodes:
  - 🟢 **Green** - Internal clients (RFC 1918 private IPs)
  - 🔵 **Blue** - Routers/Gateways (.1 or .254 in private ranges)
  - 🟠 **Orange** - External/Internet hosts
- **Hover tooltips** showing IP details, traffic stats, and role
- **Connected node highlighting** on hover for relationship discovery
- **Anomaly indicators** with red coloring for problematic nodes/links

#### Timeline Visualization
- **Chronological event display** showing network activity over time
- **Event type lanes** for DNS, TCP, HTTP, ARP, TLS events
- **Color-coded markers** by event type
- **Interactive tooltips** with event details

#### Sankey Traffic Flow Diagram
- **Traffic flow visualization** from Internal Clients → Gateway → Internet
- **Top external servers** shown as separate destination nodes
- **Bandwidth-based link widths** using TopConversationsByBytes data
- **Hover tooltips** showing traffic volumes in MB

### Card-Based Report Layout
- **Modern card design** with gradient headers and icons
- **Collapsible sections** for progressive disclosure
- **Executive summary** with health status indicators
- **Severity-based styling** (critical=red, warning=yellow, success=green)

### Actionable Recommendations
- **Per-finding action items** with specific troubleshooting steps
- **Collapsible action buttons** - click "Show Action" to reveal recommendations
- **8 detailed action categories**:
  1. DNS Anomalies - security investigation steps
  2. TCP Retransmissions - performance optimization
  3. ARP Conflicts - network integrity procedures
  4. TLS Certificates - security compliance guidance
  5. Suspicious Traffic - incident response actions
  6. High Latency - performance tuning
  7. BGP Routing - advanced troubleshooting
  8. QoS/DSCP - traffic management

## 🆕 New Command-Line Flags

| Flag | Description |
|------|-------------|
| `-bgp-check` | Enable BGP hijack detection using bgpview.io API |
| `-qos-analysis` | Analyze DSCP/QoS traffic classification |
| `-app-identify` | Application identification via port, SNI, ALPN heuristics |
| `-syslog-server` | Send alerts to syslog server (host:port) |
| `-splunk-hec-url` | Splunk HTTP Event Collector URL |
| `-splunk-token` | Splunk HEC authentication token |
| `-compare` | Compare multiple PCAP files for before/after analysis |
| `-debug-html` | Write debug HTML for troubleshooting |

## 📊 Enhanced Analysis Features

### BGP Hijack Detection
- Queries bgpview.io API for AS path information
- Detects unexpected AS origins for external IPs
- Flags potential BGP hijacking indicators

### QoS/DSCP Analysis
- Classifies traffic by DSCP markings
- Reports QoS class distribution
- Identifies mismatched or unexpected markings

### Application Identification
- Identifies applications by port numbers
- Uses TLS SNI and ALPN for encrypted traffic
- Payload-based heuristics for common protocols

### Multi-PCAP Comparison
- Compare network behavior across multiple captures
- Before/after analysis for change validation
- Differential reporting of findings

## 🔧 Improvements

- **Improved IP categorization** - Router/gateway detection before general internal classification
- **Better Sankey data** - Uses TopConversationsByBytes for accurate traffic flow
- **Collapsible TCP actions** - Toggle buttons for per-finding recommendations
- **Enhanced tooltips** - More detailed information on hover
- **Responsive design** - Works on various screen sizes

## 📦 Installation

### Pre-built Binaries
Download the appropriate binary for your platform:

| Platform | Architecture | Filename |
|----------|--------------|----------|
| macOS | Intel (x64) | `sdwan-triage-darwin-amd64` |
| macOS | Apple Silicon (M1/M2/M3) | `sdwan-triage-darwin-arm64` |
| Linux | x64 | `sdwan-triage-linux-amd64` |
| Linux | ARM64 | `sdwan-triage-linux-arm64` |
| Windows | x64 | `sdwan-triage-windows-amd64.exe` |

### Usage Examples

```bash
# Basic HTML report with D3.js visualizations
./sdwan-triage -html report.html capture.pcap

# Full analysis with all features
./sdwan-triage -html report.html -bgp-check -qos-analysis -app-identify capture.pcap

# Compare two captures
./sdwan-triage -compare before.pcap after.pcap

# Send alerts to Splunk
./sdwan-triage -splunk-hec-url https://splunk:8088 -splunk-token YOUR_TOKEN capture.pcap
```

## 🐛 Bug Fixes

- Fixed JavaScript template literal syntax in D3.js templates
- Fixed PathStats field references for proper data binding
- Fixed unused variable compilation errors
- Corrected IP categorization order (router before internal)

## 📋 Dependencies

- Go 1.23+
- github.com/google/gopacket
- github.com/fatih/color
- D3.js v7 (loaded from CDN in HTML reports)
- d3-sankey plugin (loaded from CDN)
- Font Awesome 6 (loaded from CDN)

## 🙏 Acknowledgments

Thank you to all contributors and users who provided feedback for this release.

---

**Full Changelog:** https://github.com/gocisse/sdwan-triage/compare/v2.5.0...v2.6.0
