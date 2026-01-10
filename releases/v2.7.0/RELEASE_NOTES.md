# SD-WAN Triage v2.7.0 Release Notes

**Release Date:** January 10, 2026

## 🎉 What's New

### Enhanced Network Topology Visualization
- **Detailed Node Information**: Nodes now display bytes transferred and connection counts
- **Traffic Volume Visualization**: Link thickness represents actual traffic volume
- **Security Issue Highlighting**: Automatic detection and highlighting of:
  - DDoS attack sources (red nodes)
  - Port scanning sources (red nodes)
  - IOC matches (red nodes)
  - DNS anomalies (red nodes)
- **Performance Issue Detection**: Links with TCP retransmissions or failed handshakes shown with dashed lines
- **Enhanced Tooltips**: Hover over nodes to see detailed statistics including bytes transferred and connection counts
- **Better Categorization**: Improved node grouping (internal, router, external, anomaly)

### Comprehensive CLI Help
- **Expanded Feature List**: Complete documentation of all 31+ capabilities
- **27 Usage Examples**: Covering security analysis, performance troubleshooting, and SD-WAN analysis
- **Organized Options**: Grouped by Output Formats, Filtering, and Analysis Options
- **Protocol Coverage**: Full list of supported protocols across all network layers

### Documentation Improvements
- **Complete README.md**: Professional documentation with installation, usage, and examples
- **Feature Verification Report**: Detailed status of all implemented features
- **Architecture Diagram**: Visual representation of the processing pipeline

## 📦 Downloads

### macOS
- **Intel (x86_64)**: `sdwan-triage-darwin-amd64.zip`
- **Apple Silicon (ARM64)**: `sdwan-triage-darwin-arm64.zip`

### Linux
- **x86_64**: `sdwan-triage-linux-amd64.zip`
- **ARM64**: `sdwan-triage-linux-arm64.zip`

### Windows
- **x86_64**: `sdwan-triage-windows-amd64.zip`

## ✨ Features Summary

### Security Analysis (6 features)
- DDoS Detection (SYN/UDP/ICMP flood)
- Port Scanning Detection (horizontal/vertical/block)
- Malware Indicators (IOC checking)
- TLS Security Analysis (weak ciphers, outdated protocols)
- BGP Hijack Heuristics
- GeoIP Analysis

### Performance Monitoring (5 features)
- TCP Retransmission Analysis
- RTT Distribution with histogram
- Failed Handshake Detection
- Bandwidth Tracking
- Jitter & Packet Loss metrics

### Protocol Analysis (5 features)
- DNS Anomaly Detection
- HTTP/HTTPS Analysis
- HTTP/2 & QUIC Detection
- VoIP/SIP Call Tracking
- RTP/RTCP Media Quality

### Tunnel & Encapsulation (6 features)
- VXLAN (VNI extraction)
- GRE/NVGRE/ERSPAN
- MPLS Label Analysis
- IPsec (ESP/AH)
- GTP-U/GTP-C
- L2TP, OpenVPN, WireGuard

### SD-WAN Specific (4 features)
- Vendor Detection (7 vendors)
- Application Identification
- Device Fingerprinting
- ARP Conflict Detection

### Visualizations (6 features)
- Interactive Timeline
- Sankey Diagram
- Enhanced Network Topology
- RTT Histogram
- Protocol Breakdown
- Bandwidth Graphs

## 🚀 Quick Start

```bash
# Extract the archive
unzip sdwan-triage-*.zip

# Make executable (macOS/Linux)
chmod +x sdwan-triage-*

# Run analysis
./sdwan-triage -html report.html capture.pcap
```

## 📊 Supported Platforms

- macOS 10.15+ (Intel and Apple Silicon)
- Linux (x86_64 and ARM64)
- Windows 10+ (x86_64)

## 🔧 Requirements

- No external dependencies for basic functionality
- **Optional**: wkhtmltopdf for PDF export

## 📝 Changelog

### Added
- Enhanced network topology with traffic volume and security issue visualization
- Comprehensive CLI help with 27 usage examples
- Complete README.md with professional documentation
- Feature verification report
- Multi-platform binary releases

### Improved
- Network topology now shows actual traffic volume on links
- Security issues automatically highlighted in topology
- Node tooltips show detailed statistics
- Better IP categorization (internal/router/external/anomaly)

### Fixed
- Corrected field references in network topology generation
- Improved error handling in visualization code

## 🐛 Known Issues

None reported for this release.

## 📖 Documentation

- **README.md**: Complete usage guide
- **FEATURE_VERIFICATION_REPORT.md**: Detailed feature status
- **CLI Help**: Run `./sdwan-triage -help` for comprehensive documentation

## 🤝 Contributing

We welcome contributions! Please see the README.md for guidelines on:
- Reporting bugs
- Requesting features
- Submitting pull requests

## 📄 License

MIT License - See LICENSE file for details

## 🔗 Links

- **GitHub Repository**: https://github.com/gocisse/sdwan-triage
- **Issue Tracker**: https://github.com/gocisse/sdwan-triage/issues
- **Releases**: https://github.com/gocisse/sdwan-triage/releases

---

**Built with ❤️ for network engineers and security professionals**
