# SD-WAN Triage v2.3.0 Release Notes

## 🎉 What's New

SD-WAN Triage v2.3.0 is a major release that adds **network path discovery** with traceroute integration, enhanced visualization capabilities, and comprehensive reporting features.

## ✨ Major Features

### 🌐 Network Path Discovery (NEW)
- **Traceroute Integration**: Optional `-trace-path` flag to discover actual network paths
- **Intelligent Target Selection**: Automatically prioritizes destinations with anomalies
- **Cross-Platform Support**: Works on Windows, Linux, and macOS
- **Visual Path Representation**: Purple triangle nodes show intermediate hops in interactive diagrams
- **Hop Details**: Displays hop number, IP address, hostname, and RTT for each hop
- **Top 5 Targets**: Limits traceroute to most significant destinations to optimize performance

### 📊 Interactive Visualizations
- **Dual Diagram System**: 
  - Static Mermaid.js flowcharts for quick overview
  - Interactive vis.js network diagrams with drag, zoom, and hover
- **Color-Coded Nodes**:
  - 🟢 Green boxes: Internal network devices
  - 🔷 Blue diamonds: Gateways/routers
  - 🟠 Orange boxes: External servers
  - 🟣 Purple triangles: Traceroute hops
  - 🔴 Red nodes: Devices with detected issues
- **Edge Visualization**:
  - Gray arrows: Direct traffic flows from PCAP
  - Purple arrows: Discovered traceroute paths
  - Dashed red lines: Connections with anomalies

### 📝 Enhanced Reporting
- **Plain-Language Descriptions**: Non-technical explanations for all findings
- **CSV Export**: Descriptive headers with actionable recommendations
- **HTML Reports**: Professional reports with executive summaries and risk levels
- **Comprehensive Help**: Built-in help system with examples and usage guide

### 🔍 Advanced Analysis
- **DNS Anomaly Detection**: Identifies DNS poisoning and suspicious redirects
- **Performance Monitoring**: Detects TCP retransmissions, high latency, and packet loss
- **Security Analysis**: Flags suspicious ports and ARP conflicts
- **Traffic Profiling**: Application breakdown and bandwidth analysis
- **Device Fingerprinting**: OS detection from TCP/IP characteristics

### 🎯 Filtering Capabilities
- **Source IP Filtering**: `-src-ip` to analyze traffic from specific devices
- **Destination IP Filtering**: `-dst-ip` to focus on specific targets
- **Service Filtering**: `-service` to analyze specific ports or services
- **Protocol Filtering**: `-protocol` to filter by TCP or UDP

## 📦 Installation

### Download Pre-built Binaries

Choose the appropriate binary for your platform:

- **Windows (64-bit)**: `sdwan-triage-v2.3.0-windows-amd64.zip`
- **Linux (64-bit)**: `sdwan-triage-v2.3.0-linux-amd64.zip`
- **macOS Intel**: `sdwan-triage-v2.3.0-darwin-amd64.zip`
- **macOS Apple Silicon**: `sdwan-triage-v2.3.0-darwin-arm64.zip`

### Installation Steps

1. Download the appropriate ZIP file for your platform
2. Extract the archive
3. Make the binary executable (Linux/macOS):
   ```bash
   chmod +x sdwan-triage-v2.3.0-*
   ```
4. Run the tool:
   ```bash
   ./sdwan-triage-v2.3.0-* -help
   ```

## 🚀 Usage Examples

### Basic Analysis
```bash
# Full analysis with terminal output
./sdwan-triage capture.pcap

# Export to HTML report
./sdwan-triage -html report.html capture.pcap

# Export to CSV for Excel
./sdwan-triage -csv findings.csv capture.pcap
```

### With Traceroute (Network Path Discovery)
```bash
# Discover network paths to destinations
./sdwan-triage -html report.html -trace-path capture.pcap

# Combine with filters
./sdwan-triage -html https-paths.html -service https -trace-path capture.pcap
```

### Advanced Filtering
```bash
# Filter by source IP
./sdwan-triage -src-ip 192.168.1.100 capture.pcap

# Filter by service
./sdwan-triage -service ssh capture.pcap

# Combine multiple filters
./sdwan-triage -src-ip 192.168.1.100 -protocol tcp -service 443 capture.pcap
```

## 🔧 Technical Details

### System Requirements
- **Operating System**: Windows 10+, Linux (any distribution), macOS 10.13+
- **Network Access**: Required for `-trace-path` feature
- **Permissions**: May require elevated privileges for traceroute on some systems

### Binary Information
- **Build Type**: Static binaries (CGO_ENABLED=0)
- **Architecture**: 64-bit (amd64/arm64)
- **Dependencies**: None (fully self-contained)
- **Size**: ~6-7 MB per binary

### Performance
- **Traceroute Timeout**: 30 seconds per destination
- **Max Hops**: 15 per traceroute
- **Target Limit**: Top 5 destinations
- **PCAP Processing**: Handles multi-GB capture files

## 📋 Changelog

### Added
- ✅ `-trace-path` flag for network path discovery
- ✅ Traceroute execution and output parsing (cross-platform)
- ✅ Interactive vis.js network diagrams
- ✅ Mermaid.js static flowcharts
- ✅ Intelligent destination prioritization
- ✅ Purple triangle nodes for traceroute hops
- ✅ Edge chains showing complete network paths
- ✅ Enhanced HTML legend with traceroute explanation
- ✅ Comprehensive help system with examples
- ✅ Plain-language CSV export
- ✅ Executive summary with risk levels

### Improved
- ✅ HTML report styling and readability
- ✅ Error handling for traceroute failures
- ✅ Cross-platform compatibility
- ✅ Documentation and help messages
- ✅ Node categorization (internal/external/router/hop)

### Fixed
- ✅ Mermaid.js syntax errors in edge labels
- ✅ Missing dependencies in go.mod
- ✅ Thread-safety in path tracking

## ⚠️ Important Notes

### Traceroute Considerations
- **Timing**: Traceroute runs at analysis time, not capture time
- **Path Changes**: Network paths may differ from historical PCAP traffic
- **Permissions**: May require root/administrator privileges
- **Firewall**: Some networks block traceroute probes (ICMP/UDP/TCP)
- **Performance**: Each traceroute adds several seconds to analysis time

### Compatibility
- Fully backward compatible with v2.2.0
- All existing features work without `-trace-path` flag
- No breaking changes to command-line interface

## 🐛 Known Issues
- None reported

## 📚 Documentation
- Built-in help: `./sdwan-triage -help`
- GitHub Repository: https://github.com/gocisse/sdwan-triage
- Example PCAP files included in repository

## 🙏 Acknowledgments
Special thanks to:
- gopacket library for PCAP parsing
- vis.js for interactive network diagrams
- Mermaid.js for static flowcharts
- fatih/color for terminal output styling

## 📄 License
This project is licensed under the MIT License.

## 🔗 Links
- **Repository**: https://github.com/gocisse/sdwan-triage
- **Issues**: https://github.com/gocisse/sdwan-triage/issues
- **Releases**: https://github.com/gocisse/sdwan-triage/releases

---

**Full Changelog**: https://github.com/gocisse/sdwan-triage/compare/v2.2.0...v2.3.0
