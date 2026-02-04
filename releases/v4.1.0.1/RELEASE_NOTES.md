# SD-WAN Triage v4.1.0.1 Release Notes

## 🎉 Major Feature: LAN Protocol Detection

This release adds comprehensive Layer 2/3 LAN protocol detection capabilities to address VRRP flapping and other LAN protocol troubleshooting scenarios.

## ✨ New Features

### LAN Protocol Detection
- **VRRP (Virtual Router Redundancy Protocol)** - IP Protocol 112
  - Detects VRRP advertisements and state changes
  - Automatic flapping detection (>3 transitions)
  - Tracks priority changes and virtual IPs
  - Timeline events for all state transitions
  - Supports VRRPv2 and VRRPv3 (IPv4 and IPv6)

- **CDP (Cisco Discovery Protocol)** - Layer 2
  - Discovers Cisco network devices
  - Extracts device ID, platform, capabilities, software version
  - Port identification and IP address mapping

- **LLDP (Link Layer Discovery Protocol)** - IEEE 802.1AB
  - Multi-vendor device discovery
  - Chassis ID, port ID, system name extraction
  - Management IP address identification

- **HSRP (Hot Standby Router Protocol)** - UDP 1985
  - Gateway redundancy monitoring
  - Tracks active/standby routers
  - State change detection (Initial, Learn, Listen, Speak, Standby, Active)

- **STP (Spanning Tree Protocol)** - IEEE 802.1D
  - Bridge and root bridge identification
  - Topology change detection
  - Root path cost calculation

### Enhanced Timeline
- All LAN protocol events now appear in the unified timeline
- Detailed state change tracking with timestamps
- Flapping detection alerts

### JSON Output Enhancement
- New `lan_protocols` section in JSON output
- Structured data for VRRP, CDP, LLDP, HSRP, and STP findings
- Flapping indicators and transition counts

## 🔧 Improvements

### Help Menu Updates
- Added LAN protocol analysis examples
- VRRP flapping detection commands
- jq filter examples for protocol-specific queries
- Updated supported protocols list

### Documentation
- Comprehensive LAN protocol detection guide
- Quick reference with Wireshark filters
- Troubleshooting scenarios and examples
- Implementation summary

## 📝 Usage Examples

### VRRP Flapping Detection
```bash
# Analyze capture with VRRP detection
./sdwan-triage analyze vrrp-capture.pcap

# Check for flapping
./sdwan-triage analyze vrrp-capture.pcap | jq '.lan_protocols.vrrp_sessions[] | select(.is_flapping == true)'

# View VRRP timeline events
./sdwan-triage analyze vrrp-capture.pcap | jq '.timeline[] | select(.protocol == "VRRP")'
```

### Device Discovery
```bash
# Discover CDP devices
./sdwan-triage -html report.html capture.pcap | jq '.lan_protocols.cdp_devices[]'

# Check HSRP failover events
./sdwan-triage analyze capture.pcap | jq '.timeline[] | select(.protocol == "HSRP")'
```

## 🐛 Bug Fixes
- Fixed VRRP packet detection (previously undetected)
- Improved Layer 2 protocol parsing

## 📦 Supported Platforms
- macOS (Intel & Apple Silicon)
- Linux (amd64 & arm64)
- Windows (amd64)

## 🔍 Wireshark Correlation

The tool now provides context-aware Wireshark filters for deep dive analysis:
- `vrrp` - All VRRP traffic
- `vrrp.virt_rtr_id == 1` - Specific VRID
- `cdp` - Cisco Discovery Protocol
- `lldp` - Link Layer Discovery Protocol
- `hsrp` - Hot Standby Router Protocol
- `stp` - Spanning Tree Protocol

## 📚 Documentation

New documentation files:
- `docs/LAN_PROTOCOL_DETECTION.md` - Comprehensive implementation guide
- `docs/QUICK_REFERENCE_LAN_PROTOCOLS.md` - Quick reference guide
- `IMPLEMENTATION_SUMMARY.md` - Technical implementation details

## 🚀 Performance

- ~5% CPU overhead for LAN protocol detection
- Minimal memory footprint
- No impact on packet throughput
- Efficient hash map-based state tracking

## 🔮 Future Enhancements

Potential additions based on user needs:
- LDP (Label Distribution Protocol)
- GLBP (Gateway Load Balancing Protocol)
- LACP (Link Aggregation Control Protocol)
- UDLD (Unidirectional Link Detection)

## 📥 Installation

Download the appropriate binary for your platform:
- macOS Intel: `sdwan-triage-darwin-amd64.zip`
- macOS Apple Silicon: `sdwan-triage-darwin-arm64.zip`
- Linux x64: `sdwan-triage-linux-amd64.zip`
- Linux ARM64: `sdwan-triage-linux-arm64.zip`
- Windows x64: `sdwan-triage-windows-amd64.zip`

Extract and run:
```bash
unzip sdwan-triage-*.zip
chmod +x sdwan-triage-*
./sdwan-triage-* --help
```

## 🙏 Acknowledgments

This release addresses real-world troubleshooting scenarios where VRRP flapping and other LAN protocol issues needed detection and analysis.

## 📞 Support

For issues, questions, or feature requests:
- GitHub Issues: https://github.com/gocisse/sdwan-triage/issues
- Documentation: https://github.com/gocisse/sdwan-triage

---

**Full Changelog**: v4.0.0...v4.1.0.1
