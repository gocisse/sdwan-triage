# SD-WAN Network Triage v3.1.0 Release Notes

**Release Date:** January 14, 2026

## 🎯 Major Features

### SD-WAN Vendor-Specific Tunnel Detection
Complete overhaul of tunnel detection logic to prioritize port-based identification over unreliable Deep Packet Inspection (DPI), eliminating false positives.

#### Supported SD-WAN Vendors:
- **Cisco SD-WAN (Viptela)**: UDP 12346 (data), UDP/TCP 23456 (control), UDP 12366 (NAT traversal)
- **VMware Velocloud**: UDP 2426 (VCMP tunnels) - primary identifier
- **Fortinet SD-WAN**: UDP/TCP 541 (data/control)
- **Aruba EdgeConnect**: UDP 4500 (IPsec NAT-T), UDP 500 (IKE), ESP protocol
- **Palo Alto Prisma SD-WAN**: UDP 4500, UDP 500, ESP protocol
- **Zscaler**: IPsec tunnels with ESP, UDP 4500/500

#### Detection Hierarchy:
1. **Vendor-specific ports** (Highest confidence)
2. **Protocol signatures** (ESP, DTLS with context)
3. **Standard tunnel protocols** (VXLAN, GTP, L2TP, MPLS)
4. **VPN detection** (Only on standard ports)

### False Positive Prevention
- Removed non-standard port DPI for OpenVPN/WireGuard
- DNS traffic (ports 53, 853) never flagged as VPN
- Known DNS servers (Google, Cloudflare, Quad9) whitelisted
- HTTPS traffic excluded unless on VPN-specific ports

### Enhanced Reporting
- **SD-WAN vendor identification** with confidence levels (High/Medium/Low)
- **Wireshark filter generation** for each detected tunnel type
- **IPsec session correlation** (IKE + NAT-T + ESP tracking)
- **TCP control plane detection** for Cisco/Fortinet
- **Session state tracking** (Handshake, Established, Data)

### HTML Report Improvements
- SD-WAN vendor badge with confidence indicator
- Detection method and confidence level display
- Vendor-specific tunnel explanations
- Color-coded confidence levels
- Interactive tunnel details with Wireshark filters

## 🐛 Bug Fixes

### Protocol Classification Fix
- **Fixed critical bug** where UDP traffic was incorrectly displayed as TCP in HTML reports
- Traffic flows now correctly show UDP/TCP protocol based on actual packet analysis
- Affects Top Traffic Flow Analysis section in HTML reports

### Example:
- **Before**: VMware Velocloud UDP 2426 traffic showed as "TCP"
- **After**: Correctly displays as "UDP"

## 🔧 Technical Improvements

### Tunnel Detection (`pkg/detector/tunnel.go`)
- Added SD-WAN vendor-specific port constants
- Implemented `analyzeSDWANTunnel()` for vendor identification
- Added `generateSDWANWiresharkFilter()` for filter generation
- Implemented `analyzeIPsecNATT()` and `analyzeIKE()` for IPsec correlation
- Enhanced session tracking for multi-flow tunnels

### Data Models (`pkg/models/report.go`)
- Added `SDWANPath` field to `TunnelFinding` for Wireshark filters
- Enhanced tunnel metadata for vendor-specific information

### Report Generation (`pkg/output/html_report.go`)
- Added `WiresharkFilter` and `VendorName` fields to `TunnelFindingView`
- Updated `convertTunnelFindings()` to extract vendor information
- Enhanced HTML template with SD-WAN-specific sections

### Traffic Analysis (`pkg/analyzer/processor.go`)
- Fixed protocol classification in `buildTrafficSummary()`
- Properly tracks TCP vs UDP flows separately
- Passes DPI-enhanced fields to tunnel findings

## 📊 Detection Examples

### Cisco SD-WAN
```
Port: UDP 12346
Confidence: High
Wireshark Filter: udp.port == 12346 || udp.port == 23456 || tcp.port == 23456
```

### VMware Velocloud
```
Port: UDP 2426
Confidence: High
Wireshark Filter: udp.port == 2426
```

### Fortinet SD-WAN
```
Port: UDP/TCP 541
Confidence: High
Wireshark Filter: udp.port == 541 || tcp.port == 541
```

### IPsec-based SD-WAN (Aruba/Palo Alto/Zscaler)
```
Ports: UDP 4500 (NAT-T), UDP 500 (IKE), ESP
Confidence: High
Wireshark Filter: (udp.port == 4500 || udp.port == 500) && esp
```

## 🧪 Testing

Validated against:
- TestFile4.pcap: No false positives (previously flagged Google DNS as OpenVPN)
- banco.pcap: Correctly identified VMware Velocloud SD-WAN traffic
- Multiple SD-WAN vendor captures

## 📦 Installation

### Download Pre-built Binaries
```bash
# macOS (Apple Silicon)
wget https://github.com/gocisse/sdwan-triage/releases/download/v3.1.0/sdwan-triage-darwin-arm64.zip
unzip sdwan-triage-darwin-arm64.zip
chmod +x sdwan-triage-darwin-arm64
./sdwan-triage-darwin-arm64 -version

# macOS (Intel)
wget https://github.com/gocisse/sdwan-triage/releases/download/v3.1.0/sdwan-triage-darwin-amd64.zip

# Linux (x86_64)
wget https://github.com/gocisse/sdwan-triage/releases/download/v3.1.0/sdwan-triage-linux-amd64.zip

# Linux (ARM64)
wget https://github.com/gocisse/sdwan-triage/releases/download/v3.1.0/sdwan-triage-linux-arm64.zip

# Windows (x86_64)
wget https://github.com/gocisse/sdwan-triage/releases/download/v3.1.0/sdwan-triage-windows-amd64.zip
```

### Build from Source
```bash
git clone https://github.com/gocisse/sdwan-triage.git
cd sdwan-triage
go build -o sdwan-triage ./cmd/sdwan-triage
```

## 🚀 Usage Examples

### Analyze SD-WAN Traffic
```bash
# Basic analysis with HTML report
sdwan-triage -html report.html capture.pcap

# Identify Velocloud tunnels
sdwan-triage -service 2426 -html velocloud-report.html capture.pcap

# Analyze Cisco SD-WAN
sdwan-triage -service 12346 -html cisco-sdwan-report.html capture.pcap

# Check IPsec-based SD-WAN
sdwan-triage -protocol esp -html ipsec-sdwan-report.html capture.pcap
```

## 🔍 What's Changed

### Files Modified:
- `cmd/sdwan-triage/main.go`: Version bump to 3.1.0
- `pkg/detector/tunnel.go`: Complete SD-WAN detection rewrite
- `pkg/models/report.go`: Added SDWANPath field
- `pkg/output/html_report.go`: Enhanced tunnel view with vendor info
- `pkg/analyzer/processor.go`: Fixed protocol classification bug
- `pkg/output/assets/templates/enterprise-dashboard.html`: SD-WAN UI enhancements

## 📝 Breaking Changes

None. This release is fully backward compatible with v2.x reports and configurations.

## 🙏 Acknowledgments

Special thanks to the SD-WAN community for providing vendor-specific port information and test captures.

## 📄 License

MIT License - See LICENSE file for details

---

**Full Changelog**: https://github.com/gocisse/sdwan-triage/compare/v2.9.0...v3.1.0
