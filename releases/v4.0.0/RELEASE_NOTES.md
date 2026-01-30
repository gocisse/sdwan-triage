# SD-WAN Network Triage v4.0.0 Release Notes

**Release Date:** January 30, 2026

## 🎯 Major Features

### Enhanced Device Fingerprinting Display
- **Device Fingerprinting table now visible on main dashboard** - No longer hidden in a separate tab
- Shows IP addresses, OS types, operating systems, and confidence levels immediately when report opens
- Scrollable table with color-coded confidence badges (High/Medium/Low)

### Geographic Distribution Improvements
- **Fixed "Unknown (Class A/B/C)" labels** - Now shows actual country/region names using GeoIP lookup
- **Added IP address lists** to each geographic region for detailed visibility
- Enhanced regional breakdown with accurate location data

### Improved Wireshark Integration
- **Fixed CSS for dark mode compatibility** in Actionable Stream Analysis pages
- **Corrected SD-WAN vendor port filters**:
  - VMware VeloCloud: UDP 2426 (was incorrectly TCP)
  - Cisco Viptela: UDP 12346 (data), UDP/TCP 23456 (control)
  - Fortinet SD-WAN: UDP/TCP 541
  - Silver Peak: UDP 4163
  - Palo Alto Prisma: UDP 4501
  - Versa Networks: UDP 4790
- **Added comprehensive vendor-specific Wireshark filters** for troubleshooting

### Cross-Platform Build Improvements
- **Pure Go implementation** - Removed CGO dependency for cross-compilation
- All binaries now build without requiring platform-specific C libraries
- Smaller, more portable executables

## 🐛 Bug Fixes

### Device Fingerprinting
- Fixed issue where Device Fingerprinting section only showed count but not the actual device table
- Data was present but hidden in tabbed UI - now displayed on main dashboard

### SD-WAN Port Filters
- Corrected VeloCloud VCMP filter from TCP to UDP 2426
- Fixed multiple vendor-specific port mappings in Wireshark Quick Reference

### CSS/UI Fixes
- Fixed unreadable text in dark mode for Wireshark guide sections
- Updated hardcoded colors to use CSS variables for theme compatibility

## 🔧 Technical Improvements

### Build System
- Replaced `gopacket/pcap` (CGO) with `pcapgo` (pure Go) in streaming_advanced.go
- Added `CGO_ENABLED=0` to build script for reliable cross-compilation
- All platforms now build from single build script without errors

### Template Updates
- Added Device Fingerprinting card to main dashboard section in enterprise-dashboard.html
- Enhanced geographic distribution with IP address visibility
- Improved dark mode CSS variable usage throughout

## 📦 Installation

### Download Pre-built Binaries
```bash
# macOS (Apple Silicon)
wget https://github.com/gocisse/sdwan-triage/releases/download/v4.0.0/sdwan-triage-darwin-arm64.zip
unzip sdwan-triage-darwin-arm64.zip
chmod +x sdwan-triage-darwin-arm64
./sdwan-triage-darwin-arm64 -version

# macOS (Intel)
wget https://github.com/gocisse/sdwan-triage/releases/download/v4.0.0/sdwan-triage-darwin-amd64.zip

# Linux (x86_64)
wget https://github.com/gocisse/sdwan-triage/releases/download/v4.0.0/sdwan-triage-linux-amd64.zip

# Linux (ARM64)
wget https://github.com/gocisse/sdwan-triage/releases/download/v4.0.0/sdwan-triage-linux-arm64.zip

# Windows (x86_64)
wget https://github.com/gocisse/sdwan-triage/releases/download/v4.0.0/sdwan-triage-windows-amd64.zip
```

### Build from Source
```bash
git clone https://github.com/gocisse/sdwan-triage.git
cd sdwan-triage
go build -o sdwan-triage ./cmd/sdwan-triage
```

## 🚀 Usage Examples

### Generate HTML Report
```bash
# Basic analysis with HTML report
sdwan-triage -html report.html capture.pcap

# Multi-page HTML report
sdwan-triage -multi-page-html ./report-dir capture.pcap
```

## 🔍 What's Changed

### Files Modified:
- `cmd/sdwan-triage/main.go`: Version bump to 4.0.0
- `pkg/analyzer/streaming_advanced.go`: Replaced pcap with pcapgo for pure Go builds
- `pkg/output/filter_builder.go`: Corrected SD-WAN vendor port filters
- `pkg/output/wireshark_guide.go`: Updated Wireshark Quick Reference with accurate ports
- `pkg/output/actionable_header.go`: Fixed dark mode CSS
- `pkg/output/assets/templates/enterprise-dashboard.html`: Added Device Fingerprinting to main dashboard
- `build-release.sh`: Added CGO_ENABLED=0 for cross-compilation

## 📝 Breaking Changes

None. This release is fully backward compatible with v3.x reports and configurations.

## 📄 License

MIT License - See LICENSE file for details

---

**Full Changelog**: https://github.com/gocisse/sdwan-triage/compare/v3.1.0...v4.0.0
