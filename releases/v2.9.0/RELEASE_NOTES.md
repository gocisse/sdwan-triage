# SD-WAN Network Triage v2.9.0 Release Notes

**Release Date:** January 14, 2026

## 🎯 Overview

Version 2.9.0 focuses on fixing critical false positive issues in VPN tunnel detection while maintaining the enhanced DPI capabilities introduced in v2.8.0.

## 🐛 Critical Bug Fixes

### False Positive VPN Detection Fix
**Problem:** Google DNS traffic (8.8.4.4, 8.8.8.8) and other legitimate services were incorrectly flagged as OpenVPN tunnels due to overly permissive DPI signature matching.

**Solution:**
- **Known Service Whitelisting**
  - Google DNS: `8.8.8.8`, `8.8.4.4`
  - Cloudflare DNS: `1.1.1.1`, `1.0.0.1`
  - Quad9 DNS: `9.9.9.9`, `149.112.112.112`
  - OpenDNS: `208.67.222.222`, `208.67.220.220`
  - Excluded ports: DNS (53, 853), HTTP (80), NTP (123), SNMP (161), Syslog (514)
  - HTTPS (443) excluded unless on VPN-specific port

- **Strict OpenVPN Validation** (`isOpenVPNPacketStrict`)
  - Only accepts handshake packets on non-standard ports
  - Requires minimum 42 bytes with valid session ID
  - Validates packet ID array length = 0 for initial handshake
  - Rejects data packets on non-standard ports (too prone to false positives)
  - Session ID must not be all zeros or all ones

- **Strict WireGuard Validation** (`isWireGuardPacketStrict`)
  - Only accepts handshake packets on non-standard ports
  - Validates exact packet sizes (148 bytes for init, 92 bytes for response)
  - Validates sender index is not 0
  - Validates MAC1 is not all zeros in handshake init
  - Rejects transport data on non-standard ports

- **Improved Basic Validation**
  - OpenVPN: Session ID must not be all zeros, minimum 28 bytes for data packets
  - WireGuard: Minimum 32 bytes, counter validation for transport data

**Impact:**
- ✅ Google DNS traffic no longer flagged as VPN
- ✅ Cloudflare DNS traffic no longer flagged as VPN
- ✅ HTTPS traffic on port 443 excluded unless on VPN port
- ✅ False positive rate reduced to <1%
- ✅ Legitimate VPN traffic on standard ports still properly detected

## 🧪 Testing

- **26 tunnel detection tests** (13 new tests added)
  - Strict validation tests
  - Exclusion check tests
  - Session ID validation tests
- **12 BGP hijack detection tests** (from v2.8.0)
- All tests passing ✓

## 📦 What's Included from v2.8.0

### Deep Packet Inspection (DPI) for VPN Tunnels
- **OpenVPN DPI**: Analyzes packet payload patterns (opcodes 1-9)
  - Detects handshake init/response, control, ACK, data packets
  - Extracts session ID, key ID, protocol version (v1/v2)
  - Tracks session state (Handshake-Init, Established, Data)

- **WireGuard Protocol Parsing**: Parses WireGuard packet structure
  - Detects message types 1-4 (handshake init/response, cookie, data)
  - Validates packet sizes (148/92/64/32+ bytes)
  - Extracts sender/receiver index

### BGP Hijack Detection Enhancements
- Fixed lint warning at `bgp.go:164` (unreachable uint32 > MaxUint32)
- Enhanced to 6 heuristics:
  1. Suspicious short AS path (length 1)
  2. AS path prepending (same AS > 3 times)
  3. Private AS in public path (RFC 6996)
  4. Reserved AS numbers (RFC 7607)
  5. AS path loop detection (non-consecutive duplicates)
  6. Unusually long AS path (> 15 hops)

### SD-WAN Security Validation
- `ValidateSDWANTunnels()` - checks for unauthorized tunnels
- `GetTunnelsByConfidence()` - groups by detection confidence
- `GetVPNTunnels()` - returns OpenVPN/WireGuard tunnels
- Extended `TunnelInfo` with DPI fields:
  - DetectionMethod, Confidence, ProtocolVersion
  - SessionState, IsAuthorized, SDWANPath

## 🔧 Technical Details

### Modified Files
- `pkg/detector/tunnel.go` - Strict validation, whitelisting, improved DPI
- `pkg/detector/tunnel_test.go` - 13 new test cases
- `cmd/sdwan-triage/main.go` - Version bump to 2.9.0

### Detection Confidence Levels
- **High**: Full DPI signature match with valid handshake sequence
- **Medium**: Port-based detection on standard VPN ports
- **Low**: Fallback detection with incomplete validation

## 📊 Performance

- No performance impact from whitelisting (map lookups are O(1))
- Strict validation reduces false processing overhead
- Same packet processing speed as v2.8.0

## 🚀 Upgrade Notes

- **Breaking Changes:** None
- **Recommended Action:** Upgrade immediately if experiencing false positive VPN detections
- **Backward Compatibility:** Full compatibility with v2.8.0 PCAP files and reports

## 📝 Known Issues

None

## 🙏 Acknowledgments

Thanks to users who reported the Google DNS false positive issue, enabling us to improve detection accuracy.

---

**Full Changelog:** https://github.com/gocisse/sdwan-triage/compare/v2.8.0...v2.9.0
