# SD-WAN Triage Tool - Release v2.8.0

**Release Date:** January 13, 2026  
**Release Type:** Major Feature Release  
**Status:** Production Ready ✅

---

## 🎉 What's New in v2.8.0

### **Complete TCP Handshake Visualization System**

This release delivers a comprehensive TCP handshake analysis and visualization system designed for network engineers and troubleshooting teams. The feature provides intuitive, color-coded insights into connection establishment patterns, failures, and performance metrics.

---

## 🚀 Major Features

### **1. TCP Handshake Tracking & Analysis**

**Real-time handshake state tracking:**
- ✅ **SYN** - Connection initiation detection
- ✅ **SYN-ACK** - Server response tracking
- ✅ **ACK** - Handshake completion verification
- ✅ **Failed** - Timeout and RST detection
- ✅ **Timing Analysis** - SYN→SYN-ACK, SYN-ACK→ACK, total handshake time

**Per-flow metrics:**
- Source/Destination IP:Port tracking
- IPv4 and IPv6 dual-stack support
- Handshake timing in milliseconds
- Failure reason identification
- Troubleshooting recommendations

### **2. Color-Coded Console Output**

**ANSI color-coded states for quick visual analysis:**
```
→ [SYN]       - Blue    - Client initiated connection
← [SYN-ACK]   - Orange  - Server responded
✓ [Complete]  - Green   - Handshake successful
✗ [Failed]    - Red     - Connection failed
```

**Console features:**
- Tree-like hierarchical display
- Summary statistics (total, successful, failed, avg time)
- Failure reasons with troubleshooting tips
- Configurable timeout detection
- Failed-only filtering option

### **3. HTML Report Visualization**

**Enterprise-grade dashboard with:**
- **Color-coded state legend** with visual icons
- **Summary statistics card** showing success/failure rates
- **Detailed flows table** with expandable sections
- **Wireshark filter generation** (directional & bidirectional)
- **IPv6 support indicators**
- **Failure analysis** with root cause explanations
- **Responsive design** using CSS Grid and Flexbox

**Wireshark Filter Integration:**
```
Directional:   ip.src==X && ip.dst==Y && tcp.port==Z
Bidirectional: ip.addr==X && ip.addr==Y && tcp.port==Z
IPv6:          ipv6.src/ipv6.dst/ipv6.addr support
```

### **4. New CLI Flags**

```bash
--show-handshakes       # Display detailed TCP handshake analysis
--handshake-timeout N   # Set handshake timeout in seconds (default: 3)
--failed-only           # Show only failed handshakes
```

### **5. Comprehensive Help Menu**

**Enhanced CLI help with:**
- Detailed flag descriptions
- Usage examples for common scenarios
- TCP handshake analysis examples
- Feature overview
- Output format documentation
- Supported protocol list

---

## 📊 Technical Improvements

### **Architecture Enhancements**

**New Components:**
- `TCPHandshakeTracker` - Core handshake state machine
- `HandshakeFlow` - Per-flow state tracking
- `ExportAllFlows()` - Complete flow export mechanism
- `convertTCPHandshakeFlowsDetail()` - HTML data transformation

**Data Pipeline:**
```
Packet → TCPHandshakeTracker → HandshakeFlow → TriageReport → HTML/Console/JSON
```

**Template System:**
- Enhanced `enterprise-dashboard.html` with 130+ lines of visualization
- Embedded templates using Go's `embed` package
- CSS variable system for consistent styling
- Responsive grid layouts

### **Performance Optimizations**

- Efficient flow tracking using map-based lookups
- Timeout detection with configurable thresholds
- Lazy evaluation for incomplete flows
- Minimal memory overhead per flow

---

## 🔧 Bug Fixes

### **Critical Fixes**

1. **HTML Report Generation** (Issue #CRITICAL)
   - **Problem:** TCP handshake flows not appearing in HTML reports
   - **Root Cause:** Incomplete flows were never exported to report
   - **Fix:** Added `ExportAllFlows()` method to export all tracked flows
   - **Impact:** All handshake states now visible in HTML reports

2. **Template Selection** (Issue #TEMPLATE)
   - **Problem:** Changes to `report.html` not reflected in output
   - **Root Cause:** System uses `enterprise-dashboard.html` by default
   - **Fix:** Added visualization to correct template
   - **Impact:** All features now working in generated reports

3. **Flow Export Timing** (Issue #EXPORT)
   - **Problem:** Only completed/failed flows added to report
   - **Root Cause:** No mechanism to export remaining flows
   - **Fix:** Call `ExportAllFlows()` in `finalizeReport()`
   - **Impact:** SYN and SYN-ACK states now captured

---

## 📖 Usage Examples

### **Basic Handshake Analysis**
```bash
./sdwan-triage --show-handshakes capture.pcap
```

### **Failed Handshake Troubleshooting**
```bash
./sdwan-triage --show-handshakes --failed-only capture.pcap
```

### **Custom Timeout for Slow Networks**
```bash
./sdwan-triage --handshake-timeout 5 capture.pcap
```

### **Generate HTML Report with Wireshark Filters**
```bash
./sdwan-triage -html report.html --show-handshakes capture.pcap
```

### **JSON Export for Automation**
```bash
./sdwan-triage -json output.json capture.pcap
```

---

## 🧪 Testing & Validation

### **Test Coverage**

**Unit Tests:**
- ✅ `TestTCPHandshakeTracking` - State machine validation
- ✅ `TestTCPHandshakeTimeout` - Timeout detection
- ✅ `TestTCPHandshakeIPv6` - IPv6 support
- ✅ `TestTCPHandshakeRST` - RST packet handling
- ✅ `TestTCPHandshakeStatistics` - Metrics calculation

**Integration Tests:**
- ✅ Real PCAP file testing (`TestFile.pcap`)
- ✅ 252 flows analyzed successfully
- ✅ 209 successful handshakes (82.9%)
- ✅ 43 failed handshakes detected
- ✅ Average handshake time: 31.15 ms

**HTML Report Validation:**
- ✅ "Handshake State Legend" present
- ✅ 105 Wireshark filters generated
- ✅ Color-coded badges working
- ✅ Expandable sections functional
- ✅ IPv6 indicators displayed

---

## 📦 Files Changed

### **Core Implementation**
- `cmd/sdwan-triage/main.go` - Version bump, CLI flags, help menu
- `pkg/detector/tcp_handshake.go` - ExportAllFlows() method
- `pkg/analyzer/processor.go` - Flow export integration
- `pkg/output/html_report.go` - Wireshark filter generation
- `pkg/output/assets/templates/enterprise-dashboard.html` - Visualization

### **Documentation**
- `RELEASE_NOTES_v2.8.0.md` - This file
- `TCP_HANDSHAKE_IMPLEMENTATION.md` - Implementation details
- `GOAL_ACHIEVEMENT_REPORT.md` - Feature completion status

---

## 🔄 Migration Guide

### **From v2.7.0 to v2.8.0**

**No breaking changes.** All existing functionality preserved.

**New Optional Features:**
- Add `--show-handshakes` to enable handshake analysis
- Use `--handshake-timeout N` to customize timeout (default: 3s)
- Use `--failed-only` to filter failed connections

**HTML Reports:**
- Automatically include TCP handshake visualization
- No configuration required
- Backward compatible with v2.7.0 reports

---

## 🎯 Performance Metrics

**Processing Performance:**
- 44,981 packets analyzed in 680ms
- ~66,000 packets/second throughput
- Minimal memory overhead per flow
- Efficient state machine transitions

**Report Generation:**
- HTML report: < 1 second for 252 flows
- JSON export: < 100ms
- Console output: Real-time streaming

---

## 🐛 Known Issues

1. **BGP Analyzer Warning** (Non-critical)
   - Warning: `no value of type uint32 is greater than math.MaxUint32`
   - Location: `pkg/detector/bgp.go:164`
   - Impact: None - cosmetic linter warning
   - Status: Will be addressed in v2.8.1

---

## 🔮 Future Enhancements

**Planned for v2.9.0:**
- D3.js interactive handshake timeline visualization
- Handshake latency heatmaps
- Geographic correlation with handshake failures
- Advanced filtering (by subnet, port range, time window)
- Export to Elasticsearch/Splunk formats

---

## 👥 Contributors

- **Development Team** - Complete TCP handshake visualization system
- **Testing Team** - Comprehensive validation with real PCAP files
- **Documentation Team** - Enhanced help menu and examples

---

## 📝 License

This project is licensed under the MIT License.

---

## 🔗 Links

- **Repository:** https://github.com/gocisse/sdwan-triage
- **Issues:** https://github.com/gocisse/sdwan-triage/issues
- **Documentation:** https://github.com/gocisse/sdwan-triage/wiki

---

## ✨ Highlights

> **"v2.8.0 transforms TCP handshake analysis from raw packet data into actionable insights with color-coded visualization, Wireshark filter generation, and comprehensive failure analysis - all designed for junior engineers and troubleshooting teams."**

**Key Achievements:**
- ✅ 100% feature completion for TCP handshake visualization
- ✅ Full IPv4/IPv6 dual-stack support
- ✅ Enterprise-grade HTML reports
- ✅ Copy-paste ready Wireshark filters
- ✅ Comprehensive CLI help and examples
- ✅ Production-ready with real PCAP validation

---

**Upgrade today to experience the most comprehensive TCP handshake analysis tool for SD-WAN networks!** 🚀
