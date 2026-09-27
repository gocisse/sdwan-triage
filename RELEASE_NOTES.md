# SD-WAN Triage v6.2.0 — The Security Forensics Release

> **Bridging the gap between network troubleshooting and security forensics. One binary, zero dependencies.**

---

## Highlights

### Threat Intelligence Integration (NEW)
Cross-reference observed IPs, domains, and hashes against known threat feeds in **STIX 2.1 format**:

- **STIX 2.1 Parser** — loads indicator bundles from any directory of JSON feed files
- **O(1) Map Lookups** — 10,000+ IOCs matched against every packet with zero performance penalty
- **Rich Metadata** — Threat Type (C2, Malware, Botnet, Phishing, Ransomware), Confidence, Source attribution, First Seen date
- **Red Shield Badge** — instant visual indicator on any FindingCard with a threat intel hit
- **Expanded Detail View** — per-indicator breakdown with type, confidence, source feed, and description
- **CLI & Web** — `--threat-intel feeds/` flag works in both CLI and web server modes

```bash
# Load STIX feeds and analyze
./sdwan-triage --threat-intel feeds/ capture.pcap

# Web mode with feeds
./sdwan-triage -web --threat-intel feeds/
```

### Global Web Filtering (NEW)
Real-time packet filtering by IP, Port, and Protocol directly in the Web UI:

- **FilterContext** — React Context managing global filter state (Source IP, Dest IP, Port/Service, Protocol)
- **GlobalFilterBar** — horizontal bar with instant Apply/Clear, Enter-to-submit, amber "Filtered" badge
- **Partial Match** — typing `10.0` matches all IPs in that subnet; typing `https` resolves to port 443
- **Composable** — global filter stacks with the existing forensic display filter and timeline scrubber
- **Filtered Badge** — Network Health Assessment shows "(Filtered)" indicator when active

### Interactive Forensic Workflow
Every finding card is a **guided 3-step troubleshooting workflow**:

| Step | Focus | What It Does |
|------|-------|--------------|
| **1. Verify** (Eye) | Wireshark | Exact display filter with copy button and mock packet visualization |
| **2. Diagnose** (Hands) | Device CLI | Vendor-specific or generic CLI commands as a checklist |
| **3. Resolve** (Fix) | Action | Concrete resolution steps with risk warnings and progress tracking |

- Persistent checklists (localStorage), 18 risk warnings, generic CLI fallback

### Wireshark Academy
Educational modal for Junior Engineers:

- Split-panel "Our Analysis" vs "Wireshark View" comparison
- TCP Header SVG with dynamic field highlighting (SYN red, Seq/Ack amber, Window purple)
- Color-coded mock packet list for 13 finding types
- Per-finding Wireshark tips

### Self-Contained Binary
- **~97MB** binary includes: React frontend, GeoIP database (63MB), all Go analyzers
- `CGO_ENABLED=0` — fully static, no shared library dependencies
- Embedded GeoIP with automatic fallback to disk paths

---

## What's New Since v6.1

| Feature | Status |
|---------|--------|
| STIX 2.1 Threat Intel Parser & Matcher | **New** |
| `--threat-intel` CLI/Web flag | **New** |
| Threat Intel red shield badge on FindingCards | **New** |
| Threat Intel expanded detail section | **New** |
| Global Web Filtering (IP/Port/Protocol) | **New** |
| FilterContext + GlobalFilterBar components | **New** |
| Partial IP/Service name matching | **New** |
| "Filtered" badge on Network Health Assessment | **New** |
| filterResults utility for all data structures | **New** |
| Sample STIX feed (`feeds/example-threat-feed.json`) | **New** |

---

## Platform Support

| Platform | Architecture | Binary |
|----------|-------------|--------|
| Linux | amd64 | `sdwan-triage-v6.2.0.0-linux-amd64` |
| macOS | Intel (amd64) | `sdwan-triage-v6.2.0.0-darwin-amd64` |
| macOS | Apple Silicon (arm64) | `sdwan-triage-v6.2.0.0-darwin-arm64` |
| Windows | amd64 | `sdwan-triage-v6.2.0.0-windows-amd64.exe` |

All binaries are statically linked and include the embedded frontend + GeoIP database.

---

## Quick Start

```bash
# Download the binary for your platform
chmod +x sdwan-triage-darwin-arm64

# Web mode (opens browser automatically)
./sdwan-triage -web

# Web mode with threat intel feeds
./sdwan-triage -web --threat-intel ./feeds/ -port 9090

# CLI analysis with threat intel
./sdwan-triage --threat-intel ./feeds/ capture.pcap

# CLI analysis with filters
./sdwan-triage -src-ip 10.0.0.1 -protocol tcp capture.pcap
```

---

## Threat Intel Feed Format

Place STIX 2.1 JSON bundle files in a directory and point `--threat-intel` at it:

```json
{
  "type": "bundle",
  "id": "bundle--example",
  "objects": [
    {
      "type": "indicator",
      "pattern": "[ipv4-addr:value = '185.220.101.1']",
      "pattern_type": "stix",
      "labels": ["command-and-control"],
      "confidence": 85,
      "external_references": [{"source_name": "AlienVault OTX"}]
    }
  ]
}
```

Supported indicator types: `ipv4-addr`, `ipv6-addr`, `domain-name`, `file:hashes`, `url:value`

---

## Build From Source

```bash
git clone https://github.com/gocisse/sdwan-triage.git
cd sdwan-triage
make build           # Build for current platform
make release         # Cross-compile for all platforms
make github-release  # Create GitHub release (requires gh CLI)
```

---

## Full Changelog

See [commit history](https://github.com/gocisse/sdwan-triage/compare/v6.1.0.0...v6.2.0.0) for all changes.
