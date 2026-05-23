# SD-WAN Triage v6.1.0.0 — The Wireshark Academy Release

> **A single binary that transforms raw PCAP files into actionable, educational network forensics.**

---

## Highlights

### Interactive Forensic Workflow
Every finding card is now a **"mentor in a box"** — a guided 3-step troubleshooting workflow:

| Step | Focus | What It Does |
|------|-------|--------------|
| **1. Verify** (Eye) | Wireshark | Provides the exact display filter, copy button, and mock packet visualization |
| **2. Diagnose** (Hands) | Device CLI | Vendor-specific or generic CLI commands as a checklist with copy-to-clipboard |
| **3. Resolve** (Fix) | Action | Concrete resolution steps with risk warnings and progress tracking |

- **Persistent checklists** — progress is saved to localStorage, survives page refresh
- **Risk warnings** — 18 finding-specific "what NOT to do" cautions to prevent mistakes
- **Generic CLI fallback** — when no vendor runbook exists, category-appropriate diagnostic commands are generated automatically

### Wireshark Academy
A new educational modal for Junior Engineers:

- **Split-panel view** — "Our Analysis" vs "Wireshark View" side-by-side
- **TCP Header SVG Diagram** — interactive visualization with dynamic field highlighting based on finding type (SYN flag red for floods, Seq/Ack amber for retransmissions, Window purple for latency)
- **Mock Packet List** — color-coded (red/yellow/green/grey) Wireshark-style rows for 13 finding types with real IP/port context
- **Wireshark Tips** — per-finding-type guidance on what to look for in the real tool

### Embedded GeoIP Database
- **Self-contained binary** — GeoLite2-City.mmdb (63MB) is compiled into the binary via `//go:embed`
- **Zero external dependencies** — no need to download or place the database file separately
- **Automatic fallback** — if embedded data fails, searches standard disk paths (`./data/`, `/usr/share/GeoIP/`)
- **Full geolocation** — country, city, coordinates for map visualization

### JA3/JA3S Fingerprinting
- Extracts JA3 client and JA3S server fingerprints from TLS handshakes
- Matches against known malware, bot, and application fingerprint databases
- Displays fingerprint hashes with confidence scores in the findings panel

### Timeline Scrubber
- Cross-panel time range synchronization
- Click and drag to filter all panels (findings, conversations, protocol stats) to a specific time window
- Visual packet-rate histogram overlay
- Press Escape to reset time filter

---

## What's New Since v6.0

| Feature | Status |
|---------|--------|
| Interactive Forensic Workflow (3-step) | New |
| Persistent checklist state (localStorage) | New |
| Wireshark Comparison Modal | New |
| TCP Header SVG with dynamic highlights | New |
| Embedded GeoIP in binary | New |
| Generic CLI fallback commands | New |
| Risk warnings per finding type | New |
| Full ELI5 text (no truncation) | Fixed |
| packetContext propagation to FindingCards | New |

---

## Platform Support

| Platform | Architecture | Binary |
|----------|-------------|--------|
| Linux | amd64 | `sdwan-triage-linux-amd64` |
| macOS | Intel (amd64) | `sdwan-triage-darwin-amd64` |
| macOS | Apple Silicon (arm64) | `sdwan-triage-darwin-arm64` |
| Windows | amd64 | `sdwan-triage-windows-amd64.exe` |

All binaries are statically linked (`CGO_ENABLED=0`) and include the embedded frontend + GeoIP database.

---

## Quick Start

```bash
# Download the binary for your platform and make it executable
chmod +x sdwan-triage-darwin-arm64

# Run web mode (opens browser)
./sdwan-triage -web

# Run web mode on custom port, no browser
./sdwan-triage -web -port 9090 -no-browser

# CLI mode — analyze a PCAP directly
./sdwan-triage -lan capture-lan.pcap -wan capture-wan.pcap
```

---

## Binary Size

~97MB (includes embedded React frontend + 63MB GeoIP database + Go binary)

---

## Build From Source

```bash
git clone https://github.com/gocisse/sdwan-triage.git
cd sdwan-triage
make build        # Build for current platform
make release      # Cross-compile for all platforms
make github-release  # Create GitHub release (requires gh CLI)
```

---

## Full Changelog

See [commit history](https://github.com/gocisse/sdwan-triage/compare/v6.0.0...v6.1.0.0) for all changes.
