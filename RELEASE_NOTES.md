<p align="center">
  <img src="Pharaoh.svg.png" alt="SD-WAN Triage" width="100" />
</p>

# SD-WAN Triage v6.0.0 — Modular Architecture & Guided UX

Major release delivering a **fully modular frontend**, **guided onboarding**, and **professional UX enhancements** on top of the existing 35+ network analyzers.

---

## Highlights

### 🏗️ ResultsPage Refactor — Modular Architecture

The monolithic `ResultsPage.tsx` (2,100+ lines) has been decomposed into focused sub-components:

| Component | Lines | Responsibility |
|-----------|-------|---------------|
| `ResultsPage.tsx` | 238 | Thin orchestrator — state management & routing |
| `SummarySection.tsx` | 246 | Top bar, executive summary, topology, filter bar, export |
| `FindingsSection.tsx` | 1,685 | Troubleshooting guidance + all finding categories |
| `DrillDownSection.tsx` | 116 | Forensic sub-tabs (IO Graph, Protocols, Conversations, Expert Info, QoS, Latency, Search) |

### ✨ Onboarding Tour

New first-visit guided tour (5 steps) with spotlight highlighting, keyboard navigation (←/→/Esc), and `localStorage` persistence. Zero external dependencies.

### ⌨️ Keyboard Shortcuts Modal

Press `?` anywhere to see all available keyboard shortcuts. Auto-dismisses on Escape. Skips input fields.

### 💀 Loading Skeletons

Replaced plain spinners with animated skeleton UI (`SummarySkeleton`, `DrillDownSkeleton`, `CardSkeleton`, `TableSkeleton`) for smoother perceived loading.

### 🔬 Backend Analyzers (carried from v5.x)

- **35+ protocol analyzers**: DDoS, port scan, TLS weakness, DNS tunneling, C2 beaconing, DHCP/NTP anomalies, TCP advanced, BFD/IKE/STP flapping, VoIP/RTP, and more
- **Streaming comparison engine**: O(flows) memory, forensic summary with latency/retransmission/handshake analysis
- **Control plane exclusion**: Accurate Path Integrity Score by filtering BFD/OMP/keepalive from WAN denominator

---

## Download

| Platform | Download |
|----------|----------|
| **macOS (Apple Silicon)** | `sdwan-triage-v6.0.0-darwin-arm64.tar.gz` |
| **macOS (Intel)** | `sdwan-triage-v6.0.0-darwin-amd64.tar.gz` |
| **Linux (x86_64)** | `sdwan-triage-v6.0.0-linux-amd64.tar.gz` |
| **Windows (x86_64)** | `sdwan-triage-v6.0.0-windows-amd64.zip` |

Verify integrity: `shasum -a 256 -c checksums-v6.0.0.txt`

---

**Full Changelog:** [v5.0.0...v6.0.0](https://github.com/gocisse/sdwan-triage/compare/v5.0.0...v6.0.0)
