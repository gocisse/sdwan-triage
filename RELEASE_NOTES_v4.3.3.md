# SD-WAN Triage v4.3.3 — Release Notes

**Release Date:** February 24, 2026
**Tag:** `v4.3.3`

---

## Highlights

### 🔬 Tunnel-Aware PCAP Comparison

Compare LAN-side and WAN-side captures across SD-WAN devices with **automatic tunnel decapsulation**. The comparator detects encapsulated traffic and extracts inner IP headers for accurate packet matching — no manual decap needed.

**Supported Tunnel Types:**

| Tunnel | Detection | Decapsulation |
|--------|-----------|---------------|
| **Cisco Viptela** | UDP 12346–12426 | ✅ Clear-text control / ⚠️ DTLS encrypted flagged |
| **VMware VeloCloud VCMP** | UDP 2426 | ✅ Proprietary header auto-detected |
| **VXLAN** | UDP 4789 | ✅ 8B VXLAN + 14B inner Ethernet stripped |
| **GRE** | IP Protocol 47 | ✅ Inner IP extracted from GRE payload |
| **IPsec ESP** | IP Protocol 50 | ⚠️ Encrypted — ESP SPI/Seq extracted for correlation |

**What it reports:**
- **Path Integrity Score** — percentage of packets successfully traversing the device
- **Tunnel Encapsulation Banner** — per-type packet counts, decapsulation success rate
- **Encrypted Packet Handling** — ESP/DTLS packets excluded from false MISSING_A counts
- **NAT Detection** — identifies source IP translation across the device
- **TTL/DSCP Modification Tracking** — expected hop decrements vs. QoS remarking

### 📊 Flow Graph Visualization (Sequence Diagrams)

New visual troubleshooting for non-packet-experts. Click **"Flow Graph"** on any flow in the Comparison results to see a sequence diagram:

- 🟢 **Green solid arrow** — Packet matched (present in both captures)
- 🔴 **Red dashed arrow + ✕** — Packet dropped (stops at SD-WAN device)
- 🟡 **Yellow solid arrow** — Packet modified (NAT/TTL/DSCP change with field diff)
- 🔵 **Cyan dashed arrow + 🔒** — Encrypted tunnel packet
- 🟣 **Purple dashed arrow** — Asymmetric (WAN-only, injected or return-path)

Pure SVG rendering — zero external dependencies. Up to 60 events per flow, sorted by timestamp.

### 🔍 Packet Inspection Enhancements

- **Hex Viewer** — byte-level packet inspection with offset/ASCII display
- **TCP Stream Reassembly** — reconstruct application-layer conversations

### 🔐 Security & Persistence

- **JWT Authentication** — all API endpoints secured with 24-hour token expiry
- **SQLite Persistence** — user accounts, analysis history, and settings survive restarts
- **Role-Based Access** — admin, analyst, viewer roles

---

## CLI Changes

```bash
# NEW: LAN vs WAN comparison with tunnel decapsulation
./sdwan-triage -compare lan-side.pcap wan-side.pcap

# Comparison output includes tunnel detection banner
# and per-flow match rates with encrypted packet handling
```

## Web UI Changes

- **Compare tab** added to navigation
- **Tunnel Encapsulation Banner** — cyan panel showing detected tunnel types, decapsulated/encrypted counts
- **Flow Table** — tunnel type badges (cyan) alongside NAT badges per flow
- **Flow Graph button** — opens sequence diagram modal from the Flows tab
- **Discrepancy Table** — tunnel type and encryption indicators per packet

---

## Files Changed

### Backend (Go)
- `cmd/sdwan-triage/main.go` — Version bump to 4.3.3
- `pkg/analyzer/comparator.go` — Tunnel detection engine (ESP, GRE, VXLAN, VCMP, Viptela), inner IP decapsulation, encrypted packet handling, tunnel metadata in report/discrepancies/flows

### Frontend (React/TypeScript)
- `web/frontend/src/components/FlowGraphView.tsx` — **NEW** — SVG sequence diagram component
- `web/frontend/src/components/ComparisonView.tsx` — Tunnel banner, Flow Graph button, visualize modal
- `web/frontend/src/types/index.ts` — Tunnel fields in ComparisonReport, Discrepancy, FlowComparisonSummary

### Build & Docs
- `Makefile` — Version bump to 4.3.3
- `README.md` — Forensic Workflow section, Flow Graph documentation, updated CLI reference

---

## Build & Install

```bash
# From source
git clone https://github.com/gocisse/sdwan-triage.git
cd sdwan-triage
make release VERSION=4.3.3

# Or download pre-built binaries:
# macOS (Apple Silicon): sdwan-triage-v4.3.3-darwin-arm64.tar.gz
# macOS (Intel):         sdwan-triage-v4.3.3-darwin-amd64.tar.gz
# Linux (x86_64):        sdwan-triage-v4.3.3-linux-amd64.tar.gz
# Windows (x86_64):      sdwan-triage-v4.3.3-windows-amd64.zip
```

Verify with `checksums-v4.3.3.txt`.

---

## Upgrade Notes

- **No breaking changes** from v4.3.2
- Comparison mode is additive — all existing CLI flags and web features unchanged
- Tunnel decapsulation is automatic — no configuration required
- Encrypted tunnel packets (ESP/DTLS) are gracefully handled and reported, not silently dropped

---

**Full Changelog:** [`v4.3.2...v4.3.3`](https://github.com/gocisse/sdwan-triage/compare/v4.3.2...v4.3.3)
