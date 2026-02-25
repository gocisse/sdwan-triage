# SD-WAN Network Triage v4.5.0

[![Release](https://img.shields.io/github/v/release/gocisse/sdwan-triage)](https://github.com/gocisse/sdwan-triage/releases/latest)
[![Go Version](https://img.shields.io/badge/Go-1.24+-00ADD8?logo=go)](https://golang.org/)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-macOS%20|%20Linux%20|%20Windows-lightgrey)](https://github.com/gocisse/sdwan-triage/releases)

**Unified single-binary PCAP analysis platform for SD-WAN networks.** 35+ parallel detectors, JWT-secured React dashboard, vendor-specific troubleshooting runbooks, and enterprise integrations (Prometheus, ServiceNow). One download, zero dependencies.

<p align="center">
  <img src="Pharaoh.svg.png" alt="SD-WAN Triage" width="120" />
</p>

![SD-WAN Triage Dashboard](https://raw.githubusercontent.com/gocisse/sdwan-triage/main/docs/dashboard-preview.png)

---

## Quick Start (Zero Install)

**3 steps. No Node.js. No npm. No Docker. Just one binary.**

```bash
# 1. Download (macOS Apple Silicon example)
curl -LO https://github.com/gocisse/sdwan-triage/releases/latest/download/sdwan-triage-v4.5.0-darwin-arm64.tar.gz
tar xzf sdwan-triage-v4.5.0-darwin-arm64.tar.gz

# 2. Run
./sdwan-triage-darwin-arm64 -web

# 3. Open browser → http://127.0.0.1:8080
#    Login: admin / admin (change password immediately)
```

That's it. The React dashboard, API server, and SQLite database are all embedded in the single binary.

### Download Links

| Platform | Download |
|---|---|
| **macOS (Apple Silicon)** | [`sdwan-triage-v4.5.0-darwin-arm64.tar.gz`](https://github.com/gocisse/sdwan-triage/releases/latest/download/sdwan-triage-v4.5.0-darwin-arm64.tar.gz) |
| **macOS (Intel)** | [`sdwan-triage-v4.5.0-darwin-amd64.tar.gz`](https://github.com/gocisse/sdwan-triage/releases/latest/download/sdwan-triage-v4.5.0-darwin-amd64.tar.gz) |
| **Linux (x86_64)** | [`sdwan-triage-v4.5.0-linux-amd64.tar.gz`](https://github.com/gocisse/sdwan-triage/releases/latest/download/sdwan-triage-v4.5.0-linux-amd64.tar.gz) |
| **Windows (x86_64)** | [`sdwan-triage-v4.5.0-windows-amd64.zip`](https://github.com/gocisse/sdwan-triage/releases/latest/download/sdwan-triage-v4.5.0-windows-amd64.zip) |

Verify downloads with [`checksums-v4.5.0.txt`](https://github.com/gocisse/sdwan-triage/releases/latest/download/checksums-v4.5.0.txt).

---

## Two Modes of Operation

The same binary supports two workflows. Choose the one that fits your role.

### Web Mode — Interactive Dashboard

**Best for:** Junior engineers, visual triage, team collaboration, guided troubleshooting.

```bash
./sdwan-triage -web                    # Opens browser automatically
./sdwan-triage -web -port 9090         # Custom port
./sdwan-triage -web -no-browser        # Don't auto-open browser
```

**What you get:**
- Drag-and-drop PCAP upload with real-time progress
- Executive summary with risk scoring
- Interactive findings with the **Troubleshooting Wizard** (see below)
- Topology visualization, flow tables, bandwidth charts
- History of past analyses
- JWT-secured login with role-based access

### CLI Mode — Automation & Scripting

**Best for:** Senior engineers, CI/CD pipelines, batch processing, automation.

```bash
# Console output with executive summary
./sdwan-triage capture.pcap

# Interactive HTML report (recommended for sharing)
./sdwan-triage -html report.html capture.pcap

# JSON output for automation pipelines
./sdwan-triage -json capture.pcap > results.json

# CSV export for spreadsheets
./sdwan-triage -csv findings.csv capture.pcap

# PDF report (requires wkhtmltopdf)
./sdwan-triage -pdf report.pdf capture.pcap

# Plain English report for non-technical stakeholders
./sdwan-triage -simple capture.pcap

# Compare two captures (before/after change window)
./sdwan-triage -compare before.pcap after.pcap

# Compare LAN vs WAN with tunnel decapsulation
./sdwan-triage -compare lan-capture.pcap wan-capture.pcap
```

---

## Forensic Workflow — LAN vs. WAN Comparison

Version 4.5.0 introduces **tunnel-aware PCAP comparison** for forensic troubleshooting across SD-WAN devices. Place a capture on the LAN side and another on the WAN side of your SD-WAN appliance to determine exactly where packets are dropped, modified, or encrypted.

### How It Works

```
   [LAN Capture]               [SD-WAN Device]              [WAN Capture]
   (clear-text)          ┌─────────────────────┐          (encapsulated)
  ────────────────────►   │  IPsec / VXLAN / GRE │   ────────────────────►
   10.1.1.5:443 → ...    │  VCMP / Viptela DTLS │   Outer: WAN_A → WAN_B
                          └─────────────────────┘   Inner: 10.1.1.5:443 → ...
```

1. **Upload two PCAPs** — File A (LAN-side, before SD-WAN) and File B (WAN-side, after SD-WAN)
2. The comparator **auto-detects tunnel encapsulation** on the WAN capture:
   - **Cisco Viptela** (UDP 12346–12426, DTLS)
   - **VMware VeloCloud** VCMP (UDP 2426)
   - **VXLAN** (UDP 4789)
   - **GRE** (IP Protocol 47)
   - **IPsec ESP** (IP Protocol 50)
3. **Inner IP headers are extracted** from decapsulatable tunnels and matched against LAN-side packets using the 5-tuple (Src IP, Dst IP, Src Port, Dst Port, Protocol)
4. Encrypted tunnels (ESP, DTLS) are flagged — the tool reports them separately since inner headers are hidden by encryption

### CLI Usage

```bash
# Basic comparison
./sdwan-triage -compare lan-side.pcap wan-side.pcap

# With HTML report
./sdwan-triage -compare -html comparison.html lan-side.pcap wan-side.pcap
```

### Example Output

```
  ╔══════════════════════════════════════════╗
  ║  Path Integrity Score:  87.3% (Healthy)  ║
  ╚══════════════════════════════════════════╝

  ━━━ TUNNEL ENCAPSULATION DETECTED ━━━
  ● Viptela: 5824 packets
  Decapsulated (inner extracted): 4920
  ⚠ 904 packets encrypted (ESP/DTLS) — inner flow hidden

  ━━━ PACKET SUMMARY ━━━
  Matched (PRESENT_BOTH):        8734
  Missing from WAN (MISSING_B):  312  (dropped by device)
  Modified (TTL/DSCP/NAT):       89
```

### Web Dashboard

In the web UI, navigate to the **Compare** tab to upload two PCAPs and view an interactive comparison report with:

- **Path Integrity Score** — percentage of packets successfully traversing the device
- **Tunnel Encapsulation Banner** — detected tunnel types, decapsulation stats, encryption warnings
- **Flow Table** — per-flow match rates with NAT and tunnel badges
- **Flow Graph** — visual sequence diagrams (see below)
- **Discrepancy List** — filterable list of dropped, modified, and asymmetric packets

---

## Flow Graph Visualization

The **Flow Graph** renders a sequence diagram for any selected flow, making packet drops and modifications immediately obvious to non-packet-experts.

<!-- Screenshot: docs/flow-graph-preview.png -->
![Flow Graph Sequence Diagram](https://raw.githubusercontent.com/gocisse/sdwan-triage/main/docs/flow-graph-preview.png)

### Visual Encoding

| Arrow Style | Color | Meaning |
|---|---|---|
| **Solid →** | 🟢 Green | Packet matched — present in both LAN and WAN captures |
| **Dashed ╌╌ ✕** | 🔴 Red | Packet dropped — present in LAN, missing from WAN (stops at SD-WAN device) |
| **Solid →** | 🟡 Yellow | Packet modified — NAT translation, TTL decrement, or DSCP remarking detected |
| **Dashed 🔒** | 🔵 Cyan | Encrypted tunnel packet — inner flow hidden by IPsec/DTLS |
| **Dashed →** | 🟣 Purple | Asymmetric — packet in WAN but not LAN (injected or return-path traffic) |

### How to Use

1. Go to the **Compare** tab and run a comparison
2. Switch to the **Flows** tab
3. Click the **"Flow Graph"** button on any flow row
4. A modal opens with the sequence diagram showing every packet event for that flow

```
  [LAN Client]              [SD-WAN Device]              [WAN Server]
      |                          |                           |
      |  ──[SYN]──────────►     |     ────────────────►     |  ✅ Matched
      |                          |                           |
      |  ◄──[SYN-ACK]────  ✕   |                           |  ❌ Dropped
      |                          |                           |
      |  ──[SYN]──────────►     |     ────────────────►     |  ✅ Retransmission Matched
      |                          |                           |
      |  ──[PSH,ACK]─────►     |     ──── 🔒 ────────►     |  🔐 Encrypted
      |                          |                           |
      |  ──[FIN,ACK]─────►     |     ────(NAT)────►        |  ⚠️  Modified (src IP changed)
```

---

## Authentication

All API endpoints require JWT authentication. On first startup, a default admin user is created:

```
┌──────────────────────────────────────────────────────────────┐
│  ⚠  WARNING: Default admin user created.                     │
│  Username: admin  |  Password: admin                         │
│  PLEASE CHANGE THE PASSWORD IMMEDIATELY.                     │
└──────────────────────────────────────────────────────────────┘
```

**Change your password:** Click your username in the top-right corner → **Change Password**.

### Roles

| Role | Permissions |
|---|---|
| `admin` | Full access + user management (`/api/auth/users`) |
| `analyst` | Upload PCAPs, run analysis, view results |
| `viewer` | View results only |

### API Authentication (for scripts)

```bash
# 1. Get a token
TOKEN=$(curl -s -X POST http://127.0.0.1:8080/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin"}' | jq -r '.token')

# 2. Use the token
curl -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8080/api/history
```

---

## Troubleshooting Wizard

The web dashboard includes a **guided troubleshooting wizard** that helps engineers diagnose findings step-by-step.

### How It Works

1. Click any finding card in the results page
2. The wizard checks for **vendor-specific runbooks** first (e.g., VeloCloud `debug.py` commands)
3. Falls back to **generic knowledge base** entries if no vendor runbook exists
4. Every finding includes an **ELI5** (Explain Like I'm 5) explanation

### VeloCloud Example

When a VeloCloud tunnel flapping issue is detected, the wizard shows:

```
📋 Vendor Runbook: VMware VeloCloud — Tunnel Flapping

CLI Steps:
  1. debug.py --tunnel --status
     → Shows current tunnel state and uptime
  2. debug.py --path --list
     → Lists all paths and their quality metrics
  3. debug.py --tunnel --history
     → Shows tunnel state change history

⚠️  Safety: These commands are read-only but may increase CPU briefly.

GUI Steps:
  1. Navigate to Monitor → Edges → [Edge Name] → Paths
  2. Check path quality metrics (latency, jitter, loss)
  3. Review Events tab for tunnel state changes

💡 ELI5: "The secure highway between your offices keeps closing and
reopening. Every time it closes, traffic has to find another route."
```

Supported vendors: **VeloCloud**, Cisco Viptela, Fortinet, Palo Alto Prisma, Silver Peak, Aruba EdgeConnect, Versa Networks.

---

## Troubleshooting Workflow

Version 4.5.0 provides a complete **end-to-end troubleshooting pipeline**. Follow these four stages to go from raw PCAP to actionable resolution.

```
  ┌──────────┐    ┌──────────┐    ┌───────────────────┐    ┌──────────┐
  │  Upload   │───►│  Wizard   │───►│  Forensic         │───►│  Export   │
  │           │    │           │    │  Drill-Down        │    │           │
  │ Drag-drop │    │ Guided    │    │ Protocol Hierarchy │    │ Filtered  │
  │ PCAP file │    │ step-by-  │    │ Conversations      │    │ PCAP for  │
  │           │    │ step fix  │    │ IO Graphs          │    │ Wireshark │
  └──────────┘    └──────────┘    └───────────────────┘    └──────────┘
```

### Stage 1: Upload

Drag and drop a PCAP or pcapng file into the web dashboard. The tool runs **35+ detectors in parallel** and produces results within seconds. The **Executive Summary** gives you a risk score and top findings immediately.

### Stage 2: Wizard

Click any finding card to open the **Troubleshooting Wizard**. It checks for vendor-specific CLI runbooks first (e.g., VeloCloud `debug.py`, Viptela `show` commands), then falls back to generic knowledge base entries. Every finding includes:
- **WHAT** — Plain-English explanation of the issue
- **WHY** — Root cause analysis and impact
- **HOW** — Step-by-step remediation with CLI commands and Wireshark filters

### Stage 3: Forensic Drill-Down

Switch to the **Forensic Drill-Down** tab for deep-dive analysis:
- **IO Graphs** — Time-series packet/byte charts with click-to-zoom
- **Protocol Hierarchy** — Ethernet → IP → TCP/UDP → Application breakdown with percentages
- **Conversations** — Sortable src↔dst matrix with packets, bytes, duration, throughput
- **Expert Info** — Aggregated anomaly stream from all detectors with severity filtering
- **Display Filter** — Wireshark-like filter bar (`ip.src == 10.0.0.1 && tcp.port == 443`)

### Stage 4: Export

Click **Export Filtered PCAP** to download a subset of the original capture matching your current display filter. Open it directly in Wireshark for packet-level inspection, or attach it to a TAC/vendor support case.

---

## Smart Insights for Junior Engineers

Version 4.5.0 introduces a clear distinction between **Issues** (actionable problems) and **Insights** (passive observations). This helps junior engineers focus on what matters without being confused by informational findings.

### Issues vs. Insights

| Type | Badge | Meaning | Example |
|------|-------|---------|---------|
| **Issue** | `3` (solid badge) | Actionable problem requiring investigation | DDoS Attack, DHCP Rogue Server, TCP Retransmissions |
| **Insight** | `+2` (subtle badge) | Passive observation — healthy, no action needed | CDP/LLDP Device Discovery, STP Topology, VRRP Sessions |

### Category Breakdown

Each sidebar category can show **both Issues and Insights**. Here's what to expect:

| Category | Issues (Red/Amber) | Insights (Grey) |
|----------|-------------------|-----------------|
| **Security** | DDoS, Port Scan, DNS Tunneling, C2 Beaconing | IOC database status |
| **Performance** | High RTT, Retransmissions, Packet Loss, TCP Zero Window | QoS class distribution, Bandwidth stats |
| **Infrastructure** | DHCP Rogue Server, NTP Amplification, BFD Flapping | CDP/LLDP Discovery, STP Topology, VRRP/HSRP Sessions |
| **Stability** | BFD Flapping, IKE Tunnel Rebuild, STP TCN Storm, HSRP/VRRP Flapping | Stable redundancy protocol sessions |
| **SD-WAN** | Tunnel Flapping, Path Quality Degradation | Vendor detection, Overlay tunnel inventory |

> **Tip for Junior Engineers:** Red badges mean "investigate now." Grey `+N` badges mean "good to know." Start with red, then use grey insights to understand the network topology and context around the issue.

### How It Appears in the Sidebar

```
Security        3         ← 3 actionable issues (red/amber)
Performance     1         ← 1 actionable issue
Infrastructure  +3        ← 3 healthy observations (subtle, no alarm)
SD-WAN          +2        ← 2 informational detections
```

The sidebar also includes a helper legend:

> **Insights (+N):** Passive observations about your network — not errors or issues. These help you understand what's running, but require no action.

### Vendor-Specific Wireshark Filters

Each tunnel finding now shows the **correct vendor-specific Wireshark filter**, so junior engineers can copy-paste directly into Wireshark without guessing ports:

| Vendor | Wireshark Filter |
|--------|-----------------|
| **Cisco Viptela** | `udp.port == 12346 \|\| udp.port == 12366 \|\| udp.port == 23456 \|\| tcp.port == 23456` |
| **VMware VeloCloud** | `udp.port == 2426` |
| **Fortinet** | `udp.port == 541 \|\| tcp.port == 541` |
| **Aruba EdgeConnect** | `udp.port == 4163 \|\| udp.port == 4980 \|\| udp.port == 4500 \|\| esp` |

> **Tip:** Insights like CDP, LLDP, and STP help you map the network topology without triggering alarms for healthy redundancy protocols. Use them to build documentation and verify your physical/logical design.

---

## Enterprise Integration Setup

### Prometheus Metrics

Metrics are always enabled. Scrape the standard endpoint:

```yaml
# prometheus.yml
scrape_configs:
  - job_name: 'sdwan-triage'
    static_configs:
      - targets: ['127.0.0.1:8080']
    metrics_path: '/metrics'
```

```bash
# Verify
curl http://127.0.0.1:8080/metrics
```

Exposed metrics include analysis counters, packet rates, risk scores, and finding type distributions.

### ServiceNow Ticketing

Automatically creates incidents for **Critical** risk findings.

```bash
./sdwan-triage -web \
  -servicenow-url https://your-instance.service-now.com \
  -servicenow-user api_user \
  -servicenow-password your_password
```

When a PCAP analysis produces a Critical risk score (>50), a ServiceNow incident is created with the finding details, recommended actions, and a link to the full report.

### Automation Engine

Built-in triggers fire on analysis events. Default triggers:
- **Log** all detected issues
- **Slack notification** on Critical findings (requires webhook URL)
- **ServiceNow ticket** on Critical findings (requires credentials above)

---

## Security

> **⚠️ IMPORTANT:** The web server binds to `127.0.0.1` (localhost only) by default. If you need remote access, use a reverse proxy (nginx, Caddy) with TLS termination.

- **Authentication:** JWT tokens with 24-hour expiry, bcrypt-hashed passwords
- **Database:** SQLite stored at `~/.sdwan-triage/sdwan.db`
- **Secret:** JWT signing key is randomly generated per process start — all tokens invalidate on restart
- **Default credentials:** `admin` / `admin` — **change immediately**
- **HTTPS:** Not built-in. Use a reverse proxy for production deployments

---

## Detectors (35+)

### Security Analysis

| Detector | Description |
|---|---|
| **DDoS Detection** | SYN flood, UDP flood, ICMP flood with configurable thresholds |
| **Port Scanning** | Horizontal, vertical, and block scan detection |
| **TLS Security** | Weak ciphers, outdated protocols, certificate chain analysis |
| **IOC Matching** | Indicator of Compromise checking with custom databases |
| **BGP Hijack Heuristics** | Route anomaly detection + live RIPE stat API lookups |
| **DNS Tunneling** | Shannon entropy, query length, subdomain count analysis |
| **C2 Beaconing** | Interval regularity, payload consistency, outbound-only detection |
| **DHCP Attacks** | Rogue server detection, starvation attacks, NAK storms |
| **NTP Attacks** | Amplification, stratum changes, monlist responses |
| **ICMP Anomalies** | Unusual ICMP patterns and covert channel detection |
| **GeoIP Analysis** | Country/city-level traffic distribution (MaxMind MMDB or heuristic) |
| **Suspicious Traffic** | Anomalous flow patterns and protocol misuse |

### Performance Monitoring

| Detector | Description |
|---|---|
| **TCP Handshake Analysis** | SYN/SYN-ACK/ACK tracking with color-coded states |
| **TCP Retransmissions** | Packet loss and congestion identification |
| **TCP Advanced** | Zero Window, Small Window, Out-of-Order detection |
| **RTT Distribution** | Latency histogram with configurable thresholds |
| **Bandwidth Tracking** | Per-flow and aggregate throughput with time series |
| **Packet Loss** | Per-flow loss percentage and duplicate detection |
| **Jitter & VoIP Quality** | SIP call tracking, RTP stream quality, codec identification |
| **Wireshark Filters** | Auto-generated per-flow directional and bidirectional filters |

### Protocol & Tunnel Detection

| Category | Protocols |
|---|---|
| **DNS/HTTP** | NXDOMAIN, DGA, status codes, HTTP/2, QUIC |
| **TLS/SSL** | Certificate extraction, cipher suite analysis |
| **VoIP** | SIP call tracking, RTP/RTCP stream quality |
| **ARP** | Conflict and spoofing detection |
| **LAN** | VRRP, CDP, LLDP, HSRP, STP (with flapping detection) |
| **Tunnels** | VXLAN, GRE, NVGRE, ERSPAN, MPLS, IPsec, GTP, L2TP |
| **VPN** | OpenVPN, WireGuard |
| **SD-WAN** | Cisco Viptela, VMware VeloCloud, Fortinet, Palo Alto Prisma, Silver Peak, Aruba, Versa, Citrix |

---

## CLI Reference

### Filtering

```bash
./sdwan-triage -src-ip 192.168.1.100 capture.pcap
./sdwan-triage -dst-ip 10.0.0.50 capture.pcap
./sdwan-triage -service https capture.pcap
./sdwan-triage -protocol tcp capture.pcap
```

### Advanced Analysis

```bash
./sdwan-triage -qos-analysis -html qos.html capture.pcap   # QoS/DSCP
./sdwan-triage -show-handshakes capture.pcap                # TCP handshakes
./sdwan-triage -failed-only capture.pcap                    # Failed handshakes only
./sdwan-triage -app-identify capture.pcap                   # Deep app identification
./sdwan-triage -bgp-check capture.pcap                      # BGP via RIPE stat
./sdwan-triage -trace-path capture.pcap                     # Traceroute anomalies
./sdwan-triage -bgp-check -no-external-lookup capture.pcap  # Offline mode
```

### All Flags

| Flag | Description |
|---|---|
| `-web` | Start web server with embedded React dashboard |
| `-port <N>` | Web server port (default: 8080) |
| `-no-browser` | Don't auto-open browser in web mode |
| `-servicenow-url <url>` | ServiceNow instance URL |
| `-servicenow-user <user>` | ServiceNow API username |
| `-servicenow-password <pw>` | ServiceNow API password |
| `-html <file>` | Interactive HTML report |
| `-multi-page-html <dir>` | Multi-page HTML report |
| `-json` | JSON output for automation |
| `-csv <file>` | CSV export |
| `-pdf <file>` | PDF report (requires wkhtmltopdf) |
| `-simple` | Plain English report |
| `-config <path>` | Threshold config: `default`, `performance`, `security`, or YAML |
| `-src-ip <ip>` | Filter by source IP |
| `-dst-ip <ip>` | Filter by destination IP |
| `-service <port>` | Filter by service port or name |
| `-protocol <proto>` | Filter by protocol: `tcp` or `udp` |
| `-qos-analysis` | QoS/DSCP traffic class analysis |
| `-show-handshakes` | TCP handshake analysis |
| `-failed-only` | Failed TCP handshakes only |
| `-app-identify` | Deep application identification |
| `-bgp-check` | BGP prefix lookup via RIPE stat |
| `-no-external-lookup` | Disable all external network calls |
| `-compare` | Compare LAN vs WAN PCAPs with tunnel-aware decapsulation |
| `-verbose` | Debug output |

---

## Configuration

Override detection thresholds using `-config`:

```bash
./sdwan-triage -config security capture.pcap    # Built-in preset
./sdwan-triage -config thresholds.yaml capture.pcap  # Custom YAML
```

```yaml
# thresholds.yaml
ddos:
  syn_threshold: 50
  udp_threshold: 100
  icmp_threshold: 50

performance:
  high_rtt_ms: 50.0
  critical_rtt_ms: 100.0
  packet_loss_warn: 0.5
  jitter_warn_ms: 20.0

analysis:
  detection_window_sec: 10.0
  max_flows_in_report: 500
```

---

## GeoIP Database

Optional. Enables country/city-level IP geolocation. Without it, the tool uses built-in IP range heuristics.

```bash
# Automatic setup
export MAXMIND_LICENSE_KEY=your_key   # Free signup at maxmind.com
make setup-geoip

# Manual: place GeoLite2-City.mmdb in ./data/ or any standard path
make check-geoip   # Verify
```

---

## Performance

Tested on Apple M2 Pro (12-core, 32GB RAM):

| PCAP Size | Packets | Time | Memory | Flows |
|---|---|---|---|---|
| 10 MB | ~15K | 0.3s | 45 MB | ~200 |
| 100 MB | ~150K | 1.8s | 120 MB | ~2,500 |
| 500 MB | ~750K | 8.2s | 380 MB | ~12,000 |
| 1 GB | ~1.5M | 16.5s | 650 MB | ~25,000 |

~90K packets/sec sustained. HTML reports render in <500ms. Frontend handles 100K+ rows via virtualized tables.

---

## Build from Source

```bash
git clone https://github.com/gocisse/sdwan-triage.git
cd sdwan-triage

make build          # Frontend + backend → single binary
make test           # Run all tests
make release        # Cross-compile all platforms + checksums
make run-web        # Dev: run web mode
make frontend-dev   # Dev: Vite dev server with HMR
make help           # Show all targets
```

**Requirements:** Go 1.24+, Node.js 18+ (build only — not needed to run the binary).

---

## Project Structure

```
sdwan-triage/
├── cmd/sdwan-triage/              # Unified entry point
│   ├── main.go                    # CLI flags, mode dispatch
│   ├── webserver.go               # Gin server, auth middleware, routes
│   ├── auth_handlers.go           # Login, user management endpoints
│   ├── embed.go                   # //go:embed for React dist/
│   └── dist/                      # Embedded frontend (build artifact)
├── pkg/
│   ├── analyzer/                  # Packet processing engine (35+ detectors) + PCAP comparator
│   ├── database/                  # SQLite user DB (modernc.org/sqlite)
│   ├── middleware/                # JWT auth middleware
│   ├── detector/                  # All protocol & security detectors
│   ├── integration/               # ServiceNow, Automation engine
│   ├── intelligence/              # Customer intelligence DB
│   ├── metrics/                   # Prometheus collector
│   ├── models/                    # TriageReport, finding structs
│   ├── output/                    # HTML, CSV, PDF, JSON report generators
│   ├── web/handlers/              # API handlers (upload, analyze, results)
│   └── web/storage/               # Embedded Redis for job state
├── web/frontend/                  # React + Vite + TailwindCSS
│   └── src/
│       ├── auth/                  # AuthContext, token management
│       ├── pages/                 # Login, Home, Analysis, Results, History
│       ├── components/            # ComparisonView, FlowGraphView, HexViewer, StreamModal
│       ├── components/dashboard/  # ExecutiveSummary, WizardModal, FindingCard
│       ├── data/                  # knowledgeBase, vendorRunbooks
│       └── hooks/                 # useAnalysis, useWebSocket, useFileUpload
├── Makefile                       # build, release, test, frontend targets
└── README.md
```

---

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Run tests (`make test`)
4. Commit your changes (`git commit -m 'Add amazing feature'`)
5. Push to the branch (`git push origin feature/amazing-feature`)
6. Open a Pull Request

---

## License

MIT License — see [LICENSE](LICENSE).

## Acknowledgments

- [gopacket](https://github.com/google/gopacket) — Packet processing
- [maxminddb-golang](https://github.com/oschwald/maxminddb-golang) — GeoIP database reader
- [modernc.org/sqlite](https://pkg.go.dev/modernc.org/sqlite) — Pure Go SQLite
- [golang-jwt](https://github.com/golang-jwt/jwt) — JWT authentication
- [D3.js](https://d3js.org/) — Interactive visualizations
- [React](https://react.dev/) + [Vite](https://vitejs.dev/) + [TailwindCSS](https://tailwindcss.com/) — Frontend stack
- [RIPE stat](https://stat.ripe.net/) — BGP prefix lookup API

## Support

- **Issues**: [GitHub Issues](https://github.com/gocisse/sdwan-triage/issues)
- **Discussions**: [GitHub Discussions](https://github.com/gocisse/sdwan-triage/discussions)

---

**Made with care for the network engineering community**
