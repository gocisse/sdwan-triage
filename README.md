# SD-WAN Network Triage v4.5.3

[![Release](https://img.shields.io/github/v/release/gocisse/sdwan-triage)](https://github.com/gocisse/sdwan-triage/releases/latest)
[![Go Version](https://img.shields.io/badge/Go-1.24+-00ADD8?logo=go)](https://golang.org/)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-macOS%20|%20Linux%20|%20Windows-lightgrey)](https://github.com/gocisse/sdwan-triage/releases)

**Unified single-binary PCAP analysis platform for SD-WAN networks.** 35+ parallel detectors, Wireshark-style forensic drill-down, Follow Stream, JWT-secured React dashboard, vendor-specific troubleshooting runbooks, and enterprise integrations (Prometheus, ServiceNow). One download, zero dependencies.

<p align="center">
  <img src="Pharaoh.svg.png" alt="SD-WAN Triage" width="120" />
</p>

![SD-WAN Triage Dashboard](https://raw.githubusercontent.com/gocisse/sdwan-triage/main/docs/dashboard-preview.png)

---

## Table of Contents

- [Quick Start](#quick-start-zero-install)
- [Two Modes of Operation](#two-modes-of-operation)
- [Forensic Drill-Down](#forensic-drill-down)
- [Follow Stream](#follow-stream)
- [Packet Inspection & Hex Viewer](#packet-inspection--hex-viewer)
- [LAN vs WAN Comparison](#forensic-workflow--lan-vs-wan-comparison)
- [Flow Graph Visualization](#flow-graph-visualization)
- [Troubleshooting Wizard](#troubleshooting-wizard)
- [Authentication & Roles](#authentication)
- [Detectors (35+)](#detectors-35)
- [CLI Reference](#cli-reference)
- [Enterprise Integrations](#enterprise-integration-setup)
- [Configuration](#configuration)
- [API Reference](#api-reference)
- [Build from Source](#build-from-source)
- [Project Structure](#project-structure)

---

## Quick Start (Zero Install)

**3 steps. No Node.js. No npm. No Docker. Just one binary.**

```bash
# 1. Download (macOS Apple Silicon example)
curl -LO https://github.com/gocisse/sdwan-triage/releases/latest/download/sdwan-triage-v4.5.3-darwin-arm64.tar.gz
tar xzf sdwan-triage-v4.5.3-darwin-arm64.tar.gz

# 2. Run
./sdwan-triage-darwin-arm64 -web

# 3. Open browser → http://127.0.0.1:8080
#    Login: admin / admin (change password immediately)
```

That's it. The React dashboard, API server, and SQLite database are all embedded in the single binary.

### Download Links

| Platform | Download |
|---|---|
| **macOS (Apple Silicon)** | [`sdwan-triage-v4.5.3-darwin-arm64.tar.gz`](https://github.com/gocisse/sdwan-triage/releases/latest/download/sdwan-triage-v4.5.3-darwin-arm64.tar.gz) |
| **macOS (Intel)** | [`sdwan-triage-v4.5.3-darwin-amd64.tar.gz`](https://github.com/gocisse/sdwan-triage/releases/latest/download/sdwan-triage-v4.5.3-darwin-amd64.tar.gz) |
| **Linux (x86_64)** | [`sdwan-triage-v4.5.3-linux-amd64.tar.gz`](https://github.com/gocisse/sdwan-triage/releases/latest/download/sdwan-triage-v4.5.3-linux-amd64.tar.gz) |
| **Windows (x86_64)** | [`sdwan-triage-v4.5.3-windows-amd64.zip`](https://github.com/gocisse/sdwan-triage/releases/latest/download/sdwan-triage-v4.5.3-windows-amd64.zip) |

Verify downloads with [`checksums-v4.5.3.txt`](https://github.com/gocisse/sdwan-triage/releases/latest/download/checksums-v4.5.3.txt).

> **macOS users:** Binaries are ad-hoc codesigned. If you still see a Gatekeeper warning after extracting, run:
> ```bash
> xattr -d com.apple.quarantine sdwan-triage-darwin-arm64
> ```

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
- Executive summary with risk scoring and network health assessment
- Interactive findings with the **Troubleshooting Wizard**
- **Forensic Drill-Down** — IO Graphs, Protocol Hierarchy, Conversations, Expert Info
- **Follow Stream** — TCP/UDP stream reassembly with Wireshark filter export
- **Packet Inspection** — Hex viewer with protocol layer decode
- **Export Filtered PCAP** — Wireshark-like display filter + PCAP carving
- **Network Topology** — Auto-discovered topology graph with CDP/LLDP data
- History of past analyses with comparison
- JWT-secured login with role-based access (admin, analyst, viewer)

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

## Forensic Drill-Down

Switch to the **Forensic Drill-Down** tab after analyzing a PCAP for Wireshark-level deep-dive analysis — all inside the browser.

### IO Graphs

Time-series packet/byte charts with configurable bucket sizes. Click any bar to drill down into that time window — the display filter auto-updates to `frame.time_epoch > X && frame.time_epoch < Y`.

### Protocol Hierarchy

Tree-structured breakdown of all protocols detected in the capture:

```
Ethernet                100.0%   10,175 pkts   4.9 MB
  └─ IPv4                98.2%    9,993 pkts   4.8 MB
       ├─ TCP            85.4%    8,689 pkts   4.2 MB
       │    ├─ TLS       42.1%    4,284 pkts   2.1 MB
       │    └─ HTTP       3.2%      326 pkts   158 KB
       └─ UDP            12.8%    1,304 pkts   634 KB
            ├─ DNS        4.1%      417 pkts   203 KB
            └─ NTP        0.3%       31 pkts    15 KB
```

### Conversations

Sortable source ↔ destination matrix with packets, bytes, duration, and throughput. Click any row to set a display filter. Search by IP or port.

### Expert Info

Aggregated anomaly stream from all 35+ detectors — filter by severity (Critical, Warning, Info) or category (Security, Performance, Infrastructure). Click to jump to the hex viewer or follow a stream.

### Display Filter

Wireshark-like filter bar supporting:

```
ip.src == 10.0.0.1 && tcp.port == 443
ip.addr == 192.168.1.0/24
udp.port == 53 && dns.qry.name contains "example"
frame.protocol == TLS
```

Supported fields: `ip.src`, `ip.dst`, `ip.addr`, `tcp.port`, `tcp.srcport`, `tcp.dstport`, `udp.port`, `udp.srcport`, `udp.dstport`, `dns.qry.name`, `frame.protocol`, `eth.type`, `frame.time_epoch`.

---

## Follow Stream

Click the **Follow Stream** button on any flow in the Conversations table, Expert Info, or Findings panel to open a Wireshark-style TCP/UDP stream reassembly view.

**What you see:**
- **Client → Server** segments interleaved with **Server → Client** segments
- Timestamp, packet index, and byte count for each segment
- Hex dump toggle per segment
- **Wireshark filter** — auto-generated, click to copy:
  ```
  (ip.addr == 10.152.9.52 && ip.addr == 10.255.242.169) && (tcp.port == 443 && tcp.port == 50137)
  ```
- Stream metadata: protocol, application (HTTP/TLS/DNS), packet count, total bytes

---

## Packet Inspection & Hex Viewer

Click any packet index in the Follow Stream modal or Expert Info to open the **Hex Viewer**:

- Full protocol layer decode (Ethernet → IPv4 → TCP → Application)
- Field-by-field breakdown with flags (SYN, ACK, PSH, etc.)
- Wireshark-style hex dump with ASCII representation
- Navigate between packets with arrow keys
- Auto-generated per-packet Wireshark filter

---

## Forensic Workflow — LAN vs. WAN Comparison

**Tunnel-aware PCAP comparison** for forensic troubleshooting across SD-WAN devices. Place a capture on the LAN side and another on the WAN side to determine exactly where packets are dropped, modified, or encrypted.

### How It Works

```
   [LAN Capture]               [SD-WAN Device]              [WAN Capture]
   (clear-text)          ┌─────────────────────┐          (encapsulated)
  ────────────────────►   │  IPsec / VXLAN / GRE │   ────────────────────►
   10.1.1.5:443 → ...    │  VCMP / Viptela DTLS │   Outer: WAN_A → WAN_B
                          └─────────────────────┘   Inner: 10.1.1.5:443 → ...
```

1. **Upload two PCAPs** — File A (LAN-side) and File B (WAN-side)
2. Auto-detects tunnel encapsulation: **Cisco Viptela** (DTLS), **VeloCloud** (VCMP), **VXLAN**, **GRE**, **IPsec ESP**
3. Inner IP headers are extracted and matched against LAN-side packets by 5-tuple
4. Encrypted tunnels (ESP, DTLS) are flagged separately

### CLI Usage

```bash
./sdwan-triage -compare lan-side.pcap wan-side.pcap
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

In the **Compare** tab:
- **Path Integrity Score** — percentage of packets traversing the device
- **Tunnel Encapsulation Banner** — detected tunnel types, decapsulation stats
- **Flow Table** — per-flow match rates with NAT and tunnel badges
- **Flow Graph** — visual sequence diagrams
- **Discrepancy List** — filterable dropped, modified, and asymmetric packets

---

## Flow Graph Visualization

The **Flow Graph** renders a sequence diagram for any selected flow.

### Visual Encoding

| Arrow Style | Color | Meaning |
|---|---|---|
| **Solid →** | Green | Packet matched — present in both LAN and WAN captures |
| **Dashed ╌╌ ✕** | Red | Packet dropped — present in LAN, missing from WAN |
| **Solid →** | Yellow | Packet modified — NAT, TTL decrement, or DSCP remarking |
| **Dashed 🔒** | Cyan | Encrypted tunnel — inner flow hidden by IPsec/DTLS |
| **Dashed →** | Purple | Asymmetric — packet in WAN but not LAN |

```
  [LAN Client]              [SD-WAN Device]              [WAN Server]
      |                          |                           |
      |  ──[SYN]──────────►     |     ────────────────►     |  Matched
      |  ◄──[SYN-ACK]────  ✕   |                           |  Dropped
      |  ──[SYN]──────────►     |     ────────────────►     |  Retransmission Matched
      |  ──[PSH,ACK]─────►     |     ──── 🔒 ────────►     |  Encrypted
      |  ──[FIN,ACK]─────►     |     ────(NAT)────►        |  Modified (src IP changed)
```

---

## Troubleshooting Wizard

The web dashboard includes a **guided troubleshooting wizard** for step-by-step diagnosis.

### How It Works

1. Click any finding card in the results page
2. The wizard checks for **vendor-specific runbooks** first (e.g., Cisco `show` commands, VeloCloud `debug.py`)
3. Falls back to **generic knowledge base** entries if no vendor runbook exists
4. Every finding includes an **ELI5** (Explain Like I'm 5) explanation

### Cisco SD-WAN Example

When a **control connection down** issue is detected:

```
Vendor Runbook: Cisco SD-WAN — Control Connection Down

Diagnose:
  1. show control connections
  2. show control connections-history
  3. show certificate installed
  4. show clock
  5. show organization-name
  6. request port-hop

Error Code Quick Reference:
  DCONFAIL   → Firewall blocking UDP 12346/12366
  CRTVERFL   → Certificate or clock mismatch
  CTORGNMMIS → Org-name typo (case-sensitive!)
  BIDNTVRFD  → Serial number not in vManage

Check: NTP sync, UDP 12346/12366 open, org-name exact match
```

### Supported Vendors

**Cisco Viptela**, VMware VeloCloud, Fortinet, Palo Alto Prisma, Silver Peak, Aruba EdgeConnect, Versa Networks.

---

## Authentication

All API endpoints require JWT authentication. On first startup:

```
┌──────────────────────────────────────────────────────────────┐
│  ⚠  WARNING: Default admin user created.                     │
│  Username: admin  |  Password: admin                         │
│  PLEASE CHANGE THE PASSWORD IMMEDIATELY.                     │
└──────────────────────────────────────────────────────────────┘
```

### Roles

| Role | Permissions |
|---|---|
| `admin` | Full access + user management |
| `analyst` | Upload PCAPs, run analysis, view results |
| `viewer` | View results only |

### API Authentication

```bash
# Get a token
TOKEN=$(curl -s -X POST http://127.0.0.1:8080/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin"}' | jq -r '.token')

# Use the token
curl -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8080/api/history
```

---

## Smart Insights for Junior Engineers

Clear distinction between **Issues** (actionable problems) and **Insights** (passive observations).

| Type | Badge | Meaning | Example |
|------|-------|---------|---------|
| **Issue** | `3` (solid) | Actionable problem | DDoS, DHCP Rogue Server, Retransmissions |
| **Insight** | `+2` (subtle) | Healthy observation | CDP/LLDP Discovery, STP Topology, VRRP Sessions |

### Category Breakdown

| Category | Issues | Insights |
|----------|--------|----------|
| **Security** | DDoS, Port Scan, DNS Tunneling, C2 Beaconing | IOC database status |
| **Performance** | High RTT, Retransmissions, Packet Loss, Zero Window | QoS distribution, Bandwidth |
| **Infrastructure** | DHCP Rogue, NTP Amplification, BFD Flapping | CDP/LLDP Discovery, STP, VRRP/HSRP |
| **Stability** | BFD Flapping, IKE Rebuild, STP TCN Storm | Stable redundancy sessions |
| **SD-WAN** | Tunnel Flapping, Path Degradation | Vendor detection, Overlay inventory |

### Vendor-Specific Wireshark Filters

Each tunnel finding shows the correct vendor filter for copy-paste into Wireshark:

| Vendor | Wireshark Filter |
|--------|-----------------|
| **Cisco Viptela** | `udp.port == 12346 \|\| udp.port == 12366 \|\| udp.port == 23456` |
| **VMware VeloCloud** | `udp.port == 2426` |
| **Fortinet** | `udp.port == 541 \|\| tcp.port == 541` |
| **Aruba EdgeConnect** | `udp.port == 4163 \|\| udp.port == 4980 \|\| esp` |

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

Exposed metrics: analysis counters, packet rates, risk scores, finding type distributions.

### ServiceNow Ticketing

Automatically creates incidents for **Critical** risk findings.

```bash
./sdwan-triage -web \
  -servicenow-url https://your-instance.service-now.com \
  -servicenow-user api_user \
  -servicenow-password your_password
```

### Automation Engine

Built-in triggers fire on analysis events:
- **Log** all detected issues
- **Slack notification** on Critical findings (requires webhook URL)
- **ServiceNow ticket** on Critical findings (requires credentials above)

---

## Security

> **IMPORTANT:** The web server binds to `127.0.0.1` (localhost only) by default. Use a reverse proxy (nginx, Caddy) with TLS for remote access.

- **Authentication:** JWT tokens with 24-hour expiry, bcrypt-hashed passwords
- **Database:** SQLite at `~/.sdwan-triage/sdwan.db`
- **Secret:** JWT signing key randomly generated per process — all tokens invalidate on restart
- **Default credentials:** `admin` / `admin` — **change immediately**
- **HTTPS:** Not built-in; use a reverse proxy for production

---

## Configuration

Override detection thresholds using `-config`:

```bash
./sdwan-triage -config security capture.pcap         # Built-in preset
./sdwan-triage -config thresholds.yaml capture.pcap   # Custom YAML
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
export MAXMIND_LICENSE_KEY=your_key   # Free signup at maxmind.com
make setup-geoip
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

## API Reference

All endpoints are prefixed with `/api` and require `Authorization: Bearer <token>` unless noted.

### Authentication

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/login` | Get JWT token. Body: `{"username":"...","password":"..."}` |
| `GET` | `/api/auth/me` | Current user info |
| `POST` | `/api/auth/change-password` | Change password |
| `GET` | `/api/auth/users` | List users (admin only) |
| `POST` | `/api/auth/users` | Create user (admin only) |

### Analysis

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/upload` | Upload PCAP file (multipart) |
| `POST` | `/api/analyze/:id` | Start analysis |
| `GET` | `/api/analyze/:id/status` | Analysis status |
| `POST` | `/api/analyze/:id/cancel` | Cancel running analysis |
| `GET` | `/api/results/:id` | Full analysis results (JSON) |
| `GET` | `/api/results/:id/json` | Download results as JSON file |
| `GET` | `/api/results/:id/html` | Download results as HTML report |

### Packet Inspection

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/packets/:jobID` | List packets (paginated: `?offset=0&limit=100`) |
| `GET` | `/api/packet/:jobID/:index` | Full packet detail with hex dump |
| `GET` | `/api/streams/:jobID` | List all TCP/UDP streams |
| `GET` | `/api/stream/:jobID/*streamID` | Follow Stream — reassembled stream data |

### Export & Annotations

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/export-pcap/:jobID` | Export filtered PCAP. Body: `{"filter_expr":"ip.src == 10.0.0.1"}` |
| `GET` | `/api/annotations/:jobID` | List packet annotations |
| `POST` | `/api/annotations/:jobID` | Create annotation |
| `DELETE` | `/api/annotations/:jobID/:id` | Delete annotation |

### Other

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/topology/:id` | Network topology graph data |
| `POST` | `/api/wizard/:id` | Troubleshooting wizard query |
| `POST` | `/api/compare` | Compare two analyses |
| `POST` | `/api/compare-pcap` | Upload and compare two PCAPs |
| `GET` | `/api/trends` | Historical trend data |
| `GET` | `/api/history` | List past analyses |
| `DELETE` | `/api/history/:id` | Delete an analysis |
| `GET` | `/api/ws/:id` | WebSocket for real-time analysis progress |
| `GET` | `/metrics` | Prometheus metrics (no auth required) |

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
│   ├── analyzer/                  # Packet processing engine (35+ detectors)
│   ├── database/                  # SQLite user DB (modernc.org/sqlite)
│   ├── middleware/                # JWT auth middleware
│   ├── detector/                  # All protocol & security detectors
│   ├── integration/               # ServiceNow, Automation engine
│   ├── intelligence/              # Customer intelligence DB
│   ├── metrics/                   # Prometheus collector
│   ├── models/                    # TriageReport, finding structs, PacketStore
│   ├── output/                    # HTML, CSV, PDF, JSON report generators
│   ├── web/handlers/              # API handlers (upload, analyze, results, packets, streams, export)
│   └── web/storage/               # Embedded Redis for job state
├── web/frontend/                  # React + Vite + TailwindCSS
│   └── src/
│       ├── auth/                  # AuthContext, token management
│       ├── pages/                 # Login, Home, Analysis, Results, History
│       ├── components/            # StreamModal, HexViewer, FilterBar, IOGraphView, ExportButton
│       ├── components/dashboard/  # ExecutiveSummary, WizardModal, FindingCard, IssueSidebar
│       ├── data/                  # knowledgeBase, vendorRunbooks
│       └── hooks/                 # useAnalysis, useWebSocket, useFileUpload, useForensicFilter
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
- [Gin](https://gin-gonic.com/) — HTTP web framework
- [React](https://react.dev/) + [Vite](https://vitejs.dev/) + [TailwindCSS](https://tailwindcss.com/) — Frontend stack
- [Lucide](https://lucide.dev/) — Icon library
- [RIPE stat](https://stat.ripe.net/) — BGP prefix lookup API

## Support

- **Issues**: [GitHub Issues](https://github.com/gocisse/sdwan-triage/issues)
- **Discussions**: [GitHub Discussions](https://github.com/gocisse/sdwan-triage/discussions)

---

**Made with care for the network engineering community**
