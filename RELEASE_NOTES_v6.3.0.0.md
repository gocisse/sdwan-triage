# SD-WAN Triage v6.3.0.0 — The Trustworthy Baseline Release

> **Same detectors, correct answers.** This release fixes the analysis engine's evidence so that what it reports about a capture is what the capture actually shows — and makes it 2.5–6× faster while doing it.

---

## Why this release matters

Before v6.3, several findings were wrong on *every* capture:

| Symptom on a healthy 2-minute office capture | v6.2.0.0 | v6.3.0.0 |
|---|---|---|
| Flows flagged with TCP retransmissions | 1,240 | **188** |
| Reported packet loss | 25.2 % | **0.64 %** |
| "DDoS" findings (incl. Google DNS 8.8.8.8) | 27 | **3** |
| Failed TCP handshakes | 363 | **126** |
| Risk score | 4275 / Critical | capped 0–100 |
| `-json` output parses | ✗ | **✓** |
| Analysis time (37 MB) | 5.0–6.3 s | **2.0–2.2 s** |

## Fixed

### Evidence correctness
- **TCP retransmission false positive** — pure ACKs were recorded as "sent data", so every connection's first data segment looked like a retransmission. Only sequence-consuming segments (data / SYN / FIN) are tracked now.
- **Packet-loss inflation** — the same pure-ACK bug in the loss detector reported ~25 % loss on healthy traffic.
- **Wall-clock time in evidence** — handshake timeouts, retransmission timestamps, stream idle eviction, DDoS windows, VPN session times and TLS certificate expiry were compared against *now* instead of capture time. A capture analysed a day later no longer shows every pending SYN as "failed" or every certificate as "expired".
- **DDoS detection window never reset** (wall-clock origin) — per-host counters accumulated over the whole capture, flagging ordinary repeated ICMP/UDP traffic as floods.
- **Stream reassembly discarded every stream each 10,000 packets** — "Follow stream" and vendor DPI now see data from the whole capture.
- **Completed handshakes counted twice** in `tcp_handshake_flows`.

### New detections (using existing models)
- **DNS failures** — unanswered queries (client retries, or ≥2 s outstanding at end of capture) and `NXDOMAIN` / `SERVFAIL` / `REFUSED` responses are now DNS anomalies. Response matching uses a transaction-ID index (was an O(n) name scan per response).
- **BFD Session Down** — a single Up → Down transition is now a stability finding. Previously only sustained flapping (≥4 transitions) was reported, so the most important SD-WAN path-loss evidence was invisible.

### Stability and performance
- **Deadlock fixed** — loading a threat-intel feed and hitting a single IOC hung the process forever (re-entrant `report.Mu`). Reproduced, fixed, regression-tested.
- **Detector registry runs sequentially** — the previous 30-goroutines-per-packet fan-out was fully serialised by a shared mutex; removing it gives 2.5× (real traffic) to 6× (flow-heavy synthetic) speedups.
- **Bounded per-flow memory** — per-flow sequence history is a fixed 512-entry FIFO instead of unbounded maps; RTT samples, timeline (20k, reservoir-sampled), handshake/window/OOO/C2/port-scan trackers are all capped. Memory no longer grows with the length of a flow.
- `-json` writes **only** JSON to stdout; banner and progress go to stderr.

## Testing
- New deterministic fixture package (`internal/testpcap`) — the learning-platform sample captures are now byte-reproducible and double as golden regression tests.
- Golden tests: `handshake`, `mtu_issue`, `dns_failure`, `bfd_tunnel_drop`, `retransmission_storm`, JSON validity, stdout purity, capture-time SYN timeout, threat-intel deadlock.
- `go test ./...`, `go vet`, and `-race` all clean.

## Known limitations (unchanged in this release)
- DDoS / port-scan thresholds are unchanged (100 ICMP or 200 UDP packets per host per 10 s still reports a flood).
- Risk scoring remains count-additive (now capped at 100); a redesign is planned with the upcoming Finding model.
- Retransmissions more than 512 data segments after the original are not detected.

## Installation

```bash
# macOS (Apple Silicon)
tar -xzf sdwan-triage-v6.3.0.0-darwin-arm64.tar.gz && ./sdwan-triage-darwin-arm64 capture.pcap

# Linux
tar -xzf sdwan-triage-v6.3.0.0-linux-amd64.tar.gz && ./sdwan-triage-linux-amd64 -web

# Windows
Expand-Archive sdwan-triage-v6.3.0.0-windows-amd64.zip; .\sdwan-triage-windows-amd64.exe -web
```

Verify downloads with `checksums-v6.3.0.0.txt` (SHA-256).
