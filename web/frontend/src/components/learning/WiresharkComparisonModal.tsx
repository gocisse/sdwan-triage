// WiresharkComparisonModal — Side-by-Side "Our Tool vs Wireshark" view
// Helps Junior Engineers translate findings into standard Wireshark packet analysis

import { useEffect, useCallback } from 'react';
import { X, Lightbulb, BookOpen, Filter } from 'lucide-react';
import type { IssueKnowledge } from '../../data/knowledgeBase';

// ─── Types ──────────────────────────────────────────────────

export interface WiresharkMockPacket {
  no: number;
  time: string;
  source: string;
  destination: string;
  protocol: string;
  length: number;
  info: string;
  highlight?: 'red' | 'grey' | 'yellow' | 'green' | 'blue';
}

export interface WiresharkComparisonData {
  findingKey: string;
  title: string;
  knowledge: IssueKnowledge;
  packets: WiresharkMockPacket[];
  eli5Mode?: boolean;
}

interface WiresharkComparisonModalProps {
  data: WiresharkComparisonData;
  onClose: () => void;
}

// ─── Wireshark Row Colors ───────────────────────────────────

const HIGHLIGHT_STYLES: Record<string, string> = {
  red: 'bg-red-900/60 text-red-200 border-l-2 border-red-500',
  grey: 'bg-slate-700/40 text-slate-300',
  yellow: 'bg-yellow-900/40 text-yellow-200 border-l-2 border-yellow-500',
  green: 'bg-green-900/40 text-green-200',
  blue: 'bg-blue-900/40 text-blue-200',
};

// ─── Component ──────────────────────────────────────────────

export function WiresharkComparisonModal({ data, onClose }: WiresharkComparisonModalProps) {
  const { knowledge, packets, eli5Mode } = data;

  // Close on Escape
  const handleKey = useCallback((e: KeyboardEvent) => {
    if (e.key === 'Escape') {
      e.preventDefault();
      e.stopPropagation();
      onClose();
    }
  }, [onClose]);

  useEffect(() => {
    window.addEventListener('keydown', handleKey, true);
    return () => window.removeEventListener('keydown', handleKey, true);
  }, [handleKey]);

  return (
    <div className="fixed inset-0 z-[100] flex items-center justify-center">
      {/* Backdrop */}
      <div className="absolute inset-0 bg-black/70 backdrop-blur-sm" onClick={onClose} />

      {/* Modal */}
      <div className="relative w-[95vw] max-w-6xl max-h-[90vh] bg-slate-900 border border-slate-700 rounded-2xl shadow-2xl flex flex-col overflow-hidden">
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-slate-700/50 bg-slate-800/80">
          <div className="flex items-center gap-3">
            <span className="text-lg">🦈</span>
            <div>
              <h2 className="text-sm font-bold text-white">Our Tool vs. Wireshark</h2>
              <p className="text-xs text-slate-400">{data.title}</p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-2 rounded-lg hover:bg-slate-700 transition-colors text-slate-400 hover:text-white"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Split Content */}
        <div className="flex-1 overflow-auto flex flex-col lg:flex-row divide-y lg:divide-y-0 lg:divide-x divide-slate-700/50">

          {/* Left Panel — Our View */}
          <div className="lg:w-1/2 p-5 overflow-y-auto space-y-4">
            <div className="flex items-center gap-2 mb-3">
              <div className="w-6 h-6 rounded-lg bg-purple-500/20 flex items-center justify-center">
                <Lightbulb className="w-3.5 h-3.5 text-purple-400" />
              </div>
              <h3 className="text-xs font-bold text-purple-400 uppercase tracking-wider">Our Analysis</h3>
            </div>

            {/* ELI5 */}
            {eli5Mode && knowledge.eli5 && (
              <div className="bg-purple-500/10 border border-purple-500/20 rounded-lg p-3">
                <span className="text-[10px] font-bold text-purple-400 uppercase tracking-wider block mb-1">Plain English</span>
                <p className="text-xs text-purple-200 leading-relaxed">{knowledge.eli5}</p>
              </div>
            )}

            {/* WHAT */}
            <div className="space-y-1.5">
              <div className="flex items-center gap-2">
                <div className="w-5 h-5 rounded bg-blue-500/20 flex items-center justify-center">
                  <span className="text-[10px] font-bold text-blue-400">W</span>
                </div>
                <h4 className="text-xs font-semibold text-blue-400 uppercase">What is happening?</h4>
              </div>
              <p className="text-xs text-slate-300 leading-relaxed ml-7">{knowledge.what}</p>
            </div>

            {/* WHY */}
            <div className="space-y-1.5">
              <div className="flex items-center gap-2">
                <div className="w-5 h-5 rounded bg-amber-500/20 flex items-center justify-center">
                  <span className="text-[10px] font-bold text-amber-400">W</span>
                </div>
                <h4 className="text-xs font-semibold text-amber-400 uppercase">Why does it matter?</h4>
              </div>
              <p className="text-xs text-slate-300 leading-relaxed ml-7">{knowledge.why}</p>
            </div>

            {/* HOW */}
            <div className="space-y-1.5">
              <div className="flex items-center gap-2">
                <div className="w-5 h-5 rounded bg-green-500/20 flex items-center justify-center">
                  <span className="text-[10px] font-bold text-green-400">H</span>
                </div>
                <h4 className="text-xs font-semibold text-green-400 uppercase">How to fix</h4>
              </div>
              <ol className="space-y-1 ml-7">
                {knowledge.how.slice(0, 4).map((step, i) => (
                  <li key={i} className="text-xs text-slate-300 leading-relaxed flex gap-2">
                    <span className="text-green-500 font-medium shrink-0">{i + 1}.</span>
                    {step}
                  </li>
                ))}
              </ol>
            </div>

            {/* Wireshark Filter Hint */}
            {knowledge.wiresharkFilter && (
              <div className="bg-slate-800 rounded-lg px-3 py-2 border border-slate-700/50 flex items-center gap-2">
                <Filter className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
                <span className="text-[10px] text-slate-400">Wireshark Filter:</span>
                <code className="text-[11px] text-cyan-300 font-mono">{knowledge.wiresharkFilter}</code>
              </div>
            )}
          </div>

          {/* Right Panel — Wireshark Mock */}
          <div className="lg:w-1/2 p-5 overflow-y-auto space-y-4 bg-slate-950/50">
            <div className="flex items-center gap-2 mb-3">
              <div className="w-6 h-6 rounded-lg bg-cyan-500/20 flex items-center justify-center">
                <BookOpen className="w-3.5 h-3.5 text-cyan-400" />
              </div>
              <h3 className="text-xs font-bold text-cyan-400 uppercase tracking-wider">Wireshark View</h3>
              <span className="text-[10px] text-slate-500 bg-slate-800 px-2 py-0.5 rounded">Mock Packet List</span>
            </div>

            {/* Mock Wireshark Packet List */}
            <div className="rounded-lg border border-slate-700/60 overflow-hidden">
              {/* Column headers — mimics Wireshark */}
              <div className="bg-slate-800/90 border-b border-slate-600/50">
                <div className="grid grid-cols-[50px_70px_1fr_1fr_60px_50px_2fr] gap-0 text-[10px] font-semibold text-slate-400 uppercase tracking-wider">
                  <div className="px-2 py-2 border-r border-slate-700/40">No.</div>
                  <div className="px-2 py-2 border-r border-slate-700/40">Time</div>
                  <div className="px-2 py-2 border-r border-slate-700/40">Source</div>
                  <div className="px-2 py-2 border-r border-slate-700/40">Destination</div>
                  <div className="px-2 py-2 border-r border-slate-700/40">Proto</div>
                  <div className="px-2 py-2 border-r border-slate-700/40">Len</div>
                  <div className="px-2 py-2">Info</div>
                </div>
              </div>

              {/* Packet rows */}
              <div className="divide-y divide-slate-800/60">
                {packets.map((pkt, idx) => {
                  const hl = pkt.highlight ? HIGHLIGHT_STYLES[pkt.highlight] : 'bg-slate-900/30 text-slate-300';
                  return (
                    <div
                      key={idx}
                      className={`grid grid-cols-[50px_70px_1fr_1fr_60px_50px_2fr] gap-0 text-[11px] font-mono ${hl} transition-colors hover:brightness-110`}
                    >
                      <div className="px-2 py-1.5 border-r border-slate-800/40 text-slate-500">{pkt.no}</div>
                      <div className="px-2 py-1.5 border-r border-slate-800/40">{pkt.time}</div>
                      <div className="px-2 py-1.5 border-r border-slate-800/40 truncate">{pkt.source}</div>
                      <div className="px-2 py-1.5 border-r border-slate-800/40 truncate">{pkt.destination}</div>
                      <div className="px-2 py-1.5 border-r border-slate-800/40">{pkt.protocol}</div>
                      <div className="px-2 py-1.5 border-r border-slate-800/40">{pkt.length}</div>
                      <div className="px-2 py-1.5 truncate">{pkt.info}</div>
                    </div>
                  );
                })}
              </div>
            </div>

            {/* Legend */}
            <div className="flex flex-wrap gap-3 text-[10px]">
              <div className="flex items-center gap-1.5">
                <span className="w-3 h-3 rounded bg-red-900/60 border border-red-500" />
                <span className="text-slate-400">Problematic Packet</span>
              </div>
              <div className="flex items-center gap-1.5">
                <span className="w-3 h-3 rounded bg-slate-700/40 border border-slate-500" />
                <span className="text-slate-400">Original / Context</span>
              </div>
              <div className="flex items-center gap-1.5">
                <span className="w-3 h-3 rounded bg-yellow-900/40 border border-yellow-500" />
                <span className="text-slate-400">Warning / Anomaly</span>
              </div>
              <div className="flex items-center gap-1.5">
                <span className="w-3 h-3 rounded bg-green-900/40 border border-green-500" />
                <span className="text-slate-400">Normal / Expected</span>
              </div>
            </div>

            {/* Explanation of what to look for in Wireshark */}
            <div className="bg-slate-800/60 rounded-lg p-3 border border-slate-700/40 space-y-2">
              <h4 className="text-[10px] font-bold text-slate-400 uppercase tracking-wider">What to look for in Wireshark</h4>
              <ul className="space-y-1">
                {getWiresharkTips(data.findingKey).map((tip, i) => (
                  <li key={i} className="text-xs text-slate-300 flex gap-2">
                    <span className="text-cyan-400 shrink-0">→</span>
                    {tip}
                  </li>
                ))}
              </ul>
            </div>
          </div>
        </div>

        {/* Footer */}
        <div className="px-6 py-3 border-t border-slate-700/50 bg-slate-800/60 flex items-center justify-between">
          <p className="text-[10px] text-slate-500">
            Press <kbd className="px-1.5 py-0.5 rounded bg-slate-700 text-slate-300 font-mono">Esc</kbd> to close
          </p>
          <p className="text-[10px] text-slate-500">
            Open this PCAP in Wireshark and apply filter: <code className="text-cyan-400 font-mono">{knowledge.wiresharkFilter || 'tcp'}</code>
          </p>
        </div>
      </div>
    </div>
  );
}

// ─── Wireshark Tips Per Finding Type ────────────────────────

function getWiresharkTips(findingKey: string): string[] {
  const tips: Record<string, string[]> = {
    tcp_retransmission: [
      'Look for black/dark-red rows in the packet list — these are retransmissions',
      'Check the "Info" column for "[TCP Retransmission]" tags',
      'Right-click → Follow TCP Stream to see the full conversation',
      'Use Statistics → TCP Stream Graphs → Time-Sequence to visualize retransmits',
      'High retransmission = packet loss between these two endpoints',
    ],
    tcp_handshake_failure: [
      'Look for SYN packets with no corresponding SYN-ACK reply',
      'Red/black rows often indicate RST (connection reset) responses',
      'Filter with "tcp.flags.syn==1 && !tcp.flags.ack" to see only SYN packets',
      'Check if a RST comes back — this means the port is closed or firewall is blocking',
      'Multiple SYN retries to the same destination = server or path is down',
    ],
    packet_loss: [
      'Look for "[TCP Previous segment not captured]" in the Info column',
      'These indicate gaps in the sequence numbers — packets were lost',
      'Use Statistics → TCP Stream Graphs → Throughput to spot drop points',
      'Check for duplicate ACKs (3+ dupes = fast retransmit triggered)',
      'Lost segments often cluster during high-bandwidth bursts',
    ],
    high_latency: [
      'Use Statistics → TCP Stream Graphs → Round Trip Time',
      'Look for ACK packets with high delta-time from the previous packet',
      'Add "tcp.analysis.ack_rtt" as a column to see per-packet RTT',
      'High RTT often correlates with geographic distance or congestion',
      'Compare RTT across different flows to isolate the slow path',
    ],
    ddos_syn_flood: [
      'Massive number of SYN packets from one source with no completed handshakes',
      'Use Statistics → Conversations to see packet count per IP pair',
      'Look for thousands of half-open connections (SYN_SENT state)',
      'Source port often changes rapidly (ephemeral port scan pattern)',
      'Destination never responds or responds with RST to all',
    ],
    ddos_udp_flood: [
      'Huge number of UDP packets all targeting the same destination',
      'Use Statistics → Endpoints to see traffic volume per IP',
      'Look for ICMP "Destination Unreachable" responses (port unreachable)',
      'Packet sizes may be uniform (amplification attack signature)',
      'Source IP may be spoofed — check for impossible source addresses',
    ],
    dns_anomaly: [
      'Filter "dns" and look for unusually long query names (potential tunneling)',
      'Check response codes — NXDOMAIN floods indicate DGA malware',
      'Look for queries to non-standard DNS servers (not your configured resolvers)',
      'High query rate to single domain = potential C2 beaconing',
      'TXT record queries with encoded data = DNS exfiltration',
    ],
    tls_weakness: [
      'Filter "tls.handshake.type == 1" to see Client Hellos',
      'Check the "TLS Version" field — anything below 1.2 is weak',
      'Look at the cipher suites offered — RC4, DES, MD5 are weak',
      'Filter "tls.handshake.version < 0x0303" for pre-TLS-1.2 connections',
      'Server Hello shows what was actually negotiated — may differ from offered',
    ],
    arp_conflict: [
      'Filter "arp" and look for duplicate ARP announcements for the same IP',
      'Two different MAC addresses claiming the same IP = conflict',
      'Look for rapid ARP request/reply storms (ARP spoofing pattern)',
      'Check timestamps — legitimate GARP happens at boot, not repeatedly',
      'Use Edit → Preferences → Protocols → ARP to enable duplicate detection',
    ],
    port_scan: [
      'Look for SYN packets to many different ports on the same destination',
      'Use Statistics → Conversations to see the scanner spreading across ports',
      'RST responses = closed ports, no response = filtered ports',
      'SYN-ACK = open port found (attacker now knows what services are running)',
      'Vertical scan = one host, many ports; Horizontal = one port, many hosts',
    ],
    ddos_icmp_flood: [
      'Filter "icmp" and look for thousands of Echo Request packets',
      'Source IP may be spoofed — check for unreachable source addresses',
      'Look for ICMP packets with unusual sizes (>1000 bytes = amplification)',
      'High packet rate from single source = classic ping flood',
      'Check if target responds — no response may indicate it is overwhelmed',
    ],
    dhcp_rogue: [
      'Filter "bootp" or "dhcp" to see all DHCP traffic',
      'Look for DHCP Offer from unexpected server IPs',
      'Multiple servers offering IPs = rogue DHCP server on the network',
      'Compare the MAC of the DHCP server against known infrastructure devices',
      'Check the gateway and DNS offered — rogue servers may redirect traffic',
    ],
    ntp_amplification: [
      'Filter "ntp" and look for large response packets (monlist responses)',
      'Response much larger than request = amplification attack',
      'Check for "Mode 7" NTP packets — these are the exploited type',
      'Look for many different source IPs responding to your address (reflection)',
      'Packet size ratio > 10:1 (request:response) confirms amplification',
    ],
    dns_tunneling: [
      'Filter "dns" and sort by query name length',
      'Tunneling queries have base64-encoded data as subdomains',
      'Query names > 50 characters are highly suspicious',
      'Look for high volume of TXT record queries to a single domain',
      'Subdomain randomness + consistent base domain = tunneling',
    ],
    c2_beaconing: [
      'Use Statistics → IO Graph with 1-second intervals to spot periodic patterns',
      'Regular interval between connections (±2s jitter) = beaconing',
      'Filter by the suspect IP and check connection timing regularity',
      'Look for small, fixed-size packets at regular intervals',
      'HTTPS beaconing shows as TLS connections to the same SNI on a timer',
    ],
  };
  return tips[findingKey] || [
    'Open the PCAP in Wireshark and apply the suggested filter',
    'Look for highlighted packets (red/black = errors, yellow = warnings)',
    'Right-click a packet → Follow Stream to see the full conversation',
    'Use Statistics → Conversations for an overview of traffic between hosts',
    'Check the Expert Information (Analyze → Expert Information) for a summary',
  ];
}

// ─── Mock Packet Generator ──────────────────────────────────

/**
 * Generate mock Wireshark packets for a given finding type.
 * Uses real data (srcIp, dstIp, etc.) when available to make the mock realistic.
 */
export function generateMockPackets(
  findingKey: string,
  context?: { srcIp?: string; dstIp?: string; srcPort?: number; dstPort?: number; protocol?: string },
): WiresharkMockPacket[] {
  const src = context?.srcIp || '192.168.1.100';
  const dst = context?.dstIp || '10.0.0.1';
  const sport = context?.srcPort || 52481;
  const dport = context?.dstPort || 443;
  const proto = context?.protocol?.toUpperCase() || 'TCP';

  switch (findingKey) {
    case 'tcp_retransmission':
      return [
        { no: 1042, time: '3.241', source: src, destination: dst, protocol: proto, length: 1514, info: `${sport} → ${dport} [PSH, ACK] Seq=15201 Ack=8401 Win=65535 Len=1460`, highlight: 'grey' },
        { no: 1043, time: '3.242', source: dst, destination: src, protocol: proto, length: 66, info: `${dport} → ${sport} [ACK] Seq=8401 Ack=15201 Win=65535 Len=0`, highlight: 'green' },
        { no: 1044, time: '3.245', source: src, destination: dst, protocol: proto, length: 1514, info: `${sport} → ${dport} [PSH, ACK] Seq=16661 Ack=8401 Win=65535 Len=1460`, highlight: 'grey' },
        { no: 1045, time: '3.450', source: src, destination: dst, protocol: proto, length: 1514, info: `[TCP Retransmission] ${sport} → ${dport} [PSH, ACK] Seq=16661 Ack=8401 Win=65535 Len=1460`, highlight: 'red' },
        { no: 1046, time: '3.451', source: dst, destination: src, protocol: proto, length: 66, info: `${dport} → ${sport} [ACK] Seq=8401 Ack=18121 Win=65535 Len=0 [TCP Dup ACK]`, highlight: 'yellow' },
        { no: 1047, time: '3.855', source: src, destination: dst, protocol: proto, length: 1514, info: `[TCP Retransmission] ${sport} → ${dport} [PSH, ACK] Seq=16661 Ack=8401 Win=65535 Len=1460`, highlight: 'red' },
      ];

    case 'tcp_handshake_failure':
      return [
        { no: 201, time: '0.000', source: src, destination: dst, protocol: proto, length: 74, info: `${sport} → ${dport} [SYN] Seq=0 Win=64240 Len=0 MSS=1460 SACK_PERM`, highlight: 'grey' },
        { no: 202, time: '1.003', source: src, destination: dst, protocol: proto, length: 74, info: `[TCP Retransmission] ${sport} → ${dport} [SYN] Seq=0 Win=64240 Len=0`, highlight: 'yellow' },
        { no: 203, time: '3.015', source: src, destination: dst, protocol: proto, length: 74, info: `[TCP Retransmission] ${sport} → ${dport} [SYN] Seq=0 Win=64240 Len=0`, highlight: 'red' },
        { no: 204, time: '7.031', source: src, destination: dst, protocol: proto, length: 74, info: `[TCP Retransmission] ${sport} → ${dport} [SYN] Seq=0 Win=64240 Len=0`, highlight: 'red' },
        { no: 205, time: '7.032', source: dst, destination: src, protocol: proto, length: 54, info: `${dport} → ${sport} [RST, ACK] Seq=1 Ack=1 Win=0 Len=0`, highlight: 'red' },
      ];

    case 'packet_loss':
      return [
        { no: 500, time: '1.200', source: src, destination: dst, protocol: proto, length: 1514, info: `${sport} → ${dport} [ACK] Seq=44001 Ack=1201 Win=65535 Len=1460`, highlight: 'grey' },
        { no: 501, time: '1.201', source: src, destination: dst, protocol: proto, length: 1514, info: `${sport} → ${dport} [ACK] Seq=45461 Ack=1201 Win=65535 Len=1460`, highlight: 'grey' },
        { no: 502, time: '1.210', source: dst, destination: src, protocol: proto, length: 66, info: `[TCP Previous segment not captured] ${dport} → ${sport} [ACK] Seq=1201 Ack=48381 Win=65535`, highlight: 'red' },
        { no: 503, time: '1.211', source: dst, destination: src, protocol: proto, length: 66, info: `${dport} → ${sport} [TCP Dup ACK 502#1] Seq=1201 Ack=45461 Win=65535`, highlight: 'yellow' },
        { no: 504, time: '1.212', source: dst, destination: src, protocol: proto, length: 66, info: `${dport} → ${sport} [TCP Dup ACK 502#2] Seq=1201 Ack=45461 Win=65535`, highlight: 'yellow' },
        { no: 505, time: '1.213', source: dst, destination: src, protocol: proto, length: 66, info: `${dport} → ${sport} [TCP Dup ACK 502#3] Seq=1201 Ack=45461 Win=65535`, highlight: 'red' },
      ];

    case 'high_latency':
      return [
        { no: 100, time: '0.000', source: src, destination: dst, protocol: proto, length: 74, info: `${sport} → ${dport} [SYN] Seq=0 Win=64240 Len=0 MSS=1460`, highlight: 'grey' },
        { no: 101, time: '0.245', source: dst, destination: src, protocol: proto, length: 74, info: `${dport} → ${sport} [SYN, ACK] Seq=0 Ack=1 Win=65535 Len=0 [RTT: 245ms]`, highlight: 'yellow' },
        { no: 102, time: '0.246', source: src, destination: dst, protocol: proto, length: 66, info: `${sport} → ${dport} [ACK] Seq=1 Ack=1 Win=64240 Len=0`, highlight: 'green' },
        { no: 103, time: '0.247', source: src, destination: dst, protocol: proto, length: 571, info: `${sport} → ${dport} [PSH, ACK] Seq=1 Ack=1 Win=64240 Len=505`, highlight: 'grey' },
        { no: 104, time: '0.512', source: dst, destination: src, protocol: proto, length: 1514, info: `${dport} → ${sport} [ACK] Seq=1 Ack=506 Win=65535 Len=1460 [RTT: 265ms]`, highlight: 'yellow' },
      ];

    case 'ddos_syn_flood':
      return [
        { no: 1, time: '0.000', source: src, destination: dst, protocol: proto, length: 74, info: `${sport} → ${dport} [SYN] Seq=0 Win=1024 Len=0`, highlight: 'red' },
        { no: 2, time: '0.001', source: src, destination: dst, protocol: proto, length: 74, info: `${sport + 1} → ${dport} [SYN] Seq=0 Win=1024 Len=0`, highlight: 'red' },
        { no: 3, time: '0.001', source: src, destination: dst, protocol: proto, length: 74, info: `${sport + 2} → ${dport} [SYN] Seq=0 Win=1024 Len=0`, highlight: 'red' },
        { no: 4, time: '0.002', source: src, destination: dst, protocol: proto, length: 74, info: `${sport + 3} → ${dport} [SYN] Seq=0 Win=1024 Len=0`, highlight: 'red' },
        { no: 5, time: '0.002', source: src, destination: dst, protocol: proto, length: 74, info: `${sport + 4} → ${dport} [SYN] Seq=0 Win=1024 Len=0`, highlight: 'red' },
        { no: 6, time: '0.003', source: dst, destination: src, protocol: proto, length: 74, info: `${dport} → ${sport} [SYN, ACK] Seq=0 Ack=1 Win=65535 Len=0`, highlight: 'grey' },
      ];

    case 'ddos_udp_flood':
      return [
        { no: 1, time: '0.000', source: src, destination: dst, protocol: 'UDP', length: 1472, info: `Source port: ${sport}  Destination port: ${dport}  Len: 1430`, highlight: 'red' },
        { no: 2, time: '0.000', source: src, destination: dst, protocol: 'UDP', length: 1472, info: `Source port: ${sport}  Destination port: ${dport + 1}  Len: 1430`, highlight: 'red' },
        { no: 3, time: '0.001', source: src, destination: dst, protocol: 'UDP', length: 1472, info: `Source port: ${sport}  Destination port: ${dport + 2}  Len: 1430`, highlight: 'red' },
        { no: 4, time: '0.001', source: dst, destination: src, protocol: 'ICMP', length: 96, info: `Destination unreachable (Port unreachable)`, highlight: 'yellow' },
        { no: 5, time: '0.001', source: src, destination: dst, protocol: 'UDP', length: 1472, info: `Source port: ${sport}  Destination port: ${dport + 3}  Len: 1430`, highlight: 'red' },
      ];

    case 'dns_anomaly':
    case 'dns_tunneling':
      return [
        { no: 10, time: '0.100', source: src, destination: dst, protocol: 'DNS', length: 89, info: `Standard query A normal-site.com`, highlight: 'green' },
        { no: 11, time: '0.102', source: dst, destination: src, protocol: 'DNS', length: 105, info: `Standard query response A 93.184.216.34`, highlight: 'green' },
        { no: 12, time: '0.500', source: src, destination: dst, protocol: 'DNS', length: 245, info: `Standard query TXT aGVsbG8gd29ybGQ.c2VjcmV0LWRhdGE.evil-domain.com`, highlight: 'red' },
        { no: 13, time: '0.510', source: dst, destination: src, protocol: 'DNS', length: 512, info: `Standard query response TXT "RXhmaWx0cmF0ZWQgZGF0YSBoZXJl..."`, highlight: 'red' },
        { no: 14, time: '1.001', source: src, destination: dst, protocol: 'DNS', length: 267, info: `Standard query TXT bm90LXN1c3BpY2lvdXM.evil-domain.com`, highlight: 'yellow' },
      ];

    case 'tls_weakness':
      return [
        { no: 50, time: '0.000', source: src, destination: dst, protocol: 'TLSv1', length: 247, info: `Client Hello, Version: TLS 1.0, Cipher Suites (23)`, highlight: 'yellow' },
        { no: 51, time: '0.045', source: dst, destination: src, protocol: 'TLSv1', length: 107, info: `Server Hello, Version: TLS 1.0, Cipher: TLS_RSA_WITH_RC4_128_SHA`, highlight: 'red' },
        { no: 52, time: '0.046', source: dst, destination: src, protocol: 'TLSv1', length: 1239, info: `Certificate, Server Hello Done`, highlight: 'grey' },
        { no: 53, time: '0.048', source: src, destination: dst, protocol: 'TLSv1', length: 364, info: `Client Key Exchange, Change Cipher Spec, Encrypted Handshake Message`, highlight: 'grey' },
        { no: 54, time: '0.095', source: dst, destination: src, protocol: 'TLSv1', length: 63, info: `Change Cipher Spec, Encrypted Handshake Message`, highlight: 'grey' },
      ];

    case 'arp_conflict':
      return [
        { no: 1, time: '0.000', source: 'aa:bb:cc:11:22:33', destination: 'ff:ff:ff:ff:ff:ff', protocol: 'ARP', length: 60, info: `Who has ${dst}? Tell ${src}`, highlight: 'grey' },
        { no: 2, time: '0.001', source: 'aa:bb:cc:11:22:33', destination: 'dd:ee:ff:44:55:66', protocol: 'ARP', length: 60, info: `${dst} is at aa:bb:cc:11:22:33`, highlight: 'green' },
        { no: 3, time: '0.500', source: '11:22:33:44:55:66', destination: 'ff:ff:ff:ff:ff:ff', protocol: 'ARP', length: 60, info: `${dst} is at 11:22:33:44:55:66 [Duplicate IP detected!]`, highlight: 'red' },
        { no: 4, time: '0.501', source: 'aa:bb:cc:11:22:33', destination: 'ff:ff:ff:ff:ff:ff', protocol: 'ARP', length: 60, info: `${dst} is at aa:bb:cc:11:22:33 [Duplicate IP detected!]`, highlight: 'red' },
      ];

    case 'c2_beaconing':
      return [
        { no: 100, time: '0.000', source: src, destination: dst, protocol: 'TLS', length: 583, info: `Client Hello, SNI: update-service.suspicious.com`, highlight: 'grey' },
        { no: 101, time: '0.120', source: dst, destination: src, protocol: 'TLS', length: 1514, info: `Application Data [Len: 1460]`, highlight: 'grey' },
        { no: 200, time: '60.005', source: src, destination: dst, protocol: 'TLS', length: 583, info: `Client Hello, SNI: update-service.suspicious.com`, highlight: 'yellow' },
        { no: 201, time: '60.130', source: dst, destination: src, protocol: 'TLS', length: 1514, info: `Application Data [Len: 1460]`, highlight: 'grey' },
        { no: 300, time: '120.002', source: src, destination: dst, protocol: 'TLS', length: 583, info: `Client Hello, SNI: update-service.suspicious.com`, highlight: 'red' },
        { no: 301, time: '120.118', source: dst, destination: src, protocol: 'TLS', length: 1514, info: `Application Data [Len: 1460]`, highlight: 'grey' },
      ];

    default:
      return [
        { no: 1, time: '0.000', source: src, destination: dst, protocol: proto, length: 74, info: `${sport} → ${dport} [SYN] Seq=0 Win=64240 Len=0`, highlight: 'grey' },
        { no: 2, time: '0.045', source: dst, destination: src, protocol: proto, length: 74, info: `${dport} → ${sport} [SYN, ACK] Seq=0 Ack=1 Win=65535 Len=0`, highlight: 'green' },
        { no: 3, time: '0.046', source: src, destination: dst, protocol: proto, length: 66, info: `${sport} → ${dport} [ACK] Seq=1 Ack=1 Win=64240 Len=0`, highlight: 'green' },
        { no: 4, time: '0.050', source: src, destination: dst, protocol: proto, length: 571, info: `${sport} → ${dport} [PSH, ACK] Seq=1 Ack=1 Win=64240 Len=505`, highlight: 'grey' },
      ];
  }
}
