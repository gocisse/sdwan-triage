// Expert Info Stream — aggregated anomaly list with click-to-jump to packet hex view

import { useState, useMemo } from 'react';
import { AlertTriangle, Shield, Activity, Search, ExternalLink, Wifi } from 'lucide-react';
import type { AnalysisResults } from '../types';

interface ExpertInfoProps {
  results: AnalysisResults;
  onJumpToPacket?: (packetIndex: number) => void;
  onFollowStream?: (streamId: string) => void;
}

interface ExpertEntry {
  timestamp: string;
  category: 'TCP' | 'Security' | 'DNS' | 'Performance' | 'Protocol' | 'Tunnel';
  severity: 'Error' | 'Warning' | 'Note' | 'Chat';
  summary: string;
  srcIp?: string;
  dstIp?: string;
  srcPort?: number;
  dstPort?: number;
  protocol?: string;
  packetIndex?: number;
  streamId?: string;
}

type SeverityFilter = 'all' | 'Error' | 'Warning' | 'Note' | 'Chat';
type CategoryFilter = 'all' | ExpertEntry['category'];

function buildExpertEntries(results: AnalysisResults): ExpertEntry[] {
  const entries: ExpertEntry[] = [];

  // TCP Retransmissions
  const retrans = results.tcp_retransmissions || [];
  for (const r of retrans) {
    entries.push({
      timestamp: '',
      category: 'TCP',
      severity: 'Warning',
      summary: `Retransmission ${r.src_ip}:${r.src_port} → ${r.dst_ip}:${r.dst_port}`,
      srcIp: r.src_ip,
      dstIp: r.dst_ip,
      srcPort: r.src_port,
      dstPort: r.dst_port,
      protocol: 'TCP',
      streamId: `${r.src_ip}:${r.src_port}->${r.dst_ip}:${r.dst_port}/TCP`,
    });
  }

  // Failed Handshakes
  const failedH = results.tcp_handshakes?.failed_handshake_attempts || [];
  for (const h of failedH) {
    entries.push({
      timestamp: h.timestamp ? new Date(h.timestamp * 1000).toISOString() : '',
      category: 'TCP',
      severity: 'Error',
      summary: `Failed handshake (${h.state}) ${h.src_ip}:${h.src_port} → ${h.dst_ip}:${h.dst_port}`,
      srcIp: h.src_ip,
      dstIp: h.dst_ip,
      srcPort: h.src_port,
      dstPort: h.dst_port,
      protocol: 'TCP',
    });
  }

  // TCP Zero Window
  const tcpWin = results.tcp_window_findings || [];
  for (const w of tcpWin) {
    entries.push({
      timestamp: w.timestamp ? new Date(w.timestamp * 1000).toISOString() : '',
      category: 'TCP',
      severity: w.type === 'Zero Window' ? 'Error' : 'Warning',
      summary: `${w.type} (${w.window_size} bytes, ${w.count}×) ${w.src_ip}:${w.src_port} → ${w.dst_ip}:${w.dst_port}`,
      srcIp: w.src_ip,
      dstIp: w.dst_ip,
      srcPort: w.src_port,
      dstPort: w.dst_port,
      protocol: 'TCP',
    });
  }

  // TCP Out-of-Order
  const ooo = results.tcp_out_of_order_flows || [];
  for (const o of ooo) {
    entries.push({
      timestamp: '',
      category: 'TCP',
      severity: o.percentage > 10 ? 'Error' : 'Warning',
      summary: `Out-of-Order ${o.out_of_order_count}/${o.total_packets} packets (${o.percentage.toFixed(1)}%) ${o.src_ip}:${o.src_port} → ${o.dst_ip}:${o.dst_port}`,
      srcIp: o.src_ip,
      dstIp: o.dst_ip,
      srcPort: o.src_port,
      dstPort: o.dst_port,
      protocol: 'TCP',
    });
  }

  // DDoS
  const ddos = results.security?.ddos_findings || [];
  for (const d of ddos) {
    entries.push({
      timestamp: d.timestamp ? new Date(d.timestamp * 1000).toISOString() : '',
      category: 'Security',
      severity: 'Error',
      summary: `DDoS ${d.type} from ${d.source_ip} → ${d.target_ip || 'multiple'} (${d.packet_count.toLocaleString()} packets)`,
      srcIp: d.source_ip,
      dstIp: d.target_ip,
    });
  }

  // Port Scans
  const scans = results.security?.port_scan_findings || [];
  for (const s of scans) {
    entries.push({
      timestamp: s.timestamp ? new Date(s.timestamp * 1000).toISOString() : '',
      category: 'Security',
      severity: 'Warning',
      summary: `Port scan (${s.type}) from ${s.source_ip} — ${s.ports_scanned} ports`,
      srcIp: s.source_ip,
      dstIp: s.target_ip,
    });
  }

  // TLS Weaknesses
  const tls = results.security?.tls_security_findings || [];
  for (const t of tls) {
    entries.push({
      timestamp: t.timestamp ? new Date(t.timestamp * 1000).toISOString() : '',
      category: 'Security',
      severity: 'Warning',
      summary: `TLS ${t.weakness_type}: ${t.tls_version} on ${t.server_ip}:${t.server_port}`,
      dstIp: t.server_ip,
      dstPort: t.server_port,
      protocol: 'TLS',
    });
  }

  // DNS Anomalies
  const dns = results.dns_anomalies || [];
  for (const d of dns) {
    entries.push({
      timestamp: d.timestamp ? new Date(d.timestamp * 1000).toISOString() : '',
      category: 'DNS',
      severity: 'Warning',
      summary: `DNS anomaly: ${d.reason} — ${d.query} (server: ${d.server_ip})`,
      dstIp: d.server_ip,
      protocol: 'DNS',
    });
  }

  // DNS Tunneling
  const dnsTunnel = results.dns_tunneling_findings || [];
  for (const t of dnsTunnel) {
    entries.push({
      timestamp: t.timestamp ? new Date(t.timestamp * 1000).toISOString() : '',
      category: 'Security',
      severity: 'Error',
      summary: `DNS tunneling: ${t.domain} (entropy: ${t.entropy_score.toFixed(2)}, ${t.query_count} queries) from ${t.source_ip}`,
      srcIp: t.source_ip,
      dstIp: t.server_ip,
      protocol: 'DNS',
    });
  }

  // C2 Beaconing
  const c2 = results.c2_beaconing_findings || [];
  for (const b of c2) {
    entries.push({
      timestamp: b.timestamp ? new Date(b.timestamp * 1000).toISOString() : '',
      category: 'Security',
      severity: 'Error',
      summary: `C2 beaconing: ${b.source_ip} → ${b.dest_ip}:${b.dest_port} (interval: ${b.beacon_interval_sec.toFixed(0)}s, jitter: ${b.interval_jitter_pct.toFixed(1)}%)`,
      srcIp: b.source_ip,
      dstIp: b.dest_ip,
      dstPort: b.dest_port,
      protocol: b.protocol,
    });
  }

  // DHCP
  const dhcp = results.dhcp_findings || [];
  for (const d of dhcp) {
    entries.push({
      timestamp: d.timestamp ? new Date(d.timestamp * 1000).toISOString() : '',
      category: 'Protocol',
      severity: d.severity === 'Critical' ? 'Error' : 'Warning',
      summary: `DHCP ${d.type}: ${d.description}`,
      srcIp: d.server_ip,
      protocol: 'DHCP',
    });
  }

  // NTP
  const ntp = results.ntp_findings || [];
  for (const n of ntp) {
    entries.push({
      timestamp: n.timestamp ? new Date(n.timestamp * 1000).toISOString() : '',
      category: 'Protocol',
      severity: n.severity === 'Critical' ? 'Error' : 'Warning',
      summary: `NTP ${n.type}: ${n.description}`,
      srcIp: n.source_ip,
      dstIp: n.dest_ip,
      protocol: 'NTP',
    });
  }

  // ARP Conflicts
  const arp = results.arp_conflicts || [];
  for (const a of arp) {
    entries.push({
      timestamp: '',
      category: 'Protocol',
      severity: 'Warning',
      summary: `ARP conflict: ${a.ip_address} claimed by ${a.mac_addresses.length} MACs (${a.mac_addresses.join(', ')})`,
      srcIp: a.ip_address,
      protocol: 'ARP',
    });
  }

  // Tunnel findings
  const tunnels = results.tunnel_analysis || [];
  for (const t of tunnels) {
    entries.push({
      timestamp: '',
      category: 'Tunnel',
      severity: 'Note',
      summary: `${t.type} tunnel: ${t.src_ip}${t.src_port ? ':' + t.src_port : ''} → ${t.dst_ip}${t.dst_port ? ':' + t.dst_port : ''} (${t.packet_count.toLocaleString()} packets)`,
      srcIp: t.src_ip,
      dstIp: t.dst_ip,
      srcPort: t.src_port,
      dstPort: t.dst_port,
    });
  }

  // Timeline events as Chat-level entries
  const timeline = results.timeline || [];
  for (const ev of timeline.slice(0, 100)) {
    const sev = ev.severity === 'Critical' ? 'Error' as const :
                ev.severity === 'Warning' ? 'Warning' as const :
                'Note' as const;
    entries.push({
      timestamp: ev.timestamp,
      category: 'Protocol',
      severity: sev,
      summary: `[${ev.protocol}] ${ev.description}`,
      srcIp: ev.source_ip,
      dstIp: ev.dest_ip,
      protocol: ev.protocol,
    });
  }

  // Sort: Errors first, then Warnings, then Notes, then Chat
  const sevOrder: Record<string, number> = { Error: 0, Warning: 1, Note: 2, Chat: 3 };
  entries.sort((a, b) => (sevOrder[a.severity] ?? 3) - (sevOrder[b.severity] ?? 3));

  return entries;
}

const sevConfig: Record<string, { bg: string; text: string; dot: string; icon: typeof AlertTriangle }> = {
  Error:   { bg: 'bg-red-500/10', text: 'text-red-400', dot: 'bg-red-500', icon: AlertTriangle },
  Warning: { bg: 'bg-amber-500/10', text: 'text-amber-400', dot: 'bg-amber-500', icon: AlertTriangle },
  Note:    { bg: 'bg-blue-500/10', text: 'text-blue-400', dot: 'bg-blue-500', icon: Activity },
  Chat:    { bg: 'bg-slate-500/10', text: 'text-slate-400', dot: 'bg-slate-500', icon: Activity },
};

const catIcons: Record<string, typeof Shield> = {
  TCP: Activity,
  Security: Shield,
  DNS: Wifi,
  Performance: Activity,
  Protocol: Activity,
  Tunnel: Wifi,
};

export default function ExpertInfo({ results, onJumpToPacket, onFollowStream }: ExpertInfoProps) {
  const allEntries = useMemo(() => buildExpertEntries(results), [results]);
  const [sevFilter, setSevFilter] = useState<SeverityFilter>('all');
  const [catFilter, setCatFilter] = useState<CategoryFilter>('all');
  const [search, setSearch] = useState('');
  const [limit, setLimit] = useState(100);

  const filtered = useMemo(() => {
    let entries = allEntries;
    if (sevFilter !== 'all') entries = entries.filter(e => e.severity === sevFilter);
    if (catFilter !== 'all') entries = entries.filter(e => e.category === catFilter);
    if (search.trim()) {
      const q = search.toLowerCase();
      entries = entries.filter(e =>
        e.summary.toLowerCase().includes(q) ||
        (e.srcIp && e.srcIp.includes(q)) ||
        (e.dstIp && e.dstIp.includes(q))
      );
    }
    return entries;
  }, [allEntries, sevFilter, catFilter, search]);

  // Count by severity
  const counts = useMemo(() => {
    const c: Record<string, number> = { Error: 0, Warning: 0, Note: 0, Chat: 0 };
    for (const e of allEntries) c[e.severity] = (c[e.severity] || 0) + 1;
    return c;
  }, [allEntries]);

  // Count by category
  const catCounts = useMemo(() => {
    const c: Record<string, number> = {};
    for (const e of allEntries) c[e.category] = (c[e.category] || 0) + 1;
    return c;
  }, [allEntries]);

  if (allEntries.length === 0) {
    return (
      <div className="bg-slate-800/60 border border-slate-700/50 rounded-xl p-8 text-center">
        <AlertTriangle className="w-8 h-8 text-slate-600 mx-auto mb-3" />
        <p className="text-sm text-slate-500">No expert info entries</p>
      </div>
    );
  }

  return (
    <div className="bg-slate-800/60 border border-slate-700/50 rounded-xl overflow-hidden">
      {/* Header */}
      <div className="flex items-center justify-between px-5 py-3 border-b border-slate-700/50">
        <div className="flex items-center gap-2.5">
          <AlertTriangle className="w-4 h-4 text-amber-400" />
          <h3 className="text-sm font-semibold text-white">Expert Info</h3>
          <span className="text-[10px] text-slate-500 bg-slate-700/50 px-1.5 py-0.5 rounded">{allEntries.length}</span>
        </div>

        {/* Severity badges */}
        <div className="flex items-center gap-1.5">
          {(['Error', 'Warning', 'Note'] as const).map(sev => (
            <button
              key={sev}
              onClick={() => setSevFilter(sevFilter === sev ? 'all' : sev)}
              className={`inline-flex items-center gap-1 px-2 py-1 rounded-md text-[10px] font-medium transition-all ${
                sevFilter === sev
                  ? `${sevConfig[sev].bg} ${sevConfig[sev].text} ring-1 ring-current/30`
                  : 'text-slate-500 hover:text-slate-300'
              }`}
            >
              <span className={`w-1.5 h-1.5 rounded-full ${sevConfig[sev].dot}`} />
              {counts[sev] || 0}
            </button>
          ))}
        </div>
      </div>

      {/* Filter bar */}
      <div className="flex items-center gap-2 px-5 py-2 border-b border-slate-700/30">
        {/* Category filter chips */}
        <div className="flex items-center gap-1 flex-1 overflow-x-auto">
          <button
            onClick={() => setCatFilter('all')}
            className={`px-2 py-0.5 rounded text-[10px] font-medium transition-colors whitespace-nowrap ${
              catFilter === 'all' ? 'bg-slate-600 text-white' : 'text-slate-500 hover:text-slate-300'
            }`}
          >
            All
          </button>
          {Object.entries(catCounts).sort((a, b) => b[1] - a[1]).map(([cat, count]) => (
            <button
              key={cat}
              onClick={() => setCatFilter(catFilter === cat as CategoryFilter ? 'all' : cat as CategoryFilter)}
              className={`px-2 py-0.5 rounded text-[10px] font-medium transition-colors whitespace-nowrap ${
                catFilter === cat ? 'bg-slate-600 text-white' : 'text-slate-500 hover:text-slate-300'
              }`}
            >
              {cat} ({count})
            </button>
          ))}
        </div>

        {/* Search */}
        <div className="relative w-40 flex-shrink-0">
          <Search className="absolute left-2 top-1/2 -translate-y-1/2 w-3 h-3 text-slate-500" />
          <input
            type="text"
            value={search}
            onChange={e => setSearch(e.target.value)}
            placeholder="Search..."
            className="w-full pl-6 pr-2 py-1 text-[10px] bg-slate-900/50 border border-slate-700/50 rounded text-slate-300 placeholder:text-slate-600 outline-none focus:border-amber-500/40"
          />
        </div>
      </div>

      {/* Entries list */}
      <div className="max-h-[500px] overflow-y-auto">
        {filtered.slice(0, limit).map((entry, i) => {
          const sev = sevConfig[entry.severity] || sevConfig.Note;
          const CatIcon = catIcons[entry.category] || Activity;

          return (
            <div
              key={i}
              className={`flex items-start gap-2.5 px-5 py-2 border-b border-slate-700/10 hover:bg-slate-700/20 transition-colors ${
                entry.streamId || entry.packetIndex !== undefined ? 'cursor-pointer' : ''
              }`}
              onClick={() => {
                if (entry.packetIndex !== undefined && onJumpToPacket) {
                  onJumpToPacket(entry.packetIndex);
                } else if (entry.streamId && onFollowStream) {
                  onFollowStream(entry.streamId);
                }
              }}
            >
              {/* Severity dot */}
              <span className={`w-2 h-2 rounded-full ${sev.dot} mt-1.5 flex-shrink-0`} />

              {/* Category icon */}
              <CatIcon className={`w-3.5 h-3.5 ${sev.text} mt-0.5 flex-shrink-0`} />

              {/* Content */}
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2">
                  <span className={`text-[10px] font-medium px-1 py-0.5 rounded ${sev.bg} ${sev.text}`}>
                    {entry.severity}
                  </span>
                  <span className="text-[10px] text-slate-600">{entry.category}</span>
                  {entry.timestamp && (
                    <span className="text-[10px] text-slate-600 font-mono">
                      {entry.timestamp.includes('T') ? entry.timestamp.split('T')[1]?.split('.')[0] || '' : entry.timestamp}
                    </span>
                  )}
                </div>
                <p className="text-xs text-slate-300 mt-0.5 leading-snug">{entry.summary}</p>
              </div>

              {/* Jump icon */}
              {(entry.streamId || entry.packetIndex !== undefined) && (
                <ExternalLink className="w-3 h-3 text-slate-600 mt-1 flex-shrink-0" />
              )}
            </div>
          );
        })}

        {filtered.length > limit && (
          <button
            onClick={() => setLimit(l => l + 100)}
            className="w-full py-3 text-xs text-slate-500 hover:text-slate-300 transition-colors"
          >
            Show more ({filtered.length - limit} remaining)
          </button>
        )}
      </div>

      {/* Footer */}
      <div className="px-5 py-2 border-t border-slate-700/50 text-[10px] text-slate-600 flex items-center justify-between">
        <span>{filtered.length} of {allEntries.length} entries shown</span>
        <span>Click an entry with a stream ID to jump to packet view</span>
      </div>
    </div>
  );
}
