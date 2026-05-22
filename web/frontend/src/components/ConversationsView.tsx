// Conversations Matrix — Src IP ↔ Dst IP with packets, bytes, duration, throughput

import { useState, useMemo, useCallback } from 'react';
import { ArrowUpDown, ArrowRightLeft, Filter, Search } from 'lucide-react';
import type { AnalysisResults } from '../types';
import { useTimeFilteredData } from '../hooks/useTimeFilteredData';

interface ConversationsViewProps {
  results: AnalysisResults;
  onFilterConversation?: (srcIp: string, dstIp: string) => void;
}

interface Conversation {
  srcIp: string;
  dstIp: string;
  packets: number;
  bytes: number;
  protocols: Set<string>;
  firstSeen: number;
  lastSeen: number;
}

interface ConversationRow {
  srcIp: string;
  dstIp: string;
  packets: number;
  bytes: number;
  protocols: string;
  durationSec: number;
  throughputBps: number;
  firstSeen: number;
  lastSeen: number;
}

type SortKey = 'srcIp' | 'dstIp' | 'packets' | 'bytes' | 'durationSec' | 'throughputBps';

function buildConversations(results: AnalysisResults): ConversationRow[] {
  const map = new Map<string, Conversation>();

  // From traffic flows
  const flows = results.traffic_analysis || [];
  for (const f of flows) {
    // Normalize key so A↔B and B↔A merge
    const [lo, hi] = f.src_ip < f.dst_ip ? [f.src_ip, f.dst_ip] : [f.dst_ip, f.src_ip];
    const key = `${lo}|${hi}`;
    const existing = map.get(key);
    if (existing) {
      existing.packets += 1;
      existing.bytes += f.total_bytes;
      existing.protocols.add((f.protocol || 'Unknown').toUpperCase());
    } else {
      map.set(key, {
        srcIp: lo,
        dstIp: hi,
        packets: 1,
        bytes: f.total_bytes,
        protocols: new Set([(f.protocol || 'Unknown').toUpperCase()]),
        firstSeen: 0,
        lastSeen: 0,
      });
    }
  }

  // From bandwidth report for additional data
  const bwConvs = results.bandwidth_report?.top_conversations_by_bytes || [];
  for (const c of bwConvs) {
    const [lo, hi] = c.src_ip < c.dst_ip ? [c.src_ip, c.dst_ip] : [c.dst_ip, c.src_ip];
    const key = `${lo}|${hi}`;
    const existing = map.get(key);
    if (existing) {
      // Only update if bandwidth data has more info
      if (c.packets > existing.packets) existing.packets = c.packets;
      if (c.bytes > existing.bytes) existing.bytes = c.bytes;
      existing.protocols.add((c.protocol || 'Unknown').toUpperCase());
    } else {
      map.set(key, {
        srcIp: lo,
        dstIp: hi,
        packets: c.packets,
        bytes: c.bytes,
        protocols: new Set([(c.protocol || 'Unknown').toUpperCase()]),
        firstSeen: 0,
        lastSeen: 0,
      });
    }
  }

  // Estimate duration from timeline events
  const timeline = results.timeline || [];
  for (const ev of timeline) {
    const srcIp = ev.source_ip || '';
    const dstIp = ev.dest_ip || '';
    if (!srcIp || !dstIp) continue;
    const [lo, hi] = srcIp < dstIp ? [srcIp, dstIp] : [dstIp, srcIp];
    const key = `${lo}|${hi}`;
    const existing = map.get(key);
    if (existing) {
      const ts = new Date(ev.timestamp).getTime() / 1000;
      if (ts > 0) {
        if (existing.firstSeen === 0 || ts < existing.firstSeen) existing.firstSeen = ts;
        if (ts > existing.lastSeen) existing.lastSeen = ts;
      }
    }
  }

  // Convert to rows
  const rows: ConversationRow[] = [];
  for (const conv of map.values()) {
    const durationSec = conv.lastSeen > conv.firstSeen ? conv.lastSeen - conv.firstSeen : 0;
    const throughputBps = durationSec > 0 ? (conv.bytes * 8) / durationSec : 0;
    rows.push({
      srcIp: conv.srcIp,
      dstIp: conv.dstIp,
      packets: conv.packets,
      bytes: conv.bytes,
      protocols: Array.from(conv.protocols).sort().join(', '),
      durationSec,
      throughputBps,
      firstSeen: conv.firstSeen,
      lastSeen: conv.lastSeen,
    });
  }

  return rows;
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB`;
}

function formatDuration(sec: number): string {
  if (sec <= 0) return '-';
  if (sec < 1) return `${(sec * 1000).toFixed(0)}ms`;
  if (sec < 60) return `${sec.toFixed(1)}s`;
  if (sec < 3600) return `${Math.floor(sec / 60)}m ${Math.floor(sec % 60)}s`;
  return `${Math.floor(sec / 3600)}h ${Math.floor((sec % 3600) / 60)}m`;
}

function formatThroughput(bps: number): string {
  if (bps <= 0) return '-';
  if (bps < 1000) return `${bps.toFixed(0)} bps`;
  if (bps < 1000000) return `${(bps / 1000).toFixed(1)} Kbps`;
  if (bps < 1000000000) return `${(bps / 1000000).toFixed(1)} Mbps`;
  return `${(bps / 1000000000).toFixed(2)} Gbps`;
}

export default function ConversationsView({ results, onFilterConversation }: ConversationsViewProps) {
  const allRowsRaw = useMemo(() => buildConversations(results), [results]);

  // Global time-range filter: include rows whose time span overlaps the selection
  const getRowTimestamp = useCallback((r: ConversationRow) => {
    // Use firstSeen as representative timestamp; items without timestamps pass through
    return r.firstSeen > 0 ? r.firstSeen : 0;
  }, []);
  const allRows = useTimeFilteredData(allRowsRaw, getRowTimestamp);

  const [sortKey, setSortKey] = useState<SortKey>('bytes');
  const [sortAsc, setSortAsc] = useState(false);
  const [search, setSearch] = useState('');

  const handleSort = useCallback((key: SortKey) => {
    if (sortKey === key) {
      setSortAsc(!sortAsc);
    } else {
      setSortKey(key);
      setSortAsc(false);
    }
  }, [sortKey, sortAsc]);

  const filteredRows = useMemo(() => {
    let rows = allRows;
    if (search.trim()) {
      const q = search.toLowerCase();
      rows = rows.filter(r =>
        r.srcIp.includes(q) || r.dstIp.includes(q) || r.protocols.toLowerCase().includes(q)
      );
    }
    rows = [...rows].sort((a, b) => {
      const av = a[sortKey];
      const bv = b[sortKey];
      if (typeof av === 'string' && typeof bv === 'string') {
        return sortAsc ? av.localeCompare(bv) : bv.localeCompare(av);
      }
      return sortAsc ? (av as number) - (bv as number) : (bv as number) - (av as number);
    });
    return rows;
  }, [allRows, sortKey, sortAsc, search]);

  if (allRows.length === 0) {
    return (
      <div className="bg-slate-800/60 border border-slate-700/50 rounded-xl p-8 text-center">
        <ArrowRightLeft className="w-8 h-8 text-slate-600 mx-auto mb-3" />
        <p className="text-sm text-slate-500">No conversation data available</p>
      </div>
    );
  }

  const SortHeader = ({ label, field, className = '' }: { label: string; field: SortKey; className?: string }) => (
    <th
      className={`px-3 py-2 text-left text-slate-500 font-medium cursor-pointer hover:text-slate-300 transition-colors select-none ${className}`}
      onClick={() => handleSort(field)}
    >
      <span className="inline-flex items-center gap-1">
        {label}
        {sortKey === field && (
          <ArrowUpDown className={`w-3 h-3 ${sortAsc ? 'rotate-180' : ''}`} />
        )}
      </span>
    </th>
  );

  return (
    <div className="bg-slate-800/60 border border-slate-700/50 rounded-xl overflow-hidden">
      {/* Header */}
      <div className="flex items-center justify-between px-5 py-3 border-b border-slate-700/50">
        <div className="flex items-center gap-2.5">
          <ArrowRightLeft className="w-4 h-4 text-cyan-400" />
          <h3 className="text-sm font-semibold text-white">Conversations</h3>
          <span className="text-[10px] text-slate-500 bg-slate-700/50 px-1.5 py-0.5 rounded">{allRows.length}</span>
        </div>
        {/* Search */}
        <div className="relative w-52">
          <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-slate-500" />
          <input
            type="text"
            value={search}
            onChange={e => setSearch(e.target.value)}
            placeholder="Filter IPs or protocols..."
            className="w-full pl-8 pr-3 py-1.5 text-xs bg-slate-900/50 border border-slate-700/50 rounded-lg text-slate-300 placeholder:text-slate-600 outline-none focus:border-cyan-500/40"
          />
        </div>
      </div>

      {/* Table */}
      <div className="overflow-x-auto max-h-[480px] overflow-y-auto">
        <table className="w-full text-xs">
          <thead className="sticky top-0 bg-slate-800/95 backdrop-blur-sm z-10">
            <tr className="border-b border-slate-700/50">
              <SortHeader label="Address A" field="srcIp" />
              <th className="px-1 py-2 text-slate-600 font-normal">↔</th>
              <SortHeader label="Address B" field="dstIp" />
              <th className="px-3 py-2 text-left text-slate-500 font-medium">Protocols</th>
              <SortHeader label="Packets" field="packets" className="text-right" />
              <SortHeader label="Bytes" field="bytes" className="text-right" />
              <SortHeader label="Duration" field="durationSec" className="text-right" />
              <SortHeader label="Throughput" field="throughputBps" className="text-right" />
              {onFilterConversation && <th className="px-2 py-2 w-8" />}
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-700/20">
            {filteredRows.slice(0, 200).map((row, i) => (
              <tr
                key={`${row.srcIp}-${row.dstIp}-${i}`}
                className={`hover:bg-slate-700/20 transition-colors ${onFilterConversation ? 'cursor-pointer' : ''}`}
                onClick={() => onFilterConversation?.(row.srcIp, row.dstIp)}
              >
                <td className="px-3 py-2 font-mono text-slate-300">{row.srcIp}</td>
                <td className="px-1 py-2 text-slate-600">↔</td>
                <td className="px-3 py-2 font-mono text-slate-300">{row.dstIp}</td>
                <td className="px-3 py-2 text-slate-400">{row.protocols}</td>
                <td className="px-3 py-2 text-right text-slate-400">{row.packets.toLocaleString()}</td>
                <td className="px-3 py-2 text-right text-slate-300">{formatBytes(row.bytes)}</td>
                <td className="px-3 py-2 text-right text-slate-400">{formatDuration(row.durationSec)}</td>
                <td className="px-3 py-2 text-right text-slate-400">{formatThroughput(row.throughputBps)}</td>
                {onFilterConversation && (
                  <td className="px-2 py-2">
                    <button
                      onClick={(e) => {
                        e.stopPropagation();
                        onFilterConversation(row.srcIp, row.dstIp);
                      }}
                      className="p-1 rounded hover:bg-cyan-500/20 text-slate-500 hover:text-cyan-400 transition-colors"
                      title="Filter to this conversation"
                    >
                      <Filter className="w-3 h-3" />
                    </button>
                  </td>
                )}
              </tr>
            ))}
          </tbody>
        </table>
        {filteredRows.length > 200 && (
          <p className="text-xs text-slate-500 px-4 py-2 text-center">Showing 200 of {filteredRows.length} conversations</p>
        )}
      </div>
    </div>
  );
}
