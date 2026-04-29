import React, { useState, useMemo, useEffect, useCallback } from 'react';
import {
  X,
  MessageSquare,
  ArrowRight,
  ArrowLeft,
  AlertTriangle,
  XCircle,
  CheckCircle,
  Clock,
  Zap,
  HelpCircle,
  Copy,
  Filter,
  TrendingUp,
  FileText,
  Loader2,
} from 'lucide-react';
import type { Discrepancy, FlowComparisonSummary, ForensicSummary, StreamResponse } from '../types';
import type { TCPGraphPoint } from './TCPSequenceGraph';
import { TCPStreamGraphs } from './TCPStreamGraphs';
import { getAuthToken } from '../api/client';

// ─── Types ────────────────────────────────────────────────────────

interface StreamConversationProps {
  /** All discrepancies from the comparison report */
  allDiscrepancies: Discrepancy[];
  /** The flow to display — used to filter discrepancies */
  flow: FlowComparisonSummary;
  /** Forensics data for latency information */
  forensics?: ForensicSummary;
  /** Job ID for fetching stream data (optional - for payload tab) */
  jobId?: string;
  onClose: () => void;
}

interface ConversationPacket {
  discrepancy: Discrepancy;
  direction: 'client' | 'server';
  event: PacketEvent;
  lanTimestamp?: string;
  wanTimestamp?: string;
  latencyMs?: number;
}

interface PacketEvent {
  label: string;
  color: string;
  bgColor: string;
  borderColor: string;
  icon: React.ReactNode;
  explanation: string;
}

// ─── Main Component ───────────────────────────────────────────────

export const StreamConversation: React.FC<StreamConversationProps> = ({
  allDiscrepancies,
  flow,
  forensics,
  jobId,
  onClose,
}) => {
  const [showExplanation, setShowExplanation] = useState<number | null>(null);
  const [filterType, setFilterType] = useState<string>('all');
  const [copiedFilter, setCopiedFilter] = useState(false);
  const [activeView, setActiveView] = useState<'conversation' | 'graph' | 'payload'>('conversation');
  
  // Payload tab state
  const [streamData, setStreamData] = useState<StreamResponse | null>(null);
  const [payloadLoading, setPayloadLoading] = useState(false);
  const [payloadError, setPayloadError] = useState<string | null>(null);
  const [payloadView, setPayloadView] = useState<'ascii' | 'hex'>('ascii');

  // Fetch stream data when payload tab is selected
  const fetchStreamData = useCallback(async () => {
    if (!jobId) {
      setPayloadError('Job ID not available for payload view');
      return;
    }

    const streamId = `${flow.src_ip}:${flow.src_port}->${flow.dst_ip}:${flow.dst_port}/${flow.protocol}`;
    setPayloadLoading(true);
    setPayloadError(null);

    try {
      const token = getAuthToken();
      const response = await fetch(`/api/stream/${jobId}/${encodeURIComponent(streamId)}`, {
        headers: token ? { Authorization: `Bearer ${token}` } : {},
      });
      if (!response.ok) {
        throw new Error('Failed to fetch stream data');
      }
      const data = await response.json();
      setStreamData(data);
    } catch (err) {
      setPayloadError(err instanceof Error ? err.message : 'Unknown error');
    } finally {
      setPayloadLoading(false);
    }
  }, [jobId, flow]);

  useEffect(() => {
    if (activeView === 'payload' && !streamData && !payloadLoading) {
      fetchStreamData();
    }
  }, [activeView, streamData, payloadLoading, fetchStreamData]);

  // Filter discrepancies for this specific flow
  const flowPackets = useMemo(() => {
    const matching = allDiscrepancies.filter(
      (d) =>
        ((d.src_ip === flow.src_ip && d.dst_ip === flow.dst_ip &&
          d.src_port === flow.src_port && d.dst_port === flow.dst_port) ||
         (d.src_ip === flow.dst_ip && d.dst_ip === flow.src_ip &&
          d.src_port === flow.dst_port && d.dst_port === flow.src_port)) &&
        d.protocol === flow.protocol
    );

    // Sort by timestamp
    matching.sort((a, b) => a.timestamp.localeCompare(b.timestamp));

    return matching.map((d): ConversationPacket => {
      const isClient = d.src_ip === flow.src_ip && d.src_port === flow.src_port;
      return {
        discrepancy: d,
        direction: isClient ? 'client' : 'server',
        event: classifyPacketEvent(d),
        lanTimestamp: d.state !== 'MISSING_A' ? d.timestamp : undefined,
        wanTimestamp: d.state !== 'MISSING_B' ? d.timestamp : undefined,
        latencyMs: forensics ? estimateLatency(d, forensics) : undefined,
      };
    });
  }, [allDiscrepancies, flow, forensics]);

  const filteredPackets = useMemo(() => {
    if (filterType === 'all') return flowPackets;
    if (filterType === 'drops') return flowPackets.filter(p => p.discrepancy.state === 'MISSING_B');
    if (filterType === 'events') return flowPackets.filter(p =>
      p.event.label !== 'Data' && p.event.label !== 'Matched'
    );
    return flowPackets;
  }, [flowPackets, filterType]);

  // TCP sequence graph points derived from the in-memory Discrepancy list.
  // Only TCP flows produce meaningful data; UDP/ICMP flows yield an empty array
  // which the graph component renders as an empty-state panel.
  const graphPoints = useMemo<TCPGraphPoint[]>(() => {
    if (flow.protocol !== 'TCP' || flowPackets.length === 0) return [];

    // Determine t=0 using the earliest timestamp seen on this flow.
    // timestamps are stored as formatted strings ("15:04:05.000000"), so we
    // compute a millisecond offset by parsing the HH:MM:SS.fraction structure.
    const tsMs = (ts: string): number => {
      // Accept "HH:MM:SS.ffffff" OR RFC3339. Fallback to 0 on parse failure.
      const m = /^(\d{1,2}):(\d{2}):(\d{2})(?:\.(\d+))?$/.exec(ts);
      if (m) {
        const h = parseInt(m[1], 10);
        const mm = parseInt(m[2], 10);
        const s = parseInt(m[3], 10);
        const frac = m[4] ? parseFloat('0.' + m[4]) : 0;
        return ((h * 3600 + mm * 60 + s) + frac) * 1000;
      }
      const parsed = Date.parse(ts);
      return isNaN(parsed) ? 0 : parsed;
    };

    const sorted = [...flowPackets].sort(
      (a, b) => tsMs(a.discrepancy.timestamp) - tsMs(b.discrepancy.timestamp),
    );
    const t0 = tsMs(sorted[0].discrepancy.timestamp);

    // Track seen (direction, seq, payload) tuples for retransmission detection.
    const seen = new Set<string>();

    return sorted
      .filter(p => typeof p.discrepancy.seq_num === 'number')
      .map<TCPGraphPoint>(p => {
        const d = p.discrepancy;
        const seq = d.seq_num ?? 0;
        const ack = d.ack_num ?? 0;
        const win = d.window_size ?? 0;
        const payload = d.payload_len ?? 0;
        const direction: 'forward' | 'reverse' = p.direction === 'client' ? 'forward' : 'reverse';
        const flags = d.tcp_flags ?? '';
        const isSyn = flags.includes('SYN');
        const isFin = flags.includes('FIN');
        const isRst = flags.includes('RST');
        const isDropped = d.state === 'MISSING_B';

        // Retransmission = same (direction, seq, payload) seen more than once;
        // ignore pure ACKs (payload=0) since they legitimately share seq.
        let isRetx = false;
        if (payload > 0) {
          const key = `${direction}|${seq}|${payload}`;
          if (seen.has(key)) isRetx = true;
          else seen.add(key);
        }

        return {
          packet_index: d.packet_index,
          relative_time: Math.max(0, (tsMs(d.timestamp) - t0) / 1000),
          absolute_time: d.timestamp,
          direction,
          seq_num: seq,
          ack_num: ack,
          window_size: win,
          payload_len: payload,
          flags,
          is_retransmission: isRetx,
          is_syn: isSyn,
          is_fin: isFin,
          is_rst: isRst,
          is_dropped: isDropped,
        };
      });
  }, [flowPackets, flow.protocol]);

  const wiresharkFilter = `(ip.addr == ${flow.src_ip} && ip.addr == ${flow.dst_ip}) && (${
    flow.protocol === 'TCP' ? 'tcp' : 'udp'
  }.port == ${flow.src_port} && ${flow.protocol === 'TCP' ? 'tcp' : 'udp'}.port == ${flow.dst_port})`;

  const handleCopyFilter = () => {
    navigator.clipboard.writeText(wiresharkFilter);
    setCopiedFilter(true);
    setTimeout(() => setCopiedFilter(false), 2000);
  };

  // Stats
  const stats = useMemo(() => {
    let syn = 0, fin = 0, rst = 0, drops = 0, retransmit = 0, data = 0;
    for (const p of flowPackets) {
      const label = p.event.label;
      if (label === 'SYN') syn++;
      else if (label === 'FIN') fin++;
      else if (label === 'RST') rst++;
      else if (label === 'Dropped') drops++;
      else if (label === 'Retransmission') retransmit++;
      else data++;
    }
    return { syn, fin, rst, drops, retransmit, data, total: flowPackets.length };
  }, [flowPackets]);

  return (
    <div className="fixed inset-0 bg-black/70 backdrop-blur-sm z-50 flex items-center justify-center p-4">
      <div className="bg-slate-900 border border-slate-700 rounded-xl shadow-2xl w-full max-w-5xl h-[90vh] flex flex-col">
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-slate-700">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-green-500/10 rounded-lg">
              <MessageSquare className="w-5 h-5 text-green-400" />
            </div>
            <div>
              <h2 className="text-lg font-semibold text-white">Follow Stream: Conversation View</h2>
              <p className="text-xs text-slate-400">
                {flow.src_ip}:{flow.src_port} ↔ {flow.dst_ip}:{flow.dst_port} • {flow.protocol} • {stats.total} packets
              </p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            {/* View Tabs — Conversation / Graph */}
            <div className="flex items-center rounded-lg border border-slate-700 bg-slate-800/60 p-0.5">
              <button
                onClick={() => setActiveView('conversation')}
                className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors flex items-center gap-1.5 ${
                  activeView === 'conversation'
                    ? 'bg-slate-700 text-white'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
                title="Chat-style conversation view"
              >
                <MessageSquare className="w-3.5 h-3.5" />
                Conversation
              </button>
              <button
                onClick={() => setActiveView('graph')}
                className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors flex items-center gap-1.5 ${
                  activeView === 'graph'
                    ? 'bg-slate-700 text-white'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
                title="TCP performance graphs — Time-Sequence, RTT, Throughput"
                disabled={flow.protocol !== 'TCP'}
              >
                <TrendingUp className="w-3.5 h-3.5" />
                Graphs
                {flow.protocol !== 'TCP' && (
                  <span className="text-[9px] text-slate-500 ml-0.5">(TCP only)</span>
                )}
              </button>
              <button
                onClick={() => setActiveView('payload')}
                className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors flex items-center gap-1.5 ${
                  activeView === 'payload'
                    ? 'bg-slate-700 text-white'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
                title="Reassembled TCP payload — view raw data"
                disabled={flow.protocol !== 'TCP' || !jobId}
              >
                <FileText className="w-3.5 h-3.5" />
                Payload
                {(flow.protocol !== 'TCP' || !jobId) && (
                  <span className="text-[9px] text-slate-500 ml-0.5">(TCP only)</span>
                )}
              </button>
            </div>
            <button onClick={onClose} className="p-2 hover:bg-slate-800 rounded-lg transition-colors">
              <X className="w-5 h-5 text-slate-400" />
            </button>
          </div>
        </div>

        {/* Toolbar */}
        <div className="px-6 py-3 border-b border-slate-700/50 bg-slate-800/30 flex items-center gap-4 flex-wrap">
          {/* Wireshark Filter */}
          <div className="flex items-center gap-2 flex-1 min-w-0">
            <Filter className="w-3.5 h-3.5 text-slate-500 flex-shrink-0" />
            <code className="text-[10px] text-slate-400 font-mono truncate flex-1">{wiresharkFilter}</code>
            <button
              onClick={handleCopyFilter}
              className="px-2 py-1 text-[10px] bg-slate-700 hover:bg-slate-600 text-slate-300 rounded flex items-center gap-1 flex-shrink-0"
            >
              <Copy className="w-3 h-3" />
              {copiedFilter ? 'Copied!' : 'Copy'}
            </button>
          </div>

          {/* Filter Buttons */}
          <div className="flex gap-1">
            {(['all', 'drops', 'events'] as const).map(f => (
              <button
                key={f}
                onClick={() => setFilterType(f)}
                className={`px-2.5 py-1 text-[10px] rounded transition-colors ${
                  filterType === f
                    ? 'bg-blue-500/20 text-blue-400 border border-blue-500/40'
                    : 'bg-slate-700/50 text-slate-400 hover:text-slate-300'
                }`}
              >
                {f === 'all' ? `All (${stats.total})` : f === 'drops' ? `Drops (${stats.drops})` : 'Events Only'}
              </button>
            ))}
          </div>
        </div>

        {/* Stats Bar */}
        <div className="px-6 py-2 border-b border-slate-700/30 flex items-center gap-4 text-[10px]">
          {stats.syn > 0 && <span className="text-blue-400">SYN: {stats.syn}</span>}
          {stats.fin > 0 && <span className="text-slate-400">FIN: {stats.fin}</span>}
          {stats.rst > 0 && <span className="text-orange-400">RST: {stats.rst}</span>}
          {stats.drops > 0 && <span className="text-red-400">Drops: {stats.drops}</span>}
          {stats.retransmit > 0 && <span className="text-yellow-400">Retransmissions: {stats.retransmit}</span>}
          <span className="text-slate-500">Data: {stats.data}</span>
          {forensics && forensics.avg_one_way_latency_ms > 0 && (
            <span className="text-cyan-400 ml-auto">Avg Latency: {forensics.avg_one_way_latency_ms.toFixed(1)}ms</span>
          )}
        </div>

        {/* Body — Conversation Timeline OR TCP Performance Graphs OR Payload */}
        <div className="flex-1 overflow-y-auto px-6 py-4">
          {activeView === 'graph' ? (
            <TCPStreamGraphs
              points={graphPoints}
              forwardLabel={`Client → Server (${flow.src_ip}:${flow.src_port})`}
              reverseLabel={`Server → Client (${flow.dst_ip}:${flow.dst_port})`}
              title={`TCP Stream — ${flow.src_ip}:${flow.src_port} ↔ ${flow.dst_ip}:${flow.dst_port}`}
            />
          ) : activeView === 'payload' ? (
            <PayloadView
              streamData={streamData}
              loading={payloadLoading}
              error={payloadError}
              view={payloadView}
              onViewChange={setPayloadView}
              flow={flow}
            />
          ) : (
            <>
              {/* Endpoint Labels */}
              <div className="flex items-center justify-between mb-4 px-2">
                <div className="flex items-center gap-2">
                  <div className="w-3 h-3 rounded-full bg-red-500/60" />
                  <span className="text-xs font-medium text-red-400">
                    Client: {flow.src_ip}:{flow.src_port}
                  </span>
                </div>
                <div className="text-xs text-slate-600">← Time →</div>
                <div className="flex items-center gap-2">
                  <span className="text-xs font-medium text-blue-400">
                    Server: {flow.dst_ip}:{flow.dst_port}
                  </span>
                  <div className="w-3 h-3 rounded-full bg-blue-500/60" />
                </div>
              </div>

              {/* Packets */}
              <div className="space-y-2">
                {filteredPackets.length === 0 ? (
                  <div className="text-center text-slate-500 py-8 text-sm">
                    No packets match the current filter
                  </div>
                ) : (
                  filteredPackets.map((packet, idx) => (
                    <ConversationBubble
                      key={idx}
                      packet={packet}
                      index={idx}
                      isCompareMode={!!forensics}
                      showExplanation={showExplanation === idx}
                      onToggleExplanation={() =>
                        setShowExplanation(showExplanation === idx ? null : idx)
                      }
                    />
                  ))
                )}
              </div>

              {/* End of Stream Marker */}
              {filteredPackets.length > 0 && (
                <div className="flex items-center justify-center gap-2 mt-4 pt-4 border-t border-slate-700/30">
                  <div className="h-px flex-1 bg-slate-700/50" />
                  <span className="text-[10px] text-slate-600 px-2">End of Conversation ({filteredPackets.length} packets shown)</span>
                  <div className="h-px flex-1 bg-slate-700/50" />
                </div>
              )}
            </>
          )}
        </div>

        {/* Footer Legend */}
        <div className="px-6 py-3 border-t border-slate-700 bg-slate-800/50">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-4 text-[10px]">
              <span className="flex items-center gap-1"><div className="w-2 h-2 rounded-full bg-red-500/60" /> Client</span>
              <span className="flex items-center gap-1"><div className="w-2 h-2 rounded-full bg-blue-500/60" /> Server</span>
              <span className="flex items-center gap-1"><div className="w-2 h-2 rounded-full bg-yellow-500/60" /> Event</span>
              <span className="flex items-center gap-1"><div className="w-2 h-2 rounded-full bg-red-600" /> Drop/Error</span>
              <span className="text-slate-600 ml-2">Click ? for explanations</span>
            </div>
            <button
              onClick={onClose}
              className="px-4 py-2 bg-green-600 hover:bg-green-700 text-white text-sm rounded-lg transition-colors"
            >
              Close
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

// ─── Conversation Bubble Component ────────────────────────────────

interface ConversationBubbleProps {
  packet: ConversationPacket;
  index: number;
  isCompareMode: boolean;
  showExplanation: boolean;
  onToggleExplanation: () => void;
}

const ConversationBubble: React.FC<ConversationBubbleProps> = ({
  packet,
  index,
  isCompareMode,
  showExplanation,
  onToggleExplanation,
}) => {
  const { discrepancy: d, direction, event } = packet;
  const isClient = direction === 'client';
  const isDrop = d.state === 'MISSING_B';
  const isAsymmetric = d.state === 'MISSING_A';

  return (
    <div className={`flex ${isClient ? 'justify-start' : 'justify-end'}`}>
      <div className={`max-w-[75%] ${isClient ? 'mr-auto' : 'ml-auto'}`}>
        {/* Sequence number + timestamp */}
        <div className={`flex items-center gap-2 mb-1 text-[10px] ${isClient ? '' : 'justify-end'}`}>
          <span className="text-slate-600">#{index + 1}</span>
          <span className="text-slate-500 font-mono">{d.timestamp}</span>
          {d.length > 0 && <span className="text-slate-600">{d.length}B</span>}
        </div>

        {/* Bubble */}
        <div
          className={`rounded-xl px-4 py-2.5 border relative ${event.bgColor} ${event.borderColor} ${
            isDrop ? 'border-dashed' : ''
          }`}
        >
          {/* Direction Arrow */}
          <div className="flex items-center gap-2 mb-1">
            {isClient ? (
              <ArrowRight className="w-3 h-3 text-red-400 flex-shrink-0" />
            ) : (
              <ArrowLeft className="w-3 h-3 text-blue-400 flex-shrink-0" />
            )}
            <span className={`text-xs font-semibold ${event.color}`}>
              {event.label}
            </span>
            {event.icon}

            {/* Explain Button */}
            <button
              onClick={onToggleExplanation}
              className="ml-auto p-0.5 hover:bg-white/10 rounded transition-colors flex-shrink-0"
              title="Explain this packet"
            >
              <HelpCircle className="w-3 h-3 text-slate-500 hover:text-blue-400" />
            </button>
          </div>

          {/* Packet Info */}
          <div className="text-[11px] text-slate-300 leading-relaxed">
            {/* TCP Flags */}
            {d.tcp_flags && (
              <span className="font-mono text-[10px] px-1.5 py-0.5 bg-slate-700/50 rounded mr-1">
                [{d.tcp_flags}]
              </span>
            )}

            {/* State Badge */}
            {isDrop && (
              <span className="text-[10px] px-1.5 py-0.5 bg-red-500/20 text-red-400 rounded mr-1">
                DROPPED
              </span>
            )}
            {isAsymmetric && (
              <span className="text-[10px] px-1.5 py-0.5 bg-purple-500/20 text-purple-400 rounded mr-1">
                WAN ONLY
              </span>
            )}
            {d.state === 'MODIFIED' && (
              <span className="text-[10px] px-1.5 py-0.5 bg-yellow-500/20 text-yellow-400 rounded mr-1">
                MODIFIED
              </span>
            )}

            {/* Flow Info */}
            <span className="text-slate-500 text-[10px] font-mono">
              {d.src_ip}:{d.src_port} → {d.dst_ip}:{d.dst_port}
            </span>
          </div>

          {/* One-Way Latency (Compare Mode) */}
          {isCompareMode && packet.latencyMs !== undefined && packet.latencyMs > 0 && (
            <div className="mt-1.5 pt-1.5 border-t border-slate-600/20 flex items-center gap-2">
              <Clock className="w-3 h-3 text-cyan-400" />
              <div className="text-[10px]">
                <span className="text-slate-500">LAN: </span>
                <span className="text-slate-300 font-mono">{packet.lanTimestamp || '—'}</span>
                <span className="text-slate-600 mx-1">→</span>
                <span className="text-slate-500">WAN: </span>
                <span className="text-slate-300 font-mono">{packet.wanTimestamp || '—'}</span>
                <span className={`ml-2 font-semibold ${
                  packet.latencyMs > 100 ? 'text-red-400' : packet.latencyMs > 50 ? 'text-yellow-400' : 'text-cyan-400'
                }`}>
                  [{packet.latencyMs.toFixed(1)}ms delay]
                </span>
              </div>
            </div>
          )}

          {/* Field Changes for MODIFIED packets */}
          {d.field_changes && d.field_changes.length > 0 && (
            <div className="mt-1.5 flex flex-wrap gap-1">
              {d.field_changes.map((fc, j) => (
                <span key={j} className="px-1.5 py-0.5 text-[9px] bg-yellow-500/10 text-yellow-400 rounded border border-yellow-500/20">
                  {fc.field}: {fc.value_a} → {fc.value_b}
                </span>
              ))}
            </div>
          )}

          {/* Drop Strikethrough Visual */}
          {isDrop && (
            <div className="absolute inset-0 flex items-center justify-center pointer-events-none">
              <div className="w-full h-px bg-red-500/40 mx-4" />
            </div>
          )}
        </div>

        {/* Educational Explanation */}
        {showExplanation && (
          <div className={`mt-2 p-3 bg-blue-900/20 border border-blue-700/30 rounded-lg ${
            isClient ? '' : 'text-right'
          }`}>
            <div className="text-[10px] font-semibold text-blue-400 mb-1">📚 What's Happening Here:</div>
            <p className="text-[11px] text-slate-300 leading-relaxed">{event.explanation}</p>

            {/* State-specific educational content */}
            {isDrop && (
              <div className="mt-2 pt-2 border-t border-blue-700/20">
                <div className="text-[10px] font-semibold text-red-400 mb-1">🔴 Why Was This Dropped?</div>
                <p className="text-[11px] text-slate-400 leading-relaxed">
                  {getDropExplanation(d)}
                </p>
              </div>
            )}

            {isAsymmetric && (
              <div className="mt-2 pt-2 border-t border-blue-700/20">
                <div className="text-[10px] font-semibold text-purple-400 mb-1">🟣 Why Is This WAN-Only?</div>
                <p className="text-[11px] text-slate-400 leading-relaxed">
                  This packet appeared on the WAN side but not on the LAN side. It may be return
                  traffic from the remote site, a device-generated packet (BFD/OMP), or traffic
                  arriving via asymmetric routing.
                </p>
              </div>
            )}

            {d.state === 'MODIFIED' && (
              <div className="mt-2 pt-2 border-t border-blue-700/20">
                <div className="text-[10px] font-semibold text-yellow-400 mb-1">🟡 What Changed?</div>
                <p className="text-[11px] text-slate-400 leading-relaxed">
                  The SD-WAN device modified this packet during transit. Common changes include:
                  NAT (IP address translation), QoS remarking (DSCP), or TTL decrement (normal routing).
                  {d.field_changes?.map(fc => ` ${fc.field}: ${fc.value_a} → ${fc.value_b}.`).join('')}
                </p>
              </div>
            )}

            {isCompareMode && (
              <div className="mt-2 pt-2 border-t border-blue-700/20">
                <div className="text-[10px] font-semibold text-cyan-400 mb-1">⏱ Compare Mode: One-Way Latency</div>
                <p className="text-[11px] text-slate-400 leading-relaxed">
                  {packet.latencyMs !== undefined && packet.latencyMs > 0
                    ? `This packet took ${packet.latencyMs.toFixed(1)}ms to transit the SD-WAN device. ${
                        packet.latencyMs > 100
                          ? 'This is HIGH latency. Check for QoS queuing, interface congestion, or crypto processing delays.'
                          : packet.latencyMs > 50
                          ? 'This is moderate latency. May indicate queuing on the device.'
                          : 'This is normal transit latency.'
                      }`
                    : 'Latency data not available for this packet. Only matched packets have LAN-to-WAN transit times.'}
                </p>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
};

// ─── Packet Event Classifier ──────────────────────────────────────

function classifyPacketEvent(d: Discrepancy): PacketEvent {
  const flags = d.tcp_flags || '';

  // Dropped packet
  if (d.state === 'MISSING_B') {
    if (flags.includes('SYN') && !flags.includes('ACK')) {
      return {
        label: 'SYN Dropped',
        color: 'text-red-400',
        bgColor: 'bg-red-900/20',
        borderColor: 'border-red-700/40',
        icon: <XCircle className="w-3 h-3 text-red-400" />,
        explanation: 'A TCP SYN (connection request) was sent from the client but the SD-WAN device dropped it. This means a firewall rule, ACL, or policy blocked this new connection before it could reach the WAN.',
      };
    }
    return {
      label: 'Dropped',
      color: 'text-red-400',
      bgColor: 'bg-red-900/20',
      borderColor: 'border-red-700/40',
      icon: <XCircle className="w-3 h-3 text-red-400" />,
      explanation: `This ${d.protocol} packet was dropped by the SD-WAN device. It entered the LAN interface but never appeared on the WAN interface. Possible causes: firewall policy, QoS policer, MTU issue, or route blackhole.`,
    };
  }

  // Asymmetric (WAN-only)
  if (d.state === 'MISSING_A') {
    return {
      label: 'Asymmetric',
      color: 'text-purple-400',
      bgColor: 'bg-purple-900/15',
      borderColor: 'border-purple-700/30',
      icon: <AlertTriangle className="w-3 h-3 text-purple-400" />,
      explanation: 'This packet appeared on the WAN but not on the LAN. It may be return traffic from the remote site, a control plane packet generated by the device (BFD/OMP), or traffic arriving via a different path (asymmetric routing).',
    };
  }

  // Modified
  if (d.state === 'MODIFIED') {
    return {
      label: 'Modified',
      color: 'text-yellow-400',
      bgColor: 'bg-yellow-900/15',
      borderColor: 'border-yellow-700/30',
      icon: <AlertTriangle className="w-3 h-3 text-yellow-400" />,
      explanation: 'This packet was found in both captures but with changes. The SD-WAN device modified it during transit — typically NAT (IP translation), QoS (DSCP remarking), or TTL decrement.',
    };
  }

  // TCP Events (PRESENT_BOTH or matched)
  if (flags.includes('SYN') && !flags.includes('ACK')) {
    return {
      label: 'SYN',
      color: 'text-blue-400',
      bgColor: 'bg-blue-900/15',
      borderColor: 'border-blue-700/30',
      icon: <Zap className="w-3 h-3 text-blue-400" />,
      explanation: 'SYN (Synchronize) — The client is starting a new TCP connection. This is step 1 of the 3-way handshake: Client sends SYN → Server replies SYN-ACK → Client sends ACK. The connection is then "established".',
    };
  }

  if (flags.includes('SYN') && flags.includes('ACK')) {
    return {
      label: 'SYN-ACK',
      color: 'text-blue-400',
      bgColor: 'bg-blue-900/15',
      borderColor: 'border-blue-700/30',
      icon: <Zap className="w-3 h-3 text-blue-400" />,
      explanation: 'SYN-ACK — The server is responding to the client\'s connection request. This is step 2 of the 3-way handshake. The server accepts the connection and proposes its own sequence number.',
    };
  }

  if (flags.includes('FIN')) {
    return {
      label: 'FIN',
      color: 'text-slate-400',
      bgColor: 'bg-slate-800/30',
      borderColor: 'border-slate-600/30',
      icon: <CheckCircle className="w-3 h-3 text-slate-400" />,
      explanation: 'FIN (Finish) — One side is closing the connection gracefully. A proper TCP shutdown has four steps: Side A sends FIN → Side B sends ACK → Side B sends FIN → Side A sends ACK. Both sides must agree to close.',
    };
  }

  if (flags.includes('RST')) {
    return {
      label: 'RST',
      color: 'text-orange-400',
      bgColor: 'bg-orange-900/15',
      borderColor: 'border-orange-700/30',
      icon: <XCircle className="w-3 h-3 text-orange-400" />,
      explanation: 'RST (Reset) — The connection was aborted immediately. No graceful shutdown. Common causes: the server rejected the connection, the application crashed, a firewall sent a fake RST to kill the connection, or the connection timed out.',
    };
  }

  if (flags.includes('PSH')) {
    return {
      label: 'PSH, ACK',
      color: 'text-green-400',
      bgColor: 'bg-green-900/10',
      borderColor: 'border-green-700/20',
      icon: <ArrowRight className="w-3 h-3 text-green-400" />,
      explanation: 'PSH (Push) + ACK — Data is being sent and should be delivered to the application immediately. This is the most common flag combination during an active data transfer (HTTP requests, file downloads, etc.).',
    };
  }

  // Retransmission detection (heuristic: same flow, same flags, close timestamps)
  if (d.detail?.toLowerCase().includes('retransmit')) {
    return {
      label: 'Retransmission',
      color: 'text-yellow-400',
      bgColor: 'bg-yellow-900/15',
      borderColor: 'border-yellow-700/30',
      icon: <AlertTriangle className="w-3 h-3 text-yellow-400" />,
      explanation: 'This packet is a retransmission — the original was lost or the ACK was delayed. TCP automatically resends data when it doesn\'t receive acknowledgment within the retransmission timeout (RTO). Frequent retransmissions indicate network congestion or packet loss.',
    };
  }

  // Default: normal data packet
  return {
    label: 'Data',
    color: 'text-slate-300',
    bgColor: isClient(d) ? 'bg-red-900/10' : 'bg-blue-900/10',
    borderColor: isClient(d) ? 'border-red-700/20' : 'border-blue-700/20',
    icon: <ArrowRight className="w-3 h-3 text-slate-500" />,
    explanation: `A ${d.protocol} data packet (${d.length} bytes) in an established connection. This is normal data transfer between client and server.`,
  };
}

function isClient(d: Discrepancy): boolean {
  // Heuristic: lower port number is typically the server
  return d.src_port > d.dst_port;
}

// ─── Drop Explanation Generator ───────────────────────────────────

function getDropExplanation(d: Discrepancy): string {
  const flags = d.tcp_flags || '';

  if (flags.includes('SYN') && !flags.includes('ACK')) {
    return `A TCP SYN packet (new connection request) from ${d.src_ip}:${d.src_port} to ${d.dst_ip}:${d.dst_port} was blocked by the SD-WAN device. Check: Zone-Based Firewall (ZBFW), Access Control Lists (ACL), and App-Aware Routing policy. Look for "implicit deny" rules.`;
  }

  if (flags.includes('RST')) {
    return 'A TCP RST (reset) was dropped. The device may be filtering resets for connections it considers already closed. This is usually harmless.';
  }

  if (d.length > 1400) {
    return `This large packet (${d.length} bytes) was dropped, possibly due to an MTU issue. The tunnel encapsulation adds 40-60 bytes of overhead, which may push the packet over the WAN interface MTU. Check: interface MTU, tunnel MTU, TCP MSS clamping, and PMTUD (Path MTU Discovery).`;
  }

  if (d.protocol === 'UDP') {
    return `A UDP packet to port ${d.dst_port} was dropped. UDP has no retransmission mechanism, so this data is permanently lost. Check: App-Aware routing policy, port-based ACLs, and QoS policers.`;
  }

  return `This ${d.protocol} packet was dropped mid-flow. The connection was already established, suggesting this is not a policy block but rather congestion, buffer overflow, or a routing change. Check: WAN interface utilization, QoS queue statistics, and routing table stability.`;
}

// ─── Latency Estimator ────────────────────────────────────────────

function estimateLatency(d: Discrepancy, forensics: ForensicSummary): number | undefined {
  // For matched packets, estimate latency from the forensic averages
  if (d.state === 'PRESENT_BOTH' || d.state === 'MODIFIED') {
    return forensics.avg_one_way_latency_ms > 0 ? forensics.avg_one_way_latency_ms : undefined;
  }
  return undefined;
}

// ─── Payload View Component (P1) ──────────────────────────────────

interface PayloadViewProps {
  streamData: StreamResponse | null;
  loading: boolean;
  error: string | null;
  view: 'ascii' | 'hex';
  onViewChange: (view: 'ascii' | 'hex') => void;
  flow: FlowComparisonSummary;
}

function PayloadView({ streamData, loading, error, view, onViewChange, flow }: PayloadViewProps) {
  if (loading) {
    return (
      <div className="flex items-center justify-center py-16">
        <Loader2 className="w-8 h-8 text-blue-400 animate-spin" />
        <span className="ml-3 text-slate-400">Loading stream data...</span>
      </div>
    );
  }

  if (error) {
    return (
      <div className="bg-red-900/20 border border-red-700/40 rounded-lg p-6 text-center">
        <AlertTriangle className="w-8 h-8 text-red-400 mx-auto mb-3" />
        <p className="text-red-400 font-medium">Failed to load payload</p>
        <p className="text-red-400/70 text-sm mt-1">{error}</p>
      </div>
    );
  }

  if (!streamData) {
    return (
      <div className="text-center text-slate-500 py-16">
        <FileText className="w-12 h-12 mx-auto mb-3 opacity-40" />
        <p>No stream data available</p>
      </div>
    );
  }

  const hasClientData = streamData.reassembled_client_bytes && streamData.reassembled_client_bytes > 0;
  const hasServerData = streamData.reassembled_server_bytes && streamData.reassembled_server_bytes > 0;

  if (!hasClientData && !hasServerData) {
    return (
      <div className="text-center text-slate-500 py-16">
        <FileText className="w-12 h-12 mx-auto mb-3 opacity-40" />
        <p>No payload data in this stream</p>
        <p className="text-xs mt-2">This may be a control-only stream (SYN/FIN/ACK only)</p>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* View Toggle */}
      <div className="flex items-center justify-between">
        <div className="text-sm text-slate-400">
          Reassembled TCP Payload
          {streamData.is_truncated && (
            <span className="ml-2 text-yellow-400 text-xs">(truncated to 64KB)</span>
          )}
        </div>
        <div className="flex items-center gap-1 bg-slate-800 rounded-lg p-0.5">
          <button
            onClick={() => onViewChange('ascii')}
            className={`px-3 py-1 text-xs rounded-md transition-colors ${
              view === 'ascii' ? 'bg-slate-700 text-white' : 'text-slate-400 hover:text-white'
            }`}
          >
            ASCII
          </button>
          <button
            onClick={() => onViewChange('hex')}
            className={`px-3 py-1 text-xs rounded-md transition-colors ${
              view === 'hex' ? 'bg-slate-700 text-white' : 'text-slate-400 hover:text-white'
            }`}
          >
            Hex
          </button>
        </div>
      </div>

      {/* Client → Server Payload */}
      {hasClientData && (
        <div className="border border-red-700/30 rounded-lg overflow-hidden">
          <div className="bg-red-900/20 px-4 py-2 border-b border-red-700/30 flex items-center justify-between">
            <div className="flex items-center gap-2">
              <ArrowRight className="w-4 h-4 text-red-400" />
              <span className="text-sm font-medium text-red-400">
                Client → Server ({flow.src_ip}:{flow.src_port})
              </span>
            </div>
            <span className="text-xs text-red-400/70">
              {formatBytes(streamData.reassembled_client_bytes || 0)}
            </span>
          </div>
          <div className="p-4 bg-slate-900/50 max-h-80 overflow-auto">
            <pre className="text-xs font-mono text-slate-300 whitespace-pre-wrap break-all">
              {view === 'ascii'
                ? streamData.reassembled_client_ascii || '[No ASCII data]'
                : formatHexDump(streamData.reassembled_client_hex || '')}
            </pre>
          </div>
        </div>
      )}

      {/* Server → Client Payload */}
      {hasServerData && (
        <div className="border border-blue-700/30 rounded-lg overflow-hidden">
          <div className="bg-blue-900/20 px-4 py-2 border-b border-blue-700/30 flex items-center justify-between">
            <div className="flex items-center gap-2">
              <ArrowLeft className="w-4 h-4 text-blue-400" />
              <span className="text-sm font-medium text-blue-400">
                Server → Client ({flow.dst_ip}:{flow.dst_port})
              </span>
            </div>
            <span className="text-xs text-blue-400/70">
              {formatBytes(streamData.reassembled_server_bytes || 0)}
            </span>
          </div>
          <div className="p-4 bg-slate-900/50 max-h-80 overflow-auto">
            <pre className="text-xs font-mono text-slate-300 whitespace-pre-wrap break-all">
              {view === 'ascii'
                ? streamData.reassembled_server_ascii || '[No ASCII data]'
                : formatHexDump(streamData.reassembled_server_hex || '')}
            </pre>
          </div>
        </div>
      )}

      {/* Application Detection */}
      {streamData.application && (
        <div className="text-center text-xs text-slate-500">
          Detected Application: <span className="text-slate-300">{streamData.application}</span>
        </div>
      )}
    </div>
  );
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / 1024 / 1024).toFixed(2)} MB`;
}

function formatHexDump(hex: string): string {
  if (!hex) return '[No hex data]';
  
  const lines: string[] = [];
  for (let i = 0; i < hex.length; i += 32) {
    const chunk = hex.slice(i, i + 32);
    const offset = (i / 2).toString(16).padStart(8, '0');
    
    // Format hex with spaces every 2 chars
    const hexPart = chunk.match(/.{1,2}/g)?.join(' ') || '';
    
    // Convert to ASCII
    const asciiPart = chunk.match(/.{1,2}/g)?.map(h => {
      const code = parseInt(h, 16);
      return code >= 32 && code < 127 ? String.fromCharCode(code) : '.';
    }).join('') || '';
    
    lines.push(`${offset}  ${hexPart.padEnd(48)}  ${asciiPart}`);
  }
  
  return lines.join('\n');
}
