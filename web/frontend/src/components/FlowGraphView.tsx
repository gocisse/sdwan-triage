import React, { useMemo } from 'react';
import { X, ArrowRight } from 'lucide-react';
import type { FlowComparisonSummary, Discrepancy } from '../types';

// ─── Public Interface ───────────────────────────────────────────

interface FlowGraphViewProps {
  flow: FlowComparisonSummary;
  discrepancies: Discrepancy[];
  onClose: () => void;
}

// ─── Internal Types ─────────────────────────────────────────────

interface SequenceEvent {
  index: number;
  timestamp: string;
  direction: 'right' | 'left';   // right = src→dst, left = dst→src
  label: string;                  // e.g. "[SYN]" or "UDP 1400B"
  sublabel: string;               // detail text
  state: 'matched' | 'dropped' | 'modified' | 'encrypted' | 'asymmetric';
  tcpFlags?: string;
  encrypted?: boolean;
  fieldChanges?: string;
}

// ─── Data Transformation ────────────────────────────────────────

function buildSequenceEvents(
  flow: FlowComparisonSummary,
  discrepancies: Discrepancy[],
): SequenceEvent[] {
  // Filter discrepancies belonging to this flow
  const flowDisc = discrepancies.filter(d =>
    (d.src_ip === flow.src_ip && d.dst_ip === flow.dst_ip &&
     d.src_port === flow.src_port && d.dst_port === flow.dst_port &&
     d.protocol === flow.protocol) ||
    (d.src_ip === flow.dst_ip && d.dst_ip === flow.src_ip &&
     d.src_port === flow.dst_port && d.dst_port === flow.src_port &&
     d.protocol === flow.protocol)
  );

  // Sort by timestamp then packet index
  const sorted = [...flowDisc].sort((a, b) => {
    if (a.timestamp !== b.timestamp) return a.timestamp.localeCompare(b.timestamp);
    return a.packet_index - b.packet_index;
  });

  // Build events (cap at 60 for rendering sanity)
  return sorted.slice(0, 60).map((d): SequenceEvent => {
    const isForward = d.src_ip === flow.src_ip && d.src_port === flow.src_port;
    const direction: 'right' | 'left' = isForward ? 'right' : 'left';

    let label = d.protocol;
    if (d.tcp_flags) {
      label = `[${d.tcp_flags}]`;
    } else {
      label = `${d.protocol} ${d.length}B`;
    }

    let state: SequenceEvent['state'];
    switch (d.state) {
      case 'MISSING_B': state = 'dropped'; break;
      case 'MISSING_A': state = 'asymmetric'; break;
      case 'MODIFIED':  state = 'modified'; break;
      default:          state = 'matched'; break;
    }
    if (d.encrypted) state = 'encrypted';

    let fieldChanges: string | undefined;
    if (d.field_changes && d.field_changes.length > 0) {
      fieldChanges = d.field_changes.map(fc => `${fc.field}: ${fc.value_a}→${fc.value_b}`).join(', ');
    }

    return {
      index: d.packet_index,
      timestamp: d.timestamp,
      direction,
      label,
      sublabel: d.detail,
      state,
      tcpFlags: d.tcp_flags,
      encrypted: d.encrypted,
      fieldChanges,
    };
  });
}

// If the flow has no discrepancies, build synthetic "matched" events
function buildSyntheticEvents(flow: FlowComparisonSummary): SequenceEvent[] {
  const events: SequenceEvent[] = [];
  for (let i = 0; i < Math.min(flow.matched, 20); i++) {
    events.push({
      index: i,
      timestamp: '',
      direction: i % 2 === 0 ? 'right' : 'left',
      label: `${flow.protocol} packet`,
      sublabel: 'Matched — present in both captures',
      state: 'matched',
    });
  }
  for (let i = 0; i < Math.min(flow.missing_b, 10); i++) {
    events.push({
      index: flow.matched + i,
      timestamp: '',
      direction: 'right',
      label: `${flow.protocol} packet`,
      sublabel: 'Dropped — missing from WAN capture',
      state: 'dropped',
    });
  }
  for (let i = 0; i < Math.min(flow.modified, 5); i++) {
    events.push({
      index: flow.matched + flow.missing_b + i,
      timestamp: '',
      direction: 'right',
      label: `${flow.protocol} packet`,
      sublabel: 'Modified — NAT/TTL/DSCP change',
      state: 'modified',
    });
  }
  return events;
}

// ─── Style Config ───────────────────────────────────────────────

const STATE_STYLES: Record<SequenceEvent['state'], {
  stroke: string; fill: string; dash: string; textColor: string; bgClass: string; label: string;
}> = {
  matched:    { stroke: '#4ade80', fill: '#4ade80', dash: '',       textColor: '#4ade80', bgClass: 'bg-green-500/15 text-green-400',  label: 'Matched' },
  dropped:    { stroke: '#f87171', fill: '#f87171', dash: '6,4',   textColor: '#f87171', bgClass: 'bg-red-500/15 text-red-400',      label: 'Dropped' },
  modified:   { stroke: '#facc15', fill: '#facc15', dash: '',       textColor: '#facc15', bgClass: 'bg-yellow-500/15 text-yellow-400', label: 'Modified' },
  encrypted:  { stroke: '#22d3ee', fill: '#22d3ee', dash: '4,3',   textColor: '#22d3ee', bgClass: 'bg-cyan-500/15 text-cyan-400',    label: 'Encrypted' },
  asymmetric: { stroke: '#c084fc', fill: '#c084fc', dash: '6,4',   textColor: '#c084fc', bgClass: 'bg-purple-500/15 text-purple-400', label: 'Asymmetric' },
};

// ─── SVG Constants ──────────────────────────────────────────────

const COL_LEFT = 100;      // LAN column x
const COL_RIGHT = 460;     // WAN column x
const ROW_START = 80;       // First event y
const ROW_HEIGHT = 52;      // Spacing per event
const SVG_WIDTH = 560;
const ARROW_HEAD = 8;
const LABEL_OFFSET_Y = -8;

// ─── Component ──────────────────────────────────────────────────

const FlowGraphView: React.FC<FlowGraphViewProps> = ({ flow, discrepancies, onClose }) => {
  const events = useMemo(() => {
    const fromDisc = buildSequenceEvents(flow, discrepancies);
    return fromDisc.length > 0 ? fromDisc : buildSyntheticEvents(flow);
  }, [flow, discrepancies]);

  const svgHeight = ROW_START + events.length * ROW_HEIGHT + 40;

  const srcLabel = `${flow.src_ip}:${flow.src_port}`;
  const dstLabel = `${flow.dst_ip}:${flow.dst_port}`;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm" onClick={onClose}>
      <div
        className="bg-slate-900 border border-slate-700 rounded-2xl shadow-2xl max-w-2xl w-full max-h-[90vh] flex flex-col"
        onClick={e => e.stopPropagation()}
      >
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-slate-700/50">
          <div>
            <h3 className="text-base font-bold text-white flex items-center gap-2">
              <ArrowRight className="w-4 h-4 text-blue-400" />
              Flow Sequence Diagram
            </h3>
            <p className="text-xs text-slate-500 mt-0.5 font-mono">
              {srcLabel} → {dstLabel} / {flow.protocol}
              {flow.encapsulated && (
                <span className="ml-2 px-1.5 py-0.5 text-[10px] bg-cyan-500/20 text-cyan-400 rounded">
                  {flow.tunnel_type || 'Tunnel'}
                </span>
              )}
            </p>
          </div>
          <button onClick={onClose} className="p-1.5 rounded-lg hover:bg-slate-700 transition-colors text-slate-400">
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Legend */}
        <div className="px-6 py-3 border-b border-slate-700/30 flex flex-wrap gap-3">
          {Object.entries(STATE_STYLES).map(([key, s]) => (
            <span key={key} className={`px-2 py-0.5 rounded text-[10px] font-medium ${s.bgClass}`}>
              {key === 'matched' ? '── ' : key === 'dropped' || key === 'asymmetric' || key === 'encrypted' ? '╌╌ ' : '── '}
              {s.label}
            </span>
          ))}
        </div>

        {/* SVG Diagram */}
        <div className="flex-1 overflow-auto px-2 py-4">
          <svg width={SVG_WIDTH} height={svgHeight} className="mx-auto" viewBox={`0 0 ${SVG_WIDTH} ${svgHeight}`}>
            <defs>
              {Object.entries(STATE_STYLES).map(([key, s]) => (
                <marker
                  key={key}
                  id={`arrow-${key}`}
                  markerWidth={ARROW_HEAD}
                  markerHeight={ARROW_HEAD}
                  refX={ARROW_HEAD - 1}
                  refY={ARROW_HEAD / 2}
                  orient="auto"
                >
                  <polygon
                    points={`0 0, ${ARROW_HEAD} ${ARROW_HEAD / 2}, 0 ${ARROW_HEAD}`}
                    fill={s.fill}
                    opacity={0.9}
                  />
                </marker>
              ))}
            </defs>

            {/* Column lifelines */}
            <line x1={COL_LEFT} y1={40} x2={COL_LEFT} y2={svgHeight - 10} stroke="#334155" strokeWidth={2} />
            <line x1={COL_RIGHT} y1={40} x2={COL_RIGHT} y2={svgHeight - 10} stroke="#334155" strokeWidth={2} />

            {/* Column headers */}
            <text x={COL_LEFT} y={22} textAnchor="middle" fill="#94a3b8" fontSize={11} fontWeight={600}>LAN Client</text>
            <text x={COL_LEFT} y={36} textAnchor="middle" fill="#64748b" fontSize={9} fontFamily="monospace">{truncate(srcLabel, 22)}</text>
            <text x={COL_RIGHT} y={22} textAnchor="middle" fill="#94a3b8" fontSize={11} fontWeight={600}>WAN Server</text>
            <text x={COL_RIGHT} y={36} textAnchor="middle" fill="#64748b" fontSize={9} fontFamily="monospace">{truncate(dstLabel, 22)}</text>

            {/* SD-WAN device indicator (center) */}
            <rect x={(COL_LEFT + COL_RIGHT) / 2 - 40} y={4} width={80} height={18} rx={4} fill="#1e293b" stroke="#475569" strokeWidth={1} />
            <text x={(COL_LEFT + COL_RIGHT) / 2} y={16} textAnchor="middle" fill="#94a3b8" fontSize={8} fontWeight={500}>SD-WAN Device</text>

            {/* Events */}
            {events.map((ev, i) => {
              const y = ROW_START + i * ROW_HEIGHT;
              const style = STATE_STYLES[ev.state];
              const x1 = ev.direction === 'right' ? COL_LEFT + 4 : COL_RIGHT - 4;
              const x2 = ev.direction === 'right' ? COL_RIGHT - 4 : COL_LEFT + 4;

              // For dropped packets, end arrow at the SD-WAN device center (packet doesn't reach server)
              const midX = (COL_LEFT + COL_RIGHT) / 2;
              const effectiveX2 = ev.state === 'dropped' ? midX : x2;

              return (
                <g key={i}>
                  {/* Timestamp */}
                  {ev.timestamp && (
                    <text x={4} y={y + 4} fill="#475569" fontSize={8} fontFamily="monospace">
                      {ev.timestamp.split('.')[0]}
                    </text>
                  )}

                  {/* Arrow line */}
                  <line
                    x1={x1}
                    y1={y}
                    x2={effectiveX2}
                    y2={y}
                    stroke={style.stroke}
                    strokeWidth={1.5}
                    strokeDasharray={style.dash}
                    markerEnd={`url(#arrow-${ev.state})`}
                    opacity={0.85}
                  />

                  {/* Drop X mark at the end for dropped packets */}
                  {ev.state === 'dropped' && (
                    <>
                      <line x1={midX - 5} y1={y - 5} x2={midX + 5} y2={y + 5} stroke="#f87171" strokeWidth={2} opacity={0.8} />
                      <line x1={midX + 5} y1={y - 5} x2={midX - 5} y2={y + 5} stroke="#f87171" strokeWidth={2} opacity={0.8} />
                    </>
                  )}

                  {/* Lock icon for encrypted */}
                  {ev.encrypted && (
                    <g transform={`translate(${midX - 5}, ${y - 12})`}>
                      <rect x={0} y={4} width={10} height={8} rx={1} fill="none" stroke="#22d3ee" strokeWidth={1} />
                      <path d="M2,4 V2 a3,3 0 0,1 6,0 V4" fill="none" stroke="#22d3ee" strokeWidth={1} />
                    </g>
                  )}

                  {/* Label above arrow */}
                  <text
                    x={(x1 + effectiveX2) / 2}
                    y={y + LABEL_OFFSET_Y}
                    textAnchor="middle"
                    fill={style.textColor}
                    fontSize={10}
                    fontWeight={500}
                    fontFamily="monospace"
                  >
                    {ev.label}
                  </text>

                  {/* Field changes for modified packets */}
                  {ev.fieldChanges && (
                    <text
                      x={(x1 + effectiveX2) / 2}
                      y={y + 14}
                      textAnchor="middle"
                      fill="#facc15"
                      fontSize={8}
                      opacity={0.7}
                    >
                      {truncate(ev.fieldChanges, 50)}
                    </text>
                  )}

                  {/* Packet index on the far right */}
                  <text x={SVG_WIDTH - 8} y={y + 4} textAnchor="end" fill="#334155" fontSize={7} fontFamily="monospace">
                    #{ev.index}
                  </text>
                </g>
              );
            })}
          </svg>
        </div>

        {/* Footer stats */}
        <div className="px-6 py-3 border-t border-slate-700/30 flex items-center justify-between text-xs text-slate-500">
          <span>{events.length} events shown (of {flow.packets_a + flow.packets_b} total packets)</span>
          <div className="flex gap-4">
            <span className="text-green-400">{flow.matched} matched</span>
            <span className="text-red-400">{flow.missing_b} dropped</span>
            <span className="text-yellow-400">{flow.modified} modified</span>
            {flow.encapsulated && <span className="text-cyan-400">tunneled</span>}
          </div>
        </div>
      </div>
    </div>
  );
};

function truncate(s: string, max: number): string {
  return s.length > max ? s.slice(0, max - 1) + '…' : s;
}

export default FlowGraphView;
