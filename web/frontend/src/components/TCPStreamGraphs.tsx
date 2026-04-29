// TCPStreamGraphs — Tabbed TCP performance graphs (Wireshark-style).
//
// Exposes three complementary views of a TCP stream:
//   1. Time-Sequence (Stevens): sequence number over time, with retransmit
//      and zero-window annotations. Best for seeing flow control stalls and
//      retransmissions.
//   2. Round-Trip Time: per-segment RTT over time. Best for seeing latency
//      spikes and jitter.
//   3. Throughput: forward + reverse bytes per second over time. Best for
//      seeing bandwidth usage patterns and bursty transmission.
//
// Graphs can be rendered from either:
//   • Full backend-derived TCPGraphData (most accurate), OR
//   • Bare TCPGraphPoint[] with RTT/throughput derived client-side (used by
//     the comparison modal where raw PCAPs are no longer available).
//
// Pure SVG, zero chart library deps.

import { useMemo, useState } from 'react';
import { TrendingUp, Clock, BarChart3, AlertTriangle } from 'lucide-react';
import {
  TCPSequenceGraph,
  type TCPGraphPoint,
  type TCPGraphRTTSample,
  type TCPGraphThroughputBin,
} from './TCPSequenceGraph';

// ─── Types ─────────────────────────────────────────────────────────

export type TCPStreamGraphsTab = 'time-sequence' | 'rtt' | 'throughput';

interface TCPStreamGraphsProps {
  points: TCPGraphPoint[];
  rttSamples?: TCPGraphRTTSample[];       // Optional: from backend. If absent, derived client-side.
  throughput?: TCPGraphThroughputBin[];   // Optional: from backend. If absent, derived client-side.
  forwardLabel?: string;
  reverseLabel?: string;
  title?: string;
  defaultTab?: TCPStreamGraphsTab;
  /** Height in pixels for the active plot area */
  height?: number;
}

// ─── Client-side Derivation ────────────────────────────────────────
//
// These mirror the backend algorithms (pkg/analyzer/tcp_graph.go) so the UI
// renders the same shapes regardless of whether the data came from the
// backend endpoint or was derived from in-memory Discrepancies.

function deriveRTTClient(points: TCPGraphPoint[]): TCPGraphRTTSample[] {
  if (points.length < 2) return [];

  const fwdIdx: number[] = [];
  const revIdx: number[] = [];
  for (let i = 0; i < points.length; i++) {
    (points[i].direction === 'forward' ? fwdIdx : revIdx).push(i);
  }

  // 32-bit TCP seq comparison (RFC 1982). `a >= b` accounting for wrap.
  const seqGE = (a: number, b: number): boolean => {
    // Normalise to signed 32-bit.
    const diff = ((a - b) | 0);
    return diff >= 0;
  };

  const out: TCPGraphRTTSample[] = [];
  const match = (
    dataIdx: number[],
    ackIdx: number[],
    direction: 'forward' | 'reverse',
  ): void => {
    if (!dataIdx.length || !ackIdx.length) return;
    let j = 0;
    for (const di of dataIdx) {
      const d = points[di];
      if (d.payload_len === 0 || d.is_retransmission || d.is_rst) continue;
      const needAck = (d.seq_num + d.payload_len) >>> 0; // force unsigned 32-bit
      while (j < ackIdx.length) {
        const a = points[ackIdx[j]];
        if (a.relative_time <= d.relative_time) {
          j++;
          continue;
        }
        if (seqGE(a.ack_num | 0, needAck | 0)) {
          const rtt = (a.relative_time - d.relative_time) * 1000;
          if (rtt >= 0 && rtt < 30000) {
            out.push({
              packet_index: d.packet_index,
              ack_index: a.packet_index,
              relative_time: d.relative_time,
              rtt_ms: rtt,
              direction,
              seq_num: d.seq_num,
              payload_len: d.payload_len,
            });
          }
          break;
        }
        j++;
      }
      if (j >= ackIdx.length) break;
    }
  };

  match(fwdIdx, revIdx, 'forward');
  match(revIdx, fwdIdx, 'reverse');
  out.sort((a, b) => a.relative_time - b.relative_time);
  return out;
}

function deriveThroughputClient(
  points: TCPGraphPoint[],
  durationSec: number,
): TCPGraphThroughputBin[] {
  if (points.length === 0) return [];
  if (durationSec <= 0) {
    const bin: TCPGraphThroughputBin = {
      start_time: 0,
      end_time: 0.001,
      forward_bytes: 0,
      reverse_bytes: 0,
      forward_packets: 0,
      reverse_packets: 0,
    };
    for (const p of points) {
      if (p.direction === 'forward') {
        bin.forward_bytes += p.payload_len;
        bin.forward_packets += 1;
      } else {
        bin.reverse_bytes += p.payload_len;
        bin.reverse_packets += 1;
      }
    }
    return [bin];
  }

  const targetBins = 60;
  const minBinSec = 0.05;
  const maxBinSec = 5.0;
  let binSec = durationSec / targetBins;
  if (binSec < minBinSec) binSec = minBinSec;
  if (binSec > maxBinSec) binSec = maxBinSec;

  const nBins = Math.floor(durationSec / binSec) + 1;
  const bins: TCPGraphThroughputBin[] = [];
  for (let i = 0; i < nBins; i++) {
    bins.push({
      start_time: i * binSec,
      end_time: (i + 1) * binSec,
      forward_bytes: 0,
      reverse_bytes: 0,
      forward_packets: 0,
      reverse_packets: 0,
    });
  }

  for (const p of points) {
    if (p.payload_len <= 0) continue;
    let idx = Math.floor(p.relative_time / binSec);
    if (idx < 0) idx = 0;
    if (idx >= nBins) idx = nBins - 1;
    if (p.direction === 'forward') {
      bins[idx].forward_bytes += p.payload_len;
      bins[idx].forward_packets += 1;
    } else {
      bins[idx].reverse_bytes += p.payload_len;
      bins[idx].reverse_packets += 1;
    }
  }

  // Trim trailing empty bins.
  let last = bins.length - 1;
  while (last > 0 && bins[last].forward_bytes === 0 && bins[last].reverse_bytes === 0) {
    last--;
  }
  return bins.slice(0, last + 1);
}

// ─── Container ─────────────────────────────────────────────────────

export function TCPStreamGraphs({
  points,
  rttSamples,
  throughput,
  forwardLabel = 'Forward (Client → Server)',
  reverseLabel = 'Reverse (Server → Client)',
  title,
  defaultTab = 'time-sequence',
  height = 380,
}: TCPStreamGraphsProps) {
  const [tab, setTab] = useState<TCPStreamGraphsTab>(defaultTab);

  const durationSec = useMemo(() => {
    if (points.length === 0) return 0;
    let maxT = 0;
    for (const p of points) {
      if (p.relative_time > maxT) maxT = p.relative_time;
    }
    return maxT;
  }, [points]);

  const derivedRTT = useMemo<TCPGraphRTTSample[]>(() => {
    return rttSamples && rttSamples.length > 0 ? rttSamples : deriveRTTClient(points);
  }, [rttSamples, points]);

  const derivedThroughput = useMemo<TCPGraphThroughputBin[]>(() => {
    return throughput && throughput.length > 0
      ? throughput
      : deriveThroughputClient(points, durationSec);
  }, [throughput, points, durationSec]);

  // Handy counts for the tab badges.
  const rttCount = derivedRTT.length;
  const retxCount = useMemo(() => points.filter(p => p.is_retransmission).length, [points]);
  const zwCount = useMemo(
    () => points.filter(p => p.is_zero_window || p.window_size === 0).length,
    [points],
  );

  return (
    <div className="w-full">
      {/* Tab row */}
      <div className="flex items-center gap-1 mb-3 overflow-x-auto">
        <TabButton
          active={tab === 'time-sequence'}
          onClick={() => setTab('time-sequence')}
          icon={<TrendingUp className="w-3.5 h-3.5" />}
          label="Time-Sequence"
          sublabel="Stevens"
          badgeText={retxCount > 0 ? `${retxCount} retx` : undefined}
          badgeTone={retxCount > 0 ? 'red' : undefined}
        />
        <TabButton
          active={tab === 'rtt'}
          onClick={() => setTab('rtt')}
          icon={<Clock className="w-3.5 h-3.5" />}
          label="Round-Trip Time"
          sublabel={`${rttCount} samples`}
          disabled={rttCount === 0}
        />
        <TabButton
          active={tab === 'throughput'}
          onClick={() => setTab('throughput')}
          icon={<BarChart3 className="w-3.5 h-3.5" />}
          label="Throughput"
          sublabel={`${derivedThroughput.length} bins`}
          disabled={derivedThroughput.length === 0}
        />

        {zwCount > 0 && (
          <span className="ml-auto inline-flex items-center gap-1 px-2 py-1 bg-amber-500/10 text-amber-400 text-[10px] rounded border border-amber-500/30">
            <AlertTriangle className="w-3 h-3" />
            {zwCount} zero-window{zwCount === 1 ? '' : 's'}
          </span>
        )}
      </div>

      {/* Active tab content */}
      {tab === 'time-sequence' && (
        <TCPSequenceGraph
          points={points}
          forwardLabel={forwardLabel}
          reverseLabel={reverseLabel}
          height={height}
          title={title ?? 'TCP Time-Sequence Graph'}
        />
      )}

      {tab === 'rtt' && (
        <RTTGraph
          samples={derivedRTT}
          points={points}
          height={height}
        />
      )}

      {tab === 'throughput' && (
        <ThroughputGraph bins={derivedThroughput} height={height} />
      )}
    </div>
  );
}

// ─── RTT Graph ────────────────────────────────────────────────────

interface RTTGraphProps {
  samples: TCPGraphRTTSample[];
  points: TCPGraphPoint[]; // used to overlay retransmission markers at matching times
  height: number;
}

const RTT_MARGIN = { top: 16, right: 24, bottom: 44, left: 72 } as const;

function RTTGraph({ samples, points, height }: RTTGraphProps) {
  const [hovered, setHovered] = useState<TCPGraphRTTSample | null>(null);
  const [width, setWidth] = useState(900);
  const containerRef = useResizeObserver(setWidth);

  if (samples.length === 0) {
    return (
      <div className="bg-slate-900/60 border border-slate-700/50 rounded-lg p-8 text-center">
        <Clock className="w-8 h-8 text-slate-600 mx-auto mb-3" />
        <p className="text-sm text-slate-400">
          No RTT samples available.
        </p>
        <p className="text-xs text-slate-500 mt-1">
          RTT samples require matched data segments and ACKs. The stream may be
          too short, one-sided, or consist entirely of retransmissions.
        </p>
      </div>
    );
  }

  // Scales
  const plotW = Math.max(10, width - RTT_MARGIN.left - RTT_MARGIN.right);
  const plotH = Math.max(10, height - RTT_MARGIN.top - RTT_MARGIN.bottom);

  const timeMax = Math.max(1e-3, ...samples.map(s => s.relative_time));
  const rttMax = Math.max(1, ...samples.map(s => s.rtt_ms));
  const rttMin = Math.min(...samples.map(s => s.rtt_ms));
  const avgRTT = samples.reduce((s, x) => s + x.rtt_ms, 0) / samples.length;

  const xScale = (t: number) => RTT_MARGIN.left + (t / timeMax) * plotW;
  const yScale = (rtt: number) => RTT_MARGIN.top + plotH - (rtt / rttMax) * plotH;

  // Separate by direction for colouring.
  const fwdSamples = samples.filter(s => s.direction === 'forward');
  const revSamples = samples.filter(s => s.direction === 'reverse');

  // Retransmission overlays: use points to place red markers at matching times.
  const retxPoints = points.filter(p => p.is_retransmission && p.payload_len > 0);

  const xTicks = makeTicks(0, timeMax, 6);
  const yTicks = makeTicks(0, rttMax, 5);

  // Build the polyline path for each direction.
  const fwdPath = fwdSamples.map((s, i) => `${i === 0 ? 'M' : 'L'} ${xScale(s.relative_time)} ${yScale(s.rtt_ms)}`).join(' ');
  const revPath = revSamples.map((s, i) => `${i === 0 ? 'M' : 'L'} ${xScale(s.relative_time)} ${yScale(s.rtt_ms)}`).join(' ');

  return (
    <div ref={containerRef} className="w-full">
      <div className="flex items-start justify-between mb-3 gap-3 flex-wrap">
        <div className="flex items-center gap-2">
          <div className="p-1.5 bg-cyan-500/15 rounded-lg">
            <Clock className="w-4 h-4 text-cyan-400" />
          </div>
          <div>
            <h3 className="text-sm font-semibold text-white">Round-Trip Time</h3>
            <p className="text-[10px] text-slate-500">
              {samples.length} samples • min {rttMin.toFixed(1)} ms •
              avg {avgRTT.toFixed(1)} ms • max {rttMax.toFixed(1)} ms
            </p>
          </div>
        </div>
        <div className="flex items-center gap-2 text-[10px] text-slate-400">
          <LegendDot color="#34d399" label={`Forward (${fwdSamples.length})`} />
          <LegendDot color="#60a5fa" label={`Reverse (${revSamples.length})`} />
          {retxPoints.length > 0 && (
            <LegendDot color="#f87171" label={`Retx markers (${retxPoints.length})`} />
          )}
        </div>
      </div>

      <div className="relative bg-slate-950/60 rounded-lg border border-slate-700/40 overflow-hidden">
        <svg width={width} height={height} role="img" aria-label="TCP RTT graph" className="block">
          {/* Grid */}
          {xTicks.map(t => (
            <line
              key={`gx-${t}`}
              x1={xScale(t)} x2={xScale(t)}
              y1={RTT_MARGIN.top} y2={RTT_MARGIN.top + plotH}
              stroke="rgba(148, 163, 184, 0.15)" strokeDasharray="2,3"
            />
          ))}
          {yTicks.map(r => (
            <line
              key={`gy-${r}`}
              x1={RTT_MARGIN.left} x2={RTT_MARGIN.left + plotW}
              y1={yScale(r)} y2={yScale(r)}
              stroke="rgba(148, 163, 184, 0.15)" strokeDasharray="2,3"
            />
          ))}

          {/* Axes */}
          <line
            x1={RTT_MARGIN.left} x2={RTT_MARGIN.left + plotW}
            y1={RTT_MARGIN.top + plotH} y2={RTT_MARGIN.top + plotH}
            stroke="rgba(148, 163, 184, 0.6)"
          />
          <line
            x1={RTT_MARGIN.left} x2={RTT_MARGIN.left}
            y1={RTT_MARGIN.top} y2={RTT_MARGIN.top + plotH}
            stroke="rgba(148, 163, 184, 0.6)"
          />

          {/* Axis labels */}
          {xTicks.map(t => (
            <text
              key={`xt-${t}`}
              x={xScale(t)} y={RTT_MARGIN.top + plotH + 16}
              textAnchor="middle" fontSize={10} fill="#94a3b8"
            >
              {formatTime(t)}
            </text>
          ))}
          {yTicks.map(r => (
            <text
              key={`yt-${r}`}
              x={RTT_MARGIN.left - 6} y={yScale(r) + 3}
              textAnchor="end" fontSize={10} fill="#94a3b8"
              fontFamily="ui-monospace, SFMono-Regular, Menlo, monospace"
            >
              {formatMs(r)}
            </text>
          ))}

          {/* Axis titles */}
          <text
            x={RTT_MARGIN.left + plotW / 2} y={height - 8}
            textAnchor="middle" fontSize={11} fill="#cbd5e1"
          >
            Time (seconds since stream start)
          </text>
          <text
            x={14} y={RTT_MARGIN.top + plotH / 2}
            transform={`rotate(-90 14 ${RTT_MARGIN.top + plotH / 2})`}
            textAnchor="middle" fontSize={11} fill="#cbd5e1"
          >
            Round-trip time (ms)
          </text>

          {/* Average RTT line */}
          <line
            x1={RTT_MARGIN.left} x2={RTT_MARGIN.left + plotW}
            y1={yScale(avgRTT)} y2={yScale(avgRTT)}
            stroke="#fbbf24" strokeDasharray="4,3" strokeOpacity={0.5}
          />
          <text
            x={RTT_MARGIN.left + plotW - 4} y={yScale(avgRTT) - 4}
            textAnchor="end" fontSize={10} fill="#fbbf24"
          >
            avg {avgRTT.toFixed(1)} ms
          </text>

          {/* Retransmission markers at their relative times (vertical red ticks) */}
          {retxPoints.map((p, i) => (
            <line
              key={`retx-${i}`}
              x1={xScale(p.relative_time)} x2={xScale(p.relative_time)}
              y1={RTT_MARGIN.top} y2={RTT_MARGIN.top + plotH}
              stroke="#f87171" strokeWidth={1} strokeDasharray="1,3" strokeOpacity={0.35}
            />
          ))}

          {/* Lines connecting samples in order (forward + reverse) */}
          {fwdPath && (
            <path d={fwdPath} stroke="#34d399" strokeWidth={1.5} fill="none" opacity={0.55} />
          )}
          {revPath && (
            <path d={revPath} stroke="#60a5fa" strokeWidth={1.5} fill="none" opacity={0.55} />
          )}

          {/* Dots — drawn on top */}
          {samples.map((s, i) => {
            const isFwd = s.direction === 'forward';
            return (
              <g
                key={`rtt-${i}`}
                onMouseEnter={() => setHovered(s)}
                onMouseLeave={() => setHovered(null)}
                style={{ cursor: 'pointer' }}
              >
                <circle
                  cx={xScale(s.relative_time)}
                  cy={yScale(s.rtt_ms)}
                  r={3}
                  fill={isFwd ? '#34d399' : '#60a5fa'}
                  opacity={0.9}
                />
                {/* Invisible wide hit area */}
                <circle
                  cx={xScale(s.relative_time)} cy={yScale(s.rtt_ms)}
                  r={8} fill="transparent"
                />
              </g>
            );
          })}

          {/* Crosshair on hover */}
          {hovered && (
            <line
              x1={xScale(hovered.relative_time)} x2={xScale(hovered.relative_time)}
              y1={RTT_MARGIN.top} y2={RTT_MARGIN.top + plotH}
              stroke="#fbbf24" strokeDasharray="2,2" strokeOpacity={0.5}
              pointerEvents="none"
            />
          )}
        </svg>

        {hovered && (
          <RTTTooltip sample={hovered} x={xScale(hovered.relative_time)} width={width} />
        )}
      </div>

      <div className="mt-2 p-2.5 bg-slate-800/40 border border-slate-700/40 rounded-md text-[10px] text-slate-400 leading-relaxed">
        <span className="text-slate-300 font-medium">How to read:</span>{' '}
        Each dot is one data segment's RTT (data→ACK time).
        <span className="text-emerald-400"> Flat line near the average</span> = stable latency.
        <span className="text-amber-400"> Sudden spikes</span> = jitter or queueing delay.
        <span className="text-red-400"> Red dashed verticals</span> mark retransmissions —
        spikes that align with them usually indicate loss-induced backoff.
      </div>
    </div>
  );
}

function RTTTooltip({ sample, x, width }: { sample: TCPGraphRTTSample; x: number; width: number }) {
  const TT_WIDTH = 220;
  const left = x + 12 + TT_WIDTH > width ? x - 12 - TT_WIDTH : x + 12;
  return (
    <div
      className="absolute pointer-events-none text-[11px] rounded-lg border border-slate-700 bg-slate-900/95 shadow-xl p-2.5 z-10"
      style={{ left, top: RTT_MARGIN.top + 4, width: TT_WIDTH }}
    >
      <div className="flex items-center justify-between mb-1.5">
        <span className="font-semibold text-white">
          #{sample.packet_index} {sample.direction === 'forward' ? '→' : '←'} #{sample.ack_index}
        </span>
        <span className="text-slate-400">{formatTime(sample.relative_time)}</span>
      </div>
      <div className="space-y-0.5 font-mono text-slate-300">
        <TooltipRow label="RTT" value={`${sample.rtt_ms.toFixed(2)} ms`} />
        <TooltipRow label="Seq" value={sample.seq_num.toLocaleString()} />
        <TooltipRow label="Len" value={`${sample.payload_len} B`} />
        <TooltipRow label="Dir" value={sample.direction} />
      </div>
    </div>
  );
}

// ─── Throughput Graph ──────────────────────────────────────────────

interface ThroughputGraphProps {
  bins: TCPGraphThroughputBin[];
  height: number;
}

const TP_MARGIN = { top: 16, right: 24, bottom: 44, left: 72 } as const;

function ThroughputGraph({ bins, height }: ThroughputGraphProps) {
  const [hovered, setHovered] = useState<TCPGraphThroughputBin | null>(null);
  const [width, setWidth] = useState(900);
  const containerRef = useResizeObserver(setWidth);

  if (bins.length === 0) {
    return (
      <div className="bg-slate-900/60 border border-slate-700/50 rounded-lg p-8 text-center">
        <BarChart3 className="w-8 h-8 text-slate-600 mx-auto mb-3" />
        <p className="text-sm text-slate-400">No throughput data available.</p>
      </div>
    );
  }

  const plotW = Math.max(10, width - TP_MARGIN.left - TP_MARGIN.right);
  const plotH = Math.max(10, height - TP_MARGIN.top - TP_MARGIN.bottom);

  const timeMin = bins[0].start_time;
  const timeMax = bins[bins.length - 1].end_time;
  const binDur = bins[0].end_time - bins[0].start_time || 1;

  // Y axis is bytes-per-second of the (forward + reverse) sum.
  const bps = (b: TCPGraphThroughputBin) =>
    (b.forward_bytes + b.reverse_bytes) / Math.max(1e-6, b.end_time - b.start_time);
  const peakBps = Math.max(1, ...bins.map(bps));

  const xScale = (t: number) =>
    TP_MARGIN.left + ((t - timeMin) / Math.max(1e-6, timeMax - timeMin)) * plotW;
  const yScale = (v: number) => TP_MARGIN.top + plotH - (v / peakBps) * plotH;
  const barW = Math.max(1, (plotW / bins.length) - 1);

  // Stats
  const totalFwd = bins.reduce((s, b) => s + b.forward_bytes, 0);
  const totalRev = bins.reduce((s, b) => s + b.reverse_bytes, 0);
  const avgBps = (totalFwd + totalRev) / Math.max(1e-6, timeMax - timeMin);

  const xTicks = makeTicks(timeMin, timeMax, 6);
  const yTicks = makeTicks(0, peakBps, 5);

  return (
    <div ref={containerRef} className="w-full">
      <div className="flex items-start justify-between mb-3 gap-3 flex-wrap">
        <div className="flex items-center gap-2">
          <div className="p-1.5 bg-purple-500/15 rounded-lg">
            <BarChart3 className="w-4 h-4 text-purple-400" />
          </div>
          <div>
            <h3 className="text-sm font-semibold text-white">Throughput</h3>
            <p className="text-[10px] text-slate-500">
              {bins.length} bins × {formatTime(binDur)} •
              peak {formatBps(peakBps)} •
              avg {formatBps(avgBps)} •
              total {formatBytes(totalFwd + totalRev)}
            </p>
          </div>
        </div>
        <div className="flex items-center gap-2 text-[10px] text-slate-400">
          <LegendSwatch color="#34d399" label={`Forward (${formatBytes(totalFwd)})`} />
          <LegendSwatch color="#60a5fa" label={`Reverse (${formatBytes(totalRev)})`} />
        </div>
      </div>

      <div className="relative bg-slate-950/60 rounded-lg border border-slate-700/40 overflow-hidden">
        <svg width={width} height={height} role="img" aria-label="TCP throughput graph" className="block">
          {/* Grid */}
          {yTicks.map(v => (
            <line
              key={`gy-${v}`}
              x1={TP_MARGIN.left} x2={TP_MARGIN.left + plotW}
              y1={yScale(v)} y2={yScale(v)}
              stroke="rgba(148, 163, 184, 0.15)" strokeDasharray="2,3"
            />
          ))}

          {/* Axes */}
          <line
            x1={TP_MARGIN.left} x2={TP_MARGIN.left + plotW}
            y1={TP_MARGIN.top + plotH} y2={TP_MARGIN.top + plotH}
            stroke="rgba(148, 163, 184, 0.6)"
          />
          <line
            x1={TP_MARGIN.left} x2={TP_MARGIN.left}
            y1={TP_MARGIN.top} y2={TP_MARGIN.top + plotH}
            stroke="rgba(148, 163, 184, 0.6)"
          />

          {/* Average line */}
          <line
            x1={TP_MARGIN.left} x2={TP_MARGIN.left + plotW}
            y1={yScale(avgBps)} y2={yScale(avgBps)}
            stroke="#fbbf24" strokeDasharray="4,3" strokeOpacity={0.45}
          />
          <text
            x={TP_MARGIN.left + plotW - 4} y={yScale(avgBps) - 4}
            textAnchor="end" fontSize={10} fill="#fbbf24"
          >
            avg {formatBps(avgBps)}
          </text>

          {/* Stacked bars (reverse on top of forward) */}
          {bins.map((b, i) => {
            const binDurLocal = Math.max(1e-6, b.end_time - b.start_time);
            const fwdBps = b.forward_bytes / binDurLocal;
            const revBps = b.reverse_bytes / binDurLocal;
            const totalBps = fwdBps + revBps;
            const x = xScale(b.start_time);
            const yTotal = yScale(totalBps);
            const yFwd = yScale(fwdBps); // top of forward portion
            // Heights are positive pixel amounts.
            const hFwd = TP_MARGIN.top + plotH - yFwd;
            const hRev = yFwd - yTotal;
            return (
              <g
                key={`bar-${i}`}
                onMouseEnter={() => setHovered(b)}
                onMouseLeave={() => setHovered(null)}
                style={{ cursor: 'pointer' }}
              >
                {b.forward_bytes > 0 && (
                  <rect
                    x={x} y={yFwd}
                    width={barW} height={hFwd}
                    fill="#34d399" opacity={0.85}
                  />
                )}
                {b.reverse_bytes > 0 && (
                  <rect
                    x={x} y={yTotal}
                    width={barW} height={Math.max(0, hRev)}
                    fill="#60a5fa" opacity={0.85}
                  />
                )}
                {/* Invisible wide hit area to improve hover UX */}
                <rect
                  x={x - 2} y={TP_MARGIN.top}
                  width={barW + 4} height={plotH}
                  fill="transparent"
                />
              </g>
            );
          })}

          {/* Axis labels */}
          {xTicks.map(t => (
            <text
              key={`xt-${t}`}
              x={xScale(t)} y={TP_MARGIN.top + plotH + 16}
              textAnchor="middle" fontSize={10} fill="#94a3b8"
            >
              {formatTime(t)}
            </text>
          ))}
          {yTicks.map(v => (
            <text
              key={`yt-${v}`}
              x={TP_MARGIN.left - 6} y={yScale(v) + 3}
              textAnchor="end" fontSize={10} fill="#94a3b8"
              fontFamily="ui-monospace, SFMono-Regular, Menlo, monospace"
            >
              {formatBps(v)}
            </text>
          ))}

          {/* Axis titles */}
          <text
            x={TP_MARGIN.left + plotW / 2} y={height - 8}
            textAnchor="middle" fontSize={11} fill="#cbd5e1"
          >
            Time (seconds since stream start)
          </text>
          <text
            x={14} y={TP_MARGIN.top + plotH / 2}
            transform={`rotate(-90 14 ${TP_MARGIN.top + plotH / 2})`}
            textAnchor="middle" fontSize={11} fill="#cbd5e1"
          >
            Bytes per second
          </text>
        </svg>

        {hovered && (
          <ThroughputTooltip bin={hovered} width={width} x={xScale((hovered.start_time + hovered.end_time) / 2)} />
        )}
      </div>

      <div className="mt-2 p-2.5 bg-slate-800/40 border border-slate-700/40 rounded-md text-[10px] text-slate-400 leading-relaxed">
        <span className="text-slate-300 font-medium">How to read:</span>{' '}
        Each bar is one time-bucket of payload bytes transmitted.
        <span className="text-emerald-400"> Green</span> = forward (client → server),
        <span className="text-blue-400"> blue</span> = reverse (server → client).
        Tall peaks = bursts. Gaps = idle or stalled periods.
      </div>
    </div>
  );
}

function ThroughputTooltip({
  bin,
  width,
  x,
}: {
  bin: TCPGraphThroughputBin;
  width: number;
  x: number;
}) {
  const TT_WIDTH = 220;
  const left = x + 12 + TT_WIDTH > width ? x - 12 - TT_WIDTH : x + 12;
  const dur = Math.max(1e-6, bin.end_time - bin.start_time);
  const fwdBps = bin.forward_bytes / dur;
  const revBps = bin.reverse_bytes / dur;
  return (
    <div
      className="absolute pointer-events-none text-[11px] rounded-lg border border-slate-700 bg-slate-900/95 shadow-xl p-2.5 z-10"
      style={{ left, top: TP_MARGIN.top + 4, width: TT_WIDTH }}
    >
      <div className="flex items-center justify-between mb-1.5">
        <span className="font-semibold text-white">
          {formatTime(bin.start_time)} – {formatTime(bin.end_time)}
        </span>
      </div>
      <div className="space-y-0.5 font-mono text-slate-300">
        <TooltipRow label="→ Forward" value={`${formatBytes(bin.forward_bytes)} (${formatBps(fwdBps)})`} />
        <TooltipRow label="← Reverse" value={`${formatBytes(bin.reverse_bytes)} (${formatBps(revBps)})`} />
        <TooltipRow label="Packets" value={`${bin.forward_packets} / ${bin.reverse_packets}`} />
      </div>
    </div>
  );
}

// ─── Shared Helpers ───────────────────────────────────────────────

function useResizeObserver(
  onResize: (width: number) => void,
): (el: HTMLDivElement | null) => void {
  return (el: HTMLDivElement | null) => {
    if (!el) return;
    const obs = new ResizeObserver(entries => {
      const w = entries[0]?.contentRect.width ?? 900;
      onResize(Math.max(320, w));
    });
    obs.observe(el);
    // The ref callback pattern doesn't allow returning a cleanup, but the
    // observer is GC'd when the element is unmounted (ResizeObserver is
    // keyed off the element, not an eager global). This is fine for a modal.
  };
}

function TabButton({
  active,
  onClick,
  icon,
  label,
  sublabel,
  disabled,
  badgeText,
  badgeTone,
}: {
  active: boolean;
  onClick: () => void;
  icon: React.ReactNode;
  label: string;
  sublabel?: string;
  disabled?: boolean;
  badgeText?: string;
  badgeTone?: 'red' | 'amber';
}) {
  const badgeColor =
    badgeTone === 'red'
      ? 'bg-red-500/15 text-red-400 border-red-500/30'
      : 'bg-amber-500/15 text-amber-400 border-amber-500/30';
  return (
    <button
      onClick={onClick}
      disabled={disabled}
      className={`flex items-center gap-2 px-3 py-2 text-xs rounded-lg border transition-colors whitespace-nowrap ${
        active
          ? 'bg-slate-700/70 border-slate-600 text-white'
          : disabled
          ? 'bg-slate-800/30 border-slate-800 text-slate-600 cursor-not-allowed'
          : 'bg-slate-800/40 border-slate-700/40 text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
      }`}
    >
      {icon}
      <div className="text-left">
        <div className="font-medium leading-tight">{label}</div>
        {sublabel && <div className="text-[9px] opacity-70 leading-tight">{sublabel}</div>}
      </div>
      {badgeText && (
        <span className={`ml-1 px-1.5 py-0.5 rounded border text-[9px] ${badgeColor}`}>
          {badgeText}
        </span>
      )}
    </button>
  );
}

function TooltipRow({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex items-center justify-between gap-3">
      <span className="text-slate-500">{label}</span>
      <span className="text-slate-200">{value}</span>
    </div>
  );
}

function LegendDot({ color, label }: { color: string; label: string }) {
  return (
    <span className="inline-flex items-center gap-1.5">
      <span className="inline-block w-2 h-2 rounded-full" style={{ backgroundColor: color }} />
      {label}
    </span>
  );
}

function LegendSwatch({ color, label }: { color: string; label: string }) {
  return (
    <span className="inline-flex items-center gap-1.5">
      <span className="inline-block w-2.5 h-2.5 rounded-sm" style={{ backgroundColor: color }} />
      {label}
    </span>
  );
}

function makeTicks(min: number, max: number, desired: number): number[] {
  if (!isFinite(min) || !isFinite(max) || min === max) return [min];
  const range = max - min;
  const rawStep = range / desired;
  const magnitude = Math.pow(10, Math.floor(Math.log10(rawStep)));
  const normalized = rawStep / magnitude;
  let step: number;
  if (normalized < 1.5) step = magnitude;
  else if (normalized < 3) step = 2 * magnitude;
  else if (normalized < 7) step = 5 * magnitude;
  else step = 10 * magnitude;

  const start = Math.ceil(min / step) * step;
  const ticks: number[] = [];
  for (let t = start; t <= max + step / 2; t += step) {
    ticks.push(t);
  }
  return ticks;
}

function formatTime(t: number): string {
  if (t < 1) return `${(t * 1000).toFixed(0)} ms`;
  if (t < 60) return `${t.toFixed(2)} s`;
  const m = Math.floor(t / 60);
  const s = Math.round(t - m * 60);
  return `${m}m ${s}s`;
}

function formatMs(v: number): string {
  if (v >= 1000) return `${(v / 1000).toFixed(2)} s`;
  if (v >= 10) return `${v.toFixed(0)} ms`;
  return `${v.toFixed(1)} ms`;
}

function formatBytes(b: number): string {
  if (b >= 1_000_000_000) return `${(b / 1_000_000_000).toFixed(2)} GB`;
  if (b >= 1_000_000) return `${(b / 1_000_000).toFixed(2)} MB`;
  if (b >= 1_000) return `${(b / 1_000).toFixed(1)} KB`;
  return `${b} B`;
}

function formatBps(bps: number): string {
  const bits = bps * 8;
  if (bits >= 1_000_000_000) return `${(bits / 1_000_000_000).toFixed(2)} Gbps`;
  if (bits >= 1_000_000) return `${(bits / 1_000_000).toFixed(2)} Mbps`;
  if (bits >= 1_000) return `${(bits / 1_000).toFixed(1)} Kbps`;
  return `${bits.toFixed(0)} bps`;
}

// Re-export the sub-components so consumers can use them independently if
// desired (e.g. dashboards that only want RTT).
export { RTTGraph, ThroughputGraph };

// Also re-export the base TCPSequenceGraph so consumers only need one import.
export { TCPSequenceGraph } from './TCPSequenceGraph';
