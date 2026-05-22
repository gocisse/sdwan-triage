// IO Graph — Interactive time-series chart showing throughput or packets/sec
// Pure SVG, zero external dependencies. Respects global filter. Click to drill-down.

import { useState, useMemo, useCallback, useRef } from 'react';
import { Activity, BarChart3, Clock, ZoomIn } from 'lucide-react';
import type { AnalysisResults } from '../types';
import { useTimeRangeOptional } from '../contexts/TimeRangeContext';

interface IOGraphViewProps {
  results: AnalysisResults;
  onTimeDrillDown?: (startEpoch: number, endEpoch: number) => void;
}

type MetricMode = 'packets' | 'bytes';

interface TimeBucket {
  time: number;       // epoch seconds (bucket start)
  label: string;      // display label
  packets: number;
  bytes: number;
}

// ─── Data Aggregation ────────────────────────────────────────────

function buildTimeSeries(results: AnalysisResults, bucketSizeSec: number): TimeBucket[] {
  const events = results.timeline || [];
  if (events.length === 0) return [];

  // Collect all timestamps
  const timestamps: number[] = [];
  for (const ev of events) {
    if (!ev.timestamp) continue;
    const ts = new Date(ev.timestamp).getTime() / 1000;
    if (ts > 0 && isFinite(ts)) timestamps.push(ts);
  }

  if (timestamps.length === 0) return [];

  timestamps.sort((a, b) => a - b);
  const minTs = timestamps[0];
  const maxTs = timestamps[timestamps.length - 1];

  if (maxTs - minTs < 0.001) return [];

  // Create buckets
  const bucketCount = Math.min(Math.ceil((maxTs - minTs) / bucketSizeSec) + 1, 500);
  const buckets: TimeBucket[] = [];

  for (let i = 0; i < bucketCount; i++) {
    const t = minTs + i * bucketSizeSec;
    const d = new Date(t * 1000);
    const label = `${d.getHours().toString().padStart(2, '0')}:${d.getMinutes().toString().padStart(2, '0')}:${d.getSeconds().toString().padStart(2, '0')}`;
    buckets.push({ time: t, label, packets: 0, bytes: 0 });
  }

  // Fill buckets from timeline
  for (const ts of timestamps) {
    const idx = Math.min(Math.floor((ts - minTs) / bucketSizeSec), bucketCount - 1);
    if (idx >= 0 && idx < buckets.length) {
      buckets[idx].packets += 1;
    }
  }

  // Also aggregate traffic flow bytes into buckets (distribute evenly if no timestamp)
  const flows = results.traffic_analysis || [];
  const totalFlowBytes = flows.reduce((s, f) => s + f.total_bytes, 0);
  if (totalFlowBytes > 0 && buckets.length > 0) {
    // Distribute proportionally based on packet density
    const totalPkts = buckets.reduce((s, b) => s + b.packets, 0) || 1;
    for (const b of buckets) {
      b.bytes = Math.round((b.packets / totalPkts) * totalFlowBytes);
    }
  }

  return buckets;
}

// ─── Auto bucket size ────────────────────────────────────────────

function autoBucketSize(results: AnalysisResults): number {
  const dur = results.duration || '';
  // Parse duration string like "12.5s" or "2m30s" or "1h5m"
  let totalSec = 0;
  const hMatch = dur.match(/(\d+)h/);
  const mMatch = dur.match(/(\d+)m/);
  const sMatch = dur.match(/([\d.]+)s/);
  if (hMatch) totalSec += parseInt(hMatch[1]) * 3600;
  if (mMatch) totalSec += parseInt(mMatch[1]) * 60;
  if (sMatch) totalSec += parseFloat(sMatch[1]);

  if (totalSec <= 0) {
    // Fallback: estimate from timeline
    const events = results.timeline || [];
    if (events.length >= 2) {
      const first = new Date(events[0].timestamp).getTime() / 1000;
      const last = new Date(events[events.length - 1].timestamp).getTime() / 1000;
      totalSec = last - first;
    }
  }

  if (totalSec <= 10) return 0.5;
  if (totalSec <= 60) return 1;
  if (totalSec <= 300) return 5;
  if (totalSec <= 600) return 10;
  if (totalSec <= 3600) return 30;
  return 60;
}

// ─── SVG Chart ───────────────────────────────────────────────────

const CHART_W = 900;
const CHART_H = 260;
const PAD = { top: 20, right: 20, bottom: 40, left: 60 };
const PLOT_W = CHART_W - PAD.left - PAD.right;
const PLOT_H = CHART_H - PAD.top - PAD.bottom;

interface ChartProps {
  buckets: TimeBucket[];
  mode: MetricMode;
  onBucketClick?: (bucket: TimeBucket) => void;
  bucketSizeSec: number;
  highlightStart?: number;
  highlightEnd?: number;
}

function Chart({ buckets, mode, onBucketClick, bucketSizeSec, highlightStart, highlightEnd }: ChartProps) {
  const [hoverIdx, setHoverIdx] = useState<number | null>(null);
  const svgRef = useRef<SVGSVGElement>(null);

  const maxVal = useMemo(() => {
    let m = 0;
    for (const b of buckets) {
      const v = mode === 'packets' ? b.packets : b.bytes;
      if (v > m) m = v;
    }
    return m || 1;
  }, [buckets, mode]);

  const barW = buckets.length > 0 ? Math.max(PLOT_W / buckets.length - 1, 1) : 4;

  // Y-axis ticks
  const yTicks = useMemo(() => {
    const ticks: number[] = [];
    const step = maxVal <= 5 ? 1 : Math.ceil(maxVal / 5);
    for (let v = 0; v <= maxVal; v += step) ticks.push(v);
    if (ticks[ticks.length - 1] < maxVal) ticks.push(maxVal);
    return ticks;
  }, [maxVal]);

  // X-axis labels (show ~8 evenly spaced)
  const xLabels = useMemo(() => {
    if (buckets.length <= 8) return buckets.map((b, i) => ({ idx: i, label: b.label }));
    const step = Math.ceil(buckets.length / 8);
    const labels: { idx: number; label: string }[] = [];
    for (let i = 0; i < buckets.length; i += step) {
      labels.push({ idx: i, label: buckets[i].label });
    }
    return labels;
  }, [buckets]);

  const formatYLabel = useCallback((v: number) => {
    if (mode === 'bytes') {
      if (v >= 1e9) return `${(v / 1e9).toFixed(1)}G`;
      if (v >= 1e6) return `${(v / 1e6).toFixed(1)}M`;
      if (v >= 1e3) return `${(v / 1e3).toFixed(1)}K`;
      return `${v}`;
    }
    if (v >= 1e6) return `${(v / 1e6).toFixed(1)}M`;
    if (v >= 1e3) return `${(v / 1e3).toFixed(1)}K`;
    return `${v}`;
  }, [mode]);

  if (buckets.length === 0) {
    return (
      <div className="flex items-center justify-center h-64 text-slate-500 text-sm">
        <Activity className="w-5 h-5 mr-2" />
        No time-series data available
      </div>
    );
  }

  return (
    <svg
      ref={svgRef}
      viewBox={`0 0 ${CHART_W} ${CHART_H}`}
      className="w-full h-auto"
      style={{ maxHeight: '320px' }}
    >
      {/* Background */}
      <rect x={PAD.left} y={PAD.top} width={PLOT_W} height={PLOT_H} fill="#0f172a" rx={4} />

      {/* Grid lines + Y-axis labels */}
      {yTicks.map((v, i) => {
        const y = PAD.top + PLOT_H - (v / maxVal) * PLOT_H;
        return (
          <g key={`y-${i}`}>
            <line x1={PAD.left} y1={y} x2={PAD.left + PLOT_W} y2={y}
              stroke="#1e293b" strokeWidth={1} strokeDasharray={v === 0 ? 'none' : '3,3'} />
            <text x={PAD.left - 8} y={y + 4} textAnchor="end"
              fill="#64748b" fontSize={10} fontFamily="monospace">
              {formatYLabel(v)}
            </text>
          </g>
        );
      })}

      {/* Bars */}
      {buckets.map((b, i) => {
        const v = mode === 'packets' ? b.packets : b.bytes;
        const barH = Math.max((v / maxVal) * PLOT_H, v > 0 ? 1 : 0);
        const x = PAD.left + (i / buckets.length) * PLOT_W;
        const y = PAD.top + PLOT_H - barH;
        const isHovered = hoverIdx === i;

        // Color: intensity based on value
        const intensity = v / maxVal;
        const fill = intensity > 0.8 ? '#ef4444' : intensity > 0.5 ? '#f59e0b' : intensity > 0.2 ? '#3b82f6' : '#22d3ee';

        // Dim bars outside the time range selection
        const inRange = highlightStart === undefined || highlightEnd === undefined ||
          (b.time + bucketSizeSec >= highlightStart && b.time <= highlightEnd);

        return (
          <g key={i}>
            {/* Invisible hover target (full height) */}
            <rect
              x={x} y={PAD.top} width={Math.max(barW, 2)} height={PLOT_H}
              fill="transparent"
              className="cursor-pointer"
              onMouseEnter={() => setHoverIdx(i)}
              onMouseLeave={() => setHoverIdx(null)}
              onClick={() => onBucketClick?.(b)}
            />
            {/* Visible bar */}
            <rect
              x={x} y={y} width={Math.max(barW - 0.5, 1)} height={barH}
              fill={isHovered ? '#a78bfa' : fill}
              rx={barW > 3 ? 1 : 0}
              opacity={isHovered ? 1 : inRange ? 0.85 : 0.2}
              className="transition-all duration-75"
            />
          </g>
        );
      })}

      {/* X-axis labels */}
      {xLabels.map(({ idx, label }) => {
        const x = PAD.left + (idx / buckets.length) * PLOT_W;
        return (
          <text key={`x-${idx}`} x={x} y={CHART_H - 8} textAnchor="middle"
            fill="#64748b" fontSize={9} fontFamily="monospace">
            {label}
          </text>
        );
      })}

      {/* Axis labels */}
      <text x={PAD.left - 8} y={12} textAnchor="start" fill="#94a3b8" fontSize={10} fontWeight="bold">
        {mode === 'packets' ? 'Packets/interval' : 'Bytes/interval'}
      </text>
      <text x={CHART_W / 2} y={CHART_H - 0} textAnchor="middle" fill="#64748b" fontSize={9}>
        Time ({bucketSizeSec >= 60 ? `${bucketSizeSec / 60}m` : `${bucketSizeSec}s`} intervals)
      </text>

      {/* Hover tooltip */}
      {hoverIdx !== null && hoverIdx < buckets.length && (() => {
        const b = buckets[hoverIdx];
        const v = mode === 'packets' ? b.packets : b.bytes;
        const tx = PAD.left + (hoverIdx / buckets.length) * PLOT_W;
        const tooltipX = tx + PLOT_W * 0.15 > CHART_W ? tx - 120 : tx + 10;
        const tooltipY = PAD.top + 10;

        return (
          <g>
            {/* Vertical line */}
            <line x1={tx} y1={PAD.top} x2={tx} y2={PAD.top + PLOT_H}
              stroke="#a78bfa" strokeWidth={1} strokeDasharray="3,3" opacity={0.6} />
            {/* Tooltip box */}
            <rect x={tooltipX} y={tooltipY} width={115} height={42}
              fill="#1e1b4b" stroke="#6366f1" strokeWidth={1} rx={4} opacity={0.95} />
            <text x={tooltipX + 8} y={tooltipY + 16} fill="#e2e8f0" fontSize={10} fontWeight="bold">
              {b.label}
            </text>
            <text x={tooltipX + 8} y={tooltipY + 32} fill="#c4b5fd" fontSize={10}>
              {mode === 'packets' ? `${v.toLocaleString()} pkts` : formatBytesShort(v)}
            </text>
          </g>
        );
      })()}
    </svg>
  );
}

function formatBytesShort(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB`;
}

// ─── Main Component ──────────────────────────────────────────────

export default function IOGraphView({ results, onTimeDrillDown }: IOGraphViewProps) {
  const [mode, setMode] = useState<MetricMode>('packets');
  const [bucketSizeSec, setBucketSizeSec] = useState<number>(() => autoBucketSize(results));
  const timeCtx = useTimeRangeOptional();

  const buckets = useMemo(
    () => buildTimeSeries(results, bucketSizeSec),
    [results, bucketSizeSec]
  );

  const handleBucketClick = useCallback((bucket: TimeBucket) => {
    if (onTimeDrillDown) {
      // Drill down: +/- 5 seconds around the clicked bucket
      const margin = 5;
      onTimeDrillDown(bucket.time - margin, bucket.time + bucketSizeSec + margin);
    }
  }, [onTimeDrillDown, bucketSizeSec]);

  // Summary stats
  const totalPkts = buckets.reduce((s, b) => s + b.packets, 0);
  const totalBytes = buckets.reduce((s, b) => s + b.bytes, 0);
  const peakPkts = Math.max(...buckets.map(b => b.packets), 0);
  const peakBytes = Math.max(...buckets.map(b => b.bytes), 0);

  return (
    <div className="bg-slate-800/60 border border-slate-700/50 rounded-xl overflow-hidden">
      {/* Header */}
      <div className="flex items-center justify-between px-5 py-3 border-b border-slate-700/50">
        <div className="flex items-center gap-2.5">
          <BarChart3 className="w-4 h-4 text-green-400" />
          <h3 className="text-sm font-semibold text-white">IO Graph</h3>
          {onTimeDrillDown && (
            <span className="text-[10px] text-slate-500 bg-slate-700/50 px-1.5 py-0.5 rounded flex items-center gap-1">
              <ZoomIn className="w-2.5 h-2.5" />
              Click bar to drill-down
            </span>
          )}
        </div>

        <div className="flex items-center gap-3">
          {/* Metric toggle */}
          <div className="flex items-center gap-1 bg-slate-900/50 rounded-lg p-0.5">
            <button
              onClick={() => setMode('packets')}
              className={`px-2.5 py-1 rounded text-[10px] font-medium transition-all ${
                mode === 'packets' ? 'bg-green-500/20 text-green-400' : 'text-slate-500 hover:text-slate-300'
              }`}
            >
              Packets
            </button>
            <button
              onClick={() => setMode('bytes')}
              className={`px-2.5 py-1 rounded text-[10px] font-medium transition-all ${
                mode === 'bytes' ? 'bg-blue-500/20 text-blue-400' : 'text-slate-500 hover:text-slate-300'
              }`}
            >
              Bytes
            </button>
          </div>

          {/* Bucket size */}
          <div className="flex items-center gap-1">
            <Clock className="w-3 h-3 text-slate-500" />
            <select
              value={bucketSizeSec}
              onChange={e => setBucketSizeSec(Number(e.target.value))}
              className="bg-slate-900/50 border border-slate-700/50 rounded text-[10px] text-slate-300 px-1.5 py-1 outline-none"
            >
              <option value={0.5}>0.5s</option>
              <option value={1}>1s</option>
              <option value={5}>5s</option>
              <option value={10}>10s</option>
              <option value={30}>30s</option>
              <option value={60}>1m</option>
              <option value={300}>5m</option>
            </select>
          </div>
        </div>
      </div>

      {/* Stats row */}
      <div className="grid grid-cols-4 gap-3 px-5 py-2.5 border-b border-slate-700/30">
        <div className="text-center">
          <p className="text-xs font-bold text-white">{totalPkts.toLocaleString()}</p>
          <p className="text-[10px] text-slate-500">Total Packets</p>
        </div>
        <div className="text-center">
          <p className="text-xs font-bold text-white">{formatBytesShort(totalBytes)}</p>
          <p className="text-[10px] text-slate-500">Total Bytes</p>
        </div>
        <div className="text-center">
          <p className="text-xs font-bold text-amber-400">{peakPkts.toLocaleString()}</p>
          <p className="text-[10px] text-slate-500">Peak Packets</p>
        </div>
        <div className="text-center">
          <p className="text-xs font-bold text-amber-400">{formatBytesShort(peakBytes)}</p>
          <p className="text-[10px] text-slate-500">Peak Bytes</p>
        </div>
      </div>

      {/* Chart */}
      <div className="px-3 py-2">
        <Chart
          buckets={buckets}
          mode={mode}
          onBucketClick={handleBucketClick}
          bucketSizeSec={bucketSizeSec}
          highlightStart={timeCtx?.isTimeFiltered ? timeCtx.timeRange.start : undefined}
          highlightEnd={timeCtx?.isTimeFiltered ? timeCtx.timeRange.end : undefined}
        />
      </div>

      {/* Footer hint */}
      {buckets.length > 0 && (
        <div className="px-5 py-2 border-t border-slate-700/30 text-[10px] text-slate-600 flex items-center justify-between">
          <span>{buckets.length} intervals · {bucketSizeSec >= 60 ? `${bucketSizeSec / 60}m` : `${bucketSizeSec}s`} resolution</span>
          {onTimeDrillDown && <span>Click a bar to filter packets ±5s around that time</span>}
        </div>
      )}
    </div>
  );
}
