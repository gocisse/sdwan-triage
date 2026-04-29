// TCPSequenceGraph — Stevens-style TCP Time-Sequence Graph.
//
// Visualizes per-packet TCP data points on an X = time / Y = sequence-number
// plane. Each segment is drawn from (t, seq) to (t, seq + payloadLen) so the
// human eye instantly perceives:
//   • Sawtooth climbing to the right      → healthy throughput
//   • Flat horizontal line                 → zero-window / congestion stall
//   • Vertical red "jumps" at same seq     → retransmissions
//   • A sudden drop/gap                    → lost segments (MISSING_B)
//
// Pure SVG, no external charting dependency. Hover a segment for a tooltip.
// Fits naturally inside a modal: consumes all available width, auto-resizing.

import { useMemo, useState, useRef, useEffect } from 'react';
import { Activity, AlertTriangle, RefreshCw, TrendingUp } from 'lucide-react';

// ─── Types ────────────────────────────────────────────────────────

export interface TCPGraphPoint {
  packet_index: number;
  relative_time: number;   // seconds since first packet
  absolute_time?: string;  // RFC3339 for tooltip
  direction: 'forward' | 'reverse';
  seq_num: number;
  ack_num: number;
  window_size: number;     // raw (unscaled) window
  scaled_window?: number;  // effective window after TCP Window Scale option
  payload_len: number;
  flags: string;
  is_retransmission: boolean;
  is_syn?: boolean;
  is_fin?: boolean;
  is_rst?: boolean;
  is_zero_window?: boolean; // backend-flagged; frontend can also derive from window_size===0
  is_dropped?: boolean;    // frontend augmentation when data comes from a comparison Discrepancy
}

export interface TCPGraphRTTSample {
  packet_index: number;
  ack_index: number;
  relative_time: number;
  rtt_ms: number;
  direction: 'forward' | 'reverse';
  seq_num: number;
  payload_len: number;
}

export interface TCPGraphThroughputBin {
  start_time: number;
  end_time: number;
  forward_bytes: number;
  reverse_bytes: number;
  forward_packets: number;
  reverse_packets: number;
}

interface TCPSequenceGraphProps {
  points: TCPGraphPoint[];
  forwardLabel?: string;   // e.g. "Client → Server"
  reverseLabel?: string;   // e.g. "Server → Client"
  height?: number;
  title?: string;
}

// ─── Layout Constants ─────────────────────────────────────────────

const MARGIN = { top: 16, right: 24, bottom: 44, left: 72 } as const;
const MIN_SEGMENT_HEIGHT_PX = 1.5;   // segments with payload=0 are ticks
const DEFAULT_HEIGHT = 380;

// Colours (consistent with the rest of the UI: Tailwind slate + accent palette)
const COLOR_FORWARD = '#34d399';        // emerald-400 (client → server data)
const COLOR_REVERSE = '#60a5fa';        // blue-400 (server → client data)
const COLOR_ACK = '#94a3b8';            // slate-400 ACK tick
const COLOR_RETRANSMIT = '#f87171';     // red-400 retransmission
const COLOR_DROP = '#dc2626';           // red-600 dropped segment
const COLOR_SYN = '#a78bfa';            // violet-400 handshake
const COLOR_RST = '#fb923c';            // orange-400 reset
const COLOR_ZERO_WINDOW = '#fbbf24';    // amber-400 receiver stalled (zero window)
const COLOR_GRID = 'rgba(148, 163, 184, 0.15)';  // slate-400 15%
const COLOR_AXIS = 'rgba(148, 163, 184, 0.6)';

// ─── Main Component ───────────────────────────────────────────────

export function TCPSequenceGraph({
  points,
  forwardLabel = 'Forward (Client → Server)',
  reverseLabel = 'Reverse (Server → Client)',
  height = DEFAULT_HEIGHT,
  title = 'TCP Time-Sequence Graph',
}: TCPSequenceGraphProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const [width, setWidth] = useState<number>(900);
  const [hovered, setHovered] = useState<TCPGraphPoint | null>(null);
  const [showForward, setShowForward] = useState(true);
  const [showReverse, setShowReverse] = useState(true);
  const [showRetransmitOnly, setShowRetransmitOnly] = useState(false);

  // Observe container width so the SVG responds to modal resize.
  useEffect(() => {
    if (!containerRef.current) return;
    const obs = new ResizeObserver(entries => {
      const w = entries[0]?.contentRect.width ?? 900;
      setWidth(Math.max(320, w));
    });
    obs.observe(containerRef.current);
    return () => obs.disconnect();
  }, []);

  // ─── Filter & derive series ─────────────────────────────────────
  const visiblePoints = useMemo(() => {
    return points.filter(p => {
      if (!showForward && p.direction === 'forward') return false;
      if (!showReverse && p.direction === 'reverse') return false;
      if (showRetransmitOnly && !p.is_retransmission && !p.is_dropped) return false;
      return true;
    });
  }, [points, showForward, showReverse, showRetransmitOnly]);

  // ─── Empty-state ────────────────────────────────────────────────
  if (points.length === 0) {
    return (
      <div
        ref={containerRef}
        className="bg-slate-900/60 border border-slate-700/50 rounded-lg p-8 text-center"
      >
        <Activity className="w-8 h-8 text-slate-600 mx-auto mb-3" />
        <p className="text-sm text-slate-400">No TCP packets available for graphing.</p>
        <p className="text-xs text-slate-500 mt-1">
          The sequence graph is only meaningful for TCP streams.
        </p>
      </div>
    );
  }

  // ─── Compute scales ─────────────────────────────────────────────
  const plotW = Math.max(10, width - MARGIN.left - MARGIN.right);
  const plotH = Math.max(10, height - MARGIN.top - MARGIN.bottom);

  // Time domain
  const timeMin = 0;
  let timeMax = 0;
  for (const p of points) {
    if (p.relative_time > timeMax) timeMax = p.relative_time;
  }
  if (timeMax <= 0) timeMax = 1; // avoid divide-by-zero

  // Sequence domain — per direction so forward and reverse each use full height.
  // For the Stevens view we plot both directions on the same Y axis using a
  // normalized offset (seq modulo a "window" picked from the data range).
  // Using the raw 32-bit seq space makes the graph unreadable, so we subtract
  // the minimum seen per direction.
  let fwdMin = Number.POSITIVE_INFINITY;
  let fwdMax = Number.NEGATIVE_INFINITY;
  let revMin = Number.POSITIVE_INFINITY;
  let revMax = Number.NEGATIVE_INFINITY;
  for (const p of points) {
    const top = p.seq_num + Math.max(0, p.payload_len);
    if (p.direction === 'forward') {
      if (p.seq_num < fwdMin) fwdMin = p.seq_num;
      if (top > fwdMax) fwdMax = top;
    } else {
      if (p.seq_num < revMin) revMin = p.seq_num;
      if (top > revMax) revMax = top;
    }
  }
  const fwdHas = isFinite(fwdMin) && isFinite(fwdMax);
  const revHas = isFinite(revMin) && isFinite(revMax);
  const fwdRange = fwdHas ? Math.max(1, fwdMax - fwdMin) : 1;
  const revRange = revHas ? Math.max(1, revMax - revMin) : 1;

  // When only one direction is shown the Y axis covers only its range; when
  // both are shown they share the plot area — forward on the top half, reverse
  // on the bottom half, separated by a thin divider. This keeps the classic
  // Stevens semantics (ever-increasing seq = data flow).
  const bothDirs = showForward && fwdHas && showReverse && revHas;

  function xScale(t: number): number {
    return MARGIN.left + (t - timeMin) / (timeMax - timeMin) * plotW;
  }

  function yScaleForward(seq: number): number {
    if (!fwdHas) return MARGIN.top + plotH; // shouldn't happen
    const norm = (seq - fwdMin) / fwdRange;        // 0 at bottom, 1 at top
    const yTop = MARGIN.top;
    const yBot = bothDirs ? MARGIN.top + plotH / 2 - 2 : MARGIN.top + plotH;
    return yBot - norm * (yBot - yTop);
  }

  function yScaleReverse(seq: number): number {
    if (!revHas) return MARGIN.top + plotH;
    const norm = (seq - revMin) / revRange;
    const yTop = bothDirs ? MARGIN.top + plotH / 2 + 2 : MARGIN.top;
    const yBot = MARGIN.top + plotH;
    return yBot - norm * (yBot - yTop);
  }

  // ─── Stats (shown in header) ────────────────────────────────────
  const stats = useMemo(() => {
    let retx = 0;
    let drops = 0;
    let syn = 0;
    let rst = 0;
    let fwd = 0;
    let rev = 0;
    let zeroWin = 0;
    for (const p of points) {
      if (p.is_retransmission) retx++;
      if (p.is_dropped) drops++;
      if (p.is_syn) syn++;
      if (p.is_rst) rst++;
      if (p.direction === 'forward') fwd++; else rev++;
      if (p.is_zero_window || (p.window_size === 0 && !p.is_rst && !p.is_syn)) zeroWin++;
    }
    return { retx, drops, syn, rst, fwd, rev, zeroWin, total: points.length };
  }, [points]);

  // ─── Axis ticks ─────────────────────────────────────────────────
  const xTicks = makeTicks(timeMin, timeMax, 6);
  const yTicksForward = fwdHas ? makeTicks(fwdMin, fwdMax, bothDirs ? 3 : 6) : [];
  const yTicksReverse = revHas ? makeTicks(revMin, revMax, bothDirs ? 3 : 6) : [];

  // ─── Render ─────────────────────────────────────────────────────
  return (
    <div ref={containerRef} className="w-full">
      {/* Header row */}
      <div className="flex items-start justify-between gap-3 flex-wrap mb-3">
        <div className="flex items-center gap-2">
          <div className="p-1.5 bg-emerald-500/15 rounded-lg">
            <TrendingUp className="w-4 h-4 text-emerald-400" />
          </div>
          <div>
            <h3 className="text-sm font-semibold text-white">{title}</h3>
            <p className="text-[10px] text-slate-500">
              {stats.total} points • {stats.fwd} forward • {stats.rev} reverse
              {stats.syn > 0 && ` • ${stats.syn} SYN`}
              {stats.rst > 0 && ` • ${stats.rst} RST`}
              {stats.retx > 0 && (
                <>
                  {' • '}
                  <span className="text-red-400">{stats.retx} retx</span>
                </>
              )}
              {stats.drops > 0 && (
                <>
                  {' • '}
                  <span className="text-red-500">{stats.drops} drops</span>
                </>
              )}
              {stats.zeroWin > 0 && (
                <>
                  {' • '}
                  <span className="text-amber-400">{stats.zeroWin} zero-window</span>
                </>
              )}
            </p>
          </div>
        </div>

        {/* Filter toggles */}
        <div className="flex items-center gap-1 flex-wrap">
          <ToggleButton active={showForward} onClick={() => setShowForward(v => !v)} color={COLOR_FORWARD}>
            Forward ({stats.fwd})
          </ToggleButton>
          <ToggleButton active={showReverse} onClick={() => setShowReverse(v => !v)} color={COLOR_REVERSE}>
            Reverse ({stats.rev})
          </ToggleButton>
          <ToggleButton
            active={showRetransmitOnly}
            onClick={() => setShowRetransmitOnly(v => !v)}
            color={COLOR_RETRANSMIT}
          >
            <RefreshCw className="w-3 h-3 inline mr-1" />
            Retx/Drops only
          </ToggleButton>
        </div>
      </div>

      {/* SVG canvas */}
      <div className="relative bg-slate-950/60 rounded-lg border border-slate-700/40 overflow-hidden">
        <svg
          width={width}
          height={height}
          role="img"
          aria-label="TCP time-sequence graph"
          className="block"
        >
          {/* Grid lines (vertical) */}
          {xTicks.map(t => (
            <line
              key={`gx-${t}`}
              x1={xScale(t)}
              x2={xScale(t)}
              y1={MARGIN.top}
              y2={MARGIN.top + plotH}
              stroke={COLOR_GRID}
              strokeDasharray="2,3"
            />
          ))}

          {/* Grid lines (horizontal forward) */}
          {showForward && fwdHas && yTicksForward.map(s => (
            <line
              key={`gyf-${s}`}
              x1={MARGIN.left}
              x2={MARGIN.left + plotW}
              y1={yScaleForward(s)}
              y2={yScaleForward(s)}
              stroke={COLOR_GRID}
              strokeDasharray="2,3"
            />
          ))}

          {/* Grid lines (horizontal reverse) */}
          {showReverse && revHas && yTicksReverse.map(s => (
            <line
              key={`gyr-${s}`}
              x1={MARGIN.left}
              x2={MARGIN.left + plotW}
              y1={yScaleReverse(s)}
              y2={yScaleReverse(s)}
              stroke={COLOR_GRID}
              strokeDasharray="2,3"
            />
          ))}

          {/* Divider between forward/reverse when both shown */}
          {bothDirs && (
            <line
              x1={MARGIN.left}
              x2={MARGIN.left + plotW}
              y1={MARGIN.top + plotH / 2}
              y2={MARGIN.top + plotH / 2}
              stroke="rgba(148, 163, 184, 0.25)"
              strokeWidth={1}
            />
          )}

          {/* Axis */}
          <line
            x1={MARGIN.left}
            x2={MARGIN.left + plotW}
            y1={MARGIN.top + plotH}
            y2={MARGIN.top + plotH}
            stroke={COLOR_AXIS}
          />
          <line
            x1={MARGIN.left}
            x2={MARGIN.left}
            y1={MARGIN.top}
            y2={MARGIN.top + plotH}
            stroke={COLOR_AXIS}
          />

          {/* X tick labels */}
          {xTicks.map(t => (
            <text
              key={`xt-${t}`}
              x={xScale(t)}
              y={MARGIN.top + plotH + 16}
              textAnchor="middle"
              fontSize={10}
              fill="#94a3b8"
            >
              {formatTime(t)}
            </text>
          ))}

          {/* Y tick labels — forward (top half) */}
          {showForward && fwdHas && yTicksForward.map(s => (
            <text
              key={`ytf-${s}`}
              x={MARGIN.left - 6}
              y={yScaleForward(s) + 3}
              textAnchor="end"
              fontSize={10}
              fill="#94a3b8"
              fontFamily="ui-monospace, SFMono-Regular, Menlo, monospace"
            >
              {formatSeq(s - fwdMin)}
            </text>
          ))}

          {/* Y tick labels — reverse (bottom half) */}
          {showReverse && revHas && yTicksReverse.map(s => (
            <text
              key={`ytr-${s}`}
              x={MARGIN.left - 6}
              y={yScaleReverse(s) + 3}
              textAnchor="end"
              fontSize={10}
              fill="#94a3b8"
              fontFamily="ui-monospace, SFMono-Regular, Menlo, monospace"
            >
              {formatSeq(s - revMin)}
            </text>
          ))}

          {/* Axis titles */}
          <text
            x={MARGIN.left + plotW / 2}
            y={height - 8}
            textAnchor="middle"
            fontSize={11}
            fill="#cbd5e1"
          >
            Time (seconds since stream start)
          </text>
          <text
            x={14}
            y={MARGIN.top + plotH / 2}
            transform={`rotate(-90 14 ${MARGIN.top + plotH / 2})`}
            textAnchor="middle"
            fontSize={11}
            fill="#cbd5e1"
          >
            Sequence number (relative)
          </text>

          {/* Segments */}
          <g>
            {visiblePoints.map((p, idx) => renderSegment(p, idx, xScale, p.direction === 'forward' ? yScaleForward : yScaleReverse, setHovered))}
          </g>

          {/* Hover crosshair */}
          {hovered && (
            <g pointerEvents="none">
              <line
                x1={xScale(hovered.relative_time)}
                x2={xScale(hovered.relative_time)}
                y1={MARGIN.top}
                y2={MARGIN.top + plotH}
                stroke="#fbbf24"
                strokeDasharray="2,2"
                strokeOpacity={0.5}
              />
            </g>
          )}
        </svg>

        {/* Tooltip */}
        {hovered && (
          <HoverTooltip point={hovered} width={width} x={xScale(hovered.relative_time)} />
        )}
      </div>

      {/* Legend */}
      <div className="mt-3 flex items-center gap-4 flex-wrap text-[10px] text-slate-400">
        <LegendSwatch color={COLOR_FORWARD} label={forwardLabel} />
        <LegendSwatch color={COLOR_REVERSE} label={reverseLabel} />
        <LegendSwatch color={COLOR_ACK} label="ACK-only tick" />
        <LegendSwatch color={COLOR_RETRANSMIT} label="Retransmission" />
        <LegendSwatch color={COLOR_DROP} label="Dropped (MISSING_B)" />
        <LegendSwatch color={COLOR_ZERO_WINDOW} label="Zero window" />
        <LegendSwatch color={COLOR_SYN} label="SYN / SYN-ACK" />
        <LegendSwatch color={COLOR_RST} label="RST" />
      </div>

      {/* Reading hints */}
      <div className="mt-2 p-2.5 bg-slate-800/40 border border-slate-700/40 rounded-md text-[10px] text-slate-400 leading-relaxed">
        <span className="text-slate-300 font-medium">How to read:</span>{' '}
        <span className="text-emerald-400">Sawtooth rising</span> = healthy throughput •{' '}
        <span className="text-amber-400">Flat plateau</span> = zero-window / stall •{' '}
        <span className="text-red-400">Repeated vertical marks</span> = retransmissions •{' '}
        <span className="text-red-500">Red ticks</span> = dropped segments that never reached WAN.
        {stats.retx > 0 && (
          <>
            {' '}
            <AlertTriangle className="w-3 h-3 inline text-red-400 mx-0.5" />
            <span className="text-red-300">
              {stats.retx} retransmission{stats.retx === 1 ? '' : 's'} detected — look for vertical
              red marks above.
            </span>
          </>
        )}
      </div>
    </div>
  );
}

// ─── Helpers ──────────────────────────────────────────────────────

function renderSegment(
  p: TCPGraphPoint,
  idx: number,
  xScale: (t: number) => number,
  yScale: (seq: number) => number,
  setHovered: (p: TCPGraphPoint | null) => void,
): JSX.Element {
  const x = xScale(p.relative_time);
  const yBottom = yScale(p.seq_num);
  const yTop = yScale(p.seq_num + Math.max(0, p.payload_len));
  let segH = Math.max(MIN_SEGMENT_HEIGHT_PX, Math.abs(yBottom - yTop));
  const yDraw = Math.min(yBottom, yTop);

  // Pick colour based on the most important attribute.
  let stroke = p.direction === 'forward' ? COLOR_FORWARD : COLOR_REVERSE;
  let strokeWidth = 2;
  if (p.payload_len === 0) {
    stroke = COLOR_ACK;
    strokeWidth = 1.25;
    segH = 3; // draw a short tick for pure ACKs so they remain visible
  }
  if (p.is_syn) {
    stroke = COLOR_SYN;
    strokeWidth = 2.25;
  }
  if (p.is_rst) {
    stroke = COLOR_RST;
    strokeWidth = 2.25;
  }
  // Zero-window receiver stall — amber tick (overrides normal ACK but still
  // keeps retransmission/drop colours as more-critical signals later).
  if (p.is_zero_window || (p.window_size === 0 && !p.is_rst && !p.is_syn)) {
    stroke = COLOR_ZERO_WINDOW;
    strokeWidth = 2.25;
  }
  if (p.is_retransmission) {
    stroke = COLOR_RETRANSMIT;
    strokeWidth = 2.5;
  }
  if (p.is_dropped) {
    stroke = COLOR_DROP;
    strokeWidth = 2.5;
  }

  return (
    <g
      key={`seg-${idx}`}
      onMouseEnter={() => setHovered(p)}
      onMouseLeave={() => setHovered(null)}
      style={{ cursor: 'pointer' }}
    >
      {/* The actual vertical segment */}
      <line
        x1={x}
        x2={x}
        y1={yDraw}
        y2={yDraw + segH}
        stroke={stroke}
        strokeWidth={strokeWidth}
        strokeLinecap="round"
        opacity={p.is_dropped ? 0.95 : 0.85}
      />
      {/* Top & bottom caps make the segment look like a Stevens "I-bar" */}
      {p.payload_len > 0 && (
        <>
          <line
            x1={x - 2}
            x2={x + 2}
            y1={yTop}
            y2={yTop}
            stroke={stroke}
            strokeWidth={strokeWidth}
            strokeLinecap="round"
            opacity={0.85}
          />
          <line
            x1={x - 2}
            x2={x + 2}
            y1={yBottom}
            y2={yBottom}
            stroke={stroke}
            strokeWidth={strokeWidth}
            strokeLinecap="round"
            opacity={0.85}
          />
        </>
      )}
      {/* Invisible wide hit area for easier hovering */}
      <rect
        x={x - 4}
        y={Math.min(yDraw, yDraw + segH) - 2}
        width={8}
        height={Math.abs(segH) + 4}
        fill="transparent"
      />
    </g>
  );
}

function HoverTooltip({ point, width, x }: { point: TCPGraphPoint; width: number; x: number }) {
  // Position tooltip to the side of the crosshair, keeping it inside the SVG.
  const TT_WIDTH = 240;
  const left = x + 12 + TT_WIDTH > width ? x - 12 - TT_WIDTH : x + 12;
  return (
    <div
      className="absolute pointer-events-none text-[11px] rounded-lg border border-slate-700 bg-slate-900/95 shadow-xl p-2.5 z-10"
      style={{ left, top: MARGIN.top + 4, width: TT_WIDTH }}
    >
      <div className="flex items-center justify-between mb-1.5">
        <span className="font-semibold text-white">
          #{point.packet_index} • {point.direction === 'forward' ? '→' : '←'}
        </span>
        <span className="text-slate-400">{formatTime(point.relative_time)}</span>
      </div>
      <div className="space-y-0.5 font-mono text-slate-300">
        <Row label="Seq" value={point.seq_num.toLocaleString()} />
        <Row label="Ack" value={point.ack_num.toLocaleString()} />
        <Row label="Win" value={point.window_size.toLocaleString()} />
        <Row label="Len" value={`${point.payload_len} B`} />
        {point.flags && <Row label="Flags" value={point.flags} mono />}
      </div>
      {point.is_retransmission && (
        <div className="mt-1.5 text-red-400 flex items-center gap-1">
          <RefreshCw className="w-3 h-3" />
          Retransmission
        </div>
      )}
      {point.is_dropped && (
        <div className="mt-1.5 text-red-500 flex items-center gap-1">
          <AlertTriangle className="w-3 h-3" />
          Dropped — never reached WAN
        </div>
      )}
      {(point.is_zero_window || point.window_size === 0) && !point.is_rst && !point.is_syn && (
        <div className="mt-1.5 text-amber-400 flex items-center gap-1">
          <AlertTriangle className="w-3 h-3" />
          Zero-window — receiver stalled
        </div>
      )}
    </div>
  );
}

function Row({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="flex items-center justify-between gap-3">
      <span className="text-slate-500">{label}</span>
      <span className={mono ? 'text-slate-200' : 'text-slate-200'}>{value}</span>
    </div>
  );
}

function ToggleButton({
  active,
  color,
  onClick,
  children,
}: {
  active: boolean;
  color: string;
  onClick: () => void;
  children: React.ReactNode;
}) {
  return (
    <button
      onClick={onClick}
      className={`px-2 py-1 text-[10px] rounded border transition-colors flex items-center gap-1.5 ${
        active
          ? 'bg-slate-700/60 border-slate-600 text-slate-100'
          : 'bg-slate-800/40 border-slate-700/40 text-slate-500 hover:text-slate-300'
      }`}
      title={active ? 'Click to hide' : 'Click to show'}
    >
      <span
        className="inline-block w-2 h-2 rounded-full"
        style={{ backgroundColor: color, opacity: active ? 1 : 0.35 }}
      />
      {children}
    </button>
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

function formatSeq(n: number): string {
  if (Math.abs(n) >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
  if (Math.abs(n) >= 1_000) return `${(n / 1_000).toFixed(1)}K`;
  return `${Math.round(n)}`;
}
