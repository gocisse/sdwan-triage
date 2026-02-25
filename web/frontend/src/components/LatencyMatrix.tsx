import { useState, useMemo, useCallback } from 'react';
import type { AnalysisResults, CellStat } from '../types';

// ─── Props ──────────────────────────────────────────────────────

interface LatencyMatrixProps {
  results: AnalysisResults | null;
  onFilterApply?: (filterExpr: string) => void;
}

// ─── Colour helpers ─────────────────────────────────────────────

function rttColor(avgRTT: number): string {
  if (avgRTT < 50) return '#22c55e';   // green-500
  if (avgRTT < 150) return '#f59e0b';  // amber-500
  return '#ef4444';                      // red-500
}

function rttBg(avgRTT: number): string {
  if (avgRTT < 50) return 'rgba(34,197,94,0.25)';
  if (avgRTT < 150) return 'rgba(245,158,11,0.25)';
  return 'rgba(239,68,68,0.30)';
}

function rttLevel(avgRTT: number): string {
  if (avgRTT < 50) return 'Healthy';
  if (avgRTT < 150) return 'Degraded';
  return 'Critical';
}

function lossColor(lossPct: number): string {
  if (lossPct < 1) return '#22c55e';
  if (lossPct < 5) return '#f59e0b';
  return '#ef4444';
}

// ─── Subnet grouping helpers ────────────────────────────────────

function subnetOf(ip: string): string {
  if (!ip) return '';
  // IPv6
  if (ip.includes(':')) {
    const parts = ip.split(':');
    const full = parts.slice(0, 4).join(':');
    return full + '::/64';
  }
  // IPv4 /24
  const octets = ip.split('.');
  if (octets.length !== 4) return '';
  return `${octets[0]}.${octets[1]}.${octets[2]}.0/24`;
}

function cellKey(src: string, dst: string): string {
  return `${src}->${dst}`;
}

// ─── Build matrix from AnalysisResults client-side ──────────────

interface MatrixData {
  subnets: string[];
  cells: Record<string, CellStat>;
  maxRTT: number;
  maxLoss: number;
  totalFlows: number;
}

function buildMatrix(results: AnalysisResults): MatrixData {
  const accum: Record<string, { sumRTT: number; minRTT: number; maxRTT: number; samples: number; lossPct: number; lossFlows: number }> = {};
  const subnetSet = new Set<string>();

  const addRTT = (srcIP: string, dstIP: string, avgRTT: number, minRTT: number, maxRTT: number, sampleSize: number) => {
    const srcSub = subnetOf(srcIP);
    const dstSub = subnetOf(dstIP);
    if (!srcSub || !dstSub || srcSub === dstSub) return;
    const key = cellKey(srcSub, dstSub);
    if (!accum[key]) {
      accum[key] = { sumRTT: 0, minRTT: Infinity, maxRTT: 0, samples: 0, lossPct: 0, lossFlows: 0 };
    }
    const a = accum[key];
    a.sumRTT += avgRTT * sampleSize;
    a.samples += sampleSize;
    if (minRTT < a.minRTT) a.minRTT = minRTT;
    if (maxRTT > a.maxRTT) a.maxRTT = maxRTT;
  };

  // RTT flows
  for (const f of results.rtt_analysis ?? []) {
    addRTT(f.src_ip, f.dst_ip, f.avg_rtt_ms, f.min_rtt_ms, f.max_rtt_ms, f.sample_size);
  }

  // Per-flow packet loss
  const perFlowLoss = results.packet_loss?.per_flow_loss ?? [];
  for (const pl of perFlowLoss) {
    const srcSub = subnetOf(pl.src_ip);
    const dstSub = subnetOf(pl.dst_ip);
    if (!srcSub || !dstSub || srcSub === dstSub) continue;
    const key = cellKey(srcSub, dstSub);
    if (!accum[key]) {
      accum[key] = { sumRTT: 0, minRTT: Infinity, maxRTT: 0, samples: 0, lossPct: 0, lossFlows: 0 };
    }
    accum[key].lossPct += pl.loss_percentage;
    accum[key].lossFlows++;
  }

  // Retransmission flows as loss proxy
  const retransmitCounts: Record<string, number> = {};
  for (const r of results.tcp_retransmissions ?? []) {
    const srcSub = subnetOf(r.src_ip);
    const dstSub = subnetOf(r.dst_ip);
    if (!srcSub || !dstSub || srcSub === dstSub) continue;
    const key = cellKey(srcSub, dstSub);
    retransmitCounts[key] = (retransmitCounts[key] || 0) + 1;
  }

  // Build final cells
  const cells: Record<string, CellStat> = {};
  let maxRTT = 0;
  let maxLoss = 0;
  let totalFlows = 0;

  for (const [key, a] of Object.entries(accum)) {
    const [src, dst] = key.split('->');
    subnetSet.add(src);
    subnetSet.add(dst);

    const cs: CellStat = {
      src_subnet: src,
      dst_subnet: dst,
      avg_rtt_ms: a.samples > 0 ? a.sumRTT / a.samples : 0,
      min_rtt_ms: a.minRTT === Infinity ? 0 : a.minRTT,
      max_rtt_ms: a.maxRTT,
      loss_pct: a.lossFlows > 0 ? a.lossPct / a.lossFlows : 0,
      flow_count: Math.max(a.samples, 1),
    };

    // Retransmit heuristic
    const rc = retransmitCounts[key] || 0;
    if (cs.loss_pct === 0 && rc > 0) {
      cs.loss_pct = Math.min(rc * 2, 100);
    }

    if (cs.max_rtt_ms > maxRTT) maxRTT = cs.max_rtt_ms;
    if (cs.loss_pct > maxLoss) maxLoss = cs.loss_pct;
    totalFlows += cs.flow_count;

    cells[key] = cs;
  }

  const subnets = Array.from(subnetSet).sort();
  return { subnets, cells, maxRTT, maxLoss, totalFlows };
}

// ─── Component ──────────────────────────────────────────────────

export default function LatencyMatrix({ results, onFilterApply }: LatencyMatrixProps) {
  const [hoveredCell, setHoveredCell] = useState<string | null>(null);
  const [tooltipPos, setTooltipPos] = useState<{ x: number; y: number }>({ x: 0, y: 0 });
  const [sortBy, setSortBy] = useState<'name' | 'rtt'>('name');

  const matrix = useMemo(() => {
    if (!results) return null;
    return buildMatrix(results);
  }, [results]);

  const sortedSubnets = useMemo(() => {
    if (!matrix) return [];
    if (sortBy === 'name') return matrix.subnets;
    // Sort by worst average RTT involving each subnet
    const worstRTT: Record<string, number> = {};
    for (const cell of Object.values(matrix.cells)) {
      const r = cell.avg_rtt_ms;
      if (!worstRTT[cell.src_subnet] || r > worstRTT[cell.src_subnet]) worstRTT[cell.src_subnet] = r;
      if (!worstRTT[cell.dst_subnet] || r > worstRTT[cell.dst_subnet]) worstRTT[cell.dst_subnet] = r;
    }
    return [...matrix.subnets].sort((a, b) => (worstRTT[b] || 0) - (worstRTT[a] || 0));
  }, [matrix, sortBy]);

  const handleCellClick = useCallback((src: string, dst: string) => {
    if (!onFilterApply) return;
    // Strip the CIDR suffix for filter — match any IP in the subnet
    const srcBase = src.replace(/\/\d+$/, '');
    const dstBase = dst.replace(/\/\d+$/, '');
    // Build Wireshark-like filter using subnet match
    const filter = `ip.src == ${srcBase} && ip.dst == ${dstBase}`;
    onFilterApply(filter);
  }, [onFilterApply]);

  const handleMouseMove = useCallback((e: React.MouseEvent) => {
    setTooltipPos({ x: e.clientX, y: e.clientY });
  }, []);

  // ─── Empty state ──────────────────────────────────────────────
  if (!results || !matrix || matrix.subnets.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center py-16 text-slate-500">
        <svg className="w-16 h-16 mb-4 opacity-30" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M3 3h18v18H3V3zm3 3h3v3H6V6zm6 0h3v3h-3V6zm6 0h3v3h-3V6zm-12 6h3v3H6v-3zm6 0h3v3h-3v-3zm6 0h3v3h-3v-3zm-12 6h3v3H6v-3zm6 0h3v3h-3v-3zm6 0h3v3h-3v-3z" />
        </svg>
        <p className="text-sm font-medium">No Latency Data Available</p>
        <p className="text-xs mt-1 max-w-xs text-center">
          RTT analysis requires TCP flows with measurable round-trip times. Upload a capture with bidirectional TCP traffic.
        </p>
      </div>
    );
  }

  const cellSize = matrix.subnets.length <= 8 ? 56 : matrix.subnets.length <= 16 ? 44 : 36;
  const labelWidth = 130;
  const hoveredData = hoveredCell ? matrix.cells[hoveredCell] : null;

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h3 className="text-sm font-semibold text-white">Site-to-Site Latency Matrix</h3>
          <p className="text-xs text-slate-400 mt-0.5">
            {sortedSubnets.length} subnets &bull; {Object.keys(matrix.cells).length} paths &bull; {matrix.totalFlows.toLocaleString()} flows
          </p>
        </div>
        <div className="flex items-center gap-3">
          {/* Legend */}
          <div className="flex items-center gap-2 text-[10px] text-slate-400">
            <span className="flex items-center gap-1"><span className="w-3 h-3 rounded" style={{ background: 'rgba(34,197,94,0.25)', border: '1px solid #22c55e' }} /> &lt;50ms</span>
            <span className="flex items-center gap-1"><span className="w-3 h-3 rounded" style={{ background: 'rgba(245,158,11,0.25)', border: '1px solid #f59e0b' }} /> 50-150ms</span>
            <span className="flex items-center gap-1"><span className="w-3 h-3 rounded" style={{ background: 'rgba(239,68,68,0.30)', border: '1px solid #ef4444' }} /> &gt;150ms</span>
          </div>
          {/* Sort toggle */}
          <button
            onClick={() => setSortBy(s => s === 'name' ? 'rtt' : 'name')}
            className="px-2 py-1 text-[10px] rounded border border-slate-600 text-slate-400 hover:text-white hover:border-slate-500 transition-colors"
          >
            Sort: {sortBy === 'name' ? 'Subnet' : 'Worst RTT'}
          </button>
        </div>
      </div>

      {/* Summary cards */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <div className="bg-slate-800/50 rounded-lg p-3 border border-slate-700/30">
          <p className="text-lg font-bold text-white">{sortedSubnets.length}</p>
          <p className="text-[10px] text-slate-400">Subnets</p>
        </div>
        <div className="bg-slate-800/50 rounded-lg p-3 border border-slate-700/30">
          <p className="text-lg font-bold text-white">{Object.keys(matrix.cells).length}</p>
          <p className="text-[10px] text-slate-400">Subnet Pairs</p>
        </div>
        <div className="bg-slate-800/50 rounded-lg p-3 border border-slate-700/30">
          <p className={`text-lg font-bold ${matrix.maxRTT > 150 ? 'text-red-400' : matrix.maxRTT > 50 ? 'text-amber-400' : 'text-green-400'}`}>
            {matrix.maxRTT.toFixed(1)}ms
          </p>
          <p className="text-[10px] text-slate-400">Peak RTT</p>
        </div>
        <div className="bg-slate-800/50 rounded-lg p-3 border border-slate-700/30">
          <p className={`text-lg font-bold ${matrix.maxLoss > 5 ? 'text-red-400' : matrix.maxLoss > 1 ? 'text-amber-400' : 'text-green-400'}`}>
            {matrix.maxLoss.toFixed(1)}%
          </p>
          <p className="text-[10px] text-slate-400">Worst Loss</p>
        </div>
      </div>

      {/* Heatmap grid */}
      <div className="bg-slate-800/30 rounded-lg border border-slate-700/30 p-4 overflow-auto" onMouseMove={handleMouseMove}>
        <div style={{ minWidth: labelWidth + sortedSubnets.length * cellSize + 20 }}>
          {/* Column headers */}
          <div className="flex" style={{ marginLeft: labelWidth }}>
            {sortedSubnets.map(sub => (
              <div
                key={`col-${sub}`}
                className="text-[9px] text-slate-500 font-mono overflow-hidden text-ellipsis whitespace-nowrap"
                style={{ width: cellSize, textAlign: 'center' }}
                title={sub}
              >
                {sub.replace('/24', '').replace('/64', '').split('.').slice(-2).join('.')}
              </div>
            ))}
          </div>

          {/* Rows */}
          {sortedSubnets.map(srcSub => (
            <div key={`row-${srcSub}`} className="flex items-center" style={{ height: cellSize }}>
              {/* Row label */}
              <div
                className="text-[10px] text-slate-400 font-mono truncate flex-shrink-0 pr-2 text-right"
                style={{ width: labelWidth }}
                title={srcSub}
              >
                {srcSub}
              </div>

              {/* Cells */}
              {sortedSubnets.map(dstSub => {
                const key = cellKey(srcSub, dstSub);
                const cell = matrix.cells[key];
                const isDiagonal = srcSub === dstSub;
                const isHovered = hoveredCell === key;

                if (isDiagonal) {
                  return (
                    <div
                      key={key}
                      className="flex items-center justify-center"
                      style={{
                        width: cellSize,
                        height: cellSize - 4,
                        margin: 2,
                        background: 'rgba(100,116,139,0.08)',
                        borderRadius: 4,
                      }}
                    >
                      <span className="text-[8px] text-slate-600">—</span>
                    </div>
                  );
                }

                if (!cell) {
                  return (
                    <div
                      key={key}
                      className="flex items-center justify-center"
                      style={{
                        width: cellSize,
                        height: cellSize - 4,
                        margin: 2,
                        background: 'rgba(100,116,139,0.05)',
                        borderRadius: 4,
                        border: '1px solid rgba(100,116,139,0.1)',
                      }}
                    >
                      <span className="text-[8px] text-slate-700">·</span>
                    </div>
                  );
                }

                return (
                  <div
                    key={key}
                    className="flex flex-col items-center justify-center cursor-pointer transition-all"
                    style={{
                      width: cellSize,
                      height: cellSize - 4,
                      margin: 2,
                      background: rttBg(cell.avg_rtt_ms),
                      border: `1.5px solid ${isHovered ? '#fff' : rttColor(cell.avg_rtt_ms)}`,
                      borderRadius: 4,
                      opacity: isHovered ? 1 : 0.85,
                      transform: isHovered ? 'scale(1.08)' : 'scale(1)',
                      zIndex: isHovered ? 10 : 1,
                    }}
                    onMouseEnter={() => setHoveredCell(key)}
                    onMouseLeave={() => setHoveredCell(null)}
                    onClick={() => handleCellClick(srcSub, dstSub)}
                  >
                    <span className="text-[10px] font-bold" style={{ color: rttColor(cell.avg_rtt_ms) }}>
                      {cell.avg_rtt_ms < 1000 ? `${Math.round(cell.avg_rtt_ms)}` : `${(cell.avg_rtt_ms / 1000).toFixed(1)}k`}
                    </span>
                    {cell.loss_pct > 0 && (
                      <span className="text-[8px]" style={{ color: lossColor(cell.loss_pct) }}>
                        {cell.loss_pct.toFixed(1)}%
                      </span>
                    )}
                  </div>
                );
              })}
            </div>
          ))}
        </div>
      </div>

      {/* Floating tooltip */}
      {hoveredData && (
        <div
          className="fixed z-50 pointer-events-none bg-slate-900 border border-slate-600 rounded-lg px-3 py-2 shadow-xl text-xs"
          style={{ left: tooltipPos.x + 14, top: tooltipPos.y - 80 }}
        >
          <div className="font-semibold text-white mb-1">Path Details</div>
          <div className="space-y-0.5 text-slate-300">
            <div><span className="text-slate-500">Source:</span> {hoveredData.src_subnet}</div>
            <div><span className="text-slate-500">Dest:</span> {hoveredData.dst_subnet}</div>
            <div className="pt-1 border-t border-slate-700 mt-1">
              <span className="text-slate-500">Avg RTT:</span>{' '}
              <span style={{ color: rttColor(hoveredData.avg_rtt_ms) }} className="font-semibold">
                {hoveredData.avg_rtt_ms.toFixed(1)}ms
              </span>
              <span className="ml-1 text-[10px]" style={{ color: rttColor(hoveredData.avg_rtt_ms) }}>
                ({rttLevel(hoveredData.avg_rtt_ms)})
              </span>
            </div>
            <div><span className="text-slate-500">Min/Max:</span> {hoveredData.min_rtt_ms.toFixed(1)}ms / {hoveredData.max_rtt_ms.toFixed(1)}ms</div>
            <div>
              <span className="text-slate-500">Loss:</span>{' '}
              <span style={{ color: lossColor(hoveredData.loss_pct) }} className="font-semibold">
                {hoveredData.loss_pct.toFixed(2)}%
              </span>
            </div>
            <div><span className="text-slate-500">Flows:</span> {hoveredData.flow_count.toLocaleString()}</div>
          </div>
          <div className="text-[9px] text-slate-500 mt-1 pt-1 border-t border-slate-700">Click to filter</div>
        </div>
      )}

      {/* Detailed table (top degraded paths) */}
      {Object.keys(matrix.cells).length > 0 && (
        <div className="bg-slate-800/30 rounded-lg border border-slate-700/30">
          <div className="px-4 py-2 border-b border-slate-700/30">
            <h4 className="text-xs font-semibold text-slate-300">Top Degraded Paths</h4>
          </div>
          <div className="overflow-auto max-h-64">
            <table className="w-full text-xs">
              <thead className="sticky top-0 bg-slate-800">
                <tr className="text-slate-500 text-left">
                  <th className="px-3 py-2 font-medium">Source Subnet</th>
                  <th className="px-3 py-2 font-medium">Dest Subnet</th>
                  <th className="px-3 py-2 font-medium text-right">Avg RTT</th>
                  <th className="px-3 py-2 font-medium text-right">Min</th>
                  <th className="px-3 py-2 font-medium text-right">Max</th>
                  <th className="px-3 py-2 font-medium text-right">Loss %</th>
                  <th className="px-3 py-2 font-medium text-right">Flows</th>
                  <th className="px-3 py-2 font-medium">Status</th>
                </tr>
              </thead>
              <tbody>
                {Object.values(matrix.cells)
                  .sort((a, b) => b.avg_rtt_ms - a.avg_rtt_ms)
                  .slice(0, 30)
                  .map((cell) => {
                    const key = cellKey(cell.src_subnet, cell.dst_subnet);
                    const level = rttLevel(cell.avg_rtt_ms);
                    return (
                      <tr
                        key={key}
                        className="border-t border-slate-700/20 hover:bg-slate-700/20 cursor-pointer"
                        onClick={() => handleCellClick(cell.src_subnet, cell.dst_subnet)}
                      >
                        <td className="px-3 py-2 font-mono text-slate-300">{cell.src_subnet}</td>
                        <td className="px-3 py-2 font-mono text-slate-300">{cell.dst_subnet}</td>
                        <td className="px-3 py-2 text-right font-semibold" style={{ color: rttColor(cell.avg_rtt_ms) }}>
                          {cell.avg_rtt_ms.toFixed(1)}ms
                        </td>
                        <td className="px-3 py-2 text-right text-slate-400">{cell.min_rtt_ms.toFixed(1)}ms</td>
                        <td className="px-3 py-2 text-right text-slate-400">{cell.max_rtt_ms.toFixed(1)}ms</td>
                        <td className="px-3 py-2 text-right" style={{ color: lossColor(cell.loss_pct) }}>
                          {cell.loss_pct.toFixed(2)}%
                        </td>
                        <td className="px-3 py-2 text-right text-slate-400">{cell.flow_count}</td>
                        <td className="px-3 py-2">
                          <span className={`px-1.5 py-0.5 rounded text-[10px] font-semibold ${
                            level === 'Healthy'
                              ? 'bg-green-500/20 text-green-400'
                              : level === 'Degraded'
                                ? 'bg-amber-500/20 text-amber-400'
                                : 'bg-red-500/20 text-red-400'
                          }`}>
                            {level}
                          </span>
                        </td>
                      </tr>
                    );
                  })}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}
