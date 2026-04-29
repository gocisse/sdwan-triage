// IOGraph.tsx — Throughput line graph over time (A3)
//
// Displays a time-series graph of bytes/sec or packets/sec
// with filtering by IP or protocol.

import { useState, useMemo, useCallback } from 'react';
import { Activity, Filter } from 'lucide-react';
import type { Discrepancy } from '../types';

// ─── Types ────────────────────────────────────────────────────────

interface IOGraphProps {
  discrepancies: Discrepancy[];
  className?: string;
}

interface DataPoint {
  time: number;
  timestamp: string;
  bytes: number;
  packets: number;
}

type MetricType = 'bytes' | 'packets';
type IntervalType = '100ms' | '500ms' | '1s' | '5s' | '10s';

// ─── Main Component ───────────────────────────────────────────────

export function IOGraph({ discrepancies, className = '' }: IOGraphProps) {
  const [metric, setMetric] = useState<MetricType>('bytes');
  const [interval, setInterval] = useState<IntervalType>('1s');
  const [filterIP, setFilterIP] = useState('');
  const [filterProtocol, setFilterProtocol] = useState<string>('all');
  const [hoveredPoint, setHoveredPoint] = useState<DataPoint | null>(null);

  // Filter discrepancies
  const filteredData = useMemo(() => {
    return discrepancies.filter(d => {
      if (filterIP && !d.src_ip.includes(filterIP) && !d.dst_ip.includes(filterIP)) {
        return false;
      }
      if (filterProtocol !== 'all' && d.protocol.toUpperCase() !== filterProtocol) {
        return false;
      }
      return true;
    });
  }, [discrepancies, filterIP, filterProtocol]);

  // Calculate time series data
  const { dataPoints, maxValue } = useMemo(() => {
    if (filteredData.length === 0) {
      return { dataPoints: [], maxValue: 0, timeRange: { start: 0, end: 0 } };
    }

    // Parse timestamps and sort
    const withTime = filteredData
      .map(d => ({
        ...d,
        ts: parseTimestamp(d.timestamp),
      }))
      .filter(d => d.ts > 0)
      .sort((a, b) => a.ts - b.ts);

    if (withTime.length === 0) {
      return { dataPoints: [], maxValue: 0, timeRange: { start: 0, end: 0 } };
    }

    const startTime = withTime[0].ts;
    const endTime = withTime[withTime.length - 1].ts;
    const intervalMs = parseInterval(interval);

    // Bucket packets by time interval
    const buckets: Map<number, { bytes: number; packets: number }> = new Map();
    
    withTime.forEach(d => {
      const bucketTime = Math.floor((d.ts - startTime) / intervalMs) * intervalMs;
      const existing = buckets.get(bucketTime) || { bytes: 0, packets: 0 };
      existing.bytes += d.length || 500;
      existing.packets += 1;
      buckets.set(bucketTime, existing);
    });

    // Convert to data points
    const points: DataPoint[] = [];
    let maxVal = 0;
    
    // Fill in gaps with zeros
    const totalBuckets = Math.ceil((endTime - startTime) / intervalMs) + 1;
    for (let i = 0; i < totalBuckets; i++) {
      const bucketTime = i * intervalMs;
      const data = buckets.get(bucketTime) || { bytes: 0, packets: 0 };
      
      // Convert to per-second rate
      const multiplier = 1000 / intervalMs;
      const bytesPerSec = data.bytes * multiplier;
      const packetsPerSec = data.packets * multiplier;
      
      points.push({
        time: bucketTime,
        timestamp: formatTime(startTime + bucketTime),
        bytes: bytesPerSec,
        packets: packetsPerSec,
      });
      
      maxVal = Math.max(maxVal, metric === 'bytes' ? bytesPerSec : packetsPerSec);
    }

    return {
      dataPoints: points,
      maxValue: maxVal,
      timeRange: { start: startTime, end: endTime },
    };
  }, [filteredData, interval, metric]);

  // Get unique protocols for filter
  const protocols = useMemo(() => {
    const set = new Set(discrepancies.map(d => d.protocol.toUpperCase()));
    return ['all', ...Array.from(set).sort()];
  }, [discrepancies]);

  // SVG dimensions
  const width = 800;
  const height = 300;
  const padding = { top: 20, right: 60, bottom: 40, left: 70 };
  const graphWidth = width - padding.left - padding.right;
  const graphHeight = height - padding.top - padding.bottom;

  // Scale functions
  const xScale = useCallback((time: number) => {
    if (dataPoints.length <= 1) return padding.left;
    const maxTime = dataPoints[dataPoints.length - 1]?.time || 1;
    return padding.left + (time / maxTime) * graphWidth;
  }, [dataPoints, graphWidth]);

  const yScale = useCallback((value: number) => {
    if (maxValue === 0) return height - padding.bottom;
    return height - padding.bottom - (value / maxValue) * graphHeight;
  }, [maxValue, graphHeight, height]);

  // Generate path
  const linePath = useMemo(() => {
    if (dataPoints.length === 0) return '';
    
    const getValue = (p: DataPoint) => metric === 'bytes' ? p.bytes : p.packets;
    
    return dataPoints.map((point, i) => {
      const x = xScale(point.time);
      const y = yScale(getValue(point));
      return `${i === 0 ? 'M' : 'L'} ${x} ${y}`;
    }).join(' ');
  }, [dataPoints, metric, xScale, yScale]);

  // Area path (for fill)
  const areaPath = useMemo(() => {
    if (dataPoints.length === 0) return '';
    
    const getValue = (p: DataPoint) => metric === 'bytes' ? p.bytes : p.packets;
    const baseline = height - padding.bottom;
    
    let path = `M ${xScale(dataPoints[0].time)} ${baseline}`;
    dataPoints.forEach(point => {
      path += ` L ${xScale(point.time)} ${yScale(getValue(point))}`;
    });
    path += ` L ${xScale(dataPoints[dataPoints.length - 1].time)} ${baseline} Z`;
    
    return path;
  }, [dataPoints, metric, xScale, yScale, height]);

  // Y-axis ticks
  const yTicks = useMemo(() => {
    const ticks: number[] = [];
    const step = maxValue / 5;
    for (let i = 0; i <= 5; i++) {
      ticks.push(Math.round(step * i));
    }
    return ticks;
  }, [maxValue]);

  // X-axis ticks
  const xTicks = useMemo(() => {
    if (dataPoints.length === 0) return [];
    const step = Math.max(1, Math.floor(dataPoints.length / 8));
    return dataPoints.filter((_, i) => i % step === 0);
  }, [dataPoints]);

  return (
    <div className={`bg-slate-800/80 rounded-xl border border-slate-700/50 overflow-hidden ${className}`}>
      {/* Header */}
      <div className="px-4 py-3 border-b border-slate-700/50 bg-slate-800/50">
        <div className="flex items-center justify-between flex-wrap gap-3">
          <div className="flex items-center gap-2">
            <Activity className="w-4 h-4 text-green-400" />
            <h3 className="text-sm font-semibold text-white">I/O Graph</h3>
          </div>

          {/* Controls */}
          <div className="flex items-center gap-3 flex-wrap">
            {/* Metric Toggle */}
            <div className="flex items-center bg-slate-900 rounded-lg p-0.5">
              <button
                onClick={() => setMetric('bytes')}
                className={`px-3 py-1 text-xs rounded-md transition-colors ${
                  metric === 'bytes' ? 'bg-blue-600 text-white' : 'text-slate-400 hover:text-white'
                }`}
              >
                Bytes/s
              </button>
              <button
                onClick={() => setMetric('packets')}
                className={`px-3 py-1 text-xs rounded-md transition-colors ${
                  metric === 'packets' ? 'bg-blue-600 text-white' : 'text-slate-400 hover:text-white'
                }`}
              >
                Packets/s
              </button>
            </div>

            {/* Interval */}
            <select
              value={interval}
              onChange={(e) => setInterval(e.target.value as IntervalType)}
              className="px-2 py-1 text-xs bg-slate-900 border border-slate-600 rounded-lg text-slate-300"
            >
              <option value="100ms">100ms</option>
              <option value="500ms">500ms</option>
              <option value="1s">1 second</option>
              <option value="5s">5 seconds</option>
              <option value="10s">10 seconds</option>
            </select>

            {/* Protocol Filter */}
            <select
              value={filterProtocol}
              onChange={(e) => setFilterProtocol(e.target.value)}
              className="px-2 py-1 text-xs bg-slate-900 border border-slate-600 rounded-lg text-slate-300"
            >
              {protocols.map(p => (
                <option key={p} value={p}>{p === 'all' ? 'All Protocols' : p}</option>
              ))}
            </select>

            {/* IP Filter */}
            <div className="relative">
              <Filter className="absolute left-2 top-1/2 -translate-y-1/2 w-3 h-3 text-slate-500" />
              <input
                type="text"
                value={filterIP}
                onChange={(e) => setFilterIP(e.target.value)}
                placeholder="Filter by IP..."
                className="pl-7 pr-3 py-1 text-xs bg-slate-900 border border-slate-600 rounded-lg text-slate-300 placeholder-slate-500 w-32"
              />
            </div>
          </div>
        </div>
      </div>

      {/* Graph */}
      <div className="p-4">
        {dataPoints.length === 0 ? (
          <div className="h-[300px] flex items-center justify-center text-slate-500 text-sm">
            No data to display
          </div>
        ) : (
          <svg
            viewBox={`0 0 ${width} ${height}`}
            className="w-full h-auto"
            style={{ maxHeight: '350px' }}
          >
            {/* Grid lines */}
            {yTicks.map((tick, i) => (
              <line
                key={i}
                x1={padding.left}
                y1={yScale(tick)}
                x2={width - padding.right}
                y2={yScale(tick)}
                stroke="#334155"
                strokeWidth="1"
                strokeDasharray="4,4"
              />
            ))}

            {/* Area fill */}
            <path
              d={areaPath}
              fill="url(#areaGradient)"
              opacity="0.3"
            />

            {/* Line */}
            <path
              d={linePath}
              fill="none"
              stroke={metric === 'bytes' ? '#3b82f6' : '#22c55e'}
              strokeWidth="2"
              strokeLinecap="round"
              strokeLinejoin="round"
            />

            {/* Data points (hover targets) */}
            {dataPoints.map((point, i) => {
              const value = metric === 'bytes' ? point.bytes : point.packets;
              return (
                <circle
                  key={i}
                  cx={xScale(point.time)}
                  cy={yScale(value)}
                  r={hoveredPoint === point ? 5 : 3}
                  fill={metric === 'bytes' ? '#3b82f6' : '#22c55e'}
                  stroke="#1e293b"
                  strokeWidth="2"
                  className="cursor-pointer transition-all"
                  onMouseEnter={() => setHoveredPoint(point)}
                  onMouseLeave={() => setHoveredPoint(null)}
                />
              );
            })}

            {/* Y-axis */}
            <line
              x1={padding.left}
              y1={padding.top}
              x2={padding.left}
              y2={height - padding.bottom}
              stroke="#475569"
              strokeWidth="1"
            />
            {yTicks.map((tick, i) => (
              <text
                key={i}
                x={padding.left - 8}
                y={yScale(tick)}
                textAnchor="end"
                dominantBaseline="middle"
                className="text-[10px] fill-slate-500"
              >
                {formatValue(tick, metric)}
              </text>
            ))}

            {/* X-axis */}
            <line
              x1={padding.left}
              y1={height - padding.bottom}
              x2={width - padding.right}
              y2={height - padding.bottom}
              stroke="#475569"
              strokeWidth="1"
            />
            {xTicks.map((point, i) => (
              <text
                key={i}
                x={xScale(point.time)}
                y={height - padding.bottom + 16}
                textAnchor="middle"
                className="text-[10px] fill-slate-500"
              >
                {point.timestamp}
              </text>
            ))}

            {/* Axis labels */}
            <text
              x={padding.left - 50}
              y={height / 2}
              textAnchor="middle"
              transform={`rotate(-90, ${padding.left - 50}, ${height / 2})`}
              className="text-xs fill-slate-400"
            >
              {metric === 'bytes' ? 'Bytes/sec' : 'Packets/sec'}
            </text>
            <text
              x={width / 2}
              y={height - 5}
              textAnchor="middle"
              className="text-xs fill-slate-400"
            >
              Time
            </text>

            {/* Gradient definition */}
            <defs>
              <linearGradient id="areaGradient" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor={metric === 'bytes' ? '#3b82f6' : '#22c55e'} stopOpacity="0.4" />
                <stop offset="100%" stopColor={metric === 'bytes' ? '#3b82f6' : '#22c55e'} stopOpacity="0" />
              </linearGradient>
            </defs>

            {/* Tooltip */}
            {hoveredPoint && (
              <g>
                <rect
                  x={xScale(hoveredPoint.time) - 60}
                  y={yScale(metric === 'bytes' ? hoveredPoint.bytes : hoveredPoint.packets) - 45}
                  width="120"
                  height="40"
                  rx="4"
                  fill="#1e293b"
                  stroke="#475569"
                />
                <text
                  x={xScale(hoveredPoint.time)}
                  y={yScale(metric === 'bytes' ? hoveredPoint.bytes : hoveredPoint.packets) - 30}
                  textAnchor="middle"
                  className="text-[10px] fill-slate-400"
                >
                  {hoveredPoint.timestamp}
                </text>
                <text
                  x={xScale(hoveredPoint.time)}
                  y={yScale(metric === 'bytes' ? hoveredPoint.bytes : hoveredPoint.packets) - 15}
                  textAnchor="middle"
                  className="text-xs fill-white font-semibold"
                >
                  {formatValue(metric === 'bytes' ? hoveredPoint.bytes : hoveredPoint.packets, metric)}
                </text>
              </g>
            )}
          </svg>
        )}
      </div>

      {/* Stats Footer */}
      <div className="px-4 py-2 border-t border-slate-700/30 bg-slate-900/30">
        <div className="flex items-center justify-between text-[10px] text-slate-500">
          <span>
            {filteredData.length.toLocaleString()} packets • {dataPoints.length} data points
          </span>
          <span>
            Peak: {formatValue(maxValue, metric)} • Interval: {interval}
          </span>
        </div>
      </div>
    </div>
  );
}

// ─── Helpers ──────────────────────────────────────────────────────

function parseTimestamp(ts: string): number {
  // Handle various timestamp formats
  if (!ts) return 0;
  
  // Try parsing as ISO date
  const date = new Date(ts);
  if (!isNaN(date.getTime())) {
    return date.getTime();
  }
  
  // Try parsing as relative time (e.g., "0.000123")
  const num = parseFloat(ts);
  if (!isNaN(num)) {
    return num * 1000; // Convert to ms
  }
  
  return 0;
}

function parseInterval(interval: IntervalType): number {
  switch (interval) {
    case '100ms': return 100;
    case '500ms': return 500;
    case '1s': return 1000;
    case '5s': return 5000;
    case '10s': return 10000;
    default: return 1000;
  }
}

function formatTime(ms: number): string {
  const seconds = (ms / 1000).toFixed(1);
  return `${seconds}s`;
}

function formatValue(value: number, metric: MetricType): string {
  if (metric === 'bytes') {
    if (value >= 1000000) return `${(value / 1000000).toFixed(1)} MB/s`;
    if (value >= 1000) return `${(value / 1000).toFixed(1)} KB/s`;
    return `${Math.round(value)} B/s`;
  } else {
    if (value >= 1000) return `${(value / 1000).toFixed(1)}K pkt/s`;
    return `${Math.round(value)} pkt/s`;
  }
}

export default IOGraph;
