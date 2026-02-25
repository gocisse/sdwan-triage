// QoS Analysis Dashboard — DSCP distribution pie chart, per-flow table, and alerts
// Integrated as a sub-tab in the Forensic Drill-Down panel.

import { useMemo, useState } from 'react';
import type { AnalysisResults, ComparisonReport, QoSClassMetrics } from '../types';

// ─── DSCP Class Metadata ────────────────────────────────────────

const DSCP_COLORS: Record<string, string> = {
  EF:   '#ef4444',
  AF41: '#f97316', AF42: '#fb923c', AF43: '#fdba74',
  AF31: '#eab308', AF32: '#facc15', AF33: '#fde047',
  AF21: '#22c55e', AF22: '#4ade80', AF23: '#86efac',
  AF11: '#06b6d4', AF12: '#22d3ee', AF13: '#67e8f9',
  CS7:  '#a855f7', CS6:  '#c084fc', CS5:  '#7c3aed',
  CS4:  '#8b5cf6', CS3:  '#6366f1', CS2:  '#818cf8',
  CS1:  '#94a3b8', BE:   '#64748b',
};

const DSCP_DESCRIPTIONS: Record<string, string> = {
  BE:   'Best Effort — Default traffic',
  CS1:  'Scavenger — Low priority background',
  AF11: 'Assured Forwarding 11 — Bulk data (low drop)',
  AF12: 'Assured Forwarding 12 — Bulk data (med drop)',
  AF13: 'Assured Forwarding 13 — Bulk data (high drop)',
  CS2:  'OAM — Operations & Management',
  AF21: 'Assured Forwarding 21 — Transactional (low drop)',
  AF22: 'Assured Forwarding 22 — Transactional (med drop)',
  AF23: 'Assured Forwarding 23 — Transactional (high drop)',
  CS3:  'Signaling — Call signaling',
  AF31: 'Assured Forwarding 31 — Multimedia streaming (low drop)',
  AF32: 'Assured Forwarding 32 — Multimedia streaming (med drop)',
  AF33: 'Assured Forwarding 33 — Multimedia streaming (high drop)',
  CS4:  'Real-time Interactive',
  AF41: 'Assured Forwarding 41 — Multimedia conferencing (low drop)',
  AF42: 'Assured Forwarding 42 — Multimedia conferencing (med drop)',
  AF43: 'Assured Forwarding 43 — Multimedia conferencing (high drop)',
  CS5:  'Broadcast Video',
  EF:   'Expedited Forwarding — Voice / Real-time',
  CS6:  'Network Control — Routing protocols',
  CS7:  'Network Control — Reserved',
};

const DSCP_VALUES: Record<string, number> = {
  BE: 0, CS1: 8, AF11: 10, AF12: 12, AF13: 14, CS2: 16,
  AF21: 18, AF22: 20, AF23: 22, CS3: 24, AF31: 26, AF32: 28,
  AF33: 30, CS4: 32, AF41: 34, AF42: 36, AF43: 38, CS5: 40,
  EF: 46, CS6: 48, CS7: 56,
};

function colorFor(className: string): string {
  return DSCP_COLORS[className] || '#94a3b8';
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1048576) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1073741824) return `${(bytes / 1048576).toFixed(1)} MB`;
  return `${(bytes / 1073741824).toFixed(2)} GB`;
}

function formatNumber(n: number): string {
  return n.toLocaleString();
}

// ─── Derived QoS Alert ──────────────────────────────────────────

interface QoSAlert {
  severity: 'Critical' | 'Warning' | 'Info';
  title: string;
  description: string;
}

// ─── Derived QoS Class Row ──────────────────────────────────────

interface ClassRow {
  className: string;
  dscpValue: number;
  description: string;
  packetCount: number;
  byteCount: number;
  percentage: number;
  color: string;
}

// ─── Derived Flow Row ───────────────────────────────────────────

interface FlowRow {
  srcIp: string;
  srcPort: number;
  dstIp: string;
  dstPort: number;
  protocol: string;
  dscpClass: string;
  dscpValue: number;
  totalBytes: number;
}

// ─── DSCP Comparison Row ────────────────────────────────────────

interface DSCPChangeRow {
  flow: string;
  lanClass: string;
  wanClass: string;
  status: 'Preserved' | 'Remarked' | 'Stripped';
}

// ─── Props ──────────────────────────────────────────────────────

interface QosDashboardProps {
  results: AnalysisResults;
  comparisonReport?: ComparisonReport | null;
}

// ─── Component ──────────────────────────────────────────────────

export default function QosDashboard({ results, comparisonReport }: QosDashboardProps) {
  const [flowSearch, setFlowSearch] = useState('');
  const [activeSection, setActiveSection] = useState<'distribution' | 'flows' | 'comparison'>('distribution');

  // ── Build class rows from QoS report ──────────────────────────
  const classRows: ClassRow[] = useMemo(() => {
    const qos = results.qos_analysis;
    if (!qos?.class_distribution) return [];

    const rows: ClassRow[] = Object.values(qos.class_distribution).map((m: QoSClassMetrics) => ({
      className: m.class_name,
      dscpValue: m.dscp_value,
      description: DSCP_DESCRIPTIONS[m.class_name] || m.class_name,
      packetCount: m.packet_count,
      byteCount: m.byte_count,
      percentage: m.percentage,
      color: colorFor(m.class_name),
    }));

    rows.sort((a, b) => b.packetCount - a.packetCount);
    return rows;
  }, [results.qos_analysis]);

  const totalPackets = results.qos_analysis?.total_packets ?? 0;
  const totalBytes = classRows.reduce((s, r) => s + r.byteCount, 0);

  // ── Build flow rows from traffic_analysis + QoS ───────────────
  const flowRows: FlowRow[] = useMemo(() => {
    if (!results.traffic_analysis) return [];

    const mismatchMap = new Map<string, string>();
    if (results.qos_analysis?.mismatched_qos) {
      for (const mm of results.qos_analysis.mismatched_qos) {
        mismatchMap.set(mm.flow, mm.expected_class);
      }
    }

    return results.traffic_analysis
      .map(tf => {
        const flowKey = `${tf.src_ip}:${tf.src_port}->${tf.dst_ip}:${tf.dst_port}`;
        const assignedClass = mismatchMap.get(flowKey) || inferDSCPClass(tf.dst_port, tf.src_port);
        return {
          srcIp: tf.src_ip,
          srcPort: tf.src_port,
          dstIp: tf.dst_ip,
          dstPort: tf.dst_port,
          protocol: tf.protocol,
          dscpClass: assignedClass,
          dscpValue: DSCP_VALUES[assignedClass] ?? 0,
          totalBytes: tf.total_bytes,
        };
      })
      .sort((a, b) => b.totalBytes - a.totalBytes)
      .slice(0, 200);
  }, [results.traffic_analysis, results.qos_analysis]);

  const filteredFlows = useMemo(() => {
    if (!flowSearch) return flowRows;
    const q = flowSearch.toLowerCase();
    return flowRows.filter(f =>
      f.srcIp.includes(q) || f.dstIp.includes(q) ||
      f.dscpClass.toLowerCase().includes(q) ||
      f.protocol.toLowerCase().includes(q) ||
      String(f.srcPort).includes(q) || String(f.dstPort).includes(q)
    );
  }, [flowRows, flowSearch]);

  // ── Build comparison data from ComparisonReport ───────────────
  const comparisonData = useMemo(() => {
    if (!comparisonReport || comparisonReport.dscp_changes === 0) return null;

    const changes: DSCPChangeRow[] = [];
    let preserved = 0;
    let remarked = 0;
    let stripped = 0;

    for (const disc of (comparisonReport.discrepancies || [])) {
      if (disc.state !== 'MODIFIED' || !disc.field_changes) continue;
      for (const ch of disc.field_changes) {
        if (ch.field !== 'DSCP') continue;
        const lanVal = parseInt(ch.value_a, 10);
        const wanVal = parseInt(ch.value_b, 10);
        const lanClass = dscpValueToClass(lanVal);
        const wanClass = dscpValueToClass(wanVal);
        let status: DSCPChangeRow['status'] = 'Remarked';
        if (wanVal === 0 && lanVal !== 0) {
          status = 'Stripped';
          stripped++;
        } else {
          remarked++;
        }
        changes.push({
          flow: `${disc.src_ip}:${disc.src_port}→${disc.dst_ip}:${disc.dst_port}`,
          lanClass,
          wanClass,
          status,
        });
      }
    }

    preserved = comparisonReport.matched_count - (remarked + stripped);

    return { changes, preserved, remarked, stripped, total: comparisonReport.dscp_changes };
  }, [comparisonReport]);

  // ── Generate alerts ───────────────────────────────────────────
  const alerts: QoSAlert[] = useMemo(() => {
    const a: QoSAlert[] = [];

    if (classRows.length === 0) return a;

    // All traffic is BE
    if (classRows.length === 1 && classRows[0].className === 'BE' && totalPackets > 100) {
      a.push({
        severity: 'Warning',
        title: 'No QoS Policy Detected — All Traffic is Best Effort',
        description: '100% of analysed packets are marked DSCP 0 (Best Effort). No QoS differentiation is applied. Voice, video, and critical business apps compete equally during congestion.',
      });
    }

    // EF + BE mix
    const ef = classRows.find(c => c.className === 'EF');
    const be = classRows.find(c => c.className === 'BE');
    if (ef && be && be.percentage > 50) {
      a.push({
        severity: 'Warning',
        title: 'Voice Traffic (EF) Mixed with Best Effort',
        description: `${ef.percentage.toFixed(1)}% marked EF but ${be.percentage.toFixed(1)}% is still Best Effort. QoS policies may not classify all traffic.`,
      });
    }

    // Mismatches within flows
    const mismatches = results.qos_analysis?.mismatched_qos?.length ?? 0;
    if (mismatches > 0) {
      a.push({
        severity: 'Warning',
        title: 'DSCP Marking Inconsistency Within Flows',
        description: `${mismatches} flow(s) have packets with different DSCP markings mid-flow. This indicates remarking or policy misconfiguration.`,
      });
    }

    // Comparison-specific alerts
    if (comparisonData) {
      if (comparisonData.stripped > 0) {
        a.push({
          severity: 'Critical',
          title: 'DSCP Markings Stripped on WAN Side',
          description: `${comparisonData.stripped} packet(s) had DSCP markings stripped to Best Effort between LAN and WAN. QoS policies are NOT preserved across the SD-WAN overlay.`,
        });
      }
      if (comparisonData.remarked > 0) {
        a.push({
          severity: 'Warning',
          title: 'DSCP Markings Remarked on WAN Side',
          description: `${comparisonData.remarked} packet(s) had DSCP values changed between LAN and WAN. Verify SD-WAN QoS policy preserves or correctly re-marks DSCP.`,
        });
      }
    }

    // Retransmissions in high-priority traffic
    if ((ef || classRows.find(c => c.className === 'AF41')) && (results.tcp_retransmissions?.length ?? 0) > 0) {
      a.push({
        severity: 'Critical',
        title: 'Retransmissions in High-Priority Traffic',
        description: 'TCP retransmissions detected alongside EF/AF41 traffic. QoS may not be providing adequate protection or the WAN link is over-subscribed.',
      });
    }

    return a;
  }, [classRows, totalPackets, results, comparisonData]);

  // ── Empty state ───────────────────────────────────────────────
  if (classRows.length === 0) {
    return (
      <div className="bg-slate-800/60 border border-slate-700/50 rounded-xl p-8 text-center">
        <div className="text-4xl mb-3">📊</div>
        <h3 className="text-lg font-semibold text-slate-200 mb-1">No QoS Data Available</h3>
        <p className="text-sm text-slate-400 max-w-md mx-auto">
          The analysed capture contains no DSCP-marked traffic, or the QoS analyser was not enabled.
          Upload a capture with IP traffic to see DSCP distribution.
        </p>
      </div>
    );
  }

  // ── Pie chart SVG ─────────────────────────────────────────────
  const pieSlices = buildPieSlices(classRows);

  return (
    <div className="space-y-4">
      {/* ── Alerts ──────────────────────────────────────────────── */}
      {alerts.length > 0 && (
        <div className="space-y-2">
          {alerts.map((alert, i) => (
            <div
              key={i}
              className={`flex items-start gap-3 px-4 py-3 rounded-lg border text-sm ${
                alert.severity === 'Critical'
                  ? 'bg-red-500/10 border-red-500/30 text-red-300'
                  : alert.severity === 'Warning'
                  ? 'bg-amber-500/10 border-amber-500/30 text-amber-300'
                  : 'bg-blue-500/10 border-blue-500/30 text-blue-300'
              }`}
            >
              <span className="text-lg mt-0.5">
                {alert.severity === 'Critical' ? '🔴' : alert.severity === 'Warning' ? '🟡' : 'ℹ️'}
              </span>
              <div>
                <div className="font-semibold">{alert.title}</div>
                <div className="text-xs opacity-80 mt-0.5">{alert.description}</div>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* ── Section tabs ───────────────────────────────────────── */}
      <div className="flex items-center gap-1 border-b border-slate-700/50 pb-0">
        {([
          { key: 'distribution' as const, label: 'DSCP Distribution' },
          { key: 'flows' as const, label: `Flow Table (${flowRows.length})` },
          ...(comparisonData ? [{ key: 'comparison' as const, label: `LAN↔WAN (${comparisonData.total})` }] : []),
        ]).map(tab => (
          <button
            key={tab.key}
            onClick={() => setActiveSection(tab.key)}
            className={`px-4 py-2 text-xs font-medium transition-all border-b-2 -mb-[1px] ${
              activeSection === tab.key
                ? 'border-cyan-500 text-cyan-400'
                : 'border-transparent text-slate-500 hover:text-slate-300'
            }`}
          >
            {tab.label}
          </button>
        ))}
      </div>

      {/* ── Distribution Section ───────────────────────────────── */}
      {activeSection === 'distribution' && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          {/* Pie Chart */}
          <div className="bg-slate-800/60 border border-slate-700/50 rounded-xl p-5">
            <h3 className="text-sm font-semibold text-slate-200 mb-4">Traffic Composition by DSCP Class</h3>
            <div className="flex items-center justify-center">
              <svg viewBox="0 0 200 200" className="w-56 h-56">
                {pieSlices.map((slice, i) => (
                  <path
                    key={i}
                    d={slice.d}
                    fill={slice.color}
                    stroke="#1e293b"
                    strokeWidth="1"
                    className="transition-opacity hover:opacity-80 cursor-pointer"
                  >
                    <title>{`${slice.label}: ${slice.percentage.toFixed(1)}% (${formatNumber(slice.packets)} pkts)`}</title>
                  </path>
                ))}
                {/* Center label */}
                <text x="100" y="95" textAnchor="middle" className="fill-slate-200 text-[11px] font-semibold">
                  {formatNumber(totalPackets)}
                </text>
                <text x="100" y="112" textAnchor="middle" className="fill-slate-400 text-[8px]">
                  packets
                </text>
              </svg>
            </div>
            {/* Legend */}
            <div className="mt-4 grid grid-cols-2 gap-x-4 gap-y-1.5">
              {classRows.map(row => (
                <div key={row.className} className="flex items-center gap-2 text-xs">
                  <span className="w-2.5 h-2.5 rounded-sm flex-shrink-0" style={{ backgroundColor: row.color }} />
                  <span className="text-slate-300 font-medium">{row.className}</span>
                  <span className="text-slate-500 ml-auto">{row.percentage.toFixed(1)}%</span>
                </div>
              ))}
            </div>
          </div>

          {/* Class Table */}
          <div className="bg-slate-800/60 border border-slate-700/50 rounded-xl p-5">
            <h3 className="text-sm font-semibold text-slate-200 mb-4">DSCP Class Breakdown</h3>
            <div className="space-y-0">
              {/* Header */}
              <div className="grid grid-cols-12 gap-2 px-3 py-2 text-[10px] font-semibold text-slate-500 uppercase tracking-wider border-b border-slate-700/50">
                <div className="col-span-3">Class</div>
                <div className="col-span-1 text-center">DSCP</div>
                <div className="col-span-3 text-right">Packets</div>
                <div className="col-span-3 text-right">Bytes</div>
                <div className="col-span-2 text-right">%</div>
              </div>
              {/* Rows */}
              {classRows.map(row => (
                <div
                  key={row.className}
                  className="grid grid-cols-12 gap-2 px-3 py-2 text-xs hover:bg-slate-700/30 transition-colors border-b border-slate-700/20"
                >
                  <div className="col-span-3 flex items-center gap-2">
                    <span className="w-2 h-2 rounded-sm flex-shrink-0" style={{ backgroundColor: row.color }} />
                    <span className="text-slate-200 font-medium">{row.className}</span>
                  </div>
                  <div className="col-span-1 text-center text-slate-400 font-mono">{row.dscpValue}</div>
                  <div className="col-span-3 text-right text-slate-300 font-mono">{formatNumber(row.packetCount)}</div>
                  <div className="col-span-3 text-right text-slate-400">{formatBytes(row.byteCount)}</div>
                  <div className="col-span-2 text-right">
                    <div className="flex items-center justify-end gap-1.5">
                      <div className="w-12 h-1.5 bg-slate-700 rounded-full overflow-hidden">
                        <div
                          className="h-full rounded-full"
                          style={{ width: `${Math.min(row.percentage, 100)}%`, backgroundColor: row.color }}
                        />
                      </div>
                      <span className="text-slate-300 font-mono w-10 text-right">{row.percentage.toFixed(1)}%</span>
                    </div>
                  </div>
                </div>
              ))}
            </div>

            {/* Summary footer */}
            <div className="mt-3 pt-3 border-t border-slate-700/50 flex justify-between text-xs text-slate-400">
              <span>{classRows.length} DSCP {classRows.length === 1 ? 'class' : 'classes'} detected</span>
              <span>Total: {formatBytes(totalBytes)}</span>
            </div>
          </div>
        </div>
      )}

      {/* ── Flow Table Section ─────────────────────────────────── */}
      {activeSection === 'flows' && (
        <div className="bg-slate-800/60 border border-slate-700/50 rounded-xl p-5">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-sm font-semibold text-slate-200">Per-Flow DSCP Assignments</h3>
            <input
              type="text"
              placeholder="Search flows (IP, port, class)…"
              value={flowSearch}
              onChange={e => setFlowSearch(e.target.value)}
              className="w-64 px-3 py-1.5 text-xs bg-slate-900/60 border border-slate-700/50 rounded-lg text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500/50"
            />
          </div>

          <div className="overflow-x-auto max-h-[420px] overflow-y-auto">
            <table className="w-full text-xs">
              <thead className="sticky top-0 bg-slate-800">
                <tr className="text-[10px] font-semibold text-slate-500 uppercase tracking-wider border-b border-slate-700/50">
                  <th className="text-left py-2 px-2">Source</th>
                  <th className="text-left py-2 px-2">Destination</th>
                  <th className="text-center py-2 px-2">Protocol</th>
                  <th className="text-center py-2 px-2">DSCP Class</th>
                  <th className="text-center py-2 px-2">DSCP Value</th>
                  <th className="text-right py-2 px-2">Bytes</th>
                </tr>
              </thead>
              <tbody>
                {filteredFlows.map((f, i) => (
                  <tr
                    key={i}
                    className="border-b border-slate-700/20 hover:bg-slate-700/30 transition-colors"
                  >
                    <td className="py-1.5 px-2 text-slate-300 font-mono">{f.srcIp}:{f.srcPort}</td>
                    <td className="py-1.5 px-2 text-slate-300 font-mono">{f.dstIp}:{f.dstPort}</td>
                    <td className="py-1.5 px-2 text-center text-slate-400">{f.protocol}</td>
                    <td className="py-1.5 px-2 text-center">
                      <span
                        className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-semibold"
                        style={{ backgroundColor: colorFor(f.dscpClass) + '20', color: colorFor(f.dscpClass) }}
                      >
                        <span className="w-1.5 h-1.5 rounded-full" style={{ backgroundColor: colorFor(f.dscpClass) }} />
                        {f.dscpClass}
                      </span>
                    </td>
                    <td className="py-1.5 px-2 text-center text-slate-400 font-mono">{f.dscpValue}</td>
                    <td className="py-1.5 px-2 text-right text-slate-300">{formatBytes(f.totalBytes)}</td>
                  </tr>
                ))}
                {filteredFlows.length === 0 && (
                  <tr>
                    <td colSpan={6} className="py-8 text-center text-slate-500">
                      {flowSearch ? 'No flows match your search' : 'No flow data available'}
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>

          <div className="mt-3 pt-3 border-t border-slate-700/50 text-xs text-slate-500">
            Showing {filteredFlows.length} of {flowRows.length} flows (top 200 by bytes)
          </div>
        </div>
      )}

      {/* ── LAN↔WAN Comparison Section ─────────────────────────── */}
      {activeSection === 'comparison' && comparisonData && (
        <div className="space-y-4">
          {/* Summary cards */}
          <div className="grid grid-cols-1 sm:grid-cols-4 gap-3">
            <StatCard label="DSCP Changes" value={comparisonData.total} color="text-amber-400" />
            <StatCard label="Preserved" value={comparisonData.preserved} color="text-emerald-400" />
            <StatCard label="Remarked" value={comparisonData.remarked} color="text-amber-400" />
            <StatCard label="Stripped to BE" value={comparisonData.stripped} color="text-red-400" />
          </div>

          {/* Preservation bar */}
          <div className="bg-slate-800/60 border border-slate-700/50 rounded-xl p-5">
            <h3 className="text-sm font-semibold text-slate-200 mb-3">DSCP Preservation Rate</h3>
            {(() => {
              const total = comparisonData.preserved + comparisonData.remarked + comparisonData.stripped;
              const preservedPct = total > 0 ? (comparisonData.preserved / total) * 100 : 0;
              const remarkedPct = total > 0 ? (comparisonData.remarked / total) * 100 : 0;
              const strippedPct = total > 0 ? (comparisonData.stripped / total) * 100 : 0;
              return (
                <div>
                  <div className="flex h-4 rounded-full overflow-hidden bg-slate-700">
                    {preservedPct > 0 && (
                      <div className="bg-emerald-500 transition-all" style={{ width: `${preservedPct}%` }} title={`Preserved: ${preservedPct.toFixed(1)}%`} />
                    )}
                    {remarkedPct > 0 && (
                      <div className="bg-amber-500 transition-all" style={{ width: `${remarkedPct}%` }} title={`Remarked: ${remarkedPct.toFixed(1)}%`} />
                    )}
                    {strippedPct > 0 && (
                      <div className="bg-red-500 transition-all" style={{ width: `${strippedPct}%` }} title={`Stripped: ${strippedPct.toFixed(1)}%`} />
                    )}
                  </div>
                  <div className="flex justify-between mt-2 text-xs text-slate-400">
                    <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-full bg-emerald-500" /> Preserved {preservedPct.toFixed(1)}%</span>
                    <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-full bg-amber-500" /> Remarked {remarkedPct.toFixed(1)}%</span>
                    <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-full bg-red-500" /> Stripped {strippedPct.toFixed(1)}%</span>
                  </div>
                </div>
              );
            })()}
          </div>

          {/* Detail table */}
          {comparisonData.changes.length > 0 && (
            <div className="bg-slate-800/60 border border-slate-700/50 rounded-xl p-5">
              <h3 className="text-sm font-semibold text-slate-200 mb-3">DSCP Changes Detail</h3>
              <div className="overflow-x-auto max-h-[320px] overflow-y-auto">
                <table className="w-full text-xs">
                  <thead className="sticky top-0 bg-slate-800">
                    <tr className="text-[10px] font-semibold text-slate-500 uppercase tracking-wider border-b border-slate-700/50">
                      <th className="text-left py-2 px-2">Flow</th>
                      <th className="text-center py-2 px-2">LAN DSCP</th>
                      <th className="text-center py-2 px-2" />
                      <th className="text-center py-2 px-2">WAN DSCP</th>
                      <th className="text-center py-2 px-2">Status</th>
                    </tr>
                  </thead>
                  <tbody>
                    {comparisonData.changes.map((ch, i) => (
                      <tr key={i} className="border-b border-slate-700/20 hover:bg-slate-700/30 transition-colors">
                        <td className="py-1.5 px-2 text-slate-300 font-mono text-[10px]">{ch.flow}</td>
                        <td className="py-1.5 px-2 text-center">
                          <span className="px-2 py-0.5 rounded-full text-[10px] font-semibold" style={{ backgroundColor: colorFor(ch.lanClass) + '20', color: colorFor(ch.lanClass) }}>
                            {ch.lanClass}
                          </span>
                        </td>
                        <td className="py-1.5 px-2 text-center text-slate-500">→</td>
                        <td className="py-1.5 px-2 text-center">
                          <span className="px-2 py-0.5 rounded-full text-[10px] font-semibold" style={{ backgroundColor: colorFor(ch.wanClass) + '20', color: colorFor(ch.wanClass) }}>
                            {ch.wanClass}
                          </span>
                        </td>
                        <td className="py-1.5 px-2 text-center">
                          <span className={`text-[10px] font-semibold ${
                            ch.status === 'Stripped' ? 'text-red-400' : ch.status === 'Remarked' ? 'text-amber-400' : 'text-emerald-400'
                          }`}>
                            {ch.status}
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ─── Stat Card ──────────────────────────────────────────────────

function StatCard({ label, value, color }: { label: string; value: number; color: string }) {
  return (
    <div className="bg-slate-800/60 border border-slate-700/50 rounded-xl p-4 text-center">
      <div className={`text-2xl font-bold ${color}`}>{formatNumber(value)}</div>
      <div className="text-xs text-slate-400 mt-1">{label}</div>
    </div>
  );
}

// ─── Pie Chart Builder ──────────────────────────────────────────

interface PieSlice {
  d: string;
  color: string;
  label: string;
  percentage: number;
  packets: number;
}

function buildPieSlices(rows: ClassRow[]): PieSlice[] {
  if (rows.length === 0) return [];

  // Single class = full circle
  if (rows.length === 1) {
    return [{
      d: 'M 100 10 A 90 90 0 1 1 99.99 10 Z',
      color: rows[0].color,
      label: rows[0].className,
      percentage: 100,
      packets: rows[0].packetCount,
    }];
  }

  const slices: PieSlice[] = [];
  const cx = 100, cy = 100, r = 90;
  let startAngle = -Math.PI / 2; // Start from top

  for (const row of rows) {
    const pct = row.percentage / 100;
    if (pct <= 0) continue;

    const endAngle = startAngle + pct * 2 * Math.PI;
    const largeArc = pct > 0.5 ? 1 : 0;

    const x1 = cx + r * Math.cos(startAngle);
    const y1 = cy + r * Math.sin(startAngle);
    const x2 = cx + r * Math.cos(endAngle);
    const y2 = cy + r * Math.sin(endAngle);

    const d = [
      `M ${cx} ${cy}`,
      `L ${x1.toFixed(2)} ${y1.toFixed(2)}`,
      `A ${r} ${r} 0 ${largeArc} 1 ${x2.toFixed(2)} ${y2.toFixed(2)}`,
      'Z',
    ].join(' ');

    slices.push({
      d,
      color: row.color,
      label: row.className,
      percentage: row.percentage,
      packets: row.packetCount,
    });

    startAngle = endAngle;
  }

  return slices;
}

// ─── Helpers ────────────────────────────────────────────────────

function inferDSCPClass(dstPort: number, srcPort: number): string {
  const port = Math.min(dstPort, srcPort);
  if (port === 5060 || port === 5061 || (port >= 16384 && port <= 32767)) return 'EF';
  if (port === 443 || port === 80) return 'BE';
  if (port === 3389 || port === 22 || port === 3200 || port === 3300) return 'AF21';
  if (port === 445 || port === 139) return 'AF11';
  if (port === 53 || port === 88 || port === 389 || port === 636) return 'CS3';
  return 'BE';
}

function dscpValueToClass(val: number): string {
  const map: Record<number, string> = {
    0: 'BE', 8: 'CS1', 10: 'AF11', 12: 'AF12', 14: 'AF13',
    16: 'CS2', 18: 'AF21', 20: 'AF22', 22: 'AF23', 24: 'CS3',
    26: 'AF31', 28: 'AF32', 30: 'AF33', 32: 'CS4', 34: 'AF41',
    36: 'AF42', 38: 'AF43', 40: 'CS5', 46: 'EF', 48: 'CS6', 56: 'CS7',
  };
  return map[val] || `Unknown(${val})`;
}
