import React, { useState, useCallback } from 'react';
import {
  Upload,
  ArrowRightLeft,
  AlertTriangle,
  CheckCircle,
  XCircle,
  ChevronDown,
  ChevronUp,
  Shield,
  Activity,
  Loader2,
  Lock,
  Layers,
} from 'lucide-react';
import type { ComparisonReport, Discrepancy, FlowComparisonSummary } from '../types';
import { getAuthToken } from '../api/client';
import FlowGraphView from './FlowGraphView';

interface ComparisonViewProps {
  onClose?: () => void;
}

const ComparisonView: React.FC<ComparisonViewProps> = ({ onClose }) => {
  const [fileA, setFileA] = useState<File | null>(null);
  const [fileB, setFileB] = useState<File | null>(null);
  const [report, setReport] = useState<ComparisonReport | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<'summary' | 'flows' | 'discrepancies'>('summary');
  const [discrepancyFilter, setDiscrepancyFilter] = useState<string>('all');
  const [expandedFlows, setExpandedFlows] = useState<Set<number>>(new Set());
  const [visualizeFlow, setVisualizeFlow] = useState<FlowComparisonSummary | null>(null);

  const handleCompare = useCallback(async () => {
    if (!fileA || !fileB) return;

    setLoading(true);
    setError(null);
    setReport(null);

    try {
      const formData = new FormData();
      formData.append('file_a', fileA);
      formData.append('file_b', fileB);

      const token = getAuthToken();
      const response = await fetch('/api/compare-pcap', {
        method: 'POST',
        headers: token ? { Authorization: `Bearer ${token}` } : {},
        body: formData,
      });

      if (!response.ok) {
        const errData = await response.json().catch(() => ({ error: 'Comparison failed' }));
        throw new Error(errData.error || `HTTP ${response.status}`);
      }

      const data: ComparisonReport = await response.json();
      setReport(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Unknown error');
    } finally {
      setLoading(false);
    }
  }, [fileA, fileB]);

  const toggleFlow = (idx: number) => {
    setExpandedFlows(prev => {
      const next = new Set(prev);
      if (next.has(idx)) next.delete(idx);
      else next.add(idx);
      return next;
    });
  };

  const filteredDiscrepancies = report?.discrepancies.filter(d =>
    discrepancyFilter === 'all' || d.state === discrepancyFilter
  ) ?? [];

  // ── Upload Section ────────────────────────────────────────────
  if (!report) {
    return (
      <div className="max-w-3xl mx-auto">
        <div className="bg-slate-800/80 border border-slate-700/50 rounded-xl p-8">
          <div className="flex items-center gap-3 mb-6">
            <ArrowRightLeft className="w-6 h-6 text-blue-400" />
            <h2 className="text-xl font-bold text-white">PCAP Comparison Mode</h2>
          </div>
          <p className="text-slate-400 text-sm mb-6">
            Compare a LAN-side and WAN-side capture to find where packets are dropped, modified (NAT/QoS), or injected.
          </p>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-6">
            <FileDropZone
              label="File A — LAN Side"
              sublabel="Capture taken before the SD-WAN device"
              file={fileA}
              onFileSelect={setFileA}
              accentColor="blue"
            />
            <FileDropZone
              label="File B — WAN Side"
              sublabel="Capture taken after the SD-WAN device"
              file={fileB}
              onFileSelect={setFileB}
              accentColor="purple"
            />
          </div>

          {error && (
            <div className="bg-red-900/30 border border-red-700 rounded-lg p-4 mb-4 text-red-400 text-sm">
              {error}
            </div>
          )}

          <button
            onClick={handleCompare}
            disabled={!fileA || !fileB || loading}
            className="w-full flex items-center justify-center gap-2 px-6 py-3 rounded-lg font-medium transition-all disabled:opacity-40 disabled:cursor-not-allowed bg-gradient-to-r from-blue-600 to-purple-600 text-white hover:from-blue-500 hover:to-purple-500 shadow-lg shadow-blue-500/20"
          >
            {loading ? (
              <>
                <Loader2 className="w-5 h-5 animate-spin" />
                Comparing packets...
              </>
            ) : (
              <>
                <ArrowRightLeft className="w-5 h-5" />
                Compare Captures
              </>
            )}
          </button>
        </div>
      </div>
    );
  }

  // ── Results Section ───────────────────────────────────────────
  const scoreColor =
    report.path_integrity_score >= 95 ? 'text-green-400' :
    report.path_integrity_score >= 80 ? 'text-yellow-400' :
    report.path_integrity_score >= 50 ? 'text-orange-400' :
    'text-red-400';

  const scoreBg =
    report.path_integrity_score >= 95 ? 'from-green-600/20 to-green-900/10 border-green-500/30' :
    report.path_integrity_score >= 80 ? 'from-yellow-600/20 to-yellow-900/10 border-yellow-500/30' :
    report.path_integrity_score >= 50 ? 'from-orange-600/20 to-orange-900/10 border-orange-500/30' :
    'from-red-600/20 to-red-900/10 border-red-500/30';

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <ArrowRightLeft className="w-6 h-6 text-blue-400" />
          <div>
            <h2 className="text-xl font-bold text-white">PCAP Comparison Results</h2>
            <p className="text-sm text-slate-400 mt-0.5">
              {report.file_a} vs {report.file_b}
            </p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => { setReport(null); setFileA(null); setFileB(null); }}
            className="px-3 py-1.5 text-sm rounded-lg bg-slate-700 hover:bg-slate-600 text-slate-300 transition-colors"
          >
            New Comparison
          </button>
          {onClose && (
            <button onClick={onClose} className="px-3 py-1.5 text-sm rounded-lg bg-slate-700 hover:bg-slate-600 text-slate-300 transition-colors">
              Close
            </button>
          )}
        </div>
      </div>

      {/* Path Integrity Score Banner */}
      <div className={`bg-gradient-to-r ${scoreBg} border rounded-xl p-6`}>
        <div className="flex items-center justify-between">
          <div>
            <div className="flex items-center gap-2 mb-1">
              <Shield className="w-5 h-5 text-slate-400" />
              <span className="text-sm font-medium text-slate-400 uppercase tracking-wider">Path Integrity Score</span>
            </div>
            <div className="flex items-baseline gap-2">
              <span className={`text-4xl font-bold ${scoreColor}`}>
                {report.path_integrity_score.toFixed(1)}%
              </span>
              <span className={`text-lg font-medium ${scoreColor}`}>
                {report.integrity_rating}
              </span>
            </div>
          </div>
          <div className="grid grid-cols-2 gap-x-8 gap-y-2 text-right">
            <Stat label="Packets A (LAN)" value={report.total_packets_a.toLocaleString()} />
            <Stat label="Packets B (WAN)" value={report.total_packets_b.toLocaleString()} />
            <Stat label="Matched" value={report.matched_count.toLocaleString()} color="text-green-400" />
            <Stat label="Dropped" value={report.missing_b_count.toLocaleString()} color={report.missing_b_count > 0 ? 'text-red-400' : undefined} />
          </div>
        </div>
      </div>

      {/* Summary Cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <SummaryCard icon={<CheckCircle className="w-5 h-5 text-green-400" />} label="Matched" value={report.matched_count} color="green" />
        <SummaryCard icon={<XCircle className="w-5 h-5 text-red-400" />} label="Dropped (B)" value={report.missing_b_count} color="red" />
        <SummaryCard icon={<AlertTriangle className="w-5 h-5 text-yellow-400" />} label="Modified" value={report.modified_count} color="yellow" />
        <SummaryCard icon={<Activity className="w-5 h-5 text-purple-400" />} label="Asymmetric (A)" value={report.missing_a_count} color="purple" />
      </div>

      {/* Tunnel Encapsulation Banner */}
      {report.tunnel_detected && (
        <div className="bg-cyan-900/20 border border-cyan-700/40 rounded-xl p-5">
          <div className="flex items-center gap-2 mb-3">
            <Layers className="w-5 h-5 text-cyan-400" />
            <span className="text-sm font-medium text-cyan-400 uppercase tracking-wider">SD-WAN Tunnel Encapsulation Detected</span>
          </div>
          <div className="flex flex-wrap gap-3 mb-3">
            {report.tunnel_types?.map(t => (
              <span key={t} className="px-2.5 py-1 text-xs font-medium bg-cyan-500/15 text-cyan-300 rounded-lg border border-cyan-500/20">
                {t}: {report.tunnel_breakdown?.[t] ?? 0} packets
              </span>
            ))}
          </div>
          <div className="flex flex-wrap gap-4 text-xs">
            <span className="text-slate-400">
              Decapsulated (inner extracted): <span className="text-cyan-300 font-medium">{report.encapsulated_count - report.encrypted_count}</span>
            </span>
            {report.encrypted_count > 0 && (
              <span className="flex items-center gap-1.5 text-yellow-400">
                <Lock className="w-3.5 h-3.5" />
                {report.encrypted_count} packets encrypted — inner flow hidden by encryption. Matching based on outer header correlation.
              </span>
            )}
          </div>
        </div>
      )}

      {/* Modification Alerts */}
      {(report.nat_detected || report.dscp_changes > 0) && (
        <div className="bg-yellow-900/20 border border-yellow-700/40 rounded-lg p-4 flex flex-wrap gap-4">
          {report.nat_detected && (
            <span className="flex items-center gap-2 text-sm text-yellow-400">
              <AlertTriangle className="w-4 h-4" />
              NAT Translation Detected
            </span>
          )}
          {report.ttl_changes > 0 && (
            <span className="text-sm text-slate-400">TTL changes: {report.ttl_changes}</span>
          )}
          {report.dscp_changes > 0 && (
            <span className="flex items-center gap-2 text-sm text-yellow-400">
              <AlertTriangle className="w-4 h-4" />
              QoS Remarking: {report.dscp_changes} packets
            </span>
          )}
        </div>
      )}

      {/* Tabs */}
      <div className="border-b border-slate-700">
        <div className="flex gap-1">
          {(['summary', 'flows', 'discrepancies'] as const).map(tab => (
            <button
              key={tab}
              onClick={() => setActiveTab(tab)}
              className={`px-4 py-2.5 text-sm font-medium border-b-2 transition-colors capitalize ${
                activeTab === tab
                  ? 'border-blue-500 text-blue-400'
                  : 'border-transparent text-slate-500 hover:text-slate-300'
              }`}
            >
              {tab}
              {tab === 'discrepancies' && report.discrepancies.length > 0 && (
                <span className="ml-2 px-1.5 py-0.5 text-xs rounded-full bg-red-500/20 text-red-400">
                  {report.discrepancies.length}
                </span>
              )}
            </button>
          ))}
        </div>
      </div>

      {/* Tab Content */}
      {activeTab === 'summary' && <SummaryTab report={report} />}
      {activeTab === 'flows' && (
        <FlowsTab
          flows={report.flow_summaries}
          expandedFlows={expandedFlows}
          onToggleFlow={toggleFlow}
          onVisualize={setVisualizeFlow}
        />
      )}

      {/* Flow Sequence Diagram Modal */}
      {visualizeFlow && (
        <FlowGraphView
          flow={visualizeFlow}
          discrepancies={report.discrepancies}
          onClose={() => setVisualizeFlow(null)}
        />
      )}
      {activeTab === 'discrepancies' && (
        <DiscrepanciesTab
          discrepancies={filteredDiscrepancies}
          filter={discrepancyFilter}
          onFilterChange={setDiscrepancyFilter}
          total={report.discrepancies.length}
        />
      )}
    </div>
  );
};

// ─── Sub-Components ─────────────────────────────────────────────

function FileDropZone({ label, sublabel, file, onFileSelect, accentColor }: {
  label: string;
  sublabel: string;
  file: File | null;
  onFileSelect: (f: File) => void;
  accentColor: string;
}) {
  const borderColor = accentColor === 'blue' ? 'border-blue-500/30 hover:border-blue-500/60' : 'border-purple-500/30 hover:border-purple-500/60';
  const iconColor = accentColor === 'blue' ? 'text-blue-400' : 'text-purple-400';

  return (
    <label className={`block border-2 border-dashed ${borderColor} rounded-xl p-6 cursor-pointer transition-colors text-center`}>
      <Upload className={`w-8 h-8 mx-auto mb-3 ${iconColor}`} />
      <span className="block text-sm font-medium text-white">{label}</span>
      <span className="block text-xs text-slate-500 mt-1">{sublabel}</span>
      {file ? (
        <span className="block text-xs text-green-400 mt-2 truncate">{file.name} ({(file.size / 1024 / 1024).toFixed(1)} MB)</span>
      ) : (
        <span className="block text-xs text-slate-600 mt-2">.pcap / .pcapng / .cap</span>
      )}
      <input
        type="file"
        accept=".pcap,.pcapng,.cap"
        className="hidden"
        onChange={e => {
          const f = e.target.files?.[0];
          if (f) onFileSelect(f);
        }}
      />
    </label>
  );
}

function Stat({ label, value, color }: { label: string; value: string; color?: string }) {
  return (
    <div>
      <div className="text-xs text-slate-500">{label}</div>
      <div className={`text-sm font-medium ${color || 'text-white'}`}>{value}</div>
    </div>
  );
}

function SummaryCard({ icon, label, value, color }: { icon: React.ReactNode; label: string; value: number; color: string }) {
  const bgMap: Record<string, string> = {
    green: 'bg-green-500/10 border-green-500/20',
    red: 'bg-red-500/10 border-red-500/20',
    yellow: 'bg-yellow-500/10 border-yellow-500/20',
    purple: 'bg-purple-500/10 border-purple-500/20',
  };
  return (
    <div className={`${bgMap[color] || ''} border rounded-lg p-4`}>
      <div className="flex items-center gap-2 mb-2">{icon}<span className="text-xs text-slate-400">{label}</span></div>
      <div className="text-2xl font-bold text-white">{value.toLocaleString()}</div>
    </div>
  );
}

function SummaryTab({ report }: { report: ComparisonReport }) {
  const total = report.matched_count + report.missing_b_count + report.missing_a_count + report.modified_count;
  const pctMatch = total > 0 ? (report.matched_count / total * 100) : 0;
  const pctDrop = total > 0 ? (report.missing_b_count / total * 100) : 0;
  const pctModified = total > 0 ? (report.modified_count / total * 100) : 0;
  const pctAsym = total > 0 ? (report.missing_a_count / total * 100) : 0;

  return (
    <div className="space-y-4">
      {/* Stacked bar */}
      <div className="bg-slate-800/80 rounded-xl p-6 border border-slate-700/50">
        <h3 className="text-sm font-medium text-slate-400 mb-4">Packet Distribution</h3>
        <div className="h-6 rounded-full overflow-hidden flex bg-slate-900">
          {pctMatch > 0 && <div className="bg-green-500 transition-all" style={{ width: `${pctMatch}%` }} title={`Matched: ${pctMatch.toFixed(1)}%`} />}
          {pctModified > 0 && <div className="bg-yellow-500 transition-all" style={{ width: `${pctModified}%` }} title={`Modified: ${pctModified.toFixed(1)}%`} />}
          {pctDrop > 0 && <div className="bg-red-500 transition-all" style={{ width: `${pctDrop}%` }} title={`Dropped: ${pctDrop.toFixed(1)}%`} />}
          {pctAsym > 0 && <div className="bg-purple-500 transition-all" style={{ width: `${pctAsym}%` }} title={`Asymmetric: ${pctAsym.toFixed(1)}%`} />}
        </div>
        <div className="flex gap-6 mt-3 text-xs">
          <span className="flex items-center gap-1.5"><span className="w-2.5 h-2.5 rounded-full bg-green-500" />Matched {pctMatch.toFixed(1)}%</span>
          <span className="flex items-center gap-1.5"><span className="w-2.5 h-2.5 rounded-full bg-yellow-500" />Modified {pctModified.toFixed(1)}%</span>
          <span className="flex items-center gap-1.5"><span className="w-2.5 h-2.5 rounded-full bg-red-500" />Dropped {pctDrop.toFixed(1)}%</span>
          <span className="flex items-center gap-1.5"><span className="w-2.5 h-2.5 rounded-full bg-purple-500" />Asymmetric {pctAsym.toFixed(1)}%</span>
        </div>
      </div>

      {/* Worst flows */}
      {report.flow_summaries.length > 0 && (
        <div className="bg-slate-800/80 rounded-xl p-6 border border-slate-700/50">
          <h3 className="text-sm font-medium text-slate-400 mb-4">Worst Flows by Match Rate</h3>
          <div className="space-y-2">
            {report.flow_summaries.slice(0, 5).map((f, i) => (
              <div key={i} className="flex items-center gap-3">
                <span className="font-mono text-xs text-slate-400 w-64 truncate">
                  {f.src_ip}:{f.src_port}→{f.dst_ip}:{f.dst_port}/{f.protocol}
                </span>
                <div className="flex-1 h-2 rounded-full bg-slate-900 overflow-hidden">
                  <div
                    className={`h-full rounded-full ${f.match_rate >= 0.95 ? 'bg-green-500' : f.match_rate >= 0.5 ? 'bg-yellow-500' : 'bg-red-500'}`}
                    style={{ width: `${f.match_rate * 100}%` }}
                  />
                </div>
                <span className={`text-xs font-medium w-12 text-right ${
                  f.match_rate >= 0.95 ? 'text-green-400' : f.match_rate >= 0.5 ? 'text-yellow-400' : 'text-red-400'
                }`}>
                  {(f.match_rate * 100).toFixed(0)}%
                </span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

function FlowsTab({ flows, expandedFlows, onToggleFlow, onVisualize }: {
  flows: FlowComparisonSummary[];
  expandedFlows: Set<number>;
  onToggleFlow: (idx: number) => void;
  onVisualize: (flow: FlowComparisonSummary) => void;
}) {
  return (
    <div className="bg-slate-800/80 rounded-xl border border-slate-700/50 overflow-hidden">
      <table className="w-full text-xs">
        <thead>
          <tr className="border-b border-slate-700/50">
            <th className="px-3 py-2.5 text-left text-slate-500 font-medium">Flow</th>
            <th className="px-3 py-2.5 text-right text-slate-500 font-medium">Pkts A</th>
            <th className="px-3 py-2.5 text-right text-slate-500 font-medium">Pkts B</th>
            <th className="px-3 py-2.5 text-right text-slate-500 font-medium">Match</th>
            <th className="px-3 py-2.5 text-right text-slate-500 font-medium">Drop</th>
            <th className="px-3 py-2.5 text-right text-slate-500 font-medium">Rate</th>
            <th className="px-3 py-2.5 text-center text-slate-500 font-medium w-20">Visualize</th>
            <th className="px-3 py-2.5 text-center text-slate-500 font-medium w-8" />
          </tr>
        </thead>
        <tbody className="divide-y divide-slate-700/30">
          {flows.map((f, i) => {
            const expanded = expandedFlows.has(i);
            const rateColor = f.match_rate >= 0.95 ? 'text-green-400' : f.match_rate >= 0.5 ? 'text-yellow-400' : 'text-red-400';
            return (
              <React.Fragment key={i}>
                <tr className="hover:bg-slate-700/20 cursor-pointer" onClick={() => onToggleFlow(i)}>
                  <td className="px-3 py-2 font-mono text-slate-300">
                    {f.src_ip}:{f.src_port} → {f.dst_ip}:{f.dst_port}
                    <span className="ml-2 text-slate-500">{f.protocol}</span>
                    {f.has_nat && <span className="ml-2 px-1.5 py-0.5 text-[10px] bg-yellow-500/20 text-yellow-400 rounded">NAT</span>}
                    {f.encapsulated && <span className="ml-1 px-1.5 py-0.5 text-[10px] bg-cyan-500/20 text-cyan-400 rounded">{f.tunnel_type || 'Tunnel'}</span>}
                  </td>
                  <td className="px-3 py-2 text-right text-slate-400">{f.packets_a}</td>
                  <td className="px-3 py-2 text-right text-slate-400">{f.packets_b}</td>
                  <td className="px-3 py-2 text-right text-green-400">{f.matched}</td>
                  <td className="px-3 py-2 text-right text-red-400">{f.missing_b}</td>
                  <td className={`px-3 py-2 text-right font-medium ${rateColor}`}>{(f.match_rate * 100).toFixed(0)}%</td>
                  <td className="px-3 py-2 text-center">
                    <button
                      onClick={e => { e.stopPropagation(); onVisualize(f); }}
                      className="px-2 py-1 text-[10px] font-medium rounded bg-blue-600/20 text-blue-400 hover:bg-blue-600/40 transition-colors"
                      title="Open sequence diagram"
                    >
                      Flow Graph
                    </button>
                  </td>
                  <td className="px-3 py-2 text-center text-slate-500">
                    {expanded ? <ChevronUp className="w-3.5 h-3.5 inline" /> : <ChevronDown className="w-3.5 h-3.5 inline" />}
                  </td>
                </tr>
                {expanded && (
                  <tr>
                    <td colSpan={8} className="px-6 py-3 bg-slate-900/50">
                      <div className="grid grid-cols-3 gap-4 text-xs">
                        <div><span className="text-slate-500">Missing from WAN:</span> <span className="text-red-400">{f.missing_b}</span></div>
                        <div><span className="text-slate-500">Missing from LAN:</span> <span className="text-purple-400">{f.missing_a}</span></div>
                        <div><span className="text-slate-500">Modified:</span> <span className="text-yellow-400">{f.modified}</span></div>
                      </div>
                    </td>
                  </tr>
                )}
              </React.Fragment>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

function DiscrepanciesTab({ discrepancies, filter, onFilterChange, total }: {
  discrepancies: Discrepancy[];
  filter: string;
  onFilterChange: (f: string) => void;
  total: number;
}) {
  const stateColors: Record<string, string> = {
    MISSING_B: 'bg-red-500/20 text-red-400',
    MISSING_A: 'bg-purple-500/20 text-purple-400',
    MODIFIED: 'bg-yellow-500/20 text-yellow-400',
  };

  return (
    <div className="space-y-4">
      {/* Filter bar */}
      <div className="flex items-center gap-2">
        <span className="text-xs text-slate-500">Filter:</span>
        {['all', 'MISSING_B', 'MISSING_A', 'MODIFIED'].map(f => (
          <button
            key={f}
            onClick={() => onFilterChange(f)}
            className={`px-2.5 py-1 text-xs rounded-lg transition-colors ${
              filter === f
                ? 'bg-blue-600 text-white'
                : 'bg-slate-700 text-slate-400 hover:bg-slate-600'
            }`}
          >
            {f === 'all' ? `All (${total})` : f.replace('_', ' ')}
          </button>
        ))}
      </div>

      {/* Discrepancy list */}
      <div className="bg-slate-800/80 rounded-xl border border-slate-700/50 overflow-hidden max-h-[600px] overflow-y-auto">
        <table className="w-full text-xs">
          <thead className="sticky top-0 bg-slate-800">
            <tr className="border-b border-slate-700/50">
              <th className="px-3 py-2.5 text-left text-slate-500 font-medium">State</th>
              <th className="px-3 py-2.5 text-left text-slate-500 font-medium">#</th>
              <th className="px-3 py-2.5 text-left text-slate-500 font-medium">Time</th>
              <th className="px-3 py-2.5 text-left text-slate-500 font-medium">Flow</th>
              <th className="px-3 py-2.5 text-left text-slate-500 font-medium">Detail</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-700/30">
            {discrepancies.slice(0, 500).map((d, i) => (
              <tr key={i} className="hover:bg-slate-700/20">
                <td className="px-3 py-2">
                  <span className={`px-1.5 py-0.5 rounded text-[10px] font-medium ${stateColors[d.state] || 'text-slate-400'}`}>
                    {d.state.replace('_', ' ')}
                  </span>
                </td>
                <td className="px-3 py-2 text-slate-500 font-mono">{d.packet_index}</td>
                <td className="px-3 py-2 text-slate-400 font-mono">{d.timestamp}</td>
                <td className="px-3 py-2 font-mono text-slate-300">
                  {d.src_ip}:{d.src_port}→{d.dst_ip}:{d.dst_port}
                  <span className="ml-1 text-slate-500">{d.protocol}</span>
                  {d.tcp_flags && <span className="ml-1 text-slate-600">[{d.tcp_flags}]</span>}
                </td>
                <td className="px-3 py-2 text-slate-400 max-w-xs truncate" title={d.detail}>{d.detail}</td>
              </tr>
            ))}
          </tbody>
        </table>
        {discrepancies.length > 500 && (
          <div className="px-4 py-2 text-xs text-slate-500 bg-slate-800 border-t border-slate-700/50">
            Showing first 500 of {discrepancies.length} discrepancies
          </div>
        )}
      </div>
    </div>
  );
}

export default ComparisonView;
