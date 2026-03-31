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
  MessageSquare,
} from 'lucide-react';
import type { ComparisonReport, Discrepancy, FlowComparisonSummary, ForensicSummary } from '../types';
import { getAuthToken } from '../api/client';
import FlowGraphView from './FlowGraphView';
import { EducationalLegend, InfoTooltip, METRIC_TOOLTIPS, getDiscrepancyAnalysis } from './ComparisonEducational';
import { DiscrepancyDeepDive } from './DiscrepancyDeepDive';
import { InvestigationChecklist } from './InvestigationChecklist';
import { PacketDissector } from './PacketDissector';
import { StreamConversation } from './StreamConversation';
import { FilterBuilderEducator } from './FilterBuilderEducator';
import { GuidedTroubleshooting } from './GuidedTroubleshooting';

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

      {/* Educational Legend */}
      <EducationalLegend />

      {/* Investigation Checklist */}
      <InvestigationChecklist report={report} />

      {/* Filter Builder & Explainer */}
      <FilterBuilderEducator discrepancies={report.discrepancies} />

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
            <Stat label="Packets A (LAN)" value={report.total_packets_a.toLocaleString()} tooltip={METRIC_TOOLTIPS.packetsA} />
            <Stat label="Packets B (WAN)" value={report.total_packets_b.toLocaleString()} tooltip={METRIC_TOOLTIPS.packetsB} />
            <Stat label="Matched" value={report.matched_count.toLocaleString()} color="text-green-400" tooltip={METRIC_TOOLTIPS.matched} />
            <Stat label="Dropped" value={report.missing_b_count.toLocaleString()} color={report.missing_b_count > 0 ? 'text-red-400' : undefined} tooltip={METRIC_TOOLTIPS.dropped} />
          </div>
        </div>
      </div>

      {/* Summary Cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <SummaryCard icon={<CheckCircle className="w-5 h-5 text-green-400" />} label="Matched" value={report.matched_count} color="green" tooltip={METRIC_TOOLTIPS.matched} />
        <SummaryCard icon={<XCircle className="w-5 h-5 text-red-400" />} label="Dropped (B)" value={report.missing_b_count} color="red" tooltip={METRIC_TOOLTIPS.dropped} />
        <SummaryCard icon={<AlertTriangle className="w-5 h-5 text-yellow-400" />} label="Modified" value={report.modified_count} color="yellow" tooltip={METRIC_TOOLTIPS.modified} />
        <SummaryCard icon={<Activity className="w-5 h-5 text-purple-400" />} label="Asymmetric (A)" value={report.missing_a_count} color="purple" tooltip={METRIC_TOOLTIPS.asymmetric} />
      </div>

      {/* Additional Metrics Row */}
      {(report.verified_encrypted_count > 0 || report.ignored_control_plane_count > 0 || report.policy_drop_count > 0) && (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          {report.verified_encrypted_count > 0 && (
            <SummaryCard icon={<Lock className="w-5 h-5 text-cyan-400" />} label="Verified Encrypted" value={report.verified_encrypted_count} color="cyan" tooltip={METRIC_TOOLTIPS.verifiedEncrypted} />
          )}
          {report.policy_drop_count > 0 && (
            <SummaryCard icon={<XCircle className="w-5 h-5 text-red-400" />} label="Policy Drops" value={report.policy_drop_count} color="red" tooltip={METRIC_TOOLTIPS.policyDrop} />
          )}
          {report.ignored_control_plane_count > 0 && (
            <SummaryCard icon={<Activity className="w-5 h-5 text-slate-400" />} label="Control Plane" value={report.ignored_control_plane_count} color="slate" tooltip={METRIC_TOOLTIPS.controlPlane} />
          )}
          {(report.ignored_local_count + report.ignored_mgmt_count + report.ignored_routing_count + report.ignored_local_lan_count) > 0 && (
            <SummaryCard icon={<AlertTriangle className="w-5 h-5 text-yellow-400" />} label="Noise Excluded" value={report.ignored_local_count + report.ignored_mgmt_count + report.ignored_routing_count + report.ignored_local_lan_count} color="yellow" tooltip={METRIC_TOOLTIPS.noiseTraffic} />
          )}
        </div>
      )}

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
      {activeTab === 'summary' && <GuidedTroubleshooting report={report} onSwitchTab={(tab) => setActiveTab(tab as 'summary' | 'flows' | 'discrepancies')} />}
      {activeTab === 'flows' && (
        <FlowsTab
          flows={report.flow_summaries}
          expandedFlows={expandedFlows}
          onToggleFlow={toggleFlow}
          onVisualize={setVisualizeFlow}
          allDiscrepancies={report.discrepancies}
          forensics={report.forensics}
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
          allDiscrepancies={report.discrepancies}
          forensics={report.forensics}
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

function Stat({ label, value, color, tooltip }: { label: string; value: string; color?: string; tooltip?: string }) {
  return (
    <div>
      <div className="text-xs text-slate-500 flex items-center justify-end gap-0.5">
        {label}
        {tooltip && <InfoTooltip text={tooltip} />}
      </div>
      <div className={`text-sm font-medium ${color || 'text-white'}`}>{value}</div>
    </div>
  );
}

function SummaryCard({ icon, label, value, color, tooltip }: { icon: React.ReactNode; label: string; value: number; color: string; tooltip?: string }) {
  const bgMap: Record<string, string> = {
    green: 'bg-green-500/10 border-green-500/20',
    red: 'bg-red-500/10 border-red-500/20',
    yellow: 'bg-yellow-500/10 border-yellow-500/20',
    purple: 'bg-purple-500/10 border-purple-500/20',
    cyan: 'bg-cyan-500/10 border-cyan-500/20',
    slate: 'bg-slate-500/10 border-slate-500/20',
  };
  return (
    <div className={`${bgMap[color] || ''} border rounded-lg p-4`}>
      <div className="flex items-center gap-2 mb-2">
        {icon}
        <span className="text-xs text-slate-400">{label}</span>
        {tooltip && <InfoTooltip text={tooltip} />}
      </div>
      <div className="text-2xl font-bold text-white">{value.toLocaleString()}</div>
    </div>
  );
}

function FlowsTab({ flows, expandedFlows, onToggleFlow, onVisualize, allDiscrepancies, forensics }: {
  flows: FlowComparisonSummary[];
  expandedFlows: Set<number>;
  onToggleFlow: (idx: number) => void;
  onVisualize: (flow: FlowComparisonSummary) => void;
  allDiscrepancies: Discrepancy[];
  forensics?: ForensicSummary;
}) {
  const [conversationFlow, setConversationFlow] = useState<FlowComparisonSummary | null>(null);

  return (
    <div>
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
              <th className="px-3 py-2.5 text-center text-slate-500 font-medium w-20">Actions</th>
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
                      <div className="flex items-center justify-center gap-1">
                        <button
                          onClick={e => { e.stopPropagation(); onVisualize(f); }}
                          className="px-2 py-1 text-[10px] font-medium rounded bg-blue-600/20 text-blue-400 hover:bg-blue-600/40 transition-colors"
                          title="Open sequence diagram"
                        >
                          Flow Graph
                        </button>
                        <button
                          onClick={e => { e.stopPropagation(); setConversationFlow(f); }}
                          className="px-2 py-1 text-[10px] font-medium rounded bg-green-600/20 text-green-400 hover:bg-green-600/40 transition-colors flex items-center gap-1"
                          title="Follow Stream — View as conversation"
                        >
                          <MessageSquare className="w-3 h-3" />
                          Follow
                        </button>
                      </div>
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

      {/* Stream Conversation Modal */}
      {conversationFlow && (
        <StreamConversation
          allDiscrepancies={allDiscrepancies}
          flow={conversationFlow}
          forensics={forensics}
          onClose={() => setConversationFlow(null)}
        />
      )}
    </div>
  );
}

function DiscrepanciesTab({ discrepancies, filter, onFilterChange, total, allDiscrepancies, forensics }: {
  discrepancies: Discrepancy[];
  filter: string;
  onFilterChange: (f: string) => void;
  total: number;
  allDiscrepancies: Discrepancy[];
  forensics?: ForensicSummary;
}) {
  const [expandedRows, setExpandedRows] = useState<Set<number>>(new Set());
  const [deepDiveDiscrepancy, setDeepDiveDiscrepancy] = useState<Discrepancy | null>(null);
  const [dissectorDiscrepancy, setDissectorDiscrepancy] = useState<Discrepancy | null>(null);
  const [conversationFlow, setConversationFlow] = useState<FlowComparisonSummary | null>(null);

  const toggleRow = (idx: number) => {
    setExpandedRows(prev => {
      const next = new Set(prev);
      if (next.has(idx)) next.delete(idx);
      else next.add(idx);
      return next;
    });
  };

  const stateColors: Record<string, string> = {
    MISSING_B: 'bg-red-500/20 text-red-400',
    MISSING_A: 'bg-purple-500/20 text-purple-400',
    MODIFIED: 'bg-yellow-500/20 text-yellow-400',
  };

  const severityBg: Record<string, string> = {
    critical: 'bg-red-900/30 border-red-700/40',
    warning: 'bg-yellow-900/30 border-yellow-700/40',
    info: 'bg-slate-800/60 border-slate-600/40',
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
          <thead className="sticky top-0 bg-slate-800 z-10">
            <tr className="border-b border-slate-700/50">
              <th className="px-3 py-2.5 text-left text-slate-500 font-medium">State</th>
              <th className="px-3 py-2.5 text-left text-slate-500 font-medium">#</th>
              <th className="px-3 py-2.5 text-left text-slate-500 font-medium">Time</th>
              <th className="px-3 py-2.5 text-left text-slate-500 font-medium">Flow</th>
              <th className="px-3 py-2.5 text-left text-slate-500 font-medium">Detail</th>
              <th className="px-3 py-2.5 text-left text-slate-500 font-medium">
                Analysis
                <InfoTooltip text="Click any row to see a plain-English explanation of why this packet is flagged and what to check." />
              </th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-700/30">
            {discrepancies.slice(0, 500).map((d, i) => {
              const analysis = getDiscrepancyAnalysis(d);
              const isExpanded = expandedRows.has(i);
              return (
                <React.Fragment key={i}>
                  <tr className="hover:bg-slate-700/20 cursor-pointer" onClick={() => toggleRow(i)}>
                    <td className="px-3 py-2">
                      <span className={`px-1.5 py-0.5 rounded text-[10px] font-medium ${stateColors[d.state] || 'text-slate-400'}`}>
                        {d.state.replace('_', ' ')}
                      </span>
                    </td>
                    <td className="px-3 py-2">
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          setDissectorDiscrepancy(d);
                        }}
                        className="text-slate-500 hover:text-cyan-400 font-mono transition-colors underline decoration-dotted"
                        title="Open Packet Dissector"
                      >
                        {d.packet_index}
                      </button>
                    </td>
                    <td className="px-3 py-2 text-slate-400 font-mono">{d.timestamp}</td>
                    <td className="px-3 py-2 font-mono text-slate-300">
                      {d.src_ip}:{d.src_port}→{d.dst_ip}:{d.dst_port}
                      <span className="ml-1 text-slate-500">{d.protocol}</span>
                      {d.tcp_flags && <span className="ml-1 text-slate-600">[{d.tcp_flags}]</span>}
                    </td>
                    <td className="px-3 py-2 text-slate-400 max-w-[200px] truncate" title={d.detail}>{d.detail}</td>
                    <td className="px-3 py-2">
                      <div className="flex items-center gap-1.5">
                        {analysis.icon}
                        <span className="text-slate-300 truncate max-w-[140px]">{analysis.summary}</span>
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            setDeepDiveDiscrepancy(d);
                          }}
                          className="px-2 py-0.5 text-[10px] bg-blue-500/20 hover:bg-blue-500/30 text-blue-400 rounded transition-colors flex-shrink-0"
                          title="Open Forensic Coach Deep-Dive"
                        >
                          Deep Dive
                        </button>
                        {isExpanded
                          ? <ChevronUp className="w-3 h-3 text-slate-500 flex-shrink-0" />
                          : <ChevronDown className="w-3 h-3 text-slate-500 flex-shrink-0" />
                        }
                      </div>
                    </td>
                  </tr>
                  {isExpanded && (
                    <tr>
                      <td colSpan={6} className="px-0 py-0">
                        <div className={`mx-3 my-2 px-4 py-3 rounded-lg border ${severityBg[analysis.severity]}`}>
                          <div className="flex items-start gap-2">
                            <div className="mt-0.5 flex-shrink-0">{analysis.icon}</div>
                            <div>
                              <div className="text-xs font-semibold text-white mb-1">{analysis.summary}</div>
                              <p className="text-[11px] text-slate-400 leading-relaxed mb-2">{analysis.suggestion}</p>
                              {analysis.seniorTip && (
                                <div className="mt-2 pt-2 border-t border-slate-600/30">
                                  <div className="text-[10px] font-semibold text-yellow-400 mb-1">💡 Senior Engineer Tip:</div>
                                  <p className="text-[11px] text-slate-400 leading-relaxed">{analysis.seniorTip}</p>
                                </div>
                              )}
                              {d.field_changes && d.field_changes.length > 0 && (
                                <div className="mt-2 flex flex-wrap gap-2">
                                  {d.field_changes.map((fc, j) => (
                                    <span key={j} className="px-2 py-0.5 text-[10px] bg-yellow-500/10 text-yellow-400 rounded border border-yellow-500/20">
                                      {fc.field}: {fc.value_a} → {fc.value_b}
                                    </span>
                                  ))}
                                </div>
                              )}
                              {/* Follow Stream Button */}
                              <button
                                onClick={() => setConversationFlow({
                                  src_ip: d.src_ip, dst_ip: d.dst_ip,
                                  src_port: d.src_port, dst_port: d.dst_port,
                                  protocol: d.protocol,
                                  packets_a: 0, packets_b: 0, matched: 0,
                                  missing_b: 0, missing_a: 0, modified: 0,
                                  match_rate: 0, has_nat: false, encapsulated: false,
                                })}
                                className="mt-2 px-3 py-1.5 text-[10px] font-medium rounded bg-green-600/20 text-green-400 hover:bg-green-600/40 transition-colors inline-flex items-center gap-1.5"
                              >
                                <MessageSquare className="w-3 h-3" />
                                Follow This Stream — View Full Conversation
                              </button>
                            </div>
                          </div>
                        </div>
                      </td>
                    </tr>
                  )}
                </React.Fragment>
              );
            })}
          </tbody>
        </table>
        {discrepancies.length > 500 && (
          <div className="px-4 py-2 text-xs text-slate-500 bg-slate-800 border-t border-slate-700/50">
            Showing first 500 of {discrepancies.length} discrepancies
          </div>
        )}
      </div>

      {/* Deep Dive Modal */}
      {deepDiveDiscrepancy && (
        <DiscrepancyDeepDive
          discrepancy={deepDiveDiscrepancy}
          onClose={() => setDeepDiveDiscrepancy(null)}
        />
      )}

      {/* Packet Dissector Modal */}
      {dissectorDiscrepancy && (
        <PacketDissector
          discrepancy={dissectorDiscrepancy}
          onClose={() => setDissectorDiscrepancy(null)}
        />
      )}

      {/* Stream Conversation Modal */}
      {conversationFlow && (
        <StreamConversation
          allDiscrepancies={allDiscrepancies}
          flow={conversationFlow}
          forensics={forensics}
          onClose={() => setConversationFlow(null)}
        />
      )}
    </div>
  );
}

export default ComparisonView;
