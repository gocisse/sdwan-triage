import React, { useState, useCallback, useRef, useEffect } from 'react';
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
  Key,
  X,
  Filter,
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
import { AnalysisBadges } from './AnalysisBadges';
import { FilterProvider } from './FilterContext';
import { GlobalContextMenuProvider, useContextMenu } from './GlobalContextMenu';
import { FilterAutocomplete } from './FilterAutocomplete';
import { useKeyboardNavigation, getPacketRowColor, PacketColorLegend } from './useKeyboardNavigation';
import { SamplePcapLoader, ChallengeMode, ChallengeModeToggle } from './SamplePcapLoader';
import { GlossaryProvider } from './Glossary';
import { ProtocolHierarchy } from './ProtocolHierarchy';
import { IOGraph } from './IOGraph';

interface ComparisonViewProps {
  onClose?: () => void;
}

// Sample PCAP type (matches SamplePcapLoader)
interface SamplePcap {
  id: string;
  name: string;
  filename: string;
  description: string;
  category: string;
  difficulty: 'beginner' | 'intermediate' | 'advanced';
  learningObjectives: string[];
  challenge: { question: string; hint: string; answer: string };
}

const ComparisonView: React.FC<ComparisonViewProps> = ({ onClose }) => {
  const [fileA, setFileA] = useState<File | null>(null);
  const [fileB, setFileB] = useState<File | null>(null);
  const [keyLogFile, setKeyLogFile] = useState<File | null>(null);
  const [report, setReport] = useState<ComparisonReport | null>(null);
  
  // Learning Platform State
  const [challengeModeEnabled, setChallengeModeEnabled] = useState(false);
  const [activeSample, setActiveSample] = useState<SamplePcap | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<'summary' | 'flows' | 'discrepancies' | 'hierarchy' | 'throughput'>('summary');
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
      if (keyLogFile) {
        formData.append('keylog', keyLogFile);
      }

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

  // Discrepancy filter supports both state-based ('all', 'MISSING_B', 'MISSING_A',
  // 'MODIFIED') and Wireshark-style analysis-flag filters ('retx', 'dup-ack',
  // 'zero-window', 'keep-alive'). Flag filters ignore the state.
  const filteredDiscrepancies = report?.discrepancies.filter(d => {
    switch (discrepancyFilter) {
      case 'all':
        return true;
      case 'retx':
        return !!d.is_retransmission;
      case 'dup-ack':
        return !!d.is_duplicate_ack;
      case 'zero-window':
        return !!d.is_zero_window;
      case 'keep-alive':
        return !!d.is_keep_alive;
      default:
        return d.state === discrepancyFilter;
    }
  }) ?? [];

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

          {/* Learning Platform Controls */}
          <div className="flex items-center justify-between mb-6 p-4 bg-slate-900/50 rounded-lg border border-slate-700/50">
            <SamplePcapLoader
              onLoadSample={(file, sample) => {
                setFileA(file);
                setActiveSample(sample);
              }}
            />
            <ChallengeModeToggle
              enabled={challengeModeEnabled}
              onChange={setChallengeModeEnabled}
            />
          </div>

          {/* Active Sample Info */}
          {activeSample && (
            <div className="mb-6 p-4 bg-purple-900/20 border border-purple-500/30 rounded-lg">
              <div className="flex items-center gap-2 mb-2">
                <span className="text-sm font-semibold text-purple-300">📚 Training Sample Loaded</span>
                <span className={`px-1.5 py-0.5 text-[9px] rounded ${
                  activeSample.difficulty === 'beginner' ? 'bg-green-500/20 text-green-400' :
                  activeSample.difficulty === 'intermediate' ? 'bg-yellow-500/20 text-yellow-400' :
                  'bg-red-500/20 text-red-400'
                }`}>
                  {activeSample.difficulty}
                </span>
              </div>
              <p className="text-sm text-purple-200">{activeSample.name}</p>
              <p className="text-xs text-purple-300/70 mt-1">{activeSample.description}</p>
            </div>
          )}

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

          {/* SSL Key Log File (Optional) for TLS Decryption */}
          <div className="mb-6">
            <KeyLogDropZone
              file={keyLogFile}
              onFileSelect={setKeyLogFile}
              onClear={() => setKeyLogFile(null)}
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
    // FilterProvider + GlobalContextMenuProvider + GlossaryProvider wrap the entire result
    // view so right-click actions anywhere inside can push clauses into
    // the FilterBuilder scratchpad, and glossary terms are clickable.
    <GlossaryProvider>
    <FilterProvider>
      <GlobalContextMenuProvider>
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
            onClick={() => { setReport(null); setFileA(null); setFileB(null); setActiveSample(null); }}
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

      {/* Challenge Mode Panel (Learning Platform) */}
      {activeSample && challengeModeEnabled && (
        <ChallengeMode
          sample={activeSample}
          onClose={() => setActiveSample(null)}
        />
      )}

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
          {([
              { key: 'summary' as const, label: 'Summary' },
              { key: 'flows' as const, label: 'Flows' },
              { key: 'discrepancies' as const, label: 'Discrepancies' },
              { key: 'hierarchy' as const, label: 'Protocol Hierarchy' },
              { key: 'throughput' as const, label: 'Throughput Graph' },
            ]).map(tab => (
            <button
              key={tab.key}
              onClick={() => setActiveTab(tab.key)}
              className={`px-4 py-2.5 text-sm font-medium border-b-2 transition-colors ${
                activeTab === tab.key
                  ? 'border-blue-500 text-blue-400'
                  : 'border-transparent text-slate-500 hover:text-slate-300'
              }`}
            >
              {tab.label}
              {tab.key === 'discrepancies' && report.discrepancies.length > 0 && (
                <span className="ml-2 px-1.5 py-0.5 text-xs rounded-full bg-red-500/20 text-red-400">
                  {report.discrepancies.length}
                </span>
              )}
            </button>
          ))}
        </div>
      </div>

      {/* Tab Content */}
      {activeTab === 'summary' && <GuidedTroubleshooting report={report} onSwitchTab={(tab) => setActiveTab(tab as 'summary' | 'flows' | 'discrepancies' | 'hierarchy' | 'throughput')} />}
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
      {activeTab === 'hierarchy' && (
        <ProtocolHierarchy
          discrepancies={report.discrepancies}
          flows={report.flow_summaries}
          totalPackets={report.total_packets_a + report.total_packets_b}
          totalBytes={report.discrepancies.reduce((sum, d) => sum + (d.length || 0), 0)}
        />
      )}
      {activeTab === 'throughput' && (
        <IOGraph
          discrepancies={report.discrepancies}
        />
      )}
    </div>
      </GlobalContextMenuProvider>
    </FilterProvider>
    </GlossaryProvider>
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

function KeyLogDropZone({ file, onFileSelect, onClear }: {
  file: File | null;
  onFileSelect: (f: File) => void;
  onClear: () => void;
}) {
  return (
    <div className="border border-dashed border-emerald-500/30 hover:border-emerald-500/50 rounded-lg p-4 transition-colors">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="p-2 bg-emerald-500/10 rounded-lg">
            <Key className="w-5 h-5 text-emerald-400" />
          </div>
          <div>
            <div className="text-sm font-medium text-white">SSL Key Log File <span className="text-slate-500 font-normal">(Optional)</span></div>
            <div className="text-xs text-slate-500">
              {file ? (
                <span className="text-emerald-400">{file.name}</span>
              ) : (
                'NSS Key Log format for TLS decryption'
              )}
            </div>
          </div>
        </div>
        <div className="flex items-center gap-2">
          {file && (
            <button
              onClick={onClear}
              className="p-1.5 text-slate-400 hover:text-red-400 transition-colors"
              title="Remove key log file"
            >
              <X className="w-4 h-4" />
            </button>
          )}
          <label className="px-3 py-1.5 text-xs font-medium bg-emerald-500/20 text-emerald-400 rounded-md cursor-pointer hover:bg-emerald-500/30 transition-colors">
            {file ? 'Change' : 'Browse'}
            <input
              type="file"
              accept=".log,.txt,.keys"
              className="hidden"
              onChange={e => {
                const f = e.target.files?.[0];
                if (f) onFileSelect(f);
              }}
            />
          </label>
        </div>
      </div>
    </div>
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
  
  // U1: Advanced filter with autocomplete
  const [advancedFilter, setAdvancedFilter] = useState('');
  const filterInputRef = useRef<HTMLInputElement>(null);
  
  // U3: Keyboard navigation
  const [selectedRowIndex, setSelectedRowIndex] = useState(-1);
  
  // C3: Stream filter for "Follow Stream" highlighting
  const [streamFilter, setStreamFilter] = useState<{ srcIp: string; dstIp: string; srcPort: number; dstPort: number; protocol: string } | null>(null);

  // Right-click menu hook — the provider is mounted at the top of
  // ComparisonView, so this is safe anywhere in the results tree.
  const { onContextMenu } = useContextMenu();

  // Filter discrepancies by stream if streamFilter is set (C3)
  const streamFilteredDiscrepancies = streamFilter
    ? discrepancies.filter(d =>
        ((d.src_ip === streamFilter.srcIp && d.dst_ip === streamFilter.dstIp &&
          d.src_port === streamFilter.srcPort && d.dst_port === streamFilter.dstPort) ||
         (d.src_ip === streamFilter.dstIp && d.dst_ip === streamFilter.srcIp &&
          d.src_port === streamFilter.dstPort && d.dst_port === streamFilter.srcPort)) &&
        d.protocol === streamFilter.protocol
      )
    : discrepancies;

  // Apply advanced filter (U1)
  const filteredByAdvanced = advancedFilter.trim()
    ? streamFilteredDiscrepancies.filter(d => {
        const filterLower = advancedFilter.toLowerCase();
        // Simple matching for now - can be extended with proper parser
        if (filterLower.includes('ip.src')) {
          const match = advancedFilter.match(/ip\.src\s*==\s*["']?([^"'\s]+)["']?/i);
          if (match && d.src_ip !== match[1]) return false;
        }
        if (filterLower.includes('ip.dst')) {
          const match = advancedFilter.match(/ip\.dst\s*==\s*["']?([^"'\s]+)["']?/i);
          if (match && d.dst_ip !== match[1]) return false;
        }
        if (filterLower.includes('tcp.port')) {
          const match = advancedFilter.match(/tcp\.port\s*==\s*(\d+)/i);
          if (match) {
            const port = parseInt(match[1]);
            if (d.src_port !== port && d.dst_port !== port) return false;
          }
        }
        if (filterLower.includes('tcp.flags')) {
          const match = advancedFilter.match(/tcp\.flags\s+contains\s+["']?(\w+)["']?/i);
          if (match && !d.tcp_flags?.toUpperCase().includes(match[1].toUpperCase())) return false;
        }
        return true;
      })
    : streamFilteredDiscrepancies;

  // U3: Keyboard navigation hook
  useKeyboardNavigation({
    itemCount: Math.min(filteredByAdvanced.length, 500),
    selectedIndex: selectedRowIndex,
    onSelectionChange: setSelectedRowIndex,
    onEnter: (idx) => {
      if (idx >= 0 && idx < filteredByAdvanced.length) {
        toggleRow(idx);
      }
    },
    onEscape: () => {
      if (dissectorDiscrepancy) setDissectorDiscrepancy(null);
      else if (deepDiveDiscrepancy) setDeepDiveDiscrepancy(null);
      else if (conversationFlow) setConversationFlow(null);
      else setSelectedRowIndex(-1);
    },
    filterInputRef,
    enabled: !dissectorDiscrepancy && !deepDiveDiscrepancy && !conversationFlow,
  });

  // Scroll selected row into view
  useEffect(() => {
    if (selectedRowIndex >= 0) {
      const row = document.getElementById(`discrepancy-row-${selectedRowIndex}`);
      row?.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    }
  }, [selectedRowIndex]);

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

  // Count how many discrepancies match each analysis flag for use in chip labels.
  const flagCounts = {
    retx: allDiscrepancies.filter(d => d.is_retransmission).length,
    dupAck: allDiscrepancies.filter(d => d.is_duplicate_ack).length,
    zeroWin: allDiscrepancies.filter(d => d.is_zero_window).length,
    keepAlive: allDiscrepancies.filter(d => d.is_keep_alive).length,
  };

  return (
    <div className="space-y-4">
      {/* Filter bar — state-based filters */}
      <div className="flex items-center gap-2 flex-wrap">
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
        {/* Analysis-flag filter chips — only rendered when at least one
            discrepancy has that flag set, so the UI stays clean for
            captures without TCP oddities. */}
        {(flagCounts.retx + flagCounts.dupAck + flagCounts.zeroWin + flagCounts.keepAlive) > 0 && (
          <>
            <span className="text-xs text-slate-600 ml-2">|</span>
            {flagCounts.retx > 0 && (
              <FlagChip
                active={filter === 'retx'}
                onClick={() => onFilterChange('retx')}
                label={`Retx (${flagCounts.retx})`}
                color="red"
              />
            )}
            {flagCounts.dupAck > 0 && (
              <FlagChip
                active={filter === 'dup-ack'}
                onClick={() => onFilterChange('dup-ack')}
                label={`Dup ACK (${flagCounts.dupAck})`}
                color="orange"
              />
            )}
            {flagCounts.zeroWin > 0 && (
              <FlagChip
                active={filter === 'zero-window'}
                onClick={() => onFilterChange('zero-window')}
                label={`Zero Win (${flagCounts.zeroWin})`}
                color="amber"
              />
            )}
            {flagCounts.keepAlive > 0 && (
              <FlagChip
                active={filter === 'keep-alive'}
                onClick={() => onFilterChange('keep-alive')}
                label={`Keep-Alive (${flagCounts.keepAlive})`}
                color="purple"
              />
            )}
          </>
        )}
      </div>

      {/* U1: Advanced Filter with Autocomplete */}
      <div className="flex items-center gap-3">
        <FilterAutocomplete
          value={advancedFilter}
          onChange={setAdvancedFilter}
          placeholder="Wireshark-style filter: ip.src == 192.168.1.1 && tcp.port == 443"
          className="flex-1"
          inputRef={filterInputRef}
        />
        <span className="text-[10px] text-slate-500">Press / to focus</span>
      </div>

      {/* C3: Stream Filter Banner */}
      {streamFilter && (
        <div className="flex items-center gap-3 px-4 py-2 bg-green-900/30 border border-green-700/40 rounded-lg">
          <Filter className="w-4 h-4 text-green-400" />
          <span className="text-sm text-green-400">
            Following stream: {streamFilter.srcIp}:{streamFilter.srcPort} ↔ {streamFilter.dstIp}:{streamFilter.dstPort} ({streamFilter.protocol})
          </span>
          <span className="text-xs text-green-400/70">
            ({streamFilteredDiscrepancies.length} packets)
          </span>
          <button
            onClick={() => setStreamFilter(null)}
            className="ml-auto px-3 py-1 text-xs bg-green-600/30 hover:bg-green-600/50 text-green-400 rounded transition-colors flex items-center gap-1"
          >
            <X className="w-3 h-3" />
            Clear Filter
          </button>
        </div>
      )}

      {/* U2: Color Legend */}
      <PacketColorLegend className="px-1" />

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
                <InfoTooltip text="Click any row to see a plain-English explanation. Use j/k or arrows to navigate, Enter to expand." />
              </th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-700/30">
            {filteredByAdvanced.slice(0, 500).map((d, i) => {
              const analysis = getDiscrepancyAnalysis(d);
              const isExpanded = expandedRows.has(i);
              const isSelected = selectedRowIndex === i;
              const rowColor = getPacketRowColor(d);
              return (
                <React.Fragment key={i}>
                  <tr
                    id={`discrepancy-row-${i}`}
                    className={`cursor-pointer transition-colors ${rowColor.rowClass} ${
                      isSelected ? 'ring-2 ring-blue-500 ring-inset' : ''
                    }`}
                    onClick={() => {
                      setSelectedRowIndex(i);
                      toggleRow(i);
                    }}
                  >
                    <td
                      className="px-3 py-2"
                      onContextMenu={onContextMenu({ field: 'state', value: d.state, label: 'Discrepancy State' })}
                    >
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
                      <div className="flex items-center gap-1.5 flex-wrap">
                        {/* Each IP / port is independently right-clickable so the
                            user can apply it as a filter clause. */}
                        <span>
                          <span
                            onContextMenu={onContextMenu({ field: 'ip.src', value: d.src_ip, label: 'Source IP' })}
                            className="hover:bg-slate-700/40 rounded px-0.5"
                          >
                            {d.src_ip}
                          </span>
                          :
                          <span
                            onContextMenu={onContextMenu({ field: 'tcp.srcport', value: d.src_port, label: 'Source Port' })}
                            className="hover:bg-slate-700/40 rounded px-0.5"
                          >
                            {d.src_port}
                          </span>
                          →
                          <span
                            onContextMenu={onContextMenu({ field: 'ip.dst', value: d.dst_ip, label: 'Destination IP' })}
                            className="hover:bg-slate-700/40 rounded px-0.5"
                          >
                            {d.dst_ip}
                          </span>
                          :
                          <span
                            onContextMenu={onContextMenu({ field: 'tcp.dstport', value: d.dst_port, label: 'Destination Port' })}
                            className="hover:bg-slate-700/40 rounded px-0.5"
                          >
                            {d.dst_port}
                          </span>
                        </span>
                        <span
                          className="text-slate-500"
                          onContextMenu={onContextMenu({ field: 'frame.protocol', value: d.protocol, label: 'Protocol' })}
                        >
                          {d.protocol}
                        </span>
                        {d.tcp_flags && (
                          <span
                            className="text-slate-600"
                            onContextMenu={onContextMenu({ field: 'tcp.flags', value: d.tcp_flags, label: 'TCP Flags' })}
                          >
                            [{d.tcp_flags}]
                          </span>
                        )}
                        <AnalysisBadges d={d} compact />
                      </div>
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
                              <div className="text-xs font-semibold text-white mb-1 flex items-center gap-2 flex-wrap">
                                <span>{analysis.summary}</span>
                                <AnalysisBadges d={d} />
                              </div>
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
                              {/* Follow Stream Buttons (C3) */}
                              <div className="mt-2 flex items-center gap-2">
                                <button
                                  onClick={() => setStreamFilter({
                                    srcIp: d.src_ip, dstIp: d.dst_ip,
                                    srcPort: d.src_port, dstPort: d.dst_port,
                                    protocol: d.protocol,
                                  })}
                                  className="px-3 py-1.5 text-[10px] font-medium rounded bg-cyan-600/20 text-cyan-400 hover:bg-cyan-600/40 transition-colors inline-flex items-center gap-1.5"
                                  title="Filter table to show only packets from this stream"
                                >
                                  <Filter className="w-3 h-3" />
                                  Follow Stream (Filter)
                                </button>
                                <button
                                  onClick={() => setConversationFlow({
                                    src_ip: d.src_ip, dst_ip: d.dst_ip,
                                    src_port: d.src_port, dst_port: d.dst_port,
                                    protocol: d.protocol,
                                    packets_a: 0, packets_b: 0, matched: 0,
                                    missing_b: 0, missing_a: 0, modified: 0,
                                    match_rate: 0, has_nat: false, encapsulated: false,
                                  })}
                                  className="px-3 py-1.5 text-[10px] font-medium rounded bg-green-600/20 text-green-400 hover:bg-green-600/40 transition-colors inline-flex items-center gap-1.5"
                                  title="Open conversation view modal"
                                >
                                  <MessageSquare className="w-3 h-3" />
                                  Conversation View
                                </button>
                              </div>
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
        {filteredByAdvanced.length > 500 && (
          <div className="px-4 py-2 text-xs text-slate-500 bg-slate-800 border-t border-slate-700/50">
            Showing first 500 of {filteredByAdvanced.length} discrepancies
            {(streamFilter || advancedFilter) && ` (filtered from ${total})`}
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

// FlagChip renders a small filter button for a Wireshark-style analysis
// flag. Colour is tied to the same palette used by <AnalysisBadges> so a
// flag's chip and its badge look visually consistent.
function FlagChip({
  active,
  onClick,
  label,
  color,
}: {
  active: boolean;
  onClick: () => void;
  label: string;
  color: 'red' | 'orange' | 'amber' | 'purple';
}) {
  const palette: Record<string, { active: string; idle: string }> = {
    red: {
      active: 'bg-red-600 text-white',
      idle: 'bg-red-500/15 text-red-400 hover:bg-red-500/25',
    },
    orange: {
      active: 'bg-orange-600 text-white',
      idle: 'bg-orange-500/15 text-orange-400 hover:bg-orange-500/25',
    },
    amber: {
      active: 'bg-amber-600 text-white',
      idle: 'bg-amber-500/15 text-amber-400 hover:bg-amber-500/25',
    },
    purple: {
      active: 'bg-purple-600 text-white',
      idle: 'bg-purple-500/15 text-purple-400 hover:bg-purple-500/25',
    },
  };
  const c = palette[color];
  return (
    <button
      onClick={onClick}
      className={`px-2.5 py-1 text-xs rounded-lg border border-transparent transition-colors ${
        active ? c.active : c.idle
      }`}
    >
      {label}
    </button>
  );
}

export default ComparisonView;
