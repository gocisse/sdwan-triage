import React, { useState, useMemo } from 'react';
import {
  CheckCircle2,
  Circle,
  AlertTriangle,
  XCircle,
  Shield,
  Activity,
  Zap,
  ChevronDown,
  ChevronUp,
  ArrowRight,
  Lightbulb,
  Brain,
  Target,
  Radio,
  Workflow,
  Clock,
  Ban,
  Layers,
} from 'lucide-react';
import type { ComparisonReport } from '../types';
import { GlossaryTerm, GLOSSARY } from './Glossary';

// Helper to render text with glossary-linked terms
function renderWithGlossaryTerms(text: string): React.ReactNode {
  const glossaryTerms = Object.keys(GLOSSARY);
  const parts: React.ReactNode[] = [];
  let key = 0;

  // Match common abbreviations
  const abbrevRegex = /\b(TTL|DSCP|MSS|RTT|RTO|BFD|OMP|CWND|RWND|MTU|PMTUD|RST|FIN|SYN|ACK)\b/g;
  let match;
  let lastIndex = 0;

  while ((match = abbrevRegex.exec(text)) !== null) {
    if (match.index > lastIndex) {
      parts.push(text.slice(lastIndex, match.index));
    }
    
    const abbrev = match[1];
    const glossaryKey = glossaryTerms.find(t => {
      const entry = GLOSSARY[t];
      return entry.abbreviation?.toUpperCase() === abbrev || t.toUpperCase() === abbrev;
    });

    if (glossaryKey) {
      parts.push(<GlossaryTerm key={key++} term={glossaryKey}>{abbrev}</GlossaryTerm>);
    } else {
      parts.push(abbrev);
    }
    
    lastIndex = match.index + match[0].length;
  }

  if (lastIndex < text.length) {
    parts.push(text.slice(lastIndex));
  }

  return parts.length > 0 ? parts : text;
}

// ─── Types ────────────────────────────────────────────────────────

interface GuidedTroubleshootingProps {
  report: ComparisonReport;
  onSwitchTab?: (tab: string) => void;
}

type CheckStatus = 'healthy' | 'warning' | 'critical' | 'info';

interface ChecklistItem {
  id: string;
  title: string;
  description: string;
  status: CheckStatus;
  statusLabel: string;
  icon: React.ReactNode;
  metric: string;
  steps: NextStep[];
  details?: string;
}

interface NextStep {
  instruction: string;
  action?: string;
  actionLabel?: string;
}

interface RootCause {
  theory: string;
  narrative: string;
  confidence: 'high' | 'medium' | 'low';
  evidence: string[];
  recommendation: string;
  cliCommands?: string[];
}

// ─── Main Component ───────────────────────────────────────────────

export const GuidedTroubleshooting: React.FC<GuidedTroubleshootingProps> = ({ report, onSwitchTab }) => {
  const [checkedItems, setCheckedItems] = useState<Set<string>>(new Set());
  const [expandedItem, setExpandedItem] = useState<string | null>(null);

  const checklist = useMemo(() => buildChecklist(report), [report]);
  const rootCauses = useMemo(() => generateRootCauses(report), [report]);
  const progress = checkedItems.size;
  const totalItems = checklist.length;
  const pctComplete = totalItems > 0 ? (progress / totalItems) * 100 : 0;

  const toggleCheck = (id: string) => {
    setCheckedItems(prev => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id); else next.add(id);
      return next;
    });
  };

  const statusIcon = (status: CheckStatus) => {
    switch (status) {
      case 'healthy': return <CheckCircle2 className="w-4.5 h-4.5 text-green-400" />;
      case 'warning': return <AlertTriangle className="w-4.5 h-4.5 text-yellow-400" />;
      case 'critical': return <XCircle className="w-4.5 h-4.5 text-red-400" />;
      case 'info': return <Activity className="w-4.5 h-4.5 text-blue-400" />;
    }
  };

  const statusColor = (status: CheckStatus) => {
    switch (status) {
      case 'healthy': return 'text-green-400';
      case 'warning': return 'text-yellow-400';
      case 'critical': return 'text-red-400';
      case 'info': return 'text-blue-400';
    }
  };

  const statusBg = (status: CheckStatus) => {
    switch (status) {
      case 'healthy': return 'bg-green-500/10 border-green-500/20';
      case 'warning': return 'bg-yellow-500/10 border-yellow-500/20';
      case 'critical': return 'bg-red-500/10 border-red-500/20';
      case 'info': return 'bg-blue-500/10 border-blue-500/20';
    }
  };

  // Overall severity
  const overallSeverity = useMemo(() => {
    if (checklist.some(c => c.status === 'critical')) return 'critical';
    if (checklist.some(c => c.status === 'warning')) return 'warning';
    return 'healthy';
  }, [checklist]);

  return (
    <div className="space-y-5">
      {/* ── Investigation Dashboard Header ────────────────────────── */}
      <div className="bg-slate-800/80 rounded-xl border border-slate-700/50 overflow-hidden">
        <div className="px-6 py-5">
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center gap-3">
              <div className={`p-2 rounded-lg ${
                overallSeverity === 'critical' ? 'bg-red-500/15' :
                overallSeverity === 'warning' ? 'bg-yellow-500/15' : 'bg-green-500/15'
              }`}>
                <Workflow className={`w-5 h-5 ${
                  overallSeverity === 'critical' ? 'text-red-400' :
                  overallSeverity === 'warning' ? 'text-yellow-400' : 'text-green-400'
                }`} />
              </div>
              <div>
                <h3 className="text-base font-semibold text-white">Guided Investigation</h3>
                <p className="text-xs text-slate-500 mt-0.5">Follow this checklist like a Senior Engineer would</p>
              </div>
            </div>
            <div className="text-right">
              <div className="text-xs text-slate-500">Progress</div>
              <div className="text-sm font-semibold text-white">{progress}/{totalItems} checked</div>
            </div>
          </div>

          {/* Progress Bar */}
          <div className="h-2 rounded-full bg-slate-900/80 overflow-hidden">
            <div
              className={`h-full rounded-full transition-all duration-500 ${
                pctComplete >= 100 ? 'bg-green-500' :
                pctComplete >= 50 ? 'bg-blue-500' : 'bg-slate-600'
              }`}
              style={{ width: `${pctComplete}%` }}
            />
          </div>
          {pctComplete >= 100 && (
            <div className="mt-2 text-xs text-green-400 flex items-center gap-1">
              <CheckCircle2 className="w-3 h-3" />
              All checks reviewed. See Root Cause Theory below.
            </div>
          )}
        </div>
      </div>

      {/* ── Problem Checklist ─────────────────────────────────────── */}
      <div className="space-y-3">
        {checklist.map((item, idx) => {
          const isExpanded = expandedItem === item.id;
          const isChecked = checkedItems.has(item.id);

          return (
            <div
              key={item.id}
              className={`rounded-xl border overflow-hidden transition-all ${
                isChecked
                  ? 'bg-slate-800/40 border-slate-700/30 opacity-80'
                  : `${statusBg(item.status)}`
              }`}
            >
              {/* Checklist Row */}
              <div className="flex items-start gap-3 px-5 py-4">
                {/* Checkbox */}
                <button
                  onClick={() => toggleCheck(item.id)}
                  className="mt-0.5 flex-shrink-0 transition-transform hover:scale-110"
                  title={isChecked ? 'Mark as not reviewed' : 'Mark as reviewed'}
                >
                  {isChecked ? (
                    <CheckCircle2 className="w-5 h-5 text-green-400" />
                  ) : (
                    <Circle className="w-5 h-5 text-slate-600" />
                  )}
                </button>

                {/* Content */}
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 mb-1">
                    <span className="text-xs text-slate-500 font-medium">Step {idx + 1}</span>
                    {item.icon}
                    <span className={`text-sm font-semibold ${isChecked ? 'text-slate-500 line-through' : 'text-white'}`}>
                      {item.title}
                    </span>
                  </div>
                  <p className={`text-xs leading-relaxed ${isChecked ? 'text-slate-600' : 'text-slate-400'}`}>
                    {renderWithGlossaryTerms(item.description)}
                  </p>

                  {/* Status Badge + Metric */}
                  <div className="flex items-center gap-3 mt-2">
                    <span className={`flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-[11px] font-medium ${statusBg(item.status)}`}>
                      {statusIcon(item.status)}
                      <span className={statusColor(item.status)}>{item.statusLabel}</span>
                    </span>
                    <span className="text-[11px] text-slate-500 font-mono">{item.metric}</span>
                  </div>
                </div>

                {/* Expand Button */}
                <button
                  onClick={() => setExpandedItem(isExpanded ? null : item.id)}
                  className="mt-1 px-3 py-1.5 text-[10px] font-medium rounded-lg bg-slate-700/50 hover:bg-slate-700 text-slate-300 transition-colors flex items-center gap-1 flex-shrink-0"
                >
                  {isExpanded ? (
                    <><ChevronUp className="w-3 h-3" /> Close</>
                  ) : (
                    <><Lightbulb className="w-3 h-3 text-yellow-400" /> What do I do?</>
                  )}
                </button>
              </div>

              {/* ── Expanded: Next Steps ────────────────────────────── */}
              {isExpanded && (
                <div className="px-5 pb-5 pt-0">
                  <div className="ml-8 space-y-3">
                    {/* Details */}
                    {item.details && (
                      <div className="p-3 bg-slate-900/50 rounded-lg border border-slate-700/30">
                        <div className="text-[10px] font-semibold text-slate-400 mb-1">📋 Details:</div>
                        <p className="text-[11px] text-slate-400 leading-relaxed">{renderWithGlossaryTerms(item.details)}</p>
                      </div>
                    )}

                    {/* Steps */}
                    <div className="space-y-2">
                      {item.steps.map((step, si) => (
                        <div key={si} className="flex items-start gap-2.5">
                          <div className="flex-shrink-0 w-5 h-5 rounded-full bg-blue-500/20 flex items-center justify-center mt-0.5">
                            <span className="text-[10px] font-bold text-blue-400">{si + 1}</span>
                          </div>
                          <div className="flex-1">
                            <p className="text-xs text-slate-300 leading-relaxed">{step.instruction}</p>
                            {step.action && step.actionLabel && (
                              <button
                                onClick={() => {
                                  if (step.action === 'switch:discrepancies' && onSwitchTab) {
                                    onSwitchTab('discrepancies');
                                  } else if (step.action === 'switch:flows' && onSwitchTab) {
                                    onSwitchTab('flows');
                                  }
                                }}
                                className="mt-1.5 px-3 py-1 text-[10px] font-medium rounded bg-blue-600/20 text-blue-400 hover:bg-blue-600/40 transition-colors inline-flex items-center gap-1"
                              >
                                <ArrowRight className="w-3 h-3" />
                                {step.actionLabel}
                              </button>
                            )}
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              )}
            </div>
          );
        })}
      </div>

      {/* ── Packet Distribution (kept, but compact) ───────────────── */}
      <PacketDistributionBar report={report} />

      {/* ── Root Cause Theory ─────────────────────────────────────── */}
      {rootCauses.length > 0 && (
        <RootCauseSection causes={rootCauses} />
      )}
    </div>
  );
};

// ─── Packet Distribution Bar (compact version) ───────────────────

const PacketDistributionBar: React.FC<{ report: ComparisonReport }> = ({ report }) => {
  const total = report.matched_count + report.missing_b_count + report.missing_a_count + report.modified_count;
  const pctMatch = total > 0 ? (report.matched_count / total * 100) : 0;
  const pctDrop = total > 0 ? (report.missing_b_count / total * 100) : 0;
  const pctModified = total > 0 ? (report.modified_count / total * 100) : 0;
  const pctAsym = total > 0 ? (report.missing_a_count / total * 100) : 0;

  return (
    <div className="bg-slate-800/80 rounded-xl p-5 border border-slate-700/50">
      <h3 className="text-xs font-medium text-slate-500 uppercase tracking-wider mb-3">Packet Distribution</h3>
      <div className="h-4 rounded-full overflow-hidden flex bg-slate-900">
        {pctMatch > 0 && <div className="bg-green-500 transition-all" style={{ width: `${pctMatch}%` }} title={`Matched: ${pctMatch.toFixed(1)}%`} />}
        {pctModified > 0 && <div className="bg-yellow-500 transition-all" style={{ width: `${pctModified}%` }} title={`Modified: ${pctModified.toFixed(1)}%`} />}
        {pctDrop > 0 && <div className="bg-red-500 transition-all" style={{ width: `${pctDrop}%` }} title={`Dropped: ${pctDrop.toFixed(1)}%`} />}
        {pctAsym > 0 && <div className="bg-purple-500 transition-all" style={{ width: `${pctAsym}%` }} title={`Asymmetric: ${pctAsym.toFixed(1)}%`} />}
      </div>
      <div className="flex gap-6 mt-2.5 text-[10px]">
        <span className="flex items-center gap-1.5"><span className="w-2 h-2 rounded-full bg-green-500" />Matched {pctMatch.toFixed(1)}%</span>
        <span className="flex items-center gap-1.5"><span className="w-2 h-2 rounded-full bg-yellow-500" />Modified {pctModified.toFixed(1)}%</span>
        <span className="flex items-center gap-1.5"><span className="w-2 h-2 rounded-full bg-red-500" />Dropped {pctDrop.toFixed(1)}%</span>
        <span className="flex items-center gap-1.5"><span className="w-2 h-2 rounded-full bg-purple-500" />Asymmetric {pctAsym.toFixed(1)}%</span>
      </div>
    </div>
  );
};

// ─── Root Cause Section ───────────────────────────────────────────

const RootCauseSection: React.FC<{ causes: RootCause[] }> = ({ causes }) => {
  const [expandedCause, setExpandedCause] = useState<number>(0);

  const confidenceColor = (c: RootCause['confidence']) => {
    switch (c) {
      case 'high': return 'text-red-400 bg-red-500/15 border-red-500/25';
      case 'medium': return 'text-yellow-400 bg-yellow-500/15 border-yellow-500/25';
      case 'low': return 'text-slate-400 bg-slate-500/15 border-slate-500/25';
    }
  };

  return (
    <div className="bg-slate-800/80 rounded-xl border border-slate-700/50 overflow-hidden">
      <div className="px-6 py-4 border-b border-slate-700/30">
        <div className="flex items-center gap-2.5">
          <div className="p-2 bg-purple-500/15 rounded-lg">
            <Brain className="w-5 h-5 text-purple-400" />
          </div>
          <div>
            <h3 className="text-sm font-semibold text-white">Root Cause Theory</h3>
            <p className="text-[10px] text-slate-500 mt-0.5">
              Heuristic analysis based on observed packet behavior
            </p>
          </div>
        </div>
      </div>

      <div className="p-5 space-y-4">
        {causes.map((cause, idx) => {
          const isExpanded = expandedCause === idx;
          return (
            <div
              key={idx}
              className={`rounded-lg border overflow-hidden transition-all ${
                isExpanded ? 'border-purple-500/30 bg-purple-900/10' : 'border-slate-700/30 bg-slate-800/30'
              }`}
            >
              <button
                onClick={() => setExpandedCause(isExpanded ? -1 : idx)}
                className="w-full flex items-start gap-3 px-4 py-3.5 text-left hover:bg-slate-700/10 transition-colors"
              >
                <Target className={`w-4 h-4 mt-0.5 flex-shrink-0 ${
                  idx === 0 ? 'text-purple-400' : 'text-slate-500'
                }`} />
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 mb-1">
                    {idx === 0 && <span className="text-[9px] font-bold text-purple-400 bg-purple-500/20 px-1.5 py-0.5 rounded">PRIMARY</span>}
                    {idx === 1 && <span className="text-[9px] font-bold text-slate-400 bg-slate-500/20 px-1.5 py-0.5 rounded">SECONDARY</span>}
                    {idx > 1 && <span className="text-[9px] font-bold text-slate-500 bg-slate-600/20 px-1.5 py-0.5 rounded">CONTRIBUTING</span>}
                    <span className={`text-[9px] font-medium px-1.5 py-0.5 rounded border ${confidenceColor(cause.confidence)}`}>
                      {cause.confidence.toUpperCase()} CONFIDENCE
                    </span>
                  </div>
                  <div className="text-sm font-semibold text-white">{cause.theory}</div>
                </div>
                {isExpanded ? <ChevronUp className="w-3.5 h-3.5 text-slate-500 mt-1" /> : <ChevronDown className="w-3.5 h-3.5 text-slate-500 mt-1" />}
              </button>

              {isExpanded && (
                <div className="px-4 pb-4 space-y-3">
                  {/* Narrative */}
                  <div className="p-3.5 bg-slate-900/60 rounded-lg border border-slate-700/20">
                    <div className="text-[10px] font-semibold text-purple-400 mb-1.5">🔍 Analysis Narrative:</div>
                    <p className="text-xs text-slate-300 leading-relaxed">{cause.narrative}</p>
                  </div>

                  {/* Evidence */}
                  <div>
                    <div className="text-[10px] font-semibold text-slate-400 mb-1.5">📊 Supporting Evidence:</div>
                    <ul className="space-y-1">
                      {cause.evidence.map((ev, ei) => (
                        <li key={ei} className="flex items-start gap-2 text-[11px] text-slate-400">
                          <span className="text-green-400 mt-0.5 flex-shrink-0">✓</span>
                          <span className="leading-relaxed">{ev}</span>
                        </li>
                      ))}
                    </ul>
                  </div>

                  {/* Recommendation */}
                  <div className="p-3 bg-green-900/15 rounded-lg border border-green-700/20">
                    <div className="text-[10px] font-semibold text-green-400 mb-1">✅ Recommended Action:</div>
                    <p className="text-xs text-slate-300 leading-relaxed">{cause.recommendation}</p>
                  </div>

                  {/* CLI Commands */}
                  {cause.cliCommands && cause.cliCommands.length > 0 && (
                    <div>
                      <div className="text-[10px] font-semibold text-slate-400 mb-1.5">💻 Verification Commands:</div>
                      <div className="space-y-1">
                        {cause.cliCommands.map((cmd, ci) => (
                          <code key={ci} className="block text-[10px] font-mono text-cyan-400 bg-slate-900/80 px-3 py-1.5 rounded border border-slate-700/30">
                            {cmd}
                          </code>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
};

// ─── Checklist Builder ────────────────────────────────────────────

function buildChecklist(report: ComparisonReport): ChecklistItem[] {
  const items: ChecklistItem[] = [];
  const f = report.forensics;

  // 1. Control Plane Health
  const controlPlaneDrops = report.ignored_control_plane_count || 0;
  const bfdOmpOk = controlPlaneDrops === 0;
  items.push({
    id: 'control-plane',
    title: 'Control Plane Health',
    description: 'Check if BFD/OMP tunnels are up. BFD probes monitor tunnel health — if they fail, the tunnel is declared dead.',
    status: bfdOmpOk ? 'healthy' : 'warning',
    statusLabel: bfdOmpOk ? 'Healthy' : `${controlPlaneDrops} Control Plane Issues`,
    icon: <Radio className="w-3.5 h-3.5 text-blue-400" />,
    metric: `${controlPlaneDrops} control plane packets flagged`,
    details: bfdOmpOk
      ? 'No control plane anomalies detected. BFD and OMP appear stable in this capture window.'
      : `${controlPlaneDrops} control plane packets were flagged. This could indicate BFD flaps, OMP route withdrawals, or DTLS tunnel renegotiations.`,
    steps: bfdOmpOk ? [
      { instruction: 'Control plane looks healthy. BFD probes and OMP routes are passing through the device normally.' },
      { instruction: 'For extra confidence, verify BFD sessions on the router: check session state, timers, and flap count.' },
    ] : [
      { instruction: `Review the ${controlPlaneDrops} flagged control plane packets. Look for BFD (UDP 3784/4784) and OMP (DTLS) packets.` },
      { instruction: 'On the router, check BFD session state. If sessions are flapping, check interface stability and QoS (control plane should be in a priority queue).', },
      { instruction: 'Check OMP peer state. If peers are going DOWN, DTLS tunnels may be failing — check certificate expiry and MTU.', },
      { instruction: 'Switch to the Discrepancies tab and filter for control plane traffic to see the exact packets.', action: 'switch:discrepancies', actionLabel: 'View Control Plane Drops' },
    ],
  });

  // 2. Path Integrity (Drops)
  const drops = report.missing_b_count;
  const dropPct = report.total_packets_a > 0 ? (drops / report.total_packets_a * 100) : 0;
  const dropStatus: CheckStatus = drops === 0 ? 'healthy' : dropPct > 5 ? 'critical' : 'warning';
  const policyDrops = report.policy_drop_count || 0;
  const blackholeDrops = report.blackhole_count || 0;

  // Count SYN drops
  const synDrops = report.discrepancies.filter(d =>
    d.state === 'MISSING_B' && d.tcp_flags?.includes('SYN') && !d.tcp_flags?.includes('ACK')
  ).length;

  items.push({
    id: 'path-integrity',
    title: 'Path Integrity — Dropped Traffic',
    description: 'Check for user traffic that entered the LAN interface but never appeared on the WAN. These are packets the SD-WAN device silently dropped.',
    status: dropStatus,
    statusLabel: drops === 0 ? 'No Drops' : `${drops} Drops (${dropPct.toFixed(1)}%)`,
    icon: <Shield className="w-3.5 h-3.5 text-red-400" />,
    metric: `${drops} dropped | ${policyDrops} policy | ${blackholeDrops} blackhole | ${synDrops} SYN drops`,
    details: drops === 0
      ? 'All user traffic passed through the SD-WAN device successfully. No packets were silently dropped.'
      : `${drops} packets were dropped (${dropPct.toFixed(1)}% loss). ${policyDrops > 0 ? `${policyDrops} appear to be policy drops (ACL/Firewall). ` : ''}${blackholeDrops > 0 ? `${blackholeDrops} may be route blackholes. ` : ''}${synDrops > 0 ? `${synDrops} are SYN packets (blocked new connections).` : ''}`,
    steps: drops === 0 ? [
      { instruction: 'No drops detected. Path integrity is healthy for this capture window.' },
    ] : [
      { instruction: `Review the ${policyDrops > 0 ? policyDrops : drops} policy drops. These are often caused by Zone-Based Firewall (ZBFW) rules or Access Control Lists (ACL).` },
      ...(synDrops > 0 ? [{
        instruction: `${synDrops} TCP SYN packets were blocked — these are new connections that were refused. Check firewall policy for the destination ports involved.`,
      }] : []),
      ...(blackholeDrops > 0 ? [{
        instruction: `${blackholeDrops} packets appear to be route blackholes — the device had no valid route for these destinations. Check the routing table and OMP advertised routes.`,
      }] : []),
      { instruction: 'Click below to see the specific flows and packets that were dropped.', action: 'switch:discrepancies', actionLabel: 'View Dropped Packets' },
      { instruction: 'On the router, check the drop counters and policy logs to confirm the drop reason.' },
    ],
  });

  // 3. NAT / Modifications
  const modified = report.modified_count;
  const natDetected = report.nat_detected;
  const dscpChanges = report.dscp_changes || 0;
  const ttlChanges = report.ttl_changes || 0;
  const modStatus: CheckStatus = modified === 0 ? 'healthy' : natDetected && dscpChanges > 0 ? 'warning' : 'info';

  items.push({
    id: 'modifications',
    title: 'Packet Modifications (NAT/QoS/TTL)',
    description: 'Check if the SD-WAN device is modifying packets in transit. NAT, DSCP remarking, and TTL decrement are expected — other changes may be unexpected.',
    status: modStatus,
    statusLabel: modified === 0 ? 'No Modifications' : `${modified} Modified`,
    icon: <Layers className="w-3.5 h-3.5 text-yellow-400" />,
    metric: `NAT: ${natDetected ? 'Yes' : 'No'} | DSCP: ${dscpChanges} | TTL: ${ttlChanges}`,
    details: modified === 0
      ? 'No packet modifications detected. The device is forwarding packets without alteration.'
      : `${modified} packets were modified. ${natDetected ? 'NAT was detected (expected for DIA/internet traffic). ' : ''}${dscpChanges > 0 ? `${dscpChanges} DSCP changes (QoS remarking). ` : ''}${ttlChanges > 0 ? `${ttlChanges} TTL changes (normal routing decrement). ` : ''}`,
    steps: modified === 0 ? [
      { instruction: 'No modifications. Packets are passing through unchanged — this is normal for transparent bridge mode or same-VLAN routing.' },
    ] : [
      ...(natDetected ? [{
        instruction: 'NAT is active. This is expected for Direct Internet Access (DIA) traffic where the device translates private IPs to the WAN interface IP. Verify the NAT pool or overload configuration.',
      }] : []),
      ...(dscpChanges > 0 ? [{
        instruction: `${dscpChanges} packets had their DSCP value changed. This is QoS remarking — the device is classifying traffic and setting priority. Verify the QoS policy matches your intent.`,
      }] : []),
      ...(ttlChanges > 0 ? [{
        instruction: `${ttlChanges} TTL changes detected. This is normal — each router hop decrements TTL by 1. If TTL drops by more than 1, there may be hidden hops (tunnels).`,
      }] : []),
      { instruction: 'View the specific modified packets to see exactly which fields changed.', action: 'switch:discrepancies', actionLabel: 'View Modified Packets' },
    ],
  });

  // 4. Performance — Latency
  const avgLatency = f?.avg_one_way_latency_ms || 0;
  const p95Latency = f?.p95_one_way_latency_ms || 0;
  const maxLatency = f?.max_one_way_latency_ms || 0;
  const latencyStatus: CheckStatus = avgLatency === 0 ? 'info' : avgLatency > 100 ? 'critical' : avgLatency > 50 ? 'warning' : 'healthy';

  items.push({
    id: 'latency',
    title: 'Performance — One-Way Latency',
    description: 'Measure the time it takes packets to transit through the SD-WAN device (LAN → WAN delay). High latency indicates queuing, crypto processing, or interface congestion.',
    status: latencyStatus,
    statusLabel: avgLatency === 0 ? 'No Data' : `Avg: ${avgLatency.toFixed(1)}ms`,
    icon: <Clock className="w-3.5 h-3.5 text-cyan-400" />,
    metric: avgLatency > 0 ? `Avg: ${avgLatency.toFixed(1)}ms | P95: ${p95Latency.toFixed(1)}ms | Max: ${maxLatency.toFixed(1)}ms` : 'No latency samples available',
    details: avgLatency === 0
      ? 'No latency data was computed. This may mean the captures were not time-synchronized, or no matched packets had measurable delay.'
      : `Average one-way latency is ${avgLatency.toFixed(1)}ms. ${p95Latency > 100 ? `P95 is ${p95Latency.toFixed(1)}ms — the worst 5% of packets experience significant delay.` : `P95 is ${p95Latency.toFixed(1)}ms, which is within normal range.`} ${maxLatency > 200 ? `Maximum observed latency was ${maxLatency.toFixed(1)}ms — investigate potential queuing or bufferbloat.` : ''}`,
    steps: avgLatency === 0 ? [
      { instruction: 'No latency data available. To get accurate latency measurements, ensure both capture timestamps are synchronized (PTP or GPS).' },
    ] : avgLatency > 100 ? [
      { instruction: `Average latency of ${avgLatency.toFixed(1)}ms is HIGH. This will impact real-time applications (voice/video).` },
      { instruction: 'Check WAN interface utilization — if the link is saturated (>80%), queuing delays are expected.' },
      { instruction: 'Check QoS queuing statistics on the device. High queue drops indicate the shaper/policer is congested.' },
      { instruction: 'If the device uses IPsec encryption, check crypto engine utilization — hardware vs software encryption matters.' },
      { instruction: 'View per-flow latency details.', action: 'switch:flows', actionLabel: 'View Flow Details' },
    ] : avgLatency > 50 ? [
      { instruction: `Average latency of ${avgLatency.toFixed(1)}ms is MODERATE. May impact voice calls but acceptable for data.` },
      { instruction: 'Check if QoS is prioritizing voice/video traffic. Latency-sensitive traffic should be in a Low-Latency Queue (LLQ).' },
      { instruction: 'Compare P95 vs average — if P95 is much higher, there may be periodic congestion bursts.' },
    ] : [
      { instruction: `Average latency of ${avgLatency.toFixed(1)}ms is NORMAL. The SD-WAN device is processing packets efficiently.` },
      { instruction: 'No immediate action needed. Continue to monitor during peak hours for degradation.' },
    ],
  });

  // 5. Retransmissions / Reliability
  const retransmitDropped = f?.total_retransmissions_dropped || 0;
  const failedHandshakes = f?.failed_handshakes?.length || 0;
  const mtuOffenders = f?.top_retransmission_offenders?.filter(o => o.mtu_blackhole) || [];
  const retransmitStatus: CheckStatus = retransmitDropped === 0 && failedHandshakes === 0 ? 'healthy' :
    mtuOffenders.length > 0 ? 'critical' : retransmitDropped > 10 ? 'warning' : 'info';

  items.push({
    id: 'retransmissions',
    title: 'Reliability — Retransmissions & Handshakes',
    description: 'Check for TCP retransmissions that were dropped and failed connection handshakes. These indicate reliability issues where recovery mechanisms are also failing.',
    status: retransmitStatus,
    statusLabel: retransmitDropped === 0 && failedHandshakes === 0 ? 'Healthy' :
      `${retransmitDropped} retransmit drops, ${failedHandshakes} failed handshakes`,
    icon: <Zap className="w-3.5 h-3.5 text-orange-400" />,
    metric: `Retransmit drops: ${retransmitDropped} | Failed handshakes: ${failedHandshakes} | MTU blackholes: ${mtuOffenders.length}`,
    details: retransmitDropped === 0 && failedHandshakes === 0
      ? 'No retransmission or handshake issues detected. TCP reliability mechanisms are functioning normally.'
      : `${retransmitDropped > 0 ? `${retransmitDropped} TCP retransmissions were also dropped — the original AND the retry both failed to pass. ` : ''}${failedHandshakes > 0 ? `${failedHandshakes} TCP handshakes failed to complete (SYN sent but no SYN-ACK received). ` : ''}${mtuOffenders.length > 0 ? `${mtuOffenders.length} flows show MTU blackhole patterns (large packets fail, small packets pass).` : ''}`,
    steps: retransmitDropped === 0 && failedHandshakes === 0 ? [
      { instruction: 'TCP reliability is healthy. No retransmission or handshake issues detected in this capture window.' },
    ] : [
      ...(mtuOffenders.length > 0 ? [
        { instruction: `🚨 MTU BLACKHOLE DETECTED in ${mtuOffenders.length} flow(s). Large TCP packets are being dropped while small packets (BFD/ACKs) pass fine. This is the classic MTU problem.` },
        { instruction: `The largest payload that passed was ${mtuOffenders[0]?.max_payload || 'unknown'} bytes. Set interface MTU or tunnel MTU below this value.` },
        { instruction: 'Enable TCP MSS clamping: "ip tcp adjust-mss 1360" to prevent TCP from sending oversized segments.' },
      ] : []),
      ...(failedHandshakes > 0 ? [{
        instruction: `${failedHandshakes} TCP handshakes failed. The SYN was sent but the connection was never established. Check firewall rules for the destination IP/port.`,
      }] : []),
      ...(retransmitDropped > 0 ? [{
        instruction: `${retransmitDropped} retransmissions were also dropped. When both the original packet AND retransmission are dropped, it indicates a persistent block (policy) rather than transient congestion.`,
      }] : []),
      { instruction: 'View the specific flows experiencing these issues.', action: 'switch:flows', actionLabel: 'View Problem Flows' },
    ],
  });

  // 6. Tunnel / Encryption
  const tunnelDetected = report.tunnel_detected;
  const tunnelTypes = report.tunnel_types || [];
  const encapsulatedCount = report.encapsulated_count || 0;
  const encryptedCount = report.encrypted_count || 0;
  const tunnelStatus: CheckStatus = !tunnelDetected ? 'info' : 'healthy';

  items.push({
    id: 'tunnel',
    title: 'Tunnel & Encryption Status',
    description: 'Check if SD-WAN tunnels (IPsec/GRE/DTLS) are active and encrypting traffic as expected.',
    status: tunnelStatus,
    statusLabel: tunnelDetected ? `${tunnelTypes.join(', ')} detected` : 'No Tunnels',
    icon: <Ban className="w-3.5 h-3.5 text-purple-400" />,
    metric: `Tunnels: ${tunnelTypes.length > 0 ? tunnelTypes.join(', ') : 'None'} | Encapsulated: ${encapsulatedCount} | Encrypted: ${encryptedCount}`,
    details: !tunnelDetected
      ? 'No tunnel encapsulation detected in the captures. This is expected if both captures are from the same side of the tunnel, or if the device uses transparent forwarding.'
      : `Tunnel types detected: ${tunnelTypes.join(', ')}. ${encapsulatedCount} packets were encapsulated, ${encryptedCount} were encrypted. This is expected behavior for SD-WAN overlay traffic.`,
    steps: !tunnelDetected ? [
      { instruction: 'No tunnels detected. If you expected to see tunnel encapsulation, verify you captured on the correct interface (WAN interface should show tunnel headers).' },
      { instruction: 'If captures are from LAN and WAN interfaces of the same device, the LAN side will have plain packets and the WAN side will show tunnel encapsulation.' },
    ] : [
      { instruction: `${tunnelTypes.join(' and ')} tunnel(s) detected. The SD-WAN device is encapsulating traffic as expected.` },
      { instruction: `${encryptedCount > 0 ? `${encryptedCount} packets are encrypted — these cannot be inspected further without decryption keys.` : 'No encryption detected on encapsulated packets. Check if IPsec is enabled on the tunnel.'}` },
      { instruction: 'Verify tunnel MTU is set correctly to avoid fragmentation. IPsec adds 50-80 bytes of overhead; GRE adds 24 bytes.' },
    ],
  });

  return items;
}

// ─── Root Cause Heuristic Engine ──────────────────────────────────

function generateRootCauses(report: ComparisonReport): RootCause[] {
  const causes: RootCause[] = [];
  const f = report.forensics;

  // Compute derived metrics
  const drops = report.missing_b_count;
  const total = report.total_packets_a;
  const dropPct = total > 0 ? (drops / total * 100) : 0;
  const synDrops = report.discrepancies.filter(d =>
    d.state === 'MISSING_B' && d.tcp_flags?.includes('SYN') && !d.tcp_flags?.includes('ACK')
  ).length;
  const largeDrops = report.discrepancies.filter(d =>
    d.state === 'MISSING_B' && d.length > 1400
  ).length;
  const smallDrops = report.discrepancies.filter(d =>
    d.state === 'MISSING_B' && d.length <= 100
  ).length;
  const mtuOffenders = f?.top_retransmission_offenders?.filter(o => o.mtu_blackhole) || [];
  const failedHandshakes = f?.failed_handshakes?.length || 0;
  const retransmitDropped = f?.total_retransmissions_dropped || 0;
  const policyDrops = report.policy_drop_count || 0;
  const blackholeDrops = report.blackhole_count || 0;
  const avgLatency = f?.avg_one_way_latency_ms || 0;
  const p95Latency = f?.p95_one_way_latency_ms || 0;

  // ── Heuristic 1: MTU Blackhole ──────────────────────────────
  if (mtuOffenders.length > 0 || (largeDrops > 5 && smallDrops < largeDrops * 0.3)) {
    const maxPayload = mtuOffenders[0]?.max_payload || 1400;
    causes.push({
      theory: 'MTU Blackholing',
      confidence: mtuOffenders.length > 0 ? 'high' : 'medium',
      narrative: `Analysis suggests the primary issue is MTU Blackholing. We see ${largeDrops} large TCP packets (>1400 bytes) being dropped or retransmitted without success, while smaller packets (BFD keepalives, TCP ACKs) pass through the device normally. This is the classic "large packets fail, small packets pass" pattern that indicates the tunnel or WAN interface MTU is too small for the encapsulated payload. The SD-WAN tunnel adds ${report.tunnel_detected ? '50-80 bytes of IPsec/GRE overhead' : 'encapsulation overhead'}, pushing large packets over the effective MTU. Path MTU Discovery (PMTUD) may be failing because ICMP "Fragmentation Needed" messages are being blocked.`,
      evidence: [
        `${largeDrops} packets >1400 bytes were dropped (vs ${smallDrops} small packets dropped)`,
        ...(mtuOffenders.length > 0 ? [`${mtuOffenders.length} flows explicitly flagged as MTU blackhole pattern`] : []),
        ...(mtuOffenders[0]?.max_payload ? [`Largest successful payload: ${maxPayload} bytes`] : []),
        `${retransmitDropped > 0 ? `${retransmitDropped} retransmissions also dropped — retry doesn't help (persistent block)` : 'Retransmissions also failing for these flows'}`,
        ...(report.tunnel_detected ? [`${(report.tunnel_types || []).join('/')} tunnel detected — adds encapsulation overhead`] : []),
      ],
      recommendation: `Lower the interface MTU or tunnel MTU to account for encapsulation overhead. Enable TCP MSS clamping to prevent endpoints from sending oversized segments. If using IPsec, set "ip mtu 1400" and "ip tcp adjust-mss 1360" on the tunnel interface. Also ensure ICMP is not blocked — PMTUD relies on ICMP "Fragmentation Needed" (Type 3, Code 4) messages.`,
      cliCommands: [
        '# Check current MTU',
        'show interface tunnel <id> | include MTU',
        '# Lower tunnel MTU',
        'interface Tunnel <id>',
        ' ip mtu 1400',
        '# Enable TCP MSS clamping',
        ' ip tcp adjust-mss 1360',
        '# Verify ICMP is not blocked',
        'show access-lists | include icmp',
      ],
    });
  }

  // ── Heuristic 2: Firewall Policy Block ──────────────────────
  if (policyDrops > 0 || synDrops > 3) {
    const affectedPorts = new Set<number>();
    report.discrepancies.filter(d => d.state === 'MISSING_B' && d.tcp_flags?.includes('SYN'))
      .forEach(d => affectedPorts.add(d.dst_port));
    const portList = Array.from(affectedPorts).slice(0, 10).join(', ');

    causes.push({
      theory: 'Firewall / Policy Block',
      confidence: synDrops > 5 ? 'high' : policyDrops > 0 ? 'medium' : 'low',
      narrative: `The SD-WAN device is actively blocking new connections. We detected ${synDrops} TCP SYN packets (connection requests) that were silently dropped — the client sends a SYN, but it never reaches the WAN. ${policyDrops > 0 ? `${policyDrops} packets match known policy drop patterns. ` : ''}This is consistent with a Zone-Based Firewall (ZBFW) deny rule, a centralized data policy drop action, or an implicit deny at the end of an ACL. The affected destination ports are: ${portList || 'various'}.${failedHandshakes > 0 ? ` Additionally, ${failedHandshakes} handshakes completely failed.` : ''}`,
      evidence: [
        `${synDrops} TCP SYN packets dropped (new connections blocked)`,
        ...(policyDrops > 0 ? [`${policyDrops} packets match policy drop patterns`] : []),
        `Affected ports: ${portList || 'multiple'}`,
        ...(failedHandshakes > 0 ? [`${failedHandshakes} complete handshake failures`] : []),
        'Small/keepalive packets pass — this is not an MTU or congestion issue',
      ],
      recommendation: `Review the Zone-Based Firewall (ZBFW) policy on vManage. Check for implicit deny rules at the end of the security policy. Verify that the affected destination ports (${portList || 'listed above'}) are permitted in the firewall zone pair matching VPN-to-VPN or VPN-to-Internet traffic. Also check centralized data policies for any "drop" actions matching this traffic.`,
      cliCommands: [
        '# Check ZBFW policy',
        'show zone-pair security',
        'show policy-firewall stats all',
        '# Check centralized data policy',
        'show sdwan policy data-policy from-vsmart',
        '# Check ACL drops',
        'show access-lists | include deny',
        'show platform packet-trace summary',
      ],
    });
  }

  // ── Heuristic 3: Route Blackhole ────────────────────────────
  if (blackholeDrops > 0) {
    causes.push({
      theory: 'Route Blackhole',
      confidence: blackholeDrops > 10 ? 'high' : 'medium',
      narrative: `${blackholeDrops} packets appear to be dropped due to routing blackholes — the device received the packets but had no valid route to forward them. This can happen when OMP routes are withdrawn, a VPN route is missing, or the routing table has a default route pointing to Null0 (blackhole route).`,
      evidence: [
        `${blackholeDrops} packets match blackhole drop pattern`,
        'Packets from various flows with different destinations are affected',
        'No policy block pattern detected — this is a routing issue',
      ],
      recommendation: `Check the routing table for the affected VPN/VRF. Verify OMP routes are being advertised and received. Look for Null0 routes or missing default routes. If routes recently disappeared, check OMP graceful restart and BGP neighbor state.`,
      cliCommands: [
        '# Check routing table for VPN',
        'show ip route vrf <vpn-id>',
        '# Check OMP routes',
        'show sdwan omp routes',
        'show sdwan omp peers',
        '# Check for Null0 routes',
        'show ip route vrf <vpn-id> | include Null0',
      ],
    });
  }

  // ── Heuristic 4: High Latency / Congestion ──────────────────
  if (avgLatency > 50) {
    causes.push({
      theory: 'WAN Congestion / High Processing Latency',
      confidence: avgLatency > 100 ? 'high' : 'medium',
      narrative: `One-way latency through the SD-WAN device averages ${avgLatency.toFixed(1)}ms${p95Latency > avgLatency * 2 ? `, with P95 spiking to ${p95Latency.toFixed(1)}ms` : ''}. This is ${avgLatency > 100 ? 'significantly' : 'moderately'} above normal for device transit time (expected <10ms). ${p95Latency > avgLatency * 2 ? 'The large gap between average and P95 suggests periodic congestion bursts rather than constant overload. ' : ''}Possible causes: WAN interface utilization near capacity, QoS shaper/policer queuing delay, or software crypto processing overhead (check if IPsec is using hardware acceleration).`,
      evidence: [
        `Average one-way latency: ${avgLatency.toFixed(1)}ms (normal: <10ms)`,
        `P95 latency: ${p95Latency.toFixed(1)}ms`,
        `${f?.latency_sample_count || 0} latency samples measured`,
        ...(dropPct > 1 ? [`${dropPct.toFixed(1)}% packet loss — congestion typically causes both latency AND drops`] : []),
      ],
      recommendation: `Check WAN interface utilization (should be <80%). Review QoS queue statistics for tail drops or queue overflows. If using IPsec, verify the platform supports hardware crypto acceleration. For periodic spikes, look at time-of-day traffic patterns.`,
      cliCommands: [
        '# Check interface utilization',
        'show interface <wan-if> | include rate',
        '# Check QoS queue drops',
        'show policy-map interface <wan-if>',
        '# Check crypto engine',
        'show crypto engine brief',
        '# Check CPU',
        'show process cpu sorted | head 10',
      ],
    });
  }

  // ── Heuristic 5: Asymmetric Routing ─────────────────────────
  if (report.missing_a_count > report.total_packets_b * 0.1 && report.missing_a_count > 20) {
    causes.push({
      theory: 'Asymmetric Routing / Multi-Path',
      confidence: 'low',
      narrative: `${report.missing_a_count} packets appeared on the WAN but not on the LAN. While some are normal (control plane, return traffic), this volume suggests traffic may be arriving from multiple paths or the return path differs from the forward path. In SD-WAN environments, this can happen with ECMP, application-aware routing policy changes, or mid-flow path switches.`,
      evidence: [
        `${report.missing_a_count} WAN-only packets (${(report.missing_a_count / (report.total_packets_b || 1) * 100).toFixed(1)}% of WAN capture)`,
        'Traffic from remote sites may arrive via different tunnels',
        'SD-WAN path selection may have shifted traffic mid-flow',
      ],
      recommendation: `This is often normal in SD-WAN deployments. However, if applications are breaking, check the App-Aware routing policy for mid-flow path switches. Ensure SLA policies have appropriate fallback behavior and that "preferred color" settings are consistent.`,
      cliCommands: [
        '# Check App-Aware routing policy',
        'show sdwan policy app-route-policy from-vsmart',
        '# Check SLA status',
        'show sdwan app-route sla-class',
        '# Check BFD sessions (multiple paths)',
        'show sdwan bfd sessions',
      ],
    });
  }

  // ── Fallback: Healthy ───────────────────────────────────────
  if (causes.length === 0) {
    causes.push({
      theory: 'No Significant Issues Detected',
      confidence: 'high',
      narrative: `Analysis of ${total} packets shows a healthy SD-WAN path with ${report.path_integrity_score}% integrity. ${drops === 0 ? 'No packets were dropped.' : `Only ${drops} packets were dropped (${dropPct.toFixed(1)}%), which is within acceptable thresholds.`} The SD-WAN device is forwarding traffic as expected. Control plane is stable, no MTU issues detected, and latency is within normal parameters.`,
      evidence: [
        `Path integrity score: ${report.path_integrity_score}%`,
        `${report.matched_count} packets matched successfully`,
        `${drops} total drops (${dropPct.toFixed(2)}%)`,
        ...(avgLatency > 0 ? [`Average latency: ${avgLatency.toFixed(1)}ms`] : ['No latency anomalies']),
      ],
      recommendation: 'No immediate action required. Continue monitoring during peak hours and save this capture as a baseline for future comparisons.',
    });
  }

  // Sort by confidence: high first
  const order = { high: 0, medium: 1, low: 2 };
  causes.sort((a, b) => order[a.confidence] - order[b.confidence]);

  return causes;
}
