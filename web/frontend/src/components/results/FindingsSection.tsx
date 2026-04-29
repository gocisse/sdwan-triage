// FindingsSection — Extracted from ResultsPage.tsx
// Contains TroubleshootingGuidance and FindingsPanel sub-components

import { useState, useMemo } from 'react';
import {
  CheckCircle,
  Sparkles,
  X,
  ArrowRightLeft,
  Info,
} from 'lucide-react';
import type { AnalysisResults } from '../../types';
import { FindingCard, IssueSidebar, type CategoryId, VirtualizedFlowTable, type Column } from '../dashboard';
import { issueKnowledgeBase, getSeverityConfig } from '../../data/knowledgeBase';
import { getActiveFindings, wizardSymptoms } from '../../data/wizardData';

// ─── Main Exported Component ──────────────────────────────────

export interface FindingsSectionProps {
  results: AnalysisResults;
  filteredResults: AnalysisResults | null;
  isFiltered: boolean;
  eli5Mode: boolean;
  detectedVendors: string[];
  activeCategory: CategoryId;
  onCategoryChange: (cat: CategoryId) => void;
  onOpenWizard: () => void;
  onFollowStream: (streamId: string) => void;
}

export function FindingsSection({
  results,
  filteredResults,
  isFiltered,
  eli5Mode,
  detectedVendors,
  activeCategory,
  onCategoryChange,
  onOpenWizard,
  onFollowStream,
}: FindingsSectionProps) {
  const [sidebarOpen, setSidebarOpen] = useState(false);

  return (
    <>
      {/* Troubleshooting Guidance */}
      <TroubleshootingGuidance results={results} onOpenWizard={onOpenWizard} />

      {/* Findings layout */}
      <div className="flex flex-col lg:flex-row gap-6">
        {/* Mobile Sidebar Toggle */}
        <button
          onClick={() => setSidebarOpen(!sidebarOpen)}
          className="lg:hidden flex items-center justify-between w-full px-4 py-3 rounded-xl bg-slate-800/80 border border-slate-700/50 text-sm text-slate-300 hover:text-white transition-colors"
        >
          <span className="font-medium">Categories</span>
          <svg className={`w-4 h-4 transition-transform ${sidebarOpen ? 'rotate-180' : ''}`} fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" /></svg>
        </button>

        {/* Sidebar */}
        <div className={`lg:w-64 flex-shrink-0 ${sidebarOpen ? 'block' : 'hidden lg:block'}`} data-tour="sidebar">
          <div className="lg:sticky lg:top-24">
            <IssueSidebar
              results={results}
              activeCategory={activeCategory}
              onCategoryChange={(cat) => { onCategoryChange(cat); setSidebarOpen(false); }}
            />
          </div>
        </div>

        {/* Findings List */}
        <div className="flex-1 min-w-0 space-y-4">
          <FindingsPanel
            results={isFiltered && filteredResults ? filteredResults : results}
            category={activeCategory}
            eli5Mode={eli5Mode}
            detectedVendors={detectedVendors}
            onFollowStream={onFollowStream}
          />
        </div>
      </div>
    </>
  );
}

// ─── Troubleshooting Guidance (Inline) ───────────────────────
// Always-visible panel for junior engineers — shows top issues with quick-start steps
// and a prominent CTA to open the full Wizard for guided investigation.

interface TroubleshootingGuidanceProps {
  results: AnalysisResults;
  onOpenWizard: () => void;
}

function TroubleshootingGuidance({ results, onOpenWizard }: TroubleshootingGuidanceProps) {
  const activeFindings = useMemo(() => getActiveFindings(results), [results]);
  const [dismissed, setDismissed] = useState(false);

  if (dismissed) return null;

  // Sort findings by severity: Critical first, then Warning
  const sevOrder: Record<string, number> = { Critical: 0, Warning: 1, Info: 2 };
  const sortedFindings = Array.from(activeFindings.entries())
    .sort((a, b) => (sevOrder[a[1].severity] ?? 3) - (sevOrder[b[1].severity] ?? 3));

  const criticalCount = sortedFindings.filter(([, v]) => v.severity === 'Critical').length;
  const warningCount = sortedFindings.filter(([, v]) => v.severity === 'Warning').length;
  const topFindings = sortedFindings.slice(0, 5);

  // Pick a matching symptom suggestion based on what's detected
  const suggestedSymptom = useMemo(() => {
    for (const symptom of wizardSymptoms) {
      const matchCount = symptom.relatedFindings.filter(f => activeFindings.has(f)).length;
      if (matchCount >= 2) return symptom;
    }
    return null;
  }, [activeFindings]);

  return (
    <div className="bg-gradient-to-br from-slate-800/90 to-slate-800/70 border border-purple-500/20 rounded-2xl overflow-hidden">
      {/* Header */}
      <div className="flex items-center justify-between px-6 py-4 border-b border-slate-700/50 bg-gradient-to-r from-purple-500/10 to-blue-500/10">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-purple-500 to-blue-500 flex items-center justify-center flex-shrink-0">
            <Sparkles className="w-5 h-5 text-white" />
          </div>
          <div>
            <h2 className="text-base font-bold text-white">Troubleshooting Guidance</h2>
            <p className="text-xs text-slate-400">
              {activeFindings.size === 0
                ? 'No issues detected — network looks healthy'
                : `${activeFindings.size} issue${activeFindings.size !== 1 ? 's' : ''} found — ${criticalCount > 0 ? `${criticalCount} critical` : ''}${criticalCount > 0 && warningCount > 0 ? ', ' : ''}${warningCount > 0 ? `${warningCount} warning${warningCount !== 1 ? 's' : ''}` : ''}`
              }
            </p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={onOpenWizard}
            className="flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-semibold bg-gradient-to-r from-purple-600 to-blue-600 text-white hover:from-purple-500 hover:to-blue-500 transition-all shadow-lg shadow-purple-500/20"
          >
            <Sparkles className="w-3.5 h-3.5" />
            Open Full Wizard
          </button>
          <button
            onClick={() => setDismissed(true)}
            className="p-1.5 rounded-lg hover:bg-slate-700/50 transition-colors text-slate-500 hover:text-slate-300"
            title="Dismiss guidance panel"
          >
            <X className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* Body */}
      <div className="px-6 py-4">
        {activeFindings.size === 0 ? (
          <div className="flex items-center gap-3 py-2">
            <CheckCircle className="w-8 h-8 text-green-400 flex-shrink-0" />
            <div>
              <p className="text-sm text-green-300 font-medium">All Clear</p>
              <p className="text-xs text-slate-400">No significant issues were detected in this capture. The network appears healthy. You can still use the Wizard to investigate specific symptoms.</p>
            </div>
          </div>
        ) : (
          <div className="space-y-4">
            {/* Suggested starting point */}
            {suggestedSymptom && (
              <div className="flex items-start gap-3 p-3 rounded-xl bg-amber-500/5 border border-amber-500/20">
                <span className="text-xl flex-shrink-0 mt-0.5">{suggestedSymptom.icon}</span>
                <div className="flex-1 min-w-0">
                  <p className="text-sm font-medium text-amber-300">Suggested Starting Point</p>
                  <p className="text-xs text-slate-400 mt-0.5">{suggestedSymptom.description}</p>
                  <button
                    onClick={onOpenWizard}
                    className="mt-2 inline-flex items-center gap-1.5 text-xs text-purple-400 hover:text-purple-300 font-medium transition-colors"
                  >
                    Start guided investigation
                    <Sparkles className="w-3 h-3" />
                  </button>
                </div>
              </div>
            )}

            {/* Top findings quick list */}
            <div>
              <p className="text-xs font-medium text-slate-500 uppercase tracking-wider mb-2">Top Issues to Investigate</p>
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2">
                {topFindings.map(([key, info], i) => {
                  const knowledge = issueKnowledgeBase[key];
                  const sevColor = info.severity === 'Critical'
                    ? 'border-red-500/30 bg-red-500/5'
                    : info.severity === 'Warning'
                    ? 'border-amber-500/30 bg-amber-500/5'
                    : 'border-blue-500/30 bg-blue-500/5';
                  const sevDot = info.severity === 'Critical'
                    ? 'bg-red-500'
                    : info.severity === 'Warning'
                    ? 'bg-amber-500'
                    : 'bg-blue-500';

                  return (
                    <div key={key} className={`p-3 rounded-xl border ${sevColor} transition-all`}>
                      <div className="flex items-center gap-2 mb-1">
                        <div className={`w-2 h-2 rounded-full ${sevDot} flex-shrink-0`} />
                        <span className="text-xs font-semibold text-white truncate">{info.label}</span>
                        {i === 0 && (
                          <span className="px-1.5 py-0.5 rounded text-[9px] font-bold bg-amber-500/20 text-amber-400 border border-amber-500/30 uppercase tracking-wider flex-shrink-0">
                            Start Here
                          </span>
                        )}
                      </div>
                      <p className="text-[11px] text-slate-400">
                        {info.count} occurrence{info.count !== 1 ? 's' : ''}
                        {knowledge?.eli5 ? ` — ${knowledge.eli5.slice(0, 80)}${knowledge.eli5.length > 80 ? '...' : ''}` : ''}
                      </p>
                      {knowledge?.how?.[0] && (
                        <p className="text-[10px] text-slate-500 mt-1.5 flex items-start gap-1">
                          <span className="text-green-500 font-bold">1.</span>
                          <span className="truncate">{knowledge.how[0]}</span>
                        </p>
                      )}
                    </div>
                  );
                })}
              </div>
            </div>

            {sortedFindings.length > 5 && (
              <p className="text-xs text-slate-500 text-center">
                +{sortedFindings.length - 5} more issue{sortedFindings.length - 5 !== 1 ? 's' : ''} — scroll down to Findings or use the Wizard for guided triage
              </p>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

// ─── Findings Panel ──────────────────────────────────────────
interface FindingsPanelProps {
  results: AnalysisResults;
  category: CategoryId;
  eli5Mode: boolean;
  detectedVendors?: string[];
  onFollowStream?: (streamId: string) => void;
}

function FindingsPanel({ results, category, eli5Mode, detectedVendors, onFollowStream }: FindingsPanelProps) {
  // Column definitions for virtualized tables (stable references via useMemo)
  const retransColumns: Column<import('../../types').TCPFlow>[] = useMemo(() => [
    {
      key: 'src',
      label: 'Source',
      width: 'w-1/2',
      render: (r) => <span className="font-mono text-slate-400">{r.src_ip}:{r.src_port}</span>,
      sortValue: (r) => r.src_ip,
    },
    {
      key: 'dst',
      label: 'Destination',
      width: 'w-1/2',
      render: (r) => <span className="font-mono text-slate-400">{r.dst_ip}:{r.dst_port}</span>,
      sortValue: (r) => r.dst_ip,
    },
  ], []);

  const trafficColumns: Column<import('../../types').TrafficFlow>[] = useMemo(() => [
    {
      key: 'src',
      label: 'Source',
      width: 'w-1/4',
      render: (f) => <span className="font-mono text-slate-400">{f.src_ip}:{f.src_port}</span>,
      sortValue: (f) => f.src_ip,
    },
    {
      key: 'dst',
      label: 'Destination',
      width: 'w-1/4',
      render: (f) => <span className="font-mono text-slate-400">{f.dst_ip}:{f.dst_port}</span>,
      sortValue: (f) => f.dst_ip,
    },
    {
      key: 'proto',
      label: 'Protocol',
      width: 'w-1/6',
      render: (f) => <span className="text-slate-300">{f.protocol}</span>,
      sortValue: (f) => f.protocol,
    },
    {
      key: 'bytes',
      label: 'Bytes',
      width: 'w-1/6',
      render: (f) => <span className="text-slate-300">{(f.total_bytes / 1024).toFixed(1)} KB</span>,
      sortValue: (f) => f.total_bytes,
    },
    {
      key: 'actions',
      label: '',
      width: 'w-16',
      render: (f) => (
        <button
          onClick={() => {
            const streamId = `${f.src_ip}:${f.src_port}->${f.dst_ip}:${f.dst_port}/${f.protocol}`;
            onFollowStream?.(streamId);
          }}
          className="flex items-center gap-1 px-2 py-1 text-xs text-blue-400 hover:text-blue-300 hover:bg-blue-500/10 rounded transition-colors"
          title="Follow Stream"
        >
          <ArrowRightLeft className="w-3 h-3" />
        </button>
      ),
    },
  ], []);

  const rttColumns: Column<import('../../types').RTTFlow>[] = useMemo(() => [
    {
      key: 'src',
      label: 'Source',
      width: 'w-1/3',
      render: (r) => <span className="font-mono text-slate-400">{r.src_ip}:{r.src_port}</span>,
      sortValue: (r) => r.src_ip,
    },
    {
      key: 'dst',
      label: 'Destination',
      width: 'w-1/3',
      render: (r) => <span className="font-mono text-slate-400">{r.dst_ip}:{r.dst_port}</span>,
      sortValue: (r) => r.dst_ip,
    },
    {
      key: 'avgrtt',
      label: 'Avg RTT',
      width: 'w-1/6',
      render: (r) => <span className={r.avg_rtt_ms > 100 ? 'text-amber-400' : 'text-slate-300'}>{r.avg_rtt_ms.toFixed(1)}ms</span>,
      sortValue: (r) => r.avg_rtt_ms,
    },
    {
      key: 'maxrtt',
      label: 'Max RTT',
      width: 'w-1/6',
      render: (r) => <span className={r.max_rtt_ms > 200 ? 'text-red-400' : 'text-slate-400'}>{r.max_rtt_ms.toFixed(1)}ms</span>,
      sortValue: (r) => r.max_rtt_ms,
    },
  ], []);

  const findings: React.ReactNode[] = [];

  // ─── SECURITY FINDINGS ─────────────────────────────────────
  if (category === 'all' || category === 'security') {
    // DDoS
    const ddos = results.security?.ddos_findings || [];
    if (ddos.length > 0) {
      findings.push(
        <FindingCard
          key="ddos"
          title={`DDoS Attacks Detected`}
          severity={ddos.some(d => d.severity === 'Critical' || d.severity === 'High') ? 'Critical' : 'Warning'}
          count={ddos.length}
          description={`${ddos.length} DDoS attack pattern${ddos.length > 1 ? 's' : ''} detected including ${[...new Set(ddos.map(d => d.type))].join(', ')}`}
          knowledge={issueKnowledgeBase.ddos_syn_flood}
          eli5Mode={eli5Mode}
          findingKey="ddos_syn_flood"
          detectedVendors={detectedVendors}
          details={
            <div className="overflow-x-auto">
              <table className="w-full text-xs">
                <thead>
                  <tr className="border-b border-slate-700/50">
                    <th className="px-3 py-2 text-left text-slate-500 font-medium">Type</th>
                    <th className="px-3 py-2 text-left text-slate-500 font-medium">Source</th>
                    <th className="px-3 py-2 text-left text-slate-500 font-medium">Target</th>
                    <th className="px-3 py-2 text-left text-slate-500 font-medium">Packets</th>
                    <th className="px-3 py-2 text-left text-slate-500 font-medium">Severity</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-700/30">
                  {ddos.slice(0, 15).map((d, i) => {
                    const sev = getSeverityConfig(d.severity);
                    return (
                      <tr key={i} className="hover:bg-slate-700/20">
                        <td className="px-3 py-2 text-slate-300">{d.type}</td>
                        <td className="px-3 py-2 font-mono text-slate-400">{d.source_ip}</td>
                        <td className="px-3 py-2 font-mono text-slate-400">{d.target_ip || '-'}</td>
                        <td className="px-3 py-2 text-slate-400">{d.packet_count.toLocaleString()}</td>
                        <td className="px-3 py-2">
                          <span className={`px-1.5 py-0.5 rounded text-xs ${sev.bg} ${sev.text}`}>{d.severity}</span>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
              {ddos.length > 15 && <p className="text-xs text-slate-500 px-3 py-2">...and {ddos.length - 15} more</p>}
            </div>
          }
        />
      );
    }

    // Port Scans
    const portScans = results.security?.port_scan_findings || [];
    if (portScans.length > 0) {
      findings.push(
        <FindingCard
          key="portscan"
          title="Port Scanning Detected"
          severity="Warning"
          findingKey="port_scan"
          detectedVendors={detectedVendors}
          count={portScans.length}
          description={`${portScans.length} port scanning activit${portScans.length > 1 ? 'ies' : 'y'} from ${[...new Set(portScans.map(p => p.source_ip))].length} source${[...new Set(portScans.map(p => p.source_ip))].length > 1 ? 's' : ''}`}
          knowledge={issueKnowledgeBase.port_scan}
          eli5Mode={eli5Mode}
          details={
            <div className="overflow-x-auto">
              <table className="w-full text-xs">
                <thead>
                  <tr className="border-b border-slate-700/50">
                    <th className="px-3 py-2 text-left text-slate-500 font-medium">Source</th>
                    <th className="px-3 py-2 text-left text-slate-500 font-medium">Target</th>
                    <th className="px-3 py-2 text-left text-slate-500 font-medium">Type</th>
                    <th className="px-3 py-2 text-left text-slate-500 font-medium">Ports Scanned</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-700/30">
                  {portScans.slice(0, 10).map((p, i) => (
                    <tr key={i} className="hover:bg-slate-700/20">
                      <td className="px-3 py-2 font-mono text-slate-400">{p.source_ip}</td>
                      <td className="px-3 py-2 font-mono text-slate-400">{p.target_ip || '-'}</td>
                      <td className="px-3 py-2 text-slate-300">{p.type}</td>
                      <td className="px-3 py-2 text-slate-400">{p.ports_scanned}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          }
        />
      );
    }

    // TLS Weaknesses
    const tls = results.security?.tls_security_findings || [];
    if (tls.length > 0) {
      findings.push(
        <FindingCard
          key="tls"
          title="TLS Security Weaknesses"
          severity="Warning"
          findingKey="tls_weakness"
          detectedVendors={detectedVendors}
          count={tls.length}
          description={`${tls.length} TLS weakness${tls.length > 1 ? 'es' : ''} found including ${[...new Set(tls.map(t => t.weakness_type))].join(', ')}`}
          knowledge={issueKnowledgeBase.tls_weakness}
          eli5Mode={eli5Mode}
          details={
            <div className="overflow-x-auto">
              <table className="w-full text-xs">
                <thead>
                  <tr className="border-b border-slate-700/50">
                    <th className="px-3 py-2 text-left text-slate-500 font-medium">Server</th>
                    <th className="px-3 py-2 text-left text-slate-500 font-medium">Version</th>
                    <th className="px-3 py-2 text-left text-slate-500 font-medium">Weakness</th>
                    <th className="px-3 py-2 text-left text-slate-500 font-medium">Description</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-700/30">
                  {tls.slice(0, 10).map((t, i) => (
                    <tr key={i} className="hover:bg-slate-700/20">
                      <td className="px-3 py-2 font-mono text-slate-400">{t.server_ip}:{t.server_port}</td>
                      <td className="px-3 py-2 text-slate-300">{t.tls_version}</td>
                      <td className="px-3 py-2 text-slate-300">{t.weakness_type}</td>
                      <td className="px-3 py-2 text-slate-400 max-w-xs truncate">{t.description}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          }
        />
      );
    }

    // DNS Anomalies
    const dns = results.dns_anomalies || [];
    if (dns.length > 0) {
      findings.push(
        <FindingCard
          key="dns"
          title="DNS Anomalies"
          severity="Warning"
          findingKey="dns_anomaly"
          detectedVendors={detectedVendors}
          count={dns.length}
          description={`${dns.length} suspicious DNS quer${dns.length > 1 ? 'ies' : 'y'} detected from ${[...new Set(dns.map(d => d.server_ip))].length} DNS server${[...new Set(dns.map(d => d.server_ip))].length > 1 ? 's' : ''}`}
          knowledge={issueKnowledgeBase.dns_anomaly}
          eli5Mode={eli5Mode}
          details={
            <div className="overflow-x-auto">
              <table className="w-full text-xs">
                <thead>
                  <tr className="border-b border-slate-700/50">
                    <th className="px-3 py-2 text-left text-slate-500 font-medium">Query</th>
                    <th className="px-3 py-2 text-left text-slate-500 font-medium">Server</th>
                    <th className="px-3 py-2 text-left text-slate-500 font-medium">Answer</th>
                    <th className="px-3 py-2 text-left text-slate-500 font-medium">Reason</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-700/30">
                  {dns.slice(0, 15).map((d, i) => (
                    <tr key={i} className="hover:bg-slate-700/20">
                      <td className="px-3 py-2 font-mono text-slate-400 max-w-[200px] truncate">{d.query}</td>
                      <td className="px-3 py-2 font-mono text-slate-400">{d.server_ip}</td>
                      <td className="px-3 py-2 font-mono text-slate-400">{d.answer_ip || '-'}</td>
                      <td className="px-3 py-2 text-slate-400 text-xs">{d.reason}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {dns.length > 15 && <p className="text-xs text-slate-500 px-3 py-2">...and {dns.length - 15} more</p>}
            </div>
          }
        />
      );
    }

    // ARP Conflicts
    const arp = results.arp_conflicts || [];
    if (arp.length > 0) {
      findings.push(
        <FindingCard
          key="arp"
          title="ARP Conflicts"
          severity="Warning"
          findingKey="arp_conflict"
          detectedVendors={detectedVendors}
          count={arp.length}
          description={`${arp.length} IP address${arp.length > 1 ? 'es have' : ' has'} multiple MAC addresses responding`}
          knowledge={issueKnowledgeBase.arp_conflict}
          eli5Mode={eli5Mode}
          details={
            <div className="overflow-x-auto">
              <table className="w-full text-xs">
                <thead>
                  <tr className="border-b border-slate-700/50">
                    <th className="px-3 py-2 text-left text-slate-500 font-medium">IP Address</th>
                    <th className="px-3 py-2 text-left text-slate-500 font-medium">MAC Addresses</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-700/30">
                  {arp.map((a, i) => (
                    <tr key={i} className="hover:bg-slate-700/20">
                      <td className="px-3 py-2 font-mono text-white">{a.ip_address}</td>
                      <td className="px-3 py-2">
                        <div className="flex flex-wrap gap-1">
                          {a.mac_addresses.map((mac, j) => (
                            <span key={j} className="font-mono text-xs bg-slate-700 px-2 py-0.5 rounded text-slate-300">{mac}</span>
                          ))}
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          }
        />
      );
    }

    // TLS Certificates
    const certs = results.tls_certs?.filter(c => c.is_expired || c.is_self_signed) || [];
    if (certs.length > 0) {
      findings.push(
        <FindingCard
          key="certs"
          title="TLS Certificate Issues"
          severity="Warning"
          findingKey="tls_certificate_issue"
          detectedVendors={detectedVendors}
          count={certs.length}
          description={`${certs.length} certificate${certs.length > 1 ? 's' : ''} with issues (expired or self-signed)`}
          knowledge={issueKnowledgeBase.tls_certificate_issue}
          eli5Mode={eli5Mode}
        />
      );
    }

    // DNS Tunneling
    const dnsTunnel = results.dns_tunneling_findings || [];
    if (dnsTunnel.length > 0) {
      findings.push(
        <FindingCard
          key="dns-tunnel"
          title="DNS Tunneling Suspected"
          severity="Critical"
          findingKey="dns_tunneling"
          detectedVendors={detectedVendors}
          count={dnsTunnel.length}
          description={`${dnsTunnel.length} suspected DNS tunneling activit${dnsTunnel.length > 1 ? 'ies' : 'y'} — data may be exfiltrated via DNS`}
          knowledge={issueKnowledgeBase.dns_tunneling}
          eli5Mode={eli5Mode}
          details={
            <div className="overflow-x-auto">
              <table className="w-full text-xs">
                <thead>
                  <tr className="border-b border-slate-700/50">
                    <th className="px-3 py-2 text-left text-slate-500 font-medium">Source</th>
                    <th className="px-3 py-2 text-left text-slate-500 font-medium">Domain</th>
                    <th className="px-3 py-2 text-left text-slate-500 font-medium">Queries</th>
                    <th className="px-3 py-2 text-left text-slate-500 font-medium">Avg Length</th>
                    <th className="px-3 py-2 text-left text-slate-500 font-medium">Entropy</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-700/30">
                  {dnsTunnel.map((t, i) => (
                    <tr key={i} className="hover:bg-slate-700/20">
                      <td className="px-3 py-2 font-mono text-slate-400">{t.source_ip}</td>
                      <td className="px-3 py-2 font-mono text-red-400">{t.domain}</td>
                      <td className="px-3 py-2 text-slate-400">{t.query_count}</td>
                      <td className="px-3 py-2 text-slate-400">{t.avg_query_length.toFixed(0)} chars</td>
                      <td className="px-3 py-2 text-amber-400">{t.entropy_score.toFixed(2)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          }
        />
      );
    }

    // C2 Beaconing
    const c2 = results.c2_beaconing_findings || [];
    if (c2.length > 0) {
      findings.push(
        <FindingCard
          key="c2"
          title="C2 Beaconing Detected"
          severity="Critical"
          findingKey="c2_beaconing"
          detectedVendors={detectedVendors}
          count={c2.length}
          description={`${c2.length} host${c2.length > 1 ? 's are' : ' is'} exhibiting Command-and-Control beaconing patterns`}
          knowledge={issueKnowledgeBase.c2_beaconing}
          eli5Mode={eli5Mode}
          details={
            <div className="overflow-x-auto">
              <table className="w-full text-xs">
                <thead>
                  <tr className="border-b border-slate-700/50">
                    <th className="px-3 py-2 text-left text-slate-500 font-medium">Source</th>
                    <th className="px-3 py-2 text-left text-slate-500 font-medium">Destination</th>
                    <th className="px-3 py-2 text-left text-slate-500 font-medium">Interval</th>
                    <th className="px-3 py-2 text-left text-slate-500 font-medium">Jitter</th>
                    <th className="px-3 py-2 text-left text-slate-500 font-medium">Confidence</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-700/30">
                  {c2.map((b, i) => {
                    const confColor = b.confidence === 'High' ? 'text-red-400' : b.confidence === 'Medium' ? 'text-amber-400' : 'text-blue-400';
                    return (
                      <tr key={i} className="hover:bg-slate-700/20">
                        <td className="px-3 py-2 font-mono text-slate-400">{b.source_ip}</td>
                        <td className="px-3 py-2 font-mono text-slate-400">{b.dest_ip}:{b.dest_port}</td>
                        <td className="px-3 py-2 text-slate-300">{b.beacon_interval_sec.toFixed(0)}s</td>
                        <td className="px-3 py-2 text-slate-400">{b.interval_jitter_pct.toFixed(1)}%</td>
                        <td className={`px-3 py-2 font-medium ${confColor}`}>{b.confidence}</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          }
        />
      );
    }
  }

  // ─── PERFORMANCE FINDINGS ──────────────────────────────────
  if (category === 'all' || category === 'performance') {
    // TCP Retransmissions
    const retrans = results.tcp_retransmissions || [];
    if (retrans.length > 0) {
      findings.push(
        <FindingCard
          key="retrans"
          title="TCP Retransmissions"
          findingKey="tcp_retransmission"
          detectedVendors={detectedVendors}
          severity={retrans.length > 500 ? 'Critical' : 'Warning'}
          count={retrans.length}
          description={`${retrans.length.toLocaleString()} retransmitted packets detected across ${[...new Set(retrans.map(r => r.src_ip))].length} sources`}
          knowledge={issueKnowledgeBase.tcp_retransmission}
          eli5Mode={eli5Mode}
          details={
            <div className="space-y-4">
              {/* Summary stats */}
              <div className="grid grid-cols-3 gap-3">
                <div className="bg-slate-900/40 rounded-lg p-3 text-center">
                  <p className="text-lg font-bold text-amber-400">{retrans.length.toLocaleString()}</p>
                  <p className="text-xs text-slate-500">Total</p>
                </div>
                <div className="bg-slate-900/40 rounded-lg p-3 text-center">
                  <p className="text-lg font-bold text-white">{[...new Set(retrans.map(r => r.src_ip))].length}</p>
                  <p className="text-xs text-slate-500">Sources</p>
                </div>
                <div className="bg-slate-900/40 rounded-lg p-3 text-center">
                  <p className="text-lg font-bold text-white">{[...new Set(retrans.map(r => `${r.dst_ip}:${r.dst_port}`))].length}</p>
                  <p className="text-xs text-slate-500">Destinations</p>
                </div>
              </div>
              {/* Virtualized retransmission flow table — handles 10k+ rows */}
              <VirtualizedFlowTable
                data={retrans}
                rowHeight={34}
                maxHeight={340}
                searchable={retrans.length > 50}
                searchPlaceholder="Filter by IP or port..."
                searchFilter={(r, q) =>
                  r.src_ip.includes(q) || r.dst_ip.includes(q) ||
                  String(r.src_port).includes(q) || String(r.dst_port).includes(q)
                }
                columns={retransColumns}
              />
            </div>
          }
        />
      );
    }

    // Packet Loss
    const pktLoss = results.packet_loss;
    if (pktLoss && pktLoss.packets_lost > 0) {
      const lossPct = pktLoss.loss_percentage;
      const lossSeverity = lossPct > 5 ? 'Critical' : lossPct > 1 ? 'Warning' : 'Info';
      findings.push(
        <FindingCard
          key="packet-loss"
          title="Packet Loss Detected"
          findingKey="packet_loss"
          detectedVendors={detectedVendors}
          severity={lossSeverity}
          count={pktLoss.packets_lost}
          description={`${lossPct.toFixed(1)}% packet loss (${pktLoss.packets_lost.toLocaleString()} of ${pktLoss.total_packets_sent.toLocaleString()} packets lost)`}
          knowledge={issueKnowledgeBase.packet_loss}
          eli5Mode={eli5Mode}
          details={
            <div className="space-y-4">
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                <div className="bg-slate-900/40 rounded-lg p-3 text-center">
                  <p className="text-lg font-bold text-white">{pktLoss.total_packets_sent.toLocaleString()}</p>
                  <p className="text-xs text-slate-500">Packets Sent</p>
                </div>
                <div className="bg-slate-900/40 rounded-lg p-3 text-center">
                  <p className="text-lg font-bold text-red-400">{pktLoss.packets_lost.toLocaleString()}</p>
                  <p className="text-xs text-slate-500">Packets Lost</p>
                </div>
                <div className="bg-slate-900/40 rounded-lg p-3 text-center">
                  <p className={`text-lg font-bold ${lossPct > 5 ? 'text-red-400' : lossPct > 1 ? 'text-amber-400' : 'text-green-400'}`}>{lossPct.toFixed(2)}%</p>
                  <p className="text-xs text-slate-500">Loss Rate</p>
                </div>
                <div className="bg-slate-900/40 rounded-lg p-3 text-center">
                  <p className="text-lg font-bold text-amber-400">{pktLoss.retransmission_rate.toFixed(2)}%</p>
                  <p className="text-xs text-slate-500">Retransmit Rate</p>
                </div>
              </div>
              {pktLoss.per_flow_loss && pktLoss.per_flow_loss.length > 0 && (
                <div className="overflow-x-auto">
                  <table className="w-full text-xs">
                    <thead>
                      <tr className="border-b border-slate-700/50">
                        <th className="px-3 py-2 text-left text-slate-500 font-medium">Source</th>
                        <th className="px-3 py-2 text-left text-slate-500 font-medium">Destination</th>
                        <th className="px-3 py-2 text-right text-slate-500 font-medium">Sent</th>
                        <th className="px-3 py-2 text-right text-slate-500 font-medium">Lost</th>
                        <th className="px-3 py-2 text-right text-slate-500 font-medium">Loss %</th>
                      </tr>
                    </thead>
                    <tbody>
                      {pktLoss.per_flow_loss.sort((a, b) => b.loss_percentage - a.loss_percentage).slice(0, 10).map((f, i) => (
                        <tr key={i} className="border-b border-slate-700/20">
                          <td className="px-3 py-1.5 font-mono text-slate-300">{f.src_ip}:{f.src_port}</td>
                          <td className="px-3 py-1.5 font-mono text-slate-300">{f.dst_ip}:{f.dst_port}</td>
                          <td className="px-3 py-1.5 text-right text-slate-400">{f.packets_sent.toLocaleString()}</td>
                          <td className="px-3 py-1.5 text-right text-red-400">{f.packets_lost.toLocaleString()}</td>
                          <td className="px-3 py-1.5 text-right font-medium text-red-400">{f.loss_percentage.toFixed(1)}%</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                  {pktLoss.per_flow_loss.length > 10 && <p className="text-xs text-slate-500 px-3 py-2">...and {pktLoss.per_flow_loss.length - 10} more flows</p>}
                </div>
              )}
            </div>
          }
        />
      );
    }

    // Failed TCP Handshakes
    const failedH = results.tcp_handshakes?.failed_handshake_attempts || [];
    if (failedH.length > 0) {
      const successH = results.tcp_handshakes?.successful_handshakes || [];
      const total = successH.length + failedH.length;
      const failRate = total > 0 ? ((failedH.length / total) * 100).toFixed(1) : '0';

      findings.push(
        <FindingCard
          key="handshake"
          title="TCP Handshake Failures"
          severity="Warning"
          findingKey="tcp_handshake_failure"
          detectedVendors={detectedVendors}
          count={failedH.length}
          description={`${failedH.length} failed out of ${total} total handshakes (${failRate}% failure rate)`}
          knowledge={issueKnowledgeBase.tcp_handshake_failure}
          eli5Mode={eli5Mode}
          details={
            <div className="space-y-4">
              <div className="grid grid-cols-4 gap-3">
                <div className="bg-slate-900/40 rounded-lg p-3 text-center">
                  <p className="text-lg font-bold text-white">{total}</p>
                  <p className="text-xs text-slate-500">Total</p>
                </div>
                <div className="bg-green-500/10 rounded-lg p-3 text-center">
                  <p className="text-lg font-bold text-green-400">{successH.length}</p>
                  <p className="text-xs text-slate-500">Success</p>
                </div>
                <div className="bg-red-500/10 rounded-lg p-3 text-center">
                  <p className="text-lg font-bold text-red-400">{failedH.length}</p>
                  <p className="text-xs text-slate-500">Failed</p>
                </div>
                <div className="bg-blue-500/10 rounded-lg p-3 text-center">
                  <p className="text-lg font-bold text-blue-400">{(100 - parseFloat(failRate)).toFixed(1)}%</p>
                  <p className="text-xs text-slate-500">Success Rate</p>
                </div>
              </div>
              <div className="overflow-x-auto">
                <table className="w-full text-xs">
                  <thead>
                    <tr className="border-b border-slate-700/50">
                      <th className="px-3 py-2 text-left text-slate-500 font-medium">Source</th>
                      <th className="px-3 py-2 text-left text-slate-500 font-medium">Destination</th>
                      <th className="px-3 py-2 text-left text-slate-500 font-medium">State</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-700/30">
                    {failedH.slice(0, 10).map((h, i) => (
                      <tr key={i} className="hover:bg-slate-700/20">
                        <td className="px-3 py-2 font-mono text-slate-400">{h.src_ip}:{h.src_port}</td>
                        <td className="px-3 py-2 font-mono text-slate-400">{h.dst_ip}:{h.dst_port}</td>
                        <td className="px-3 py-2 text-red-400 text-xs">{h.state}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          }
        />
      );
    }

    // TCP Window Issues
    const tcpWin = results.tcp_window_findings || [];
    if (tcpWin.length > 0) {
      const zeroWin = tcpWin.filter(w => w.type === 'Zero Window');
      const smallWin = tcpWin.filter(w => w.type === 'Small Window');
      findings.push(
        <FindingCard
          key="tcp-window"
          title="TCP Window Size Issues"
          findingKey="tcp_zero_window"
          detectedVendors={detectedVendors}
          severity={zeroWin.length > 0 ? 'Critical' : 'Warning'}
          count={tcpWin.length}
          description={`${zeroWin.length > 0 ? `${zeroWin.length} Zero Window` : ''}${zeroWin.length > 0 && smallWin.length > 0 ? ' and ' : ''}${smallWin.length > 0 ? `${smallWin.length} Small Window` : ''} events — receivers are struggling to keep up`}
          knowledge={zeroWin.length > 0 ? issueKnowledgeBase.tcp_zero_window : issueKnowledgeBase.tcp_small_window}
          eli5Mode={eli5Mode}
          details={
            <div className="overflow-x-auto">
              <table className="w-full text-xs">
                <thead>
                  <tr className="border-b border-slate-700/50">
                    <th className="px-3 py-2 text-left text-slate-500 font-medium">Type</th>
                    <th className="px-3 py-2 text-left text-slate-500 font-medium">Source</th>
                    <th className="px-3 py-2 text-left text-slate-500 font-medium">Destination</th>
                    <th className="px-3 py-2 text-left text-slate-500 font-medium">Window</th>
                    <th className="px-3 py-2 text-left text-slate-500 font-medium">Count</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-700/30">
                  {tcpWin.slice(0, 15).map((w, i) => {
                    const typeColor = w.type === 'Zero Window' ? 'text-red-400' : 'text-amber-400';
                    return (
                      <tr key={i} className="hover:bg-slate-700/20">
                        <td className={`px-3 py-2 font-medium ${typeColor}`}>{w.type}</td>
                        <td className="px-3 py-2 font-mono text-slate-400">{w.src_ip}:{w.src_port}</td>
                        <td className="px-3 py-2 font-mono text-slate-400">{w.dst_ip}:{w.dst_port}</td>
                        <td className="px-3 py-2 text-slate-300">{w.window_size} bytes</td>
                        <td className="px-3 py-2 text-slate-400">{w.count}</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
              {tcpWin.length > 15 && <p className="text-xs text-slate-500 px-3 py-2">...and {tcpWin.length - 15} more</p>}
            </div>
          }
        />
      );
    }

    // TCP Out-of-Order
    const tcpOoo = results.tcp_out_of_order_flows || [];
    if (tcpOoo.length > 0) {
      findings.push(
        <FindingCard
          key="tcp-ooo"
          title="TCP Out-of-Order Packets"
          findingKey="tcp_out_of_order"
          detectedVendors={detectedVendors}
          severity={tcpOoo.some(o => o.percentage > 10) ? 'Critical' : 'Warning'}
          count={tcpOoo.length}
          description={`${tcpOoo.length} flow${tcpOoo.length > 1 ? 's' : ''} with significant out-of-order packets — possible routing or load balancing issues`}
          knowledge={issueKnowledgeBase.tcp_out_of_order}
          eli5Mode={eli5Mode}
          details={
            <div className="overflow-x-auto">
              <table className="w-full text-xs">
                <thead>
                  <tr className="border-b border-slate-700/50">
                    <th className="px-3 py-2 text-left text-slate-500 font-medium">Source</th>
                    <th className="px-3 py-2 text-left text-slate-500 font-medium">Destination</th>
                    <th className="px-3 py-2 text-left text-slate-500 font-medium">OOO Packets</th>
                    <th className="px-3 py-2 text-left text-slate-500 font-medium">Total</th>
                    <th className="px-3 py-2 text-left text-slate-500 font-medium">Rate</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-700/30">
                  {tcpOoo.slice(0, 15).map((o, i) => {
                    const rateColor = o.percentage > 10 ? 'text-red-400' : 'text-amber-400';
                    return (
                      <tr key={i} className="hover:bg-slate-700/20">
                        <td className="px-3 py-2 font-mono text-slate-400">{o.src_ip}:{o.src_port}</td>
                        <td className="px-3 py-2 font-mono text-slate-400">{o.dst_ip}:{o.dst_port}</td>
                        <td className="px-3 py-2 text-slate-300">{o.out_of_order_count.toLocaleString()}</td>
                        <td className="px-3 py-2 text-slate-400">{o.total_packets.toLocaleString()}</td>
                        <td className={`px-3 py-2 font-medium ${rateColor}`}>{o.percentage.toFixed(1)}%</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          }
        />
      );
    }

    // Traffic Flows (virtualized for large datasets)
    const trafficFlows = results.traffic_analysis || [];
    if (trafficFlows.length > 0) {
      const totalBytes = results.total_bytes || trafficFlows.reduce((sum, f) => sum + f.total_bytes, 0);
      findings.push(
        <FindingCard
          key="traffic-flows"
          title="Traffic Flows"
          severity="Info"
          count={trafficFlows.length}
          description={`${trafficFlows.length.toLocaleString()} flow${trafficFlows.length > 1 ? 's' : ''} captured, ${(totalBytes / 1024 / 1024).toFixed(2)} MB total`}
          knowledge={null}
          eli5Mode={eli5Mode}
          details={
            <div className="space-y-4">
              <div className="grid grid-cols-3 gap-3">
                <div className="bg-slate-900/40 rounded-lg p-3 text-center">
                  <p className="text-lg font-bold text-white">{trafficFlows.length.toLocaleString()}</p>
                  <p className="text-xs text-slate-500">Total Flows</p>
                </div>
                <div className="bg-slate-900/40 rounded-lg p-3 text-center">
                  <p className="text-lg font-bold text-white">{[...new Set(trafficFlows.map(f => f.src_ip))].length}</p>
                  <p className="text-xs text-slate-500">Sources</p>
                </div>
                <div className="bg-slate-900/40 rounded-lg p-3 text-center">
                  <p className="text-lg font-bold text-white">{[...new Set(trafficFlows.map(f => f.dst_ip))].length}</p>
                  <p className="text-xs text-slate-500">Destinations</p>
                </div>
              </div>
              <VirtualizedFlowTable
                data={trafficFlows}
                rowHeight={34}
                maxHeight={340}
                searchable={trafficFlows.length > 50}
                searchPlaceholder="Filter by IP, port, or protocol..."
                searchFilter={(f, q) =>
                  f.src_ip.includes(q) || f.dst_ip.includes(q) ||
                  String(f.src_port).includes(q) || String(f.dst_port).includes(q) ||
                  f.protocol.toLowerCase().includes(q)
                }
                columns={trafficColumns}
              />
            </div>
          }
        />
      );
    }

    // RTT Analysis (virtualized for large datasets)
    const rttFlows = results.rtt_analysis || [];
    if (rttFlows.length > 0) {
      const highRtt = rttFlows.filter(r => r.avg_rtt_ms > 100);
      const veryHighRtt = rttFlows.filter(r => r.avg_rtt_ms > 200);
      findings.push(
        <FindingCard
          key="rtt-analysis"
          title="RTT Analysis"
          findingKey="high_rtt"
          detectedVendors={detectedVendors}
          severity={veryHighRtt.length > 0 ? 'Warning' : 'Info'}
          count={rttFlows.length}
          description={`${rttFlows.length} flow${rttFlows.length > 1 ? 's' : ''} with RTT measurements${highRtt.length > 0 ? `, ${highRtt.length} with >100ms avg` : ''}`}
          knowledge={highRtt.length > 0 ? issueKnowledgeBase.high_rtt : null}
          eli5Mode={eli5Mode}
          details={
            <div className="space-y-4">
              <div className="grid grid-cols-4 gap-3">
                <div className="bg-slate-900/40 rounded-lg p-3 text-center">
                  <p className="text-lg font-bold text-white">{rttFlows.length.toLocaleString()}</p>
                  <p className="text-xs text-slate-500">Total Flows</p>
                </div>
                <div className="bg-amber-500/10 rounded-lg p-3 text-center">
                  <p className="text-lg font-bold text-amber-400">{highRtt.length}</p>
                  <p className="text-xs text-slate-500">&gt;100ms RTT</p>
                </div>
                <div className="bg-red-500/10 rounded-lg p-3 text-center">
                  <p className="text-lg font-bold text-red-400">{veryHighRtt.length}</p>
                  <p className="text-xs text-slate-500">&gt;200ms RTT</p>
                </div>
                <div className="bg-slate-900/40 rounded-lg p-3 text-center">
                  <p className="text-lg font-bold text-blue-400">
                    {(rttFlows.reduce((sum, r) => sum + r.avg_rtt_ms, 0) / rttFlows.length).toFixed(1)}ms
                  </p>
                  <p className="text-xs text-slate-500">Avg RTT</p>
                </div>
              </div>
              <VirtualizedFlowTable
                data={rttFlows}
                rowHeight={34}
                maxHeight={340}
                searchable={rttFlows.length > 50}
                searchPlaceholder="Filter by IP or port..."
                searchFilter={(r, q) =>
                  r.src_ip.includes(q) || r.dst_ip.includes(q) ||
                  String(r.src_port).includes(q) || String(r.dst_port).includes(q)
                }
                columns={rttColumns}
              />
            </div>
          }
        />
      );
    }
  }

  // ─── STABILITY FINDINGS ────────────────────────────────────
  if (category === 'all' || category === 'stability') {
    // Interface Stability / Flapping findings (BFD, IKE, STP TCN, HSRP, VRRP)
    const stabilityFindings = results.stability_findings || [];
    if (stabilityFindings.length > 0) {
      // Map finding type to knowledge base key
      const typeToKB: Record<string, string> = {
        'BFD Flapping': 'bfd_flapping',
        'IKE Tunnel Rebuild': 'ike_tunnel_rebuild',
        'STP TCN Storm': 'stp_tcn_storm',
        'HSRP Flapping': 'interface_flapping',
        'VRRP Flapping': 'interface_flapping',
      };

      stabilityFindings.forEach((sf, idx) => {
        const kbKey = typeToKB[sf.type] || 'interface_flapping';
        findings.push(
          <FindingCard
            key={`stability-${idx}`}
            title={`Interface Instability: ${sf.type}`}
            severity={sf.severity === 'Critical' ? 'Critical' : sf.severity === 'High' ? 'Warning' : 'Info'}
            findingKey={kbKey}
            detectedVendors={detectedVendors}
            count={sf.state_changes}
            description={sf.description}
            knowledge={issueKnowledgeBase[kbKey]}
            eli5Mode={eli5Mode}
            details={
              <div className="space-y-2 text-xs">
                <div className="grid grid-cols-2 gap-2">
                  <div className="bg-slate-800/60 rounded-lg p-2">
                    <span className="text-slate-500">Protocol</span>
                    <div className="text-white font-medium">{sf.protocol}</div>
                  </div>
                  <div className="bg-slate-800/60 rounded-lg p-2">
                    <span className="text-slate-500">State Changes</span>
                    <div className="text-red-400 font-medium">{sf.state_changes}</div>
                  </div>
                  <div className="bg-slate-800/60 rounded-lg p-2">
                    <span className="text-slate-500">Identifier</span>
                    <div className="text-white font-mono">{sf.identifier}</div>
                  </div>
                  <div className="bg-slate-800/60 rounded-lg p-2">
                    <span className="text-slate-500">Window</span>
                    <div className="text-slate-300">{sf.window_seconds.toFixed(1)}s</div>
                  </div>
                </div>
                {sf.root_cause_hint && (
                  <div className="bg-amber-500/10 border border-amber-500/20 rounded-lg p-2 text-amber-300">
                    <span className="font-semibold">Root Cause Hint:</span> {sf.root_cause_hint}
                  </div>
                )}
              </div>
            }
          />
        );
      });
    }

    // VRRP Flapping
    const vrrpFlapping = results.lan_protocols?.vrrp_sessions?.filter(s => s.is_flapping) || [];
    if (vrrpFlapping.length > 0) {
      findings.push(
        <FindingCard
          key="vrrp"
          title="VRRP Flapping"
          severity="Critical"
          findingKey="vrrp_flapping"
          detectedVendors={detectedVendors}
          count={vrrpFlapping.length}
          description={`${vrrpFlapping.length} VRRP session${vrrpFlapping.length > 1 ? 's are' : ' is'} flapping — causing intermittent network outages`}
          knowledge={issueKnowledgeBase.vrrp_flapping}
          eli5Mode={eli5Mode}
          details={
            <div className="overflow-x-auto">
              <table className="w-full text-xs">
                <thead>
                  <tr className="border-b border-slate-700/50">
                    <th className="px-3 py-2 text-left text-slate-500 font-medium">Router ID</th>
                    <th className="px-3 py-2 text-left text-slate-500 font-medium">Master IP</th>
                    <th className="px-3 py-2 text-left text-slate-500 font-medium">Transitions</th>
                    <th className="px-3 py-2 text-left text-slate-500 font-medium">Reason</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-700/30">
                  {vrrpFlapping.map((v, i) => (
                    <tr key={i} className="hover:bg-slate-700/20">
                      <td className="px-3 py-2 text-white font-medium">{v.virtual_router_id}</td>
                      <td className="px-3 py-2 font-mono text-slate-400">{v.master_ip}</td>
                      <td className="px-3 py-2 text-red-400">{v.transition_count}</td>
                      <td className="px-3 py-2 text-slate-400">{v.flapping_reason || 'Multiple transitions detected'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          }
        />
      );
    }

    // HSRP Groups (stability info)
    const hsrp = results.lan_protocols?.hsrp_groups || [];
    if (hsrp.length > 0) {
      findings.push(
        <FindingCard
          key="hsrp"
          title="HSRP Groups Detected"
          findingKey="hsrp_instability"
          detectedVendors={detectedVendors}
          severity="Info"
          count={hsrp.length}
          description={`${hsrp.length} HSRP group${hsrp.length > 1 ? 's' : ''} detected for gateway redundancy`}
          knowledge={issueKnowledgeBase.hsrp_instability}
          eli5Mode={eli5Mode}
        />
      );
    }
  }

  // ─── SD-WAN FINDINGS ───────────────────────────────────────
  if (category === 'all' || category === 'sdwan') {
    // SD-WAN Vendors
    const vendors = results.sdwan_vendors || [];
    if (vendors.length > 0) {
      findings.push(
        <FindingCard
          key="sdwan-vendor"
          title="SD-WAN Vendor Detection"
          severity="Info"
          findingKey="sdwan_vendor_detected"
          detectedVendors={detectedVendors}
          count={vendors.length}
          description={`Insight: ${vendors.map(v => v.name).join(', ')} identified in capture — vendor-specific troubleshooting steps are now available.`}
          knowledge={issueKnowledgeBase.sdwan_vendor_detected}
          eli5Mode={eli5Mode}
          details={
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              {vendors.map((v, i) => (
                <div key={i} className="bg-slate-900/40 rounded-lg p-3 border border-slate-700/30">
                  <p className="text-sm font-medium text-white">{v.name}</p>
                  <p className="text-xs text-slate-400 mt-1">Confidence: {v.confidence}</p>
                </div>
              ))}
            </div>
          }
        />
      );
    }

    // Tunnels
    const tunnels = results.tunnel_analysis || [];
    if (tunnels.length > 0) {
      // Derive the vendor-specific Wireshark filter from tunnel sdwan_path data.
      // Deduplicate filters across all tunnels and join them.
      const tunnelFilters = [...new Set(tunnels.map(t => t.sdwan_path).filter(Boolean))];
      const vendorWiresharkFilter = tunnelFilters.length > 0 ? tunnelFilters.join(' || ') : undefined;

      findings.push(
        <FindingCard
          key="tunnels"
          title="Tunnel Protocols"
          severity="Info"
          findingKey="tunnel_flapping"
          detectedVendors={detectedVendors}
          count={tunnels.length}
          description={`Insight: ${tunnels.length} tunnel${tunnels.length > 1 ? 's' : ''} detected (${[...new Set(tunnels.map(t => t.type))].join(', ')}) — use the Wireshark filter below to isolate this traffic.`}
          knowledge={issueKnowledgeBase.tunnel_flapping}
          wiresharkFilter={vendorWiresharkFilter}
          eli5Mode={eli5Mode}
          details={
            <div className="overflow-x-auto">
              <table className="w-full text-xs">
                <thead>
                  <tr className="border-b border-slate-700/50">
                    <th className="px-3 py-2 text-left text-slate-500 font-medium">Type</th>
                    <th className="px-3 py-2 text-left text-slate-500 font-medium">Source</th>
                    <th className="px-3 py-2 text-left text-slate-500 font-medium">Destination</th>
                    <th className="px-3 py-2 text-left text-slate-500 font-medium">Packets</th>
                    <th className="px-3 py-2 text-left text-slate-500 font-medium">Confidence</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-700/30">
                  {tunnels.map((t, i) => (
                    <tr key={i} className="hover:bg-slate-700/20">
                      <td className="px-3 py-2 text-white">{t.type}</td>
                      <td className="px-3 py-2 font-mono text-slate-400">{t.src_ip}{t.src_port ? `:${t.src_port}` : ''}</td>
                      <td className="px-3 py-2 font-mono text-slate-400">{t.dst_ip}{t.dst_port ? `:${t.dst_port}` : ''}</td>
                      <td className="px-3 py-2 text-slate-400">{t.packet_count.toLocaleString()}</td>
                      <td className="px-3 py-2 text-slate-400">{t.confidence || '-'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          }
        />
      );
    }
  }

  // ─── INFRASTRUCTURE FINDINGS ───────────────────────────────
  if (category === 'all' || category === 'infrastructure') {
    // ── Issues (Warning/Critical) — rendered first ──────────

    // DHCP Findings
    const dhcp = results.dhcp_findings || [];
    if (dhcp.length > 0) {
      const rogueCount = dhcp.filter(d => d.type === 'Rogue Server').length;
      const starvCount = dhcp.filter(d => d.type === 'Starvation').length;
      const nakCount = dhcp.filter(d => d.type === 'NAK Storm').length;
      const topSeverity = rogueCount > 0 || starvCount > 0 ? 'Critical' : 'Warning';
      const types = [
        rogueCount > 0 ? `${rogueCount} Rogue Server` : '',
        starvCount > 0 ? `${starvCount} Starvation Attack` : '',
        nakCount > 0 ? `${nakCount} NAK Storm` : '',
      ].filter(Boolean).join(', ');

      findings.push(
        <FindingCard
          key="dhcp"
          title="DHCP Issues Detected"
          findingKey="dhcp_rogue_server"
          detectedVendors={detectedVendors}
          severity={topSeverity}
          count={dhcp.length}
          description={`${dhcp.length} DHCP issue${dhcp.length > 1 ? 's' : ''}: ${types}`}
          knowledge={rogueCount > 0 ? issueKnowledgeBase.dhcp_rogue_server : starvCount > 0 ? issueKnowledgeBase.dhcp_starvation : issueKnowledgeBase.dhcp_nak_storm}
          eli5Mode={eli5Mode}
          details={
            <div className="overflow-x-auto">
              <table className="w-full text-xs">
                <thead>
                  <tr className="border-b border-slate-700/50">
                    <th className="px-3 py-2 text-left text-slate-500 font-medium">Type</th>
                    <th className="px-3 py-2 text-left text-slate-500 font-medium">Server IP</th>
                    <th className="px-3 py-2 text-left text-slate-500 font-medium">Client MAC</th>
                    <th className="px-3 py-2 text-left text-slate-500 font-medium">Severity</th>
                    <th className="px-3 py-2 text-left text-slate-500 font-medium">Description</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-700/30">
                  {dhcp.map((d, i) => {
                    const sev = getSeverityConfig(d.severity);
                    return (
                      <tr key={i} className="hover:bg-slate-700/20">
                        <td className="px-3 py-2 text-white font-medium">{d.type}</td>
                        <td className="px-3 py-2 font-mono text-slate-400">{d.server_ip || '-'}</td>
                        <td className="px-3 py-2 font-mono text-slate-400">{d.client_mac || '-'}</td>
                        <td className="px-3 py-2">
                          <span className={`px-1.5 py-0.5 rounded text-xs ${sev.bg} ${sev.text}`}>{d.severity}</span>
                        </td>
                        <td className="px-3 py-2 text-slate-400 max-w-xs truncate">{d.description}</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          }
        />
      );
    }

    // NTP Findings
    const ntp = results.ntp_findings || [];
    if (ntp.length > 0) {
      const ampCount = ntp.filter(n => n.type === 'Amplification').length;
      const topSev = ampCount > 0 ? 'Critical' : 'Warning';

      findings.push(
        <FindingCard
          key="ntp"
          title="NTP Issues Detected"
          findingKey="ntp_amplification"
          detectedVendors={detectedVendors}
          severity={topSev}
          count={ntp.length}
          description={`${ntp.length} NTP issue${ntp.length > 1 ? 's' : ''}: ${[...new Set(ntp.map(n => n.type))].join(', ')}`}
          knowledge={ampCount > 0 ? issueKnowledgeBase.ntp_amplification : issueKnowledgeBase.ntp_stratum_change}
          eli5Mode={eli5Mode}
          details={
            <div className="overflow-x-auto">
              <table className="w-full text-xs">
                <thead>
                  <tr className="border-b border-slate-700/50">
                    <th className="px-3 py-2 text-left text-slate-500 font-medium">Type</th>
                    <th className="px-3 py-2 text-left text-slate-500 font-medium">Source</th>
                    <th className="px-3 py-2 text-left text-slate-500 font-medium">Severity</th>
                    <th className="px-3 py-2 text-left text-slate-500 font-medium">Description</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-700/30">
                  {ntp.map((n, i) => {
                    const sev = getSeverityConfig(n.severity);
                    return (
                      <tr key={i} className="hover:bg-slate-700/20">
                        <td className="px-3 py-2 text-white font-medium">{n.type}</td>
                        <td className="px-3 py-2 font-mono text-slate-400">{n.source_ip}</td>
                        <td className="px-3 py-2">
                          <span className={`px-1.5 py-0.5 rounded text-xs ${sev.bg} ${sev.text}`}>{n.severity}</span>
                        </td>
                        <td className="px-3 py-2 text-slate-400 max-w-xs truncate">{n.description}</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          }
        />
      );
    }

    // ICMP Anomalies
    const icmpAll = results.icmp_analysis || [];
    const icmpAnomalies = icmpAll.filter(i => i.is_anomaly);
    if (icmpAnomalies.length > 0) {
      findings.push(
        <FindingCard
          key="icmp"
          title="ICMP Anomalies Detected"
          findingKey="icmp_anomaly"
          detectedVendors={detectedVendors}
          severity="Warning"
          count={icmpAnomalies.length}
          description={`${icmpAnomalies.length} unusual ICMP pattern${icmpAnomalies.length > 1 ? 's' : ''} detected — may indicate scanning, tunneling, or routing issues`}
          knowledge={issueKnowledgeBase.icmp_anomaly}
          eli5Mode={eli5Mode}
          details={
            <div className="overflow-x-auto">
              <table className="w-full text-xs">
                <thead>
                  <tr className="border-b border-slate-700/50">
                    <th className="px-3 py-2 text-left text-slate-500 font-medium">Type</th>
                    <th className="px-3 py-2 text-left text-slate-500 font-medium">Source</th>
                    <th className="px-3 py-2 text-left text-slate-500 font-medium">Destination</th>
                    <th className="px-3 py-2 text-left text-slate-500 font-medium">Count</th>
                    <th className="px-3 py-2 text-left text-slate-500 font-medium">Description</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-700/30">
                  {icmpAnomalies.map((ic, i) => (
                    <tr key={i} className="hover:bg-slate-700/20">
                      <td className="px-3 py-2 text-white font-medium">{ic.type_name}</td>
                      <td className="px-3 py-2 font-mono text-slate-400">{ic.source_ip}</td>
                      <td className="px-3 py-2 font-mono text-slate-400">{ic.dest_ip}</td>
                      <td className="px-3 py-2 text-slate-400">{ic.count.toLocaleString()}</td>
                      <td className="px-3 py-2 text-slate-400 max-w-xs truncate">{ic.description || `ICMP type ${ic.icmp_type} code ${ic.icmp_code}`}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          }
        />
      );
    }

    // ── Insights (Info) — passive observations, rendered below issues ──
    const cdp = results.lan_protocols?.cdp_devices || [];
    const lldp = results.lan_protocols?.lldp_devices || [];
    const stp = results.lan_protocols?.stp_bridges || [];
    const vrrpOk = results.lan_protocols?.vrrp_sessions?.filter(s => !s.is_flapping) || [];
    const icmpInfo = icmpAll.filter(i => !i.is_anomaly);
    const hasInsights = cdp.length > 0 || lldp.length > 0 || stp.length > 0 || vrrpOk.length > 0 || icmpInfo.length > 0;

    if (hasInsights) {
      // Visual separator between issues and insights
      findings.push(
        <div key="infra-insights-divider" className="flex items-center gap-3 pt-2">
          <div className="h-px flex-1 bg-slate-700/50" />
          <span className="text-[10px] font-semibold text-slate-500 uppercase tracking-wider flex items-center gap-1.5">
            <Info className="w-3 h-3" />
            Infrastructure Insights
          </span>
          <div className="h-px flex-1 bg-slate-700/50" />
        </div>
      );

      // CDP Devices
      if (cdp.length > 0) {
        findings.push(
          <FindingCard
            key="cdp"
            title="CDP Device Discovery"
            severity="Info"
            count={cdp.length}
            description={`Healthy: ${cdp.length} Cisco device${cdp.length > 1 ? 's' : ''} discovered via CDP — useful for topology mapping. No action required.`}
            knowledge={issueKnowledgeBase.network_discovery}
            eli5Mode={eli5Mode}
            details={
              <div className="overflow-x-auto">
                <table className="w-full text-xs">
                  <thead>
                    <tr className="border-b border-slate-700/50">
                      <th className="px-3 py-2 text-left text-slate-500 font-medium">Device</th>
                      <th className="px-3 py-2 text-left text-slate-500 font-medium">IP</th>
                      <th className="px-3 py-2 text-left text-slate-500 font-medium">Platform</th>
                      <th className="px-3 py-2 text-left text-slate-500 font-medium">Port</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-700/30">
                    {cdp.map((c, i) => (
                      <tr key={i} className="hover:bg-slate-700/20">
                        <td className="px-3 py-2 text-white font-medium">{c.device_id}</td>
                        <td className="px-3 py-2 font-mono text-slate-400">{c.ip_address}</td>
                        <td className="px-3 py-2 text-slate-300">{c.platform}</td>
                        <td className="px-3 py-2 text-slate-400">{c.port_id}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            }
          />
        );
      }

      // LLDP Devices
      if (lldp.length > 0) {
        findings.push(
          <FindingCard
            key="lldp"
            title="LLDP Device Discovery"
            severity="Info"
            count={lldp.length}
            description={`Healthy: ${lldp.length} device${lldp.length > 1 ? 's' : ''} discovered via LLDP — use this to verify physical topology. No action required.`}
            knowledge={issueKnowledgeBase.network_discovery}
            eli5Mode={eli5Mode}
            details={
              <div className="overflow-x-auto">
                <table className="w-full text-xs">
                  <thead>
                    <tr className="border-b border-slate-700/50">
                      <th className="px-3 py-2 text-left text-slate-500 font-medium">System Name</th>
                      <th className="px-3 py-2 text-left text-slate-500 font-medium">Chassis ID</th>
                      <th className="px-3 py-2 text-left text-slate-500 font-medium">Mgmt IP</th>
                      <th className="px-3 py-2 text-left text-slate-500 font-medium">Port</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-700/30">
                    {lldp.map((l, i) => (
                      <tr key={i} className="hover:bg-slate-700/20">
                        <td className="px-3 py-2 text-white font-medium">{l.system_name || '-'}</td>
                        <td className="px-3 py-2 font-mono text-slate-400">{l.chassis_id}</td>
                        <td className="px-3 py-2 font-mono text-slate-400">{l.management_ip || '-'}</td>
                        <td className="px-3 py-2 text-slate-400">{l.port_id}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            }
          />
        );
      }

      // STP Bridges
      if (stp.length > 0) {
        findings.push(
          <FindingCard
            key="stp"
            title="STP Topology"
            severity="Info"
            count={stp.length}
            description={`Healthy: ${stp.length} STP bridge${stp.length > 1 ? 's' : ''} providing loop prevention — network redundancy is active. No action required.`}
            knowledge={issueKnowledgeBase.stp_topology}
            eli5Mode={eli5Mode}
          />
        );
      }

      // VRRP Sessions (non-flapping - info)
      if (vrrpOk.length > 0) {
        findings.push(
          <FindingCard
            key="vrrp-ok"
            title="VRRP Sessions (Healthy)"
            severity="Info"
            count={vrrpOk.length}
            description={`Healthy: ${vrrpOk.length} stable VRRP session${vrrpOk.length > 1 ? 's' : ''} providing gateway redundancy — failover protection is active. No action required.`}
            knowledge={null}
            eli5Mode={eli5Mode}
          />
        );
      }

      // ICMP informational (non-anomaly)
      if (icmpInfo.length > 0 && category === 'infrastructure') {
        findings.push(
          <FindingCard
            key="icmp-info"
            title="ICMP Traffic Summary"
            severity="Info"
            count={icmpInfo.length}
            description={`Healthy: ${icmpInfo.length} normal ICMP pattern${icmpInfo.length > 1 ? 's' : ''} observed (ping, traceroute, etc.) — standard network diagnostic traffic. No action required.`}
            knowledge={null}
            eli5Mode={eli5Mode}
          />
        );
      }
    }
  }

  // ─── APPLICATION FINDINGS ──────────────────────────────────
  if (category === 'all' || category === 'application') {
    // VoIP Analysis
    const voip = results.voip_analysis;
    if (voip && (voip.total_rtp_streams > 0 || voip.total_calls > 0)) {
      const hasJitter = voip.avg_jitter_ms > 30;
      const hasLoss = voip.packet_loss_rate > 1;
      const voipSeverity = hasJitter || hasLoss ? 'Warning' : 'Info';

      findings.push(
        <FindingCard
          key="voip"
          title="VoIP/RTP Analysis"
          findingKey="voip_quality"
          detectedVendors={detectedVendors}
          severity={voipSeverity}
          count={voip.total_rtp_streams + voip.total_calls}
          description={`${voip.total_calls} SIP call${voip.total_calls !== 1 ? 's' : ''}, ${voip.total_rtp_streams} RTP stream${voip.total_rtp_streams !== 1 ? 's' : ''}${hasJitter ? `, avg jitter ${voip.avg_jitter_ms.toFixed(1)}ms` : ''}${hasLoss ? `, ${voip.packet_loss_rate.toFixed(1)}% loss` : ''}`}
          knowledge={hasJitter ? issueKnowledgeBase.voip_jitter : null}
          eli5Mode={eli5Mode}
          details={
            <div className="space-y-4">
              <div className="grid grid-cols-4 gap-3">
                <div className="bg-slate-900/40 rounded-lg p-3 text-center">
                  <p className="text-lg font-bold text-white">{voip.total_calls}</p>
                  <p className="text-xs text-slate-500">SIP Calls</p>
                </div>
                <div className="bg-slate-900/40 rounded-lg p-3 text-center">
                  <p className="text-lg font-bold text-white">{voip.total_rtp_streams}</p>
                  <p className="text-xs text-slate-500">RTP Streams</p>
                </div>
                <div className={`rounded-lg p-3 text-center ${hasJitter ? 'bg-amber-500/10' : 'bg-slate-900/40'}`}>
                  <p className={`text-lg font-bold ${hasJitter ? 'text-amber-400' : 'text-green-400'}`}>{voip.avg_jitter_ms.toFixed(1)}ms</p>
                  <p className="text-xs text-slate-500">Avg Jitter</p>
                </div>
                <div className={`rounded-lg p-3 text-center ${hasLoss ? 'bg-red-500/10' : 'bg-slate-900/40'}`}>
                  <p className={`text-lg font-bold ${hasLoss ? 'text-red-400' : 'text-green-400'}`}>{voip.packet_loss_rate.toFixed(1)}%</p>
                  <p className="text-xs text-slate-500">Packet Loss</p>
                </div>
              </div>
              {voip.rtp_streams && voip.rtp_streams.length > 0 && (
                <div className="overflow-x-auto">
                  <table className="w-full text-xs">
                    <thead>
                      <tr className="border-b border-slate-700/50">
                        <th className="px-3 py-2 text-left text-slate-500 font-medium">Source</th>
                        <th className="px-3 py-2 text-left text-slate-500 font-medium">Destination</th>
                        <th className="px-3 py-2 text-left text-slate-500 font-medium">Codec</th>
                        <th className="px-3 py-2 text-left text-slate-500 font-medium">Packets</th>
                        <th className="px-3 py-2 text-left text-slate-500 font-medium">Jitter</th>
                        <th className="px-3 py-2 text-left text-slate-500 font-medium">Lost</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-700/30">
                      {voip.rtp_streams.slice(0, 10).map((s, i) => (
                        <tr key={i} className="hover:bg-slate-700/20">
                          <td className="px-3 py-2 font-mono text-slate-400">{s.src_ip}</td>
                          <td className="px-3 py-2 font-mono text-slate-400">{s.dst_ip}</td>
                          <td className="px-3 py-2 text-slate-300">{s.payload_type}</td>
                          <td className="px-3 py-2 text-slate-400">{s.packet_count.toLocaleString()}</td>
                          <td className={`px-3 py-2 ${s.jitter_ms > 30 ? 'text-amber-400' : 'text-slate-400'}`}>{s.jitter_ms.toFixed(1)}ms</td>
                          <td className={`px-3 py-2 ${s.lost_packets > 0 ? 'text-red-400' : 'text-slate-400'}`}>{s.lost_packets}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          }
        />
      );
    }

    // TLS Certs (all)
    const allCerts = results.tls_certs || [];
    if (allCerts.length > 0 && category === 'application') {
      findings.push(
        <FindingCard
          key="all-certs"
          title="TLS Certificates Observed"
          severity="Info"
          count={allCerts.length}
          description={`${allCerts.length} TLS certificate${allCerts.length > 1 ? 's' : ''} observed in the capture`}
          knowledge={null}
          eli5Mode={eli5Mode}
        />
      );
    }
  }

  // ─── NO FINDINGS ───────────────────────────────────────────
  if (findings.length === 0) {
    const catLabel = category === 'all' ? '' : category.charAt(0).toUpperCase() + category.slice(1);
    return (
      <div className="bg-slate-800/80 border border-slate-700/50 rounded-xl p-12 text-center">
        <CheckCircle className="w-12 h-12 text-green-400 mx-auto mb-4" />
        <h3 className="text-lg font-semibold text-white mb-2">
          {category === 'all' ? 'No Issues Detected' : `No ${catLabel} Findings`}
        </h3>
        <p className="text-slate-400 text-sm max-w-md mx-auto">
          {category === 'all'
            ? 'The analysis did not detect any significant issues in this capture. The network appears healthy.'
            : `No ${category} findings were found in this capture. Try selecting "All Findings" to see other categories.`}
        </p>
      </div>
    );
  }

  return <>{findings}</>;
}
