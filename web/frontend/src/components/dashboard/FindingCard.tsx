import { useState } from 'react';
import { ChevronDown, ChevronUp, Lightbulb, Terminal, BookOpen, Copy, Check, Zap, Eye, Wrench, Shield, AlertTriangle, ChevronRight } from 'lucide-react';
import { getSeverityConfig, type IssueKnowledge } from '../../data/knowledgeBase';
import { ConfidenceBadge, computeConfidence, type ConfidenceLevel } from './ConfidenceBadge';
import { VendorRunbookPanel } from './VendorRunbook';
import { getVendorRunbook, getVendorFindingRunbook } from '../../data/vendorRunbooks';
import { WiresharkComparisonModal, generateMockPackets, type WiresharkComparisonData } from '../learning/WiresharkComparisonModal';

interface FindingCardProps {
  title: string;
  severity: string;
  count: number;
  description: string;
  details?: React.ReactNode;
  knowledge?: IssueKnowledge | null;
  eli5Mode?: boolean;
  findingKey?: string;
  detectedVendors?: string[];
  wiresharkFilter?: string;
  packetContext?: { srcIp?: string; dstIp?: string; srcPort?: number; dstPort?: number; protocol?: string };
}

export function FindingCard({ title, severity, count, description, details, knowledge, eli5Mode, findingKey, detectedVendors, wiresharkFilter: wiresharkFilterOverride, packetContext }: FindingCardProps) {
  const [expanded, setExpanded] = useState(false);
  const [copiedCmd, setCopiedCmd] = useState<string | null>(null);
  const [wsModalData, setWsModalData] = useState<WiresharkComparisonData | null>(null);
  const [checkedSteps, setCheckedSteps] = useState<Set<string>>(new Set());
  const [showWhyDetail, setShowWhyDetail] = useState(false);
  const sev = getSeverityConfig(severity);

  const confidenceLevel: ConfidenceLevel | null = findingKey ? computeConfidence(findingKey, count, severity) : null;

  // Find matching vendor runbook
  const vendorRunbookData = findingKey && detectedVendors && detectedVendors.length > 0
    ? (() => {
        for (const vendor of detectedVendors) {
          const runbook = getVendorRunbook(vendor);
          const findingRb = getVendorFindingRunbook(vendor, findingKey);
          if (runbook && findingRb) return { vendor: runbook, finding: findingRb };
        }
        return null;
      })()
    : null;

  // Determine if detected vendor is non-Cisco (for fallback filtering)
  const detectedVendorKey = detectedVendors && detectedVendors.length > 0
    ? (() => {
        const v = detectedVendors[0].toLowerCase();
        if (v.includes('cisco') || v.includes('viptela') || v.includes('vmanage')) return 'cisco';
        return 'non-cisco';
      })()
    : null;

  // Filter out Cisco-specific content when a non-Cisco vendor is detected but no vendor runbook exists
  const isCiscoSpecific = (text: string): boolean => {
    const lower = text.toLowerCase();
    return lower.includes('show sdwan') || lower.includes('show standby') ||
      lower.includes('show vrrp') || lower.includes('vmanage') ||
      lower.includes('ios-xe') || lower.includes('vedge') || lower.includes('cedge') ||
      lower.includes('cisco tac') || lower.includes('show ip cef') ||
      lower.includes('show platform hardware') || lower.includes('show access-lists') ||
      lower.includes('show policy-map') || lower.includes('show ip dhcp snooping') ||
      lower.includes('show ntp status') || lower.includes('show mac address-table');
  };

  const filterCiscoContent = !vendorRunbookData && detectedVendorKey === 'non-cisco';

  const copyCommand = (cmd: string) => {
    navigator.clipboard.writeText(cmd).then(() => {
      setCopiedCmd(cmd);
      setTimeout(() => setCopiedCmd(null), 2000);
    });
  };

  const toggleCheck = (id: string) => {
    setCheckedSteps(prev => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  // Compute workflow progress
  const totalCheckable = knowledge ? (
    1 + // Wireshark verify step
    (knowledge.commands?.length || 0) + // Diagnose steps
    knowledge.how.length // Resolve steps
  ) : 0;
  const completedCount = checkedSteps.size;
  const progressPct = totalCheckable > 0 ? Math.round((completedCount / totalCheckable) * 100) : 0;

  return (
    <div className={`border ${sev.border} rounded-xl overflow-hidden transition-all duration-200 ${expanded ? 'ring-1 ring-slate-600' : ''}`}>
      {/* Header */}
      <button
        onClick={() => setExpanded(!expanded)}
        className={`w-full ${sev.bg} px-5 py-4 flex items-center justify-between gap-3 hover:brightness-110 transition-all`}
      >
        <div className="flex items-center gap-3 min-w-0">
          <div className={`w-2.5 h-2.5 rounded-full ${sev.dot} flex-shrink-0`} />
          <div className="text-left min-w-0">
            <div className="flex items-center gap-2 flex-wrap">
              <h3 className="font-semibold text-white text-sm">{title}</h3>
              <span className={`px-2 py-0.5 rounded-full text-xs font-medium ${sev.bg} ${sev.text} border ${sev.border}`}>
                {severity.toLowerCase() === 'info' ? 'Insight' : severity}
              </span>
              {count > 1 && (
                <span className="px-2 py-0.5 rounded-full text-xs font-medium bg-slate-700 text-slate-300">
                  {count} found
                </span>
              )}
              {confidenceLevel && <ConfidenceBadge level={confidenceLevel} />}
            </div>
            <p className="text-slate-400 text-xs mt-1 line-clamp-1">{description}</p>
          </div>
        </div>
        {expanded ? (
          <ChevronUp className="w-5 h-5 text-slate-400 flex-shrink-0" />
        ) : (
          <ChevronDown className="w-5 h-5 text-slate-400 flex-shrink-0" />
        )}
      </button>

      {/* Expanded: Forensic Workflow */}
      {expanded && (
        <div className="bg-slate-800/60 border-t border-slate-700/50">
          {knowledge && (
            <div className="p-5 space-y-5">

              {/* ELI5 Mode */}
              {eli5Mode && knowledge.eli5 && (
                <div className="bg-purple-500/10 border border-purple-500/20 rounded-lg p-4">
                  <div className="flex items-center gap-2 mb-2">
                    <Lightbulb className="w-4 h-4 text-purple-400" />
                    <span className="text-xs font-semibold text-purple-400 uppercase tracking-wide">Plain English</span>
                  </div>
                  <p className="text-sm text-purple-200 leading-relaxed">{knowledge.eli5}</p>
                </div>
              )}

              {/* What is happening — brief context */}
              <div className="bg-slate-900/40 rounded-lg px-4 py-3 border border-slate-700/30">
                <p className="text-sm text-slate-300 leading-relaxed">{knowledge.what}</p>
              </div>

              {/* Progress bar */}
              {totalCheckable > 0 && completedCount > 0 && (
                <div className="flex items-center gap-3">
                  <div className="flex-1 h-1.5 bg-slate-700 rounded-full overflow-hidden">
                    <div
                      className="h-full bg-gradient-to-r from-cyan-500 to-green-500 rounded-full transition-all duration-300"
                      style={{ width: `${progressPct}%` }}
                    />
                  </div>
                  <span className="text-[10px] text-slate-500 font-medium shrink-0">{completedCount}/{totalCheckable} done</span>
                </div>
              )}

              {/* ═══════════════ STEP 1: Verify with Wireshark (The Eye) ═══════════════ */}
              <div className="rounded-lg border border-cyan-500/20 overflow-hidden">
                <div className="bg-cyan-500/5 px-4 py-3 border-b border-cyan-500/15 flex items-center gap-3">
                  <div className="w-7 h-7 rounded-lg bg-cyan-500/20 flex items-center justify-center shrink-0">
                    <Eye className="w-4 h-4 text-cyan-400" />
                  </div>
                  <div>
                    <h4 className="text-xs font-bold text-cyan-400 uppercase tracking-wider">Step 1: Verify with Wireshark</h4>
                    <p className="text-[10px] text-slate-500">Confirm the finding with packet evidence</p>
                  </div>
                </div>
                <div className="p-4 space-y-3">
                  {/* Wireshark filter with copy */}
                  {(() => {
                    const wsFilter = wiresharkFilterOverride || knowledge.wiresharkFilter;
                    return wsFilter ? (
                      <div className="space-y-2">
                        <div className="flex items-center gap-2">
                          <input
                            type="checkbox"
                            checked={checkedSteps.has('ws-filter')}
                            onChange={() => toggleCheck('ws-filter')}
                            className="w-3.5 h-3.5 rounded border-slate-600 bg-slate-800 text-cyan-500 focus:ring-cyan-500/30"
                          />
                          <span className="text-xs text-slate-300">Apply this display filter in Wireshark:</span>
                        </div>
                        <div className="flex items-center gap-2 ml-6 bg-slate-950 rounded-lg px-3 py-2 border border-slate-700/50">
                          <BookOpen className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
                          <code className="text-xs text-cyan-300 font-mono flex-1">{wsFilter}</code>
                          <button
                            onClick={() => copyCommand(wsFilter)}
                            className="p-1 rounded hover:bg-slate-700 transition-colors"
                            title="Copy filter"
                          >
                            {copiedCmd === wsFilter ? (
                              <Check className="w-3.5 h-3.5 text-green-400" />
                            ) : (
                              <Copy className="w-3.5 h-3.5 text-slate-500" />
                            )}
                          </button>
                        </div>
                      </div>
                    ) : null;
                  })()}

                  {/* Visual aid: See in Wireshark button */}
                  {findingKey && (
                    <button
                      onClick={() => {
                        if (!knowledge) return;
                        const packets = generateMockPackets(findingKey, packetContext);
                        setWsModalData({ findingKey, title, knowledge, packets, eli5Mode });
                      }}
                      className="ml-6 flex items-center gap-2 px-3 py-2 bg-cyan-500/10 hover:bg-cyan-500/20 border border-cyan-500/25 rounded-lg transition-colors group"
                    >
                      <span className="text-sm group-hover:scale-110 transition-transform">🦈</span>
                      <span className="text-[11px] font-semibold text-cyan-400">Visual Aid: See Mock Packets</span>
                    </button>
                  )}
                </div>
              </div>

              {/* ═══════════════ STEP 2: Diagnose on Device (The Hands) ═══════════════ */}
              <div className="rounded-lg border border-amber-500/20 overflow-hidden">
                <div className="bg-amber-500/5 px-4 py-3 border-b border-amber-500/15 flex items-center gap-3">
                  <div className="w-7 h-7 rounded-lg bg-amber-500/20 flex items-center justify-center shrink-0">
                    <Terminal className="w-4 h-4 text-amber-400" />
                  </div>
                  <div>
                    <h4 className="text-xs font-bold text-amber-400 uppercase tracking-wider">Step 2: Diagnose on Device</h4>
                    <p className="text-[10px] text-slate-500">Run these commands to find the root cause</p>
                  </div>
                </div>
                <div className="p-4 space-y-3">
                  {/* Vendor Runbook (takes priority) */}
                  {vendorRunbookData && (
                    <VendorRunbookPanel vendor={vendorRunbookData.vendor} findingRunbook={vendorRunbookData.finding} />
                  )}

                  {/* CLI Commands as checklist */}
                  {!vendorRunbookData && knowledge.commands && knowledge.commands.length > 0 && (
                    <div className="space-y-2">
                      {knowledge.commands.map((cmd, i) => {
                        if (filterCiscoContent && isCiscoSpecific(cmd)) return null;
                        const stepId = `cmd-${i}`;
                        return (
                          <div key={i} className="flex items-start gap-2 group">
                            <input
                              type="checkbox"
                              checked={checkedSteps.has(stepId)}
                              onChange={() => toggleCheck(stepId)}
                              className="w-3.5 h-3.5 mt-1.5 rounded border-slate-600 bg-slate-800 text-amber-500 focus:ring-amber-500/30 shrink-0"
                            />
                            <div className="flex-1 flex items-center gap-2">
                              <code className="flex-1 text-xs bg-slate-950 text-green-300 px-3 py-2 rounded font-mono border border-slate-800">
                                {cmd}
                              </code>
                              <button
                                onClick={() => copyCommand(cmd)}
                                className="p-1.5 rounded hover:bg-slate-700 transition-colors opacity-0 group-hover:opacity-100"
                                title="Copy command"
                              >
                                {copiedCmd === cmd ? (
                                  <Check className="w-3.5 h-3.5 text-green-400" />
                                ) : (
                                  <Copy className="w-3.5 h-3.5 text-slate-500" />
                                )}
                              </button>
                            </div>
                          </div>
                        );
                      })}
                    </div>
                  )}

                  {/* What to look for */}
                  {!vendorRunbookData && knowledge.tacTip && !(filterCiscoContent && isCiscoSpecific(knowledge.tacTip)) && (
                    <div className="ml-6 bg-amber-500/5 border border-amber-500/15 rounded-lg px-3 py-2.5">
                      <div className="flex items-start gap-2">
                        <Zap className="w-3.5 h-3.5 text-amber-400 shrink-0 mt-0.5" />
                        <div>
                          <span className="text-[10px] font-bold text-amber-400 uppercase tracking-wider block mb-0.5">What to look for</span>
                          <span className="text-xs text-amber-200/90">{knowledge.tacTip}</span>
                        </div>
                      </div>
                    </div>
                  )}

                  {/* Fallback: no commands available */}
                  {!vendorRunbookData && (!knowledge.commands || knowledge.commands.length === 0) && (
                    <p className="text-xs text-slate-500 italic ml-6">No specific CLI commands available for this finding. Check your device logs and interface counters.</p>
                  )}
                </div>
              </div>

              {/* ═══════════════ STEP 3: Resolve (The Fix) ═══════════════ */}
              <div className="rounded-lg border border-green-500/20 overflow-hidden">
                <div className="bg-green-500/5 px-4 py-3 border-b border-green-500/15 flex items-center gap-3">
                  <div className="w-7 h-7 rounded-lg bg-green-500/20 flex items-center justify-center shrink-0">
                    <Wrench className="w-4 h-4 text-green-400" />
                  </div>
                  <div>
                    <h4 className="text-xs font-bold text-green-400 uppercase tracking-wider">Step 3: Resolve</h4>
                    <p className="text-[10px] text-slate-500">Take action to fix the issue</p>
                  </div>
                  {knowledge.fixRate && (
                    <span className="ml-auto text-[10px] bg-green-500/15 text-green-400 px-2 py-0.5 rounded-full font-medium">
                      {knowledge.fixRate}
                    </span>
                  )}
                </div>
                <div className="p-4 space-y-2">
                  {(() => {
                    const howSteps = filterCiscoContent ? knowledge.how.filter(step => !isCiscoSpecific(step)) : knowledge.how;
                    return howSteps.map((step, i) => {
                      const stepId = `fix-${i}`;
                      return (
                        <div key={i} className="flex items-start gap-2.5">
                          <input
                            type="checkbox"
                            checked={checkedSteps.has(stepId)}
                            onChange={() => toggleCheck(stepId)}
                            className="w-3.5 h-3.5 mt-0.5 rounded border-slate-600 bg-slate-800 text-green-500 focus:ring-green-500/30 shrink-0"
                          />
                          <div className="flex items-start gap-2 flex-1 min-w-0">
                            <span className="flex-shrink-0 w-4 h-4 rounded-full bg-green-500/15 text-green-400 text-[10px] flex items-center justify-center font-bold mt-0.5">
                              {i + 1}
                            </span>
                            <span className={`text-xs leading-relaxed ${checkedSteps.has(stepId) ? 'text-slate-500 line-through' : 'text-slate-300'}`}>{step}</span>
                          </div>
                        </div>
                      );
                    });
                  })()}

                  {/* Risk warning */}
                  {findingKey && getRiskWarning(findingKey) && (
                    <div className="mt-3 ml-6 bg-red-500/5 border border-red-500/20 rounded-lg px-3 py-2.5 flex items-start gap-2">
                      <AlertTriangle className="w-3.5 h-3.5 text-red-400 shrink-0 mt-0.5" />
                      <div>
                        <span className="text-[10px] font-bold text-red-400 uppercase tracking-wider block mb-0.5">Caution</span>
                        <span className="text-xs text-red-200/90">{getRiskWarning(findingKey)}</span>
                      </div>
                    </div>
                  )}
                </div>
              </div>

              {/* ═══════════════ Confidence + Actions ═══════════════ */}
              <div className="flex items-center gap-3 flex-wrap">
                {confidenceLevel && (
                  <ConfidenceBadge level={confidenceLevel} showDetails />
                )}
              </div>

              {/* ═══════════════ Why This Happens (collapsible) ═══════════════ */}
              <div className="border border-slate-700/40 rounded-lg overflow-hidden">
                <button
                  onClick={() => setShowWhyDetail(!showWhyDetail)}
                  className="w-full px-4 py-3 flex items-center gap-2 hover:bg-slate-700/20 transition-colors text-left"
                >
                  <ChevronRight className={`w-3.5 h-3.5 text-slate-500 transition-transform ${showWhyDetail ? 'rotate-90' : ''}`} />
                  <Shield className="w-3.5 h-3.5 text-slate-500" />
                  <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Why This Happens</span>
                  <span className="text-[10px] text-slate-600 ml-auto">Junior Engineer Context</span>
                </button>
                {showWhyDetail && (
                  <div className="px-4 pb-4 pt-1 border-t border-slate-700/30">
                    <p className="text-xs text-slate-300 leading-relaxed">{knowledge.why}</p>
                    {knowledge.references && knowledge.references.length > 0 && (
                      <div className="mt-3 space-y-1">
                        <span className="text-[10px] font-semibold text-slate-500 uppercase">References</span>
                        {knowledge.references.map((ref, i) => (
                          <a key={i} href={ref} target="_blank" rel="noopener noreferrer" className="block text-[11px] text-blue-400 hover:text-blue-300 truncate">
                            {ref}
                          </a>
                        ))}
                      </div>
                    )}
                  </div>
                )}
              </div>

            </div>
          )}

          {/* Data Details Table */}
          {details && (
            <div className="border-t border-slate-700/50 p-5">
              <h4 className="text-xs font-semibold text-slate-400 uppercase tracking-wide mb-3">Evidence &amp; Details</h4>
              {details}
            </div>
          )}
        </div>
      )}

      {/* Wireshark Comparison Modal */}
      {wsModalData && (
        <WiresharkComparisonModal
          data={wsModalData}
          onClose={() => setWsModalData(null)}
        />
      )}
    </div>
  );
}

// ─── Risk Warnings Per Finding Type ─────────────────────────

function getRiskWarning(findingKey: string): string | null {
  const warnings: Record<string, string> = {
    ddos_syn_flood: 'Do not block all traffic from the source IP if it is a NAT gateway — you may block legitimate users behind it.',
    ddos_udp_flood: 'Do not disable UDP entirely — DNS, NTP, SNMP, and VoIP all rely on UDP.',
    ddos_icmp_flood: 'Do not block all ICMP on WAN interfaces — Path MTU Discovery and traceroute require ICMP.',
    port_scan: 'Verify the source is not an authorized vulnerability scanner (Nessus, Qualys) before blocking.',
    dns_anomaly: 'Do not block DNS traffic entirely — this will break all name resolution for users.',
    tls_weakness: 'Disabling TLS 1.0/1.1 may break legacy applications — test with non-production first.',
    arp_conflict: 'Do not clear ARP on production routers during business hours — it causes brief packet loss for all connected devices.',
    tcp_retransmission: 'Enabling FEC (Forward Error Correction) adds ~10% overhead. Only enable on lossy links, not clean paths.',
    tcp_handshake_failure: 'Do not assume the server is down — a firewall may be silently dropping SYN packets. Check path firewalls first.',
    packet_loss: 'Do not increase interface buffers excessively — this trades loss for latency, which harms real-time applications.',
    high_latency: 'Do not change SD-WAN path selection policy during peak hours — failover may cause a brief outage.',
    vrrp_flapping: 'Do not change VRRP priority on the active router without planning — it will trigger a failover.',
    hsrp_instability: 'Do not modify HSRP on both routers simultaneously — change one, verify, then change the other.',
    bfd_flapping: 'Do not disable BFD to "fix" flapping — this hides the problem and delays convergence from milliseconds to seconds.',
    ike_tunnel_rebuild: 'Do not clear crypto sessions during business hours — all VPN users will be disconnected.',
    dns_tunneling: 'Do not block the tunneling domain without verifying it is not a legitimate service (e.g., iCloud Private Relay).',
    c2_beaconing: 'Do not alert the infected host user — isolate the device at the switch port level first to preserve forensic evidence.',
    ntp_amplification: 'Do not block NTP entirely — disable monlist/mode 7 on your NTP servers instead.',
  };
  return warnings[findingKey] || null;
}
