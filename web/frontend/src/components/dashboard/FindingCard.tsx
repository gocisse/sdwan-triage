import { useState } from 'react';
import { ChevronDown, ChevronUp, Lightbulb, Terminal, BookOpen, Copy, Check, Zap } from 'lucide-react';
import { getSeverityConfig, type IssueKnowledge } from '../../data/knowledgeBase';
import { ConfidenceBadge, computeConfidence, type ConfidenceLevel } from './ConfidenceBadge';
import { VendorRunbookPanel } from './VendorRunbook';
import { getVendorRunbook, getVendorFindingRunbook } from '../../data/vendorRunbooks';

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
}

export function FindingCard({ title, severity, count, description, details, knowledge, eli5Mode, findingKey, detectedVendors, wiresharkFilter: wiresharkFilterOverride }: FindingCardProps) {
  const [expanded, setExpanded] = useState(false);
  const [copiedCmd, setCopiedCmd] = useState<string | null>(null);
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

      {/* Expanded Content */}
      {expanded && (
        <div className="bg-slate-800/60 border-t border-slate-700/50">
          {/* WHAT / WHY / HOW sections */}
          {knowledge && (
            <div className="p-5 space-y-5">
              {/* ELI5 Mode */}
              {eli5Mode && knowledge.eli5 && (
                <div className="bg-purple-500/10 border border-purple-500/20 rounded-lg p-4">
                  <div className="flex items-center gap-2 mb-2">
                    <Lightbulb className="w-4 h-4 text-purple-400" />
                    <span className="text-xs font-semibold text-purple-400 uppercase tracking-wide">Explain Like I'm 5</span>
                  </div>
                  <p className="text-sm text-purple-200 leading-relaxed">{knowledge.eli5}</p>
                </div>
              )}

              {/* WHAT */}
              <div>
                <div className="flex items-center gap-2 mb-2">
                  <div className="w-6 h-6 rounded-md bg-blue-500/20 flex items-center justify-center">
                    <span className="text-xs font-bold text-blue-400">W</span>
                  </div>
                  <h4 className="text-sm font-semibold text-blue-400 uppercase tracking-wide">What is happening?</h4>
                </div>
                <p className="text-sm text-slate-300 leading-relaxed ml-8">{knowledge.what}</p>
              </div>

              {/* WHY */}
              <div>
                <div className="flex items-center gap-2 mb-2">
                  <div className="w-6 h-6 rounded-md bg-amber-500/20 flex items-center justify-center">
                    <span className="text-xs font-bold text-amber-400">W</span>
                  </div>
                  <h4 className="text-sm font-semibold text-amber-400 uppercase tracking-wide">Why does it matter?</h4>
                </div>
                <p className="text-sm text-slate-300 leading-relaxed ml-8">{knowledge.why}</p>
              </div>

              {/* Vendor Runbook — replaces generic HOW/Commands/TAC when vendor-specific data is available */}
              {vendorRunbookData && (
                <VendorRunbookPanel vendor={vendorRunbookData.vendor} findingRunbook={vendorRunbookData.finding} />
              )}

              {/* HOW — hidden when vendor runbook exists (it has Diagnose/Fix/Verify with correct vendor commands) */}
              {!vendorRunbookData && (() => {
                const howSteps = filterCiscoContent ? knowledge.how.filter(step => !isCiscoSpecific(step)) : knowledge.how;
                return howSteps.length > 0 ? (
                <div>
                  <div className="flex items-center gap-2 mb-2">
                    <div className="w-6 h-6 rounded-md bg-green-500/20 flex items-center justify-center">
                      <span className="text-xs font-bold text-green-400">H</span>
                    </div>
                    <h4 className="text-sm font-semibold text-green-400 uppercase tracking-wide">How do I fix it?</h4>
                  </div>
                  <ol className="space-y-2 ml-8">
                    {howSteps.map((step, i) => (
                      <li key={i} className="flex gap-3 text-sm">
                        <span className="flex-shrink-0 w-5 h-5 rounded-full bg-green-500/20 text-green-400 text-xs flex items-center justify-center font-medium">
                          {i + 1}
                        </span>
                        <span className="text-slate-300 leading-relaxed">{step}</span>
                      </li>
                    ))}
                  </ol>
                </div>
                ) : null;
              })()}

              {/* CLI Commands — hidden when vendor-specific runbook is available (it has its own commands) */}
              {knowledge.commands && knowledge.commands.length > 0 && !vendorRunbookData && !(filterCiscoContent && knowledge.commands.every(cmd => isCiscoSpecific(cmd))) && (
                <div className="bg-slate-900/60 rounded-lg p-4 border border-slate-700/50">
                  <div className="flex items-center gap-2 mb-3">
                    <Terminal className="w-4 h-4 text-slate-400" />
                    <span className="text-xs font-semibold text-slate-400 uppercase tracking-wide">Diagnostic Commands</span>
                  </div>
                  <div className="space-y-2">
                    {knowledge.commands.map((cmd, i) => (
                      <div key={i} className="flex items-center gap-2 group">
                        <code className="flex-1 text-xs bg-slate-950 text-green-300 px-3 py-2 rounded font-mono">
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
                    ))}
                  </div>
                </div>
              )}

              {/* Wireshark Filter — vendor-specific override takes precedence over static knowledge filter */}
              {(() => {
                const wsFilter = wiresharkFilterOverride || knowledge.wiresharkFilter;
                return wsFilter ? (
                  <div className="flex items-center gap-2 bg-slate-900/40 rounded-lg px-4 py-3 border border-slate-700/30">
                    <BookOpen className="w-4 h-4 text-cyan-400 flex-shrink-0" />
                    <span className="text-xs text-slate-400">Wireshark Filter:</span>
                    <code className="text-xs text-cyan-300 font-mono">{wsFilter}</code>
                    <button
                      onClick={() => copyCommand(wsFilter)}
                      className="ml-auto p-1 rounded hover:bg-slate-700 transition-colors"
                    >
                      {copiedCmd === wsFilter ? (
                        <Check className="w-3 h-3 text-green-400" />
                      ) : (
                        <Copy className="w-3 h-3 text-slate-500" />
                      )}
                    </button>
                  </div>
                ) : null;
              })()}

              {/* TAC Tip & Fix Rate — hidden when vendor runbook exists (vendor runbook has its own tacNotes) */}
              <div className="flex flex-wrap gap-3">
                {knowledge.tacTip && !vendorRunbookData && !(filterCiscoContent && isCiscoSpecific(knowledge.tacTip)) && (
                  <div className="flex items-start gap-2 bg-blue-500/10 rounded-lg px-4 py-3 border border-blue-500/20 flex-1 min-w-[200px]">
                    <Zap className="w-4 h-4 text-blue-400 flex-shrink-0 mt-0.5" />
                    <div>
                      <span className="text-xs font-semibold text-blue-400 block mb-0.5">TAC Tip</span>
                      <span className="text-xs text-blue-200">{knowledge.tacTip}</span>
                    </div>
                  </div>
                )}
                {knowledge.fixRate && (
                  <div className="flex items-start gap-2 bg-green-500/10 rounded-lg px-4 py-3 border border-green-500/20 flex-1 min-w-[200px]">
                    <Zap className="w-4 h-4 text-green-400 flex-shrink-0 mt-0.5" />
                    <div>
                      <span className="text-xs font-semibold text-green-400 block mb-0.5">Fix Rate</span>
                      <span className="text-xs text-green-200">{knowledge.fixRate}</span>
                    </div>
                  </div>
                )}
              </div>

              {/* Confidence Detail */}
              {confidenceLevel && (
                <ConfidenceBadge level={confidenceLevel} showDetails />
              )}

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
    </div>
  );
}
