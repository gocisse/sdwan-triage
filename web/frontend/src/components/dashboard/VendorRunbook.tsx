// Vendor-Specific Runbook Panel
// Shows vendor-specific GUI paths, CLI commands, scripts, warnings, known bugs, and documentation
// Adapts display based on vendor's primary interface (CLI, GUI, or hybrid)

import { useState } from 'react';
import { Terminal, Monitor, Code2, Bug, Tag, ExternalLink, Copy, Check, ChevronDown, ChevronUp, AlertTriangle, BookOpen, Info } from 'lucide-react';
import type { VendorFindingRunbook, VendorRunbook as VendorRunbookType } from '../../data/vendorRunbooks';

type MethodTab = 'gui' | 'cli' | 'script';
type PhaseTab = 'diagnose' | 'fix' | 'verify';

interface VendorRunbookProps {
  vendor: VendorRunbookType;
  findingRunbook: VendorFindingRunbook;
}

function getAvailableMethods(phase: VendorFindingRunbook['diagnose']): MethodTab[] {
  const methods: MethodTab[] = [];
  if (phase.gui && phase.gui.length > 0) methods.push('gui');
  if (phase.cli && phase.cli.length > 0) methods.push('cli');
  if (phase.script && phase.script.length > 0) methods.push('script');
  return methods;
}

function getMethodIcon(method: MethodTab) {
  switch (method) {
    case 'gui': return Monitor;
    case 'cli': return Terminal;
    case 'script': return Code2;
  }
}

function getMethodLabel(method: MethodTab) {
  switch (method) {
    case 'gui': return 'GUI';
    case 'cli': return 'CLI';
    case 'script': return 'Script';
  }
}

function getPhaseData(findingRunbook: VendorFindingRunbook, phase: PhaseTab) {
  return findingRunbook[phase];
}

export function VendorRunbookPanel({ vendor, findingRunbook }: VendorRunbookProps) {
  const [expanded, setExpanded] = useState(true);
  const [copiedCmd, setCopiedCmd] = useState<string | null>(null);
  const [activePhase, setActivePhase] = useState<PhaseTab>('diagnose');
  const [showGettingStarted, setShowGettingStarted] = useState(false);

  const phaseData = getPhaseData(findingRunbook, activePhase);
  const availableMethods = getAvailableMethods(phaseData);

  // Default to vendor's primary interface if available, otherwise first available
  const defaultMethod = availableMethods.includes(vendor.primaryInterface === 'hybrid' ? 'gui' : vendor.primaryInterface as MethodTab)
    ? (vendor.primaryInterface === 'hybrid' ? 'gui' : vendor.primaryInterface as MethodTab)
    : availableMethods[0] || 'cli';
  const [activeMethod, setActiveMethod] = useState<MethodTab>(defaultMethod);

  // Ensure activeMethod is valid when phase changes
  const currentMethod = availableMethods.includes(activeMethod) ? activeMethod : availableMethods[0] || 'cli';
  const commands = phaseData[currentMethod] || [];

  const interfaceLabel = vendor.primaryInterface === 'cli' ? 'CLI-based' : vendor.primaryInterface === 'gui' ? 'GUI-based' : 'Hybrid (GUI + CLI)';
  const interfaceColor = vendor.primaryInterface === 'cli' ? 'text-green-400' : vendor.primaryInterface === 'gui' ? 'text-blue-400' : 'text-purple-400';

  const copyCommand = (cmd: string) => {
    navigator.clipboard.writeText(cmd).then(() => {
      setCopiedCmd(cmd);
      setTimeout(() => setCopiedCmd(null), 2000);
    });
  };

  const copyAllCommands = (cmds: string[]) => {
    const filtered = cmds.filter(c => !c.startsWith('!') && !c.startsWith('#'));
    navigator.clipboard.writeText(filtered.join('\n')).then(() => {
      setCopiedCmd('__all__');
      setTimeout(() => setCopiedCmd(null), 2000);
    });
  };

  return (
    <div className={`${vendor.bgColor} border ${vendor.borderColor} rounded-lg overflow-hidden`}>
      {/* Header */}
      <button
        onClick={() => setExpanded(!expanded)}
        className="w-full px-4 py-3 flex items-center justify-between hover:brightness-110 transition-all"
      >
        <div className="flex items-center gap-3">
          <div className={`w-7 h-7 rounded-md ${vendor.bgColor} border ${vendor.borderColor} flex items-center justify-center`}>
            <span className={`text-sm font-bold ${vendor.color}`}>{vendor.logo}</span>
          </div>
          <div className="text-left">
            <div className="flex items-center gap-2">
              <span className={`text-xs font-semibold ${vendor.color}`}>{vendor.vendor}</span>
              <span className={`text-[9px] px-1.5 py-0.5 rounded-full font-medium ${interfaceColor} bg-slate-800/60 border border-slate-700/30`}>
                {interfaceLabel}
              </span>
            </div>
            <p className="text-[10px] text-slate-500">Vendor-specific troubleshooting runbook</p>
          </div>
        </div>
        {expanded ? (
          <ChevronUp className={`w-4 h-4 ${vendor.color}`} />
        ) : (
          <ChevronDown className={`w-4 h-4 ${vendor.color}`} />
        )}
      </button>

      {/* Expanded Content */}
      {expanded && (
        <div className="border-t border-slate-700/30 px-4 py-4 space-y-4">

          {/* Getting Started Toggle */}
          <button
            onClick={() => setShowGettingStarted(!showGettingStarted)}
            className="w-full flex items-center gap-2 px-3 py-2 rounded-lg bg-slate-800/40 border border-slate-700/30 hover:bg-slate-700/40 transition-colors text-left"
          >
            <Info className="w-3.5 h-3.5 text-slate-400 flex-shrink-0" />
            <span className="text-[11px] text-slate-400 flex-1">
              New to {vendor.vendor}? Click for a quick primer
            </span>
            {showGettingStarted ? <ChevronUp className="w-3 h-3 text-slate-500" /> : <ChevronDown className="w-3 h-3 text-slate-500" />}
          </button>

          {/* Getting Started Panel */}
          {showGettingStarted && (
            <div className="bg-slate-800/40 border border-slate-700/30 rounded-lg p-4 space-y-3">
              <p className="text-xs text-slate-300 leading-relaxed">{vendor.gettingStarted.primer}</p>

              <div className="bg-slate-900/40 rounded-lg p-3 border border-slate-700/20">
                <div className="flex items-center gap-2 mb-1">
                  <Monitor className="w-3 h-3 text-slate-400" />
                  <span className="text-[10px] font-semibold text-slate-400 uppercase tracking-wider">Interface</span>
                </div>
                <p className="text-[11px] text-slate-300">{vendor.gettingStarted.interfaceNote}</p>
              </div>

              <div className="bg-slate-900/40 rounded-lg p-3 border border-slate-700/20">
                <div className="flex items-center gap-2 mb-1">
                  <Terminal className="w-3 h-3 text-slate-400" />
                  <span className="text-[10px] font-semibold text-slate-400 uppercase tracking-wider">Login</span>
                </div>
                <p className="text-[11px] text-slate-300 font-mono">{vendor.gettingStarted.loginInfo}</p>
              </div>

              {vendor.gettingStarted.commonMistakes.length > 0 && (
                <div>
                  <div className="flex items-center gap-2 mb-1.5">
                    <AlertTriangle className="w-3 h-3 text-amber-400" />
                    <span className="text-[10px] font-semibold text-amber-400 uppercase tracking-wider">Common Mistakes</span>
                  </div>
                  <ul className="space-y-1">
                    {vendor.gettingStarted.commonMistakes.map((m, i) => (
                      <li key={i} className="text-[11px] text-amber-200/70 flex items-start gap-2">
                        <span className="text-amber-400 flex-shrink-0 mt-0.5">!</span>
                        {m}
                      </li>
                    ))}
                  </ul>
                </div>
              )}

              {vendor.gettingStarted.quickLinks.length > 0 && (
                <div className="flex flex-wrap gap-2">
                  {vendor.gettingStarted.quickLinks.map((link, i) => (
                    <a key={i} href={link.url} target="_blank" rel="noopener noreferrer" className={`flex items-center gap-1.5 text-[10px] ${vendor.color} hover:underline px-2 py-1 rounded-md bg-slate-900/40 border border-slate-700/20`}>
                      <ExternalLink className="w-2.5 h-2.5" />
                      {link.title}
                    </a>
                  ))}
                </div>
              )}
            </div>
          )}

          {/* Phase Tabs: Diagnose / Fix / Verify */}
          <div>
            <div className="flex gap-1 mb-3">
              {(['diagnose', 'fix', 'verify'] as const).map(phase => (
                <button
                  key={phase}
                  onClick={() => setActivePhase(phase)}
                  className={`px-3 py-1.5 rounded-md text-xs font-medium transition-all ${
                    activePhase === phase
                      ? `${vendor.bgColor} ${vendor.color} border ${vendor.borderColor}`
                      : 'text-slate-400 hover:text-white hover:bg-slate-700/50'
                  }`}
                >
                  {phase === 'diagnose' ? '1. Diagnose' : phase === 'fix' ? '2. Fix' : '3. Verify'}
                </button>
              ))}
            </div>

            {/* Method Tabs: GUI / CLI / Script */}
            {availableMethods.length > 1 && (
              <div className="flex gap-1 mb-2">
                {availableMethods.map(method => {
                  const Icon = getMethodIcon(method);
                  return (
                    <button
                      key={method}
                      onClick={() => setActiveMethod(method)}
                      className={`flex items-center gap-1.5 px-2.5 py-1 rounded text-[10px] font-medium transition-all ${
                        currentMethod === method
                          ? 'bg-slate-700/80 text-white border border-slate-600/50'
                          : 'text-slate-500 hover:text-slate-300 hover:bg-slate-800/40'
                      }`}
                    >
                      <Icon className="w-3 h-3" />
                      {getMethodLabel(method)}
                    </button>
                  );
                })}
              </div>
            )}

            {/* Commands / Paths List */}
            {commands.length > 0 && (
              <div className="bg-slate-900/60 rounded-lg p-3 border border-slate-700/50">
                <div className="flex items-center justify-between mb-2">
                  <div className="flex items-center gap-2">
                    {currentMethod === 'gui' ? (
                      <Monitor className="w-3.5 h-3.5 text-blue-400" />
                    ) : currentMethod === 'script' ? (
                      <Code2 className="w-3.5 h-3.5 text-purple-400" />
                    ) : (
                      <Terminal className="w-3.5 h-3.5 text-green-400" />
                    )}
                    <span className="text-[10px] font-semibold text-slate-400 uppercase tracking-wider">
                      {currentMethod === 'gui' ? 'GUI Navigation' : currentMethod === 'script' ? 'Scripts' : 'CLI Commands'}
                    </span>
                  </div>
                  {currentMethod !== 'gui' && (
                    <button
                      onClick={() => copyAllCommands(commands)}
                      className="text-[10px] text-slate-500 hover:text-white transition-colors flex items-center gap-1"
                    >
                      {copiedCmd === '__all__' ? <Check className="w-3 h-3 text-green-400" /> : <Copy className="w-3 h-3" />}
                      {copiedCmd === '__all__' ? 'Copied!' : 'Copy All'}
                    </button>
                  )}
                </div>
                <div className="space-y-1.5">
                  {commands.map((cmd, i) => {
                    const isComment = cmd.startsWith('!') || cmd.startsWith('#');
                    const isGuiPath = currentMethod === 'gui';
                    return (
                      <div key={i} className="flex items-center gap-2 group">
                        {isGuiPath ? (
                          <div className="flex-1 flex items-start gap-2 px-2.5 py-1.5 rounded bg-blue-500/5 border border-blue-500/10">
                            <span className="text-blue-400 text-[10px] mt-0.5 flex-shrink-0">▸</span>
                            <span className="text-[11px] text-blue-200/90">{cmd}</span>
                          </div>
                        ) : (
                          <code className={`flex-1 text-[11px] px-2.5 py-1.5 rounded font-mono ${
                            isComment
                              ? 'text-slate-500 italic bg-transparent'
                              : 'bg-slate-950 text-green-300'
                          }`}>
                            {cmd}
                          </code>
                        )}
                        {!isComment && !isGuiPath && (
                          <button
                            onClick={() => copyCommand(cmd)}
                            className="p-1 rounded hover:bg-slate-700 transition-colors opacity-0 group-hover:opacity-100 flex-shrink-0"
                          >
                            {copiedCmd === cmd ? (
                              <Check className="w-3 h-3 text-green-400" />
                            ) : (
                              <Copy className="w-3 h-3 text-slate-500" />
                            )}
                          </button>
                        )}
                      </div>
                    );
                  })}
                </div>
              </div>
            )}

            {commands.length === 0 && (
              <div className="bg-slate-900/40 rounded-lg p-4 text-center">
                <p className="text-xs text-slate-500">No {getMethodLabel(currentMethod)} steps available for this phase. Try another method tab.</p>
              </div>
            )}
          </div>

          {/* Warnings */}
          {findingRunbook.warnings.length > 0 && (
            <div className="bg-amber-500/5 border border-amber-500/20 rounded-lg p-3">
              <div className="flex items-center gap-2 mb-1.5">
                <AlertTriangle className="w-3.5 h-3.5 text-amber-400" />
                <span className="text-[10px] font-semibold text-amber-400 uppercase tracking-wider">Warnings</span>
              </div>
              <ul className="space-y-1">
                {findingRunbook.warnings.map((w, i) => (
                  <li key={i} className="text-[11px] text-amber-200/80 flex items-start gap-2">
                    <span className="text-amber-400 flex-shrink-0">⚠</span>
                    {w}
                  </li>
                ))}
              </ul>
            </div>
          )}

          {/* TAC Notes */}
          {findingRunbook.tacNotes && findingRunbook.tacNotes.length > 0 && (
            <div className="bg-blue-500/5 border border-blue-500/20 rounded-lg p-3">
              <div className="flex items-center gap-2 mb-1.5">
                <BookOpen className="w-3.5 h-3.5 text-blue-400" />
                <span className="text-[10px] font-semibold text-blue-400 uppercase tracking-wider">TAC / Escalation Notes</span>
              </div>
              <ul className="space-y-1">
                {findingRunbook.tacNotes.map((note, i) => (
                  <li key={i} className="text-xs text-blue-200/80 flex items-start gap-2">
                    <span className="text-blue-400 flex-shrink-0">•</span>
                    {note}
                  </li>
                ))}
              </ul>
            </div>
          )}

          {/* Known Bugs & Recommended Versions */}
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            {findingRunbook.knownBugs && findingRunbook.knownBugs.length > 0 && (
              <div>
                <div className="flex items-center gap-2 mb-1.5">
                  <Bug className="w-3.5 h-3.5 text-red-400" />
                  <span className="text-[10px] font-semibold text-slate-400 uppercase tracking-wider">Known Bugs</span>
                </div>
                <ul className="space-y-1">
                  {findingRunbook.knownBugs.map((bug, i) => (
                    <li key={i} className="text-[11px] text-red-300/80 font-mono">{bug}</li>
                  ))}
                </ul>
              </div>
            )}

            {findingRunbook.recommendedVersions && findingRunbook.recommendedVersions.length > 0 && (
              <div>
                <div className="flex items-center gap-2 mb-1.5">
                  <Tag className="w-3.5 h-3.5 text-green-400" />
                  <span className="text-[10px] font-semibold text-slate-400 uppercase tracking-wider">Recommended Versions</span>
                </div>
                <ul className="space-y-1">
                  {findingRunbook.recommendedVersions.map((ver, i) => (
                    <li key={i} className="text-[11px] text-green-300/80">{ver}</li>
                  ))}
                </ul>
              </div>
            )}
          </div>

          {/* Documentation Links */}
          {findingRunbook.documentationLinks && findingRunbook.documentationLinks.length > 0 && (
            <div>
              <span className="text-[10px] font-semibold text-slate-400 uppercase tracking-wider block mb-1.5">Documentation</span>
              <div className="space-y-1">
                {findingRunbook.documentationLinks.map((link, i) => (
                  <a
                    key={i}
                    href={link.url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className={`flex items-center gap-2 text-xs ${vendor.color} hover:underline`}
                  >
                    <ExternalLink className="w-3 h-3 flex-shrink-0" />
                    {link.title}
                  </a>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
