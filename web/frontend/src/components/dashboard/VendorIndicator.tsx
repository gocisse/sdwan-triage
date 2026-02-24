// Vendor Indicator Banner
// Shows detected SD-WAN vendor prominently with interface type and quick-start link
// Helps junior engineers immediately understand what platform they're dealing with

import { useState } from 'react';
import { Monitor, Terminal, Layers, ExternalLink, ChevronDown, ChevronUp, AlertTriangle, Key, BookOpen } from 'lucide-react';
import { getVendorRunbook } from '../../data/vendorRunbooks';
import type { VendorRunbook } from '../../data/vendorRunbooks';

interface VendorIndicatorProps {
  vendorNames: string[];
}

export function VendorIndicator({ vendorNames }: VendorIndicatorProps) {
  const [expanded, setExpanded] = useState(false);

  if (!vendorNames || vendorNames.length === 0) return null;

  const vendors: VendorRunbook[] = [];
  for (const name of vendorNames) {
    const rb = getVendorRunbook(name);
    if (rb && !vendors.some(v => v.vendorKey === rb.vendorKey)) {
      vendors.push(rb);
    }
  }

  if (vendors.length === 0) return null;

  const primary = vendors[0];
  const InterfaceIcon = primary.primaryInterface === 'cli' ? Terminal : primary.primaryInterface === 'gui' ? Monitor : Layers;
  const interfaceLabel = primary.primaryInterface === 'cli' ? 'CLI-based troubleshooting' : primary.primaryInterface === 'gui' ? 'GUI-based troubleshooting' : 'Hybrid (GUI + CLI) troubleshooting';

  return (
    <div className={`${primary.bgColor} border ${primary.borderColor} rounded-xl overflow-hidden`}>
      <button
        onClick={() => setExpanded(!expanded)}
        className="w-full px-5 py-3 flex items-center justify-between hover:brightness-110 transition-all"
      >
        <div className="flex items-center gap-3">
          <div className={`w-9 h-9 rounded-lg ${primary.bgColor} border ${primary.borderColor} flex items-center justify-center`}>
            <span className={`text-lg font-bold ${primary.color}`}>{primary.logo}</span>
          </div>
          <div className="text-left">
            <div className="flex items-center gap-2 flex-wrap">
              <span className={`text-sm font-semibold ${primary.color}`}>{primary.vendor} Detected</span>
              <span className={`flex items-center gap-1 text-[10px] px-2 py-0.5 rounded-full font-medium ${primary.color} bg-slate-800/60 border border-slate-700/30`}>
                <InterfaceIcon className="w-3 h-3" />
                {interfaceLabel}
              </span>
            </div>
            <p className="text-[11px] text-slate-400 mt-0.5">
              Vendor-specific runbooks are available in each finding card below
            </p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <span className={`text-[10px] ${primary.color}`}>{expanded ? 'Hide' : 'Quick Start'}</span>
          {expanded ? <ChevronUp className={`w-4 h-4 ${primary.color}`} /> : <ChevronDown className={`w-4 h-4 ${primary.color}`} />}
        </div>
      </button>

      {expanded && (
        <div className="border-t border-slate-700/30 px-5 py-4 space-y-3">
          <p className="text-xs text-slate-300 leading-relaxed">{primary.gettingStarted.primer}</p>

          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
            <div className="bg-slate-900/40 rounded-lg p-3 border border-slate-700/20">
              <div className="flex items-center gap-2 mb-1">
                <Key className="w-3.5 h-3.5 text-slate-400" />
                <span className="text-[10px] font-semibold text-slate-400 uppercase tracking-wider">How to Connect</span>
              </div>
              <p className="text-[11px] text-slate-300">{primary.gettingStarted.loginInfo}</p>
            </div>
            <div className="bg-slate-900/40 rounded-lg p-3 border border-slate-700/20">
              <div className="flex items-center gap-2 mb-1">
                <InterfaceIcon className="w-3.5 h-3.5 text-slate-400" />
                <span className="text-[10px] font-semibold text-slate-400 uppercase tracking-wider">Interface Type</span>
              </div>
              <p className="text-[11px] text-slate-300">{primary.gettingStarted.interfaceNote}</p>
            </div>
            <div className="bg-slate-900/40 rounded-lg p-3 border border-slate-700/20">
              <div className="flex items-center gap-2 mb-1">
                <BookOpen className="w-3.5 h-3.5 text-slate-400" />
                <span className="text-[10px] font-semibold text-slate-400 uppercase tracking-wider">Authentication</span>
              </div>
              <p className="text-[11px] text-slate-300">{primary.authentication}</p>
            </div>
          </div>

          {primary.gettingStarted.commonMistakes && primary.gettingStarted.commonMistakes.length > 0 && (
            <div className="bg-amber-500/5 rounded-lg p-3 border border-amber-500/15">
              <div className="flex items-center gap-2 mb-2">
                <AlertTriangle className="w-3.5 h-3.5 text-amber-400" />
                <span className="text-[10px] font-semibold text-amber-400 uppercase tracking-wider">Common Mistakes to Avoid</span>
              </div>
              <ul className="space-y-1">
                {primary.gettingStarted.commonMistakes.slice(0, 4).map((mistake, i) => (
                  <li key={i} className="text-[11px] text-slate-300 flex items-start gap-2">
                    <span className="text-amber-400/60 mt-0.5">•</span>
                    <span>{mistake}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}

          {primary.gettingStarted.quickLinks.length > 0 && (
            <div className="flex flex-wrap gap-2">
              {primary.gettingStarted.quickLinks.map((link, i) => (
                <a key={i} href={link.url} target="_blank" rel="noopener noreferrer" className={`flex items-center gap-1.5 text-[11px] ${primary.color} hover:underline px-3 py-1.5 rounded-lg bg-slate-900/40 border border-slate-700/20`}>
                  <ExternalLink className="w-3 h-3" />
                  {link.title}
                </a>
              ))}
            </div>
          )}

          {vendors.length > 1 && (
            <div className="mt-3 pt-3 border-t border-slate-700/20">
              <p className="text-[10px] text-slate-500 mb-2">Also detected:</p>
              <div className="flex flex-wrap gap-2">
                {vendors.slice(1).map((v, i) => (
                  <span key={i} className={`flex items-center gap-1.5 text-[11px] px-2.5 py-1 rounded-lg ${v.bgColor} border ${v.borderColor}`}>
                    <span className={`text-xs font-bold ${v.color}`}>{v.logo}</span>
                    <span className={`${v.color} font-medium`}>{v.vendor}</span>
                  </span>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
