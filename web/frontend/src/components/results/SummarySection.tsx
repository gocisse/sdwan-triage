// SummarySection — Top bar, help modal, emergency banner, executive summary,
// vendor indicator, network topology, filter bar + export button
// Extracted from ResultsPage.tsx

import { useState } from 'react';
import { Link } from 'react-router-dom';
import {
  ArrowLeft,
  FileJson,
  Loader2,
  Lightbulb,
  Download,
  Sparkles,
  Map,
  HelpCircle,
  X,
} from 'lucide-react';
import type { AnalysisResults } from '../../types';
import type { ParsedFilter } from '../../hooks';
import { downloadFile } from '../../api/client';
import { formatDate } from '../../utils';
import { ExecutiveSummary, WizardModal, EmergencyBanner, NetworkTopology, VendorIndicator } from '../dashboard';
import { FilterBar, ExportButton } from '../../components';

export interface SummarySectionProps {
  id: string;
  results: AnalysisResults;
  filteredResults: AnalysisResults | null;
  isFiltered: boolean;
  filterText: string;
  parsedFilter: ParsedFilter;
  detectedVendors: string[];
  eli5Mode: boolean;
  onEli5Toggle: () => void;
  onFilterChange: (text: string) => void;
  onOpenWizard: () => void;
}

export function SummarySection({
  id,
  results,
  filteredResults,
  isFiltered,
  filterText,
  parsedFilter,
  detectedVendors,
  eli5Mode,
  onEli5Toggle,
  onFilterChange,
  onOpenWizard,
}: SummarySectionProps) {
  const [downloading, setDownloading] = useState<'json' | 'html' | null>(null);
  const [wizardOpen, setWizardOpen] = useState(false);
  const [showTopology, setShowTopology] = useState(true);
  const [helpOpen, setHelpOpen] = useState(false);

  return (
    <>
      {/* Top Bar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <Link
            to="/history"
            className="inline-flex items-center gap-2 text-slate-400 hover:text-white mb-2 transition-colors text-sm"
          >
            <ArrowLeft className="w-4 h-4" />
            Back
          </Link>
          <h1 className="text-xl sm:text-2xl font-bold text-white truncate max-w-xl">
            {results.file_name}
          </h1>
          <p className="text-sm text-slate-400 mt-0.5">
            {results.file_size} &bull; {results.packet_count?.toLocaleString()} packets &bull; {formatDate(results.generated_at)}
          </p>
        </div>

        <div className="flex items-center gap-2 flex-shrink-0 flex-wrap" data-tour="export">
          {/* Wizard Button */}
          <button
            onClick={() => { setWizardOpen(true); onOpenWizard(); }}
            className="flex items-center gap-2 px-3 py-2 rounded-lg text-xs font-medium bg-gradient-to-r from-purple-600 to-blue-600 text-white hover:from-purple-500 hover:to-blue-500 transition-all shadow-lg shadow-purple-500/20"
          >
            <Sparkles className="w-3.5 h-3.5" />
            Help Me Troubleshoot
          </button>

          {/* Topology Toggle */}
          <button
            onClick={() => setShowTopology(!showTopology)}
            className={`flex items-center gap-2 px-3 py-2 rounded-lg text-xs font-medium transition-all ${
              showTopology
                ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/30'
                : 'bg-slate-700/50 text-slate-400 border border-slate-600/30 hover:text-white'
            }`}
            title="Show network topology map"
          >
            <Map className="w-3.5 h-3.5" />
            Topology
          </button>

          {/* ELI5 Toggle */}
          <button
            onClick={onEli5Toggle}
            className={`flex items-center gap-2 px-3 py-2 rounded-lg text-xs font-medium transition-all ${
              eli5Mode
                ? 'bg-purple-500/20 text-purple-300 border border-purple-500/30'
                : 'bg-slate-700/50 text-slate-400 border border-slate-600/30 hover:text-white'
            }`}
            title="Simplify explanations for junior engineers"
          >
            <Lightbulb className="w-3.5 h-3.5" />
            ELI5
          </button>

          {/* Downloads — authenticated fetch + blob download */}
          <button
            onClick={async () => {
              if (!id || downloading) return;
              setDownloading('json');
              try { await downloadFile(id, 'json'); } catch (e) { console.error('JSON download failed:', e); }
              setDownloading(null);
            }}
            disabled={downloading === 'json'}
            className="flex items-center gap-1.5 px-3 py-2 rounded-lg text-xs font-medium bg-slate-700/50 text-slate-400 border border-slate-600/30 hover:text-white transition-colors disabled:opacity-50"
          >
            {downloading === 'json' ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <FileJson className="w-3.5 h-3.5" />}
            JSON
          </button>
          <button
            onClick={async () => {
              if (!id || downloading) return;
              setDownloading('html');
              try { await downloadFile(id, 'html'); } catch (e) { console.error('HTML download failed:', e); }
              setDownloading(null);
            }}
            disabled={downloading === 'html'}
            className="flex items-center gap-1.5 px-3 py-2 rounded-lg text-xs font-medium bg-blue-600 text-white hover:bg-blue-500 transition-colors disabled:opacity-50"
          >
            {downloading === 'html' ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Download className="w-3.5 h-3.5" />}
            Report
          </button>
          <button
            onClick={() => setHelpOpen(true)}
            className="flex items-center gap-1.5 px-3 py-2 rounded-lg text-xs font-medium bg-slate-700/50 text-slate-400 border border-slate-600/30 hover:text-white transition-colors"
            title="Quick reference guide"
          >
            <HelpCircle className="w-3.5 h-3.5" />
            Help
          </button>
        </div>
      </div>

      {/* Help Modal */}
      {helpOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm" onClick={() => setHelpOpen(false)}>
          <div className="bg-slate-800 border border-slate-700 rounded-2xl shadow-2xl max-w-lg w-full mx-4 max-h-[80vh] overflow-y-auto" onClick={e => e.stopPropagation()}>
            <div className="flex items-center justify-between px-6 py-4 border-b border-slate-700">
              <h2 className="text-lg font-semibold text-white">Quick Reference</h2>
              <button onClick={() => setHelpOpen(false)} className="p-1 rounded-lg hover:bg-slate-700 transition-colors"><X className="w-5 h-5 text-slate-400" /></button>
            </div>
            <div className="px-6 py-4 space-y-4 text-sm">
              <div>
                <h3 className="font-semibold text-blue-400 mb-1">How to Read Results</h3>
                <p className="text-slate-300 leading-relaxed">Each card represents a detected issue. Colors indicate severity: <span className="text-red-400 font-medium">Critical</span> (act now), <span className="text-amber-400 font-medium">Warning</span> (investigate soon), <span className="text-blue-400 font-medium">Info</span> (awareness).</p>
              </div>
              <div>
                <h3 className="font-semibold text-green-400 mb-1">Vendor Runbooks</h3>
                <p className="text-slate-300 leading-relaxed">When an SD-WAN vendor is detected, each finding card shows a vendor-specific runbook with <strong>Diagnose → Fix → Verify</strong> steps. Use the GUI/CLI/Script tabs to match your access method.</p>
              </div>
              <div>
                <h3 className="font-semibold text-purple-400 mb-1">Wizard Mode</h3>
                <p className="text-slate-300 leading-relaxed">Click <strong>"Help Me Troubleshoot"</strong> to describe your symptoms. The wizard reorders findings by relevance and marks the best starting point.</p>
              </div>
              <div>
                <h3 className="font-semibold text-amber-400 mb-1">ELI5 Mode</h3>
                <p className="text-slate-300 leading-relaxed">Toggle <strong>ELI5</strong> for simplified explanations of each issue, designed for junior engineers or non-technical stakeholders.</p>
              </div>
              <div>
                <h3 className="font-semibold text-cyan-400 mb-1">Confidence Badges</h3>
                <p className="text-slate-300 leading-relaxed"><span className="text-green-400">High</span> = strong evidence, <span className="text-amber-400">Medium</span> = likely but verify, <span className="text-slate-400">Low</span> = possible false positive. Focus on high-confidence findings first.</p>
              </div>
              <div>
                <h3 className="font-semibold text-red-400 mb-1">Emergency Banner</h3>
                <p className="text-slate-300 leading-relaxed">A red banner appears for active threats (DDoS, C2 beaconing, DNS tunneling). Use the one-click incident report to escalate immediately.</p>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Emergency Banner */}
      <EmergencyBanner results={results} />

      {/* Vendor Indicator */}
      {detectedVendors.length > 0 && <VendorIndicator vendorNames={detectedVendors} />}

      {/* Executive Summary */}
      <div data-tour="summary">
        <ExecutiveSummary results={results} />
      </div>

      {/* Network Topology Map */}
      {showTopology && <NetworkTopology results={results} />}
      {!showTopology && (
        <button
          onClick={() => setShowTopology(true)}
          className="w-full py-4 rounded-xl border-2 border-dashed border-slate-700/50 text-slate-500 hover:text-cyan-400 hover:border-cyan-500/30 transition-all flex items-center justify-center gap-2 text-sm"
        >
          <Map className="w-4 h-4" />
          Show Network Topology Map
        </button>
      )}

      {/* ─── Display Filter Bar + Export Button ─────────────────── */}
      <div className="flex items-center gap-2" data-tour="filter-bar">
        <div className="flex-1">
          <FilterBar value={filterText} onChange={onFilterChange} parsedFilter={parsedFilter} />
        </div>
        <ExportButton
          jobId={id}
          filterText={filterText}
          parsedFilter={parsedFilter}
          isFiltered={isFiltered}
        />
      </div>

      {/* Filter active indicator */}
      {isFiltered && filteredResults && (
        <div className="flex items-center gap-2 px-4 py-2 rounded-xl bg-green-500/10 border border-green-500/20 text-xs text-green-400">
          <span className="font-medium">Filter active</span>
          <span className="text-green-500/70">—</span>
          <span>{filteredResults.traffic_analysis?.length ?? 0} flows, {filteredResults.timeline?.length ?? 0} events match</span>
          <button onClick={() => onFilterChange('')} className="ml-auto text-green-500 hover:text-green-300 transition-colors underline">Clear</button>
        </div>
      )}

      {/* Wizard Modal */}
      <WizardModal
        results={results}
        isOpen={wizardOpen}
        onClose={() => setWizardOpen(false)}
        detectedVendors={detectedVendors}
      />
    </>
  );
}
