// Results page — thin orchestrator that delegates to sub-components

import { useEffect, useState, useMemo, useCallback } from 'react';
import { useParams, Link } from 'react-router-dom';
import { ArrowLeft } from 'lucide-react';
import { useAnalysis } from '../hooks';
import { parseFilter, applyFilter, type ForensicFilterContextValue } from '../hooks';
import type { CategoryId } from '../components/dashboard';
import { StreamModal, HexViewer } from '../components';
import { SummarySection } from '../components/results/SummarySection';
import { FindingsSection } from '../components/results/FindingsSection';
import { DrillDownSection } from '../components/results/DrillDownSection';
import { SummarySkeleton } from '../components/ui/Skeletons';
import { KeyboardShortcutsModal } from '../components/ui/KeyboardShortcutsModal';
import { OnboardingTour } from '../components/onboarding/OnboardingTour';
import { TimeRangeProvider } from '../contexts/TimeRangeContext';
import { TimelineScrubber } from '../components/ui/TimelineScrubber';

export function ResultsPage() {
  const { id } = useParams<{ id: string }>();
  const { results, isLoading, error, loadStatus, loadResults } = useAnalysis();
  const [activeCategory, setActiveCategory] = useState<CategoryId>('all');
  const [eli5Mode, setEli5Mode] = useState(false);

  // Packet inspection state
  const [streamModalOpen, setStreamModalOpen] = useState(false);
  const [selectedStreamId, setSelectedStreamId] = useState<string | null>(null);
  const [hexViewerOpen, setHexViewerOpen] = useState(false);
  const [selectedPacketIndex, setSelectedPacketIndex] = useState<number>(-1);

  // Forensic drill-down state
  const [forensicTab, setForensicTab] = useState<'findings' | 'forensic'>('findings');
  const [filterText, setFilterText] = useState('');

  // Keyboard shortcuts modal
  const [shortcutsOpen, setShortcutsOpen] = useState(false);

  // Global keyboard listener for '?' shortcut
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if (e.key === '?' && !e.ctrlKey && !e.metaKey) {
        const tag = (e.target as HTMLElement)?.tagName;
        if (tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT') return;
        e.preventDefault();
        setShortcutsOpen((prev) => !prev);
      }
    };
    window.addEventListener('keydown', handler);
    return () => window.removeEventListener('keydown', handler);
  }, []);

  // Parse filter and compute filtered results
  const parsedFilter = useMemo(() => parseFilter(filterText), [filterText]);
  const filteredResults = useMemo(
    () => results ? applyFilter(results, parsedFilter) : null,
    [results, parsedFilter]
  );
  const isFiltered = parsedFilter.valid && parsedFilter.tokens.length > 0;

  // Filter context value
  const filterCtxValue = useMemo<ForensicFilterContextValue | null>(() => {
    if (!results || !filteredResults) return null;
    return {
      filterText,
      parsedFilter,
      setFilterText,
      filteredResults,
      isFiltered,
      clearFilter: () => setFilterText(''),
    };
  }, [filterText, parsedFilter, filteredResults, isFiltered, results]);

  // Compute capture time span from timeline events for TimeRangeProvider
  const captureSpan = useMemo(() => {
    const events = results?.timeline || [];
    let min = Infinity;
    let max = -Infinity;
    for (const ev of events) {
      if (!ev.timestamp) continue;
      const ts = new Date(ev.timestamp).getTime() / 1000;
      if (ts > 0 && isFinite(ts)) {
        if (ts < min) min = ts;
        if (ts > max) max = ts;
      }
    }
    if (!isFinite(min) || !isFinite(max) || max <= min) {
      return { start: 0, end: 1 };
    }
    return { start: min, end: max };
  }, [results?.timeline]);

  // Extract detected vendor names for runbook integration
  const detectedVendors = useMemo(() => {
    if (!results?.sdwan_vendors) return [];
    return results.sdwan_vendors.map(v => v.name);
  }, [results?.sdwan_vendors]);

  // Callbacks for child components
  const handleSelectPacket = useCallback((packetIndex: number) => {
    setSelectedPacketIndex(packetIndex);
    setHexViewerOpen(true);
  }, []);

  const handleFollowStream = useCallback((streamId: string) => {
    setSelectedStreamId(streamId);
    setStreamModalOpen(true);
  }, []);

  // Load job status and results
  useEffect(() => {
    if (id) {
      loadStatus(id).catch(() => {});
      loadResults(id).catch(() => {});
    }
  }, [id, loadStatus, loadResults]);

  if (!id) {
    return (
      <div className="text-center py-12">
        <p className="text-slate-400">Invalid analysis ID</p>
        <Link to="/" className="btn-primary mt-4 inline-flex items-center gap-2">
          <ArrowLeft className="w-4 h-4" />
          Back to Home
        </Link>
      </div>
    );
  }

  if (isLoading && !results) {
    return <SummarySkeleton />;
  }

  if (error && !results) {
    return (
      <div className="max-w-lg mx-auto text-center py-12">
        <div className="bg-slate-800/80 border border-slate-700/50 rounded-xl p-8">
          <h2 className="text-xl font-bold text-red-400 mb-2">Error Loading Results</h2>
          <p className="text-slate-400 mb-6">{error}</p>
          <Link to="/" className="btn-primary inline-flex items-center gap-2">
            <ArrowLeft className="w-4 h-4" />
            Back to Home
          </Link>
        </div>
      </div>
    );
  }

  if (!results) {
    return (
      <div className="text-center py-12">
        <p className="text-slate-400">Results not found</p>
        <Link to="/" className="btn-primary mt-4 inline-flex items-center gap-2">
          <ArrowLeft className="w-4 h-4" />
          Back to Home
        </Link>
      </div>
    );
  }

  return (
    <TimeRangeProvider captureStart={captureSpan.start} captureEnd={captureSpan.end}>
    <div className="space-y-6">
      {/* Onboarding Tour (first visit only) */}
      <OnboardingTour />

      {/* Keyboard Shortcuts Modal */}
      <KeyboardShortcutsModal isOpen={shortcutsOpen} onClose={() => setShortcutsOpen(false)} />

      {/* ─── Summary Section (top bar, exec summary, topology, filter bar) ─── */}
      <SummarySection
        id={id}
        results={results}
        filteredResults={filteredResults}
        isFiltered={isFiltered}
        filterText={filterText}
        parsedFilter={parsedFilter}
        detectedVendors={detectedVendors}
        eli5Mode={eli5Mode}
        onEli5Toggle={() => setEli5Mode(prev => !prev)}
        onFilterChange={setFilterText}
        onOpenWizard={() => {}}
      />


      {/* ─── Timeline Scrubber (global time filter) ─────────────── */}
      {captureSpan.start > 0 && (
        <TimelineScrubber results={results} />
      )}

      {/* ─── View Mode Tabs: Findings | Forensic ───────────────── */}
      <div className="flex items-center gap-1 p-1 rounded-xl bg-slate-800/60 border border-slate-700/50 w-fit">
        <button
          onClick={() => setForensicTab('findings')}
          className={`px-4 py-2 rounded-lg text-xs font-medium transition-all ${
            forensicTab === 'findings'
              ? 'bg-blue-600 text-white shadow-lg shadow-blue-500/20'
              : 'text-slate-400 hover:text-white hover:bg-slate-700/50'
          }`}
        >
          Findings
        </button>
        <button
          onClick={() => setForensicTab('forensic')}
          className={`px-4 py-2 rounded-lg text-xs font-medium transition-all ${
            forensicTab === 'forensic'
              ? 'bg-blue-600 text-white shadow-lg shadow-blue-500/20'
              : 'text-slate-400 hover:text-white hover:bg-slate-700/50'
          }`}
        >
          Forensic Drill-Down
        </button>
      </div>

      {/* ─── Active Tab Content ─────────────────────────────────── */}
      {forensicTab === 'findings' ? (
        <FindingsSection
          results={results}
          filteredResults={filteredResults}
          isFiltered={isFiltered}
          eli5Mode={eli5Mode}
          detectedVendors={detectedVendors}
          activeCategory={activeCategory}
          onCategoryChange={setActiveCategory}
          onOpenWizard={() => {}}
          onFollowStream={handleFollowStream}
        />
      ) : (
        <DrillDownSection
          results={results}
          filteredResults={filteredResults}
          isFiltered={isFiltered}
          filterCtxValue={filterCtxValue}
          filterText={filterText}
          parsedFilter={parsedFilter}
          jobId={id}
          onFilterChange={setFilterText}
          onSelectPacket={handleSelectPacket}
          onFollowStream={handleFollowStream}
        />
      )}

      {/* ─── Packet Inspection Modals ───────────────────────────── */}
      {streamModalOpen && selectedStreamId && (
        <StreamModal
          isOpen={streamModalOpen}
          onClose={() => { setStreamModalOpen(false); setSelectedStreamId(null); }}
          jobId={id}
          streamId={selectedStreamId}
          onFilterStream={(sid) => setFilterText(`ip.addr == ${sid.split('->')[0]?.split(':')[0] ?? ''}`)}
          onSelectPacket={handleSelectPacket}
        />
      )}

      {hexViewerOpen && selectedPacketIndex >= 0 && (
        <HexViewer
          isOpen={hexViewerOpen}
          onClose={() => { setHexViewerOpen(false); setSelectedPacketIndex(-1); }}
          jobId={id}
          packetIndex={selectedPacketIndex}
          onSelectStream={handleFollowStream}
        />
      )}
    </div>
    </TimeRangeProvider>
  );
}
