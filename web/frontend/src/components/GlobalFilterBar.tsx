// GlobalFilterBar — Horizontal filter bar for source IP, dest IP, port, and protocol.
// Placed at the top of ResultsPage above the summary section.

import { Filter, X } from 'lucide-react';
import { useGlobalFilter } from '../contexts/FilterContext';

export function GlobalFilterBar() {
  const { draft, isActive, setDraftField, applyFilters, clearFilters } = useGlobalFilter();

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter') {
      e.preventDefault();
      applyFilters();
    }
  };

  return (
    <div className="rounded-xl border border-slate-700/50 bg-slate-800/60 backdrop-blur-sm p-3">
      <div className="flex items-center gap-3 flex-wrap">
        {/* Label */}
        <div className="flex items-center gap-2 shrink-0">
          <Filter className="w-4 h-4 text-blue-400" />
          <span className="text-xs font-semibold text-slate-300 uppercase tracking-wider">Filter</span>
        </div>

        {/* Source IP */}
        <div className="flex-1 min-w-[140px]">
          <input
            type="text"
            value={draft.srcIP}
            onChange={e => setDraftField('srcIP', e.target.value)}
            onKeyDown={handleKeyDown}
            placeholder="Source IP (e.g., 10.0.0.5)"
            className="w-full px-3 py-1.5 text-xs rounded-lg bg-slate-900/80 border border-slate-600/50 text-slate-200 placeholder-slate-500 focus:outline-none focus:ring-1 focus:ring-blue-500/50 focus:border-blue-500/50 transition-all"
          />
        </div>

        {/* Destination IP */}
        <div className="flex-1 min-w-[140px]">
          <input
            type="text"
            value={draft.dstIP}
            onChange={e => setDraftField('dstIP', e.target.value)}
            onKeyDown={handleKeyDown}
            placeholder="Dest IP (e.g., 192.168.1.1)"
            className="w-full px-3 py-1.5 text-xs rounded-lg bg-slate-900/80 border border-slate-600/50 text-slate-200 placeholder-slate-500 focus:outline-none focus:ring-1 focus:ring-blue-500/50 focus:border-blue-500/50 transition-all"
          />
        </div>

        {/* Service / Port */}
        <div className="flex-1 min-w-[120px] max-w-[160px]">
          <input
            type="text"
            value={draft.port}
            onChange={e => setDraftField('port', e.target.value)}
            onKeyDown={handleKeyDown}
            placeholder="Port (443 or https)"
            className="w-full px-3 py-1.5 text-xs rounded-lg bg-slate-900/80 border border-slate-600/50 text-slate-200 placeholder-slate-500 focus:outline-none focus:ring-1 focus:ring-blue-500/50 focus:border-blue-500/50 transition-all"
          />
        </div>

        {/* Protocol Dropdown */}
        <div className="shrink-0">
          <select
            value={draft.protocol}
            onChange={e => setDraftField('protocol', e.target.value)}
            className="px-3 py-1.5 text-xs rounded-lg bg-slate-900/80 border border-slate-600/50 text-slate-200 focus:outline-none focus:ring-1 focus:ring-blue-500/50 focus:border-blue-500/50 transition-all appearance-none cursor-pointer"
          >
            <option value="all">All Protocols</option>
            <option value="tcp">TCP</option>
            <option value="udp">UDP</option>
          </select>
        </div>

        {/* Action Buttons */}
        <div className="flex items-center gap-2 shrink-0">
          <button
            onClick={applyFilters}
            className="px-3 py-1.5 text-xs font-medium rounded-lg bg-blue-600 hover:bg-blue-500 text-white transition-colors shadow-sm shadow-blue-500/20"
          >
            Apply
          </button>
          {isActive && (
            <button
              onClick={clearFilters}
              className="px-2.5 py-1.5 text-xs font-medium rounded-lg bg-slate-700 hover:bg-slate-600 text-slate-300 hover:text-white transition-colors flex items-center gap-1"
            >
              <X className="w-3 h-3" />
              Clear
            </button>
          )}
        </div>

        {/* Active filter indicator */}
        {isActive && (
          <span className="text-[10px] text-amber-400 bg-amber-500/10 border border-amber-500/20 px-2 py-0.5 rounded-full font-medium shrink-0">
            Filtered
          </span>
        )}
      </div>
    </div>
  );
}
