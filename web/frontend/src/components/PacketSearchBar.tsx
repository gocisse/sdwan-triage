import React, { useCallback, useState } from 'react';
import { Search, Loader2, AlertCircle } from 'lucide-react';
import { getAuthToken } from '../api/client';

// PacketSearchBar — Wireshark-style full-text packet search.
//
// Calls GET /api/packets/search/:jobID with one of three modes:
//   address  — match on source/destination IP and/or port
//   string   — ASCII substring match against raw packet bytes
//   hex      — raw-byte sequence match
//
// Results are rendered inline under the search bar. Clicking a result row
// triggers `onSelectPacket(index)` so the parent can open the HexViewer /
// PacketDissector at that packet index — mirroring Wireshark's "Find
// Packet" → double-click behaviour.

export type SearchMode = 'address' | 'string' | 'hex';

export interface SearchMatch {
  index: number;
  timestamp: string;
  length: number;
  src_ip: string;
  dst_ip: string;
  src_port?: number;
  dst_port?: number;
  protocol: string;
  summary: string;
  match_offset?: number;
  match_length?: number;
  preview?: string;
}

interface SearchResponse {
  query: string;
  mode: SearchMode;
  total: number;
  truncated: boolean;
  scanned: number;
  matches: SearchMatch[];
}

interface PacketSearchBarProps {
  jobId: string;
  /** Called when the user selects a result row. */
  onSelectPacket?: (packetIndex: number) => void;
  /** Optional initial mode (default 'string'). */
  initialMode?: SearchMode;
}

const MODE_HELP: Record<SearchMode, string> = {
  address:
    'Address — match on IP/port. Examples: 10.0.0.5, 10.0.0.5:443, port:8080, 10.0.0.5,10.0.0.6',
  string:
    'String — case-insensitive ASCII substring search across raw packet bytes (like Wireshark "Find Packet → String").',
  hex: 'Hex — match a byte sequence. Spaces and colons are ignored: 160301, 16 03 01, de:ad:be:ef.',
};

const MODE_PLACEHOLDER: Record<SearchMode, string> = {
  address: '10.0.0.5 or port:443',
  string: 'HTTP or Cookie:',
  hex: '160301 or de:ad:be:ef',
};

export const PacketSearchBar: React.FC<PacketSearchBarProps> = ({
  jobId,
  onSelectPacket,
  initialMode = 'string',
}) => {
  const [mode, setMode] = useState<SearchMode>(initialMode);
  const [query, setQuery] = useState('');
  const [caseSensitive, setCaseSensitive] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<SearchResponse | null>(null);

  const runSearch = useCallback(async () => {
    const q = query.trim();
    if (!q) return;
    setLoading(true);
    setError(null);
    try {
      const token = getAuthToken();
      const params = new URLSearchParams({ q, mode });
      if (mode === 'string' && caseSensitive) params.set('case', '1');
      const response = await fetch(
        `/api/packets/search/${encodeURIComponent(jobId)}?${params.toString()}`,
        {
          headers: token ? { Authorization: `Bearer ${token}` } : {},
        },
      );
      if (!response.ok) {
        const data = await response.json().catch(() => ({ error: 'Search failed' }));
        throw new Error(data.error || `HTTP ${response.status}`);
      }
      const data: SearchResponse = await response.json();
      setResult(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Unknown error');
      setResult(null);
    } finally {
      setLoading(false);
    }
  }, [query, mode, caseSensitive, jobId]);

  const handleKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Enter') runSearch();
  };

  return (
    <div className="bg-slate-800/80 border border-slate-700/50 rounded-xl p-4 space-y-3">
      <div className="flex items-center gap-2">
        <Search className="w-4 h-4 text-cyan-400 flex-shrink-0" />
        <h3 className="text-sm font-semibold text-white">Packet Search</h3>
        <span className="text-xs text-slate-500">{MODE_HELP[mode]}</span>
      </div>

      <div className="flex flex-wrap items-center gap-2">
        {/* Mode selector */}
        <div className="inline-flex rounded-lg overflow-hidden border border-slate-600/50 text-xs">
          {(['address', 'string', 'hex'] as SearchMode[]).map(m => (
            <button
              key={m}
              onClick={() => setMode(m)}
              className={`px-3 py-1.5 transition-colors ${
                mode === m
                  ? 'bg-cyan-600 text-white'
                  : 'bg-slate-700 text-slate-300 hover:bg-slate-600'
              }`}
            >
              {m.charAt(0).toUpperCase() + m.slice(1)}
            </button>
          ))}
        </div>

        {/* Query input */}
        <input
          type="text"
          value={query}
          onChange={e => setQuery(e.target.value)}
          onKeyDown={handleKeyDown}
          placeholder={MODE_PLACEHOLDER[mode]}
          className="flex-1 min-w-[200px] px-3 py-1.5 text-sm bg-slate-900 border border-slate-600/50 rounded-lg text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500"
        />

        {/* Case toggle (string mode only) */}
        {mode === 'string' && (
          <label className="flex items-center gap-1.5 text-xs text-slate-400 cursor-pointer select-none">
            <input
              type="checkbox"
              checked={caseSensitive}
              onChange={e => setCaseSensitive(e.target.checked)}
              className="accent-cyan-500"
            />
            Case-sensitive
          </label>
        )}

        {/* Run button */}
        <button
          onClick={runSearch}
          disabled={loading || !query.trim()}
          className="px-4 py-1.5 text-sm font-medium rounded-lg bg-cyan-600 text-white hover:bg-cyan-500 disabled:opacity-50 disabled:cursor-not-allowed transition-colors inline-flex items-center gap-1.5"
        >
          {loading ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Search className="w-3.5 h-3.5" />}
          Search
        </button>
      </div>

      {/* Error state */}
      {error && (
        <div className="flex items-start gap-2 px-3 py-2 rounded-lg bg-red-900/30 border border-red-700/40 text-red-300 text-xs">
          <AlertCircle className="w-3.5 h-3.5 flex-shrink-0 mt-0.5" />
          <span>{error}</span>
        </div>
      )}

      {/* Results */}
      {result && !error && (
        <div className="border-t border-slate-700/40 pt-3 space-y-2">
          <div className="flex items-center justify-between text-xs">
            <span className="text-slate-400">
              {result.total === 0 ? (
                <>No matches found in {result.scanned.toLocaleString()} packets.</>
              ) : (
                <>
                  <span className="text-cyan-400 font-semibold">{result.total.toLocaleString()}</span>
                  {' '}match{result.total === 1 ? '' : 'es'} in {result.scanned.toLocaleString()} packets
                  {result.truncated && (
                    <span className="ml-1 text-yellow-400">(result capped — refine your query)</span>
                  )}
                </>
              )}
            </span>
            {result.total > 0 && (
              <button
                onClick={() => setResult(null)}
                className="text-slate-500 hover:text-slate-300"
              >
                Clear
              </button>
            )}
          </div>

          {result.total > 0 && (
            <div className="max-h-64 overflow-y-auto rounded-lg border border-slate-700/40 bg-slate-900/60">
              <table className="w-full text-xs">
                <thead className="sticky top-0 bg-slate-800/90">
                  <tr className="border-b border-slate-700/40">
                    <th className="px-3 py-1.5 text-left text-slate-500 font-medium w-16">#</th>
                    <th className="px-3 py-1.5 text-left text-slate-500 font-medium w-32">Time</th>
                    <th className="px-3 py-1.5 text-left text-slate-500 font-medium">Flow</th>
                    <th className="px-3 py-1.5 text-left text-slate-500 font-medium">Preview</th>
                    <th className="px-3 py-1.5 text-right text-slate-500 font-medium w-20">Offset</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/50">
                  {result.matches.map(m => (
                    <tr
                      key={m.index}
                      onClick={() => onSelectPacket?.(m.index)}
                      className="hover:bg-slate-700/30 cursor-pointer"
                    >
                      <td className="px-3 py-1.5 font-mono text-cyan-400">{m.index}</td>
                      <td className="px-3 py-1.5 font-mono text-slate-400">{m.timestamp}</td>
                      <td className="px-3 py-1.5 font-mono text-slate-300 truncate max-w-[200px]" title={m.summary}>
                        {m.summary}
                      </td>
                      <td className="px-3 py-1.5 font-mono text-slate-400 truncate max-w-[260px]">
                        {m.preview ? (
                          <span title={m.preview}>{m.preview}</span>
                        ) : (
                          <span className="text-slate-600">—</span>
                        )}
                      </td>
                      <td className="px-3 py-1.5 text-right text-slate-500 font-mono">
                        {m.match_offset !== undefined ? `+${m.match_offset}` : ''}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}
    </div>
  );
};

export default PacketSearchBar;
