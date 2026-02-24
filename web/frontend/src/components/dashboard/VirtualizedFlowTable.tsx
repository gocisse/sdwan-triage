// VirtualizedFlowTable — renders large datasets (10k+ rows) using react-window v2
// Only visible rows are mounted in the DOM, keeping node count low and scroll smooth.

import { type CSSProperties, useCallback, useMemo, useState } from 'react';
import { List } from 'react-window';
import { ChevronDown, ChevronUp, Search } from 'lucide-react';

// ─── Generic column definition ─────────────────────────────
export interface Column<T> {
  key: string;
  label: string;
  width?: string;           // Tailwind width class, e.g. 'w-40'
  align?: 'left' | 'right';
  render: (row: T, index: number) => React.ReactNode;
  sortValue?: (row: T) => number | string;
}

interface VirtualizedFlowTableProps<T> {
  data: T[];
  columns: Column<T>[];
  rowHeight?: number;        // px per row (default 36)
  maxHeight?: number;        // px max table height (default 400)
  searchable?: boolean;      // Enable search filter
  searchPlaceholder?: string;
  searchFilter?: (row: T, query: string) => boolean;
  emptyMessage?: string;
}

type SortDir = 'asc' | 'desc';

// Row props passed via react-window v2 rowProps
interface FlowRowProps<T> {
  sorted: T[];
  columns: Column<T>[];
}

// Row component for react-window v2 (receives index, style, and custom rowProps)
function FlowRow<T>({ index, style, ...rest }: {
  index: number;
  style: CSSProperties;
  ariaAttributes: Record<string, unknown>;
} & FlowRowProps<T>) {
  const { sorted, columns } = rest;
  const row = sorted[index];
  if (!row) return null;
  return (
    <div
      style={style}
      className={`flex items-center text-xs border-b border-slate-700/20 ${
        index % 2 === 0 ? 'bg-slate-800/30' : 'bg-slate-800/10'
      } hover:bg-slate-700/30 transition-colors`}
    >
      {columns.map(col => (
        <div
          key={col.key}
          className={`px-3 truncate ${col.width || 'flex-1'} ${
            col.align === 'right' ? 'text-right' : 'text-left'
          }`}
        >
          {col.render(row, index)}
        </div>
      ))}
    </div>
  );
}

export function VirtualizedFlowTable<T>({
  data,
  columns,
  rowHeight = 36,
  maxHeight = 400,
  searchable = false,
  searchPlaceholder = 'Filter rows...',
  searchFilter,
  emptyMessage = 'No data',
}: VirtualizedFlowTableProps<T>) {
  const [sortCol, setSortCol] = useState<string | null>(null);
  const [sortDir, setSortDir] = useState<SortDir>('desc');
  const [query, setQuery] = useState('');

  // Filter
  const filtered = useMemo(() => {
    if (!query || !searchFilter) return data;
    const q = query.toLowerCase();
    return data.filter(row => searchFilter(row, q));
  }, [data, query, searchFilter]);

  // Sort
  const sorted = useMemo(() => {
    if (!sortCol) return filtered;
    const col = columns.find(c => c.key === sortCol);
    if (!col?.sortValue) return filtered;
    const fn = col.sortValue;
    const dir = sortDir === 'asc' ? 1 : -1;
    return [...filtered].sort((a, b) => {
      const va = fn(a);
      const vb = fn(b);
      if (typeof va === 'number' && typeof vb === 'number') return (va - vb) * dir;
      return String(va).localeCompare(String(vb)) * dir;
    });
  }, [filtered, sortCol, sortDir, columns]);

  const handleSort = useCallback((key: string) => {
    if (sortCol === key) {
      setSortDir(d => (d === 'asc' ? 'desc' : 'asc'));
    } else {
      setSortCol(key);
      setSortDir('desc');
    }
  }, [sortCol]);

  // Memoize row props to avoid re-renders
  const rowProps = useMemo(() => ({ sorted, columns }), [sorted, columns]);

  if (data.length === 0) {
    return (
      <p className="text-xs text-slate-500 px-3 py-4 text-center">{emptyMessage}</p>
    );
  }

  const listHeight = Math.min(sorted.length * rowHeight, maxHeight);

  return (
    <div className="space-y-2">
      {/* Search bar */}
      {searchable && (
        <div className="relative">
          <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-slate-500" />
          <input
            type="text"
            value={query}
            onChange={e => setQuery(e.target.value)}
            placeholder={searchPlaceholder}
            className="w-full pl-8 pr-3 py-1.5 text-xs bg-slate-900/50 border border-slate-700/50 rounded-lg text-slate-300 placeholder-slate-500 focus:outline-none focus:border-blue-500/50"
          />
          {query && (
            <span className="absolute right-2.5 top-1/2 -translate-y-1/2 text-[10px] text-slate-500">
              {sorted.length.toLocaleString()} / {data.length.toLocaleString()}
            </span>
          )}
        </div>
      )}

      {/* Header */}
      <div className="flex items-center text-[10px] font-semibold text-slate-500 uppercase tracking-wider border-b border-slate-700/50 pb-1">
        {columns.map(col => (
          <div
            key={col.key}
            className={`px-3 ${col.width || 'flex-1'} ${
              col.align === 'right' ? 'text-right' : 'text-left'
            } ${col.sortValue ? 'cursor-pointer hover:text-slate-300 select-none' : ''}`}
            onClick={() => col.sortValue && handleSort(col.key)}
          >
            <span className="inline-flex items-center gap-1">
              {col.label}
              {sortCol === col.key && (
                sortDir === 'asc'
                  ? <ChevronUp className="w-3 h-3" />
                  : <ChevronDown className="w-3 h-3" />
              )}
            </span>
          </div>
        ))}
      </div>

      {/* Virtualized rows via react-window v2 */}
      <List
        rowComponent={FlowRow}
        rowCount={sorted.length}
        rowHeight={rowHeight}
        rowProps={rowProps}
        overscanCount={10}
        style={{ height: listHeight, overflow: 'auto' }}
      />

      {/* Footer stats */}
      <div className="flex items-center justify-between px-3 pt-1 text-[10px] text-slate-500">
        <span>
          Showing {sorted.length.toLocaleString()} of {data.length.toLocaleString()} rows
        </span>
        {sorted.length > 100 && (
          <span className="text-slate-600">Scroll to see more ↓</span>
        )}
      </div>
    </div>
  );
}
